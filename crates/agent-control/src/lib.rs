//! Local control protocol DTOs and newline-delimited JSON framing for Marmot agents.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const AGENT_CONTROL_PROTOCOL_V2: &str = "marmot.agent-control.v2";
pub const MAX_AGENT_CONTROL_FRAME_BYTES: usize = 1024 * 1024;
pub const AGENT_CONTROL_STREAM_STATUS_STARTED: &str = "started";
pub const AGENT_CONTROL_REFERENCED_TEXT_MAX_CHARS: usize = 2_000;
pub const AGENT_CONTROL_REFERENCED_ATTACHMENTS_MAX: usize = 16;
pub const AGENT_CONTROL_TIMELINE_DEFAULT_LIMIT: u32 = 20;
pub const AGENT_CONTROL_TIMELINE_MAX_LIMIT: u32 = 50;
pub const AGENT_CONTROL_TIMELINE_TEXT_MAX_CHARS: usize = 8_192;
pub const AGENT_CONTROL_TIMELINE_REACTIONS_MAX: usize = 64;

/// Account-scoped policy for confirming inbound Marmot group invites.
///
/// A policy never makes an unauthenticated Welcome acceptable. The
/// `any_authenticated_direct` variant additionally requires the joined MLS
/// group to contain exactly the local agent and one peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentControlInvitePolicy {
    Deny,
    #[default]
    Allowlist,
    #[serde(alias = "any-authenticated-direct")]
    AnyAuthenticatedDirect,
    #[serde(alias = "any-authenticated")]
    AnyAuthenticated,
}

impl AgentControlInvitePolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allowlist => "allowlist",
            Self::AnyAuthenticatedDirect => "any-authenticated-direct",
            Self::AnyAuthenticated => "any-authenticated",
        }
    }
}

impl std::fmt::Display for AgentControlInvitePolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for AgentControlInvitePolicy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "deny" => Ok(Self::Deny),
            "allowlist" => Ok(Self::Allowlist),
            "any-authenticated-direct" => Ok(Self::AnyAuthenticatedDirect),
            "any-authenticated" => Ok(Self::AnyAuthenticated),
            _ => Err(format!(
                "invalid invite policy {value:?}; expected deny, allowlist, any-authenticated-direct, or any-authenticated"
            )),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentControlError {
    #[error("agent control frame is empty")]
    EmptyFrame,
    #[error("agent control frame exceeds max size: {0}")]
    FrameTooLarge(usize),
    #[error("wrong agent control protocol: {0}")]
    WrongProtocol(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlEnvelope<T> {
    pub marmot_agent_control: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(flatten)]
    pub payload: T,
}

impl<T> AgentControlEnvelope<T> {
    pub fn new(id: Option<String>, payload: T) -> Self {
        Self {
            marmot_agent_control: AGENT_CONTROL_PROTOCOL_V2.to_owned(),
            id,
            auth_token: None,
            payload,
        }
    }

    pub fn request(id: Option<String>, payload: T) -> Self {
        Self::new(id, payload)
    }

    pub fn with_auth_token(mut self, auth_token: impl Into<String>) -> Self {
        self.auth_token = Some(auth_token.into());
        self
    }

    pub fn validate_protocol(&self) -> Result<(), AgentControlError> {
        if self.marmot_agent_control == AGENT_CONTROL_PROTOCOL_V2 {
            Ok(())
        } else {
            Err(AgentControlError::WrongProtocol(
                self.marmot_agent_control.clone(),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentControlRequest {
    SubscribeInbound {
        account_id_hex: Option<String>,
        group_id_hex: Option<String>,
    },
    /// Resolve one row from the materialized, user-visible timeline.
    TimelineMessageGet {
        account_id_hex: String,
        group_id_hex: String,
        message_id_hex: String,
    },
    /// Page through the materialized, user-visible timeline in stable
    /// `(recorded_at, message_id_hex)` order. `before` and `after` are mutually
    /// exclusive; an omitted cursor returns the newest page.
    TimelineList {
        account_id_hex: String,
        group_id_hex: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        before: Option<AgentControlTimelineCursor>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<AgentControlTimelineCursor>,
        #[serde(default)]
        before_inclusive: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
    },
    SendFinal {
        account_id_hex: String,
        group_id_hex: String,
        text: String,
        reply_to_message_id_hex: Option<String>,
        /// Optional client-supplied dedup key. When present, the connector dedups
        /// repeated sends with the same key (returning the original message ids)
        /// so a retry after a post-write timeout cannot double-post an
        /// unrecallable durable message. Omitted = no dedup (legacy behavior).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idempotency_key: Option<String>,
    },
    DeleteMessage {
        account_id_hex: String,
        group_id_hex: String,
        target_message_id_hex: String,
    },
    /// Add bounded, control-free, non-blank reaction content to a durable message.
    SendReaction {
        account_id_hex: String,
        group_id_hex: String,
        target_message_id_hex: String,
        emoji: String,
    },
    /// Retract this account's active reactions from a durable message. When
    /// `emoji` is present, only active reactions with that exact content are
    /// retracted; when absent, all of this account's active reactions on the
    /// target are retracted in one durable delete event.
    RemoveReaction {
        account_id_hex: String,
        group_id_hex: String,
        target_message_id_hex: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        emoji: Option<String>,
    },
    StreamBegin {
        account_id_hex: String,
        group_id_hex: String,
        stream_id_hex: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_message_id_hex: Option<String>,
        quic_candidates: Vec<String>,
    },
    StreamAppend {
        stream_id_hex: String,
        stream_capability: String,
        append_text: String,
        /// Optional client-supplied preview dedup key. A matching retry is
        /// acknowledged without re-applying the mutation. Reuse with different
        /// inputs fails with `stream_preview_idempotency_conflict`. Preview
        /// receipts are process-local and do not survive a restart.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idempotency_key: Option<String>,
    },
    StreamStatus {
        stream_id_hex: String,
        stream_capability: String,
        status: String,
        /// Optional client-supplied preview dedup key. A matching retry is
        /// acknowledged without re-applying the mutation. Reuse with different
        /// inputs fails with `stream_preview_idempotency_conflict`. Preview
        /// receipts are process-local and do not survive a restart.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idempotency_key: Option<String>,
    },
    StreamProgress {
        stream_id_hex: String,
        stream_capability: String,
        text: String,
        /// Optional client-supplied preview dedup key. A matching retry is
        /// acknowledged without re-applying the mutation. Reuse with different
        /// inputs fails with `stream_preview_idempotency_conflict`. Preview
        /// receipts are process-local and do not survive a restart.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idempotency_key: Option<String>,
    },
    /// Finalize an active preview stream into the durable final message.
    ///
    /// If `final_text`, `transcript_hash_hex`, or `chunk_count` do not match
    /// the transcript composed from the preceding appends, the request fails
    /// WITHOUT tearing down the stream session: the agent may append again
    /// and/or re-issue `StreamFinalize`, or cancel the stream.
    StreamFinalize {
        stream_id_hex: String,
        stream_capability: String,
        final_text: String,
        transcript_hash_hex: String,
        chunk_count: u64,
        /// Optional client-supplied dedup key. When present, the connector
        /// returns the original stream-final message ids for a retry whose
        /// finalized transcript matches the first successful finalize.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idempotency_key: Option<String>,
    },
    StreamCancel {
        stream_id_hex: String,
        stream_capability: String,
        reason: Option<String>,
    },
    AccountList,
    AccountCreate {
        label: Option<String>,
        publish_key_package: bool,
    },
    AccountPublishKeyPackage {
        account_id_hex: String,
    },
    AccountPublishProfile {
        account_id_hex: String,
        name: String,
        display_name: Option<String>,
    },
    /// Resolve whether the selected account already has a valid published
    /// Nostr kind-0 profile. The connector returns a typed outcome so relay
    /// failures can never be mistaken for a confirmed absence.
    AccountProfileLookup {
        account_id_hex: String,
    },
    SendAgentActivity {
        account_id_hex: String,
        group_id_hex: String,
        status: String,
        text: String,
        reply_to_message_id_hex: Option<String>,
        extra: Option<Value>,
    },
    SendAgentOperationEvent {
        account_id_hex: String,
        group_id_hex: String,
        event_type: String,
        status: String,
        operation_id: Option<String>,
        run_id: Option<String>,
        turn_id: Option<String>,
        name: Option<String>,
        text: String,
        preview: Option<String>,
        details: Option<Value>,
        sequence: Option<u64>,
        ok: Option<bool>,
        duration_ms: Option<u64>,
        reply_to_message_id_hex: Option<String>,
    },
    SendGroupSystemEvent {
        account_id_hex: String,
        group_id_hex: String,
        system_type: String,
        text: String,
        data: Option<Value>,
    },
    GroupInfo {
        account_id_hex: String,
        group_id_hex: String,
    },
    MaintenanceStatus {
        account_id_hex: String,
        group_id_hex: String,
    },
    KeyPackageMaintenanceStatus {
        account_id_hex: String,
    },
    MaintenanceScheduleSelfUpdate {
        account_id_hex: String,
        group_id_hex: String,
    },
    MaintenanceGetPolicy {
        account_id_hex: String,
    },
    MaintenanceSetPolicy {
        account_id_hex: String,
        enabled_for_new_groups: bool,
    },
    MaintenancePause {
        account_id_hex: String,
    },
    MaintenanceResume {
        account_id_hex: String,
    },
    MaintenanceRun {
        account_id_hex: String,
    },
    AllowlistList {
        account_id_hex: String,
    },
    AllowlistAdd {
        account_id_hex: String,
        welcomer_account_id_hex: String,
    },
    AllowlistRemove {
        account_id_hex: String,
        welcomer_account_id_hex: String,
    },
    InvitePolicyGet {
        account_id_hex: String,
    },
    InvitePolicySet {
        account_id_hex: String,
        policy: AgentControlInvitePolicy,
    },
    DebugInjectInbound {
        account_id_hex: String,
        group_id_hex: String,
        message_id_hex: String,
        sender_account_id_hex: String,
        text: String,
    },
    DebugRecordedFinals,
    /// Encrypt + upload local files as encrypted media and send them as a kind-9
    /// message in the group. Files are read from the connector host by `path`;
    /// the control plane never carries plaintext bytes or the content key.
    SendMedia {
        account_id_hex: String,
        group_id_hex: String,
        attachments: Vec<AgentControlMediaUpload>,
        caption: Option<String>,
        /// Optional client-supplied dedup key. Matching retries return the
        /// original durable message ids without re-uploading or re-publishing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idempotency_key: Option<String>,
    },
    /// Fetch + decrypt an inbound media reference and write the plaintext to a
    /// temp file on the connector host. The content key stays in the connector;
    /// the reply carries only the local path and metadata.
    DownloadMedia {
        account_id_hex: String,
        group_id_hex: String,
        media: AgentControlMediaRef,
    },
}

/// A local file to encrypt + upload as an attachment. The connector reads the
/// bytes from `path`; the control plane never carries plaintext or a content key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlMediaUpload {
    pub path: String,
    pub media_type: String,
    pub file_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbhash: Option<String>,
}

/// A single fetch locator for an encrypted media reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlMediaLocator {
    pub kind: String,
    pub value: String,
}

/// Faithful, non-secret mirror of `MediaAttachmentReference`. Carries everything
/// needed to fetch + authenticate a blob EXCEPT the content key, which never
/// leaves the connector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlMediaRef {
    pub media_type: String,
    pub file_name: String,
    pub ciphertext_sha256: String,
    pub plaintext_sha256: String,
    pub nonce_hex: String,
    pub version: String,
    pub source_epoch: u64,
    pub locators: Vec<AgentControlMediaLocator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbhash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentControlResponse {
    Ack,
    Error {
        code: String,
        message: String,
    },
    AccountList {
        accounts: Vec<AgentControlAccount>,
    },
    TimelineMessage {
        account_id_hex: String,
        group_id_hex: String,
        message_id_hex: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<AgentControlTimelineMessage>,
    },
    TimelinePage {
        account_id_hex: String,
        group_id_hex: String,
        messages: Vec<AgentControlTimelineMessage>,
        has_more_before: bool,
        has_more_after: bool,
    },
    AccountCreated {
        account: AgentControlAccount,
    },
    KeyPackagePublished {
        account_id_hex: String,
        key_package_bytes: usize,
    },
    ProfilePublished {
        account_id_hex: String,
        name: String,
        display_name: Option<String>,
    },
    ProfileLookup {
        account_id_hex: String,
        status: AgentControlProfileLookupStatus,
        retryable: bool,
    },
    FinalSent {
        message_ids_hex: Vec<String>,
        #[serde(default)]
        maintenance_disposition: AgentControlSendMaintenanceDisposition,
    },
    AppEventSent {
        message_ids_hex: Vec<String>,
        #[serde(default)]
        maintenance_disposition: AgentControlSendMaintenanceDisposition,
    },
    Allowlist {
        account_id_hex: String,
        welcomer_account_ids_hex: Vec<String>,
    },
    InvitePolicy {
        account_id_hex: String,
        policy: AgentControlInvitePolicy,
    },
    GroupInfo {
        account_id_hex: String,
        group_id_hex: String,
        member_count: u32,
        /// True when the group has exactly two members (the agent + one peer),
        /// i.e. an effective direct conversation where the agent always replies.
        is_direct: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject: Option<String>,
    },
    MaintenanceStatus {
        status: AgentControlMaintenanceStatus,
    },
    KeyPackageMaintenanceStatus {
        status: Option<AgentControlKeyPackageMaintenanceStatus>,
    },
    MaintenanceScheduled {
        obligation_id_hex: String,
    },
    MaintenancePolicy {
        enabled_for_new_groups: bool,
    },
    MaintenanceRun {
        published: u32,
        message_ids_hex: Vec<String>,
        deferred: u32,
        ambiguous_exposure: u32,
        failures: u32,
    },
    StreamBegun {
        stream_id_hex: String,
        /// Random 256-bit bearer capability required for every subsequent
        /// operation on this stream. Never log or persist this value.
        stream_capability: String,
        start_message_id_hex: String,
        quic_candidates: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_max_plaintext_frame_len: Option<u32>,
    },
    StreamFinalized {
        stream_id_hex: String,
        message_ids_hex: Vec<String>,
    },
    DebugRecordedFinals {
        sends: Vec<AgentControlDebugFinalSend>,
    },
    /// An inbound media reference was fetched, decrypted, and written to a local
    /// temp file on the connector host. The path is host-local; no bytes or key
    /// material cross the control plane.
    MediaDownloaded {
        path: String,
        media_type: String,
        file_name: String,
        size_bytes: u64,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentControlSendMaintenanceDisposition {
    #[default]
    Ready,
    PostJoinRotationPendingRetryable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentControlProfileLookupStatus {
    ProfileFound,
    ProfileNotFound,
    Indeterminate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlAccount {
    pub account_id_hex: String,
    pub label: String,
    pub local_signing: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlDebugFinalSend {
    pub account_id_hex: String,
    pub group_id_hex: String,
    pub text: String,
    pub reply_to_message_id_hex: Option<String>,
    pub message_ids_hex: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlActor {
    pub account_id_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub is_self: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlTimelineCursor {
    pub recorded_at: u64,
    pub message_id_hex: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentControlTimelineMessageAvailability {
    Available,
    Deleted,
    Invalidated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlTimelineReaction {
    pub reaction_message_id_hex: String,
    pub actor: AgentControlActor,
    pub emoji: String,
    pub reacted_at: u64,
}

/// A bounded, privacy-aware view of one materialized timeline row. Deleted and
/// invalidated rows retain identity/attribution but never carry plaintext or
/// attachment summaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlTimelineMessage {
    pub message_id_hex: String,
    pub sender: AgentControlActor,
    pub direction: String,
    pub kind: u64,
    /// Sender-authenticated timeline time in Unix seconds.
    pub recorded_at: u64,
    /// Local observation/creation time in Unix seconds.
    pub observed_at: u64,
    pub availability: AgentControlTimelineMessageAvailability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default)]
    pub text_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AgentControlAttachmentSummary>,
    #[serde(default)]
    pub attachments_truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reactions: Vec<AgentControlTimelineReaction>,
    #[serde(default)]
    pub reactions_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlMessage {
    pub message_id_hex: String,
    pub sender: AgentControlActor,
    pub text: String,
    /// Sender-authenticated inner app-event time in Unix seconds.
    pub recorded_at: u64,
    /// Encrypted media references attached to the message. The content key
    /// remains inside `wn-agent`; connectors pass these refs back to
    /// `download_media`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub media: Vec<AgentControlMediaRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlAttachmentSummary {
    pub media_type: String,
    pub file_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dim: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentControlReferencedMessageAvailability {
    Available,
    Missing,
    Deleted,
    Invalidated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlReferencedMessage {
    pub message_id_hex: String,
    pub availability: AgentControlReferencedMessageAvailability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<AgentControlActor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_excerpt: Option<String>,
    #[serde(default)]
    pub text_truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AgentControlAttachmentSummary>,
    #[serde(default)]
    pub attachments_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlMaintenanceObligation {
    pub id_hex: String,
    pub trigger: String,
    pub phase: String,
    pub created_at: u64,
    pub operational_target_at: Option<u64>,
    pub overdue: bool,
    pub eose_deadline_at: Option<u64>,
    pub grace_until: Option<u64>,
    pub quiet_since: Option<u64>,
    pub sampled_jitter_ms: u64,
    pub not_before: Option<u64>,
    pub attempt_count: u32,
    pub semantic_rearm_count: u32,
    pub last_failure_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlMaintenanceStatus {
    pub group_id_hex: String,
    pub enrolled_at: Option<u64>,
    pub periodic_enrolled: bool,
    pub last_own_leaf_rotation_at: Option<u64>,
    pub next_periodic_rotation_at: Option<u64>,
    pub obligations: Vec<AgentControlMaintenanceObligation>,
    pub preparing_evolutions: u32,
    pub prepared_evolutions: u32,
    pub attempting_evolutions: u32,
    pub confirmed_evolutions: u32,
    pub superseded_evolutions: u32,
    pub accepted_fanout_targets: u32,
    pub unattempted_fanout_targets: u32,
    pub failed_fanout_targets: u32,
    pub policy_prohibited_fanout_targets: u32,
    pub paused: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlKeyPackageMaintenanceStatus {
    pub stable_slot_id: String,
    pub phase: String,
    pub current_key_package_ref_hex: Option<String>,
    pub current_not_after: Option<u64>,
    pub refresh_at: Option<u64>,
    pub authored_event_id_hex: Option<String>,
    pub last_consumed_key_package_ref_hex: Option<String>,
    pub retained_private_material_count: u32,
    pub accepted_fanout_targets: u32,
    pub unattempted_fanout_targets: u32,
    pub failed_fanout_targets: u32,
    pub policy_prohibited_fanout_targets: u32,
    pub pending_event_id_hex: Option<String>,
    pub pending_attempt_count: u32,
    pub pending_last_failure_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentControlEvent {
    InboundMessage {
        account_id_hex: String,
        group_id_hex: String,
        message: AgentControlMessage,
        /// True when the message addresses the receiving agent account: a `p`
        /// tag, an inline `nostr:<account-pubkey-hex>` reference, or a visible
        /// `npub` mention parsed from the message body. Lets a channel gate
        /// group replies on being addressed.
        #[serde(default)]
        mentions_self: bool,
        /// Bounded, privacy-aware snapshot of the replied-to message.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply_to: Option<AgentControlReferencedMessage>,
    },
    /// An accepted kind-1009 edit changed a prior message.
    MessageEdited {
        account_id_hex: String,
        group_id_hex: String,
        event_id_hex: String,
        target_message_id_hex: String,
        actor: AgentControlActor,
        replacement_text: String,
        recorded_at: u64,
        target: AgentControlReferencedMessage,
    },
    /// A previously-sent group message was deleted (kind-5) by another member.
    MessageDeleted {
        account_id_hex: String,
        group_id_hex: String,
        event_id_hex: String,
        target_message_id_hex: String,
        actor: AgentControlActor,
        recorded_at: u64,
        target: AgentControlReferencedMessage,
    },
    /// A kind-7 reaction was accepted for a message.
    ReactionAdded {
        account_id_hex: String,
        group_id_hex: String,
        event_id_hex: String,
        target_message_id_hex: String,
        actor: AgentControlActor,
        emoji: String,
        recorded_at: u64,
        target: AgentControlReferencedMessage,
    },
    /// A kind-5 deletion retracted a prior kind-7 reaction.
    ReactionRemoved {
        account_id_hex: String,
        group_id_hex: String,
        event_id_hex: String,
        reaction_event_id_hex: String,
        target_message_id_hex: String,
        actor: AgentControlActor,
        emoji: String,
        recorded_at: u64,
        target: AgentControlReferencedMessage,
    },
    /// A durable, MLS-authenticated change to group state was observed (a member
    /// add/remove/leave, an admin grant/revoke, a group rename/avatar change,
    /// or a disappearing-message timer change).
    /// Privacy: the subject member's pubkey is never surfaced — only a coarse
    /// `change` kind plus, for a rename, the new group display name in `detail`.
    GroupStateChanged {
        account_id_hex: String,
        group_id_hex: String,
        /// Coarse change kind: `"member_added"`, `"member_removed"`,
        /// `"member_left"`, `"admin_added"`, `"admin_removed"`,
        /// `"group_renamed"`, `"group_avatar_changed"`, or
        /// `"disappearing_timer_changed"`.
        change: String,
        /// The new group display name for `group_renamed`; `None` otherwise.
        /// Never carries a member pubkey.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    GroupInvite {
        account_id_hex: String,
        group_id_hex: String,
        via_welcome_message_id_hex: String,
        welcomer_account_id_hex: Option<String>,
    },
    StreamUpdate {
        account_id_hex: String,
        group_id_hex: String,
        stream_id_hex: String,
        status: String,
    },
    /// The connector's inbound broadcast lagged and dropped events before they could be
    /// delivered on this subscription. Dropped inbound messages are gone from the channel and
    /// will not be re-emitted, so the agent must re-query/re-sync state (e.g. via its own
    /// message history) to recover anything it missed. `dropped_events` is the number of
    /// broadcast slots that overflowed (not necessarily all inbound messages).
    ResyncRequired {
        account_id_hex: Option<String>,
        group_id_hex: Option<String>,
        dropped_events: u64,
    },
}

pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, AgentControlError> {
    let mut bytes = serde_json::to_vec(message)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, AgentControlError> {
    let frame = trim_line_ending(frame);
    if frame.is_empty() {
        return Err(AgentControlError::EmptyFrame);
    }
    if frame.len() > MAX_AGENT_CONTROL_FRAME_BYTES {
        return Err(AgentControlError::FrameTooLarge(frame.len()));
    }
    Ok(serde_json::from_slice(frame)?)
}

pub fn decode_envelope<T: DeserializeOwned>(
    frame: &[u8],
) -> Result<AgentControlEnvelope<T>, AgentControlError> {
    let envelope: AgentControlEnvelope<T> = decode_frame(frame)?;
    envelope.validate_protocol()?;
    Ok(envelope)
}

pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<(), AgentControlError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let frame = encode_frame(message)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, AgentControlError>
where
    R: AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    let mut frame = Vec::new();
    // Cap the read itself so a client that never sends a newline cannot make us
    // buffer unbounded memory before the size check runs. We allow one byte past
    // the limit so an over-cap frame is detectable (read_until on a Take adapter
    // stops silently at the limit instead of erroring).
    let limit = (MAX_AGENT_CONTROL_FRAME_BYTES + 1) as u64;
    let read = {
        let mut limited = (&mut *reader).take(limit);
        limited.read_until(b'\n', &mut frame).await?
    };
    if read == 0 {
        return Ok(None);
    }
    if frame.len() > MAX_AGENT_CONTROL_FRAME_BYTES {
        return Err(AgentControlError::FrameTooLarge(frame.len()));
    }
    decode_frame(&frame).map(Some)
}

pub async fn read_envelope<R, T>(
    reader: &mut R,
) -> Result<Option<AgentControlEnvelope<T>>, AgentControlError>
where
    R: AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    match read_frame(reader).await? {
        Some(envelope) => {
            let envelope: AgentControlEnvelope<T> = envelope;
            envelope.validate_protocol()?;
            Ok(Some(envelope))
        }
        None => Ok(None),
    }
}

fn trim_line_ending(frame: &[u8]) -> &[u8] {
    let frame = frame.strip_suffix(b"\n").unwrap_or(frame);
    frame.strip_suffix(b"\r").unwrap_or(frame)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use tokio::io::AsyncReadExt;
    use tokio::io::BufReader;

    use crate::{
        AgentControlEnvelope, AgentControlError, AgentControlEvent, AgentControlInvitePolicy,
        AgentControlMediaUpload, AgentControlProfileLookupStatus, AgentControlRequest,
        AgentControlResponse, AgentControlSendMaintenanceDisposition, AgentControlTimelineCursor,
        MAX_AGENT_CONTROL_FRAME_BYTES, decode_envelope, encode_frame, read_envelope, read_frame,
        write_frame,
    };

    #[test]
    fn invite_policy_accepts_cli_aliases_without_changing_canonical_wire_values() {
        assert_eq!(
            serde_json::from_str::<AgentControlInvitePolicy>("\"any-authenticated-direct\"")
                .unwrap(),
            AgentControlInvitePolicy::AnyAuthenticatedDirect
        );
        assert_eq!(
            serde_json::from_str::<AgentControlInvitePolicy>("\"any-authenticated\"").unwrap(),
            AgentControlInvitePolicy::AnyAuthenticated
        );
        assert_eq!(
            serde_json::to_string(&AgentControlInvitePolicy::AnyAuthenticatedDirect).unwrap(),
            "\"any_authenticated_direct\""
        );
    }

    #[test]
    fn rich_context_golden_events_decode_and_deleted_targets_are_redacted() {
        let fixture = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/agent-control-v2-rich-context.json"),
        )
        .unwrap();
        let events: Vec<AgentControlEvent> = serde_json::from_str(&fixture).unwrap();
        assert_eq!(events.len(), 8);
        let deleted = events
            .iter()
            .find_map(|event| match event {
                AgentControlEvent::MessageDeleted { target, .. } => Some(target),
                _ => None,
            })
            .expect("message_deleted fixture");
        assert_eq!(
            deleted.availability,
            crate::AgentControlReferencedMessageAvailability::Deleted
        );
        assert!(deleted.text_excerpt.is_none());
        assert!(deleted.attachments.is_empty());
    }

    #[test]
    fn stream_append_frame_round_trips_as_append_only_text() {
        let frame = AgentControlEnvelope::request(
            Some("req-1".to_owned()),
            AgentControlRequest::StreamAppend {
                stream_id_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                stream_capability: "11".repeat(32),
                append_text: "lo".to_owned(),
                idempotency_key: None,
            },
        );

        let encoded = encode_frame(&frame).unwrap();
        assert!(encoded.ends_with(b"\n"));
        let json: Value = serde_json::from_slice(&encoded[..encoded.len() - 1]).unwrap();
        assert_eq!(json["marmot_agent_control"], "marmot.agent-control.v2");
        assert_eq!(json["id"], "req-1");
        assert_eq!(json["type"], "stream_append");
        assert_eq!(json["append_text"], "lo");
        assert_eq!(json["stream_capability"], "11".repeat(32));
        assert!(json.get("text").is_none());
        assert!(json.get("replace_text").is_none());
        assert!(json.get("idempotency_key").is_none());

        let decoded: AgentControlEnvelope<AgentControlRequest> = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn stream_preview_idempotency_key_is_optional_and_round_trips() {
        let request: AgentControlRequest = serde_json::from_value(serde_json::json!({
            "type": "stream_progress",
            "stream_id_hex": "aa",
            "stream_capability": "bb",
            "text": "working",
            "idempotency_key": "operation-1"
        }))
        .unwrap();
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["idempotency_key"], "operation-1");
    }

    #[test]
    fn envelope_auth_token_round_trips_when_present() {
        let frame = AgentControlEnvelope::request(
            Some("req-auth".to_owned()),
            AgentControlRequest::AccountList,
        )
        .with_auth_token("test-token");

        let encoded = encode_frame(&frame).unwrap();
        let json: Value = serde_json::from_slice(&encoded[..encoded.len() - 1]).unwrap();
        assert_eq!(json["auth_token"], "test-token");

        let decoded: AgentControlEnvelope<AgentControlRequest> = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn stream_begin_parent_message_id_is_optional_and_round_trips_when_present() {
        let without = AgentControlRequest::StreamBegin {
            account_id_hex: "aa".repeat(32),
            group_id_hex: "cc".repeat(32),
            stream_id_hex: None,
            parent_message_id_hex: None,
            quic_candidates: vec!["quic://broker.example:4450".to_owned()],
        };
        let value = serde_json::to_value(&without).unwrap();
        assert!(
            value.get("parent_message_id_hex").is_none(),
            "absent parent must not be serialized"
        );
        let decoded: AgentControlRequest = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, without);

        let with = AgentControlRequest::StreamBegin {
            account_id_hex: "aa".repeat(32),
            group_id_hex: "cc".repeat(32),
            stream_id_hex: Some("55".repeat(32)),
            parent_message_id_hex: Some("dd".repeat(32)),
            quic_candidates: vec!["quic://broker.example:4450".to_owned()],
        };
        let value = serde_json::to_value(&with).unwrap();
        assert_eq!(value["parent_message_id_hex"], "dd".repeat(32));
        let decoded: AgentControlRequest = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, with);
    }

    #[test]
    fn reaction_requests_have_stable_wire_shapes() {
        let send = AgentControlRequest::SendReaction {
            account_id_hex: account(),
            group_id_hex: group(),
            target_message_id_hex: message(),
            emoji: "👀".to_owned(),
        };
        let value = serde_json::to_value(&send).unwrap();
        assert_eq!(value["type"], "send_reaction");
        assert_eq!(value["emoji"], "👀");
        assert_eq!(value["target_message_id_hex"], message());
        assert_eq!(
            serde_json::from_value::<AgentControlRequest>(value).unwrap(),
            send
        );

        let remove = AgentControlRequest::RemoveReaction {
            account_id_hex: account(),
            group_id_hex: group(),
            target_message_id_hex: message(),
            emoji: None,
        };
        let value = serde_json::to_value(&remove).unwrap();
        assert_eq!(value["type"], "remove_reaction");
        assert!(value.get("emoji").is_none());
        assert_eq!(
            serde_json::from_value::<AgentControlRequest>(value).unwrap(),
            remove
        );

        let matching_remove = AgentControlRequest::RemoveReaction {
            account_id_hex: account(),
            group_id_hex: group(),
            target_message_id_hex: message(),
            emoji: Some("👀".to_owned()),
        };
        let value = serde_json::to_value(&matching_remove).unwrap();
        assert_eq!(value["emoji"], "👀");
        assert_eq!(
            serde_json::from_value::<AgentControlRequest>(value).unwrap(),
            matching_remove
        );
    }

    #[test]
    fn send_final_idempotency_key_is_omitted_when_absent_and_present_when_set() {
        // Optional field: omitted from the wire when None; present and
        // round-tripping when
        // a client supplies it for dedup.
        let without = AgentControlRequest::SendFinal {
            account_id_hex: "aa".repeat(32),
            group_id_hex: "cc".repeat(32),
            text: "done".to_owned(),
            reply_to_message_id_hex: None,
            idempotency_key: None,
        };
        let value = serde_json::to_value(&without).unwrap();
        assert!(
            value.get("idempotency_key").is_none(),
            "absent key must not be serialized"
        );

        let with = AgentControlRequest::SendFinal {
            account_id_hex: "aa".repeat(32),
            group_id_hex: "cc".repeat(32),
            text: "done".to_owned(),
            reply_to_message_id_hex: None,
            idempotency_key: Some("key-1".to_owned()),
        };
        let value = serde_json::to_value(&with).unwrap();
        assert_eq!(value["idempotency_key"], "key-1");
        let round_tripped: AgentControlRequest = serde_json::from_value(value).unwrap();
        assert_eq!(round_tripped, with);
    }

    #[test]
    fn send_media_idempotency_key_is_omitted_when_absent_and_present_when_set() {
        let upload = || AgentControlMediaUpload {
            path: "/tmp/a.png".to_owned(),
            media_type: "image/png".to_owned(),
            file_name: "a.png".to_owned(),
            dim: None,
            thumbhash: None,
        };
        let without = AgentControlRequest::SendMedia {
            account_id_hex: "aa".repeat(32),
            group_id_hex: "cc".repeat(32),
            attachments: vec![upload()],
            caption: Some("look".to_owned()),
            idempotency_key: None,
        };
        let value = serde_json::to_value(&without).unwrap();
        assert!(value.get("idempotency_key").is_none());

        let with = AgentControlRequest::SendMedia {
            account_id_hex: "aa".repeat(32),
            group_id_hex: "cc".repeat(32),
            attachments: vec![upload()],
            caption: Some("look".to_owned()),
            idempotency_key: Some("media-key-1".to_owned()),
        };
        let value = serde_json::to_value(&with).unwrap();
        assert_eq!(value["idempotency_key"], "media-key-1");
        let round_tripped: AgentControlRequest = serde_json::from_value(value).unwrap();
        assert_eq!(round_tripped, with);
    }

    #[test]
    fn successful_send_response_carries_machine_readable_maintenance_disposition() {
        let response = AgentControlResponse::FinalSent {
            message_ids_hex: vec![message()],
            maintenance_disposition:
                AgentControlSendMaintenanceDisposition::PostJoinRotationPendingRetryable,
        };
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["type"], "final_sent");
        assert_eq!(
            value["maintenance_disposition"],
            "post_join_rotation_pending_retryable"
        );
        assert_eq!(
            serde_json::from_value::<AgentControlResponse>(value).unwrap(),
            response
        );
    }

    #[test]
    fn stream_finalize_idempotency_key_is_omitted_when_absent_and_present_when_set() {
        // Same additive contract as send_final: old peers see the same frame
        // when the key is absent, while newer clients can opt into dedup.
        let without = AgentControlRequest::StreamFinalize {
            stream_id_hex: "55".repeat(32),
            stream_capability: "66".repeat(32),
            final_text: "done".to_owned(),
            transcript_hash_hex: "ab".repeat(32),
            chunk_count: 1,
            idempotency_key: None,
        };
        let value = serde_json::to_value(&without).unwrap();
        assert!(
            value.get("idempotency_key").is_none(),
            "absent key must not be serialized"
        );

        let with = AgentControlRequest::StreamFinalize {
            stream_id_hex: "55".repeat(32),
            stream_capability: "66".repeat(32),
            final_text: "done".to_owned(),
            transcript_hash_hex: "ab".repeat(32),
            chunk_count: 1,
            idempotency_key: Some("stream-key-1".to_owned()),
        };
        let value = serde_json::to_value(&with).unwrap();
        assert_eq!(value["idempotency_key"], "stream-key-1");
        let round_tripped: AgentControlRequest = serde_json::from_value(value).unwrap();
        assert_eq!(round_tripped, with);
    }

    #[test]
    fn stream_begun_response_carries_policy_plaintext_cap_when_present() {
        let begun = AgentControlResponse::StreamBegun {
            stream_id_hex: "aa".repeat(32),
            stream_capability: "cc".repeat(32),
            start_message_id_hex: "bb".repeat(32),
            quic_candidates: vec!["quic://127.0.0.1:4433".to_owned()],
            policy_max_plaintext_frame_len: Some(4),
        };

        let value = serde_json::to_value(&begun).unwrap();
        assert_eq!(value["type"], "stream_begun");
        assert_eq!(value["policy_max_plaintext_frame_len"], 4);

        let round_tripped: AgentControlResponse = serde_json::from_value(value).unwrap();
        assert_eq!(round_tripped, begun);
    }

    #[test]
    fn group_state_changed_event_round_trips_with_optional_detail() {
        let renamed = AgentControlEvent::GroupStateChanged {
            account_id_hex: "aa".repeat(32),
            group_id_hex: "cc".repeat(32),
            change: "group_renamed".to_owned(),
            detail: Some("Team".to_owned()),
        };
        let value = serde_json::to_value(&renamed).unwrap();
        assert_eq!(value["type"], "group_state_changed");
        assert_eq!(value["change"], "group_renamed");
        assert_eq!(value["detail"], "Team");
        let back: AgentControlEvent = serde_json::from_value(value).unwrap();
        assert_eq!(back, renamed);

        let member_added = AgentControlEvent::GroupStateChanged {
            account_id_hex: "aa".repeat(32),
            group_id_hex: "cc".repeat(32),
            change: "member_added".to_owned(),
            detail: None,
        };
        let value = serde_json::to_value(&member_added).unwrap();
        assert!(
            value.get("detail").is_none(),
            "no member detail must be surfaced"
        );
        let back: AgentControlEvent = serde_json::from_value(value).unwrap();
        assert_eq!(back, member_added);
    }

    #[tokio::test]
    async fn async_frame_helpers_exchange_typed_requests_and_responses() {
        let (client, server) = tokio::io::duplex(4096);
        let (client_read, mut client_write) = tokio::io::split(client);
        let (server_read, mut server_write) = tokio::io::split(server);
        let mut client_read = BufReader::new(client_read);
        let mut server_read = BufReader::new(server_read);

        let request = AgentControlEnvelope::request(
            Some("req-2".to_owned()),
            AgentControlRequest::AccountList,
        );
        write_frame(&mut client_write, &request).await.unwrap();
        let received: AgentControlEnvelope<AgentControlRequest> =
            read_envelope(&mut server_read).await.unwrap().unwrap();
        assert_eq!(received, request);

        let response =
            AgentControlEnvelope::new(Some("req-2".to_owned()), AgentControlResponse::Ack);
        write_frame(&mut server_write, &response).await.unwrap();
        let received: AgentControlEnvelope<AgentControlResponse> =
            read_envelope(&mut client_read).await.unwrap().unwrap();
        assert_eq!(received, response);
    }

    #[tokio::test]
    async fn write_frame_emits_one_json_line() {
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let request = AgentControlEnvelope::request(
            Some("req-single-frame".to_owned()),
            AgentControlRequest::AccountList,
        );

        write_frame(&mut writer, &request).await.unwrap();
        drop(writer);

        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        let lines = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "write_frame should emit exactly one frame");
        let decoded: AgentControlEnvelope<AgentControlRequest> = decode_envelope(&bytes).unwrap();
        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_frame_without_buffering_unbounded() {
        // A client that streams data without a trailing newline must not be able
        // to make read_frame buffer past the cap. The read-side `.take()` adapter
        // stops at MAX + 1 bytes, so the post-read size check fires deterministically
        // instead of letting allocation grow unbounded (pre-auth OOM, mdk#212).
        let oversize = MAX_AGENT_CONTROL_FRAME_BYTES + 4096;
        let payload = vec![b'a'; oversize]; // no newline, intentionally over the cap
        let mut reader = BufReader::new(std::io::Cursor::new(payload));

        let result: Result<Option<AgentControlEnvelope<AgentControlRequest>>, _> =
            read_envelope(&mut reader).await;
        match result {
            Err(AgentControlError::FrameTooLarge(len)) => {
                // We buffer at most one byte past the cap, never the full payload.
                assert_eq!(len, MAX_AGENT_CONTROL_FRAME_BYTES + 1);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_frame_accepts_frame_at_the_cap_boundary() {
        // A frame whose encoded line is exactly MAX_AGENT_CONTROL_FRAME_BYTES
        // (including its trailing newline) must still round-trip; the read-side
        // limit allows one byte past the cap precisely so a legal max-size frame
        // is not truncated. We pad `append_text` with ASCII bytes (which serde
        // serializes 1:1 with no escaping) so we can hit the cap to the byte.
        let make = |append_text: String| {
            AgentControlEnvelope::request(
                Some("req-boundary".to_owned()),
                AgentControlRequest::StreamAppend {
                    stream_id_hex:
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_owned(),
                    stream_capability: capability(),
                    append_text,
                    idempotency_key: None,
                },
            )
        };
        // Measure the frame size with an empty body, then pad the body so the
        // total encoded length (JSON + trailing newline) is exactly the cap.
        let base_len = encode_frame(&make(String::new())).unwrap().len();
        assert!(base_len < MAX_AGENT_CONTROL_FRAME_BYTES);
        let padding = MAX_AGENT_CONTROL_FRAME_BYTES - base_len;
        let request = make("a".repeat(padding));

        let mut encoded = encode_frame(&request).unwrap();
        assert!(encoded.ends_with(b"\n"));
        assert_eq!(
            encoded.len(),
            MAX_AGENT_CONTROL_FRAME_BYTES,
            "boundary frame must encode to exactly the cap"
        );
        // Append a following frame's bytes to prove read_frame stops at the first
        // newline and does not over-read past the cap into trailing data.
        encoded.extend_from_slice(b"trailing");
        let mut reader = BufReader::new(std::io::Cursor::new(encoded));

        let received: AgentControlEnvelope<AgentControlRequest> =
            read_envelope(&mut reader).await.unwrap().unwrap();
        assert_eq!(received, request);
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_empty_stream() {
        let mut reader = BufReader::new(std::io::Cursor::new(Vec::<u8>::new()));
        let result: Option<AgentControlEnvelope<AgentControlRequest>> =
            read_frame(&mut reader).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn all_initial_request_variants_have_stable_type_names() {
        let requests = vec![
            (
                AgentControlRequest::SubscribeInbound {
                    account_id_hex: None,
                    group_id_hex: None,
                },
                "subscribe_inbound",
            ),
            (
                AgentControlRequest::TimelineMessageGet {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    message_id_hex: message(),
                },
                "timeline_message_get",
            ),
            (
                AgentControlRequest::TimelineList {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    before: Some(AgentControlTimelineCursor {
                        recorded_at: 42,
                        message_id_hex: message(),
                    }),
                    after: None,
                    before_inclusive: false,
                    limit: Some(20),
                },
                "timeline_list",
            ),
            (
                AgentControlRequest::SendFinal {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    text: "done".to_owned(),
                    reply_to_message_id_hex: None,
                    idempotency_key: None,
                },
                "send_final",
            ),
            (
                AgentControlRequest::DeleteMessage {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    target_message_id_hex: message(),
                },
                "delete_message",
            ),
            (
                AgentControlRequest::SendReaction {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    target_message_id_hex: message(),
                    emoji: "👀".to_owned(),
                },
                "send_reaction",
            ),
            (
                AgentControlRequest::RemoveReaction {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    target_message_id_hex: message(),
                    emoji: None,
                },
                "remove_reaction",
            ),
            (
                AgentControlRequest::StreamBegin {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    stream_id_hex: None,
                    parent_message_id_hex: None,
                    quic_candidates: vec!["quic://127.0.0.1:4450".to_owned()],
                },
                "stream_begin",
            ),
            (
                AgentControlRequest::StreamAppend {
                    stream_id_hex: stream(),
                    stream_capability: capability(),
                    append_text: "hel".to_owned(),
                    idempotency_key: None,
                },
                "stream_append",
            ),
            (
                AgentControlRequest::StreamStatus {
                    stream_id_hex: stream(),
                    stream_capability: capability(),
                    status: "thinking".to_owned(),
                    idempotency_key: None,
                },
                "stream_status",
            ),
            (
                AgentControlRequest::StreamProgress {
                    stream_id_hex: stream(),
                    stream_capability: capability(),
                    text: "{\"v\":1,\"status\":\"started\"}".to_owned(),
                    idempotency_key: None,
                },
                "stream_progress",
            ),
            (
                AgentControlRequest::StreamFinalize {
                    stream_id_hex: stream(),
                    stream_capability: capability(),
                    final_text: "hello".to_owned(),
                    transcript_hash_hex: hash(),
                    chunk_count: 1,
                    idempotency_key: Some("stream-final-1".to_owned()),
                },
                "stream_finalize",
            ),
            (
                AgentControlRequest::StreamCancel {
                    stream_id_hex: stream(),
                    stream_capability: capability(),
                    reason: Some("gateway_replaced_text".to_owned()),
                },
                "stream_cancel",
            ),
            (AgentControlRequest::AccountList, "account_list"),
            (
                AgentControlRequest::AccountCreate {
                    label: Some("agent".to_owned()),
                    publish_key_package: true,
                },
                "account_create",
            ),
            (
                AgentControlRequest::AccountPublishKeyPackage {
                    account_id_hex: account(),
                },
                "account_publish_key_package",
            ),
            (
                AgentControlRequest::AccountPublishProfile {
                    account_id_hex: account(),
                    name: "agent".to_owned(),
                    display_name: Some("Agent".to_owned()),
                },
                "account_publish_profile",
            ),
            (
                AgentControlRequest::AccountProfileLookup {
                    account_id_hex: account(),
                },
                "account_profile_lookup",
            ),
            (
                AgentControlRequest::SendAgentActivity {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    status: "thinking".to_owned(),
                    text: "Thinking".to_owned(),
                    reply_to_message_id_hex: Some(message()),
                    extra: None,
                },
                "send_agent_activity",
            ),
            (
                AgentControlRequest::SendAgentOperationEvent {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    event_type: "tool_call".to_owned(),
                    status: "started".to_owned(),
                    operation_id: Some("call-1".to_owned()),
                    run_id: Some("run-1".to_owned()),
                    turn_id: Some("turn-1".to_owned()),
                    name: Some("search".to_owned()),
                    text: "Searching".to_owned(),
                    preview: Some("query".to_owned()),
                    details: None,
                    sequence: Some(1),
                    ok: None,
                    duration_ms: None,
                    reply_to_message_id_hex: Some(message()),
                },
                "send_agent_operation_event",
            ),
            (
                AgentControlRequest::SendGroupSystemEvent {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    system_type: "member_added".to_owned(),
                    text: "Member added".to_owned(),
                    data: None,
                },
                "send_group_system_event",
            ),
            (
                AgentControlRequest::GroupInfo {
                    account_id_hex: account(),
                    group_id_hex: group(),
                },
                "group_info",
            ),
            (
                AgentControlRequest::MaintenanceStatus {
                    account_id_hex: account(),
                    group_id_hex: group(),
                },
                "maintenance_status",
            ),
            (
                AgentControlRequest::KeyPackageMaintenanceStatus {
                    account_id_hex: account(),
                },
                "key_package_maintenance_status",
            ),
            (
                AgentControlRequest::MaintenanceScheduleSelfUpdate {
                    account_id_hex: account(),
                    group_id_hex: group(),
                },
                "maintenance_schedule_self_update",
            ),
            (
                AgentControlRequest::MaintenanceGetPolicy {
                    account_id_hex: account(),
                },
                "maintenance_get_policy",
            ),
            (
                AgentControlRequest::MaintenanceSetPolicy {
                    account_id_hex: account(),
                    enabled_for_new_groups: true,
                },
                "maintenance_set_policy",
            ),
            (
                AgentControlRequest::MaintenancePause {
                    account_id_hex: account(),
                },
                "maintenance_pause",
            ),
            (
                AgentControlRequest::MaintenanceResume {
                    account_id_hex: account(),
                },
                "maintenance_resume",
            ),
            (
                AgentControlRequest::MaintenanceRun {
                    account_id_hex: account(),
                },
                "maintenance_run",
            ),
            (
                AgentControlRequest::AllowlistList {
                    account_id_hex: account(),
                },
                "allowlist_list",
            ),
            (
                AgentControlRequest::AllowlistAdd {
                    account_id_hex: account(),
                    welcomer_account_id_hex: welcomer(),
                },
                "allowlist_add",
            ),
            (
                AgentControlRequest::AllowlistRemove {
                    account_id_hex: account(),
                    welcomer_account_id_hex: welcomer(),
                },
                "allowlist_remove",
            ),
            (
                AgentControlRequest::InvitePolicyGet {
                    account_id_hex: account(),
                },
                "invite_policy_get",
            ),
            (
                AgentControlRequest::InvitePolicySet {
                    account_id_hex: account(),
                    policy: crate::AgentControlInvitePolicy::AnyAuthenticatedDirect,
                },
                "invite_policy_set",
            ),
            (
                AgentControlRequest::DebugInjectInbound {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    message_id_hex: message(),
                    sender_account_id_hex: welcomer(),
                    text: "hello agent".to_owned(),
                },
                "debug_inject_inbound",
            ),
            (
                AgentControlRequest::DebugRecordedFinals,
                "debug_recorded_finals",
            ),
            (
                AgentControlRequest::SendMedia {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    attachments: vec![crate::AgentControlMediaUpload {
                        path: "/tmp/a.png".to_owned(),
                        media_type: "image/png".to_owned(),
                        file_name: "a.png".to_owned(),
                        dim: Some("16x16".to_owned()),
                        thumbhash: None,
                    }],
                    caption: Some("look".to_owned()),
                    idempotency_key: None,
                },
                "send_media",
            ),
            (
                AgentControlRequest::DownloadMedia {
                    account_id_hex: account(),
                    group_id_hex: group(),
                    media: crate::AgentControlMediaRef {
                        media_type: "image/png".to_owned(),
                        file_name: "a.png".to_owned(),
                        ciphertext_sha256: hash(),
                        plaintext_sha256: hash(),
                        nonce_hex: "0".repeat(24),
                        version: "marmot.encrypted-media.v1".to_owned(),
                        source_epoch: 0,
                        locators: vec![crate::AgentControlMediaLocator {
                            kind: "blossom-v1".to_owned(),
                            value: "https://example.invalid/a".to_owned(),
                        }],
                        dim: None,
                        thumbhash: None,
                    },
                },
                "download_media",
            ),
        ];

        for (request, expected_type) in requests {
            let value = serde_json::to_value(request).unwrap();
            assert_eq!(value["type"], expected_type);
        }
    }

    #[test]
    fn account_profile_lookup_has_typed_found_absent_and_indeterminate_outcomes() {
        let request = AgentControlRequest::AccountProfileLookup {
            account_id_hex: account(),
        };
        let request_json = serde_json::to_value(&request).unwrap();
        assert_eq!(request_json["type"], "account_profile_lookup");
        assert_eq!(request_json["account_id_hex"], account());

        for (status, retryable) in [
            (AgentControlProfileLookupStatus::ProfileFound, false),
            (AgentControlProfileLookupStatus::ProfileNotFound, false),
            (AgentControlProfileLookupStatus::Indeterminate, true),
        ] {
            let response = AgentControlResponse::ProfileLookup {
                account_id_hex: account(),
                status,
                retryable,
            };
            let value = serde_json::to_value(&response).unwrap();
            assert_eq!(value["type"], "profile_lookup");
            assert_eq!(value["account_id_hex"], account());
            assert_eq!(value["retryable"], retryable);
            let round_tripped: AgentControlResponse = serde_json::from_value(value).unwrap();
            assert_eq!(round_tripped, response);
        }
    }

    fn account() -> String {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
    }

    fn welcomer() -> String {
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
    }

    fn group() -> String {
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned()
    }

    fn stream() -> String {
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned()
    }

    fn capability() -> String {
        "6666666666666666666666666666666666666666666666666666666666666666".to_owned()
    }

    fn message() -> String {
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned()
    }

    fn hash() -> String {
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned()
    }
}
