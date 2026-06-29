//! Stringification + extraction helpers for the forensic audit log.
//!
//! Kept in one place so audit-event variants stay consistent across call
//! sites. These produce stable, low-cardinality strings that an analyzer
//! can group on.

use cgka_traits::app_components::{
    GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_MESSAGE_RETENTION_COMPONENT_ID,
    GROUP_PROFILE_COMPONENT_ID,
};
use cgka_traits::engine::{GroupStateChange, SendIntent, SendResult};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use cgka_traits::message::MessageState;
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, MemberId, MessageId};
use marmot_forensics::{
    AttachmentMetadata, AuditEventKind, ConvergenceAppWitness, ConvergenceCandidate,
    ConvergenceRuleEvaluation, ConvergenceScore, DecodedApplicationEvent, DecodedPayload,
    DigestHex, MemberRefHex, MembershipChangeSource, MessageArtifactKind, MessageAuthor,
    MessageRefHex, OutboundMessage,
};
use sha2::{Digest, Sha256};

use crate::convergence::{
    AppWitness, BranchScore, BranchSelectionTrace, CandidateEvaluation, RuleEvaluation,
    tip_priority_str,
};
use crate::epoch_manager::PendingKind;
use openmls::prelude::Proposal;

pub(crate) fn pending_kind_str(kind: PendingKind) -> &'static str {
    match kind {
        PendingKind::CreateGroup => "create_group",
        PendingKind::GroupEvolution => "group_evolution",
    }
}

pub(crate) fn proposal_kind_str(proposal: &Proposal) -> &'static str {
    match proposal {
        Proposal::Add(_) => "add",
        Proposal::Update(_) => "update",
        Proposal::Remove(_) => "remove",
        Proposal::PreSharedKey(_) => "pre_shared_key",
        Proposal::ReInit(_) => "re_init",
        Proposal::ExternalInit(_) => "external_init",
        Proposal::GroupContextExtensions(_) => "group_context_extensions",
        Proposal::SelfRemove => "self_remove",
        Proposal::AppEphemeral(_) => "app_ephemeral",
        Proposal::AppDataUpdate(_) => "app_data_update",
        Proposal::Custom(_) => "custom",
    }
}

pub(crate) fn envelope_kind_str(env: &TransportEnvelope) -> &'static str {
    match env {
        TransportEnvelope::Welcome { .. } => "welcome",
        TransportEnvelope::GroupMessage { .. } => "group_message",
    }
}

pub(crate) fn ingest_outcome_kind_str(outcome: &IngestOutcome) -> &'static str {
    match outcome {
        IngestOutcome::Processed => "processed",
        IngestOutcome::Buffered { .. } => "buffered",
        IngestOutcome::Stale { .. } => "stale",
    }
}

pub(crate) fn stale_reason_str(reason: &StaleReason) -> &'static str {
    match reason {
        StaleReason::AlreadySeen => "already_seen",
        StaleReason::AlreadyAtEpoch { .. } => "already_at_epoch",
        StaleReason::NotForThisClient => "not_for_this_client",
        StaleReason::UnknownGroup => "unknown_group",
        StaleReason::OwnEcho => "own_echo",
        StaleReason::PeelFailed => "peel_failed",
    }
}

pub(crate) fn ingest_outcome_epoch(outcome: &IngestOutcome) -> Option<u64> {
    match outcome {
        IngestOutcome::Buffered { epoch, .. } => Some(epoch.0),
        IngestOutcome::Stale {
            reason: StaleReason::AlreadyAtEpoch { current, .. },
        } => Some(current.0),
        _ => None,
    }
}

pub(crate) fn ingest_outcome_group_ref(outcome: &IngestOutcome) -> Option<String> {
    match outcome {
        IngestOutcome::Buffered { group_id, .. } => Some(hex::encode(group_id.as_slice())),
        _ => None,
    }
}

pub(crate) fn send_intent_kind_str(intent: &SendIntent) -> &'static str {
    match intent {
        SendIntent::AppMessage { .. } => "app_message",
        SendIntent::Invite { .. } => "invite",
        SendIntent::RemoveMembers { .. } => "remove_members",
        SendIntent::Leave { .. } => "leave",
        SendIntent::UpdateAppComponents { .. } => "update_app_components",
        SendIntent::UpdateGroupData { .. } => "update_group_data",
    }
}

pub(crate) fn send_intent_group_ref(intent: &SendIntent) -> Option<String> {
    Some(hex::encode(send_intent_group_id(intent).as_slice()))
}

/// The group a send intent targets. Every `SendIntent` variant is group-scoped.
pub(crate) fn send_intent_group_id(intent: &SendIntent) -> cgka_traits::GroupId {
    match intent {
        SendIntent::AppMessage { group_id, .. }
        | SendIntent::Invite { group_id, .. }
        | SendIntent::RemoveMembers { group_id, .. }
        | SendIntent::Leave { group_id }
        | SendIntent::UpdateAppComponents { group_id, .. }
        | SendIntent::UpdateGroupData { group_id, .. } => group_id.clone(),
    }
}

pub(crate) fn send_result_kind_str(result: &SendResult) -> &'static str {
    match result {
        SendResult::ApplicationMessage { .. } => "application_message",
        SendResult::Queued { .. } => "queued",
        SendResult::Proposal { .. } => "proposal",
        SendResult::GroupEvolution { .. } => "group_evolution",
        SendResult::GroupCreated { .. } => "group_created",
    }
}

pub(crate) fn message_state_str(state: MessageState) -> &'static str {
    match state {
        MessageState::Sent => "sent",
        MessageState::Created => "created",
        MessageState::Processed => "processed",
        MessageState::Failed => "failed",
        MessageState::Retryable => "retryable",
        MessageState::PeelDeferred => "peel_deferred",
        MessageState::EpochInvalidated => "epoch_invalidated",
    }
}

pub(crate) fn epoch_state_name_str(name: &str) -> &'static str {
    match name {
        "Stable" => "stable",
        "PendingPublish" => "pending_publish",
        "Merging" => "merging",
        "Recovering" => "recovering",
        "Unrecoverable" => "unrecoverable",
        _ => "unknown",
    }
}

pub(crate) fn member_ref_hex(member: &MemberId) -> MemberRefHex {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-audit-member-ref/v1");
    hasher.update(member.as_slice());
    hex::encode(&hasher.finalize()[..16])
}

fn value_digest_hex(change_kind: &str, value: &[u8]) -> DigestHex {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-audit-group-state-value/v1");
    hasher.update(change_kind.as_bytes());
    hasher.update(value);
    hex::encode(hasher.finalize())
}

pub(crate) fn group_state_change_kind_str(change: &GroupStateChange) -> &'static str {
    match change {
        GroupStateChange::MemberAdded { .. } => "member_added",
        GroupStateChange::MemberRemoved { .. } => "member_removed",
        GroupStateChange::MemberLeft { .. } => "member_left",
        GroupStateChange::AdminAdded { .. } => "admin_added",
        GroupStateChange::AdminRemoved { .. } => "admin_removed",
        GroupStateChange::GroupRenamed { .. } => "group_renamed",
        GroupStateChange::GroupAvatarChanged => "group_avatar_changed",
        GroupStateChange::MessageRetentionChanged { .. } => "message_retention_changed",
    }
}

fn group_state_change_fields(change: &GroupStateChange) -> Vec<String> {
    let fields: &[&str] = match change {
        GroupStateChange::MemberAdded { .. } | GroupStateChange::MemberRemoved { .. } => {
            &["members"]
        }
        GroupStateChange::MemberLeft { .. } => &["membership"],
        GroupStateChange::AdminAdded { .. } | GroupStateChange::AdminRemoved { .. } => &["admins"],
        GroupStateChange::GroupRenamed { .. } => &["name"],
        GroupStateChange::GroupAvatarChanged => &["avatar"],
        GroupStateChange::MessageRetentionChanged { .. } => &["message_retention"],
    };
    fields.iter().map(|field| (*field).to_string()).collect()
}

fn group_state_change_component_ids(change: &GroupStateChange) -> Vec<u16> {
    match change {
        GroupStateChange::AdminAdded { .. } | GroupStateChange::AdminRemoved { .. } => {
            vec![GROUP_ADMIN_POLICY_COMPONENT_ID]
        }
        GroupStateChange::GroupRenamed { .. } => vec![GROUP_PROFILE_COMPONENT_ID],
        GroupStateChange::GroupAvatarChanged => vec![
            GROUP_AVATAR_URL_COMPONENT_ID,
            GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
        ],
        GroupStateChange::MessageRetentionChanged { .. } => {
            vec![GROUP_MESSAGE_RETENTION_COMPONENT_ID]
        }
        GroupStateChange::MemberAdded { .. }
        | GroupStateChange::MemberRemoved { .. }
        | GroupStateChange::MemberLeft { .. } => Vec::new(),
    }
}

fn group_state_subject_member(change: &GroupStateChange) -> Option<&MemberId> {
    match change {
        GroupStateChange::MemberAdded { member }
        | GroupStateChange::MemberRemoved { member }
        | GroupStateChange::MemberLeft { member }
        | GroupStateChange::AdminAdded { member }
        | GroupStateChange::AdminRemoved { member } => Some(member),
        GroupStateChange::GroupRenamed { .. }
        | GroupStateChange::GroupAvatarChanged
        | GroupStateChange::MessageRetentionChanged { .. } => None,
    }
}

/// Full member pubkey hex for `full_data` mode only. A `MemberId` in this engine
/// is the 32-byte account identity; non-32-byte ids (test fixtures) are skipped
/// so the output always matches the schema's pubkey pattern.
fn member_pubkey_hex(member: &MemberId, full_data: bool) -> Option<String> {
    (full_data && member.as_slice().len() == 32).then(|| hex::encode(member.as_slice()))
}

pub(crate) fn group_state_changed_event(
    epoch: EpochId,
    actor: Option<&MemberId>,
    change: &GroupStateChange,
    origin_commit_id: Option<&MessageId>,
    full_data: bool,
) -> AuditEventKind {
    let change_kind = group_state_change_kind_str(change);
    // Always carry digest+len; the cleartext value (text/json) is full-data only.
    let value = match change {
        GroupStateChange::GroupRenamed { name, .. } => Some(marmot_forensics::GroupStateValue {
            digest: Some(value_digest_hex(change_kind, name.as_bytes())),
            len: Some(name.len() as u64),
            text: full_data.then(|| name.clone()),
            json: None,
            pubkeys_hex: Vec::new(),
        }),
        GroupStateChange::MessageRetentionChanged { new_seconds, .. } => {
            Some(marmot_forensics::GroupStateValue {
                digest: Some(value_digest_hex(change_kind, &new_seconds.to_be_bytes())),
                len: Some(new_seconds.to_be_bytes().len() as u64),
                text: None,
                json: full_data.then(|| serde_json::json!(new_seconds)),
                pubkeys_hex: Vec::new(),
            })
        }
        _ => None,
    };
    let subject = group_state_subject_member(change);
    // Attribute membership changes: a self-leave, an admin action (an actor is
    // present), or — for a removal with no attributable actor — a
    // convergence-resolved departure. Non-membership changes carry no source.
    let membership_change_source = match change {
        GroupStateChange::MemberLeft { .. } => Some(MembershipChangeSource::SelfLeave),
        GroupStateChange::MemberRemoved { .. } => Some(if actor.is_some() {
            MembershipChangeSource::AdminAction
        } else {
            MembershipChangeSource::Convergence
        }),
        GroupStateChange::MemberAdded { .. } => Some(if actor.is_some() {
            MembershipChangeSource::AdminAction
        } else {
            MembershipChangeSource::RemoteCommit
        }),
        _ => None,
    };
    AuditEventKind::GroupStateChanged {
        epoch: epoch.0,
        change_kind: change_kind.to_string(),
        membership_change_source,
        actor_member_ref: actor.map(member_ref_hex),
        actor_pubkey_hex: actor.and_then(|actor| member_pubkey_hex(actor, full_data)),
        subject_member_ref: subject.map(member_ref_hex),
        subject_pubkey_hex: subject.and_then(|subject| member_pubkey_hex(subject, full_data)),
        origin_commit_id: origin_commit_id.map(|id| hex::encode(id.as_slice())),
        fields: group_state_change_fields(change),
        component_ids: group_state_change_component_ids(change),
        value,
    }
}

pub(crate) fn epoch_state_changed_event(
    previous_state: Option<&str>,
    new_state: &str,
    epoch: EpochId,
    reason: &str,
    pending_ref: Option<PendingStateRef>,
    pending_kind: Option<&str>,
) -> AuditEventKind {
    AuditEventKind::EpochStateChanged {
        previous_state: previous_state.map(str::to_string),
        new_state: new_state.to_string(),
        epoch: epoch.0,
        reason: reason.to_string(),
        pending_ref: pending_ref.map(PendingStateRef::as_u64),
        pending_kind: pending_kind.map(str::to_string),
    }
}

/// Build a `TransportReceived` event from an inbound transport message and the
/// wire envelope captured by the transport layer. Emitted before `IngestEntry`
/// so the wire identifiers are recorded ahead of engine ingest. The payload
/// length and digest match `ingest_entry_event` for the same message.
pub(crate) fn transport_received_event(
    msg: &TransportMessage,
    wire: marmot_forensics::AuditTransportWire,
) -> AuditEventKind {
    AuditEventKind::TransportReceived {
        msg_id: Some(hex::encode(msg.id.as_slice())),
        transport: wire,
        payload_len: msg.payload.len() as u64,
        payload_digest: hex::encode(Sha256::digest(&msg.payload)) as DigestHex,
    }
}

/// Parse NIP-94-style `imeta` tags into attachment descriptors. Only non-secret
/// metadata (mime, size, sha-256 digest, name) is captured — never bytes or keys.
fn parse_imeta_attachments(tags: &[Vec<String>]) -> Vec<AttachmentMetadata> {
    tags.iter()
        .filter(|tag| tag.first().map(|name| name == "imeta").unwrap_or(false))
        .map(|tag| {
            let mut attachment = AttachmentMetadata::default();
            for field in &tag[1..] {
                let mut parts = field.splitn(2, ' ');
                let (key, value) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                match key {
                    "m" => attachment.content_type = Some(value.to_string()),
                    "size" => attachment.byte_len = value.parse::<u64>().ok(),
                    "name" => attachment.file_name = Some(value.to_string()),
                    "x" if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) => {
                        attachment.digest = Some(value.to_string());
                    }
                    _ => {}
                }
            }
            attachment
        })
        .collect()
}

/// Build a `MessageContentDecoded` event from a decrypted application payload.
///
/// FULL-DATA ONLY: callers must gate this on
/// [`marmot_forensics::AuditDataMode::FullData`]; it carries decrypted content
/// and full author identities. Returns `None` when the payload is not a
/// decodable Marmot app event.
pub(crate) fn message_content_decoded_event(
    msg_id_hex: MessageRefHex,
    sender: &MemberId,
    payload: &[u8],
) -> Option<AuditEventKind> {
    let event = cgka_traits::app_event::MarmotAppEvent::decode(payload).ok()?;
    let raw = serde_json::json!({
        "id": event.id,
        "pubkey": event.pubkey,
        "created_at": event.created_at,
        "kind": event.kind,
        "tags": event.tags,
        "content": event.content,
    });
    let author = MessageAuthor {
        member_ref: Some(member_ref_hex(sender)),
        member_pubkey_hex: (sender.as_slice().len() == 32).then(|| hex::encode(sender.as_slice())),
        account_pubkey_hex: (!event.pubkey.is_empty()).then(|| event.pubkey.clone()),
        npub: None,
    };
    let decoded_app_event = DecodedApplicationEvent {
        format: "marmot.app_event.v1".to_string(),
        kind: Some(event.kind),
        content: Some(event.content.clone()),
        pubkey_hex: (!event.pubkey.is_empty()).then(|| event.pubkey.clone()),
        tags: event.tags.clone(),
        created_at_ms: Some(event.created_at.saturating_mul(1000)),
        client_message_id: None,
        reply_to_message_id: None,
        thread_root_message_id: None,
        attachments: parse_imeta_attachments(&event.tags),
        raw: Some(raw.clone()),
    };
    Some(AuditEventKind::MessageContentDecoded {
        msg_id: msg_id_hex,
        artifact_kind: Some(MessageArtifactKind::ApplicationMessage),
        author,
        decoded_payload: DecodedPayload {
            content_type: "application/x-marmot-app-event+json".to_string(),
            text: None,
            json: Some(raw),
            bytes_b64: None,
        },
        decoded_app_event: Some(decoded_app_event),
    })
}

/// Build an `IngestEntry` event from an inbound transport message.
pub(crate) fn ingest_entry_event(msg: &TransportMessage) -> AuditEventKind {
    AuditEventKind::IngestEntry {
        msg_id: hex::encode(msg.id.as_slice()),
        envelope_kind: envelope_kind_str(&msg.envelope).to_string(),
        transport_source: msg.source.0.clone(),
        payload_len: msg.payload.len() as u64,
        payload_digest: hex::encode(Sha256::digest(&msg.payload)) as DigestHex,
    }
}

/// Build an `IngestOutcome` event from a classified outcome.
pub(crate) fn ingest_outcome_event(
    msg_id_hex: MessageRefHex,
    outcome: &IngestOutcome,
) -> AuditEventKind {
    AuditEventKind::IngestOutcome {
        msg_id: msg_id_hex,
        outcome_kind: ingest_outcome_kind_str(outcome).to_string(),
        stale_reason: match outcome {
            IngestOutcome::Stale { reason } => Some(stale_reason_str(reason).to_string()),
            _ => None,
        },
        epoch: ingest_outcome_epoch(outcome),
    }
}

/// Build a `MessageStateChanged` event.
pub(crate) fn message_state_changed_event(
    msg_id_hex: MessageRefHex,
    state: MessageState,
    reason: &str,
) -> AuditEventKind {
    AuditEventKind::MessageStateChanged {
        msg_id: msg_id_hex,
        artifact_kind: None,
        previous_state: None,
        new_state: message_state_str(state).to_string(),
        epoch: None,
        reason: reason.to_string(),
    }
}

pub(crate) fn message_state_transition_event(
    msg_id_hex: MessageRefHex,
    previous_state: Option<MessageState>,
    state: MessageState,
    epoch: Option<EpochId>,
    reason: &str,
) -> AuditEventKind {
    AuditEventKind::MessageStateChanged {
        msg_id: msg_id_hex,
        artifact_kind: None,
        previous_state: previous_state.map(message_state_str).map(str::to_string),
        new_state: message_state_str(state).to_string(),
        epoch: epoch.map(|epoch| epoch.0),
        reason: reason.to_string(),
    }
}

/// Map a `SendResult` to its outbound message inventory (id + artifact kind).
///
/// Per-message recipient expectations are emitted as separate
/// `recipient_expectation` rows (see `Engine::recipient_expectation_records`)
/// because they need the engine's authenticated membership roster, which is not
/// available from the `SendResult` alone.
pub(crate) fn send_outbound_messages(result: &SendResult) -> Vec<OutboundMessage> {
    fn outbound(msg: &TransportMessage, artifact_kind: MessageArtifactKind) -> OutboundMessage {
        OutboundMessage {
            msg_id: hex::encode(msg.id.as_slice()),
            artifact_kind,
            transport: None,
            recipient_expectation: None,
        }
    }
    let mut messages = Vec::new();
    match result {
        SendResult::ApplicationMessage { msg } => {
            messages.push(outbound(msg, MessageArtifactKind::ApplicationMessage));
        }
        SendResult::Proposal { msg } => {
            messages.push(outbound(msg, MessageArtifactKind::Proposal));
        }
        SendResult::GroupEvolution { msg, welcomes, .. } => {
            messages.push(outbound(msg, MessageArtifactKind::Commit));
            messages.extend(
                welcomes
                    .iter()
                    .map(|w| outbound(w, MessageArtifactKind::Welcome)),
            );
        }
        SendResult::GroupCreated { welcomes, .. } => {
            messages.extend(
                welcomes
                    .iter()
                    .map(|w| outbound(w, MessageArtifactKind::Welcome)),
            );
        }
        SendResult::Queued { .. } => {}
    }
    messages
}

/// Build a `SendOutcome` event from a `SendResult`.
pub(crate) fn send_outcome_event(intent_kind: String, result: &SendResult) -> AuditEventKind {
    AuditEventKind::SendOutcome {
        intent_kind,
        result_kind: send_result_kind_str(result).to_string(),
        outbound_messages: send_outbound_messages(result),
    }
}

pub(crate) fn create_group_outcome_event(result: &SendResult) -> AuditEventKind {
    AuditEventKind::CreateGroupOutcome {
        result_kind: send_result_kind_str(result).to_string(),
        outbound_messages: send_outbound_messages(result),
    }
}

pub(crate) fn engine_error_kind(err: &EngineError) -> &'static str {
    match err {
        EngineError::UnknownGroup(_) => "unknown_group",
        EngineError::UnknownPending => "unknown_pending",
        EngineError::NotAMember { .. } => "not_a_member",
        EngineError::NotGroupAdmin { .. } => "not_group_admin",
        EngineError::UnknownMember { .. } => "unknown_member",
        EngineError::InvalidCredentialIdentity(_) => "invalid_credential_identity",
        EngineError::AdminCannotSelfRemove { .. } => "admin_cannot_self_remove",
        EngineError::AdminDepletion { .. } => "admin_depletion",
        EngineError::MissingRequiredCapabilities { .. } => "missing_required_capabilities",
        EngineError::UnsupportedCiphersuite { .. } => "unsupported_ciphersuite",
        EngineError::InvalidAppMessagePayload(_) => "invalid_app_message_payload",
        EngineError::InvalidAccountIdentityProof(_) => "invalid_account_identity_proof",
        EngineError::ForkedEpoch { .. } => "forked_epoch",
        EngineError::InvalidTransition(_) => "invalid_transition",
        EngineError::Storage(_) => "storage",
        EngineError::Peeler(_) => "peeler",
        EngineError::Serialize(_) => "serialize",
        EngineError::Backend(_) => "backend",
        EngineError::Other(_) => "other",
    }
}

pub(crate) fn engine_error_detail(err: &EngineError) -> Option<String> {
    Some(err.to_string())
}

pub(crate) fn peeler_error_kind(err: &PeelerError) -> &'static str {
    match err {
        PeelerError::Malformed(_) => "malformed",
        PeelerError::DecryptFailed => "decrypt_failed",
        PeelerError::StaleEpoch { .. } => "stale_epoch",
        PeelerError::MissingContext { .. } => "missing_context",
        PeelerError::WrapFailed(_) => "wrap_failed",
        PeelerError::Backend(_) => "backend",
    }
}

/// Build an `EpochConfirmed` event.
pub(crate) fn epoch_confirmed_event(
    from_epoch: EpochId,
    to_epoch: EpochId,
    pending_kind: &str,
) -> AuditEventKind {
    AuditEventKind::EpochConfirmed {
        from_epoch: from_epoch.0,
        to_epoch: to_epoch.0,
        pending_kind: pending_kind.to_string(),
        // The confirming commit's origin id is not threaded to this call site;
        // the same commit is attributed on the accompanying group_state_changed
        // row's origin_commit_id.
        origin_commit_id: None,
    }
}

/// Build an `EpochRolledBack` event.
pub(crate) fn epoch_rolled_back_event(
    pending_epoch: EpochId,
    restored_epoch: EpochId,
    pending_kind: &str,
) -> AuditEventKind {
    AuditEventKind::EpochRolledBack {
        pending_epoch: pending_epoch.0,
        restored_epoch: restored_epoch.0,
        pending_kind: pending_kind.to_string(),
    }
}

/// Build a `ConvergenceDecision` audit event from a branch-selection trace.
/// Full committer/witness pubkeys are included only in `full_data` mode; member
/// refs (salted hashes) and digests are always emitted.
pub(crate) fn convergence_decision_event(
    current_tip_epoch: u64,
    max_rewind_commits: u64,
    trace: Option<&BranchSelectionTrace>,
    error_kinds: Vec<String>,
    full_data: bool,
) -> AuditEventKind {
    let Some(trace) = trace else {
        return AuditEventKind::ConvergenceDecision {
            current_tip_epoch,
            max_rewind_commits,
            candidates: Vec::new(),
            rule_trace: Vec::new(),
            selected_branch_id: None,
            selected_fork_epoch: None,
            selected_tip_epoch: None,
            losing_branch_ids: Vec::new(),
            error_kinds,
        };
    };
    let selected = trace
        .selected_branch_id
        .as_ref()
        .and_then(|id| trace.candidates.iter().find(|c| &c.branch_id == id));
    AuditEventKind::ConvergenceDecision {
        current_tip_epoch,
        max_rewind_commits,
        candidates: trace
            .candidates
            .iter()
            .map(|candidate| convergence_candidate(candidate, full_data))
            .collect(),
        rule_trace: trace.rule_trace.iter().map(convergence_rule_eval).collect(),
        selected_branch_id: trace.selected_branch_id.clone(),
        selected_fork_epoch: selected.map(|c| c.fork_epoch),
        selected_tip_epoch: selected.map(|c| c.tip_epoch),
        losing_branch_ids: trace.losing_branch_ids.clone(),
        error_kinds,
    }
}

fn committer_ref(committer: &[u8]) -> Option<MemberRefHex> {
    (!committer.is_empty()).then(|| member_ref_hex(&MemberId::new(committer.to_vec())))
}

fn committer_pubkey_hex(committer: &[u8], full_data: bool) -> Option<String> {
    (full_data && committer.len() == 32).then(|| hex::encode(committer))
}

fn convergence_candidate(candidate: &CandidateEvaluation, full_data: bool) -> ConvergenceCandidate {
    ConvergenceCandidate {
        branch_id: candidate.branch_id.clone(),
        fork_epoch: candidate.fork_epoch,
        tip_epoch: candidate.tip_epoch,
        commit_ids: Vec::new(),
        commit_count: None,
        // Per-candidate full MLS-state digest is intentionally not computed
        // (materializing each branch's state is too costly for the hot path).
        state_digest: None,
        tip_digest: Some(hex::encode(candidate.tip_digest)),
        tip_priority: Some(tip_priority_str(candidate.tip_priority).to_string()),
        tip_committer_ref: committer_ref(&candidate.tip_committer),
        tip_committer_pubkey_hex: committer_pubkey_hex(&candidate.tip_committer, full_data),
        retained_anchor_status: None,
        // Selector input timing is a per-run value carried on convergence_run_state,
        // not duplicated per candidate.
        last_input_time_ms: None,
        eligible: Some(candidate.eligible),
        rejection_reasons: candidate.rejection_reasons.clone(),
        score: Some(convergence_score(&candidate.score, full_data)),
        app_witnesses: candidate
            .app_witnesses
            .iter()
            .map(|witness| convergence_app_witness(witness, full_data))
            .collect(),
    }
}

fn convergence_score(score: &BranchScore, full_data: bool) -> ConvergenceScore {
    ConvergenceScore {
        valid_commit_depth: Some(score.valid_commit_depth),
        effective_commit_depth: Some(score.effective_commit_depth),
        witness_quorum_met: Some(score.witness_quorum_met),
        app_witness_score: Some(score.app_witness_score as u64),
        tip_priority: Some(tip_priority_str(score.tip_priority).to_string()),
        tip_committer_ref: committer_ref(&score.tip_committer),
        tip_committer_pubkey_hex: committer_pubkey_hex(&score.tip_committer, full_data),
        tip_digest: Some(hex::encode(score.tip_digest)),
    }
}

fn convergence_app_witness(witness: &AppWitness, full_data: bool) -> ConvergenceAppWitness {
    ConvergenceAppWitness {
        epoch: witness.epoch,
        sender_ref: committer_ref(&witness.sender),
        sender_pubkey_hex: committer_pubkey_hex(&witness.sender, full_data),
    }
}

fn convergence_rule_eval(rule: &RuleEvaluation) -> ConvergenceRuleEvaluation {
    ConvergenceRuleEvaluation {
        rule_name: rule.rule_name.to_string(),
        scope: Some("candidate_pair".to_string()),
        candidate_branch_id: Some(rule.winner_branch_id.clone()),
        other_candidate_branch_id: Some(rule.other_branch_id.clone()),
        inputs: None,
        result: serde_json::json!({
            "winner": rule.winner_value,
            "other": rule.other_value,
        }),
        decisive: Some(rule.decisive),
        selected_branch_id: rule.decisive.then(|| rule.winner_branch_id.clone()),
        rejected_branch_id: rule.decisive.then(|| rule.other_branch_id.clone()),
    }
}
