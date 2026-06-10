//! Stringification + extraction helpers for the forensic audit log.
//!
//! Kept in one place so audit-event variants stay consistent across call
//! sites. These produce stable, low-cardinality strings that an analyzer
//! can group on.

use cgka_traits::engine::{SendIntent, SendResult};
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use cgka_traits::message::MessageState;
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::EpochId;
use marmot_forensics::{AuditEventKind, DigestHex, MessageRefHex};

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
    match intent {
        SendIntent::AppMessage { group_id, .. }
        | SendIntent::Invite { group_id, .. }
        | SendIntent::RemoveMembers { group_id, .. }
        | SendIntent::Leave { group_id }
        | SendIntent::UpdateAppComponents { group_id, .. }
        | SendIntent::UpdateGroupData { group_id, .. } => Some(hex::encode(group_id.as_slice())),
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

pub(crate) fn send_outbound_ids(
    result: &SendResult,
) -> (Option<MessageRefHex>, Vec<MessageRefHex>) {
    match result {
        SendResult::ApplicationMessage { msg } | SendResult::Proposal { msg } => {
            (Some(hex::encode(msg.id.as_slice())), Vec::new())
        }
        SendResult::GroupEvolution { msg, welcomes, .. } => (
            Some(hex::encode(msg.id.as_slice())),
            welcomes
                .iter()
                .map(|w| hex::encode(w.id.as_slice()))
                .collect(),
        ),
        SendResult::GroupCreated { welcomes, .. } => (
            None,
            welcomes
                .iter()
                .map(|w| hex::encode(w.id.as_slice()))
                .collect(),
        ),
        SendResult::Queued { .. } => (None, Vec::new()),
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

/// Build an `IngestEntry` event from an inbound transport message.
pub(crate) fn ingest_entry_event(msg: &TransportMessage) -> AuditEventKind {
    use sha2::{Digest, Sha256};
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
        previous_state: previous_state.map(message_state_str).map(str::to_string),
        new_state: message_state_str(state).to_string(),
        epoch: epoch.map(|epoch| epoch.0),
        reason: reason.to_string(),
    }
}

/// Build a `SendOutcome` event from a `SendResult`.
pub(crate) fn send_outcome_event(intent_kind: String, result: &SendResult) -> AuditEventKind {
    let (outbound_msg_id, outbound_welcome_msg_ids) = send_outbound_ids(result);
    AuditEventKind::SendOutcome {
        intent_kind,
        result_kind: send_result_kind_str(result).to_string(),
        outbound_msg_id,
        outbound_welcome_msg_ids,
    }
}

pub(crate) fn create_group_outcome_event(result: &SendResult) -> AuditEventKind {
    let (_outbound_msg_id, outbound_welcome_msg_ids) = send_outbound_ids(result);
    AuditEventKind::CreateGroupOutcome {
        result_kind: send_result_kind_str(result).to_string(),
        outbound_welcome_msg_ids,
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
