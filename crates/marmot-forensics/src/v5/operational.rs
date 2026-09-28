//! Typed v4 operation facts carried as direct v5 event kinds. The legacy
//! payload types remain the source-side catalog; references and free-form
//! transport strings are converted before any v5 byte is written.
use crate::audit::{AuditEventContext, AuditEventKind, AuditRecord};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{ContractError, EndpointRef, EngineMessageRef, GroupRef};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalEvent {
    pub kind: AuditEventKind,
    pub context: Option<AuditEventContext>,
    // A decoded v5 event already contains diagnostic references. Never hash
    // them a second time during strict structural round-trip validation.
    wire: Option<Value>,
}

impl OperationalEvent {
    pub fn from_audit(record: AuditRecord) -> Self {
        Self {
            kind: record.kind,
            context: record.context,
            wire: None,
        }
    }

    pub(crate) fn to_wire(&self) -> Result<Value, ContractError> {
        if let Some(wire) = &self.wire {
            return Ok(wire.clone());
        }
        let mut wire = serde_json::to_value(&self.kind)
            .map_err(|_| ContractError::rule("operation serialization failed"))?;
        if let Some(context) = &self.context {
            wire.as_object_mut()
                .ok_or_else(|| ContractError::rule("operation shape invalid"))?
                .insert(
                    "record_context".to_owned(),
                    serde_json::to_value(context).map_err(|_| {
                        ContractError::rule("operation context serialization failed")
                    })?,
                );
        }
        protect(&mut wire)?;
        Ok(wire)
    }

    pub(crate) fn from_wire(mut wire: Value) -> Result<Self, ContractError> {
        validate_protected(&wire)?;
        let original = wire.clone();
        unprotect_names(&mut wire)?;
        let context = wire
            .as_object_mut()
            .ok_or_else(|| ContractError::rule("operation shape invalid"))?
            .remove("record_context")
            .map(|value| {
                serde_json::from_value(value)
                    .map_err(|_| ContractError::rule("operation context shape invalid"))
            })
            .transpose()?;
        let kind = serde_json::from_value(wire)
            .map_err(|_| ContractError::rule("operation kind shape invalid"))?;
        let mut canonical = serde_json::to_value(&kind)
            .map_err(|_| ContractError::rule("operation serialization failed"))?;
        if let Some(context) = &context {
            canonical.as_object_mut().expect("enum object").insert(
                "record_context".to_owned(),
                serde_json::to_value(context)
                    .map_err(|_| ContractError::rule("operation context serialization failed"))?,
            );
        }
        protect_names_only(&mut canonical)?;
        if canonical != original {
            return Err(ContractError::rule("noncanonical operation shape"));
        }
        Ok(Self {
            kind,
            context,
            wire: Some(original),
        })
    }
}

impl Serialize for OperationalEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_wire()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for OperationalEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_wire(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The existing v4 group reference is raw MLS GroupId bytes in hex. Hash the
/// decoded bytes in the same v5 domain as the Welcome source-side capture.
pub fn group_ref_from_legacy_hex(raw: &str) -> Result<GroupRef, ContractError> {
    let bytes =
        hex::decode(raw).map_err(|_| ContractError::rule("invalid legacy group reference"))?;
    GroupRef::from_group_id(&bytes)
}

fn diagnostic_ref(kind: &str, input: &str) -> String {
    let namespace = match kind {
        "branch_id" | "selected_branch_id" | "losing_branch_ids" => "branch",
        "snapshot_name" | "fallback_snapshot_name" => "snapshot",
        other => other,
    };
    let mut hash = Sha256::new();
    hash.update(b"marmot-audit-operational-ref/v5\0");
    hash.update(namespace.as_bytes());
    hash.update([0]);
    hash.update((input.len() as u32).to_be_bytes());
    hash.update(input.as_bytes());
    hex::encode(hash.finalize())
}

fn message_ref(input: &str) -> Result<String, ContractError> {
    let bytes =
        hex::decode(input).map_err(|_| ContractError::rule("invalid legacy message reference"))?;
    Ok(EngineMessageRef::from_message_id(&bytes)?
        .as_str()
        .to_owned())
}

fn safe_category(input: &str) -> String {
    if !input.is_empty()
        && input.len() <= 64
        && input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        input.to_owned()
    } else {
        "unclassified".to_owned()
    }
}

/// Error/reason fields may originate in generic adapters or `Display` text.
/// Only the established semantic vocabulary can cross the v5 boundary; a
/// short alphanumeric string alone is not evidence that it is a category.
fn safe_failure_category(input: &str) -> String {
    match input {
        "open"
        | "pre_commit"
        | "publish_confirmed"
        | "already_seen"
        | "timeout"
        | "unknown_group"
        | "unknown_member"
        | "unknown_pending"
        | "group_not_hydrated"
        | "not_a_member"
        | "not_group_admin"
        | "invalid_credential_identity"
        | "admin_cannot_self_remove"
        | "leave_already_requested"
        | "admin_depletion"
        | "missing_required_capabilities"
        | "disbanding_unsupported_members"
        | "disbanding_not_enabled"
        | "unsupported_ciphersuite"
        | "invalid_app_message_payload"
        | "invalid_account_identity_proof"
        | "invalid_key_package_lifetime"
        | "invalid_key_package_capabilities"
        | "app_message_epoch_mismatch"
        | "app_message_epoch_unsettled"
        | "forked_epoch"
        | "queued_outbound_at_capacity"
        | "group_unrecoverable_repair_required"
        | "invalid_transition"
        | "storage"
        | "peeler"
        | "serialize"
        | "invalid_welcome"
        | "missing_welcome_key_package"
        | "welcome_already_processed"
        | "backend"
        | "other"
        | "malformed"
        | "invalid_signature"
        | "wrong_recipient"
        | "decrypt_failed"
        | "stale_epoch"
        | "missing_context"
        | "wrap_failed"
        | "account_transport"
        | "history_coverage_unproven"
        | "group_epoch_unavailable"
        | "backfill_drain_no_progress_quantum_yield"
        | "missing_retained_anchor"
        | "frozen_pass_integrity_failure"
        | "frozen_member_integrity"
        | "group_quarantined"
        | "already_unrecoverable"
        | "no_eligible_input"
        | "blocked"
        | "group_not_stable"
        | "fork_rival_missing_retained_anchor"
        | "queued_outbound_intent_discarded_group_removed"
        | "set_group_convergence_policy"
        | "input_window_open"
        | "not_lowest_index"
        | "fork_loser"
        | "unattributable_sender"
        | "fanout_adapter_error"
        | "fanout_endpoint_did_not_acknowledge"
        | "insufficient_publish_acknowledgements"
        | "publish_acknowledgement_unknown"
        | "publish_attempt_failed_before_exposure"
        // Closed categories emitted by the typed app, recovery, storage,
        // and engine outcome producers. Keep them explicit: generic adapter
        // and Display text must still fall through to `unclassified`.
        | "account_catch_up"
        | "account_clock_skew_blocked"
        | "account_delivery_queue_overflow"
        | "account_home_account_exists"
        | "account_home_account_id_in_use"
        | "account_home_account_id_mismatch"
        | "account_home_empty_passphrase"
        | "account_home_empty_secret_store_service"
        | "account_home_encrypted_secret_export"
        | "account_home_hex"
        | "account_home_invalid_account_label"
        | "account_home_invalid_public_key"
        | "account_home_invalid_secret_key"
        | "account_home_io"
        | "account_home_json"
        | "account_home_secret_not_found"
        | "account_home_secret_store"
        | "account_home_secret_store_not_initialized"
        | "account_home_secret_store_unavailable"
        | "account_home_setup_state_missing"
        | "account_home_unknown_account"
        | "account_home_unsupported_secret_backend"
        | "account_key_package"
        | "account_key_package_rotation_in_progress"
        | "account_session_busy"
        | "account_setup_key_package_recovery_available"
        | "account_setup_recovery_required"
        | "account_setup_reset_not_applicable"
        | "account_setup_retry_required"
        | "account_transport_routing"
        | "account_unknown"
        | "account_worker_busy"
        | "account_worker_response_timed_out"
        | "account_wrong_delivery"
        | "agent_stream_finish_mismatch"
        | "agent_stream_invalid_candidate"
        | "agent_stream_missing_candidate"
        | "agent_stream_missing_start"
        | "agent_stream_publisher"
        | "agent_stream_send_failed"
        | "agent_stream_start_not_confirmed"
        | "agent_stream_unsupported_route"
        | "already_at_epoch"
        | "attachment_account_signed_out"
        | "attachment_mode_required"
        | "audit_log_upload"
        | "authorization_failed"
        | "backfill_drain_eose_timeout"
        | "backfill_drain_no_relay_eose"
        | "backfill_drain_novel_progress_quantum_yield"
        | "beyond_anchor"
        | "beyond_app_retention"
        | "beyond_rollback_horizon"
        | "blob_store"
        | "block_list_unavailable"
        | "block_publication_uncertain"
        | "blocking_task"
        | "chat_presentation_not_ready"
        | "created_group_projection_unavailable"
        | "direct_conversation_index_not_ready"
        | "duplicate"
        | "external_signer_mismatch"
        | "external_signer_rejected"
        | "external_signer_unavailable"
        | "follow_list_unavailable"
        | "full_history_coverage_unproven"
        | "full_history_repair_cancelled"
        | "full_history_repair_deadline"
        | "full_history_repair_unconfirmed"
        | "group_create_includes_creator"
        | "group_disbanding"
        | "group_invite_not_pending"
        | "group_removed"
        | "hex"
        | "identity_key_mismatch"
        | "invalid_against_canonical_state"
        | "invalid_agent_text_stream_policy"
        | "invalid_audit_log_file"
        | "invalid_cached_identity_page"
        | "invalid_chat_pin"
        | "invalid_directory_search"
        | "invalid_encoding"
        | "invalid_encrypted_media"
        | "invalid_group_avatar_url"
        | "invalid_group_membership_page"
        | "invalid_group_profile"
        | "invalid_key_package_event"
        | "invalid_message_draft"
        | "invalid_nostr_routing"
        | "invalid_public_key"
        | "invalid_push_gossip"
        | "invalid_push_server"
        | "invalid_push_token"
        | "invalid_relay_telemetry_settings"
        | "invalid_self_remove"
        | "io"
        | "json"
        | "losing_branch"
        | "media_attachment_rejected"
        | "media_download_failed"
        | "media_reference_epoch_unsettled"
        | "media_reference_stale_epoch"
        | "media_unfetchable"
        | "media_upload_timed_out"
        | "message_draft_revision_conflict"
        | "missing_default_relays"
        | "missing_directory_entry"
        | "missing_key_package"
        | "missing_member_inbox_route"
        | "missing_relay_lists"
        | "not_for_this_client"
        | "notifications_disabled"
        | "onboarding_action_unavailable"
        | "onboarding_required"
        | "own_echo"
        | "pre_membership"
        | "predates_local_copy"
        | "publish"
        | "quarantined"
        | "reaction_not_found"
        | "rejoin_confirmation_required"
        | "relay_directory"
        | "removed"
        | "resource_refused_deferred_capacity"
        | "resource_refused_residence_budget"
        | "resource_refused_retry_budget"
        | "runtime_busy"
        | "runtime_stopping"
        | "self_evicted"
        | "sqlcipher_key_derivation"
        | "sqlite"
        | "storage_already_exists"
        | "storage_backend"
        | "storage_busy"
        | "storage_capacity"
        | "storage_closed"
        | "storage_corruption"
        | "storage_not_found"
        | "storage_serialization"
        | "storage_snapshot_missing"
        | "storage_timeline_cursor_expired"
        | "storage_unsupported_schema_version"
        | "transport"
        | "transport_closed"
        | "transport_deferred"
        | "unexpected_private_key"
        | "unsafe_media_fetch"
        | "unsupported_proposal"
        | "unsupported_required_feature"
        | "usage_diagnostics"
        | "user_blocked"
        | "admin_set_unreadable"
        | "buffered_into_convergence"
        | "leaver_identity_malformed"
        | "leaver_still_admin"
        | "proposal_not_self_remove"
        | "self_remove_remaining_member"
        | "sender_not_member"
        | "we_are_target"
        | "openmls_load_failed"
        | "openmls_group_missing"
        | "member_validation_failed"
        | "group_record_load_failed"
        | "pending_commit_recovery_failed"
        | "founding_welcome_persisted"
        | "founding_create"
        | "superseded_by_replacement_welcome"
        | "beyond_retained_anchor"
        | "superseded_processed_commit"
        | "publish_failed"
        | "update_group_data_stage_failed"
        | "create_group"
        | "hydrate_unrecoverable_group"
        | "hydrate_durable_group_evolution"
        | "canonical_application_drain"
        | "persist"
        | "state_update"
        | "terminal_group"
        | "stale_epoch_no_snapshot"
        | "auto_commit_stage_failed"
        | "begin_pending"
        | "hydrate_removed_group"
        | "hydrate_seed_group"
        | "hydrate_stable_group"
        | "join_welcome_repair"
        | "recipient_confirmed_rejoin"
        | "join_welcome"
        | "unclassified" => input.to_owned(),
        "fanout adapter error" => "fanout_adapter_error".to_owned(),
        "fanout endpoint did not acknowledge" => "fanout_endpoint_did_not_acknowledge".to_owned(),
        "insufficient publish acknowledgements" => {
            "insufficient_publish_acknowledgements".to_owned()
        }
        "publish acknowledgement unknown" => "publish_acknowledgement_unknown".to_owned(),
        "publish attempt failed before exposure" => {
            "publish_attempt_failed_before_exposure".to_owned()
        }
        // Fixed Nostr adapter failure phrases. The SDK's free-form relay
        // suffix is never preserved; only typed protocol-prefix outcomes and
        // these locally authored phrases have an audit category.
        "connect relay failed" => "connect_relay_failed".to_owned(),
        "send event failed" => "send_event_failed".to_owned(),
        "relay did not acknowledge event" => "relay_did_not_acknowledge_event".to_owned(),
        "send event timed out" => "send_event_timed_out".to_owned(),
        "configure publish relay failed" => "configure_publish_relay_failed".to_owned(),
        "add publish relay failed" => "add_publish_relay_failed".to_owned(),
        "publish acknowledgement unknown (error)" => "publish_acknowledgement_unknown".to_owned(),
        "relay rejected event (duplicate)" => "relay_rejected_duplicate".to_owned(),
        "relay rejected event (pow)" => "relay_rejected_pow".to_owned(),
        "relay rejected event (blocked)" => "relay_rejected_blocked".to_owned(),
        "relay rejected event (rate-limited)" => "relay_rejected_rate_limited".to_owned(),
        "relay rejected event (invalid)" => "relay_rejected_invalid".to_owned(),
        "relay rejected event (unsupported)" => "relay_rejected_unsupported".to_owned(),
        "relay rejected event (auth-required)" => "relay_rejected_auth_required".to_owned(),
        "relay rejected event (restricted)" => "relay_rejected_restricted".to_owned(),
        _ => "unclassified".to_owned(),
    }
}

fn safe_metadata(input: &str, punctuation: &[u8]) -> String {
    if !input.is_empty()
        && input.len() <= 64
        && input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || punctuation.contains(&b))
    {
        input.to_owned()
    } else {
        "unclassified".to_owned()
    }
}

fn preserve_legacy_hex(input: &str, bytes: usize) -> Result<String, ContractError> {
    if input.len() == bytes * 2
        && input
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(input.to_owned())
    } else {
        Err(ContractError::rule("invalid legacy diagnostic hash"))
    }
}

fn renamed(key: &str) -> &str {
    match key {
        "relay_url" => "endpoint_ref",
        "relay_urls" => "endpoint_refs",
        "accepted_relay_urls" => "accepted_endpoint_refs",
        "msg_id" => "message_ref",
        "origin_commit_id" => "origin_commit_ref",
        "basis_commit_id" => "basis_commit_ref",
        "invalidated_msg_id" => "invalidated_message_ref",
        "commit_ids" => "commit_refs",
        "message_ids" => "message_refs",
        "wire_id" => "wire_ref",
        "wire_pubkey_hex" => "wire_pubkey_ref",
        "transport_group_id" => "transport_group_ref",
        "nostr_event_id" => "nostr_event_diagnostic_ref",
        "nostr_pubkey_hex" => "nostr_pubkey_ref",
        "gift_wrap_event_id" => "gift_wrap_event_diagnostic_ref",
        "welcome_nostr_event_id" => "welcome_nostr_event_diagnostic_ref",
        "welcome_rumor_event_id" => "welcome_rumor_event_diagnostic_ref",
        "welcome_key_package_tag" => "welcome_key_package_tag_ref",
        "publish_result_id" => "publish_result_ref",
        "subscription_id" => "subscription_ref",
        "branch_id" => "branch_ref",
        "selected_branch_id" => "selected_branch_ref",
        "losing_branch_ids" => "losing_branch_refs",
        "run_id" => "run_ref",
        "operation_id" => "operation_ref",
        "snapshot_name" => "snapshot_ref",
        "fallback_snapshot_name" => "fallback_snapshot_ref",
        "device_id" => "device_ref",
        other => other,
    }
}

fn old_name(key: &str) -> &str {
    match key {
        "endpoint_ref" => "relay_url",
        "endpoint_refs" => "relay_urls",
        "accepted_endpoint_refs" => "accepted_relay_urls",
        "message_ref" => "msg_id",
        "origin_commit_ref" => "origin_commit_id",
        "basis_commit_ref" => "basis_commit_id",
        "invalidated_message_ref" => "invalidated_msg_id",
        "commit_refs" => "commit_ids",
        "message_refs" => "message_ids",
        "wire_ref" => "wire_id",
        "wire_pubkey_ref" => "wire_pubkey_hex",
        "transport_group_ref" => "transport_group_id",
        "nostr_event_diagnostic_ref" => "nostr_event_id",
        "nostr_pubkey_ref" => "nostr_pubkey_hex",
        "gift_wrap_event_diagnostic_ref" => "gift_wrap_event_id",
        "welcome_nostr_event_diagnostic_ref" => "welcome_nostr_event_id",
        "welcome_rumor_event_diagnostic_ref" => "welcome_rumor_event_id",
        "welcome_key_package_tag_ref" => "welcome_key_package_tag",
        "publish_result_ref" => "publish_result_id",
        "subscription_ref" => "subscription_id",
        "branch_ref" => "branch_id",
        "selected_branch_ref" => "selected_branch_id",
        "losing_branch_refs" => "losing_branch_ids",
        "run_ref" => "run_id",
        "operation_ref" => "operation_id",
        "snapshot_ref" => "snapshot_name",
        "fallback_snapshot_ref" => "fallback_snapshot_name",
        "device_ref" => "device_id",
        other => other,
    }
}

fn map_strings(
    value: &mut Value,
    mut f: impl FnMut(&str) -> Result<String, ContractError>,
) -> Result<(), ContractError> {
    match value {
        Value::String(s) => *s = f(s)?,
        Value::Array(items) => {
            for item in items {
                if let Value::String(s) = item {
                    *s = f(s)?;
                }
            }
        }
        Value::Null => {}
        _ => return Err(ContractError::rule("invalid operation reference shape")),
    }
    Ok(())
}

fn protect(value: &mut Value) -> Result<(), ContractError> {
    match value {
        Value::Object(object) => {
            let mut next = Map::new();
            for (key, mut child) in std::mem::take(object) {
                if key == "detail" {
                    continue;
                }
                protect(&mut child)?;
                match key.as_str() {
                    "relay_url" | "relay_urls" | "accepted_relay_urls" => {
                        map_strings(&mut child, |s| {
                            Ok(EndpointRef::from_normalized_url(s)?.as_str().to_owned())
                        })?;
                    }
                    "msg_id" | "origin_commit_id" | "basis_commit_id" | "invalidated_msg_id"
                    | "commit_ids" | "message_ids" => {
                        map_strings(&mut child, message_ref)?;
                    }
                    "wire_id"
                    | "wire_pubkey_hex"
                    | "transport_group_id"
                    | "nostr_event_id"
                    | "nostr_pubkey_hex"
                    | "gift_wrap_event_id"
                    | "welcome_nostr_event_id"
                    | "welcome_rumor_event_id"
                    | "welcome_key_package_tag"
                    | "publish_result_id"
                    | "subscription_id"
                    | "branch_id"
                    | "selected_branch_id"
                    | "losing_branch_ids"
                    | "run_id"
                    | "operation_id"
                    | "snapshot_name"
                    | "fallback_snapshot_name"
                    | "device_id" => {
                        map_strings(&mut child, |s| Ok(diagnostic_ref(&key, s)))?;
                    }
                    "hardware_model" => map_strings(&mut child, |s| Ok(safe_metadata(s, b",._-")))?,
                    "app_version" => map_strings(&mut child, |s| Ok(safe_metadata(s, b"._+-")))?,
                    // These are already v4 one-way diagnostic hashes, not raw
                    // member identities or v5 MemberRef values. Keep their
                    // distinct legacy domain and exact cross-row equality.
                    "local_member_ref"
                    | "expected_member_refs"
                    | "sender_ref"
                    | "tip_committer_ref"
                    | "actor_member_ref"
                    | "subject_member_ref" => {
                        map_strings(&mut child, |s| preserve_legacy_hex(s, 16))?;
                    }
                    "payload_digest" | "group_digest" | "state_digest" | "candidate_digest"
                    | "incumbent_digest" | "tip_digest" | "digest" => {
                        map_strings(&mut child, |s| preserve_legacy_hex(s, 32))?;
                    }
                    "reason" | "error_kind" | "stale_reason" | "rejection_reasons"
                    | "error_kinds" => {
                        map_strings(&mut child, |s| Ok(safe_failure_category(s)))?;
                    }
                    "action"
                    | "origin"
                    | "phase"
                    | "target_kind"
                    | "intent_kind"
                    | "result_kind"
                    | "change_kind"
                    | "pending_kind"
                    | "stage"
                    | "proposal_kind"
                    | "decision"
                    | "outcome_kind"
                    | "envelope_kind"
                    | "transport_source"
                    | "delivery_plane"
                    | "wire_kind"
                    | "transport"
                    | "recorder"
                    | "upload_trigger"
                    | "platform"
                    | "fields"
                    | "tip_priority"
                    | "retained_anchor_status"
                    | "previous_state"
                    | "new_state"
                    | "decisive_rule"
                    | "artifact_kind"
                    | "recipient_scope"
                    | "membership_change_source"
                    | "winner"
                    | "outcome"
                    | "trigger"
                    | "seam"
                    | "replay_scope"
                    | "activation_outcome"
                    | "completion_kind" => {
                        if matches!(child, Value::String(_) | Value::Array(_)) {
                            map_strings(&mut child, |s| Ok(safe_category(s)))?;
                        }
                    }
                    "type" => {}
                    _ => {
                        if matches!(child, Value::String(_))
                            || matches!(&child, Value::Array(items) if items.iter().any(Value::is_string))
                        {
                            // A future source field must receive an explicit
                            // privacy classification before it can be written.
                            return Err(ContractError::rule("unclassified operation text field"));
                        }
                    }
                }
                next.insert(renamed(&key).to_owned(), child);
            }
            *object = next;
        }
        Value::Array(items) => {
            for item in items {
                protect(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn unprotect_names(value: &mut Value) -> Result<(), ContractError> {
    match value {
        Value::Object(object) => {
            let mut next = Map::new();
            for (key, mut child) in std::mem::take(object) {
                unprotect_names(&mut child)?;
                let old = old_name(&key);
                if next.insert(old.to_owned(), child).is_some() {
                    return Err(ContractError::rule("duplicate operation field"));
                }
            }
            *object = next;
        }
        Value::Array(items) => {
            for item in items {
                unprotect_names(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn protect_names_only(value: &mut Value) -> Result<(), ContractError> {
    match value {
        Value::Object(object) => {
            let mut next = Map::new();
            for (key, mut child) in std::mem::take(object) {
                protect_names_only(&mut child)?;
                if next.insert(renamed(&key).to_owned(), child).is_some() {
                    return Err(ContractError::rule("duplicate operation field"));
                }
            }
            *object = next;
        }
        Value::Array(items) => {
            for item in items {
                protect_names_only(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_protected(value: &Value) -> Result<(), ContractError> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if key == "detail" || renamed(key) != key {
                    // v5 must not admit a legacy plaintext field alongside its
                    // diagnostic-reference counterpart.
                    return Err(ContractError::rule("unsafe operation field"));
                }
                let hashed = matches!(
                    key.as_str(),
                    "endpoint_ref"
                        | "endpoint_refs"
                        | "accepted_endpoint_refs"
                        | "message_ref"
                        | "origin_commit_ref"
                        | "basis_commit_ref"
                        | "invalidated_message_ref"
                        | "commit_refs"
                        | "message_refs"
                        | "wire_ref"
                        | "wire_pubkey_ref"
                        | "transport_group_ref"
                        | "nostr_event_diagnostic_ref"
                        | "nostr_pubkey_ref"
                        | "gift_wrap_event_diagnostic_ref"
                        | "welcome_nostr_event_diagnostic_ref"
                        | "welcome_rumor_event_diagnostic_ref"
                        | "welcome_key_package_tag_ref"
                        | "publish_result_ref"
                        | "subscription_ref"
                        | "branch_ref"
                        | "selected_branch_ref"
                        | "losing_branch_refs"
                        | "run_ref"
                        | "operation_ref"
                        | "snapshot_ref"
                        | "fallback_snapshot_ref"
                        | "device_ref"
                );
                if hashed {
                    let valid = |s: &str| {
                        s.len() == 64
                            && s.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    };
                    let ok = match child {
                        Value::String(s) => valid(s),
                        Value::Array(items) => {
                            items.iter().all(|item| item.as_str().is_some_and(valid))
                        }
                        _ => false,
                    };
                    if !ok {
                        return Err(ContractError::rule("invalid operation reference"));
                    }
                } else {
                    validate_protected(child)?;
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                validate_protected(item)?;
            }
        }
        Value::String(s)
            if s.len() > 128
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._,+-".contains(&b)) =>
        {
            return Err(ContractError::rule("unsafe operation text"));
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{diagnostic_ref, protect};
    use serde_json::json;

    #[test]
    fn operational_branch_and_snapshot_aliases_share_their_semantic_domains() {
        let branch = "branch-17";
        assert_eq!(
            diagnostic_ref("branch_id", branch),
            diagnostic_ref("selected_branch_id", branch)
        );
        assert_eq!(
            diagnostic_ref("branch_id", branch),
            diagnostic_ref("losing_branch_ids", branch)
        );
        assert_eq!(
            diagnostic_ref("snapshot_name", "snapshot-1"),
            diagnostic_ref("fallback_snapshot_name", "snapshot-1")
        );
        assert_ne!(
            diagnostic_ref("branch_id", branch),
            diagnostic_ref("snapshot_name", branch)
        );
    }

    #[test]
    fn unknown_source_string_cannot_pass_as_a_safe_category() {
        let mut future = json!({"type":"send_entry", "intent_kind":"application", "future_raw_id":"ab".repeat(32)});
        assert!(protect(&mut future).is_err());
        let mut known = json!({"type":"send_entry", "intent_kind":"application"});
        assert!(protect(&mut known).is_ok());
    }

    #[test]
    fn typed_recovery_and_engine_failure_categories_survive_protection() {
        for category in [
            "account_delivery_queue_overflow",
            "backfill_drain_eose_timeout",
            "backfill_drain_no_relay_eose",
            "backfill_drain_novel_progress_quantum_yield",
            "backfill_drain_no_progress_quantum_yield",
            "full_history_repair_deadline",
            "resource_refused_deferred_capacity",
            "transport_deferred",
            "authorization_failed",
            "leaver_still_admin",
            "storage_busy",
        ] {
            let mut event = json!({"type": "epoch_stall_backfill_failed", "error_kind": category});
            protect(&mut event).unwrap();
            assert_eq!(event["error_kind"], category);
        }
    }

    #[test]
    fn fixed_adapter_phrases_keep_categories_without_remote_suffixes() {
        for (source, expected) in [
            ("connect relay failed", "connect_relay_failed"),
            ("send event failed", "send_event_failed"),
            (
                "relay did not acknowledge event",
                "relay_did_not_acknowledge_event",
            ),
            ("send event timed out", "send_event_timed_out"),
            (
                "configure publish relay failed",
                "configure_publish_relay_failed",
            ),
            ("add publish relay failed", "add_publish_relay_failed"),
            (
                "publish acknowledgement unknown (error)",
                "publish_acknowledgement_unknown",
            ),
            ("relay rejected event (blocked)", "relay_rejected_blocked"),
            (
                "relay rejected event (rate-limited)",
                "relay_rejected_rate_limited",
            ),
            (
                "relay rejected event (auth-required)",
                "relay_rejected_auth_required",
            ),
        ] {
            let mut event = json!({
                "type": "publish_outcome",
                "failed_relays": [{"relay_url": "wss://relay.example", "reason": source}]
            });
            protect(&mut event).unwrap();
            assert_eq!(event["failed_relays"][0]["reason"], expected);
        }
        let mut arbitrary =
            json!({"type": "publish_failure", "reason": "relay rejected event (Secret42)"});
        protect(&mut arbitrary).unwrap();
        assert_eq!(arbitrary["reason"], "unclassified");
    }

    #[test]
    fn short_free_form_transport_and_error_reasons_are_not_exported() {
        let mut event = json!({
            "type": "publish_outcome",
            "failed_relays": [{"relay_url": "wss://relay.example", "reason": "Secret42"}],
            "error_kind": "TokenABC",
            "rejection_reasons": ["Bearer123"],
            "stale_reason": "timeout"
        });
        protect(&mut event).unwrap();
        assert_eq!(event["failed_relays"][0]["reason"], "unclassified");
        assert_eq!(event["error_kind"], "unclassified");
        assert_eq!(event["rejection_reasons"][0], "unclassified");
        assert_eq!(event["stale_reason"], "timeout");
        let encoded = event.to_string();
        assert!(!encoded.contains("Secret42"));
        assert!(!encoded.contains("TokenABC"));
        assert!(!encoded.contains("Bearer123"));

        let mut failure = json!({"type": "publish_failure", "reason": "ApiKey7"});
        protect(&mut failure).unwrap();
        assert_eq!(failure["reason"], "unclassified");
    }
}
