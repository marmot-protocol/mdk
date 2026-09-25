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
                    "reason"
                    | "error_kind"
                    | "action"
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
                    | "rejection_reasons"
                    | "stale_reason"
                    | "previous_state"
                    | "new_state"
                    | "decisive_rule"
                    | "error_kinds"
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
}
