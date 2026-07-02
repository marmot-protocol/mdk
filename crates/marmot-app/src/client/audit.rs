use cgka_traits::GroupId;
use cgka_traits::app_components::{
    GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID,
};
use marmot_forensics::{AuditEventContext, AuditEventKind, AuditHumanActionContext};

use crate::messages::AppMessageIntent;
use crate::{AppError, AppGroupRecord};

use super::ObservedHumanActionAudit;

use super::AppClient;

impl AppClient {
    pub(crate) fn local_human_action_context(
        action: impl Into<String>,
        fields: Vec<&'static str>,
        component_ids: Vec<u16>,
        target_count: Option<u64>,
    ) -> AuditEventContext {
        AuditEventContext {
            human_action: Some(AuditHumanActionContext {
                action: action.into(),
                origin: "local_user".into(),
                fields: fields.into_iter().map(str::to_string).collect(),
                component_ids,
                target_count,
            }),
            ..AuditEventContext::default()
        }
    }

    fn observed_human_action_context(
        action: impl Into<String>,
        fields: Vec<&'static str>,
        component_ids: Vec<u16>,
        target_count: Option<u64>,
    ) -> AuditEventContext {
        AuditEventContext {
            human_action: Some(AuditHumanActionContext {
                action: action.into(),
                origin: "observed_group_event".into(),
                fields: fields.into_iter().map(str::to_string).collect(),
                component_ids,
                target_count,
            }),
            ..AuditEventContext::default()
        }
    }

    /// Map a user-authored message intent to its audit `human_action` context.
    /// Machine, agent, and system intents return `None` so they stay untagged —
    /// the audit log marks human actions, not stream, gossip, or push-token
    /// traffic. Resolve this from the original intent *before* the
    /// `Unreact` → `Delete` rewrite so a retracted reaction stays `unreact`.
    pub(crate) fn message_human_action_context(
        intent: &AppMessageIntent,
    ) -> Option<AuditEventContext> {
        let (action, target_count): (&'static str, Option<u64>) = match intent {
            AppMessageIntent::Chat { .. } => ("send_message", None),
            AppMessageIntent::Reply { .. } => ("reply_message", None),
            AppMessageIntent::Edit { .. } => ("edit_message", None),
            AppMessageIntent::Reaction { .. } => ("react", None),
            AppMessageIntent::Unreact { .. } => ("unreact", None),
            AppMessageIntent::Delete { .. } => ("delete_message", None),
            AppMessageIntent::Media { attachments, .. } => {
                ("send_media", Some(attachments.len() as u64))
            }
            AppMessageIntent::StreamStart { .. }
            | AppMessageIntent::StreamFinal { .. }
            | AppMessageIntent::AgentActivity { .. }
            | AppMessageIntent::AgentOperation { .. }
            | AppMessageIntent::GroupSystem { .. }
            | AppMessageIntent::PushTokenUpdate { .. }
            | AppMessageIntent::PushTokenRemoval { .. } => return None,
        };
        Some(Self::local_human_action_context(
            action,
            Vec::new(),
            Vec::new(),
            target_count,
        ))
    }

    fn record_human_action(
        &self,
        group_id: &GroupId,
        context: &AuditEventContext,
        phase: &'static str,
        message_ids: Vec<String>,
        from_epoch: Option<u64>,
        to_epoch: Option<u64>,
    ) {
        let Some(action) = context.human_action.as_ref() else {
            return;
        };
        self.runtime.session().record_audit_event(
            Some(group_id),
            Some(context.clone()),
            AuditEventKind::HumanAction {
                action: action.action.clone(),
                origin: action.origin.clone(),
                phase: phase.to_string(),
                fields: action.fields.clone(),
                component_ids: action.component_ids.clone(),
                target_count: action.target_count,
                message_ids: schema_valid_message_ids(message_ids),
                from_epoch,
                to_epoch,
                error_kind: None,
                detail: None,
            },
        );
    }

    pub(crate) fn record_human_action_succeeded(
        &self,
        group_id: &GroupId,
        context: &AuditEventContext,
        effects: &marmot_account::AccountDeviceEffects,
    ) {
        self.record_human_action(
            group_id,
            context,
            "succeeded",
            audit_message_ids_from_effects(effects),
            None,
            None,
        );
    }

    /// Apply the audit-logging switch to this live session by swapping the
    /// recorder in place: a file-backed recorder when `enabled`, or a no-op
    /// recorder when off. Dropping the prior recorder flushes and closes any
    /// file it held, so no session reopen is required.
    pub(crate) fn set_audit_recording(&mut self, enabled: bool) {
        let recorder = self.app.build_audit_recorder(&self.state.label, enabled);
        self.runtime.session_mut().set_audit_recorder(recorder);
    }

    /// Switch the audit data mode on this live session in place. A file-backed
    /// recorder rotates so the file carries a single mode and writes an
    /// `audit_data_mode_changed` boundary row; a no-op recorder (audit logging
    /// off) ignores it. Best-effort: a rotation IO failure is logged and
    /// swallowed so a settings change never breaks the worker.
    pub(crate) fn set_audit_data_mode(&self, mode: marmot_forensics::AuditDataMode, reason: &str) {
        if let Err(e) = self.runtime.session().set_audit_data_mode(mode, reason) {
            tracing::warn!(
                target: "marmot_app",
                method = "set_audit_data_mode",
                error = %e,
                "failed to switch audit data mode on live session; continuing"
            );
        }
    }

    /// Rotate the live forensic recorder iff it is the one appending to
    /// `path`, returning whether a rotation happened.
    ///
    /// Returns `true` only when this session holds a file-backed recorder
    /// writing exactly `path`: in that case the recorder deletes the file and
    /// reopens a fresh one, so the held handle is never orphaned and recording
    /// continues. Returns `false` when no recorder is installed (audit logging
    /// off) or it appends elsewhere (e.g. a stale file with a different engine
    /// id), leaving the caller to delete `path` directly.
    pub(crate) fn rotate_audit_log_if_active(
        &self,
        path: &std::path::Path,
    ) -> Result<bool, AppError> {
        if self.runtime.session().audit_log_path().as_deref() == Some(path) {
            self.runtime.session().rotate_audit_log()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn audit_observed_group_event(
        &self,
        event: &cgka_traits::engine::GroupEvent,
        previous: Option<&AppGroupRecord>,
        updated: Option<&AppGroupRecord>,
        source_message_id_hex: &str,
    ) {
        match event {
            cgka_traits::engine::GroupEvent::GroupCreated { group_id } => {
                self.record_observed_human_action(
                    group_id,
                    ObservedHumanActionAudit::source(
                        "create_group",
                        vec!["membership"],
                        Vec::new(),
                        source_message_id_hex,
                    )
                    .with_target_count(1),
                );
            }
            cgka_traits::engine::GroupEvent::GroupJoined {
                group_id,
                via_welcome,
                ..
            } => {
                self.record_observed_human_action(
                    group_id,
                    ObservedHumanActionAudit::messages(
                        "group_joined",
                        vec!["membership"],
                        Vec::new(),
                        vec![hex::encode(via_welcome.as_slice())],
                    )
                    .with_target_count(1),
                );
            }
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                group_id, change, ..
            } => {
                // Keep a self-leave distinct from a moderator removal so the
                // audit trail preserves the split that GroupStateChanged makes.
                let membership_action = match change {
                    cgka_traits::engine::GroupStateChange::MemberAdded { .. } => {
                        Some(("invite_members", "members"))
                    }
                    cgka_traits::engine::GroupStateChange::MemberRemoved { .. } => {
                        Some(("remove_members", "members"))
                    }
                    cgka_traits::engine::GroupStateChange::MemberLeft { .. } => {
                        Some(("leave_group", "membership"))
                    }
                    // Admin/profile changes are audited from the projection
                    // delta on the accompanying EpochChanged event.
                    _ => None,
                };
                if let Some((action, field)) = membership_action {
                    self.record_observed_human_action(
                        group_id,
                        ObservedHumanActionAudit::source(
                            action,
                            vec![field],
                            Vec::new(),
                            source_message_id_hex,
                        )
                        .with_target_count(1),
                    );
                }
            }
            cgka_traits::engine::GroupEvent::EpochChanged { group_id, from, to } => {
                if let (Some(previous), Some(updated)) = (previous, updated)
                    && self.audit_observed_group_projection_delta(
                        group_id,
                        previous,
                        updated,
                        source_message_id_hex,
                        Some(from.0),
                        Some(to.0),
                    )
                {
                    return;
                }
                self.record_observed_human_action(
                    group_id,
                    ObservedHumanActionAudit::source(
                        "epoch_changed",
                        Vec::new(),
                        Vec::new(),
                        source_message_id_hex,
                    )
                    .with_epoch_range(Some(from.0), Some(to.0)),
                );
            }
            _ => {}
        }
    }

    fn audit_observed_group_projection_delta(
        &self,
        group_id: &GroupId,
        previous: &AppGroupRecord,
        updated: &AppGroupRecord,
        source_message_id_hex: &str,
        from_epoch: Option<u64>,
        to_epoch: Option<u64>,
    ) -> bool {
        let mut recorded = false;
        let mut profile_fields = Vec::new();
        if previous.profile.name != updated.profile.name {
            profile_fields.push("name");
        }
        if previous.profile.description != updated.profile.description {
            profile_fields.push("description");
        }
        if !profile_fields.is_empty() {
            self.record_observed_human_action(
                group_id,
                ObservedHumanActionAudit::source(
                    "update_group_profile",
                    profile_fields,
                    vec![GROUP_PROFILE_COMPONENT_ID],
                    source_message_id_hex,
                )
                .with_epoch_range(from_epoch, to_epoch),
            );
            recorded = true;
        }
        if previous.admin_policy.admins != updated.admin_policy.admins {
            let action = match updated
                .admin_policy
                .admins
                .len()
                .cmp(&previous.admin_policy.admins.len())
            {
                std::cmp::Ordering::Greater => "promote_admin",
                std::cmp::Ordering::Less => "demote_admin",
                std::cmp::Ordering::Equal => "update_admin_policy",
            };
            let delta = previous
                .admin_policy
                .admins
                .len()
                .abs_diff(updated.admin_policy.admins.len());
            self.record_observed_human_action(
                group_id,
                ObservedHumanActionAudit::source(
                    action,
                    vec!["admins"],
                    vec![GROUP_ADMIN_POLICY_COMPONENT_ID],
                    source_message_id_hex,
                )
                .with_target_count(delta.max(1) as u64)
                .with_epoch_range(from_epoch, to_epoch),
            );
            recorded = true;
        }
        if previous.message_retention.data_hex != updated.message_retention.data_hex {
            self.record_observed_human_action(
                group_id,
                ObservedHumanActionAudit::source(
                    "update_message_retention",
                    vec!["message_retention"],
                    vec![GROUP_MESSAGE_RETENTION_COMPONENT_ID],
                    source_message_id_hex,
                )
                .with_epoch_range(from_epoch, to_epoch),
            );
            recorded = true;
        }
        if previous.avatar_url.data_hex != updated.avatar_url.data_hex {
            self.record_observed_human_action(
                group_id,
                ObservedHumanActionAudit::source(
                    "update_group_avatar_url",
                    vec!["avatar_url"],
                    vec![GROUP_AVATAR_URL_COMPONENT_ID],
                    source_message_id_hex,
                )
                .with_epoch_range(from_epoch, to_epoch),
            );
            recorded = true;
        }
        if previous.image.data_hex != updated.image.data_hex {
            self.record_observed_human_action(
                group_id,
                ObservedHumanActionAudit::source(
                    "update_group_image",
                    vec!["image"],
                    vec![GROUP_BLOSSOM_IMAGE_COMPONENT_ID],
                    source_message_id_hex,
                )
                .with_epoch_range(from_epoch, to_epoch),
            );
            recorded = true;
        }
        if previous.encrypted_media.data_hex != updated.encrypted_media.data_hex {
            self.record_observed_human_action(
                group_id,
                ObservedHumanActionAudit::source(
                    "replace_encrypted_media_blob_endpoints",
                    vec!["encrypted_media"],
                    vec![GROUP_ENCRYPTED_MEDIA_COMPONENT_ID],
                    source_message_id_hex,
                )
                .with_target_count(updated.encrypted_media.default_blob_endpoints.len() as u64)
                .with_epoch_range(from_epoch, to_epoch),
            );
            recorded = true;
        }
        recorded
    }

    fn record_observed_human_action(&self, group_id: &GroupId, audit: ObservedHumanActionAudit) {
        let context = Self::observed_human_action_context(
            audit.action,
            audit.fields,
            audit.component_ids,
            audit.target_count,
        );
        self.record_human_action(
            group_id,
            &context,
            "observed",
            audit.message_ids,
            audit.from_epoch,
            audit.to_epoch,
        );
    }
}

fn audit_message_ids_from_effects(effects: &marmot_account::AccountDeviceEffects) -> Vec<String> {
    effects
        .reports
        .iter()
        .map(|report| hex::encode(report.message_id.as_slice()))
        .collect()
}

/// Keep only message ids that satisfy the forensic schema's `messageId`
/// contract: a 64-character lowercase-or-uppercase hex digest (the SHA-256 of
/// the MLS content bytes). Locally-originated events (drained session events,
/// scheduled convergence) carry no inbound transport message, so their
/// synthetic source id is an empty string; left in place that produced a
/// `"message_ids": [""]` row that the analyzer rejects ("must be a list of 64
/// hex characters"). Dropping non-conforming entries yields an empty vec, which
/// `skip_serializing_if = "Vec::is_empty"` omits from the row entirely — the
/// schema-valid representation of "no source message id".
fn schema_valid_message_ids(message_ids: Vec<String>) -> Vec<String> {
    message_ids
        .into_iter()
        .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::schema_valid_message_ids;

    const VALID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn drops_empty_synthetic_source_id() {
        // Locally-originated events (drain / convergence) feed an empty source
        // id; it must not survive into the row as `[""]`.
        assert!(schema_valid_message_ids(vec![String::new()]).is_empty());
    }

    #[test]
    fn keeps_valid_64_hex_digests_and_drops_malformed() {
        let upper = VALID.to_uppercase();
        let ids = vec![
            VALID.to_string(),    // valid lowercase
            upper.clone(),        // valid uppercase
            String::new(),        // empty
            "abc".to_string(),    // too short
            format!("{VALID}00"), // too long
            "z".repeat(64),       // right length, non-hex
        ];
        assert_eq!(
            schema_valid_message_ids(ids),
            vec![VALID.to_string(), upper]
        );
    }
}
