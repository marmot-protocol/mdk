use cgka_traits::GroupId;
use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent as MarmotInnerEvent};

use crate::groups::{EventGroupProjection, GroupConfirmationProjection, add_group};
use crate::{
    AppAgentTextStreamComponent, AppError, AppGroupAdminPolicyComponent,
    AppGroupAvatarUrlComponent, AppGroupEncryptedMediaComponent, AppGroupImageInput,
    AppGroupMessageRetentionComponent, AppGroupNostrRoutingComponent, AppGroupRecord,
    AppMessageProjection, SecureDeleteExpiredResult, unix_now_seconds,
};

use super::AppClient;

impl AppClient {
    pub(crate) fn record_local_app_event_projection(
        &self,
        group_id_hex: &str,
        sender: &str,
        event: &MarmotInnerEvent,
        source_message_id_hex: Option<String>,
        source_epoch: Option<u64>,
    ) -> Result<crate::AppProjectionUpdate, AppError> {
        let message_projection = AppMessageProjection {
            message_id_hex: event.id.clone(),
            source_message_id_hex,
            direction: "sent".to_owned(),
            group_id_hex: group_id_hex.to_owned(),
            sender: sender.to_owned(),
            plaintext: event.content.clone(),
            kind: event.kind,
            tags: event.tags.clone(),
            source_epoch,
            recorded_at: Some(event.created_at),
            // Only synthesized kind-1210 system rows carry an origin commit;
            // ordinary sent app events do not.
            origin_commit_id: None,
        };
        let update = self
            .app
            .record_account_app_event(&self.state.label, &message_projection)?;
        if event.kind == MARMOT_APP_EVENT_KIND_CHAT {
            let read_marker =
                self.app
                    .mark_timeline_message_read(&self.state.label, group_id_hex, &event.id);
            if let Err(err) = read_marker {
                let error_code = read_marker_error_code(&err);
                tracing::warn!(
                    target: "marmot_app::messages",
                    method = "record_local_app_event_projection",
                    error_code = %error_code,
                    "local read marker update skipped after local send projection",
                );
            }
        }
        Ok(update)
    }

    pub(crate) fn state_group_record(&self, group_id: &GroupId) -> Option<AppGroupRecord> {
        let group_id_hex = hex::encode(group_id.as_slice());
        self.state
            .groups
            .iter()
            .find(|group| group.group_id_hex == group_id_hex)
            .cloned()
    }

    pub(crate) fn refresh_group(&mut self, group_id: &GroupId) {
        let group_metadata = self.runtime.group_record(group_id).ok();
        let Ok(nostr_routing) = self.nostr_routing_for_group(group_id) else {
            return;
        };
        let projection = EventGroupProjection {
            nostr_routing,
            group_metadata: group_metadata.as_ref(),
            admin_policy: self.admin_policy_for_group(group_id),
            message_retention: self.message_retention_for_group(group_id),
            agent_text_stream: self.agent_text_stream_for_group(group_id),
            avatar_url: self.avatar_url_for_group(group_id),
            encrypted_media: self.encrypted_media_for_group(group_id),
            image: self.image_for_group(group_id),
        };
        add_group(
            &mut self.state,
            group_id,
            &projection,
            GroupConfirmationProjection::Preserve,
        );
    }

    pub(crate) fn add_group(&mut self, group_id: &GroupId) -> Result<(), AppError> {
        let group_metadata = self.runtime.group_record(group_id).ok();
        let nostr_routing = self.nostr_routing_for_group(group_id)?;
        let subscription = nostr_routing.subscription(group_id)?;
        let projection = EventGroupProjection {
            nostr_routing,
            group_metadata: group_metadata.as_ref(),
            admin_policy: self.admin_policy_for_group(group_id),
            message_retention: self.message_retention_for_group(group_id),
            agent_text_stream: self.agent_text_stream_for_group(group_id),
            avatar_url: self.avatar_url_for_group(group_id),
            encrypted_media: self.encrypted_media_for_group(group_id),
            image: self.image_for_group(group_id),
        };
        add_group(
            &mut self.state,
            group_id,
            &projection,
            GroupConfirmationProjection::Accepted,
        );
        self.routing.add_group(subscription);
        Ok(())
    }

    pub(crate) fn admin_policy_for_group(
        &self,
        group_id: &GroupId,
    ) -> AppGroupAdminPolicyComponent {
        self.runtime
            .admin_pubkeys(group_id)
            .map(AppGroupAdminPolicyComponent::new)
            .unwrap_or_else(|_| AppGroupAdminPolicyComponent::new(Vec::new()))
    }

    pub(crate) fn message_retention_for_group(
        &self,
        group_id: &GroupId,
    ) -> AppGroupMessageRetentionComponent {
        self.runtime
            .app_component(group_id, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .ok()
            .flatten()
            .map(|bytes| AppGroupMessageRetentionComponent::from_bytes(&bytes))
            .unwrap_or_else(AppGroupMessageRetentionComponent::disabled)
    }

    pub(crate) fn prune_plaintext_retention_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<(), AppError> {
        self.secure_delete_expired_plaintext_for_group(group_id)
            .map(|_| ())
    }

    pub fn secure_delete_expired_plaintext_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<SecureDeleteExpiredResult, AppError> {
        let retention = self.message_retention_for_group(group_id);
        if retention.disappearing_message_secs == 0 {
            return Ok(SecureDeleteExpiredResult::default());
        }
        let cutoff = unix_now_seconds().saturating_sub(retention.disappearing_message_secs);
        self.app.secure_prune_account_app_events_before(
            &self.state.label,
            &hex::encode(group_id.as_slice()),
            cutoff,
        )
    }

    pub(crate) fn agent_text_stream_for_group(
        &self,
        group_id: &GroupId,
    ) -> AppAgentTextStreamComponent {
        self.runtime
            .app_component(group_id, AGENT_TEXT_STREAM_QUIC_COMPONENT_ID)
            .ok()
            .flatten()
            .map(|bytes| AppAgentTextStreamComponent::from_bytes(&bytes))
            .unwrap_or_else(AppAgentTextStreamComponent::disabled)
    }

    pub(crate) fn avatar_url_for_group(&self, group_id: &GroupId) -> AppGroupAvatarUrlComponent {
        self.runtime
            .app_component(group_id, GROUP_AVATAR_URL_COMPONENT_ID)
            .ok()
            .flatten()
            .map(|bytes| AppGroupAvatarUrlComponent::from_bytes(&bytes))
            .unwrap_or_else(AppGroupAvatarUrlComponent::absent)
    }

    pub(crate) fn encrypted_media_for_group(
        &self,
        group_id: &GroupId,
    ) -> AppGroupEncryptedMediaComponent {
        self.runtime
            .app_component(group_id, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID)
            .ok()
            .flatten()
            .map(|bytes| AppGroupEncryptedMediaComponent::from_bytes(&bytes))
            .unwrap_or_else(AppGroupEncryptedMediaComponent::disabled)
    }

    pub(crate) fn image_for_group(&self, group_id: &GroupId) -> AppGroupImageInput {
        self.runtime
            .app_component(group_id, GROUP_BLOSSOM_IMAGE_COMPONENT_ID)
            .ok()
            .flatten()
            .and_then(|bytes| AppGroupImageInput::from_component_bytes(&bytes))
            .unwrap_or_default()
    }

    /// Persist and queue kind-1210 system rows for our own authenticated commits.
    /// Call only after the caller's final fallible persistence step succeeds so
    /// failed commands do not leave stale buffered timeline updates.
    pub(crate) fn queue_own_group_system_projection_updates(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) {
        // Gate on having published a commit: own send paths always carry a
        // report, while reportless paths (e.g. convergence retry) re-emit the
        // same changes unattributed. Those are already synthesized — attributed —
        // on the inbound path, so skipping here avoids a duplicate, actor-less row.
        if effects.reports.is_empty() {
            return;
        }
        self.pending_projection_updates
            .extend(self.project_group_system_rows(&effects.events, unix_now_seconds()));
    }

    pub(crate) fn take_pending_projection_updates(&mut self) -> Vec<crate::AppProjectionUpdate> {
        std::mem::take(&mut self.pending_projection_updates)
    }

    /// Synthesize a durable kind-1210 group system row for each
    /// `GroupStateChanged` event and persist it to the timeline. Used by both
    /// the inbound delivery path (peer commits) and our own send path (local
    /// commits). Failures are logged, not propagated: a missing system row must
    /// never fail message delivery.
    pub(crate) fn project_group_system_rows(
        &self,
        events: &[cgka_traits::engine::GroupEvent],
        recorded_at: u64,
    ) -> Vec<crate::AppProjectionUpdate> {
        let mut updates = Vec::new();
        for event in events {
            if let cgka_traits::engine::GroupEvent::GroupStateChanged {
                group_id,
                epoch,
                actor,
                change,
                origin_commit_id,
            } = event
            {
                let projection = match build_group_system_projection(
                    group_id,
                    epoch.0,
                    actor.as_ref(),
                    change,
                    recorded_at,
                    origin_commit_id
                        .as_ref()
                        .map(|id| hex::encode(id.as_slice())),
                ) {
                    Ok(projection) => projection,
                    Err(_err) => {
                        tracing::warn!(
                            target: "marmot_app::groups",
                            method = "project_group_system_rows",
                            error_code = "projection_build_failed",
                            "failed to build group system row",
                        );
                        continue;
                    }
                };
                match self
                    .app
                    .record_account_app_event(&self.state.label, &projection)
                {
                    Ok(update) => updates.push(update),
                    Err(_err) => {
                        tracing::warn!(
                            target: "marmot_app::groups",
                            method = "project_group_system_rows",
                            error_code = "projection_apply_failed",
                            "failed to project group system row",
                        );
                    }
                }
            }
        }
        updates
    }

    pub(crate) fn nostr_routing_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<AppGroupNostrRoutingComponent, AppError> {
        let bytes = self
            .runtime
            .app_component(group_id, NOSTR_ROUTING_COMPONENT_ID)?
            .ok_or_else(|| {
                AppError::InvalidNostrRouting(
                    "group is missing marmot.transport.nostr.routing.v1".into(),
                )
            })?;
        AppGroupNostrRoutingComponent::from_bytes(&bytes)
    }
}

/// Build the durable kind-1210 group system row projection for one
/// authenticated [`GroupStateChange`]. The row is synthesized locally
/// (Approach A) — no kind-1210 message is sent on the wire. The message id is
/// deterministic over (actor, epoch, system_type, content) so re-processing the
/// same change upserts instead of duplicating. The row carries a null
/// `source_message_id_hex` (one commit can synthesize several rows, which would
/// collide on the partial unique source index); instead `origin_commit_id`
/// links the row back to the commit that produced it, so losing-branch fork
/// recovery can invalidate every row derived from a rolled-back commit (1:N).
fn build_group_system_projection(
    group_id: &cgka_traits::types::GroupId,
    epoch: u64,
    actor: Option<&cgka_traits::types::MemberId>,
    change: &cgka_traits::engine::GroupStateChange,
    recorded_at: u64,
    origin_commit_id: Option<String>,
) -> Result<AppMessageProjection, cgka_traits::app_event::MarmotAppEventError> {
    use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_GROUP_SYSTEM, group_system_event_material};

    let material = group_system_event_material(group_id, epoch, actor, change)?;

    Ok(AppMessageProjection {
        message_id_hex: material.message_id_hex,
        // Synthesized rows carry no source: several rows can come from one
        // commit, which would collide on the partial unique source index, and
        // commit ids are never targeted by source-based invalidation anyway.
        source_message_id_hex: None,
        direction: "system".to_owned(),
        group_id_hex: material.group_id_hex,
        sender: material.sender,
        plaintext: material.content,
        kind: MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        tags: material.tags,
        source_epoch: Some(epoch),
        recorded_at: Some(recorded_at),
        // Non-unique link to the origin commit so a losing-branch rollback can
        // invalidate every row this commit synthesized (1:N).
        origin_commit_id,
    })
}

fn read_marker_error_code(error: &AppError) -> &'static str {
    match error {
        AppError::Account(_) => "read_marker_failed:account",
        AppError::AccountHome(_) => "read_marker_failed:account_home",
        AppError::Session(_) => "read_marker_failed:session",
        AppError::Storage(_) => "read_marker_failed:storage",
        AppError::Transport(_) => "read_marker_failed:transport",
        AppError::Io(_) => "read_marker_failed:io",
        AppError::Json(_) => "read_marker_failed:json",
        AppError::Sqlite(_) => "read_marker_failed:sqlite",
        AppError::Hex(_) => "read_marker_failed:hex",
        AppError::MissingKeyPackage(_) => "read_marker_failed:missing_key_package",
        AppError::UnknownGroup(_) => "read_marker_failed:unknown_group",
        AppError::AgentStreamMissingStart => "read_marker_failed:agent_stream_missing_start",
        AppError::AgentStreamStartNotConfirmed => {
            "read_marker_failed:agent_stream_start_not_confirmed"
        }
        AppError::AgentStreamUnsupportedRoute => {
            "read_marker_failed:agent_stream_unsupported_route"
        }
        AppError::AgentStreamMissingCandidate => {
            "read_marker_failed:agent_stream_missing_candidate"
        }
        AppError::AgentStreamInvalidCandidate(_) => {
            "read_marker_failed:agent_stream_invalid_candidate"
        }
        AppError::Publish(_) => "read_marker_failed:publish",
        AppError::MissingDefaultRelays => "read_marker_failed:missing_default_relays",
        AppError::MissingRelayLists(_) => "read_marker_failed:missing_relay_lists",
        AppError::RelayDirectory(_) => "read_marker_failed:relay_directory",
        AppError::InvalidPublicKey => "read_marker_failed:invalid_public_key",
        AppError::InvalidKeyPackageEvent(_) => "read_marker_failed:invalid_key_package_event",
        AppError::MissingDirectoryEntry(_) => "read_marker_failed:missing_directory_entry",
        AppError::InvalidDirectorySearch(_) => "read_marker_failed:invalid_directory_search",
        AppError::InvalidGroupProfile(_) => "read_marker_failed:invalid_group_profile",
        AppError::InvalidNostrRouting(_) => "read_marker_failed:invalid_nostr_routing",
        AppError::InvalidGroupAvatarUrl(_) => "read_marker_failed:invalid_group_avatar_url",
        AppError::InvalidAgentTextStreamPolicy(_) => {
            "read_marker_failed:invalid_agent_text_stream_policy"
        }
        AppError::InvalidEncryptedMedia(_) => "read_marker_failed:invalid_encrypted_media",
        AppError::BlobStore(_) => "read_marker_failed:blob_store",
        AppError::InvalidAppMessagePayload(_) => "read_marker_failed:invalid_app_message_payload",
        AppError::InvalidPushToken(_) => "read_marker_failed:invalid_push_token",
        AppError::InvalidPushServer(_) => "read_marker_failed:invalid_push_server",
        AppError::InvalidPushGossip(_) => "read_marker_failed:invalid_push_gossip",
        AppError::InvalidRelayTelemetrySettings(_) => {
            "read_marker_failed:invalid_relay_telemetry_settings"
        }
        AppError::InvalidAuditLogFile(_) => "read_marker_failed:invalid_audit_log_file",
        AppError::AuditLogUpload(_) => "read_marker_failed:audit_log_upload",
        AppError::NotificationsDisabled => "read_marker_failed:notifications_disabled",
        AppError::SqlcipherKeyDerivation(_) => "read_marker_failed:sqlcipher_key_derivation",
        AppError::BlockingTask(_) => "read_marker_failed:blocking_task",
        AppError::RuntimeStopping => "read_marker_failed:runtime_stopping",
        AppError::ReactionNotFound => "read_marker_failed:reaction_not_found",
        AppError::TransportClosed => "read_marker_failed:transport_closed",
    }
}
