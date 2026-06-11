use std::collections::{HashMap, HashSet};

use cgka_engine::key_package::is_last_resort_key_package;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY, AgentTextStreamQuicPolicyV1,
};
use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, AppComponentData, BlobStoreEndpointV1,
    ENCRYPTED_MEDIA_FORMAT_V1, EncryptedMediaPolicyV1, GROUP_ADMIN_POLICY_COMPONENT_ID,
    GROUP_AVATAR_URL_COMPONENT_ID, GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID,
    encode_nostr_routing_v1,
};
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_REACTION,
    MarmotAppEvent as MarmotInnerEvent,
};
use cgka_traits::engine::{CreateGroupRequest, KeyPackage, SendIntent};
use cgka_traits::{GroupId, SecretBytes, TransportAdapter, TransportEndpoint};
use marmot_forensics::{AuditEventContext, AuditEventKind, AuditHumanActionContext};
use tokio::time::timeout;
use transport_nostr_peeler::NostrTransportEvent;

use crate::groups::{
    EventGroupProjection, GroupConfirmationProjection, add_group, event_group_id,
    fail_if_publish_failed, observe_event, send_summary_from_effects, validate_group_profile,
};
use crate::ids::{admin_pubkey_from_account_id_hex, admin_pubkey_from_member_id};
use crate::media::{
    DEFAULT_BLOSSOM_SERVER_URL, download_encrypted_media, fetch_group_image,
    media_imeta_tags_are_valid, upload_encrypted_media, upload_group_image,
};
use crate::messages::{AppMessageIntent, build_inner_event, encode_inner_event, tag_value};
use crate::notifications;
use crate::{
    AccountState, AgentOperationEventRequest, AgentTextStreamFinishRequest,
    AppAgentTextStreamComponent, AppBlobEndpoint, AppError, AppGroupAdminPolicyComponent,
    AppGroupAvatarUrlComponent, AppGroupEncryptedMediaComponent, AppGroupImageComponent,
    AppGroupImageInput, AppGroupMemberRecord, AppGroupMessageRetentionComponent, AppGroupMlsState,
    AppGroupNostrRoutingComponent, AppGroupRecord, AppMessageProjection, AppMessageQuery,
    AppRuntime, AppTransportRouting, GroupInviteDeclineResult, MarmotApp, MarmotRelayPlane,
    MarmotRelayPlaneAccountAdapter, MediaAttachmentReference, MediaDownloadResult,
    MediaUploadRequest, MediaUploadResult, SDK_DRAIN_WAIT, SDK_FIRST_SYNC_WAIT, SendSummary,
    SyncSummary, refresh_seen_lookup_if_needed, remember_seen_event, unix_now_seconds,
};
pub struct AppClient {
    pub(crate) app: MarmotApp,
    pub(crate) runtime: AppRuntime,
    pub(crate) adapter: MarmotRelayPlaneAccountAdapter,
    pub(crate) routing: AppTransportRouting,
    pub(crate) relay_plane: MarmotRelayPlane,
    pub(crate) state: AccountState,
    /// Group-system timeline rows synthesized during the most recent publish
    /// path. The runtime account worker drains this after each command and
    /// broadcasts `ProjectionUpdated` so live timeline subscriptions refresh.
    pub(crate) pending_projection_updates: Vec<crate::AppProjectionUpdate>,
}

struct ObservedHumanActionAudit {
    action: &'static str,
    fields: Vec<&'static str>,
    component_ids: Vec<u16>,
    target_count: Option<u64>,
    message_ids: Vec<String>,
    from_epoch: Option<u64>,
    to_epoch: Option<u64>,
}

impl ObservedHumanActionAudit {
    fn source(
        action: &'static str,
        fields: Vec<&'static str>,
        component_ids: Vec<u16>,
        source_message_id_hex: &str,
    ) -> Self {
        Self {
            action,
            fields,
            component_ids,
            target_count: None,
            message_ids: vec![source_message_id_hex.to_string()],
            from_epoch: None,
            to_epoch: None,
        }
    }

    fn messages(
        action: &'static str,
        fields: Vec<&'static str>,
        component_ids: Vec<u16>,
        message_ids: Vec<String>,
    ) -> Self {
        Self {
            action,
            fields,
            component_ids,
            target_count: None,
            message_ids,
            from_epoch: None,
            to_epoch: None,
        }
    }

    fn with_target_count(mut self, target_count: u64) -> Self {
        self.target_count = Some(target_count);
        self
    }

    fn with_epoch_range(mut self, from_epoch: Option<u64>, to_epoch: Option<u64>) -> Self {
        self.from_epoch = from_epoch;
        self.to_epoch = to_epoch;
        self
    }
}

impl AppClient {
    fn local_human_action_context(
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
    fn message_human_action_context(intent: &AppMessageIntent) -> Option<AuditEventContext> {
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
                message_ids,
                from_epoch,
                to_epoch,
                error_kind: None,
                detail: None,
            },
        );
    }

    fn record_human_action_succeeded(
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

    async fn sync_runtime_groups(&self) -> Result<(), AppError> {
        let rebuild_since = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp);
        self.cache_current_encrypted_media_epoch_secrets();
        self.runtime.sync_transport_groups(rebuild_since).await?;
        self.cache_current_encrypted_media_epoch_secrets();
        Ok(())
    }

    pub async fn publish_key_package(&mut self) -> Result<KeyPackage, AppError> {
        self.app
            .ensure_local_account_relay_lists(&self.state.label)
            .await?;
        self.refresh_routing()?;
        self.runtime.activate_transport(None).await?;
        match self.app.latest_key_package(&self.state.label) {
            Ok(key_package) if is_last_resort_key_package(&key_package).unwrap_or(false) => {
                self.app
                    .publish_cached_key_package(&self.state.label, key_package)
                    .await
            }
            Ok(_) => Ok(self.runtime.publish_fresh_key_package().await?),
            Err(AppError::MissingKeyPackage(_)) => {
                Ok(self.runtime.publish_fresh_key_package().await?)
            }
            Err(err) => Err(err),
        }
    }

    pub async fn rotate_key_package(&mut self) -> Result<KeyPackage, AppError> {
        self.app
            .ensure_local_account_relay_lists(&self.state.label)
            .await?;
        self.refresh_routing()?;
        self.runtime.activate_transport(None).await?;
        Ok(self.runtime.publish_fresh_key_package().await?)
    }

    pub async fn create_group(
        &mut self,
        name: &str,
        member_refs: &[&str],
    ) -> Result<GroupId, AppError> {
        validate_group_profile(name, "")?;
        let mut members = Vec::with_capacity(member_refs.len());
        for member in member_refs {
            members.push(self.app.member_key_package(member).await?);
        }
        self.refresh_routing()?;
        let nostr_routing = self.app.new_nostr_routing()?;
        let nostr_routing_bytes =
            encode_nostr_routing_v1(&nostr_routing).map_err(AppError::InvalidNostrRouting)?;
        let mut app_components = vec![AppComponentData {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            data: nostr_routing_bytes,
        }];
        app_components.push(
            AgentTextStreamQuicPolicyV1::user_to_agent_default()
                .to_app_component_data()
                .map_err(|err| AppError::InvalidAgentTextStreamPolicy(err.to_string()))?,
        );
        app_components.push(self.encrypted_media_component_for_new_group()?);
        let audit_context = Self::local_human_action_context(
            "create_group",
            vec!["name", "members"],
            vec![
                NOSTR_ROUTING_COMPONENT_ID,
                AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
                GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
            ],
            Some(member_refs.len() as u64),
        );

        let (group_id, effects) = self
            .runtime
            .create_group_with_audit_context(
                CreateGroupRequest {
                    name: name.to_owned(),
                    description: String::new(),
                    members,
                    required_features: Vec::new(),
                    app_components,
                    initial_admins: Vec::new(),
                },
                audit_context.clone(),
            )
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.record_human_action_succeeded(&group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.add_group(&group_id)?;
        self.sync_runtime_groups().await?;
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(group_id)
    }

    pub fn members(&self, group_id: &GroupId) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        self.ensure_group(group_id)?;
        let profiles = self.app.profiles_by_id()?;
        Ok(self
            .runtime
            .members(group_id)?
            .into_iter()
            .map(|member| {
                let member_id_hex = hex::encode(member.id.as_slice());
                let account = profiles.get(&member_id_hex).cloned();
                AppGroupMemberRecord {
                    member_id_hex,
                    local: account.is_some(),
                    account,
                }
            })
            .collect())
    }

    pub fn group_mls_state(&self, group_id: &GroupId) -> Result<AppGroupMlsState, AppError> {
        self.ensure_group(group_id)?;
        let group = self.runtime.group_record(group_id)?;
        Ok(AppGroupMlsState {
            group_id_hex: hex::encode(group_id.as_slice()),
            epoch: group.epoch.0,
            member_count: group.members.len(),
            required_app_components: group
                .required_capabilities
                .app_components
                .ids
                .iter()
                .copied()
                .collect(),
        })
    }

    pub fn safe_export_secret(
        &mut self,
        group_id: &GroupId,
        component_id: cgka_traits::AppComponentId,
    ) -> Result<SecretBytes, AppError> {
        self.ensure_group(group_id)?;
        Ok(self.runtime.safe_export_secret(group_id, component_id)?)
    }

    pub fn agent_text_stream_exporter_secret(
        &self,
        group_id: &GroupId,
    ) -> Result<SecretBytes, AppError> {
        self.exporter_secret(group_id, AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY, 32)
    }

    pub(crate) fn exporter_secret(
        &self,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> Result<SecretBytes, AppError> {
        self.ensure_group(group_id)?;
        Ok(self.runtime.exporter_secret(group_id, label, length)?)
    }

    pub async fn invite_members(
        &mut self,
        group_id: &GroupId,
        member_refs: &[&str],
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let mut key_packages = Vec::with_capacity(member_refs.len());
        for member in member_refs {
            key_packages.push(self.app.member_key_package(member).await?);
        }
        self.refresh_routing()?;
        let audit_context = Self::local_human_action_context(
            "invite_members",
            vec!["members"],
            Vec::new(),
            Some(member_refs.len() as u64),
        );

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::Invite {
                    group_id: group_id.clone(),
                    key_packages,
                },
                audit_context.clone(),
            )
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.prune_plaintext_retention_for_group(group_id)?;
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        let summary = send_summary_from_effects(&effects);
        self.publish_notification_trigger_best_effort(
            group_id,
            notifications::NotificationTrigger::GroupInvite,
        )
        .await;
        Ok(summary)
    }

    pub async fn remove_members(
        &mut self,
        group_id: &GroupId,
        member_refs: &[&str],
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let mut members = Vec::with_capacity(member_refs.len());
        for member in member_refs {
            members.push(self.app.member_id(member)?);
        }
        let audit_context = Self::local_human_action_context(
            "remove_members",
            vec!["members"],
            Vec::new(),
            Some(member_refs.len() as u64),
        );

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::RemoveMembers {
                    group_id: group_id.clone(),
                    members,
                },
                audit_context.clone(),
            )
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.cleanup_stale_push_tokens_best_effort(group_id);
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn leave_group(&mut self, group_id: &GroupId) -> Result<SendSummary, AppError> {
        let audit_context = Self::local_human_action_context(
            "leave_group",
            vec!["membership"],
            Vec::new(),
            Some(1),
        );
        self.leave_group_with_audit_context(group_id, audit_context)
            .await
    }

    async fn leave_group_with_audit_context(
        &mut self,
        group_id: &GroupId,
        audit_context: AuditEventContext,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::Leave {
                    group_id: group_id.clone(),
                },
                audit_context.clone(),
            )
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(send_summary_from_effects(&effects))
    }

    pub fn accept_group_invite(&mut self, group_id: &GroupId) -> Result<AppGroupRecord, AppError> {
        self.set_group_invite_confirmation(group_id, false, false)
    }

    pub async fn decline_group_invite(
        &mut self,
        group_id: &GroupId,
    ) -> Result<GroupInviteDeclineResult, AppError> {
        let audit_context = Self::local_human_action_context(
            "decline_group_invite",
            vec!["membership"],
            Vec::new(),
            Some(1),
        );
        let summary = self
            .leave_group_with_audit_context(group_id, audit_context)
            .await?;
        let group = self.set_group_invite_confirmation(group_id, false, true)?;
        Ok(GroupInviteDeclineResult { group, summary })
    }

    pub async fn promote_admin(
        &mut self,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let mut admins = self.runtime.admin_pubkeys(group_id)?;
        admins.push(admin_pubkey_from_member_id(
            &self.app.member_id(member_ref)?,
        )?);
        let audit_context = Self::local_human_action_context(
            "promote_admin",
            vec!["admins"],
            vec![GROUP_ADMIN_POLICY_COMPONENT_ID],
            Some(1),
        );
        self.update_admin_policy(group_id, admins, audit_context)
            .await
    }

    pub async fn demote_admin(
        &mut self,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let target = admin_pubkey_from_member_id(&self.app.member_id(member_ref)?)?;
        let mut admins = self.runtime.admin_pubkeys(group_id)?;
        admins.retain(|admin| admin != &target);
        let audit_context = Self::local_human_action_context(
            "demote_admin",
            vec!["admins"],
            vec![GROUP_ADMIN_POLICY_COMPONENT_ID],
            Some(1),
        );
        self.update_admin_policy(group_id, admins, audit_context)
            .await
    }

    pub async fn self_demote_admin(&mut self, group_id: &GroupId) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let account = self.app.account_home().account(&self.state.label)?;
        let local = admin_pubkey_from_account_id_hex(&account.account_id_hex)?;
        let mut admins = self.runtime.admin_pubkeys(group_id)?;
        admins.retain(|admin| admin != &local);
        let audit_context = Self::local_human_action_context(
            "self_demote_admin",
            vec!["admins"],
            vec![GROUP_ADMIN_POLICY_COMPONENT_ID],
            Some(1),
        );
        self.update_admin_policy(group_id, admins, audit_context)
            .await
    }

    async fn update_admin_policy(
        &mut self,
        group_id: &GroupId,
        admins: Vec<[u8; 32]>,
        audit_context: AuditEventContext,
    ) -> Result<SendSummary, AppError> {
        let component = AppGroupAdminPolicyComponent::new(admins).to_app_component_data()?;

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateAppComponents {
                    group_id: group_id.clone(),
                    updates: vec![component],
                },
                audit_context.clone(),
            )
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn update_message_retention(
        &mut self,
        group_id: &GroupId,
        disappearing_message_secs: u64,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let component = AppGroupMessageRetentionComponent::new(disappearing_message_secs)
            .to_app_component_data()?;
        let audit_context = Self::local_human_action_context(
            "update_message_retention",
            vec!["message_retention"],
            vec![GROUP_MESSAGE_RETENTION_COMPONENT_ID],
            None,
        );

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateAppComponents {
                    group_id: group_id.clone(),
                    updates: vec![component],
                },
                audit_context.clone(),
            )
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.prune_plaintext_retention_for_group(group_id)?;
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn replace_encrypted_media_blob_endpoints(
        &mut self,
        group_id: &GroupId,
        endpoints: Vec<AppBlobEndpoint>,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let endpoint_count = endpoints.len() as u64;
        let mut allowed_locator_kinds = Vec::new();
        for endpoint in &endpoints {
            if !allowed_locator_kinds
                .iter()
                .any(|kind| kind == &endpoint.locator_kind)
            {
                allowed_locator_kinds.push(endpoint.locator_kind.clone());
            }
        }
        let policy = EncryptedMediaPolicyV1::new(
            ENCRYPTED_MEDIA_FORMAT_V1.to_owned(),
            allowed_locator_kinds,
            endpoints.into_iter().map(|endpoint| BlobStoreEndpointV1 {
                locator_kind: endpoint.locator_kind,
                base_url: endpoint.base_url,
            }),
            true,
        )
        .map_err(AppError::InvalidEncryptedMedia)?;
        let component = AppGroupEncryptedMediaComponent::new(policy)?.to_app_component_data()?;
        let audit_context = Self::local_human_action_context(
            "replace_encrypted_media_blob_endpoints",
            vec!["encrypted_media"],
            vec![GROUP_ENCRYPTED_MEDIA_COMPONENT_ID],
            Some(endpoint_count),
        );

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateAppComponents {
                    group_id: group_id.clone(),
                    updates: vec![component],
                },
                audit_context.clone(),
            )
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(send_summary_from_effects(&effects))
    }

    /// Set (or clear) the group's URL-based avatar (`marmot.group.avatar-url.v1`).
    /// Passing `url = None` clears the avatar to the absent state. The URL is
    /// validated and normalized before it is committed.
    pub async fn update_group_avatar_url(
        &mut self,
        group_id: &GroupId,
        url: Option<String>,
        dim: Option<String>,
        thumbhash: Option<String>,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let component = match url {
            Some(url) if !url.is_empty() => {
                AppGroupAvatarUrlComponent::new(url, dim, thumbhash)?.to_app_component_data()?
            }
            _ => AppGroupAvatarUrlComponent::absent().to_app_component_data()?,
        };
        let audit_context = Self::local_human_action_context(
            "update_group_avatar_url",
            vec!["avatar_url"],
            vec![GROUP_AVATAR_URL_COMPONENT_ID],
            None,
        );

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateAppComponents {
                    group_id: group_id.clone(),
                    updates: vec![component],
                },
                audit_context.clone(),
            )
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn send(
        &mut self,
        group_id: &GroupId,
        payload: &[u8],
    ) -> Result<SendSummary, AppError> {
        self.send_with_local_projection(group_id, payload, |_| {})
            .await
    }

    pub(crate) async fn send_with_local_projection<F>(
        &mut self,
        group_id: &GroupId,
        payload: &[u8],
        on_local_projection: F,
    ) -> Result<SendSummary, AppError>
    where
        F: FnMut(crate::AppProjectionUpdate),
    {
        // The transport-facing `send` carries plain UTF-8 chat text; structured
        // payloads use `send_app_event` with a typed intent.
        let content = String::from_utf8(payload.to_vec()).map_err(|_| {
            AppError::InvalidAppMessagePayload("chat message must be valid UTF-8".into())
        })?;
        let (_event, summary) = self
            .send_app_event_with_local_projection(
                group_id,
                AppMessageIntent::Chat { content },
                on_local_projection,
            )
            .await?;
        Ok(summary)
    }

    /// Build, encrypt, send, and project the inner Marmot app event for `intent`.
    /// Returns the built event so callers (agent-stream start/finish) can surface
    /// its tags. The authoring account id and clock are resolved here so the
    /// inner `pubkey` always equals the MLS-authenticated sender.
    pub(crate) async fn send_app_event(
        &mut self,
        group_id: &GroupId,
        intent: AppMessageIntent,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.send_app_event_with_local_projection(group_id, intent, |_| {})
            .await
    }

    pub(crate) async fn send_app_event_with_local_projection<F>(
        &mut self,
        group_id: &GroupId,
        intent: AppMessageIntent,
        mut on_local_projection: F,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError>
    where
        F: FnMut(crate::AppProjectionUpdate),
    {
        self.ensure_group(group_id)?;
        // Capture the human-action descriptor before `Unreact` is rewritten to
        // `Delete` below, so the audit log records the user's actual intent.
        let audit_context = Self::message_human_action_context(&intent);
        let sender = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        // NIP-25 has no native un-react: a kind-7 reaction is retracted with a
        // kind-5 delete of that reaction event. Resolve the user's own reaction
        // event id from the projection before building the tombstone.
        let intent = match intent {
            AppMessageIntent::Unreact { target_message_id } => {
                let reaction_id =
                    self.own_reaction_event_id(group_id, &sender, &target_message_id)?;
                AppMessageIntent::Delete {
                    target_message_id: reaction_id,
                }
            }
            other => other,
        };
        let source_epoch = match &intent {
            AppMessageIntent::Media { attachments, .. } => attachments
                .first()
                .map(|attachment| attachment.source_epoch),
            _ => None,
        };
        let event = build_inner_event(&intent, &sender, unix_now_seconds())?;
        let payload = encode_inner_event(&event)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let app_event_id = event.id.clone();

        let should_project_locally = !notifications::is_push_gossip_kind(event.kind);
        if should_project_locally {
            let update = self.record_local_app_event_projection(
                &group_id_hex,
                &sender,
                &event,
                None,
                source_epoch,
            )?;
            on_local_projection(update);
        }

        let effects = match async {
            self.sync_runtime_groups().await?;
            let send_intent = SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload,
            };
            // Thread the human-action context through the engine so the send's
            // audit rows carry `human_action`, matching create_group/invite/etc.
            let effects = match &audit_context {
                Some(context) => {
                    self.runtime
                        .send_with_audit_context(send_intent, context.clone())
                        .await?
                }
                None => self.runtime.send(send_intent).await?,
            };
            fail_if_publish_failed(&effects.failures)?;
            Ok::<_, AppError>(effects)
        }
        .await
        {
            Ok(effects) => effects,
            Err(err) => {
                if should_project_locally {
                    match self.app.invalidate_timeline_app_event(
                        &self.state.label,
                        &app_event_id,
                        "local_publish_failed",
                    ) {
                        Ok(Some(update)) => on_local_projection(update),
                        Ok(None) => {}
                        Err(_) => {
                            tracing::warn!(
                                target: "marmot_app::messages",
                                method = "send_app_event_with_local_projection",
                                error_code = "local_projection_retract_failed",
                                "failed to retract local projection after publish failure"
                            );
                        }
                    }
                }
                return Err(err);
            }
        };
        if let Some(context) = &audit_context {
            self.record_human_action_succeeded(group_id, context, &effects);
        }
        self.remember_published_reports(&effects);
        let source_message_id_hex = effects
            .reports
            .first()
            .map(|report| hex::encode(report.message_id.as_slice()));
        if should_project_locally {
            let update = self.record_local_app_event_projection(
                &group_id_hex,
                &sender,
                &event,
                source_message_id_hex,
                source_epoch,
            )?;
            on_local_projection(update);
            self.prune_plaintext_retention_for_group(group_id)?;
        }
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        if notification_trigger_for_intent(&intent).is_some() {
            self.publish_notification_trigger_best_effort(
                group_id,
                notifications::NotificationTrigger::NewMessage,
            )
            .await;
        }
        Ok((
            event,
            SendSummary {
                published: effects.reports.len(),
                message_ids: vec![app_event_id],
            },
        ))
    }

    fn record_local_app_event_projection(
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

    /// Apply the audit-logging switch to this live session by swapping the
    /// recorder in place: a file-backed recorder when `enabled`, or a no-op
    /// recorder when off. Dropping the prior recorder flushes and closes any
    /// file it held, so no session reopen is required.
    pub(crate) fn set_audit_recording(&mut self, enabled: bool) {
        let recorder = self.app.build_audit_recorder(&self.state.label, enabled);
        self.runtime.session_mut().set_audit_recorder(recorder);
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

    pub(crate) async fn share_push_registration(&mut self) -> Result<usize, AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let settings = self.app.notification_settings(&account.label)?;
        let Some(registration) = self.app.stored_push_registration(&account.label)? else {
            return Ok(0);
        };
        if !settings.native_push_enabled {
            return Ok(0);
        }
        let mut shared = 0_usize;
        for group in self.state.groups.clone() {
            let Ok(group_id_bytes) = hex::decode(&group.group_id_hex) else {
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            let Ok((member_id_hex, leaf_index)) = self.local_member_leaf(&group_id) else {
                continue;
            };
            let (payload, record) = notifications::local_token_gossip_payload(
                group.group_id_hex.clone(),
                member_id_hex,
                leaf_index,
                &registration,
            )?;
            self.app.upsert_group_push_token(&account.label, &record)?;
            let content = serde_json::to_string(&payload)?;
            match self
                .send_app_event(&group_id, AppMessageIntent::PushTokenUpdate { content })
                .await
            {
                Ok((_event, _summary)) => shared += 1,
                Err(err) => {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "share_push_registration",
                        "push token gossip publish failed: {err}",
                    );
                }
            }
        }
        if shared > 0 {
            self.app
                .mark_push_registration_shared(&account.label, notifications::unix_now_ms())?;
        }
        Ok(shared)
    }

    pub(crate) async fn remove_push_registration(
        &mut self,
        registration: crate::PushRegistration,
    ) -> Result<usize, AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let mut removed = 0_usize;
        for group in self.state.groups.clone() {
            let Ok(group_id_bytes) = hex::decode(&group.group_id_hex) else {
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            let Ok((member_id_hex, _leaf_index)) = self.local_member_leaf(&group_id) else {
                continue;
            };
            let payload = notifications::local_token_removal_payload(member_id_hex, &registration);
            let content = serde_json::to_string(&payload)?;
            match self
                .send_app_event(&group_id, AppMessageIntent::PushTokenRemoval { content })
                .await
            {
                Ok((_event, _summary)) => removed += 1,
                Err(err) => {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "remove_push_registration",
                        "push token removal gossip publish failed: {err}",
                    );
                }
            }
            self.app.remove_group_push_tokens_for_member(
                &account.label,
                &group.group_id_hex,
                &account.account_id_hex,
            )?;
        }
        Ok(removed)
    }

    async fn publish_notification_trigger_best_effort(
        &self,
        group_id: &GroupId,
        trigger: notifications::NotificationTrigger,
    ) {
        if let Err(err) = self.publish_notification_trigger(group_id, trigger).await {
            tracing::warn!(
                target: "marmot_app::notifications",
                method = "publish_notification_trigger_best_effort",
                "notification trigger publish failed: {err}",
            );
        }
    }

    async fn publish_notification_trigger(
        &self,
        group_id: &GroupId,
        _trigger: notifications::NotificationTrigger,
    ) -> Result<(), AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let tokens = self.app.group_push_tokens(&account.label, &group_id_hex)?;
        let by_server = notifications::token_records_by_server(tokens, &account.account_id_hex);
        if by_server.is_empty() {
            return Ok(());
        }
        let keys = self
            .app
            .account_home()
            .load_signing_keys(&self.state.label)?;
        for (server_pubkey_hex, records) in by_server {
            let encrypted_tokens = records
                .iter()
                .map(|record| record.encrypted_token.clone())
                .collect::<Vec<_>>();
            let endpoints = records
                .iter()
                .filter_map(|record| record.relay_hint.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .map(TransportEndpoint)
                .collect::<Vec<_>>();
            if endpoints.is_empty() {
                continue;
            }
            let event =
                notifications::build_notification_gift_wrap(&server_pubkey_hex, &encrypted_tokens)
                    .await?;
            self.app
                .relay_client_for_endpoints(&keys, &endpoints)
                .publish_event(&endpoints, &event, 1)
                .await
                .map_err(AppError::Transport)?;
        }
        Ok(())
    }

    fn local_member_leaf(&self, group_id: &GroupId) -> Result<(String, u32), AppError> {
        let local_account = self.app.account_home().account(&self.state.label)?;
        self.runtime
            .members(group_id)?
            .into_iter()
            .enumerate()
            .find_map(|(index, member)| {
                let member_id_hex = hex::encode(member.id.as_slice());
                (member_id_hex == local_account.account_id_hex)
                    .then_some((member_id_hex, index as u32))
            })
            .ok_or_else(|| AppError::UnknownGroup(hex::encode(group_id.as_slice())))
    }

    fn cleanup_stale_push_tokens_best_effort(&self, group_id: &GroupId) {
        let Ok(account) = self.app.account_home().account(&self.state.label) else {
            return;
        };
        let Ok(members) = self.runtime.members(group_id) else {
            return;
        };
        let active_members = members
            .into_iter()
            .map(|member| hex::encode(member.id.as_slice()))
            .collect::<Vec<_>>();
        let group_id_hex = hex::encode(group_id.as_slice());
        let _ =
            self.app
                .remove_stale_group_push_tokens(&account.label, &group_id_hex, &active_members);
    }

    /// Most recent kind-7 reaction this account authored that targets
    /// `target_message_id`, identified by its own message id. Used to build the
    /// kind-5 retraction for an un-react.
    fn own_reaction_event_id(
        &self,
        group_id: &GroupId,
        sender: &str,
        target_message_id: &str,
    ) -> Result<String, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let messages = self.app.messages_with_query(
            &self.state.label,
            AppMessageQuery {
                group_id_hex: Some(group_id_hex),
                limit: None,
            },
        )?;
        messages
            .into_iter()
            .rev()
            .find(|message| {
                message.kind == MARMOT_APP_EVENT_KIND_REACTION
                    && message.sender == sender
                    && tag_value(&message.tags, EVENT_REF_TAG) == Some(target_message_id)
                    && !message.message_id_hex.is_empty()
            })
            .map(|message| message.message_id_hex)
            .ok_or(AppError::ReactionNotFound)
    }

    pub async fn react_to_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
        emoji: &str,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Reaction {
                    target_message_id: target_message_id.to_owned(),
                    emoji: emoji.to_owned(),
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn unreact_from_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Unreact {
                    target_message_id: target_message_id.to_owned(),
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn delete_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Delete {
                    target_message_id: target_message_id.to_owned(),
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn reply_to_message(
        &mut self,
        group_id: &GroupId,
        target_message_id: &str,
        text: &str,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Reply {
                    target_message_id: target_message_id.to_owned(),
                    text: text.to_owned(),
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn send_media_attachments(
        &mut self,
        group_id: &GroupId,
        attachments: Vec<MediaAttachmentReference>,
        caption: Option<String>,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::Media {
                    attachments,
                    caption,
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn upload_media(
        &mut self,
        group_id: &GroupId,
        request: MediaUploadRequest,
    ) -> Result<MediaUploadResult, AppError> {
        self.ensure_group(group_id)?;
        self.sync_runtime_groups().await?;
        let policy = self.encrypted_media_policy_for_group(group_id)?;
        let default_endpoint = policy.default_blob_endpoints.first().ok_or_else(|| {
            AppError::InvalidEncryptedMedia("encrypted media policy has no default endpoint".into())
        })?;
        let (source_epoch, media_secret) = self.encrypted_media_secret(group_id)?;
        let keys = self
            .app
            .account_home()
            .load_signing_keys(&self.state.label)?;
        let should_send = request.send;
        let caption = request.caption.clone();
        let mut result = upload_encrypted_media(
            request,
            source_epoch,
            media_secret.as_ref(),
            &keys,
            default_endpoint,
        )
        .await?;
        if should_send {
            let attachments = result
                .attachments
                .iter()
                .map(|attachment| attachment.reference.clone())
                .collect();
            result.sent = Some(
                self.send_media_attachments(group_id, attachments, caption)
                    .await?,
            );
        }
        Ok(result)
    }

    pub async fn download_media(
        &mut self,
        group_id: &GroupId,
        reference: MediaAttachmentReference,
    ) -> Result<MediaDownloadResult, AppError> {
        self.ensure_group(group_id)?;
        self.sync_runtime_groups().await?;
        let policy = self.encrypted_media_policy_for_group(group_id)?;
        let media_secret =
            self.encrypted_media_secret_for_epoch(group_id, reference.source_epoch)?;
        download_encrypted_media(
            reference,
            media_secret.as_ref(),
            &policy.default_blob_endpoints,
        )
        .await
    }

    /// Encrypt + upload a group avatar to Blossom, then publish the
    /// `marmot.group.blossom.image.v1` component via an MLS commit. Admin
    /// authorization is enforced by the engine on send. Passing an empty
    /// `plaintext` clears the image.
    pub async fn update_group_image(
        &mut self,
        group_id: &GroupId,
        plaintext: Vec<u8>,
        media_type: &str,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let audit_context = Self::local_human_action_context(
            "update_group_image",
            vec!["image"],
            vec![GROUP_BLOSSOM_IMAGE_COMPONENT_ID],
            None,
        );
        self.sync_runtime_groups().await?;
        let input = if plaintext.is_empty() {
            AppGroupImageInput::default()
        } else {
            let upload = upload_group_image(&plaintext, media_type, None).await?;
            AppGroupImageInput {
                image_hash_hex: upload.image_hash_hex,
                image_key_hex: upload.image_key_hex,
                image_nonce_hex: upload.image_nonce_hex,
                image_upload_key_hex: upload.image_upload_key_hex,
                media_type: Some(upload.media_type),
            }
        };
        let data = hex::decode(AppGroupImageComponent::new(input).data_hex)?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateAppComponents {
                    group_id: group_id.clone(),
                    updates: vec![AppComponentData {
                        component_id: GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
                        data,
                    }],
                },
                audit_context.clone(),
            )
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        let summary = send_summary_from_effects(&effects);
        self.refresh_group(group_id);
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(summary)
    }

    /// Fetch + decrypt the group's avatar. Errors when the group has no image set.
    pub async fn download_group_image(&mut self, group_id: &GroupId) -> Result<Vec<u8>, AppError> {
        self.ensure_group(group_id)?;
        self.sync_runtime_groups().await?;
        let input = self.image_for_group(group_id);
        if !input.is_present() {
            return Err(AppError::InvalidEncryptedMedia(
                "group has no image set".into(),
            ));
        }
        fetch_group_image(
            &input.image_hash_hex,
            &input.image_key_hex,
            &input.image_nonce_hex,
            input.media_type.as_deref().unwrap_or_default(),
            None,
        )
        .await
    }

    pub async fn start_agent_text_stream(
        &mut self,
        group_id: &GroupId,
        stream_id: &[u8],
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.start_agent_text_stream_with_local_projection(
            group_id,
            stream_id,
            quic_candidates,
            |_| {},
        )
        .await
    }

    pub(crate) async fn start_agent_text_stream_with_local_projection<F>(
        &mut self,
        group_id: &GroupId,
        stream_id: &[u8],
        quic_candidates: Vec<String>,
        on_local_projection: F,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError>
    where
        F: FnMut(crate::AppProjectionUpdate),
    {
        self.send_app_event_with_local_projection(
            group_id,
            AppMessageIntent::StreamStart {
                stream_id: stream_id.to_vec(),
                quic_candidates,
            },
            on_local_projection,
        )
        .await
    }

    pub async fn finish_agent_text_stream(
        &mut self,
        group_id: &GroupId,
        request: AgentTextStreamFinishRequest,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.finish_agent_text_stream_with_local_projection(group_id, request, |_| {})
            .await
    }

    pub(crate) async fn finish_agent_text_stream_with_local_projection<F>(
        &mut self,
        group_id: &GroupId,
        request: AgentTextStreamFinishRequest,
        on_local_projection: F,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError>
    where
        F: FnMut(crate::AppProjectionUpdate),
    {
        self.send_app_event_with_local_projection(
            group_id,
            AppMessageIntent::StreamFinal { request },
            on_local_projection,
        )
        .await
    }

    pub async fn send_agent_activity(
        &mut self,
        group_id: &GroupId,
        status: String,
        text: String,
        reply_to_message_id: Option<String>,
        extra: Option<serde_json::Value>,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::AgentActivity {
                    status,
                    text,
                    reply_to_message_id,
                    extra,
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn send_agent_operation_event(
        &mut self,
        group_id: &GroupId,
        request: AgentOperationEventRequest,
    ) -> Result<SendSummary, AppError> {
        let AgentOperationEventRequest {
            event_type,
            status,
            operation_id,
            run_id,
            turn_id,
            name,
            text,
            preview,
            details,
            sequence,
            ok,
            duration_ms,
            reply_to_message_id,
        } = request;
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::AgentOperation {
                    event_type,
                    status,
                    operation_id,
                    run_id,
                    turn_id,
                    name,
                    text,
                    preview,
                    details,
                    sequence,
                    ok,
                    duration_ms,
                    reply_to_message_id,
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn send_group_system_event(
        &mut self,
        group_id: &GroupId,
        system_type: String,
        text: String,
        data: Option<serde_json::Value>,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(
                group_id,
                AppMessageIntent::GroupSystem {
                    system_type,
                    text,
                    data,
                },
            )
            .await?;
        Ok(summary)
    }

    pub async fn retry_group_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;

        self.sync_runtime_groups().await?;
        let effects = self.runtime.advance_convergence(group_id).await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.prune_plaintext_retention_for_group(group_id)?;
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn update_group_profile(
        &mut self,
        group_id: &GroupId,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<SendSummary, AppError> {
        if name.is_none() && description.is_none() {
            return Err(AppError::InvalidGroupProfile(
                "name or description is required".into(),
            ));
        }
        validate_group_profile(name.unwrap_or(""), description.unwrap_or(""))?;
        self.ensure_group(group_id)?;
        let mut fields = Vec::new();
        if name.is_some() {
            fields.push("name");
        }
        if description.is_some() {
            fields.push("description");
        }
        let audit_context = Self::local_human_action_context(
            "update_group_profile",
            fields,
            vec![GROUP_PROFILE_COMPONENT_ID],
            None,
        );

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::UpdateGroupData {
                    group_id: group_id.clone(),
                    name: name.map(ToOwned::to_owned),
                    description: description.map(ToOwned::to_owned),
                },
                audit_context.clone(),
            )
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        let message_ids = effects
            .reports
            .iter()
            .map(|report| hex::encode(report.message_id.as_slice()))
            .collect::<Vec<_>>();
        let group_metadata = self.runtime.group_record(group_id).ok();
        let nostr_routing = self.nostr_routing_for_group(group_id)?;
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
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(SendSummary {
            published: effects.reports.len(),
            message_ids,
        })
    }

    pub async fn sync(&mut self) -> Result<SyncSummary, AppError> {
        let rebuild_since = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp);
        self.runtime.activate_transport(rebuild_since).await?;
        self.sync_runtime_groups().await?;
        self.sync_sdk_relay().await
    }

    pub async fn next_event(&mut self) -> Result<SyncSummary, AppError> {
        let display_names = self.app.display_names_by_id()?;
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let mut seen = self
            .state
            .seen_events
            .iter()
            .cloned()
            .collect::<HashSet<_>>();

        loop {
            let delivery = self
                .adapter
                .receive()
                .await?
                .ok_or(AppError::TransportClosed)?;
            let event_id = hex::encode(delivery.message.id.as_slice());
            if is_own_relay_echo(&delivery, &local_account_id_hex, &seen) {
                continue;
            }
            if seen.contains(&event_id) {
                continue;
            }
            seen.insert(event_id.clone());
            remember_seen_event(&mut self.state, event_id);
            refresh_seen_lookup_if_needed(&mut seen, &self.state);

            let mut summary = SyncSummary::default();
            self.ingest_delivery(delivery, &display_names, &mut summary)
                .await?;
            self.app.save_state(&self.state)?;
            if summary.joined_groups.is_empty()
                && summary.messages.is_empty()
                && summary.events.is_empty()
            {
                continue;
            }
            return Ok(summary);
        }
    }

    async fn sync_sdk_relay(&mut self) -> Result<SyncSummary, AppError> {
        let display_names = self.app.display_names_by_id()?;
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let mut summary = SyncSummary::default();
        let mut seen = self
            .state
            .seen_events
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let mut first_wait = true;

        loop {
            let wait = if first_wait {
                SDK_FIRST_SYNC_WAIT
            } else {
                SDK_DRAIN_WAIT
            };
            first_wait = false;

            let delivery = match timeout(wait, self.adapter.receive()).await {
                Ok(Ok(Some(delivery))) => delivery,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            };
            let event_id = hex::encode(delivery.message.id.as_slice());
            if is_own_relay_echo(&delivery, &local_account_id_hex, &seen) {
                continue;
            }
            if seen.contains(&event_id) {
                continue;
            }
            seen.insert(event_id.clone());
            remember_seen_event(&mut self.state, event_id);
            refresh_seen_lookup_if_needed(&mut seen, &self.state);
            self.ingest_delivery(delivery, &display_names, &mut summary)
                .await?;
        }

        self.app.save_state(&self.state)?;
        Ok(summary)
    }

    async fn ingest_delivery(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
        display_names: &HashMap<String, String>,
        summary: &mut SyncSummary,
    ) -> Result<(), AppError> {
        let source_message_id_hex = hex::encode(delivery.message.id.as_slice());
        let source_recorded_at = delivery.message.timestamp.0;
        let effects = self.runtime.ingest_delivery(delivery).await?;
        fail_if_publish_failed(&effects.effects.failures)?;
        self.remember_transport_cursor(source_recorded_at);
        for event in &effects.effects.events {
            let before = self.state.groups.len();
            let previous_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            let group_metadata =
                event_group_id(event).and_then(|group_id| self.runtime.group_record(group_id).ok());
            let group_projection = event_group_id(event)
                .map(|group_id| {
                    Ok::<_, AppError>(EventGroupProjection {
                        nostr_routing: self.nostr_routing_for_group(group_id)?,
                        group_metadata: group_metadata.as_ref(),
                        admin_policy: self
                            .runtime
                            .admin_pubkeys(group_id)
                            .map(AppGroupAdminPolicyComponent::new)
                            .unwrap_or_else(|_| AppGroupAdminPolicyComponent::new(Vec::new())),
                        message_retention: self.message_retention_for_group(group_id),
                        agent_text_stream: self.agent_text_stream_for_group(group_id),
                        avatar_url: self.avatar_url_for_group(group_id),
                        encrypted_media: self.encrypted_media_for_group(group_id),
                        image: self.image_for_group(group_id),
                    })
                })
                .transpose()?;
            if let Some(message) = observe_event(
                &mut self.state,
                display_names,
                summary,
                event,
                group_projection.as_ref(),
                &source_message_id_hex,
                source_recorded_at,
            ) {
                if notifications::is_push_gossip_kind(message.kind) {
                    if let Err(err) = self
                        .app
                        .ingest_push_gossip_message(&self.state.label, &message)
                    {
                        tracing::warn!(
                            target: "marmot_app::notifications",
                            method = "ingest_delivery",
                            "ignoring malformed push token gossip: {err}",
                        );
                    }
                    summary
                        .messages
                        .retain(|candidate| candidate.message_id_hex != message.message_id_hex);
                    continue;
                }
                if message.kind == MARMOT_APP_EVENT_KIND_CHAT
                    && media_imeta_tags_are_valid(&message.tags)
                    && self
                        .remember_current_encrypted_media_secret(&message.group_id)
                        .is_err()
                {
                    tracing::warn!(
                        target: "marmot_app::media",
                        method = "ingest_delivery",
                        error_code = "encrypted_media_secret_cache_skipped",
                        "failed to cache encrypted media source epoch secret",
                    );
                }
                self.app.remember_directory_message_sender(&message)?;
                let message_projection = AppMessageProjection {
                    message_id_hex: message.message_id_hex.clone(),
                    source_message_id_hex: Some(message.source_message_id_hex.clone()),
                    direction: "received".to_owned(),
                    group_id_hex: hex::encode(message.group_id.as_slice()),
                    sender: message.sender.clone(),
                    plaintext: message.plaintext.clone(),
                    kind: message.kind,
                    tags: message.tags.clone(),
                    source_epoch: Some(message.source_epoch),
                    recorded_at: Some(source_recorded_at),
                };
                let projection_update = self
                    .app
                    .record_account_app_event(&self.state.label, &message_projection)?;
                summary.projection_updates.push(projection_update);
                self.prune_plaintext_retention_for_group(&message.group_id)?;
            }
            let updated_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            self.audit_observed_group_event(
                event,
                previous_group.as_ref(),
                updated_group.as_ref(),
                &source_message_id_hex,
            );
            if let cgka_traits::engine::GroupEvent::AppMessageInvalidated {
                message_id, reason, ..
            } = event
                && let Some(projection_update) = self.app.invalidate_timeline_source_message(
                    &self.state.label,
                    &hex::encode(message_id.as_slice()),
                    &format!("{reason:?}"),
                )?
            {
                summary.projection_updates.push(projection_update);
            }
            if self.state.groups.len() != before {
                self.refresh_group_routes()?;
                self.sync_runtime_groups().await?;
            }
            if let cgka_traits::engine::GroupEvent::GroupStateChanged {
                group_id,
                change:
                    cgka_traits::engine::GroupStateChange::MemberRemoved { member }
                    | cgka_traits::engine::GroupStateChange::MemberLeft { member },
                ..
            } = event
            {
                let group_id_hex = hex::encode(group_id.as_slice());
                let member_id_hex = hex::encode(member.as_slice());
                let _ = self.app.remove_group_push_tokens_for_member(
                    &self.state.label,
                    &group_id_hex,
                    &member_id_hex,
                );
            }
        }
        // Synthesize durable kind-1210 system rows from this delivery's
        // authenticated state changes (peer commits and auto-commits).
        let system_updates =
            self.project_group_system_rows(&effects.effects.events, source_recorded_at);
        summary.projection_updates.extend(system_updates);
        Ok(())
    }

    fn ensure_group(&self, group_id: &GroupId) -> Result<(), AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        if self
            .state
            .groups
            .iter()
            .any(|group| group.group_id_hex == group_id_hex)
        {
            Ok(())
        } else {
            Err(AppError::UnknownGroup(group_id_hex))
        }
    }

    fn state_group_record(&self, group_id: &GroupId) -> Option<AppGroupRecord> {
        let group_id_hex = hex::encode(group_id.as_slice());
        self.state
            .groups
            .iter()
            .find(|group| group.group_id_hex == group_id_hex)
            .cloned()
    }

    fn audit_observed_group_event(
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

    fn set_group_invite_confirmation(
        &mut self,
        group_id: &GroupId,
        pending_confirmation: bool,
        archived: bool,
    ) -> Result<AppGroupRecord, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let group = self
            .state
            .groups
            .iter_mut()
            .find(|group| group.group_id_hex == group_id_hex)
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
        group.pending_confirmation = pending_confirmation;
        group.archived = archived;
        let group = group.clone();
        self.app.save_state(&self.state)?;
        Ok(group)
    }

    fn refresh_group(&mut self, group_id: &GroupId) {
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

    fn add_group(&mut self, group_id: &GroupId) -> Result<(), AppError> {
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

    fn admin_policy_for_group(&self, group_id: &GroupId) -> AppGroupAdminPolicyComponent {
        self.runtime
            .admin_pubkeys(group_id)
            .map(AppGroupAdminPolicyComponent::new)
            .unwrap_or_else(|_| AppGroupAdminPolicyComponent::new(Vec::new()))
    }

    fn message_retention_for_group(&self, group_id: &GroupId) -> AppGroupMessageRetentionComponent {
        self.runtime
            .app_component(group_id, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .ok()
            .flatten()
            .map(|bytes| AppGroupMessageRetentionComponent::from_bytes(&bytes))
            .unwrap_or_else(AppGroupMessageRetentionComponent::disabled)
    }

    fn prune_plaintext_retention_for_group(&self, group_id: &GroupId) -> Result<(), AppError> {
        let retention = self.message_retention_for_group(group_id);
        if retention.disappearing_message_secs == 0 {
            return Ok(());
        }
        let cutoff = unix_now_seconds().saturating_sub(retention.disappearing_message_secs);
        self.app.prune_account_app_events_before(
            &self.state.label,
            &hex::encode(group_id.as_slice()),
            cutoff,
        )?;
        Ok(())
    }

    fn agent_text_stream_for_group(&self, group_id: &GroupId) -> AppAgentTextStreamComponent {
        self.runtime
            .app_component(group_id, AGENT_TEXT_STREAM_QUIC_COMPONENT_ID)
            .ok()
            .flatten()
            .map(|bytes| AppAgentTextStreamComponent::from_bytes(&bytes))
            .unwrap_or_else(AppAgentTextStreamComponent::disabled)
    }

    fn avatar_url_for_group(&self, group_id: &GroupId) -> AppGroupAvatarUrlComponent {
        self.runtime
            .app_component(group_id, GROUP_AVATAR_URL_COMPONENT_ID)
            .ok()
            .flatten()
            .map(|bytes| AppGroupAvatarUrlComponent::from_bytes(&bytes))
            .unwrap_or_else(AppGroupAvatarUrlComponent::absent)
    }

    fn encrypted_media_for_group(&self, group_id: &GroupId) -> AppGroupEncryptedMediaComponent {
        self.runtime
            .app_component(group_id, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID)
            .ok()
            .flatten()
            .map(|bytes| AppGroupEncryptedMediaComponent::from_bytes(&bytes))
            .unwrap_or_else(AppGroupEncryptedMediaComponent::disabled)
    }

    fn image_for_group(&self, group_id: &GroupId) -> AppGroupImageInput {
        self.runtime
            .app_component(group_id, GROUP_BLOSSOM_IMAGE_COMPONENT_ID)
            .ok()
            .flatten()
            .and_then(|bytes| AppGroupImageInput::from_component_bytes(&bytes))
            .unwrap_or_default()
    }

    fn encrypted_media_policy_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<EncryptedMediaPolicyV1, AppError> {
        self.encrypted_media_for_group(group_id).endpoint_policy()
    }

    fn encrypted_media_secret(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(u64, SecretBytes), AppError> {
        let (epoch, secret) = self.runtime.exporter_secret_with_epoch(
            group_id,
            GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY,
            32,
        )?;
        self.remember_encrypted_media_epoch_secret(group_id, epoch.0, secret.as_ref())?;
        Ok((epoch.0, secret))
    }

    fn encrypted_media_secret_for_epoch(
        &mut self,
        group_id: &GroupId,
        source_epoch: u64,
    ) -> Result<SecretBytes, AppError> {
        if let Some(secret) = self.cached_encrypted_media_epoch_secret(group_id, source_epoch)? {
            return Ok(SecretBytes::new(secret));
        }
        let (epoch, secret) = self.runtime.exporter_secret_with_epoch(
            group_id,
            GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY,
            32,
        )?;
        self.remember_encrypted_media_epoch_secret(group_id, epoch.0, secret.as_ref())?;
        if epoch.0 != source_epoch {
            return Err(AppError::InvalidEncryptedMedia(format!(
                "missing encrypted media secret for epoch {source_epoch}"
            )));
        }
        Ok(secret)
    }

    fn remember_current_encrypted_media_secret(&self, group_id: &GroupId) -> Result<(), AppError> {
        let (epoch, secret) = self.runtime.exporter_secret_with_epoch(
            group_id,
            GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY,
            32,
        )?;
        self.remember_encrypted_media_epoch_secret(group_id, epoch.0, secret.as_ref())
    }

    fn cache_current_encrypted_media_epoch_secrets(&self) {
        for group in &self.state.groups {
            let Ok(group_id_bytes) = hex::decode(&group.group_id_hex) else {
                tracing::warn!(
                    target: "marmot_app::media",
                    method = "cache_current_encrypted_media_epoch_secrets",
                    error_code = "encrypted_media_group_record_skipped",
                    "skipping malformed encrypted media group record",
                );
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            if !self.encrypted_media_for_group(&group_id).required {
                continue;
            }
            if self
                .remember_current_encrypted_media_secret(&group_id)
                .is_err()
            {
                tracing::warn!(
                    target: "marmot_app::media",
                    method = "cache_current_encrypted_media_epoch_secrets",
                    error_code = "encrypted_media_secret_cache_skipped",
                    "failed to cache encrypted media epoch secret for one group",
                );
            }
        }
    }

    fn remember_encrypted_media_epoch_secret(
        &self,
        group_id: &GroupId,
        source_epoch: u64,
        secret: &[u8],
    ) -> Result<(), AppError> {
        self.app
            .account_storage(&self.state.label)?
            .remember_encrypted_media_epoch_secret(
                &hex::encode(group_id.as_slice()),
                GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
                source_epoch,
                secret,
            )?;
        Ok(())
    }

    fn cached_encrypted_media_epoch_secret(
        &self,
        group_id: &GroupId,
        source_epoch: u64,
    ) -> Result<Option<Vec<u8>>, AppError> {
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .encrypted_media_epoch_secret(
                &hex::encode(group_id.as_slice()),
                GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
                source_epoch,
            )?)
    }

    fn encrypted_media_component_for_new_group(&self) -> Result<AppComponentData, AppError> {
        let endpoints = if self
            .app
            .service_endpoints()
            .encrypted_media_blob_endpoints
            .is_empty()
        {
            vec![DEFAULT_BLOSSOM_SERVER_URL.to_owned()]
        } else {
            self.app
                .service_endpoints()
                .encrypted_media_blob_endpoints
                .clone()
        };
        let policy = EncryptedMediaPolicyV1::blossom_default(endpoints, true)
            .map_err(AppError::InvalidEncryptedMedia)?;
        AppGroupEncryptedMediaComponent::new(policy)?.to_app_component_data()
    }

    fn refresh_group_routes(&mut self) -> Result<(), AppError> {
        for group in &self.state.groups {
            let group_id = GroupId::new(hex::decode(&group.group_id_hex)?);
            self.routing
                .add_group(group.nostr_routing.subscription(&group_id)?);
        }
        Ok(())
    }

    fn refresh_routing(&mut self) -> Result<(), AppError> {
        let routing = self.app.routing_for(&self.state)?;
        self.routing.replace(routing.snapshot());
        Ok(())
    }

    fn remember_transport_cursor(&mut self, timestamp: u64) {
        self.state.last_transport_timestamp = Some(
            self.state
                .last_transport_timestamp
                .map(|current| current.max(timestamp))
                .unwrap_or(timestamp),
        );
    }

    fn remember_published_reports(&mut self, effects: &marmot_account::AccountDeviceEffects) {
        for report in &effects.reports {
            let event_id = hex::encode(report.message_id.as_slice());
            remember_seen_event(&mut self.state, event_id);
        }
    }

    /// Persist and queue kind-1210 system rows for our own authenticated commits.
    /// Call only after the caller's final fallible persistence step succeeds so
    /// failed commands do not leave stale buffered timeline updates.
    fn queue_own_group_system_projection_updates(
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
    fn project_group_system_rows(
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
            } = event
            {
                let projection = match build_group_system_projection(
                    group_id,
                    epoch.0,
                    actor.as_ref(),
                    change,
                    recorded_at,
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

    fn nostr_routing_for_group(
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
/// same change upserts instead of duplicating; the `source_message_id_hex` link
/// lets a commit that is later invalidated on a losing branch invalidate this
/// row through the same path as any other app event.
fn build_group_system_projection(
    group_id: &cgka_traits::types::GroupId,
    epoch: u64,
    actor: Option<&cgka_traits::types::MemberId>,
    change: &cgka_traits::engine::GroupStateChange,
    recorded_at: u64,
) -> Result<AppMessageProjection, cgka_traits::app_event::MarmotAppEventError> {
    use cgka_traits::app_event::{
        GROUP_SYSTEM_DATA_ACTOR, GROUP_SYSTEM_DATA_NAME, GROUP_SYSTEM_DATA_SUBJECT,
        GROUP_SYSTEM_TYPE_ADMIN_ADDED, GROUP_SYSTEM_TYPE_ADMIN_REMOVED,
        GROUP_SYSTEM_TYPE_GROUP_AVATAR_CHANGED, GROUP_SYSTEM_TYPE_GROUP_RENAMED,
        GROUP_SYSTEM_TYPE_MEMBER_ADDED, GROUP_SYSTEM_TYPE_MEMBER_LEFT,
        GROUP_SYSTEM_TYPE_MEMBER_REMOVED, GROUP_SYSTEM_TYPE_TAG, GroupSystemEvent,
        MARMOT_APP_EVENT_KIND_GROUP_SYSTEM, canonical_event_id,
    };
    use cgka_traits::engine::GroupStateChange;
    use cgka_traits::types::MemberId;

    let (system_type, subject, name, text): (&str, Option<&MemberId>, Option<&str>, &str) =
        match change {
            GroupStateChange::MemberAdded { member } => (
                GROUP_SYSTEM_TYPE_MEMBER_ADDED,
                Some(member),
                None,
                "Member added",
            ),
            GroupStateChange::MemberRemoved { member } => (
                GROUP_SYSTEM_TYPE_MEMBER_REMOVED,
                Some(member),
                None,
                "Member removed",
            ),
            GroupStateChange::MemberLeft { member } => (
                GROUP_SYSTEM_TYPE_MEMBER_LEFT,
                Some(member),
                None,
                "Member left",
            ),
            GroupStateChange::AdminAdded { member } => (
                GROUP_SYSTEM_TYPE_ADMIN_ADDED,
                Some(member),
                None,
                "Admin added",
            ),
            GroupStateChange::AdminRemoved { member } => (
                GROUP_SYSTEM_TYPE_ADMIN_REMOVED,
                Some(member),
                None,
                "Admin removed",
            ),
            GroupStateChange::GroupRenamed { name } => (
                GROUP_SYSTEM_TYPE_GROUP_RENAMED,
                None,
                Some(name.as_str()),
                "Group renamed",
            ),
            GroupStateChange::GroupAvatarChanged => (
                GROUP_SYSTEM_TYPE_GROUP_AVATAR_CHANGED,
                None,
                None,
                "Group avatar changed",
            ),
        };

    let actor_hex = actor.map(|id| hex::encode(id.as_slice()));
    let mut data = serde_json::Map::new();
    if let Some(actor_hex) = actor_hex.as_ref() {
        data.insert(
            GROUP_SYSTEM_DATA_ACTOR.to_owned(),
            serde_json::Value::String(actor_hex.clone()),
        );
    }
    if let Some(subject) = subject {
        data.insert(
            GROUP_SYSTEM_DATA_SUBJECT.to_owned(),
            serde_json::Value::String(hex::encode(subject.as_slice())),
        );
    }
    if let Some(name) = name {
        data.insert(
            GROUP_SYSTEM_DATA_NAME.to_owned(),
            serde_json::Value::String(name.to_owned()),
        );
    }
    let data = (!data.is_empty()).then_some(serde_json::Value::Object(data));
    let content = GroupSystemEvent::new(system_type, text, data).to_content()?;
    let group_id_hex = hex::encode(group_id.as_slice());
    let tags = vec![vec![
        GROUP_SYSTEM_TYPE_TAG.to_owned(),
        system_type.to_owned(),
    ]];
    let sender = actor_hex.unwrap_or_default();
    // Deterministic, local-only id. `epoch` (not the wall-clock `recorded_at`)
    // anchors it so the same change yields the same id on every pass; `group_id`
    // is folded in so the same change in two groups can't collide (the canonical
    // id is also used by message-id-keyed ops like reactions/invalidation).
    let id_preimage = format!("{group_id_hex}\u{1f}{content}");
    let message_id_hex = canonical_event_id(
        &sender,
        epoch,
        MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        &tags,
        &id_preimage,
    );

    Ok(AppMessageProjection {
        message_id_hex,
        // Synthesized rows carry no source: several rows can come from one
        // commit, which would collide on the partial unique source index, and
        // commit ids are never targeted by source-based invalidation anyway.
        source_message_id_hex: None,
        direction: "system".to_owned(),
        group_id_hex,
        sender,
        plaintext: content,
        kind: MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        tags,
        source_epoch: Some(epoch),
        recorded_at: Some(recorded_at),
    })
}

fn audit_message_ids_from_effects(effects: &marmot_account::AccountDeviceEffects) -> Vec<String> {
    effects
        .reports
        .iter()
        .map(|report| hex::encode(report.message_id.as_slice()))
        .collect()
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

pub(crate) fn is_own_relay_echo(
    delivery: &cgka_traits::TransportDelivery,
    local_account_id_hex: &str,
    known_event_ids: &HashSet<String>,
) -> bool {
    let event_id = hex::encode(delivery.message.id.as_slice());
    if !known_event_ids.contains(&event_id) {
        return false;
    }
    NostrTransportEvent::from_transport_message(&delivery.message)
        .ok()
        .is_some_and(|event| event.pubkey == local_account_id_hex)
}

fn notification_trigger_for_intent(
    intent: &AppMessageIntent,
) -> Option<notifications::NotificationTrigger> {
    match intent {
        AppMessageIntent::Chat { .. }
        | AppMessageIntent::Reply { .. }
        | AppMessageIntent::Media { .. }
        | AppMessageIntent::StreamFinal { .. } => {
            Some(notifications::NotificationTrigger::NewMessage)
        }
        AppMessageIntent::Reaction { .. }
        | AppMessageIntent::Unreact { .. }
        | AppMessageIntent::Edit { .. }
        | AppMessageIntent::Delete { .. }
        | AppMessageIntent::StreamStart { .. }
        | AppMessageIntent::AgentActivity { .. }
        | AppMessageIntent::AgentOperation { .. }
        | AppMessageIntent::GroupSystem { .. }
        | AppMessageIntent::PushTokenUpdate { .. }
        | AppMessageIntent::PushTokenRemoval { .. } => None,
    }
}
