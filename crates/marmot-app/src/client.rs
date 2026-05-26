use std::collections::{HashMap, HashSet};

use cgka_engine::key_package::is_last_resort_key_package;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_EXPORTER_LABEL, AgentTextStreamQuicPolicyV1,
};
use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, AppComponentData, GROUP_MESSAGE_RETENTION_COMPONENT_ID,
    NOSTR_ROUTING_COMPONENT_ID, encode_nostr_routing_v1,
};
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_REACTION, MarmotAppEvent as MarmotInnerEvent,
};
use cgka_traits::engine::{CreateGroupRequest, KeyPackage, SendIntent};
use cgka_traits::{GroupId, SecretBytes, TransportAdapter, TransportEndpoint};
use tokio::time::timeout;
use transport_nostr_peeler::NostrTransportEvent;

use crate::groups::{
    EventGroupProjection, GroupConfirmationProjection, add_group, event_group_id,
    fail_if_publish_failed, observe_event, send_summary_from_effects, validate_group_profile,
};
use crate::ids::{admin_pubkey_from_account_id_hex, admin_pubkey_from_member_id};
use crate::media::{
    ENCRYPTED_MEDIA_EXPORTER_LABEL, download_encrypted_media, upload_encrypted_media,
};
use crate::messages::{AppMessageIntent, build_inner_event, encode_inner_event, tag_value};
use crate::notifications;
use crate::{
    AccountState, AgentTextStreamFinishRequest, AppAgentTextStreamComponent, AppError,
    AppGroupAdminPolicyComponent, AppGroupMemberRecord, AppGroupMessageRetentionComponent,
    AppGroupMlsState, AppGroupNostrRoutingComponent, AppGroupRecord, AppMessageProjection,
    AppMessageQuery, AppRuntime, AppTransportRouting, GroupInviteDeclineResult, MarmotApp,
    MarmotRelayPlane, MarmotRelayPlaneAccountAdapter, MediaDownloadResult, MediaReference,
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
}

impl AppClient {
    async fn sync_runtime_groups(&self) -> Result<(), AppError> {
        let rebuild_since = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp);
        self.runtime.sync_transport_groups(rebuild_since).await?;
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

        let (group_id, effects) = self
            .runtime
            .create_group(CreateGroupRequest {
                name: name.to_owned(),
                description: String::new(),
                members,
                required_features: Vec::new(),
                app_components,
                initial_admins: Vec::new(),
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.add_group(&group_id)?;
        self.sync_runtime_groups().await?;
        self.app.save_state(&self.state)?;
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
        self.exporter_secret(group_id, AGENT_TEXT_STREAM_EXPORTER_LABEL, 32)
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

    fn encrypted_media_exporter_secret(&self, group_id: &GroupId) -> Result<SecretBytes, AppError> {
        self.exporter_secret(group_id, ENCRYPTED_MEDIA_EXPORTER_LABEL, 32)
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

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages,
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.prune_plaintext_retention_for_group(group_id)?;
        self.app.save_state(&self.state)?;
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

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::RemoveMembers {
                group_id: group_id.clone(),
                members,
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.cleanup_stale_push_tokens_best_effort(group_id);
        self.app.save_state(&self.state)?;
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn leave_group(&mut self, group_id: &GroupId) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.app.save_state(&self.state)?;
        Ok(send_summary_from_effects(&effects))
    }

    pub fn accept_group_invite(&mut self, group_id: &GroupId) -> Result<AppGroupRecord, AppError> {
        self.set_group_invite_confirmation(group_id, false, false)
    }

    pub async fn decline_group_invite(
        &mut self,
        group_id: &GroupId,
    ) -> Result<GroupInviteDeclineResult, AppError> {
        let summary = self.leave_group(group_id).await?;
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
        self.update_admin_policy(group_id, admins).await
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
        self.update_admin_policy(group_id, admins).await
    }

    pub async fn self_demote_admin(&mut self, group_id: &GroupId) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;
        let account = self.app.account_home().account(&self.state.label)?;
        let local = admin_pubkey_from_account_id_hex(&account.account_id_hex)?;
        let mut admins = self.runtime.admin_pubkeys(group_id)?;
        admins.retain(|admin| admin != &local);
        self.update_admin_policy(group_id, admins).await
    }

    async fn update_admin_policy(
        &mut self,
        group_id: &GroupId,
        admins: Vec<[u8; 32]>,
    ) -> Result<SendSummary, AppError> {
        let component = AppGroupAdminPolicyComponent::new(admins).to_app_component_data()?;

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::UpdateAppComponents {
                group_id: group_id.clone(),
                updates: vec![component],
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.app.save_state(&self.state)?;
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

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::UpdateAppComponents {
                group_id: group_id.clone(),
                updates: vec![component],
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);
        self.prune_plaintext_retention_for_group(group_id)?;
        self.app.save_state(&self.state)?;
        Ok(send_summary_from_effects(&effects))
    }

    pub async fn send(
        &mut self,
        group_id: &GroupId,
        payload: &[u8],
    ) -> Result<SendSummary, AppError> {
        // The transport-facing `send` carries plain UTF-8 chat text; structured
        // payloads use `send_app_event` with a typed intent.
        let content = String::from_utf8(payload.to_vec()).map_err(|_| {
            AppError::InvalidAppMessagePayload("chat message must be valid UTF-8".into())
        })?;
        let (_event, summary) = self
            .send_app_event(group_id, AppMessageIntent::Chat { content })
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
        self.ensure_group(group_id)?;
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
        let event = build_inner_event(&intent, &sender, unix_now_seconds())?;
        let payload = encode_inner_event(&event)?;

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload,
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
        self.remember_published_reports(&effects);
        let group_id_hex = hex::encode(group_id.as_slice());
        let app_event_id = event.id.clone();
        if !notifications::is_push_gossip_kind(event.kind) {
            let projection = self.app.account_projection(&self.state.label)?;
            projection.record_message(&AppMessageProjection {
                message_id_hex: app_event_id.clone(),
                direction: "sent".to_owned(),
                group_id_hex: group_id_hex.clone(),
                sender: sender.clone(),
                plaintext: event.content.clone(),
                kind: event.kind,
                tags: event.tags.clone(),
                recorded_at: None,
            })?;
            self.prune_plaintext_retention_for_group(group_id)?;
        }
        self.app.save_state(&self.state)?;
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
        let messages =
            self.app
                .account_projection(&self.state.label)?
                .messages(AppMessageQuery {
                    group_id_hex: Some(group_id_hex),
                    limit: None,
                })?;
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

    pub async fn send_media_reference(
        &mut self,
        group_id: &GroupId,
        reference: MediaReference,
        caption: Option<String>,
    ) -> Result<SendSummary, AppError> {
        let (_event, summary) = self
            .send_app_event(group_id, AppMessageIntent::Media { reference, caption })
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
        let exporter_secret = self.encrypted_media_exporter_secret(group_id)?;
        let keys = self
            .app
            .account_home()
            .load_signing_keys(&self.state.label)?;
        let should_send = request.send;
        let caption = request.caption.clone();
        let mut result = upload_encrypted_media(request, exporter_secret.as_ref(), &keys).await?;
        if should_send {
            result.sent = Some(
                self.send_media_reference(group_id, result.reference.clone(), caption)
                    .await?,
            );
        }
        Ok(result)
    }

    pub async fn download_media(
        &mut self,
        group_id: &GroupId,
        reference: MediaReference,
    ) -> Result<MediaDownloadResult, AppError> {
        self.ensure_group(group_id)?;
        self.sync_runtime_groups().await?;
        let exporter_secret = self.encrypted_media_exporter_secret(group_id)?;
        download_encrypted_media(reference, exporter_secret.as_ref()).await
    }

    pub async fn start_agent_text_stream(
        &mut self,
        group_id: &GroupId,
        stream_id: &[u8],
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.send_app_event(
            group_id,
            AppMessageIntent::StreamStart {
                stream_id: stream_id.to_vec(),
                quic_candidates,
            },
        )
        .await
    }

    pub async fn finish_agent_text_stream(
        &mut self,
        group_id: &GroupId,
        request: AgentTextStreamFinishRequest,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.send_app_event(group_id, AppMessageIntent::StreamFinal { request })
            .await
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

        self.sync_runtime_groups().await?;
        let effects = self
            .runtime
            .send(SendIntent::UpdateGroupData {
                group_id: group_id.clone(),
                name: name.map(ToOwned::to_owned),
                description: description.map(ToOwned::to_owned),
            })
            .await?;
        fail_if_publish_failed(&effects.failures)?;
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
        };
        add_group(
            &mut self.state,
            group_id,
            &projection,
            GroupConfirmationProjection::Preserve,
        );
        self.app.save_state(&self.state)?;
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
                self.app.remember_directory_message_sender(&message)?;
                self.app
                    .account_projection(&self.state.label)?
                    .record_message(&AppMessageProjection {
                        message_id_hex: message.message_id_hex.clone(),
                        direction: "received".to_owned(),
                        group_id_hex: hex::encode(message.group_id.as_slice()),
                        sender: message.sender.clone(),
                        plaintext: message.plaintext.clone(),
                        kind: message.kind,
                        tags: message.tags.clone(),
                        recorded_at: Some(source_recorded_at),
                    })?;
                self.prune_plaintext_retention_for_group(&message.group_id)?;
            }
            if self.state.groups.len() != before {
                self.refresh_group_routes()?;
                self.sync_runtime_groups().await?;
            }
            if let cgka_traits::engine::GroupEvent::MemberRemoved { group_id, member } = event {
                let group_id_hex = hex::encode(group_id.as_slice());
                let member_id_hex = hex::encode(member.as_slice());
                let _ = self.app.remove_group_push_tokens_for_member(
                    &self.state.label,
                    &group_id_hex,
                    &member_id_hex,
                );
            }
        }
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
        self.app
            .account_projection(&self.state.label)?
            .prune_group_messages_before(&hex::encode(group_id.as_slice()), cutoff)?;
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
        | AppMessageIntent::Delete { .. }
        | AppMessageIntent::StreamStart { .. }
        | AppMessageIntent::PushTokenUpdate { .. }
        | AppMessageIntent::PushTokenRemoval { .. } => None,
    }
}
