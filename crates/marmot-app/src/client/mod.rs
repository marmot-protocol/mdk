use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use cgka_engine::key_package::is_last_resort_key_package;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY, AgentTextStreamQuicPolicyV1,
};
use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, AppComponentData, BLOSSOM_LOCATOR_KIND_V1,
    BlobStoreEndpointV1, ENCRYPTED_MEDIA_FORMAT_V1, EncryptedMediaPolicyV1,
    GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY, GROUP_MESSAGE_RETENTION_COMPONENT_ID,
    GROUP_PROFILE_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID, encode_nostr_routing_v1,
};
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_REACTION, MarmotAppEvent as MarmotInnerEvent,
};
use cgka_traits::engine::{CreateGroupRequest, KeyPackage, SendIntent};
use cgka_traits::{GroupId, SecretBytes};
use marmot_forensics::AuditEventContext;

use crate::app_telemetry::AppPerformanceOperation;
use crate::groups::{
    EventGroupProjection, GroupConfirmationProjection, add_group, fail_if_publish_failed,
    send_summary_from_effects, validate_group_profile,
};
use crate::ids::{admin_pubkey_from_account_id_hex, admin_pubkey_from_member_id};
use crate::media::{
    DEFAULT_BLOSSOM_SERVER_URL, download_encrypted_media, fetch_group_image,
    is_loopback_http_endpoint, upload_encrypted_media, upload_group_image,
};
use crate::messages::{AppMessageIntent, build_inner_event, encode_inner_event, tag_value};
use crate::notifications;
use crate::{
    AccountState, AgentOperationEventRequest, AgentTextStreamFinishRequest, AppBlobEndpoint,
    AppError, AppGroupAdminPolicyComponent, AppGroupAvatarUrlComponent,
    AppGroupEncryptedMediaComponent, AppGroupImageComponent, AppGroupImageInput,
    AppGroupMemberRecord, AppGroupMessageRetentionComponent, AppGroupMlsState, AppGroupRecord,
    AppMessageQuery, AppPerformanceTelemetry, AppQuarantinedGroup, AppRuntime, AppTransportRouting,
    GroupInviteDeclineResult, MarmotApp, MarmotRelayPlane, MarmotRelayPlaneAccountAdapter,
    MediaAttachmentReference, MediaDownloadResult, MediaUploadRequest, MediaUploadResult,
    SendSummary, remember_seen_event, unix_now_seconds,
};

mod audit;
mod projection;
mod push;
mod sync;

use push::notification_trigger_for_intent;
// Re-exported so the crate's `tests` module can keep calling
// `client::is_own_relay_echo`; the function itself lives in `client::sync`.
#[cfg(test)]
pub(crate) use sync::is_own_relay_echo;

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
    pub(crate) pending_convergence_groups: HashSet<GroupId>,
}

/// A point-in-time copy of the live session's read-only group projections
/// (`members`, `group_mls_state`, `quarantined_groups`).
///
/// The account worker captures this from the freshly hydrated session and uses
/// it to answer read commands *while the initial relay catch-up runs in the
/// background* — the catch-up future holds `&mut AppClient`, so concurrent reads
/// cannot touch the live session and are served from this snapshot instead.
/// Membership/epoch only change on a committed group operation, which the
/// catch-up surfaces via `GroupStateUpdated` so subscribers re-read once it
/// lands; the snapshot is therefore a brief, self-healing stand-in, only used
/// until the initial catch-up completes (after which reads go live again).
///
/// Groups whose live read errored at capture time (e.g. quarantined / not yet
/// live) are simply absent; a read for an absent group returns `UnknownGroup`,
/// the same shape the live path returns for a group the session does not hold.
#[derive(Default)]
pub(crate) struct GroupReadSnapshot {
    members: HashMap<GroupId, Vec<AppGroupMemberRecord>>,
    mls_state: HashMap<GroupId, AppGroupMlsState>,
    quarantined: Vec<AppQuarantinedGroup>,
}

impl GroupReadSnapshot {
    pub(crate) fn members(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        self.members
            .get(group_id)
            .cloned()
            .ok_or_else(|| AppError::UnknownGroup(hex::encode(group_id.as_slice())))
    }

    pub(crate) fn group_mls_state(&self, group_id: &GroupId) -> Result<AppGroupMlsState, AppError> {
        self.mls_state
            .get(group_id)
            .cloned()
            .ok_or_else(|| AppError::UnknownGroup(hex::encode(group_id.as_slice())))
    }

    pub(crate) fn quarantined_groups(&self) -> Vec<AppQuarantinedGroup> {
        self.quarantined.clone()
    }
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

fn record_app_performance(
    telemetry: Option<&AppPerformanceTelemetry>,
    operation: AppPerformanceOperation,
    duration: Duration,
    success: bool,
) {
    if let Some(telemetry) = telemetry {
        telemetry.record(operation, duration, success);
    }
}

impl AppClient {
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
        fail_if_publish_failed(&effects)?;
        self.record_human_action_succeeded(&group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.add_group(&group_id)?;
        self.sync_runtime_groups().await?;
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        Ok(group_id)
    }

    pub fn members(&self, group_id: &GroupId) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        let profiles = self.app.profiles_by_id()?;
        self.members_with_profiles(group_id, &profiles)
    }

    /// Build a group's member records against a caller-provided account-profile
    /// map, avoiding a fresh `profiles_by_id` load per group. `members` loads the
    /// map for a single read; [`AppClient::group_read_snapshot`] loads it once
    /// and reuses it across every group so capturing the snapshot stays a single
    /// profile read plus in-memory engine reads (it runs on the worker readiness
    /// path).
    fn members_with_profiles(
        &self,
        group_id: &GroupId,
        profiles: &HashMap<String, String>,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        self.ensure_group(group_id)?;
        self.members_with_profiles_unchecked(group_id, profiles)
    }

    fn members_with_profiles_unchecked(
        &self,
        group_id: &GroupId,
        profiles: &HashMap<String, String>,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
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
        self.group_mls_state_unchecked(group_id)
    }

    fn group_mls_state_unchecked(&self, group_id: &GroupId) -> Result<AppGroupMlsState, AppError> {
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

    /// Stored groups that failed session-open hydration and were skipped so the
    /// rest of the account could open (darkmatter#151 / #417). The application
    /// reads this to surface a per-group recovery flow (darkmatter#426) — these
    /// groups are not in the live roster and otherwise vanish with no
    /// explanation. Each entry carries a coarse, privacy-safe recovery reason.
    pub fn quarantined_groups(&self) -> Vec<AppQuarantinedGroup> {
        self.runtime
            .quarantined_groups()
            .into_iter()
            .map(|(group_id, reason)| AppQuarantinedGroup {
                group_id_hex: hex::encode(group_id.as_slice()),
                reason: reason.into(),
            })
            .collect()
    }

    /// Capture a [`GroupReadSnapshot`] of every known group's read-only
    /// projections from the live (hydrated) session.
    ///
    /// Used by the account worker to answer read commands during the initial
    /// relay catch-up without blocking on it; see [`GroupReadSnapshot`]. Reads
    /// that error for a given group (quarantined / not yet live) are omitted —
    /// the snapshot accessor reports those as `UnknownGroup`, matching the live
    /// path for a group the session does not hold.
    ///
    /// Returns the storage error if the one shared profile load fails, rather
    /// than masking it as empty profiles (which would make every member read
    /// `account: None` / `local: false` during the catch-up window). The worker
    /// then falls back to serving those reads from the live session after
    /// catch-up, matching the live path's error semantics.
    pub(crate) fn group_read_snapshot(&self) -> Result<GroupReadSnapshot, AppError> {
        // Load account profiles once and reuse across every group: the rest of
        // the capture is in-memory engine reads, so the snapshot adds a single
        // storage read to the worker readiness path regardless of group count.
        let profiles = self.app.profiles_by_id()?;
        let mut members = HashMap::new();
        let mut mls_state = HashMap::new();
        let mut skipped_malformed_group_records = 0usize;
        for group in &self.state.groups {
            let Ok(bytes) = hex::decode(&group.group_id_hex) else {
                skipped_malformed_group_records += 1;
                continue;
            };
            let group_id = GroupId::new(bytes);
            if let Ok(records) = self.members_with_profiles_unchecked(&group_id, &profiles) {
                members.insert(group_id.clone(), records);
            }
            if let Ok(state) = self.group_mls_state_unchecked(&group_id) {
                mls_state.insert(group_id, state);
            }
        }
        if skipped_malformed_group_records > 0 {
            tracing::warn!(
                target: "marmot_app::client",
                method = "group_read_snapshot",
                skipped_malformed_group_records,
                "skipping malformed group records while building group read snapshot"
            );
        }
        Ok(GroupReadSnapshot {
            members,
            mls_state,
            quarantined: self.quarantined_groups(),
        })
    }

    /// Re-attempt hydration of a single quarantined group (darkmatter#426).
    ///
    /// This is the non-destructive, user-initiated recovery path for a
    /// transiently-bad group (e.g. a partial DB restore that has since
    /// completed). Returns `Ok(true)` if the group recovered and is now a live
    /// group, `Ok(false)` if it is still unhealthy and stays quarantined.
    /// Errors with `UnknownGroup` if the id is not currently quarantined.
    ///
    /// On success the engine queues a `GroupHydrationRecovered` event, so the
    /// caller should follow up with a sync/catch-up to surface the recovered
    /// group in chat-list projections.
    pub fn retry_hydrate_quarantined_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        Ok(self.runtime.retry_hydrate_quarantined_group(group_id)?)
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
        self.invite_members_with_optional_telemetry(group_id, member_refs, None)
            .await
    }

    pub(crate) async fn invite_members_with_telemetry(
        &mut self,
        group_id: &GroupId,
        member_refs: &[&str],
        telemetry: &AppPerformanceTelemetry,
    ) -> Result<SendSummary, AppError> {
        self.invite_members_with_optional_telemetry(group_id, member_refs, Some(telemetry))
            .await
    }

    async fn invite_members_with_optional_telemetry(
        &mut self,
        group_id: &GroupId,
        member_refs: &[&str],
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group_id)?;

        let key_package_started_at = Instant::now();
        let key_packages = async {
            let mut key_packages = Vec::with_capacity(member_refs.len());
            for member in member_refs {
                key_packages.push(self.app.member_key_package(member).await?);
            }
            Ok::<_, AppError>(key_packages)
        }
        .await;
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInviteKeyPackageLookup,
            key_package_started_at.elapsed(),
            key_packages.is_ok(),
        );
        let key_packages = key_packages?;

        let routing_refresh_started_at = Instant::now();
        let routing_refresh = self.refresh_routing();
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInviteRoutingRefresh,
            routing_refresh_started_at.elapsed(),
            routing_refresh.is_ok(),
        );
        routing_refresh?;

        let audit_context = Self::local_human_action_context(
            "invite_members",
            vec!["members"],
            Vec::new(),
            Some(member_refs.len() as u64),
        );

        let pre_send_sync_started_at = Instant::now();
        let pre_send_sync = self.sync_runtime_groups().await;
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInvitePreSendSync,
            pre_send_sync_started_at.elapsed(),
            pre_send_sync.is_ok(),
        );
        pre_send_sync?;

        let engine_publish_started_at = Instant::now();
        let effects = self
            .runtime
            .send_with_audit_context(
                SendIntent::Invite {
                    group_id: group_id.clone(),
                    key_packages,
                },
                audit_context.clone(),
            )
            .await
            .map_err(AppError::from)
            .and_then(|effects| {
                fail_if_publish_failed(&effects)?;
                Ok(effects)
            });
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInviteEnginePublish,
            engine_publish_started_at.elapsed(),
            effects.is_ok(),
        );
        let effects = effects?;

        let local_refresh_started_at = Instant::now();
        let local_refresh = (|| {
            self.record_human_action_succeeded(group_id, &audit_context, &effects);
            self.remember_published_reports(&effects);
            self.refresh_group(group_id);
            self.prune_plaintext_retention_for_group(group_id)?;
            self.app.save_state(&self.state)?;
            self.queue_own_group_system_projection_updates(&effects);
            Ok::<_, AppError>(())
        })();
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInviteLocalRefresh,
            local_refresh_started_at.elapsed(),
            local_refresh.is_ok(),
        );
        local_refresh?;

        let summary = send_summary_from_effects(&effects);

        let notification_started_at = Instant::now();
        self.publish_notification_trigger_best_effort(
            group_id,
            notifications::NotificationTrigger::GroupInvite,
        )
        .await;
        record_app_performance(
            telemetry,
            AppPerformanceOperation::GroupInviteNotificationTrigger,
            notification_started_at.elapsed(),
            true,
        );

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
        fail_if_publish_failed(&effects)?;
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

    /// Delete only this group's app-local data. This intentionally does not send
    /// an MLS leave and does not delete the stored MLS/OpenMLS group state; a
    /// future fresh group delivery can recreate the chat-list projection.
    ///
    /// The live transport route is removed and synced before the DB wipe so the
    /// account stops actively subscribing to the group before local rows vanish.
    pub async fn delete_group_local(&mut self, group_id: &GroupId) -> Result<bool, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let original_groups = self.state.groups.clone();
        let was_live = original_groups
            .iter()
            .any(|group| group.group_id_hex == group_id_hex);

        if was_live {
            self.state
                .groups
                .retain(|group| group.group_id_hex != group_id_hex);
            if let Err(error) = self.refresh_routing() {
                self.state.groups = original_groups;
                self.refresh_routing()?;
                return Err(error);
            }
            if let Err(error) = self.sync_runtime_groups().await {
                self.state.groups = original_groups;
                self.refresh_routing()?;
                self.sync_runtime_groups().await?;
                return Err(error);
            }
        }

        match self
            .app
            .delete_group_local_data(&self.state.label, &group_id_hex)
        {
            Ok(deleted) => Ok(deleted || was_live),
            Err(error) => {
                if was_live {
                    self.state.groups = original_groups;
                    self.refresh_routing()?;
                    self.sync_runtime_groups().await?;
                }
                Err(error)
            }
        }
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
        fail_if_publish_failed(&effects)?;
        self.record_human_action_succeeded(group_id, &audit_context, &effects);
        self.remember_published_reports(&effects);
        self.app.save_state(&self.state)?;
        self.queue_own_group_system_projection_updates(&effects);
        // A local leave / decline departs the group just like an observed
        // self-removal does. The inbound `observe_account_device_effects` path
        // suppresses the account unread aggregate for self-removal, but our own
        // relay echoes are skipped, so the locally initiated departure must
        // suppress here too. No-op if no `account_groups` row exists yet, so it
        // never resurrects pruned projection state. This is the source-of-truth
        // write for the account unread aggregate, so propagate its error (like
        // the nearby projection writes) rather than swallow it: a silently
        // failed update would leave `account_unread_total()` returning an
        // inflated badge after a leave that otherwise reports success.
        self.app.set_group_self_membership(
            &self.state.label,
            &hex::encode(group_id.as_slice()),
            true,
        )?;
        Ok(send_summary_from_effects(&effects))
    }

    /// One-time open/upgrade backfill of `account_groups.self_membership`.
    ///
    /// Migration 0018 defaults every existing `account_groups` row to
    /// `'member'`, which means accounts that already left / were removed from a
    /// group *before* upgrading keep an inflated `account_unread_total()`: the
    /// frozen unread row has no future removal event to flip the flag to
    /// `'removed'`. This backfill closes that gap by deriving membership from
    /// current engine state once, right after the account is opened.
    ///
    /// For each row still carrying the default `'member'`, it asks the engine
    /// for the group's roster (`runtime.members`, sourced from the Marmot
    /// record's authoritative post-merge member set) and flips the row to
    /// `'removed'` only when the call succeeds and the local account id is
    /// definitively absent. Engine errors / unknown groups are skipped so
    /// uncertainty never suppresses (matching the projection's existing
    /// invariant). The work is gated behind a once-only account-import marker,
    /// so subsequent opens are a single marker read and the hot path stays
    /// projection-only.
    pub(crate) fn backfill_self_membership_once(&self) -> Result<(), AppError> {
        if self
            .app
            .account_import_marker(&self.state.label, crate::SELF_MEMBERSHIP_BACKFILL_MARKER)?
        {
            return Ok(());
        }
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        for group_id_hex in self
            .app
            .account_group_ids_defaulting_to_member(&self.state.label)?
        {
            let Ok(group_id_bytes) = hex::decode(&group_id_hex) else {
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            // Authoritative roster from engine state. On any engine error
            // (unknown/quarantined group, partially-missing live state) leave
            // the row at the preserving default — uncertainty never suppresses.
            let Ok(members) = self.runtime.members(&group_id) else {
                continue;
            };
            if local_account_removed_from_roster(&members, &local_account_id_hex) {
                self.app
                    .set_group_self_membership(&self.state.label, &group_id_hex, true)?;
            }
        }
        self.app.mark_account_import_complete(
            &self.state.label,
            crate::SELF_MEMBERSHIP_BACKFILL_MARKER,
        )?;
        Ok(())
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
        fail_if_publish_failed(&effects)?;
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
        fail_if_publish_failed(&effects)?;
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
        fail_if_publish_failed(&effects)?;
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
        fail_if_publish_failed(&effects)?;
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
            fail_if_publish_failed(&effects)?;
            Ok::<_, AppError>(effects)
        }
        .await
        {
            Ok(effects) => effects,
            Err(err) => {
                if should_project_locally {
                    match self.app.invalidate_timeline_app_event(
                        &self.state.label,
                        &group_id_hex,
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
        self.ensure_group(group_id)?;
        self.sync_runtime_groups().await?;
        // Validate every outbound attachment against the group's ACTUAL
        // `marmot.group.encrypted-media.v1` policy before sending: a reference
        // whose locator kind the group does not allow would be rejected by
        // receivers, so fail the send early rather than emit it.
        let allowed_locator_kinds = self
            .encrypted_media_policy_for_group(group_id)?
            .allowed_locator_kinds;
        for attachment in &attachments {
            attachment.validate_outbound(
                &allowed_locator_kinds,
                self.app.allow_loopback_blob_endpoints(),
            )?;
        }
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
        // `upload_encrypted_media` always performs Blossom upload semantics and
        // emits a `blossom-v1` locator, so every default upload candidate MUST be
        // a Blossom endpoint. Iterate all usable candidates in policy order so a
        // single server outage does not fail the send. Skip loopback-HTTP policy
        // endpoints unless this build is configured for dev/test: they are valid
        // component state but a production client MUST NOT upload to the local
        // host (a remote admin could point the policy at the victim's loopback
        // services). An explicit per-request `blossom_server` override is an
        // intentional single-server dev escape hatch: it bypasses endpoint
        // failover, but the group policy must still allow `blossom-v1` locators.
        let allow_loopback = self.app.allow_loopback_blob_endpoints();
        let policy_allows_blossom = policy.allowed_locator_kinds.is_empty()
            || policy
                .allowed_locator_kinds
                .iter()
                .any(|kind| kind == BLOSSOM_LOCATOR_KIND_V1);
        if !policy_allows_blossom {
            return Err(AppError::InvalidEncryptedMedia(
                "group policy has no usable Blossom endpoint for upload".into(),
            ));
        }
        let has_explicit_server = request.blossom_server.is_some();
        let default_endpoints = if has_explicit_server {
            Vec::new()
        } else {
            let endpoints = policy
                .default_blob_endpoints
                .iter()
                .filter(|endpoint| {
                    endpoint.locator_kind == BLOSSOM_LOCATOR_KIND_V1
                        && (allow_loopback || !is_loopback_http_endpoint(&endpoint.base_url))
                })
                .cloned()
                .collect::<Vec<_>>();
            if endpoints.is_empty() {
                return Err(AppError::InvalidEncryptedMedia(
                    "group policy has no usable Blossom endpoint for upload".into(),
                ));
            }
            endpoints
        };
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
            &default_endpoints,
            &policy.allowed_locator_kinds,
            allow_loopback,
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
            &policy.allowed_locator_kinds,
            self.app.allow_loopback_blob_endpoints(),
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
        fail_if_publish_failed(&effects)?;
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
        fail_if_publish_failed(&effects)?;
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
        fail_if_publish_failed(&effects)?;
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

    /// Flip a group's local `archived` flag on the worker-owned in-memory
    /// `AccountState` and persist it. Routing archive toggles through here (and
    /// the account worker) instead of a detached `MarmotApp::set_group_archived`
    /// keeps the long-lived worker's snapshot authoritative: a later inbound
    /// delivery that re-persists `self.state` will carry the updated flag rather
    /// than silently reverting it to a stale `archived = false`.
    pub fn set_group_archived(
        &mut self,
        group_id: &GroupId,
        archived: bool,
    ) -> Result<AppGroupRecord, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let group = self
            .state
            .groups
            .iter_mut()
            .find(|group| group.group_id_hex == group_id_hex)
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
        let previous = group.archived;
        group.archived = archived;
        let group = group.clone();
        // Roll the in-memory flag back if persistence fails so the worker's
        // authoritative snapshot stays consistent with what is on disk; a later
        // unrelated `save_state` must not silently re-apply a toggle the caller
        // was told had failed.
        if let Err(err) = self.app.save_state(&self.state) {
            if let Some(group) = self
                .state
                .groups
                .iter_mut()
                .find(|group| group.group_id_hex == group_id_hex)
            {
                group.archived = previous;
            }
            return Err(err);
        }
        Ok(group)
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

    pub(crate) fn cache_current_encrypted_media_epoch_secrets(&self) {
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

    pub(crate) fn refresh_group_routes(&mut self) -> Result<(), AppError> {
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

    fn remember_published_reports(&mut self, effects: &marmot_account::AccountDeviceEffects) {
        self.pending_convergence_groups
            .extend(effects.pending_convergence.iter().cloned());
        for report in &effects.reports {
            let event_id = hex::encode(report.message_id.as_slice());
            remember_seen_event(&mut self.state, event_id);
        }
    }
}

/// Whether the local account (`local_account_id_hex`) is absent from a group's
/// engine roster — the backfill's suppression decision. MLS member ids in this
/// design are the Nostr account pubkey hex, so an account is "still a member"
/// iff some roster entry's hex id matches the local id (case-insensitively).
/// An empty roster is treated as absent. Kept pure and named so
/// [`AppClient::backfill_self_membership_once`] is unit-testable without an
/// engine harness.
fn local_account_removed_from_roster(
    members: &[cgka_traits::group::Member],
    local_account_id_hex: &str,
) -> bool {
    !members
        .iter()
        .any(|member| hex::encode(member.id.as_slice()).eq_ignore_ascii_case(local_account_id_hex))
}

#[cfg(test)]
mod self_membership_backfill_tests {
    use super::local_account_removed_from_roster;
    use cgka_traits::MemberId;
    use cgka_traits::group::Member;

    fn member(id_hex: &str) -> Member {
        Member {
            id: MemberId::new(hex::decode(id_hex).unwrap()),
            credential: Vec::new(),
        }
    }

    #[test]
    fn local_account_in_roster_is_not_removed() {
        let roster = vec![member("aa"), member("bb")];
        // Local account ("aa") is still a member: must not be flagged removed.
        assert!(!local_account_removed_from_roster(&roster, "aa"));
        // Case-insensitive id match (uppercase local id).
        assert!(!local_account_removed_from_roster(&roster, "AA"));
    }

    #[test]
    fn local_account_absent_from_roster_is_removed() {
        // Roster has only peers; the local account ("aa") was removed/left.
        let roster = vec![member("bb"), member("cc")];
        assert!(local_account_removed_from_roster(&roster, "aa"));
    }

    #[test]
    fn empty_roster_is_treated_as_removed() {
        assert!(local_account_removed_from_roster(&[], "aa"));
    }
}
