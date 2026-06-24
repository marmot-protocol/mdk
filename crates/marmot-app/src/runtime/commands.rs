//! [`AccountManager`] command-RPC wrappers: each sends an
//! [`AccountWorkerCommand`] to the per-account worker and awaits its oneshot
//! reply.

use std::time::Instant;

use cgka_traits::app_event::MarmotAppEvent as MarmotInnerEvent;
use cgka_traits::{GroupId, SecretBytes};
use tokio::sync::oneshot;

use super::{
    AccountManager, AccountWorkerCommand, account_worker_response,
    publish_app_runtime_group_state_updated,
};
use crate::app_telemetry::AppPerformanceOperation;
use crate::messages::AppMessageIntent;
use crate::{
    AgentOperationEventRequest, AgentTextStreamFinishRequest, AppBlobEndpoint, AppError,
    AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord, AppQuarantinedGroup,
    GroupInviteDeclineResult, GroupPushDebugInfo, MediaAttachmentReference, MediaDownloadResult,
    MediaUploadRequest, MediaUploadResult, PushRegistration, SendSummary,
};

impl AccountManager {
    pub async fn create_group(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
    ) -> Result<GroupId, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::CreateGroup {
                name: name.to_owned(),
                members: members.to_vec(),
                description,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let group_id = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        self.schedule_audit_log_tracker_update("create_group");
        Ok(group_id)
    }

    pub async fn group_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::Members {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn group_mls_state(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupMlsState, AppError> {
        let started_at = Instant::now();
        let result = async {
            let command = self.worker_commands(account_ref).await?;
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::GroupMlsState {
                    group_id: group_id.clone(),
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            account_worker_response(response).await
        }
        .await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::GroupMlsStateRead,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
    }

    /// Stored groups that failed session-open hydration and were skipped
    /// (darkmatter#151 / #417). Backs the per-group recovery surface
    /// (darkmatter#426).
    pub async fn quarantined_groups(
        &self,
        account_ref: &str,
    ) -> Result<Vec<AppQuarantinedGroup>, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::QuarantinedGroups { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    /// Re-attempt hydration of a single quarantined group (darkmatter#426).
    /// `Ok(true)` if it recovered and is now live, `Ok(false)` if still
    /// unhealthy. On success the recovered group is refreshed in chat-list
    /// projections.
    ///
    /// The return value reflects ONLY the engine recovery outcome — it is the
    /// contract that `true` = the group was removed from quarantine and is now
    /// live. Post-recovery catch-up (relay sync) is best-effort: once the
    /// engine has recovered the group the success is irreversible, so a failing
    /// catch-up must NOT turn an already-successful recovery into `Err` (that
    /// would make the UI show a failed retry for a group that is in fact live).
    /// A catch-up failure here just means the recovered group will sync on the
    /// next normal sync cycle; it is logged, not surfaced. (darkmatter#441
    /// finding 2.)
    pub async fn retry_hydrate_quarantined_group(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RetryHydrateQuarantinedGroup {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let recovered = account_worker_response(response).await?;
        if recovered {
            // Best-effort post-recovery sync: the engine has already made the
            // group live, so do not let a relay/account-worker sync failure
            // mask that irreversible success. Log and continue.
            if let Err(error) = self.catch_up_accounts().await {
                tracing::warn!(
                    target: "marmot_app::runtime",
                    method = "retry_hydrate_quarantined_group",
                    error = %error,
                    "group recovered from quarantine but post-recovery catch-up failed; \
                     group is live and will sync on the next cycle"
                );
            }
            self.schedule_audit_log_tracker_update("retry_hydrate_quarantined_group");
        }
        Ok(recovered)
    }

    pub async fn safe_export_secret(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        component_id: cgka_traits::AppComponentId,
    ) -> Result<SecretBytes, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SafeExportSecret {
                group_id: group_id.clone(),
                component_id,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    /// See `MarmotApp::reveal_nsec`. darkmatter#543. Reads from the keystore
    /// directly; does not require a running account worker. `caller_context` is
    /// the privacy-safe surface label recorded in the reveal audit entry.
    pub fn reveal_nsec(&self, account_ref: &str, caller_context: &str) -> Result<String, AppError> {
        self.app.reveal_nsec(account_ref, caller_context)
    }

    /// See `MarmotApp::export_encrypted_secret_key`. darkmatter#544. Reads from
    /// the keystore directly; does not require a running account worker.
    /// `caller_context` is the privacy-safe surface label recorded in the export
    /// audit entry.
    pub fn export_encrypted_secret_key(
        &self,
        account_ref: &str,
        passphrase: &str,
        caller_context: &str,
    ) -> Result<String, AppError> {
        self.app
            .export_encrypted_secret_key(account_ref, passphrase, caller_context)
    }

    pub async fn exporter_secret(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> Result<SecretBytes, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ExporterSecret {
                group_id: group_id.clone(),
                label: label.to_owned(),
                length,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn invite_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        members: &[String],
    ) -> Result<SendSummary, AppError> {
        let started_at = Instant::now();
        let result = async {
            let command = self.worker_commands(account_ref).await?;
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::InviteMembers {
                    group_id: group_id.clone(),
                    members: members.to_vec(),
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            let summary = account_worker_response(response).await?;

            let catch_up_started_at = Instant::now();
            let catch_up = self.catch_up_accounts().await;
            self.shared.app_performance_telemetry().record(
                AppPerformanceOperation::GroupInvitePostMutationCatchUp,
                catch_up_started_at.elapsed(),
                catch_up.is_ok(),
            );
            catch_up?;

            self.schedule_audit_log_tracker_update("invite_members");
            Ok(summary)
        }
        .await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::GroupInviteMembers,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
    }

    pub async fn remove_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        members: &[String],
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RemoveMembers {
                group_id: group_id.clone(),
                members: members.to_vec(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        self.schedule_audit_log_tracker_update("remove_members");
        Ok(summary)
    }

    pub async fn leave_group(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::LeaveGroup {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        self.schedule_audit_log_tracker_update("leave_group");
        Ok(summary)
    }

    pub async fn delete_group_local(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.resolve(account_ref)?;
        if !account.is_active_local_signing() {
            let group_id_hex = hex::encode(group_id.as_slice());
            let deleted = self
                .app
                .delete_group_local_data(&account.label, &group_id_hex)?;
            if deleted {
                publish_app_runtime_group_state_updated(
                    &self.events,
                    &account.account_id_hex,
                    &account.label,
                    group_id,
                );
            }
            return Ok(deleted);
        }

        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DeleteGroupLocal {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn accept_group_invite(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupRecord, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::AcceptGroupInvite {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn decline_group_invite(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<GroupInviteDeclineResult, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DeclineGroupInvite {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let result = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        self.schedule_audit_log_tracker_update("decline_group_invite");
        Ok(result)
    }

    pub async fn set_group_archived(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        archived: bool,
    ) -> Result<AppGroupRecord, AppError> {
        // Prefer the account worker so its authoritative in-memory
        // `AccountState` is updated in place; otherwise a later inbound
        // delivery would re-persist the stale `archived = false` snapshot and
        // silently un-archive the chat (darkmatter#178).
        //
        // Only a non-local-signing (public-only) account can never own a
        // long-lived worker, so its direct persistence write is safe: there is
        // no live in-memory snapshot to clobber it. For local-signing accounts
        // we MUST route through the worker and propagate any worker error. A
        // transient worker startup / `reconcile()` failure (e.g. an
        // `APP_RUNTIME_ACCOUNT_READY_WAIT` timeout while the worker is still in
        // startup sync) must NOT fall back to a direct write, because a freshly
        // spawned worker may already hold the pre-archive snapshot and would
        // later re-persist it, reverting the flag again.
        let account = self.resolve(account_ref)?;
        if !account.is_active_local_signing() {
            let group_id_hex = hex::encode(group_id.as_slice());
            return self
                .app
                .set_group_archived(&account.label, &group_id_hex, archived);
        }
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SetGroupArchived {
                group_id: group_id.clone(),
                archived,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn update_group_image(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        plaintext: Vec<u8>,
        media_type: String,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UpdateGroupImage {
                group_id: group_id.clone(),
                plaintext,
                media_type,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        Ok(summary)
    }

    pub async fn download_group_image(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<u8>, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DownloadGroupImage {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn update_message_retention(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        disappearing_message_secs: u64,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UpdateMessageRetention {
                group_id: group_id.clone(),
                disappearing_message_secs,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        self.schedule_audit_log_tracker_update("update_message_retention");
        Ok(summary)
    }

    pub async fn replace_encrypted_media_blob_endpoints(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        endpoints: Vec<AppBlobEndpoint>,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ReplaceEncryptedMediaBlobEndpoints {
                group_id: group_id.clone(),
                endpoints,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        self.schedule_audit_log_tracker_update("replace_encrypted_media_blob_endpoints");
        Ok(summary)
    }

    pub async fn update_group_avatar_url(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        url: Option<String>,
        dim: Option<String>,
        thumbhash: Option<String>,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UpdateGroupAvatarUrl {
                group_id: group_id.clone(),
                url,
                dim,
                thumbhash,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        self.schedule_audit_log_tracker_update("update_group_avatar_url");
        Ok(summary)
    }

    pub async fn promote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        let started_at = Instant::now();
        let result = async {
            let command = self.worker_commands(account_ref).await?;
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::PromoteAdmin {
                    group_id: group_id.clone(),
                    member_ref: member_ref.to_owned(),
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            let summary = account_worker_response(response).await?;
            self.catch_up_accounts().await?;
            self.schedule_audit_log_tracker_update("promote_admin");
            Ok(summary)
        }
        .await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::GroupPromoteAdmin,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
    }

    pub async fn demote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DemoteAdmin {
                group_id: group_id.clone(),
                member_ref: member_ref.to_owned(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        self.schedule_audit_log_tracker_update("demote_admin");
        Ok(summary)
    }

    pub async fn self_demote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SelfDemoteAdmin {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        self.schedule_audit_log_tracker_update("self_demote_admin");
        Ok(summary)
    }

    pub async fn update_group_profile(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UpdateGroupProfile {
                group_id: group_id.clone(),
                name,
                description,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        self.schedule_audit_log_tracker_update("update_group_profile");
        Ok(summary)
    }

    pub async fn send_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        payload: Vec<u8>,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SendMessage {
                group_id: group_id.clone(),
                payload,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.schedule_audit_log_tracker_update("send_message");
        Ok(summary)
    }

    pub(crate) async fn share_push_registration(
        &self,
        account_ref: &str,
    ) -> Result<usize, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SharePushRegistration { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let published = account_worker_response(response).await?;
        if published > 0 {
            self.schedule_audit_log_tracker_update("share_push_registration");
        }
        Ok(published)
    }

    pub(crate) async fn remove_push_registration(
        &self,
        account_ref: &str,
        registration: PushRegistration,
    ) -> Result<usize, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RemovePushRegistration {
                registration,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let removed = account_worker_response(response).await?;
        if removed > 0 {
            self.schedule_audit_log_tracker_update("remove_push_registration");
        }
        Ok(removed)
    }

    pub(crate) async fn group_push_debug_info(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<GroupPushDebugInfo, AppError> {
        let account = self.resolve(account_ref)?;
        self.reconcile().await?;
        let command = self.worker_commands(&account.account_id_hex).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::Members {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let members = account_worker_response(response)
            .await?
            .into_iter()
            .map(|member| member.member_id_hex)
            .collect::<Vec<_>>();
        self.app
            .group_push_debug_info(&account.label, &hex::encode(group_id.as_slice()), &members)
    }

    pub(crate) async fn send_app_event(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        intent: AppMessageIntent,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SendAppEvent {
                group_id: group_id.clone(),
                intent,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.schedule_audit_log_tracker_update("send_app_event");
        Ok(summary)
    }

    pub(crate) async fn send_agent_activity(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        status: String,
        text: String,
        reply_to_message_id: Option<String>,
        extra: Option<serde_json::Value>,
    ) -> Result<SendSummary, AppError> {
        self.send_app_event(
            account_ref,
            group_id,
            AppMessageIntent::AgentActivity {
                status,
                text,
                reply_to_message_id,
                extra,
            },
        )
        .await
    }

    pub(crate) async fn send_agent_operation_event(
        &self,
        account_ref: &str,
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
        self.send_app_event(
            account_ref,
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
        .await
    }

    pub(crate) async fn send_group_system_event(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        system_type: String,
        text: String,
        data: Option<serde_json::Value>,
    ) -> Result<SendSummary, AppError> {
        self.send_app_event(
            account_ref,
            group_id,
            AppMessageIntent::GroupSystem {
                system_type,
                text,
                data,
            },
        )
        .await
    }

    pub(crate) async fn upload_media(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        request: MediaUploadRequest,
    ) -> Result<MediaUploadResult, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UploadMedia {
                group_id: group_id.clone(),
                request,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let result = account_worker_response(response).await?;
        if result.sent.is_some() {
            self.schedule_audit_log_tracker_update("upload_media_send");
        }
        Ok(result)
    }

    pub(crate) async fn download_media(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        reference: MediaAttachmentReference,
    ) -> Result<MediaDownloadResult, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DownloadMedia {
                group_id: group_id.clone(),
                reference,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub(crate) async fn start_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        stream_id: Vec<u8>,
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::StartAgentTextStream {
                group_id: group_id.clone(),
                stream_id,
                quic_candidates,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let result = account_worker_response(response).await?;
        self.schedule_audit_log_tracker_update("start_agent_text_stream");
        Ok(result)
    }

    pub(crate) async fn finish_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        request: AgentTextStreamFinishRequest,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::FinishAgentTextStream {
                group_id: group_id.clone(),
                request,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let result = account_worker_response(response).await?;
        self.schedule_audit_log_tracker_update("finish_agent_text_stream");
        Ok(result)
    }

    pub async fn retry_group_convergence(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RetryGroupConvergence {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_accounts().await?;
        self.schedule_audit_log_tracker_update("retry_group_convergence");
        Ok(summary)
    }

    pub async fn publish_key_package(&self, account_ref: &str) -> Result<usize, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::PublishKeyPackage { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn rotate_key_package(&self, account_ref: &str) -> Result<usize, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RotateKeyPackage { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }
}
