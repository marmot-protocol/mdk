//! [`AccountManager`] command-RPC wrappers: each sends an
//! [`AccountWorkerCommand`] to the per-account worker and awaits its oneshot
//! reply.

use crate::RuntimePerformanceOperation as RuntimeOp;
use zeroize::Zeroizing;

use std::collections::BTreeSet;
use std::time::Instant;

use cgka_traits::app_event::MarmotAppEvent as MarmotInnerEvent;
use cgka_traits::{GroupId, SecretBytes};
use tokio::sync::{mpsc, oneshot};

use super::{
    AccountManager, AccountWorkerCommand, account_worker_response, group_contributes_co_members,
    local_account_worker_response, long_account_worker_catch_up_response,
    long_account_worker_response, publish_app_runtime_group_state_updated,
};
use crate::app_telemetry::AppPerformanceOperation;
use crate::messages::AppMessageIntent;
use crate::{
    AgentOperationEventRequest, AgentTextStreamFinishRequest, AppBlobEndpoint,
    AppCreateGroupOptions, AppDisbandRequest, AppError, AppGroupConversationSnapshot,
    AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord, AppGroupRoster,
    AppPreparedGroupImageUpload, AppQuarantinedGroup, CanonicalCreatedGroup, CreatedGroup,
    GroupInviteDeclineResult, GroupPushDebugInfo, MaintenanceRunSummary, MediaAttachmentReference,
    MediaDownloadResult, MediaUploadRequest, MediaUploadResult, NotificationSettings,
    PendingWelcomeDelivery, PushPlatform, PushRegistration, PushRegistrationShareOutcome,
    PushRegistrationSyncResult, RetentionSweepReport, SecureDeleteExpiredResult, SendSummary,
};

impl AccountManager {
    #[cfg(test)]
    pub(super) async fn unhydrated_group_count_for_test(
        &self,
        account_ref: &str,
    ) -> Result<usize, AppError> {
        let commands = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::UnhydratedGroupCount { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        match tokio::time::timeout(super::APP_RUNTIME_ACCOUNT_READY_WAIT, response).await {
            Ok(Ok(count)) => Ok(count),
            Ok(Err(_)) => Err(AppError::TransportClosed),
            Err(_) => Err(AppError::BlockingTask(
                "account worker unhydrated-group probe timed out".into(),
            )),
        }
    }

    pub(super) fn spawn_invite_catch_up(&self, command: mpsc::Sender<AccountWorkerCommand>) {
        let mut tasks = self
            .invite_catch_up_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tasks.handles.retain(|task| !task.is_finished());
        if !tasks.accepting {
            return;
        }
        let post_mutation = self.clone();
        let handle = tokio::spawn(async move {
            let catch_up_started_at = Instant::now();
            let catch_up = post_mutation.catch_up_account_commands(vec![command]).await;
            post_mutation.shared.app_performance_telemetry().record(
                AppPerformanceOperation::GroupInvitePostMutationCatchUp,
                catch_up_started_at.elapsed(),
                catch_up.is_ok(),
            );
            if let Err(error) = catch_up {
                tracing::warn!(
                    target: "marmot_app::runtime",
                    method = "invite_members",
                    error_kind = error.privacy_safe_kind(),
                    "committed mutation succeeded but post-mutation catch-up failed; state will refresh on the next cycle"
                );
            }
        });
        tasks.handles.push(handle);
    }

    /// Refresh the affected account after an irreversible mutation without
    /// changing the mutation's result. Once the command worker has confirmed
    /// a publish, a read-side catch-up fault cannot roll it back; surfacing
    /// that fault would tell the host to retry work already visible to peers.
    async fn catch_up_committed(
        &self,
        command: mpsc::Sender<AccountWorkerCommand>,
        method: &'static str,
    ) {
        let observation = self
            .shared
            .app_performance_telemetry()
            .observe(RuntimeOp::CatchUpAfterMutation);
        let result = self.catch_up_account_commands(vec![command]).await;
        observation.finish_app(&result);
        if let Err(error) = result {
            tracing::warn!(
                target: "marmot_app::runtime",
                method = method,
                error_kind = error.privacy_safe_kind(),
                "committed mutation succeeded but post-mutation catch-up failed; state will refresh on the next cycle"
            );
        }
    }

    fn spawn_create_catch_up(&self, command: mpsc::Sender<AccountWorkerCommand>) {
        let manager = self.clone();
        tokio::spawn(async move {
            // Test-only barrier (`test-policy-overrides`): lets integration
            // tests prove the caller returned while this catch-up was still
            // blocked, instead of depending on scheduler timing.
            if cfg!(feature = "test-policy-overrides")
                && let Some(barrier) = manager.shared.create_group_catch_up_barrier()
            {
                barrier.notified().await;
            }
            let started_at = Instant::now();
            let result = manager.catch_up_account_commands(vec![command]).await;
            manager
                .shared
                .app_performance_telemetry()
                .record_classified_result(
                    AppPerformanceOperation::AccountCatchUp,
                    started_at.elapsed(),
                    result
                        .as_ref()
                        .err()
                        .map(super::account_catch_up_metric_classification),
                );
            manager.shared.app_performance_telemetry().record(
                AppPerformanceOperation::GroupCreatePostMutationCatchUp,
                started_at.elapsed(),
                result.is_ok(),
            );
            if let Err(error) = result {
                tracing::warn!(
                    target: "marmot_app::runtime",
                    method = "create_group_post_mutation_catch_up",
                    error_kind = error.privacy_safe_kind(),
                    "committed group creation outpaced post-mutation catch-up; state will refresh on the next cycle"
                );
            }
        });
    }

    /// Force one complete relay-history query for a local account and project
    /// every returned event through the ordinary runtime path.
    pub async fn repair_full_history(&self, account_ref: &str) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RepairFullHistory { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        long_account_worker_catch_up_response(response).await
    }

    /// Create the group and return its canonical id. Invitation delivery is
    /// reported independently through `WelcomeDeliveryPending` events and
    /// `pending_welcome_deliveries`.
    pub async fn create_group(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
    ) -> Result<GroupId, AppError> {
        self.create_group_with_options(
            account_ref,
            name,
            members,
            AppCreateGroupOptions {
                description: description.unwrap_or_default(),
                ..Default::default()
            },
        )
        .await
    }

    /// Prewarm the current group-composition roster outside the account-worker
    /// mutation queue. Dropping the returned future cancels the caller's wait;
    /// relay-plane coalescing may still safely satisfy a later identical create
    /// request, and no KeyPackage is reserved or consumed here. Every member
    /// must also resolve a safe Marmot inbox route; missing routes return a
    /// typed readiness error while successfully fetched material stays cached.
    pub async fn prewarm_group_member_key_packages(
        &self,
        account_ref: &str,
        members: &[String],
    ) -> Result<crate::MemberKeyPackagePrewarmSummary, AppError> {
        let started_at = Instant::now();
        self.shared.lifecycle().ensure_running()?;
        self.resolve(account_ref)?;
        let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
        let result = self
            .app
            .prewarm_group_member_key_packages(&member_refs)
            .await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::GroupMemberKeyPackagePrewarm,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
    }

    pub async fn create_group_detailed(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
    ) -> Result<CreatedGroup, AppError> {
        self.create_group_with_options_detailed(
            account_ref,
            name,
            members,
            AppCreateGroupOptions {
                description: description.unwrap_or_default(),
                ..Default::default()
            },
        )
        .await
    }

    pub async fn create_group_with_initial_image(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
        initial_image: Option<crate::AppInitialGroupImage>,
    ) -> Result<GroupId, AppError> {
        self.create_group_with_options(
            account_ref,
            name,
            members,
            AppCreateGroupOptions {
                description: description.unwrap_or_default(),
                initial_image,
                ..Default::default()
            },
        )
        .await
    }

    pub async fn create_group_with_options(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        options: AppCreateGroupOptions,
    ) -> Result<GroupId, AppError> {
        let started_at = Instant::now();
        let result = async {
            let command = self.worker_commands(account_ref).await?;
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::CreateGroup {
                    queued_at: Instant::now(),
                    name: name.to_owned(),
                    members: members.to_vec(),
                    options,
                    prepared_image_upload_id: None,
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            let created = long_account_worker_response(response).await?;
            self.spawn_create_catch_up(command);
            Ok::<_, AppError>(created)
        }
        .await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::GroupCreateTotalCallerLatency,
            started_at.elapsed(),
            result.is_ok(),
        );
        let group_id = result?.group_id;
        self.schedule_audit_log_tracker_update("create_group");
        Ok(group_id)
    }

    pub async fn stage_prepared_group_image(
        &self,
        account_ref: &str,
        plaintext: Vec<u8>,
        media_type: String,
    ) -> Result<AppPreparedGroupImageUpload, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::StagePreparedGroupImage {
                plaintext,
                media_type,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn upload_prepared_group_image(
        &self,
        account_ref: &str,
        upload_id: String,
    ) -> Result<AppPreparedGroupImageUpload, AppError> {
        self.upload_prepared_group_image_to_server(account_ref, upload_id, None)
            .await
    }

    pub(crate) async fn upload_prepared_group_image_to_server(
        &self,
        account_ref: &str,
        upload_id: String,
        server: Option<String>,
    ) -> Result<AppPreparedGroupImageUpload, AppError> {
        let status = self
            .prepared_group_image_status(account_ref, upload_id.clone())
            .await?;
        if matches!(
            status.state,
            crate::AppPreparedGroupImageUploadState::Uploaded
                | crate::AppPreparedGroupImageUploadState::Consumed
        ) {
            return Ok(status);
        }
        let (command, admission) = self.media_worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UploadPreparedGroupImage {
                admission,
                upload_id,
                server,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        long_account_worker_response(response).await
    }

    pub async fn prepared_group_image_status(
        &self,
        account_ref: &str,
        upload_id: String,
    ) -> Result<AppPreparedGroupImageUpload, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::PreparedGroupImageStatus { upload_id, respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn prepared_group_images(
        &self,
        account_ref: &str,
    ) -> Result<Vec<AppPreparedGroupImageUpload>, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::PreparedGroupImages { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn create_group_with_prepared_initial_image(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
        upload_id: String,
    ) -> Result<GroupId, AppError> {
        let started_at = Instant::now();
        let result = async {
            let command = self.worker_commands(account_ref).await?;
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::CreateGroup {
                    queued_at: Instant::now(),
                    name: name.to_owned(),
                    members: members.to_vec(),
                    options: AppCreateGroupOptions {
                        description: description.unwrap_or_default(),
                        ..Default::default()
                    },
                    prepared_image_upload_id: Some(upload_id),
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            long_account_worker_response(response).await
        }
        .await;
        let result = result.map(|created| created.group_id);
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::GroupCreateTotalCallerLatency,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
    }

    pub async fn create_group_with_initial_image_detailed(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
        initial_image: Option<crate::AppInitialGroupImage>,
    ) -> Result<CreatedGroup, AppError> {
        self.create_group_with_options_detailed(
            account_ref,
            name,
            members,
            AppCreateGroupOptions {
                description: description.unwrap_or_default(),
                initial_image,
                ..Default::default()
            },
        )
        .await
    }

    pub async fn create_group_with_options_detailed(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        options: AppCreateGroupOptions,
    ) -> Result<CreatedGroup, AppError> {
        let started_at = Instant::now();
        let result = self
            .create_group_with_options_outcome(account_ref, name, members, options)
            .await
            .and_then(CanonicalCreatedGroup::into_detailed);
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::GroupCreateTotalCallerLatency,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
    }

    async fn create_group_with_options_outcome(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        options: AppCreateGroupOptions,
    ) -> Result<CanonicalCreatedGroup, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::CreateGroup {
                queued_at: Instant::now(),
                name: name.to_owned(),
                members: members.to_vec(),
                options,
                prepared_image_upload_id: None,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let result = long_account_worker_response(response).await;
        if result.is_ok() {
            self.spawn_create_catch_up(command);
            self.schedule_audit_log_tracker_update("create_group");
        }
        result
    }

    /// Accounts the local account currently shares a group with, deduplicated
    /// and excluding the account itself.
    ///
    /// See [`MarmotAppRuntime::group_co_members`] for why this lives with the
    /// worker-backed reads rather than in the directory.
    pub async fn group_co_members(&self, account_ref: &str) -> Result<Vec<String>, AppError> {
        let account = self.resolve(account_ref)?;
        let mut co_members = BTreeSet::new();
        for group in self.app.groups(&account.label)? {
            if !group_contributes_co_members(&group) {
                continue;
            }
            let group_id = GroupId::new(hex::decode(&group.group_id_hex)?);
            for member in self.group_members(account_ref, &group_id).await? {
                if member.member_id_hex != account.account_id_hex {
                    co_members.insert(member.member_id_hex);
                }
            }
        }
        Ok(co_members.into_iter().collect())
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
        local_account_worker_response(response).await
    }

    /// Read identifier-only member and admin rosters for a bounded page of
    /// groups in one account-worker round trip.
    ///
    /// The response preserves input order and fails as a whole if any group is
    /// unknown or hydration-quarantined; it never returns a partial page.
    pub async fn group_member_ids_page(
        &self,
        account_ref: &str,
        group_ids: &[GroupId],
    ) -> Result<Vec<crate::AppGroupMemberIds>, AppError> {
        if group_ids.len() > crate::MAX_GROUP_MEMBER_IDS_PAGE_SIZE {
            return Err(AppError::InvalidGroupMembershipPage(format!(
                "at most {} groups are allowed",
                crate::MAX_GROUP_MEMBER_IDS_PAGE_SIZE
            )));
        }
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::MemberIdsPage {
                group_ids: group_ids.to_vec(),
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

    pub async fn group_roster(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupRoster, AppError> {
        let snapshot = self
            .group_conversation_snapshot(account_ref, group_id)
            .await?;
        Ok(crate::groups::app_group_roster_from_session(
            crate::groups::AppGroupRosterSession {
                group_record: snapshot.group,
                members: snapshot.members,
                mls_state: snapshot.mls_state,
            },
            &snapshot.my_account_id_hex,
            snapshot.display_names,
        ))
    }

    /// Capture the group record, member projection, and MLS state in one
    /// account-worker command, then enrich member display names on a blocking
    /// task without worker queue re-entry.
    pub async fn group_conversation_snapshot(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupConversationSnapshot, AppError> {
        let account = self.resolve(account_ref)?;
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::GroupRoster {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let session = account_worker_response(response).await?;
        let member_ids = session
            .members
            .iter()
            .map(|member| member.member_id_hex.clone())
            .collect::<Vec<_>>();
        // Display names are optional directory enrichment; preserve the
        // authoritative roster if that cache is unavailable.
        let app = self.app.clone();
        let display_names =
            crate::blocking_app_task(move || app.display_names_for_account_ids(&member_ids))
                .await
                .unwrap_or_default();
        Ok(AppGroupConversationSnapshot {
            my_account_id_hex: account.account_id_hex,
            group: session.group_record,
            members: session.members,
            mls_state: session.mls_state,
            display_names,
        })
    }

    pub async fn enable_group_disbanding(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::EnableGroupDisbanding {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_committed(command, "enable_group_disbanding")
            .await;
        self.schedule_audit_log_tracker_update("enable_group_disbanding");
        Ok(summary)
    }

    pub async fn disband_group(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppDisbandRequest, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DisbandGroup {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let request = account_worker_response(response).await?;
        self.catch_up_committed(command, "disband_group").await;
        self.schedule_audit_log_tracker_update("disband_group");
        Ok(request)
    }

    pub async fn acknowledge_disband_failure(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::AcknowledgeDisbandFailure {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    /// Stored groups that failed session-open hydration and were skipped
    /// (mdk#151 / #417). Backs the per-group recovery surface
    /// (mdk#426).
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
        local_account_worker_response(response).await
    }

    /// Re-attempt hydration of a single quarantined group (mdk#426).
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
    /// next normal sync cycle; it is logged, not surfaced. (mdk#441
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
                    error_kind = error.privacy_safe_kind(),
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

    /// See `MarmotApp::reveal_nsec`. mdk#543. Reads from the keystore
    /// directly; does not require a running account worker. `caller_context` is
    /// the privacy-safe surface label recorded in the reveal audit entry.
    pub fn reveal_nsec(
        &self,
        account_ref: &str,
        caller_context: &str,
    ) -> Result<Zeroizing<String>, AppError> {
        self.app.reveal_nsec(account_ref, caller_context)
    }

    /// See `MarmotApp::export_encrypted_secret_key`. mdk#544. Reads from
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
        self.invite_members_with_initial_admins(account_ref, group_id, members, &[])
            .await
    }

    pub async fn invite_members_with_initial_admins(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        members: &[String],
        initial_admins: &[String],
    ) -> Result<SendSummary, AppError> {
        let started_at = Instant::now();
        let result = async {
            let command = self.worker_commands(account_ref).await?;
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::InviteMembers {
                    group_id: group_id.clone(),
                    members: members.to_vec(),
                    initial_admins: initial_admins.to_vec(),
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            let summary = account_worker_response(response).await?;
            self.spawn_invite_catch_up(command);

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
        self.catch_up_committed(command, "remove_members").await;
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
        self.catch_up_committed(command, "leave_group").await;
        self.schedule_audit_log_tracker_update("leave_group");
        Ok(summary)
    }

    pub async fn forget_group_local(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.resolve(account_ref)?;
        if !account.is_active_local_signing() {
            use cgka_traits::storage::GroupStorage;
            let changed = self
                .app
                .account_storage(&account.label)?
                .forget_group_local(group_id, cgka_traits::Timestamp(crate::unix_now_seconds()))?;
            if changed {
                publish_app_runtime_group_state_updated(
                    &self.events,
                    &account.account_id_hex,
                    &account.label,
                    group_id,
                );
            }
            return Ok(changed);
        }

        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ForgetGroupLocal {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
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

    pub async fn group_recovery_status(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<crate::GroupRecoveryStatus, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::GroupRecoveryStatus {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn confirm_group_rejoin(
        &self,
        account_ref: &str,
        welcome_id: &cgka_traits::MessageId,
        token: &[u8],
    ) -> Result<crate::GroupRecoveryStatus, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ConfirmGroupRejoin {
                welcome_id: welcome_id.clone(),
                token: token.to_vec(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn decline_group_rejoin(
        &self,
        account_ref: &str,
        welcome_id: &cgka_traits::MessageId,
    ) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DeclineGroupRejoin {
                welcome_id: welcome_id.clone(),
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
        let started_at = Instant::now();
        let result = async {
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
        .await;
        self.shared
            .app_performance_telemetry()
            .record_classified_result(
                AppPerformanceOperation::GroupAcceptInvite,
                started_at.elapsed(),
                result.as_ref().err().map(|error| {
                    crate::SyncFailureClassification::new(
                        crate::SyncFailureStage::AccountWorker,
                        error.sync_error_class(),
                    )
                }),
            );
        result
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
        self.catch_up_committed(command, "decline_group_invite")
            .await;
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
        // silently un-archive the chat (mdk#178).
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
        local_account_worker_response(response).await
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
        let summary = long_account_worker_response(response).await?;
        self.catch_up_committed(command, "update_group_image").await;
        Ok(summary)
    }

    pub async fn download_group_blossom_image(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<u8>, AppError> {
        let (command, admission) = self.media_worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DownloadGroupImage {
                admission,
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        long_account_worker_response(response).await
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
        self.catch_up_committed(command, "update_message_retention")
            .await;
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
        self.catch_up_committed(command, "replace_encrypted_media_blob_endpoints")
            .await;
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
        self.catch_up_committed(command, "update_group_avatar_url")
            .await;
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
            self.catch_up_committed(command, "promote_admin").await;
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
        self.catch_up_committed(command, "demote_admin").await;
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
        self.catch_up_committed(command, "self_demote_admin").await;
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
        self.catch_up_committed(command, "update_group_profile")
            .await;
        self.schedule_audit_log_tracker_update("update_group_profile");
        Ok(summary)
    }

    pub async fn send_message_draft(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        revision: crate::MessageDraftRevision,
        attachments: Vec<MediaAttachmentReference>,
    ) -> Result<SendSummary, AppError> {
        let telemetry = self.shared.app_performance_telemetry();
        let caller = telemetry.observe(RuntimeOp::DraftSendCaller);
        let enqueued_at = Instant::now();
        let result = async {
            let acquire = telemetry.observe(RuntimeOp::SendWorkerAcquire);
            let command = self.worker_commands(account_ref).await;
            acquire.finish_app(&command);
            let command = command?;
            let (respond, response) = oneshot::channel();
            let admission = telemetry.observe(RuntimeOp::SendAdmission);
            let admitted = command
                .send(AccountWorkerCommand::SendMessageDraft {
                    enqueued_at,
                    queued: Some(telemetry.observe(RuntimeOp::SendQueue)),
                    group_id: group_id.clone(),
                    revision,
                    attachments,
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed);
            admission.finish_app(&admitted);
            admitted?;
            account_worker_response(response).await
        }
        .await;
        caller.finish_app(&result);
        telemetry.record(
            AppPerformanceOperation::OutboundMessageResponse,
            enqueued_at.elapsed(),
            result.is_ok(),
        );
        let summary = result?;
        self.schedule_audit_log_tracker_update("send_message_draft");
        Ok(summary)
    }

    pub async fn send_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        payload: Vec<u8>,
    ) -> Result<SendSummary, AppError> {
        let telemetry = self.shared.app_performance_telemetry();
        let caller = telemetry.observe(RuntimeOp::DirectSendCaller);
        let enqueued_at = Instant::now();
        let result = async {
            let acquire = telemetry.observe(RuntimeOp::SendWorkerAcquire);
            let command = self.worker_commands(account_ref).await;
            acquire.finish_app(&command);
            let command = command?;
            let (respond, response) = oneshot::channel();
            let admission = telemetry.observe(RuntimeOp::SendAdmission);
            let admitted = command
                .send(AccountWorkerCommand::SendMessage {
                    enqueued_at,
                    queued: Some(telemetry.observe(RuntimeOp::SendQueue)),
                    group_id: group_id.clone(),
                    payload,
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed);
            admission.finish_app(&admitted);
            admitted?;
            account_worker_response(response).await
        }
        .await;
        caller.finish_app(&result);
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::OutboundMessageResponse,
            enqueued_at.elapsed(),
            result.is_ok(),
        );
        let summary = result?;
        self.schedule_audit_log_tracker_update("send_message");
        Ok(summary)
    }

    pub(crate) async fn share_push_registration(
        &self,
        account_ref: &str,
    ) -> Result<PushRegistrationShareOutcome, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SharePushRegistration { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let outcome = account_worker_response(response).await?;
        if outcome.succeeded_groups > 0 {
            self.schedule_audit_log_tracker_update("share_push_registration");
        }
        Ok(outcome)
    }

    pub(crate) async fn upsert_push_registration(
        &self,
        account_ref: &str,
        platform: PushPlatform,
        raw_token: &str,
        server_pubkey_hex: &str,
        relay_hint: Option<String>,
    ) -> Result<PushRegistrationSyncResult, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UpsertPushRegistration {
                platform,
                raw_token: Zeroizing::new(raw_token.to_owned()),
                server_pubkey_hex: server_pubkey_hex.to_owned(),
                relay_hint,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let result = account_worker_response(response).await?;
        if result.share.succeeded_groups > 0 {
            self.schedule_audit_log_tracker_update("upsert_push_registration");
        }
        Ok(result)
    }

    pub(crate) async fn clear_push_registration(
        &self,
        account_ref: &str,
    ) -> Result<PushRegistrationShareOutcome, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ClearPushRegistration { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let outcome = account_worker_response(response).await?;
        if outcome.succeeded_groups > 0 {
            self.schedule_audit_log_tracker_update("clear_push_registration");
        }
        Ok(outcome)
    }

    pub(crate) async fn set_native_push_enabled(
        &self,
        account_ref: &str,
        enabled: bool,
    ) -> Result<NotificationSettings, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SetNativePushEnabled { enabled, respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
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
        let enqueued_at = Instant::now();
        let result = async {
            let command = self.worker_commands(account_ref).await?;
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::SendAppEvent {
                    enqueued_at,
                    group_id: group_id.clone(),
                    intent,
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            account_worker_response(response).await
        }
        .await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::OutboundMessageResponse,
            enqueued_at.elapsed(),
            result.is_ok(),
        );
        let summary = result?;
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

    pub(crate) async fn send_custom_event(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Result<SendSummary, AppError> {
        self.send_app_event(
            account_ref,
            group_id,
            AppMessageIntent::Custom {
                kind,
                tags,
                content,
            },
        )
        .await
    }

    pub(crate) async fn create_poll(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        question: String,
        options: Vec<String>,
        poll_type: cgka_traits::PollType,
        ends_at: Option<u64>,
    ) -> Result<SendSummary, AppError> {
        self.send_app_event(
            account_ref,
            group_id,
            AppMessageIntent::Poll {
                question,
                options,
                poll_type,
                ends_at,
            },
        )
        .await
    }

    pub(crate) async fn cast_poll_vote(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        poll_event_id: String,
        option_ids: Vec<String>,
    ) -> Result<SendSummary, AppError> {
        let account = self.resolve(account_ref)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let poll = self
            .app
            .timeline_message(&account.label, &group_id_hex, &poll_event_id)?
            .and_then(|message| message.poll)
            .ok_or_else(|| {
                AppError::InvalidAppMessagePayload(
                    "poll response requires a valid locally accepted poll in this group".into(),
                )
            })?;
        if !poll.open {
            return Err(AppError::InvalidAppMessagePayload("poll is closed".into()));
        }
        let option_ids_in_poll = poll
            .options
            .iter()
            .map(|option| option.id.clone())
            .collect::<Vec<_>>();
        cgka_traits::validate_poll_selection(poll.poll_type, &option_ids_in_poll, &option_ids)
            .map_err(|error| AppError::InvalidAppMessagePayload(error.to_string()))?;
        self.send_app_event(
            &account.label,
            group_id,
            AppMessageIntent::PollResponse {
                poll_event_id,
                option_ids,
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
        let (command, admission) = self.media_worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UploadMedia {
                admission,
                group_id: group_id.clone(),
                request,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let result = long_account_worker_response(response).await?;
        if result.sent.is_some() {
            self.schedule_audit_log_tracker_update("upload_media_send");
        }
        Ok(result)
    }

    pub(crate) async fn build_media_imeta_tag(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        reference: MediaAttachmentReference,
    ) -> Result<Vec<String>, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::BuildMediaImetaTag {
                group_id: group_id.clone(),
                reference,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub(crate) async fn download_media(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        reference: MediaAttachmentReference,
    ) -> Result<MediaDownloadResult, AppError> {
        let enqueued_at = Instant::now();
        let (command, admission) = self.media_worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DownloadMedia {
                admission,
                group_id: group_id.clone(),
                reference,
                enqueued_at,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        long_account_worker_response(response).await
    }

    pub(crate) async fn secure_delete_expired_plaintext(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SecureDeleteExpiredResult, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SecureDeleteExpiredPlaintext {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub(crate) async fn sweep_expired_retention(
        &self,
        account_ref: &str,
        now_ms: u64,
    ) -> Result<RetentionSweepReport, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SweepExpiredRetention { now_ms, respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub(crate) async fn start_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        stream_id: Vec<u8>,
        parent_message_id: Option<String>,
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::StartAgentTextStream {
                group_id: group_id.clone(),
                stream_id,
                parent_message_id,
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
        self.catch_up_committed(command, "retry_group_convergence")
            .await;
        self.schedule_audit_log_tracker_update("retry_group_convergence");
        Ok(summary)
    }

    pub async fn pending_welcome_deliveries(
        &self,
        account_ref: &str,
    ) -> Result<Vec<PendingWelcomeDelivery>, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::PendingWelcomeDeliveries { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn redeliver_welcome(
        &self,
        account_ref: &str,
        message_id_hex: &str,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RedeliverWelcome {
                message_id_hex: message_id_hex.to_owned(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.schedule_audit_log_tracker_update("redeliver_welcome");
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

    pub(crate) async fn publish_setup_key_package(
        &self,
        account_ref: &str,
    ) -> Result<usize, AppError> {
        let command = self.worker_commands_for_setup(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::PublishSetupKeyPackage { respond })
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

    pub async fn key_package_maintenance_status(
        &self,
        account_ref: &str,
    ) -> Result<Option<cgka_traits::KeyPackageLifecycleState>, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::KeyPackageMaintenanceStatus { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn diagnostic_key_package_maintenance_status(
        &self,
        account_ref: &str,
    ) -> Result<Option<Option<cgka_traits::KeyPackageLifecycleState>>, AppError> {
        let Some(command) = self.existing_worker_commands(account_ref).await? else {
            return Ok(None);
        };
        let (respond, response) = oneshot::channel();
        command
            .try_send(AccountWorkerCommand::KeyPackageMaintenanceStatus { respond })
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    AppError::AccountWorkerResponseTimedOut
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => AppError::TransportClosed,
            })?;
        Ok(Some(account_worker_response(response).await?))
    }

    pub async fn diagnostic_group_mls_state(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Option<AppGroupMlsState>, AppError> {
        let Some(command) = self.existing_worker_commands(account_ref).await? else {
            return Ok(None);
        };
        let (respond, response) = oneshot::channel();
        command
            .try_send(AccountWorkerCommand::GroupMlsState {
                group_id: group_id.clone(),
                respond,
            })
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    AppError::AccountWorkerResponseTimedOut
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => AppError::TransportClosed,
            })?;
        Ok(Some(account_worker_response(response).await?))
    }

    pub async fn durably_owned_key_packages(
        &self,
        account_ref: &str,
    ) -> Result<Vec<cgka_traits::engine::KeyPackage>, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DurablyOwnedKeyPackages { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn maintenance_status(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<cgka_traits::GroupMaintenanceStatus, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::MaintenanceStatus {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn schedule_manual_self_update(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<String, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ScheduleManualSelfUpdate {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn periodic_maintenance_policy(
        &self,
        account_ref: &str,
    ) -> Result<cgka_traits::PeriodicMaintenancePolicy, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::PeriodicMaintenancePolicy { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn set_periodic_maintenance_policy(
        &self,
        account_ref: &str,
        policy: cgka_traits::PeriodicMaintenancePolicy,
    ) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SetPeriodicMaintenancePolicy { policy, respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn pause_maintenance(&self, account_ref: &str) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::PauseMaintenance { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn resume_maintenance(&self, account_ref: &str) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ResumeMaintenance { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn run_due_maintenance(
        &self,
        account_ref: &str,
    ) -> Result<MaintenanceRunSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RunDueMaintenance { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_committed(command, "run_due_maintenance")
            .await;
        self.schedule_audit_log_tracker_update("run_due_maintenance");
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn accept_waits_past_local_limit() {
        use super::super::{ManagedAccountWorker, MarmotAppRuntime};
        let dir = tempfile::tempdir().unwrap();
        let account = marmot_account::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let runtime = MarmotAppRuntime::new(crate::MarmotApp::with_relay(
            dir.path(),
            "wss://relay.example",
        ));
        let manager = runtime.accounts();
        let (commands, mut received) = mpsc::channel(1);
        let (shutdown, stopped) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let Some(AccountWorkerCommand::AcceptGroupInvite { respond, .. }) =
                received.recv().await
            else {
                panic!("expected invite acceptance");
            };
            tokio::time::sleep(std::time::Duration::from_secs(11)).await;
            respond
                .send(Err(AppError::InvalidAppMessagePayload(
                    "test protocol failure".into(),
                )))
                .unwrap();
            let _ = stopped.await;
        });
        manager.workers.lock().await.insert(
            account.account_id_hex.clone(),
            ManagedAccountWorker {
                ready: true,
                media_admission: std::sync::Arc::new(tokio::sync::Semaphore::new(
                    super::super::MEDIA_COMMAND_QUEUE_LIMIT,
                )),
                handle,
                commands,
                shutdown,
            },
        );
        let error = manager
            .accept_group_invite(&account.label, &GroupId::new([1; 16]))
            .await
            .unwrap_err();
        assert!(
            matches!(error, AppError::InvalidAppMessagePayload(_)),
            "{error}"
        );
        let recorded = manager
            .shared
            .app_performance_telemetry()
            .snapshot()
            .group_accept_invite;
        assert_eq!(recorded.attempts, 1);
        assert_eq!(
            recorded.failure_classifications[0]
                .classification
                .error_class,
            crate::SyncErrorClass::Protocol
        );
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn catch_up_uses_mutation_worker() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = super::super::MarmotAppRuntime::new(crate::MarmotApp::with_relay(
            dir.path(),
            "wss://relay.example",
        ));
        let manager = runtime.accounts();
        let (command, mut received) = mpsc::channel(1);
        let catch_up = manager.catch_up_committed(command, "test");
        let worker = async {
            let Some(AccountWorkerCommand::CatchUp { respond }) = received.recv().await else {
                panic!("catch-up must reach the mutation's worker");
            };
            respond.send(Ok(crate::SyncSummary::default())).unwrap();
            assert!(received.recv().await.is_none(), "exactly one catch-up");
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(catch_up, worker);
        })
        .await
        .unwrap();
        assert!(manager.workers.lock().await.is_empty(), "no reconciliation");
    }

    #[tokio::test]
    async fn diagnostic_reads_reject_saturated_worker_queue() {
        use super::super::{ManagedAccountWorker, MarmotAppRuntime};
        let dir = tempfile::tempdir().unwrap();
        let account = marmot_account::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let runtime = MarmotAppRuntime::new(crate::MarmotApp::with_relay(
            dir.path(),
            "wss://relay.example",
        ));
        let (commands, mut received) = mpsc::channel(1);
        let (respond, _response) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::KeyPackageMaintenanceStatus { respond })
            .unwrap();
        let (shutdown, stopped) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = stopped.await;
        });
        runtime.accounts().workers.lock().await.insert(
            account.account_id_hex.clone(),
            ManagedAccountWorker {
                ready: true,
                media_admission: std::sync::Arc::new(tokio::sync::Semaphore::new(
                    super::super::MEDIA_COMMAND_QUEUE_LIMIT,
                )),
                handle,
                commands,
                shutdown,
            },
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            assert!(matches!(
                runtime
                    .diagnostic_key_package_maintenance_status(&account.label)
                    .await,
                Err(AppError::AccountWorkerResponseTimedOut)
            ));
            assert!(matches!(
                runtime
                    .diagnostic_group_mls_state(&account.label, &GroupId::new([1; 16]))
                    .await,
                Err(AppError::AccountWorkerResponseTimedOut)
            ));
        })
        .await
        .expect("diagnostic enqueue must not wait for queue capacity");
        assert_eq!(runtime.reconcile_invocation_count().await, 0);
        assert!(received.try_recv().is_ok());
        assert!(received.try_recv().is_err());
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn diagnostic_reads_do_not_start_or_reconcile_workers() {
        use super::super::{ManagedAccountWorker, MarmotAppRuntime};
        let dir = tempfile::tempdir().unwrap();
        let account = marmot_account::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let runtime = MarmotAppRuntime::new(crate::MarmotApp::with_relay(
            dir.path(),
            "wss://relay.example",
        ));
        let group_id = GroupId::new([1; 16]);
        assert!(
            runtime
                .diagnostic_key_package_maintenance_status(&account.label)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            runtime
                .diagnostic_group_mls_state(&account.label, &group_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(runtime.reconcile_invocation_count().await, 0);
        assert!(runtime.accounts().workers.lock().await.is_empty());

        let manager = runtime.accounts();
        let (commands, mut received) = mpsc::channel(1);
        let (shutdown, stopped) = oneshot::channel();
        let handle = tokio::spawn(async move {
            while let Some(command) = received.recv().await {
                match command {
                    AccountWorkerCommand::KeyPackageMaintenanceStatus { respond } => {
                        respond.send(Ok(None)).unwrap();
                    }
                    AccountWorkerCommand::GroupMlsState { respond, .. } => {
                        respond
                            .send(Err(AppError::UnknownGroup("missing".into())))
                            .unwrap();
                    }
                    _ => panic!("diagnostic path sent an unexpected command"),
                }
            }
            let _ = stopped.await;
        });
        manager.workers.lock().await.insert(
            account.account_id_hex.clone(),
            ManagedAccountWorker {
                ready: true,
                media_admission: std::sync::Arc::new(tokio::sync::Semaphore::new(
                    super::super::MEDIA_COMMAND_QUEUE_LIMIT,
                )),
                handle,
                commands,
                shutdown,
            },
        );
        assert!(
            runtime
                .diagnostic_key_package_maintenance_status(&account.label)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            runtime
                .diagnostic_group_mls_state(&account.label, &group_id)
                .await
                .unwrap_err()
                .to_string()
                .contains("unknown local group")
        );
        assert_eq!(runtime.reconcile_invocation_count().await, 0);
        runtime.shutdown().await;
    }
}
