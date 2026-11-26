//! [`AccountManager`] command-RPC wrappers: each sends an
//! [`AccountWorkerCommand`] to the per-account worker and awaits its oneshot
//! reply.

use crate::RuntimePerformanceOperation as RuntimeOp;
use zeroize::Zeroizing;

use std::sync::Arc;
use std::time::Instant;

use cgka_traits::{GroupId, SecretBytes};
use tokio::sync::{mpsc, oneshot};

use super::account_worker::GroupCreationRequest;
use super::{
    AccountManager, AccountWorkerCommand, Emit, ReadClass, ReadReply, Unpublished, WorkerCommands,
    WorkerLane, account_worker_response, local_account_worker_response,
    long_account_worker_catch_up_response, long_account_worker_response,
    publish_app_runtime_group_state_updated,
};
use crate::client::read_state::{ReadAnswer, ReadState, reissue};
use crate::messages::AppMessageIntent;
use crate::{
    AppBlobEndpoint, AppCreateGroupOptions, AppDisbandRequest, AppError,
    AppGroupConversationSnapshot, AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord,
    AppGroupRoster, AppPreparedGroupImageUpload, AppQuarantinedGroup, CanonicalCreatedGroup,
    CreatedGroup, GroupInviteDeclineResult, GroupPushDebugInfo, MaintenanceRunSummary,
    MediaAttachmentReference, MediaDownloadResult, MediaUploadRequest, MediaUploadResult,
    NotificationSettings, PendingWelcomeDelivery, PushPlatform, PushRegistration,
    PushRegistrationShareOutcome, PushRegistrationSyncResult, RetentionSweepReport,
    SecureDeleteExpiredResult, SendSummary,
};
use marmot_observability::AppPerformanceOperation;

/// How a read answered from A behaves where its worker command differs: the
/// wait a request to the worker takes, and whether a failure is counted.
#[derive(Clone, Copy)]
enum StateRead {
    /// An in-memory read the worker answers through `reply`, within the
    /// local wait.
    Local,
    /// A storage read the worker answers through `respond_diagnosed`,
    /// within the app wait: a failure is counted as a storage failure.
    Diagnosed,
    /// A read the worker answers through `respond_diagnosed` within the
    /// local wait: a failure is counted as a storage failure.
    DiagnosedLocal,
    /// A storage read the worker answers through `reply`, within the app
    /// wait: no failure is counted.
    Uncounted,
}

impl StateRead {
    fn counts_failures(self) -> bool {
        matches!(self, Self::Diagnosed | Self::DiagnosedLocal)
    }

    async fn wait<T>(
        self,
        response: oneshot::Receiver<Result<T, AppError>>,
    ) -> Result<T, AppError> {
        match self {
            Self::Local | Self::DiagnosedLocal => local_account_worker_response(response).await,
            Self::Diagnosed | Self::Uncounted => account_worker_response(response).await,
        }
    }
}

/// How a read reaches the worker when it has to.
#[derive(Clone, Copy)]
enum Admission {
    /// Wait for room in the worker's queue, as any host command does.
    Queue,
    /// Refuse a full queue rather than wait in it, as diagnostics do.
    Refuse,
}

/// What a group read does with a failed hydration of a group it names: the
/// reads that propagated one before they answered from A return it, the
/// others answer from the acknowledging version regardless.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HydrationFailure {
    Returned,
    Ignored,
}

/// Why a group read did not reach an answer.
enum GroupReadVersionError {
    /// The worker did not answer the hydration request: not counted.
    Wait(AppError),
    /// The read's own failure: counted as its answer would be.
    Answer(AppError),
}

impl AccountManager {
    /// One account read answered from the worker's published read state, A
    /// (mdk#3273). Admission is the worker lane's, as for a read the worker
    /// answers; the answer then comes from one version on the caller's task,
    /// with no queue wait. The worker answers instead, through `command`,
    /// before its first publish and for a published failure that has no
    /// exact copy ([`reissue`]).
    async fn read_from_state<T>(
        &self,
        account_ref: &str,
        class: ReadClass,
        read: StateRead,
        answer: impl FnOnce(&ReadState) -> ReadAnswer<T>,
        command: impl FnOnce(ReadReply<Result<T, AppError>>) -> AccountWorkerCommand,
    ) -> Result<T, AppError> {
        self.read_from_state_where_held(
            account_ref,
            class,
            read,
            |state| Some(answer(state)),
            command,
        )
        .await
    }

    /// [`Self::read_from_state`] for a read whose answer the version may not
    /// hold: `answer` gives `None` for such a request, which the worker
    /// then answers.
    async fn read_from_state_where_held<T>(
        &self,
        account_ref: &str,
        class: ReadClass,
        read: StateRead,
        answer: impl FnOnce(&ReadState) -> Option<ReadAnswer<T>>,
        command: impl FnOnce(ReadReply<Result<T, AppError>>) -> AccountWorkerCommand,
    ) -> Result<T, AppError> {
        let lane = self.worker_lane(account_ref).await?;
        if let Some(answer) = self.answer_from_state(&lane, read, answer) {
            return answer;
        }
        self.ask_worker(&lane, class, read, Admission::Queue, command)
            .await
    }

    /// `answer` from `lane`'s current version of A, or `None` when the
    /// worker must answer: before its first publish, for a request the
    /// version holds no answer to (`answer` gives `None`), or for a
    /// published failure [`reissue`] cannot copy exactly.
    fn answer_from_state<T>(
        &self,
        lane: &WorkerLane,
        read: StateRead,
        answer: impl FnOnce(&ReadState) -> Option<ReadAnswer<T>>,
    ) -> Option<Result<T, AppError>> {
        let result = match lane.read_state.version(&self.app.storage_closed) {
            Ok(Some(state)) => reissue(answer(&state)?)?,
            Ok(None) => return None,
            Err(error) => Err(error),
        };
        Some(self.counted(read, result))
    }

    /// One group read answered from A (mdk#3273 PR 4), as
    /// [`Self::read_from_state`], with the hydration request: when the
    /// version shows a group in `group_ids` seeded but not hydrated, the
    /// read asks the worker to hydrate it, within the read's wait, and
    /// answers from the version that acknowledges the request. There each
    /// named group is live, quarantined or gone. `answer` gives `None` for a
    /// published failure with no exact copy, which the worker then answers.
    #[allow(clippy::too_many_arguments)]
    async fn read_group_from_state<T, Fut>(
        &self,
        lane: &WorkerLane,
        class: ReadClass,
        read: StateRead,
        admission: Admission,
        group_ids: &[GroupId],
        hydration: HydrationFailure,
        answer: impl FnOnce(Arc<ReadState>) -> Fut,
        command: impl FnOnce(ReadReply<Result<T, AppError>>) -> AccountWorkerCommand,
    ) -> Result<T, AppError>
    where
        Fut: Future<Output = Option<Result<T, AppError>>>,
    {
        let state = match self
            .group_read_version(lane, class, read, admission, group_ids, hydration)
            .await
        {
            Ok(Some(state)) => state,
            Ok(None) => return self.ask_worker(lane, class, read, admission, command).await,
            Err(GroupReadVersionError::Wait(error)) => return Err(error),
            Err(GroupReadVersionError::Answer(error)) => return self.counted(read, Err(error)),
        };
        match answer(state).await {
            Some(result) => self.counted(read, result),
            None => self.ask_worker(lane, class, read, admission, command).await,
        }
    }

    /// The version a group read answers from: the lane's current one, or
    /// once a named group awaits hydration there, the one acknowledging the
    /// request to hydrate it. `None` before the worker's first publish.
    async fn group_read_version(
        &self,
        lane: &WorkerLane,
        class: ReadClass,
        read: StateRead,
        admission: Admission,
        group_ids: &[GroupId],
        hydration: HydrationFailure,
    ) -> Result<Option<Arc<ReadState>>, GroupReadVersionError> {
        let state = match lane.read_state.version(&self.app.storage_closed) {
            Ok(Some(state)) => state,
            Ok(None) => return Ok(None),
            Err(error) => return Err(GroupReadVersionError::Answer(error)),
        };
        let awaiting = state.awaiting_hydration(group_ids);
        if awaiting.is_empty() {
            return Ok(Some(state));
        }
        let ack = self
            .ask_worker(lane, class, read, admission, |respond| {
                AccountWorkerCommand::HydrateGroups {
                    group_ids: awaiting,
                    respond,
                }
            })
            .await
            .map_err(GroupReadVersionError::Wait)?;
        let state = ack
            .version(&self.app.storage_closed)
            .map_err(GroupReadVersionError::Answer)?;
        match ack.failure {
            Some(failure) if hydration == HydrationFailure::Returned => {
                Err(GroupReadVersionError::Answer(failure))
            }
            _ => Ok(Some(state)),
        }
    }

    /// Wait on the caller's task, within a diagnosed read's wait, for a
    /// version of A that holds every group in `group_ids` whose stored row
    /// remains, or lists it quarantined (mdk#3273 PR 4). A read whose groups
    /// come from stored rows waits here before it reads them from A: every
    /// stored group is in the first version published after its row
    /// commits, so a group whose row committed before the read began
    /// answers from A rather than as unknown. A group forgotten or deleted
    /// since is not waited for; the read then answers it as unknown, as the
    /// worker would. Resolves at once before the worker's first publish,
    /// when the reads go to the worker. A wait that runs out fails with
    /// [`AppError::AccountWorkerResponseTimedOut`].
    pub(crate) async fn wait_for_published_groups(
        &self,
        account_ref: &str,
        group_ids: &[GroupId],
    ) -> Result<(), AppError> {
        let account = self.resolve(account_ref)?;
        let lane = self.worker_lane(account_ref).await?;
        let still_stored = |waiting: Vec<GroupId>| {
            let storage = self.app.account_storage(&account.label)?;
            let mut stored = Vec::with_capacity(waiting.len());
            for group_id in waiting {
                if !storage
                    .app_storage()
                    .account_groups(Some(&hex::encode(group_id.as_slice())))?
                    .is_empty()
                {
                    stored.push(group_id);
                }
            }
            Ok(stored)
        };
        tokio::time::timeout(
            crate::APP_RUNTIME_WORKER_RESPONSE_WAIT,
            lane.read_state
                .holding(&self.app.storage_closed, group_ids, still_stored),
        )
        .await
        .map_err(|_| AppError::AccountWorkerResponseTimedOut)?
    }

    /// Send `command` to the worker and wait for its answer, within the
    /// read's wait and observed under its class.
    async fn ask_worker<T>(
        &self,
        lane: &WorkerLane,
        class: ReadClass,
        read: StateRead,
        admission: Admission,
        command: impl FnOnce(ReadReply<Result<T, AppError>>) -> AccountWorkerCommand,
    ) -> Result<T, AppError> {
        let (respond, response) = lane.read_reply(self.shared.observer.performance(), class);
        match admission {
            Admission::Queue => lane
                .commands
                .send(command(respond))
                .await
                .map_err(|_| AppError::TransportClosed)?,
            Admission::Refuse => {
                lane.commands
                    .try_send(command(respond))
                    .map_err(|error| match error {
                        mpsc::error::TrySendError::Full(_) => {
                            AppError::AccountWorkerResponseTimedOut
                        }
                        mpsc::error::TrySendError::Closed(_) => AppError::TransportClosed,
                    })?
            }
        }
        read.wait(response).await
    }

    /// `result`, its failure counted as a storage failure where the read's
    /// worker command counts one.
    fn counted<T>(&self, read: StateRead, result: Result<T, AppError>) -> Result<T, AppError> {
        if let (true, Err(error)) = (read.counts_failures(), &result) {
            let product = self.shared.observer.product();
            product.storage_failure(product.permit().as_ref(), error);
        }
        result
    }

    /// The account profiles a member read names members by, loaded at read
    /// time off the caller's task, as the worker loaded them for its read.
    /// Each load is one `account_profile_load` sample.
    async fn member_profiles(&self) -> Result<std::collections::HashMap<String, String>, AppError> {
        let app = self.app.clone();
        let started_at = Instant::now();
        let profiles = crate::blocking_app_task(move || app.profiles_by_id()).await;
        self.shared.observer.performance().record(
            AppPerformanceOperation::AccountProfileLoad,
            started_at.elapsed(),
            profiles.is_ok(),
        );
        profiles
    }

    #[cfg(test)]
    pub(super) async fn unlink_device_for_test(&self, account_ref: &str) -> Result<(), AppError> {
        let commands = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::UnlinkDeviceForTest { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        response.await.map_err(|_| AppError::TransportClosed)?
    }

    #[cfg(test)]
    pub(super) async fn overdue_component_recheck_for_test(
        &self,
        account_ref: &str,
    ) -> Result<(), AppError> {
        let commands = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::OverdueComponentRecheckForTest { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        response.await.map_err(|_| AppError::TransportClosed)?
    }

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

    pub(super) fn spawn_invite_catch_up(&self, command: WorkerCommands) {
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
            post_mutation.shared.observer.performance().record(
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
    async fn catch_up_committed(&self, command: WorkerCommands, method: &'static str) {
        let observation = self
            .shared
            .observer
            .performance()
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

    fn spawn_create_catch_up(&self, command: WorkerCommands) {
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
                .observer
                .performance()
                .record_classified_result(
                    AppPerformanceOperation::AccountCatchUp,
                    started_at.elapsed(),
                    result
                        .as_ref()
                        .err()
                        .map(super::account_catch_up_metric_classification),
                );
            manager.shared.observer.performance().record(
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
    ) -> Result<crate::GroupMemberResult<GroupId>, AppError> {
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
            .directory()
            .prewarm_group_member_key_packages(&member_refs)
            .await;
        self.shared.observer.performance().record(
            AppPerformanceOperation::GroupMemberKeyPackagePrewarm,
            started_at.elapsed(),
            result.is_ok(),
        );
        Ok(result?)
    }

    pub async fn create_group_detailed(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
    ) -> Result<crate::GroupMemberResult<CreatedGroup>, AppError> {
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
    ) -> Result<crate::GroupMemberResult<GroupId>, AppError> {
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

    pub(super) async fn start_direct_conversation(
        &self,
        account_ref: &str,
        peer_account_id: &str,
        options: crate::DirectConversationOptions,
    ) -> Result<GroupId, AppError> {
        let account = self.resolve(account_ref)?;
        let peer_account_id_hex = crate::ids::account_id_hex_from_ref(peer_account_id)?;
        if peer_account_id_hex == account.account_id_hex {
            return Err(AppError::GroupCreateIncludesCreator);
        }
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::CreateGroup {
                queued_at: Instant::now(),
                request: GroupCreationRequest::Direct {
                    peer_account_id_hex: peer_account_id_hex.clone(),
                },
                // The worker applies these only when it creates the group;
                // reuse returns the founded group untouched.
                options: AppCreateGroupOptions {
                    disappearing_message_secs: options.disappearing_message_secs,
                    ..Default::default()
                },
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let created = long_account_worker_response(response).await?;
        let created = created
            .operation
            .ok_or_else(|| AppError::DirectoryLookupIncomplete(peer_account_id_hex))?;
        self.spawn_create_catch_up(command);
        self.schedule_audit_log_tracker_update("start_direct_conversation");
        Ok(created.group_id)
    }

    pub async fn create_group_with_options(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        options: AppCreateGroupOptions,
    ) -> Result<crate::GroupMemberResult<GroupId>, AppError> {
        let started_at = Instant::now();
        let result = async {
            let command = self.worker_commands(account_ref).await?;
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::CreateGroup {
                    queued_at: Instant::now(),
                    request: GroupCreationRequest::Group {
                        name: name.to_owned(),
                        members: members.to_vec(),
                        prepared_image_upload_id: None,
                    },
                    options,
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            let created = long_account_worker_response(response).await?;
            if created.operation.is_some() {
                self.spawn_create_catch_up(command);
            }
            Ok::<_, AppError>(created)
        }
        .await;
        self.shared.observer.performance().record(
            AppPerformanceOperation::GroupCreateTotalCallerLatency,
            started_at.elapsed(),
            result.is_ok(),
        );
        let created = result?;
        if created.operation.is_some() {
            self.schedule_audit_log_tracker_update("create_group");
        }
        Ok(crate::GroupMemberResult {
            operation: created.operation.map(|created| created.group_id),
            member_outcomes: created.member_outcomes,
        })
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

    /// From A (mdk#3273 PR 5), except while the version's list of prepared
    /// uploads failed: the worker's single read of the upload answers then.
    pub async fn prepared_group_image_status(
        &self,
        account_ref: &str,
        upload_id: String,
    ) -> Result<AppPreparedGroupImageUpload, AppError> {
        let lookup = upload_id.clone();
        self.read_from_state_where_held(
            account_ref,
            ReadClass::R1,
            StateRead::Diagnosed,
            move |state| state.prepared_group_image_status(&lookup),
            |respond| AccountWorkerCommand::PreparedGroupImageStatus { upload_id, respond },
        )
        .await
    }

    pub async fn prepared_group_images(
        &self,
        account_ref: &str,
    ) -> Result<Vec<AppPreparedGroupImageUpload>, AppError> {
        self.read_from_state(
            account_ref,
            ReadClass::R1,
            StateRead::Diagnosed,
            ReadState::prepared_group_images,
            |respond| AccountWorkerCommand::PreparedGroupImages { respond },
        )
        .await
    }

    pub async fn create_group_with_prepared_initial_image(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
        upload_id: String,
    ) -> Result<crate::GroupMemberResult<GroupId>, AppError> {
        let started_at = Instant::now();
        let result = async {
            let command = self.worker_commands(account_ref).await?;
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::CreateGroup {
                    queued_at: Instant::now(),
                    request: GroupCreationRequest::Group {
                        name: name.to_owned(),
                        members: members.to_vec(),
                        prepared_image_upload_id: Some(upload_id),
                    },
                    options: AppCreateGroupOptions {
                        description: description.unwrap_or_default(),
                        ..Default::default()
                    },
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            long_account_worker_response(response).await
        }
        .await;
        let result = result.map(|created| crate::GroupMemberResult {
            operation: created.operation.map(|created| created.group_id),
            member_outcomes: created.member_outcomes,
        });
        self.shared.observer.performance().record(
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
    ) -> Result<crate::GroupMemberResult<CreatedGroup>, AppError> {
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
    ) -> Result<crate::GroupMemberResult<CreatedGroup>, AppError> {
        let started_at = Instant::now();
        let result = self
            .create_group_with_options_outcome(account_ref, name, members, options)
            .await
            .and_then(|created| {
                Ok(crate::GroupMemberResult {
                    operation: created
                        .operation
                        .map(CanonicalCreatedGroup::into_detailed)
                        .transpose()?,
                    member_outcomes: created.member_outcomes,
                })
            });
        self.shared.observer.performance().record(
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
    ) -> Result<crate::GroupMemberResult<CanonicalCreatedGroup>, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::CreateGroup {
                queued_at: Instant::now(),
                request: GroupCreationRequest::Group {
                    name: name.to_owned(),
                    members: members.to_vec(),
                    prepared_image_upload_id: None,
                },
                options,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let result = long_account_worker_response(response).await;
        if result
            .as_ref()
            .is_ok_and(|created| created.operation.is_some())
        {
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
        let lane = self.worker_lane(account_ref).await?;
        // The groups the hydration request names come from the current
        // version; the answer reads its groups' saved-row standings and
        // members from the one version the read settles on (mdk#3273 PR 4).
        let groups = match lane.read_state.version(&self.app.storage_closed) {
            Ok(Some(state)) => state.co_member_groups(),
            Ok(None) | Err(_) => Vec::new(),
        };
        self.read_group_from_state(
            &lane,
            ReadClass::R3,
            StateRead::DiagnosedLocal,
            Admission::Queue,
            &groups,
            HydrationFailure::Ignored,
            |state| async move {
                // A group that came to await hydration after `groups` was
                // taken goes to the worker, which hydrates it first, as
                // each member read did.
                if !state
                    .awaiting_hydration(&state.co_member_groups())
                    .is_empty()
                {
                    return None;
                }
                reissue(state.co_members(&account.account_id_hex))
            },
            |respond| AccountWorkerCommand::GroupCoMembers { respond },
        )
        .await
    }

    pub async fn group_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        let lane = self.worker_lane(account_ref).await?;
        self.read_group_from_state(
            &lane,
            ReadClass::R3,
            StateRead::DiagnosedLocal,
            Admission::Queue,
            std::slice::from_ref(group_id),
            HydrationFailure::Ignored,
            |state| async move {
                // The profiles load before anything else, as for the
                // worker's read.
                let profiles = match self.member_profiles().await {
                    Ok(profiles) => profiles,
                    Err(error) => return Some(Err(error)),
                };
                reissue(state.members(group_id, &profiles))
            },
            |respond| AccountWorkerCommand::Members {
                group_id: group_id.clone(),
                respond,
            },
        )
        .await
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
        let lane = self.worker_lane(account_ref).await?;
        self.read_group_from_state(
            &lane,
            ReadClass::R3,
            StateRead::Diagnosed,
            Admission::Queue,
            group_ids,
            HydrationFailure::Returned,
            |state| async move { reissue(state.member_ids_page(group_ids)) },
            |respond| AccountWorkerCommand::MemberIdsPage {
                group_ids: group_ids.to_vec(),
                respond,
            },
        )
        .await
    }

    pub async fn group_mls_state(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupMlsState, AppError> {
        let started_at = Instant::now();
        let result = async {
            let lane = self.worker_lane(account_ref).await?;
            self.group_mls_state_from(&lane, Admission::Queue, group_id)
                .await
        }
        .await;
        self.shared.observer.performance().record(
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

    /// `GroupMlsState` from A, for the host read and its diagnostic form.
    async fn group_mls_state_from(
        &self,
        lane: &WorkerLane,
        admission: Admission,
        group_id: &GroupId,
    ) -> Result<AppGroupMlsState, AppError> {
        self.read_group_from_state(
            lane,
            ReadClass::R4,
            StateRead::Diagnosed,
            admission,
            std::slice::from_ref(group_id),
            HydrationFailure::Ignored,
            |state| async move { reissue(state.group_mls_state(group_id)) },
            |respond| AccountWorkerCommand::GroupMlsState {
                group_id: group_id.clone(),
                respond,
            },
        )
        .await
    }

    /// Read the group record, member projection, and MLS state from one
    /// version of A, then enrich member display names on a blocking task
    /// without worker queue re-entry.
    pub async fn group_conversation_snapshot(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupConversationSnapshot, AppError> {
        let account = self.resolve(account_ref)?;
        let lane = self.worker_lane(account_ref).await?;
        let session = self
            .read_group_from_state(
                &lane,
                ReadClass::R3,
                StateRead::Diagnosed,
                Admission::Queue,
                std::slice::from_ref(group_id),
                HydrationFailure::Returned,
                |state| async move {
                    // The profiles load once the group is known, as for the
                    // worker's read. Their failure is the caller's, not A's,
                    // so it answers here, as for `group_members`.
                    let profiles = if state.groups.contains_key(group_id) {
                        match self.member_profiles().await {
                            Ok(profiles) => profiles,
                            Err(error) => return Some(Err(error)),
                        }
                    } else {
                        Default::default()
                    };
                    match state.group_roster(group_id, move || Ok(profiles)) {
                        Ok(session) => Some(Ok(session)),
                        Err(error) => reissue(Err(error)),
                    }
                },
                |respond| AccountWorkerCommand::GroupRoster {
                    group_id: group_id.clone(),
                    respond,
                },
            )
            .await?;
        let member_ids = session
            .members
            .iter()
            .map(|member| member.member_id_hex.clone())
            .collect::<Vec<_>>();
        // Display names are optional directory enrichment; preserve the
        // authoritative roster if that cache is unavailable.
        let app = self.app.clone();
        let display_names = crate::blocking_app_task(move || {
            Ok(app.directory().display_names_for_account_ids(&member_ids)?)
        })
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

    pub async fn account_devices_activation(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<crate::AppAccountDevicesActivation, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R4).await?;
        command
            .send(AccountWorkerCommand::AccountDevicesActivation {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn enable_account_devices(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::EnableAccountDevices {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_committed(command, "enable_account_devices")
            .await;
        self.schedule_audit_log_tracker_update("enable_account_devices");
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
        self.read_from_state(
            account_ref,
            ReadClass::R3,
            StateRead::Local,
            |state| Ok(state.quarantined_groups()),
            |respond| AccountWorkerCommand::QuarantinedGroups { respond },
        )
        .await
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
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R5).await?;
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
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R5).await?;
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
    ) -> Result<crate::GroupMemberResult<SendSummary>, AppError> {
        self.invite_members_with_initial_admins(
            account_ref,
            group_id,
            members,
            &[],
            crate::MemberResolutionPolicy::Partial,
        )
        .await
    }

    pub async fn invite_members_with_initial_admins(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        members: &[String],
        initial_admins: &[String],
        member_resolution: crate::MemberResolutionPolicy,
    ) -> Result<crate::GroupMemberResult<SendSummary>, AppError> {
        let started_at = Instant::now();
        let result = async {
            let command = self.worker_commands(account_ref).await?;
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::InviteMembers {
                    group_id: group_id.clone(),
                    members: members.to_vec(),
                    initial_admins: initial_admins.to_vec(),
                    member_resolution,
                    respond,
                })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            let summary = account_worker_response(response).await?;
            if summary.operation.is_some() {
                self.spawn_invite_catch_up(command);
                self.schedule_audit_log_tracker_update("invite_members");
            }
            Ok(summary)
        }
        .await;
        self.shared.observer.performance().record(
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
        self.leave_group_command(account_ref, |respond| AccountWorkerCommand::LeaveGroup {
            group_id: group_id.clone(),
            respond,
        })
        .await
    }

    /// Leave `group_id` for `sign_out_and_wipe`, or keep this device's leaf
    /// where its account is an active admin (mdk#2818).
    pub(crate) async fn leave_group_for_sign_out(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<crate::client::sign_out::SignOutLeave, AppError> {
        self.leave_group_command(account_ref, |respond| {
            AccountWorkerCommand::LeaveGroupForSignOut {
                group_id: group_id.clone(),
                respond,
            }
        })
        .await
    }

    async fn leave_group_command<T>(
        &self,
        account_ref: &str,
        command_for: impl FnOnce(oneshot::Sender<Result<T, AppError>>) -> AccountWorkerCommand,
    ) -> Result<T, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(command_for(respond))
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let outcome = account_worker_response(response).await?;
        self.catch_up_committed(command, "leave_group").await;
        self.schedule_audit_log_tracker_update("leave_group");
        Ok(outcome)
    }

    pub async fn cancel_leave(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::CancelLeave {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn forget_group_local(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.resolve(account_ref)?;
        if !self.signs_on_worker(&account)
            && let Some((account, changed)) = self
                .write_without_worker(account_ref, |account| {
                    use cgka_traits::storage::GroupStorage;
                    Ok(self
                        .app
                        .account_storage(&account.label)?
                        .forget_group_local(
                            group_id,
                            cgka_traits::Timestamp(crate::unix_now_seconds()),
                        )?)
                })
                .await?
        {
            if changed {
                publish_app_runtime_group_state_updated(
                    Emit::Unpublished(Unpublished::NoClient),
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
        if !self.signs_on_worker(&account)
            && let Some((account, deleted)) = self
                .write_without_worker(account_ref, |account| {
                    self.app
                        .delete_group_local_data(&account.label, &hex::encode(group_id.as_slice()))
                })
                .await?
        {
            if deleted {
                publish_app_runtime_group_state_updated(
                    Emit::Unpublished(Unpublished::NoClient),
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

    /// `GroupRecoveryStatus` from A (mdk#3273 PR 8) for a group in the
    /// version's mirror, after the hydration request its worker command
    /// made with `ensure_group_hydrated`. Any other id, a locally deleted
    /// group whose MLS state is kept or one the engine does not store, is
    /// answered by the worker command, which answers it as before A: the
    /// third exception to answering from A, beside the hydration request
    /// and a failure with no exact copy. The version's mirror decides,
    /// never a failure (mdk#3273 decision 1).
    pub async fn group_recovery_status(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<crate::GroupRecoveryStatus, AppError> {
        let lane = self.worker_lane(account_ref).await?;
        self.read_group_from_state(
            &lane,
            ReadClass::R9,
            StateRead::Uncounted,
            Admission::Queue,
            std::slice::from_ref(group_id),
            HydrationFailure::Returned,
            |state| async move { reissue(state.group_recovery_status(group_id)?) },
            |respond| AccountWorkerCommand::GroupRecoveryStatus {
                group_id: group_id.clone(),
                respond,
            },
        )
        .await
    }

    pub async fn history_notices(
        &self,
        account_ref: &str,
    ) -> Result<Vec<crate::HistoryNotice>, AppError> {
        self.read_from_state(
            account_ref,
            ReadClass::R9,
            StateRead::Diagnosed,
            ReadState::history_notices,
            |respond| AccountWorkerCommand::HistoryNotices { respond },
        )
        .await
    }

    pub async fn account_recovery_status(
        &self,
        account_ref: &str,
    ) -> Result<crate::AccountRecoveryStatus, AppError> {
        self.read_from_state(
            account_ref,
            ReadClass::R9,
            StateRead::Diagnosed,
            ReadState::account_recovery_status,
            |respond| AccountWorkerCommand::AccountRecoveryStatus { respond },
        )
        .await
    }

    pub async fn linked_devices(
        &self,
        account_ref: &str,
    ) -> Result<Vec<crate::LinkedDevice>, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R6).await?;
        command
            .send(AccountWorkerCommand::LinkedDevices { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn chat_history_imports(
        &self,
        account_ref: &str,
    ) -> Result<Vec<crate::ChatHistoryImport>, AppError> {
        self.read_from_state(
            account_ref,
            ReadClass::R2,
            StateRead::DiagnosedLocal,
            ReadState::chat_history_imports,
            |respond| AccountWorkerCommand::ChatHistoryImports { respond },
        )
        .await
    }

    pub async fn key_package_refresh_overdue(&self, account_ref: &str) -> Result<bool, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R6).await?;
        command
            .send(AccountWorkerCommand::KeyPackageRefreshOverdue { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn unrecognized_sign_ins(
        &self,
        account_ref: &str,
    ) -> Result<Vec<crate::UnrecognizedSignIn>, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R6).await?;
        command
            .send(AccountWorkerCommand::UnrecognizedSignIns { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn answer_sign_in(
        &self,
        account_ref: &str,
        slot_id_hex: &str,
        response: crate::SignInResponse,
    ) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, receiver) = oneshot::channel();
        command
            .send(AccountWorkerCommand::AnswerSignIn {
                slot_id_hex: slot_id_hex.to_owned(),
                response,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(receiver).await
    }

    pub async fn check_sign_ins(
        &self,
        account_ref: &str,
    ) -> Result<Vec<crate::UnrecognizedSignIn>, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::CheckSignIns { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn start_fresh(&self, account_ref: &str) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::StartFresh { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn started_fresh(&self, account_ref: &str) -> Result<bool, AppError> {
        self.read_from_state(
            account_ref,
            ReadClass::R2,
            StateRead::DiagnosedLocal,
            ReadState::started_fresh,
            |respond| AccountWorkerCommand::StartedFresh { respond },
        )
        .await
    }

    pub async fn compromise_warning(
        &self,
        account_ref: &str,
    ) -> Result<Vec<crate::CompromiseWarningItem>, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R6).await?;
        command
            .send(AccountWorkerCommand::CompromiseWarning { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn dismiss_compromise_warning(&self, account_ref: &str) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DismissCompromiseWarning { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn rename_linked_device(
        &self,
        account_ref: &str,
        slot_id_hex: String,
        label: String,
    ) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RenameLinkedDevice {
                slot_id_hex,
                label,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn update_linked_device_settings(
        &self,
        account_ref: &str,
        slot_id_hex: String,
        add_to_all_chats: Option<bool>,
        bring_history: Option<bool>,
        keep_while_inactive: Option<bool>,
    ) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UpdateLinkedDeviceSettings {
                slot_id_hex,
                add_to_all_chats,
                bring_history,
                keep_while_inactive,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn remove_linked_device(
        &self,
        account_ref: &str,
        slot_id_hex: String,
    ) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RemoveLinkedDevice {
                slot_id_hex,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    /// One step of signing out through siblings (mdk#2628 D67), run in the
    /// account's worker so deliveries keep settling between steps.
    pub(crate) async fn sign_out_through_siblings_step(
        &self,
        account_ref: &str,
    ) -> Result<crate::client::sign_out::SiblingSignOut, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SignOutThroughSiblingsStep { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    /// Where an admin's sign-out leave from `group_id` stands (mdk#2818).
    pub(crate) async fn sign_out_admin_leave(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<crate::client::sign_out::SignOutAdminLeave, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SignOutAdminLeave {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn removed_device_leftover_chats(&self, account_ref: &str) -> Result<u32, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R6).await?;
        command
            .send(AccountWorkerCommand::RemovedDeviceLeftoverChats { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn chats_closed_to_linked_devices(&self, account_ref: &str) -> Result<u32, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R6).await?;
        command
            .send(AccountWorkerCommand::ChatsClosedToLinkedDevices { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn begin_recovery_words(
        &self,
        account_ref: &str,
    ) -> Result<crate::RecoveryWords, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::BeginRecoveryWords { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn confirm_recovery_words(
        &self,
        account_ref: &str,
        answers: Vec<String>,
    ) -> Result<(), AppError> {
        let answers = Zeroizing::new(answers);
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ConfirmRecoveryWords { answers, respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn cancel_recovery_words(&self, account_ref: &str) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::CancelRecoveryWords { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn turn_off_backups(&self, account_ref: &str) -> Result<(), AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::TurnOffBackups { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn set_backup_background_conditions(
        &self,
        account_ref: &str,
        wifi: bool,
        charging: bool,
    ) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.resolve(account_ref)?;
        self.setup_records()
            .require_onboarding_complete_for(&account)?;
        if !account.can_sign() {
            return Err(
                marmot_account::AccountHomeError::SecretNotFound(account.account_id_hex).into(),
            );
        }
        if account.signed_out {
            return Err(AppError::RelayDirectory("account is signed out".into()));
        }
        self.shared
            .report_backup_background_conditions(wifi, charging)
    }

    /// Wait for one due pass, including startup catch-up before admission.
    /// The caller owns its wait budget; cancellation detaches only its wait.
    pub async fn run_due_backup_pass(
        &self,
        account_ref: &str,
    ) -> Result<super::BackgroundBackupOutcome, AppError> {
        self.shared.lifecycle().ensure_running()?;
        if !self.app.device_groups_enabled() {
            return Ok(super::BackgroundBackupOutcome::NotStarted);
        }
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::RunDueBackupPass { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        // The host owns this wait, including admission deferred by startup.
        let Some(mut completion) = response.await.map_err(|_| AppError::TransportClosed)?? else {
            return Ok(super::BackgroundBackupOutcome::NotStarted);
        };
        loop {
            let finished = *completion.borrow_and_update();
            if finished {
                return Ok(super::BackgroundBackupOutcome::FinishedAttempt);
            }
            completion
                .changed()
                .await
                .map_err(|_| AppError::TransportClosed)?;
        }
    }

    pub async fn begin_backup_restore(
        &self,
        account_ref: &str,
        words: crate::BackupRestoreWords,
    ) -> Result<crate::BackupRestoreStatus, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::BeginBackupRestore { words, respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn cancel_backup_restore(
        &self,
        account_ref: &str,
        operation: crate::BackupRestoreId,
    ) -> Result<bool, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::CancelBackupRestore { operation, respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn backup_restore_status(
        &self,
        account_ref: &str,
    ) -> Result<crate::BackupRestoreStatus, AppError> {
        self.read_from_state(
            account_ref,
            ReadClass::R7,
            StateRead::Local,
            |state| Ok(state.backup_restore_status()),
            |respond| AccountWorkerCommand::BackupRestoreStatus { respond },
        )
        .await
    }

    pub async fn watch_backup_restore(
        &self,
        account_ref: &str,
    ) -> Result<crate::BackupRestoreWatch, AppError> {
        self.read_from_state(
            account_ref,
            ReadClass::R7,
            StateRead::Local,
            |state| Ok(state.watch_backup_restore()),
            |respond| AccountWorkerCommand::WatchBackupRestore { respond },
        )
        .await
    }

    pub async fn history_import_provenance(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        event_id: &str,
    ) -> Result<Option<crate::HistoryImportProvenance>, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R2).await?;
        command
            .send(AccountWorkerCommand::HistoryImportProvenance {
                group_id: group_id.clone(),
                event_id: event_id.into(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn backup_history_availability(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<crate::BackupHistoryAvailability>, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R6).await?;
        command
            .send(AccountWorkerCommand::BackupHistoryAvailability {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn backup_settings(
        &self,
        account_ref: &str,
    ) -> Result<crate::BackupSettings, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R6).await?;
        command
            .send(AccountWorkerCommand::BackupSettings { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        local_account_worker_response(response).await
    }

    pub async fn acknowledge_group_catching_up(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::AcknowledgeGroupCatchingUp {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn acknowledge_group_commit_undelivered(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::AcknowledgeGroupCommitUndelivered {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn group_commit_delivery(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Option<crate::GroupCommitDelivery>, AppError> {
        let lane = self.worker_lane(account_ref).await?;
        self.read_group_from_state(
            &lane,
            ReadClass::R3,
            StateRead::Diagnosed,
            Admission::Queue,
            std::slice::from_ref(group_id),
            HydrationFailure::Ignored,
            |state| async move { reissue(state.group_commit_delivery(group_id)) },
            |respond| AccountWorkerCommand::GroupCommitDelivery {
                group_id: group_id.clone(),
                respond,
            },
        )
        .await
    }

    pub async fn group_changes_not_delivered(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<crate::GroupChangeNotDelivered>, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R3).await?;
        command
            .send(AccountWorkerCommand::GroupChangesNotDelivered {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn group_pending_commit(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Option<crate::GroupPendingCommit>, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R3).await?;
        command
            .send(AccountWorkerCommand::GroupPendingCommit {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn acknowledge_change_not_delivered(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        commit_id_hex: &str,
    ) -> Result<bool, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::AcknowledgeChangeNotDelivered {
                group_id: group_id.clone(),
                commit_id_hex: commit_id_hex.to_owned(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn dismiss_history_notice(
        &self,
        account_ref: &str,
        notice_id: &str,
    ) -> Result<bool, AppError> {
        // Reject a malformed id before it queues behind other mutations.
        crate::history_notices::decode_notice_id(notice_id)?;
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DismissHistoryNotice {
                notice_id: notice_id.to_owned(),
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
        self.shared.observer.performance().record_classified_result(
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
        self.set_group_archived_on_worker(account_ref, group_id, archived)
            .await
            .map(|(group, _)| group)
    }

    /// [`Self::set_group_archived`], and why the caller's events about the
    /// change go out without publishing A: the worker published it before
    /// replying ([`Unpublished::AfterReply`]), or the account runs no worker
    /// ([`Unpublished::NoClient`]).
    ///
    /// An account that signs on a worker archives through it, so the
    /// worker's in-memory `AccountState` changes in place: a direct write
    /// would be undone by the worker's next save of that group's record, for
    /// example for an inbound commit (mdk#178, mdk#3318). A worker error,
    /// such as a startup or `reconcile()` failure, fails the call and never
    /// falls back to a direct write, because a worker that is starting may
    /// already hold the record from before the archive. Only an account that
    /// signs on no worker writes storage directly.
    pub(super) async fn set_group_archived_on_worker(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        archived: bool,
    ) -> Result<(AppGroupRecord, Unpublished), AppError> {
        let account = self.resolve(account_ref)?;
        if !self.signs_on_worker(&account)
            && let Some((_, group)) = self
                .write_without_worker(account_ref, |account| {
                    self.app.set_group_archived(
                        &account.label,
                        &hex::encode(group_id.as_slice()),
                        archived,
                    )
                })
                .await?
        {
            return Ok((group, Unpublished::NoClient));
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
        Ok((
            local_account_worker_response(response).await?,
            Unpublished::AfterReply,
        ))
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

    pub async fn group_app_component(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        component_id: u16,
    ) -> Result<Option<Vec<u8>>, AppError> {
        let lane = self.worker_lane(account_ref).await?;
        // A protocol-space id fails on its own input, so it is answered here,
        // ahead of any hydration request, and never reaches the worker.
        crate::client::validate_app_component(component_id, &[])?;
        self.read_group_from_state(
            &lane,
            ReadClass::R4,
            StateRead::DiagnosedLocal,
            Admission::Queue,
            std::slice::from_ref(group_id),
            HydrationFailure::Returned,
            |state| async move { reissue(state.group_app_component(group_id, component_id)) },
            |respond| AccountWorkerCommand::GroupAppComponent {
                group_id: group_id.clone(),
                component_id,
                respond,
            },
        )
        .await
    }

    pub async fn update_app_component(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        component_id: u16,
        data: Vec<u8>,
    ) -> Result<SendSummary, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UpdateAppComponent {
                group_id: group_id.clone(),
                component_id,
                data,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        let summary = account_worker_response(response).await?;
        self.catch_up_committed(command, "update_app_component")
            .await;
        self.schedule_audit_log_tracker_update("update_app_component");
        Ok(summary)
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
        self.shared.observer.performance().record(
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
        let telemetry = self.shared.observer.performance().clone();
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
        let telemetry = self.shared.observer.performance().clone();
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
        self.shared.observer.performance().record(
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
        let (command, respond, response) = self
            .read_command(&account.account_id_hex, ReadClass::R4)
            .await?;
        command
            .send(AccountWorkerCommand::GroupPushDebugInfo {
                group_id: group_id.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
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
        self.shared.observer.performance().record(
            AppPerformanceOperation::OutboundMessageResponse,
            enqueued_at.elapsed(),
            result.is_ok(),
        );
        let summary = result?;
        self.schedule_audit_log_tracker_update("send_app_event");
        Ok(summary)
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
                request: crate::media::file_transfer::MediaUploadPayload::Bytes(request),
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

    pub(crate) async fn upload_media_files(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        request: crate::MediaFileUploadRequest,
        control: std::sync::Arc<crate::MediaFileTransferControl>,
    ) -> Result<MediaUploadResult, AppError> {
        self.upload_file_sources(
            account_ref,
            group_id,
            crate::media::file_transfer::FileUploadSources::Host(request),
            control,
        )
        .await
    }

    pub(crate) async fn upload_file_sources(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        request: crate::media::file_transfer::FileUploadSources,
        control: std::sync::Arc<crate::MediaFileTransferControl>,
    ) -> Result<MediaUploadResult, AppError> {
        control.check()?;
        let (command, admission) = self.media_worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::UploadMedia {
                admission,
                group_id: group_id.clone(),
                request: crate::media::file_transfer::MediaUploadPayload::Files(request, control),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        // File preparation and ordered endpoint attempts can outlast the legacy
        // worker wait. Keep ownership until completion; HTTP bounds each attempt.
        let result = response.await.map_err(|_| AppError::TransportClosed)??;
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
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R8).await?;
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

    pub(crate) async fn discard_failed_send(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        message_id_hex: &str,
    ) -> Result<crate::DiscardFailedSendResult, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DiscardFailedSend {
                group_id: group_id.clone(),
                message_id_hex: message_id_hex.to_owned(),
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
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R3).await?;
        command
            .send(AccountWorkerCommand::PendingWelcomeDeliveries { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn invite_deliveries(
        &self,
        account_ref: &str,
        group_id: Option<&GroupId>,
    ) -> Result<Vec<crate::InviteDelivery>, AppError> {
        let (command, respond, response) = self.read_command(account_ref, ReadClass::R3).await?;
        command
            .send(AccountWorkerCommand::InviteDeliveries {
                group_id: group_id.cloned(),
                respond,
            })
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

    pub(crate) async fn device_link(
        &self,
        account_ref: &str,
        op: crate::DeviceLinkOp,
    ) -> Result<crate::DeviceLinkSnapshot, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::DeviceLink { op, respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
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

    pub async fn withdraw_key_package_slot(&self, account_ref: &str) -> Result<usize, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.resolve(account_ref)?;
        if account.signed_out && account.can_sign() {
            // A signed-out account runs no worker, so nothing else publishes
            // into its slot: open its session for the withdrawal alone. The
            // session is exclusive, so no worker opens it until this closes.
            self.ensure_worker_reaped(&account.account_id_hex).await?;
            let mut client = self
                .app
                .local_client_with_relay_plane(
                    &account.label,
                    &self.app.relay_plane,
                    Some(self.shared.lifecycle()),
                )
                .await?;
            return client.withdraw_key_package_slot().await;
        }
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::WithdrawKeyPackageSlot { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    pub async fn key_package_maintenance_status(
        &self,
        account_ref: &str,
    ) -> Result<Option<cgka_traits::KeyPackageLifecycleState>, AppError> {
        self.read_from_state(
            account_ref,
            ReadClass::R3,
            StateRead::Diagnosed,
            ReadState::key_package_maintenance_status,
            |respond| AccountWorkerCommand::KeyPackageMaintenanceStatus { respond },
        )
        .await
    }

    pub async fn diagnostic_key_package_maintenance_status(
        &self,
        account_ref: &str,
    ) -> Result<Option<Option<cgka_traits::KeyPackageLifecycleState>>, AppError> {
        let Some(lane) = self.existing_worker_commands(account_ref).await? else {
            return Ok(None);
        };
        if let Some(answer) = self.answer_from_state(&lane, StateRead::Diagnosed, |state| {
            Some(state.key_package_maintenance_status())
        }) {
            return answer.map(Some);
        }
        self.ask_worker(
            &lane,
            ReadClass::R3,
            StateRead::Diagnosed,
            Admission::Refuse,
            |respond| AccountWorkerCommand::KeyPackageMaintenanceStatus { respond },
        )
        .await
        .map(Some)
    }

    pub async fn diagnostic_group_mls_state(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Option<AppGroupMlsState>, AppError> {
        let Some(lane) = self.existing_worker_commands(account_ref).await? else {
            return Ok(None);
        };
        self.group_mls_state_from(&lane, Admission::Refuse, group_id)
            .await
            .map(Some)
    }

    pub async fn durably_owned_key_packages(
        &self,
        account_ref: &str,
    ) -> Result<Vec<cgka_traits::engine::KeyPackage>, AppError> {
        self.read_from_state(
            account_ref,
            ReadClass::R3,
            StateRead::Diagnosed,
            ReadState::durably_owned_key_packages,
            |respond| AccountWorkerCommand::DurablyOwnedKeyPackages { respond },
        )
        .await
    }

    pub async fn maintenance_status(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<cgka_traits::GroupMaintenanceStatus, AppError> {
        let lane = self.worker_lane(account_ref).await?;
        self.read_group_from_state(
            &lane,
            ReadClass::R3,
            StateRead::Diagnosed,
            Admission::Queue,
            std::slice::from_ref(group_id),
            HydrationFailure::Ignored,
            |state| async move { reissue(state.maintenance_status(group_id)) },
            |respond| AccountWorkerCommand::MaintenanceStatus {
                group_id: group_id.clone(),
                respond,
            },
        )
        .await
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

    /// Ask the account's worker for an inbox check; it answers when the
    /// check ends. Without a running worker nothing is dialed.
    pub(super) async fn check_inbox_relays(&self, account_ref: &str) -> Result<(), AppError> {
        let account = self.resolve(account_ref)?;
        let not_active = || {
            AppError::from(cgka_traits::TransportAdapterError::AccountNotActive(
                cgka_traits::MemberId::new(
                    hex::decode(&account.account_id_hex).unwrap_or_default(),
                ),
            ))
        };
        let command = self
            .existing_worker_commands(account_ref)
            .await?
            .ok_or_else(not_active)?
            .commands;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::CheckRelays { respond })
            .await
            .map_err(|_| not_active())?;
        long_account_worker_response(response).await
    }

    /// The account worker's inbox checks, as `account_relay_health` reads
    /// them; nothing while no worker runs.
    pub(super) async fn relay_check_snapshot(
        &self,
        account_id_hex: &str,
    ) -> crate::relay_health::CheckSnapshot {
        self.workers
            .lock()
            .await
            .get(account_id_hex)
            .map(|worker| worker.relay_checks.borrow().clone())
            .unwrap_or_default()
    }

    pub(super) async fn reconnect_relay(
        &self,
        account_ref: &str,
        canonical_url: String,
    ) -> Result<crate::RelayLiveness, AppError> {
        let command = self
            .existing_worker_commands(account_ref)
            .await?
            .ok_or(AppError::TransportClosed)?
            .commands;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ReconnectRelay {
                canonical_url,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        long_account_worker_response(response).await
    }

    pub async fn periodic_maintenance_policy(
        &self,
        account_ref: &str,
    ) -> Result<cgka_traits::PeriodicMaintenancePolicy, AppError> {
        self.read_from_state(
            account_ref,
            ReadClass::R3,
            StateRead::Diagnosed,
            ReadState::periodic_maintenance_policy,
            |respond| AccountWorkerCommand::PeriodicMaintenancePolicy { respond },
        )
        .await
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
    use crate::runtime::ReadReply;

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
        let (commands, mut received) = crate::runtime::test_worker_channel(1);
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
                unit: Default::default(),
                read_state: Default::default(),
                relay_checks: tokio::sync::watch::channel(Default::default()).1,
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn catch_up_uses_mutation_worker() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = super::super::MarmotAppRuntime::new(crate::MarmotApp::with_relay(
            dir.path(),
            "wss://relay.example",
        ));
        let manager = runtime.accounts();
        let (command, mut received) = crate::runtime::test_worker_channel(1);
        let catch_up = manager.catch_up_committed(command, "test");
        let worker = async {
            let Some(AccountWorkerCommand::CatchUp { respond }) = received.recv().await else {
                panic!("catch-up must reach the mutation's worker");
            };
            respond.send(Ok(())).unwrap();
            assert!(received.recv().await.is_none(), "exactly one catch-up");
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(catch_up, worker);
        })
        .await
        .unwrap();
        assert!(manager.workers.lock().await.is_empty(), "no reconciliation");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        let (commands, mut received) = crate::runtime::test_worker_channel(1);
        let (respond, _response) = ReadReply::unobserved();
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
                unit: Default::default(),
                read_state: Default::default(),
                relay_checks: tokio::sync::watch::channel(Default::default()).1,
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        let (commands, mut received) = crate::runtime::test_worker_channel(1);
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
                unit: Default::default(),
                read_state: Default::default(),
                relay_checks: tokio::sync::watch::channel(Default::default()).1,
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

    /// A failure in A that `reissue` copies reaches the host as the answer
    /// the worker gives for it, compared by debug form as the oracle's
    /// `same_answer` compares failures, with no queue wait. One with no exact
    /// copy is answered by the worker's own command instead, its wait
    /// recorded under the read's class (mdk#3273).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_published_failure_is_reissued_exactly_or_answered_by_the_worker() {
        use super::super::{ManagedAccountWorker, MarmotAppRuntime};
        use crate::client::read_state::read_state_channel;
        use cgka_traits::PeriodicMaintenancePolicy;
        use cgka_traits::error::EngineError;
        use marmot_session::{AccountError, SessionError};

        /// The read as the host makes it, answered by the fake worker with
        /// `answer` if it goes to the worker.
        async fn read(
            manager: &AccountManager,
            account: &str,
            received: &mut crate::runtime::TestWorkerReceiver,
            answer: Option<AppError>,
        ) -> Result<PeriodicMaintenancePolicy, AppError> {
            let Some(answer) = answer else {
                return tokio::select! {
                    biased;
                    read = manager.periodic_maintenance_policy(account) => read,
                    _ = received.recv() => panic!("the read went to the worker"),
                };
            };
            let pending = manager.periodic_maintenance_policy(account);
            tokio::pin!(pending);
            let respond = tokio::select! {
                biased;
                command = received.recv() => match command {
                    Some(AccountWorkerCommand::PeriodicMaintenancePolicy { respond }) => respond,
                    _ => panic!("the read goes to the worker"),
                },
                read = &mut pending => panic!("the read answered without the worker: {read:?}"),
            };
            let _ = respond.send(Err(answer));
            pending.await
        }

        let dir = tempfile::tempdir().unwrap();
        let account = marmot_account::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let runtime = MarmotAppRuntime::new(crate::MarmotApp::with_relay(
            dir.path(),
            "wss://relay.example",
        ));
        let manager = runtime.accounts();
        let (commands, mut received) = crate::runtime::test_worker_channel(1);
        let (publisher, read_state) = read_state_channel();
        let (shutdown, stopped) = oneshot::channel();
        let handle = tokio::spawn(async move {
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
                unit: Default::default(),
                read_state,
                relay_checks: tokio::sync::watch::channel(Default::default()).1,
            },
        );
        let telemetry = runtime.shared_services().observer.performance().clone();
        let waits = || {
            telemetry
                .snapshot()
                .runtime_operations
                .into_iter()
                .find(|sample| sample.operation == crate::RuntimePerformanceOperation::ReadQueueR3)
                .map_or(0, |sample| sample.successes)
        };
        let publish = |failure: AppError| {
            publisher.publish_for_test(|account| {
                account.periodic_maintenance_policy = Err(std::sync::Arc::new(failure));
            });
        };

        let group = GroupId::new(vec![0x11; 16]);
        let storage = || cgka_traits::StorageError::Backend("disk".into());
        let account_engine = |engine| AppError::Account(AccountError::Engine(engine));
        let session_engine =
            |engine| AppError::Account(AccountError::Session(SessionError::Engine(engine)));
        let app_session_engine = |engine| AppError::Session(SessionError::Engine(engine));
        let lifetime = || EngineError::InvalidKeyPackageLifetime {
            not_before: Some(1),
            not_after: None,
        };
        let copyable: [&dyn Fn() -> AppError; 13] = [
            &|| AppError::UnknownGroup("11".to_owned()),
            &|| AppError::Storage(storage()),
            &|| account_engine(EngineError::UnknownGroup(group.clone())),
            &|| account_engine(EngineError::GroupNotHydrated(group.clone())),
            &|| account_engine(EngineError::Storage(storage())),
            &|| account_engine(lifetime()),
            &|| session_engine(EngineError::UnknownGroup(group.clone())),
            &|| session_engine(EngineError::GroupNotHydrated(group.clone())),
            &|| session_engine(EngineError::Storage(storage())),
            &|| app_session_engine(EngineError::UnknownGroup(group.clone())),
            &|| app_session_engine(EngineError::GroupNotHydrated(group.clone())),
            &|| app_session_engine(EngineError::Storage(storage())),
            &|| app_session_engine(lifetime()),
        ];
        let uncopyable: [&dyn Fn() -> AppError; 4] = [
            &|| AppError::Sqlite(rusqlite::Error::InvalidQuery),
            &|| account_engine(EngineError::UnknownPending),
            &|| session_engine(EngineError::UnknownPending),
            &|| app_session_engine(EngineError::UnknownPending),
        ];
        for (index, failure) in copyable.iter().enumerate() {
            // A failure with no exact copy sends the read to the worker, whose
            // answer the host gets, and whose wait counts under R3.
            publish(uncopyable[index % uncopyable.len()]());
            let before = waits();
            let worker = read(&manager, &account.label, &mut received, Some(failure()))
                .await
                .unwrap_err();
            assert_eq!(waits(), before + 1);

            // The same failure in A answers on the caller's task, the same
            // answer by debug form, and waits on no queue.
            publish(failure());
            let served = read(&manager, &account.label, &mut received, None)
                .await
                .unwrap_err();
            assert_eq!(format!("{served:?}"), format!("{worker:?}"));
            assert_eq!(waits(), before + 1);
        }
        runtime.shutdown().await;
    }
}
