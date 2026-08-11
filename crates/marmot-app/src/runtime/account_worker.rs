//! Per-account worker: command surface, the worker loop, reconnect backoff,
//! and the runtime-event publishing helpers the loop drives.

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::time::{Duration, Instant};

use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_AGENT_STREAM_START;
use cgka_traits::engine::KeyPackage;
use cgka_traits::{GroupId, SecretBytes};
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant as TokioInstant, MissedTickBehavior, Sleep, interval, sleep, timeout};
use zeroize::Zeroizing;

use super::{
    MarmotAppEvent, RuntimeAccountError, RuntimeAgentStreamMessage, RuntimeGroupEvent,
    RuntimeLifecycle, RuntimeMessageReceived, RuntimeProjectionUpdate, RuntimeSharedServices,
    wait_for_runtime_shutdown,
};
use crate::app_telemetry::AppPerformanceOperation;
use crate::messages::AppMessageIntent;
use crate::{
    ACCOUNT_WORKER_RECONNECT_BASE_DELAY, ACCOUNT_WORKER_RECONNECT_JITTER_MAX_MS,
    ACCOUNT_WORKER_RECONNECT_MAX_DELAY, APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT,
    AgentTextStreamFinishRequest, AppBlobEndpoint, AppClient, AppDisbandRequest, AppError,
    AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord, AppInitialGroupImage,
    AppProjectionUpdate, AppQuarantinedGroup, ConvergenceScheduleState, GroupInviteDeclineResult,
    MaintenanceRunSummary, MarmotApp, MarmotRelayPlane, MediaAttachmentReference,
    MediaDownloadResult, MediaUploadRequest, MediaUploadResult, NotificationSettings,
    PendingWelcomeDelivery, PushPlatform, PushRegistration, PushRegistrationShareOutcome,
    PushRegistrationSyncResult, ReceivedMessage, RetentionSweepReport, SecureDeleteExpiredResult,
    SendSummary, SyncSummary,
};
use cgka_traits::app_event::MarmotAppEvent as MarmotInnerEvent;

pub(crate) struct ManagedAccountWorker {
    pub(crate) handle: JoinHandle<()>,
    pub(crate) commands: mpsc::Sender<AccountWorkerCommand>,
    pub(crate) shutdown: oneshot::Sender<()>,
}

impl ManagedAccountWorker {
    pub(crate) async fn shutdown(self) {
        self.shutdown_with_timeout(APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT)
            .await;
    }

    pub(crate) async fn shutdown_with_timeout(self, wait: Duration) {
        let _ = self.shutdown.send(());
        let mut handle = self.handle;
        tokio::select! {
            result = &mut handle => {
                if let Err(err) = result {
                    tracing::debug!(
                        target: "marmot_app::runtime",
                        method = "shutdown",
                        error_kind = if err.is_panic() { "panic" } else { "cancelled" },
                        "managed account worker exited during shutdown",
                    );
                }
            }
            _ = sleep(wait) => {
                tracing::warn!(
                    target: "marmot_app::runtime",
                    method = "shutdown",
                    "managed account worker shutdown timed out; aborting",
                );
                handle.abort();
                // Reaping is the ownership handoff: the task owns AppClient,
                // whose drop releases the account-session guard. Do not return
                // until cancellation has run its destructors, or a replacement
                // worker could race the still-live engine.
                let _ = handle.await;
            }
        }
    }
}

pub(crate) struct AccountWorkerRuntime {
    pub(crate) app: MarmotApp,
    pub(crate) account_label: String,
    pub(crate) account_id_hex: String,
    pub(crate) relay_plane: MarmotRelayPlane,
    pub(crate) events: broadcast::Sender<MarmotAppEvent>,
    pub(crate) lifecycle: RuntimeLifecycle,
    pub(crate) shared: RuntimeSharedServices,
}

pub(crate) enum AccountWorkerCommand {
    CatchUp {
        respond: oneshot::Sender<Result<(), String>>,
    },
    RepairFullHistory {
        respond: oneshot::Sender<Result<(), String>>,
    },
    CreateGroup {
        queued_at: Instant,
        name: String,
        members: Vec<String>,
        description: Option<String>,
        initial_image: Option<AppInitialGroupImage>,
        respond: oneshot::Sender<Result<GroupId, AppError>>,
    },
    Members {
        group_id: GroupId,
        respond: oneshot::Sender<Result<Vec<AppGroupMemberRecord>, AppError>>,
    },
    MemberIdsPage {
        group_ids: Vec<GroupId>,
        respond: oneshot::Sender<Result<Vec<crate::AppGroupMemberIds>, AppError>>,
    },
    GroupMlsState {
        group_id: GroupId,
        respond: oneshot::Sender<Result<AppGroupMlsState, AppError>>,
    },
    GroupRoster {
        group_id: GroupId,
        respond: oneshot::Sender<Result<crate::groups::AppGroupRosterSession, AppError>>,
    },
    EnableGroupDisbanding {
        group_id: GroupId,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    DisbandGroup {
        group_id: GroupId,
        respond: oneshot::Sender<Result<AppDisbandRequest, AppError>>,
    },
    AcknowledgeDisbandFailure {
        group_id: GroupId,
        respond: oneshot::Sender<Result<bool, AppError>>,
    },
    QuarantinedGroups {
        respond: oneshot::Sender<Result<Vec<AppQuarantinedGroup>, AppError>>,
    },
    NetworkStartupSettled {
        respond: oneshot::Sender<()>,
    },
    RetryHydrateQuarantinedGroup {
        group_id: GroupId,
        respond: oneshot::Sender<Result<bool, AppError>>,
    },
    SafeExportSecret {
        group_id: GroupId,
        component_id: cgka_traits::AppComponentId,
        respond: oneshot::Sender<Result<SecretBytes, AppError>>,
    },
    ExporterSecret {
        group_id: GroupId,
        label: String,
        length: usize,
        respond: oneshot::Sender<Result<SecretBytes, AppError>>,
    },
    InviteMembers {
        group_id: GroupId,
        members: Vec<String>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    RemoveMembers {
        group_id: GroupId,
        members: Vec<String>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    LeaveGroup {
        group_id: GroupId,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    DeleteGroupLocal {
        group_id: GroupId,
        respond: oneshot::Sender<Result<bool, AppError>>,
    },
    AcceptGroupInvite {
        group_id: GroupId,
        respond: oneshot::Sender<Result<AppGroupRecord, AppError>>,
    },
    DeclineGroupInvite {
        group_id: GroupId,
        respond: oneshot::Sender<Result<GroupInviteDeclineResult, AppError>>,
    },
    SetGroupArchived {
        group_id: GroupId,
        archived: bool,
        respond: oneshot::Sender<Result<AppGroupRecord, AppError>>,
    },
    PromoteAdmin {
        group_id: GroupId,
        member_ref: String,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    DemoteAdmin {
        group_id: GroupId,
        member_ref: String,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    SelfDemoteAdmin {
        group_id: GroupId,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    UpdateGroupProfile {
        group_id: GroupId,
        name: Option<String>,
        description: Option<String>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    UpdateGroupImage {
        group_id: GroupId,
        plaintext: Vec<u8>,
        media_type: String,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    DownloadGroupImage {
        group_id: GroupId,
        respond: oneshot::Sender<Result<Vec<u8>, AppError>>,
    },
    UpdateMessageRetention {
        group_id: GroupId,
        disappearing_message_secs: u64,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    ReplaceEncryptedMediaBlobEndpoints {
        group_id: GroupId,
        endpoints: Vec<AppBlobEndpoint>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    UpdateGroupAvatarUrl {
        group_id: GroupId,
        url: Option<String>,
        dim: Option<String>,
        thumbhash: Option<String>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    SendMessage {
        group_id: GroupId,
        payload: Vec<u8>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    SendAppEvent {
        group_id: GroupId,
        intent: AppMessageIntent,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    BuildMediaImetaTag {
        group_id: GroupId,
        reference: MediaAttachmentReference,
        respond: oneshot::Sender<Result<Vec<String>, AppError>>,
    },
    UploadMedia {
        group_id: GroupId,
        request: MediaUploadRequest,
        respond: oneshot::Sender<Result<MediaUploadResult, AppError>>,
    },
    DownloadMedia {
        group_id: GroupId,
        reference: MediaAttachmentReference,
        respond: oneshot::Sender<Result<MediaDownloadResult, AppError>>,
    },
    SecureDeleteExpiredPlaintext {
        group_id: GroupId,
        respond: oneshot::Sender<Result<SecureDeleteExpiredResult, AppError>>,
    },
    SweepExpiredRetention {
        now_ms: u64,
        respond: oneshot::Sender<Result<RetentionSweepReport, AppError>>,
    },
    StartAgentTextStream {
        group_id: GroupId,
        stream_id: Vec<u8>,
        parent_message_id: Option<String>,
        quic_candidates: Vec<String>,
        respond: oneshot::Sender<Result<(MarmotInnerEvent, SendSummary), AppError>>,
    },
    FinishAgentTextStream {
        group_id: GroupId,
        request: AgentTextStreamFinishRequest,
        respond: oneshot::Sender<Result<(MarmotInnerEvent, SendSummary), AppError>>,
    },
    RetryGroupConvergence {
        group_id: GroupId,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    PendingWelcomeDeliveries {
        respond: oneshot::Sender<Result<Vec<PendingWelcomeDelivery>, AppError>>,
    },
    RedeliverWelcome {
        message_id_hex: String,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    PublishKeyPackage {
        respond: oneshot::Sender<Result<usize, AppError>>,
    },
    RotateKeyPackage {
        respond: oneshot::Sender<Result<usize, AppError>>,
    },
    KeyPackageMaintenanceStatus {
        respond: oneshot::Sender<Result<Option<cgka_traits::KeyPackageLifecycleState>, AppError>>,
    },
    DurablyOwnedKeyPackages {
        respond: oneshot::Sender<Result<Vec<KeyPackage>, AppError>>,
    },
    MaintenanceStatus {
        group_id: GroupId,
        respond: oneshot::Sender<Result<cgka_traits::GroupMaintenanceStatus, AppError>>,
    },
    ScheduleManualSelfUpdate {
        group_id: GroupId,
        respond: oneshot::Sender<Result<String, AppError>>,
    },
    PeriodicMaintenancePolicy {
        respond: oneshot::Sender<Result<cgka_traits::PeriodicMaintenancePolicy, AppError>>,
    },
    SetPeriodicMaintenancePolicy {
        policy: cgka_traits::PeriodicMaintenancePolicy,
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    PauseMaintenance {
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    ResumeMaintenance {
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    RunDueMaintenance {
        respond: oneshot::Sender<Result<MaintenanceRunSummary, AppError>>,
    },
    SharePushRegistration {
        respond: oneshot::Sender<Result<PushRegistrationShareOutcome, AppError>>,
    },
    UpsertPushRegistration {
        platform: PushPlatform,
        raw_token: Zeroizing<String>,
        server_pubkey_hex: String,
        relay_hint: Option<String>,
        respond: oneshot::Sender<Result<PushRegistrationSyncResult, AppError>>,
    },
    ClearPushRegistration {
        respond: oneshot::Sender<Result<PushRegistrationShareOutcome, AppError>>,
    },
    SetNativePushEnabled {
        enabled: bool,
        respond: oneshot::Sender<Result<NotificationSettings, AppError>>,
    },
    RemovePushRegistration {
        registration: PushRegistration,
        respond: oneshot::Sender<Result<usize, AppError>>,
    },
    RetryPushRegistration {
        respond: oneshot::Sender<bool>,
    },
    DeleteAuditLog {
        path: std::path::PathBuf,
        respond: oneshot::Sender<Result<bool, AppError>>,
    },
    SetAuditRecording {
        enabled: bool,
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    SetAuditDataMode {
        mode: marmot_forensics::AuditDataMode,
        reason: String,
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    /// Count seeded groups the session has not fully hydrated yet, without
    /// promoting them on demand (mdk#1337 regression probe).
    #[cfg(test)]
    UnhydratedGroupCount {
        respond: oneshot::Sender<usize>,
    },
}

impl AccountWorkerCommand {
    fn may_change_push_registration_work(&self) -> bool {
        matches!(
            self,
            Self::SharePushRegistration { .. }
                | Self::UpsertPushRegistration { .. }
                | Self::ClearPushRegistration { .. }
                | Self::SetNativePushEnabled { .. }
                | Self::RemovePushRegistration { .. }
        )
    }
}

/// A command held back during the initial background catch-up, replayed in
/// arrival order once the catch-up completes.
///
/// Keeping `CatchUp` waiters inline in this sequence (rather than fulfilling
/// them all up front) preserves FIFO: a `CatchUp` enqueued after an earlier
/// deferred mutation is answered only after that mutation has run.
enum DeferredStartupCommand {
    /// A non-read command to run against the live session after catch-up. Boxed
    /// because `AccountWorkerCommand` is far larger than the `CatchUp` variant.
    Command(Box<AccountWorkerCommand>),
    /// A `CatchUp` coalesced onto the initial catch-up, fulfilled with its
    /// result at this position in the sequence.
    CatchUp(oneshot::Sender<Result<(), String>>),
}

pub(crate) fn spawn_app_runtime_account_worker(
    runtime: AccountWorkerRuntime,
    command_tx: mpsc::Sender<AccountWorkerCommand>,
    commands: mpsc::Receiver<AccountWorkerCommand>,
    ready: oneshot::Sender<Result<(), AppError>>,
    shutdown: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(run_app_runtime_account_worker(
        runtime, command_tx, commands, ready, shutdown,
    ))
}

async fn run_app_runtime_account_worker(
    runtime: AccountWorkerRuntime,
    command_tx: mpsc::Sender<AccountWorkerCommand>,
    mut commands: mpsc::Receiver<AccountWorkerCommand>,
    ready: oneshot::Sender<Result<(), AppError>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut ready = Some(ready);
    let AccountWorkerRuntime {
        app,
        account_label,
        account_id_hex,
        relay_plane,
        events,
        lifecycle,
        shared,
    } = runtime;
    let mut lifecycle_shutdown = lifecycle.subscribe_shutdown();
    let mut open_client =
        std::pin::pin!(app.runtime_local_client(&account_label, &relay_plane, lifecycle.clone(),));
    let mut client = match tokio::select! {
        _ = &mut shutdown => {
            release_startup_client_if_opened(open_client.as_mut()).await;
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err(AppError::BlockingTask(
                    "runtime startup cancelled".into(),
                )));
            }
            return;
        }
        _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => {
            release_startup_client_if_opened(open_client.as_mut()).await;
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err(AppError::BlockingTask(
                    "runtime startup cancelled".into(),
                )));
            }
            return;
        }
        result = open_client.as_mut() => result,
    } {
        Ok(client) => client,
        Err(err) => {
            let message = account_error_message("runtime startup failed", &err);
            publish_app_runtime_account_error(
                &events,
                &account_id_hex,
                &account_label,
                message.clone(),
            );
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err(err));
            }
            return;
        }
    };
    let mut scheduled_convergence = ScheduledConvergence::with_test_delay(
        convergence_settlement_delay(&app),
        scheduled_convergence_test_delay(&app),
    );
    let mut scheduled_push_retry = ScheduledPushRegistrationRetry::new();

    // The session's cheap open pass has seeded every stored group. Signal
    // command-readiness *now*: the hydration pipeline right below enters its
    // command-serving loop immediately, so "ready" genuinely means "serving
    // commands" — group reads (`Members` / `MemberIdsPage` / `GroupMlsState` /
    // `GroupRoster` / `QuarantinedGroups`) issued from this point hydrate the
    // group(s) they name and answer live. Everything else
    // joins the startup deferral. `AccountOpen` (recorded by `reconcile` as the ready-wait)
    // measures the seeded open; the mdk#1161 stage telemetry attributes it
    // (`AccountSessionOpen` / `AccountGroupHydration` for the open the
    // worker just awaited, with the pipeline and snapshot capture measured
    // separately below).

    {
        let open_timings = client.runtime.session().open_timings();
        let telemetry = shared.app_performance_telemetry();
        telemetry.record(
            AppPerformanceOperation::AccountSessionOpen,
            open_timings.total,
            true,
        );
        telemetry.record(
            AppPerformanceOperation::AccountGroupHydration,
            open_timings.group_hydration,
            true,
        );
    }
    if let Some(ready) = ready.take() {
        let _ = ready.send(Ok(()));
    }

    // Background hydration pipeline (mdk#1161): the deferred open above only
    // seeded stored groups, so fully hydrate them now — chat-list recency
    // first — while serving commands. Group reads for a not-yet-hydrated
    // group hydrate that one group and answer live ("waits for that group
    // only"); mutations and catch-ups join the same startup deferral the
    // catch-up window has always used and replay in arrival order after it.
    let mut deferred: Vec<DeferredStartupCommand> = Vec::new();
    match run_startup_hydration_pipeline(
        &app,
        &mut client,
        &mut commands,
        &mut deferred,
        &events,
        &account_id_hex,
        &account_label,
        &shared,
        &mut shutdown,
        &lifecycle,
    )
    .await
    {
        StartupHydrationOutcome::Completed => {}
        StartupHydrationOutcome::Shutdown => return,
    }

    // The snapshot answers read commands while the initial sync holds
    // `&mut client`; its only failure is the shared profile load. Readiness
    // was already acknowledged (the pipeline above served commands), so a
    // capture failure must NOT kill the worker — a dead worker behind a
    // successful `start()` is the failure mode mdk#1306 review flagged.
    // Degrade instead: publish the error and run the catch-up window without
    // a snapshot, deferring read commands alongside mutations so they replay
    // on live state after catch-up.
    let snapshot_started = Instant::now();
    let read_snapshot = {
        let capture =
            client.group_read_snapshot_with_stage_telemetry(&shared.app_performance_telemetry());
        shared.app_performance_telemetry().record(
            AppPerformanceOperation::AccountGroupReadSnapshot,
            snapshot_started.elapsed(),
            capture.is_ok(),
        );
        match capture {
            Ok(snapshot) => Some(snapshot),
            Err(err) => {
                let message =
                    account_error_message("runtime startup snapshot capture failed", &err);
                publish_app_runtime_account_error(
                    &events,
                    &account_id_hex,
                    &account_label,
                    message,
                );
                None
            }
        }
    };

    // Start signer installation, transport activation, group-subscription
    // registration, and initial catch-up only after local readiness has been
    // signalled. The sync future holds `&mut client` for its whole lifetime, so
    // while it is in flight the command loop must not touch the live session:
    // read commands are answered from `read_snapshot`, and every other command
    // is deferred and replayed on live state once catch-up lands, in arrival
    // order. `CatchUp` requests that arrive during the initial sync are
    // coalesced onto it.
    let sync_started_at = Instant::now();
    let startup_stage_telemetry = shared.app_performance_telemetry();
    let startup_sync_result = {
        let mut initial_sync = std::pin::pin!(async {
            let summary = client
                .sync_with_startup_stage_telemetry(&startup_stage_telemetry)
                .await?;
            app.finish_client_open_network_maintenance(&mut client)
                .await;
            Ok::<_, AppError>(summary)
        });
        loop {
            tokio::select! {
                _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => return,
                _ = &mut shutdown => return,
                result = &mut initial_sync => break result,
                command = commands.recv() => {
                    match command {
                        None => return,
                        Some(AccountWorkerCommand::Members { group_id, respond }) => {
                            match &read_snapshot {
                                Some(snapshot) => {
                                    let _ = respond.send(snapshot.members(&group_id));
                                }
                                // Degraded (capture failed): answer from live
                                // state after catch-up instead of guessing.
                                None => deferred.push(DeferredStartupCommand::Command(Box::new(
                                    AccountWorkerCommand::Members { group_id, respond },
                                ))),
                            }
                        }
                        Some(AccountWorkerCommand::MemberIdsPage { group_ids, respond }) => {
                            match &read_snapshot {
                                Some(snapshot) => {
                                    let _ = respond.send(snapshot.member_ids_page(&group_ids));
                                }
                                None => deferred.push(DeferredStartupCommand::Command(Box::new(
                                    AccountWorkerCommand::MemberIdsPage { group_ids, respond },
                                ))),
                            }
                        }
                        Some(AccountWorkerCommand::GroupMlsState { group_id, respond }) => {
                            match &read_snapshot {
                                Some(snapshot) => {
                                    let _ = respond.send(snapshot.group_mls_state(&group_id));
                                }
                                None => deferred.push(DeferredStartupCommand::Command(Box::new(
                                    AccountWorkerCommand::GroupMlsState { group_id, respond },
                                ))),
                            }
                        }
                        Some(AccountWorkerCommand::GroupRoster { group_id, respond }) => {
                            match &read_snapshot {
                                Some(snapshot) => {
                                    let result = group_roster_from_snapshot(
                                        &app,
                                        &account_label,
                                        snapshot,
                                        &group_id,
                                    );
                                    let _ = respond.send(result);
                                }
                                None => deferred.push(DeferredStartupCommand::Command(Box::new(
                                    AccountWorkerCommand::GroupRoster { group_id, respond },
                                ))),
                            }
                        }
                        Some(AccountWorkerCommand::QuarantinedGroups { respond }) => {
                            match &read_snapshot {
                                Some(snapshot) => {
                                    let _ = respond.send(Ok(snapshot.quarantined_groups()));
                                }
                                None => deferred.push(DeferredStartupCommand::Command(Box::new(
                                    AccountWorkerCommand::QuarantinedGroups { respond },
                                ))),
                            }
                        }
                        Some(AccountWorkerCommand::CatchUp { respond }) => {
                            // Coalesce onto the in-flight initial catch-up rather
                            // than starting a second sync; fulfilled in arrival
                            // order below when it completes.
                            deferred.push(DeferredStartupCommand::CatchUp(respond));
                        }
                        Some(other) => {
                            deferred.push(DeferredStartupCommand::Command(Box::new(other)))
                        }
                    }
                }
            }
        }
    };
    shared.app_performance_telemetry().record(
        AppPerformanceOperation::AccountSync,
        sync_started_at.elapsed(),
        startup_sync_result.is_ok(),
    );
    let catch_up_result = match startup_sync_result {
        Ok(summary) => {
            publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
            schedule_pending_convergence_groups(&mut scheduled_convergence, &mut client);
            let backfill_result = run_pending_epoch_backfill_reporting_arm(
                &mut client,
                &events,
                &account_id_hex,
                &account_label,
                &shared,
            )
            .await;
            if sync_summary_triggers_audit_tracker_update(&summary) {
                shared.schedule_audit_log_tracker_update("startup_sync");
            }
            backfill_result
        }
        Err(err) => {
            publish_client_pending_applied_summary(
                &mut client,
                &events,
                &account_id_hex,
                &account_label,
            );
            // A failed initial catch-up surfaces as an account error but must not
            // fail worker readiness — readiness was already signalled above.
            let message = account_error_message("runtime startup receive failed", &err);
            publish_app_runtime_account_error(
                &events,
                &account_id_hex,
                &account_label,
                message.clone(),
            );
            // Hydration may already have scheduled durable queued intents from
            // a prior process. Initial transport activation failed before the
            // normal sync path could drain those engine effects, so transfer
            // their scheduling edge into the app client now. Queued intents do
            // not require transport merely to drain; any incidental fanout
            // failure remains retryable and is reported separately.
            match client.drain_pending_session_events().await {
                Ok(summary) => {
                    publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
                }
                Err(drain_error) => {
                    publish_app_runtime_account_error(
                        &events,
                        &account_id_hex,
                        &account_label,
                        account_error_message(
                            "runtime startup queued-work wake failed",
                            &drain_error,
                        ),
                    );
                }
            }
            Err(message)
        }
    };
    // Replay commands deferred during the initial catch-up in arrival order, now
    // on live state. Coalesced `CatchUp` waiters are fulfilled at their position
    // with the initial catch-up's result.
    for deferred_command in deferred {
        match deferred_command {
            DeferredStartupCommand::CatchUp(respond) => {
                let _ = respond.send(catch_up_result.clone());
            }
            DeferredStartupCommand::Command(command) => {
                handle_account_worker_command(
                    &mut client,
                    *command,
                    &events,
                    &account_id_hex,
                    &account_label,
                    &shared,
                )
                .await;
            }
        }
    }
    // Automatic gossip is best-effort network work. Run it only after startup
    // callers have received their deferred responses so a degraded relay cannot
    // extend account-open latency.
    let push_work_pending = client
        .retry_pending_push_registration_shares_best_effort()
        .await;
    scheduled_push_retry.schedule_after_attempt(push_work_pending, &command_tx);
    publish_client_pending_applied_summary(&mut client, &events, &account_id_hex, &account_label);

    // #637: mutations replayed during deferred startup (e.g. a queued SendMessage
    // / InviteMembers) can buffer convergence groups. The steady-state arms below
    // drain `take_pending_convergence_groups()` after every command/event, but the
    // deferred-replay loop above does not — so schedule them here before entering
    // the loop, otherwise buffered groups stay stranded until the next unrelated
    // command/event (a liveness gap). `schedule_groups` is an idempotent set
    // insert, so this is safe even when the loop buffered nothing.
    schedule_pending_convergence_groups(&mut scheduled_convergence, &mut client);

    let mut reconnect_backoff = AccountWorkerReconnectBackoff::default();
    let mut maintenance_tick = interval(Duration::from_secs(15));
    maintenance_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    'worker: loop {
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => {
                return;
            }
            _ = &mut shutdown => {
                return;
            }
            _ = scheduled_convergence.timer.as_mut() => {
                let groups = scheduled_convergence.take_ready();
                match client.sync_runtime_groups().await {
                    Ok(()) => {
                        let mut remaining = groups.len();
                        for group_id in groups {
                            // Each group's convergence pass is a long blocking
                            // stretch of synchronous engine + SQLite work with
                            // no await inside it, so `JoinHandle::abort` cannot
                            // land there: without this check the shutdown budget
                            // is spent running the whole batch to completion.
                            // The group boundary is the only cut point where no
                            // snapshot guard is live, so it is also the only one
                            // that cannot leave a group half-rolled-back.
                            // Undispatched groups need no hand-off — their
                            // convergence inputs are durable, so the next
                            // runtime rediscovers them at catch-up.
                            if lifecycle.is_stopping() {
                                tracing::debug!(
                                    target: "marmot_app::runtime",
                                    method = "scheduled_convergence",
                                    skipped_groups = remaining,
                                    "shutdown requested; leaving remaining convergence passes for the next runtime",
                                );
                                break;
                            }
                            remaining -= 1;
                            match client.advance_convergence_after_runtime_sync(&group_id).await {
                                Ok(summary) => {
                                    publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
                                    match client.convergence_schedule_state(&group_id) {
                                        Ok(state) => scheduled_convergence
                                            .schedule_after_pass(&group_id, state),
                                        Err(err) => {
                                            scheduled_convergence
                                                .schedule_retry_groups([group_id.clone()]);
                                            publish_app_runtime_account_error(
                                                &events,
                                                &account_id_hex,
                                                &account_label,
                                                account_error_message(
                                                    "convergence schedule state failed",
                                                    &err,
                                                ),
                                            );
                                        }
                                    }
                                    schedule_pending_convergence_groups(
                                        &mut scheduled_convergence,
                                        &mut client,
                                    );
                                    let _ = run_pending_epoch_backfill_reporting_arm(
                                        &mut client,
                                        &events,
                                        &account_id_hex,
                                        &account_label,
                                        &shared,
                                    )
                                    .await;
                                    if sync_summary_triggers_audit_tracker_update(&summary) {
                                        shared.schedule_audit_log_tracker_update("scheduled_convergence");
                                    }
                                }
                                Err(err) => {
                                    let mut retry_groups = client.take_pending_convergence_groups();
                                    retry_groups.push(group_id.clone());
                                    scheduled_convergence.schedule_retry_groups(retry_groups);
                                    publish_app_runtime_account_error(
                                        &events,
                                        &account_id_hex,
                                        &account_label,
                                        account_error_message("scheduled convergence failed", &err),
                                    );
                                }
                            }
                        }
                    }
                    Err(err) => {
                        let account_inactive = err.is_account_not_active();
                        scheduled_convergence.schedule_retry_groups(groups);
                        publish_app_runtime_account_error(
                            &events,
                            &account_id_hex,
                            &account_label,
                            account_error_message("scheduled convergence sync failed", &err),
                        );
                        if account_inactive
                            && let Err(activation_error) = client.prepare_transport().await
                        {
                            publish_app_runtime_account_error(
                                &events,
                                &account_id_hex,
                                &account_label,
                                account_error_message(
                                    "scheduled convergence transport reactivation failed",
                                    &activation_error,
                                ),
                            );
                        }
                    }
                }
            }
            command = commands.recv() => {
                match command {
                    Some(command) => {
                        let mut pending = VecDeque::from([command]);
                        while let Some(command) = pending.pop_front() {
                            let may_change_push_registration_work =
                                command.may_change_push_registration_work();
                            match command {
                                AccountWorkerCommand::CatchUp { respond } => {
                                    handle_account_worker_catch_up(
                                        &mut client,
                                        respond,
                                        &mut commands,
                                        &mut pending,
                                        AccountWorkerCatchUpContext {
                                            app: &app,
                                            events: &events,
                                            account_id_hex: &account_id_hex,
                                            account_label: &account_label,
                                            shared: &shared,
                                        },
                                    )
                                    .await;
                                }
                                command => {
                                    handle_account_worker_command(
                                        &mut client,
                                        command,
                                        &events,
                                        &account_id_hex,
                                        &account_label,
                                        &shared,
                                    )
                                    .await;
                                }
                            }
                            schedule_pending_convergence_groups(
                                &mut scheduled_convergence,
                                &mut client,
                            );
                            if may_change_push_registration_work {
                                scheduled_push_retry.observe_pending(
                                    client.has_pending_push_registration_work(),
                                    &command_tx,
                                );
                            }
                        }
                    }
                    None => return,
                }
            }
            received = client.receive_next_delivery() => {
                // Only the transport wait participates in `select!`. Once a
                // delivery has been claimed, finish ingest + incidental
                // publish + projection as one uncancelled worker operation;
                // commands remain queued until that durable sequence lands.
                let result = match received {
                    Ok(delivery) => client.ingest_received_delivery(delivery).await,
                    Err(err) => Err(err),
                };
                match result {
                    Ok(summary) => {
                        reconnect_backoff.reset();
                        publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
                        schedule_pending_convergence_groups(
                            &mut scheduled_convergence,
                            &mut client,
                        );
                        let _ = run_pending_epoch_backfill_reporting_arm(
                            &mut client,
                            &events,
                            &account_id_hex,
                            &account_label,
                            &shared,
                        )
                        .await;
                        if sync_summary_triggers_audit_tracker_update(&summary) {
                            shared.schedule_audit_log_tracker_update("receive");
                        }
                        if !summary.joined_groups.is_empty() {
                            let pending = client
                                .retry_pending_push_registration_shares_best_effort()
                                .await;
                            scheduled_push_retry.schedule_after_attempt(pending, &command_tx);
                            publish_client_pending_applied_summary(
                                &mut client,
                                &events,
                                &account_id_hex,
                                &account_label,
                            );
                        }
                    }
                    Err(err) => {
                        publish_app_runtime_account_error(
                            &events,
                            &account_id_hex,
                            &account_label,
                            account_error_message("runtime receive failed", &err),
                        );
                        // The account-session ownership guard is held by
                        // `AppClient`. Destroy the failed engine before the
                        // backoff as well as before hydrating its replacement;
                        // this leaves room for a one-shot client during a
                        // prolonged transport outage.
                        drop(client);
                        client = loop {
                            let mut retry_delay =
                                std::pin::pin!(sleep(reconnect_backoff.next_delay()));
                            loop {
                                tokio::select! {
                                    _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => return,
                                    _ = &mut shutdown => return,
                                    _ = &mut retry_delay => break,
                                    command = commands.recv() => {
                                        match command {
                                            // There is deliberately no engine
                                            // session during this backoff.
                                            // Poll the bounded channel and
                                            // reject callers promptly by
                                            // dropping their response sender
                                            // instead of letting the queue fill
                                            // until host-side timeouts fire.
                                            Some(command) => drop(command),
                                            None => return,
                                        }
                                    }
                                }
                            }
                            match tokio::select! {
                                _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => return,
                                _ = &mut shutdown => return,
                                result = app.runtime_local_client(&account_label, &relay_plane, lifecycle.clone()) => result,
                            } {
                                Ok(mut reopened) => {
                                    // A reconnect open is deferred like the
                                    // startup open; drain the hydration
                                    // eagerly here — the steady-state loop
                                    // below answers reads live and must not
                                    // hand out not-hydrated errors after a
                                    // mid-session reconnect (mdk#1161).
                                    if let Err(err) = drain_deferred_hydration(&mut reopened).await
                                    {
                                        publish_app_runtime_account_error(
                                            &events,
                                            &account_id_hex,
                                            &account_label,
                                            account_error_message(
                                                "runtime restart hydration failed",
                                                &err,
                                            ),
                                        );
                                        drop(reopened);
                                        continue;
                                    }
                                    // Reconnect restores transport activation
                                    // and subscriptions, then resumes the live
                                    // receive tail. Do not block the command
                                    // loop on a full catch-up; the maintenance
                                    // path performs bounded repair syncs when
                                    // required.
                                    let prepare_transport = tokio::select! {
                                        _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => return,
                                        _ = &mut shutdown => return,
                                        result = reopened.prepare_transport() => result,
                                    };
                                    if let Err(transport_err) = prepare_transport {
                                        publish_app_runtime_account_error(
                                            &events,
                                            &account_id_hex,
                                            &account_label,
                                            account_error_message(
                                                "runtime restart transport failed",
                                                &transport_err,
                                            ),
                                        );
                                        drop(reopened);
                                        continue;
                                    }
                                    app.finish_client_open_network_maintenance(&mut reopened)
                                        .await;
                                    match reopened.drain_pending_session_events().await {
                                        Ok(summary) => {
                                            publish_app_runtime_summary(
                                                &events,
                                                &account_id_hex,
                                                &account_label,
                                                &summary,
                                            );
                                        }
                                        Err(error) => {
                                            publish_app_runtime_account_error(
                                                &events,
                                                &account_id_hex,
                                                &account_label,
                                                account_error_message(
                                                    "runtime restart queued-work wake failed",
                                                    &error,
                                                ),
                                            );
                                        }
                                    }
                                    let pending = reopened
                                        .retry_pending_push_registration_shares_best_effort()
                                        .await;
                                    scheduled_push_retry
                                        .schedule_after_attempt(pending, &command_tx);
                                    publish_client_pending_applied_summary(
                                        &mut reopened,
                                        &events,
                                        &account_id_hex,
                                        &account_label,
                                    );
                                    break reopened;
                                }
                                Err(setup_err) => {
                                    publish_app_runtime_account_error(
                                        &events,
                                        &account_id_hex,
                                        &account_label,
                                        account_error_message("runtime restart failed", &setup_err),
                                    );
                                }
                            }
                        };
                        schedule_pending_convergence_groups(
                            &mut scheduled_convergence,
                            &mut client,
                        );
                        continue 'worker;
                    }
                }
            }
            _ = maintenance_tick.tick() => {
                // Periodic maintenance is never urgent, and its catch-up leg is
                // capped at 15s — three times the whole shutdown budget. Skip
                // the tick outright once shutdown is requested rather than
                // starting work the drain would then have to wait out.
                if lifecycle.is_stopping() {
                    continue 'worker;
                }
                if client.key_package_maintenance_requires_catch_up() {
                    match timeout(Duration::from_secs(15), client.sync()).await {
                        Ok(Ok(summary)) => {
                            publish_app_runtime_summary(
                                &events,
                                &account_id_hex,
                                &account_label,
                                &summary,
                            );
                            publish_client_pending_projection_updates(
                                &mut client,
                                &events,
                                &account_id_hex,
                                &account_label,
                            );
                            schedule_pending_convergence_groups(
                                &mut scheduled_convergence,
                                &mut client,
                            );
                        }
                        Ok(Err(err)) => {
                            publish_client_pending_applied_summary(
                                &mut client,
                                &events,
                                &account_id_hex,
                                &account_label,
                            );
                            publish_app_runtime_account_error(
                                &events,
                                &account_id_hex,
                                &account_label,
                                account_error_message(
                                    "key package maintenance catch-up failed",
                                    &err,
                                ),
                            );
                        }
                        Err(_) => {
                            tracing::warn!(
                                target: "marmot_app::runtime",
                                method = "key_package_maintenance_catch_up",
                                "key package maintenance catch-up reached its time cap"
                            );
                        }
                    }
                }
                let _ = run_pending_epoch_backfill_reporting_arm(
                    &mut client,
                    &events,
                    &account_id_hex,
                    &account_label,
                    &shared,
                )
                .await;
                if let Err(err) = client.advance_post_join_maintenance_subscriptions().await {
                    publish_app_runtime_account_error(
                        &events,
                        &account_id_hex,
                        &account_label,
                        account_error_message("post-join maintenance subscription failed", &err),
                    );
                }
                match client.run_due_maintenance().await {
                    Ok(summary) => {
                        let _ = summary;
                        publish_client_pending_projection_updates(
                            &mut client,
                            &events,
                            &account_id_hex,
                            &account_label,
                        );
                        publish_client_pending_applied_summary(
                            &mut client,
                            &events,
                            &account_id_hex,
                            &account_label,
                        );
                        schedule_pending_convergence_groups(
                            &mut scheduled_convergence,
                            &mut client,
                        );
                    }
                    Err(err) => {
                        publish_app_runtime_account_error(
                            &events,
                            &account_id_hex,
                            &account_label,
                            account_error_message("scheduled maintenance failed", &err),
                        );
                    }
                }
            }
        }
    }
}

/// Run a steady-state catch-up while preserving prompt read-only projection
/// access. The sync future exclusively borrows the live client, so reads that
/// arrive before another state-changing command are answered from a snapshot
/// captured immediately before the sync. Once a non-read command is deferred,
/// later reads remain behind it to preserve worker FIFO semantics.
/// Additional catch-up requests received before such a command coalesce onto
/// the in-flight sync.
struct AccountWorkerCatchUpContext<'a> {
    app: &'a MarmotApp,
    events: &'a broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &'a str,
    account_label: &'a str,
    shared: &'a RuntimeSharedServices,
}

async fn handle_account_worker_catch_up(
    client: &mut AppClient,
    respond: oneshot::Sender<Result<(), String>>,
    commands: &mut mpsc::Receiver<AccountWorkerCommand>,
    pending: &mut VecDeque<AccountWorkerCommand>,
    context: AccountWorkerCatchUpContext<'_>,
) {
    let read_snapshot = match client.group_read_snapshot() {
        Ok(snapshot) => Some(snapshot),
        Err(err) => {
            let message = account_error_message("runtime catch-up snapshot failed", &err);
            publish_app_runtime_account_error(
                context.events,
                context.account_id_hex,
                context.account_label,
                message,
            );
            // Snapshot availability controls whether reads can run concurrently
            // with sync; it must not prevent the explicit catch-up itself from
            // retrieving updates that may advance or repair degraded state.
            // Defer reads to live state until sync releases `&mut client`.
            None
        }
    };
    let mut catch_up_responders = vec![respond];
    let mut deferred = VecDeque::new();
    let mut commands_open = true;
    let sync_started_at = Instant::now();
    let sync_result = {
        let mut sync = std::pin::pin!(client.sync());
        loop {
            let command = if let Some(command) = pending.pop_front() {
                Some(command)
            } else {
                tokio::select! {
                    biased;
                    result = &mut sync => break result,
                    command = commands.recv(), if commands_open => {
                        if command.is_none() {
                            commands_open = false;
                        }
                        command
                    }
                }
            };
            let Some(command) = command else {
                continue;
            };
            let snapshot_reads_available = read_snapshot.is_some() && deferred.is_empty();
            match command {
                AccountWorkerCommand::Members { group_id, respond } if snapshot_reads_available => {
                    let snapshot = read_snapshot
                        .as_ref()
                        .expect("snapshot availability checked above");
                    let _ = respond.send(snapshot.members(&group_id));
                }
                AccountWorkerCommand::MemberIdsPage { group_ids, respond }
                    if snapshot_reads_available =>
                {
                    let snapshot = read_snapshot
                        .as_ref()
                        .expect("snapshot availability checked above");
                    let _ = respond.send(snapshot.member_ids_page(&group_ids));
                }
                AccountWorkerCommand::GroupMlsState { group_id, respond }
                    if snapshot_reads_available =>
                {
                    let snapshot = read_snapshot
                        .as_ref()
                        .expect("snapshot availability checked above");
                    let _ = respond.send(snapshot.group_mls_state(&group_id));
                }
                AccountWorkerCommand::GroupRoster { group_id, respond }
                    if snapshot_reads_available =>
                {
                    let snapshot = read_snapshot
                        .as_ref()
                        .expect("snapshot availability checked above");
                    let _ = respond.send(group_roster_from_snapshot(
                        context.app,
                        context.account_label,
                        snapshot,
                        &group_id,
                    ));
                }
                AccountWorkerCommand::QuarantinedGroups { respond } if snapshot_reads_available => {
                    let snapshot = read_snapshot
                        .as_ref()
                        .expect("snapshot availability checked above");
                    let _ = respond.send(Ok(snapshot.quarantined_groups()));
                }
                AccountWorkerCommand::CatchUp { respond } if deferred.is_empty() => {
                    catch_up_responders.push(respond);
                }
                command => deferred.push_back(command),
            }
        }
    };
    let result = match sync_result {
        Ok(summary) => {
            publish_app_runtime_summary(
                context.events,
                context.account_id_hex,
                context.account_label,
                &summary,
            );
            let backfill_result = run_pending_epoch_backfill_reporting_arm(
                client,
                context.events,
                context.account_id_hex,
                context.account_label,
                context.shared,
            )
            .await;
            if sync_summary_triggers_audit_tracker_update(&summary) {
                context.shared.schedule_audit_log_tracker_update("catch_up");
            }
            backfill_result
        }
        Err(err) => {
            publish_client_pending_applied_summary(
                client,
                context.events,
                context.account_id_hex,
                context.account_label,
            );
            let message = account_error_message("runtime catch-up failed", &err);
            publish_app_runtime_account_error(
                context.events,
                context.account_id_hex,
                context.account_label,
                message.clone(),
            );
            Err(message)
        }
    };
    context.shared.app_performance_telemetry().record(
        AppPerformanceOperation::AccountSync,
        sync_started_at.elapsed(),
        result.is_ok(),
    );
    let retry_after_response = result.is_ok();
    for respond in catch_up_responders {
        let _ = respond.send(result.clone());
    }
    pending.append(&mut deferred);
    if retry_after_response {
        client
            .retry_pending_push_registration_shares_best_effort()
            .await;
    }
}

/// Groups fully hydrated per background-pipeline batch (mdk#1161). Small so
/// a command queued mid-pipeline waits at most one batch of MLS loads plus
/// its own group's hydration.
const STARTUP_HYDRATION_BATCH_SIZE: usize = 4;

#[cfg(test)]
pub(crate) const STARTUP_HYDRATION_BATCH_SIZE_FOR_TEST: usize = STARTUP_HYDRATION_BATCH_SIZE;

/// Commands served between hydration batches. Bounded so sustained
/// account-worker traffic cannot starve the pipeline: without a budget, an
/// unbounded drain-until-empty could defer hydration (and the mutation
/// replay behind it) indefinitely while the `deferred` vec grows. The
/// command channel itself holds 8, so under continuous producers each batch
/// interleaves one channel's worth of commands with one batch of hydration.
const STARTUP_HYDRATION_COMMAND_BUDGET: usize = 8;

enum StartupHydrationOutcome {
    Completed,
    Shutdown,
}

/// Fully hydrate every group the deferred session open only seeded, in
/// chat-list recency order, while serving commands between batches
/// (mdk#1161). Group reads hydrate their one group and answer live;
/// mutations and catch-ups join `deferred` and replay in arrival order after
/// the initial catch-up, exactly like the catch-up window's own deferral.
/// Recovery events surface incrementally after each batch. A storage-level
/// pipeline failure stops the pipeline but not the worker: remaining groups
/// stay gated with the retryable not-hydrated state and still promote on
/// demand from send/ingest paths.
#[allow(clippy::too_many_arguments)]
async fn run_startup_hydration_pipeline(
    app: &MarmotApp,
    client: &mut AppClient,
    commands: &mut mpsc::Receiver<AccountWorkerCommand>,
    deferred: &mut Vec<DeferredStartupCommand>,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    shared: &RuntimeSharedServices,
    shutdown: &mut oneshot::Receiver<()>,
    lifecycle: &RuntimeLifecycle,
) -> StartupHydrationOutcome {
    if client.runtime.session().unhydrated_group_ids().is_empty() {
        finish_deferred_hydration_reconciliation(client);
        return StartupHydrationOutcome::Completed;
    }
    let pipeline_started = Instant::now();
    // Chat-list recency order from the durable projection: the groups the
    // user sees first hydrate first. The session appends any stored group
    // the projection does not know about.
    let hydration_order: Vec<GroupId> = app
        .chat_list(account_label, true)
        .map(|rows| {
            rows.iter()
                .filter_map(|row| hex::decode(&row.group_id_hex).ok().map(GroupId::new))
                .collect()
        })
        .unwrap_or_default();
    let batch_delay = startup_hydration_batch_test_delay(app);
    let mut lifecycle_shutdown = lifecycle.subscribe_shutdown();
    let mut pipeline_ok = true;
    loop {
        // Test-only pre-batch hold (`test-policy-overrides` builds): keeps
        // groups in the seeded state so integration tests can assert the
        // persisted chat projection and per-group read behavior. Commands are
        // still served while holding, and shutdown interrupts the hold so
        // teardown exercises the graceful exit rather than the abort timeout.
        if !batch_delay.is_zero() {
            let hold_until = TokioInstant::now() + batch_delay;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(hold_until) => break,
                    _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => {
                        return StartupHydrationOutcome::Shutdown;
                    }
                    _ = &mut *shutdown => return StartupHydrationOutcome::Shutdown,
                    command = commands.recv() => match command {
                        Some(command) => {
                            handle_startup_hydration_command(client, command, deferred).await;
                        }
                        None => return StartupHydrationOutcome::Shutdown,
                    },
                }
            }
        }
        let mut commands_served = 0usize;
        while commands_served < STARTUP_HYDRATION_COMMAND_BUDGET {
            match commands.try_recv() {
                Ok(command) => {
                    commands_served += 1;
                    handle_startup_hydration_command(client, command, deferred).await;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return StartupHydrationOutcome::Shutdown;
                }
            }
        }
        if !matches!(
            shutdown.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ) || lifecycle.ensure_running().is_err()
        {
            return StartupHydrationOutcome::Shutdown;
        }
        let progress = match client
            .runtime
            .session_mut()
            .hydrate_next_groups(&hydration_order, STARTUP_HYDRATION_BATCH_SIZE)
        {
            Ok(progress) => progress,
            Err(err) => {
                let message =
                    account_error_message("startup group hydration failed", &AppError::from(err));
                publish_app_runtime_account_error(events, account_id_hex, account_label, message);
                // Remaining groups stay gated retryable; the stage sample
                // below must not report this aborted pipeline as a success.
                pipeline_ok = false;
                break;
            }
        };
        // Surface this batch's recovery events (PendingCommitRecovered,
        // hydration quarantines, restored leave requests) exactly as a live
        // drain would, so the projection updates incrementally.
        if let Ok(summary) = client.drain_pending_session_events().await {
            publish_app_runtime_summary(events, account_id_hex, account_label, &summary);
        }
        if progress.remaining == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    shared.app_performance_telemetry().record(
        AppPerformanceOperation::AccountGroupHydration,
        pipeline_started.elapsed(),
        pipeline_ok,
    );
    // Live group state is readable now; finish the projection repairs that
    // the deferred open deliberately skipped.
    finish_deferred_hydration_reconciliation(client);
    StartupHydrationOutcome::Completed
}

fn finish_deferred_hydration_reconciliation(client: &mut AppClient) {
    if let Err(err) = client.reconcile_hydrated_account_state() {
        tracing::warn!(
            target: "marmot_app::runtime",
            method = "run_startup_hydration_pipeline",
            error_kind = err.privacy_safe_kind(),
            "post-hydration account reconciliation failed; retrying next open"
        );
    }
}

/// Eagerly drain a deferred open's hydration without serving commands, for
/// paths (reconnect) whose callers previously relied on the fully-eager open.
async fn drain_deferred_hydration(client: &mut AppClient) -> Result<(), AppError> {
    loop {
        let progress = client
            .runtime
            .session_mut()
            .hydrate_next_groups(&[], STARTUP_HYDRATION_BATCH_SIZE)?;
        if progress.remaining == 0 {
            return client.reconcile_hydrated_account_state();
        }
        tokio::task::yield_now().await;
    }
}

/// Serve one command that arrived while the startup hydration pipeline was
/// running. Group-local reads answer live — hydrating exactly the group
/// they name first, so a read "waits for that group only". The quarantine
/// list answers the incrementally-growing set; later additions reach
/// subscribers through their `GroupHydrationQuarantined` events. Everything
/// else joins the startup deferral in arrival order.
async fn handle_startup_hydration_command(
    client: &mut AppClient,
    command: AccountWorkerCommand,
    deferred: &mut Vec<DeferredStartupCommand>,
) {
    match command {
        AccountWorkerCommand::Members { group_id, respond } => {
            let _ = client
                .runtime
                .session_mut()
                .ensure_group_hydrated(&group_id);
            let _ = respond.send(client.members(&group_id));
        }
        AccountWorkerCommand::MemberIdsPage { group_ids, respond } => {
            let _ = respond.send(member_ids_page_after_hydration(client, &group_ids));
        }
        AccountWorkerCommand::GroupMlsState { group_id, respond } => {
            let _ = client
                .runtime
                .session_mut()
                .ensure_group_hydrated(&group_id);
            let _ = respond.send(client.group_mls_state(&group_id));
        }
        AccountWorkerCommand::GroupRoster { group_id, respond } => {
            let _ = respond.send(group_roster_after_hydration(client, &group_id));
        }
        AccountWorkerCommand::QuarantinedGroups { respond } => {
            let _ = respond.send(Ok(client.quarantined_groups()));
        }
        #[cfg(test)]
        AccountWorkerCommand::UnhydratedGroupCount { respond } => {
            let count = client.runtime.session().unhydrated_group_ids().len();
            let _ = respond.send(count);
        }
        AccountWorkerCommand::CatchUp { respond } => {
            deferred.push(DeferredStartupCommand::CatchUp(respond));
        }
        other => deferred.push(DeferredStartupCommand::Command(Box::new(other))),
    }
}

/// Process a single account-worker command against the live session.
///
/// Extracted so the worker can drive commands from two places: the steady-state
/// command loop, and the deferred-command replay that runs after catch-up
/// completes (commands that arrived while catch-up held `&mut client`). Read
/// commands (`Members` / `MemberIdsPage` / `GroupMlsState` /
/// `QuarantinedGroups`) are also
/// intercepted inline during catch-up and answered from a `GroupReadSnapshot`;
/// here they read the live session.
async fn handle_account_worker_command(
    client: &mut AppClient,
    command: AccountWorkerCommand,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    shared: &RuntimeSharedServices,
) {
    match command {
        AccountWorkerCommand::NetworkStartupSettled { respond } => {
            let _ = respond.send(());
        }
        #[cfg(test)]
        AccountWorkerCommand::UnhydratedGroupCount { respond } => {
            let count = client.runtime.session().unhydrated_group_ids().len();
            let _ = respond.send(count);
        }
        AccountWorkerCommand::CatchUp { respond } => {
            let sync_started_at = Instant::now();
            let result = match client.sync().await {
                Ok(summary) => {
                    publish_app_runtime_summary(events, account_id_hex, account_label, &summary);
                    let backfill_result = run_pending_epoch_backfill_reporting_arm(
                        client,
                        events,
                        account_id_hex,
                        account_label,
                        shared,
                    )
                    .await;
                    if sync_summary_triggers_audit_tracker_update(&summary) {
                        shared.schedule_audit_log_tracker_update("catch_up");
                    }
                    backfill_result
                }
                Err(err) => {
                    publish_client_pending_applied_summary(
                        client,
                        events,
                        account_id_hex,
                        account_label,
                    );
                    let message = account_error_message("runtime catch-up failed", &err);
                    publish_app_runtime_account_error(
                        events,
                        account_id_hex,
                        account_label,
                        message.clone(),
                    );
                    Err(message)
                }
            };
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::AccountSync,
                sync_started_at.elapsed(),
                result.is_ok(),
            );
            let retry_after_response = result.is_ok();
            let _ = respond.send(result);
            if retry_after_response {
                client
                    .retry_pending_push_registration_shares_best_effort()
                    .await;
            }
        }
        AccountWorkerCommand::RepairFullHistory { respond } => {
            let sync_started_at = Instant::now();
            let result = match client.repair_full_history().await {
                Ok(summary) => {
                    publish_app_runtime_summary(events, account_id_hex, account_label, &summary);
                    if client.has_pending_epoch_backfill() {
                        client.finish_pending_epoch_backfill_after_replay();
                        shared.schedule_audit_log_tracker_update("epoch_backfill_armed");
                    }
                    if sync_summary_triggers_audit_tracker_update(&summary) {
                        shared.schedule_audit_log_tracker_update("repair_full_history");
                    }
                    Ok(())
                }
                Err(err) => {
                    publish_client_pending_applied_summary(
                        client,
                        events,
                        account_id_hex,
                        account_label,
                    );
                    let message = account_error_message("full-history repair failed", &err);
                    publish_app_runtime_account_error(
                        events,
                        account_id_hex,
                        account_label,
                        message.clone(),
                    );
                    Err(message)
                }
            };
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::AccountSync,
                sync_started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond.send(result);
        }
        AccountWorkerCommand::CreateGroup {
            queued_at,
            name,
            members,
            description,
            initial_image,
            respond,
        } => {
            let telemetry = shared.app_performance_telemetry();
            telemetry.record(
                AppPerformanceOperation::GroupCreateQueueWait,
                queued_at.elapsed(),
                true,
            );
            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
            let result = client
                .create_group_with_initial_profile_and_telemetry(
                    &name,
                    description.as_deref().unwrap_or_default(),
                    &member_refs,
                    initial_image,
                    &telemetry,
                )
                .await;
            if let Ok(group_id) = &result {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    group_id,
                );
            }
            publish_pending_welcome_delivery_events(events, account_id_hex, account_label, client);
            let created = result.is_ok();
            let _ = respond.send(result);
            if created {
                let subscription_started_at = Instant::now();
                let subscription_refresh = client.sync_runtime_groups().await;
                telemetry.record(
                    AppPerformanceOperation::GroupCreateSubscriptionRefresh,
                    subscription_started_at.elapsed(),
                    subscription_refresh.is_ok(),
                );
                if let Err(error) = subscription_refresh {
                    tracing::warn!(
                        target: "marmot_app::runtime",
                        method = "create_group_subscription_refresh",
                        error_kind = error.privacy_safe_kind(),
                        "confirmed group creation could not refresh subscriptions immediately"
                    );
                }
                client
                    .retry_pending_push_registration_shares_best_effort()
                    .await;
            }
        }
        AccountWorkerCommand::Members { group_id, respond } => {
            // On-demand promotion (mdk#1161): normally a no-op (the startup
            // pipeline hydrated everything), but if the pipeline aborted on a
            // storage error the leftover groups must still promote on first
            // read instead of surfacing GroupHydrationPending forever.
            let _ = client
                .runtime
                .session_mut()
                .ensure_group_hydrated(&group_id);
            let result = client.members(&group_id);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::MemberIdsPage { group_ids, respond } => {
            // The page is one worker command, but each requested group keeps
            // the same on-demand promotion and quarantine gate as `Members`.
            let _ = respond.send(member_ids_page_after_hydration(client, &group_ids));
        }
        AccountWorkerCommand::GroupMlsState { group_id, respond } => {
            // See the Members arm: on-demand promotion for pipeline-abort
            // leftovers.
            let _ = client
                .runtime
                .session_mut()
                .ensure_group_hydrated(&group_id);
            let result = client.group_mls_state(&group_id);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::GroupRoster { group_id, respond } => {
            let result = group_roster_after_hydration(client, &group_id);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::EnableGroupDisbanding { group_id, respond } => {
            let result = client.enable_group_disbanding(&group_id).await;
            if result.is_ok() {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::DisbandGroup { group_id, respond } => {
            let result = client.disband_group(&group_id).await;
            publish_app_runtime_group_state_updated(
                events,
                account_id_hex,
                account_label,
                &group_id,
            );
            let _ = respond.send(result);
        }
        AccountWorkerCommand::AcknowledgeDisbandFailure { group_id, respond } => {
            let result = client.acknowledge_disband_failure(&group_id);
            if matches!(result, Ok(true)) {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::QuarantinedGroups { respond } => {
            let result = Ok(client.quarantined_groups());
            let _ = respond.send(result);
        }
        AccountWorkerCommand::RetryHydrateQuarantinedGroup { group_id, respond } => {
            let result = client.retry_hydrate_quarantined_group(&group_id);
            if matches!(result, Ok(true)) {
                // The group is live again; the engine queued a
                // `GroupHydrationRecovered` event. Drain it now so
                // subscribers see the typed recovery event
                // deterministically at retry time rather than only
                // when unrelated relay traffic later triggers a
                // drain (mdk#426). Publish those events plus a
                // `GroupStateUpdated` so chat-list / projection
                // consumers refresh and the group leaves the recovery
                // surface and reappears as a normal chat.
                match client.drain_pending_session_events().await {
                    Ok(summary) => {
                        publish_app_runtime_summary(events, account_id_hex, account_label, &summary)
                    }
                    Err(err) => publish_app_runtime_account_error(
                        events,
                        account_id_hex,
                        account_label,
                        account_error_message("retry recovery drain failed", &err),
                    ),
                }
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::UpdateMessageRetention {
            group_id,
            disappearing_message_secs,
            respond,
        } => {
            let result = client
                .update_message_retention(&group_id, disappearing_message_secs)
                .await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::ReplaceEncryptedMediaBlobEndpoints {
            group_id,
            endpoints,
            respond,
        } => {
            let result = client
                .replace_encrypted_media_blob_endpoints(&group_id, endpoints)
                .await;
            if result.is_ok() {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::UpdateGroupAvatarUrl {
            group_id,
            url,
            dim,
            thumbhash,
            respond,
        } => {
            let result = client
                .update_group_avatar_url(&group_id, url, dim, thumbhash)
                .await;
            if result.is_ok() {
                // Drain the kind-1210 row this commit queued, like the
                // sibling UpdateGroupProfile / UpdateGroupImage handlers —
                // otherwise the avatar-changed caption reaches live
                // timeline subscribers only on the next snapshot reload.
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::SafeExportSecret {
            group_id,
            component_id,
            respond,
        } => {
            let result = client.safe_export_secret(&group_id, component_id);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::ExporterSecret {
            group_id,
            label,
            length,
            respond,
        } => {
            let result = client.exporter_secret(&group_id, &label, length);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::InviteMembers {
            group_id,
            members,
            respond,
        } => {
            let result = async {
                let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
                let telemetry = shared.app_performance_telemetry();
                client
                    .invite_members_with_telemetry(&group_id, &member_refs, &telemetry)
                    .await
            }
            .await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            publish_pending_welcome_delivery_events(events, account_id_hex, account_label, client);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::RemoveMembers {
            group_id,
            members,
            respond,
        } => {
            let result = async {
                let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
                client.remove_members(&group_id, &member_refs).await
            }
            .await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::LeaveGroup { group_id, respond } => {
            let result = client.leave_group(&group_id).await;
            // Published regardless of outcome. The engine records the durable
            // leave request before it publishes, so a leave that failed at the
            // relay still changed what subscribers should render: the group is
            // now pending-leave even though `self_membership` is still `Member`.
            // Without this, a failed leave leaves the flag invisible until some
            // unrelated refresh. A no-op re-read is cheap — `subscribe_chat_list`
            // fingerprint-dedupes it away when nothing actually changed.
            publish_app_runtime_group_state_updated(
                events,
                account_id_hex,
                account_label,
                &group_id,
            );
            let _ = respond.send(result);
        }
        AccountWorkerCommand::DeleteGroupLocal { group_id, respond } => {
            let result = client.delete_group_local(&group_id).await;
            if matches!(result, Ok(true)) {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::AcceptGroupInvite { group_id, respond } => {
            let result = client.accept_group_invite(&group_id);
            if result.is_ok() {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let retry_after_response = result.is_ok();
            let _ = respond.send(result);
            if retry_after_response {
                client
                    .retry_pending_push_registration_shares_best_effort()
                    .await;
            }
        }
        AccountWorkerCommand::DeclineGroupInvite { group_id, respond } => {
            let result = client.decline_group_invite(&group_id).await;
            if result.is_ok() {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::SetGroupArchived {
            group_id,
            archived,
            respond,
        } => {
            // The archive projection events (ArchiveChanged chat-list
            // update + GroupStateUpdated) are published by the single
            // caller `MarmotAppRuntime::set_group_archived` after this
            // command returns. Emitting `GroupStateUpdated` here too
            // would race ahead of the ArchiveChanged trigger and get
            // fingerprint-deduped by `subscribe_chat_list`, so
            // subscribers would see a generic state change instead of
            // the archive-specific trigger. Keep this worker handler
            // limited to mutating the authoritative in-memory state.
            let result = client.set_group_archived(&group_id, archived);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::PromoteAdmin {
            group_id,
            member_ref,
            respond,
        } => {
            let result = client.promote_admin(&group_id, &member_ref).await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::DemoteAdmin {
            group_id,
            member_ref,
            respond,
        } => {
            let result = client.demote_admin(&group_id, &member_ref).await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::SelfDemoteAdmin { group_id, respond } => {
            let result = client.self_demote_admin(&group_id).await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::UpdateGroupProfile {
            group_id,
            name,
            description,
            respond,
        } => {
            let result = client
                .update_group_profile(&group_id, name.as_deref(), description.as_deref())
                .await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::UpdateGroupImage {
            group_id,
            plaintext,
            media_type,
            respond,
        } => {
            let result = client
                .update_group_image(&group_id, plaintext, &media_type)
                .await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::DownloadGroupImage { group_id, respond } => {
            let result = client.download_group_blossom_image(&group_id).await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::SendMessage {
            group_id,
            payload,
            respond,
        } => {
            let send_started_at = Instant::now();
            let result = client
                .send_with_local_projection(&group_id, &payload, |update| {
                    publish_app_runtime_projection_update(
                        events,
                        account_id_hex,
                        account_label,
                        update,
                    );
                })
                .await;
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::OutboundMessageSend,
                send_started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond.send(result);
        }
        AccountWorkerCommand::SendAppEvent {
            group_id,
            intent,
            respond,
        } => {
            let send_started_at = Instant::now();
            let result = client
                .send_app_event_with_local_projection(&group_id, intent, |update| {
                    publish_app_runtime_projection_update(
                        events,
                        account_id_hex,
                        account_label,
                        update,
                    );
                })
                .await
                .map(|(_event, summary)| summary);
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::OutboundMessageSend,
                send_started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond.send(result);
        }
        AccountWorkerCommand::BuildMediaImetaTag {
            group_id,
            reference,
            respond,
        } => {
            let result = client.build_media_imeta_tag(&group_id, &reference).await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::UploadMedia {
            group_id,
            request,
            respond,
        } => {
            let upload_started_at = Instant::now();
            let result = client.upload_media(&group_id, request).await;
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::MediaUpload,
                upload_started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond.send(result);
        }
        AccountWorkerCommand::DownloadMedia {
            group_id,
            reference,
            respond,
        } => {
            let download_started_at = Instant::now();
            let result = client.download_media(&group_id, reference).await;
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::MediaDownload,
                download_started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond.send(result);
        }
        AccountWorkerCommand::SecureDeleteExpiredPlaintext { group_id, respond } => {
            let result = client.secure_delete_expired_plaintext_for_group(&group_id);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::SweepExpiredRetention { now_ms, respond } => {
            let result = client.sweep_expired_retention(now_ms);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::StartAgentTextStream {
            group_id,
            stream_id,
            parent_message_id,
            quic_candidates,
            respond,
        } => {
            let result = client
                .start_agent_text_stream_with_local_projection(
                    &group_id,
                    &stream_id,
                    parent_message_id,
                    quic_candidates,
                    |update| {
                        publish_app_runtime_projection_update(
                            events,
                            account_id_hex,
                            account_label,
                            update,
                        );
                    },
                )
                .await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::FinishAgentTextStream {
            group_id,
            request,
            respond,
        } => {
            let result = client
                .finish_agent_text_stream_with_local_projection(&group_id, request, |update| {
                    publish_app_runtime_projection_update(
                        events,
                        account_id_hex,
                        account_label,
                        update,
                    );
                })
                .await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::RetryGroupConvergence { group_id, respond } => {
            let result = client.retry_group_convergence(&group_id).await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::PendingWelcomeDeliveries { respond } => {
            let result = client.pending_welcome_deliveries();
            let _ = respond.send(result);
        }
        AccountWorkerCommand::RedeliverWelcome {
            message_id_hex,
            respond,
        } => {
            let result = client.redeliver_welcome(&message_id_hex).await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::PublishKeyPackage { respond } => {
            let result = async {
                let key_package = client.publish_key_package().await?;
                Ok(key_package.bytes().len())
            }
            .await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::RotateKeyPackage { respond } => {
            let result = async {
                let key_package = client.rotate_key_package().await?;
                Ok(key_package.bytes().len())
            }
            .await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::KeyPackageMaintenanceStatus { respond } => {
            let _ = respond.send(client.key_package_maintenance_status());
        }
        AccountWorkerCommand::DurablyOwnedKeyPackages { respond } => {
            let _ = respond.send(client.durably_owned_key_packages());
        }
        AccountWorkerCommand::MaintenanceStatus { group_id, respond } => {
            let _ = respond.send(client.maintenance_status(&group_id));
        }
        AccountWorkerCommand::ScheduleManualSelfUpdate { group_id, respond } => {
            let _ = respond.send(client.schedule_manual_self_update(&group_id));
        }
        AccountWorkerCommand::PeriodicMaintenancePolicy { respond } => {
            let _ = respond.send(client.periodic_maintenance_policy());
        }
        AccountWorkerCommand::SetPeriodicMaintenancePolicy { policy, respond } => {
            let _ = respond.send(client.set_periodic_maintenance_policy(policy));
        }
        AccountWorkerCommand::PauseMaintenance { respond } => {
            client.pause_maintenance();
            let _ = respond.send(Ok(()));
        }
        AccountWorkerCommand::ResumeMaintenance { respond } => {
            client.resume_maintenance();
            let _ = respond.send(Ok(()));
        }
        AccountWorkerCommand::RunDueMaintenance { respond } => {
            let result = client.run_due_maintenance().await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::SharePushRegistration { respond } => {
            let result = client.share_push_registration().await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::UpsertPushRegistration {
            platform,
            raw_token,
            server_pubkey_hex,
            relay_hint,
            respond,
        } => {
            let result = client
                .upsert_and_share_push_registration(
                    platform,
                    &raw_token,
                    &server_pubkey_hex,
                    relay_hint,
                )
                .await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::ClearPushRegistration { respond } => {
            let result = client.clear_and_share_push_registration().await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::SetNativePushEnabled { enabled, respond } => {
            let result = client
                .app
                .set_native_push_enabled(&client.state.label, enabled);
            let should_retry = result.is_ok();
            let _ = respond.send(result);
            if should_retry {
                client
                    .retry_pending_push_registration_shares_best_effort()
                    .await;
            }
        }
        AccountWorkerCommand::RemovePushRegistration {
            registration,
            respond,
        } => {
            let result = client.remove_push_registration(registration).await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::RetryPushRegistration { respond } => {
            let pending = client
                .retry_pending_push_registration_shares_best_effort()
                .await;
            let _ = respond.send(pending);
        }
        AccountWorkerCommand::DeleteAuditLog { path, respond } => {
            let result = client.rotate_audit_log_if_active(&path);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::SetAuditRecording { enabled, respond } => {
            client.set_audit_recording(enabled);
            let _ = respond.send(Ok(()));
        }
        AccountWorkerCommand::SetAuditDataMode {
            mode,
            reason,
            respond,
        } => {
            client.set_audit_data_mode(mode, &reason);
            let _ = respond.send(Ok(()));
        }
    }
    // Publishing from this seam — rather than inside each send arm — keeps
    // every command path covered; the summary is empty for commands that
    // applied nothing.
    publish_client_pending_applied_summary(client, events, account_id_hex, account_label);
}

pub(super) fn group_roster_after_hydration(
    client: &mut AppClient,
    group_id: &GroupId,
) -> Result<crate::groups::AppGroupRosterSession, AppError> {
    client
        .runtime
        .session_mut()
        .ensure_group_hydrated(group_id)?;
    client.reconcile_group_self_membership(group_id)?;
    client.group_roster_session(group_id)
}

fn member_ids_page_after_hydration(
    client: &mut AppClient,
    group_ids: &[GroupId],
) -> Result<Vec<crate::AppGroupMemberIds>, AppError> {
    // Match every existing worker-routed group read: a seeded group promotes
    // on demand, while a failed promotion enters quarantine and is exposed as
    // UnknownGroup. Build the response only after all requested rosters pass
    // that gate so callers never receive a partial page.
    for group_id in group_ids {
        let _live = client
            .runtime
            .session_mut()
            .ensure_group_hydrated(group_id)?;
    }
    client.member_ids_page(group_ids)
}

fn group_roster_from_snapshot(
    app: &MarmotApp,
    account_label: &str,
    snapshot: &crate::client::GroupReadSnapshot,
    group_id: &GroupId,
) -> Result<crate::groups::AppGroupRosterSession, AppError> {
    let mut session = snapshot.group_roster(group_id)?;
    if let Some(membership) =
        app.stored_group_self_membership(account_label, &session.group_record.group_id_hex)?
    {
        session.group_record.self_membership = membership;
    }
    Ok(session)
}

#[derive(Debug, Clone)]
pub(crate) struct AccountWorkerReconnectBackoff {
    base: Duration,
    max: Duration,
    next: Duration,
}

impl Default for AccountWorkerReconnectBackoff {
    fn default() -> Self {
        Self::new(
            ACCOUNT_WORKER_RECONNECT_BASE_DELAY,
            ACCOUNT_WORKER_RECONNECT_MAX_DELAY,
        )
    }
}

impl AccountWorkerReconnectBackoff {
    pub(crate) fn new(base: Duration, max: Duration) -> Self {
        let base = std::cmp::min(base, max);
        Self {
            base,
            max,
            next: base,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.next = self.base;
    }

    fn next_delay(&mut self) -> Duration {
        self.next_delay_with_jitter(account_worker_reconnect_jitter())
    }

    pub(crate) fn next_delay_with_jitter(&mut self, jitter: Duration) -> Duration {
        let delay = std::cmp::min(self.next.saturating_add(jitter), self.max);
        self.next = std::cmp::min(self.next.saturating_mul(2), self.max);
        delay
    }
}

fn account_worker_reconnect_jitter() -> Duration {
    let jitter_ms = OsRng.next_u64() % (ACCOUNT_WORKER_RECONNECT_JITTER_MAX_MS + 1);
    Duration::from_millis(jitter_ms)
}

fn push_registration_retry_base_delay() -> Duration {
    if cfg!(test) {
        Duration::from_millis(25)
    } else {
        Duration::from_secs(5)
    }
}

fn push_registration_retry_max_delay() -> Duration {
    if cfg!(test) {
        Duration::from_millis(1_600)
    } else {
        Duration::from_secs(5 * 60)
    }
}

fn push_registration_retry_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6);
    let multiplier = 1u32 << shift;
    push_registration_retry_base_delay()
        .saturating_mul(multiplier)
        .min(push_registration_retry_max_delay())
}

/// A bounded backoff timer that exists only while durable push outbox rows
/// remain. This is not a periodic poll: successful drain disarms it completely.
struct ScheduledPushRegistrationRetry {
    timer_task: Option<JoinHandle<()>>,
}

impl ScheduledPushRegistrationRetry {
    fn new() -> Self {
        Self { timer_task: None }
    }

    fn is_armed(&self) -> bool {
        self.timer_task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    }

    fn observe_pending(&mut self, pending: bool, commands: &mpsc::Sender<AccountWorkerCommand>) {
        if !pending {
            self.disarm();
        } else if !self.is_armed() {
            self.arm(commands.clone(), 1);
        }
    }

    fn schedule_after_attempt(
        &mut self,
        pending: bool,
        commands: &mpsc::Sender<AccountWorkerCommand>,
    ) {
        if !pending {
            self.disarm();
            return;
        }
        self.arm(commands.clone(), 1);
    }

    fn arm(&mut self, commands: mpsc::Sender<AccountWorkerCommand>, first_attempt: u32) {
        if let Some(task) = self.timer_task.take() {
            task.abort();
        }
        self.timer_task = Some(tokio::spawn(async move {
            let mut attempt = first_attempt;
            loop {
                sleep(push_registration_retry_delay(attempt)).await;
                let (respond, response) = oneshot::channel();
                if commands
                    .send(AccountWorkerCommand::RetryPushRegistration { respond })
                    .await
                    .is_err()
                {
                    return;
                }
                match response.await {
                    Ok(true) => {
                        attempt = attempt.saturating_add(1);
                    }
                    Ok(false) | Err(_) => return,
                }
            }
        }));
    }

    fn disarm(&mut self) {
        if let Some(task) = self.timer_task.take() {
            task.abort();
        }
    }
}

impl Drop for ScheduledPushRegistrationRetry {
    fn drop(&mut self) {
        if let Some(task) = self.timer_task.take() {
            task.abort();
        }
    }
}

/// Extra delay beyond the engine quiescence window before the first scheduled
/// convergence tick fires. Avoids off-by-one-ms races where the timer fires
/// while `ConvergenceStatus` is still `Syncing` (mdk#494).
const CONVERGENCE_SETTLEMENT_SCHEDULE_MARGIN_MS: u64 = 100;
const IDLE_CONVERGENCE_TIMER_DELAY: Duration = Duration::from_secs(365 * 24 * 60 * 60);
const MIN_CONVERGENCE_SETTLEMENT_DELAY: Duration = Duration::from_millis(10);
const CONVERGENCE_RETRY_BASE_DELAY: Duration = Duration::from_secs(1);
const CONVERGENCE_RETRY_MAX_DELAY: Duration = Duration::from_secs(60);
/// After this many unsettled re-arms, fall back to error-style backoff so a
/// never-settling input cannot keep the worker waking every ~1.1s indefinitely.
const CONVERGENCE_UNSETTLED_MAX_REARMS: u32 = 10;

struct ScheduledConvergence {
    delay: Duration,
    test_delay: Duration,
    deadlines: HashMap<GroupId, TokioInstant>,
    retry_attempts: HashMap<GroupId, u32>,
    unsettled_rearm_attempts: HashMap<GroupId, u32>,
    timer: Pin<Box<Sleep>>,
}

impl ScheduledConvergence {
    #[cfg(test)]
    fn new(delay: Duration) -> Self {
        Self::with_test_delay(delay, Duration::ZERO)
    }

    fn with_test_delay(delay: Duration, test_delay: Duration) -> Self {
        Self {
            delay,
            test_delay,
            deadlines: HashMap::new(),
            retry_attempts: HashMap::new(),
            unsettled_rearm_attempts: HashMap::new(),
            timer: Box::pin(sleep(IDLE_CONVERGENCE_TIMER_DELAY)),
        }
    }

    /// Arm the timer for a group from the engine's structured scheduling
    /// state. An in-window wake (`Collecting`) is on time, not a failure: it
    /// arms at the pass's actual remaining cutoff and never touches the
    /// unsettled re-arm counter. Only `PendingUnopenable` — pending inputs
    /// with no pass able to open — counts toward the re-arm cap and its
    /// eventual error-style backoff.
    fn schedule_after_pass(&mut self, group_id: &GroupId, state: ConvergenceScheduleState) {
        match state {
            ConvergenceScheduleState::Idle => self.note_success(group_id),
            ConvergenceScheduleState::Collecting { remaining_ms } => {
                self.retry_attempts.remove(group_id);
                self.unsettled_rearm_attempts.remove(group_id);
                let delay = Duration::from_millis(
                    remaining_ms.saturating_add(CONVERGENCE_SETTLEMENT_SCHEDULE_MARGIN_MS),
                )
                .saturating_add(self.test_delay);
                self.arm_no_later(group_id.clone(), TokioInstant::now() + delay);
                self.reset_timer_to_earliest();
            }
            ConvergenceScheduleState::Ready => {
                self.retry_attempts.remove(group_id);
                self.unsettled_rearm_attempts.remove(group_id);
                self.arm_no_later(
                    group_id.clone(),
                    TokioInstant::now()
                        + MIN_CONVERGENCE_SETTLEMENT_DELAY.saturating_add(self.test_delay),
                );
                self.reset_timer_to_earliest();
            }
            ConvergenceScheduleState::PendingUnopenable => {
                self.schedule_unsettled_groups([group_id.clone()]);
            }
            ConvergenceScheduleState::PendingOutbound => {
                // A waiting outbound queue keeps the wakeup armed on the
                // normal delay but is not unsettled convergence: it never
                // feeds the re-arm cap, so a healthy queue cannot be demoted
                // to error backoff (transport failures reach backoff through
                // the sync/drain error paths instead). It also clears the
                // counter: this state means pending inputs are gone, so any
                // prior unopenable streak genuinely ended.
                self.retry_attempts.remove(group_id);
                self.unsettled_rearm_attempts.remove(group_id);
                self.arm_no_later(group_id.clone(), TokioInstant::now() + self.normal_delay());
                self.reset_timer_to_earliest();
            }
        }
    }

    #[cfg(test)]
    fn schedule_groups(&mut self, groups: impl IntoIterator<Item = GroupId>) {
        let delay = self.normal_delay();
        self.schedule_groups_with_delays(groups.into_iter().map(|group_id| (group_id, delay)));
    }

    #[cfg(test)]
    fn schedule_groups_with_delays(
        &mut self,
        groups: impl IntoIterator<Item = (GroupId, Duration)>,
    ) {
        let now = TokioInstant::now();
        for (group_id, delay) in groups {
            self.retry_attempts.remove(&group_id);
            self.unsettled_rearm_attempts.remove(&group_id);
            self.arm_no_later(group_id, now + delay.max(MIN_CONVERGENCE_SETTLEMENT_DELAY));
        }
        self.reset_timer_to_earliest();
    }

    fn schedule_retry_groups(&mut self, groups: impl IntoIterator<Item = GroupId>) {
        let now = TokioInstant::now();
        for group_id in groups {
            let attempts = self.retry_attempts.entry(group_id.clone()).or_insert(0);
            *attempts = attempts.saturating_add(1);
            let group_delay = retry_delay_for_attempt(*attempts);
            self.arm_no_later(group_id, now + group_delay);
        }
        self.reset_timer_to_earliest();
    }

    /// Re-arm the timer for groups whose scheduled pass did not settle stored
    /// convergence inputs (for example, the tick fired inside the quiescence
    /// window). Unlike [`Self::schedule_retry_groups`], this is not an error
    /// backoff — it waits one full settlement delay before retrying.
    fn schedule_unsettled_groups(&mut self, groups: impl IntoIterator<Item = GroupId>) {
        let now = TokioInstant::now();
        let normal_delay = self.normal_delay();
        for group_id in groups {
            let attempts = self
                .unsettled_rearm_attempts
                .entry(group_id.clone())
                .or_insert(0);
            *attempts = attempts.saturating_add(1);
            if *attempts > CONVERGENCE_UNSETTLED_MAX_REARMS {
                let retry_attempts = self.retry_attempts.entry(group_id.clone()).or_insert(0);
                *retry_attempts = retry_attempts.saturating_add(1);
                let group_delay = retry_delay_for_attempt(*retry_attempts);
                self.arm_no_later(group_id.clone(), now + group_delay);
            } else {
                self.arm_no_later(group_id.clone(), now + normal_delay);
            }
        }
        self.reset_timer_to_earliest();
    }

    fn take_ready(&mut self) -> Vec<GroupId> {
        let Some(earliest) = self.deadlines.values().copied().min() else {
            self.reset_timer_to_earliest();
            return Vec::new();
        };
        let now = TokioInstant::now();
        let mut ready: Vec<GroupId> = self
            .deadlines
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(group_id, _)| group_id.clone())
            .collect();
        if ready.is_empty() {
            ready.extend(
                self.deadlines
                    .iter()
                    .filter(|(_, deadline)| **deadline == earliest)
                    .map(|(group_id, _)| group_id.clone()),
            );
        }
        for group_id in &ready {
            self.deadlines.remove(group_id);
        }
        self.reset_timer_to_earliest();
        ready
    }

    fn note_success(&mut self, group_id: &GroupId) {
        self.retry_attempts.remove(group_id);
        self.unsettled_rearm_attempts.remove(group_id);
        self.deadlines.remove(group_id);
        self.reset_timer_to_earliest();
    }

    fn normal_delay(&self) -> Duration {
        self.delay.max(MIN_CONVERGENCE_SETTLEMENT_DELAY)
    }

    fn arm_no_later(&mut self, group_id: GroupId, deadline: TokioInstant) {
        self.deadlines
            .entry(group_id)
            .and_modify(|current| *current = (*current).min(deadline))
            .or_insert(deadline);
    }

    fn reset_timer_to_earliest(&mut self) {
        let deadline = self
            .deadlines
            .values()
            .copied()
            .min()
            .unwrap_or_else(|| TokioInstant::now() + IDLE_CONVERGENCE_TIMER_DELAY);
        self.timer.as_mut().reset(deadline);
    }
}

fn schedule_pending_convergence_groups(
    scheduled: &mut ScheduledConvergence,
    client: &mut AppClient,
) {
    for group_id in client.take_pending_convergence_groups() {
        match client.convergence_schedule_state(&group_id) {
            Ok(state) => scheduled.schedule_after_pass(&group_id, state),
            Err(_) => {
                // A schedule-state failure must keep a future wakeup armed:
                // swallowing it as "no work" would cancel the group's timer
                // and strand pending inputs (liveness). Privacy-safe signal
                // only — no group id.
                tracing::warn!(
                    target: "marmot_app::runtime::account_worker",
                    method = "schedule_pending_convergence_groups",
                    "convergence schedule-state read failed; arming retry backoff"
                );
                scheduled.schedule_retry_groups([group_id]);
            }
        }
    }
}

fn convergence_settlement_delay(app: &MarmotApp) -> Duration {
    // Normal builds always schedule against the pinned v1 quiescence window
    // (mdk#970); the override exists only in explicit test-policy builds.
    let quiescence_ms = if cfg!(feature = "test-policy-overrides") {
        app.config
            .dev_settlement_quiescence_ms
            .unwrap_or(cgka_engine::canonicalization::V1_SETTLEMENT_QUIESCENCE_MS)
    } else {
        cgka_engine::canonicalization::V1_SETTLEMENT_QUIESCENCE_MS
    };
    Duration::from_millis(quiescence_ms.saturating_add(CONVERGENCE_SETTLEMENT_SCHEDULE_MARGIN_MS))
}

fn startup_hydration_batch_test_delay(app: &MarmotApp) -> Duration {
    if cfg!(feature = "test-policy-overrides") {
        Duration::from_millis(
            app.config
                .dev_startup_hydration_batch_delay_ms
                .unwrap_or_default(),
        )
    } else {
        Duration::ZERO
    }
}

fn scheduled_convergence_test_delay(app: &MarmotApp) -> Duration {
    if cfg!(feature = "test-policy-overrides") {
        Duration::from_millis(
            app.config
                .dev_scheduled_convergence_delay_ms
                .unwrap_or_default(),
        )
    } else {
        Duration::ZERO
    }
}

fn retry_delay_for_attempt(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6);
    let multiplier = 1u32 << shift;
    CONVERGENCE_RETRY_BASE_DELAY
        .saturating_mul(multiplier)
        .min(CONVERGENCE_RETRY_MAX_DELAY)
}

fn sync_summary_triggers_audit_tracker_update(summary: &SyncSummary) -> bool {
    !summary.joined_groups.is_empty()
        || !summary.messages.is_empty()
        || !summary.events.is_empty()
        // An escalation is the highest-value evidence this crate produces and it
        // can ride a summary that carries no other visible activity (the arming
        // pass often ingests only undecryptable traffic), so it must trip the
        // gate on its own.
        || !summary.epoch_stall_escalations.is_empty()
}

/// Run any pending epoch-gap backfill and push its arm evidence to the audit
/// tracker. The arm state is captured *before* the replay drains it, and the
/// tracker is scheduled unconditionally on the replay outcome: the
/// `epoch_stall_backfill_armed` row is already durable, a failing replay is the
/// highest-value upload, and the arming pass returns an empty summary that
/// never trips the visible-activity gate. Shared by every incremental sync and
/// ingest seam so the capture-before-run ordering cannot drift. A replay
/// activation failure is both published and returned: explicit catch-up fails
/// its response while background seams retain their existing event-only
/// reporting behavior. Explicit full-history repair already performed the
/// unfloored replay and consumes the same intent without calling this helper.
async fn run_pending_epoch_backfill_reporting_arm(
    client: &mut AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    shared: &RuntimeSharedServices,
) -> Result<(), String> {
    let backfill_armed = client.has_pending_epoch_backfill();
    let result = client.run_pending_epoch_backfill().await.map_err(|err| {
        let message = account_error_message("epoch-gap backfill failed", &err);
        publish_app_runtime_account_error(events, account_id_hex, account_label, message.clone());
        message
    });
    if backfill_armed {
        shared.schedule_audit_log_tracker_update("epoch_backfill_armed");
    }
    result
}

fn publish_app_runtime_summary(
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    summary: &SyncSummary,
) {
    for group_id in &summary.joined_groups {
        let _ = events.send(MarmotAppEvent::GroupJoined {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            group_id: group_id.clone(),
        });
    }
    for message in &summary.messages {
        // Raw message subscribers get kind-1200 starts as a typed open-preview
        // signal. The storage timeline still materializes the same start as a
        // kind-1200 timeline row so timeline-only subscribers can discover and
        // watch the live stream.
        if let Some(event) = agent_stream_runtime_event(account_id_hex, account_label, message) {
            let _ = events.send(event);
        } else {
            let _ = events.send(MarmotAppEvent::MessageReceived(RuntimeMessageReceived {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
                message: message.clone(),
            }));
        }
    }
    for update in &summary.projection_updates {
        let _ = events.send(MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            update: update.clone(),
        }));
    }
    for event in &summary.events {
        let _ = events.send(MarmotAppEvent::GroupEvent(RuntimeGroupEvent {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            event: event.clone(),
        }));
    }
    for escalation in &summary.epoch_stall_escalations {
        let _ = events.send(MarmotAppEvent::EpochStallEscalated {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            group_id: escalation.group_id.clone(),
            stalled_epoch: escalation.stalled_epoch,
            arms: escalation.arms,
        });
    }
}

fn publish_app_runtime_projection_update(
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    update: AppProjectionUpdate,
) {
    let _ = events.send(MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate {
        account_id_hex: account_id_hex.to_owned(),
        account_label: account_label.to_owned(),
        update,
    }));
}

fn publish_client_pending_projection_updates(
    client: &mut AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
) {
    for update in client.take_pending_projection_updates() {
        publish_app_runtime_projection_update(events, account_id_hex, account_label, update);
    }
}

/// Broadcast durable effects retained outside their originating operation. This
/// covers retained inbound convergence commits folded by a send and completed
/// catch-up deliveries preserved across a later batch error. Called before the
/// corresponding error is reported and from every worker seam that can buffer
/// applied effects. A no-op when the summary is empty.
fn publish_client_pending_applied_summary(
    client: &mut AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
) {
    let summary = client.take_pending_applied_sync_summary();
    publish_app_runtime_summary(events, account_id_hex, account_label, &summary);
}

pub(crate) fn publish_app_runtime_group_state_updated(
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    group_id: &GroupId,
) {
    let _ = events.send(MarmotAppEvent::GroupStateUpdated {
        account_id_hex: account_id_hex.to_owned(),
        account_label: account_label.to_owned(),
        group_id: group_id.clone(),
    });
}

/// Broadcast a `WelcomeDeliveryPending` event for each welcome a just-completed
/// create/invite queued for re-delivery (mdk#352), so subscribers learn a member
/// is unjoinable without polling the durable queue.
fn publish_pending_welcome_delivery_events(
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    client: &mut AppClient,
) {
    for pending in client.take_pending_welcome_delivery_events() {
        let Ok(group_id_bytes) = hex::decode(&pending.group_id_hex) else {
            continue;
        };
        let _ = events.send(MarmotAppEvent::WelcomeDeliveryPending {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            group_id: GroupId::new(group_id_bytes),
            message_id_hex: pending.message_id_hex,
            recipient_hex: pending.recipient_hex,
        });
    }
}

/// Emit a runtime `AgentStreamStarted` for a kind-1200 start event. Kind-9
/// stream-final messages are normal timeline messages and do not fire here.
fn agent_stream_runtime_event(
    account_id_hex: &str,
    account_label: &str,
    message: &ReceivedMessage,
) -> Option<MarmotAppEvent> {
    if message.kind != MARMOT_APP_EVENT_KIND_AGENT_STREAM_START {
        return None;
    }
    Some(MarmotAppEvent::AgentStreamStarted(
        RuntimeAgentStreamMessage {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            message: message.clone(),
        },
    ))
}

/// Build a [`RuntimeAccountError`] message from a static prefix and the
/// error's privacy-safe kind. These messages leave the runtime: the CLI daemon
/// persists them into `wn daemon status --json` and the TUI, and host apps may
/// log them. Never interpolate the raw error — `AppError::Transport` Display
/// can embed relay URLs, which the privacy invariant forbids surfacing.
fn account_error_message(prefix: &str, err: &AppError) -> String {
    format!("{prefix}: {}", err.privacy_safe_kind())
}

async fn release_startup_client_if_opened(
    open_client: Pin<&mut impl std::future::Future<Output = Result<AppClient, AppError>>>,
) {
    // Let an in-flight local open finish so its AppClient (and session guard)
    // destructors run before a replacement worker can contend on the same label.
    if let Ok(client) = open_client.await {
        drop(client);
    }
}

fn publish_app_runtime_account_error(
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    message: String,
) {
    let _ = events.send(MarmotAppEvent::AccountError(RuntimeAccountError {
        account_id_hex: account_id_hex.to_owned(),
        account_label: account_label.to_owned(),
        message,
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use marmot_account::AccountHome;

    use crate::client::epoch_stall::BackfillDecision;
    use crate::tests::ScriptedPushRelayClient;

    fn test_group_id(byte: u8) -> GroupId {
        GroupId::new(vec![byte])
    }

    #[test]
    fn account_error_message_never_carries_transport_error_detail() {
        // Transport errors commonly embed relay URLs (nostr-sdk error strings,
        // per-endpoint failure reasons). RuntimeAccountError messages are
        // persisted into `wn daemon status --json` and host surfaces, so only
        // the stable privacy-safe kind may appear.
        let err = AppError::Transport(cgka_traits::TransportAdapterError::Publish(
            "connect relay: wss://private-relay.example".to_owned(),
        ));
        let message = account_error_message("runtime receive failed", &err);
        assert_eq!(message, "runtime receive failed: transport");
        assert!(!message.contains("private-relay.example"), "{message}");
    }

    #[tokio::test]
    async fn pending_epoch_backfill_failure_is_reported_retained_and_coalesced() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("alice").await.unwrap();
        client.apply_backfill_decision(&test_group_id(7), 3, BackfillDecision::Arm);

        let (events, mut subscriber) = broadcast::channel(4);
        let shared = RuntimeSharedServices::default();
        relay.fail_next_subscribe();
        let error = run_pending_epoch_backfill_reporting_arm(
            &mut client,
            &events,
            "account-id",
            "alice",
            &shared,
        )
        .await
        .expect_err("failed replay activation must be returned");

        assert_eq!(error, "epoch-gap backfill failed: account_transport");
        assert!(client.has_pending_epoch_backfill());
        assert!(matches!(
            subscriber.try_recv().unwrap(),
            MarmotAppEvent::AccountError(RuntimeAccountError { message, .. })
                if message == "epoch-gap backfill failed: account_transport"
        ));

        run_pending_epoch_backfill_reporting_arm(
            &mut client,
            &events,
            "account-id",
            "alice",
            &shared,
        )
        .await
        .unwrap();
        assert!(!client.has_pending_epoch_backfill());
        let subscriptions_after_replay = relay.subscription_count();

        run_pending_epoch_backfill_reporting_arm(
            &mut client,
            &events,
            "account-id",
            "alice",
            &shared,
        )
        .await
        .unwrap();
        assert_eq!(relay.subscription_count(), subscriptions_after_replay);
    }

    #[tokio::test]
    async fn explicit_catch_up_runs_prearmed_backfill_before_success_response() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("alice").await.unwrap();
        client.apply_backfill_decision(&test_group_id(8), 3, BackfillDecision::Arm);

        let (events, _subscriber) = broadcast::channel(4);
        let shared = RuntimeSharedServices::default();
        let (command_tx, mut commands) = mpsc::channel(1);
        let mut pending = VecDeque::new();
        let context = AccountWorkerCatchUpContext {
            app: &app,
            events: &events,
            shared: &shared,
            account_id_hex: "account-id",
            account_label: "alice",
        };
        let (respond, response) = oneshot::channel();

        handle_account_worker_catch_up(&mut client, respond, &mut commands, &mut pending, context)
            .await;

        response.await.unwrap().unwrap();
        assert!(
            !client.has_pending_epoch_backfill(),
            "catch-up must consume the replay intent before sending success",
        );
        assert!(
            relay.subscription_count() >= 2,
            "catch-up must perform its floored sync and the pending unfloored replay",
        );
        drop(command_tx);
    }

    #[tokio::test]
    async fn full_history_repair_consumes_prearmed_backfill_without_replaying_twice() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("alice").await.unwrap();
        client.apply_backfill_decision(&test_group_id(9), 3, BackfillDecision::Arm);

        let (events, _subscriber) = broadcast::channel(4);
        let shared = RuntimeSharedServices::default();
        let (respond, response) = oneshot::channel();
        handle_account_worker_command(
            &mut client,
            AccountWorkerCommand::RepairFullHistory { respond },
            &events,
            "account-id",
            "alice",
            &shared,
        )
        .await;

        response.await.unwrap().unwrap();
        assert!(
            !client.has_pending_epoch_backfill(),
            "every successful sync seam must consume an armed replay intent",
        );
        assert_eq!(
            relay.subscription_count(),
            2,
            "the explicit unfloored repair already fulfills the pending replay",
        );
    }

    #[test]
    fn a_summary_escalation_reaches_subscribers_as_one_typed_event() {
        // The escalation rides the sync summary that observed it, so every worker
        // seam that publishes a summary publishes it. Without this fan-out the
        // signal would stop inside the client — the silent failure the
        // escalation exists to end.
        let (events, mut subscriber) = broadcast::channel(4);
        let summary = SyncSummary {
            epoch_stall_escalations: vec![crate::EpochStallEscalation {
                group_id: test_group_id(3),
                stalled_epoch: 12,
                arms: 3,
            }],
            ..SyncSummary::default()
        };

        publish_app_runtime_summary(&events, "account-id", "label", &summary);

        assert_eq!(
            subscriber.try_recv().unwrap(),
            MarmotAppEvent::EpochStallEscalated {
                account_id_hex: "account-id".to_owned(),
                account_label: "label".to_owned(),
                group_id: test_group_id(3),
                stalled_epoch: 12,
                arms: 3,
            }
        );
        assert!(
            subscriber.try_recv().is_err(),
            "one escalation must publish exactly one event"
        );
    }

    #[test]
    fn retry_delay_for_attempt_backs_off_and_caps() {
        assert_eq!(retry_delay_for_attempt(0), Duration::from_secs(1));
        assert_eq!(retry_delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(retry_delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(retry_delay_for_attempt(3), Duration::from_secs(4));
        assert_eq!(
            retry_delay_for_attempt(u32::MAX),
            CONVERGENCE_RETRY_MAX_DELAY
        );
    }

    #[tokio::test]
    async fn push_registration_retry_is_bounded_and_disarms_when_drained() {
        assert_eq!(
            push_registration_retry_delay(1),
            push_registration_retry_base_delay()
        );
        assert_eq!(
            push_registration_retry_delay(u32::MAX),
            push_registration_retry_max_delay()
        );

        let (commands, mut received_commands) = mpsc::channel(2);
        let mut scheduled = ScheduledPushRegistrationRetry::new();
        scheduled.observe_pending(true, &commands);
        assert!(scheduled.is_armed());
        let first = received_commands.recv().await.unwrap();
        let AccountWorkerCommand::RetryPushRegistration { respond } = first else {
            panic!("timer must enqueue an internal push retry")
        };
        respond.send(true).unwrap();

        let second = received_commands.recv().await.unwrap();
        let AccountWorkerCommand::RetryPushRegistration { respond } = second else {
            panic!("pending work must enqueue a backed-off retry")
        };
        respond.send(false).unwrap();
        tokio::task::yield_now().await;

        scheduled.schedule_after_attempt(false, &commands);
        assert!(!scheduled.is_armed());
    }

    #[test]
    fn push_registration_retry_observation_is_scoped_to_relevant_commands() {
        let (share_respond, _share_response) = oneshot::channel();
        assert!(
            AccountWorkerCommand::SharePushRegistration {
                respond: share_respond
            }
            .may_change_push_registration_work()
        );

        let (convergence_respond, _convergence_response) = oneshot::channel();
        assert!(
            !AccountWorkerCommand::RetryGroupConvergence {
                group_id: test_group_id(1),
                respond: convergence_respond,
            }
            .may_change_push_registration_work(),
            "unrelated convergence commands must not arm push maintenance"
        );
    }

    #[tokio::test]
    async fn scheduled_convergence_clamps_zero_delay_and_clears_retry_state() {
        let group_id = test_group_id(7);
        let mut scheduled = ScheduledConvergence::new(Duration::ZERO);

        assert_eq!(scheduled.normal_delay(), MIN_CONVERGENCE_SETTLEMENT_DELAY);

        scheduled.schedule_retry_groups([group_id.clone()]);
        assert_eq!(scheduled.retry_attempts.get(&group_id), Some(&1));

        scheduled.schedule_groups([group_id.clone()]);
        assert!(!scheduled.retry_attempts.contains_key(&group_id));

        let ready = scheduled.take_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], group_id);
    }

    #[tokio::test]
    async fn schedule_unsettled_groups_rearms_settlement_delay() {
        let group_id = test_group_id(9);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));

        scheduled.schedule_unsettled_groups([group_id.clone()]);
        let ready = scheduled.take_ready();
        assert_eq!(ready, vec![group_id.clone()]);
        assert!(!scheduled.retry_attempts.contains_key(&group_id));
    }

    #[tokio::test]
    async fn schedule_after_pass_rearms_when_inputs_remain_pending() {
        let group_id = test_group_id(10);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));

        scheduled.schedule_after_pass(&group_id, ConvergenceScheduleState::PendingUnopenable);

        let ready = scheduled.take_ready();
        assert_eq!(ready, vec![group_id.clone()]);
        assert!(!scheduled.retry_attempts.contains_key(&group_id));
        assert_eq!(scheduled.unsettled_rearm_attempts.get(&group_id), Some(&1));
    }

    #[tokio::test]
    async fn schedule_after_pass_notes_success_when_inputs_are_settled() {
        let group_id = test_group_id(11);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));
        scheduled.schedule_unsettled_groups([group_id.clone()]);
        assert_eq!(scheduled.unsettled_rearm_attempts.get(&group_id), Some(&1));
        scheduled.take_ready();

        scheduled.schedule_after_pass(&group_id, ConvergenceScheduleState::Idle);

        assert!(!scheduled.retry_attempts.contains_key(&group_id));
        assert!(!scheduled.unsettled_rearm_attempts.contains_key(&group_id));
        assert!(scheduled.deadlines.is_empty());
    }

    #[tokio::test]
    async fn pending_outbound_rearms_without_counting_toward_backoff() {
        let group_id = test_group_id(15);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));

        for _ in 0..=CONVERGENCE_UNSETTLED_MAX_REARMS {
            scheduled.schedule_after_pass(&group_id, ConvergenceScheduleState::PendingOutbound);
            scheduled.take_ready();
        }

        // A healthy waiting queue re-arms on the normal delay indefinitely
        // without ever being demoted to error backoff.
        assert!(!scheduled.unsettled_rearm_attempts.contains_key(&group_id));
        assert!(!scheduled.retry_attempts.contains_key(&group_id));

        // Alternating unopenable/outbound states must not accrue the cap
        // either: an outbound tick means pending inputs cleared, ending any
        // unopenable streak.
        for _ in 0..=CONVERGENCE_UNSETTLED_MAX_REARMS {
            scheduled.schedule_after_pass(&group_id, ConvergenceScheduleState::PendingUnopenable);
            scheduled.take_ready();
            scheduled.schedule_after_pass(&group_id, ConvergenceScheduleState::PendingOutbound);
            scheduled.take_ready();
        }
        assert!(!scheduled.unsettled_rearm_attempts.contains_key(&group_id));
        assert!(!scheduled.retry_attempts.contains_key(&group_id));
    }

    #[tokio::test]
    async fn collecting_tick_does_not_increment_rearm_counter() {
        let group_id = test_group_id(13);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));
        // Simulate a prior demotion pressure, then an in-window wake: the
        // engine reports Collecting, which is on time — the counter resets
        // and the group is never pushed toward error backoff.
        scheduled.schedule_unsettled_groups([group_id.clone()]);
        assert_eq!(scheduled.unsettled_rearm_attempts.get(&group_id), Some(&1));

        scheduled.schedule_after_pass(
            &group_id,
            ConvergenceScheduleState::Collecting { remaining_ms: 400 },
        );

        assert!(!scheduled.unsettled_rearm_attempts.contains_key(&group_id));
        assert!(!scheduled.retry_attempts.contains_key(&group_id));
        assert!(scheduled.deadlines.contains_key(&group_id));
    }

    #[tokio::test]
    async fn post_cutoff_retained_input_arms_from_remaining_cutoff() {
        let group_id = test_group_id(14);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));
        let before = TokioInstant::now();

        scheduled.schedule_after_pass(
            &group_id,
            ConvergenceScheduleState::Collecting { remaining_ms: 200 },
        );

        let deadline = scheduled.deadlines[&group_id];
        let margin = Duration::from_millis(200 + CONVERGENCE_SETTLEMENT_SCHEDULE_MARGIN_MS);
        // Armed at the engine-reported remaining cutoff plus margin — not the
        // full settlement delay the old scheduler always used.
        assert!(deadline >= before + margin);
        assert!(deadline < before + margin + Duration::from_millis(500));

        scheduled.schedule_after_pass(&group_id, ConvergenceScheduleState::Ready);
        assert!(
            scheduled.deadlines[&group_id] <= before + margin,
            "Ready must never postpone an armed deadline"
        );
    }

    #[tokio::test]
    async fn scheduling_one_group_never_postpones_an_earlier_group_cutoff() {
        let first = test_group_id(21);
        let noisy = test_group_id(22);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));

        scheduled.schedule_groups_with_delays([
            (first.clone(), Duration::from_millis(50)),
            (noisy.clone(), Duration::from_millis(100)),
        ]);
        let first_deadline = scheduled.deadlines[&first];
        scheduled.schedule_groups_with_delays([(noisy.clone(), Duration::from_millis(500))]);

        assert_eq!(scheduled.deadlines[&first], first_deadline);
        assert_eq!(scheduled.take_ready(), vec![first]);
        assert!(scheduled.deadlines.contains_key(&noisy));
    }

    #[tokio::test]
    async fn rescheduling_same_group_never_postpones_its_frozen_cutoff() {
        let group_id = test_group_id(23);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));
        scheduled.schedule_groups_with_delays([(group_id.clone(), Duration::from_millis(50))]);
        let frozen_cutoff = scheduled.deadlines[&group_id];

        scheduled.schedule_unsettled_groups([group_id.clone()]);
        scheduled.schedule_retry_groups([group_id.clone()]);

        assert_eq!(scheduled.deadlines[&group_id], frozen_cutoff);
    }

    #[tokio::test]
    async fn take_ready_drains_every_overdue_group_in_one_tick() {
        let first = test_group_id(24);
        let second = test_group_id(25);
        let future = test_group_id(26);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));
        let now = TokioInstant::now();
        scheduled.deadlines.insert(first.clone(), now);
        scheduled
            .deadlines
            .insert(second.clone(), now - Duration::from_millis(1));
        scheduled
            .deadlines
            .insert(future.clone(), now + Duration::from_secs(10));

        let ready = scheduled.take_ready();

        assert_eq!(ready.len(), 2);
        assert!(ready.contains(&first));
        assert!(ready.contains(&second));
        assert_eq!(
            scheduled.deadlines.keys().collect::<Vec<_>>(),
            vec![&future]
        );
    }

    #[tokio::test]
    async fn schedule_unsettled_groups_falls_back_to_retry_backoff_after_cap() {
        let group_id = test_group_id(12);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));

        for _ in 0..=CONVERGENCE_UNSETTLED_MAX_REARMS {
            scheduled.schedule_unsettled_groups([group_id.clone()]);
            scheduled.take_ready();
        }

        assert_eq!(
            scheduled.unsettled_rearm_attempts.get(&group_id),
            Some(&(CONVERGENCE_UNSETTLED_MAX_REARMS + 1))
        );
        assert_eq!(scheduled.retry_attempts.get(&group_id), Some(&1));
    }
}
