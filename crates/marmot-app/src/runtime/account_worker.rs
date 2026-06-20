//! Per-account worker: command surface, the worker loop, reconnect backoff,
//! and the runtime-event publishing helpers the loop drives.

use std::time::{Duration, Instant};

use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_AGENT_STREAM_START;
use cgka_traits::{GroupId, SecretBytes};
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

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
    AgentTextStreamFinishRequest, AppBlobEndpoint, AppClient, AppError, AppGroupMemberRecord,
    AppGroupMlsState, AppGroupRecord, AppProjectionUpdate, AppQuarantinedGroup,
    GroupInviteDeclineResult, MarmotApp, MarmotRelayPlane, MediaAttachmentReference,
    MediaDownloadResult, MediaUploadRequest, MediaUploadResult, PushRegistration, ReceivedMessage,
    SendSummary, SyncSummary,
};
use cgka_traits::app_event::MarmotAppEvent as MarmotInnerEvent;

pub(crate) struct ManagedAccountWorker {
    pub(crate) handle: JoinHandle<()>,
    pub(crate) commands: mpsc::Sender<AccountWorkerCommand>,
    pub(crate) shutdown: oneshot::Sender<()>,
}

impl ManagedAccountWorker {
    pub(crate) fn stop(self) {
        let _ = self.shutdown.send(());
        self.handle.abort();
    }

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
                        error = %err,
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
                let _ = timeout(Duration::from_millis(250), &mut handle).await;
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
    CreateGroup {
        name: String,
        members: Vec<String>,
        description: Option<String>,
        respond: oneshot::Sender<Result<GroupId, AppError>>,
    },
    Members {
        group_id: GroupId,
        respond: oneshot::Sender<Result<Vec<AppGroupMemberRecord>, AppError>>,
    },
    GroupMlsState {
        group_id: GroupId,
        respond: oneshot::Sender<Result<AppGroupMlsState, AppError>>,
    },
    QuarantinedGroups {
        respond: oneshot::Sender<Result<Vec<AppQuarantinedGroup>, AppError>>,
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
    StartAgentTextStream {
        group_id: GroupId,
        stream_id: Vec<u8>,
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
    PublishKeyPackage {
        respond: oneshot::Sender<Result<usize, AppError>>,
    },
    RotateKeyPackage {
        respond: oneshot::Sender<Result<usize, AppError>>,
    },
    SharePushRegistration {
        respond: oneshot::Sender<Result<usize, AppError>>,
    },
    RemovePushRegistration {
        registration: PushRegistration,
        respond: oneshot::Sender<Result<usize, AppError>>,
    },
    DeleteAuditLog {
        path: std::path::PathBuf,
        respond: oneshot::Sender<Result<bool, AppError>>,
    },
    SetAuditRecording {
        enabled: bool,
        respond: oneshot::Sender<Result<(), AppError>>,
    },
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
    commands: mpsc::Receiver<AccountWorkerCommand>,
    ready: oneshot::Sender<Result<(), String>>,
    shutdown: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(run_app_runtime_account_worker(
        runtime, commands, ready, shutdown,
    ))
}

async fn run_app_runtime_account_worker(
    runtime: AccountWorkerRuntime,
    mut commands: mpsc::Receiver<AccountWorkerCommand>,
    ready: oneshot::Sender<Result<(), String>>,
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
    let mut client = match tokio::select! {
        _ = &mut shutdown => {
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err("runtime startup cancelled".into()));
            }
            return;
        }
        _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => {
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err("runtime startup cancelled".into()));
            }
            return;
        }
        result = app.runtime_client(&account_label, &relay_plane, lifecycle.clone()) => result,
    } {
        Ok(client) => client,
        Err(err) => {
            let message = format!("runtime startup failed: {err}");
            publish_app_runtime_account_error(
                &events,
                &account_id_hex,
                &account_label,
                message.clone(),
            );
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err(message));
            }
            return;
        }
    };

    // The session is hydrated. Capture a read snapshot and signal
    // command-readiness *now*, before the initial relay catch-up. "Ready" means
    // "hydrated + serving commands", not "caught up": the conversation's
    // group-detail reads (`Members` / `GroupMlsState` / `QuarantinedGroups`)
    // route through this worker, and blocking them on the catch-up made the
    // first conversation opened after a foreground resume take seconds. The
    // catch-up still runs (below) and its results flow to subscribers via the
    // normal event mechanism; it is only removed from the readiness/blocking
    // path. See `GroupReadSnapshot`. `AccountOpen` (recorded by `reconcile` as
    // the ready-wait) now measures time-to-command-ready (hydrate + connect +
    // subscribe), while `AccountSync` (below) measures the catch-up.
    //
    // Snapshot capture is best-effort: its only failure is the shared profile
    // load. On failure, surface the error and serve read commands by deferring
    // them to the live session after catch-up (matching the live path's error
    // semantics) instead of masking it as empty profiles. Readiness is never
    // gated on it.
    let read_snapshot = match client.group_read_snapshot() {
        Ok(snapshot) => Some(snapshot),
        Err(err) => {
            publish_app_runtime_account_error(
                &events,
                &account_id_hex,
                &account_label,
                format!("runtime startup snapshot capture failed: {err}"),
            );
            None
        }
    };
    if let Some(ready) = ready.take() {
        let _ = ready.send(Ok(()));
    }

    // Run the initial catch-up in the background. The `client.sync()` future
    // holds `&mut client` for its whole lifetime, so while it is in flight the
    // command loop must not touch the live session: read commands are answered
    // from `read_snapshot`, and every other command is deferred and replayed on
    // live state once the catch-up lands, in arrival order. `CatchUp` requests
    // that arrive during the initial sync are coalesced onto it (kept in the same
    // deferred sequence so they cannot jump ahead of an earlier mutation), so a
    // second concurrent sync on the same client is never started. Shutdown drops
    // the pinned future, cancelling the sync.
    let mut deferred: Vec<DeferredStartupCommand> = Vec::new();
    let sync_started_at = Instant::now();
    let startup_sync_result = {
        let mut initial_sync = std::pin::pin!(client.sync());
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
                                None => deferred.push(DeferredStartupCommand::Command(Box::new(AccountWorkerCommand::Members { group_id, respond }))),
                            }
                        }
                        Some(AccountWorkerCommand::GroupMlsState { group_id, respond }) => {
                            match &read_snapshot {
                                Some(snapshot) => {
                                    let _ = respond.send(snapshot.group_mls_state(&group_id));
                                }
                                None => deferred.push(DeferredStartupCommand::Command(Box::new(AccountWorkerCommand::GroupMlsState { group_id, respond }))),
                            }
                        }
                        Some(AccountWorkerCommand::QuarantinedGroups { respond }) => {
                            match &read_snapshot {
                                Some(snapshot) => {
                                    let _ = respond.send(Ok(snapshot.quarantined_groups()));
                                }
                                None => deferred.push(DeferredStartupCommand::Command(Box::new(AccountWorkerCommand::QuarantinedGroups { respond }))),
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
            if sync_summary_triggers_audit_tracker_update(&summary) {
                shared.schedule_audit_log_tracker_update("startup_sync");
            }
            Ok(())
        }
        Err(err) => {
            // A failed initial catch-up surfaces as an account error but must not
            // fail worker readiness — readiness was already signalled above.
            let message = format!("runtime startup receive failed: {err}");
            publish_app_runtime_account_error(
                &events,
                &account_id_hex,
                &account_label,
                message.clone(),
            );
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

    let mut reconnect_backoff = AccountWorkerReconnectBackoff::default();

    loop {
        tokio::select! {
            _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => {
                return;
            }
            _ = &mut shutdown => {
                return;
            }
            command = commands.recv() => {
                match command {
                    Some(command) => {
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
                    None => return,
                }
            }
            result = client.next_event() => {
                match result {
                    Ok(summary) => {
                        reconnect_backoff.reset();
                        publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
                        if sync_summary_triggers_audit_tracker_update(&summary) {
                            shared.schedule_audit_log_tracker_update("receive");
                        }
                    }
                    Err(err) => {
                        publish_app_runtime_account_error(
                            &events,
                            &account_id_hex,
                            &account_label,
                            format!("runtime receive failed: {err}"),
                        );
                        tokio::select! {
                            _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => return,
                            _ = &mut shutdown => return,
                            _ = sleep(reconnect_backoff.next_delay()) => {}
                        }
                        match tokio::select! {
                            _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => return,
                            _ = &mut shutdown => return,
                            result = app.runtime_client(&account_label, &relay_plane, lifecycle.clone()) => result,
                        } {
                            Ok(reopened) => {
                                // The reopen re-hydrates + reconnects + resubscribes
                                // (via `runtime_client`) but does NOT run the
                                // catch-up `sync()` on the readiness path — it
                                // resumes the live `next_event` tail below — so it
                                // does not reintroduce the catch-up blocking this
                                // worker removed from startup.
                                client = reopened;
                            }
                            Err(setup_err) => {
                                publish_app_runtime_account_error(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    format!("runtime restart failed: {setup_err}"),
                                );
                                tokio::select! {
                                    _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => return,
                                    _ = &mut shutdown => return,
                                    _ = sleep(reconnect_backoff.next_delay()) => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Process a single account-worker command against the live session.
///
/// Extracted so the worker can drive commands from two places: the steady-state
/// command loop, and the deferred-command replay that runs after the initial
/// catch-up completes (commands that arrived while the catch-up held
/// `&mut client`). Read commands (`Members` / `GroupMlsState` /
/// `QuarantinedGroups`) are also intercepted inline during the initial catch-up
/// and answered from a `GroupReadSnapshot`; here they read the live session.
async fn handle_account_worker_command(
    client: &mut AppClient,
    command: AccountWorkerCommand,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    shared: &RuntimeSharedServices,
) {
    match command {
        AccountWorkerCommand::CatchUp { respond } => {
            let sync_started_at = Instant::now();
            let result = match client.sync().await {
                Ok(summary) => {
                    publish_app_runtime_summary(events, account_id_hex, account_label, &summary);
                    if sync_summary_triggers_audit_tracker_update(&summary) {
                        shared.schedule_audit_log_tracker_update("catch_up");
                    }
                    Ok(())
                }
                Err(err) => {
                    let message = format!("runtime catch-up failed: {err}");
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
            name,
            members,
            description,
            respond,
        } => {
            let result = async {
                let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
                let group_id = client.create_group(&name, &member_refs).await?;
                if description.is_some() {
                    client
                        .update_group_profile(&group_id, None, description.as_deref())
                        .await?;
                }
                Ok(group_id)
            }
            .await;
            if let Ok(group_id) = &result {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    group_id,
                );
            }
            let _ = respond.send(result);
        }
        AccountWorkerCommand::Members { group_id, respond } => {
            let result = client.members(&group_id);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::GroupMlsState { group_id, respond } => {
            let result = client.group_mls_state(&group_id);
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
                // drain (darkmatter#426). Publish those events plus a
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
                        format!("retry recovery drain failed: {err}"),
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
                client.invite_members(&group_id, &member_refs).await
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
            let _ = respond.send(result);
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
            let result = client.download_group_image(&group_id).await;
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
        AccountWorkerCommand::StartAgentTextStream {
            group_id,
            stream_id,
            quic_candidates,
            respond,
        } => {
            let result = client
                .start_agent_text_stream_with_local_projection(
                    &group_id,
                    &stream_id,
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
        AccountWorkerCommand::SharePushRegistration { respond } => {
            let result = client.share_push_registration().await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::RemovePushRegistration {
            registration,
            respond,
        } => {
            let result = client.remove_push_registration(registration).await;
            let _ = respond.send(result);
        }
        AccountWorkerCommand::DeleteAuditLog { path, respond } => {
            let result = client.rotate_audit_log_if_active(&path);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::SetAuditRecording { enabled, respond } => {
            client.set_audit_recording(enabled);
            let _ = respond.send(Ok(()));
        }
    }
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

fn sync_summary_triggers_audit_tracker_update(summary: &SyncSummary) -> bool {
    !summary.joined_groups.is_empty() || !summary.messages.is_empty() || !summary.events.is_empty()
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
