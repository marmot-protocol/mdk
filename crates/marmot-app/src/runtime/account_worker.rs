//! Per-account worker: command surface, the worker loop, reconnect backoff,
//! and the runtime-event publishing helpers the loop drives.

mod attachments;
mod bounded_recovery;

use crate::RuntimePerformanceOperation as RuntimeOp;
use crate::app_telemetry::runtime::{Observation, Outcome as TelemetryOutcome};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_AGENT_STREAM_START;
use cgka_traits::engine::KeyPackage;
use cgka_traits::{GroupId, MessageId, SecretBytes};
use marmot_account::{AccountHomeError, AccountSetupKind, AccountSetupPhase, AccountSetupState};
use marmot_forensics::EpochBackfillExecutionSeam;
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant as TokioInstant, MissedTickBehavior, Sleep, interval, sleep, timeout};
use zeroize::Zeroizing;

use super::conversation_window::{
    CapturedConversation, ConversationWindowError, capture_conversation,
};
use super::{
    MarmotAppEvent, RuntimeAccountError, RuntimeAgentStreamMessage, RuntimeGroupEvent,
    RuntimeLifecycle, RuntimeMessageReceived, RuntimeProjectionUpdate, RuntimeSharedServices,
    wait_for_runtime_shutdown,
};
use crate::app_telemetry::{AppPerformanceOperation, SyncFailureClassification, SyncFailureStage};
use crate::client::{
    CompletedWelcomeDeliveryRecovery, EncryptedMediaUploadFinish, PreparedGroupImageUploadStart,
};
use crate::messages::AppMessageIntent;
use crate::{
    ACCOUNT_WORKER_RECONNECT_BASE_DELAY, ACCOUNT_WORKER_RECONNECT_JITTER_MAX_MS,
    ACCOUNT_WORKER_RECONNECT_MAX_DELAY, APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT, AccountCatchUpFailure,
    AgentTextStreamFinishRequest, AppBlobEndpoint, AppClient, AppCreateGroupOptions,
    AppDisbandRequest, AppError, AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord,
    AppPreparedGroupImageUpload, AppProjectionUpdate, AppQuarantinedGroup, CanonicalCreatedGroup,
    ChatListUpdateTrigger, ClassifiedSyncFailure, ConvergenceScheduleState,
    DeliveryOverflowRecoveryOutcome, EpochBackfillRunOutcome, GroupInviteDeclineResult,
    MaintenanceRunSummary, MarmotApp, MarmotRelayPlane, MediaAttachmentReference,
    MediaDownloadResult, MediaUploadRequest, MediaUploadResult, NotificationSettings,
    PendingWelcomeDelivery, PushPlatform, PushRegistration, PushRegistrationShareOutcome,
    PushRegistrationSyncResult, ReceivedMessage, RetentionSweepReport, SecureDeleteExpiredResult,
    SendSummary, SyncSummary,
};
use cgka_traits::app_event::MarmotAppEvent as MarmotInnerEvent;

pub(crate) struct ManagedAccountWorker {
    pub(super) ready: bool,
    pub(crate) handle: JoinHandle<()>,
    pub(crate) commands: mpsc::Sender<AccountWorkerCommand>,
    pub(crate) media_admission: Arc<Semaphore>,
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
        respond: oneshot::Sender<Result<(), AccountCatchUpFailure>>,
    },
    /// The host observed usable connectivity after an outage. Interrupt
    /// transport-failure backoff for already-durable convergence work; this
    /// signal never creates or replays application work on its own.
    ConnectivityRestored {
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    /// Startup-coalesced catch-up response held in the same FIFO as deferred
    /// mutations so later live reads cannot bypass those mutations.
    StartupCatchUpResult {
        result: Result<(), AccountCatchUpFailure>,
        respond: oneshot::Sender<Result<(), AccountCatchUpFailure>>,
    },
    RepairFullHistory {
        respond: oneshot::Sender<Result<(), AccountCatchUpFailure>>,
    },
    CreateGroup {
        queued_at: Instant,
        name: String,
        members: Vec<String>,
        options: AppCreateGroupOptions,
        prepared_image_upload_id: Option<String>,
        respond: oneshot::Sender<Result<CanonicalCreatedGroup, AppError>>,
    },
    StagePreparedGroupImage {
        plaintext: Vec<u8>,
        media_type: String,
        respond: oneshot::Sender<Result<AppPreparedGroupImageUpload, AppError>>,
    },
    UploadPreparedGroupImage {
        admission: OwnedSemaphorePermit,
        upload_id: String,
        server: Option<String>,
        respond: oneshot::Sender<Result<AppPreparedGroupImageUpload, AppError>>,
    },
    PreparedGroupImageStatus {
        upload_id: String,
        respond: oneshot::Sender<Result<AppPreparedGroupImageUpload, AppError>>,
    },
    PreparedGroupImages {
        respond: oneshot::Sender<Result<Vec<AppPreparedGroupImageUpload>, AppError>>,
    },
    Members {
        group_id: GroupId,
        respond: oneshot::Sender<Result<Vec<AppGroupMemberRecord>, AppError>>,
    },
    MemberIdsPage {
        group_ids: Vec<GroupId>,
        respond: oneshot::Sender<Result<Vec<crate::AppGroupMemberIds>, AppError>>,
    },
    CaptureConversation {
        queued: Option<Observation>,
        group_id: GroupId,
        query: storage_sqlite::ConversationWindowQuery,
        store_epoch: Vec<u8>,
        observer: Option<std::sync::Weak<super::SendCapture>>,
        respond: oneshot::Sender<Result<CapturedConversation, ConversationWindowError>>,
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
    /// Wait until in-flight create/invite Welcome fanout (and any mutations
    /// queued ahead of this command) have finished, then reply. One-shot CLI
    /// uses this before shutting the relay plane.
    Drain {
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
        initial_admins: Vec<String>,
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
    ForgetGroupLocal {
        group_id: GroupId,
        respond: oneshot::Sender<Result<bool, AppError>>,
    },

    DeleteGroupLocal {
        group_id: GroupId,
        respond: oneshot::Sender<Result<bool, AppError>>,
    },
    GroupRecoveryStatus {
        group_id: GroupId,
        respond: oneshot::Sender<Result<crate::GroupRecoveryStatus, AppError>>,
    },
    ConfirmGroupRejoin {
        welcome_id: cgka_traits::MessageId,
        token: Vec<u8>,
        respond: oneshot::Sender<Result<crate::GroupRecoveryStatus, AppError>>,
    },
    DeclineGroupRejoin {
        welcome_id: cgka_traits::MessageId,
        respond: oneshot::Sender<Result<(), AppError>>,
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
        admission: OwnedSemaphorePermit,
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
    SendMessageDraft {
        enqueued_at: Instant,
        queued: Option<Observation>,
        group_id: GroupId,
        revision: crate::MessageDraftRevision,
        attachments: Vec<MediaAttachmentReference>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    SendMessage {
        queued: Option<Observation>,
        enqueued_at: Instant,
        group_id: GroupId,
        payload: Vec<u8>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    SendAppEvent {
        enqueued_at: Instant,
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
        admission: OwnedSemaphorePermit,
        group_id: GroupId,
        request: MediaUploadRequest,
        respond: oneshot::Sender<Result<MediaUploadResult, AppError>>,
    },
    DownloadMedia {
        admission: OwnedSemaphorePermit,
        group_id: GroupId,
        reference: MediaAttachmentReference,
        enqueued_at: Instant,
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
    /// Complete the exact KeyPackage publication authorized by the durable
    /// account-setup journal. This is deliberately distinct from the general
    /// publication command so no other mutation can enter the startup lane.
    PublishSetupKeyPackage {
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
    RetryRuntimeGroupSubscriptions {
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
    #[cfg(test)]
    HoldMediaHttp {
        admission: OwnedSemaphorePermit,
        started: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
        respond: oneshot::Sender<Result<Vec<u8>, AppError>>,
    },
    /// Count seeded groups the session has not fully hydrated yet, without
    /// promoting them on demand (mdk#1337 regression probe).
    /// Controlled-clock fixture; changes no durable row and grants no I/O.
    #[cfg(any(test, feature = "test-policy-overrides"))]
    AdvanceRecoveryClock {
        elapsed: Duration,
        respond: oneshot::Sender<()>,
    },
    #[cfg(any(test, feature = "test-policy-overrides"))]
    RecoveryRetrySnapshot {
        respond: oneshot::Sender<(storage_sqlite::RecoveryRetryState, Duration, bool)>,
    },
    #[cfg(test)]
    UnhydratedGroupCount {
        respond: oneshot::Sender<usize>,
    },
}

impl AccountWorkerCommand {
    fn needs_media_slot(&self) -> bool {
        match self {
            Self::UploadPreparedGroupImage { .. }
            | Self::DownloadGroupImage { .. }
            | Self::UploadMedia { .. }
            | Self::DownloadMedia { .. } => true,
            #[cfg(test)]
            Self::HoldMediaHttp { .. } => true,
            _ => false,
        }
    }

    fn may_change_push_registration_work(&self) -> bool {
        matches!(
            self,
            Self::SharePushRegistration { .. }
                | Self::UpsertPushRegistration { .. }
                | Self::ClearPushRegistration { .. }
                | Self::SetNativePushEnabled { .. }
                | Self::RemovePushRegistration { .. }
                | Self::ForgetGroupLocal { .. }
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
    CatchUp(oneshot::Sender<Result<(), AccountCatchUpFailure>>),
}

/// Relay-only startup Welcome work. Dropping the worker aborts the task so no
/// detached publication can outlive relay-plane/account shutdown; the exact
/// durable artifact remains retryable on the next open.
struct WelcomeRecoveryTask {
    handle: JoinHandle<CompletedWelcomeDeliveryRecovery>,
    message_ids: Vec<MessageId>,
    drain_waiters: Vec<oneshot::Sender<()>>,
}

impl Drop for WelcomeRecoveryTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn install_storage_telemetry(client: &AppClient, telemetry: &crate::AppPerformanceTelemetry) {
    if let Ok(storage) = client.app.account_storage(&client.state.label) {
        let telemetry = telemetry.clone();
        storage.set_timing_observer(Some(Arc::new(move |operation, duration, success| {
            let operation = match operation {
                storage_sqlite::SqliteTimingOperation::ConnectionWait => {
                    RuntimeOp::StorageConnectionWait
                }
                storage_sqlite::SqliteTimingOperation::Transaction => RuntimeOp::StorageTransaction,
                storage_sqlite::SqliteTimingOperation::WriteBegin => RuntimeOp::StorageWriteBegin,
            };
            telemetry.record_runtime(
                operation,
                duration,
                if success {
                    TelemetryOutcome::Success
                } else {
                    TelemetryOutcome::Failure
                },
            );
        })));
    }
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
    let worker_started_at = Instant::now();
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
    let startup = shared
        .app_performance_telemetry()
        .observe(RuntimeOp::AccountStartup);
    let opened = tokio::select! {
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
    };
    startup.finish_app(&opened);
    let mut client = match opened {
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
    install_storage_telemetry(&client, &shared.app_performance_telemetry());
    client.runtime_telemetry = Some(shared.app_performance_telemetry());
    let mut scheduled_convergence = ScheduledConvergence::with_test_delay(
        convergence_settlement_delay(&app),
        scheduled_convergence_test_delay(&app),
    );
    let mut scheduled_push_retry = ScheduledPushRegistrationRetry::new();
    let mut scheduled_runtime_group_subscription_refresh =
        ScheduledRuntimeGroupSubscriptionRefresh::new();

    // The session's cheap open pass has seeded every stored group. Signal
    // command-readiness *now*: the hydration pipeline right below enters its
    // command-serving loop immediately, so "ready" genuinely means "serving
    // commands" — group reads (`Members` / `MemberIdsPage` / `GroupMlsState` /
    // `GroupRoster` / `QuarantinedGroups`) issued from this point hydrate the
    // group(s) they name and answer live; projection-only invite acceptance
    // also runs immediately. Everything else joins the startup deferral.
    // `AccountOpen` (recorded by `reconcile` as the ready-wait)
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
    // Snapshot setup intent before publishing readiness. Generated-account
    // local readiness deliberately returns while bootstrap publication is
    // still background work, and that task may advance the journal as soon as
    // the ready signal is observed. Capturing here preserves the narrow
    // priority lane for the exact locally prepared KeyPackage.
    let setup_key_package_priority =
        setup_key_package_priority(app.account_home().account_setup_state(&account_label));
    if let Err(error) = &setup_key_package_priority {
        publish_app_runtime_account_error(
            &events,
            &account_id_hex,
            &account_label,
            account_error_message("account setup state lookup failed", error),
        );
    }
    if let Some(ready) = ready.take() {
        shared.app_performance_telemetry().record(
            AppPerformanceOperation::AccountWorkerReadiness,
            worker_started_at.elapsed(),
            true,
        );
        let _ = ready.send(Ok(()));
    }

    // The durable setup journal records publication intent before the worker
    // is reconciled. That marker authorizes exactly one narrow startup action:
    // publish (or retry) the lifecycle-owned exact KeyPackage before unrelated
    // hydration and initial catch-up. General mutations, including the public
    // PublishKeyPackage command, remain on the ordinary startup FIFO.
    let mut setup_key_package_result = match setup_key_package_priority {
        Ok(SetupKeyPackagePriority::PublishExactDurableInitial) => {
            let started_at = Instant::now();
            let result = async {
                let key_package = client.publish_setup_key_package().await?;
                Ok(key_package.bytes().len())
            }
            .await;
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::AccountInitialKeyPackagePublish,
                started_at.elapsed(),
                result.is_ok(),
            );
            // The durable setup lane serializes these phases by design. Record
            // an explicit zero rather than omitting the sample so hosts can
            // distinguish "publication finished before sync" from "overlap
            // was not observed".
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::AccountInitialSyncOverlap,
                Duration::ZERO,
                result.is_ok(),
            );
            Some(result)
        }
        Ok(SetupKeyPackagePriority::Skip) => None,
        Err(error) => Some(Err(error)),
    };

    // Background hydration pipeline (mdk#1161): the deferred open above only
    // seeded stored groups, so fully hydrate them now — chat-list recency
    // first — while serving commands. Group reads for a not-yet-hydrated
    // group hydrate that one group and answer live ("waits for that group
    // only"); projection-only invite acceptance also runs live. Other
    // mutations and catch-ups join the same startup deferral the catch-up
    // window has always used and replay in arrival order after it.
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
        &mut setup_key_package_result,
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
    // read commands are answered from `read_snapshot`, invite acceptance gets
    // a typed definitely-not-started busy response, and every other command is
    // deferred and replayed on live state once catch-up lands, in arrival
    // order. `CatchUp` requests that arrive during the initial sync are
    // coalesced onto it.
    let sync_started_at = Instant::now();
    let startup_stage_telemetry = shared.app_performance_telemetry();
    let startup_sync_result = {
        let mut initial_sync = std::pin::pin!(async {
            #[cfg(any(test, feature = "test-policy-overrides"))]
            if let Some(barrier) = shared.take_next_startup_sync_barrier() {
                // First acknowledge entry, then hold sync until the test has
                // exercised the command loop below.
                barrier.wait().await;
                barrier.wait().await;
            }
            let summary = client
                .sync_with_stage_telemetry(&startup_stage_telemetry, false)
                .await?;
            app.finish_client_open_network_maintenance(&mut client)
                .await;
            Ok::<_, ClassifiedSyncFailure>(summary)
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
                        Some(AccountWorkerCommand::CaptureConversation { respond, queued, .. }) => {
                            // Frozen startup facts cannot be composed with newer account rows.
                            if let Some(queued) = queued { queued.finish(TelemetryOutcome::NotReady); }
                            let _ = respond.send(Err(ConversationWindowError::NotReady));
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
                        Some(AccountWorkerCommand::ConfirmGroupRejoin { respond, .. }) => {
                            let _ = respond.send(Err(AppError::AccountWorkerBusy));
                        }
                        Some(AccountWorkerCommand::DeclineGroupRejoin { respond, .. }) => {
                            let _ = respond.send(Err(AppError::AccountWorkerBusy));
                        }
                        Some(AccountWorkerCommand::AcceptGroupInvite { respond, .. }) => {
                            // `initial_sync` owns `&mut client`, so the command
                            // cannot start here. Report that fact explicitly
                            // instead of retaining the oneshot behind an
                            // unbounded catch-up.
                            let _ = respond.send(Err(AppError::AccountWorkerBusy));
                        }
                        Some(AccountWorkerCommand::CatchUp { respond }) => {
                            // Coalesce onto the in-flight initial catch-up rather
                            // than starting a second sync; fulfilled in arrival
                            // order below when it completes.
                            deferred.push(DeferredStartupCommand::CatchUp(respond));
                        }
                        Some(AccountWorkerCommand::PublishSetupKeyPackage { respond }) => {
                            match setup_key_package_result.take() {
                                Some(result) => {
                                    let _ = respond.send(result);
                                }
                                None => deferred.push(DeferredStartupCommand::Command(Box::new(
                                    AccountWorkerCommand::PublishSetupKeyPackage { respond },
                                ))),
                            }
                        }
                        Some(other) => {
                            deferred.push(DeferredStartupCommand::Command(Box::new(other)))
                        }
                    }
                }
            }
        }
    };
    shared.app_performance_telemetry().record_classified_result(
        AppPerformanceOperation::AccountSync,
        sync_started_at.elapsed(),
        startup_sync_result
            .as_ref()
            .err()
            .map(ClassifiedSyncFailure::classification),
    );
    let catch_up_result = match startup_sync_result {
        Ok(summary) => {
            publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
            start_post_join_history_after_visibility(
                &mut client,
                &summary,
                &events,
                &account_id_hex,
                &account_label,
            )
            .await;
            schedule_pending_convergence_groups(&mut scheduled_convergence, &mut client);
            if sync_summary_triggers_audit_tracker_update(&summary) {
                shared.schedule_audit_log_tracker_update("startup_sync");
            }
            Ok(())
        }
        Err(failure) => {
            publish_sync_summary_with_audit(
                &events,
                &account_id_hex,
                &account_label,
                &failure.partial_summary,
                &shared,
                "startup_sync",
            );
            start_post_join_history_after_visibility(
                &mut client,
                &failure.partial_summary,
                &events,
                &account_id_hex,
                &account_label,
            )
            .await;
            // A failed initial catch-up surfaces as an account error but must not
            // fail worker readiness — readiness was already signalled above.
            let message = account_error_message("runtime startup receive failed", &failure.source);
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
                    start_post_join_history_after_visibility(
                        &mut client,
                        &summary,
                        &events,
                        &account_id_hex,
                        &account_label,
                    )
                    .await;
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
            Err(AccountCatchUpFailure::new(
                message,
                failure.classification(),
            ))
        }
    };
    // Replay commands deferred during the initial catch-up in arrival order, now
    // on live state. Coalesced `CatchUp` waiters are fulfilled at their position
    // with the initial catch-up's result. Replay uses the live command queue so
    // post-canonical snapshot reads (Members / GroupRoster / …) can land while
    // a deferred create/invite still owns Welcome fanout.
    let (media_http_tx, mut media_http_rx) = mpsc::unbounded_channel();
    let (media_http_worker_lifetime, _) = watch::channel(());
    let media_http = MediaHttpContext {
        product: shared.product_analytics.clone(),
        tx: media_http_tx,
        permits: Arc::new(Semaphore::new(MEDIA_HTTP_IN_FLIGHT_LIMIT)),
        prepared_group_image_uploads: Arc::new(Mutex::new(HashSet::new())),
        worker_lifetime: media_http_worker_lifetime,
    };
    let mut pending = deferred
        .into_iter()
        .map(|deferred_command| match deferred_command {
            DeferredStartupCommand::CatchUp(respond) => {
                AccountWorkerCommand::StartupCatchUpResult {
                    result: catch_up_result.clone(),
                    respond,
                }
            }
            DeferredStartupCommand::Command(command) => *command,
        })
        .collect::<VecDeque<_>>();
    // Skip only media waiting for capacity; retain FIFO order among the rest.
    while let Some(index) = ready_command_index(&pending, &media_http) {
        let command = pending
            .remove(index)
            .expect("selected pending command exists");
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
                    AccountWorkerCommandContext {
                        commands: &mut commands,
                        pending: &mut pending,
                        app: &app,
                        events: &events,
                        account_id_hex: &account_id_hex,
                        account_label: &account_label,
                        shared: &shared,
                        media_http: &media_http,
                        scheduled_convergence: &mut scheduled_convergence,
                    },
                )
                .await;
            }
        }
        schedule_pending_convergence_groups(&mut scheduled_convergence, &mut client);
    }
    scheduled_runtime_group_subscription_refresh.observe_pending(
        client.has_pending_runtime_group_subscription_refresh(),
        &command_tx,
    );
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
    let product_backlog = shared.product_analytics.backlog_source();
    let mut maintenance_tick = interval(Duration::from_secs(15));
    maintenance_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut legacy_message_promotion = LegacyMessagePromotionSchedule::new();
    let mut presentation_maintenance = super::presentation::PresentationMaintenance::default();
    let mut presentation_wakeups = app.presentation_signals.subscribe_work();
    let mut local_submission_wakeups = shared.local_submission_wakeups.subscribe();
    let mut local_submission_due = true;
    let mut local_submission_retry_at = TokioInstant::now();
    let mut presentation_due = true;
    let mut avatar_due = true;
    let mut attachment_due = true;
    let mut attachment_admission = attachments::Admission::default();
    let mut avatar_resumed = false;
    let mut avatar_identities = super::avatar::IdentityAvatarMaintenance::default();

    // Prepare exact Welcome attempts under the serialized owner, then let only
    // relay I/O run independently. The worker stays available for inbound
    // delivery, maintenance, media completions, timers, and commands while a
    // degraded relay is slow. Drain waiters join reconciliation below.
    let mut welcome_recovery = client
        .prepare_pending_welcome_delivery_recovery_best_effort()
        .map(|recovery| {
            let message_ids = recovery.message_ids().to_vec();
            WelcomeRecoveryTask {
                handle: tokio::spawn(recovery.run()),
                message_ids,
                drain_waiters: Vec::new(),
            }
        });

    let mut yield_to_convergence = false;
    let mut bounded_recovery: Option<bounded_recovery::Job> = None;
    let mut yield_to_bounded_admission = false;
    let mut bounded_probe_at = TokioInstant::now();
    let mut bounded_prepare_error_reported = false;
    'worker: loop {
        // Activation is deliberately test-only until #1358 supplies and
        // qualifies the real backend. This is the actual worker dispatch seam:
        // the grant is captured here, while only the owned request crosses the
        // network await. The active owner lease prevents legacy overlap.
        let bounded_enabled = shared
            .bounded_group_recovery_enabled
            .load(std::sync::atomic::Ordering::Relaxed);
        if bounded_enabled && bounded_recovery.is_none() && TokioInstant::now() >= bounded_probe_at
        {
            let now = TokioInstant::now();
            bounded_probe_at = now + bounded_recovery::PROBE_INTERVAL;
            let probe = (|| -> Result<Option<bounded_recovery::Plan>, AppError> {
                let storage = client.app.account_storage(&client.state.label)?;
                let remaining = client
                    .recovery_owner
                    .retry_remaining(&storage, Instant::now())?;
                if !remaining.is_zero() {
                    bounded_probe_at = now + remaining.min(bounded_recovery::PROBE_INTERVAL);
                    return Ok(None);
                }
                #[cfg(test)]
                shared
                    .bounded_preparation_probes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                bounded_recovery::prepare(&mut client, EpochBackfillExecutionSeam::Maintenance)
            })();
            match probe {
                Ok(Some(plan)) => {
                    bounded_prepare_error_reported = false;
                    bounded_recovery = Some(bounded_recovery::Job::start(&client, plan))
                }
                Ok(None) => bounded_prepare_error_reported = false,
                Err(error) => {
                    if !bounded_prepare_error_reported {
                        publish_app_runtime_account_error(
                            &events,
                            &account_id_hex,
                            &account_label,
                            account_error_message("bounded recovery preparation failed", &error),
                        );
                        bounded_prepare_error_reported = true;
                    }
                }
            }
        }
        let ready_command = ready_command_index(&pending, &media_http);
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => {
                return;
            }
            _ = &mut shutdown => {
                return;
            }
            _ = tokio::time::sleep_until(bounded_probe_at), if bounded_enabled && bounded_recovery.is_none() => {}
            completed = async {
                bounded_recovery.as_mut().expect("bounded task exists").wait().await
            }, if bounded_recovery.as_ref().is_some_and(bounded_recovery::Job::waiting) => {
                bounded_recovery.as_mut().expect("bounded task exists").accept(completed);
                #[cfg(test)]
                shared.bounded_result_ready.notify_one();
                yield_to_bounded_admission = true;
            }
            recovered = async {
                let recovery = welcome_recovery
                    .as_mut()
                    .expect("Welcome recovery branch requires a live task");
                (&mut recovery.handle).await
            }, if welcome_recovery.is_some() => {
                let mut recovery = welcome_recovery
                    .take()
                    .expect("completed Welcome recovery task must still be owned");
                match recovered {
                    Ok(completed) => {
                        client
                            .finish_pending_welcome_delivery_recovery_best_effort(completed)
                            .await;
                    }
                    Err(error) => {
                        client.abandon_pending_welcome_delivery_recovery(
                            &recovery.message_ids,
                        );
                        tracing::warn!(
                            target: "marmot_app::runtime",
                            method = "startup_welcome_recovery",
                            error_kind = if error.is_panic() { "panic" } else { "cancelled" },
                            "startup Welcome relay task ended before reconciliation"
                        );
                    }
                }
                for respond in recovery.drain_waiters.drain(..) {
                    let _ = respond.send(());
                }
            }
            // Consume completed blobs before admitting more commands.
            done = media_http_rx.recv() => {
                match done {
                    Some(done) => {
                        complete_media_http(&mut client, done, &shared, &media_http).await;
                        avatar_due = true;
                        attachment_due = true;
                        schedule_pending_convergence_groups(
                            &mut scheduled_convergence,
                            &mut client,
                        );
                    }
                    None => return,
                }
            }
            // Alternate a command and a ready recovery quantum. A permanently
            // nonempty command channel must not starve group convergence.
            command = async {
                match ready_command.and_then(|index| pending.remove(index)) {
                    Some(command) => Some(command),
                    None => commands.recv().await,
                }
            }, if (!yield_to_convergence || !scheduled_convergence.has_ready() || scheduled_convergence_held_for_test(&account_id_hex))
                && (!yield_to_bounded_admission || !bounded_recovery.as_ref().is_some_and(bounded_recovery::Job::ready)) => {
                yield_to_convergence = true;
                yield_to_bounded_admission = true;
                match command {
                    Some(command) => {
                        let command = match command {
                            AccountWorkerCommand::Drain { respond } => {
                                if let Some(recovery) = &mut welcome_recovery {
                                    recovery.drain_waiters.push(respond);
                                } else {
                                    let _ = respond.send(());
                                }
                                continue;
                            }
                            command => command,
                        };
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
                                    AccountWorkerCommandContext {
                                        commands: &mut commands,
                                        pending: &mut pending,
                                        app: &app,
                                        events: &events,
                                        account_id_hex: &account_id_hex,
                                        account_label: &account_label,
                                        shared: &shared,
                                        media_http: &media_http,
                                        scheduled_convergence: &mut scheduled_convergence,
                                    },
                                )
                                .await;
                            }
                        }
                        schedule_pending_convergence_groups(
                            &mut scheduled_convergence,
                            &mut client,
                        );
                        scheduled_runtime_group_subscription_refresh.observe_pending(
                            client.has_pending_runtime_group_subscription_refresh(),
                            &command_tx,
                        );
                        if may_change_push_registration_work {
                            scheduled_push_retry.observe_pending(
                                client.has_pending_push_registration_work(),
                                &command_tx,
                            );
                        }
                    }
                    None => return,
                }
            }
            _ = scheduled_convergence.timer.as_mut(), if (!yield_to_bounded_admission
                || !bounded_recovery.as_ref().is_some_and(bounded_recovery::Job::ready))
                && !scheduled_convergence_held_for_test(&account_id_hex) => {
                yield_to_convergence = false;
                yield_to_bounded_admission = true;
                let Some(group_id) = scheduled_convergence.take_ready() else { continue };
                let phase = shared.app_performance_telemetry().observe(RuntimeOp::WorkerConvergence);
                // Recovery owns the live client, but member/roster reads can
                // use the last committed snapshot while its relay I/O waits.
                // Mutations retain worker FIFO order; reads use the snapshot.
                let read_snapshot = capture_group_read_snapshot(
                    &client,
                    &events,
                    &account_id_hex,
                    &account_label,
                    "runtime scheduled convergence snapshot failed",
                );
                Box::pin(serve_snapshot_reads_until(
                    read_snapshot,
                    async {
                        #[cfg(any(test, feature = "test-policy-overrides"))]
                        if let Some(barrier) = shared.take_next_scheduled_convergence_barrier() {
                            barrier.wait().await;
                            barrier.wait().await;
                        }
                        match client.retry_pending_runtime_group_subscription_refresh().await {
                            Ok(_) => {
                                // Shutdown is safe here: no engine snapshot guard is live.
                                if lifecycle.is_stopping() { return; }
                                match client.advance_convergence_after_runtime_sync(&group_id).await {
                                    Ok(summary) => {
                                        publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
                                        // A pass that superseded one of this
                                        // device's own commits reports it
                                        // through the client's pending
                                        // buffer; this arm is the only seam
                                        // that can observe such a pass
                                        // without a later command to drain
                                        // it (mdk#1734).
                                        publish_client_pending_projection_updates(
                                            &mut client,
                                            &events,
                                            &account_id_hex,
                                            &account_label,
                                        );
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
                                            EpochBackfillExecutionSeam::Maintenance,
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
                            Err(err) => {
                                scheduled_convergence.schedule_retry_groups([group_id]);
                                publish_app_runtime_account_error(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    account_error_message("scheduled convergence sync failed", &err),
                                );
                            }
                        }
                    },
                    &mut commands,
                    &mut pending,
                    &app,
                    &account_label,
                ))
                .await;

                phase.finish(TelemetryOutcome::Success);
            }
            _ = async {}, if yield_to_bounded_admission
                && bounded_recovery.as_ref().is_some_and(bounded_recovery::Job::ready)
                && !bounded_admission_test_paused(&shared, bounded_recovery.as_ref()) => {
                let job = bounded_recovery.as_mut().expect("bounded admission job exists");
                for _ in 0..bounded_recovery::MAX_ADMISSION_PER_TURN {
                    #[cfg(test)]
                    let had_input = job.has_input();
                    match job.admit_one(&mut client).await {
                        Ok(summary) => {
                            publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
                            publish_client_pending_projection_updates(&mut client, &events, &account_id_hex, &account_label);
                            schedule_pending_convergence_groups(&mut scheduled_convergence, &mut client);
                            #[cfg(test)]
                            if had_input {
                                shared.bounded_prefix_admitted.notify_one();
                            }
                        }
                        Err(error) => {
                            publish_app_runtime_account_error(&events, &account_id_hex, &account_label,
                                account_error_message("bounded recovery admission failed", &error));
                            // The durable demand and successfully admitted prefix survive.
                            bounded_recovery = None;
                            #[cfg(test)]
                            shared.bounded_recovery_finished.notify_one();
                            break;
                        }
                    }
                }
                if bounded_recovery.as_ref().is_some_and(|job| job.ready() && !job.has_input())
                    && let Some(job) = bounded_recovery.take() {
                        if let Err(error) = job.finish(&mut client) {
                            publish_app_runtime_account_error(&events, &account_id_hex, &account_label,
                                account_error_message("bounded recovery checkpoint failed", &error));
                        }
                        #[cfg(test)]
                        shared.bounded_recovery_finished.notify_one();
                }
                yield_to_bounded_admission = false;
            }
            _ = async {
                #[cfg(test)]
                if shared.bounded_pause_before_admission.load(std::sync::atomic::Ordering::SeqCst)
                    || shared.bounded_pause_after_first_admission.load(std::sync::atomic::Ordering::SeqCst) {
                    std::future::pending::<()>().await;
                }
                sleep(bounded_recovery::ADMISSION_YIELD_DELAY).await;
            }, if !yield_to_bounded_admission
                && bounded_recovery.as_ref().is_some_and(bounded_recovery::Job::ready) => {
                yield_to_bounded_admission = true;
            }
            received = client.receive_next_delivery() => {
                yield_to_bounded_admission = true;
                // Only the transport wait participates in `select!`. Once a
                // delivery has been claimed, finish ingest + incidental
                // publish + projection as one uncancelled worker operation;
                // commands remain queued until that durable sequence lands.
                let delivery_started = matches!(&received, Ok(crate::relay_plane::AccountDeliveryReceive::Delivery(_)))
                    .then(Instant::now);
                let receive_observation = shared.app_performance_telemetry().observe(RuntimeOp::WorkerReceive);
                let (result, overflow_recovery_incomplete) = match received {
                    Ok(crate::relay_plane::AccountDeliveryReceive::Delivery(delivery)) => {
                        (client.ingest_received_delivery(*delivery).await, false)
                    }
                    Ok(crate::relay_plane::AccountDeliveryReceive::Overflow(_)) => {
                        match client.recover_delivery_overflow().await {
                            Ok(DeliveryOverflowRecoveryOutcome::Completed(summary)) => {
                                (Ok(summary), false)
                            }
                            Ok(DeliveryOverflowRecoveryOutcome::Incomplete(summary)) => {
                                publish_app_runtime_account_error(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    "account delivery overflow recovery incomplete".to_owned(),
                                );
                                // The durable marker remains armed. Keep the
                                // account session available and let the next
                                // receive/catch-up seam retry the replay.
                                (Ok(summary), true)
                            }
                            Err(failure) => {
                                publish_app_runtime_summary(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    &failure.partial_summary,
                                );
                                (Err(failure.source), false)
                            }
                        }
                    }
                    Err(err) => (Err(err), false),
                };
                if result.is_err() && let Some(started) = delivery_started {
                    shared.app_performance_telemetry().record(
                        AppPerformanceOperation::InboundDeliveryProjection,
                        started.elapsed(),
                        false,
                    );
                }
                receive_observation.finish_app(&result);
                match result {
                    Ok(summary) => {
                        reconnect_backoff.reset();
                        publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
                        // An inline convergence pass on a delivered rival can
                        // supersede one of this device's own commits; the
                        // report waits in the client's pending buffer and this
                        // arm has no later command to drain it (mdk#1734).
                        publish_client_pending_projection_updates(
                            &mut client,
                            &events,
                            &account_id_hex,
                            &account_label,
                        );
                        if let Some(started) = delivery_started {
                            shared.app_performance_telemetry().record(
                                AppPerformanceOperation::InboundDeliveryProjection,
                                started.elapsed(),
                                true,
                            );
                        }
                        start_post_join_history_after_visibility(
                            &mut client,
                            &summary,
                            &events,
                            &account_id_hex,
                            &account_label,
                        )
                        .await;
                        scheduled_runtime_group_subscription_refresh.observe_pending(
                            client.has_pending_runtime_group_subscription_refresh(),
                            &command_tx,
                        );
                        schedule_pending_convergence_groups(
                            &mut scheduled_convergence,
                            &mut client,
                        );
                        if !overflow_recovery_incomplete {
                            let _ = run_pending_epoch_backfill_reporting_arm(
                                &mut client,
                                &events,
                                &account_id_hex,
                                &account_label,
                                &shared,
                                EpochBackfillExecutionSeam::Receive,
                            )
                            .await;
                        }
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
                            let reconnect_wait = shared.app_performance_telemetry().observe(RuntimeOp::WorkerReconnectWait);
                            let retry_started_at = Instant::now();
                            let mut retry_delay =
                                std::pin::pin!(sleep(reconnect_backoff.next_delay()));
                            loop {
                                tokio::select! {
                                    _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => return,
                                    _ = &mut shutdown => return,
                                    _ = &mut retry_delay => break,
                                    command = commands.recv() => {
                                        match command {
                                            Some(
                                                command @ (AccountWorkerCommand::CatchUp { .. }
                                                | AccountWorkerCommand::ConnectivityRestored { .. }),
                                            ) => {
                                                // Host recovery commands are meaningful without
                                                // an engine session: retain their responses and use
                                                // them to end only this stale sleep. Coalesce an
                                                // already queued burst into the same reopen attempt;
                                                // new signals can still interrupt later sleeps, so
                                                // extra attempts remain bounded by host signal rate
                                                // while the network stays unavailable.
                                                pending.push_back(command);
                                                while let Ok(command) = commands.try_recv() {
                                                    match command {
                                                        command @ (AccountWorkerCommand::CatchUp { .. }
                                                        | AccountWorkerCommand::ConnectivityRestored { .. }) => {
                                                            pending.push_back(command);
                                                        }
                                                        AccountWorkerCommand::CaptureConversation { respond, queued, .. } => {
                                                            if let Some(queued) = queued { queued.finish(TelemetryOutcome::NotReady); }
                                                            let _ = respond.send(Err(ConversationWindowError::NotReady));
                                                        }
                                                        command => {
                                                            shared.app_performance_telemetry().record_runtime(RuntimeOp::ReconnectCommandRejected, Duration::ZERO, TelemetryOutcome::NotReady);
                                                            drop(command);
                                                        },
                                                    }
                                                }
                                                tracing::debug!(
                                                    target: "marmot_app::runtime",
                                                    method = "account_worker_reconnect",
                                                    phase = "backoff_wait",
                                                    outcome = "interrupted",
                                                    elapsed_ms = u64::try_from(
                                                        retry_started_at.elapsed().as_millis()
                                                    )
                                                    .unwrap_or(u64::MAX),
                                                    "host recovery interrupted account worker reconnect backoff",
                                                );
                                                break;
                                            }
                                            Some(AccountWorkerCommand::CaptureConversation { respond, queued, .. }) => {
                                                if let Some(queued) = queued { queued.finish(TelemetryOutcome::NotReady); }
                                                let _ = respond.send(Err(ConversationWindowError::NotReady));
                                            }
                                            // There is deliberately no engine
                                            // session during this backoff.
                                            // Poll the bounded channel and
                                            // reject callers promptly by
                                            // dropping their response sender
                                            // instead of letting the queue fill
                                            // until host-side timeouts fire.
                                            Some(command) => {
                                                shared.app_performance_telemetry().record_runtime(RuntimeOp::ReconnectCommandRejected, Duration::ZERO, TelemetryOutcome::NotReady);
                                                drop(command);
                                            },
                                            None => return,
                                        }
                                    }
                                }
                            }
                            reconnect_wait.finish(TelemetryOutcome::Success);
                            let reopen = shared.app_performance_telemetry().observe(RuntimeOp::WorkerReopen);
                            let reopened_result = tokio::select! {
                                _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => return,
                                _ = &mut shutdown => return,
                                result = app.runtime_local_client(&account_label, &relay_plane, lifecycle.clone()) => result,
                            };
                            reopen.finish_app(&reopened_result);
                            match reopened_result {
                                Ok(mut reopened) => {
                                    install_storage_telemetry(&reopened, &shared.app_performance_telemetry());
                                    reopened.runtime_telemetry = Some(shared.app_performance_telemetry());
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
                                    let telemetry = shared.app_performance_telemetry();
                                    let prepare_transport = tokio::select! {
                                        _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => return,
                                        _ = &mut shutdown => return,
                                        result = reopened.prepare_transport_with_telemetry(Some(&telemetry)) => result,
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
                                            start_post_join_history_after_visibility(
                                                &mut reopened,
                                                &summary,
                                                &events,
                                                &account_id_hex,
                                                &account_label,
                                            )
                                            .await;
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
            _ = tokio::task::yield_now(), if avatar_due && !lifecycle.is_stopping() => {
                avatar_due = false;
                let identities = avatar_identities.run(&client, &account_id_hex);
                let acquisition = schedule_avatar_acquisition(&client, &media_http, &mut avatar_resumed);
                avatar_due |= identities.as_ref().is_ok_and(|more| *more)
                    || acquisition.as_ref().is_ok_and(|more| *more);
                if identities.is_err() || acquisition.is_err() {
                    tracing::warn!(target: "marmot_app::runtime", method = "avatar_acquisition",
                        "avatar maintenance failed; retrying on the next tick");
                }
            }
            _ = local_submission_wakeups.changed() => { local_submission_due = true; }
            _ = tokio::time::sleep_until(local_submission_retry_at), if local_submission_due => {
                local_submission_due = false;
                if let Ok(storage) = app.account_storage(&account_label)
                    && let Ok(Some(submission)) = storage.next_local_submission()
                {
                    let execution = shared.app_performance_telemetry().observe(RuntimeOp::SendExecution);
                    let started = Instant::now();
                    client.send_telemetry = Some(shared.app_performance_telemetry());
                    let result = client.publish_local_submission(&submission, |update| {
                        publish_app_runtime_projection_update(&events, &account_id_hex, &account_label, update);
                    }).await;
                    client.send_telemetry = None;
                    execution.finish_app(&result);
                    shared.app_performance_telemetry().record(AppPerformanceOperation::OutboundMessageSend, started.elapsed(), result.is_ok());
                    // A failed completion write must not strand later app-owned
                    // rows until maintenance. Bound retries too: a pre-engine
                    // failure can leave this same row at the head of the queue.
                    let finished = app.finish_local_message(&account_label, &submission, &result);
                    local_submission_due = true;
                    local_submission_retry_at = TokioInstant::now()
                        + if finished.is_err() { Duration::from_millis(100) } else { Duration::ZERO };
                    if let Ok(Some(update)) = finished {
                        publish_app_runtime_projection_update(&events, &account_id_hex, &account_label, update);
                    }
                    publish_client_pending_projection_updates(&mut client, &events, &account_id_hex, &account_label);
                    publish_client_pending_applied_summary(&mut client, &events, &account_id_hex, &account_label);
                    schedule_pending_convergence_groups(&mut scheduled_convergence, &mut client);
                }
            }
            result = presentation_wakeups.changed() => {
                if result.is_ok() { presentation_due = true; avatar_due = true; attachment_due = true; }
            }
            _ = tokio::task::yield_now(), if presentation_due => {
                if lifecycle.is_stopping() { continue 'worker; }
                avatar_due = true;
                presentation_due = match presentation_maintenance.run(&client, &account_id_hex) {
                    Ok(more) => more,
                    Err(_) => {
                        tracing::warn!(target: "marmot_app::runtime", method = "chat_presentation_maintenance",
                            "local chat presentation maintenance failed; retrying on the next wakeup or maintenance tick");
                        false
                    }
                };
            }
            _ = attachment_admission.ready(), if attachment_admission.is_waiting() => {
                attachment_due = true;
            }
            _ = tokio::task::yield_now(), if attachment_due => {
                if lifecycle.is_stopping() { continue 'worker; }
                attachment_due = match attachments::schedule(&client, &shared, &media_http, &mut attachment_admission) {
                    Ok(more) => more,
                    Err(_) => {
                        tracing::warn!(target: "marmot_app::runtime", method = "attachment_acquisition",
                            "attachment maintenance failed; retrying on next wakeup or tick");
                        false
                    }
                };
            }
            _ = maintenance_tick.tick() => {
                local_submission_due = true;
                attachment_due = true;
                presentation_due = true;
                avatar_due = true;
                // Periodic maintenance is never urgent, and its longest legs
                // run well past the whole shutdown budget: the key-package
                // catch-up below is capped at 15s, and an armed epoch-gap
                // backfill can hold the worker for EPOCH_BACKFILL_EOSE_WAIT
                // waiting on end-of-stored-events. Skip the tick outright once
                // shutdown is requested rather than starting work the drain
                // would then have to wait out.
                if lifecycle.is_stopping() {
                    continue 'worker;
                }
                let phase = shared.app_performance_telemetry().observe(RuntimeOp::WorkerMaintenance);
                if client.backfill_content_reports().is_err() {
                    tracing::warn!(
                        target: "marmot_app::account_worker",
                        method = "maintenance_tick",
                        "report backfill deferred"
                    );
                }
                run_legacy_message_promotion_batch(
                    &client,
                    &mut legacy_message_promotion,
                );
                if client.key_package_maintenance_requires_catch_up() {
                    let observation = shared.product_analytics.begin(
                        crate::ProductFamily::Maintenance, "catch_up", crate::ProductUnit::Attempt,
                    );
                    let catch_up = timeout(
                        Duration::from_secs(15), client.sync_automatically_with_partial_progress(),
                    ).await;
                    let outcome = match &catch_up {
                        Ok(Ok(_)) => KeyPackageMaintenanceCatchUpOutcome::Completed,
                        Ok(Err(_)) => KeyPackageMaintenanceCatchUpOutcome::Failed,
                        Err(_) => KeyPackageMaintenanceCatchUpOutcome::TimedOut,
                    };
                    if let Some(observation) = observation {
                        observation.finish(outcome.as_str());
                    }
                    match catch_up {
                        Ok(Ok(summary)) => {
                            publish_app_runtime_summary(
                                &events,
                                &account_id_hex,
                                &account_label,
                                &summary,
                            );
                            start_post_join_history_after_visibility(
                                &mut client,
                                &summary,
                                &events,
                                &account_id_hex,
                                &account_label,
                            )
                            .await;
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
                        Ok(Err(failure)) => {
                            publish_sync_summary_with_audit(
                                &events,
                                &account_id_hex,
                                &account_label,
                                &failure.partial_summary,
                                &shared,
                                "key_package_maintenance_catch_up",
                            );
                            start_post_join_history_after_visibility(
                                &mut client,
                                &failure.partial_summary,
                                &events,
                                &account_id_hex,
                                &account_label,
                            )
                            .await;
                            publish_app_runtime_account_error(
                                &events,
                                &account_id_hex,
                                &account_label,
                                account_error_message(
                                    "key package maintenance catch-up failed",
                                    &failure.source,
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
                scheduled_runtime_group_subscription_refresh.observe_pending(
                    client.has_pending_runtime_group_subscription_refresh(),
                    &command_tx,
                );
                let _ = run_pending_epoch_backfill_reporting_arm(
                    &mut client,
                    &events,
                    &account_id_hex,
                    &account_label,
                    &shared,
                    EpochBackfillExecutionSeam::Maintenance,
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
                let backlog_permit = shared.product_analytics.permit();
                match client.run_due_maintenance().await {
                    Ok(summary) => {
                        if let Some(permit) = &backlog_permit {
                            product_backlog.sample(
                                permit, crate::ProductFamily::Maintenance, "pending",
                                u64::from(summary.deferred),
                            );
                            product_backlog.sample(
                                permit, crate::ProductFamily::Maintenance, "ambiguous",
                                u64::from(summary.ambiguous_exposure),
                            );
                            product_backlog.sample(
                                permit, crate::ProductFamily::Maintenance, "failed",
                                u64::from(client.maintenance_failed_backlog),
                            );
                            product_backlog.sample(
                                permit, crate::ProductFamily::Recovery, "quarantine",
                                client.runtime.quarantined_group_count() as u64,
                            );
                        }
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

                phase.finish(TelemetryOutcome::Success);
            }
        }
    }
}

/// Run a steady-state catch-up while preserving prompt read-only projection
/// access. The sync future exclusively borrows the live client, so reads that
/// arrive during sync are answered from a snapshot captured immediately before
/// it, including when mutations are deferred. Mutations retain FIFO order;
/// reads observe pre-sync state until the window ends.
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
    respond: oneshot::Sender<Result<(), AccountCatchUpFailure>>,
    commands: &mut mpsc::Receiver<AccountWorkerCommand>,
    pending: &mut VecDeque<AccountWorkerCommand>,
    context: AccountWorkerCatchUpContext<'_>,
) {
    let telemetry = context.shared.app_performance_telemetry();
    let catch_up_observation = telemetry.observe(RuntimeOp::WorkerCatchUp);
    let snapshot_observation = telemetry.observe(RuntimeOp::WorkerSnapshot);
    let snapshot_result = client.group_read_snapshot();
    snapshot_observation.finish_app(&snapshot_result);
    let read_snapshot = match snapshot_result {
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
    let stage_telemetry = context.shared.app_performance_telemetry();
    let sync_result = {
        let mut sync = std::pin::pin!(client.sync_with_stage_telemetry(&stage_telemetry, true));
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
            let snapshot_reads_available = read_snapshot.is_some();
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
                AccountWorkerCommand::CaptureConversation {
                    respond, queued, ..
                } => {
                    if let Some(queued) = queued {
                        queued.finish(TelemetryOutcome::NotReady);
                    }
                    let _ = respond.send(Err(ConversationWindowError::NotReady));
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
                AccountWorkerCommand::ConfirmGroupRejoin { respond, .. } => {
                    let _ = respond.send(Err(AppError::AccountWorkerBusy));
                }
                AccountWorkerCommand::DeclineGroupRejoin { respond, .. } => {
                    let _ = respond.send(Err(AppError::AccountWorkerBusy));
                }
                AccountWorkerCommand::AcceptGroupInvite { respond, .. } => {
                    // The pinned sync exclusively owns the live client. This
                    // mutation was definitely not started, so a caller may
                    // safely retry after catch-up rather than waiting behind
                    // an arbitrarily slow relay drain.
                    let _ = respond.send(Err(AppError::AccountWorkerBusy));
                }
                AccountWorkerCommand::RetryRuntimeGroupSubscriptions { respond } => {
                    // This is worker-owned maintenance, not caller work. Keep
                    // its retry armed without placing it in the deferred FIFO;
                    // otherwise it would unnecessarily force later snapshot
                    // reads to wait behind the whole catch-up.
                    let _ = respond.send(true);
                }
                AccountWorkerCommand::CatchUp { respond } if deferred.is_empty() => {
                    telemetry.record_runtime(
                        RuntimeOp::CatchUpCoalesced,
                        Duration::ZERO,
                        TelemetryOutcome::Success,
                    );
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
            start_post_join_history_after_visibility(
                client,
                &summary,
                context.events,
                context.account_id_hex,
                context.account_label,
            )
            .await;
            if sync_summary_triggers_audit_tracker_update(&summary) {
                context.shared.schedule_audit_log_tracker_update("catch_up");
            }
            Ok(())
        }
        Err(failure) => {
            publish_sync_summary_with_audit(
                context.events,
                context.account_id_hex,
                context.account_label,
                &failure.partial_summary,
                context.shared,
                "catch_up",
            );
            start_post_join_history_after_visibility(
                client,
                &failure.partial_summary,
                context.events,
                context.account_id_hex,
                context.account_label,
            )
            .await;
            let message = account_error_message("runtime catch-up failed", &failure.source);
            publish_app_runtime_account_error(
                context.events,
                context.account_id_hex,
                context.account_label,
                message.clone(),
            );
            Err(AccountCatchUpFailure::new(
                message,
                failure.classification(),
            ))
        }
    };
    context
        .shared
        .app_performance_telemetry()
        .record_classified_result(
            AppPerformanceOperation::AccountSync,
            sync_started_at.elapsed(),
            result
                .as_ref()
                .err()
                .map(AccountCatchUpFailure::classification),
        );
    let retry_after_response = result.is_ok();
    catch_up_observation.finish(if result.is_ok() {
        TelemetryOutcome::Success
    } else {
        TelemetryOutcome::Failure
    });
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

/// Legacy rows promoted per steady-state maintenance tick. Keep this much
/// smaller than the storage API's hard maximum so a message-heavy account
/// remains responsive and shutdown never waits on a history-sized batch.
const LEGACY_MESSAGE_PROMOTION_BATCH_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegacyMessagePromotionStatus {
    Pending,
    Complete,
    Halted,
}

struct LegacyMessagePromotionSchedule {
    status: LegacyMessagePromotionStatus,
    promoted_total: usize,
}

impl LegacyMessagePromotionSchedule {
    fn new() -> Self {
        Self {
            status: LegacyMessagePromotionStatus::Pending,
            promoted_total: 0,
        }
    }
}

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

/// Run one storage-only promotion transaction after account readiness.
///
/// Transient lock failures retry on the next 15-second maintenance tick.
/// Durable decode failures halt this optional sweep until the next process
/// start so a malformed legacy row cannot create a hot retry loop. Reads keep
/// their legacy fallback either way, so this never gates account use.
fn run_legacy_message_promotion_batch(
    client: &AppClient,
    schedule: &mut LegacyMessagePromotionSchedule,
) {
    run_legacy_message_promotion_batch_with(schedule, |limit| {
        client.runtime.session().promote_legacy_message_rows(limit)
    });
}

fn run_legacy_message_promotion_batch_with(
    schedule: &mut LegacyMessagePromotionSchedule,
    promote: impl FnOnce(
        usize,
    )
        -> cgka_session::SessionResult<storage_sqlite::MessageFormatPromotionProgress>,
) {
    if schedule.status != LegacyMessagePromotionStatus::Pending {
        return;
    }
    let started = Instant::now();
    match promote(LEGACY_MESSAGE_PROMOTION_BATCH_SIZE) {
        Ok(progress) => {
            schedule.promoted_total = schedule.promoted_total.saturating_add(progress.promoted);
            if progress.has_more {
                tracing::info!(
                    target: "marmot_app::storage_maintenance",
                    method = "promote_legacy_message_rows",
                    promoted = progress.promoted,
                    promoted_total = schedule.promoted_total,
                    duration_ms = started.elapsed().as_millis() as u64,
                    "promoted one bounded legacy-message batch"
                );
            } else {
                schedule.status = LegacyMessagePromotionStatus::Complete;
                if schedule.promoted_total == 0 {
                    tracing::debug!(
                        target: "marmot_app::storage_maintenance",
                        method = "promote_legacy_message_rows",
                        "legacy-message promotion is already complete"
                    );
                } else {
                    tracing::info!(
                        target: "marmot_app::storage_maintenance",
                        method = "promote_legacy_message_rows",
                        promoted = progress.promoted,
                        promoted_total = schedule.promoted_total,
                        duration_ms = started.elapsed().as_millis() as u64,
                        "completed legacy-message promotion"
                    );
                }
            }
        }
        Err(error) => {
            let transient = error.is_transient();
            let error_kind = AppError::from(error).privacy_safe_kind();
            if !transient {
                schedule.status = LegacyMessagePromotionStatus::Halted;
            }
            tracing::warn!(
                target: "marmot_app::storage_maintenance",
                method = "promote_legacy_message_rows",
                error_kind,
                retry_scheduled = transient,
                promoted_total = schedule.promoted_total,
                "legacy-message promotion batch failed"
            );
        }
    }
}

/// Fully hydrate every group the deferred session open only seeded, in
/// chat-list recency order, while serving commands between batches
/// (mdk#1161). Group reads hydrate their one group and answer live;
/// projection-only invite acceptance runs immediately; other mutations and
/// catch-ups join `deferred` and replay in arrival order after the initial
/// catch-up, exactly like the catch-up window's own deferral.
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
    setup_key_package_result: &mut Option<Result<usize, AppError>>,
    shutdown: &mut oneshot::Receiver<()>,
    lifecycle: &RuntimeLifecycle,
) -> StartupHydrationOutcome {
    if client.runtime.session().unhydrated_group_ids().is_empty() {
        finish_deferred_hydration_reconciliation(client);
        return StartupHydrationOutcome::Completed;
    }
    let hydration_observation = shared
        .app_performance_telemetry()
        .observe(RuntimeOp::WorkerHydration);
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
                            handle_startup_hydration_command(
                                client,
                                command,
                                deferred,
                                events,
                                account_id_hex,
                                account_label,
                                setup_key_package_result,
                            )
                            .await;
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
                    handle_startup_hydration_command(
                        client,
                        command,
                        deferred,
                        events,
                        account_id_hex,
                        account_label,
                        setup_key_package_result,
                    )
                    .await;
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
    hydration_observation.finish(if pipeline_ok {
        TelemetryOutcome::Success
    } else {
        TelemetryOutcome::Failure
    });
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
pub(crate) async fn drain_deferred_hydration(client: &mut AppClient) -> Result<(), AppError> {
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
/// subscribers through their `GroupHydrationQuarantined` events. Invite
/// acceptance also runs live; everything else joins the startup deferral in
/// arrival order.
async fn handle_startup_hydration_command(
    client: &mut AppClient,
    command: AccountWorkerCommand,
    deferred: &mut Vec<DeferredStartupCommand>,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    setup_key_package_result: &mut Option<Result<usize, AppError>>,
) {
    match command {
        AccountWorkerCommand::GroupRecoveryStatus { group_id, respond } => {
            let _ = respond.send(group_recovery_after_hydration(client, &group_id));
        }
        AccountWorkerCommand::ConfirmGroupRejoin {
            welcome_id,
            token,
            respond,
        } => {
            let result = client.confirm_group_rejoin(&welcome_id, &token).await;
            publish_client_pending_projection_updates(
                client,
                events,
                account_id_hex,
                account_label,
            );
            publish_client_pending_applied_summary(client, events, account_id_hex, account_label);
            let _ = respond.send(result);
        }
        AccountWorkerCommand::DeclineGroupRejoin {
            welcome_id,
            respond,
        } => {
            let result = client.decline_group_rejoin(&welcome_id);
            publish_client_pending_projection_updates(
                client,
                events,
                account_id_hex,
                account_label,
            );
            let _ = respond.send(result);
        }
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
        AccountWorkerCommand::CaptureConversation {
            queued,
            group_id,
            query,
            store_epoch,
            observer,
            respond,
        } => {
            if let Some(queued) = queued {
                queued.finish(if respond.is_closed() {
                    TelemetryOutcome::Cancelled
                } else {
                    TelemetryOutcome::Success
                });
            }
            if !respond.is_closed() {
                client.register_conversation_capture(observer);
                let capture = client
                    .runtime_telemetry
                    .as_ref()
                    .map(|t| t.observe(RuntimeOp::ConversationCapture));
                let result = capture_conversation(client, &group_id, query, &store_epoch);
                if let Some(capture) = capture {
                    capture.finish(super::conversation_window::telemetry_outcome(&result));
                }
                let _ = respond.send(result);
            }
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
        AccountWorkerCommand::AcceptGroupInvite { group_id, respond } => {
            // Invite confirmation is a projection-only mutation and does not
            // need the remaining MLS groups to finish hydrating. Apply and
            // publish it immediately so a locally visible invite cannot be
            // held behind unrelated startup work.
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
        #[cfg(any(test, feature = "test-policy-overrides"))]
        AccountWorkerCommand::RecoveryRetrySnapshot { respond } => {
            let storage = client.app.account_storage(&client.state.label).unwrap();
            let _ = respond.send((
                storage.recovery_retry_state().unwrap(),
                client.recovery_owner.test_retry_remaining(&storage),
                storage.recovery_comparison().unwrap().pending(),
            ));
        }
        #[cfg(test)]
        AccountWorkerCommand::UnhydratedGroupCount { respond } => {
            let count = client.runtime.session().unhydrated_group_ids().len();
            let _ = respond.send(count);
        }
        AccountWorkerCommand::CatchUp { respond } => {
            deferred.push(DeferredStartupCommand::CatchUp(respond));
        }
        AccountWorkerCommand::PublishSetupKeyPackage { respond } => {
            match setup_key_package_result.take() {
                Some(result) => {
                    let _ = respond.send(result);
                }
                None => deferred.push(DeferredStartupCommand::Command(Box::new(
                    AccountWorkerCommand::PublishSetupKeyPackage { respond },
                ))),
            }
        }
        other => deferred.push(DeferredStartupCommand::Command(Box::new(other))),
    }
}

const MEDIA_HTTP_IN_FLIGHT_LIMIT: usize = 4;

struct MediaHttpContext {
    product: crate::product_analytics::ProductAnalytics,
    tx: mpsc::UnboundedSender<MediaHttpDone>,
    permits: Arc<Semaphore>,
    /// Prevent concurrent host retries from uploading the same durable blob
    /// more than once. This state is deliberately ephemeral: after a worker
    /// restart, the durable staged/failed record remains retryable.
    prepared_group_image_uploads: Arc<Mutex<HashSet<String>>>,
    /// Never sends a value. Dropping the worker-owned sender closes every
    /// receiver and cancels active HTTP futures on every worker exit path.
    worker_lifetime: watch::Sender<()>,
}

struct MediaHttpDone {
    /// Capacity remains reserved while a whole-blob result waits for and runs
    /// account-worker completion, so the unbounded channel is effectively
    /// bounded by `MEDIA_HTTP_IN_FLIGHT_LIMIT`.
    permit: OwnedSemaphorePermit,
    completion: MediaHttpCompletion,
    cancellation: Option<crate::ProductObservation>,
}

enum MediaHttpCompletion {
    Attachment {
        job: storage_sqlite::AttachmentAcquisition,
        result: Result<MediaDownloadResult, crate::media::AttachmentDownloadFailure>,
        byte_budget: u64,
        background_permit: OwnedSemaphorePermit,
    },
    Avatar {
        job: storage_sqlite::AvatarAcquisition,
        result: Result<storage_sqlite::AvatarImage, AppError>,
    },
    Upload {
        finish: EncryptedMediaUploadFinish,
        result: Result<MediaUploadResult, AppError>,
        respond: oneshot::Sender<Result<MediaUploadResult, AppError>>,
        started_at: Instant,
    },
    Download {
        result: Result<MediaDownloadResult, AppError>,
        respond: oneshot::Sender<Result<MediaDownloadResult, AppError>>,
        started_at: Instant,
    },
    GroupImage {
        result: Result<Vec<u8>, AppError>,
        respond: oneshot::Sender<Result<Vec<u8>, AppError>>,
    },
    PreparedGroupImageUpload {
        upload_id: String,
        result: Result<(), AppError>,
        respond: oneshot::Sender<Result<AppPreparedGroupImageUpload, AppError>>,
        started_at: Instant,
    },
}

fn schedule_avatar_acquisition(
    client: &AppClient,
    media_http: &MediaHttpContext,
    resumed: &mut bool,
) -> Result<bool, AppError> {
    let storage = client.app.account_storage(&client.state.label)?;
    let transport = client.blossom_http_transport.clone();
    let mut dispatched = false;
    let result = dispatch_avatar_acquisition(
        &storage,
        media_http,
        resumed,
        &mut dispatched,
        move |descriptor| {
            let transport = transport.clone();
            async move { crate::media::avatar::fetch(&descriptor, &transport).await }
        },
    );
    if dispatched {
        let _ = client
            .app
            .presentation_signals
            .avatars
            .send(client.state.label.clone());
    }
    result
}

fn dispatch_avatar_acquisition<F, Fut>(
    storage: &storage_sqlite::SqliteAccountStorage,
    media_http: &MediaHttpContext,
    resumed: &mut bool,
    dispatched: &mut bool,
    fetch: F,
) -> Result<bool, AppError>
where
    F: Fn(storage_sqlite::SelectedAvatar) -> Fut,
    Fut: std::future::Future<Output = Result<storage_sqlite::AvatarImage, AppError>>
        + Send
        + 'static,
{
    if !*resumed {
        storage.resume_avatar_acquisition()?;
        *resumed = true;
    }
    let more_bootstrap = storage.bootstrap_avatar_acquisition()?;
    // Command demand gets first admission; this shares the existing four permits
    // and completion channel rather than starting a second HTTP pool.
    for _ in 0..MEDIA_HTTP_IN_FLIGHT_LIMIT {
        // Keep a foreground slot free even across repeated dispatch passes.
        if media_http.permits.available_permits() <= 1 {
            break;
        }
        let Ok(permit) = media_http.permits.clone().try_acquire_owned() else {
            break;
        };
        let Some(job) = storage.claim_avatar_acquisition(crate::unix_now_seconds())? else {
            break;
        };
        *dispatched = true;
        let descriptor = job.descriptor.clone();
        spawn_media_http(media_http, permit, fetch(descriptor), move |result| {
            MediaHttpCompletion::Avatar { job, result }
        });
    }
    Ok(more_bootstrap)
}

fn spawn_media_http<T>(
    media_http: &MediaHttpContext,
    permit: OwnedSemaphorePermit,
    work: impl std::future::Future<Output = T> + Send + 'static,
    into_done: impl FnOnce(T) -> MediaHttpCompletion + Send + 'static,
) {
    let cancellation = media_http.product.begin(
        crate::ProductFamily::Media,
        "cancel",
        crate::ProductUnit::Attempt,
    );
    let tx = media_http.tx.clone();
    let mut worker_lifetime = media_http.worker_lifetime.subscribe();
    tokio::spawn(async move {
        let output = tokio::select! {
            biased;
            _ = worker_lifetime.changed() => return,
            output = work => output,
        };
        let _ = tx.send(MediaHttpDone {
            permit,
            completion: into_done(output),
            cancellation,
        });
    });
}

fn ready_command_index(
    pending: &VecDeque<AccountWorkerCommand>,
    media_http: &MediaHttpContext,
) -> Option<usize> {
    let has_capacity =
        !media_http.permits.is_closed() && media_http.permits.available_permits() != 0;
    pending
        .iter()
        .position(|command| has_capacity || !command.needs_media_slot())
}

fn reserve_media_http(media_http: &MediaHttpContext) -> OwnedSemaphorePermit {
    // Startup replay and the steady loop use ready_command_index; fresh
    // commands pass handle_account_worker_command. All three gate capacity,
    // and this worker alone acquires permits without yielding between gates.
    debug_assert!(media_http.permits.available_permits() != 0);
    media_http
        .permits
        .clone()
        .try_acquire_owned()
        .expect("media commands dispatch only with capacity")
}

fn reserve_prepared_group_image_upload(
    media_http: &MediaHttpContext,
    upload_id: &str,
) -> Result<(), AppError> {
    let mut uploads = media_http
        .prepared_group_image_uploads
        .lock()
        .map_err(|_| AppError::AccountWorkerBusy)?;
    if !uploads.insert(upload_id.to_owned()) {
        return Err(AppError::AccountWorkerBusy);
    }
    Ok(())
}

fn release_prepared_group_image_upload(media_http: &MediaHttpContext, upload_id: &str) {
    if let Ok(mut uploads) = media_http.prepared_group_image_uploads.lock() {
        uploads.remove(upload_id);
    }
}

fn prepared_group_image_upload_is_in_flight(
    media_http: &MediaHttpContext,
    upload_id: &str,
) -> bool {
    media_http
        .prepared_group_image_uploads
        .lock()
        .map(|uploads| uploads.contains(upload_id))
        .unwrap_or(false)
}

async fn complete_media_http(
    client: &mut AppClient,
    done: MediaHttpDone,
    shared: &RuntimeSharedServices,
    media_http: &MediaHttpContext,
) {
    let MediaHttpDone {
        permit,
        completion,
        cancellation,
    } = done;
    if let Some(cancellation) = cancellation {
        cancellation.discard();
    }
    match completion {
        MediaHttpCompletion::Attachment {
            job,
            result,
            byte_budget,
            background_permit,
        } => {
            if attachments::complete(client, &job, result, byte_budget).is_err() {
                tracing::warn!(target: "marmot_app::runtime", method = "attachment_acquisition",
                    "attachment completion failed; durable lease permits recovery");
            }
            shared.attachment_updates.send_modify(|_| {});
            drop(background_permit);
        }
        MediaHttpCompletion::Avatar { job, result } => {
            if let Ok(storage) = client.app.account_storage(&client.state.label) {
                let now = crate::unix_now_seconds();
                let completed = match result {
                    Ok(image) => {
                        let refresh = matches!(
                            job.descriptor,
                            storage_sqlite::SelectedAvatar::RemoteImage { .. }
                        )
                        .then(|| now.saturating_add(24 * 60 * 60));
                        storage
                            .complete_avatar_acquisition(&job, &image, refresh)
                            .map(|_| ())
                    }
                    Err(error) => storage
                        .fail_avatar_acquisition(&job, now, crate::media::avatar::retryable(&error))
                        .map(|_| ()),
                };
                if completed.is_err() {
                    // Publication failure leaves the old bytes untouched. Avoid
                    // stranding a fetching row until process reconstruction.
                    let _ = storage.fail_avatar_acquisition(&job, now, true);
                    tracing::warn!(target: "marmot_app::runtime", method = "avatar_acquisition",
                        "avatar completion could not be committed");
                }
            }
            let _ = client
                .app
                .presentation_signals
                .avatars
                .send(client.state.label.clone());
        }
        MediaHttpCompletion::Upload {
            finish,
            result,
            respond,
            started_at,
        } => {
            let result = match result {
                Ok(result) => client.finish_encrypted_media_upload(finish, result).await,
                Err(err) => Err(err),
            };
            // Mixed uploads are one batch attempt, classified as other.
            let media_type = result
                .as_ref()
                .ok()
                .and_then(|v| {
                    v.attachments
                        .first()
                        .filter(|first| {
                            v.attachments
                                .iter()
                                .all(|item| item.reference.media_type == first.reference.media_type)
                        })
                        .map(|item| item.reference.media_type.as_str())
                })
                .unwrap_or("");
            shared.app_performance_telemetry().record_media(
                AppPerformanceOperation::MediaUpload,
                started_at.elapsed(),
                result.is_ok(),
                media_type,
            );
            let _ = respond.send(result);
        }
        MediaHttpCompletion::Download {
            result,
            respond,
            started_at,
        } => {
            shared.app_performance_telemetry().record_media(
                AppPerformanceOperation::MediaDownload,
                started_at.elapsed(),
                result.is_ok(),
                result.as_ref().map(|v| v.media_type.as_str()).unwrap_or(""),
            );
            let _ = respond.send(result);
        }
        MediaHttpCompletion::GroupImage { result, respond } => {
            let _ = respond.send(result);
        }
        MediaHttpCompletion::PreparedGroupImageUpload {
            upload_id,
            result,
            respond,
            started_at,
        } => {
            release_prepared_group_image_upload(media_http, &upload_id);
            let succeeded = result.is_ok();
            let status = client.finish_initial_group_image_upload(&upload_id, &result);
            let response = match result {
                Ok(()) => status,
                Err(upload_error) => match status {
                    Ok(_) => Err(upload_error),
                    Err(persistence_error) => Err(persistence_error),
                },
            };
            shared.app_performance_telemetry().record_media(
                AppPerformanceOperation::GroupCreateImageUpload,
                started_at.elapsed(),
                succeeded,
                "image/",
            );
            let _ = respond.send(response);
        }
    }
    drop(permit);
}

/// Closed command channel for handlers that never serve concurrent commands
/// (unit tests that call `handle_account_worker_command` directly). Startup
/// deferred replay uses the live worker queue instead.
#[cfg(test)]
fn unused_account_worker_command_io() -> (
    mpsc::Receiver<AccountWorkerCommand>,
    VecDeque<AccountWorkerCommand>,
) {
    let (tx, rx) = mpsc::channel(1);
    drop(tx);
    (rx, VecDeque::new())
}

fn capture_group_read_snapshot(
    client: &AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    method: &'static str,
) -> Option<crate::client::GroupReadSnapshot> {
    match client.group_read_snapshot() {
        Ok(snapshot) => Some(snapshot),
        Err(err) => {
            publish_app_runtime_account_error(
                events,
                account_id_hex,
                account_label,
                account_error_message(method, &err),
            );
            None
        }
    }
}

/// Serve safe snapshot reads while `work` exclusively borrows the live client.
/// Mutations stay queued FIFO behind `work`; reads continue observing the
/// snapshot until it completes. Worker-owned catch-up runs afterward because
/// create/invite spawn it immediately after the caller-visible reply.
async fn serve_snapshot_reads_until<Fut>(
    read_snapshot: Option<crate::client::GroupReadSnapshot>,
    work: Fut,
    commands: &mut mpsc::Receiver<AccountWorkerCommand>,
    pending: &mut VecDeque<AccountWorkerCommand>,
    app: &MarmotApp,
    account_label: &str,
) -> Fut::Output
where
    Fut: Future,
{
    let mut deferred = VecDeque::new();
    let mut follow_up = VecDeque::new();
    let mut commands_open = true;
    let mut work = std::pin::pin!(work);
    let output = loop {
        let command = if let Some(command) = pending.pop_front() {
            Some(command)
        } else {
            tokio::select! {
                biased;
                result = &mut work => break result,
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
        let snapshot_reads_available = read_snapshot.is_some();
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
            AccountWorkerCommand::CaptureConversation {
                respond, queued, ..
            } => {
                if let Some(queued) = queued {
                    queued.finish(TelemetryOutcome::NotReady);
                }
                let _ = respond.send(Err(ConversationWindowError::NotReady));
            }
            AccountWorkerCommand::GroupMlsState { group_id, respond }
                if snapshot_reads_available =>
            {
                let snapshot = read_snapshot
                    .as_ref()
                    .expect("snapshot availability checked above");
                let _ = respond.send(snapshot.group_mls_state(&group_id));
            }
            AccountWorkerCommand::GroupRoster { group_id, respond } if snapshot_reads_available => {
                let snapshot = read_snapshot
                    .as_ref()
                    .expect("snapshot availability checked above");
                let _ = respond.send(group_roster_from_snapshot(
                    app,
                    account_label,
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
            AccountWorkerCommand::CatchUp { .. } => {
                follow_up.push_back(command);
            }
            AccountWorkerCommand::RetryRuntimeGroupSubscriptions { respond } => {
                let _ = respond.send(true);
            }
            command => deferred.push_back(command),
        }
    };
    pending.append(&mut deferred);
    pending.append(&mut follow_up);
    output
}

struct AccountWorkerCommandContext<'a> {
    commands: &'a mut mpsc::Receiver<AccountWorkerCommand>,
    pending: &'a mut VecDeque<AccountWorkerCommand>,
    app: &'a MarmotApp,
    events: &'a broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &'a str,
    account_label: &'a str,
    shared: &'a RuntimeSharedServices,
    media_http: &'a MediaHttpContext,
    scheduled_convergence: &'a mut ScheduledConvergence,
}

// Keep response ownership and error classification outside the large async dispatch
// frame. Inlining the result moves at every arm grows debug poll stacks substantially.
#[inline(never)]
fn respond_diagnosed<T>(
    shared: &RuntimeSharedServices,
    permit: Option<&crate::DiagnosticsPermit>,
    respond: oneshot::Sender<Result<T, AppError>>,
    result: Result<T, AppError>,
) -> Result<(), Result<T, AppError>> {
    if let Err(error) = &result {
        shared.product_analytics.storage_failure(permit, error);
    }
    respond.send(result)
}

/// Commands that arrived while a previous handler held `&mut client` stay in
/// `pending` until that handler returns. Read commands (`Members` /
/// `MemberIdsPage` / `GroupMlsState` / `GroupRoster` / `QuarantinedGroups`) are
/// intercepted inline during catch-up and Welcome fanout and answered from a
/// `GroupReadSnapshot`; here they read the live session.
async fn handle_account_worker_command(
    client: &mut AppClient,
    command: AccountWorkerCommand,
    context: AccountWorkerCommandContext<'_>,
) {
    if (context.media_http.permits.is_closed()
        || context.media_http.permits.available_permits() == 0)
        && command.needs_media_slot()
    {
        // Only newly received commands reach this gate; parked media keep their order.
        context.pending.push_back(command);
        return;
    }
    let events = context.events;
    let account_id_hex = context.account_id_hex;
    let account_label = context.account_label;
    if account_worker_command_future(client, command, context).await {
        // One publication seam covers all successful dispatch completions. Early
        // admission failures and cancelled commands retain their previous behavior.
        publish_client_pending_applied_summary(client, events, account_id_hex, account_label);
    }
}

// Construct only the selected command's async state. The synchronous factory's
// construction frame is gone before polling begins, keeping dispatch overhead
// out of nested engine/publication stacks on 2 MiB runtime threads.
fn account_worker_command_future<'a>(
    client: &'a mut AppClient,
    command: AccountWorkerCommand,
    context: AccountWorkerCommandContext<'a>,
) -> Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
    let AccountWorkerCommandContext {
        commands,
        pending,
        app,
        events,
        account_id_hex,
        account_label,
        shared,
        media_http,
        scheduled_convergence,
    } = context;
    let storage_permit = shared.product_analytics.permit();
    match command {
        AccountWorkerCommand::ConnectivityRestored { respond } => Box::pin(async move {
            let result = client.note_connectivity_restored().map(|_| ());
            scheduled_convergence.wake_after_connectivity_restored();
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::NetworkStartupSettled { respond } => Box::pin(async move {
            let _ = respond.send(());
            true
        }),
        AccountWorkerCommand::StartupCatchUpResult { result, respond } => Box::pin(async move {
            let _ = respond.send(result);
            true
        }),
        AccountWorkerCommand::Drain { respond } => Box::pin(async move {
            let _ = respond.send(());
            true
        }),
        AccountWorkerCommand::RetryRuntimeGroupSubscriptions { respond } => Box::pin(async move {
            let pending = match client
                .retry_pending_runtime_group_subscription_refresh()
                .await
            {
                Ok(pending) => pending,
                Err(error) => {
                    publish_app_runtime_account_error(
                        events,
                        account_id_hex,
                        account_label,
                        account_error_message("runtime group subscription refresh failed", &error),
                    );
                    true
                }
            };
            let _ = respond.send(pending);
            true
        }),
        #[cfg(test)]
        AccountWorkerCommand::HoldMediaHttp {
            admission,
            started,
            release,
            respond,
        } => Box::pin(async move {
            let permit = reserve_media_http(media_http);
            drop(admission);
            spawn_media_http(
                media_http,
                permit,
                async move {
                    let _ = started.send(());
                    release.await.expect("test releases transfer");
                    Ok(Vec::new())
                },
                move |result| MediaHttpCompletion::GroupImage { result, respond },
            );
            false
        }),
        #[cfg(any(test, feature = "test-policy-overrides"))]
        AccountWorkerCommand::AdvanceRecoveryClock { elapsed, respond } => Box::pin(async move {
            client.recovery_owner.test_advance_clock(elapsed);
            let _ = respond.send(());
            true
        }),
        #[cfg(any(test, feature = "test-policy-overrides"))]
        AccountWorkerCommand::RecoveryRetrySnapshot { respond } => Box::pin(async move {
            let storage = client.app.account_storage(&client.state.label).unwrap();
            let _ = respond.send((
                storage.recovery_retry_state().unwrap(),
                client.recovery_owner.test_retry_remaining(&storage),
                storage.recovery_comparison().unwrap().pending(),
            ));
            true
        }),
        #[cfg(test)]
        AccountWorkerCommand::UnhydratedGroupCount { respond } => Box::pin(async move {
            let count = client.runtime.session().unhydrated_group_ids().len();
            let _ = respond.send(count);
            true
        }),
        AccountWorkerCommand::CatchUp { respond } => Box::pin(async move {
            let sync_started_at = Instant::now();
            let result = match client.sync_with_classified_partial_progress().await {
                Ok(summary) => {
                    publish_app_runtime_summary(events, account_id_hex, account_label, &summary);
                    publish_client_pending_projection_updates(
                        client,
                        events,
                        account_id_hex,
                        account_label,
                    );
                    if sync_summary_triggers_audit_tracker_update(&summary) {
                        shared.schedule_audit_log_tracker_update("catch_up");
                    }
                    Ok(())
                }
                Err(failure) => {
                    publish_sync_summary_with_audit(
                        events,
                        account_id_hex,
                        account_label,
                        &failure.partial_summary,
                        shared,
                        "catch_up",
                    );
                    let message = account_error_message("runtime catch-up failed", &failure.source);
                    publish_app_runtime_account_error(
                        events,
                        account_id_hex,
                        account_label,
                        message.clone(),
                    );
                    Err(AccountCatchUpFailure::new(
                        message,
                        failure.classification(),
                    ))
                }
            };
            shared.app_performance_telemetry().record_classified_result(
                AppPerformanceOperation::AccountSync,
                sync_started_at.elapsed(),
                result
                    .as_ref()
                    .err()
                    .map(AccountCatchUpFailure::classification),
            );
            let retry_after_response = result.is_ok();
            let _ = respond.send(result);
            if retry_after_response {
                client
                    .retry_pending_push_registration_shares_best_effort()
                    .await;
            }
            true
        }),
        AccountWorkerCommand::RepairFullHistory { respond } => Box::pin(async move {
            let sync_started_at = Instant::now();
            let read_snapshot = capture_group_read_snapshot(
                client,
                events,
                account_id_hex,
                account_label,
                "full-history repair snapshot failed",
            );
            // Observe cancellation at checkpoint boundaries, never by dropping
            // an in-flight durable ingest or a live engine transaction.
            let cancelled = || respond.is_closed() || shared.lifecycle().is_stopping();
            let repaired = Box::pin(serve_snapshot_reads_until(
                read_snapshot,
                client.repair_full_history_cancellable(&cancelled),
                commands,
                pending,
                app,
                account_label,
            ))
            .await;
            let result = match repaired {
                Ok(summary) => {
                    publish_app_runtime_summary(events, account_id_hex, account_label, &summary);
                    publish_client_pending_projection_updates(
                        client,
                        events,
                        account_id_hex,
                        account_label,
                    );
                    if sync_summary_triggers_audit_tracker_update(&summary) {
                        shared.schedule_audit_log_tracker_update("repair_full_history");
                    }
                    Ok(())
                }
                Err(failure) => {
                    publish_sync_summary_with_audit(
                        events,
                        account_id_hex,
                        account_label,
                        &failure.partial_summary,
                        shared,
                        "repair_full_history",
                    );
                    let message =
                        account_error_message("full-history repair failed", &failure.source);
                    publish_app_runtime_account_error(
                        events,
                        account_id_hex,
                        account_label,
                        message.clone(),
                    );
                    Err(AccountCatchUpFailure::from_sync_failure(message, &failure))
                }
            };
            shared.app_performance_telemetry().record_classified_result(
                AppPerformanceOperation::AccountSync,
                sync_started_at.elapsed(),
                result
                    .as_ref()
                    .err()
                    .map(AccountCatchUpFailure::classification),
            );
            let _ = respond.send(result);
            true
        }),
        AccountWorkerCommand::CreateGroup {
            queued_at,
            name,
            members,
            options,
            prepared_image_upload_id,
            respond,
        } => Box::pin(async move {
            let telemetry = shared.app_performance_telemetry();
            telemetry.record(
                AppPerformanceOperation::GroupCreateQueueWait,
                queued_at.elapsed(),
                true,
            );
            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
            let result = match prepared_image_upload_id {
                None => {
                    client
                        .create_group_with_options_and_telemetry(
                            &name,
                            &member_refs,
                            options,
                            &telemetry,
                        )
                        .await
                }
                Some(upload_id) => {
                    client
                        .create_group_with_prepared_initial_image_and_telemetry(
                            &name,
                            &member_refs,
                            options,
                            &upload_id,
                            &telemetry,
                        )
                        .await
                }
            };
            let response_handoff_started_at = Instant::now();
            if let Ok(created_group) = &result {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &created_group.group_id,
                );
                if let Some(chat_list_row) = &created_group.chat_list_row {
                    let _ =
                        events.send(MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate {
                            account_id_hex: account_id_hex.to_owned(),
                            account_label: account_label.to_owned(),
                            update: AppProjectionUpdate {
                                group_id_hex: chat_list_row.group_id_hex.clone(),
                                timeline_messages: Vec::new(),
                                timeline_changes: Vec::new(),
                                chat_list_row: Some(chat_list_row.clone()),
                                chat_list_trigger: ChatListUpdateTrigger::NewGroup,
                            },
                        }));
                }
            }
            let created = result.is_ok();
            let response_sent =
                respond_diagnosed(shared, storage_permit.as_ref(), respond, result).is_ok();
            telemetry.record(
                AppPerformanceOperation::GroupCreateResponseHandoff,
                response_handoff_started_at.elapsed(),
                response_sent,
            );
            if created {
                let read_snapshot = capture_group_read_snapshot(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                    "runtime post-create snapshot failed",
                );
                Box::pin(serve_snapshot_reads_until(
                    read_snapshot,
                    async {
                        client
                            .drive_unpublished_welcome_delivery(Some(&telemetry))
                            .await;
                        publish_pending_welcome_delivery_events(
                            events,
                            account_id_hex,
                            account_label,
                            client,
                        );
                        client
                            .retry_pending_push_registration_shares_best_effort()
                            .await;
                    },
                    commands,
                    pending,
                    app,
                    account_label,
                ))
                .await;
            }
            true
        }),
        AccountWorkerCommand::StagePreparedGroupImage {
            plaintext,
            media_type,
            respond,
        } => Box::pin(async move {
            let started_at = Instant::now();
            let result = client.stage_prepared_initial_group_image(&plaintext, &media_type);
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::GroupCreateImagePreprocess,
                started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::UploadPreparedGroupImage {
            admission,
            upload_id,
            server,
            respond,
        } => Box::pin(async move {
            match client.prepare_initial_group_image_upload(
                &upload_id,
                server,
                app.allow_loopback_blob_endpoints(),
            ) {
                Ok(PreparedGroupImageUploadStart::Complete(status)) => {
                    let _ = respond.send(Ok(status));
                }
                Ok(PreparedGroupImageUploadStart::Http(http)) => {
                    if let Err(err) = reserve_prepared_group_image_upload(media_http, &upload_id) {
                        let _ =
                            respond_diagnosed(shared, storage_permit.as_ref(), respond, Err(err));
                        return false;
                    }
                    let permit = reserve_media_http(media_http);
                    let started_at = Instant::now();
                    spawn_media_http(media_http, permit, http.run(), move |result| {
                        MediaHttpCompletion::PreparedGroupImageUpload {
                            upload_id,
                            result,
                            respond,
                            started_at,
                        }
                    });
                }
                Err(err) => {
                    let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, Err(err));
                }
            }
            drop(admission);
            true
        }),
        AccountWorkerCommand::PreparedGroupImageStatus { upload_id, respond } => {
            Box::pin(async move {
                let result =
                    client
                        .prepared_initial_group_image_status(&upload_id)
                        .map(|mut status| {
                            if prepared_group_image_upload_is_in_flight(media_http, &upload_id) {
                                status.state = crate::AppPreparedGroupImageUploadState::Uploading;
                            }
                            status
                        });
                let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
                true
            })
        }
        AccountWorkerCommand::PreparedGroupImages { respond } => Box::pin(async move {
            let result = client.prepared_initial_group_images().map(|mut statuses| {
                for status in &mut statuses {
                    if prepared_group_image_upload_is_in_flight(media_http, &status.upload_id) {
                        status.state = crate::AppPreparedGroupImageUploadState::Uploading;
                    }
                }
                statuses
            });
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::Members { group_id, respond } => Box::pin(async move {
            // On-demand promotion (mdk#1161): normally a no-op (the startup
            // pipeline hydrated everything), but if the pipeline aborted on a
            // storage error the leftover groups must still promote on first
            // read instead of surfacing GroupHydrationPending forever.
            let _ = client
                .runtime
                .session_mut()
                .ensure_group_hydrated(&group_id);
            let result = client.members(&group_id);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::MemberIdsPage { group_ids, respond } => Box::pin(async move {
            // The page is one worker command, but each requested group keeps
            // the same on-demand promotion and quarantine gate as `Members`.
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                member_ids_page_after_hydration(client, &group_ids),
            );
            true
        }),
        AccountWorkerCommand::CaptureConversation {
            queued,
            group_id,
            query,
            store_epoch,
            observer,
            respond,
        } => Box::pin(async move {
            if let Some(queued) = queued {
                queued.finish(if respond.is_closed() {
                    TelemetryOutcome::Cancelled
                } else {
                    TelemetryOutcome::Success
                });
            }
            if !respond.is_closed() {
                client.register_conversation_capture(observer);
                let capture = client
                    .runtime_telemetry
                    .as_ref()
                    .map(|t| t.observe(RuntimeOp::ConversationCapture));
                let result = capture_conversation(client, &group_id, query, &store_epoch);
                if let Some(capture) = capture {
                    capture.finish(super::conversation_window::telemetry_outcome(&result));
                }
                let _ = respond.send(result);
            }
            true
        }),
        AccountWorkerCommand::GroupMlsState { group_id, respond } => Box::pin(async move {
            // See the Members arm: on-demand promotion for pipeline-abort
            // leftovers.
            let _ = client
                .runtime
                .session_mut()
                .ensure_group_hydrated(&group_id);
            let result = client.group_mls_state(&group_id);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::GroupRoster { group_id, respond } => Box::pin(async move {
            let result = group_roster_after_hydration(client, &group_id);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::EnableGroupDisbanding { group_id, respond } => Box::pin(async move {
            let result = client.enable_group_disbanding(&group_id).await;
            if result.is_ok() {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::DisbandGroup { group_id, respond } => Box::pin(async move {
            let result = client.disband_group(&group_id).await;
            publish_app_runtime_group_state_updated(
                events,
                account_id_hex,
                account_label,
                &group_id,
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::AcknowledgeDisbandFailure { group_id, respond } => {
            Box::pin(async move {
                let result = client.acknowledge_disband_failure(&group_id);
                if matches!(result, Ok(true)) {
                    publish_app_runtime_group_state_updated(
                        events,
                        account_id_hex,
                        account_label,
                        &group_id,
                    );
                }
                let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
                true
            })
        }
        AccountWorkerCommand::QuarantinedGroups { respond } => Box::pin(async move {
            let result = Ok(client.quarantined_groups());
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::RetryHydrateQuarantinedGroup { group_id, respond } => {
            Box::pin(async move {
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
                        Ok(summary) => publish_app_runtime_summary(
                            events,
                            account_id_hex,
                            account_label,
                            &summary,
                        ),
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
                let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
                true
            })
        }
        AccountWorkerCommand::UpdateMessageRetention {
            group_id,
            disappearing_message_secs,
            respond,
        } => Box::pin(async move {
            let result = client
                .update_message_retention(&group_id, disappearing_message_secs)
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::ReplaceEncryptedMediaBlobEndpoints {
            group_id,
            endpoints,
            respond,
        } => Box::pin(async move {
            let result = client
                .replace_encrypted_media_blob_endpoints(&group_id, endpoints)
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::UpdateGroupAvatarUrl {
            group_id,
            url,
            dim,
            thumbhash,
            respond,
        } => Box::pin(async move {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::SafeExportSecret {
            group_id,
            component_id,
            respond,
        } => Box::pin(async move {
            let result = client.safe_export_secret(&group_id, component_id);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::ExporterSecret {
            group_id,
            label,
            length,
            respond,
        } => Box::pin(async move {
            let result = client.exporter_secret(&group_id, &label, length);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::InviteMembers {
            group_id,
            members,
            initial_admins,
            respond,
        } => Box::pin(async move {
            let telemetry = shared.app_performance_telemetry();
            let result = async {
                let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
                let admin_refs = initial_admins
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                client
                    .invite_members_with_telemetry(&group_id, &member_refs, &admin_refs, &telemetry)
                    .await
            }
            .await;
            let canonical = result.as_ref().is_ok_and(|summary| {
                summary.accept_disposition == cgka_traits::SendAcceptDisposition::Published
            });
            if canonical {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            if canonical {
                // Reply first so the inviter is not blocked on Welcome publish.
                // Snapshot reads (members, MLS state, roster) are served from a
                // post-commit snapshot while fanout owns the live client.
                // Later mutations stay queued FIFO behind this delivery.
                let read_snapshot = capture_group_read_snapshot(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                    "runtime post-invite snapshot failed",
                );
                Box::pin(serve_snapshot_reads_until(
                    read_snapshot,
                    async {
                        client
                            .drive_unpublished_welcome_delivery(Some(&telemetry))
                            .await;
                        publish_pending_welcome_delivery_events(
                            events,
                            account_id_hex,
                            account_label,
                            client,
                        );
                    },
                    commands,
                    pending,
                    app,
                    account_label,
                ))
                .await;
            }
            true
        }),
        AccountWorkerCommand::RemoveMembers {
            group_id,
            members,
            respond,
        } => Box::pin(async move {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::LeaveGroup { group_id, respond } => Box::pin(async move {
            let result = client.leave_group(&group_id).await;
            // Drain the kind-1210 "member left" row this commit queued. Sibling
            // mutators (invite/remove/profile) already flush
            // `pending_projection_updates`; without this the live timeline stays
            // stale until some later unrelated command emits the row mis-timed.
            publish_client_pending_projection_updates(
                client,
                events,
                account_id_hex,
                account_label,
            );
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::ForgetGroupLocal { group_id, respond } => Box::pin(async move {
            let result = client.forget_group_local(&group_id).await;
            if result.is_ok() {
                scheduled_convergence.note_success(&group_id);
            }
            if matches!(result, Ok(true)) {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::DeleteGroupLocal { group_id, respond } => Box::pin(async move {
            let result = client.delete_group_local(&group_id).await;
            if matches!(result, Ok(true)) {
                publish_app_runtime_group_state_updated(
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::GroupRecoveryStatus { group_id, respond } => Box::pin(async move {
            let _ = respond.send(group_recovery_after_hydration(client, &group_id));
            true
        }),
        AccountWorkerCommand::ConfirmGroupRejoin {
            welcome_id,
            token,
            respond,
        } => Box::pin(async move {
            let result = client.confirm_group_rejoin(&welcome_id, &token).await;
            publish_client_pending_projection_updates(
                client,
                events,
                account_id_hex,
                account_label,
            );
            publish_client_pending_applied_summary(client, events, account_id_hex, account_label);
            let _ = respond.send(result);
            true
        }),
        AccountWorkerCommand::DeclineGroupRejoin {
            welcome_id,
            respond,
        } => Box::pin(async move {
            let result = client.decline_group_rejoin(&welcome_id);
            publish_client_pending_projection_updates(
                client,
                events,
                account_id_hex,
                account_label,
            );
            let _ = respond.send(result);
            true
        }),
        AccountWorkerCommand::AcceptGroupInvite { group_id, respond } => Box::pin(async move {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            if retry_after_response {
                client
                    .retry_pending_push_registration_shares_best_effort()
                    .await;
            }
            true
        }),
        AccountWorkerCommand::DeclineGroupInvite { group_id, respond } => Box::pin(async move {
            let result = client.decline_group_invite(&group_id).await;
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::SetGroupArchived {
            group_id,
            archived,
            respond,
        } => Box::pin(async move {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::PromoteAdmin {
            group_id,
            member_ref,
            respond,
        } => Box::pin(async move {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::DemoteAdmin {
            group_id,
            member_ref,
            respond,
        } => Box::pin(async move {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::SelfDemoteAdmin { group_id, respond } => Box::pin(async move {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::UpdateGroupProfile {
            group_id,
            name,
            description,
            respond,
        } => Box::pin(async move {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::UpdateGroupImage {
            group_id,
            plaintext,
            media_type,
            respond,
        } => Box::pin(async move {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::DownloadGroupImage {
            admission,
            group_id,
            respond,
        } => Box::pin(async move {
            let permit = reserve_media_http(media_http);
            drop(admission);
            match client.prepare_group_image_download(&group_id).await {
                Ok(http) => spawn_media_http(media_http, permit, http.run(), move |result| {
                    MediaHttpCompletion::GroupImage { result, respond }
                }),
                Err(err) => {
                    let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, Err(err));
                }
            }
            true
        }),
        AccountWorkerCommand::SendMessageDraft {
            enqueued_at,
            queued,
            group_id,
            revision,
            attachments,
            respond,
        } => Box::pin(async move {
            if let Some(queued) = queued {
                queued.finish(TelemetryOutcome::Success);
            }
            let telemetry = shared.app_performance_telemetry();
            let execution = telemetry.observe(RuntimeOp::SendExecution);
            let send_started_at = Instant::now();
            telemetry.record(
                AppPerformanceOperation::OutboundMessageQueueWait,
                enqueued_at.elapsed(),
                true,
            );
            let mut first_projection = true;
            client.send_telemetry = Some(telemetry.clone());
            let result = client
                .send_message_draft_with_local_projection(
                    &group_id,
                    revision,
                    attachments,
                    |update| {
                        if first_projection {
                            telemetry.record(
                                AppPerformanceOperation::OutboundMessageLocalProjection,
                                enqueued_at.elapsed(),
                                true,
                            );
                            first_projection = false;
                        }
                        publish_app_runtime_projection_update(
                            events,
                            account_id_hex,
                            account_label,
                            update,
                        );
                    },
                )
                .await;
            client.send_telemetry = None;
            execution.finish_app(&result);
            telemetry.record(
                AppPerformanceOperation::OutboundMessageSend,
                send_started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::SendMessage {
            enqueued_at,
            queued,
            group_id,
            payload,
            respond,
        } => Box::pin(async move {
            if let Some(queued) = queued {
                queued.finish(TelemetryOutcome::Success);
            }
            let execution = shared
                .app_performance_telemetry()
                .observe(RuntimeOp::SendExecution);
            let send_started_at = Instant::now();
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::OutboundMessageQueueWait,
                enqueued_at.elapsed(),
                true,
            );
            let mut first_projection = true;
            client.send_telemetry = Some(shared.app_performance_telemetry());
            let result = client
                .send_with_local_projection(&group_id, &payload, |update| {
                    if first_projection {
                        shared.app_performance_telemetry().record(
                            AppPerformanceOperation::OutboundMessageLocalProjection,
                            enqueued_at.elapsed(),
                            true,
                        );
                        first_projection = false;
                    }
                    publish_app_runtime_projection_update(
                        events,
                        account_id_hex,
                        account_label,
                        update,
                    );
                })
                .await;
            client.send_telemetry = None;
            execution.finish_app(&result);
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::OutboundMessageSend,
                send_started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::SendAppEvent {
            enqueued_at,
            group_id,
            intent,
            respond,
        } => Box::pin(async move {
            let send_started_at = Instant::now();
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::OutboundMessageQueueWait,
                enqueued_at.elapsed(),
                true,
            );
            let mut first_projection = true;
            client.send_telemetry = Some(shared.app_performance_telemetry());
            let result = match intent {
                AppMessageIntent::Reaction {
                    target_message_id,
                    emoji,
                } => {
                    client
                        .react_to_message_with_local_projection(
                            &group_id,
                            &target_message_id,
                            &emoji,
                            |update| {
                                if first_projection {
                                    shared.app_performance_telemetry().record(
                                        AppPerformanceOperation::OutboundMessageLocalProjection,
                                        enqueued_at.elapsed(),
                                        true,
                                    );
                                    first_projection = false;
                                }
                                publish_app_runtime_projection_update(
                                    events,
                                    account_id_hex,
                                    account_label,
                                    update,
                                );
                            },
                        )
                        .await
                }
                intent => client
                    .send_app_event_with_local_projection(&group_id, intent, |update| {
                        if first_projection {
                            shared.app_performance_telemetry().record(
                                AppPerformanceOperation::OutboundMessageLocalProjection,
                                enqueued_at.elapsed(),
                                true,
                            );
                            first_projection = false;
                        }
                        publish_app_runtime_projection_update(
                            events,
                            account_id_hex,
                            account_label,
                            update,
                        );
                    })
                    .await
                    .map(|(_event, summary)| summary),
            };
            client.send_telemetry = None;
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::OutboundMessageSend,
                send_started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::BuildMediaImetaTag {
            group_id,
            reference,
            respond,
        } => Box::pin(async move {
            let result = client.build_media_imeta_tag(&group_id, &reference).await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::UploadMedia {
            admission,
            group_id,
            request,
            respond,
        } => Box::pin(async move {
            let started_at = Instant::now();
            let permit = reserve_media_http(media_http);
            drop(admission);
            match client
                .prepare_encrypted_media_upload(&group_id, request)
                .await
            {
                Ok((http, finish)) => {
                    spawn_media_http(media_http, permit, http.run(), move |result| {
                        MediaHttpCompletion::Upload {
                            finish,
                            result,
                            respond,
                            started_at,
                        }
                    })
                }
                Err(err) => {
                    shared.app_performance_telemetry().record(
                        AppPerformanceOperation::MediaUpload,
                        started_at.elapsed(),
                        false,
                    );
                    let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, Err(err));
                }
            }
            true
        }),
        AccountWorkerCommand::DownloadMedia {
            admission,
            group_id,
            reference,
            enqueued_at,
            respond,
        } => Box::pin(async move {
            let telemetry = shared.app_performance_telemetry();
            telemetry.record(
                AppPerformanceOperation::MediaDownloadQueueWait,
                enqueued_at.elapsed(),
                true,
            );
            let permit = reserve_media_http(media_http);
            drop(admission);
            let preparation_started = Instant::now();
            match client
                .prepare_encrypted_media_download(&group_id, reference)
                .await
            {
                Ok(http) => {
                    telemetry.record(
                        AppPerformanceOperation::MediaDownloadPreparation,
                        preparation_started.elapsed(),
                        true,
                    );
                    spawn_media_http(
                        media_http,
                        permit,
                        http.run(Some(telemetry)),
                        move |result| MediaHttpCompletion::Download {
                            result,
                            respond,
                            started_at: enqueued_at,
                        },
                    )
                }
                Err(err) => {
                    telemetry.record(
                        AppPerformanceOperation::MediaDownloadPreparation,
                        preparation_started.elapsed(),
                        false,
                    );
                    telemetry.record(
                        AppPerformanceOperation::MediaDownload,
                        enqueued_at.elapsed(),
                        false,
                    );
                    let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, Err(err));
                }
            }
            true
        }),
        AccountWorkerCommand::SecureDeleteExpiredPlaintext { group_id, respond } => {
            Box::pin(async move {
                let result = client.secure_delete_expired_plaintext_for_group(&group_id);
                let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
                true
            })
        }
        AccountWorkerCommand::SweepExpiredRetention { now_ms, respond } => Box::pin(async move {
            let result = client.sweep_expired_retention(now_ms);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::StartAgentTextStream {
            group_id,
            stream_id,
            parent_message_id,
            quic_candidates,
            respond,
        } => Box::pin(async move {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::FinishAgentTextStream {
            group_id,
            request,
            respond,
        } => Box::pin(async move {
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::RetryGroupConvergence { group_id, respond } => Box::pin(async move {
            let result = client.retry_group_convergence(&group_id).await;
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::PendingWelcomeDeliveries { respond } => Box::pin(async move {
            let result = client.pending_welcome_deliveries();
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::RedeliverWelcome {
            message_id_hex,
            respond,
        } => Box::pin(async move {
            let result = client.redeliver_welcome(&message_id_hex).await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::PublishKeyPackage { respond } => Box::pin(async move {
            let result = async {
                let key_package = client.publish_key_package().await?;
                Ok(key_package.bytes().len())
            }
            .await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::PublishSetupKeyPackage { respond } => Box::pin(async move {
            let started_at = Instant::now();
            let result = async {
                let key_package = client.publish_setup_key_package().await?;
                Ok(key_package.bytes().len())
            }
            .await;
            shared.app_performance_telemetry().record(
                AppPerformanceOperation::AccountInitialKeyPackagePublish,
                started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::RotateKeyPackage { respond } => Box::pin(async move {
            let result = async {
                let key_package = client.rotate_key_package().await?;
                Ok(key_package.bytes().len())
            }
            .await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::KeyPackageMaintenanceStatus { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.key_package_maintenance_status(),
            );
            true
        }),
        AccountWorkerCommand::DurablyOwnedKeyPackages { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.durably_owned_key_packages(),
            );
            true
        }),
        AccountWorkerCommand::MaintenanceStatus { group_id, respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.maintenance_status(&group_id),
            );
            true
        }),
        AccountWorkerCommand::ScheduleManualSelfUpdate { group_id, respond } => {
            Box::pin(async move {
                let _ = respond_diagnosed(
                    shared,
                    storage_permit.as_ref(),
                    respond,
                    client.schedule_manual_self_update(&group_id),
                );
                true
            })
        }
        AccountWorkerCommand::PeriodicMaintenancePolicy { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.periodic_maintenance_policy(),
            );
            true
        }),
        AccountWorkerCommand::SetPeriodicMaintenancePolicy { policy, respond } => {
            Box::pin(async move {
                let _ = respond_diagnosed(
                    shared,
                    storage_permit.as_ref(),
                    respond,
                    client.set_periodic_maintenance_policy(policy),
                );
                true
            })
        }
        AccountWorkerCommand::PauseMaintenance { respond } => Box::pin(async move {
            client.pause_maintenance();
            let _ = respond.send(Ok(()));
            true
        }),
        AccountWorkerCommand::ResumeMaintenance { respond } => Box::pin(async move {
            client.resume_maintenance();
            let _ = respond.send(Ok(()));
            true
        }),
        AccountWorkerCommand::RunDueMaintenance { respond } => Box::pin(async move {
            let result = client.run_due_maintenance().await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::SharePushRegistration { respond } => Box::pin(async move {
            let result = client.share_push_registration().await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::UpsertPushRegistration {
            platform,
            raw_token,
            server_pubkey_hex,
            relay_hint,
            respond,
        } => Box::pin(async move {
            let result = client
                .upsert_and_share_push_registration(
                    platform,
                    &raw_token,
                    &server_pubkey_hex,
                    relay_hint,
                )
                .await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::ClearPushRegistration { respond } => Box::pin(async move {
            let result = client.clear_and_share_push_registration().await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::SetNativePushEnabled { enabled, respond } => Box::pin(async move {
            let result = client
                .app
                .set_native_push_enabled(&client.state.label, enabled);
            let should_retry = result.is_ok();
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            if should_retry {
                client
                    .retry_pending_push_registration_shares_best_effort()
                    .await;
            }
            true
        }),
        AccountWorkerCommand::RemovePushRegistration {
            registration,
            respond,
        } => Box::pin(async move {
            let result = client.remove_push_registration(registration).await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::RetryPushRegistration { respond } => Box::pin(async move {
            let pending = client
                .retry_pending_push_registration_shares_best_effort()
                .await;
            let _ = respond.send(pending);
            true
        }),
        AccountWorkerCommand::DeleteAuditLog { path, respond } => Box::pin(async move {
            let result = client.rotate_audit_log_if_active(&path);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result);
            true
        }),
        AccountWorkerCommand::SetAuditRecording { enabled, respond } => Box::pin(async move {
            client.set_audit_recording(enabled);
            let _ = respond.send(Ok(()));
            true
        }),
    }
}

fn group_recovery_after_hydration(
    client: &mut AppClient,
    group_id: &GroupId,
) -> Result<crate::GroupRecoveryStatus, AppError> {
    client
        .runtime
        .session_mut()
        .ensure_group_hydrated(group_id)?;
    client.group_recovery_status(group_id)
}

pub(super) fn group_roster_after_hydration(
    client: &mut AppClient,
    group_id: &GroupId,
) -> Result<crate::groups::AppGroupRosterSession, AppError> {
    client
        .runtime
        .session_mut()
        .ensure_group_hydrated(group_id)?;
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

fn runtime_group_subscription_retry_base_delay() -> Duration {
    if cfg!(test) {
        Duration::from_millis(25)
    } else {
        Duration::from_secs(1)
    }
}

fn runtime_group_subscription_retry_max_delay() -> Duration {
    if cfg!(test) {
        Duration::from_millis(1_600)
    } else {
        Duration::from_secs(60)
    }
}

fn runtime_group_subscription_retry_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6);
    let multiplier = 1u32 << shift;
    runtime_group_subscription_retry_base_delay()
        .saturating_mul(multiplier)
        .min(runtime_group_subscription_retry_max_delay())
}

/// Bounded retry for an ordinary group-subscription rebuild that follows a
/// durable live ingest. The task speaks through the worker queue so it never
/// races the engine-owning [`AppClient`]; successful refresh disarms it.
struct ScheduledRuntimeGroupSubscriptionRefresh {
    timer_task: Option<JoinHandle<()>>,
}

impl ScheduledRuntimeGroupSubscriptionRefresh {
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
            self.arm(commands.clone());
        }
    }

    fn arm(&mut self, commands: mpsc::Sender<AccountWorkerCommand>) {
        if let Some(task) = self.timer_task.take() {
            task.abort();
        }
        self.timer_task = Some(tokio::spawn(async move {
            let mut attempt = 1u32;
            loop {
                sleep(runtime_group_subscription_retry_delay(attempt)).await;
                let (respond, response) = oneshot::channel();
                if commands
                    .send(AccountWorkerCommand::RetryRuntimeGroupSubscriptions { respond })
                    .await
                    .is_err()
                {
                    return;
                }
                match response.await {
                    Ok(true) => attempt = attempt.saturating_add(1),
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

impl Drop for ScheduledRuntimeGroupSubscriptionRefresh {
    fn drop(&mut self) {
        self.disarm();
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

#[cfg(test)]
static HELD_SCHEDULED_CONVERGENCE_ACCOUNTS: std::sync::LazyLock<Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));

#[cfg(test)]
fn scheduled_convergence_held_for_test(account_id_hex: &str) -> bool {
    HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
        .lock()
        .unwrap()
        .contains(account_id_hex)
}

#[cfg(not(test))]
fn scheduled_convergence_held_for_test(_account_id_hex: &str) -> bool {
    false
}

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
            ConvergenceScheduleState::PendingOutbound { retry_after_ms } => {
                // A waiting outbound queue keeps the wakeup armed on the
                // durable fanout's exact cutoff (or the normal delay for
                // queued/local-only work) but is not unsettled convergence:
                // it never feeds the re-arm cap. It also clears the counter:
                // this state means pending inputs are gone, so any prior
                // unopenable streak genuinely ended.
                self.retry_attempts.remove(group_id);
                self.unsettled_rearm_attempts.remove(group_id);
                let delay = retry_after_ms.map_or_else(
                    || self.normal_delay(),
                    |remaining_ms| {
                        Duration::from_millis(remaining_ms)
                            .max(MIN_CONVERGENCE_SETTLEMENT_DELAY)
                            .saturating_add(self.test_delay)
                    },
                );
                self.arm_no_later(group_id.clone(), TokioInstant::now() + delay);
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

    /// A host-provided usable-connectivity edge invalidates transport-failure
    /// backoff. Wake every already-scheduled group now; an in-window
    /// convergence pass will simply re-arm its true cutoff, while pending
    /// outbound work gets an immediate chance to drain. Reset only error
    /// retries so a relay that is still reconnecting starts again from the
    /// short backoff instead of returning directly to the 60-second cap.
    fn wake_after_connectivity_restored(&mut self) {
        if self.deadlines.is_empty() {
            return;
        }
        let now = TokioInstant::now();
        self.deadlines
            .values_mut()
            .for_each(|deadline| *deadline = now);
        self.retry_attempts.clear();
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

    fn has_ready(&self) -> bool {
        !self.deadlines.is_empty() && self.timer.deadline() <= TokioInstant::now()
    }

    fn take_ready(&mut self) -> Option<GroupId> {
        // One group per worker turn: a pass can await relay recovery, so taking
        // every overdue group would multiply that wait by the account's size.
        // Earliest-first keeps an unsettled group from jumping ahead when it
        // re-arms; undispatched groups retain their original deadlines.
        let next = self
            .deadlines
            .iter()
            .min_by(
                |(left_group, left_deadline), (right_group, right_deadline)| {
                    left_deadline
                        .cmp(right_deadline)
                        .then_with(|| left_group.as_slice().cmp(right_group.as_slice()))
                },
            )
            .map(|(group_id, _)| group_id.clone());
        let Some(group_id) = next else {
            self.reset_timer_to_earliest();
            return None;
        };
        self.deadlines.remove(&group_id);
        self.reset_timer_to_earliest();
        Some(group_id)
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

/// Start the temporary full-history subscription only after the caller has
/// published the summary containing `GroupJoined`. This ordering makes the
/// durable group visible even when relay subscription installation is slow or
/// fails; the existing maintenance tick retries any obligation still in its
/// `CatchUp` phase without changing the engine's grace/quiet/jitter policy.
async fn start_post_join_history_after_visibility(
    client: &mut AppClient,
    summary: &SyncSummary,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
) {
    if summary.joined_groups.is_empty() {
        return;
    }
    // Visibility is already published. Install ordinary live interest now,
    // independently of the history owner's cooldown. Waiting for the retry
    // timer leaves a newly joined account unrouted while another local account
    // can already receive the SDK's single deduplicated copy of a group event.
    // Failures retain the existing bounded registration-retry intent.
    if let Err(error) = client
        .retry_pending_runtime_group_subscription_refresh()
        .await
    {
        publish_app_runtime_account_error(
            events,
            account_id_hex,
            account_label,
            account_error_message("post-join live subscription refresh failed", &error),
        );
    }
    if let Err(error) = client.advance_post_join_maintenance_subscriptions().await {
        publish_app_runtime_account_error(
            events,
            account_id_hex,
            account_label,
            account_error_message("post-join maintenance subscription failed", &error),
        );
    }
}

fn publish_sync_summary_with_audit(
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    summary: &SyncSummary,
    shared: &RuntimeSharedServices,
    audit_trigger: &'static str,
) {
    publish_app_runtime_summary(events, account_id_hex, account_label, summary);
    if sync_summary_triggers_audit_tracker_update(summary) {
        shared.schedule_audit_log_tracker_update(audit_trigger);
    }
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
/// reporting behavior. A deferred result is deliberately accepted only after
/// the caller's ordinary sync has completed; the distinct outcome keeps that
/// policy choice visible instead of conflating deferral with no pending work.
/// Explicit full-history repair already performed the unfloored replay and
/// consumes the same intent without calling this helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyPackageMaintenanceCatchUpOutcome {
    Completed,
    Failed,
    TimedOut,
}
impl KeyPackageMaintenanceCatchUpOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "success",
            Self::Failed => "failure",
            Self::TimedOut => "timeout",
        }
    }
}

async fn run_pending_epoch_backfill_reporting_arm(
    client: &mut AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    shared: &RuntimeSharedServices,
    seam: EpochBackfillExecutionSeam,
) -> Result<(), AccountCatchUpFailure> {
    let backfill_armed = client.has_pending_epoch_backfill();
    let observation = backfill_armed
        .then(|| {
            shared.product_analytics.begin(
                crate::ProductFamily::Recovery,
                "backfill",
                crate::ProductUnit::Attempt,
            )
        })
        .flatten();
    let backfill_result = client.run_pending_epoch_backfill(seam).await;
    if let Some(observation) = observation {
        observation.finish(match &backfill_result {
            Ok(EpochBackfillRunOutcome::Completed(_)) => "success",
            Ok(EpochBackfillRunOutcome::Incomplete(_)) => "partial",
            Ok(EpochBackfillRunOutcome::Deferred) => "deferred",
            Ok(EpochBackfillRunOutcome::NotPending) => "no_work_due",
            Err(_) => "failure",
        });
    }
    let result = match backfill_result {
        // An incomplete replay published the same real summary: it ingested
        // whatever it reached before the relays failed to confirm they had
        // served the account's stored history. Its intent stays pending, so the
        // next seam retries it; nothing here needs to report a worker failure.
        Ok(
            EpochBackfillRunOutcome::Completed(summary)
            | EpochBackfillRunOutcome::Incomplete(summary),
        ) => {
            publish_app_runtime_summary(events, account_id_hex, account_label, &summary);
            Ok(())
        }
        Ok(EpochBackfillRunOutcome::Deferred | EpochBackfillRunOutcome::NotPending) => Ok(()),
        Err(error) => {
            let message = account_error_message("epoch-gap backfill failed", &error);
            publish_app_runtime_account_error(
                events,
                account_id_hex,
                account_label,
                message.clone(),
            );
            // run_pending_epoch_backfill returns only AppError, after several
            // distinct sync boundaries. Preserve its typed broad cause but do
            // not derive a stage from that cause.
            Err(AccountCatchUpFailure::new(
                message,
                SyncFailureClassification::new(SyncFailureStage::Unknown, error.sync_error_class()),
            ))
        }
    };
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

pub(super) fn publish_app_runtime_projection_update(
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
    for group_id in client.pending_recovery_status_updates.drain() {
        publish_app_runtime_group_state_updated(events, account_id_hex, account_label, &group_id);
    }
    // Superseded own commits ride the same drain: every worker seam that can
    // observe convergence effects already flushes projection updates here.
    for report in client.take_pending_superseded_change_events() {
        let _ = events.send(MarmotAppEvent::GroupChangeSuperseded {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            group_id: report.group_id,
            commit_id_hex: hex::encode(report.commit_id.as_slice()),
            kind: report.kind,
            outcome: report.outcome,
            reason: report.reason,
        });
    }
}

/// Broadcast group events a send applied as a side effect (retained inbound
/// convergence commits folded before publishing). Called from every worker seam
/// that can run a send — the command chokepoint, the receive arm's post-join
/// push retry, the maintenance tick, and startup — so the applied events reach
/// chat-list/group-state subscribers instead of buffering indefinitely. A no-op
/// when the buffered summary is empty.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupKeyPackagePriority {
    PublishExactDurableInitial,
    Skip,
}

fn setup_key_package_priority(
    state: Result<Option<AccountSetupState>, AccountHomeError>,
) -> Result<SetupKeyPackagePriority, AppError> {
    let publish = state?.is_some_and(|state| {
        state.kind == AccountSetupKind::GeneratedIdentity
            && matches!(
                state.phase,
                AccountSetupPhase::LocalReady
                    | AccountSetupPhase::BootstrapPublicationStarted
                    | AccountSetupPhase::BootstrapPublicationConfirmed
                    | AccountSetupPhase::KeyPackagePublicationStarted
            )
    });
    Ok(if publish {
        SetupKeyPackagePriority::PublishExactDurableInitial
    } else {
        SetupKeyPackagePriority::Skip
    })
}

/// Build a [`RuntimeAccountError`] message from a static prefix and the
/// error's privacy-safe kind. These messages leave the runtime: the CLI daemon
/// persists them into `wn daemon status --json` and the TUI, and host apps may
/// log them. Never interpolate the raw error — `AppError::Transport` Display
/// can embed relay URLs, which the privacy invariant forbids surfacing.
fn account_error_message(prefix: &str, err: &AppError) -> String {
    format!("{prefix}: {}", err.privacy_safe_kind())
}

fn bounded_admission_test_paused(
    shared: &RuntimeSharedServices,
    job: Option<&bounded_recovery::Job>,
) -> bool {
    #[cfg(test)]
    {
        job.is_some_and(|job| {
            shared
                .bounded_pause_before_admission
                .load(std::sync::atomic::Ordering::SeqCst)
                || (shared
                    .bounded_pause_after_first_admission
                    .load(std::sync::atomic::Ordering::SeqCst)
                    && job.has_admitted_prefix())
        })
    }
    #[cfg(not(test))]
    {
        let _ = (shared, job);
        false
    }
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

    mod real_sdk_bounded_tests;
    mod real_sdk_progress_fairness_tests;

    static BOUNDED_WORKER_FIXTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    use marmot_account::AccountHome;

    use crate::client::epoch_stall::BackfillDecision;
    use crate::tests::{
        ScriptedPushRelayClient, bounded_epoch_backfill_config, client_on_app_relay_plane,
        every_subscription, scripted_eose_pump,
    };
    use crate::{AuditLogSettings, MarmotApp};
    use marmot_forensics::{EpochBackfillExecutionSeam, EpochStallBackfillTrigger};

    fn setup_state(kind: AccountSetupKind, phase: AccountSetupPhase) -> AccountSetupState {
        AccountSetupState {
            account_id_hex: "00".repeat(32),
            reused_account_id_credential: false,
            kind,
            phase,
        }
    }

    #[tokio::test]
    async fn conversation_capture_retries_while_snapshot_work_owns_client_even_without_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let client = app.client("alice").await.unwrap();
        for available in [true, false] {
            let snapshot = available.then(|| client.group_read_snapshot().unwrap());
            let (commands, mut receiver) = mpsc::channel(8);
            let (respond, response) = oneshot::channel();
            commands
                .try_send(AccountWorkerCommand::CaptureConversation {
                    queued: None,
                    group_id: GroupId::new(vec![1; 16]),
                    query: Default::default(),
                    store_epoch: vec![],
                    observer: None,
                    respond,
                })
                .unwrap();
            let (release, work) = oneshot::channel::<()>();
            let mut pending = VecDeque::new();
            let serve = serve_snapshot_reads_until(
                snapshot,
                work,
                &mut receiver,
                &mut pending,
                &app,
                "alice",
            );
            let check = async {
                assert!(matches!(
                    timeout(Duration::from_secs(1), response)
                        .await
                        .unwrap()
                        .unwrap(),
                    Err(ConversationWindowError::NotReady)
                ));
                release.send(()).unwrap();
            };
            let (result, ()) = tokio::join!(serve, check);
            result.unwrap();
            assert!(
                pending.is_empty(),
                "captures must not queue behind stalled work"
            );
        }
    }

    #[tokio::test]
    async fn reads_bypass_deferred_work() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let client = app.client("alice").await.unwrap();
        let snapshot = client.group_read_snapshot().unwrap();
        let (commands, mut receiver) = mpsc::channel(8);
        let (respond, mut mutation) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::ConnectivityRestored { respond })
            .unwrap();
        let (respond, read) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::QuarantinedGroups { respond })
            .unwrap();
        let (release, work) = oneshot::channel::<()>();
        let mut pending = VecDeque::new();
        let serve = serve_snapshot_reads_until(
            Some(snapshot),
            work,
            &mut receiver,
            &mut pending,
            &app,
            "alice",
        );
        let check = async {
            assert!(
                timeout(Duration::from_secs(1), read)
                    .await
                    .expect("snapshot read must finish while work is held")
                    .unwrap()
                    .unwrap()
                    .is_empty()
            );
            assert!(matches!(
                mutation.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            release.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(serve, check);
        result.unwrap();
        assert_eq!(pending.len(), 1);
        assert!(matches!(
            pending.pop_front(),
            Some(AccountWorkerCommand::ConnectivityRestored { .. })
        ));
    }

    #[tokio::test]
    async fn bounded_known_group_acquisition_wait_keeps_worker_and_live_subscriptions_available() {
        let _bounded_fixture = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
        use storage_sqlite::RecoveryRequest;
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let bob = home.create_account("bob").unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
        let runtime = super::super::MarmotAppRuntime::new(app.clone());
        runtime
            .shared_services()
            .bounded_group_recovery_enabled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        runtime.reconcile_accounts().await.unwrap();
        runtime.publish_key_package("bob").await.unwrap();
        let group = runtime
            .create_group_with_options(
                "alice",
                "bounded",
                std::slice::from_ref(&bob.account_id_hex),
                AppCreateGroupOptions {
                    relays: Some(vec![
                        "wss://relay.example".into(),
                        "wss://relay-two.example".into(),
                    ]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        runtime.catch_up_accounts().await.unwrap();
        runtime
            .accounts()
            .workers
            .lock()
            .await
            .remove(&bob.account_id_hex)
            .unwrap()
            .shutdown()
            .await;
        runtime
            .send_message("alice", &group, b"known but unreceived".to_vec())
            .await
            .unwrap();
        let historical = relay
            .last_published_group_event()
            .expect("real group ciphertext was published");
        let event_id: [u8; 32] = hex::decode(&historical.id).unwrap().try_into().unwrap();
        let storage = app.account_storage("bob").unwrap();
        let group_route = match historical.to_transport_message().unwrap().envelope {
            cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id } => {
                storage_sqlite::TransportReconciliationRoute::Group(
                    transport_group_id.try_into().unwrap(),
                )
            }
            _ => unreachable!("published event is group ciphertext"),
        };
        assert!(
            !storage
                .retained_recovery_event(&group_route, &event_id, None, historical.created_at)
                .unwrap(),
            "the controlled SDK has seen this ID, but MDK has not retained it"
        );
        runtime.reconcile_accounts().await.unwrap();
        storage
            .request_recovery(
                RecoveryRequest::KnownEvent {
                    group_id: group.as_slice(),
                    event_id: &event_id,
                },
                crate::client::recovery::wall_now_ms().unwrap(),
            )
            .unwrap();
        *relay.acquisition_result.lock().unwrap() =
            Some(transport_nostr_adapter::NostrAcquisitionResult {
                endpoints:
                    ["wss://relay.example", "wss://relay-two.example"]
                        .into_iter()
                        .map(
                            |endpoint| {
                                transport_nostr_adapter::NostrAcquisitionEndpoint {
                    endpoint: cgka_traits::TransportEndpoint(endpoint.into()),
                    session_generation: Some(1),
                    events: vec![historical.clone()],
                    end: transport_nostr_adapter::NostrAcquisitionEnd::RequestPolicySatisfied,
                    stats: Default::default(),
                }
                            },
                        )
                        .collect(),
            });
        relay
            .acquisition_block
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let commands = runtime.accounts().worker_commands("bob").await.unwrap();
        let (respond, advanced) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::AdvanceRecoveryClock {
                elapsed: Duration::from_secs(600),
                respond,
            })
            .unwrap();
        timeout(Duration::from_secs(5), advanced)
            .await
            .unwrap()
            .unwrap();
        let (respond, response) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::GroupRecoveryStatus {
                group_id: group.clone(),
                respond,
            })
            .unwrap();
        timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(5), relay.acquisition_entered.notified())
            .await
            .expect("owner-authorized acquisition starts");
        let subscriptions = relay.subscription_count();
        timeout(
            Duration::from_secs(5),
            runtime.send_message("bob", &group, b"live while history waits".to_vec()),
        )
        .await
        .expect("queued send must not wait for EOSE")
        .unwrap();
        timeout(Duration::from_secs(5), async {
            loop {
                if app.messages("alice").unwrap().iter().any(|message| {
                    message.group_id_hex == hex::encode(&group)
                        && message.plaintext == "live while history waits"
                }) {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("live projection continues while history waits");
        runtime
            .send_message("alice", &group, b"incoming while history waits".to_vec())
            .await
            .unwrap();
        timeout(Duration::from_secs(5), async {
            loop {
                if app.messages("bob").unwrap().iter().any(|message| {
                    message.group_id_hex == hex::encode(&group)
                        && message.plaintext == "incoming while history waits"
                }) {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("acquiring account projects live input while history waits");
        let bob_commands = runtime.accounts().worker_commands("alice").await.unwrap();
        let (respond, response) = oneshot::channel();
        bob_commands
            .try_send(AccountWorkerCommand::QuarantinedGroups { respond })
            .unwrap();
        timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            relay.subscription_count(),
            subscriptions,
            "bounded history does not rebuild live interests"
        );
        assert_eq!(
            relay
                .acquisition_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.known_event_id == Some(event_id))
        );
        relay.acquisition_release.notify_one();
        timeout(Duration::from_secs(5), async {
            loop {
                if storage
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .all(|demand| demand.known_event_id != Some(event_id))
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("known event becomes durably disposed after duplicate copies");
        assert!(
            storage
                .retained_recovery_event(&group_route, &event_id, None, historical.created_at)
                .unwrap()
        );
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn bounded_three_relay_scope_leaves_legacy_attempt_eligible() {
        let _bounded_fixture = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
        use storage_sqlite::RecoveryRequest;
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let bob = home.create_account("bob").unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
        let runtime = super::super::MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        runtime.publish_key_package("bob").await.unwrap();
        let group = runtime
            .create_group_with_options(
                "alice",
                "three relays",
                std::slice::from_ref(&bob.account_id_hex),
                AppCreateGroupOptions {
                    relays: Some(vec![
                        "wss://relay.example".into(),
                        "wss://relay-two.example".into(),
                        "wss://relay-three.example".into(),
                    ]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        runtime.catch_up_accounts().await.unwrap();
        runtime
            .accounts()
            .workers
            .lock()
            .await
            .remove(&bob.account_id_hex)
            .unwrap()
            .shutdown()
            .await;
        runtime
            .send_message("alice", &group, b"known but unreceived".to_vec())
            .await
            .unwrap();
        let historical = relay.last_published_group_event().unwrap();
        let event_id: [u8; 32] = hex::decode(&historical.id).unwrap().try_into().unwrap();
        let storage = app.account_storage("bob").unwrap();
        storage
            .request_recovery(
                RecoveryRequest::KnownEvent {
                    group_id: group.as_slice(),
                    event_id: &event_id,
                },
                crate::client::recovery::wall_now_ms().unwrap(),
            )
            .unwrap();
        let mut client = app.client("bob").await.unwrap();
        client.recovery_owner.test_advance_to_retry(&storage);
        let before = storage.recovery_retry_state().unwrap();
        assert!(
            bounded_recovery::prepare(&mut client, EpochBackfillExecutionSeam::Maintenance)
                .unwrap()
                .is_none()
        );
        let after = storage.recovery_retry_state().unwrap();
        assert_eq!(after.attempt_serial, before.attempt_serial);
        assert_eq!(after.not_before_ms, before.not_before_ms);
        assert_eq!(
            relay
                .acquisition_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        let grant = client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .expect("legacy executor remains eligible for the full route");
        assert!(grant.plan().unwrap().iter().any(|obligation| {
            obligation.scopes.iter().any(|scope| {
                scope.goal.known_event_id == Some(event_id)
                    && scope.goal.required_endpoints.len() == 3
            })
        }));
        drop(grant);
        drop(client);
        runtime.shutdown().await;
    }

    struct BoundedKnownFixture {
        _dir: tempfile::TempDir,
        app: MarmotApp,
        runtime: super::super::MarmotAppRuntime,
        relay: Arc<ScriptedPushRelayClient>,
        group: GroupId,
        historical: transport_nostr_peeler::NostrTransportEvent,
        event_id: [u8; 32],
        route: storage_sqlite::TransportReconciliationRoute,
        demand_id: [u8; 16],
    }

    async fn bounded_known_fixture() -> BoundedKnownFixture {
        bounded_known_fixture_with_delay(None).await
    }

    async fn bounded_known_fixture_with_delay(delay_ms: Option<u64>) -> BoundedKnownFixture {
        use storage_sqlite::RecoveryRequest;
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let bob = home.create_account("bob").unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let mut config = crate::MarmotAppConfig::default();
        if let Some(delay_ms) = delay_ms {
            config = config
                .with_dev_settlement_quiescence_ms(100)
                .with_dev_scheduled_convergence_delay_ms(delay_ms);
        }
        let app = MarmotApp::with_relay_and_config(dir.path(), "wss://relay.example", config)
            .with_test_relay_client(relay.clone());
        crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
        let runtime = super::super::MarmotAppRuntime::new(app.clone());
        runtime
            .shared_services()
            .bounded_group_recovery_enabled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        runtime.reconcile_accounts().await.unwrap();
        runtime.publish_key_package("bob").await.unwrap();
        let group = runtime
            .create_group_with_options(
                "alice",
                "bounded fixture",
                std::slice::from_ref(&bob.account_id_hex),
                AppCreateGroupOptions {
                    relays: Some(vec![
                        "wss://relay.example".into(),
                        "wss://relay-two.example".into(),
                    ]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        runtime.catch_up_accounts().await.unwrap();
        runtime
            .accounts()
            .workers
            .lock()
            .await
            .remove(&bob.account_id_hex)
            .unwrap()
            .shutdown()
            .await;
        runtime
            .send_message("alice", &group, b"known but unreceived".to_vec())
            .await
            .unwrap();
        let historical = relay.last_published_group_event().unwrap();
        let event_id: [u8; 32] = hex::decode(&historical.id).unwrap().try_into().unwrap();
        let storage = app.account_storage("bob").unwrap();
        let route = match historical.to_transport_message().unwrap().envelope {
            cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id } => {
                storage_sqlite::TransportReconciliationRoute::Group(
                    transport_group_id.try_into().unwrap(),
                )
            }
            _ => unreachable!(),
        };
        runtime.reconcile_accounts().await.unwrap();
        let demand_id = storage
            .request_recovery(
                RecoveryRequest::KnownEvent {
                    group_id: group.as_slice(),
                    event_id: &event_id,
                },
                crate::client::recovery::wall_now_ms().unwrap(),
            )
            .unwrap()
            .id;
        BoundedKnownFixture {
            _dir: dir,
            app,
            runtime,
            relay,
            group,
            historical,
            event_id,
            route,
            demand_id,
        }
    }

    async fn advance_bounded_fixture_clock(fixture: &BoundedKnownFixture) {
        let commands = fixture
            .runtime
            .accounts()
            .worker_commands("bob")
            .await
            .unwrap();
        let (respond, advanced) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::AdvanceRecoveryClock {
                elapsed: Duration::from_secs(600),
                respond,
            })
            .unwrap();
        timeout(Duration::from_secs(5), advanced)
            .await
            .unwrap()
            .unwrap();
    }

    async fn wake_bounded_fixture(fixture: &BoundedKnownFixture) {
        advance_bounded_fixture_clock(fixture).await;
        let commands = fixture
            .runtime
            .accounts()
            .worker_commands("bob")
            .await
            .unwrap();
        let (respond, response) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::GroupRecoveryStatus {
                group_id: fixture.group.clone(),
                respond,
            })
            .unwrap();
        timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    fn controlled_bounded_result(
        left: Vec<transport_nostr_peeler::NostrTransportEvent>,
        left_end: transport_nostr_adapter::NostrAcquisitionEnd,
        right: Vec<transport_nostr_peeler::NostrTransportEvent>,
        right_end: transport_nostr_adapter::NostrAcquisitionEnd,
    ) -> transport_nostr_adapter::NostrAcquisitionResult {
        transport_nostr_adapter::NostrAcquisitionResult {
            endpoints: [
                ("wss://relay.example", left, left_end),
                ("wss://relay-two.example", right, right_end),
            ]
            .into_iter()
            .map(
                |(endpoint, events, end)| transport_nostr_adapter::NostrAcquisitionEndpoint {
                    endpoint: cgka_traits::TransportEndpoint(endpoint.into()),
                    session_generation: Some(1),
                    events,
                    end,
                    stats: Default::default(),
                },
            )
            .collect::<Vec<_>>(),
        }
    }

    #[tokio::test]
    async fn bounded_saturation_preserves_demand_then_partial_result_admits_known_event() {
        let _bounded_fixture = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
        use storage_sqlite::RecoveryScopeOutcome;
        use transport_nostr_adapter::NostrAcquisitionEnd;
        let fixture = bounded_known_fixture().await;
        let storage = fixture.app.account_storage("bob").unwrap();
        *fixture.relay.acquisition_result.lock().unwrap() = Some(controlled_bounded_result(
            vec![fixture.historical.clone(); bounded_recovery::MAX_EVENTS_PER_ENDPOINT + 1],
            NostrAcquisitionEnd::ItemLimitReached,
            Vec::new(),
            NostrAcquisitionEnd::Deadline,
        ));
        fixture
            .relay
            .acquisition_block
            .store(true, std::sync::atomic::Ordering::SeqCst);
        wake_bounded_fixture(&fixture).await;
        timeout(
            Duration::from_secs(5),
            fixture.relay.acquisition_entered.notified(),
        )
        .await
        .unwrap();
        fixture.relay.acquisition_release.notify_one();
        timeout(Duration::from_secs(5), async {
            loop {
                if storage
                    .recovery_scope_snapshots(fixture.demand_id)
                    .unwrap()
                    .iter()
                    .any(|scope| {
                        scope
                            .checkpoints
                            .iter()
                            .any(|checkpoint| checkpoint.outcome == RecoveryScopeOutcome::Unknown)
                    })
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("saturated response checkpoints without admission");
        assert!(
            !storage
                .retained_recovery_event(
                    &fixture.route,
                    &fixture.event_id,
                    None,
                    fixture.historical.created_at
                )
                .unwrap()
        );
        assert!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.ticket.id == fixture.demand_id)
        );
        let probes = fixture
            .runtime
            .shared_services()
            .bounded_preparation_probes
            .load(std::sync::atomic::Ordering::SeqCst);
        let retry = storage.recovery_retry_state().unwrap();
        let commands = fixture
            .runtime
            .accounts()
            .worker_commands("bob")
            .await
            .unwrap();
        for _ in 0..24 {
            let (respond, response) = oneshot::channel();
            commands
                .try_send(AccountWorkerCommand::GroupRecoveryStatus {
                    group_id: fixture.group.clone(),
                    respond,
                })
                .unwrap();
            timeout(Duration::from_secs(5), response)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        assert_eq!(
            fixture
                .runtime
                .shared_services()
                .bounded_preparation_probes
                .load(std::sync::atomic::Ordering::SeqCst),
            probes,
            "live command bursts do not re-run bounded preparation during owner cooldown"
        );
        assert_eq!(storage.recovery_retry_state().unwrap(), retry);

        fixture.runtime.shutdown().await;

        let partial = bounded_known_fixture().await;
        let partial_storage = partial.app.account_storage("bob").unwrap();
        *partial.relay.acquisition_result.lock().unwrap() = Some(controlled_bounded_result(
            vec![partial.historical.clone()],
            NostrAcquisitionEnd::RequestPolicySatisfied,
            Vec::new(),
            NostrAcquisitionEnd::Deadline,
        ));
        wake_bounded_fixture(&partial).await;
        timeout(Duration::from_secs(5), async {
            loop {
                if partial_storage
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .all(|demand| demand.ticket.id != partial.demand_id)
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("partial relay result retains exact known event");
        assert!(
            partial_storage
                .retained_recovery_event(
                    &partial.route,
                    &partial.event_id,
                    None,
                    partial.historical.created_at
                )
                .unwrap()
        );
        assert_eq!(
            partial
                .relay
                .acquisition_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        partial.runtime.shutdown().await;
    }

    #[tokio::test]
    async fn bounded_stale_loss_and_route_results_cannot_clear_known_demand() {
        let _bounded_fixture = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
        use transport_nostr_adapter::NostrAcquisitionEnd;
        for new_loss in [true, false] {
            let fixture = bounded_known_fixture().await;
            let storage = fixture.app.account_storage("bob").unwrap();
            let before = storage.recovery_revision_fence().unwrap();
            *fixture.relay.acquisition_result.lock().unwrap() = Some(controlled_bounded_result(
                vec![fixture.historical.clone()],
                NostrAcquisitionEnd::RequestPolicySatisfied,
                Vec::new(),
                NostrAcquisitionEnd::Deadline,
            ));
            fixture
                .relay
                .acquisition_block
                .store(true, std::sync::atomic::Ordering::SeqCst);
            wake_bounded_fixture(&fixture).await;
            timeout(
                Duration::from_secs(5),
                fixture.relay.acquisition_entered.notified(),
            )
            .await
            .unwrap();
            if new_loss {
                storage
                    .record_account_delivery_loss("bob", 777, 1, crate::unix_now_seconds())
                    .unwrap();
                storage.synchronize_account_delivery_loss("bob").unwrap();
            } else {
                storage.observe_recovery_route_snapshot([0xAA; 32]).unwrap();
            }
            let changed = storage.recovery_revision_fence().unwrap();
            assert!(if new_loss {
                changed.loss_revision > before.loss_revision
            } else {
                changed.route_revision > before.route_revision
            });
            fixture.relay.acquisition_release.notify_one();
            timeout(
                Duration::from_secs(5),
                fixture
                    .runtime
                    .shared_services()
                    .bounded_recovery_finished
                    .notified(),
            )
            .await
            .expect("stale result finishes without admission");
            assert!(
                !storage
                    .retained_recovery_event(
                        &fixture.route,
                        &fixture.event_id,
                        None,
                        fixture.historical.created_at,
                    )
                    .unwrap()
            );
            assert!(
                storage
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .any(|demand| demand.ticket.id == fixture.demand_id)
            );
            fixture.runtime.shutdown().await;
        }
    }

    #[tokio::test]
    async fn bounded_shutdown_after_durable_prefix_preserves_pending_demand_on_reopen() {
        let _bounded_fixture = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
        use transport_nostr_adapter::NostrAcquisitionEnd;
        let fixture = bounded_known_fixture().await;
        fixture
            .runtime
            .shared_services()
            .bounded_pause_after_first_admission
            .store(true, std::sync::atomic::Ordering::SeqCst);
        *fixture.relay.acquisition_result.lock().unwrap() = Some(controlled_bounded_result(
            vec![fixture.historical.clone(), fixture.historical.clone()],
            NostrAcquisitionEnd::RequestPolicySatisfied,
            Vec::new(),
            NostrAcquisitionEnd::Deadline,
        ));
        wake_bounded_fixture(&fixture).await;
        timeout(
            Duration::from_secs(5),
            fixture
                .runtime
                .shared_services()
                .bounded_prefix_admitted
                .notified(),
        )
        .await
        .expect("first input is durably admitted before the next worker turn");
        let storage = fixture.app.account_storage("bob").unwrap();
        assert!(
            storage
                .retained_recovery_event(
                    &fixture.route,
                    &fixture.event_id,
                    None,
                    fixture.historical.created_at,
                )
                .unwrap()
        );
        assert!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.ticket.id == fixture.demand_id),
            "an uncheckpointed exact ID remains retryable after its durable prefix"
        );
        fixture.runtime.shutdown().await;
        assert_eq!(
            bounded_recovery::available_credits(),
            bounded_recovery::MAX_CONCURRENT_JOBS
        );
        drop(storage);

        let reopened = MarmotApp::with_relay(fixture._dir.path(), "wss://relay.example")
            .with_test_relay_client(fixture.relay.clone());
        let reopened_storage = reopened.account_storage("bob").unwrap();
        assert!(
            reopened_storage
                .retained_recovery_event(
                    &fixture.route,
                    &fixture.event_id,
                    None,
                    fixture.historical.created_at,
                )
                .unwrap()
        );
        assert!(
            reopened_storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.ticket.id == fixture.demand_id)
        );
    }

    #[tokio::test]
    async fn bounded_shutdown_before_admission_reopens_unretained_demand() {
        let _bounded_fixture = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
        use transport_nostr_adapter::NostrAcquisitionEnd;
        let fixture = bounded_known_fixture().await;
        fixture
            .runtime
            .shared_services()
            .bounded_pause_before_admission
            .store(true, std::sync::atomic::Ordering::SeqCst);
        *fixture.relay.acquisition_result.lock().unwrap() = Some(controlled_bounded_result(
            vec![fixture.historical.clone()],
            NostrAcquisitionEnd::RequestPolicySatisfied,
            Vec::new(),
            NostrAcquisitionEnd::Deadline,
        ));
        advance_bounded_fixture_clock(&fixture).await;
        timeout(
            Duration::from_secs(5),
            fixture
                .runtime
                .shared_services()
                .bounded_result_ready
                .notified(),
        )
        .await
        .expect("network result is owned but admission is paused");
        let storage = fixture.app.account_storage("bob").unwrap();
        let attempt = storage.recovery_retry_state().unwrap().attempt_serial;
        assert!(
            !storage
                .retained_recovery_event(
                    &fixture.route,
                    &fixture.event_id,
                    None,
                    fixture.historical.created_at,
                )
                .unwrap()
        );
        assert!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.ticket.id == fixture.demand_id)
        );
        fixture.runtime.shutdown().await;
        assert_eq!(
            bounded_recovery::available_credits(),
            bounded_recovery::MAX_CONCURRENT_JOBS
        );
        drop(storage);

        let reopened = MarmotApp::with_relay(fixture._dir.path(), "wss://relay.example")
            .with_test_relay_client(fixture.relay.clone());
        let reopened_storage = reopened.account_storage("bob").unwrap();
        assert_eq!(
            reopened_storage
                .recovery_retry_state()
                .unwrap()
                .attempt_serial,
            attempt
        );
        assert!(
            !reopened_storage
                .retained_recovery_event(
                    &fixture.route,
                    &fixture.event_id,
                    None,
                    fixture.historical.created_at,
                )
                .unwrap()
        );
        assert!(
            reopened_storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.ticket.id == fixture.demand_id)
        );
    }

    #[tokio::test]
    #[cfg(feature = "test-policy-overrides")]
    async fn retained_multi_epoch_backlog_advances_while_bounded_history_waits() {
        let _bounded_fixture = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
        use cgka_traits::storage::ConvergencePassStorage;
        use transport_nostr_adapter::NostrAcquisitionEnd;
        let fixture = bounded_known_fixture_with_delay(Some(60_000)).await;
        let storage = fixture.app.account_storage("bob").unwrap();
        let initial_epoch = fixture
            .runtime
            .group_mls_state("bob", &fixture.group)
            .await
            .unwrap()
            .epoch;
        fixture
            .runtime
            .update_group_profile("alice", &fixture.group, Some("epoch one".into()), None)
            .await
            .unwrap();
        let first = fixture.relay.last_published_group_event().unwrap();
        fixture
            .runtime
            .update_group_profile("alice", &fixture.group, Some("epoch two".into()), None)
            .await
            .unwrap();
        let second = fixture.relay.last_published_group_event().unwrap();
        assert_ne!(first.id, second.id);
        timeout(Duration::from_secs(5), async {
            loop {
                let retained = [&first, &second].into_iter().all(|event| {
                    let id: [u8; 32] = hex::decode(&event.id).unwrap().try_into().unwrap();
                    storage
                        .retained_recovery_event(&fixture.route, &id, None, event.created_at)
                        .unwrap()
                });
                if retained && storage.convergence_pass(&fixture.group).unwrap().is_some() {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("two epoch inputs are retained before acquisition begins");
        let alice_tip = fixture
            .runtime
            .group_mls_state("alice", &fixture.group)
            .await
            .unwrap()
            .epoch;
        assert!(alice_tip >= initial_epoch + 2);
        assert!(
            fixture
                .runtime
                .group_mls_state("bob", &fixture.group)
                .await
                .unwrap()
                .epoch
                < alice_tip
        );
        *fixture.relay.acquisition_result.lock().unwrap() = Some(controlled_bounded_result(
            Vec::new(),
            NostrAcquisitionEnd::Deadline,
            Vec::new(),
            NostrAcquisitionEnd::Deadline,
        ));
        fixture
            .relay
            .acquisition_block
            .store(true, std::sync::atomic::Ordering::SeqCst);
        wake_bounded_fixture(&fixture).await;
        timeout(
            Duration::from_secs(5),
            fixture.relay.acquisition_entered.notified(),
        )
        .await
        .unwrap();
        let retry = storage.recovery_retry_state().unwrap();
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(120)).await;
        tokio::time::resume();
        timeout(Duration::from_secs(10), async {
            loop {
                if fixture
                    .runtime
                    .group_mls_state("bob", &fixture.group)
                    .await
                    .unwrap()
                    .epoch
                    > initial_epoch
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("first retained epoch advances without a recovery retry");
        // The next durable pass starts at the new engine epoch and needs its
        // own 100 ms local settlement window before the scheduled wake.
        sleep(Duration::from_millis(150)).await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(120)).await;
        tokio::time::resume();
        let converged = timeout(Duration::from_secs(30), async {
            loop {
                let epoch = fixture
                    .runtime
                    .group_mls_state("bob", &fixture.group)
                    .await
                    .unwrap()
                    .epoch;
                let profile = fixture
                    .app
                    .group("bob", &hex::encode(&fixture.group))
                    .unwrap()
                    .unwrap()
                    .profile
                    .name;
                if epoch >= alice_tip && profile == "epoch two" {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            converged.is_ok(),
            "retained backlog stalled: bob_epoch={}, alice_epoch={}, bob_profile={}, pass={}",
            fixture
                .runtime
                .group_mls_state("bob", &fixture.group)
                .await
                .unwrap()
                .epoch,
            alice_tip,
            fixture
                .app
                .group("bob", &hex::encode(&fixture.group))
                .unwrap()
                .unwrap()
                .profile
                .name,
            storage.convergence_pass(&fixture.group).unwrap().is_some()
        );
        assert_eq!(
            storage.recovery_retry_state().unwrap().attempt_serial,
            retry.attempt_serial
        );
        assert_eq!(
            fixture
                .relay
                .acquisition_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        fixture.relay.acquisition_release.notify_one();
        fixture.runtime.shutdown().await;
    }

    #[tokio::test]
    #[cfg(feature = "test-policy-overrides")]
    async fn due_convergence_interleaves_with_a_backlog_of_worker_commands() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let alice = home.create_account("alice").unwrap();
        let bob = home.create_account("bob").unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example",
            crate::MarmotAppConfig::default()
                .with_dev_settlement_quiescence_ms(100)
                .with_dev_scheduled_convergence_delay_ms(60_000)
                .with_dev_epoch_backfill_retry_backoff_ms(300_000),
        )
        .with_test_relay_client(relay.clone());
        crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
        let runtime = super::super::MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        runtime.publish_key_package("bob").await.unwrap();
        let first = runtime
            .create_group(
                "alice",
                "first",
                std::slice::from_ref(&bob.account_id_hex),
                None,
            )
            .await
            .unwrap();
        let second = runtime
            .create_group(
                "alice",
                "second",
                std::slice::from_ref(&bob.account_id_hex),
                None,
            )
            .await
            .unwrap();
        runtime.catch_up_accounts().await.unwrap();
        let commands = runtime.accounts().worker_commands("bob").await.unwrap();
        runtime
            .update_group_profile("alice", &first, Some("first changed".into()), None)
            .await
            .unwrap();
        runtime
            .update_group_profile("alice", &second, Some("second changed".into()), None)
            .await
            .unwrap();
        // Wait for durable evidence that both inbound commits have armed a pass,
        // rather than assuming the second delivery beats the first timer.
        use cgka_traits::storage::ConvergencePassStorage;
        let storage = app.account_storage("bob").unwrap();
        timeout(Duration::from_secs(30), async {
            loop {
                if storage.convergence_pass(&first).unwrap().is_some()
                    && storage.convergence_pass(&second).unwrap().is_some()
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("both inbound commits arm durable convergence passes");
        // Only Bob participates in the barrier and queue assertion. Alice's
        // real publications above already supplied all the recovery work.
        runtime
            .accounts()
            .workers
            .lock()
            .await
            .remove(&alice.account_id_hex)
            .unwrap()
            .shutdown()
            .await;
        // Lost history remains independent of the runnable local passes. The
        // account already owes the cooldown reserved by catch-up.
        let retry = storage.recovery_retry_state().unwrap();
        let activations = relay.subscription_count();
        storage
            .record_account_delivery_loss("bob", 771, 1, crate::unix_now_seconds())
            .unwrap();
        let first_pass = Arc::new(tokio::sync::Barrier::new(2));
        runtime
            .shared_services()
            .set_next_scheduled_convergence_barrier(first_pass.clone());
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(120)).await;
        tokio::time::resume();
        timeout(Duration::from_secs(30), first_pass.wait())
            .await
            .expect("first recovery pass starts with both group deadlines due");
        let next_pass = Arc::new(tokio::sync::Barrier::new(2));
        runtime
            .shared_services()
            .set_next_scheduled_convergence_barrier(next_pass.clone());
        let mut responses = Vec::new();
        for _ in 0..8 {
            let (respond, response) = oneshot::channel();
            commands
                .try_send(AccountWorkerCommand::GroupRecoveryStatus {
                    group_id: first.clone(),
                    respond,
                })
                .expect("the held worker's command queue has capacity");
            responses.push(response);
        }
        first_pass.wait().await;
        timeout(Duration::from_secs(30), next_pass.wait())
            .await
            .expect("recovery progresses despite queued commands");
        let queued_count = responses.len();
        let mut remaining = Vec::new();
        for mut response in responses {
            match response.try_recv() {
                Ok(result) => {
                    result.expect("a completed queued command must succeed");
                }
                Err(oneshot::error::TryRecvError::Empty) => remaining.push(response),
                Err(oneshot::error::TryRecvError::Closed) => {
                    panic!("the worker dropped a queued command without replying");
                }
            }
        }
        let completed = queued_count - remaining.len();
        assert!(
            completed <= 1,
            "a due group must run after at most one queued command, observed {completed}"
        );
        next_pass.wait().await;
        timeout(Duration::from_secs(5), async {
            for response in remaining {
                response
                    .await
                    .expect("the worker must reply to every queued command")
                    .expect("every queued command must succeed");
            }
        })
        .await
        .expect("recovery must not starve the queued commands");
        assert_eq!(
            storage.recovery_retry_state().unwrap(),
            retry,
            "both actual scheduled convergence passes preserve history retry cost"
        );
        assert_eq!(
            relay.subscription_count(),
            activations,
            "post-convergence and maintenance cannot bypass the owner cooldown"
        );
        assert!(
            storage
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|d| d.cause == storage_sqlite::RecoveryCause::QueueLoss)
        );
        runtime.drain_in_flight_work().await.unwrap();
        runtime.shutdown_and_close().await.unwrap();
    }

    #[tokio::test]
    async fn recovery_warning_notifications_survive_projection_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group_id = client
            .create_group("recovery notifications", &[])
            .await
            .unwrap();
        let epoch = client.runtime.group_record(&group_id).unwrap().epoch;
        let (events, mut received) = broadcast::channel(16);
        publish_client_pending_projection_updates(
            &mut client,
            &events,
            &account.account_id_hex,
            "alice",
        );
        while received.try_recv().is_ok() {}
        assert_eq!(
            client
                .epoch_stall
                .observe_resource_refusal(group_id.clone(), epoch, 1),
            BackfillDecision::Arm
        );
        // This test exercises notification delivery from a durable warning,
        // not qualification. Actual evidence counting is covered by the
        // qualified local-evaluation and storage certificate tests.
        client.epoch_stall.restore_wedge_evidence([(
            group_id.clone(),
            crate::client::epoch_stall::EpochStallEvidence {
                stalled_epoch: epoch.0,
                fruitless_completions: 3,
                fruitless_reported: true,
                last_arm_at_ms: 1,
            },
        )]);
        client.persist_epoch_stall_evidence([&group_id]);
        client
            .finish_scheduled_convergence_effects(
                &group_id,
                &marmot_account::AccountDeviceEffects::default(),
            )
            .await
            .unwrap();
        assert!(
            client.pending_group_projection_updates.is_empty(),
            "the checkpoint consumed the storage delta"
        );
        publish_client_pending_projection_updates(
            &mut client,
            &events,
            &account.account_id_hex,
            "alice",
        );
        assert!(
            matches!(received.try_recv().unwrap(), MarmotAppEvent::GroupStateUpdated { group_id: updated, .. } if updated == group_id)
        );
        assert!(
            client
                .group_recovery_status(&group_id)
                .unwrap()
                .automatic_recovery_failed
        );
        publish_client_pending_projection_updates(
            &mut client,
            &events,
            &account.account_id_hex,
            "alice",
        );
        assert!(
            received.try_recv().is_err(),
            "a status transition is broadcast once"
        );
        let effects = marmot_account::AccountDeviceEffects {
            events: vec![cgka_traits::engine::GroupEvent::GroupJoined {
                group_id: group_id.clone(),
                via_welcome: cgka_traits::MessageId::new(vec![1; 32]),
                welcomer: None,
                explicitly_confirmed: true,
            }],
            ..Default::default()
        };
        client.observe_recovery_health(&effects).unwrap();
        publish_client_pending_projection_updates(
            &mut client,
            &events,
            &account.account_id_hex,
            "alice",
        );
        assert!(
            matches!(received.try_recv().unwrap(), MarmotAppEvent::GroupStateUpdated { group_id: updated, .. } if updated == group_id)
        );
        assert!(
            !client
                .group_recovery_status(&group_id)
                .unwrap()
                .automatic_recovery_failed
        );
    }

    #[tokio::test]
    async fn rejoin_decisions_answer_during_startup_hydration() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let (events, _) = broadcast::channel(16);
        let mut deferred = Vec::new();
        let mut setup = None;
        let id = cgka_traits::MessageId::new(vec![0x75; 32]);
        let (respond, mut confirm) = oneshot::channel();
        handle_startup_hydration_command(
            &mut client,
            AccountWorkerCommand::ConfirmGroupRejoin {
                welcome_id: id.clone(),
                token: vec![0; 32],
                respond,
            },
            &mut deferred,
            &events,
            "",
            "alice",
            &mut setup,
        )
        .await;
        assert!(
            confirm
                .try_recv()
                .expect("confirm must answer without deferral")
                .is_err()
        );
        let (respond, mut decline) = oneshot::channel();
        handle_startup_hydration_command(
            &mut client,
            AccountWorkerCommand::DeclineGroupRejoin {
                welcome_id: id,
                respond,
            },
            &mut deferred,
            &events,
            "",
            "alice",
            &mut setup,
        )
        .await;
        assert!(
            decline
                .try_recv()
                .expect("decline must answer without deferral")
                .is_err()
        );
        assert!(
            deferred.is_empty(),
            "unrelated hydration must not retain rejoin decisions"
        );
    }

    #[test]
    fn generated_setup_priority_selects_the_exact_durable_initial_key_package() {
        for phase in [
            AccountSetupPhase::LocalReady,
            AccountSetupPhase::BootstrapPublicationStarted,
            AccountSetupPhase::BootstrapPublicationConfirmed,
            AccountSetupPhase::KeyPackagePublicationStarted,
        ] {
            assert_eq!(
                setup_key_package_priority(Ok(Some(setup_state(
                    AccountSetupKind::GeneratedIdentity,
                    phase,
                ))))
                .unwrap(),
                SetupKeyPackagePriority::PublishExactDurableInitial,
                "phase {phase:?} must select the lifecycle-owned initial KeyPackage"
            );
        }
    }

    #[test]
    fn setup_priority_rejects_imported_absent_and_terminal_states() {
        for phase in [
            AccountSetupPhase::LocalReady,
            AccountSetupPhase::BootstrapPublicationStarted,
            AccountSetupPhase::BootstrapPublicationConfirmed,
            AccountSetupPhase::KeyPackagePublicationStarted,
        ] {
            assert_eq!(
                setup_key_package_priority(Ok(Some(setup_state(
                    AccountSetupKind::ImportedIdentity,
                    phase,
                ))))
                .unwrap(),
                SetupKeyPackagePriority::Skip
            );
        }
        for phase in [
            AccountSetupPhase::LocalStateCreated,
            AccountSetupPhase::KeyPackagePublicationConfirmed,
        ] {
            assert_eq!(
                setup_key_package_priority(Ok(Some(setup_state(
                    AccountSetupKind::GeneratedIdentity,
                    phase,
                ))))
                .unwrap(),
                SetupKeyPackagePriority::Skip
            );
        }
        assert_eq!(
            setup_key_package_priority(Ok(None)).unwrap(),
            SetupKeyPackagePriority::Skip
        );
    }

    #[test]
    fn setup_state_lookup_failure_never_enters_the_publication_lane() {
        let error = setup_key_package_priority(Err(AccountHomeError::AccountSetupStateMissing))
            .expect_err("lookup failure must be surfaced");

        assert!(matches!(error, AppError::AccountHome(_)));
    }

    fn test_group_id(byte: u8) -> GroupId {
        GroupId::new(vec![byte])
    }

    fn media_http_context(
        limit: usize,
    ) -> (MediaHttpContext, mpsc::UnboundedReceiver<MediaHttpDone>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let (worker_lifetime, _) = watch::channel(());
        (
            MediaHttpContext {
                product: Default::default(),
                tx,
                permits: Arc::new(Semaphore::new(limit)),
                prepared_group_image_uploads: Arc::new(Mutex::new(HashSet::new())),
                worker_lifetime,
            },
            rx,
        )
    }

    #[tokio::test]
    async fn avatar_dispatch_shares_media_capacity_and_holds_it_through_publication() {
        let store = storage_sqlite::SqliteAccountStorage::in_memory().unwrap();
        for n in 0..5 {
            store
                .request_avatar_acquisition(
                    &format!("owner-{n}"),
                    &storage_sqlite::SelectedAvatar::RemoteImage {
                        url: "https://example.com/avatar".into(),
                        cache_key: format!("source-{n}"),
                    },
                    false,
                )
                .unwrap();
        }
        let (media_http, mut completions) = media_http_context(4);
        let foreground = reserve_media_http(&media_http);
        let mut resumed = false;
        dispatch_avatar_acquisition(&store, &media_http, &mut resumed, &mut false, |_| async {
            Ok(storage_sqlite::AvatarImage::new(
                vec![1; 8],
                storage_sqlite::AvatarImageFormat::Png,
                1,
                1,
            )
            .unwrap())
        })
        .unwrap();
        dispatch_avatar_acquisition(&store, &media_http, &mut resumed, &mut false, |_| async {
            panic!("another background pass must preserve the foreground slot")
        })
        .unwrap();
        assert_eq!(media_http.permits.available_permits(), 1);
        let mut reserved = Vec::new();
        for _ in 0..2 {
            let done = timeout(Duration::from_secs(2), completions.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(media_http.permits.available_permits(), 1);
            let MediaHttpCompletion::Avatar { job, result } = &done.completion else {
                panic!("avatar completion");
            };
            store
                .complete_avatar_acquisition(job, result.as_ref().unwrap(), None)
                .unwrap();
            drop(done);
            // Reserve the freed slot to keep the assertion identical each pass.
            reserved.push(reserve_media_http(&media_http));
        }
        drop(foreground);
        assert_eq!(store.avatar_cache_usage().unwrap().byte_count, 16);
        assert!(
            store
                .claim_avatar_acquisition(crate::unix_now_seconds())
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn avatar_shutdown_cancels_io_and_leaves_resumable_intent() {
        let store = storage_sqlite::SqliteAccountStorage::in_memory().unwrap();
        let reference = store
            .request_avatar_acquisition(
                "owner",
                &storage_sqlite::SelectedAvatar::RemoteImage {
                    url: "https://example.com/avatar".into(),
                    cache_key: "source".into(),
                },
                false,
            )
            .unwrap()
            .unwrap();
        let (media_http, mut completions) = media_http_context(2);
        let permits = media_http.permits.clone();
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let (dropped_tx, mut dropped_rx) = mpsc::unbounded_channel();
        struct CancelProbe(mpsc::UnboundedSender<()>);
        impl Drop for CancelProbe {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        dispatch_avatar_acquisition(&store, &media_http, &mut false, &mut false, |_| {
            let started = started_tx.clone();
            let dropped = dropped_tx.clone();
            async move {
                let _guard = CancelProbe(dropped);
                started.send(()).unwrap();
                std::future::pending().await
            }
        })
        .unwrap();
        timeout(Duration::from_secs(2), started_rx.recv())
            .await
            .unwrap()
            .unwrap();
        drop(media_http);
        timeout(Duration::from_secs(2), dropped_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(permits.available_permits(), 2);
        assert!(completions.recv().await.is_none());
        assert_eq!(
            store.avatar_status(&reference, 0).unwrap().availability,
            storage_sqlite::AvatarAvailability::Missing
        );
        store.resume_avatar_acquisition().unwrap();
        assert_eq!(
            store
                .claim_avatar_acquisition(0)
                .unwrap()
                .unwrap()
                .reference,
            reference
        );
    }

    #[test]
    fn prepared_group_image_upload_reservation_rejects_duplicate_until_release() {
        let (media_http, _completions) = media_http_context(1);
        reserve_prepared_group_image_upload(&media_http, "upload-1").unwrap();
        assert!(prepared_group_image_upload_is_in_flight(
            &media_http,
            "upload-1"
        ));
        assert!(matches!(
            reserve_prepared_group_image_upload(&media_http, "upload-1"),
            Err(AppError::AccountWorkerBusy)
        ));

        release_prepared_group_image_upload(&media_http, "upload-1");
        assert!(!prepared_group_image_upload_is_in_flight(
            &media_http,
            "upload-1"
        ));
        reserve_prepared_group_image_upload(&media_http, "upload-1").unwrap();
    }

    #[tokio::test]
    async fn media_http_capacity_stays_reserved_until_completion_is_consumed() {
        let (media_http, mut completions) = media_http_context(1);
        let permit = reserve_media_http(&media_http);
        let (respond, _response) = oneshot::channel();
        spawn_media_http(
            &media_http,
            permit,
            async { Ok(Vec::new()) },
            move |result| MediaHttpCompletion::GroupImage { result, respond },
        );

        let completion = timeout(Duration::from_secs(1), completions.recv())
            .await
            .expect("HTTP work completes")
            .expect("worker completion channel remains open");
        assert!(
            media_http.permits.clone().try_acquire_owned().is_err(),
            "a queued whole-blob result must continue to consume capacity"
        );

        drop(completion);
        let _permit = reserve_media_http(&media_http);
    }

    #[tokio::test]
    async fn full_media_capacity_queues() {
        use image::ImageEncoder as _;

        let admission = Arc::new(Semaphore::new(super::super::MEDIA_COMMAND_QUEUE_LIMIT));
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let client = app.client("alice").await.unwrap();
        let mut png = Vec::new();
        image::codecs::png::PngEncoder::new(&mut png)
            .write_image(&[0, 0, 0, 255], 1, 1, image::ExtendedColorType::Rgba8)
            .unwrap();
        let staged = client
            .stage_prepared_initial_group_image(&png, "image/png")
            .unwrap();
        client
            .finish_initial_group_image_upload(&staged.upload_id, &Ok(()))
            .unwrap();
        let (respond, _response) = oneshot::channel();
        assert!(
            AccountWorkerCommand::UploadPreparedGroupImage {
                admission: admission.clone().try_acquire_owned().unwrap(),
                upload_id: "missing".into(),
                server: None,
                respond,
            }
            .needs_media_slot()
        );
        drop(client);

        // Fill the startup channel before spawning the real worker.
        let (commands, receiver) = mpsc::channel(8);
        let mut transfers = Vec::new();
        for _ in 0..MEDIA_HTTP_IN_FLIGHT_LIMIT {
            let (started, start) = oneshot::channel();
            let (release, wait) = oneshot::channel();
            let (respond, response) = oneshot::channel();
            commands
                .try_send(AccountWorkerCommand::HoldMediaHttp {
                    admission: admission.clone().try_acquire_owned().unwrap(),
                    started,
                    release: wait,
                    respond,
                })
                .unwrap();
            transfers.push((start, release, response));
        }
        let (respond, mut queued) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::DownloadGroupImage {
                admission: admission.clone().try_acquire_owned().unwrap(),
                group_id: GroupId::new(vec![1; 16]),
                respond,
            })
            .unwrap();
        let (respond, drained) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::Drain { respond })
            .unwrap();
        let shared = RuntimeSharedServices::default();
        let startup = Arc::new(tokio::sync::Barrier::new(2));
        shared.set_next_startup_sync_barrier(startup.clone());
        let (events, _) = broadcast::channel(8);
        let (ready, readiness) = oneshot::channel();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let worker = spawn_app_runtime_account_worker(
            AccountWorkerRuntime {
                app: app.clone(),
                account_label: "alice".into(),
                account_id_hex: account.account_id_hex.clone(),
                relay_plane: app.relay_plane.clone(),
                events,
                lifecycle: shared.lifecycle(),
                shared,
            },
            commands.clone(),
            receiver,
            ready,
            shutdown_rx,
        );
        let runtime = super::super::MarmotAppRuntime::new(app.clone());
        let manager = runtime.accounts();
        manager.workers.lock().await.insert(
            account.account_id_hex.clone(),
            ManagedAccountWorker {
                ready: true,
                handle: worker,
                commands: commands.clone(),
                shutdown,
                media_admission: admission.clone(),
            },
        );
        timeout(Duration::from_secs(5), readiness)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(5), startup.wait())
            .await
            .unwrap();
        // A snapshot reply proves every preceding command entered startup replay.
        let (respond, snapshot) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::QuarantinedGroups { respond })
            .await
            .unwrap();
        timeout(Duration::from_secs(5), snapshot)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(5), startup.wait())
            .await
            .unwrap();
        let mut active = Vec::new();
        for (start, release, response) in transfers {
            timeout(Duration::from_secs(5), start)
                .await
                .unwrap()
                .unwrap();
            active.push((release, response));
        }
        timeout(Duration::from_secs(5), drained)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            queued.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        // The steady-state receiver must also stay live behind parked media.
        let (started, mut next_start) = oneshot::channel();
        let (release, wait) = oneshot::channel();
        let (respond, response) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::HoldMediaHttp {
                admission: admission.clone().try_acquire_owned().unwrap(),
                started,
                release: wait,
                respond,
            })
            .await
            .unwrap();
        let (respond, drained) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::Drain { respond })
            .await
            .unwrap();
        timeout(Duration::from_secs(5), drained)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            next_start.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        // Fill the remaining admission budget through the real caller API.
        let mut callers = Vec::new();
        for _ in 0..super::super::MEDIA_COMMAND_QUEUE_LIMIT - 2 {
            let manager = manager.clone();
            callers.push(tokio::spawn(async move {
                manager
                    .download_group_blossom_image("alice", &GroupId::new(vec![1; 16]))
                    .await
            }));
        }
        timeout(Duration::from_secs(5), async {
            while admission.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut waiting = Box::pin(manager.media_worker_commands("alice"));
        std::future::poll_fn(|cx| {
            assert!(
                waiting.as_mut().poll(cx).is_pending(),
                "ninth media command waits before enqueue"
            );
            std::task::Poll::Ready(())
        })
        .await;

        // Caller cancellation cannot release the permit retained by its queued command.
        let cancelled = callers.remove(0);
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        assert_eq!(admission.available_permits(), 0);
        let status = timeout(
            Duration::from_secs(5),
            manager.upload_prepared_group_image("alice", staged.upload_id.clone()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            status.state,
            crate::AppPreparedGroupImageUploadState::Uploaded
        );
        let (respond, drained) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::Drain { respond })
            .await
            .unwrap();
        timeout(Duration::from_secs(5), drained)
            .await
            .unwrap()
            .unwrap();

        // Consuming one completion admits the parked download; its preparation
        // error frees that slot for the next transfer, without a busy response.
        let (first_release, first_response) = active.remove(0);
        first_release.send(()).unwrap();
        timeout(Duration::from_secs(5), first_response)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let result = timeout(Duration::from_secs(5), queued)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err());
        assert!(!matches!(result, Err(AppError::AccountWorkerBusy)));
        timeout(Duration::from_secs(5), next_start)
            .await
            .unwrap()
            .unwrap();
        let (_, admitted) = timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
        drop(admitted);
        active.push((release, response));
        for (release, response) in active {
            release.send(()).unwrap();
            timeout(Duration::from_secs(5), response)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        for caller in callers {
            let result = timeout(Duration::from_secs(5), caller)
                .await
                .unwrap()
                .unwrap();
            assert!(result.is_err());
            assert!(!matches!(result, Err(AppError::AccountWorkerBusy)));
        }
        let _held = admission
            .clone()
            .acquire_many_owned(super::super::MEDIA_COMMAND_QUEUE_LIMIT as u32)
            .await
            .unwrap();
        let mut waiting = Box::pin(manager.media_worker_commands("alice"));
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        tokio::time::pause();
        tokio::time::advance(super::super::APP_RUNTIME_LONG_WORKER_RESPONSE_WAIT).await;
        assert!(matches!(
            waiting.await,
            Err(AppError::AccountWorkerResponseTimedOut)
        ));
        tokio::time::resume();
        let mut waiting = Box::pin(manager.media_worker_commands("alice"));
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        runtime.shutdown().await;
        assert!(matches!(
            timeout(Duration::from_secs(5), waiting).await.unwrap(),
            Err(AppError::TransportClosed)
        ));
    }

    #[tokio::test]
    async fn prepared_group_image_upload_failure_is_durable_and_returned_as_error() {
        use image::ImageEncoder as _;

        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let mut png = Vec::new();
        image::codecs::png::PngEncoder::new(&mut png)
            .write_image(&[0, 0, 0, 255], 1, 1, image::ExtendedColorType::Rgba8)
            .unwrap();
        let staged = client
            .stage_prepared_initial_group_image(&png, "image/png")
            .unwrap();

        let (media_http, _completions) = media_http_context(1);
        reserve_prepared_group_image_upload(&media_http, &staged.upload_id).unwrap();
        let permit = reserve_media_http(&media_http);
        let (respond, response) = oneshot::channel();
        let done = MediaHttpDone {
            cancellation: None,
            permit,
            completion: MediaHttpCompletion::PreparedGroupImageUpload {
                upload_id: staged.upload_id.clone(),
                result: Err(AppError::BlobStore("injected upload failure".into())),
                respond,
                started_at: Instant::now(),
            },
        };

        complete_media_http(
            &mut client,
            done,
            &RuntimeSharedServices::default(),
            &media_http,
        )
        .await;

        let error = response
            .await
            .unwrap()
            .expect_err("a durable failed status must not turn upload failure into success");
        assert_eq!(error.privacy_safe_kind(), "blob_store");
        let status = client
            .prepared_initial_group_image_status(&staged.upload_id)
            .unwrap();
        assert_eq!(
            status.state,
            crate::AppPreparedGroupImageUploadState::Failed
        );
        assert_eq!(status.attempt_count, 1);
        assert_eq!(status.last_error_kind.as_deref(), Some("blob_store"));
    }

    #[tokio::test]
    async fn dropping_media_http_context_cancels_active_work_and_releases_capacity() {
        struct CancellationWitness(Option<oneshot::Sender<()>>);

        impl Drop for CancellationWitness {
            fn drop(&mut self) {
                if let Some(cancelled) = self.0.take() {
                    let _ = cancelled.send(());
                }
            }
        }

        let (media_http, _completions) = media_http_context(1);
        let permits = media_http.permits.clone();
        let permit = reserve_media_http(&media_http);
        let (started_tx, started_rx) = oneshot::channel();
        let (cancelled_tx, cancelled_rx) = oneshot::channel();
        let (respond, _response) = oneshot::channel();
        spawn_media_http(
            &media_http,
            permit,
            async move {
                let _witness = CancellationWitness(Some(cancelled_tx));
                let _ = started_tx.send(());
                std::future::pending::<Result<Vec<u8>, AppError>>().await
            },
            move |result| MediaHttpCompletion::GroupImage { result, respond },
        );
        started_rx.await.expect("HTTP future starts");

        drop(media_http);
        timeout(Duration::from_secs(1), cancelled_rx)
            .await
            .expect("worker exit cancels HTTP future")
            .expect("cancellation witness is delivered");
        assert_eq!(permits.available_permits(), 1);
    }

    #[test]
    fn legacy_message_promotion_completes_and_stops_scheduling() {
        let mut schedule = LegacyMessagePromotionSchedule::new();
        let mut calls = 0;

        run_legacy_message_promotion_batch_with(&mut schedule, |limit| {
            calls += 1;
            assert_eq!(limit, LEGACY_MESSAGE_PROMOTION_BATCH_SIZE);
            Ok(storage_sqlite::MessageFormatPromotionProgress {
                promoted: 7,
                has_more: false,
            })
        });
        run_legacy_message_promotion_batch_with(&mut schedule, |_| {
            calls += 1;
            unreachable!("completed promotion must not call storage again")
        });

        assert_eq!(calls, 1);
        assert_eq!(schedule.promoted_total, 7);
        assert_eq!(schedule.status, LegacyMessagePromotionStatus::Complete);
    }

    #[test]
    fn legacy_message_promotion_retries_transient_failures() {
        let mut schedule = LegacyMessagePromotionSchedule::new();

        run_legacy_message_promotion_batch_with(&mut schedule, |_| {
            Err(cgka_session::SessionError::Storage(
                cgka_traits::storage::StorageError::Busy("test contention".into()),
            ))
        });

        assert_eq!(schedule.status, LegacyMessagePromotionStatus::Pending);
        assert_eq!(schedule.promoted_total, 0);
    }

    #[test]
    fn legacy_message_promotion_halts_after_durable_failure() {
        let mut schedule = LegacyMessagePromotionSchedule::new();
        let mut calls = 0;

        run_legacy_message_promotion_batch_with(&mut schedule, |_| {
            calls += 1;
            Err(cgka_session::SessionError::Storage(
                cgka_traits::storage::StorageError::Serialization("malformed legacy row".into()),
            ))
        });
        run_legacy_message_promotion_batch_with(&mut schedule, |_| {
            calls += 1;
            unreachable!("durable failure must halt this process's sweep")
        });

        assert_eq!(calls, 1);
        assert_eq!(schedule.status, LegacyMessagePromotionStatus::Halted);
        assert_eq!(schedule.promoted_total, 0);
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
    async fn pending_epoch_backfill_records_correlated_qualified_and_incomplete_attempts() {
        for qualified in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            AccountHome::open(dir.path())
                .create_account("alice")
                .unwrap();
            let relay = Arc::new(ScriptedPushRelayClient::default());
            let app = MarmotApp::with_relay_and_config(
                dir.path(),
                "wss://relay.example".to_owned(),
                bounded_epoch_backfill_config(),
            )
            .with_test_relay_client(relay.clone());
            app.set_audit_log_settings(AuditLogSettings { enabled: true })
                .unwrap();
            let _eose =
                scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
            let mut client = client_on_app_relay_plane(&app, "alice").await;
            let group_id = client
                .create_group("successful epoch backfill audit", &[])
                .await
                .unwrap();
            let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
            client.apply_backfill_decision(
                &group_id,
                stalled_epoch,
                BackfillDecision::Arm,
                EpochStallBackfillTrigger::UndecryptableThreshold,
            );

            if qualified {
                client.test_recovery_evidence = Some(crate::client::recovery::empty_finite_history);
            }
            let (events, _subscriber) = broadcast::channel(4);
            let shared = RuntimeSharedServices::default();
            run_pending_epoch_backfill_reporting_arm(
                &mut client,
                &events,
                "account-id",
                "alice",
                &shared,
                EpochBackfillExecutionSeam::ExplicitCatchUp,
            )
            .await
            .unwrap();

            let rows: Vec<serde_json::Value> = app
                .audit_log_files()
                .unwrap()
                .into_iter()
                .flat_map(|file| {
                    std::fs::read_to_string(file.path)
                        .unwrap()
                        .lines()
                        .map(|line| serde_json::from_str(line).unwrap())
                        .collect::<Vec<_>>()
                })
                .collect();
            let attempt_id = rows
                .iter()
                .find(|row| row["kind"]["type"] == "epoch_stall_backfill_started")
                .and_then(|row| row["context"]["operation_id"].as_str())
                .expect("owner attempt must carry operation_id");
            assert_eq!(
                rows.iter()
                    .filter(|row| row["kind"]["type"] == "epoch_stall_backfill_started")
                    .count(),
                1
            );
            assert_eq!(
                rows.iter()
                    .filter(|row| row["kind"]["type"] == "epoch_stall_backfill_completed")
                    .count(),
                usize::from(qualified)
            );
            assert!(
                rows.iter()
                    .filter(|row| row["kind"]["type"] == "epoch_stall_backfill_failed")
                    .count()
                    == usize::from(!qualified)
            );
            assert!(rows.iter().all(|row| {
                !matches!(
                    row["kind"]["type"].as_str(),
                    Some(
                        "epoch_stall_backfill_started"
                            | "epoch_stall_backfill_completed"
                            | "epoch_stall_backfill_failed"
                    )
                ) || row["context"]["operation_id"].as_str() == Some(attempt_id)
            }));
        }
    }

    #[tokio::test]
    async fn pending_epoch_backfill_failure_is_reported_retained_and_coalesced() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config().with_dev_epoch_backfill_retry_backoff_ms(300_000),
        )
        .with_test_relay_client(relay.clone());
        app.set_audit_log_settings(AuditLogSettings { enabled: true })
            .unwrap();
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_id = client
            .create_group("failed epoch backfill audit", &[])
            .await
            .unwrap();
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        client.apply_backfill_decision(
            &group_id,
            stalled_epoch,
            BackfillDecision::Arm,
            EpochStallBackfillTrigger::UndecryptableThreshold,
        );

        let (events, mut subscriber) = broadcast::channel(4);
        let shared = RuntimeSharedServices::default();
        relay.fail_next_subscribe();
        let error = run_pending_epoch_backfill_reporting_arm(
            &mut client,
            &events,
            "account-id",
            "alice",
            &shared,
            EpochBackfillExecutionSeam::ExplicitCatchUp,
        )
        .await
        .expect_err("failed replay activation must be returned");

        assert_eq!(
            error.to_string(),
            "epoch-gap backfill failed: account_transport"
        );
        assert!(client.has_pending_epoch_backfill());
        let failed_rows: Vec<serde_json::Value> = app
            .audit_log_files()
            .unwrap()
            .into_iter()
            .flat_map(|file| {
                std::fs::read_to_string(file.path)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                    .collect::<Vec<_>>()
            })
            .filter(|row| row["kind"]["type"] == "epoch_stall_backfill_failed")
            .collect();
        assert_eq!(failed_rows.len(), 1);
        assert_eq!(
            failed_rows[0]["kind"]["activation_outcome"].as_str(),
            Some("failed")
        );
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
            EpochBackfillExecutionSeam::ExplicitCatchUp,
        )
        .await
        .unwrap();
        assert!(client.has_pending_epoch_backfill());
        let subscriptions_after_replay = relay.subscription_count();
        let retry = app
            .account_storage("alice")
            .unwrap()
            .recovery_retry_state()
            .unwrap();
        assert_eq!(retry.attempt_serial, 2);

        run_pending_epoch_backfill_reporting_arm(
            &mut client,
            &events,
            "account-id",
            "alice",
            &shared,
            EpochBackfillExecutionSeam::Maintenance,
        )
        .await
        .unwrap();
        assert_eq!(relay.subscription_count(), subscriptions_after_replay);
        assert_eq!(
            app.account_storage("alice")
                .unwrap()
                .recovery_retry_state()
                .unwrap(),
            retry
        );
    }

    /// The Phase-A workload: epoch and overflow join one owner reservation;
    /// a later receive seam cannot bypass the durable account cooldown.
    #[cfg(feature = "test-policy-overrides")]
    #[tokio::test]
    async fn recovery_owner_coalesces_overflow_and_epoch_demand_across_seams() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config()
                .with_dev_epoch_backfill_eose_wait_ms(25)
                .with_dev_epoch_backfill_retry_backoff_ms(300_000),
        )
        .with_test_relay_client(relay.clone());
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group = client
            .create_group("ownership baseline", &[])
            .await
            .unwrap();
        let epoch = client.group_mls_state(&group).unwrap().epoch;
        client.apply_backfill_decision(
            &group,
            epoch,
            BackfillDecision::Arm,
            EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        app.account_storage("alice")
            .unwrap()
            .mark_account_delivery_recovery("alice", 7, 1)
            .unwrap();
        client.delivery_overflow_recovery_pending = true;
        client.delivery_overflow_recovery_marker_token = Some(7);
        let (events, _subscriber) = broadcast::channel(16);
        let shared = RuntimeSharedServices::default();
        let before = relay.unfloored_account_subscription_count();
        client
            .sync_with_stage_telemetry(&shared.app_performance_telemetry(), false)
            .await
            .unwrap();
        for (seam, expected_activations, reason) in [
            (
                EpochBackfillExecutionSeam::Maintenance,
                1,
                "startup joined compatible epoch, incremental and overflow demand in one activation",
            ),
            (
                EpochBackfillExecutionSeam::Receive,
                1,
                "receive cannot bypass the account owner cooldown",
            ),
        ] {
            run_pending_epoch_backfill_reporting_arm(
                &mut client,
                &events,
                "account-id",
                "alice",
                &shared,
                seam,
            )
            .await
            .unwrap();
            let retry = app
                .account_storage("alice")
                .unwrap()
                .recovery_retry_state()
                .unwrap();
            assert_eq!(retry.attempt_serial, 1);
            assert_eq!(retry.not_before_ms - retry.recorded_at_ms, 300_000);
            assert_eq!(
                relay.unfloored_account_subscription_count() - before,
                expected_activations,
                "{reason}",
            );
        }
        let retry = app
            .account_storage("alice")
            .unwrap()
            .recovery_retry_state()
            .unwrap();
        client
            .advance_convergence_after_runtime_sync(&group)
            .await
            .unwrap();
        run_pending_epoch_backfill_reporting_arm(
            &mut client,
            &events,
            "account-id",
            "alice",
            &shared,
            EpochBackfillExecutionSeam::Maintenance,
        )
        .await
        .unwrap();
        assert_eq!(
            app.account_storage("alice")
                .unwrap()
                .recovery_retry_state()
                .unwrap(),
            retry
        );
        assert_eq!(relay.unfloored_account_subscription_count() - before, 1);
        client
            .sync_with_classified_partial_progress()
            .await
            .unwrap();
        assert_eq!(
            app.account_storage("alice")
                .unwrap()
                .recovery_retry_state()
                .unwrap()
                .attempt_serial,
            2
        );
        assert_eq!(
            relay.unfloored_account_subscription_count() - before,
            2,
            "one genuine explicit caller spends one override without a nested overflow replay"
        );
        assert!(client.has_pending_epoch_backfill());
        assert!(client.delivery_overflow_recovery_pending);
        assert_eq!(
            app.relay_plane
                .relay_health()
                .await
                .account_delivery_recovery_attempts,
            2,
        );
    }

    #[tokio::test]
    async fn incomplete_delivery_overflow_recovery_does_not_fail_catch_up() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config().with_dev_epoch_backfill_eose_wait_ms(25),
        )
        .with_test_relay_client(relay);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let marker_token = 7;
        app.account_storage("alice")
            .unwrap()
            .mark_account_delivery_recovery("alice", marker_token, 1)
            .unwrap();
        client.delivery_overflow_recovery_pending = true;
        client.delivery_overflow_recovery_marker_token = Some(marker_token);

        let (events, _subscriber) = broadcast::channel(4);
        run_pending_epoch_backfill_reporting_arm(
            &mut client,
            &events,
            "account-id",
            "alice",
            &RuntimeSharedServices::default(),
            EpochBackfillExecutionSeam::ExplicitCatchUp,
        )
        .await
        .expect("missing relay EOSE is incomplete recovery, not a catch-up failure");

        assert!(client.delivery_overflow_recovery_pending);
        assert!(
            app.account_storage("alice")
                .unwrap()
                .account_delivery_recovery("alice")
                .unwrap()
                .is_some(),
            "incomplete recovery must retain its durable retry marker"
        );
    }

    #[tokio::test]
    async fn explicit_catch_up_runs_prearmed_backfill_before_success_response() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(relay.clone());
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_id = client
            .create_group("explicit catch-up epoch backfill", &[])
            .await
            .unwrap();
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        client.apply_backfill_decision(
            &group_id,
            stalled_epoch,
            BackfillDecision::Arm,
            EpochStallBackfillTrigger::UndecryptableThreshold,
        );

        let before = relay.unfloored_account_subscription_count();
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
            client.has_pending_epoch_backfill(),
            "ordinary catch-up cannot certify complete historical coverage",
        );
        assert_eq!(relay.unfloored_account_subscription_count(), before + 1);
        assert_eq!(
            app.account_storage("alice")
                .unwrap()
                .recovery_retry_state()
                .unwrap()
                .attempt_serial,
            1
        );
        drop(command_tx);
    }

    #[tokio::test]
    async fn explicit_catch_up_succeeds_after_ordinary_sync_when_backfill_defers() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("alice").await.unwrap();
        let group_id = client
            .create_group("deferred explicit catch-up", &[])
            .await
            .unwrap();
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        client.apply_backfill_decision(
            &group_id,
            stalled_epoch,
            BackfillDecision::Arm,
            EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        let storage = app.account_storage("alice").unwrap();
        let mut orphan = client.runtime.group_record(&group_id).unwrap();
        orphan.id = test_group_id(0xde);
        cgka_traits::storage::GroupStorage::put_group(&storage, &orphan).unwrap();
        storage
            .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(orphan.id.as_slice()),
                stalled_epoch: 1,
            }])
            .unwrap();
        let subscriptions_before = relay.subscription_count();

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

        response
            .await
            .unwrap()
            .expect("the completed ordinary catch-up remains successful");
        assert!(
            relay.subscription_count() > subscriptions_before,
            "ordinary catch-up must still activate and drain transport"
        );
        assert!(
            client.has_pending_epoch_backfill(),
            "the unavailable recovery intent must remain pending"
        );
        let outcome = client
            .run_pending_epoch_backfill(EpochBackfillExecutionSeam::Maintenance)
            .await
            .expect("rechecking a deferred intent must not fail");
        assert!(
            matches!(outcome, EpochBackfillRunOutcome::Deferred),
            "deferred work must remain distinct from no pending work"
        );
        drop(command_tx);
    }

    #[tokio::test]
    async fn full_history_repair_consumes_prearmed_backfill_without_replaying_twice() {
        for qualified in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            AccountHome::open(dir.path())
                .create_account("alice")
                .unwrap();
            let relay = Arc::new(ScriptedPushRelayClient::default());
            let app = MarmotApp::with_relay_and_config(
                dir.path(),
                "wss://relay.example".to_owned(),
                bounded_epoch_backfill_config(),
            )
            .with_test_relay_client(relay.clone());
            let _eose =
                scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
            let mut client = client_on_app_relay_plane(&app, "alice").await;
            let group_id = client
                .create_group("full-history epoch backfill", &[])
                .await
                .unwrap();
            let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
            client.apply_backfill_decision(
                &group_id,
                stalled_epoch,
                BackfillDecision::Arm,
                EpochStallBackfillTrigger::UndecryptableThreshold,
            );
            if qualified {
                client.test_recovery_evidence = Some(crate::client::recovery::empty_finite_history);
            }
            let subscriptions_before_repair = relay.subscription_count();

            let (events, _subscriber) = broadcast::channel(4);
            let shared = RuntimeSharedServices::default();
            let (respond, response) = oneshot::channel();
            let (media_http_tx, _media_http_rx) = mpsc::unbounded_channel();
            let (media_http_worker_lifetime, _) = watch::channel(());
            let media_http = MediaHttpContext {
                product: Default::default(),
                tx: media_http_tx,
                permits: Arc::new(Semaphore::new(MEDIA_HTTP_IN_FLIGHT_LIMIT)),
                prepared_group_image_uploads: Arc::new(Mutex::new(HashSet::new())),
                worker_lifetime: media_http_worker_lifetime,
            };
            let (mut unused_commands, mut unused_pending) = unused_account_worker_command_io();
            let mut scheduled_convergence = ScheduledConvergence::new(Duration::ZERO);
            handle_account_worker_command(
                &mut client,
                AccountWorkerCommand::RepairFullHistory { respond },
                AccountWorkerCommandContext {
                    commands: &mut unused_commands,
                    pending: &mut unused_pending,
                    app: &app,
                    events: &events,
                    account_id_hex: "account-id",
                    account_label: "alice",
                    shared: &shared,
                    media_http: &media_http,
                    scheduled_convergence: &mut scheduled_convergence,
                },
            )
            .await;

            let result = response.await.unwrap();
            if qualified {
                result.unwrap();
                assert!(!client.has_pending_epoch_backfill());
            } else {
                let failure = result.unwrap_err();
                assert!(
                    failure
                        .to_string()
                        .contains("full_history_coverage_unproven"),
                    "{failure}"
                );
                assert!(client.has_pending_epoch_backfill());
            }
            assert_eq!(
                app.account_storage("alice")
                    .unwrap()
                    .recovery_retry_state()
                    .unwrap()
                    .attempt_serial,
                1
            );
            assert_eq!(
                relay.subscription_count(),
                subscriptions_before_repair + 2,
                "one activation serves the coalesced demands without a second replay",
            );
        }
    }

    #[tokio::test]
    async fn full_history_repair_resolves_overflow_after_prearmed_backfill() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(relay.clone());
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_id = client
            .create_group("combined full-history repair", &[])
            .await
            .unwrap();
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        client.apply_backfill_decision(
            &group_id,
            stalled_epoch,
            BackfillDecision::Arm,
            EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        let marker_token = 7;
        app.account_storage("alice")
            .unwrap()
            .mark_account_delivery_recovery("alice", marker_token, 1)
            .unwrap();
        client.delivery_overflow_recovery_pending = true;
        client.delivery_overflow_recovery_marker_token = Some(marker_token);

        client
            .repair_full_history()
            .await
            .expect_err("EOSE alone cannot complete either recovery predicate");

        assert!(client.has_pending_epoch_backfill());
        assert!(client.delivery_overflow_recovery_pending);
        assert!(
            app.account_storage("alice")
                .unwrap()
                .account_delivery_recovery("alice")
                .unwrap()
                .is_some(),
            "unproven coverage must preserve the durable overflow marker",
        );
    }

    #[tokio::test]
    async fn explicit_full_history_repair_retains_incomplete_overflow_recovery() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(relay);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let marker_token = 7;
        app.account_storage("alice")
            .unwrap()
            .mark_account_delivery_recovery("alice", marker_token, 1)
            .unwrap();
        client.delivery_overflow_recovery_pending = true;
        client.delivery_overflow_recovery_marker_token = Some(marker_token);

        let failure = client
            .repair_full_history()
            .await
            .expect_err("relay silence cannot resolve the durable delivery gap");

        assert_eq!(
            failure.classification().failure_stage,
            SyncFailureStage::RelayReceive
        );
        assert!(
            failure.source.privacy_safe_kind() == "account_delivery_queue_overflow",
            "the public failure must identify the unresolved durable gap",
        );
        assert!(
            matches!(
                failure.source,
                AppError::FullHistoryRepairIncomplete {
                    reason,
                    delivery_loss_pending: true,
                } if reason == if cfg!(feature = "test-policy-overrides") {
                    crate::FullHistoryRepairIncompleteReason::NoRelayEose
                } else {
                    crate::FullHistoryRepairIncompleteReason::Deadline
                }
            ),
            "the stop reason and independent loss fact must both survive: {:?}",
            failure.source
        );
        assert!(
            client.delivery_overflow_recovery_pending,
            "an unconfirmed recovery must remain armed",
        );
        assert!(
            app.account_storage("alice")
                .unwrap()
                .account_delivery_recovery("alice")
                .unwrap()
                .is_some(),
            "an unconfirmed recovery must retain its durable marker",
        );
    }

    #[tokio::test]
    async fn full_history_repair_falls_back_when_every_pending_intent_defers() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example".to_owned(),
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(relay.clone());
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_id = client
            .create_group("deferred full-history repair", &[])
            .await
            .unwrap();
        let stalled_epoch = client.group_mls_state(&group_id).unwrap().epoch;
        client.apply_backfill_decision(
            &group_id,
            stalled_epoch,
            BackfillDecision::Arm,
            EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        let storage = app.account_storage("alice").unwrap();
        let mut orphan = client.runtime.group_record(&group_id).unwrap();
        orphan.id = test_group_id(0xde);
        cgka_traits::storage::GroupStorage::put_group(&storage, &orphan).unwrap();
        storage
            .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(orphan.id.as_slice()),
                stalled_epoch: 1,
            }])
            .unwrap();
        let subscriptions_before = relay.subscription_count();

        client
            .repair_full_history()
            .await
            .expect_err("one owner attempt retains unproven and unresolved history");

        assert_eq!(
            relay.subscription_count(),
            subscriptions_before + 2,
            "the fallback repair must install the complete account-wide replay"
        );
        assert!(
            client.has_pending_epoch_backfill(),
            "the deferred audit intent must remain retryable"
        );
    }

    #[tokio::test]
    async fn full_history_repair_coalesces_new_demand_after_an_inflight_failure() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example",
            bounded_epoch_backfill_config(),
        )
        .with_test_relay_client(relay.clone());
        let _eose = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_a = client.create_group("demand a", &[]).await.unwrap();
        let group_b = client.create_group("demand b", &[]).await.unwrap();
        let storage = app.account_storage("alice").unwrap();
        client.apply_backfill_decision(
            &group_a,
            client.group_mls_state(&group_a).unwrap().epoch,
            BackfillDecision::Arm,
            EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        let grant = client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        client.apply_backfill_decision(
            &group_b,
            client.group_mls_state(&group_b).unwrap().epoch,
            BackfillDecision::Arm,
            EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        relay.fail_next_subscribe();
        assert!(
            client
                .execute_recovery_grant(grant, None, None)
                .await
                .is_err()
        );
        let before = relay.unfloored_account_subscription_count();
        let attempts = storage.recovery_retry_state().unwrap().attempt_serial;
        assert!(
            client
                .repair_full_history()
                .await
                .unwrap_err()
                .source
                .to_string()
                .contains("full_history_coverage_unproven")
        );
        assert_eq!(relay.unfloored_account_subscription_count(), before + 1);
        assert_eq!(
            storage.recovery_retry_state().unwrap().attempt_serial,
            attempts + 1
        );
        assert_eq!(
            storage.pending_epoch_backfill_intents().unwrap().len(),
            2,
            "both independent gap predicates remain incomplete after the shared EOSE"
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

    #[tokio::test]
    async fn runtime_group_subscription_retry_is_bounded_and_disarms_when_refreshed() {
        assert_eq!(
            runtime_group_subscription_retry_delay(1),
            runtime_group_subscription_retry_base_delay()
        );
        assert_eq!(
            runtime_group_subscription_retry_delay(u32::MAX),
            runtime_group_subscription_retry_max_delay()
        );

        let (commands, mut received_commands) = mpsc::channel(2);
        let mut scheduled = ScheduledRuntimeGroupSubscriptionRefresh::new();
        scheduled.observe_pending(true, &commands);
        assert!(scheduled.is_armed());

        let first = received_commands.recv().await.unwrap();
        let AccountWorkerCommand::RetryRuntimeGroupSubscriptions { respond } = first else {
            panic!("timer must enqueue an internal group-subscription retry")
        };
        respond.send(true).unwrap();

        let second = received_commands.recv().await.unwrap();
        let AccountWorkerCommand::RetryRuntimeGroupSubscriptions { respond } = second else {
            panic!("pending refresh must enqueue a backed-off retry")
        };
        respond.send(false).unwrap();
        scheduled.observe_pending(false, &commands);
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
        assert_eq!(ready, Some(group_id));
    }

    #[tokio::test]
    async fn schedule_unsettled_groups_rearms_settlement_delay() {
        let group_id = test_group_id(9);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));

        scheduled.schedule_unsettled_groups([group_id.clone()]);
        let ready = scheduled.take_ready();
        assert_eq!(ready, Some(group_id.clone()));
        assert!(!scheduled.retry_attempts.contains_key(&group_id));
    }

    #[tokio::test]
    async fn schedule_after_pass_rearms_when_inputs_remain_pending() {
        let group_id = test_group_id(10);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));

        scheduled.schedule_after_pass(&group_id, ConvergenceScheduleState::PendingUnopenable);

        let ready = scheduled.take_ready();
        assert_eq!(ready, Some(group_id.clone()));
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
            scheduled.schedule_after_pass(
                &group_id,
                ConvergenceScheduleState::PendingOutbound {
                    retry_after_ms: None,
                },
            );
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
            scheduled.schedule_after_pass(
                &group_id,
                ConvergenceScheduleState::PendingOutbound {
                    retry_after_ms: None,
                },
            );
            scheduled.take_ready();
        }
        assert!(!scheduled.unsettled_rearm_attempts.contains_key(&group_id));
        assert!(!scheduled.retry_attempts.contains_key(&group_id));
    }

    #[tokio::test(start_paused = true)]
    async fn pending_outbound_arms_at_the_durable_retry_cutoff() {
        let group_id = test_group_id(16);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));
        let before = TokioInstant::now();

        scheduled.schedule_after_pass(
            &group_id,
            ConvergenceScheduleState::PendingOutbound {
                retry_after_ms: Some(30_000),
            },
        );

        assert_eq!(
            scheduled.deadlines[&group_id],
            before + Duration::from_secs(30),
            "a frozen fanout must sleep until its durable cutoff instead of polling every settlement interval"
        );
        tokio::time::advance(Duration::from_millis(1_100)).await;
        assert!(
            scheduled.deadlines[&group_id] > TokioInstant::now(),
            "the ordinary convergence delay must not wake a backpressured fanout"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connectivity_restore_wakes_pending_outbound_before_durable_cutoff() {
        let group_id = test_group_id(17);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));
        let before = TokioInstant::now();

        scheduled.schedule_after_pass(
            &group_id,
            ConvergenceScheduleState::PendingOutbound {
                retry_after_ms: Some(5_000),
            },
        );
        assert_eq!(
            scheduled.deadlines[&group_id],
            before + Duration::from_secs(5)
        );

        scheduled.wake_after_connectivity_restored();

        assert_eq!(
            scheduled.deadlines[&group_id],
            TokioInstant::now(),
            "connectivity recovery must make a backpressured fanout immediately eligible"
        );
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
        assert_eq!(scheduled.take_ready(), Some(first));
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
    async fn take_ready_preserves_other_overdue_groups_for_later_worker_turns() {
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

        assert_eq!(ready, Some(second));
        assert_eq!(scheduled.deadlines[&first], now);
        assert_eq!(scheduled.take_ready(), Some(first));
        assert_eq!(
            scheduled.deadlines.keys().collect::<Vec<_>>(),
            vec![&future]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn fifty_overdue_groups_progress_despite_one_group_rearming() {
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));
        let groups: Vec<_> = (1..=50).map(test_group_id).collect();
        scheduled.schedule_groups(groups.clone());
        tokio::time::advance(Duration::from_secs(2)).await;
        let deadlines = scheduled.deadlines.clone();

        for group in &groups {
            assert_eq!(scheduled.take_ready(), Some(group.clone()));
            scheduled.schedule_unsettled_groups([group.clone()]);
            for later in groups
                .iter()
                .filter(|later| later.as_slice() > group.as_slice())
            {
                assert_eq!(scheduled.deadlines[later], deadlines[later]);
            }
        }
        assert_eq!(scheduled.deadlines.len(), 50);
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
    #[cfg(feature = "test-policy-overrides")]
    #[tokio::test]
    async fn full_history_repair_serves_snapshot_reads_and_stops_at_checkpoint() {
        for caller_cancels in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            AccountHome::open(dir.path())
                .create_account("alice")
                .unwrap();
            AccountHome::open(dir.path()).create_account("bob").unwrap();
            let relay = Arc::new(ScriptedPushRelayClient::default());
            let app = MarmotApp::with_relay_and_config(
                dir.path(),
                "wss://relay.example".to_owned(),
                bounded_epoch_backfill_config().with_dev_epoch_backfill_execution_quantum_ms(10),
            )
            .with_test_relay_client(relay.clone());
            let mut client = client_on_app_relay_plane(&app, "alice").await;
            let mut bob = client_on_app_relay_plane(&app, "bob").await;
            let bob_id = cgka_traits::MemberId::new(
                hex::decode(app.account_home().account("bob").unwrap().account_id_hex).unwrap(),
            );
            let bob_before = relay.inbox_subscription_count(&bob_id);
            let before = relay.subscription_count();
            let (events, _subscriber) = broadcast::channel(4);
            let shared = RuntimeSharedServices::default();
            let (respond, mut response) = oneshot::channel();
            let (media_http_tx, _media_http_rx) = mpsc::unbounded_channel();
            let (worker_lifetime, _) = watch::channel(());
            let media_http = MediaHttpContext {
                product: Default::default(),
                tx: media_http_tx,
                permits: Arc::new(Semaphore::new(MEDIA_HTTP_IN_FLIGHT_LIMIT)),
                prepared_group_image_uploads: Arc::new(Mutex::new(HashSet::new())),
                worker_lifetime,
            };
            let (command_tx, mut commands) = mpsc::channel(4);
            let mut pending = VecDeque::new();
            let mut scheduled_convergence = ScheduledConvergence::new(Duration::ZERO);
            let handler = handle_account_worker_command(
                &mut client,
                AccountWorkerCommand::RepairFullHistory { respond },
                AccountWorkerCommandContext {
                    commands: &mut commands,
                    pending: &mut pending,
                    app: &app,
                    events: &events,
                    account_id_hex: "account-id",
                    account_label: "alice",
                    shared: &shared,
                    media_http: &media_http,
                    scheduled_convergence: &mut scheduled_convergence,
                },
            );
            let observer = async {
                while relay.subscription_count() == before {
                    tokio::task::yield_now().await;
                }
                let (respond, read) = oneshot::channel();
                command_tx
                    .send(AccountWorkerCommand::QuarantinedGroups { respond })
                    .await
                    .unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_secs(1), read)
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap()
                        .is_empty()
                );
                assert!(matches!(
                    response.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ));
                // Another account uses its own worker catch-up path while
                // Alice's history drain still waits for cancellation. No relay
                // boundary is supplied to manufacture either completion.
                let (bob_tx, mut bob_commands) = mpsc::channel(1);
                let mut bob_pending = VecDeque::new();
                let (bob_respond, bob_response) = oneshot::channel();
                handle_account_worker_catch_up(
                    &mut bob,
                    bob_respond,
                    &mut bob_commands,
                    &mut bob_pending,
                    AccountWorkerCatchUpContext {
                        app: &app,
                        events: &events,
                        account_id_hex: "bob-id",
                        account_label: "bob",
                        shared: &shared,
                    },
                )
                .await;
                bob_response.await.unwrap().unwrap();
                assert_eq!(relay.inbox_subscription_count(&bob_id), bob_before + 1);
                drop(bob_tx);
                if caller_cancels {
                    drop(response);
                } else {
                    shared.lifecycle().begin_shutdown();
                    let failure = response.await.unwrap().unwrap_err();
                    assert_eq!(
                        failure.classification().failure_stage,
                        crate::SyncFailureStage::RelayReceive
                    );
                }
            };
            tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(handler, observer);
            })
            .await
            .unwrap();
            assert_eq!(relay.subscription_count(), before + 2);
            assert_eq!(
                app.account_storage("bob")
                    .unwrap()
                    .recovery_retry_state()
                    .unwrap()
                    .attempt_serial,
                1
            );
        }
    }
}
