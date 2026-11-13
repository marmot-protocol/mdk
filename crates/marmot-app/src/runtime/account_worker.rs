//! Per-account worker: command surface, the worker loop, reconnect backoff,
//! and the runtime-event publishing helpers the loop drives.

mod attachments;
mod read_queue;
pub(crate) mod recovery_credits;

pub(crate) use read_queue::{
    ReadClass, ReadReply, WorkerLane, WorkerReply, WorkerUnit, WorkerUnitGauge,
};

use crate::RuntimePerformanceOperation as RuntimeOp;
use marmot_observability::{Observation, Outcome as TelemetryOutcome};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_AGENT_STREAM_START;
use cgka_traits::engine::KeyPackage;
use cgka_traits::{GroupId, MessageId, SecretBytes};
use futures::FutureExt;
use marmot_account::{AccountHomeError, AccountSetupKind, AccountSetupPhase, AccountSetupState};
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
    runtime_shutdown_requested, wait_for_runtime_shutdown,
};
use crate::client::read_state::UploadsInFlight;
use crate::client::recovery_runner::host::{SpawnedRunner, next_runner_turn};
use crate::client::{
    CommittedSyncProgress, CompletedWelcomeDeliveryRecovery, EncryptedMediaUploadFinish,
    PreparedGroupImageUploadStart, RetainedSendWake,
};
use crate::messages::AppMessageIntent;
use crate::{
    ACCOUNT_WORKER_RECONNECT_BASE_DELAY, ACCOUNT_WORKER_RECONNECT_JITTER_MAX_MS,
    ACCOUNT_WORKER_RECONNECT_MAX_DELAY, APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT, AccountCatchUpFailure,
    AgentTextStreamFinishRequest, AppBlobEndpoint, AppClient, AppCreateGroupOptions,
    AppDisbandRequest, AppError, AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord,
    AppPreparedGroupImageUpload, AppProjectionUpdate, AppQuarantinedGroup, CanonicalCreatedGroup,
    ChatListUpdateTrigger, ClassifiedSyncFailure, ConvergenceScheduleState,
    EpochBackfillRunOutcome, GroupInviteDeclineResult, MaintenanceRunSummary, MarmotApp,
    MarmotRelayPlane, MediaAttachmentReference, MediaDownloadResult, MediaUploadResult,
    NotificationSettings, PendingWelcomeDelivery, PushPlatform, PushRegistration,
    PushRegistrationShareOutcome, PushRegistrationSyncResult, ReceivedMessage,
    RetentionSweepReport, SecureDeleteExpiredResult, SendSummary, SyncSummary,
};
use cgka_traits::app_event::MarmotAppEvent as MarmotInnerEvent;
use marmot_observability::{AppPerformanceOperation, SyncFailureClassification, SyncFailureStage};

pub(crate) struct ManagedAccountWorker {
    pub(super) ready: bool,
    pub(crate) handle: JoinHandle<()>,
    pub(crate) commands: mpsc::Sender<AccountWorkerCommand>,
    pub(crate) media_admission: Arc<Semaphore>,
    pub(crate) shutdown: oneshot::Sender<()>,
    /// Which long unit the worker is inside, for host-read telemetry.
    pub(crate) unit: Arc<WorkerUnitGauge>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelayConfigWork {
    Idle,
    Ready,
    RetryOnTick,
}

impl ManagedAccountWorker {
    pub(crate) fn lane(&self) -> WorkerLane {
        WorkerLane::new(self.commands.clone(), self.unit.clone())
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

/// The pre-ready step an account worker is in (mdk#1911).
///
/// The startup path records nothing durable until the worker is ready, so
/// each step is an in-flight span on its runtime operation instead. The set is
/// closed and names only steps; it is exported as a runtime operation name,
/// never with account context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum AccountStartupStage {
    /// The worker task exists but has not submitted its blocking open.
    Spawned,
    /// The blocking open is waiting for a blocking-pool thread.
    OpenQueued,
    /// `ensure_account_state`: projection migration and first account
    /// database open, under the process-wide account-state lock.
    AccountState,
    /// `open_account`: session-owner claim, SQLCipher key and session open,
    /// and seeded group hydration.
    SessionOpen,
    /// Synchronous account-storage restore after the session opened:
    /// recovery owner, startup history request, receipts and durable sweeps.
    ClientRestore,
    /// The worker holds its client and is recording open timings and reading
    /// the setup journal before it signals ready.
    ReadyHandoff,
}

impl AccountStartupStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Spawned => "spawned",
            Self::OpenQueued => "open_queued",
            Self::AccountState => "account_state",
            Self::SessionOpen => "session_open",
            Self::ClientRestore => "client_restore",
            Self::ReadyHandoff => "ready_handoff",
        }
    }

    /// The runtime operation that carries this stage's spans.
    pub(crate) const fn operation(self) -> RuntimeOp {
        match self {
            Self::Spawned => RuntimeOp::AccountStartupSpawned,
            Self::OpenQueued => RuntimeOp::AccountStartupOpenQueued,
            Self::AccountState => RuntimeOp::AccountStartupAccountState,
            Self::SessionOpen => RuntimeOp::AccountStartupSessionOpen,
            Self::ClientRestore => RuntimeOp::AccountStartupClientRestore,
            Self::ReadyHandoff => RuntimeOp::AccountStartupReadyHandoff,
        }
    }
}

/// The stage a starting worker is in and its open span, shared by the worker,
/// its blocking open and its ready-waiter.
///
/// Entering a stage completes the previous span. The last clone to drop ends
/// an open span as cancelled, so a blocking open that outlives its aborted
/// worker keeps its stage in flight until the open itself moves on.
///
/// Entering a stage, and each migration an open of the account's database
/// applies, also counts as progress: the ready-waiter gives up only on a
/// startup that made none for its whole wait (mdk#3145).
#[derive(Clone, Debug)]
pub(crate) struct AccountStartupProgress {
    telemetry: marmot_observability::PerformanceRecorder,
    state: Arc<Mutex<StartupStageState>>,
    account_open: Arc<AccountOpenProgress>,
}

/// When an open of one account's database last applied a migration,
/// whichever caller ran it. A fresh database's first open applies every
/// migration, and a relay-list publish or the directory's block-list
/// reconcile can be the one running it while the starting worker waits on the
/// database's open lock (mdk#3145).
#[derive(Debug, Default)]
pub(crate) struct AccountOpenProgress(Mutex<Option<TokioInstant>>);

impl AccountOpenProgress {
    pub(crate) fn migration_applied(&self) {
        *self.last_migration() = Some(TokioInstant::now());
    }

    fn last_migration(&self) -> std::sync::MutexGuard<'_, Option<TokioInstant>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Debug)]
struct StartupStageState {
    stage: AccountStartupStage,
    span: StageSpan,
    stage_entered: TokioInstant,
}

/// A starting worker made no progress for its whole ready-wait.
#[derive(Debug)]
pub(crate) struct StartupStalled;

#[derive(Debug, Default)]
struct StageSpan {
    observation: Option<Observation>,
    /// The ready-wait expired in this stage: the span ends as a timeout,
    /// whenever and however it ends.
    expired: bool,
}

impl StageSpan {
    fn end(&mut self, outcome: TelemetryOutcome) {
        if let Some(observation) = self.observation.take() {
            observation.finish(if self.expired {
                TelemetryOutcome::Timeout
            } else {
                outcome
            });
        }
    }
}

impl Drop for StageSpan {
    fn drop(&mut self) {
        self.end(TelemetryOutcome::Cancelled);
    }
}

impl AccountStartupProgress {
    /// Open the `Spawned` span of a worker about to be spawned for the
    /// account whose database opens report to `account_open`.
    pub(crate) fn new(
        telemetry: marmot_observability::PerformanceRecorder,
        account_open: Arc<AccountOpenProgress>,
    ) -> Self {
        let stage = AccountStartupStage::Spawned;
        let span = StageSpan {
            observation: Some(telemetry.observe(stage.operation())),
            expired: false,
        };
        Self {
            telemetry,
            state: Arc::new(Mutex::new(StartupStageState {
                stage,
                span,
                stage_entered: TokioInstant::now(),
            })),
            account_open,
        }
    }

    pub(crate) fn enter(&self, stage: AccountStartupStage) {
        let next = StageSpan {
            observation: Some(self.telemetry.observe(stage.operation())),
            expired: false,
        };
        let mut previous = {
            let mut state = self.state();
            state.stage = stage;
            state.stage_entered = TokioInstant::now();
            std::mem::replace(&mut state.span, next)
        };
        previous.end(TelemetryOutcome::Success);
    }

    fn last_progress(&self) -> TokioInstant {
        let stage_entered = self.state().stage_entered;
        let migrated = *self.account_open.last_migration();
        migrated.map_or(stage_entered, |migrated| migrated.max(stage_entered))
    }

    /// Wait for the worker's ready signal until its startup has made no
    /// progress for `stall`. A long open that keeps moving, such as a fresh
    /// database applying every migration on a slow disk, is not stuck; the
    /// blocking open cannot be cancelled anyway, so giving up on it would only
    /// fail the caller of a startup that is about to finish.
    pub(crate) async fn wait_ready<T>(
        &self,
        mut ready: oneshot::Receiver<T>,
        stall: Duration,
    ) -> Result<Result<T, oneshot::error::RecvError>, StartupStalled> {
        loop {
            let deadline = self.last_progress() + stall;
            match tokio::time::timeout_at(deadline, &mut ready).await {
                Ok(result) => return Ok(result),
                Err(_) if self.last_progress() + stall > TokioInstant::now() => {}
                Err(_) => return Err(StartupStalled),
            }
        }
    }

    /// End the current stage's span: the worker signalled ready, or its open
    /// failed.
    pub(crate) fn finish(&self, outcome: TelemetryOutcome) {
        let mut span = std::mem::take(&mut self.state().span);
        span.end(outcome);
    }

    /// Mark the ready-wait expired in the current stage and name it. The span
    /// stays in flight for as long as the worker's open is in that stage.
    pub(crate) fn expire(&self) -> AccountStartupStage {
        let mut state = self.state();
        state.span.expired = true;
        state.stage
    }

    fn state(&self) -> std::sync::MutexGuard<'_, StartupStageState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
    /// Fired once when the device group unlinks this device and the worker
    /// stops, so the runtime deactivates the account (mdk#2628 D67).
    pub(crate) unlinked: oneshot::Sender<()>,
    /// The gauge the worker sets while it is inside a long unit.
    pub(crate) unit: Arc<WorkerUnitGauge>,
}

pub(crate) enum GroupCreationRequest {
    Group {
        name: String,
        members: Vec<String>,
        prepared_image_upload_id: Option<String>,
    },
    Direct {
        peer_account_id_hex: String,
    },
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
        request: GroupCreationRequest,
        options: AppCreateGroupOptions,
        respond: oneshot::Sender<Result<crate::GroupMemberResult<CanonicalCreatedGroup>, AppError>>,
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
        respond: ReadReply<Result<AppPreparedGroupImageUpload, AppError>>,
    },
    PreparedGroupImages {
        respond: ReadReply<Result<Vec<AppPreparedGroupImageUpload>, AppError>>,
    },
    Members {
        group_id: GroupId,
        respond: ReadReply<Result<Vec<AppGroupMemberRecord>, AppError>>,
    },
    MemberIdsPage {
        group_ids: Vec<GroupId>,
        respond: ReadReply<Result<Vec<crate::AppGroupMemberIds>, AppError>>,
    },
    CaptureConversation {
        queued: Option<Observation>,
        group_id: GroupId,
        query: storage_sqlite::ConversationWindowQuery,
        store_epoch: Vec<u8>,
        observer: Option<std::sync::Weak<super::SendCapture>>,
        respond: ReadReply<Result<CapturedConversation, ConversationWindowError>>,
    },
    GroupMlsState {
        group_id: GroupId,
        respond: ReadReply<Result<AppGroupMlsState, AppError>>,
    },
    GroupRoster {
        group_id: GroupId,
        respond: ReadReply<Result<crate::groups::AppGroupRosterSession, AppError>>,
    },
    EnableGroupDisbanding {
        group_id: GroupId,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    AccountDevicesActivation {
        group_id: GroupId,
        respond: ReadReply<Result<crate::AppAccountDevicesActivation, AppError>>,
    },
    EnableAccountDevices {
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
        respond: ReadReply<Result<Vec<AppQuarantinedGroup>, AppError>>,
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
        respond: ReadReply<Result<SecretBytes, AppError>>,
    },
    ExporterSecret {
        group_id: GroupId,
        label: String,
        length: usize,
        respond: ReadReply<Result<SecretBytes, AppError>>,
    },
    InviteMembers {
        group_id: GroupId,
        members: Vec<String>,
        initial_admins: Vec<String>,
        member_resolution: crate::MemberResolutionPolicy,
        respond: oneshot::Sender<Result<crate::GroupMemberResult<SendSummary>, AppError>>,
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
    CancelLeave {
        group_id: GroupId,
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    /// Stage 1 of `sign_out_and_wipe` for one chat (mdk#2818).
    LeaveGroupForSignOut {
        group_id: GroupId,
        respond: oneshot::Sender<Result<crate::client::sign_out::SignOutLeave, AppError>>,
    },
    /// Where an admin's sign-out leave from one chat stands (mdk#2818).
    SignOutAdminLeave {
        group_id: GroupId,
        respond: oneshot::Sender<Result<crate::client::sign_out::SignOutAdminLeave, AppError>>,
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
        respond: ReadReply<Result<crate::GroupRecoveryStatus, AppError>>,
    },
    HistoryNotices {
        respond: ReadReply<Result<Vec<crate::HistoryNotice>, AppError>>,
    },
    AccountRecoveryStatus {
        respond: ReadReply<Result<crate::AccountRecoveryStatus, AppError>>,
    },
    LinkedDevices {
        respond: ReadReply<Result<Vec<crate::LinkedDevice>, AppError>>,
    },
    ChatHistoryImports {
        respond: ReadReply<Result<Vec<crate::ChatHistoryImport>, AppError>>,
    },
    KeyPackageRefreshOverdue {
        respond: ReadReply<Result<bool, AppError>>,
    },
    UnrecognizedSignIns {
        respond: ReadReply<Result<Vec<crate::UnrecognizedSignIn>, AppError>>,
    },
    AnswerSignIn {
        slot_id_hex: String,
        response: crate::SignInResponse,
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    CheckSignIns {
        respond: oneshot::Sender<Result<Vec<crate::UnrecognizedSignIn>, AppError>>,
    },
    StartFresh {
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    StartedFresh {
        respond: ReadReply<Result<bool, AppError>>,
    },
    CompromiseWarning {
        respond: ReadReply<Result<Vec<crate::CompromiseWarningItem>, AppError>>,
    },
    DismissCompromiseWarning {
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    RenameLinkedDevice {
        slot_id_hex: String,
        label: String,
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    UpdateLinkedDeviceSettings {
        slot_id_hex: String,
        add_to_all_chats: Option<bool>,
        bring_history: Option<bool>,
        keep_while_inactive: Option<bool>,
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    RemoveLinkedDevice {
        slot_id_hex: String,
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    RemovedDeviceLeftoverChats {
        respond: ReadReply<Result<u32, AppError>>,
    },
    ChatsClosedToLinkedDevices {
        respond: ReadReply<Result<u32, AppError>>,
    },
    SignOutThroughSiblingsStep {
        respond: oneshot::Sender<Result<crate::client::sign_out::SiblingSignOut, AppError>>,
    },
    BeginRecoveryWords {
        respond: oneshot::Sender<Result<crate::RecoveryWords, AppError>>,
    },
    ConfirmRecoveryWords {
        answers: Zeroizing<Vec<String>>,
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    CancelRecoveryWords {
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    TurnOffBackups {
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    RunDueBackupPass {
        respond: oneshot::Sender<Result<Option<watch::Receiver<bool>>, AppError>>,
    },
    BeginBackupRestore {
        words: crate::BackupRestoreWords,
        respond: oneshot::Sender<Result<crate::BackupRestoreStatus, AppError>>,
    },
    CancelBackupRestore {
        operation: crate::BackupRestoreId,
        respond: oneshot::Sender<Result<bool, AppError>>,
    },
    BackupRestoreStatus {
        respond: ReadReply<Result<crate::BackupRestoreStatus, AppError>>,
    },
    WatchBackupRestore {
        respond: ReadReply<Result<crate::BackupRestoreWatch, AppError>>,
    },
    HistoryImportProvenance {
        group_id: GroupId,
        event_id: String,
        respond: ReadReply<Result<Option<crate::HistoryImportProvenance>, AppError>>,
    },
    BackupHistoryAvailability {
        group_id: GroupId,
        respond: ReadReply<Result<Vec<crate::BackupHistoryAvailability>, AppError>>,
    },
    BackupSettings {
        respond: ReadReply<Result<crate::BackupSettings, AppError>>,
    },
    DismissHistoryNotice {
        notice_id: String,
        respond: oneshot::Sender<Result<bool, AppError>>,
    },
    AcknowledgeGroupCatchingUp {
        group_id: GroupId,
        respond: oneshot::Sender<Result<bool, AppError>>,
    },
    AcknowledgeGroupCommitUndelivered {
        group_id: GroupId,
        respond: oneshot::Sender<Result<bool, AppError>>,
    },
    GroupCommitDelivery {
        group_id: GroupId,
        respond: ReadReply<Result<Option<crate::GroupCommitDelivery>, AppError>>,
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
    GroupAppComponent {
        group_id: GroupId,
        component_id: u16,
        respond: ReadReply<Result<Option<Vec<u8>>, AppError>>,
    },
    UpdateAppComponent {
        group_id: GroupId,
        component_id: u16,
        data: Vec<u8>,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
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
        respond: ReadReply<Result<Vec<String>, AppError>>,
    },
    UploadMedia {
        admission: OwnedSemaphorePermit,
        group_id: GroupId,
        request: crate::media::file_transfer::MediaUploadPayload,
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
        respond: ReadReply<Result<Vec<PendingWelcomeDelivery>, AppError>>,
    },
    RedeliverWelcome {
        message_id_hex: String,
        respond: oneshot::Sender<Result<SendSummary, AppError>>,
    },
    PublishKeyPackage {
        respond: oneshot::Sender<Result<usize, AppError>>,
    },
    /// Linking a new device of this account (mdk#2628 item 3.3b).
    DeviceLink {
        op: crate::DeviceLinkOp,
        respond: oneshot::Sender<Result<crate::DeviceLinkSnapshot, AppError>>,
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
    /// Delete this device's KeyPackage slot before sign-out tears the worker
    /// down. Answers with the number of relays that accepted.
    WithdrawKeyPackageSlot {
        respond: oneshot::Sender<Result<usize, AppError>>,
    },
    KeyPackageMaintenanceStatus {
        respond: ReadReply<Result<Option<cgka_traits::KeyPackageLifecycleState>, AppError>>,
    },
    DurablyOwnedKeyPackages {
        respond: ReadReply<Result<Vec<KeyPackage>, AppError>>,
    },
    MaintenanceStatus {
        group_id: GroupId,
        respond: ReadReply<Result<cgka_traits::GroupMaintenanceStatus, AppError>>,
    },
    ScheduleManualSelfUpdate {
        group_id: GroupId,
        respond: oneshot::Sender<Result<String, AppError>>,
    },
    PeriodicMaintenancePolicy {
        respond: ReadReply<Result<cgka_traits::PeriodicMaintenancePolicy, AppError>>,
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
    GroupPushDebugInfo {
        group_id: GroupId,
        respond: ReadReply<Result<crate::GroupPushDebugInfo, AppError>>,
    },
    RetryPushRegistration {
        respond: oneshot::Sender<bool>,
    },
    RetryRuntimeGroupSubscriptions {
        respond: oneshot::Sender<bool>,
    },
    ReconnectRelay {
        canonical_url: String,
        respond: oneshot::Sender<Result<crate::RelayLiveness, AppError>>,
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
    #[cfg(test)]
    UnhydratedGroupCount {
        respond: oneshot::Sender<usize>,
    },
    /// Unlink this device as the device group's removal would.
    #[cfg(test)]
    UnlinkDeviceForTest {
        respond: oneshot::Sender<Result<(), AppError>>,
    },
    /// Whether the worker runs a recovery runner, and if so one explicit pass
    /// of it, awaited off the worker. `None` without a runner.
    #[cfg(test)]
    RecoveryRunnerPassForTest {
        budget: Duration,
        respond: oneshot::Sender<Option<crate::client::recovery_runner::PassReport>>,
    },
    /// A receiver on the account's published read state (mdk#3273), `None`
    /// before the worker starts publishing it.
    #[cfg(test)]
    SubscribeReadStateForTest {
        respond:
            oneshot::Sender<Option<watch::Receiver<Arc<crate::client::read_state::ReadState>>>>,
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

/// The original startup command policy applies during both the initial sync
/// future and its off-worker comparison wait. Snapshot reads remain available;
/// mutations and catch-up keep their arrival order in `deferred`. If snapshot
/// capture failed after readiness, reads join that FIFO and use live state
/// after catch-up rather than guessing from an incomplete snapshot.
fn handle_startup_sync_command(
    command: AccountWorkerCommand,
    read_snapshot: Option<&crate::client::GroupReadSnapshot>,
    deferred: &mut Vec<DeferredStartupCommand>,
    setup_key_package_result: &mut Option<Result<usize, AppError>>,
    app: &MarmotApp,
    account_label: &str,
) {
    match command {
        AccountWorkerCommand::Members { group_id, respond } => {
            if let Some(snapshot) = read_snapshot {
                let _ = respond.send_from_snapshot(|| snapshot.members(&group_id));
            } else {
                deferred.push(DeferredStartupCommand::Command(Box::new(
                    AccountWorkerCommand::Members { group_id, respond },
                )));
            }
        }
        AccountWorkerCommand::MemberIdsPage { group_ids, respond } => {
            if let Some(snapshot) = read_snapshot {
                let _ = respond.send_from_snapshot(|| snapshot.member_ids_page(&group_ids));
            } else {
                deferred.push(DeferredStartupCommand::Command(Box::new(
                    AccountWorkerCommand::MemberIdsPage { group_ids, respond },
                )));
            }
        }
        AccountWorkerCommand::CaptureConversation {
            respond, queued, ..
        } => {
            if let Some(queued) = queued {
                queued.finish(TelemetryOutcome::NotReady);
            }
            let _ = respond.send_not_ready(Err(ConversationWindowError::NotReady));
        }
        AccountWorkerCommand::GroupMlsState { group_id, respond } => {
            if let Some(snapshot) = read_snapshot {
                let _ = respond.send_from_snapshot(|| snapshot.group_mls_state(&group_id));
            } else {
                deferred.push(DeferredStartupCommand::Command(Box::new(
                    AccountWorkerCommand::GroupMlsState { group_id, respond },
                )));
            }
        }
        AccountWorkerCommand::GroupRoster { group_id, respond } => {
            if let Some(snapshot) = read_snapshot {
                let _ = respond.send_from_snapshot(|| {
                    group_roster_from_snapshot(app, account_label, snapshot, &group_id)
                });
            } else {
                deferred.push(DeferredStartupCommand::Command(Box::new(
                    AccountWorkerCommand::GroupRoster { group_id, respond },
                )));
            }
        }
        AccountWorkerCommand::QuarantinedGroups { respond } => {
            if let Some(snapshot) = read_snapshot {
                let _ = respond.send_from_snapshot(|| Ok(snapshot.quarantined_groups()));
            } else {
                deferred.push(DeferredStartupCommand::Command(Box::new(
                    AccountWorkerCommand::QuarantinedGroups { respond },
                )));
            }
        }
        AccountWorkerCommand::ConfirmGroupRejoin { respond, .. } => {
            let _ = answer_off_quiescent(respond, Err(AppError::AccountWorkerBusy));
        }
        AccountWorkerCommand::DeclineGroupRejoin { respond, .. } => {
            let _ = answer_off_quiescent(respond, Err(AppError::AccountWorkerBusy));
        }
        AccountWorkerCommand::AcceptGroupInvite { respond, .. } => {
            // Invite acceptance needs live group state and cannot run from a
            // frozen snapshot while initial sync is still pending.
            let _ = answer_off_quiescent(respond, Err(AppError::AccountWorkerBusy));
        }
        AccountWorkerCommand::CatchUp { respond } => {
            // Join the initial catch-up at this FIFO position; do not start a
            // second acquisition while the startup grant is still owned.
            deferred.push(DeferredStartupCommand::CatchUp(respond));
        }
        AccountWorkerCommand::PublishSetupKeyPackage { respond } => {
            match setup_key_package_result.take() {
                Some(result) => {
                    let _ = answer_off_quiescent(respond, result);
                }
                None => deferred.push(DeferredStartupCommand::Command(Box::new(
                    AccountWorkerCommand::PublishSetupKeyPackage { respond },
                ))),
            }
        }
        other => deferred.push(DeferredStartupCommand::Command(Box::new(other))),
    }
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

fn install_storage_telemetry(
    client: &AppClient,
    telemetry: &marmot_observability::PerformanceRecorder,
) {
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
    startup_progress: AccountStartupProgress,
    shutdown: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(run_app_runtime_account_worker(
        runtime,
        command_tx,
        commands,
        ready,
        startup_progress,
        shutdown,
    ))
}

/// Stop the worker's recovery runner, if it runs one, while `client` is
/// still the account's: a quantum in flight settles on it
/// ([`SpawnedRunner::stop`]). Boxed like a command's future, so each of the
/// loop's exits adds a pointer to its stack, not the stop.
fn stop_recovery_runner<'a>(
    runner: &'a mut Option<SpawnedRunner>,
    client: &'a mut AppClient,
) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        if let Some(runner) = runner.take() {
            runner.stop(client).await;
        }
    })
}

async fn run_app_runtime_account_worker(
    runtime: AccountWorkerRuntime,
    command_tx: mpsc::Sender<AccountWorkerCommand>,
    mut commands: mpsc::Receiver<AccountWorkerCommand>,
    ready: oneshot::Sender<Result<(), AppError>>,
    startup_progress: AccountStartupProgress,
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
        unlinked,
        unit,
    } = runtime;
    let mut lifecycle_shutdown = lifecycle.subscribe_shutdown();
    let mut relay_config_updates = app.presentation_signals.profile_updates.subscribe();
    let mut open_client = std::pin::pin!(app.runtime_local_client(
        &account_label,
        &relay_plane,
        lifecycle.clone(),
        Some(&startup_progress),
    ));
    let startup = shared
        .observer
        .performance()
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
        Ok(client) => {
            startup_progress.enter(AccountStartupStage::ReadyHandoff);
            client
        }
        Err(err) => {
            startup_progress.finish(TelemetryOutcome::Failure);
            let message = account_error_message("runtime startup failed", &err);
            publish_app_runtime_account_error(
                Emit::Unpublished(Unpublished::NoClient),
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
    install_storage_telemetry(&client, shared.observer.performance());
    client.runtime_telemetry = Some(shared.observer.performance().clone());
    client.recovery_credits = shared.recovery_credit_pool();
    // A, the published read state, starts before readiness: a host that saw
    // the account ready reads at least the opened state (mdk#3273).
    let prepared_group_image_uploads = UploadsInFlight::default();
    client.start_read_state(prepared_group_image_uploads.clone());
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
        let open_timings = client.runtime.open_timings();
        let telemetry = shared.observer.performance().clone();
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
            Emit::Quiescent(&client),
            &events,
            &account_id_hex,
            &account_label,
            account_error_message("account setup state lookup failed", error),
        );
    }
    if let Some(ready) = ready.take() {
        shared.observer.performance().record(
            AppPerformanceOperation::AccountWorkerReadiness,
            worker_started_at.elapsed(),
            true,
        );
        startup_progress.finish(TelemetryOutcome::Success);
        // Readiness answers the host's reconcile: publish what the open wrote.
        client.publish_read_state();
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
            shared.observer.performance().record(
                AppPerformanceOperation::AccountInitialKeyPackagePublish,
                started_at.elapsed(),
                result.is_ok(),
            );
            // The durable setup lane serializes these phases by design. Record
            // an explicit zero rather than omitting the sample so hosts can
            // distinguish "publication finished before sync" from "overlap
            // was not observed".
            shared.observer.performance().record(
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
        StartupHydrationOutcome::Shutdown { explicit } => {
            if explicit {
                client.finish_audit_recording();
            }
            return;
        }
    }
    // A removal from the device group applied on an earlier run, which then
    // ended before it was followed, stops the account before catch-up sends
    // anything (mdk#2628 D67).
    client.follow_device_group_removal().await;
    if client.device_unlinked() {
        stop_unlinked_worker(&mut client, unlinked).await;
        return;
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
            client.group_read_snapshot_with_stage_telemetry(shared.observer.performance());
        shared.observer.performance().record(
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
                    Emit::Quiescent(&client),
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
    // signalled. Until a comparison network job is selected, the sync future
    // holds `&mut client`: read commands use `read_snapshot`, invite acceptance
    // gets a typed definitely-not-started busy response, and other commands
    // join the startup FIFO. During an off-worker comparison the worker can
    // serve eligible live commands without passing ownership of `client` to
    // the network job. Deferred commands replay in arrival order after catch-up.
    let mut local_submission_wakeups = shared.local_submission_wakeups.subscribe();
    let mut local_submission_due = true;
    let mut local_submission_retry_at = TokioInstant::now();
    let sync_started_at = Instant::now();
    let startup_stage_telemetry = shared.observer.performance().clone();
    let mut startup_explicit_shutdown = false;
    let publish_startup_summary = |client: &AppClient, summary: &SyncSummary| {
        publish_app_runtime_summary_with_v5_at(
            Emit::Unpublished(Unpublished::DrainProgress),
            client,
            &events,
            &account_id_hex,
            &account_label,
            summary,
        );
        if sync_summary_triggers_audit_tracker_update(summary) {
            shared.schedule_audit_log_tracker_update("startup_sync");
        }
    };
    let report_startup_join_errors = |live_error, history_error| {
        publish_join_errors(
            Emit::Unpublished(Unpublished::DrainProgress),
            live_error,
            history_error,
            &events,
            &account_id_hex,
            &account_label,
        );
    };
    let publish_startup_progress = CommittedSyncProgress {
        publish: &publish_startup_summary,
        post_join_errors: &report_startup_join_errors,
    };
    let startup_sync_result = {
        let _unit = unit.enter(WorkerUnit::StartupSync);
        let mut initial_sync: Pin<
            Box<dyn Future<Output = Result<SyncSummary, ClassifiedSyncFailure>> + Send + '_>,
        > = Box::pin(async {
            #[cfg(any(test, feature = "test-policy-overrides"))]
            if let Some(barrier) = shared.take_next_startup_sync_barrier() {
                // First acknowledge entry, then hold sync until the test has
                // exercised the command loop below.
                barrier.wait().await;
                barrier.wait().await;
            }
            let state_persist = |error| {
                ClassifiedSyncFailure::at_stage(
                    SyncSummary::default(),
                    error,
                    SyncFailureStage::StatePersist,
                )
            };
            // Activation installs the complete current group set, so a routing
            // change found here needs no separate refresh.
            client.refresh_sync_routes().map_err(state_persist)?;
            // The session's first live subscriptions, floored at the cursor,
            // go out before recovery observations are flushed. A failed
            // attempt has side effects, so it is startup's failure.
            client
                .activate_live_transport(Some(&startup_stage_telemetry))
                .await?;
            client
                .prepare_startup_recovery()
                .await
                .map_err(state_persist)?;
            let summary = client
                .finish_deferred_comparison_sync(Some(&publish_startup_progress))
                .await?;
            if !client.device_unlinked() {
                app.finish_client_open_network_maintenance(&mut client)
                    .await;
            }
            Ok::<_, ClassifiedSyncFailure>(summary)
        });
        loop {
            tokio::select! {
                _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => {
                    startup_explicit_shutdown = runtime_shutdown_requested(&lifecycle_shutdown);
                    break None;
                }
                stop = &mut shutdown => {
                    startup_explicit_shutdown = stop.is_ok();
                    break None;
                }
                result = &mut initial_sync => break Some(result),
                command = commands.recv() => {
                    match command {
                        None => break None,
                        Some(command) => handle_startup_sync_command(
                            command,
                            read_snapshot.as_ref(),
                            &mut deferred,
                            &mut setup_key_package_result,
                            &app,
                            &account_label,
                        ),
                    }
                }
            }
        }
    };
    let Some(startup_sync_result) = startup_sync_result else {
        if startup_explicit_shutdown {
            client.finish_audit_recording();
        }
        return;
    };
    let mut startup_sync_result = startup_sync_result;
    // A removal the catch-up applied stops the account before anything
    // else goes out (mdk#2628 D67).
    if client.device_unlinked() {
        stop_unlinked_worker(&mut client, unlinked).await;
        return;
    }
    if let Err(failure) = &mut startup_sync_result {
        client.drain_epoch_stall_escalations(&mut failure.partial_summary);
    }
    shared.observer.performance().record_classified_result(
        AppPerformanceOperation::AccountSync,
        sync_started_at.elapsed(),
        startup_sync_result
            .as_ref()
            .err()
            .map(ClassifiedSyncFailure::classification),
    );
    let catch_up_result = match startup_sync_result {
        Ok(summary) => {
            publish_app_runtime_summary_with_v5(
                &client,
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
            // A start gets no host connectivity edge, so wake the sends a
            // previous process left backed off (mdk#2762).
            wake_retained_sends_after_transport_start(&mut client, "startup_retained_send_wake");
            schedule_pending_convergence_groups(&mut scheduled_convergence, &mut client);
            if sync_summary_triggers_audit_tracker_update(&summary) {
                shared.schedule_audit_log_tracker_update("startup_sync");
            }
            Ok(())
        }
        Err(failure) => {
            publish_sync_summary_with_audit(
                &client,
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
                Emit::Quiescent(&client),
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
                    publish_app_runtime_summary_with_v5(
                        &client,
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
                }
                Err(drain_error) => {
                    publish_app_runtime_account_error(
                        Emit::Quiescent(&client),
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
    // A removal from the device group that the catch-up applied stops the
    // account before the deferred commands replay (mdk#2628 D67).
    client.follow_device_group_removal().await;
    if client.device_unlinked() {
        stop_unlinked_worker(&mut client, unlinked).await;
        return;
    }
    // Replay commands deferred during the initial catch-up in arrival order, now
    // on live state. Coalesced `CatchUp` waiters are fulfilled at their position
    // with the initial catch-up's result. Replay uses the live command queue so
    // post-canonical snapshot reads (Members / GroupRoster / …) can land while
    // a deferred create/invite still owns Welcome fanout.
    let (media_http_tx, mut media_http_rx) = mpsc::unbounded_channel();
    let (media_http_worker_lifetime, _) = watch::channel(());
    let media_http = MediaHttpContext {
        product: shared.observer.product().clone(),
        tx: media_http_tx,
        permits: Arc::new(Semaphore::new(MEDIA_HTTP_IN_FLIGHT_LIMIT)),
        prepared_group_image_uploads,
        history_blobs: HistoryBlobFlights::default(),
        backup_background_conditions: shared.backup_background_conditions.clone(),
        worker_lifetime: media_http_worker_lifetime,
    };
    let mut backup_condition_updates = client
        .app
        .device_groups_enabled()
        .then(|| shared.backup_background_conditions.subscribe());
    // The account's recovery runner (mdk#2660 phase 4). Spawned before the
    // deferred commands replay, so a repair among them goes through it; its
    // turns wait until a repair or the loop below serves them.
    let mut recovery_runner = client.spawn_recovery_runner().await;
    // What the runner's survey finds catching up; only a runner changes it.
    // Each client has its own, so a reconnect subscribes again.
    let mut recovery_catching_up = client.routing.subscribe_recovery_runner_catching_up();
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
                        unit: &unit,
                    },
                )
                .await;
            }
            AccountWorkerCommand::PublishSetupKeyPackage { respond }
                if setup_key_package_result.is_some() =>
            {
                // The durable setup lane may publish before background setup
                // sends its worker command. Return that exact result even if
                // the initial catch-up has already finished.
                let _ = reply(
                    respond,
                    setup_key_package_result
                        .take()
                        .expect("cached setup result"),
                    &client,
                );
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
                        recovery_runner: recovery_runner.as_mut(),
                        unit: &unit,
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
    // Automatic gossip must not postpone the first durable drain behind
    // unrelated network I/O. The durable outbox arms the existing retry timer;
    // explicit registration and departure commands retain their own semantics.
    scheduled_push_retry.observe_pending(client.has_pending_push_registration_work(), &command_tx);
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
    let product_backlog = shared.observer.product().backlog_source();
    let mut maintenance_tick = interval(Duration::from_secs(15));
    maintenance_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut legacy_message_promotion = LegacyMessagePromotionSchedule::new();
    let mut presentation_maintenance = super::presentation::PresentationMaintenance::default();
    let mut presentation_wakeups = app.presentation_signals.subscribe_work();
    let mut relay_config_work = RelayConfigWork::Ready;
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
    let mut local_submission_service_owed = false;
    let mut replay_changes = client.adapter.replay_changes().await;
    let mut admission_retry = ReplayAdmissionRetry::default();
    'worker: loop {
        // The previous unit has ended: publish what it wrote (mdk#3273).
        client.publish_read_state();
        // An unlinked device stops: no sends, commits, publications or
        // pairing answers once its device group removed it. The account is
        // already marked unlinked; the runtime deactivates it once this
        // worker has exited (mdk#2628 D67).
        if client.device_unlinked() {
            stop_recovery_runner(&mut recovery_runner, &mut client).await;
            stop_unlinked_worker(&mut client, unlinked).await;
            break 'worker;
        }
        if recovery_runner.is_none() && client.recovery_runner_due() {
            // A successful paced preparation retry starts the runner here,
            // even when that refresh failed afterwards. A failure re-arms
            // that retry rather than spinning in this loop.
            recovery_runner = client.spawn_recovery_runner().await;
        }
        // Activation may replace the source watch. Reacquire only a live
        // receiver; a closed activation must not turn this into a busy loop.
        if replay_changes.is_none() {
            replay_changes = client
                .adapter
                .replay_changes()
                .await
                .filter(|changes| changes.has_changed().is_ok());
            if replay_changes.is_some() {
                relay_config_work = RelayConfigWork::Ready;
            }
        }
        // Native frames admit a few per turn; a failed turn paces its retry.
        let native_progress = match if !admission_retry.ready() {
            Ok(false)
        } else {
            admission_retry.admit_native_turn(&mut client).await
        } {
            Ok(progress) => progress,
            Err(error) => {
                publish_app_runtime_account_error(
                    Emit::Quiescent(&client),
                    &events,
                    &account_id_hex,
                    &account_label,
                    account_error_message("native replay admission failed", &error),
                );
                false
            }
        };
        // Admission can apply this device's removal; the loop top stops.
        if client.device_unlinked() {
            continue 'worker;
        }
        // One recovery runner turn per pass of the loop, as native admission
        // gets one above, so ready commands and live input never starve the
        // runner (or a credit its quantum holds). What it admits publishes
        // below.
        if !client.has_pending_effect_projections()
            && let Some(turn) = recovery_runner.as_mut().and_then(SpawnedRunner::ready_turn)
        {
            turn.serve(&mut client).await;
            publish_settled_recovery_copies(&mut client, &events, &account_id_hex, &account_label);
        }
        // Native and runner admission may have advanced frames. Publish their
        // committed effects before live input.
        let admitted = client.take_pending_applied_sync_summary();
        let native_received = client.take_native_receive_need();
        publish_app_runtime_summary_with_v5(
            &client,
            &events,
            &account_id_hex,
            &account_label,
            &admitted,
        );
        if native_received || admitted != SyncSummary::default() {
            publish_client_pending_projection_updates(
                &mut client,
                &events,
                &account_id_hex,
                &account_label,
            );
            start_post_join_history_after_visibility(
                &mut client,
                &admitted,
                &events,
                &account_id_hex,
                &account_label,
            )
            .await;
            // Native-owned live group frames have the same recovery follow-up
            // as ordinary receives, including frames with no visible summary.
            let _ = refresh_recovery_at_seam(
                &mut client,
                EpochBackfillReportContext {
                    events: &events,
                    account_id_hex: &account_id_hex,
                    account_label: &account_label,
                    shared: &shared,
                },
            )
            .await;
            let audit_tracker_update = sync_summary_triggers_audit_tracker_update(&admitted);
            let retry_push_registration = !admitted.joined_groups.is_empty();
            finish_receive_after_recovery(
                &mut client,
                ReceiveTailContext {
                    events: &events,
                    account_id_hex: &account_id_hex,
                    account_label: &account_label,
                    shared: &shared,
                    scheduled_push_retry: &mut scheduled_push_retry,
                    command_tx: &command_tx,
                },
                audit_tracker_update,
                retry_push_registration,
            )
            .await;
        }
        scheduled_runtime_group_subscription_refresh.observe_pending(
            client.has_pending_runtime_group_subscription_refresh(),
            &command_tx,
        );
        schedule_push_work_after_turn(&mut client, &mut scheduled_push_retry, &command_tx);
        schedule_pending_convergence_groups(&mut scheduled_convergence, &mut client);
        // Whichever seam parked or woke a convergence pass (mdk#2684), its
        // schedule read above queued the notice.
        for group_id in client.take_convergence_park_notices() {
            publish_app_runtime_group_state_updated(
                Emit::Quiescent(&client),
                &events,
                &account_id_hex,
                &account_label,
                &group_id,
            );
        }
        let ready_command = ready_command_index(&pending, &media_http);
        #[cfg(test)]
        tests::secondary_retry_scheduler_tests::record_turn(
            &account_id_hex,
            pending.len(),
            commands.len(),
            yield_to_convergence,
        );
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => {
                client.finish_audit_recording();
                stop_recovery_runner(&mut recovery_runner, &mut client).await;
                break 'worker;
            }
            stop = &mut shutdown => {
                if stop.is_ok() {
                    client.finish_audit_recording();
                }
                stop_recovery_runner(&mut recovery_runner, &mut client).await;
                break 'worker;
            }
            () = std::future::ready(()), if relay_config_work == RelayConfigWork::Ready => {
                relay_config_work = match client.sync_relay_liveness().await {
                    Ok(_) => RelayConfigWork::Idle,
                    Err(error) if error.is_account_not_active() => RelayConfigWork::RetryOnTick,
                    Err(error) => {
                        publish_app_runtime_account_error(
                            Emit::Quiescent(&client),
                            &events,
                            &account_id_hex,
                            &account_label,
                            account_error_message("relay configuration reconciliation failed", &error),
                        );
                        RelayConfigWork::RetryOnTick
                    }
                };
            }
            result = relay_config_updates.recv() => {
                let mut changed = match result {
                    Ok(account_id) => account_id == account_id_hex,
                    Err(broadcast::error::RecvError::Lagged(_)) => true,
                    Err(broadcast::error::RecvError::Closed) => break 'worker,
                };
                loop {
                    match relay_config_updates.try_recv() {
                        Ok(account_id) => changed |= account_id == account_id_hex,
                        Err(broadcast::error::TryRecvError::Lagged(_)) => changed = true,
                        Err(broadcast::error::TryRecvError::Empty) => break,
                        Err(broadcast::error::TryRecvError::Closed) => break 'worker,
                    }
                }
                if changed {
                    relay_config_work = RelayConfigWork::Ready;
                }
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
                    let _ = reply(respond, (), &client);
                }
            }
            // Consume completed blobs before admitting more commands.
            done = media_http_rx.recv() => {
                match done {
                    Some(done) => {
                        complete_media_http(&mut client, done, &shared, &media_http).await;
                        // Ordinary transfers return the same credits used by
                        // restore; resume only after completion released one.
                        dispatch_backup_restore(&mut client, &media_http);
                        dispatch_backup_pass(&mut client, &media_http);
                        // A fetched history imports messages; show them, and
                        // the chat's history state, now, not at the next
                        // maintenance pass.
                        publish_client_pending_projection_updates(
                            &mut client,
                            &events,
                            &account_id_hex,
                            &account_label,
                        );
                        publish_device_group_changes(
                            &mut client,
                            &events,
                            &account_id_hex,
                            &account_label,
                        );
                        avatar_due = true;
                        attachment_due = true;
                        schedule_pending_convergence_groups(
                            &mut scheduled_convergence,
                            &mut client,
                        );
                    }
                    None => {
                        stop_recovery_runner(&mut recovery_runner, &mut client).await;
                        break 'worker;
                    }
                }
            }
            // Settle ready media before a platform wake admits more work.
            _ = async {
                backup_condition_updates
                    .as_mut()
                    .expect("enabled backup condition subscription")
                    .changed()
                    .await
            }, if backup_condition_updates.is_some() => {
                dispatch_backup_pass(&mut client, &media_http);
            }
            // Alternate a command and a ready recovery quantum. A permanently
            // nonempty command channel must not starve group convergence.
            command = async {
                match ready_command.and_then(|index| pending.remove(index)) {
                    Some(command) => Some(command),
                    None => commands.recv().await,
                }
            }, if !yield_to_convergence || !scheduled_convergence.has_ready() || scheduled_convergence_held_for_test(&account_id_hex) => {
                yield_to_convergence = true;
                match command {
                    Some(command) => {
                        #[cfg(test)]
                        tests::secondary_retry_scheduler_tests::record_command(&account_id_hex, &command);
                        let command = match command {
                            AccountWorkerCommand::Drain { respond } => {
                                if let Some(recovery) = &mut welcome_recovery {
                                    recovery.drain_waiters.push(respond);
                                } else {
                                    let _ = reply(respond, (), &client);
                                }
                                continue;
                            }
                            #[cfg(test)]
                            AccountWorkerCommand::RecoveryRunnerPassForTest { budget, respond } => {
                                match &recovery_runner {
                                    Some(runner) => {
                                        let handle = runner.handle().clone();
                                        tokio::spawn(async move {
                                            let _ = answer_off_quiescent(respond, handle.run_pass(budget).await);
                                        });
                                    }
                                    None => {
                                        let _ = reply(respond, None, &client);
                                    }
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
                                        unit: &unit,
                                    },
                                )
                                .await;
                            }
                            AccountWorkerCommand::PublishSetupKeyPackage { respond }
                                if setup_key_package_result.is_some() =>
                            {
                                let _ = reply( respond,
                                    setup_key_package_result.take().expect("cached setup result"),&client,
                                );
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
                                        recovery_runner: recovery_runner.as_mut(),
                                        unit: &unit,
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
                    None => {
                        stop_recovery_runner(&mut recovery_runner, &mut client).await;
                        break 'worker;
                    }
                }
            }
            // A completed optional retry owes durable admission one turn once
            // its finite command predecessors have drained. Keep the existing
            // command/convergence alternation, including blocked predecessors.
            _ = tokio::time::sleep_until(local_submission_retry_at),
                if local_submission_service_owed && local_submission_due
                    && pending.is_empty() && commands.is_empty()
                    && !lifecycle.is_stopping() => {
                // Recheck after polling the deadline: a buffered command may
                // have arrived while the normal command arm was fairness-gated.
                if !pending.is_empty() || !commands.is_empty() { continue 'worker; }
                let retry = publish_next_local_submission(
                    &mut client, &app, &shared, &unit, &events,
                    &account_id_hex, &account_label,
                ).await;
                local_submission_service_owed = false;
                local_submission_due = retry.is_some();
                if let Some(delay) = retry {
                    local_submission_retry_at = TokioInstant::now() + delay;
                    schedule_pending_convergence_groups(&mut scheduled_convergence, &mut client);
                }
            }
            _ = scheduled_convergence.timer.as_mut(), if !scheduled_convergence_held_for_test(&account_id_hex) => {
                yield_to_convergence = false;
                let Some(group_id) = scheduled_convergence.take_ready() else { continue };
                let local_submission_yield = wait_for_local_submission_or_shutdown(
                    app.clone(),
                    account_label.clone(),
                    shared.local_submission_gate(&account_id_hex),
                    shared.local_submission_wakeups.subscribe(),
                    lifecycle.subscribe_shutdown(),
                ).boxed().shared();
                let yield_observation = local_submission_yield.clone();
                let (send_waiting, send_requested) = oneshot::channel();
                let secondary_retry_yield = async move {
                    tokio::select! {
                        biased;
                        _ = local_submission_yield => {},
                        _ = send_requested => {},
                    }
                };
                let phase = shared.observer.performance().observe(RuntimeOp::WorkerConvergence);
                let _unit = unit.enter(WorkerUnit::Convergence);
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
                                let progress = Arc::new(ProjectionPublicationProgress::new(
                                    events.clone(), &account_id_hex, &account_label,
                                ));
                                let progress_sink = progress.clone();
                                let on_publication = Arc::new(move |update| {
                                    progress_sink.publish(update);
                                });
                                let result = client.advance_convergence_with_projection_progress_and_yield(
                                    &group_id, Some(on_publication), secondary_retry_yield,
                                ).await;
                                record_runtime_publication(
                                    &client,
                                    marmot_forensics::v5::RuntimePublicationCategory::ProjectionUpdate,
                                    None,
                                    progress.take_publication(),
                                );
                                match result {
                                    Ok(summary) => {
                                        publish_app_runtime_summary_with_v5(&client, &events, &account_id_hex, &account_label, &summary);
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
                                                    Emit::Quiescent(&client),
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
                                        let audit_tracker_update = sync_summary_triggers_audit_tracker_update(&summary);
                                        let _ = refresh_recovery_at_seam(
                                            &mut client,
                                            EpochBackfillReportContext {
                                                events: &events,
                                                account_id_hex: &account_id_hex,
                                                account_label: &account_label,
                                                shared: &shared,
                                            },
                                        ).await;
                                        if audit_tracker_update {
                                            shared.schedule_audit_log_tracker_update("scheduled_convergence");
                                        }
                                    }
                                    Err(err) => {
                                        let mut retry_groups = client.take_pending_convergence_groups();
                                        retry_groups.push(group_id.clone());
                                        scheduled_convergence.schedule_retry_groups(retry_groups);
                                        publish_app_runtime_account_error(
                                            Emit::Quiescent(&client),
                                            &events,
                                            &account_id_hex,
                                            &account_label,
                                            account_error_message("scheduled convergence failed", &err),
                                        );
                                        // A failure that spent the pass's budget
                                        // parks it (mdk#2684); the next turn
                                        // tells hosts to re-read the group.
                                        if let Ok(parked) = client.convergence_pass_parked(&group_id) {
                                            client.note_convergence_park(&group_id, parked);
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                scheduled_convergence.schedule_retry_groups([group_id]);
                                publish_app_runtime_account_error(
                                    Emit::Quiescent(&client),
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
                    Some(send_waiting),
                ))
                .await;
                // Durable work can arrive after a direct send ended the relay
                // wait. Poll again before deciding whether it is owed a turn.
                if yield_observation.now_or_never().is_some() {
                    local_submission_service_owed = true;
                    // Never erase the ordinary drain's contention/completion
                    // backoff merely because another optional pass yielded.
                    if !local_submission_due {
                        local_submission_due = true;
                        local_submission_retry_at = TokioInstant::now();
                    }
                }
                #[cfg(test)]
                tests::secondary_retry_scheduler_tests::pass_tail(&account_id_hex).await;

                phase.finish(TelemetryOutcome::Success);
            }
            changed = wait_for_replay_change(&mut replay_changes) => {
                if !changed {
                    replay_changes = None;
                    continue 'worker;
                }
                if let Err(error) = client.synchronize_native_replay().await {
                    publish_app_runtime_account_error(
                        Emit::Quiescent(&client),
                        &events,
                        &account_id_hex,
                        &account_label,
                        account_error_message("native replay synchronization failed", &error),
                    );
                }
                publish_account_level_changes(
                    &mut client, &events, &account_id_hex, &account_label,
                );
            }
            received = client.receive_next_delivery(), if !client.has_pending_effect_projections() => {
                #[cfg(test)]
                if let Ok(transport_nostr::AccountDeliveryReceive::Delivery(delivery)) = &received
                    && let (Ok(event_id), Some(subscription_id)) = (
                        <[u8; 32]>::try_from(delivery.message.id.as_slice()),
                        delivery.source.subscription_id.as_ref(),
                    )
                {
                    let drop_this = shared
                        .ordinary_drop_once
                        .lock()
                        .unwrap()
                        .take_if(|target| {
                            target.account_label == account_label && target.event_id == event_id
                        })
                        .is_some();
                    if drop_this {
                        *shared.ordinary_drop_witness.lock().unwrap() =
                            Some(subscription_id.clone());
                        shared.ordinary_delivery_dropped.notify_one();
                        continue 'worker;
                    }
                }
                // Only the transport wait participates in `select!`. Once a
                // delivery has been claimed, finish ingest + incidental
                // publish + projection as one uncancelled worker operation;
                // commands remain queued until that durable sequence lands.
                let delivery_started = matches!(&received, Ok(transport_nostr::AccountDeliveryReceive::Delivery(_)))
                    .then(Instant::now);
                let receive_observation = shared.observer.performance().observe(RuntimeOp::WorkerReceive);
                let result = match received {
                    Ok(transport_nostr::AccountDeliveryReceive::Delivery(delivery)) => {
                        let ingested = client.ingest_received_delivery(*delivery).await;
                        // Pairing messages arrive among the account's gift
                        // wraps; answer them while the other device waits.
                        client.drive_device_pairing().await;
                        ingested
                    }
                    // receive_next_delivery persisted the loss. The owned
                    // comparison job dispatched below recovers it off the
                    // worker, never by replaying live subscriptions.
                    Ok(transport_nostr::AccountDeliveryReceive::Overflow(_)) => {
                        Ok(SyncSummary::default())
                    }
                    Err(err) => Err(err),
                };
                if result.is_err() && let Some(started) = delivery_started {
                    shared.observer.performance().record(
                        AppPerformanceOperation::InboundDeliveryProjection,
                        started.elapsed(),
                        false,
                    );
                }
                receive_observation.finish_app(&result);
                match result {
                    Ok(summary) => {
                        reconnect_backoff.reset();
                        publish_app_runtime_summary_with_v5(&client, &events, &account_id_hex, &account_label, &summary);
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
                            shared.observer.performance().record(
                                AppPerformanceOperation::InboundDeliveryProjection,
                                started.elapsed(),
                                true,
                            );
                        }
                        if client.device_unlinked() {
                            // Nothing more goes out; the next turn stops the worker.
                            continue 'worker;
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
                        let _ = refresh_recovery_at_seam(
                            &mut client,
                            EpochBackfillReportContext {
                                events: &events,
                                account_id_hex: &account_id_hex,
                                account_label: &account_label,
                                shared: &shared,
                            },
                        ).await;
                        let audit_tracker_update = sync_summary_triggers_audit_tracker_update(&summary);
                        let retry_push_registration = !summary.joined_groups.is_empty();
                        finish_receive_after_recovery(
                            &mut client,
                            ReceiveTailContext {
                                events: &events,
                                account_id_hex: &account_id_hex,
                                account_label: &account_label,
                                shared: &shared,
                                scheduled_push_retry: &mut scheduled_push_retry,
                                command_tx: &command_tx,
                            },
                            audit_tracker_update, retry_push_registration,
                        ).await;
                    }
                    Err(err) => {
                        publish_app_runtime_account_error(
                            Emit::Quiescent(&client),
                            &events,
                            &account_id_hex,
                            &account_label,
                            account_error_message("runtime receive failed", &err),
                        );
                        if client.arm_failed_receive_projection_retry() {
                            // Reopening cannot reconstruct consumed activity events
                            // or the output of a batch awaiting its state checkpoint.
                            // Keep the owning client for the bounded projection retry.
                            scheduled_runtime_group_subscription_refresh.observe_pending(
                                true, &command_tx,
                            );
                            continue 'worker;
                        }
                        // The account-session ownership guard is held by
                        // `AppClient`. Destroy the failed engine before the
                        // backoff as well as before hydrating its replacement;
                        // this leaves room for a one-shot client during a
                        // prolonged transport outage.
                        let transport_account = client.adapter.account_id().clone();
                        // Its turns need this client; the reopened one gets
                        // a runner of its own.
                        stop_recovery_runner(&mut recovery_runner, &mut client).await;
                        // A outlives the client: its successor continues
                        // the versions (mdk#3273).
                        let mut read_state = client.take_read_state();
                        drop(client);
                        client = loop {
                            let reconnect_wait = shared.observer.performance().observe(RuntimeOp::WorkerReconnectWait);
                            let retry_started_at = Instant::now();
                            let mut retry_delay =
                                std::pin::pin!(sleep(reconnect_backoff.next_delay()));
                            loop {
                                tokio::select! {
                                    _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => break 'worker,
                                    _ = &mut shutdown => break 'worker,
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
                                                            let _ = respond.send_not_ready(Err(ConversationWindowError::NotReady));
                                                        }
                                                        command => {
                                                            shared.observer.performance().record_runtime(RuntimeOp::ReconnectCommandRejected, Duration::ZERO, TelemetryOutcome::NotReady);
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
                                                let _ = respond.send_not_ready(Err(ConversationWindowError::NotReady));
                                            }
                                            // There is deliberately no engine
                                            // session during this backoff.
                                            // Poll the bounded channel and
                                            // reject callers promptly by
                                            // dropping their response sender
                                            // instead of letting the queue fill
                                            // until host-side timeouts fire.
                                            Some(command) => {
                                                shared.observer.performance().record_runtime(RuntimeOp::ReconnectCommandRejected, Duration::ZERO, TelemetryOutcome::NotReady);
                                                drop(command);
                                            },
                                            None => break 'worker,
                                        }
                                    }
                                }
                            }
                            reconnect_wait.finish(TelemetryOutcome::Success);
                            let reopen = shared.observer.performance().observe(RuntimeOp::WorkerReopen);
                            let reopened_result = tokio::select! {
                                _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => break 'worker,
                                _ = &mut shutdown => break 'worker,
                                result = async {
                                    // The reopened session registers a new signer,
                                    // so retire the previous session's SDK context.
                                    relay_plane.retire_account_session_transport(&transport_account).await;
                                    app.runtime_local_client(&account_label, &relay_plane, lifecycle.clone(), None).await
                                } => result,
                            };
                            reopen.finish_app(&reopened_result);
                            match reopened_result {
                                Ok(mut reopened) => {
                                    install_storage_telemetry(&reopened, shared.observer.performance());
                                    reopened.runtime_telemetry = Some(shared.observer.performance().clone());
                                    reopened.recovery_credits = shared.recovery_credit_pool();
                                    reopened.resume_read_state(read_state.take());
                                    // A reconnect open is deferred like the
                                    // startup open; drain the hydration
                                    // eagerly here — the steady-state loop
                                    // below answers reads live and must not
                                    // hand out not-hydrated errors after a
                                    // mid-session reconnect (mdk#1161).
                                    if let Err(err) = drain_deferred_hydration(&mut reopened).await
                                    {
                                        publish_app_runtime_account_error(
                                            Emit::Quiescent(&reopened),
                                            &events,
                                            &account_id_hex,
                                            &account_label,
                                            account_error_message(
                                                "runtime restart hydration failed",
                                                &err,
                                            ),
                                        );
                                        read_state = reopened.take_read_state();
                                        drop(reopened);
                                        continue;
                                    }
                                    // Reconnect restores transport activation
                                    // and subscriptions, then resumes the live
                                    // receive tail. Do not block the command
                                    // loop on a full catch-up; the maintenance
                                    // path performs bounded repair syncs when
                                    // required.
                                    let telemetry = shared.observer.performance().clone();
                                    let prepare_transport = tokio::select! {
                                        _ = wait_for_runtime_shutdown(&mut lifecycle_shutdown) => {
                                            reopened.finish_audit_recording();
                                            break 'worker;
                                        }
                                        stop = &mut shutdown => {
                                            if stop.is_ok() {
                                                reopened.finish_audit_recording();
                                            }
                                            break 'worker;
                                        }
                                        result = reopened.prepare_transport_with_telemetry(Some(&telemetry)) => result,
                                    };
                                    if let Err(transport_err) = prepare_transport {
                                        publish_app_runtime_account_error(
                                            Emit::Quiescent(&reopened),
                                            &events,
                                            &account_id_hex,
                                            &account_label,
                                            account_error_message(
                                                "runtime restart transport failed",
                                                &transport_err,
                                            ),
                                        );
                                        read_state = reopened.take_read_state();
                                        drop(reopened);
                                        continue;
                                    }
                                    app.finish_client_open_network_maintenance(&mut reopened)
                                        .await;
                                    match reopened.drain_pending_session_events().await {
                                        Ok(summary) => {
                                            publish_app_runtime_summary_with_v5(&reopened,
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
                                                Emit::Quiescent(&reopened),
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
                                    // A reopen while the host's network
                                    // stayed up gets no connectivity edge to
                                    // release sends backed off by the outage
                                    // that closed the old transport (mdk#2762).
                                    wake_retained_sends_after_transport_start(
                                        &mut reopened,
                                        "reopen_retained_send_wake",
                                    );
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
                                        Emit::Unpublished(Unpublished::NoClient),
                                        &events,
                                        &account_id_hex,
                                        &account_label,
                                        account_error_message("runtime restart failed", &setup_err),
                                    );
                                }
                            }
                        };
                        relay_config_work = RelayConfigWork::Ready;
                        replay_changes = client.adapter.replay_changes().await;
                        recovery_runner = client.spawn_recovery_runner().await;
                        recovery_catching_up =
                            client.routing.subscribe_recovery_runner_catching_up();
                        schedule_pending_convergence_groups(
                            &mut scheduled_convergence,
                            &mut client,
                        );
                        continue 'worker;
                    }
                }
            }
            // An idle worker waits for the runner's next turn here; the
            // loop's top serves one per pass while other work is ready.
            turn = next_runner_turn(&mut recovery_runner), if !client.has_pending_effect_projections() => {
                turn.serve(&mut client).await;
                publish_settled_recovery_copies(&mut client, &events, &account_id_hex, &account_label);
            }
            Ok(()) = recovery_catching_up.changed() => {
                client.recovery_status_owed = true;
                publish_account_level_changes(&mut client, &events, &account_id_hex, &account_label);
            }
            _ = tokio::task::yield_now(), if avatar_due && !lifecycle.is_stopping() => {
                avatar_due = false;
                let step = shared.observer.performance().observe(RuntimeOp::WorkerAvatarPass);
                let identities = avatar_identities.run(&client, &account_id_hex);
                let acquisition = schedule_avatar_acquisition(&client, &media_http, &mut avatar_resumed);
                step.finish(if identities.is_ok() && acquisition.is_ok() {
                    TelemetryOutcome::Success
                } else {
                    TelemetryOutcome::Failure
                });
                avatar_due |= identities.as_ref().is_ok_and(|more| *more)
                    || acquisition.as_ref().is_ok_and(|more| *more);
                if identities.is_err() || acquisition.is_err() {
                    tracing::warn!(target: "marmot_app::runtime", method = "avatar_acquisition",
                        "avatar maintenance failed; retrying on the next tick");
                }
            }
            _ = local_submission_wakeups.changed() => { local_submission_due = true; }
            _ = tokio::time::sleep_until(local_submission_retry_at),
                if local_submission_due && (!local_submission_service_owed
                    || (pending.is_empty() && commands.is_empty())) => {
                let retry = publish_next_local_submission(
                    &mut client, &app, &shared, &unit, &events,
                    &account_id_hex, &account_label,
                ).await;
                local_submission_service_owed = false;
                local_submission_due = retry.is_some();
                if let Some(delay) = retry {
                    local_submission_retry_at = TokioInstant::now() + delay;
                    schedule_pending_convergence_groups(&mut scheduled_convergence, &mut client);
                }
            }
            result = presentation_wakeups.changed() => {
                if result.is_ok() { presentation_due = true; avatar_due = true; attachment_due = true; }
            }
            _ = tokio::task::yield_now(), if presentation_due => {
                if lifecycle.is_stopping() { continue 'worker; }
                avatar_due = true;
                let step = shared.observer.performance().observe(RuntimeOp::WorkerPresentationPass);
                let presentation = presentation_maintenance.run(&client, &account_id_hex);
                step.finish_app(&presentation);
                presentation_due = match presentation {
                    Ok(more) => more,
                    Err(_) => {
                        tracing::warn!(target: "marmot_app::runtime", method = "chat_presentation_maintenance",
                            "local chat presentation maintenance failed; retrying on the next wakeup or maintenance tick");
                        false
                    }
                };
            }
            more = attachment_admission.ready(), if attachment_admission.is_waiting() => {
                attachment_due |= more;
            }
            _ = tokio::task::yield_now(), if attachment_due => {
                if lifecycle.is_stopping() { continue 'worker; }
                let step = shared.observer.performance().observe(RuntimeOp::WorkerAttachmentPass);
                let attachment = attachments::schedule(&client, &shared, &media_http, &mut attachment_admission);
                step.finish_app(&attachment);
                attachment_due = match attachment {
                    Ok(more) => more,
                    Err(_) => {
                        tracing::warn!(target: "marmot_app::runtime", method = "attachment_acquisition",
                            "attachment maintenance failed; retrying on next wakeup or tick");
                        false
                    }
                };
            }
            // Native input still being admitted takes its next turn as soon as
            // commands and live input have had theirs, instead of waiting for
            // unrelated input; a paced retry wakes the loop when it is due.
            () = admission_retry.wait() => { continue 'worker; }
            _ = tokio::task::yield_now(), if admission_retry.ready() && native_progress => {
                continue 'worker;
            }
            _ = maintenance_tick.tick() => {
                local_submission_due = true;
                attachment_due = true;
                presentation_due = true;
                avatar_due = true;
                if relay_config_work == RelayConfigWork::RetryOnTick {
                    relay_config_work = RelayConfigWork::Ready;
                }
                // Periodic maintenance is never urgent, and its longest leg
                // runs past the whole shutdown budget: the key-package
                // catch-up below is capped at 15s. Skip the tick outright once
                // shutdown is requested rather than starting work the drain
                // would then have to wait out.
                if lifecycle.is_stopping() {
                    continue 'worker;
                }
                let phase = shared.observer.performance().observe(RuntimeOp::WorkerMaintenance);
                let _unit = unit.enter(WorkerUnit::Maintenance);
                // Each phase below is also timed on its own, so a profile can
                // name the one an idle tick spends its time in (mdk#2923).
                let telemetry = shared.observer.performance().clone();
                let step = telemetry.observe(RuntimeOp::WorkerMaintenanceContentBackfill);
                let backfill = client.backfill_content_reports();
                step.finish_app(&backfill);
                if backfill.is_err() {
                    tracing::warn!(
                        target: "marmot_app::account_worker",
                        method = "maintenance_tick",
                        "report backfill deferred"
                    );
                }
                let step = telemetry.observe(RuntimeOp::WorkerMaintenanceLegacyPromotion);
                step.finish(run_legacy_message_promotion_batch(
                    &client,
                    &mut legacy_message_promotion,
                ));
                // Pairing timers, KeyPackage retries and link settlement.
                client.drive_device_pairing().await;
                if client.device_unlinked() {
                    // Nothing more goes out; the next turn stops the worker.
                    phase.finish(TelemetryOutcome::Success);
                    continue 'worker;
                }
                let step = telemetry.observe(RuntimeOp::WorkerMaintenanceCompaction);
                attachments::compact_if_due(&client, &shared, &mut attachment_admission).await;
                step.finish(TelemetryOutcome::Success);
                attachments::spawn_legacy_migration(
                    &client,
                    &shared,
                    &mut attachment_admission,
                );
                if client.key_package_maintenance_requires_catch_up() {
                    let step = telemetry.observe(RuntimeOp::WorkerMaintenanceKeyPackageCatchUp);
                    let observation = shared.observer.product().begin(
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
                    step.finish(match outcome {
                        KeyPackageMaintenanceCatchUpOutcome::Completed => TelemetryOutcome::Success,
                        KeyPackageMaintenanceCatchUpOutcome::Failed => TelemetryOutcome::Failure,
                        KeyPackageMaintenanceCatchUpOutcome::TimedOut => TelemetryOutcome::Timeout,
                    });
                    if let Some(observation) = observation {
                        observation.finish(outcome.as_str());
                    }
                    if client.device_unlinked() {
                        // The catch-up applied this device's removal:
                        // nothing more goes out (D67).
                        phase.finish(TelemetryOutcome::Success);
                        continue 'worker;
                    }
                    match catch_up {
                        Ok(Ok(summary)) => {
                            publish_app_runtime_summary_with_v5(&client,
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
                            publish_sync_summary_with_audit(&client,
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
                                Emit::Quiescent(&client),
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
                // A join window ends once T has been counted since its join
                // completed, which only time passing shows; the tick counts
                // it and notices joins that completed. Repair asks wait for
                // the same clock, and replies for their rank's slots.
                let step = telemetry.observe(RuntimeOp::WorkerMaintenancePush);
                client.advance_push_join_windows().await;
                if client.has_due_push_announce() || client.has_due_push_repair() {
                    scheduled_push_retry.observe_pending(true, &command_tx);
                }
                step.finish(TelemetryOutcome::Success);
                scheduled_runtime_group_subscription_refresh.observe_pending(
                    client.has_pending_runtime_group_subscription_refresh(),
                    &command_tx,
                );
                let step = telemetry.observe(RuntimeOp::WorkerMaintenanceRecovery);
                let selection = match refresh_recovery_at_seam(
                    &mut client,
                    EpochBackfillReportContext {
                        events: &events,
                        account_id_hex: &account_id_hex,
                        account_label: &account_label,
                        shared: &shared,
                    },
                )
                .await
                {
                    Ok(()) => TelemetryOutcome::Success,
                    Err(_) => TelemetryOutcome::Failure,
                };
                step.finish(selection);
                finish_periodic_maintenance_after_recovery(
                    &mut client,
                    &events,
                    &account_id_hex,
                    &account_label,
                    &shared,
                    &product_backlog,
                    &mut scheduled_convergence,
                )
                .await;
                let step = telemetry.observe(RuntimeOp::WorkerMaintenanceHistoryDispatch);
                dispatch_history_blobs(&mut client, &media_http);
                step.finish(TelemetryOutcome::Success);

                phase.finish(TelemetryOutcome::Success);
            }
        }
    }
    // Each exit that still held the client stopped the runner on it; any
    // other exit's drop aborts the task and refunds the attempts it left
    // open. What a quantum staged stays durable.
    drop(recovery_runner);
}

/// Wait for coalesced source changes, including same-generation progress.
/// No active source watch leaves the select branch dormant.
async fn wait_for_replay_change(changes: &mut Option<watch::Receiver<u64>>) -> bool {
    match changes {
        Some(changes) => changes.changed().await.is_ok(),
        None => std::future::pending().await,
    }
}

/// Flush recovery observations at a worker seam (receive, convergence or
/// maintenance) and report the outcome. The recovery runner owns every history
/// fetch (mdk#2660 phase 4), so a seam only records what is owed.
async fn refresh_recovery_at_seam(
    client: &mut AppClient,
    context: EpochBackfillReportContext<'_>,
) -> Result<(), AccountCatchUpFailure> {
    let backfill_armed = client.has_pending_epoch_backfill();
    let observation = backfill_armed
        .then(|| {
            context.shared.observer.product().begin(
                crate::ProductFamily::Recovery,
                "backfill",
                crate::ProductUnit::Attempt,
            )
        })
        .flatten();
    let result = client.refresh_pending_recovery().await;
    report_pending_epoch_backfill_result(client, result, backfill_armed, observation, context)
}

/// Keep the domain maintenance continuation after the recovery outcome.
async fn finish_periodic_maintenance_after_recovery(
    client: &mut AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    shared: &RuntimeSharedServices,
    product_backlog: &marmot_observability::ProductBacklogSource,
    scheduled_convergence: &mut ScheduledConvergence,
) {
    let telemetry = shared.observer.performance();
    let step = telemetry.observe(RuntimeOp::WorkerMaintenancePostJoin);
    let post_join = client.advance_post_join_maintenance_subscriptions().await;
    step.finish_app(&post_join);
    if let Err(err) = post_join {
        publish_app_runtime_account_error(
            Emit::Quiescent(client),
            events,
            account_id_hex,
            account_label,
            account_error_message("post-join maintenance subscription failed", &err),
        );
    }
    let backlog_permit = shared.observer.product().permit();
    let step = telemetry.observe(RuntimeOp::WorkerMaintenanceDue);
    let due = client.run_due_maintenance().await;
    step.finish_app(&due);
    match due {
        Ok(summary) => {
            if let Some(permit) = &backlog_permit {
                product_backlog.sample(
                    permit,
                    crate::ProductFamily::Maintenance,
                    "pending",
                    u64::from(summary.deferred),
                );
                product_backlog.sample(
                    permit,
                    crate::ProductFamily::Maintenance,
                    "ambiguous",
                    u64::from(summary.ambiguous_exposure),
                );
                product_backlog.sample(
                    permit,
                    crate::ProductFamily::Maintenance,
                    "failed",
                    u64::from(client.maintenance_failed_backlog),
                );
                product_backlog.sample(
                    permit,
                    crate::ProductFamily::Recovery,
                    "quarantine",
                    client.runtime.quarantined_group_count() as u64,
                );
            }
            publish_client_pending_projection_updates(
                client,
                events,
                account_id_hex,
                account_label,
            );
            publish_client_pending_applied_summary(client, events, account_id_hex, account_label);
            schedule_pending_convergence_groups(scheduled_convergence, client);
        }
        Err(err) => {
            publish_app_runtime_account_error(
                Emit::Quiescent(client),
                events,
                account_id_hex,
                account_label,
                account_error_message("scheduled maintenance failed", &err),
            );
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
    unit: &'a WorkerUnitGauge,
}

async fn handle_account_worker_catch_up(
    client: &mut AppClient,
    respond: oneshot::Sender<Result<(), AccountCatchUpFailure>>,
    commands: &mut mpsc::Receiver<AccountWorkerCommand>,
    pending: &mut VecDeque<AccountWorkerCommand>,
    context: AccountWorkerCatchUpContext<'_>,
) {
    let _unit = context.unit.enter(WorkerUnit::CatchUp);
    let telemetry = context.shared.observer.performance().clone();
    let catch_up_observation = telemetry.observe(RuntimeOp::WorkerCatchUp);
    let snapshot_observation = telemetry.observe(RuntimeOp::WorkerSnapshot);
    let snapshot_result = client.group_read_snapshot();
    snapshot_observation.finish_app(&snapshot_result);
    let read_snapshot = match snapshot_result {
        Ok(snapshot) => Some(snapshot),
        Err(err) => {
            let message = account_error_message("runtime catch-up snapshot failed", &err);
            publish_app_runtime_account_error(
                Emit::Quiescent(client),
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
    let stage_telemetry = context.shared.observer.performance().clone();
    let sync_result = {
        let mut sync = std::pin::pin!(async {
            #[cfg(any(test, feature = "test-policy-overrides"))]
            if let Some(barrier) = context
                .shared
                .take_next_catch_up_barrier(context.account_id_hex)
            {
                // Acknowledge entry, then hold until the test releases it.
                barrier.wait().await;
                barrier.wait().await;
            }
            client
                .sync_with_stage_telemetry(Some(&stage_telemetry), crate::client::SyncMode::Drain)
                .await
        });
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
                    let _ = respond.send_from_snapshot(|| snapshot.members(&group_id));
                }
                AccountWorkerCommand::MemberIdsPage { group_ids, respond }
                    if snapshot_reads_available =>
                {
                    let snapshot = read_snapshot
                        .as_ref()
                        .expect("snapshot availability checked above");
                    let _ = respond.send_from_snapshot(|| snapshot.member_ids_page(&group_ids));
                }
                AccountWorkerCommand::CaptureConversation {
                    respond, queued, ..
                } => {
                    if let Some(queued) = queued {
                        queued.finish(TelemetryOutcome::NotReady);
                    }
                    let _ = respond.send_not_ready(Err(ConversationWindowError::NotReady));
                }
                AccountWorkerCommand::GroupMlsState { group_id, respond }
                    if snapshot_reads_available =>
                {
                    let snapshot = read_snapshot
                        .as_ref()
                        .expect("snapshot availability checked above");
                    let _ = respond.send_from_snapshot(|| snapshot.group_mls_state(&group_id));
                }
                AccountWorkerCommand::GroupRoster { group_id, respond }
                    if snapshot_reads_available =>
                {
                    let snapshot = read_snapshot
                        .as_ref()
                        .expect("snapshot availability checked above");
                    let _ = respond.send_from_snapshot(|| {
                        group_roster_from_snapshot(
                            context.app,
                            context.account_label,
                            snapshot,
                            &group_id,
                        )
                    });
                }
                AccountWorkerCommand::QuarantinedGroups { respond } if snapshot_reads_available => {
                    let snapshot = read_snapshot
                        .as_ref()
                        .expect("snapshot availability checked above");
                    let _ = respond.send_from_snapshot(|| Ok(snapshot.quarantined_groups()));
                }
                AccountWorkerCommand::ConfirmGroupRejoin { respond, .. } => {
                    let _ = answer_off_quiescent(respond, Err(AppError::AccountWorkerBusy));
                }
                AccountWorkerCommand::DeclineGroupRejoin { respond, .. } => {
                    let _ = answer_off_quiescent(respond, Err(AppError::AccountWorkerBusy));
                }
                AccountWorkerCommand::AcceptGroupInvite { respond, .. } => {
                    // The pinned sync exclusively owns the live client. This
                    // mutation was definitely not started, so a caller may
                    // safely retry after catch-up rather than waiting behind
                    // an arbitrarily slow relay drain.
                    let _ = answer_off_quiescent(respond, Err(AppError::AccountWorkerBusy));
                }
                AccountWorkerCommand::RetryRuntimeGroupSubscriptions { respond } => {
                    // This is worker-owned maintenance, not caller work. Keep
                    // its retry armed without placing it in the deferred FIFO;
                    // otherwise it would unnecessarily force later snapshot
                    // reads to wait behind the whole catch-up.
                    let _ = answer_off_quiescent(respond, true);
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
            publish_app_runtime_summary_with_v5(
                client,
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
                client,
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
                Emit::Quiescent(client),
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
        .observer
        .performance()
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
    // A job that parked or reopened recovery debt announces it before the
    // caller, who may re-read the notices at once, gets its answer.
    publish_account_level_changes(
        client,
        context.events,
        context.account_id_hex,
        context.account_label,
    );
    for respond in catch_up_responders {
        let _ = reply(respond, result.clone(), client);
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
    Shutdown { explicit: bool },
}

/// Run one storage-only promotion transaction after account readiness.
///
/// Transient lock failures retry on the next 15-second maintenance tick.
/// Durable decode failures halt this optional sweep until the next process
/// start so a malformed legacy row cannot create a hot retry loop. Reads keep
/// their legacy fallback either way, so this never gates account use.
/// Returns the batch's outcome for its maintenance span.
fn run_legacy_message_promotion_batch(
    client: &AppClient,
    schedule: &mut LegacyMessagePromotionSchedule,
) -> TelemetryOutcome {
    run_legacy_message_promotion_batch_with(schedule, |limit| {
        client
            .engine_storage
            .promote_legacy_message_rows(limit)
            .map_err(marmot_session::SessionError::from)
    })
}

/// One promotion batch through `promote`: a failed batch is a failure,
/// whether it retries next tick or halts the sweep, and a sweep that is
/// complete or halted has nothing to do.
fn run_legacy_message_promotion_batch_with(
    schedule: &mut LegacyMessagePromotionSchedule,
    promote: impl FnOnce(
        usize,
    ) -> marmot_session::SessionResult<
        storage_sqlite::MessageFormatPromotionProgress,
    >,
) -> TelemetryOutcome {
    if schedule.status != LegacyMessagePromotionStatus::Pending {
        return TelemetryOutcome::Success;
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
            return TelemetryOutcome::Failure;
        }
    }
    TelemetryOutcome::Success
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
    if client.runtime.unhydrated_group_ids().is_empty() {
        finish_deferred_hydration_reconciliation(client);
        return StartupHydrationOutcome::Completed;
    }
    let hydration_observation = shared
        .observer
        .performance()
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
        // The previous batch or command has ended: publish what it changed.
        client.publish_read_state();
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
                        return StartupHydrationOutcome::Shutdown {
                            explicit: runtime_shutdown_requested(&lifecycle_shutdown),
                        };
                    }
                    stop = &mut *shutdown => {
                        return StartupHydrationOutcome::Shutdown { explicit: stop.is_ok() };
                    }
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
                        None => return StartupHydrationOutcome::Shutdown { explicit: false },
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
                    return StartupHydrationOutcome::Shutdown { explicit: false };
                }
            }
        }
        match shutdown.try_recv() {
            Ok(()) => return StartupHydrationOutcome::Shutdown { explicit: true },
            Err(oneshot::error::TryRecvError::Closed) => {
                return StartupHydrationOutcome::Shutdown { explicit: false };
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
        if lifecycle.ensure_running().is_err() {
            return StartupHydrationOutcome::Shutdown {
                explicit: runtime_shutdown_requested(&lifecycle_shutdown),
            };
        }
        let progress = match client
            .runtime
            .hydrate_next_groups(&hydration_order, STARTUP_HYDRATION_BATCH_SIZE)
        {
            Ok(progress) => progress,
            Err(err) => {
                let message =
                    account_error_message("startup group hydration failed", &AppError::from(err));
                publish_app_runtime_account_error(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    message,
                );
                // Remaining groups stay gated retryable; the stage sample
                // below must not report this aborted pipeline as a success.
                pipeline_ok = false;
                break;
            }
        };
        // Naming can hydrate its target. Only name an already-live trusted
        // group here: never move it ahead of the ordinary hydration order.
        // The following drain may confirm an accepted SelfRemove, so use the
        // available tag context before that confirmation consumes its leaf.
        let tag_context = (|| -> Result<(), AppError> {
            if !client.app.device_groups_enabled() {
                return Ok(());
            }
            let Some(group) = client.trusted_device_group()? else {
                return Ok(());
            };
            if client.runtime.device_tag_group() == Some(&group) {
                return Ok(());
            }
            match client.runtime.group_record(&group) {
                Ok(_) => client.sync_device_tag_group(),
                Err(error)
                    if matches!(
                        error.as_engine_error(),
                        Some(
                            cgka_traits::EngineError::UnknownGroup(_)
                                | cgka_traits::EngineError::GroupNotHydrated(_)
                        )
                    ) =>
                {
                    Ok(())
                }
                Err(error) => Err(error.into()),
            }
        })();
        if let Err(error) = tag_context {
            tracing::warn!(
                target: "marmot_app::runtime",
                method = "startup_hydration_tag_context",
                error_kind = error.privacy_safe_kind(),
                "available device tag context could not be named"
            );
        }
        // Surface this batch's recovery events (PendingCommitRecovered,
        // hydration quarantines, restored leave requests) exactly as a live
        // drain would, so the projection updates incrementally.
        if let Ok(summary) = client.drain_pending_session_events().await {
            publish_app_runtime_summary_with_v5(
                client,
                events,
                account_id_hex,
                account_label,
                &summary,
            );
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
    shared.observer.performance().record(
        AppPerformanceOperation::AccountGroupHydration,
        pipeline_started.elapsed(),
        pipeline_ok,
    );
    // Live group state is readable now; finish the projection repairs that
    // the deferred open deliberately skipped.
    finish_deferred_hydration_reconciliation(client);
    client.publish_read_state();
    StartupHydrationOutcome::Completed
}

fn finish_deferred_hydration_reconciliation(client: &mut AppClient) {
    client.record_v5_baselines(marmot_forensics::v5::BaselineReason::Opened);
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
            .hydrate_next_groups(&[], STARTUP_HYDRATION_BATCH_SIZE)?;
        if progress.remaining == 0 {
            client.record_v5_baselines(marmot_forensics::v5::BaselineReason::Opened);
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
        AccountWorkerCommand::GroupRecoveryStatus {
            group_id,
            mut respond,
        } => {
            respond.dispatched();
            let status = group_recovery_after_hydration(client, &group_id);
            let _ = reply(respond, status, client);
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
            let _ = reply(respond, result, client);
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
            let _ = reply(respond, result, client);
        }
        AccountWorkerCommand::Members {
            group_id,
            mut respond,
        } => {
            respond.dispatched();
            let _ = client.runtime.ensure_group_hydrated(&group_id);
            let _ = reply(respond, client.members(&group_id), client);
        }
        AccountWorkerCommand::MemberIdsPage {
            group_ids,
            mut respond,
        } => {
            respond.dispatched();
            let _ = reply(
                respond,
                member_ids_page_after_hydration(client, &group_ids),
                client,
            );
        }
        AccountWorkerCommand::CaptureConversation {
            queued,
            group_id,
            query,
            store_epoch,
            observer,
            mut respond,
        } => {
            respond.dispatched();
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
                let _ = reply(respond, result, client);
            }
        }
        AccountWorkerCommand::GroupMlsState {
            group_id,
            mut respond,
        } => {
            respond.dispatched();
            let _ = client.runtime.ensure_group_hydrated(&group_id);
            let _ = reply(respond, client.group_mls_state(&group_id), client);
        }
        AccountWorkerCommand::GroupRoster {
            group_id,
            mut respond,
        } => {
            respond.dispatched();
            let _ = reply(
                respond,
                group_roster_after_hydration(client, &group_id),
                client,
            );
        }
        AccountWorkerCommand::GroupPushDebugInfo {
            group_id,
            mut respond,
        } => {
            respond.dispatched();
            let _ = client.runtime.ensure_group_hydrated(&group_id);
            let _ = reply(respond, client.group_push_debug_info(&group_id), client);
        }
        AccountWorkerCommand::AccountDevicesActivation {
            group_id,
            mut respond,
        } => {
            respond.dispatched();
            let _ = client.runtime.ensure_group_hydrated(&group_id);
            let _ = reply(
                respond,
                client.account_devices_activation(&group_id),
                client,
            );
        }
        AccountWorkerCommand::QuarantinedGroups { mut respond } => {
            respond.dispatched();
            let _ = reply(respond, Ok(client.quarantined_groups()), client);
        }
        AccountWorkerCommand::AcceptGroupInvite { group_id, respond } => {
            // Invite confirmation is a projection-only mutation and does not
            // need the remaining MLS groups to finish hydrating. Apply and
            // publish it immediately so a locally visible invite cannot be
            // held behind unrelated startup work.
            let result = client.accept_group_invite(&group_id);
            if result.is_ok() {
                publish_app_runtime_group_state_updated(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let retry_after_response = result.is_ok();
            let _ = reply(respond, result, client);
            if retry_after_response {
                client
                    .retry_pending_push_registration_shares_best_effort()
                    .await;
            }
        }
        #[cfg(test)]
        AccountWorkerCommand::UnhydratedGroupCount { respond } => {
            let count = client.runtime.session().unhydrated_group_ids().len();
            let _ = reply(respond, count, client);
        }
        #[cfg(test)]
        AccountWorkerCommand::UnlinkDeviceForTest { respond } => {
            let _ = reply(respond, client.mark_device_unlinked(), client);
        }
        #[cfg(test)]
        AccountWorkerCommand::SubscribeReadStateForTest { respond } => {
            let _ = reply(respond, client.subscribe_read_state(), client);
        }
        AccountWorkerCommand::CatchUp { respond } => {
            deferred.push(DeferredStartupCommand::CatchUp(respond));
        }
        AccountWorkerCommand::PublishSetupKeyPackage { respond } => {
            match setup_key_package_result.take() {
                Some(result) => {
                    let _ = reply(respond, result, client);
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
    product: marmot_observability::ProductRecorder,
    tx: mpsc::UnboundedSender<MediaHttpDone>,
    permits: Arc<Semaphore>,
    /// Prevent concurrent host retries from uploading the same durable blob
    /// more than once. This state is deliberately ephemeral: after a worker
    /// restart, the durable staged/failed record remains retryable.
    prepared_group_image_uploads: Arc<Mutex<HashSet<String>>>,
    /// The history upload and fetch running, at most one of each.
    history_blobs: HistoryBlobFlights,
    /// Shared latest platform facts; the worker owns no independent copy.
    backup_background_conditions: watch::Sender<super::BackupBackgroundConditions>,
    /// Never sends a value. Dropping the worker-owned sender closes every
    /// receiver and cancels active HTTP futures on every worker exit path.
    worker_lifetime: watch::Sender<()>,
}

/// Whether a history upload and a history fetch (mdk#2628 4.2c) are running.
/// Ephemeral, like the uploads above: the history stays owed, or the
/// delivery parked, until one completes.
#[derive(Default)]
struct HistoryBlobFlights {
    upload: std::sync::atomic::AtomicBool,
    fetch: std::sync::atomic::AtomicBool,
    /// Sole completion sender stays on the worker, never in detached HTTP
    /// jobs. Dropping this context closes pending waits on every worker exit.
    backup: Mutex<Option<watch::Sender<bool>>>,
    restore: std::sync::atomic::AtomicBool,
}

/// Starts the next due history upload, history fetch and backup pass on the
/// media executor, unless one of that kind is running, keeping a slot free
/// for commands as avatar acquisition does. Each runs off the worker; its
/// completion sends, imports or publishes here, and a history's then starts
/// the next.
fn dispatch_history_blobs(client: &mut AppClient, media_http: &MediaHttpContext) {
    use std::sync::atomic::Ordering;
    let permit = || {
        (media_http.permits.available_permits() > 1)
            .then(|| media_http.permits.clone().try_acquire_owned().ok())
            .flatten()
    };
    if !media_http.history_blobs.upload.load(Ordering::Relaxed)
        && let Some(permit) = permit()
    {
        match client.prepare_history_upload() {
            Ok(Some(upload)) => {
                media_http
                    .history_blobs
                    .upload
                    .store(true, Ordering::Relaxed);
                spawn_media_http(
                    media_http,
                    permit,
                    upload.run(),
                    MediaHttpCompletion::HistoryUpload,
                );
            }
            Ok(None) => {}
            Err(_) => {
                tracing::warn!(target: "marmot_app::runtime", method = "dispatch_history_blobs",
                "history upload deferred")
            }
        }
    }
    if !media_http.history_blobs.fetch.load(Ordering::Relaxed)
        && let Some(permit) = permit()
    {
        match client.prepare_history_fetch() {
            Ok(Some(fetch)) => {
                media_http
                    .history_blobs
                    .fetch
                    .store(true, Ordering::Relaxed);
                spawn_media_http(
                    media_http,
                    permit,
                    fetch.run(),
                    MediaHttpCompletion::HistoryFetch,
                );
            }
            Ok(None) => {}
            Err(_) => {
                tracing::warn!(target: "marmot_app::runtime", method = "dispatch_history_blobs",
                "history fetch deferred")
            }
        }
    }
    dispatch_backup_pass(client, media_http);
    dispatch_backup_restore(client, media_http);
}

/// Admit new background backup work only under currently reported host
/// facts. Once admitted, the whole pass and its settlement finish unchanged.
fn dispatch_backup_pass(client: &mut AppClient, media_http: &MediaHttpContext) {
    if !client.app.device_groups_enabled()
        || !media_http.backup_background_conditions.borrow().allowed()
    {
        return;
    }
    let permit = || {
        (media_http.permits.available_permits() > 1)
            .then(|| media_http.permits.clone().try_acquire_owned().ok())
            .flatten()
    };
    let backup_running = media_http.history_blobs.backup.lock().unwrap().is_some();
    if !backup_running && let Some(permit) = permit() {
        match client.prepare_backup_pass() {
            Ok(Some(pass)) => {
                *media_http.history_blobs.backup.lock().unwrap() = Some(watch::channel(false).0);
                spawn_media_http(
                    media_http,
                    permit,
                    pass.run(),
                    MediaHttpCompletion::BackupPass,
                );
            }
            Ok(None) => {}
            Err(_) => {
                tracing::warn!(target: "marmot_app::runtime", method = "dispatch_history_blobs",
                "backup pass deferred")
            }
        }
    }
}

/// Manual restoration never drives a writer pass, deletes or publication.
/// Share the existing media credits and retain one for foreground commands.
fn dispatch_backup_restore(client: &mut AppClient, media_http: &MediaHttpContext) {
    use std::sync::atomic::Ordering;
    if media_http.history_blobs.restore.load(Ordering::Relaxed)
        || media_http.permits.available_permits() <= 1
    {
        return;
    }
    let Ok(permit) = media_http.permits.clone().try_acquire_owned() else {
        return;
    };
    match client.prepare_backup_restore() {
        Ok(Some(work)) => {
            media_http
                .history_blobs
                .restore
                .store(true, Ordering::Relaxed);
            spawn_media_http(
                media_http,
                permit,
                work.run(),
                MediaHttpCompletion::BackupRestore,
            );
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(
                target: "marmot_app::runtime",
                method = "dispatch_backup_restore",
                error_kind = error.privacy_safe_kind(),
                "backup restore preparation failed"
            )
        }
    }
}

struct MediaHttpDone {
    /// Capacity remains reserved while a whole-blob result waits for and runs
    /// account-worker completion, so the unbounded channel is effectively
    /// bounded by `MEDIA_HTTP_IN_FLIGHT_LIMIT`.
    permit: OwnedSemaphorePermit,
    completion: MediaHttpCompletion,
    cancellation: Option<marmot_observability::ProductOperation>,
}

/// Stores a fetched avatar image as a cache file and settles its attempt.
/// A disk too full for it, or any failure, retries the fetch later; the
/// previous image stays. Blocking: runs on the blocking pool.
fn store_acquired_avatar(
    app: &crate::MarmotApp,
    label: &str,
    job: &storage_sqlite::AvatarAcquisition,
    image: &storage_sqlite::AvatarImage,
) {
    let now = crate::unix_now_seconds();
    let refresh = matches!(
        job.descriptor,
        storage_sqlite::SelectedAvatar::RemoteImage { .. }
    )
    .then(|| now.saturating_add(24 * 60 * 60));
    let Ok(account) = app.account_storage(label) else {
        return;
    };
    let storage = account.app_storage();
    let stored = (|| {
        let media = app.account_media_store(label, &account)?;
        let reserve = storage
            .attachment_download_policy(&super::attachment_controls::default_policy(&app.config))?
            .disk_reserve;
        let directory = app.account_dir(label);
        let free = || crate::media::attachment_resume::available_space(&directory);
        crate::media::avatar_files::store_acquired(
            &storage, &media, reserve, &free, job, image, refresh,
        )
    })();
    match stored {
        Ok(crate::media::avatar_files::StoredAvatar::Stored)
        | Ok(crate::media::avatar_files::StoredAvatar::Superseded) => {}
        Ok(crate::media::avatar_files::StoredAvatar::NoRoom) => {
            let _ = storage.fail_avatar_acquisition(job, now, true);
        }
        Err(_) => {
            // Publication failure leaves the old image untouched. Avoid
            // stranding a fetching row until process reconstruction.
            let _ = storage.fail_avatar_acquisition(job, now, true);
            tracing::warn!(target: "marmot_app::runtime", method = "avatar_acquisition",
                "avatar completion could not be committed");
        }
    }
}

enum MediaHttpCompletion {
    AttachmentRetained {
        result: Result<(), AppError>,
        background_permit: OwnedSemaphorePermit,
    },
    Attachment {
        job: storage_sqlite::AttachmentAcquisition,
        result: Result<crate::client::AcquiredMediaBody, crate::media::AttachmentDownloadFailure>,
        background_permit: OwnedSemaphorePermit,
    },
    Avatar {
        job: storage_sqlite::AvatarAcquisition,
        result: Result<storage_sqlite::AvatarImage, AppError>,
    },
    /// A fetched image finished storing on the blocking pool.
    AvatarStored,
    Upload {
        finish: EncryptedMediaUploadFinish,
        result: Result<
            (
                MediaUploadResult,
                Box<crate::media::outgoing::OutgoingUploads>,
            ),
            AppError,
        >,
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
    HistoryUpload(crate::client::HistoryUploadOutcome),
    HistoryFetch(crate::client::HistoryFetchOutcome),
    BackupPass(crate::client::BackupPassOutcome),
    BackupRestore(crate::client::backup_restore::BackupRestoreOutcome),
}

fn schedule_avatar_acquisition(
    client: &AppClient,
    media_http: &MediaHttpContext,
    resumed: &mut bool,
) -> Result<bool, AppError> {
    let storage = client.app.account_storage(&client.state.label)?;
    let transport = client.blossom_http_transport.clone();
    // Unset, encrypted group images can't load; profile pictures still do.
    let group_image_server = client.app.deployment().group_image_endpoint.clone();
    let mut dispatched = false;
    let result = dispatch_avatar_acquisition(
        &storage.app_storage(),
        media_http,
        resumed,
        &mut dispatched,
        move |descriptor| {
            let transport = transport.clone();
            let group_image_server = group_image_server.clone();
            async move {
                crate::media::avatar::fetch(&descriptor, group_image_server.as_deref(), &transport)
                    .await
            }
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
    storage: &storage_sqlite::SqliteAppStorage,
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
    let cancellation = media_http.product.operation(
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
        MediaHttpCompletion::HistoryUpload(outcome) => {
            let settled = client.finish_history_upload(outcome).await;
            drop(permit);
            media_http
                .history_blobs
                .upload
                .store(false, std::sync::atomic::Ordering::Relaxed);
            // A failure waits for the next maintenance pass, so a deferral
            // that could not be written never turns into a tight retry loop.
            if settled {
                dispatch_history_blobs(client, media_http);
            }
            return;
        }
        MediaHttpCompletion::HistoryFetch(outcome) => {
            let settled = client.finish_history_fetch(outcome);
            drop(permit);
            media_http
                .history_blobs
                .fetch
                .store(false, std::sync::atomic::Ordering::Relaxed);
            // A failure waits for the next maintenance pass, so a deferral
            // that could not be written never turns into a tight retry loop.
            if settled {
                dispatch_history_blobs(client, media_http);
            }
            return;
        }
        MediaHttpCompletion::BackupRestore(outcome) => {
            client.finish_backup_restore(outcome);
            drop(permit);
            media_http
                .history_blobs
                .restore
                .store(false, std::sync::atomic::Ordering::Relaxed);
            dispatch_backup_restore(client, media_http);
            return;
        }
        MediaHttpCompletion::BackupPass(outcome) => {
            client.finish_backup_pass(outcome).await;
            drop(permit);
            let completion = media_http.history_blobs.backup.lock().unwrap().take();
            if let Some(completion) = completion {
                completion.send_replace(true);
            }
            return;
        }
        MediaHttpCompletion::Attachment {
            job,
            result,
            background_permit,
        } => {
            // A body is published into the media store on the blocking pool
            // (file I/O, hashing, AEAD); a failure is a database update.
            if result.is_ok() {
                let label = &client.state.label;
                let handles = client.app.account_storage(label).and_then(|storage| {
                    let media = client.app.account_media_store(label, &storage)?;
                    Ok((storage, media))
                });
                let fallback = super::attachment_controls::default_policy(&client.app.config);
                let directory = client.app.account_dir(&client.state.label);
                let tx = media_http.tx.clone();
                let lifetime = media_http.worker_lifetime.subscribe();
                let lifecycle = shared.lifecycle();
                // Keep both permits until storage completion, but return to the
                // worker immediately. Shutdown is checked between stream chunks.
                tokio::task::spawn_blocking(move || {
                    let result = handles.and_then(|(storage, media)| {
                        attachments::complete_acquired_stored(
                            &storage,
                            &media,
                            &fallback,
                            &directory,
                            &job,
                            result,
                            &|| lifecycle.is_stopping() || lifetime.has_changed().is_err(),
                        )
                    });
                    let _ = tx.send(MediaHttpDone {
                        permit,
                        completion: MediaHttpCompletion::AttachmentRetained {
                            result,
                            background_permit,
                        },
                        cancellation: None,
                    });
                });
                return;
            }
            if attachments::complete_acquired(client, &job, result).is_err() {
                tracing::warn!(target: "marmot_app::runtime", method = "attachment_acquisition",
                    "attachment completion failed; durable lease permits recovery");
            }
            // The attempt ended without a body: failed, retrying, cancelled or parked.
            shared.attachment_updates.state_changed();
            drop(background_permit);
        }
        MediaHttpCompletion::AttachmentRetained {
            result,
            background_permit,
        } => {
            if result.is_err() {
                tracing::warn!(target: "marmot_app::runtime", method = "attachment_acquisition",
                    "attachment completion failed; durable lease permits recovery");
            }
            // The body was published (Ready) or the attempt ended without it.
            shared.attachment_updates.state_changed();
            drop(background_permit);
        }
        MediaHttpCompletion::Avatar { job, result } => {
            match result {
                // The image becomes a cache file on the blocking pool (file
                // I/O, hashing, AEAD); the permit is held until it is stored.
                Ok(image) => {
                    let app = client.app.clone();
                    let label = client.state.label.clone();
                    let tx = media_http.tx.clone();
                    tokio::task::spawn_blocking(move || {
                        store_acquired_avatar(&app, &label, &job, &image);
                        let _ = tx.send(MediaHttpDone {
                            permit,
                            completion: MediaHttpCompletion::AvatarStored,
                            cancellation: None,
                        });
                    });
                    return;
                }
                Err(error) => {
                    if let Ok(storage) = client.app.account_storage(&client.state.label) {
                        let now = crate::unix_now_seconds();
                        let retryable = crate::media::avatar::retryable(&error);
                        if storage
                            .app_storage()
                            .fail_avatar_acquisition(&job, now, retryable)
                            .is_err()
                        {
                            tracing::warn!(target: "marmot_app::runtime", method = "avatar_acquisition",
                                "avatar completion could not be committed");
                        }
                    }
                }
            }
            let _ = client
                .app
                .presentation_signals
                .avatars
                .send(client.state.label.clone());
        }
        MediaHttpCompletion::AvatarStored => {
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
            let (result, handoff) = match result {
                Ok((result, uploads)) => match client
                    .finish_encrypted_media_upload(finish, result, *uploads)
                    .await
                {
                    Ok((result, handoff)) => (Ok(result), handoff),
                    Err(err) => (Err(err), None),
                },
                Err(err) => (Err(err), None),
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
            shared.observer.performance().record_media(
                AppPerformanceOperation::MediaUpload,
                started_at.elapsed(),
                result.is_ok(),
                media_type,
            );
            // An upload-only result's uploads stay armed until the caller has
            // its descriptors; if it is gone, dropping them releases them.
            if reply(respond, result, client).is_ok()
                && let Some(handoff) = handoff
            {
                handoff.into_tokens();
            }
        }
        MediaHttpCompletion::Download {
            result,
            respond,
            started_at,
        } => {
            shared.observer.performance().record_media(
                AppPerformanceOperation::MediaDownload,
                started_at.elapsed(),
                result.is_ok(),
                result.as_ref().map(|v| v.media_type.as_str()).unwrap_or(""),
            );
            let _ = reply(respond, result, client);
        }
        MediaHttpCompletion::GroupImage { result, respond } => {
            let _ = reply(respond, result, client);
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
            shared.observer.performance().record_media(
                AppPerformanceOperation::GroupCreateImageUpload,
                started_at.elapsed(),
                succeeded,
                "image/",
            );
            let _ = reply(respond, response, client);
        }
    }
    drop(permit);
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
                Emit::Quiescent(client),
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
/// create/invite spawn it immediately after the caller-visible reply. Keep
/// later deferred commands behind that catch-up in their arrival order.
async fn serve_snapshot_reads_until<Fut>(
    read_snapshot: Option<crate::client::GroupReadSnapshot>,
    work: Fut,
    commands: &mut mpsc::Receiver<AccountWorkerCommand>,
    pending: &mut VecDeque<AccountWorkerCommand>,
    app: &MarmotApp,
    account_label: &str,
    mut send_waiting: Option<oneshot::Sender<()>>,
) -> Fut::Output
where
    Fut: Future,
{
    let mut deferred = VecDeque::new();
    let mut follow_up = VecDeque::new();
    let mut catch_up_seen = false;
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
        // Keep mutation FIFO, but let optional relay retries finish early at
        // their safe boundary. Never drop the client-owning work future.
        if matches!(
            command,
            AccountWorkerCommand::SendMessage { .. }
                | AccountWorkerCommand::SendMessageDraft { .. }
                | AccountWorkerCommand::SendAppEvent { .. }
        ) && let Some(waiting) = send_waiting.take()
        {
            let _ = waiting.send(());
        }
        let snapshot_reads_available = read_snapshot.is_some();
        match command {
            AccountWorkerCommand::Members { group_id, respond } if snapshot_reads_available => {
                let snapshot = read_snapshot
                    .as_ref()
                    .expect("snapshot availability checked above");
                let _ = respond.send_from_snapshot(|| snapshot.members(&group_id));
            }
            AccountWorkerCommand::MemberIdsPage { group_ids, respond }
                if snapshot_reads_available =>
            {
                let snapshot = read_snapshot
                    .as_ref()
                    .expect("snapshot availability checked above");
                let _ = respond.send_from_snapshot(|| snapshot.member_ids_page(&group_ids));
            }
            AccountWorkerCommand::CaptureConversation {
                respond, queued, ..
            } => {
                if let Some(queued) = queued {
                    queued.finish(TelemetryOutcome::NotReady);
                }
                let _ = respond.send_not_ready(Err(ConversationWindowError::NotReady));
            }
            AccountWorkerCommand::GroupMlsState { group_id, respond }
                if snapshot_reads_available =>
            {
                let snapshot = read_snapshot
                    .as_ref()
                    .expect("snapshot availability checked above");
                let _ = respond.send_from_snapshot(|| snapshot.group_mls_state(&group_id));
            }
            AccountWorkerCommand::GroupRoster { group_id, respond } if snapshot_reads_available => {
                let snapshot = read_snapshot
                    .as_ref()
                    .expect("snapshot availability checked above");
                let _ = respond.send_from_snapshot(|| {
                    group_roster_from_snapshot(app, account_label, snapshot, &group_id)
                });
            }
            AccountWorkerCommand::QuarantinedGroups { respond } if snapshot_reads_available => {
                let snapshot = read_snapshot
                    .as_ref()
                    .expect("snapshot availability checked above");
                let _ = respond.send_from_snapshot(|| Ok(snapshot.quarantined_groups()));
            }
            AccountWorkerCommand::CatchUp { .. } => {
                catch_up_seen = true;
                follow_up.push_back(command);
            }
            AccountWorkerCommand::RetryRuntimeGroupSubscriptions { respond } => {
                let _ = answer_off_quiescent(respond, true);
            }
            command if catch_up_seen => follow_up.push_back(command),
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
    /// The account's recovery runner: explicit repair serves its turns while
    /// it waits on it.
    recovery_runner: Option<&'a mut SpawnedRunner>,
    unit: &'a WorkerUnitGauge,
}

// Keep response ownership and error classification outside the large async dispatch
// frame. Inlining the result moves at every arm grows debug poll stacks substantially.
#[inline(never)]
fn respond_diagnosed<T>(
    shared: &RuntimeSharedServices,
    permit: Option<&crate::DiagnosticsPermit>,
    respond: impl WorkerReply<Result<T, AppError>>,
    result: Result<T, AppError>,
    client: &AppClient,
) -> Result<(), Result<T, AppError>> {
    if let Err(error) = &result {
        shared.observer.product().storage_failure(permit, error);
    }
    reply(respond, result, client)
}

/// Reply at a quiescent point: publish A, then answer, so a host that awaited
/// the reply reads at least the state it describes (mdk#3273).
fn reply<T>(respond: impl WorkerReply<T>, value: T, client: &AppClient) -> Result<(), T> {
    client.publish_read_state();
    respond.send_reply(value)
}

/// Reply away from a quiescent point, without publishing A first: a busy
/// refusal, a worker-owned acknowledgement or a cached result while a long
/// unit holds the client, or a test-only answer from a spawned task. The
/// reply describes no write of the unit in progress (mdk#3273 decision 2).
fn answer_off_quiescent<T>(respond: oneshot::Sender<T>, value: T) -> Result<(), T> {
    respond.send(value)
}

/// Commands that arrived while a previous handler held `&mut client` stay in
/// `pending` until that handler returns. Read commands (`Members` /
/// `MemberIdsPage` / `GroupMlsState` / `GroupRoster` / `QuarantinedGroups`) are
/// intercepted inline during catch-up and Welcome fanout and answered from a
/// `GroupReadSnapshot`; here they read the live session.
async fn handle_account_worker_command(
    client: &mut AppClient,
    mut command: AccountWorkerCommand,
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
    // A host read's wait on the worker ends here, before it runs.
    command.read_dispatched();
    if account_worker_command_future(client, command, context).await {
        // One publication seam covers all successful dispatch completions. Early
        // admission failures and cancelled commands retain their previous behavior.
        publish_client_pending_applied_summary(client, events, account_id_hex, account_label);
        publish_account_level_changes(client, events, account_id_hex, account_label);
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
        recovery_runner,
        unit,
    } = context;
    let storage_permit = shared.observer.product().permit();
    match command {
        AccountWorkerCommand::ConnectivityRestored { respond } => Box::pin(async move {
            let result = client.note_connectivity_restored().map(|_| ());
            scheduled_convergence.wake_after_connectivity_restored();
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::NetworkStartupSettled { respond } => Box::pin(async move {
            let _ = reply(respond, (), client);
            true
        }),
        AccountWorkerCommand::StartupCatchUpResult { result, respond } => Box::pin(async move {
            let _ = reply(respond, result, client);
            true
        }),
        AccountWorkerCommand::Drain { respond } => Box::pin(async move {
            let _ = reply(respond, (), client);
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
                        Emit::Quiescent(client),
                        events,
                        account_id_hex,
                        account_label,
                        account_error_message("runtime group subscription refresh failed", &error),
                    );
                    true
                }
            };
            let _ = reply(respond, pending, client);
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
        #[cfg(test)]
        AccountWorkerCommand::UnhydratedGroupCount { respond } => Box::pin(async move {
            let count = client.runtime.session().unhydrated_group_ids().len();
            let _ = reply(respond, count, client);
            true
        }),
        #[cfg(test)]
        AccountWorkerCommand::UnlinkDeviceForTest { respond } => Box::pin(async move {
            let _ = reply(respond, client.mark_device_unlinked(), client);
            true
        }),
        #[cfg(test)]
        AccountWorkerCommand::SubscribeReadStateForTest { respond } => Box::pin(async move {
            let _ = reply(respond, client.subscribe_read_state(), client);
            true
        }),
        // The worker loop answers it from its runner before dispatch.
        #[cfg(test)]
        AccountWorkerCommand::RecoveryRunnerPassForTest { respond, .. } => Box::pin(async move {
            let _ = reply(respond, None, client);
            true
        }),
        AccountWorkerCommand::CatchUp { respond } => Box::pin(async move {
            let sync_started_at = Instant::now();
            let result = match client
                .sync_with_stage_telemetry(None, crate::client::SyncMode::Drain)
                .await
            {
                Ok(summary) => {
                    publish_app_runtime_summary_with_v5(
                        client,
                        events,
                        account_id_hex,
                        account_label,
                        &summary,
                    );
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
                        client,
                        events,
                        account_id_hex,
                        account_label,
                        &failure.partial_summary,
                        shared,
                        "catch_up",
                    );
                    let message = account_error_message("runtime catch-up failed", &failure.source);
                    publish_app_runtime_account_error(
                        Emit::Quiescent(client),
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
            shared.observer.performance().record_classified_result(
                AppPerformanceOperation::AccountSync,
                sync_started_at.elapsed(),
                result
                    .as_ref()
                    .err()
                    .map(AccountCatchUpFailure::classification),
            );
            let retry_after_response = result.is_ok();
            let _ = reply(respond, result, client);
            if retry_after_response {
                client
                    .retry_pending_push_registration_shares_best_effort()
                    .await;
            }
            true
        }),
        AccountWorkerCommand::RepairFullHistory { respond } => Box::pin(async move {
            let _unit = unit.enter(WorkerUnit::Repair);
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
                client.repair_full_history_cancellable(&cancelled, recovery_runner),
                commands,
                pending,
                app,
                account_label,
                None,
            ))
            .await;
            let result = match repaired {
                Ok(summary) => {
                    publish_app_runtime_summary_with_v5(
                        client,
                        events,
                        account_id_hex,
                        account_label,
                        &summary,
                    );
                    if sync_summary_triggers_audit_tracker_update(&summary) {
                        shared.schedule_audit_log_tracker_update("repair_full_history");
                    }
                    Ok(())
                }
                Err(failure) => {
                    publish_sync_summary_with_audit(
                        client,
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
                        Emit::Quiescent(client),
                        events,
                        account_id_hex,
                        account_label,
                        message.clone(),
                    );
                    Err(AccountCatchUpFailure::from_sync_failure(message, &failure))
                }
            };
            shared.observer.performance().record_classified_result(
                AppPerformanceOperation::AccountSync,
                sync_started_at.elapsed(),
                result
                    .as_ref()
                    .err()
                    .map(AccountCatchUpFailure::classification),
            );
            // Repair can rearm a group even when history remains incomplete.
            // Publish those changes before the caller re-reads its status.
            publish_client_pending_projection_updates(
                client,
                events,
                account_id_hex,
                account_label,
            );
            let _ = reply(respond, result, client);
            true
        }),
        AccountWorkerCommand::CreateGroup {
            queued_at,
            request,
            mut options,
            respond,
        } => Box::pin(async move {
            let create_unit = unit.enter(WorkerUnit::InviteOrCreate);
            let telemetry = shared.observer.performance().clone();
            telemetry.record(
                AppPerformanceOperation::GroupCreateQueueWait,
                queued_at.elapsed(),
                true,
            );
            let (name, members, prepared_image_upload_id) = match request {
                GroupCreationRequest::Group {
                    name,
                    members,
                    prepared_image_upload_id,
                } => (name, members, prepared_image_upload_id),
                GroupCreationRequest::Direct {
                    peer_account_id_hex,
                } => {
                    match client.reusable_direct_group(&peer_account_id_hex) {
                        Ok(Some(created)) => {
                            if created.chat_list_row.is_some() {
                                publish_created_group(
                                    Emit::Quiescent(client),
                                    events,
                                    account_id_hex,
                                    account_label,
                                    &created,
                                );
                            }
                            publish_client_pending_projection_updates(
                                client,
                                events,
                                account_id_hex,
                                account_label,
                            );
                            let _ = respond_diagnosed(
                                shared,
                                storage_permit.as_ref(),
                                respond,
                                Ok(crate::GroupMemberResult {
                                    operation: Some(created),
                                    member_outcomes: Vec::new(),
                                }),
                                client,
                            );
                            return true;
                        }
                        Err(error) => {
                            publish_client_pending_projection_updates(
                                client,
                                events,
                                account_id_hex,
                                account_label,
                            );
                            let _ = respond_diagnosed(
                                shared,
                                storage_permit.as_ref(),
                                respond,
                                Err(error),
                                client,
                            );
                            return true;
                        }
                        Ok(None) => {}
                    }
                    options.initial_admins = vec![peer_account_id_hex.clone()];
                    options.member_resolution = nostr_directory::MemberResolutionPolicy::Atomic;
                    (String::new(), vec![peer_account_id_hex], None)
                }
            };
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
            if let Ok(crate::GroupMemberResult {
                operation: Some(created_group),
                ..
            }) = &result
            {
                publish_created_group(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    created_group,
                );
            }
            let created = result
                .as_ref()
                .is_ok_and(|result| result.operation.is_some());
            let response_sent =
                respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client).is_ok();
            telemetry.record(
                AppPerformanceOperation::GroupCreateResponseHandoff,
                response_handoff_started_at.elapsed(),
                response_sent,
            );
            drop(create_unit);
            if created {
                let _unit = unit.enter(WorkerUnit::WelcomeFanout);
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
                        // An undelivered Welcome stays owed; the events below
                        // report it.
                        let _ = client
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
                    None,
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
            shared.observer.performance().record(
                AppPerformanceOperation::GroupCreateImagePreprocess,
                started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                    let _ = reply(respond, Ok(status), client);
                }
                Ok(PreparedGroupImageUploadStart::Http(http)) => {
                    if let Err(err) = reserve_prepared_group_image_upload(media_http, &upload_id) {
                        let _ = respond_diagnosed(
                            shared,
                            storage_permit.as_ref(),
                            respond,
                            Err(err),
                            client,
                        );
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
                    let _ = respond_diagnosed(
                        shared,
                        storage_permit.as_ref(),
                        respond,
                        Err(err),
                        client,
                    );
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
                let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::Members { group_id, respond } => Box::pin(async move {
            // On-demand promotion (mdk#1161): normally a no-op (the startup
            // pipeline hydrated everything), but if the pipeline aborted on a
            // storage error the leftover groups must still promote on first
            // read instead of surfacing GroupHydrationPending forever.
            let _ = client.runtime.ensure_group_hydrated(&group_id);
            let result = client.members(&group_id);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                client,
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
                let _ = reply(respond, result, client);
            }
            true
        }),
        AccountWorkerCommand::GroupMlsState { group_id, respond } => Box::pin(async move {
            // See the Members arm: on-demand promotion for pipeline-abort
            // leftovers.
            let _ = client.runtime.ensure_group_hydrated(&group_id);
            let result = client.group_mls_state(&group_id);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::GroupRoster { group_id, respond } => Box::pin(async move {
            let result = group_roster_after_hydration(client, &group_id);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::EnableGroupDisbanding { group_id, respond } => Box::pin(async move {
            let result = client.enable_group_disbanding(&group_id).await;
            if result.is_ok() {
                publish_app_runtime_group_state_updated(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::AccountDevicesActivation { group_id, respond } => {
            Box::pin(async move {
                let _ = client.runtime.ensure_group_hydrated(&group_id);
                let result = client.account_devices_activation(&group_id);
                let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
                true
            })
        }
        AccountWorkerCommand::EnableAccountDevices { group_id, respond } => Box::pin(async move {
            let result = client.enable_account_devices(&group_id).await;
            if result.is_ok() {
                publish_app_runtime_group_state_updated(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::DisbandGroup { group_id, respond } => Box::pin(async move {
            let result = client.disband_group(&group_id).await;
            publish_app_runtime_group_state_updated(
                Emit::Quiescent(client),
                events,
                account_id_hex,
                account_label,
                &group_id,
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::AcknowledgeDisbandFailure { group_id, respond } => {
            Box::pin(async move {
                let result = client.acknowledge_disband_failure(&group_id);
                if matches!(result, Ok(true)) {
                    publish_app_runtime_group_state_updated(
                        Emit::Quiescent(client),
                        events,
                        account_id_hex,
                        account_label,
                        &group_id,
                    );
                }
                let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
                true
            })
        }
        AccountWorkerCommand::QuarantinedGroups { respond } => Box::pin(async move {
            let result = Ok(client.quarantined_groups());
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                        Ok(summary) => publish_app_runtime_summary_with_v5(
                            client,
                            events,
                            account_id_hex,
                            account_label,
                            &summary,
                        ),
                        Err(err) => publish_app_runtime_account_error(
                            Emit::Quiescent(client),
                            events,
                            account_id_hex,
                            account_label,
                            account_error_message("retry recovery drain failed", &err),
                        ),
                    }
                    publish_app_runtime_group_state_updated(
                        Emit::Quiescent(client),
                        events,
                        account_id_hex,
                        account_label,
                        &group_id,
                    );
                }
                let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
                true
            })
        }
        AccountWorkerCommand::GroupAppComponent {
            group_id,
            component_id,
            respond,
        } => Box::pin(async move {
            let result = (|| {
                client.runtime.ensure_group_hydrated(&group_id)?;
                client.group_app_component(&group_id, component_id)
            })();
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::UpdateAppComponent {
            group_id,
            component_id,
            data,
            respond,
        } => Box::pin(async move {
            let result = client
                .update_app_component(&group_id, component_id, data)
                .await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
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
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::SafeExportSecret {
            group_id,
            component_id,
            respond,
        } => Box::pin(async move {
            let result = client.safe_export_secret(&group_id, component_id);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::ExporterSecret {
            group_id,
            label,
            length,
            respond,
        } => Box::pin(async move {
            let result = client.exporter_secret(&group_id, &label, length);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::InviteMembers {
            group_id,
            members,
            initial_admins,
            member_resolution,
            respond,
        } => Box::pin(async move {
            let invite_unit = unit.enter(WorkerUnit::InviteOrCreate);
            let telemetry = shared.observer.performance().clone();
            let result = async {
                let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
                let admin_refs = initial_admins
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                client
                    .invite_members_with_telemetry(
                        &group_id,
                        &member_refs,
                        &admin_refs,
                        member_resolution,
                        &telemetry,
                    )
                    .await
            }
            .await;
            let canonical = result.as_ref().is_ok_and(|result| {
                result.operation.as_ref().is_some_and(|summary| {
                    summary.accept_disposition == cgka_traits::SendAcceptDisposition::Published
                })
            });
            if canonical {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            drop(invite_unit);
            if canonical {
                let _unit = unit.enter(WorkerUnit::WelcomeFanout);
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
                        // An undelivered Welcome stays owed; the events below
                        // report it.
                        let _ = client
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
                    None,
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
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                Emit::Quiescent(client),
                events,
                account_id_hex,
                account_label,
                &group_id,
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::CancelLeave { group_id, respond } => Box::pin(async move {
            let result = client.cancel_leave(&group_id);
            if result.is_ok() {
                publish_app_runtime_group_state_updated(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::LeaveGroupForSignOut { group_id, respond } => Box::pin(async move {
            let result = client.leave_group_for_sign_out(&group_id).await;
            // As `LeaveGroup`: drain the queued "member left" row and
            // re-render the chat whatever the outcome.
            publish_client_pending_projection_updates(
                client,
                events,
                account_id_hex,
                account_label,
            );
            publish_app_runtime_group_state_updated(
                Emit::Quiescent(client),
                events,
                account_id_hex,
                account_label,
                &group_id,
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::ForgetGroupLocal { group_id, respond } => Box::pin(async move {
            let result = client.forget_group_local(&group_id).await;
            if result.is_ok() {
                scheduled_convergence.note_success(&group_id);
            }
            if matches!(result, Ok(true)) {
                publish_app_runtime_group_state_updated(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::DeleteGroupLocal { group_id, respond } => Box::pin(async move {
            let result = client.delete_group_local(&group_id).await;
            if matches!(result, Ok(true)) {
                publish_app_runtime_group_state_updated(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::GroupRecoveryStatus { group_id, respond } => Box::pin(async move {
            let _ = reply(
                respond,
                group_recovery_after_hydration(client, &group_id),
                client,
            );
            true
        }),
        AccountWorkerCommand::HistoryNotices { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.history_notices(),
                client,
            );
            true
        }),
        AccountWorkerCommand::AccountRecoveryStatus { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.account_recovery_status(),
                client,
            );
            true
        }),
        AccountWorkerCommand::LinkedDevices { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.linked_devices(),
                client,
            );
            true
        }),
        AccountWorkerCommand::ChatHistoryImports { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.chat_history_imports(),
                client,
            );
            true
        }),
        AccountWorkerCommand::KeyPackageRefreshOverdue { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.key_package_refresh_overdue(),
                client,
            );
            true
        }),
        AccountWorkerCommand::UnrecognizedSignIns { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.unrecognized_sign_ins(),
                client,
            );
            true
        }),
        AccountWorkerCommand::AnswerSignIn {
            slot_id_hex,
            response,
            respond,
        } => Box::pin(async move {
            let result = client.answer_sign_in(&slot_id_hex, response).await;
            // Announce the answer before the caller re-reads the list.
            publish_account_level_changes(client, events, account_id_hex, account_label);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::CheckSignIns { respond } => Box::pin(async move {
            let result = client.check_sign_ins_now().await;
            publish_account_level_changes(client, events, account_id_hex, account_label);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::StartFresh { respond } => Box::pin(async move {
            let result = client.start_fresh();
            publish_account_level_changes(client, events, account_id_hex, account_label);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::StartedFresh { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.started_fresh(),
                client,
            );
            true
        }),
        AccountWorkerCommand::CompromiseWarning { respond } => Box::pin(async move {
            let result = client.compromise_warning();
            // A read that gathered announces what it found.
            publish_account_level_changes(client, events, account_id_hex, account_label);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::DismissCompromiseWarning { respond } => Box::pin(async move {
            let result = client.dismiss_compromise_warning();
            publish_account_level_changes(client, events, account_id_hex, account_label);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::RenameLinkedDevice {
            slot_id_hex,
            label,
            respond,
        } => Box::pin(async move {
            let result = client.rename_linked_device(&slot_id_hex, &label).await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::UpdateLinkedDeviceSettings {
            slot_id_hex,
            add_to_all_chats,
            bring_history,
            keep_while_inactive,
            respond,
        } => Box::pin(async move {
            let result = client
                .update_linked_device_settings(
                    &slot_id_hex,
                    add_to_all_chats,
                    bring_history,
                    keep_while_inactive,
                )
                .await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::RemoveLinkedDevice {
            slot_id_hex,
            respond,
        } => Box::pin(async move {
            let result = client.remove_linked_device(&slot_id_hex).await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::SignOutThroughSiblingsStep { respond } => Box::pin(async move {
            let result = client.sign_out_through_siblings_step().await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::SignOutAdminLeave { group_id, respond } => Box::pin(async move {
            let result = client.sign_out_admin_leave(&group_id);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::RemovedDeviceLeftoverChats { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.removed_device_leftover_chats(),
                client,
            );
            true
        }),
        AccountWorkerCommand::ChatsClosedToLinkedDevices { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.chats_closed_to_linked_devices(),
                client,
            );
            true
        }),
        AccountWorkerCommand::BeginRecoveryWords { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.begin_recovery_words(),
                client,
            );
            true
        }),
        AccountWorkerCommand::ConfirmRecoveryWords { answers, respond } => Box::pin(async move {
            let result = client.confirm_recovery_words(&answers).await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::CancelRecoveryWords { respond } => Box::pin(async move {
            client.cancel_recovery_words();
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, Ok(()), client);
            true
        }),
        AccountWorkerCommand::TurnOffBackups { respond } => Box::pin(async move {
            let result = client.turn_off_backups().await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::RunDueBackupPass { respond } => Box::pin(async move {
            if !respond.is_closed() {
                dispatch_backup_pass(client, media_http);
                let completion = media_http
                    .history_blobs
                    .backup
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(watch::Sender::subscribe);
                let _ = reply(respond, Ok(completion), client);
            }
            true
        }),
        AccountWorkerCommand::BeginBackupRestore { words, respond } => Box::pin(async move {
            if !respond.is_closed() {
                let result = client.begin_backup_restore(words);
                let operation = result.as_ref().ok().and_then(|status| status.operation);
                let delivered =
                    respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
                if delivered.is_ok() && operation.is_some() {
                    dispatch_backup_restore(client, media_http);
                } else if let Some(operation) = operation {
                    client.cancel_backup_restore(operation);
                }
            }
            true
        }),
        AccountWorkerCommand::CancelBackupRestore { operation, respond } => Box::pin(async move {
            let result = client.cancel_backup_restore(operation);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, Ok(result), client);
            true
        }),
        AccountWorkerCommand::BackupRestoreStatus { respond } => Box::pin(async move {
            let _ = reply(respond, Ok(client.backup_restore_status()), client);
            true
        }),
        AccountWorkerCommand::WatchBackupRestore { respond } => Box::pin(async move {
            let _ = reply(respond, Ok(client.watch_backup_restore()), client);
            true
        }),
        AccountWorkerCommand::HistoryImportProvenance {
            group_id,
            event_id,
            respond,
        } => Box::pin(async move {
            let result = client.history_import_provenance(&group_id, &event_id);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::BackupHistoryAvailability { group_id, respond } => {
            Box::pin(async move {
                let result = client.backup_history_availability(&group_id);
                let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
                true
            })
        }
        AccountWorkerCommand::BackupSettings { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.backup_settings(),
                client,
            );
            true
        }),
        AccountWorkerCommand::AcknowledgeGroupCatchingUp { group_id, respond } => {
            Box::pin(async move {
                let _ = respond_diagnosed(
                    shared,
                    storage_permit.as_ref(),
                    respond,
                    client.acknowledge_group_catching_up(&group_id),
                    client,
                );
                true
            })
        }
        AccountWorkerCommand::AcknowledgeGroupCommitUndelivered { group_id, respond } => {
            Box::pin(async move {
                let _ = respond_diagnosed(
                    shared,
                    storage_permit.as_ref(),
                    respond,
                    client.acknowledge_group_commit_undelivered(&group_id),
                    client,
                );
                true
            })
        }
        AccountWorkerCommand::GroupCommitDelivery { group_id, respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.group_commit_delivery(&group_id),
                client,
            );
            true
        }),
        AccountWorkerCommand::DismissHistoryNotice { notice_id, respond } => {
            Box::pin(async move {
                let result = client.dismiss_history_notice(&notice_id);
                // Announce the removal before the caller re-reads anything.
                publish_account_level_changes(client, events, account_id_hex, account_label);
                let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
                true
            })
        }
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
            let _ = reply(respond, result, client);
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
            let _ = reply(respond, result, client);
            true
        }),
        AccountWorkerCommand::AcceptGroupInvite { group_id, respond } => Box::pin(async move {
            let result = client.accept_group_invite(&group_id);
            if result.is_ok() {
                publish_app_runtime_group_state_updated(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let retry_after_response = result.is_ok();
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            if retry_after_response {
                client
                    .retry_pending_push_registration_shares_best_effort()
                    .await;
            }
            true
        }),
        AccountWorkerCommand::DeclineGroupInvite { group_id, respond } => Box::pin(async move {
            // Declining leaves the group, which cannot be undone. A requester
            // that stopped waiting (for example after the worker response
            // deadline) reports the outcome as unknown and may have decided to
            // accept since; running its queued decline now would leave a group
            // the account meant to keep.
            if respond.is_closed() {
                return true;
            }
            let result = client.decline_group_invite(&group_id).await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                    let _ = respond_diagnosed(
                        shared,
                        storage_permit.as_ref(),
                        respond,
                        Err(err),
                        client,
                    );
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
            let _unit = unit.enter(WorkerUnit::Send);
            if let Some(queued) = queued {
                queued.finish(TelemetryOutcome::Success);
            }
            let telemetry = shared.observer.performance().clone();
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
                            Emit::Unpublished(Unpublished::LocalEcho),
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::SendMessage {
            enqueued_at,
            queued,
            group_id,
            payload,
            respond,
        } => Box::pin(async move {
            let _unit = unit.enter(WorkerUnit::Send);
            send_message_on_worker(
                client,
                enqueued_at,
                queued,
                group_id,
                payload,
                respond,
                events,
                account_id_hex,
                account_label,
                shared,
                storage_permit,
            )
            .await;
            true
        }),
        AccountWorkerCommand::SendAppEvent {
            enqueued_at,
            group_id,
            intent,
            respond,
        } => Box::pin(async move {
            let _unit = unit.enter(WorkerUnit::Send);
            let send_started_at = Instant::now();
            shared.observer.performance().record(
                AppPerformanceOperation::OutboundMessageQueueWait,
                enqueued_at.elapsed(),
                true,
            );
            let mut first_projection = true;
            client.send_telemetry = Some(shared.observer.performance().clone());
            let result = match intent {
                AppMessageIntent::Reaction {
                    target_message_id,
                    emoji,
                    tags,
                    attachments,
                } => {
                    client
                        .react_to_message_with_local_projection(
                            &group_id,
                            &target_message_id,
                            &emoji,
                            tags,
                            attachments,
                            |update| {
                                if first_projection {
                                    shared.observer.performance().record(
                                        AppPerformanceOperation::OutboundMessageLocalProjection,
                                        enqueued_at.elapsed(),
                                        true,
                                    );
                                    first_projection = false;
                                }
                                publish_app_runtime_projection_update(
                                    Emit::Unpublished(Unpublished::LocalEcho),
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
                            shared.observer.performance().record(
                                AppPerformanceOperation::OutboundMessageLocalProjection,
                                enqueued_at.elapsed(),
                                true,
                            );
                            first_projection = false;
                        }
                        publish_app_runtime_projection_update(
                            Emit::Unpublished(Unpublished::LocalEcho),
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
            shared.observer.performance().record(
                AppPerformanceOperation::OutboundMessageSend,
                send_started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::BuildMediaImetaTag {
            group_id,
            reference,
            respond,
        } => Box::pin(async move {
            let result = client.build_media_imeta_tag(&group_id, &reference).await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                .prepare_encrypted_media_upload_payload(&group_id, request)
                .await
            {
                Ok((http, finish)) => {
                    spawn_media_http(media_http, permit, http.run(), move |result| {
                        MediaHttpCompletion::Upload {
                            finish,
                            result: result.map(|(result, uploads)| (result, Box::new(uploads))),
                            respond,
                            started_at,
                        }
                    })
                }
                Err(err) => {
                    shared.observer.performance().record(
                        AppPerformanceOperation::MediaUpload,
                        started_at.elapsed(),
                        false,
                    );
                    let _ = respond_diagnosed(
                        shared,
                        storage_permit.as_ref(),
                        respond,
                        Err(err),
                        client,
                    );
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
            let telemetry = shared.observer.performance().clone();
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
                    let _ = respond_diagnosed(
                        shared,
                        storage_permit.as_ref(),
                        respond,
                        Err(err),
                        client,
                    );
                }
            }
            true
        }),
        AccountWorkerCommand::SecureDeleteExpiredPlaintext { group_id, respond } => {
            Box::pin(async move {
                let result = client.secure_delete_expired_plaintext_for_group(&group_id);
                let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
                true
            })
        }
        AccountWorkerCommand::SweepExpiredRetention { now_ms, respond } => Box::pin(async move {
            let result = client.sweep_expired_retention(now_ms);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                            Emit::Unpublished(Unpublished::LocalEcho),
                            events,
                            account_id_hex,
                            account_label,
                            update,
                        );
                    },
                )
                .await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
                        Emit::Unpublished(Unpublished::LocalEcho),
                        events,
                        account_id_hex,
                        account_label,
                        update,
                    );
                })
                .await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::RetryGroupConvergence { group_id, respond } => Box::pin(async move {
            let _unit = unit.enter(WorkerUnit::Convergence);
            let result = client.retry_group_convergence(&group_id).await;
            if result.is_ok() {
                publish_client_pending_projection_updates(
                    client,
                    events,
                    account_id_hex,
                    account_label,
                );
                publish_app_runtime_group_state_updated(
                    Emit::Quiescent(client),
                    events,
                    account_id_hex,
                    account_label,
                    &group_id,
                );
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::PendingWelcomeDeliveries { respond } => Box::pin(async move {
            let result = client.pending_welcome_deliveries();
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::RedeliverWelcome {
            message_id_hex,
            respond,
        } => Box::pin(async move {
            let result = client.redeliver_welcome(&message_id_hex).await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::DeviceLink { op, respond } => Box::pin(async move {
            let result = client.device_link(op).await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::PublishKeyPackage { respond } => Box::pin(async move {
            let result = async {
                let key_package = client.publish_key_package().await?;
                Ok(key_package.bytes().len())
            }
            .await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::PublishSetupKeyPackage { respond } => Box::pin(async move {
            let started_at = Instant::now();
            let result = async {
                let key_package = client.publish_setup_key_package().await?;
                Ok(key_package.bytes().len())
            }
            .await;
            shared.observer.performance().record(
                AppPerformanceOperation::AccountInitialKeyPackagePublish,
                started_at.elapsed(),
                result.is_ok(),
            );
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::RotateKeyPackage { respond } => Box::pin(async move {
            let result = async {
                let key_package = client.rotate_key_package().await?;
                Ok(key_package.bytes().len())
            }
            .await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::WithdrawKeyPackageSlot { respond } => Box::pin(async move {
            let result = client.withdraw_key_package_slot().await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::KeyPackageMaintenanceStatus { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.key_package_maintenance_status(),
                client,
            );
            true
        }),
        AccountWorkerCommand::DurablyOwnedKeyPackages { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.durably_owned_key_packages(),
                client,
            );
            true
        }),
        AccountWorkerCommand::MaintenanceStatus { group_id, respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.maintenance_status(&group_id),
                client,
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
                    client,
                );
                true
            })
        }
        AccountWorkerCommand::ReconnectRelay {
            canonical_url,
            respond,
        } => Box::pin(async move {
            let result = client.reconnect_relay(canonical_url).await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::PeriodicMaintenancePolicy { respond } => Box::pin(async move {
            let _ = respond_diagnosed(
                shared,
                storage_permit.as_ref(),
                respond,
                client.periodic_maintenance_policy(),
                client,
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
                    client,
                );
                true
            })
        }
        AccountWorkerCommand::PauseMaintenance { respond } => Box::pin(async move {
            client.pause_maintenance();
            let _ = reply(respond, Ok(()), client);
            true
        }),
        AccountWorkerCommand::ResumeMaintenance { respond } => Box::pin(async move {
            client.resume_maintenance();
            let _ = reply(respond, Ok(()), client);
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
                // A host that drives maintenance itself starts the history
                // blobs it made due, as the periodic pass does.
                dispatch_history_blobs(client, media_http);
            }
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::SharePushRegistration { respond } => Box::pin(async move {
            let result = client.share_push_registration().await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::ClearPushRegistration { respond } => Box::pin(async move {
            let result = client.clear_and_share_push_registration().await;
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::SetNativePushEnabled { enabled, respond } => Box::pin(async move {
            let result = client
                .app
                .set_native_push_enabled(&client.state.label, enabled);
            let should_retry = result.is_ok();
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
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
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::GroupPushDebugInfo { group_id, respond } => Box::pin(async move {
            // See the Members arm: on-demand promotion for pipeline-abort
            // leftovers.
            let _ = client.runtime.ensure_group_hydrated(&group_id);
            let result = client.group_push_debug_info(&group_id);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::RetryPushRegistration { respond } => Box::pin(async move {
            let pending = client
                .retry_pending_push_registration_shares_best_effort()
                .await;
            let _ = reply(respond, pending, client);
            true
        }),
        AccountWorkerCommand::DeleteAuditLog { path, respond } => Box::pin(async move {
            let result = client.rotate_audit_log_if_active(&path);
            let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
            true
        }),
        AccountWorkerCommand::SetAuditRecording { enabled, respond } => Box::pin(async move {
            client.set_audit_recording(enabled);
            let _ = reply(respond, Ok(()), client);
            true
        }),
    }
}

fn group_recovery_after_hydration(
    client: &mut AppClient,
    group_id: &GroupId,
) -> Result<crate::GroupRecoveryStatus, AppError> {
    client.runtime.ensure_group_hydrated(group_id)?;
    client.group_recovery_status(group_id)
}

/// Observe committed same-account work before waiting on its coalesced signal.
/// The receiver is created before this future's first queue check, so an admission
/// racing the check cannot be lost. Other accounts' wakes do not preempt this owner.
async fn wait_for_local_submission_or_shutdown(
    app: MarmotApp,
    account_label: String,
    admission_gate: Arc<tokio::sync::Mutex<()>>,
    mut wakeups: watch::Receiver<()>,
    mut stopping: watch::Receiver<bool>,
) {
    loop {
        if *stopping.borrow() {
            return;
        }
        // Storage failure also yields optional network work. The normal owner
        // retains error handling; this observer must never reopen after shutdown.
        {
            let Ok(_admission) = admission_gate.try_lock() else {
                // Admission owns this account's storage; never park the owner
                // behind it merely to decide whether optional work can wait.
                return;
            };
            if !app
                .account_storage(&account_label)
                .and_then(|storage| {
                    storage
                        .app_storage()
                        .next_local_submission()
                        .map_err(Into::into)
                })
                .is_ok_and(|submission| submission.is_none())
            {
                return;
            }
        }
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            result = wakeups.changed() => if result.is_err() { return; },
        }
    }
}

/// Publishes one durable submission under the account owner and returns its next drain delay.
/// Startup and steady state use the same completion, retry and projection boundary.
async fn publish_next_local_submission(
    client: &mut AppClient,
    app: &MarmotApp,
    shared: &RuntimeSharedServices,
    unit: &WorkerUnitGauge,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
) -> Option<Duration> {
    #[cfg(test)]
    tests::secondary_retry_scheduler_tests::record_drain(account_id_hex);
    let (submission, queued) = {
        // Account-local admission may be waiting on storage. Do not park this
        // executor thread or the worker's shutdown/read serving behind it.
        let gate = shared.local_submission_gate(account_id_hex);
        let Ok(_admission) = gate.try_lock() else {
            return Some(Duration::from_millis(100));
        };
        let storage = app.account_storage(account_label).ok()?;
        let submission = storage.app_storage().next_local_submission().ok()??;
        let queued = shared
            .local_submission_queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take(
                account_id_hex,
                &submission.group_id_hex,
                &submission.message_id_hex,
            );
        (submission, queued)
    };
    if let Some(queued) = queued {
        queued.finish(shared.observer.performance());
    }
    let _unit = unit.enter(WorkerUnit::Send);
    let execution = shared
        .observer
        .performance()
        .observe(RuntimeOp::SendExecution);
    let started = Instant::now();
    client.send_telemetry = Some(shared.observer.performance().clone());
    let result = client
        .publish_local_submission(&submission, |update| {
            publish_app_runtime_projection_update(
                Emit::Unpublished(Unpublished::LocalEcho),
                events,
                account_id_hex,
                account_label,
                update,
            );
        })
        .await;
    client.send_telemetry = None;
    execution.finish_app(&result);
    shared.observer.performance().record(
        AppPerformanceOperation::OutboundMessageSend,
        started.elapsed(),
        result.is_ok(),
    );
    // A failed completion write must not strand later app-owned rows until
    // maintenance; bound retries when this row remains at the queue's head.
    let finished = app.finish_local_message(account_label, &submission, &result);
    let retry = if finished.is_err() {
        Duration::from_millis(100)
    } else {
        Duration::ZERO
    };
    if let Ok(Some(update)) = finished {
        publish_app_runtime_projection_update(
            Emit::Quiescent(client),
            events,
            account_id_hex,
            account_label,
            update,
        );
    }
    publish_client_pending_projection_updates(client, events, account_id_hex, account_label);
    publish_client_pending_applied_summary(client, events, account_id_hex, account_label);
    Some(retry)
}

#[allow(clippy::too_many_arguments)]
async fn send_message_on_worker(
    client: &mut AppClient,
    enqueued_at: Instant,
    queued: Option<Observation>,
    group_id: GroupId,
    payload: Vec<u8>,
    respond: oneshot::Sender<Result<SendSummary, AppError>>,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    shared: &RuntimeSharedServices,
    storage_permit: Option<crate::DiagnosticsPermit>,
) {
    if let Some(queued) = queued {
        queued.finish(TelemetryOutcome::Success);
    }
    let execution = shared
        .observer
        .performance()
        .observe(RuntimeOp::SendExecution);
    let send_started_at = Instant::now();
    shared.observer.performance().record(
        AppPerformanceOperation::OutboundMessageQueueWait,
        enqueued_at.elapsed(),
        true,
    );
    let mut first_projection = true;
    client.send_telemetry = Some(shared.observer.performance().clone());
    let result = client
        .send_with_local_projection(&group_id, &payload, |update| {
            if first_projection {
                shared.observer.performance().record(
                    AppPerformanceOperation::OutboundMessageLocalProjection,
                    enqueued_at.elapsed(),
                    true,
                );
                first_projection = false;
            }
            publish_app_runtime_projection_update(
                Emit::Unpublished(Unpublished::LocalEcho),
                events,
                account_id_hex,
                account_label,
                update,
            );
        })
        .await;
    client.send_telemetry = None;
    execution.finish_app(&result);
    shared.observer.performance().record(
        AppPerformanceOperation::OutboundMessageSend,
        send_started_at.elapsed(),
        result.is_ok(),
    );
    let _ = respond_diagnosed(shared, storage_permit.as_ref(), respond, result, client);
}

pub(super) fn group_roster_after_hydration(
    client: &mut AppClient,
    group_id: &GroupId,
) -> Result<crate::groups::AppGroupRosterSession, AppError> {
    client.runtime.ensure_group_hydrated(group_id)?;
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
        let _live = client.runtime.ensure_group_hydrated(group_id)?;
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

/// Arm the push retry for the work a worker turn left: a member add on any
/// ingest or send path that queued a share or owed a snapshot, a sent message
/// that owes the periodic announce, a received announce or request to decide
/// a repair reply for, or an owed snapshot, announce or repair reply that its
/// group's state no longer holds back. What holds one back (hydration, a
/// queued invite, a disband, a block) changes only through account work, so
/// checking after every turn notices it without polling. A join window
/// ending, and a repair reply's slots passing, are noticed by the maintenance
/// tick.
fn schedule_push_work_after_turn(
    client: &mut AppClient,
    scheduled: &mut ScheduledPushRegistrationRetry,
    commands: &mpsc::Sender<AccountWorkerCommand>,
) {
    client.retry_pending_member_add_push_shares();
    if client.take_queued_push_registration_share()
        || client.has_due_push_snapshot()
        || client.has_due_push_announce()
        || client.has_due_push_repair()
    {
        scheduled.observe_pending(true, commands);
    }
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
pub(crate) static HELD_SCHEDULED_CONVERGENCE_ACCOUNTS: std::sync::LazyLock<Mutex<HashSet<String>>> =
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

/// Wake unsent retained sends when a transport starts or reopens, which no host
/// connectivity edge reports.
///
/// Their retry clocks may have backed off towards an hour during an outage that has
/// since ended without an edge, as on a cold start that is already online or a
/// reopen after the old transport died while the network stayed up. Starting the
/// transport does not prove a relay is reachable, as activation succeeds with every
/// relay unreachable, so each start or reopen costs one retry of each woken send. A
/// failed retry keeps its attempt count and resumes its backoff from it. Sends that
/// met quorum keep their secondary replication schedule. A start whose sync failed
/// gets no wake here; its sends wait out their backoff unless a reopen or a
/// connectivity edge wakes them first.
fn wake_retained_sends_after_transport_start(client: &mut AppClient, method: &'static str) {
    if let Err(error) = client.wake_retained_sends(RetainedSendWake::BelowQuorum) {
        tracing::warn!(
            target: "marmot_app::account_worker",
            method = method,
            error_kind = error.privacy_safe_kind(),
            "retained sends could not be woken after a transport start",
        );
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
    Duration::from_millis(
        app.settlement_quiescence_ms()
            .saturating_add(CONVERGENCE_SETTLEMENT_SCHEDULE_MARGIN_MS),
    )
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

/// Only automatic admission is paced. Explicit sync/next_event callers still
/// attempt retained input and observe the original storage/backend error.
/// This timer never reconnects or acquires recovery credit.
#[derive(Default)]
struct ReplayAdmissionRetry {
    attempts: u32,
    deadline: Option<TokioInstant>,
}

impl ReplayAdmissionRetry {
    async fn admit_native_turn(&mut self, client: &mut AppClient) -> Result<bool, AppError> {
        if !self.ready() {
            return Ok(false);
        }
        match client.admit_native_turn().await {
            Ok(progress) => {
                if progress {
                    self.reset();
                }
                Ok(progress)
            }
            Err(error) => {
                self.failed();
                client.yield_failed_native_turn();
                Err(error)
            }
        }
    }

    fn ready(&self) -> bool {
        self.deadline
            .is_none_or(|deadline| deadline <= TokioInstant::now())
    }

    fn failed(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.deadline = Some(TokioInstant::now() + retry_delay_for_attempt(self.attempts));
    }

    fn reset(&mut self) {
        self.attempts = 0;
        self.deadline = None;
    }

    async fn wait(&mut self) {
        match self.deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
        self.deadline = None;
    }
}

/// Finish the original Receive arm after its recovery outcome is reported.
/// The same tail runs immediately for inline/deferred work or when the owned
/// comparison joins; automatic push work schedules from the current durable
/// intent instead of awaiting an unrelated gossip batch on the receive path.
struct ReceiveTailContext<'a> {
    events: &'a broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &'a str,
    account_label: &'a str,
    shared: &'a RuntimeSharedServices,
    scheduled_push_retry: &'a mut ScheduledPushRegistrationRetry,
    command_tx: &'a mpsc::Sender<AccountWorkerCommand>,
}

/// Forget the device-group copy and ask the runtime to deactivate the
/// account, which then tells hosts the device group unlinked this device;
/// the caller ends the worker. Once the account is marked unlinked, a crash
/// from here on still leaves it signed out; a mark that failed keeps the
/// copy, so the next start finds the removal and marks it (mdk#2628 D67).
async fn stop_unlinked_worker(client: &mut AppClient, unlinked: oneshot::Sender<()>) {
    client.follow_device_group_removal().await;
    client.finish_audit_recording();
    let _ = unlinked.send(());
}

async fn finish_receive_after_recovery(
    client: &mut AppClient,
    context: ReceiveTailContext<'_>,
    audit_tracker_update: bool,
    retry_push_registration: bool,
) {
    if audit_tracker_update {
        context.shared.schedule_audit_log_tracker_update("receive");
    }
    if retry_push_registration {
        context.scheduled_push_retry.observe_pending(
            client.has_pending_push_registration_work(),
            context.command_tx,
        );
        publish_client_pending_applied_summary(
            client,
            context.events,
            context.account_id_hex,
            context.account_label,
        );
    }
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

/// Start the temporary post-join history subscription only after the caller has
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
    let (live_error, history_error) = client.advance_visible_join(summary).await;
    publish_join_errors(
        Emit::Quiescent(client),
        live_error,
        history_error,
        events,
        account_id_hex,
        account_label,
    );
}

fn publish_join_errors(
    at: Emit<'_>,
    live_error: Option<AppError>,
    history_error: Option<AppError>,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
) {
    if let Some(error) = live_error {
        publish_app_runtime_account_error(
            at,
            events,
            account_id_hex,
            account_label,
            account_error_message("post-join live subscription refresh failed", &error),
        );
    }
    if let Some(error) = history_error {
        publish_app_runtime_account_error(
            at,
            events,
            account_id_hex,
            account_label,
            account_error_message("post-join maintenance subscription failed", &error),
        );
    }
}

fn publish_sync_summary_with_audit(
    client: &AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    summary: &SyncSummary,
    shared: &RuntimeSharedServices,
    audit_trigger: &'static str,
) {
    publish_app_runtime_summary_with_v5(client, events, account_id_hex, account_label, summary);
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
/// ingest seam so the capture-before-run ordering cannot drift. A job failure
/// is both published and returned: explicit catch-up fails its response while
/// background seams retain their existing event-only reporting behavior. A
/// deferred result is deliberately accepted only after the caller's ordinary
/// sync has completed; the distinct outcome keeps that policy choice visible
/// instead of conflating deferral with no pending work.
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

struct EpochBackfillReportContext<'a> {
    events: &'a broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &'a str,
    account_label: &'a str,
    shared: &'a RuntimeSharedServices,
}

/// Report a recovery seam's outcome: product analytics, an account error for a
/// failure, and the audit tracker when epoch-gap debt was armed.
fn report_pending_epoch_backfill_result(
    client: &AppClient,
    backfill_result: Result<EpochBackfillRunOutcome, AppError>,
    backfill_armed: bool,
    observation: Option<marmot_observability::product_analytics::ProductObservation>,
    context: EpochBackfillReportContext<'_>,
) -> Result<(), AccountCatchUpFailure> {
    let EpochBackfillReportContext {
        events,
        account_id_hex,
        account_label,
        shared,
    } = context;
    if let Some(observation) = observation {
        observation.finish(match &backfill_result {
            Ok(EpochBackfillRunOutcome::Deferred) => "deferred",
            Ok(EpochBackfillRunOutcome::NotPending) => "no_work_due",
            Err(_) => "failure",
        });
    }
    let result = match backfill_result {
        Ok(EpochBackfillRunOutcome::Deferred | EpochBackfillRunOutcome::NotPending) => Ok(()),
        Err(error) => {
            let message = account_error_message("epoch-gap backfill failed", &error);
            publish_app_runtime_account_error(
                Emit::Quiescent(client),
                events,
                account_id_hex,
                account_label,
                message.clone(),
            );
            // refresh_pending_recovery returns only AppError, after several
            // distinct storage and relay boundaries. Preserve its typed broad
            // cause but do not derive a stage from that cause.
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

#[derive(Default)]
struct RuntimeSummaryPublication {
    attempted: u64,
    accepted: u64,
    no_subscribers: u64,
}

/// Broadcast committed projection progress without retaining snapshots. Only
/// bounded aggregate counts remain for the existing v5 publication outcome.
struct ProjectionPublicationProgress {
    events: broadcast::Sender<MarmotAppEvent>,
    account_id_hex: String,
    account_label: String,
    publication: std::sync::Mutex<RuntimeSummaryPublication>,
}

impl ProjectionPublicationProgress {
    fn new(
        events: broadcast::Sender<MarmotAppEvent>,
        account_id_hex: &str,
        account_label: &str,
    ) -> Self {
        Self {
            events,
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            publication: Default::default(),
        }
    }

    fn publish(&self, update: AppProjectionUpdate) {
        let accepted = publish_app_runtime_projection_update(
            Emit::Unpublished(Unpublished::ConvergenceProgress),
            &self.events,
            &self.account_id_hex,
            &self.account_label,
            update,
        );
        let mut publication = self.publication.lock().unwrap();
        publication.attempted += 1;
        if accepted {
            publication.accepted += 1;
        } else {
            publication.no_subscribers += 1;
        }
    }

    fn take_publication(&self) -> RuntimeSummaryPublication {
        std::mem::take(&mut *self.publication.lock().unwrap())
    }
}

fn publish_app_runtime_summary(
    at: Emit<'_>,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    summary: &SyncSummary,
) -> RuntimeSummaryPublication {
    let mut publication = RuntimeSummaryPublication::default();
    let mut send = |event| {
        publication.attempted += 1;
        if emit(at, events, event) {
            publication.accepted += 1;
        } else {
            publication.no_subscribers += 1;
        }
    };
    for group_id in &summary.joined_groups {
        send(MarmotAppEvent::GroupJoined {
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
            send(event);
        } else {
            send(MarmotAppEvent::MessageReceived(RuntimeMessageReceived {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
                message: message.clone(),
            }));
        }
    }
    for update in &summary.projection_updates {
        send(MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            update: update.clone(),
        }));
    }
    for event in &summary.events {
        send(MarmotAppEvent::GroupEvent(RuntimeGroupEvent {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            event: event.clone(),
        }));
    }
    for escalation in &summary.epoch_stall_escalations {
        send(MarmotAppEvent::EpochStallEscalated {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            group_id: escalation.group_id.clone(),
            stalled_epoch: escalation.stalled_epoch,
            arms: escalation.arms,
        });
    }
    publication
}

fn runtime_summary_message_ref(
    summary: &SyncSummary,
) -> Option<marmot_forensics::v5::EngineMessageRef> {
    if summary.messages.len() == 1
        && summary.joined_groups.is_empty()
        && summary.epoch_stall_escalations.is_empty()
    {
        match summary.events.as_slice() {
            [cgka_traits::engine::GroupEvent::MessageReceived { message_id, .. }]
                if hex::encode(message_id.as_slice())
                    == summary.messages[0].source_message_id_hex =>
            {
                marmot_forensics::v5::EngineMessageRef::from_message_id(message_id.as_slice()).ok()
            }
            _ => None,
        }
    } else {
        None
    }
}

fn record_runtime_publication(
    client: &AppClient,
    category: marmot_forensics::v5::RuntimePublicationCategory,
    message_ref: Option<marmot_forensics::v5::EngineMessageRef>,
    publication: RuntimeSummaryPublication,
) {
    if publication.attempted == 0 || !client.audit_v5_enabled() {
        return;
    }
    marmot_forensics::ForensicRecorder::record_v5_event(
        &client.audit,
        None,
        marmot_forensics::v5::Event::RuntimePublicationOutcome(
            marmot_forensics::v5::RuntimePublicationOutcome {
                operation_ref: None,
                message_ref,
                category,
                attempted: publication.attempted.into(),
                accepted_by_broadcast: publication.accepted.into(),
                no_subscribers: publication.no_subscribers.into(),
            },
        ),
    );
}

fn publish_app_runtime_summary_with_v5(
    client: &AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    summary: &SyncSummary,
) {
    publish_app_runtime_summary_with_v5_at(
        Emit::Quiescent(client),
        client,
        events,
        account_id_hex,
        account_label,
        summary,
    );
}

fn publish_app_runtime_summary_with_v5_at(
    at: Emit<'_>,
    client: &AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    summary: &SyncSummary,
) {
    let publication =
        publish_app_runtime_summary(at, events, account_id_hex, account_label, summary);
    record_runtime_publication(
        client,
        marmot_forensics::v5::RuntimePublicationCategory::SyncSummary,
        runtime_summary_message_ref(summary),
        publication,
    );
}

pub(super) fn publish_app_runtime_projection_update(
    at: Emit<'_>,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    update: AppProjectionUpdate,
) -> bool {
    emit(
        at,
        events,
        MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            update,
        }),
    )
}

fn publish_created_group(
    at: Emit<'_>,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    created: &CanonicalCreatedGroup,
) {
    publish_app_runtime_group_state_updated(
        at,
        events,
        account_id_hex,
        account_label,
        &created.group_id,
    );
    if let Some(row) = &created.chat_list_row {
        let _ = emit(
            at,
            events,
            MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
                update: AppProjectionUpdate {
                    group_id_hex: row.group_id_hex.clone(),
                    timeline_messages: Vec::new(),
                    timeline_changes: Vec::new(),
                    chat_list_row: Some(row.clone()),
                    chat_list_trigger: ChatListUpdateTrigger::NewGroup,
                },
            }),
        );
    }
}

fn publish_client_pending_projection_updates(
    client: &mut AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
) {
    let mut publication = RuntimeSummaryPublication::default();
    for update in client.take_pending_projection_updates() {
        publication.attempted += 1;
        if publish_app_runtime_projection_update(
            Emit::Quiescent(client),
            events,
            account_id_hex,
            account_label,
            update,
        ) {
            publication.accepted += 1;
        } else {
            publication.no_subscribers += 1;
        }
    }
    record_runtime_publication(
        client,
        marmot_forensics::v5::RuntimePublicationCategory::ProjectionUpdate,
        None,
        publication,
    );
    publish_account_level_changes(client, events, account_id_hex, account_label);
    for group_id in std::mem::take(&mut client.pending_recovery_status_updates) {
        publish_app_runtime_group_state_updated(
            Emit::Quiescent(client),
            events,
            account_id_hex,
            account_label,
            &group_id,
        );
    }
    // Welcomes a publish could not deliver ride the same drain, whichever
    // path published them (mdk#2628 3.5a).
    publish_pending_welcome_delivery_events(events, account_id_hex, account_label, client);
    // Superseded own commits ride the same drain: every worker seam that can
    // observe convergence effects already flushes projection updates here.
    for report in client.take_pending_superseded_change_events() {
        let _ = emit(
            Emit::Quiescent(client),
            events,
            MarmotAppEvent::GroupChangeSuperseded {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
                group_id: report.group_id,
                commit_id_hex: hex::encode(report.commit_id.as_slice()),
                kind: report.kind,
                outcome: report.outcome,
                reason: report.reason,
            },
        );
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
    publish_app_runtime_summary_with_v5(client, events, account_id_hex, account_label, &summary);
    // Startup and reconnect reconcile device-group trust before reaching
    // here, and no account-level seam follows them until the next command.
    publish_device_group_changes(client, events, account_id_hex, account_label);
    publish_sign_in_changes(client, events, account_id_hex, account_label);
}

/// After a runner turn: a turn that settled a changed copy may have raised or
/// cleared a rejoin notice the runner's survey does not show (mdk#2660 row
/// 11), so it publishes account-level changes even when what is catching up
/// stayed the same. A notice change announces `HistoryNoticesChanged` and
/// `RecoveryStatusChanged`; an unchanged one announces nothing.
fn publish_settled_recovery_copies(
    client: &mut AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
) {
    if std::mem::take(&mut client.recovery_copy_settled) {
        publish_account_level_changes(client, events, account_id_hex, account_label);
    }
}

/// Announce account-level changes. A change in the parked recovery set
/// ("history may be incomplete") is one `HistoryNoticesChanged`, plus
/// `GroupStateUpdated` for each group whose own notices appeared or
/// disappeared, so hosts re-read that group's `GroupRecoveryStatus`. Parking,
/// un-parking by new evidence and dismissal all surface at the next seam that
/// calls this; each call is one indexed read of the parked set. A change in
/// what the recovery runner catches up, or in the notices, is one
/// `RecoveryStatusChanged`, sent first. It also
/// announces device-group and sign-in changes
/// ([`publish_device_group_changes`], [`publish_sign_in_changes`]).
fn publish_account_level_changes(
    client: &mut AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
) {
    // Record queued subscription refusals off relay paths.
    client.record_subscription_refusals();
    publish_device_group_changes(client, events, account_id_hex, account_label);
    publish_sign_in_changes(client, events, account_id_hex, account_label);
    let notice_changes = client.take_history_notice_changes();
    if client.take_recovery_status_changed(notice_changes.is_some()) {
        let _ = emit(
            Emit::Quiescent(client),
            events,
            MarmotAppEvent::RecoveryStatusChanged {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
            },
        );
    }
    let Some(groups) = notice_changes else {
        return;
    };
    let _ = emit(
        Emit::Quiescent(client),
        events,
        MarmotAppEvent::HistoryNoticesChanged {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
        },
    );
    for group_id in groups {
        publish_app_runtime_group_state_updated(
            Emit::Quiescent(client),
            events,
            account_id_hex,
            account_label,
            &group_id,
        );
    }
}

/// One `LinkedDevicesChanged` for a hidden device-group event or a change of
/// device-group trust since the last call, or a completed deferred device-name
/// refresh, after giving storage the roster's device names again; one
/// `KeyPackageRefreshOverdueChanged` for a
/// maintenance pass that changed the overdue-refresh answer; one
/// `DeviceLinkChanged` for a change in linking a new device; and one
/// `ChatHistoryImportsChanged` for a change in chat history from another
/// device. Both the account-level seam and the applied-summary seam drain
/// them, so startup, reconnect, maintenance and every command and delivery
/// announce them.
pub(crate) fn publish_device_group_changes(
    client: &mut AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
) {
    client.publish_backup_restore_availability();
    client.refresh_device_labels(client.linked_devices_changed);
    if client.take_linked_devices_changed() {
        let _ = emit(
            Emit::Quiescent(client),
            events,
            MarmotAppEvent::LinkedDevicesChanged {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
            },
        );
    }
    if client.take_key_package_refresh_overdue_changed() {
        let _ = emit(
            Emit::Quiescent(client),
            events,
            MarmotAppEvent::KeyPackageRefreshOverdueChanged {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
            },
        );
    }
    if client.take_device_link_changed() {
        let _ = emit(
            Emit::Quiescent(client),
            events,
            MarmotAppEvent::DeviceLinkChanged {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
            },
        );
    }
    if client.take_chat_history_imports_changed() {
        let _ = emit(
            Emit::Quiescent(client),
            events,
            MarmotAppEvent::ChatHistoryImportsChanged {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
            },
        );
    }
}

/// One `UnrecognizedSignInsChanged` for a check or answer that changed the
/// unrecognized sign-ins, or a roster change, since the last call, and one
/// `CompromiseWarningChanged` when the compromise warning changed. Drained
/// at the same seams as [`publish_device_group_changes`].
fn publish_sign_in_changes(
    client: &mut AppClient,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
) {
    if client.take_unrecognized_sign_ins_changed() {
        let _ = emit(
            Emit::Quiescent(client),
            events,
            MarmotAppEvent::UnrecognizedSignInsChanged {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
            },
        );
    }
    if client.take_compromise_warning_changed() {
        let _ = emit(
            Emit::Quiescent(client),
            events,
            MarmotAppEvent::CompromiseWarningChanged {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
            },
        );
    }
}

pub(crate) fn publish_app_runtime_group_state_updated(
    at: Emit<'_>,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    group_id: &GroupId,
) {
    let _ = emit(
        at,
        events,
        MarmotAppEvent::GroupStateUpdated {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            group_id: group_id.clone(),
        },
    );
}

/// Broadcast a `WelcomeDeliveryPending` event for each Welcome a publish
/// queued for re-delivery (mdk#352), so subscribers learn delivery remains
/// pending without polling the durable queue. This is not non-delivery evidence.
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
        let _ = emit(
            Emit::Quiescent(client),
            events,
            MarmotAppEvent::WelcomeDeliveryPending {
                account_id_hex: account_id_hex.to_owned(),
                account_label: account_label.to_owned(),
                group_id: GroupId::new(group_id_bytes),
                message_id_hex: pending.message_id_hex,
                recipient_hex: pending.recipient_hex,
                size_class: pending.size_class,
            },
        );
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
    at: Emit<'_>,
    events: &broadcast::Sender<MarmotAppEvent>,
    account_id_hex: &str,
    account_label: &str,
    message: String,
) {
    let _ = emit(
        at,
        events,
        MarmotAppEvent::AccountError(RuntimeAccountError {
            account_id_hex: account_id_hex.to_owned(),
            account_label: account_label.to_owned(),
            message,
        }),
    );
}

/// Where the account worker stands when it emits a host event (mdk#3273).
#[derive(Clone, Copy)]
pub(crate) enum Emit<'a> {
    /// At a quiescent point: no engine call runs and every multi-step change
    /// has finished or rests where it is designed to. A is published first,
    /// so a host that sees the event reads at least the state it describes.
    Quiescent(&'a AppClient),
    /// Without publishing A first, for the named reason.
    Unpublished(#[allow(dead_code)] Unpublished),
}

/// Why an event goes out without publishing A first.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Unpublished {
    /// A drain turn's committed progress during startup's catch-up. The
    /// drain publishes A at most once per time bound, so reads see the state
    /// after a recent delivery rather than this one (mdk#3273 decision 2).
    DrainProgress,
    /// A convergence pass's progress. Reads see the state from before the
    /// pass until it ends (mdk#3273 decision 2).
    ConvergenceProgress,
    /// A send's local echo, emitted while the send awaits its relays: reads
    /// see the state from before the send until it ends (mdk#3273 decision 2).
    LocalEcho,
    /// A host call emitting after the worker's reply, which the worker
    /// published before it replied.
    AfterReply,
    /// No A exists: the account runs no worker, or its worker's client did
    /// not open.
    NoClient,
    /// A host call that wrote off the worker, such as a local send's
    /// admission: what it changed is not an input of A.
    OffWorker,
}

/// Send one host event from the account worker, publishing A first at a
/// quiescent point; whether any subscriber received it.
fn emit(at: Emit<'_>, events: &broadcast::Sender<MarmotAppEvent>, event: MarmotAppEvent) -> bool {
    if let Emit::Quiescent(client) = at {
        client.publish_read_state();
    }
    events.send(event).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[cfg(feature = "test-policy-overrides")]
    mod automatic_group_recovery_tests;
    #[cfg(feature = "test-policy-overrides")]
    mod local_submission_queue_tests;
    mod publication_progress_tests;
    mod read_queue_tests;
    mod read_state_tests;
    mod recovery_runner_host_tests;
    mod refused_subscription_send_tests;
    mod resource_bounds_tests;
    pub(super) mod secondary_retry_scheduler_tests;
    mod selective_history_tests;
    mod worker_recovery_resume_tests;

    static BOUNDED_WORKER_FIXTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    // Paused time pins the production retry deadlines without wall-clock sleeps.
    #[tokio::test(start_paused = true)]
    async fn native_admission_backoff() {
        let mut retry = ReplayAdmissionRetry::default();
        for expected in [1, 2, 4, 8, 16, 32, 60, 60] {
            assert!(retry.ready());
            retry.failed();
            assert!(!retry.ready());
            let deadline = retry.deadline.unwrap();
            assert_eq!(
                deadline - TokioInstant::now(),
                Duration::from_secs(expected)
            );
            tokio::time::advance(Duration::from_secs(expected) - Duration::from_millis(1)).await;
            assert!(
                !retry.ready(),
                "unrelated worker wakes cannot shorten failure backoff"
            );
            retry.wait().await;
            assert!(retry.ready());
            assert!(
                retry.deadline.is_none(),
                "a consumed retry deadline cannot hot-loop"
            );
        }
        retry.reset();
        assert_eq!(retry.attempts, 0);
        retry.failed();
        assert_eq!(
            retry.deadline.unwrap() - TokioInstant::now(),
            Duration::from_secs(1)
        );
    }

    use marmot_account::AccountHome;

    use crate::MarmotApp;
    use crate::client::epoch_stall::BackfillDecision;
    use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};

    fn setup_state(kind: AccountSetupKind, phase: AccountSetupPhase) -> AccountSetupState {
        AccountSetupState {
            account_id_hex: "00".repeat(32),
            reused_account_id_credential: false,
            kind,
            phase,
        }
    }

    /// mdk#2628 3.5a: the drain every worker seam runs broadcasts the Welcome
    /// failures its client noted, so one a maintenance or convergence pass
    /// published reaches the host without waiting for the next create or
    /// invite.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn projection_drain_broadcasts_noted_welcome_failures() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group_id = GroupId::new(vec![1; 16]);
        client
            .pending_welcome_delivery_events
            .push(crate::PendingWelcomeDelivery {
                size_class: Some(crate::EventSizeClass::From512KibTo1Mib),
                group_id_hex: hex::encode(group_id.as_slice()),
                message_id_hex: "ab".repeat(32),
                recipient_hex: "cd".repeat(32),
                recorded_at: 1,
            });
        let (events, mut received) = broadcast::channel(16);
        publish_client_pending_projection_updates(&mut client, &events, "alice-id", "alice");
        let mut announced = Vec::new();
        while let Ok(event) = received.try_recv() {
            if let MarmotAppEvent::WelcomeDeliveryPending {
                group_id,
                message_id_hex,
                size_class,
                ..
            } = event
            {
                announced.push((group_id, message_id_hex, size_class));
            }
        }
        assert_eq!(
            announced,
            [(
                group_id,
                "ab".repeat(32),
                Some(crate::EventSizeClass::From512KibTo1Mib)
            )]
        );
        assert!(client.take_pending_welcome_delivery_events().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            let (respond, response) = ReadReply::unobserved();
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
                None,
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        let (respond, read) = ReadReply::unobserved();
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
            None,
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_work_preserves_catch_up_barrier_across_pending_and_channel() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let client = app.client("alice").await.unwrap();
        let snapshot = client.group_read_snapshot().unwrap();
        let (commands, mut receiver) = mpsc::channel(8);
        let mut pending = VecDeque::new();
        let (respond, mut before) = oneshot::channel();
        pending.push_back(AccountWorkerCommand::ConnectivityRestored { respond });
        let (respond, mut catch_up) = oneshot::channel();
        pending.push_back(AccountWorkerCommand::CatchUp { respond });
        let (respond, mut after) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::ConnectivityRestored { respond })
            .unwrap();
        let (respond, mut drain) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::Drain { respond })
            .unwrap();
        let (respond, read) = ReadReply::unobserved();
        commands
            .try_send(AccountWorkerCommand::QuarantinedGroups { respond })
            .unwrap();
        let (release, work) = oneshot::channel::<()>();
        let serve = serve_snapshot_reads_until(
            Some(snapshot),
            work,
            &mut receiver,
            &mut pending,
            &app,
            "alice",
            None,
        );
        let check = async {
            assert!(
                timeout(Duration::from_secs(1), read)
                    .await
                    .expect("snapshot read remains ready while work is held")
                    .unwrap()
                    .unwrap()
                    .is_empty()
            );
            assert!(matches!(
                before.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                catch_up.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                after.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                drain.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            release.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(serve, check);
        result.unwrap();
        assert!(matches!(
            pending.pop_front(),
            Some(AccountWorkerCommand::ConnectivityRestored { .. })
        ));
        assert!(matches!(
            pending.pop_front(),
            Some(AccountWorkerCommand::CatchUp { .. })
        ));
        assert!(matches!(
            pending.pop_front(),
            Some(AccountWorkerCommand::ConnectivityRestored { .. })
        ));
        assert!(matches!(
            pending.pop_front(),
            Some(AccountWorkerCommand::Drain { .. })
        ));
        assert!(pending.is_empty());
    }

    // Pauses the clock, which needs the current-thread runtime.
    #[tokio::test(flavor = "current_thread")]
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
            crate::MarmotAppConfig::white_noise()
                .with_dev_settlement_quiescence_ms(100)
                .with_dev_scheduled_convergence_delay_ms(60_000),
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
            .unwrap()
            .operation
            .expect("eligible fixture members");
        let second = runtime
            .create_group(
                "alice",
                "second",
                std::slice::from_ref(&bob.account_id_hex),
                None,
            )
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
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
        let app = storage.app_storage();
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
        // Lost history remains independent of the runnable local passes.
        app.record_account_recovery_loss(
            "bob",
            storage_sqlite::RecoveryLossCause::Queue,
            771,
            1,
            crate::unix_now_seconds(),
        )
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
            let (respond, response) = ReadReply::unobserved();
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
        runtime.drain_in_flight_work().await.unwrap();
        runtime.shutdown_and_close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            .unwrap()
            .operation
            .expect("eligible fixture members");
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
                &marmot_session::AccountDeviceEffects::default(),
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
        let effects = marmot_session::AccountDeviceEffects {
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_notice_changes_publish_once_per_transition() {
        use crate::client::history_notices::park_recovery_for_test;
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group_id = client
            .create_group("history notices", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        let epoch = client.runtime.group_record(&group_id).unwrap().epoch.0;
        let storage = app.account_storage("alice").unwrap();
        let arm = |epoch| {
            storage
                .app_storage()
                .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                    group_id_hex: hex::encode(group_id.as_slice()),
                    stalled_epoch: epoch,
                }])
                .unwrap()
        };
        arm(epoch);
        let (events, mut received) = broadcast::channel(16);
        let publish = |client: &mut AppClient| {
            publish_client_pending_projection_updates(
                client,
                &events,
                &account.account_id_hex,
                "alice",
            );
        };
        publish(&mut client);
        while received.try_recv().is_ok() {}
        let gap = storage
            .app_storage()
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|demand| demand.cause == storage_sqlite::RecoveryCause::EpochGap)
            .unwrap()
            .ticket
            .id;
        let expect_change = |received: &mut broadcast::Receiver<MarmotAppEvent>| {
            assert!(matches!(
                received.try_recv().unwrap(),
                MarmotAppEvent::RecoveryStatusChanged { account_id_hex, account_label }
                    if account_id_hex == account.account_id_hex && account_label == "alice"
            ));
            assert!(matches!(
                received.try_recv().unwrap(),
                MarmotAppEvent::HistoryNoticesChanged { account_id_hex, account_label }
                    if account_id_hex == account.account_id_hex && account_label == "alice"
            ));
            assert!(matches!(
                received.try_recv().unwrap(),
                MarmotAppEvent::GroupStateUpdated { group_id: updated, .. } if updated == group_id
            ));
            assert!(received.try_recv().is_err());
        };

        // Parking appears once.
        park_recovery_for_test(&storage, gap);
        publish(&mut client);
        expect_change(&mut received);
        publish(&mut client);
        assert!(received.try_recv().is_err(), "an unchanged set is quiet");

        // Dismissal disappears once, from the command's own publication.
        let notice = client.history_notices().unwrap().remove(0);
        assert!(client.dismiss_history_notice(&notice.notice_id).unwrap());
        publish_account_level_changes(&mut client, &events, &account.account_id_hex, "alice");
        expect_change(&mut received);

        // New evidence reopens the retired gap as pending debt, which is not
        // a notice; parking it again is a new occurrence, and un-parking it by
        // yet newer evidence removes that notice.
        arm(epoch + 1);
        publish(&mut client);
        assert!(received.try_recv().is_err());
        park_recovery_for_test(&storage, gap);
        publish(&mut client);
        expect_change(&mut received);
        assert_ne!(
            client.history_notices().unwrap()[0].notice_id,
            notice.notice_id
        );
        arm(epoch + 2);
        publish(&mut client);
        expect_change(&mut received);
        assert!(client.history_notices().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
                history_blobs: HistoryBlobFlights::default(),
                backup_background_conditions: watch::channel(
                    crate::runtime::BackupBackgroundConditions::default(),
                )
                .0,
                worker_lifetime,
            },
            rx,
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn avatar_dispatch_shares_media_capacity_and_holds_it_through_publication() {
        let store = storage_sqlite::SqliteAccountStorage::in_memory_for_test()
            .unwrap()
            .app_storage();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn avatar_shutdown_cancels_io_and_leaves_resumable_intent() {
        let store = storage_sqlite::SqliteAccountStorage::in_memory_for_test()
            .unwrap()
            .app_storage();
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
        // The aborted task may still be dropping its permit on another thread.
        drop(
            timeout(Duration::from_secs(2), permits.acquire_many(2))
                .await
                .expect("cancelled avatar I/O releases its permit")
                .unwrap(),
        );
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    // Pauses the clock, which needs the current-thread runtime.
    #[tokio::test(flavor = "current_thread")]
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
                shared: shared.clone(),
                unlinked: oneshot::channel().0,
                unit: Arc::default(),
            },
            commands.clone(),
            receiver,
            ready,
            AccountStartupProgress::new(shared.observer.performance().clone(), Arc::default()),
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
                unit: Default::default(),
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
        let (respond, snapshot) = ReadReply::unobserved();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        // The aborted task may still be dropping its permit on another thread.
        drop(
            timeout(Duration::from_secs(1), permits.acquire())
                .await
                .expect("cancelled HTTP work releases its permit")
                .unwrap(),
        );
        assert_eq!(permits.available_permits(), 1);
    }

    #[test]
    fn legacy_message_promotion_completes_and_stops_scheduling() {
        let mut schedule = LegacyMessagePromotionSchedule::new();
        let mut calls = 0;

        let outcome = run_legacy_message_promotion_batch_with(&mut schedule, |limit| {
            calls += 1;
            assert_eq!(limit, LEGACY_MESSAGE_PROMOTION_BATCH_SIZE);
            Ok(storage_sqlite::MessageFormatPromotionProgress {
                promoted: 7,
                has_more: false,
            })
        });
        assert_eq!(outcome, TelemetryOutcome::Success);
        let outcome = run_legacy_message_promotion_batch_with(&mut schedule, |_| {
            calls += 1;
            unreachable!("completed promotion must not call storage again")
        });
        assert_eq!(outcome, TelemetryOutcome::Success, "nothing left to do");

        assert_eq!(calls, 1);
        assert_eq!(schedule.promoted_total, 7);
        assert_eq!(schedule.status, LegacyMessagePromotionStatus::Complete);
    }

    #[test]
    fn legacy_message_promotion_retries_transient_failures() {
        let mut schedule = LegacyMessagePromotionSchedule::new();

        let outcome = run_legacy_message_promotion_batch_with(&mut schedule, |_| {
            Err(marmot_session::SessionError::from(
                cgka_traits::storage::StorageError::Busy("test contention".into()),
            ))
        });
        assert_eq!(
            outcome,
            TelemetryOutcome::Failure,
            "a retried batch still failed"
        );

        assert_eq!(schedule.status, LegacyMessagePromotionStatus::Pending);
        assert_eq!(schedule.promoted_total, 0);
    }

    #[test]
    fn legacy_message_promotion_halts_after_durable_failure() {
        let mut schedule = LegacyMessagePromotionSchedule::new();
        let mut calls = 0;

        let outcome = run_legacy_message_promotion_batch_with(&mut schedule, |_| {
            calls += 1;
            Err(marmot_session::SessionError::from(
                cgka_traits::storage::StorageError::Serialization("malformed legacy row".into()),
            ))
        });
        assert_eq!(outcome, TelemetryOutcome::Failure);
        let outcome = run_legacy_message_promotion_batch_with(&mut schedule, |_| {
            calls += 1;
            unreachable!("durable failure must halt this process's sweep")
        });
        assert_eq!(
            outcome,
            TelemetryOutcome::Success,
            "a halted sweep does nothing"
        );

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

        let publication = publish_app_runtime_summary(
            Emit::Unpublished(Unpublished::NoClient),
            &events,
            "account-id",
            "label",
            &summary,
        );
        assert_eq!(publication.attempted, 1);
        assert_eq!(publication.accepted, 1);
        assert_eq!(publication.no_subscribers, 0);

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
    fn summary_publication_reports_no_subscriber_without_relabeling_app_commit() {
        let (events, receiver) = broadcast::channel(4);
        drop(receiver);
        let summary = SyncSummary {
            epoch_stall_escalations: vec![crate::EpochStallEscalation {
                group_id: test_group_id(3),
                stalled_epoch: 12,
                arms: 3,
            }],
            ..SyncSummary::default()
        };
        let publication = publish_app_runtime_summary(
            Emit::Unpublished(Unpublished::NoClient),
            &events,
            "account-id",
            "label",
            &summary,
        );
        assert_eq!(publication.attempted, 1);
        assert_eq!(publication.accepted, 0);
        assert_eq!(publication.no_subscribers, 1);
    }

    #[test]
    fn runtime_summary_message_ref_requires_a_matching_typed_engine_event() {
        let group_id = test_group_id(3);
        let message_id = cgka_traits::MessageId::new(vec![0xabu8; 32]);
        let mut summary = SyncSummary {
            messages: vec![crate::ReceivedMessage {
                authority: None,
                message_id_hex: "cc".repeat(32),
                source_message_id_hex: hex::encode(message_id.as_slice()),
                sender: "sender".into(),
                sender_display_name: None,
                group_id: group_id.clone(),
                source_epoch: 1,
                retention: None,
                plaintext: "test".into(),
                kind: 1,
                tags: Vec::new(),
                recorded_at: 1,
                received_at: 2,
            }],
            ..SyncSummary::default()
        };
        assert!(runtime_summary_message_ref(&summary).is_none());
        summary
            .events
            .push(cgka_traits::engine::GroupEvent::MessageReceived {
                group_id,
                message_id: message_id.clone(),
                sender: cgka_traits::MemberId::new(vec![0x11; 32]),
                sender_leaf_index: None,
                epoch: cgka_traits::EpochId(1),
                payload: Vec::new(),
                retention: None,
                authority: None,
                encrypted_media_secret: None,
            });
        assert_eq!(
            runtime_summary_message_ref(&summary),
            marmot_forensics::v5::EngineMessageRef::from_message_id(message_id.as_slice()).ok()
        );
        summary.messages[0].source_message_id_hex = "dd".repeat(32);
        assert!(runtime_summary_message_ref(&summary).is_none());
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    /// An owed push snapshot held back by its group's state arms no retry, and
    /// the first turn after the hold clears arms one, with no command or
    /// member add of its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn held_push_snapshot_is_scheduled_once_its_group_lets_it_send() {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app =
            MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
        let mut client = app.client(&account.label).await.unwrap();
        let group = client
            .create_group("held snapshot", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        let group_hex = hex::encode(group.as_slice());
        let epoch = client.runtime.epoch_state(&group).unwrap().epoch().0;
        // Owed once the group's epoch passes the current one.
        assert!(
            app.record_group_push_snapshot_owed(&account.label, &group_hex, epoch)
                .unwrap()
        );
        let (commands, mut received) = mpsc::channel(2);
        let mut scheduled = ScheduledPushRegistrationRetry::new();
        schedule_push_work_after_turn(&mut client, &mut scheduled, &commands);
        assert!(!scheduled.is_armed());

        client
            .update_group_profile(&group, Some("held snapshot, renamed"), None)
            .await
            .unwrap();
        let _ = client.take_queued_push_registration_share();
        schedule_push_work_after_turn(&mut client, &mut scheduled, &commands);
        assert!(scheduled.is_armed());
        let AccountWorkerCommand::RetryPushRegistration { respond } =
            received.recv().await.unwrap()
        else {
            panic!("a due snapshot must enqueue a push retry")
        };
        let pending = client
            .retry_pending_push_registration_shares_best_effort()
            .await;
        assert!(!pending);
        let _ = respond.send(pending);
        assert_eq!(
            app.group_push_snapshot_owed(&account.label, &group_hex)
                .unwrap(),
            None
        );
        schedule_push_work_after_turn(&mut client, &mut scheduled, &commands);
        tokio::task::yield_now().await;
        assert!(!client.has_due_push_snapshot());
    }

    /// A group message sent where this device has never announced owes the
    /// periodic announce once the device can fetch, and the turn that sent it
    /// arms the push retry that sends it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sent_message_owing_the_periodic_announce_arms_the_push_retry() {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app =
            MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
        let mut client = app.client(&account.label).await.unwrap();
        let group = client
            .create_group("periodic announce", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        let group_hex = hex::encode(group.as_slice());
        // The device can fetch and has settled, so it announces as soon as
        // it owes one.
        client.test_push_device_can_fetch = Some(true);
        client.push_announce_timing.catch_up_settle = Duration::ZERO;
        client.advance_push_join_windows().await;
        let (commands, mut received) = mpsc::channel(2);
        let mut scheduled = ScheduledPushRegistrationRetry::new();
        schedule_push_work_after_turn(&mut client, &mut scheduled, &commands);
        assert!(!scheduled.is_armed(), "nothing is owed before a send");

        client.send(&group, b"first message").await.unwrap();
        schedule_push_work_after_turn(&mut client, &mut scheduled, &commands);
        assert!(scheduled.is_armed());
        let AccountWorkerCommand::RetryPushRegistration { respond } =
            received.recv().await.unwrap()
        else {
            panic!("an owed announce must enqueue a push retry")
        };
        let pending = client
            .retry_pending_push_registration_shares_best_effort()
            .await;
        assert!(!pending);
        let _ = respond.send(pending);
        assert!(
            app.group_push_gossip_state(&account.label, &group_hex)
                .unwrap()
                .and_then(|state| state.last_announced_at_ms)
                .is_some()
        );
        assert!(!client.has_due_push_announce());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receive_tail_schedules_pending_push_gossip_without_awaiting_publish() {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client(&account.label).await.unwrap();
        client
            .create_group("push retry", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        app.set_native_push_enabled(&account.label, true).unwrap();
        app.upsert_push_registration(
            &account.label,
            crate::PushPlatform::Fcm,
            "synthetic-token",
            &nostr::prelude::Keys::generate().public_key().to_hex(),
            None,
        )
        .unwrap();
        assert!(client.has_pending_push_registration_work());
        let shared = RuntimeSharedServices::default();
        let (events, _) = broadcast::channel(8);
        let (commands, mut received) = mpsc::channel(2);
        let mut scheduled = ScheduledPushRegistrationRetry::new();
        relay.block_next_publish();
        let responsive = {
            let mut tail = std::pin::pin!(finish_receive_after_recovery(
                &mut client,
                ReceiveTailContext {
                    events: &events,
                    account_id_hex: &account.account_id_hex,
                    account_label: &account.label,
                    shared: &shared,
                    scheduled_push_retry: &mut scheduled,
                    command_tx: &commands,
                },
                false,
                true,
            ));
            let responsive = timeout(Duration::from_secs(1), tail.as_mut()).await.is_ok();
            if !responsive {
                // A regression must release the held engine step before dropping it.
                relay.release_publish();
                tail.as_mut().await;
            }
            responsive
        };
        assert!(
            responsive,
            "automatic receive gossip cannot occupy the account owner"
        );
        assert!(scheduled.is_armed());
        assert!(client.has_pending_push_registration_work());
        let AccountWorkerCommand::RetryPushRegistration { respond } =
            received.recv().await.unwrap()
        else {
            panic!("durable pending work must enqueue its bounded retry")
        };
        let retry = tokio::spawn(async move {
            let pending = client
                .retry_pending_push_registration_shares_best_effort()
                .await;
            let _ = respond.send(pending);
            pending
        });
        timeout(Duration::from_secs(2), relay.wait_for_blocked_publish())
            .await
            .expect("network publication starts only on the scheduled retry");
        relay.release_publish();
        assert!(
            !timeout(Duration::from_secs(2), retry)
                .await
                .unwrap()
                .unwrap()
        );
        assert!(
            !app.has_pending_push_registration_work(&account.label)
                .unwrap()
        );
        scheduled.disarm();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    /// A frozen batch that failed reports its retry delay as a collecting wait
    /// (mdk#2684). Other groups take the worker's turns meanwhile, and a parked
    /// batch leaves no deadline at all.
    #[tokio::test(start_paused = true)]
    async fn a_failed_convergence_pass_waits_out_its_retry_behind_other_groups() {
        let failing = test_group_id(43);
        let other = test_group_id(44);
        let retry_after = Duration::from_secs(16);
        let mut scheduled = ScheduledConvergence::new(Duration::ZERO);

        // The failed attempt arms the worker's error backoff; the wake it
        // gives finds the batch still waiting and re-arms at its retry time.
        scheduled.schedule_retry_groups([failing.clone()]);
        tokio::time::advance(retry_delay_for_attempt(1)).await;
        assert_eq!(scheduled.take_ready(), Some(failing.clone()));
        scheduled.schedule_after_pass(
            &failing,
            ConvergenceScheduleState::Collecting {
                remaining_ms: retry_after.as_millis() as u64,
            },
        );
        for _ in 0..3 {
            scheduled.schedule_after_pass(&other, ConvergenceScheduleState::Ready);
            tokio::time::advance(MIN_CONVERGENCE_SETTLEMENT_DELAY).await;
            assert!(scheduled.has_ready());
            assert_eq!(scheduled.take_ready(), Some(other.clone()));
        }
        assert!(!scheduled.has_ready());
        assert!(!scheduled.retry_attempts.contains_key(&failing));

        tokio::time::advance(
            retry_after + Duration::from_millis(CONVERGENCE_SETTLEMENT_SCHEDULE_MARGIN_MS),
        )
        .await;
        assert_eq!(scheduled.take_ready(), Some(failing.clone()));
        // Out of budget: the parked batch reports no work and keeps no timer.
        scheduled.schedule_after_pass(&failing, ConvergenceScheduleState::Idle);
        assert!(scheduled.deadlines.is_empty());
        assert_eq!(scheduled.take_ready(), None);
    }

    /// A runnable retained replay wakes once; failures use bounded error
    /// backoff rather than repeatedly rearming the short Ready deadline.
    #[tokio::test(start_paused = true)]
    async fn ready_replay_timer_backs_off_and_disarms_after_success() {
        let group = test_group_id(42);
        let mut scheduled = ScheduledConvergence::new(Duration::ZERO);
        scheduled.schedule_after_pass(&group, ConvergenceScheduleState::Ready);
        for delay in [
            MIN_CONVERGENCE_SETTLEMENT_DELAY,
            Duration::from_secs(1),
            Duration::from_secs(2),
        ] {
            assert_eq!(scheduled.timer.deadline() - TokioInstant::now(), delay);
            tokio::time::advance(delay - Duration::from_millis(1)).await;
            assert!(!scheduled.timer.is_elapsed());
            tokio::time::advance(Duration::from_millis(1)).await;
            scheduled.timer.as_mut().await;
            assert_eq!(scheduled.take_ready(), Some(group.clone()));
            scheduled.schedule_retry_groups([group.clone()]);
        }
        scheduled.schedule_after_pass(&group, ConvergenceScheduleState::Idle);
        assert!(scheduled.deadlines.is_empty());
        assert!(scheduled.retry_attempts.is_empty());
        assert_eq!(scheduled.take_ready(), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn schedule_unsettled_groups_rearms_settlement_delay() {
        let group_id = test_group_id(9);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));

        scheduled.schedule_unsettled_groups([group_id.clone()]);
        let ready = scheduled.take_ready();
        assert_eq!(ready, Some(group_id.clone()));
        assert!(!scheduled.retry_attempts.contains_key(&group_id));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn schedule_after_pass_rearms_when_inputs_remain_pending() {
        let group_id = test_group_id(10);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));

        scheduled.schedule_after_pass(&group_id, ConvergenceScheduleState::PendingUnopenable);

        let ready = scheduled.take_ready();
        assert_eq!(ready, Some(group_id.clone()));
        assert!(!scheduled.retry_attempts.contains_key(&group_id));
        assert_eq!(scheduled.unsettled_rearm_attempts.get(&group_id), Some(&1));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rescheduling_same_group_never_postpones_its_frozen_cutoff() {
        let group_id = test_group_id(23);
        let mut scheduled = ScheduledConvergence::new(Duration::from_millis(1_100));
        scheduled.schedule_groups_with_delays([(group_id.clone(), Duration::from_millis(50))]);
        let frozen_cutoff = scheduled.deadlines[&group_id];

        scheduled.schedule_unsettled_groups([group_id.clone()]);
        scheduled.schedule_retry_groups([group_id.clone()]);

        assert_eq!(scheduled.deadlines[&group_id], frozen_cutoff);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
