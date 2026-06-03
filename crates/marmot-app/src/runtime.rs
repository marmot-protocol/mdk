use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_EXPORTER_LABEL, AgentTextStreamKeyContextV1,
};
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MarmotAppEvent as MarmotInnerEvent,
    STREAM_BROKER_TAG, STREAM_ROUTE_TAG, STREAM_TAG,
};
use cgka_traits::engine::GroupEvent;
use cgka_traits::{GroupId, MemberId, MessageId, SecretBytes, TransportEndpoint};
use marmot_account::{AccountHomeError, AccountSummary};
use marmot_forensics::{ForensicsBundle, ForensicsExportOptions};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};
use transport_quic_broker::{
    BrokerServerTrust, SubscribeTextFromBroker, subscribe_text_from_broker_with_updates,
};
use transport_quic_stream::AgentTextStreamCrypto;

use crate::agent_streams::AgentStreamWatchManager;
use crate::directory::{DirectorySyncHandle, DirectorySyncRunSummary};
use crate::ids::normalize_group_id_hex_app;
use crate::messages::{AppMessageIntent, STREAM_ROUTE_QUIC, tag_value, tag_values};
use crate::notifications;
use crate::{
    ACCOUNT_WORKER_RECONNECT_BASE_DELAY, ACCOUNT_WORKER_RECONNECT_JITTER_MAX_MS,
    ACCOUNT_WORKER_RECONNECT_MAX_DELAY, AGENT_STREAM_START_LOOKBACK_LIMIT,
    APP_RUNTIME_ACCOUNT_READY_WAIT, APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT,
    APP_RUNTIME_RELAY_REBUILD_LOOKBACK, APP_RUNTIME_SUBSCRIPTION_BUFFER, AccountKeyPackageRecord,
    AccountRelayListBootstrap, AccountRelayListStatus, AgentTextStreamFinishRequest, AppError,
    AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord, AppMessageQuery, AppMessageRecord,
    AppProjectionUpdate, BackgroundNotificationCollection, ChatListRow, GroupInviteDeclineResult,
    GroupPushDebugInfo, MarmotApp, MarmotRelayPlane, MediaDownloadResult, MediaReference,
    MediaUploadRequest, MediaUploadResult, NotificationCollectionStatus, NotificationSettings,
    NotificationUpdate, NotificationWakeSource, PushPlatform, PushRegistration, ReceivedMessage,
    SendSummary, SyncSummary, TimelineMessageChange, TimelineMessageQuery, TimelinePage,
    TimelineUpdateTrigger, UserDirectoryRefresh, UserProfileMetadata, default_profile_pseudonym,
    unix_now_seconds,
};

#[derive(Clone)]
pub struct MarmotAppRuntime {
    events: broadcast::Sender<MarmotAppEvent>,
    shared: RuntimeSharedServices,
    accounts: AccountManager,
    directory_sync: Arc<Mutex<Option<DirectorySyncHandle>>>,
}

#[derive(Clone)]
pub struct AccountManager {
    app: MarmotApp,
    events: broadcast::Sender<MarmotAppEvent>,
    shared: RuntimeSharedServices,
    workers: Arc<Mutex<HashMap<String, ManagedAccountWorker>>>,
}

#[derive(Clone)]
pub struct RuntimeSharedServices {
    relay_plane: MarmotRelayPlane,
    agent_streams: AgentStreamWatchManager,
    lifecycle: RuntimeLifecycle,
}

impl Default for RuntimeSharedServices {
    fn default() -> Self {
        Self {
            relay_plane: MarmotRelayPlane::runtime_default(APP_RUNTIME_RELAY_REBUILD_LOOKBACK),
            agent_streams: AgentStreamWatchManager::default(),
            lifecycle: RuntimeLifecycle::new(),
        }
    }
}

impl RuntimeSharedServices {
    fn for_app(app: &MarmotApp) -> Self {
        Self {
            relay_plane: app.relay_plane.clone(),
            agent_streams: AgentStreamWatchManager::default(),
            lifecycle: RuntimeLifecycle::new(),
        }
    }

    pub fn relay_plane(&self) -> &MarmotRelayPlane {
        &self.relay_plane
    }

    pub fn agent_streams(&self) -> AgentStreamWatchManager {
        self.agent_streams.clone()
    }

    pub(crate) fn lifecycle(&self) -> RuntimeLifecycle {
        self.lifecycle.clone()
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeLifecycle {
    inner: Arc<RuntimeLifecycleInner>,
}

struct RuntimeLifecycleInner {
    stopping: AtomicBool,
    stop_tx: watch::Sender<bool>,
    active_account_opens: AtomicUsize,
    account_opens_drained: Notify,
}

pub(crate) struct RuntimeAccountOpenPermit {
    lifecycle: RuntimeLifecycle,
    started_at: Instant,
}

impl RuntimeLifecycle {
    fn new() -> Self {
        let (stop_tx, _) = watch::channel(false);
        Self {
            inner: Arc::new(RuntimeLifecycleInner {
                stopping: AtomicBool::new(false),
                stop_tx,
                active_account_opens: AtomicUsize::new(0),
                account_opens_drained: Notify::new(),
            }),
        }
    }

    pub(crate) fn begin_shutdown(&self) -> bool {
        let was_stopping = self.inner.stopping.swap(true, Ordering::AcqRel);
        if !was_stopping {
            self.inner.stop_tx.send_replace(true);
        }
        !was_stopping
    }

    pub(crate) fn is_stopping(&self) -> bool {
        self.inner.stopping.load(Ordering::Acquire)
    }

    pub(crate) fn ensure_running(&self) -> Result<(), AppError> {
        if self.is_stopping() {
            Err(AppError::RuntimeStopping)
        } else {
            Ok(())
        }
    }

    pub(crate) fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.inner.stop_tx.subscribe()
    }

    pub(crate) fn begin_account_open(&self) -> Result<RuntimeAccountOpenPermit, AppError> {
        self.ensure_running()?;
        self.inner
            .active_account_opens
            .fetch_add(1, Ordering::AcqRel);
        if self.is_stopping() {
            self.finish_account_open(Instant::now());
            return Err(AppError::RuntimeStopping);
        }
        Ok(RuntimeAccountOpenPermit {
            lifecycle: self.clone(),
            started_at: Instant::now(),
        })
    }

    pub(crate) async fn wait_for_account_opens_to_drain(&self, wait: Duration) -> bool {
        if self.active_account_opens() == 0 {
            return true;
        }
        if wait.is_zero() {
            tracing::warn!(
                target: "marmot_app::runtime",
                method = "shutdown",
                active_account_opens = self.active_account_opens(),
                "runtime account opens still running when shutdown budget expired",
            );
            return false;
        }

        let started_at = Instant::now();
        let drained = timeout(wait, async {
            while self.active_account_opens() != 0 {
                self.inner.account_opens_drained.notified().await;
            }
        })
        .await
        .is_ok();
        let elapsed_ms = started_at.elapsed().as_millis() as u64;
        if drained {
            tracing::debug!(
                target: "marmot_app::runtime",
                method = "shutdown",
                elapsed_ms,
                "runtime account opens drained during shutdown",
            );
        } else {
            tracing::warn!(
                target: "marmot_app::runtime",
                method = "shutdown",
                elapsed_ms,
                active_account_opens = self.active_account_opens(),
                "runtime account opens did not drain before shutdown budget expired",
            );
        }
        drained
    }

    fn active_account_opens(&self) -> usize {
        self.inner.active_account_opens.load(Ordering::Acquire)
    }

    fn finish_account_open(&self, started_at: Instant) {
        let previous = self
            .inner
            .active_account_opens
            .fetch_sub(1, Ordering::AcqRel);
        let remaining = previous.saturating_sub(1);
        if remaining == 0 {
            self.inner.account_opens_drained.notify_waiters();
        }
        tracing::debug!(
            target: "marmot_app::runtime",
            method = "runtime_account_open",
            elapsed_ms = started_at.elapsed().as_millis() as u64,
            active_account_opens = remaining,
            "runtime account open finished",
        );
    }
}

impl Drop for RuntimeAccountOpenPermit {
    fn drop(&mut self) {
        self.lifecycle.finish_account_open(self.started_at);
    }
}

async fn wait_for_runtime_shutdown(stopping: &mut watch::Receiver<bool>) {
    if *stopping.borrow() {
        return;
    }
    while stopping.changed().await.is_ok() {
        if *stopping.borrow() {
            return;
        }
    }
}

fn runtime_shutdown_requested(stopping: &watch::Receiver<bool>) -> bool {
    *stopping.borrow()
}

struct ManagedAccountWorker {
    handle: JoinHandle<()>,
    commands: mpsc::Sender<AccountWorkerCommand>,
    shutdown: oneshot::Sender<()>,
}

impl ManagedAccountWorker {
    fn stop(self) {
        let _ = self.shutdown.send(());
        self.handle.abort();
    }

    async fn shutdown(self) {
        self.shutdown_with_timeout(APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT)
            .await;
    }

    async fn shutdown_with_timeout(self, wait: Duration) {
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

struct AccountWorkerRuntime {
    app: MarmotApp,
    account_label: String,
    account_id_hex: String,
    relay_plane: MarmotRelayPlane,
    events: broadcast::Sender<MarmotAppEvent>,
    lifecycle: RuntimeLifecycle,
}

enum AccountWorkerCommand {
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
    GroupForensicsBundle {
        group_id: GroupId,
        options: ForensicsExportOptions,
        respond: oneshot::Sender<Result<ForensicsBundle, AppError>>,
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
    UpdateMessageRetention {
        group_id: GroupId,
        disappearing_message_secs: u64,
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
        reference: MediaReference,
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
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedAccount {
    pub label: String,
    pub account_id_hex: String,
    pub local_signing: bool,
    pub running: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountSetupRequest {
    pub identity: Option<String>,
    pub default_relays: Vec<TransportEndpoint>,
    pub bootstrap_relays: Vec<TransportEndpoint>,
    pub publish_missing_relay_lists: bool,
    pub publish_initial_key_package: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountSetupResult {
    pub account: AccountSummary,
    pub relay_lists: AccountRelayListStatus,
    pub key_package_bytes: Option<usize>,
    pub profile: Option<UserProfileMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeMessageReceived {
    pub account_id_hex: String,
    pub account_label: String,
    pub message: ReceivedMessage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeGroupEvent {
    pub account_id_hex: String,
    pub account_label: String,
    pub event: GroupEvent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeProjectionUpdate {
    pub account_id_hex: String,
    pub account_label: String,
    pub update: AppProjectionUpdate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAccountError {
    pub account_id_hex: String,
    pub account_label: String,
    pub message: String,
}

/// A kind-1200 agent-text-stream **start** observed in a group. The inner
/// event's stream metadata lives on `message.tags`; clients use it to open the
/// ephemeral QUIC preview. Raw message subscribers receive this as
/// [`RuntimeMessageUpdate::AgentStreamStarted`]; materialized timeline
/// subscribers see the same kind-1200 as a timeline row. The eventual kind-9
/// stream-final flows as a normal [`RuntimeMessageUpdate::Message`] carrying
/// `stream`/`stream-start` tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAgentStreamMessage {
    pub account_id_hex: String,
    pub account_label: String,
    pub message: ReceivedMessage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeMessageUpdate {
    Message(RuntimeMessageReceived),
    AgentStreamStarted(RuntimeAgentStreamMessage),
}

impl RuntimeMessageUpdate {
    pub fn account_id_hex(&self) -> &str {
        match self {
            Self::Message(update) => &update.account_id_hex,
            Self::AgentStreamStarted(update) => &update.account_id_hex,
        }
    }

    pub fn message(&self) -> &ReceivedMessage {
        match self {
            Self::Message(update) => &update.message,
            Self::AgentStreamStarted(update) => &update.message,
        }
    }
}

pub struct RuntimeMessagesSubscription {
    pub snapshot: Vec<AppMessageRecord>,
    updates: mpsc::Receiver<RuntimeMessageUpdate>,
    stopping: watch::Receiver<bool>,
}

impl RuntimeMessagesSubscription {
    pub async fn recv(&mut self) -> Option<RuntimeMessageUpdate> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

// `Page` carries a fully hydrated `TimelinePage`, so the variant sizes
// differ — boxing either side would change the channel's public type
// and propagate through every consumer.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeTimelineMessageUpdate {
    Page { page: TimelinePage },
    Projection(RuntimeProjectionUpdate),
}

pub struct RuntimeTimelineMessagesSubscription {
    pub snapshot: TimelinePage,
    updates: mpsc::Receiver<RuntimeTimelineMessageUpdate>,
    stopping: watch::Receiver<bool>,
}

impl RuntimeTimelineMessagesSubscription {
    pub async fn recv(&mut self) -> Option<RuntimeTimelineMessageUpdate> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

pub struct RuntimeChatsSubscription {
    pub snapshot: Vec<AppGroupRecord>,
    updates: mpsc::Receiver<AppGroupRecord>,
    stopping: watch::Receiver<bool>,
}

impl RuntimeChatsSubscription {
    pub async fn recv(&mut self) -> Option<AppGroupRecord> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

pub struct RuntimeChatListSubscription {
    pub snapshot: Vec<ChatListRow>,
    updates: mpsc::Receiver<RuntimeChatListUpdate>,
    stopping: watch::Receiver<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeChatListUpdate {
    Row {
        trigger: ChatListUpdateTrigger,
        row: Box<ChatListRow>,
    },
    RemoveRow {
        trigger: ChatListUpdateTrigger,
        group_id_hex: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatListUpdateTrigger {
    NewGroup,
    NewLastMessage,
    LastMessageDeleted,
    ArchiveChanged,
    PendingConfirmationChanged,
    MembershipChanged,
    UnreadChanged,
    SnapshotRefresh,
    Removed,
}

impl Default for ChatListUpdateTrigger {
    fn default() -> Self {
        Self::SnapshotRefresh
    }
}

impl ChatListUpdateTrigger {
    pub(crate) fn from_timeline_changes(changes: &[TimelineMessageChange]) -> Self {
        if changes.iter().any(|change| {
            matches!(
                change,
                TimelineMessageChange::Upsert {
                    trigger: TimelineUpdateTrigger::MessageDeleted,
                    ..
                }
            )
        }) {
            return Self::LastMessageDeleted;
        }
        if changes.iter().any(|change| {
            matches!(
                change,
                TimelineMessageChange::Upsert {
                    trigger: TimelineUpdateTrigger::NewMessage
                        | TimelineUpdateTrigger::AgentStreamStarted
                        | TimelineUpdateTrigger::AgentStreamFinished,
                    ..
                }
            )
        }) {
            return Self::NewLastMessage;
        }
        Self::SnapshotRefresh
    }
}

impl RuntimeChatListSubscription {
    pub async fn recv(&mut self) -> Option<RuntimeChatListUpdate> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

pub struct RuntimeGroupStateSubscription {
    pub snapshot: AppGroupRecord,
    updates: mpsc::Receiver<AppGroupRecord>,
    stopping: watch::Receiver<bool>,
}

impl RuntimeGroupStateSubscription {
    pub async fn recv(&mut self) -> Option<AppGroupRecord> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

pub struct RuntimeNotificationsSubscription {
    updates: mpsc::Receiver<NotificationUpdate>,
    stopping: watch::Receiver<bool>,
}

impl RuntimeNotificationsSubscription {
    pub async fn recv(&mut self) -> Option<NotificationUpdate> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

pub struct RuntimeEventsSubscription {
    events: broadcast::Receiver<MarmotAppEvent>,
    stopping: watch::Receiver<bool>,
}

impl RuntimeEventsSubscription {
    pub async fn recv(&mut self) -> Option<MarmotAppEvent> {
        loop {
            tokio::select! {
                event = self.events.recv() => {
                    match event {
                        Ok(event) => return Some(event),
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                }
                _ = wait_for_runtime_shutdown(&mut self.stopping) => return None,
            }
        }
    }
}

/// One update from watching a live agent text stream over QUIC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeAgentStreamUpdate {
    /// An incremental text delta. `text` is the new fragment, not the full text.
    Chunk { seq: u64, text: String },
    /// The stream closed cleanly; `text` is the complete transcript.
    Finished {
        text: String,
        transcript_hash_hex: String,
        chunk_count: u64,
    },
    /// The watch failed (connection/broker error).
    Failed { message: String },
}

#[derive(Clone, Debug, Default)]
pub struct AgentStreamWatchOptions {
    /// Watch a specific stream id; `None` watches the latest stream in the group.
    pub stream_id_hex: Option<String>,
    /// DER cert for a self-signed broker; `None` uses platform trust.
    pub server_cert_der: Option<Vec<u8>>,
    /// Loopback-only insecure trust, for local testing.
    pub insecure_local: bool,
}

/// A live agent-text-stream watch. Drains chunk/finished/failed updates from a
/// background QUIC subscription task.
pub struct RuntimeAgentStreamWatch {
    pub stream_id_hex: String,
    updates: mpsc::Receiver<RuntimeAgentStreamUpdate>,
    abort: tokio::task::AbortHandle,
    stopping: watch::Receiver<bool>,
}

impl RuntimeAgentStreamWatch {
    pub async fn recv(&mut self) -> Option<RuntimeAgentStreamUpdate> {
        tokio::select! {
            update = self.updates.recv() => update,
            _ = wait_for_runtime_shutdown(&mut self.stopping) => None,
        }
    }
}

impl Drop for RuntimeAgentStreamWatch {
    fn drop(&mut self) {
        // Cancel the background QUIC subscriber so dropping the watch handle
        // doesn't leak a task driving a (possibly hung) broker connection.
        self.abort.abort();
    }
}

// Boxing the heavier variants would ripple through every public consumer of
// this fan-out event type; the small overhead in the lighter variants is the
// intentional trade-off.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarmotAppEvent {
    GroupJoined {
        account_id_hex: String,
        account_label: String,
        group_id: GroupId,
    },
    GroupStateUpdated {
        account_id_hex: String,
        account_label: String,
        group_id: GroupId,
    },
    MessageReceived(RuntimeMessageReceived),
    AgentStreamStarted(RuntimeAgentStreamMessage),
    ProjectionUpdated(RuntimeProjectionUpdate),
    GroupEvent(RuntimeGroupEvent),
    AccountError(RuntimeAccountError),
}

impl MarmotAppRuntime {
    pub fn new(app: MarmotApp) -> Self {
        let (events, _) = broadcast::channel(1024);
        let shared = RuntimeSharedServices::for_app(&app);
        let accounts = AccountManager::new(app, events.clone(), shared.clone());
        Self {
            events,
            shared,
            accounts,
            directory_sync: Arc::new(Mutex::new(None)),
        }
    }

    pub fn open(app: MarmotApp) -> Self {
        Self::new(app)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MarmotAppEvent> {
        self.events.subscribe()
    }

    pub fn subscribe_events(&self) -> RuntimeEventsSubscription {
        RuntimeEventsSubscription {
            events: self.events.subscribe(),
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        }
    }

    pub fn display_name_for_account_id(&self, account_id_hex: &str) -> Option<String> {
        self.accounts
            .app
            .display_name_for_account_id(account_id_hex)
            .ok()
            .flatten()
    }

    pub fn subscribe_messages(
        &self,
        account_ref: &str,
        query: AppMessageQuery,
    ) -> Result<RuntimeMessagesSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let group_id_hex = query.group_id_hex.clone();
        let mut events = self.events.subscribe();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = self.messages_with_query(&account.account_id_hex, query)?;
        let mut seen_message_ids = snapshot
            .iter()
            .filter_map(|message| {
                if message.message_id_hex.is_empty() {
                    None
                } else {
                    Some(message.message_id_hex.clone())
                }
            })
            .collect::<HashSet<_>>();
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => match event {
                        Ok(event) => event,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                };
                let Some(update) = runtime_message_update_from_event(event) else {
                    continue;
                };
                if update.account_id_hex() != account_id_hex {
                    continue;
                }
                let message = update.message();
                if group_id_hex.as_deref()
                    != Some(hex::encode(message.group_id.as_slice()).as_str())
                    && group_id_hex.is_some()
                {
                    continue;
                }
                if !message.message_id_hex.is_empty()
                    && !seen_message_ids.insert(message.message_id_hex.clone())
                {
                    continue;
                }
                if updates_tx.send(update).await.is_err() {
                    return;
                }
            }
        });
        Ok(RuntimeMessagesSubscription {
            snapshot,
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub fn subscribe_timeline_messages(
        &self,
        account_ref: &str,
        query: TimelineMessageQuery,
    ) -> Result<RuntimeTimelineMessagesSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let account_label = account.label.clone();
        let group_id_hex = query.group_id_hex.clone();
        let app = self.accounts.app.clone();
        let mut events = self.events.subscribe();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = {
            let _span = tracing::debug_span!(
                target: "marmot_app::runtime",
                "timeline_subscription_snapshot",
                method = "subscribe_timeline_messages"
            )
            .entered();
            app.timeline_messages_with_query(&account_label, query.clone())?
        };
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => event,
                };
                let event = match event {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let app_for_lookup = app.clone();
                        let account_label_for_lookup = account_label.clone();
                        let query_for_lookup = query.clone();
                        let page = match blocking_app_task(move || {
                            app_for_lookup.timeline_messages_with_query(
                                &account_label_for_lookup,
                                query_for_lookup,
                            )
                        })
                        .await
                        {
                            Ok(page) => page,
                            Err(_) => continue,
                        };
                        if updates_tx
                            .send(RuntimeTimelineMessageUpdate::Page { page })
                            .await
                            .is_err()
                        {
                            return;
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                if let Some(update) = projection_update_from_event(&event)
                    && projection_update_matches_query(
                        update,
                        &account_id_hex,
                        group_id_hex.as_deref(),
                    )
                {
                    if timeline_query_can_apply_projection_delta(&query) {
                        if updates_tx
                            .send(RuntimeTimelineMessageUpdate::Projection(update.clone()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    } else {
                        let app_for_lookup = app.clone();
                        let account_label_for_lookup = account_label.clone();
                        let query_for_lookup = query.clone();
                        let page = match blocking_app_task(move || {
                            app_for_lookup.timeline_messages_with_query(
                                &account_label_for_lookup,
                                query_for_lookup,
                            )
                        })
                        .await
                        {
                            Ok(page) => page,
                            Err(_) => continue,
                        };
                        if updates_tx
                            .send(RuntimeTimelineMessageUpdate::Page { page })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    continue;
                }
            }
        });
        Ok(RuntimeTimelineMessagesSubscription {
            snapshot,
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub fn subscribe_chats(
        &self,
        account_ref: &str,
        include_archived: bool,
    ) -> Result<RuntimeChatsSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let account_label = account.label.clone();
        let app = self.accounts.app.clone();
        let mut events = self.events.subscribe();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = if include_archived {
            app.groups(&account_label)?
        } else {
            app.visible_groups(&account_label)?
        };
        let mut group_fingerprints = snapshot
            .iter()
            .map(|group| {
                (
                    group.group_id_hex.clone(),
                    app_group_record_fingerprint(group),
                )
            })
            .collect::<HashMap<_, _>>();
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => match event {
                        Ok(event) => event,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                };
                let Some((event_account_id_hex, group_id)) = runtime_group_event_route(&event)
                else {
                    continue;
                };
                if event_account_id_hex != account_id_hex {
                    continue;
                }
                let group_id_hex = hex::encode(group_id.as_slice());
                let app_for_lookup = app.clone();
                let account_label_for_lookup = account_label.clone();
                let group_id_hex_for_lookup = group_id_hex.clone();
                if runtime_shutdown_requested(&stopping) {
                    return;
                }
                let group = match blocking_app_task(move || {
                    app_for_lookup.group(&account_label_for_lookup, &group_id_hex_for_lookup)
                })
                .await
                {
                    Ok(Some(group)) => group,
                    Ok(None) | Err(_) => {
                        group_fingerprints.remove(&group_id_hex);
                        continue;
                    }
                };
                if !include_archived && group.archived {
                    group_fingerprints.remove(&group_id_hex);
                    if updates_tx.send(group).await.is_err() {
                        return;
                    }
                    continue;
                }
                let fingerprint = app_group_record_fingerprint(&group);
                if group_fingerprints.get(&group.group_id_hex) == Some(&fingerprint) {
                    continue;
                }
                group_fingerprints.insert(group.group_id_hex.clone(), fingerprint);
                if updates_tx.send(group).await.is_err() {
                    return;
                }
            }
        });
        Ok(RuntimeChatsSubscription {
            snapshot,
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub fn subscribe_chat_list(
        &self,
        account_ref: &str,
        include_archived: bool,
    ) -> Result<RuntimeChatListSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let account_label = account.label.clone();
        let app = self.accounts.app.clone();
        let mut events = self.events.subscribe();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = {
            let _span = tracing::debug_span!(
                target: "marmot_app::runtime",
                "chat_list_subscription_snapshot",
                method = "subscribe_chat_list"
            )
            .entered();
            app.chat_list(&account_label, include_archived)?
        };
        let mut row_fingerprints = snapshot
            .iter()
            .map(|row| (row.group_id_hex.clone(), chat_list_row_fingerprint(row)))
            .collect::<HashMap<_, _>>();
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => event,
                };
                let event = match event {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let app_for_lookup = app.clone();
                        let account_label_for_lookup = account_label.clone();
                        let rows = match blocking_app_task(move || {
                            app_for_lookup.chat_list(&account_label_for_lookup, include_archived)
                        })
                        .await
                        {
                            Ok(rows) => rows,
                            Err(_) => continue,
                        };
                        if !reconcile_chat_list_snapshot(
                            &updates_tx,
                            &mut row_fingerprints,
                            ChatListUpdateTrigger::SnapshotRefresh,
                            rows,
                        )
                        .await
                        {
                            return;
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                if let Some(update) = projection_update_from_event(&event)
                    && update.account_id_hex == account_id_hex
                {
                    let Some(row) = update.update.chat_list_row.clone() else {
                        if !send_chat_list_remove_update(
                            &updates_tx,
                            &mut row_fingerprints,
                            update.update.chat_list_trigger,
                            &update.update.group_id_hex,
                        )
                        .await
                        {
                            return;
                        }
                        continue;
                    };
                    if !include_archived && row.archived {
                        if !send_chat_list_remove_update(
                            &updates_tx,
                            &mut row_fingerprints,
                            update.update.chat_list_trigger,
                            &row.group_id_hex,
                        )
                        .await
                        {
                            return;
                        }
                        continue;
                    }
                    if !send_chat_list_row_update(
                        &updates_tx,
                        &mut row_fingerprints,
                        update.update.chat_list_trigger,
                        row,
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                }
                let Some((event_account_id_hex, group_id)) = chat_list_event_route(&event) else {
                    continue;
                };
                if event_account_id_hex != account_id_hex {
                    continue;
                }
                let group_id_hex = hex::encode(group_id.as_slice());
                let app_for_lookup = app.clone();
                let account_label_for_lookup = account_label.clone();
                let group_id_hex_for_lookup = group_id_hex.clone();
                if runtime_shutdown_requested(&stopping) {
                    return;
                }
                let row = match blocking_app_task(move || {
                    app_for_lookup
                        .refresh_chat_list_row(&account_label_for_lookup, &group_id_hex_for_lookup)
                })
                .await
                {
                    Ok(row) => row,
                    Err(_) => continue,
                };
                let Some(row) = row else {
                    if !send_chat_list_remove_update(
                        &updates_tx,
                        &mut row_fingerprints,
                        ChatListUpdateTrigger::SnapshotRefresh,
                        &group_id_hex,
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                };
                if !include_archived && row.archived {
                    if !send_chat_list_remove_update(
                        &updates_tx,
                        &mut row_fingerprints,
                        ChatListUpdateTrigger::Removed,
                        &row.group_id_hex,
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                }
                if !send_chat_list_row_update(
                    &updates_tx,
                    &mut row_fingerprints,
                    chat_list_trigger_from_event(&event),
                    row,
                )
                .await
                {
                    return;
                }
            }
        });
        Ok(RuntimeChatListSubscription {
            snapshot,
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub fn subscribe_group_state(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<RuntimeGroupStateSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let account_id_hex = account.account_id_hex.clone();
        let account_label = account.label.clone();
        let app = self.accounts.app.clone();
        let group_id_hex = normalize_group_id_hex_app(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let mut events = self.events.subscribe();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = app
            .group(&account_label, &group_id_hex)?
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
        let mut last_fingerprint = app_group_record_fingerprint(&snapshot);
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => match event {
                        Ok(event) => event,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                };
                let Some((event_account_id_hex, event_group_id)) =
                    runtime_group_event_route(&event)
                else {
                    continue;
                };
                if event_account_id_hex != account_id_hex || event_group_id != &group_id {
                    continue;
                }
                let app_for_lookup = app.clone();
                let account_label_for_lookup = account_label.clone();
                let group_id_hex_for_lookup = group_id_hex.clone();
                if runtime_shutdown_requested(&stopping) {
                    return;
                }
                let group = match blocking_app_task(move || {
                    app_for_lookup.group(&account_label_for_lookup, &group_id_hex_for_lookup)
                })
                .await
                {
                    Ok(Some(group)) => group,
                    Ok(None) | Err(_) => continue,
                };
                let fingerprint = app_group_record_fingerprint(&group);
                if fingerprint == last_fingerprint {
                    continue;
                }
                last_fingerprint = fingerprint;
                if updates_tx.send(group).await.is_err() {
                    return;
                }
            }
        });
        Ok(RuntimeGroupStateSubscription {
            snapshot,
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub fn subscribe_notifications(&self) -> Result<RuntimeNotificationsSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let mut events = self.events.subscribe();
        let app = self.accounts.app.clone();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let (updates_tx, updates_rx) = mpsc::channel(APP_RUNTIME_SUBSCRIPTION_BUFFER);
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    event = events.recv() => event,
                };
                match event {
                    Ok(event) => {
                        match notifications::notification_update_from_event(&app, &event) {
                            Ok(Some(update)) => {
                                if updates_tx.send(update).await.is_err() {
                                    return;
                                }
                            }
                            Ok(None) | Err(AppError::NotificationsDisabled) => {}
                            Err(_) => {
                                tracing::warn!(
                                    target: "marmot_app::notifications",
                                    method = "subscribe_notifications",
                                    error_code = "notification_projection_skipped",
                                    "notification projection skipped",
                                );
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        Ok(RuntimeNotificationsSubscription {
            updates: updates_rx,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    /// Watch a live agent text stream over the brokered QUIC channel. Resolves
    /// the latest `Start` payload for the group (or a specific `stream_id`),
    /// connects to the broker named in its `quic://` candidate, and streams
    /// incremental text chunks until the stream finishes. Must be called from
    /// within a tokio runtime (it spawns the QUIC subscriber task).
    pub async fn watch_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        options: AgentStreamWatchOptions,
    ) -> Result<RuntimeAgentStreamWatch, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let app = self.accounts.app.clone();
        let account_ref_for_query = account_ref.to_owned();
        let messages = blocking_app_task(move || {
            app.messages_with_query(
                &account_ref_for_query,
                AppMessageQuery {
                    group_id_hex: Some(group_id_hex),
                    limit: Some(AGENT_STREAM_START_LOOKBACK_LIMIT),
                },
            )
        })
        .await?;
        let (start_message_id_hex, start, sender_hex) =
            latest_agent_stream_start(messages, options.stream_id_hex.as_deref())?;
        if start_message_id_hex.is_empty() {
            // The latest start hasn't been echoed back with a message id yet, so
            // we can't reference it to the broker; surface that rather than
            // forwarding a zero-length MessageId.
            return Err(AppError::AgentStreamStartNotConfirmed);
        }
        if start.route != STREAM_ROUTE_QUIC {
            return Err(AppError::AgentStreamUnsupportedRoute);
        }
        let candidates = parse_quic_candidates(&start.quic_candidates)?;
        let server_cert_der = options.server_cert_der;
        let insecure_local = options.insecure_local;
        let stream_id = hex::decode(&start.stream_id_hex)?;
        let stream_id_hex = start.stream_id_hex.clone();
        let start_event_id = MessageId::new(hex::decode(&start_message_id_hex)?);
        let account = self.accounts.app.account_home().account(account_ref)?;
        let group_state = self.group_mls_state(&account.label, group_id).await?;
        let stream_secret = self
            .agent_text_stream_exporter_secret(&account.label, group_id)
            .await?;
        let crypto = AgentTextStreamCrypto::new(
            stream_secret,
            AgentTextStreamKeyContextV1::new(
                group_id.clone(),
                stream_id.clone(),
                cgka_traits::EpochId(group_state.epoch),
                MemberId::new(hex::decode(sender_hex)?),
                start_event_id.clone(),
            ),
        );

        let (updates_tx, updates_rx) = mpsc::channel(1024);
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let handle = tokio::spawn(async move {
            let final_update = tokio::select! {
                _ = wait_for_runtime_shutdown(&mut stopping) => return,
                update = watch_broker_candidates(
                    candidates,
                    server_cert_der,
                    insecure_local,
                    stream_id,
                    start_event_id,
                    Some(crypto),
                    updates_tx.clone(),
                ) => update,
            };
            let _ = updates_tx.send(final_update).await;
        });
        Ok(RuntimeAgentStreamWatch {
            stream_id_hex,
            updates: updates_rx,
            abort: handle.abort_handle(),
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }

    pub fn accounts(&self) -> AccountManager {
        self.accounts.clone()
    }

    pub fn shared_services(&self) -> RuntimeSharedServices {
        self.shared.clone()
    }

    pub fn is_stopping(&self) -> bool {
        self.shared.lifecycle().is_stopping()
    }

    pub async fn start(&self) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        self.sync_user_directory_subscriptions().await?;
        self.reconcile_accounts().await
    }

    pub(crate) async fn sync_user_directory_subscriptions(
        &self,
    ) -> Result<DirectorySyncRunSummary, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let directory_sync = self.ensure_directory_sync_worker().await;
        directory_sync.request_rebuild_and_wait().await
    }

    async fn ensure_directory_sync_worker(&self) -> DirectorySyncHandle {
        let mut directory_sync = self.directory_sync.lock().await;
        if let Some(handle) = directory_sync.as_ref() {
            return handle.clone();
        }
        let handle = DirectorySyncHandle::spawn(
            self.accounts.app.clone(),
            self.shared.relay_plane().clone(),
        );
        self.accounts
            .app
            .set_directory_sync_handle(Some(handle.clone()));
        *directory_sync = Some(handle.clone());
        handle
    }

    pub async fn reconcile_accounts(&self) -> Result<(), AppError> {
        self.accounts.reconcile().await
    }

    pub async fn restart_account(&self, account_id_hex: &str) -> Result<(), AppError> {
        self.accounts.restart_account(account_id_hex).await
    }

    pub async fn catch_up_accounts(&self) -> Result<(), AppError> {
        self.accounts.catch_up_accounts().await
    }

    pub async fn collect_notifications_after_wake(
        &self,
        max_wait_ms: u32,
        _source: NotificationWakeSource,
    ) -> BackgroundNotificationCollection {
        let max_wait = Duration::from_millis(u64::from(max_wait_ms.max(1)));
        let started = Instant::now();
        let mut events = self.events.subscribe();
        let catch_up = timeout(max_wait, self.catch_up_accounts()).await;
        let remaining = max_wait.saturating_sub(started.elapsed());
        let mut notifications = Vec::new();

        match catch_up {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                return BackgroundNotificationCollection {
                    status: NotificationCollectionStatus::Failed,
                    notifications,
                    error: Some(err.to_string()),
                };
            }
            Err(_) => {
                return BackgroundNotificationCollection {
                    status: NotificationCollectionStatus::Failed,
                    notifications,
                    error: Some("notification wake collection timed out".into()),
                };
            }
        }

        let app = self.accounts.app.clone();
        let drain_until = Instant::now() + remaining;
        loop {
            match events.try_recv() {
                Ok(event) => {
                    collect_notification_update_from_event(&app, &event, &mut notifications);
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    if Instant::now() >= drain_until {
                        break;
                    }
                    match timeout(
                        drain_until.saturating_duration_since(Instant::now()),
                        events.recv(),
                    )
                    .await
                    {
                        Ok(Ok(event)) => {
                            collect_notification_update_from_event(
                                &app,
                                &event,
                                &mut notifications,
                            );
                        }
                        Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                        Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => break,
                    }
                }
                Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(broadcast::error::TryRecvError::Closed) => break,
            }
        }

        let notifications = notifications::dedupe_notification_updates(notifications);
        BackgroundNotificationCollection {
            status: if notifications.is_empty() {
                NotificationCollectionStatus::NoData
            } else {
                NotificationCollectionStatus::NewData
            },
            notifications,
            error: None,
        }
    }

    pub async fn create_group(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
    ) -> Result<GroupId, AppError> {
        self.accounts
            .create_group(account_ref, name, members, description)
            .await
    }

    pub async fn group_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        self.accounts.group_members(account_ref, group_id).await
    }

    pub async fn group_mls_state(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupMlsState, AppError> {
        self.accounts.group_mls_state(account_ref, group_id).await
    }

    pub async fn group_forensics_bundle(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        options: ForensicsExportOptions,
    ) -> Result<ForensicsBundle, AppError> {
        self.accounts
            .group_forensics_bundle(account_ref, group_id, options)
            .await
    }

    pub async fn safe_export_secret(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        component_id: cgka_traits::AppComponentId,
    ) -> Result<SecretBytes, AppError> {
        self.accounts
            .safe_export_secret(account_ref, group_id, component_id)
            .await
    }

    pub async fn agent_text_stream_exporter_secret(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SecretBytes, AppError> {
        self.accounts
            .exporter_secret(account_ref, group_id, AGENT_TEXT_STREAM_EXPORTER_LABEL, 32)
            .await
    }

    pub async fn invite_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        members: &[String],
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .invite_members(account_ref, group_id, members)
            .await
    }

    pub async fn remove_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        members: &[String],
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .remove_members(account_ref, group_id, members)
            .await
    }

    pub async fn leave_group(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.accounts.leave_group(account_ref, group_id).await
    }

    pub async fn accept_group_invite(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupRecord, AppError> {
        self.accounts
            .accept_group_invite(account_ref, group_id)
            .await
    }

    pub async fn decline_group_invite(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<GroupInviteDeclineResult, AppError> {
        self.accounts
            .decline_group_invite(account_ref, group_id)
            .await
    }

    pub async fn update_group_profile(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<SendSummary, AppError> {
        let summary = self
            .accounts
            .update_group_profile(account_ref, group_id, name, description)
            .await?;
        let account = match self.accounts.resolve(account_ref) {
            Ok(account) => account,
            Err(_) => return Ok(summary),
        };
        let group_id_hex = hex::encode(group_id.as_slice());
        let chat_list_row = match self
            .accounts
            .app
            .refresh_chat_list_row(&account.label, &group_id_hex)
        {
            Ok(row) => row,
            Err(_) => return Ok(summary),
        };
        let _ = self
            .events
            .send(MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate {
                account_id_hex: account.account_id_hex,
                account_label: account.label,
                update: AppProjectionUpdate {
                    group_id_hex,
                    timeline_messages: Vec::new(),
                    timeline_changes: Vec::new(),
                    chat_list_row,
                    chat_list_trigger: ChatListUpdateTrigger::SnapshotRefresh,
                },
            }));
        Ok(summary)
    }

    pub async fn update_message_retention(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        disappearing_message_secs: u64,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .update_message_retention(account_ref, group_id, disappearing_message_secs)
            .await
    }

    pub async fn promote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .promote_admin(account_ref, group_id, member_ref)
            .await
    }

    pub async fn demote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .demote_admin(account_ref, group_id, member_ref)
            .await
    }

    pub async fn self_demote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.accounts.self_demote_admin(account_ref, group_id).await
    }

    pub async fn send_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        payload: Vec<u8>,
    ) -> Result<SendSummary, AppError> {
        let summary = self
            .accounts
            .send_message(account_ref, group_id, payload)
            .await?;
        let _ = self.publish_chat_list_projection_refresh(
            account_ref,
            &hex::encode(group_id.as_slice()),
            ChatListUpdateTrigger::NewLastMessage,
        );
        Ok(summary)
    }

    pub async fn share_push_registration(&self, account_ref: &str) -> Result<usize, AppError> {
        self.accounts.share_push_registration(account_ref).await
    }

    pub async fn remove_push_registration(
        &self,
        account_ref: &str,
        registration: PushRegistration,
    ) -> Result<usize, AppError> {
        self.accounts
            .remove_push_registration(account_ref, registration)
            .await
    }

    pub fn notification_settings(
        &self,
        account_ref: &str,
    ) -> Result<NotificationSettings, AppError> {
        self.accounts.app.notification_settings(account_ref)
    }

    pub fn set_local_notifications_enabled(
        &self,
        account_ref: &str,
        enabled: bool,
    ) -> Result<NotificationSettings, AppError> {
        self.accounts
            .app
            .set_local_notifications_enabled(account_ref, enabled)
    }

    pub async fn set_native_push_enabled(
        &self,
        account_ref: &str,
        enabled: bool,
    ) -> Result<NotificationSettings, AppError> {
        if !enabled && let Some(registration) = self.accounts.app.push_registration(account_ref)? {
            let _ = self
                .remove_push_registration(account_ref, registration)
                .await;
        }
        self.accounts
            .app
            .set_native_push_enabled(account_ref, enabled)
    }

    pub fn push_registration(
        &self,
        account_ref: &str,
    ) -> Result<Option<PushRegistration>, AppError> {
        self.accounts.app.push_registration(account_ref)
    }

    pub async fn upsert_push_registration(
        &self,
        account_ref: &str,
        platform: PushPlatform,
        raw_token: &str,
        server_pubkey_hex: &str,
        relay_hint: Option<String>,
    ) -> Result<PushRegistration, AppError> {
        let registration = self.accounts.app.upsert_push_registration(
            account_ref,
            platform,
            raw_token,
            server_pubkey_hex,
            relay_hint,
        )?;
        let _ = self.share_push_registration(account_ref).await;
        Ok(registration)
    }

    pub async fn clear_push_registration(&self, account_ref: &str) -> Result<(), AppError> {
        if let Some(registration) = self.accounts.app.push_registration(account_ref)? {
            let _ = self
                .remove_push_registration(account_ref, registration)
                .await;
        }
        self.accounts.app.clear_push_registration(account_ref)
    }

    pub async fn group_push_debug_info(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<GroupPushDebugInfo, AppError> {
        self.accounts
            .group_push_debug_info(account_ref, group_id)
            .await
    }

    pub async fn react_to_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        target_message_id: &str,
        emoji: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Reaction {
                    target_message_id: target_message_id.to_owned(),
                    emoji: emoji.to_owned(),
                },
            )
            .await
    }

    pub async fn unreact_from_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        target_message_id: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Unreact {
                    target_message_id: target_message_id.to_owned(),
                },
            )
            .await
    }

    pub async fn reply_to_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        target_message_id: &str,
        text: &str,
    ) -> Result<SendSummary, AppError> {
        let summary = self
            .accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Reply {
                    target_message_id: target_message_id.to_owned(),
                    text: text.to_owned(),
                },
            )
            .await?;
        let _ = self.publish_chat_list_projection_refresh(
            account_ref,
            &hex::encode(group_id.as_slice()),
            ChatListUpdateTrigger::NewLastMessage,
        );
        Ok(summary)
    }

    pub async fn delete_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        target_message_id: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Delete {
                    target_message_id: target_message_id.to_owned(),
                },
            )
            .await
    }

    /// Send a media attachment as a kind-9 chat carrying a NIP-92 `imeta` tag.
    pub async fn send_media_reference(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        reference: MediaReference,
        caption: Option<String>,
    ) -> Result<SendSummary, AppError> {
        let summary = self
            .accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Media { reference, caption },
            )
            .await?;
        let _ = self.publish_chat_list_projection_refresh(
            account_ref,
            &hex::encode(group_id.as_slice()),
            ChatListUpdateTrigger::NewLastMessage,
        );
        Ok(summary)
    }

    pub async fn upload_media(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        request: MediaUploadRequest,
    ) -> Result<MediaUploadResult, AppError> {
        self.accounts
            .upload_media(account_ref, group_id, request)
            .await
    }

    pub async fn download_media(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        reference: MediaReference,
    ) -> Result<MediaDownloadResult, AppError> {
        self.accounts
            .download_media(account_ref, group_id, reference)
            .await
    }

    pub async fn retry_group_convergence(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .retry_group_convergence(account_ref, group_id)
            .await
    }

    /// Anchor a kind-1200 agent text stream start. The `created_at` argument is
    /// retained for call-site stability; the worker stamps the inner event with
    /// its own clock so the canonical id matches the authoring time. Returns the
    /// built inner event (its tags carry the stream id, route, and brokers).
    pub async fn start_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        stream_id: &[u8],
        _created_at: u64,
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.accounts
            .start_agent_text_stream(account_ref, group_id, stream_id.to_vec(), quic_candidates)
            .await
    }

    /// Send the kind-9 stream-final chat carrying `stream`/`stream-hash`/
    /// `stream-chunks` tags. Returns the built inner event.
    pub async fn finish_agent_text_stream(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        request: AgentTextStreamFinishRequest,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.accounts
            .finish_agent_text_stream(account_ref, group_id, request)
            .await
    }

    pub async fn publish_key_package(&self, account_ref: &str) -> Result<usize, AppError> {
        self.accounts.publish_key_package(account_ref).await
    }

    pub async fn rotate_key_package(&self, account_ref: &str) -> Result<usize, AppError> {
        self.accounts.rotate_key_package(account_ref).await
    }

    pub async fn publish_new_key_package(&self, account_ref: &str) -> Result<usize, AppError> {
        self.rotate_key_package(account_ref).await
    }

    pub async fn account_key_packages(
        &self,
        account_ref: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<Vec<AccountKeyPackageRecord>, AppError> {
        self.accounts
            .account_key_packages(account_ref, bootstrap_relays)
            .await
    }

    pub async fn delete_key_package(
        &self,
        account_ref: &str,
        event_id_hex: &str,
        relays: Vec<TransportEndpoint>,
    ) -> Result<usize, AppError> {
        self.accounts
            .delete_key_package(account_ref, event_id_hex, relays)
            .await
    }

    pub async fn publish_user_profile(
        &self,
        account_ref: &str,
        profile: UserProfileMetadata,
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<UserProfileMetadata, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .publish_user_profile(&account.label, profile.clone(), bootstrap)
            .await?;
        self.accounts
            .app
            .remember_directory_profile(&account.account_id_hex, &profile)?;
        Ok(profile)
    }

    pub async fn publish_account_follow_list(
        &self,
        account_ref: &str,
        follows: &[String],
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<(), AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let follow_refs = follows.iter().map(String::as_str).collect::<Vec<_>>();
        self.accounts
            .app
            .publish_account_follow_list(&account.label, &follow_refs, bootstrap)
            .await
    }

    pub async fn refresh_user_directory_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<UserDirectoryRefresh, AppError> {
        self.accounts
            .app
            .refresh_user_directory_for_account_id(account_id_hex, bootstrap_relays)
            .await
    }

    pub async fn publish_account_relay_list_kind(
        &self,
        account_ref: &str,
        relay_type: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .publish_account_relay_list_kind(&account.label, relay_type, relays, bootstrap_relays)
            .await
    }

    pub fn account_nip65_relays(&self, account_ref: &str) -> Result<Vec<String>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts.app.account_nip65_relays(&account.label)
    }

    pub fn account_inbox_relays(&self, account_ref: &str) -> Result<Vec<String>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts.app.account_inbox_relays(&account.label)
    }

    pub fn account_key_package_relays(&self, account_ref: &str) -> Result<Vec<String>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts.app.account_key_package_relays(&account.label)
    }

    pub async fn set_account_nip65_relays(
        &self,
        account_ref: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .set_account_nip65_relays(&account.label, relays, bootstrap_relays)
            .await
    }

    pub async fn set_account_inbox_relays(
        &self,
        account_ref: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .set_account_inbox_relays(&account.label, relays, bootstrap_relays)
            .await
    }

    pub async fn set_account_key_package_relays(
        &self,
        account_ref: &str,
        relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .set_account_key_package_relays(&account.label, relays, bootstrap_relays)
            .await
    }

    pub fn messages_with_query(
        &self,
        account_ref: &str,
        query: AppMessageQuery,
    ) -> Result<Vec<AppMessageRecord>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts.app.messages_with_query(&account.label, query)
    }

    pub fn timeline_messages_with_query(
        &self,
        account_ref: &str,
        query: TimelineMessageQuery,
    ) -> Result<TimelinePage, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .timeline_messages_with_query(&account.label, query)
    }

    pub fn chat_list(
        &self,
        account_ref: &str,
        include_archived: bool,
    ) -> Result<Vec<ChatListRow>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .chat_list(&account.label, include_archived)
    }

    pub fn set_group_archived(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        archived: bool,
    ) -> Result<AppGroupRecord, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let group_id_hex = normalize_group_id_hex_app(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let group =
            self.accounts
                .app
                .set_group_archived(&account.label, &group_id_hex, archived)?;
        let chat_list_row = self
            .accounts
            .app
            .refresh_chat_list_row(&account.label, &group_id_hex)?;
        self.publish_chat_list_projection_update(
            account.account_id_hex.clone(),
            account.label.clone(),
            group_id_hex,
            chat_list_row,
            ChatListUpdateTrigger::ArchiveChanged,
        );
        publish_app_runtime_group_state_updated(
            &self.events,
            &account.account_id_hex,
            &account.label,
            &group_id,
        );
        Ok(group)
    }

    pub fn initialize_chat_read_state(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<Option<ChatListRow>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .initialize_chat_read_state(&account.label, group_id_hex)
    }

    pub fn mark_timeline_message_read(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> Result<Option<ChatListRow>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let row = self.accounts.app.mark_timeline_message_read(
            &account.label,
            group_id_hex,
            message_id_hex,
        )?;
        if row.is_some() {
            self.publish_chat_list_projection_update(
                account.account_id_hex,
                account.label,
                group_id_hex.to_owned(),
                row.clone(),
                ChatListUpdateTrigger::UnreadChanged,
            );
        }
        Ok(row)
    }

    fn publish_chat_list_projection_refresh(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        trigger: ChatListUpdateTrigger,
    ) -> Result<(), AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let row = self
            .accounts
            .app
            .refresh_chat_list_row(&account.label, group_id_hex)?;
        self.publish_chat_list_projection_update(
            account.account_id_hex,
            account.label,
            group_id_hex.to_owned(),
            row,
            trigger,
        );
        Ok(())
    }

    fn publish_chat_list_projection_update(
        &self,
        account_id_hex: String,
        account_label: String,
        group_id_hex: String,
        chat_list_row: Option<ChatListRow>,
        chat_list_trigger: ChatListUpdateTrigger,
    ) {
        let _ = self
            .events
            .send(MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate {
                account_id_hex,
                account_label,
                update: AppProjectionUpdate {
                    group_id_hex,
                    timeline_messages: Vec::new(),
                    timeline_changes: Vec::new(),
                    chat_list_row,
                    chat_list_trigger,
                },
            }));
    }

    pub async fn create_identity(
        &self,
        mut request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        request.identity = None;
        self.accounts.create_or_import_account(request).await
    }

    pub async fn login(
        &self,
        identity: impl Into<String>,
        mut request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        request.identity = Some(identity.into());
        self.accounts.create_or_import_account(request).await
    }

    pub async fn create_or_import_account(
        &self,
        request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        self.accounts.create_or_import_account(request).await
    }

    pub async fn shutdown(&self) {
        let started_at = Instant::now();
        self.shared.lifecycle().begin_shutdown();
        if let Some(directory_sync) = self.directory_sync.lock().await.take() {
            directory_sync.shutdown().await;
        }
        self.accounts.app.set_directory_sync_handle(None);
        let accounts = self.accounts.shutdown();
        let relay_plane = self.shared.relay_plane.shutdown();
        tokio::join!(accounts, relay_plane);
        self.shared
            .lifecycle()
            .wait_for_account_opens_to_drain(
                APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT.saturating_sub(started_at.elapsed()),
            )
            .await;
        tracing::debug!(
            target: "marmot_app::runtime",
            method = "shutdown",
            elapsed_ms = started_at.elapsed().as_millis() as u64,
            "runtime shutdown completed",
        );
    }
}

impl AccountManager {
    fn new(
        app: MarmotApp,
        events: broadcast::Sender<MarmotAppEvent>,
        shared: RuntimeSharedServices,
    ) -> Self {
        Self {
            app,
            events,
            shared,
            workers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn managed_accounts(&self) -> Result<Vec<ManagedAccount>, AppError> {
        let running = self
            .workers
            .try_lock()
            .ok()
            .map(|workers| workers.keys().cloned().collect::<HashSet<_>>())
            .unwrap_or_default();
        Ok(self
            .app
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.local_signing)
            .map(|account| ManagedAccount {
                running: running.contains(&account.account_id_hex),
                label: account.label,
                account_id_hex: account.account_id_hex,
                local_signing: account.local_signing,
            })
            .collect())
    }

    pub fn resolve(&self, account_ref: &str) -> Result<AccountSummary, AppError> {
        Ok(self.app.account_home().account(account_ref)?)
    }

    pub async fn reconcile(&self) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        let accounts = self
            .app
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.local_signing)
            .collect::<Vec<_>>();
        let active_account_ids = accounts
            .iter()
            .map(|account| account.account_id_hex.clone())
            .collect::<HashSet<_>>();

        let existing_account_ids = {
            let mut workers = self.workers.lock().await;
            let stale_account_ids = workers
                .iter()
                .filter_map(|(account_id, worker)| {
                    if active_account_ids.contains(account_id) && !worker.handle.is_finished() {
                        None
                    } else {
                        Some(account_id.clone())
                    }
                })
                .collect::<Vec<_>>();
            for account_id in stale_account_ids {
                if let Some(worker) = workers.remove(&account_id) {
                    worker.stop();
                }
            }
            workers.keys().cloned().collect::<HashSet<_>>()
        };

        let pending = accounts
            .into_iter()
            .filter(|account| !existing_account_ids.contains(&account.account_id_hex))
            .collect::<Vec<_>>();

        let mut ready_receivers = Vec::new();
        {
            let mut workers = self.workers.lock().await;
            for account in pending {
                if workers.contains_key(&account.account_id_hex) {
                    continue;
                }
                let (ready_tx, ready_rx) = oneshot::channel();
                let (shutdown_tx, shutdown_rx) = oneshot::channel();
                let (command_tx, command_rx) = mpsc::channel(8);
                let handle = spawn_app_runtime_account_worker(
                    AccountWorkerRuntime {
                        app: self.app.clone(),
                        account_label: account.label.clone(),
                        account_id_hex: account.account_id_hex.clone(),
                        relay_plane: self.shared.relay_plane().clone(),
                        events: self.events.clone(),
                        lifecycle: self.shared.lifecycle(),
                    },
                    command_rx,
                    ready_tx,
                    shutdown_rx,
                );
                workers.insert(
                    account.account_id_hex,
                    ManagedAccountWorker {
                        handle,
                        commands: command_tx,
                        shutdown: shutdown_tx,
                    },
                );
                ready_receivers.push(ready_rx);
            }
        }
        for ready in ready_receivers {
            match timeout(APP_RUNTIME_ACCOUNT_READY_WAIT, ready).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(message))) => return Err(AppError::BlockingTask(message)),
                Ok(Err(_closed)) => return Err(AppError::TransportClosed),
                Err(_elapsed) => {
                    return Err(AppError::BlockingTask(
                        "account worker startup timed out".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub async fn restart_account(&self, account_id_hex: &str) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        {
            let mut workers = self.workers.lock().await;
            if let Some(worker) = workers.remove(account_id_hex) {
                worker.stop();
            }
        }
        self.reconcile().await
    }

    pub async fn catch_up_accounts(&self) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        self.reconcile().await?;
        let commands = {
            let workers = self.workers.lock().await;
            workers
                .values()
                .map(|worker| worker.commands.clone())
                .collect::<Vec<_>>()
        };
        let mut responses = Vec::with_capacity(commands.len());
        for command in commands {
            let (respond, response) = oneshot::channel();
            command
                .send(AccountWorkerCommand::CatchUp { respond })
                .await
                .map_err(|_| AppError::TransportClosed)?;
            responses.push(response);
        }
        for response in responses {
            match timeout(APP_RUNTIME_ACCOUNT_READY_WAIT, response).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(message))) => return Err(AppError::RelayDirectory(message)),
                Ok(Err(_)) => return Err(AppError::TransportClosed),
                Err(_) => {
                    return Err(AppError::RelayDirectory(
                        "account worker catch-up timed out".into(),
                    ));
                }
            }
        }
        Ok(())
    }

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

    pub async fn group_forensics_bundle(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        options: ForensicsExportOptions,
    ) -> Result<ForensicsBundle, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::GroupForensicsBundle {
                group_id: group_id.clone(),
                options,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
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
        self.catch_up_accounts().await?;
        Ok(summary)
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
        Ok(summary)
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
        Ok(result)
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
        Ok(summary)
    }

    pub async fn promote_admin(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        member_ref: &str,
    ) -> Result<SendSummary, AppError> {
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
        Ok(summary)
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
        account_worker_response(response).await
    }

    async fn share_push_registration(&self, account_ref: &str) -> Result<usize, AppError> {
        let command = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SharePushRegistration { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    async fn remove_push_registration(
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
        account_worker_response(response).await
    }

    async fn group_push_debug_info(
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

    async fn send_app_event(
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
        account_worker_response(response).await
    }

    async fn upload_media(
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
        account_worker_response(response).await
    }

    async fn download_media(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        reference: MediaReference,
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

    async fn start_agent_text_stream(
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
        account_worker_response(response).await
    }

    async fn finish_agent_text_stream(
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
        self.catch_up_accounts().await?;
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

    pub async fn account_key_packages(
        &self,
        account_ref: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<Vec<AccountKeyPackageRecord>, AppError> {
        let account = self.resolve(account_ref)?;
        self.app
            .account_key_package_records(&account.label, bootstrap_relays)
            .await
    }

    pub async fn delete_key_package(
        &self,
        account_ref: &str,
        event_id_hex: &str,
        relays: Vec<TransportEndpoint>,
    ) -> Result<usize, AppError> {
        let account = self.resolve(account_ref)?;
        self.app
            .delete_key_package_event(&account.label, event_id_hex, relays)
            .await
    }

    async fn worker_commands(
        &self,
        account_ref: &str,
    ) -> Result<mpsc::Sender<AccountWorkerCommand>, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.resolve(account_ref)?;
        if !account.local_signing {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex).into());
        }
        self.reconcile().await?;
        let workers = self.workers.lock().await;
        workers
            .get(&account.account_id_hex)
            .map(|worker| worker.commands.clone())
            .ok_or_else(|| {
                AppError::RelayDirectory(
                    "managed account worker is not running for local signing account".into(),
                )
            })
    }

    pub async fn create_or_import_account(
        &self,
        request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let imports_private_key = request.identity.as_deref().is_some_and(is_nostr_secret);
        let creates_new_private_key = request.identity.is_none();
        let directory_bootstrap_relays = directory_bootstrap_relays_for_setup(&request);
        let account = match self.create_nostr_account(request.identity.clone()) {
            Ok(account) => account,
            Err(err) => return Err(err),
        };

        let relay_lists = match self
            .setup_relay_lists_for_account(
                &account,
                &request,
                imports_private_key,
                creates_new_private_key,
            )
            .await
        {
            Ok(relay_lists) => relay_lists,
            Err(err) => {
                return self.rollback_account_after_setup_failure(&account.label, err);
            }
        };

        let profile = if creates_new_private_key && account.local_signing {
            self.shared.lifecycle().ensure_running()?;
            match self
                .publish_default_profile_for_account(&account, &request)
                .await
            {
                Ok(profile) => Some(profile),
                Err(err) => {
                    return self.rollback_account_after_setup_failure(&account.label, err);
                }
            }
        } else {
            None
        };

        let key_package_bytes = if request.publish_initial_key_package && account.local_signing {
            self.shared.lifecycle().ensure_running()?;
            match self.publish_initial_key_package_for_account(&account).await {
                Ok(bytes) => Some(bytes),
                Err(err) => {
                    return self.rollback_account_after_setup_failure(&account.label, err);
                }
            }
        } else {
            None
        };

        self.shared.lifecycle().ensure_running()?;
        let _ = self
            .app
            .refresh_user_directory_for_account_id(
                &account.account_id_hex,
                directory_bootstrap_relays.clone(),
            )
            .await;
        self.reconcile().await?;

        Ok(AccountSetupResult {
            account,
            relay_lists,
            key_package_bytes,
            profile,
        })
    }

    async fn publish_default_profile_for_account(
        &self,
        account: &AccountSummary,
        request: &AccountSetupRequest,
    ) -> Result<UserProfileMetadata, AppError> {
        let pseudonym = default_profile_pseudonym(&account.account_id_hex);
        let profile = UserProfileMetadata {
            name: Some(pseudonym.clone()),
            display_name: Some(pseudonym),
            created_at: unix_now_seconds(),
            ..UserProfileMetadata::default()
        };
        self.app
            .publish_user_profile(
                &account.label,
                profile.clone(),
                AccountRelayListBootstrap::new(
                    request.default_relays.clone(),
                    request.bootstrap_relays.clone(),
                ),
            )
            .await?;
        self.app
            .remember_directory_profile(&account.account_id_hex, &profile)?;
        Ok(profile)
    }

    async fn setup_relay_lists_for_account(
        &self,
        account: &AccountSummary,
        request: &AccountSetupRequest,
        imports_private_key: bool,
        creates_new_private_key: bool,
    ) -> Result<AccountRelayListStatus, AppError> {
        if account.local_signing {
            if creates_new_private_key && request.default_relays.is_empty() {
                return Err(AppError::MissingDefaultRelays);
            }
            if imports_private_key
                && request.default_relays.is_empty()
                && request.bootstrap_relays.is_empty()
            {
                return Err(AppError::MissingDefaultRelays);
            }
            if imports_private_key
                && (!request.default_relays.is_empty() || !request.bootstrap_relays.is_empty())
            {
                let bootstrap = AccountRelayListBootstrap::new(
                    request.default_relays.clone(),
                    request.bootstrap_relays.clone(),
                );
                let current_status = self
                    .app
                    .fetch_account_relay_list_status_for_account_id(
                        &account.account_id_hex,
                        bootstrap.bootstrap_relays.clone(),
                    )
                    .await?;
                if current_status.complete {
                    Ok(current_status)
                } else if !request.publish_missing_relay_lists || request.default_relays.is_empty()
                {
                    Err(AppError::MissingRelayLists(current_status.missing.clone()))
                } else {
                    self.app
                        .publish_missing_account_relay_lists_from_status(
                            &account.label,
                            bootstrap,
                            current_status,
                        )
                        .await
                }
            } else {
                self.publish_relay_lists_for_new_account(&account.label, request)
                    .await
            }
        } else {
            let bootstrap_relays = directory_bootstrap_relays_for_setup(request);
            if bootstrap_relays.is_empty() {
                return Err(AppError::MissingDefaultRelays);
            }
            self.app
                .fetch_account_relay_list_status_for_account_id(
                    &account.account_id_hex,
                    bootstrap_relays,
                )
                .await
        }
    }

    async fn publish_relay_lists_for_new_account(
        &self,
        label: &str,
        request: &AccountSetupRequest,
    ) -> Result<AccountRelayListStatus, AppError> {
        if request.default_relays.is_empty() && request.bootstrap_relays.is_empty() {
            return self.app.account_relay_list_status(label);
        }
        if request.default_relays.is_empty() {
            return Err(AppError::MissingDefaultRelays);
        }
        self.app
            .publish_account_relay_lists(
                label,
                AccountRelayListBootstrap::new(
                    request.default_relays.clone(),
                    request.bootstrap_relays.clone(),
                ),
            )
            .await
    }

    async fn publish_initial_key_package_for_account(
        &self,
        account: &AccountSummary,
    ) -> Result<usize, AppError> {
        self.app.status(&account.label)?;
        let mut client = self.app.client(&account.label).await?;
        let key_package = client.publish_key_package().await?;
        Ok(key_package.bytes().len())
    }

    fn create_nostr_account(&self, identity: Option<String>) -> Result<AccountSummary, AppError> {
        let account_home = self.app.account_home();
        match identity {
            Some(value) if is_nostr_secret(&value) => {
                Ok(account_home.import_nostr_account(&value)?)
            }
            Some(value) => Ok(account_home.add_public_account(&value)?),
            None => Ok(account_home.create_nostr_account()?),
        }
    }

    fn rollback_account_after_setup_failure<T>(
        &self,
        account: &str,
        source: AppError,
    ) -> Result<T, AppError> {
        match self.app.account_home().remove_account(account) {
            Ok(()) => Err(source),
            Err(rollback) => Err(AppError::RelayDirectory(format!(
                "failed to roll back account after setup failure: {source}; rollback error: {rollback}"
            ))),
        }
    }

    pub async fn shutdown(&self) {
        self.shared.lifecycle().begin_shutdown();
        let workers = {
            let mut workers = self.workers.lock().await;
            workers
                .drain()
                .map(|(_, worker)| worker)
                .collect::<Vec<_>>()
        };
        let mut shutdowns = JoinSet::new();
        for worker in workers {
            shutdowns.spawn(async move {
                worker.shutdown().await;
            });
        }
        while shutdowns.join_next().await.is_some() {}
    }
}

fn is_nostr_secret(value: &str) -> bool {
    value.starts_with("nsec")
}

fn directory_bootstrap_relays_for_setup(request: &AccountSetupRequest) -> Vec<TransportEndpoint> {
    if request.bootstrap_relays.is_empty() {
        request.default_relays.clone()
    } else {
        request.bootstrap_relays.clone()
    }
}

async fn account_worker_response<T>(
    response: oneshot::Receiver<Result<T, AppError>>,
) -> Result<T, AppError> {
    response.await.map_err(|_| AppError::TransportClosed)?
}

pub(crate) async fn blocking_app_task<T>(
    task: impl FnOnce() -> Result<T, AppError> + Send + 'static,
) -> Result<T, AppError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|err| AppError::BlockingTask(err.to_string()))?
}

fn spawn_app_runtime_account_worker(
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

    match tokio::select! {
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
        result = client.sync() => result,
    } {
        Ok(summary) => {
            publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
        }
        Err(err) => {
            publish_app_runtime_account_error(
                &events,
                &account_id_hex,
                &account_label,
                format!("runtime startup receive failed: {err}"),
            );
        }
    }
    if let Some(ready) = ready.take() {
        let _ = ready.send(Ok(()));
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
                    Some(AccountWorkerCommand::CatchUp { respond }) => {
                        let result = match client.sync().await {
                            Ok(summary) => {
                                publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
                                Ok(())
                            }
                            Err(err) => {
                                let message = format!("runtime catch-up failed: {err}");
                                publish_app_runtime_account_error(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    message.clone(),
                                );
                                Err(message)
                            }
                        };
                        let _ = respond.send(result);
                    }
                        Some(AccountWorkerCommand::CreateGroup {
                            name,
                            members,
                            description,
                            respond,
                        }) => {
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
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    group_id,
                                );
                            }
                            let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::Members { group_id, respond }) => {
                        let result = client.members(&group_id);
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::GroupMlsState { group_id, respond }) => {
                        let result = client.group_mls_state(&group_id);
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::GroupForensicsBundle {
                        group_id,
                        options,
                        respond,
                    }) => {
                        let task = tokio::task::spawn_blocking(move || {
                            let result = client.group_forensics_bundle(&group_id, &options);
                            (client, result)
                        });
                        match task.await {
                            Ok((restored_client, result)) => {
                                client = restored_client;
                                let _ = respond.send(result);
                            }
                            Err(err) => {
                                let _ = respond.send(Err(AppError::BlockingTask(err.to_string())));
                                return;
                            }
                        }
                    }
                    Some(AccountWorkerCommand::UpdateMessageRetention {
                        group_id,
                        disappearing_message_secs,
                        respond,
                    }) => {
                        let result = client
                            .update_message_retention(&group_id, disappearing_message_secs)
                            .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::SafeExportSecret {
                        group_id,
                        component_id,
                        respond,
                    }) => {
                        let result = client.safe_export_secret(&group_id, component_id);
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::ExporterSecret {
                        group_id,
                        label,
                        length,
                        respond,
                    }) => {
                        let result = client.exporter_secret(&group_id, &label, length);
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::InviteMembers {
                        group_id,
                        members,
                        respond,
                    }) => {
                        let result = async {
                            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
                            client.invite_members(&group_id, &member_refs).await
                        }
                        .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::RemoveMembers {
                        group_id,
                        members,
                        respond,
                    }) => {
                        let result = async {
                            let member_refs = members.iter().map(String::as_str).collect::<Vec<_>>();
                            client.remove_members(&group_id, &member_refs).await
                        }
                        .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::LeaveGroup { group_id, respond }) => {
                        let result = client.leave_group(&group_id).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::AcceptGroupInvite { group_id, respond }) => {
                        let result = client.accept_group_invite(&group_id);
                        if result.is_ok() {
                            publish_app_runtime_group_state_updated(
                                &events,
                                &account_id_hex,
                                &account_label,
                                &group_id,
                            );
                        }
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::DeclineGroupInvite { group_id, respond }) => {
                        let result = client.decline_group_invite(&group_id).await;
                        if result.is_ok() {
                            publish_app_runtime_group_state_updated(
                                &events,
                                &account_id_hex,
                                &account_label,
                                &group_id,
                            );
                        }
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::PromoteAdmin {
                        group_id,
                        member_ref,
                        respond,
                    }) => {
                        let result = client.promote_admin(&group_id, &member_ref).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::DemoteAdmin {
                        group_id,
                        member_ref,
                        respond,
                    }) => {
                        let result = client.demote_admin(&group_id, &member_ref).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::SelfDemoteAdmin { group_id, respond }) => {
                        let result = client.self_demote_admin(&group_id).await;
                        let _ = respond.send(result);
                    }
                        Some(AccountWorkerCommand::UpdateGroupProfile {
                            group_id,
                            name,
                            description,
                            respond,
                        }) => {
                            let result = client
                                .update_group_profile(&group_id, name.as_deref(), description.as_deref())
                                .await;
                            if result.is_ok() {
                                publish_app_runtime_group_state_updated(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    &group_id,
                                );
                            }
                            let _ = respond.send(result);
                        }
                    Some(AccountWorkerCommand::SendMessage {
                        group_id,
                        payload,
                        respond,
                    }) => {
                        let result = client
                            .send_with_local_projection(&group_id, &payload, |update| {
                                publish_app_runtime_projection_update(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    update,
                                );
                            })
                            .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::SendAppEvent {
                        group_id,
                        intent,
                        respond,
                    }) => {
                        let result = client
                            .send_app_event_with_local_projection(&group_id, intent, |update| {
                                publish_app_runtime_projection_update(
                                    &events,
                                    &account_id_hex,
                                    &account_label,
                                    update,
                                );
                            })
                            .await
                            .map(|(_event, summary)| summary);
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::UploadMedia {
                        group_id,
                        request,
                        respond,
                    }) => {
                        let result = client.upload_media(&group_id, request).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::DownloadMedia {
                        group_id,
                        reference,
                        respond,
                    }) => {
                        let result = client.download_media(&group_id, reference).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::StartAgentTextStream {
                        group_id,
                        stream_id,
                        quic_candidates,
                        respond,
                    }) => {
                        let result = client
                            .start_agent_text_stream_with_local_projection(
                                &group_id,
                                &stream_id,
                                quic_candidates,
                                |update| {
                                    publish_app_runtime_projection_update(
                                        &events,
                                        &account_id_hex,
                                        &account_label,
                                        update,
                                    );
                                },
                            )
                            .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::FinishAgentTextStream {
                        group_id,
                        request,
                        respond,
                    }) => {
                        let result = client
                            .finish_agent_text_stream_with_local_projection(
                                &group_id,
                                request,
                                |update| {
                                    publish_app_runtime_projection_update(
                                        &events,
                                        &account_id_hex,
                                        &account_label,
                                        update,
                                    );
                                },
                            )
                            .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::RetryGroupConvergence { group_id, respond }) => {
                        let result = client.retry_group_convergence(&group_id).await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::PublishKeyPackage { respond }) => {
                        let result = async {
                            let key_package = client.publish_key_package().await?;
                            Ok(key_package.bytes().len())
                        }
                        .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::RotateKeyPackage { respond }) => {
                        let result = async {
                            let key_package = client.rotate_key_package().await?;
                            Ok(key_package.bytes().len())
                        }
                        .await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::SharePushRegistration { respond }) => {
                        let result = client.share_push_registration().await;
                        let _ = respond.send(result);
                    }
                    Some(AccountWorkerCommand::RemovePushRegistration {
                        registration,
                        respond,
                    }) => {
                        let result = client.remove_push_registration(registration).await;
                        let _ = respond.send(result);
                    }
                    None => return,
                }
            }
            result = client.next_event() => {
                match result {
                    Ok(summary) => {
                        reconnect_backoff.reset();
                        publish_app_runtime_summary(&events, &account_id_hex, &account_label, &summary);
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

fn collect_notification_update_from_event(
    app: &MarmotApp,
    event: &MarmotAppEvent,
    notifications: &mut Vec<NotificationUpdate>,
) {
    match notifications::notification_update_from_event(app, event) {
        Ok(Some(update)) => notifications.push(update),
        Ok(None) | Err(AppError::NotificationsDisabled) => {}
        Err(_) => {
            tracing::warn!(
                target: "marmot_app::notifications",
                method = "collect_notifications_after_wake",
                error_code = "notification_projection_skipped",
                "notification projection skipped",
            );
        }
    }
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

fn publish_app_runtime_group_state_updated(
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

pub(crate) struct ParsedQuicCandidate {
    pub(crate) authority: String,
    pub(crate) server_name: String,
}

struct ResolvedQuicCandidate {
    broker_addr: SocketAddr,
    server_name: String,
}

/// A kind-1200 agent text stream start, projected from its inner-event tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamStartView {
    pub stream_id_hex: String,
    pub route: String,
    pub quic_candidates: Vec<String>,
}

impl StreamStartView {
    /// Read the stream start view from a kind-1200 event's tags. Returns `None`
    /// if the event is not a stream start or is missing the `stream` tag.
    pub fn from_event(kind: u64, tags: &[Vec<String>]) -> Option<Self> {
        if kind != MARMOT_APP_EVENT_KIND_AGENT_STREAM_START {
            return None;
        }
        let stream_id_hex = tag_value(tags, STREAM_TAG)?.to_owned();
        let route = tag_value(tags, STREAM_ROUTE_TAG)
            .unwrap_or(STREAM_ROUTE_QUIC)
            .to_owned();
        let quic_candidates = tag_values(tags, STREAM_BROKER_TAG)
            .into_iter()
            .map(str::to_owned)
            .collect();
        Some(Self {
            stream_id_hex,
            route,
            quic_candidates,
        })
    }
}

/// Find the most recent kind-1200 stream start in a group's message history,
/// optionally constrained to a specific `stream_id`.
fn latest_agent_stream_start(
    messages: Vec<AppMessageRecord>,
    stream_id_hex: Option<&str>,
) -> Result<(String, StreamStartView, String), AppError> {
    messages
        .into_iter()
        .rev()
        .find_map(|message| {
            let start = StreamStartView::from_event(message.kind, &message.tags)?;
            if stream_id_hex.is_none_or(|stream_id| stream_id == start.stream_id_hex) {
                Some((message.message_id_hex, start, message.sender))
            } else {
                None
            }
        })
        .ok_or(AppError::AgentStreamMissingStart)
}

fn parse_quic_candidate(candidate: &str) -> Result<ParsedQuicCandidate, AppError> {
    let trimmed = candidate.trim();
    let Some(rest) = trimmed.strip_prefix("quic://") else {
        return Err(AppError::AgentStreamInvalidCandidate(trimmed.to_owned()));
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(AppError::AgentStreamInvalidCandidate(trimmed.to_owned()));
    }
    let server_name = candidate_server_name(authority)?;
    Ok(ParsedQuicCandidate {
        authority: authority.to_owned(),
        server_name,
    })
}

pub(crate) fn parse_quic_candidates(
    candidates: &[String],
) -> Result<Vec<ParsedQuicCandidate>, AppError> {
    let parsed = candidates
        .iter()
        .filter(|candidate| candidate.trim().starts_with("quic://"))
        .filter_map(|candidate| parse_quic_candidate(candidate).ok())
        .collect::<Vec<_>>();
    if parsed.is_empty() {
        return Err(AppError::AgentStreamMissingCandidate);
    }
    Ok(parsed)
}

fn candidate_server_name(authority: &str) -> Result<String, AppError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, _)) = rest.split_once(']') else {
            return Err(AppError::AgentStreamInvalidCandidate(authority.to_owned()));
        };
        return Ok(host.to_owned());
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| AppError::AgentStreamInvalidCandidate(authority.to_owned()))
}

async fn watch_broker_candidates(
    candidates: Vec<ParsedQuicCandidate>,
    server_cert_der: Option<Vec<u8>>,
    insecure_local: bool,
    stream_id: Vec<u8>,
    start_event_id: MessageId,
    crypto: Option<AgentTextStreamCrypto>,
    updates_tx: mpsc::Sender<RuntimeAgentStreamUpdate>,
) -> RuntimeAgentStreamUpdate {
    let mut last_error = None;
    for candidate in candidates {
        match resolve_broker_addr(&candidate.authority).await {
            Ok(broker_addr) => {
                let resolved = ResolvedQuicCandidate {
                    broker_addr,
                    server_name: candidate.server_name,
                };
                let trust = broker_trust_for_addr(
                    resolved.broker_addr,
                    server_cert_der.clone(),
                    insecure_local,
                );
                let config = SubscribeTextFromBroker {
                    broker_addr: resolved.broker_addr,
                    server_name: resolved.server_name,
                    trust,
                    stream_id: stream_id.clone(),
                    start_event_id: start_event_id.clone(),
                    crypto: crypto.clone(),
                };
                let chunk_tx = updates_tx.clone();
                match subscribe_text_from_broker_with_updates(config, |chunk| {
                    // Non-blocking: if the consumer falls behind we drop a
                    // delta; the Finished update carries the full transcript
                    // for reconcile.
                    if let Err(mpsc::error::TrySendError::Full(_)) =
                        chunk_tx.try_send(RuntimeAgentStreamUpdate::Chunk {
                            seq: chunk.seq,
                            text: chunk.text.clone(),
                        })
                    {
                        tracing::warn!(
                            target: "marmot_app::agent_stream",
                            method = "watch_agent_text_stream",
                            "dropping live agent text stream delta; consumer is behind",
                        );
                    }
                })
                .await
                {
                    Ok(received) => {
                        return RuntimeAgentStreamUpdate::Finished {
                            text: received.text,
                            transcript_hash_hex: hex::encode(received.transcript_hash),
                            chunk_count: received.chunk_count,
                        };
                    }
                    Err(err) => last_error = Some(err.to_string()),
                }
            }
            Err(err) => last_error = Some(err.to_string()),
        }
    }
    RuntimeAgentStreamUpdate::Failed {
        message: last_error.unwrap_or_else(|| AppError::AgentStreamMissingCandidate.to_string()),
    }
}

async fn resolve_broker_addr(authority: &str) -> Result<SocketAddr, AppError> {
    let mut addrs = tokio::net::lookup_host(authority)
        .await
        .map_err(|_| AppError::AgentStreamInvalidCandidate(authority.to_owned()))?;
    addrs
        .next()
        .ok_or_else(|| AppError::AgentStreamInvalidCandidate(authority.to_owned()))
}

pub(crate) fn broker_trust_for_addr(
    broker_addr: SocketAddr,
    server_cert_der: Option<Vec<u8>>,
    insecure_local: bool,
) -> BrokerServerTrust {
    if insecure_local && broker_addr.ip().is_loopback() {
        return BrokerServerTrust::InsecureLocal;
    }
    server_cert_der
        .map(BrokerServerTrust::CertificateDer)
        .unwrap_or(BrokerServerTrust::Platform)
}

fn runtime_message_update_from_event(event: MarmotAppEvent) -> Option<RuntimeMessageUpdate> {
    match event {
        // Raw message updates keep kind-1200 stream starts distinct from
        // message rows. The materialized storage timeline still includes those
        // starts when clients call `timeline_messages`.
        MarmotAppEvent::MessageReceived(message) => Some(RuntimeMessageUpdate::Message(message)),
        MarmotAppEvent::AgentStreamStarted(message) => {
            Some(RuntimeMessageUpdate::AgentStreamStarted(message))
        }
        MarmotAppEvent::GroupJoined { .. }
        | MarmotAppEvent::GroupStateUpdated { .. }
        | MarmotAppEvent::ProjectionUpdated(_)
        | MarmotAppEvent::GroupEvent(_)
        | MarmotAppEvent::AccountError(_) => None,
    }
}

fn projection_update_from_event(event: &MarmotAppEvent) -> Option<&RuntimeProjectionUpdate> {
    match event {
        MarmotAppEvent::ProjectionUpdated(update) => Some(update),
        MarmotAppEvent::GroupJoined { .. }
        | MarmotAppEvent::GroupStateUpdated { .. }
        | MarmotAppEvent::MessageReceived(_)
        | MarmotAppEvent::AgentStreamStarted(_)
        | MarmotAppEvent::GroupEvent(_)
        | MarmotAppEvent::AccountError(_) => None,
    }
}

fn projection_update_matches_query(
    update: &RuntimeProjectionUpdate,
    account_id_hex: &str,
    group_id_hex: Option<&str>,
) -> bool {
    update.account_id_hex == account_id_hex
        && group_id_hex.is_none_or(|wanted| update.update.group_id_hex == wanted)
        && (!update.update.timeline_messages.is_empty()
            || !update.update.timeline_changes.is_empty())
}

fn timeline_query_can_apply_projection_delta(query: &TimelineMessageQuery) -> bool {
    query
        .search
        .as_ref()
        .is_none_or(|search| search.trim().is_empty())
        && query.pagination.before.is_none()
        && query.pagination.before_message_id.is_none()
        && query.pagination.after.is_none()
        && query.pagination.after_message_id.is_none()
}

fn runtime_group_event_route(event: &MarmotAppEvent) -> Option<(&str, &GroupId)> {
    match event {
        MarmotAppEvent::GroupJoined {
            account_id_hex,
            group_id,
            ..
        }
        | MarmotAppEvent::GroupStateUpdated {
            account_id_hex,
            group_id,
            ..
        } => Some((account_id_hex, group_id)),
        MarmotAppEvent::GroupEvent(group_event) => match &group_event.event {
            GroupEvent::MessageReceived { .. } | GroupEvent::AppMessageInvalidated { .. } => None,
            event => Some((&group_event.account_id_hex, group_id_from_event(event))),
        },
        MarmotAppEvent::ProjectionUpdated(_)
        | MarmotAppEvent::MessageReceived(_)
        | MarmotAppEvent::AgentStreamStarted(_)
        | MarmotAppEvent::AccountError(_) => None,
    }
}

fn chat_list_event_route(event: &MarmotAppEvent) -> Option<(&str, &GroupId)> {
    match event {
        MarmotAppEvent::GroupJoined {
            account_id_hex,
            group_id,
            ..
        }
        | MarmotAppEvent::GroupStateUpdated {
            account_id_hex,
            group_id,
            ..
        } => Some((account_id_hex, group_id)),
        MarmotAppEvent::GroupEvent(group_event) => match &group_event.event {
            GroupEvent::MessageReceived { .. } | GroupEvent::AppMessageInvalidated { .. } => None,
            event => Some((&group_event.account_id_hex, group_id_from_event(event))),
        },
        MarmotAppEvent::ProjectionUpdated(_)
        | MarmotAppEvent::MessageReceived(_)
        | MarmotAppEvent::AgentStreamStarted(_)
        | MarmotAppEvent::AccountError(_) => None,
    }
}

fn chat_list_trigger_from_event(event: &MarmotAppEvent) -> ChatListUpdateTrigger {
    match event {
        MarmotAppEvent::GroupJoined { .. } => ChatListUpdateTrigger::NewGroup,
        MarmotAppEvent::GroupStateUpdated { .. } => ChatListUpdateTrigger::MembershipChanged,
        MarmotAppEvent::GroupEvent(group_event) => match &group_event.event {
            GroupEvent::GroupCreated { .. } | GroupEvent::GroupJoined { .. } => {
                ChatListUpdateTrigger::NewGroup
            }
            GroupEvent::MemberAdded { .. }
            | GroupEvent::MemberRemoved { .. }
            | GroupEvent::EpochChanged { .. }
            | GroupEvent::ForkRecovered { .. }
            | GroupEvent::GroupUnrecoverable { .. } => ChatListUpdateTrigger::MembershipChanged,
            GroupEvent::MessageReceived { .. } | GroupEvent::AppMessageInvalidated { .. } => {
                ChatListUpdateTrigger::SnapshotRefresh
            }
        },
        MarmotAppEvent::ProjectionUpdated(update) => update.update.chat_list_trigger,
        MarmotAppEvent::MessageReceived(_)
        | MarmotAppEvent::AgentStreamStarted(_)
        | MarmotAppEvent::AccountError(_) => ChatListUpdateTrigger::SnapshotRefresh,
    }
}

fn group_id_from_event(event: &GroupEvent) -> &GroupId {
    match event {
        GroupEvent::GroupCreated { group_id }
        | GroupEvent::GroupJoined { group_id, .. }
        | GroupEvent::MessageReceived { group_id, .. }
        | GroupEvent::AppMessageInvalidated { group_id, .. }
        | GroupEvent::MemberAdded { group_id, .. }
        | GroupEvent::MemberRemoved { group_id, .. }
        | GroupEvent::EpochChanged { group_id, .. }
        | GroupEvent::ForkRecovered { group_id, .. }
        | GroupEvent::GroupUnrecoverable { group_id } => group_id,
    }
}

fn app_group_record_fingerprint(group: &AppGroupRecord) -> String {
    serde_json::to_string(group).unwrap_or_else(|_| group.group_id_hex.clone())
}

fn chat_list_row_fingerprint(row: &ChatListRow) -> String {
    let mut stable = row.clone();
    stable.updated_at = 0;
    serde_json::to_string(&stable).unwrap_or_else(|_| row.group_id_hex.clone())
}

async fn send_chat_list_row_update(
    updates_tx: &mpsc::Sender<RuntimeChatListUpdate>,
    row_fingerprints: &mut HashMap<String, String>,
    trigger: ChatListUpdateTrigger,
    row: ChatListRow,
) -> bool {
    let fingerprint = chat_list_row_fingerprint(&row);
    if row_fingerprints.get(&row.group_id_hex) == Some(&fingerprint) {
        return true;
    }
    row_fingerprints.insert(row.group_id_hex.clone(), fingerprint);
    updates_tx
        .send(RuntimeChatListUpdate::Row {
            trigger,
            row: Box::new(row),
        })
        .await
        .is_ok()
}

async fn send_chat_list_remove_update(
    updates_tx: &mpsc::Sender<RuntimeChatListUpdate>,
    row_fingerprints: &mut HashMap<String, String>,
    trigger: ChatListUpdateTrigger,
    group_id_hex: &str,
) -> bool {
    if row_fingerprints.remove(group_id_hex).is_none() {
        return true;
    }
    updates_tx
        .send(RuntimeChatListUpdate::RemoveRow {
            trigger,
            group_id_hex: group_id_hex.to_owned(),
        })
        .await
        .is_ok()
}

async fn reconcile_chat_list_snapshot(
    updates_tx: &mpsc::Sender<RuntimeChatListUpdate>,
    row_fingerprints: &mut HashMap<String, String>,
    trigger: ChatListUpdateTrigger,
    rows: Vec<ChatListRow>,
) -> bool {
    let visible_group_ids = rows
        .iter()
        .map(|row| row.group_id_hex.clone())
        .collect::<HashSet<_>>();
    let removed_group_ids = row_fingerprints
        .keys()
        .filter(|group_id_hex| !visible_group_ids.contains(*group_id_hex))
        .cloned()
        .collect::<Vec<_>>();
    for group_id_hex in removed_group_ids {
        if !send_chat_list_remove_update(updates_tx, row_fingerprints, trigger, &group_id_hex).await
        {
            return false;
        }
    }
    for row in rows {
        if !send_chat_list_row_update(updates_tx, row_fingerprints, trigger, row).await {
            return false;
        }
    }
    true
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

    #[tokio::test]
    async fn managed_account_worker_shutdown_aborts_unresponsive_task_after_timeout() {
        let (commands, _commands_rx) = mpsc::channel(1);
        let (shutdown, _shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        let worker = ManagedAccountWorker {
            handle,
            commands,
            shutdown,
        };

        let started = std::time::Instant::now();
        worker
            .shutdown_with_timeout(Duration::from_millis(10))
            .await;

        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn message_subscription_recv_ends_when_runtime_shutdown_begins() {
        let lifecycle = RuntimeLifecycle::new();
        let (updates_tx, updates) = mpsc::channel(1);
        let mut subscription = RuntimeMessagesSubscription {
            snapshot: Vec::new(),
            updates,
            stopping: lifecycle.subscribe_shutdown(),
        };

        lifecycle.begin_shutdown();

        assert!(subscription.recv().await.is_none());
        drop(updates_tx);
    }

    #[tokio::test]
    async fn timeline_subscription_recv_ends_when_runtime_shutdown_begins() {
        let lifecycle = RuntimeLifecycle::new();
        let (updates_tx, updates) = mpsc::channel(1);
        let mut subscription = RuntimeTimelineMessagesSubscription {
            snapshot: TimelinePage {
                messages: Vec::new(),
                has_more_before: false,
                has_more_after: false,
            },
            updates,
            stopping: lifecycle.subscribe_shutdown(),
        };

        lifecycle.begin_shutdown();

        assert!(subscription.recv().await.is_none());
        drop(updates_tx);
    }

    #[tokio::test]
    async fn chat_list_remove_update_is_sent_once_for_visible_rows() {
        let (updates_tx, mut updates_rx) = mpsc::channel(1);
        let mut row_fingerprints = HashMap::from([("group".to_owned(), "fingerprint".to_owned())]);

        assert!(
            send_chat_list_remove_update(
                &updates_tx,
                &mut row_fingerprints,
                ChatListUpdateTrigger::Removed,
                "group",
            )
            .await
        );
        assert_eq!(
            updates_rx.recv().await,
            Some(RuntimeChatListUpdate::RemoveRow {
                trigger: ChatListUpdateTrigger::Removed,
                group_id_hex: "group".to_owned()
            })
        );

        assert!(
            send_chat_list_remove_update(
                &updates_tx,
                &mut row_fingerprints,
                ChatListUpdateTrigger::Removed,
                "group",
            )
            .await
        );
        assert!(updates_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn chat_list_snapshot_reconciliation_updates_changed_rows_and_removes_missing_rows() {
        let (updates_tx, mut updates_rx) = mpsc::channel(2);
        let initial_row = chat_list_test_row("group", "before");
        let removed_row = chat_list_test_row("removed", "gone");
        let mut row_fingerprints = HashMap::from([
            (
                initial_row.group_id_hex.clone(),
                chat_list_row_fingerprint(&initial_row),
            ),
            (
                removed_row.group_id_hex.clone(),
                chat_list_row_fingerprint(&removed_row),
            ),
        ]);

        assert!(
            reconcile_chat_list_snapshot(
                &updates_tx,
                &mut row_fingerprints,
                ChatListUpdateTrigger::SnapshotRefresh,
                vec![chat_list_test_row("group", "after")],
            )
            .await
        );

        assert!(matches!(
            updates_rx.recv().await,
            Some(RuntimeChatListUpdate::RemoveRow {
                trigger: ChatListUpdateTrigger::SnapshotRefresh,
                group_id_hex,
            }) if group_id_hex == "removed"
        ));
        assert!(matches!(
            updates_rx.recv().await,
            Some(RuntimeChatListUpdate::Row {
                trigger: ChatListUpdateTrigger::SnapshotRefresh,
                row,
            }) if row.group_id_hex == "group" && row.title == "after"
        ));
    }

    fn chat_list_test_row(group_id_hex: &str, title: &str) -> ChatListRow {
        ChatListRow {
            group_id_hex: group_id_hex.to_owned(),
            archived: false,
            pending_confirmation: false,
            title: title.to_owned(),
            group_name: title.to_owned(),
            avatar: None,
            last_message: None,
            unread_count: 0,
            has_unread: false,
            first_unread_message_id_hex: None,
            last_read_message_id_hex: None,
            last_read_timeline_at: None,
            updated_at: 0,
        }
    }

    #[test]
    fn lifecycle_refuses_account_open_after_shutdown_begins() {
        let lifecycle = RuntimeLifecycle::new();

        lifecycle.begin_shutdown();

        assert!(matches!(
            lifecycle.begin_account_open(),
            Err(AppError::RuntimeStopping)
        ));
    }
}
