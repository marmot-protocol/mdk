use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY;
use cgka_traits::app_event::MarmotAppEvent as MarmotInnerEvent;
use cgka_traits::engine::GroupEvent;
use cgka_traits::{GroupId, SecretBytes, TransportEndpoint};
use marmot_account::{AccountHomeError, AccountSummary};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::agent_streams::AgentStreamWatchManager;
use crate::app_telemetry::{AppPerformanceOperation, AppPerformanceTelemetry};
use crate::directory::{DirectorySyncHandle, DirectorySyncRunSummary};
use crate::ids::normalize_group_id_hex_app;
use crate::messages::AppMessageIntent;
use crate::notifications;
use crate::{
    APP_RUNTIME_ACCOUNT_READY_WAIT, APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT,
    APP_RUNTIME_RELAY_REBUILD_LOOKBACK, AccountKeyPackageRecord, AccountRelayListBootstrap,
    AccountRelayListStatus, AccountUnread, AgentOperationEventRequest,
    AgentTextStreamFinishRequest, AppBlobEndpoint, AppError, AppGroupMemberRecord,
    AppGroupMlsState, AppGroupRecord, AppMessageQuery, AppMessageRecord, AppProjectionUpdate,
    AppQuarantinedGroup, AuditLogDeleteOutcome, AuditLogFile, AuditLogSettings,
    AuditLogTrackerConfig, AuditLogTrackerUpdateResult, AuditLogUploadResult,
    BackgroundNotificationCollection, ChatListRow, GroupInviteDeclineResult, GroupPushDebugInfo,
    MAX_SEEN_EVENT_IDS, MarmotApp, MarmotRelayPlane, MarmotServiceEndpoints,
    MediaAttachmentReference, MediaDownloadResult, MediaUploadRequest, MediaUploadResult,
    NotificationCollectionStatus, NotificationSettings, NotificationUpdate, NotificationWakeSource,
    PushPlatform, PushRegistration, ReceivedMessage, RelayTelemetryExportConfig,
    RelayTelemetryRuntimeConfig, RelayTelemetrySettings, SendSummary, TimelineMessageQuery,
    TimelinePage, UserDirectoryRefresh, UserProfileMetadata, default_profile_pseudonym,
    unix_now_seconds,
};

mod account_worker;
mod agent_stream_watch;
mod audit_tracker;
mod commands;
mod event_routing;
mod subscriptions;

// Re-export the public surface so `crate::runtime::Item` and the
// `marmot_app::...` paths in `lib.rs` resolve unchanged after the split.
pub use agent_stream_watch::StreamStartView;
pub use subscriptions::{
    AgentStreamWatchOptions, AgentTextStreamCryptoContext, ChatListUpdateTrigger,
    RuntimeAgentStreamUpdate, RuntimeAgentStreamWatch, RuntimeChatListSubscription,
    RuntimeChatListUpdate, RuntimeChatsSubscription, RuntimeEventsSubscription,
    RuntimeGroupStateSubscription, RuntimeMessagesSubscription, RuntimeNotificationsSubscription,
    RuntimeTimelineMessageUpdate, RuntimeTimelineMessagesSubscription, TimelineWindowHandle,
};

// Bring split-out items the orchestration core references back into scope.
pub(crate) use account_worker::{
    AccountWorkerCommand, AccountWorkerRuntime, ManagedAccountWorker,
    publish_app_runtime_group_state_updated, spawn_app_runtime_account_worker,
};
pub(crate) use audit_tracker::{AuditLogTrackerUploader, post_audit_log_tracker_update_for_app};

// Surface the split-out `pub(crate)` items the test modules reach for: the
// crate-root `src/tests.rs` via `crate::runtime::Item`, and `runtime/tests.rs`
// (a child of this module) via `super::*`. Test-only, so gate them out of the
// production build to avoid unused-import noise.
#[cfg(test)]
pub(crate) use account_worker::AccountWorkerReconnectBackoff;
#[cfg(test)]
pub(crate) use agent_stream_watch::{
    broker_trust_for_addr, latest_agent_stream_start, parse_quic_candidate, parse_quic_candidates,
};
#[cfg(test)]
pub(crate) use subscriptions::{
    TIMELINE_WINDOW_LIMIT, TimelineQueryFn, TimelineSubscriptionSignal, TimelineWindow,
    TimelineWindowEdge, apply_projection_to_window, chat_list_row_fingerprint,
    merge_timeline_window, messages_recovery_query, received_message_update_from_record,
    reconcile_chat_list_snapshot, recovery_row_is_pre_subscription, send_chat_list_remove_update,
};
// External items `runtime/tests.rs` reaches through `super::*` that the
// orchestration core itself no longer references after the split.
#[cfg(test)]
use crate::messages::STREAM_ROUTE_QUIC;
#[cfg(test)]
use crate::{TimelineMessageChange, TimelineMessageRecord};
#[cfg(test)]
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, STREAM_ROUTE_TAG, STREAM_TAG,
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
    app_performance_telemetry: AppPerformanceTelemetry,
    agent_streams: AgentStreamWatchManager,
    lifecycle: RuntimeLifecycle,
    relay_telemetry_exporter: Arc<StdMutex<Option<JoinHandle<()>>>>,
    relay_telemetry_runtime_config: Arc<StdMutex<RelayTelemetryRuntimeConfig>>,
    audit_log_tracker_config: Arc<StdMutex<AuditLogTrackerConfig>>,
    service_endpoints: MarmotServiceEndpoints,
    audit_log_tracker_uploader: Option<AuditLogTrackerUploader>,
}

const MESSAGE_SUBSCRIPTION_SEEN_ID_LIMIT: usize = MAX_SEEN_EVENT_IDS;

#[derive(Debug)]
struct MessageSubscriptionSeenIds {
    ids: HashSet<String>,
    order: VecDeque<String>,
    limit: usize,
}

impl MessageSubscriptionSeenIds {
    fn with_limit(limit: usize) -> Self {
        Self {
            ids: HashSet::new(),
            order: VecDeque::new(),
            limit,
        }
    }

    fn from_ids(ids: impl IntoIterator<Item = String>, limit: usize) -> Self {
        let mut seen = Self::with_limit(limit);
        for id in ids {
            seen.insert(id);
        }
        seen
    }

    fn insert(&mut self, id: String) -> bool {
        if id.is_empty() {
            return true;
        }
        if !self.ids.insert(id.clone()) {
            return false;
        }
        self.order.push_back(id);
        while self.ids.len() > self.limit {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.ids.remove(&oldest);
        }
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.ids.len()
    }

    #[cfg(test)]
    fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }
}

impl Default for RuntimeSharedServices {
    fn default() -> Self {
        Self {
            relay_plane: MarmotRelayPlane::runtime_default(APP_RUNTIME_RELAY_REBUILD_LOOKBACK),
            app_performance_telemetry: AppPerformanceTelemetry::default(),
            agent_streams: AgentStreamWatchManager::default(),
            lifecycle: RuntimeLifecycle::new(),
            relay_telemetry_exporter: Arc::new(StdMutex::new(None)),
            relay_telemetry_runtime_config: Arc::new(StdMutex::new(
                RelayTelemetryRuntimeConfig::default(),
            )),
            audit_log_tracker_config: Arc::new(StdMutex::new(AuditLogTrackerConfig::default())),
            service_endpoints: MarmotServiceEndpoints::default(),
            audit_log_tracker_uploader: None,
        }
    }
}

impl RuntimeSharedServices {
    fn for_app(app: &MarmotApp) -> Self {
        let lifecycle = RuntimeLifecycle::new();
        let audit_log_tracker_config = Arc::new(StdMutex::new(AuditLogTrackerConfig::default()));
        let audit_log_tracker_uploader = AuditLogTrackerUploader::new(
            app.clone(),
            audit_log_tracker_config.clone(),
            lifecycle.clone(),
        );
        Self {
            relay_plane: app.relay_plane.clone(),
            app_performance_telemetry: AppPerformanceTelemetry::default(),
            agent_streams: AgentStreamWatchManager::default(),
            lifecycle,
            relay_telemetry_exporter: Arc::new(StdMutex::new(None)),
            relay_telemetry_runtime_config: Arc::new(StdMutex::new(
                RelayTelemetryRuntimeConfig::default(),
            )),
            audit_log_tracker_config,
            service_endpoints: app.service_endpoints().clone(),
            audit_log_tracker_uploader: Some(audit_log_tracker_uploader),
        }
    }

    pub fn relay_plane(&self) -> &MarmotRelayPlane {
        &self.relay_plane
    }

    pub fn app_performance_telemetry(&self) -> AppPerformanceTelemetry {
        self.app_performance_telemetry.clone()
    }

    pub fn agent_streams(&self) -> AgentStreamWatchManager {
        self.agent_streams.clone()
    }

    pub(crate) fn lifecycle(&self) -> RuntimeLifecycle {
        self.lifecycle.clone()
    }

    fn configure_relay_telemetry_exporter(&self, config: RelayTelemetryExportConfig) {
        self.stop_relay_telemetry_exporter();
        #[cfg(feature = "otlp-export")]
        {
            if let Some(exporter) = self.relay_plane.telemetry_exporter(config) {
                let shutdown = self.lifecycle.subscribe_shutdown();
                let app_performance_telemetry = self.app_performance_telemetry.clone();
                let handle = tokio::spawn(
                    exporter.run_with_app_performance(shutdown, app_performance_telemetry),
                );
                *self
                    .relay_telemetry_exporter
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handle);
            }
        }
        #[cfg(not(feature = "otlp-export"))]
        {
            if config.enabled {
                tracing::warn!(
                    target: "marmot_app::relay_telemetry_export",
                    method = "configure_relay_telemetry_exporter",
                    "relay telemetry export requested, but marmot-app was built without otlp-export",
                );
            }
        }
    }

    fn relay_telemetry_runtime_config(&self) -> RelayTelemetryRuntimeConfig {
        self.relay_telemetry_runtime_config
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn service_endpoints(&self) -> &MarmotServiceEndpoints {
        &self.service_endpoints
    }

    fn set_relay_telemetry_runtime_config(&self, config: RelayTelemetryRuntimeConfig) {
        *self
            .relay_telemetry_runtime_config
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = config;
    }

    fn audit_log_tracker_config(&self) -> AuditLogTrackerConfig {
        self.audit_log_tracker_config
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set_audit_log_tracker_config(&self, config: AuditLogTrackerConfig) {
        *self
            .audit_log_tracker_config
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = config;
    }

    fn stop_relay_telemetry_exporter(&self) {
        if let Some(handle) = self
            .relay_telemetry_exporter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            handle.abort();
        }
    }

    fn schedule_audit_log_tracker_update(&self, trigger: &'static str) {
        if self.lifecycle.is_stopping() {
            tracing::debug!(
                target: "marmot_app::audit_log",
                method = "schedule_audit_log_tracker_update",
                trigger,
                skipped_reason = "runtime_stopping",
                "skipped forensic audit log tracker update"
            );
            return;
        }
        let config = self.audit_log_tracker_config();
        if config.resolved_endpoint(self.service_endpoints()).is_none() {
            tracing::debug!(
                target: "marmot_app::audit_log",
                method = "schedule_audit_log_tracker_update",
                trigger,
                skipped_reason = "audit_log_tracker_endpoint_missing",
                "skipped forensic audit log tracker update"
            );
            return;
        }
        if config
            .authorization_bearer_token
            .as_deref()
            .is_none_or(|token| token.trim().is_empty())
        {
            tracing::debug!(
                target: "marmot_app::audit_log",
                method = "schedule_audit_log_tracker_update",
                trigger,
                skipped_reason = "audit_log_tracker_authorization_token_missing",
                "skipped forensic audit log tracker update"
            );
            return;
        }
        if !config.upload_allowed_with_endpoints(self.service_endpoints()) {
            tracing::debug!(
                target: "marmot_app::audit_log",
                method = "schedule_audit_log_tracker_update",
                trigger,
                skipped_reason = "audit_log_tracker_not_configured",
                "skipped forensic audit log tracker update"
            );
            return;
        }
        if let Some(uploader) = &self.audit_log_tracker_uploader {
            uploader.schedule(trigger);
        }
    }

    async fn shutdown_audit_log_tracker_uploader(&self) {
        if let Some(uploader) = &self.audit_log_tracker_uploader {
            uploader.shutdown().await;
        }
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeLifecycle {
    inner: Arc<RuntimeLifecycleInner>,
}

struct RuntimeLifecycleInner {
    stopping: AtomicBool,
    running: AtomicBool,
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
                running: AtomicBool::new(false),
                stop_tx,
                active_account_opens: AtomicUsize::new(0),
                account_opens_drained: Notify::new(),
            }),
        }
    }

    pub(crate) fn begin_shutdown(&self) -> bool {
        let was_stopping = self.inner.stopping.swap(true, Ordering::AcqRel);
        self.inner.running.store(false, Ordering::Release);
        if !was_stopping {
            self.inner.stop_tx.send_replace(true);
        }
        !was_stopping
    }

    pub(crate) fn mark_running(&self) {
        self.inner.running.store(true, Ordering::Release);
    }

    pub(crate) fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::Acquire) && !self.is_stopping()
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedAccount {
    pub label: String,
    pub account_id_hex: String,
    pub local_signing: bool,
    pub running: bool,
}

/// Structured outcome of [`MarmotAppRuntime::sign_out_and_wipe`].
///
/// Every stage of the destructive sign-out is reported independently so the
/// app can render progress and a partial-failure sheet. The network-bound
/// stages (group leave, KeyPackage deletion) are best-effort and may report
/// per-target failures without aborting the wipe; the local-cleanup stage is
/// all-or-nothing (see the type-level invariant on
/// [`MarmotAppRuntime::sign_out_and_wipe`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipeOutcome {
    /// Number of active MLS groups this account successfully left.
    pub groups_left: u32,
    /// Per-group leave failures. Best-effort: the wipe does not abort on these.
    pub group_leave_failures: Vec<GroupLeaveFailure>,
    /// Number of relay-published KeyPackage events successfully deleted.
    pub key_packages_deleted: u32,
    /// Per-relay KeyPackage deletion failures. Best-effort.
    pub key_package_failures: Vec<RelayFailure>,
    /// Whether the local cleanup stage (MLS DB, media cache, SQL account row,
    /// secret-store nsec, ephemeral relay/subscription state) completed.
    pub local_cleanup: LocalCleanupReport,
}

/// A failed attempt to leave a single MLS group during the wipe.
///
/// `reason` is a privacy-safe, human-readable summary — it MUST NOT contain
/// relay URLs, pubkeys, payloads, or key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupLeaveFailure {
    pub group_id_hex: String,
    pub reason: String,
}

/// A failed relay-side operation (currently KeyPackage deletion) during the
/// wipe. `event_id_hex` identifies the KeyPackage event the deletion targeted
/// (empty when the failure happened during discovery, before any specific
/// event was known) and `reason` is a privacy-safe summary — it MUST NOT
/// contain relay URLs, pubkeys, payloads, or key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayFailure {
    pub event_id_hex: String,
    pub reason: String,
}

/// Local-cleanup stage result. In darkmatter, removing the account directory
/// atomically drops the SQLCipher session database (MLS state + projections),
/// the cached media/source-epoch secrets, the on-disk KeyPackage material, the
/// SQL account record, and the secret-store nsec; the in-memory caches,
/// subscriptions, and the managed account worker are torn down first. The wipe
/// only marks this stage `completed` once that removal returns `Ok`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalCleanupReport {
    /// Whether local cleanup finished. When `false`, `reason` carries the
    /// failure summary and the account ref may still be partially valid.
    pub completed: bool,
    /// Failure summary when `completed` is `false`. Privacy-safe.
    pub reason: Option<String>,
}

/// Map an [`AppError`] to a stable, privacy-safe failure category for the
/// app-facing [`WipeOutcome`] reports.
///
/// The wipe report fields are surfaced to the app (and over FFI) for a
/// partial-failure sheet, so they must obey the same privacy contract as
/// tracing: no relay URLs, pubkeys, group/account/message ids, paths,
/// payloads, ciphertext, plaintext, or key material. Many `AppError` variants
/// wrap transparent transport/storage/IO errors whose `Display` text can embed
/// exactly those identifiers, so we never interpolate `err` here — we classify
/// it into a fixed phrase instead.
fn wipe_failure_reason(err: &AppError) -> String {
    let category = match err {
        AppError::RuntimeStopping => "runtime is shutting down",
        AppError::Transport(_) | AppError::TransportClosed => "transport error",
        AppError::Publish(_) => "relay publish failed",
        AppError::Storage(_) | AppError::Sqlite(_) | AppError::SqlcipherKeyDerivation(_) => {
            "local storage error"
        }
        AppError::Io(_) => "filesystem error",
        AppError::Account(_) | AppError::AccountHome(_) => "account error",
        AppError::Session(_) => "session error",
        AppError::UnknownGroup(_) => "unknown local group",
        AppError::MissingKeyPackage(_) => "no published key package",
        _ => "operation failed",
    };
    category.to_owned()
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

    pub fn display_names_for_account_ids(
        &self,
        account_id_hexes: &[String],
    ) -> Result<HashMap<String, String>, AppError> {
        self.accounts
            .app
            .display_names_for_account_ids(account_id_hexes)
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
        let started_at = Instant::now();
        let result: Result<RelayTelemetryExportConfig, AppError> = async {
            self.shared.lifecycle().ensure_running()?;
            let app = self.accounts.app.clone();
            blocking_app_task(move || app.warm_directory_storage()).await?;
            let config = self
                .accounts
                .app
                .relay_telemetry_settings()?
                .export_config_with_runtime_and_endpoints(
                    self.shared.relay_telemetry_runtime_config(),
                    self.shared.service_endpoints(),
                );
            self.sync_user_directory_subscriptions().await?;
            self.reconcile_accounts().await?;
            self.shared.lifecycle().mark_running();
            Ok(config)
        }
        .await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::AppStart,
            started_at.elapsed(),
            result.is_ok(),
        );
        let config = result?;
        self.shared.configure_relay_telemetry_exporter(config);
        Ok(())
    }

    pub(crate) async fn sync_user_directory_subscriptions(
        &self,
    ) -> Result<DirectorySyncRunSummary, AppError> {
        let started_at = Instant::now();
        let result = async {
            self.shared.lifecycle().ensure_running()?;
            let directory_sync = self.ensure_directory_sync_worker().await;
            directory_sync.request_rebuild_and_wait().await
        }
        .await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::DirectorySubscriptionSync,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
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

    /// Stored groups that failed session-open hydration and were skipped
    /// (darkmatter#151 / #417). Backs the per-group recovery surface
    /// (darkmatter#426).
    pub async fn quarantined_groups(
        &self,
        account_ref: &str,
    ) -> Result<Vec<AppQuarantinedGroup>, AppError> {
        self.accounts.quarantined_groups(account_ref).await
    }

    /// Re-attempt hydration of a single quarantined group (darkmatter#426).
    /// `Ok(true)` if it recovered and is now live, `Ok(false)` if still
    /// unhealthy.
    pub async fn retry_hydrate_quarantined_group(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        self.accounts
            .retry_hydrate_quarantined_group(account_ref, group_id)
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
            .exporter_secret(
                account_ref,
                group_id,
                AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY,
                32,
            )
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

    pub async fn update_group_image(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        plaintext: Vec<u8>,
        media_type: String,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .update_group_image(account_ref, group_id, plaintext, media_type)
            .await
    }

    pub async fn download_group_image(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<u8>, AppError> {
        self.accounts
            .download_group_image(account_ref, group_id)
            .await
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

    pub async fn replace_encrypted_media_blob_endpoints(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        endpoints: Vec<AppBlobEndpoint>,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .replace_encrypted_media_blob_endpoints(account_ref, group_id, endpoints)
            .await
    }

    pub async fn update_group_avatar_url(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        url: Option<String>,
        dim: Option<String>,
        thumbhash: Option<String>,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .update_group_avatar_url(account_ref, group_id, url, dim, thumbhash)
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

    pub async fn send_agent_activity(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        status: String,
        text: String,
        reply_to_message_id: Option<String>,
        extra: Option<serde_json::Value>,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_agent_activity(
                account_ref,
                group_id,
                status,
                text,
                reply_to_message_id,
                extra,
            )
            .await
    }

    pub async fn send_agent_operation_event(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        request: AgentOperationEventRequest,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_agent_operation_event(account_ref, group_id, request)
            .await
    }

    pub async fn send_group_system_event(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        system_type: String,
        text: String,
        data: Option<serde_json::Value>,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_group_system_event(account_ref, group_id, system_type, text, data)
            .await
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

    pub fn relay_telemetry_settings(&self) -> Result<RelayTelemetrySettings, AppError> {
        self.accounts.app.relay_telemetry_settings()
    }

    pub fn telemetry_install_id(&self) -> Result<String, AppError> {
        self.accounts.app.telemetry_install_id()
    }

    pub fn set_relay_telemetry_settings(
        &self,
        settings: RelayTelemetrySettings,
    ) -> Result<RelayTelemetrySettings, AppError> {
        let settings = self.accounts.app.set_relay_telemetry_settings(settings)?;
        if self.shared.lifecycle().is_running() {
            self.shared.configure_relay_telemetry_exporter(
                settings.export_config_with_runtime_and_endpoints(
                    self.shared.relay_telemetry_runtime_config(),
                    self.shared.service_endpoints(),
                ),
            );
        }
        Ok(settings)
    }

    pub fn set_relay_telemetry_runtime_config(
        &self,
        config: RelayTelemetryRuntimeConfig,
    ) -> Result<RelayTelemetryRuntimeConfig, AppError> {
        let config = config
            .normalize()
            .map_err(AppError::InvalidRelayTelemetrySettings)?;
        self.shared
            .set_relay_telemetry_runtime_config(config.clone());
        if self.shared.lifecycle().is_running() {
            let settings = self.accounts.app.relay_telemetry_settings()?;
            self.shared.configure_relay_telemetry_exporter(
                settings.export_config_with_runtime_and_endpoints(
                    config.clone(),
                    self.shared.service_endpoints(),
                ),
            );
        }
        Ok(config)
    }

    pub fn audit_log_settings(&self) -> Result<AuditLogSettings, AppError> {
        self.accounts.app.audit_log_settings()
    }

    /// Persist the local forensic audit-logging switch and apply it to any
    /// already-running sessions in place (no reopen): enabling installs a live
    /// recorder, disabling swaps in a no-op recorder and closes the file.
    pub async fn set_audit_log_settings(
        &self,
        settings: AuditLogSettings,
    ) -> Result<AuditLogSettings, AppError> {
        let previously_enabled = self
            .accounts
            .app
            .audit_log_settings()
            .ok()
            .map(|settings| settings.enabled);
        let stored = self.accounts.app.set_audit_log_settings(settings)?;
        if previously_enabled != Some(stored.enabled) {
            self.accounts
                .apply_audit_recording_to_workers(stored.enabled)
                .await;
        }
        Ok(stored)
    }

    pub fn audit_log_files(&self) -> Result<Vec<AuditLogFile>, AppError> {
        self.accounts.app.audit_log_files()
    }

    pub async fn post_audit_log_file(
        &self,
        path: &str,
        endpoint: &str,
    ) -> Result<AuditLogUploadResult, AppError> {
        self.accounts.app.post_audit_log_file(path, endpoint).await
    }

    pub fn set_audit_log_tracker_config(
        &self,
        config: AuditLogTrackerConfig,
    ) -> Result<AuditLogTrackerConfig, AppError> {
        let config = config.normalize().map_err(AppError::AuditLogUpload)?;
        self.shared.set_audit_log_tracker_config(config.clone());
        Ok(config)
    }

    pub async fn post_audit_log_tracker_update(
        &self,
    ) -> Result<AuditLogTrackerUpdateResult, AppError> {
        let config = self.shared.audit_log_tracker_config();
        post_audit_log_tracker_update_for_app(&self.accounts.app, config).await
    }

    /// Delete one local JSONL audit log file. When a session for the file's
    /// account is live and audit logging is on, the recorder rotates to a fresh
    /// file and keeps recording; otherwise the file is simply removed.
    pub async fn delete_audit_log_file(
        &self,
        path: &str,
    ) -> Result<AuditLogDeleteOutcome, AppError> {
        self.accounts.delete_audit_log_file(path).await
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

    /// Edit a prior message: publish a kind-1010 event whose single `e` tag
    /// references `target_message_id` and whose content is the replacement
    /// text. Authorship is enforced on read (an edit is only honored when its
    /// authenticated author matches the target's author), and the chat-list
    /// preview is intentionally left untouched so an edit doesn't reorder the
    /// conversation list.
    pub async fn edit_message(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        target_message_id: &str,
        content: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Edit {
                    target_message_id: target_message_id.to_owned(),
                    content: content.to_owned(),
                },
            )
            .await
    }

    /// Send a media attachment as a kind-9 chat carrying a NIP-92 `imeta` tag.
    pub async fn send_media_attachments(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        attachments: Vec<MediaAttachmentReference>,
        caption: Option<String>,
    ) -> Result<SendSummary, AppError> {
        let summary = self
            .accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Media {
                    attachments,
                    caption,
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
        reference: MediaAttachmentReference,
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

    /// Destructive sign-out: fully remove the account's footprint from this
    /// device and from the relays the engine controls publishing to.
    ///
    /// Stages run in the order the spec (darkmatter#478) mandates:
    /// 1. Best-effort leave for every active MLS group. Failures are collected
    ///    per group and do not abort the wipe. This MUST happen while MLS state
    ///    still exists — once the session DB is wiped the engine can no longer
    ///    sign leave messages. "Active" here means *locally MLS-joined*, which
    ///    in darkmatter includes groups still marked `pending_confirmation`: an
    ///    incoming Welcome auto-joins MLS state before the user accepts, so a
    ///    pending invite is a real committed membership this device must leave
    ///    (the decline path leaves such groups too). Group-enumeration failures
    ///    are surfaced as a recorded failure rather than silently dropped.
    /// 2. Best-effort delete of every relay-published KeyPackage event, always
    ///    (no toggle), mirroring the `delete_key_package` path.
    /// 3. Local cleanup (stages 3-5 of the spec): tear down the managed worker
    ///    and in-memory caches, then remove the account directory. In darkmatter
    ///    `remove_account` first **atomically renames** the live account
    ///    directory out of the active namespace and only then deletes the
    ///    tombstoned bytes (the SQLCipher session database holding MLS state,
    ///    projections, and cached media/source-epoch secrets, the on-disk
    ///    KeyPackage material, and the SQL account record) plus the secret-store
    ///    nsec. Ephemeral relay/subscription state is held by the worker that was
    ///    just shut down.
    ///
    /// # Invariants
    /// - Stage 3 (local MLS-DB wipe) is all-or-nothing: `remove_account`
    ///   atomically renames the account directory out of the live namespace as
    ///   its single commit point, so the MLS database is never observably left
    ///   partially wiped — a live account either still fully exists (rename not
    ///   done) or is entirely gone (rename done). `local_cleanup.completed` is
    ///   only `false` when that rename never happened (nothing was wiped); once
    ///   it succeeds the wipe completes even if deleting the orphaned tombstone
    ///   bytes later fails.
    /// - After a successful wipe the `account_ref` is no longer valid for any
    ///   further runtime/FFI call.
    /// - Stages 1 and 2 are network-bound; their per-target failures are
    ///   surfaced for the app's partial-failure sheet and never block local
    ///   cleanup.
    pub async fn sign_out_and_wipe(&self, account_ref: &str) -> Result<WipeOutcome, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        if !account.local_signing {
            // A wipe must sign group-leave messages and KeyPackage deletions;
            // a tracked-only (npub) account can do neither, so there is nothing
            // remote to clean up. Surface the same error the worker path uses.
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex).into());
        }

        let mut outcome = WipeOutcome::default();

        // Stage 1: best-effort leave for every active MLS group. We read the
        // group set directly from the in-memory account state (no relay round
        // trip). We attempt the leave for *every* group with local MLS
        // membership, including ones still marked `pending_confirmation`: in
        // darkmatter an incoming Welcome auto-joins MLS state while the app
        // keeps the invite pending until the user accepts, so a
        // pending-confirmation group is already a committed MLS member this
        // device can — and must — leave before its state is wiped (mirroring
        // `decline_group_invite`, which leaves the group before archiving). If
        // we skipped them, signing out before accepting an invite would wipe
        // the local MLS state without ever publishing a leave, and the engine
        // could never sign one afterwards. A failure to enumerate groups is a
        // recorded failure, not a silent "no groups" — it must not let the wipe
        // skip remote leaves without surfacing why.
        let groups = match self.accounts.app.groups(&account.label) {
            Ok(groups) => groups,
            Err(err) => {
                outcome.group_leave_failures.push(GroupLeaveFailure {
                    group_id_hex: String::new(),
                    reason: format!("group discovery failed: {}", wipe_failure_reason(&err)),
                });
                Vec::new()
            }
        };
        for group in groups {
            let group_id_hex = group.group_id_hex.clone();
            let group_id = match hex::decode(&group_id_hex) {
                Ok(bytes) => GroupId::new(bytes),
                Err(_) => {
                    outcome.group_leave_failures.push(GroupLeaveFailure {
                        group_id_hex,
                        reason: "invalid group id".to_owned(),
                    });
                    continue;
                }
            };
            match self.leave_group(account_ref, &group_id).await {
                Ok(_) => outcome.groups_left += 1,
                Err(err) => outcome.group_leave_failures.push(GroupLeaveFailure {
                    group_id_hex,
                    reason: wipe_failure_reason(&err),
                }),
            }
        }

        // Stage 2: delete every relay-published KeyPackage. Discovery itself is
        // network-bound; a discovery failure is recorded as a single failure
        // (no event id) and must not abort the wipe.
        match self.account_key_packages(account_ref, Vec::new()).await {
            Ok(packages) => {
                for package in packages {
                    if !package.relay {
                        continue;
                    }
                    let event_id_hex = package.key_package_event_id.clone();
                    let relays = package
                        .source_relays
                        .iter()
                        .cloned()
                        .map(TransportEndpoint)
                        .collect::<Vec<_>>();
                    match self
                        .delete_key_package(account_ref, &event_id_hex, relays)
                        .await
                    {
                        Ok(_) => outcome.key_packages_deleted += 1,
                        Err(err) => outcome.key_package_failures.push(RelayFailure {
                            event_id_hex,
                            reason: wipe_failure_reason(&err),
                        }),
                    }
                }
            }
            Err(err) => outcome.key_package_failures.push(RelayFailure {
                event_id_hex: String::new(),
                reason: format!(
                    "key package discovery failed: {}",
                    wipe_failure_reason(&err)
                ),
            }),
        }

        // Stages 3-5: local cleanup. `remove_account` shuts the worker down,
        // drops in-memory caches, and removes the account directory (MLS DB,
        // media, KeyPackage material, SQL row) plus the secret-store nsec in a
        // single all-or-nothing step.
        match self.accounts.remove_account(account_ref).await {
            Ok(()) => {
                outcome.local_cleanup = LocalCleanupReport {
                    completed: true,
                    reason: None,
                };
            }
            Err(err) => {
                outcome.local_cleanup = LocalCleanupReport {
                    completed: false,
                    reason: Some(wipe_failure_reason(&err)),
                };
            }
        }

        Ok(outcome)
    }

    pub async fn publish_user_profile(
        &self,
        account_ref: &str,
        mut profile: UserProfileMetadata,
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<UserProfileMetadata, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        // Stamp the just-published profile with the current time before caching
        // it. The published kind-0 event is authored with `now`, so the cached
        // own-account entry must carry a matching `created_at`. Callers that
        // arrive via FFI hardcode `created_at == 0` (see
        // `UserProfileMetadataFfi -> UserProfileMetadata`), and a zero stamp
        // loses to *any* fetched kind-0 in `remember_directory_profile_if_newer`
        // (it only retains the cache when `cached.created_at > fetched`). That
        // let a stale pre-edit copy served by a lagging relay revert the local
        // edit on the next directory refresh. Stamping `now` protects the edit
        // against relay copies published before this moment.
        stamp_published_profile_created_at(&mut profile, unix_now_seconds());
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

    /// Per-account unread aggregate for the account-switcher badge
    /// (darkmatter#461). Computed from each account's materialized chat-list
    /// projection without loading a full session/timeline, so accounts that are
    /// not the active/running one are reported too.
    pub fn account_unread_summary(&self) -> Result<Vec<AccountUnread>, AppError> {
        self.accounts.app.account_unread_summary()
    }

    pub async fn set_group_archived(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        archived: bool,
    ) -> Result<AppGroupRecord, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let group_id_hex = normalize_group_id_hex_app(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        // Route the archive toggle through the account worker so the
        // long-lived in-memory `AccountState` is updated in place. A direct
        // `MarmotApp::set_group_archived` would only touch the database; the
        // worker's stale snapshot (archived = false) would then silently revert
        // it on the next inbound delivery's `save_state`. See darkmatter#178.
        let group = self
            .accounts
            .set_group_archived(account_ref, &group_id, archived)
            .await?;
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
        self.shared.stop_relay_telemetry_exporter();
        if let Some(directory_sync) = self.directory_sync.lock().await.take() {
            directory_sync.shutdown().await;
        }
        self.accounts.app.set_directory_sync_handle(None);
        let accounts = self.accounts.shutdown();
        let relay_plane = self.shared.relay_plane.shutdown();
        tokio::join!(accounts, relay_plane);
        self.shared.shutdown_audit_log_tracker_uploader().await;
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

    fn schedule_audit_log_tracker_update(&self, trigger: &'static str) {
        self.shared.schedule_audit_log_tracker_update(trigger);
    }

    pub async fn remove_account(&self, account_ref: &str) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.app.account_home().account(account_ref)?;
        let mut workers = self.workers.lock().await;
        let worker = workers.remove(&account.account_id_hex);
        if let Some(worker) = worker {
            worker.shutdown().await;
        }
        // Hold the worker map lock until storage is updated so reconcile()
        // cannot recreate this account's worker mid-removal.
        //
        // Evict every in-memory handle and warm flag for this label BEFORE the
        // account directory is deleted. Otherwise the cached account-storage
        // connection (and directory cache) keeps pointing at the unlinked inode
        // and a later re-import silently splits writes across a stale handle.
        self.app.drop_account_caches(&account.label);
        self.app.account_home().remove_account(&account.label)?;
        Ok(())
    }

    pub async fn reconcile(&self) -> Result<(), AppError> {
        let started_at = Instant::now();
        let result = async {
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
                            shared: self.shared.clone(),
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
                    ready_receivers.push((Instant::now(), ready_rx));
                }
            }
            let mut ready_waits = JoinSet::new();
            for (account_started_at, ready) in ready_receivers {
                ready_waits.spawn(async move {
                    let ready_result = timeout(APP_RUNTIME_ACCOUNT_READY_WAIT, ready).await;
                    (account_started_at.elapsed(), ready_result)
                });
            }
            while let Some(joined) = ready_waits.join_next().await {
                let (account_open_elapsed, ready_result) = joined.map_err(|err| {
                    AppError::BlockingTask(format!("account worker readiness wait failed: {err}"))
                })?;
                self.shared.app_performance_telemetry().record(
                    AppPerformanceOperation::AccountOpen,
                    account_open_elapsed,
                    matches!(ready_result, Ok(Ok(Ok(())))),
                );
                match ready_result {
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
        .await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::AccountReconcile,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
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
        let started_at = Instant::now();
        let result = async {
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
        .await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::AccountCatchUp,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
    }

    /// Delete one local JSONL audit log file.
    ///
    /// If the owning account has a running worker whose live recorder is
    /// appending to this exact file, the recorder is rotated — the file is
    /// deleted and a fresh one is reopened — so the held file handle is never
    /// orphaned and (when audit logging is on) recording continues. Otherwise
    /// the file is removed directly. The returned outcome reports whether
    /// recording continues into a fresh file.
    pub async fn delete_audit_log_file(
        &self,
        path: &str,
    ) -> Result<AuditLogDeleteOutcome, AppError> {
        let (path, owner_account_id_hex) = self.app.resolve_audit_log_path(path)?;
        if let Some(account_id_hex) = owner_account_id_hex {
            let commands = {
                let workers = self.workers.lock().await;
                workers
                    .get(&account_id_hex)
                    .map(|worker| worker.commands.clone())
            };
            if let Some(commands) = commands {
                let (respond, response) = oneshot::channel();
                // A send error means the worker channel is closed, so its
                // session — and thus any file handle — is gone; fall through to
                // a direct removal, which is then safe.
                if commands
                    .send(AccountWorkerCommand::DeleteAuditLog {
                        path: path.clone(),
                        respond,
                    })
                    .await
                    .is_ok()
                    && account_worker_response(response).await?
                {
                    // The live recorder owned this file and rotated it: old
                    // file gone, fresh file already recording.
                    return Ok(AuditLogDeleteOutcome {
                        still_recording: true,
                    });
                }
                // Otherwise the worker's recorder does not append here (audit
                // logging off, or a stale file): fall through to a direct
                // removal below.
            }
        }
        self.app.remove_audit_log_file(&path)?;
        Ok(AuditLogDeleteOutcome {
            still_recording: false,
        })
    }

    /// Apply the audit-logging switch to every running account worker by
    /// hot-swapping its recorder in place.
    ///
    /// Best-effort: workers that are not running pick the setting up at their
    /// next open, and per-worker send/response failures are ignored (the
    /// recorder is a non-fatal debug aid). The global flag is already persisted
    /// by the caller; this only updates live sessions.
    async fn apply_audit_recording_to_workers(&self, enabled: bool) {
        let commands = {
            let workers = self.workers.lock().await;
            workers
                .values()
                .map(|worker| worker.commands.clone())
                .collect::<Vec<_>>()
        };
        for command in commands {
            let (respond, response) = oneshot::channel();
            if command
                .send(AccountWorkerCommand::SetAuditRecording { enabled, respond })
                .await
                .is_ok()
            {
                let _ = response.await;
            }
        }
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
        // Setup probes (e.g. `status()`) may have already cached this account's
        // storage/directory handles. Evict them before the directory is deleted
        // so a later re-import does not reuse a handle bound to the now-unlinked
        // inode. See `drop_account_caches` and darkmatter#220.
        self.app.drop_account_caches(account);
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

pub(crate) async fn account_worker_response<T>(
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

/// Stamp a just-published profile's `created_at` so the locally cached
/// own-account entry is protected against stale relay copies.
///
/// FFI callers construct `UserProfileMetadata` with `created_at == 0` (the
/// `From<UserProfileMetadataFfi>` impl hardcodes it). Caching a zero stamp via
/// `remember_directory_profile` makes the entry lose to *any* fetched kind-0 in
/// `remember_directory_profile_if_newer`, which only keeps the cache when
/// `cached.created_at > fetched.created_at`. A `now` stamp matches the authored
/// kind-0 event and keeps the local edit visible until the new event
/// propagates. Callers that already carry a non-zero `created_at` (e.g. the
/// default-profile path) are left untouched.
fn stamp_published_profile_created_at(profile: &mut UserProfileMetadata, now: u64) {
    if profile.created_at == 0 {
        profile.created_at = now;
    }
}

#[cfg(test)]
mod tests;
