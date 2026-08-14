use zeroize::Zeroizing;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY;
use cgka_traits::app_event::MarmotAppEvent as MarmotInnerEvent;
use cgka_traits::engine::GroupEvent;
use cgka_traits::storage::{KeyPackageBundleStorage, MaintenanceStorage};
use cgka_traits::transport_adapter::TransportEndpointRejectionCategory;
use cgka_traits::{GroupId, SecretBytes, TransportAdapterError, TransportEndpoint};
use marmot_account::{
    AccountHome, AccountHomeError, AccountSetupKind, AccountSetupPhase, AccountSummary,
    NostrAccountImport,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::agent_streams::AgentStreamWatchManager;
use crate::app_telemetry::{
    AppPerformanceOperation, AppPerformanceTelemetry, bounded_advisory_step,
};
use crate::directory::DirectorySyncHandle;
use crate::ids::normalize_group_id_hex_app;
use crate::messages::AppMessageIntent;
use crate::notifications;
use crate::{
    ACCOUNT_SETUP_ADVISORY_WAIT, APP_RUNTIME_ACCOUNT_READY_WAIT, APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT,
    APP_RUNTIME_RELAY_REBUILD_LOOKBACK, AccountKeyPackageRecord, AccountRelayListBootstrap,
    AccountRelayListStatus, AccountUnread, AgentOperationEventRequest,
    AgentTextStreamFinishRequest, AppBlobEndpoint, AppDisbandRequest, AppError,
    AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord, AppGroupRoster, AppMessageQuery,
    AppMessageRecord, AppProjectionUpdate, AppQuarantinedGroup, AuditLogDeleteOutcome,
    AuditLogFile, AuditLogSettings, AuditLogTrackerConfig, AuditLogTrackerUpdateResult,
    AuditLogUploadResult, BackgroundNotificationCollection, ChatListRow, ChatNotificationSettings,
    ChatPinState, GroupInviteDeclineResult, GroupPushDebugInfo, KeyPackageDeletionResult,
    KeyPackageDeletionTarget, MAX_SEEN_EVENT_IDS, MarmotApp, MarmotRelayPlane,
    MarmotServiceEndpoints, MediaAttachmentReference, MediaDownloadResult, MediaUploadRequest,
    MediaUploadResult, MessageDraft, MessageDraftAttachment, MessageDraftSummary,
    NotificationCollectionStatus, NotificationSettings, NotificationUpdate, NotificationWakeSource,
    PendingWelcomeDelivery, PushPlatform, PushRegistration, PushRegistrationShareOutcome,
    PushRegistrationSyncResult, ReceivedMessage, RelayTelemetryExportConfig,
    RelayTelemetryRuntimeConfig, RelayTelemetrySettings, RetentionSweepReport,
    SecureDeleteExpiredResult, SendSummary, TimelineMessageQuery, TimelineMessageRecord,
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
pub(crate) use account_worker::{
    AccountWorkerReconnectBackoff, STARTUP_HYDRATION_BATCH_SIZE_FOR_TEST,
};
#[cfg(test)]
pub(crate) use agent_stream_watch::{
    broker_trust_for_candidate, latest_agent_stream_start, parse_quic_candidate,
    parse_quic_candidates,
};
#[cfg(test)]
pub(crate) use subscriptions::{
    TIMELINE_WINDOW_LIMIT, TimelineQueryFn, TimelineSubscriptionSignal, TimelineWindow,
    TimelineWindowEdge, apply_projection_to_window, chat_list_row_fingerprint,
    merge_timeline_window_with_order, messages_recovery_query, received_message_update_from_record,
    reconcile_chat_list_snapshot, recovery_row_is_pre_subscription, send_atomic_chat_list_snapshot,
    send_chat_list_remove_update,
};
// External items `runtime/tests.rs` reaches through `super::*` that the
// orchestration core itself no longer references after the split.
#[cfg(test)]
use crate::TimelineMessageChange;
#[cfg(test)]
use crate::messages::STREAM_ROUTE_QUIC;
#[cfg(test)]
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, STREAM_ROUTE_TAG, STREAM_TAG,
};

#[derive(Clone)]
pub struct MarmotAppRuntime {
    events: broadcast::Sender<MarmotAppEvent>,
    shared: RuntimeSharedServices,
    accounts: AccountManager,
    follow_list_updates: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    directory_sync: Arc<Mutex<Option<DirectorySyncHandle>>>,
    initial_directory_sync: Arc<Mutex<Option<JoinHandle<()>>>>,
}

#[derive(Clone)]
pub struct AccountManager {
    app: MarmotApp,
    events: broadcast::Sender<MarmotAppEvent>,
    shared: RuntimeSharedServices,
    workers: Arc<Mutex<HashMap<String, ManagedAccountWorker>>>,
    tearing_down: Arc<StdMutex<HashSet<String>>>,
    worker_transactions: Arc<Mutex<()>>,
    #[cfg(test)]
    reconcile_rollback_waiters: Arc<StdMutex<Vec<std::sync::mpsc::Sender<()>>>>,
    invite_catch_up_tasks: Arc<StdMutex<InviteCatchUpTasks>>,
}

struct InviteCatchUpTasks {
    accepting: bool,
    handles: Vec<JoinHandle<()>>,
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
    /// Test-only barrier the detached post-create-group catch-up waits on, so
    /// integration tests can observe the caller boundary without depending on
    /// scheduler timing. Consulted only with the `test-policy-overrides`
    /// feature; always `None` in production.
    create_group_catch_up_barrier: Arc<StdMutex<Option<Arc<tokio::sync::Notify>>>>,
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

    /// Apply the shared live/recovery subscription dedupe rule. Empty ids are
    /// emitted without entering the seen set, so one malformed update cannot
    /// suppress later distinct updates that also lack a canonical id.
    fn should_emit(&mut self, id: String) -> bool {
        id.is_empty() || self.insert(id)
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
            create_group_catch_up_barrier: Arc::new(StdMutex::new(None)),
        }
    }
}

impl RuntimeSharedServices {
    fn for_app(app: &MarmotApp) -> Self {
        let lifecycle = RuntimeLifecycle::new();
        let audit_log_tracker_config = app.audit_log_tracker_config.clone();
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
            create_group_catch_up_barrier: Arc::new(StdMutex::new(None)),
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

    /// Test-only hook: install the barrier the detached post-create-group
    /// catch-up waits on before touching account workers. Honored only with
    /// the `test-policy-overrides` feature. Not a production entry point;
    /// hidden from the public API docs.
    #[doc(hidden)]
    pub fn set_create_group_catch_up_barrier(&self, barrier: Option<Arc<tokio::sync::Notify>>) {
        *self.create_group_catch_up_barrier.lock().unwrap() = barrier;
    }

    fn create_group_catch_up_barrier(&self) -> Option<Arc<tokio::sync::Notify>> {
        self.create_group_catch_up_barrier.lock().unwrap().clone()
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
            loop {
                // `notify_waiters` does not retain a permit. Register the
                // waiter before observing the counter so the final account
                // open cannot finish in between the check and registration.
                let notified = self.inner.account_opens_drained.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.active_account_opens() == 0 {
                    break;
                }
                notified.await;
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
    pub external_signing: bool,
    pub signed_out: bool,
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

/// Local-cleanup stage result. In mdk, removing the account directory
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

/// Options for the non-destructive sign-out path
/// ([`MarmotAppRuntime::sign_out`]).
///
/// Unlike the destructive [`MarmotAppRuntime::sign_out_and_wipe`], a plain
/// sign-out keeps the encrypted local databases (app SQL + MLS state) and the
/// secret-store nsec on device so the same identity can be re-activated from
/// the account picker with its groups, history, and drafts intact
/// (mdk#477, parent mdk-android#347).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOutOptions {
    /// Publish kind:5 deletions for every relay-published KeyPackage of this
    /// account so strangers cannot pull a stale KeyPackage and gift-wrap a
    /// Welcome into a group while the account is signed out. Defaults to
    /// `true`; the app exposes it as a toggle in the sign-out sheet.
    pub delete_key_packages: bool,
}

impl Default for SignOutOptions {
    fn default() -> Self {
        // Relay key-package hygiene is on by default per the issue spec; the
        // app may still surface a toggle to turn it off.
        Self {
            delete_key_packages: true,
        }
    }
}

/// Structured result of the non-destructive [`MarmotAppRuntime::sign_out`].
///
/// `local_cleanup` reports the always-run teardown of the managed worker,
/// active subscriptions, and in-memory caches — it does NOT remove the account
/// directory, MLS state DB, or secret-store nsec (that is the destructive
/// [`WipeOutcome`] path). The KeyPackage-deletion counters mirror the wipe
/// outcome's shape so the app can render the same per-relay partial-failure
/// sheet.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOutOutcome {
    /// Number of relay-published KeyPackage events successfully deleted. Always
    /// `0` when `delete_key_packages` was `false`.
    pub key_packages_deleted: u32,
    /// Per-relay KeyPackage deletion (or discovery) failures. Best-effort: a
    /// failure here never blocks local cleanup. No durable remote-deletion
    /// retry is implied by this outcome.
    pub key_package_failures: Vec<RelayFailure>,
    /// Result of the always-run local teardown (worker shutdown, subscription
    /// deactivation, in-memory cache eviction). Unlike a wipe this never
    /// deletes on-disk state, so `completed` is `true` whenever the teardown
    /// ran; `reason` carries a privacy-safe summary on the rare failure.
    pub local_cleanup: LocalCleanupReport,
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
        AppError::Transport(transport) => {
            if let Some(reason) = transport_publish_endpoint_failures_app_reason(transport) {
                return reason;
            }
            if matches!(transport, TransportAdapterError::PublishEndpoints(_)) {
                return "relay publish failed".to_owned();
            }
            return "transport error".to_owned();
        }
        AppError::TransportClosed => "transport error",
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

fn transport_rejection_category_app_reason(
    category: Option<TransportEndpointRejectionCategory>,
) -> String {
    match category {
        Some(category) => format!("relay rejected event ({})", category.as_str()),
        None => "relay publish failed".to_owned(),
    }
}

fn transport_publish_endpoint_failures_app_reason(
    transport: &TransportAdapterError,
) -> Option<String> {
    let failures = transport.publish_endpoint_failures();
    if failures.is_empty() {
        return None;
    }
    let mut unique = Vec::new();
    for failure in failures {
        let reason = transport_rejection_category_app_reason(failure.rejection_category);
        if !unique.contains(&reason) {
            unique.push(reason);
        }
    }
    Some(unique.join("; "))
}

fn relay_failures_from_key_package_deletion_results(
    results: Vec<KeyPackageDeletionResult>,
) -> (u32, Vec<RelayFailure>) {
    let mut deleted = 0;
    let mut failures = Vec::new();
    for result in results {
        match result.result {
            Ok(accepted) if accepted > 0 => deleted += 1,
            Ok(_) => failures.push(RelayFailure {
                event_id_hex: result.event_id_hex,
                reason: "relay publish failed".to_owned(),
            }),
            Err(error) => failures.push(RelayFailure {
                event_id_hex: result.event_id_hex,
                reason: wipe_failure_reason(&error),
            }),
        }
    }
    (deleted, failures)
}

#[derive(Default, PartialEq, Eq)]
pub struct AccountSetupRequest {
    /// Public `npub` / hex identity for import. Never holds an `nsec`.
    pub identity: Option<String>,
    /// Private key material for local account import. Moved into setup, not cloned.
    pub import_nsec: Option<Zeroizing<String>>,
    pub default_relays: Vec<TransportEndpoint>,
    pub bootstrap_relays: Vec<TransportEndpoint>,
    pub discovery_relays: Vec<TransportEndpoint>,
    pub publish_missing_relay_lists: bool,
    pub publish_initial_key_package: bool,
}

impl std::fmt::Debug for AccountSetupRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountSetupRequest")
            .field("identity", &debug_identity_field(&self.identity))
            .field(
                "import_nsec",
                &self
                    .import_nsec
                    .as_ref()
                    .map(|_| &"**redacted**" as &dyn std::fmt::Debug),
            )
            .field("default_relays", &self.default_relays)
            .field("bootstrap_relays", &self.bootstrap_relays)
            .field("discovery_relays", &self.discovery_relays)
            .field(
                "publish_missing_relay_lists",
                &self.publish_missing_relay_lists,
            )
            .field(
                "publish_initial_key_package",
                &self.publish_initial_key_package,
            )
            .finish()
    }
}

impl AccountSetupRequest {
    /// Copies relay and publish options for another setup attempt.
    ///
    /// **Clears** [`Self::identity`] and [`Self::import_nsec`]; use only when
    /// starting a fresh account setup with the same relay configuration.
    pub fn relay_options_only(&self) -> Self {
        Self {
            identity: None,
            import_nsec: None,
            default_relays: self.default_relays.clone(),
            bootstrap_relays: self.bootstrap_relays.clone(),
            discovery_relays: self.discovery_relays.clone(),
            publish_missing_relay_lists: self.publish_missing_relay_lists,
            publish_initial_key_package: self.publish_initial_key_package,
        }
    }
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
    /// A confirmed create/invite could not deliver a welcome to `recipient_hex`;
    /// the member is in the group but unjoinable until the welcome is
    /// re-delivered (mdk#352). Emitted so a UI/CLI/UniFFI subscriber learns a
    /// member needs repair without polling `pending_welcome_deliveries`. The
    /// durable record backs a later `redeliver_welcome(message_id_hex)`.
    WelcomeDeliveryPending {
        account_id_hex: String,
        account_label: String,
        group_id: GroupId,
        message_id_hex: String,
        recipient_hex: String,
    },
    /// This device has armed `arms` epoch-gap backfills for `group_id` without
    /// catching up: it is still stalled at `stalled_epoch` while the group has
    /// moved on, and full-history replay is not repairing it. Emitted once per
    /// unrecovered run (see [`crate::EpochStallEscalation`]) so a UI/CLI/UniFFI
    /// subscriber can surface "this group cannot catch up; re-syncing is
    /// recommended" and offer the stronger repair — rotating this device's key
    /// package and re-activating transport. MDK reports; the app decides.
    EpochStallEscalated {
        account_id_hex: String,
        account_label: String,
        group_id: GroupId,
        stalled_epoch: u64,
        arms: u32,
    },
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
            follow_list_updates: Arc::new(Mutex::new(HashMap::new())),
            directory_sync: Arc::new(Mutex::new(None)),
            initial_directory_sync: Arc::new(Mutex::new(None)),
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

    /// Record the fixed app-performance sample for the UniFFI
    /// `groupDetails` DTO builder.
    pub fn record_group_details_read(&self, duration: Duration, success: bool) {
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::GroupDetailsRead,
            duration,
            success,
        );
    }

    pub fn is_stopping(&self) -> bool {
        self.shared.lifecycle().is_stopping()
    }

    /// Starts the runtime through local account readiness.
    ///
    /// A successful return guarantees that persisted account state is
    /// hydrated and worker-routed local reads are available. Relay activation,
    /// group-subscription registration, directory synchronization, and initial
    /// catch-up continue asynchronously after this method returns.
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
        self.schedule_user_directory_subscription_sync().await;
        Ok(())
    }

    async fn schedule_user_directory_subscription_sync(&self) {
        let directory_sync = self.ensure_directory_sync_worker().await;
        let telemetry = self.shared.app_performance_telemetry();
        let handle = tokio::spawn(async move {
            let started_at = Instant::now();
            let result = directory_sync.request_rebuild_and_wait().await;
            telemetry.record(
                AppPerformanceOperation::DirectorySubscriptionSync,
                started_at.elapsed(),
                result.is_ok(),
            );
            if let Err(error) = result {
                tracing::warn!(
                    target: "marmot_app::runtime",
                    method = "schedule_user_directory_subscription_sync",
                    error_kind = error.privacy_safe_kind(),
                    "initial directory subscription sync deferred after startup"
                );
            }
        });
        let previous = self.initial_directory_sync.lock().await.replace(handle);
        if let Some(previous) = previous {
            previous.abort();
            let _ = previous.await;
        }
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

    pub async fn sign_in_account(&self, account_ref: &str) -> Result<ManagedAccount, AppError> {
        self.accounts.sign_in_account(account_ref).await
    }

    pub async fn catch_up_accounts(&self) -> Result<(), AppError> {
        self.accounts.catch_up_accounts().await
    }

    /// Explicitly repair a potentially incomplete incremental history.
    ///
    /// This public application operation performs one account-wide
    /// full-history relay query and uses the same ingest, convergence, and
    /// projection path as ordinary catch-up. It is intended for user- or
    /// diagnostics-directed repair; normal startup remains cursor-based.
    pub async fn repair_full_history(&self, account_ref: &str) -> Result<(), AppError> {
        self.accounts.repair_full_history(account_ref).await
    }

    pub async fn collect_notifications_after_wake(
        &self,
        max_wait_ms: u32,
        _source: NotificationWakeSource,
    ) -> BackgroundNotificationCollection {
        let max_wait = Duration::from_millis(u64::from(max_wait_ms.max(1)));
        let started = Instant::now();
        let recovery_watermark = notifications::unix_now_seconds();
        let mut events = self.events.subscribe();
        let catch_up = timeout(max_wait, self.catch_up_accounts()).await;
        let remaining = max_wait.saturating_sub(started.elapsed());
        match catch_up {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                // Catch-up failed, but events already published into this
                // receiver must still be projected so a partial ingest is not
                // discarded as an empty failure.
                let drained = drain_wake_notification_events(&mut events, Duration::ZERO).await;
                let notifications = project_wake_notification_events(
                    self.accounts.app.clone(),
                    drained,
                    Some(recovery_watermark),
                )
                .await
                .unwrap_or_default();
                if notifications.is_empty() {
                    return BackgroundNotificationCollection {
                        status: NotificationCollectionStatus::Failed,
                        notifications: Vec::new(),
                        error: Some(err.to_string()),
                    };
                }
                return BackgroundNotificationCollection {
                    status: NotificationCollectionStatus::NewData,
                    notifications,
                    error: None,
                };
            }
            Err(_) => {
                // Catch-up timed out, but events already published into this
                // receiver must still be projected. A background wake often
                // exhausts its budget on cold sockets after messages have
                // already landed.
                let drained = drain_wake_notification_events(&mut events, Duration::ZERO).await;
                let notifications = project_wake_notification_events(
                    self.accounts.app.clone(),
                    drained,
                    Some(recovery_watermark),
                )
                .await
                .unwrap_or_default();
                let timed_out = notifications.is_empty();
                return BackgroundNotificationCollection {
                    status: if timed_out {
                        NotificationCollectionStatus::Failed
                    } else {
                        NotificationCollectionStatus::NewData
                    },
                    notifications,
                    error: timed_out.then(|| "notification wake collection timed out".into()),
                };
            }
        }

        let drained = drain_wake_notification_events(&mut events, remaining).await;
        let notifications = project_wake_notification_events(
            self.accounts.app.clone(),
            drained,
            Some(recovery_watermark),
        )
        .await
        .unwrap_or_default();
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

    /// Create a locally canonical group. A successful return does not imply
    /// every invitation Welcome was delivered; subscribe for
    /// [`MarmotAppEvent::WelcomeDeliveryPending`] or query
    /// [`Self::pending_welcome_deliveries`] before presenting invite success.
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

    pub async fn create_group_with_initial_image(
        &self,
        account_ref: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
        initial_image: Option<crate::AppInitialGroupImage>,
    ) -> Result<GroupId, AppError> {
        self.accounts
            .create_group_with_initial_image(account_ref, name, members, description, initial_image)
            .await
    }

    /// Accounts the searcher currently shares a group with.
    ///
    /// Feeds [`UserSearchParams::radius_one_seeds`]: sharing a group is social
    /// proximity even when neither person has followed the other. It lives here
    /// rather than in the directory because membership is live MLS state held
    /// by the per-account worker, so reading it needs a running runtime —
    /// keeping it out of `MarmotApp::search_users` is what lets search stay a
    /// pure function of its parameters.
    ///
    /// Only groups the local account is still a member of contribute, so a
    /// group left, declined, or not yet accepted brings nobody. Archived
    /// groups do contribute: archival is a presentation choice, not a change
    /// in who you know.
    pub async fn group_co_members(&self, account_ref: &str) -> Result<Vec<String>, AppError> {
        self.accounts.group_co_members(account_ref).await
    }

    pub async fn group_members(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        self.accounts.group_members(account_ref, group_id).await
    }

    /// Identifier-only membership for a bounded page of groups, served in one
    /// per-account worker command without profile enrichment.
    pub async fn group_member_ids_page(
        &self,
        account_ref: &str,
        group_ids: &[GroupId],
    ) -> Result<Vec<crate::AppGroupMemberIds>, AppError> {
        self.accounts
            .group_member_ids_page(account_ref, group_ids)
            .await
    }

    /// Count groups the worker session has seeded but not fully hydrated,
    /// without issuing a read that would promote them (mdk#1337).
    #[cfg(test)]
    pub(crate) async fn unhydrated_group_count_for_test(
        &self,
        account_ref: &str,
    ) -> Result<usize, AppError> {
        self.accounts
            .unhydrated_group_count_for_test(account_ref)
            .await
    }

    pub async fn group_mls_state(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupMlsState, AppError> {
        self.accounts.group_mls_state(account_ref, group_id).await
    }

    pub async fn group_roster(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppGroupRoster, AppError> {
        let started_at = Instant::now();
        let result = self.accounts.group_roster(account_ref, group_id).await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::GroupRosterRead,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
    }

    pub async fn enable_group_disbanding(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .enable_group_disbanding(account_ref, group_id)
            .await
    }

    pub async fn disband_group(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<AppDisbandRequest, AppError> {
        self.accounts.disband_group(account_ref, group_id).await
    }

    pub async fn acknowledge_disband_failure(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        self.accounts
            .acknowledge_disband_failure(account_ref, group_id)
            .await
    }

    /// Stored groups that failed session-open hydration and were skipped
    /// (mdk#151 / #417). Backs the per-group recovery surface
    /// (mdk#426).
    pub async fn quarantined_groups(
        &self,
        account_ref: &str,
    ) -> Result<Vec<AppQuarantinedGroup>, AppError> {
        self.accounts.quarantined_groups(account_ref).await
    }

    /// Re-attempt hydration of a single quarantined group (mdk#426).
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

    /// See [`MarmotApp::reveal_nsec`]. mdk#543. `caller_context` is the
    /// privacy-safe surface label recorded in the reveal audit entry.
    pub fn reveal_nsec(
        &self,
        account_ref: &str,
        caller_context: &str,
    ) -> Result<Zeroizing<String>, AppError> {
        self.accounts.reveal_nsec(account_ref, caller_context)
    }

    /// See [`MarmotApp::export_encrypted_secret_key`]. mdk#544.
    /// `caller_context` is the privacy-safe surface label recorded in the
    /// encrypted-export audit entry.
    pub fn export_encrypted_secret_key(
        &self,
        account_ref: &str,
        passphrase: &str,
        caller_context: &str,
    ) -> Result<String, AppError> {
        self.accounts
            .export_encrypted_secret_key(account_ref, passphrase, caller_context)
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

    pub async fn delete_group_local(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        self.accounts
            .delete_group_local(account_ref, group_id)
            .await
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

    pub async fn download_group_blossom_image(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<Vec<u8>, AppError> {
        self.accounts
            .download_group_blossom_image(account_ref, group_id)
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

    pub async fn share_push_registration(
        &self,
        account_ref: &str,
    ) -> Result<PushRegistrationShareOutcome, AppError> {
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

    pub fn chat_notification_settings(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<ChatNotificationSettings, AppError> {
        self.accounts
            .app
            .chat_notification_settings(account_ref, group_id_hex)
    }

    pub fn message_drafts(&self, account_ref: &str) -> Result<Vec<MessageDraftSummary>, AppError> {
        self.accounts.app.message_drafts(account_ref)
    }

    pub fn message_draft(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<Option<MessageDraft>, AppError> {
        self.accounts.app.message_draft(account_ref, group_id_hex)
    }

    pub fn save_message_draft(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        content: &str,
        reply_to_message_id_hex: Option<&str>,
        media_attachments: Vec<MessageDraftAttachment>,
    ) -> Result<MessageDraft, AppError> {
        self.accounts.app.save_message_draft(
            account_ref,
            group_id_hex,
            content,
            reply_to_message_id_hex,
            media_attachments,
        )
    }

    pub fn delete_message_draft(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<(), AppError> {
        self.accounts
            .app
            .delete_message_draft(account_ref, group_id_hex)
    }

    pub fn relay_telemetry_settings(&self) -> Result<RelayTelemetrySettings, AppError> {
        self.accounts.app.relay_telemetry_settings()
    }

    pub fn telemetry_install_id(&self) -> Result<String, AppError> {
        self.accounts.app.telemetry_install_id()
    }

    /// Record a duration measured by the host application for one of MDK's
    /// approved, low-cardinality performance milestones.
    pub fn record_host_performance(
        &self,
        operation: crate::HostPerformanceOperation,
        duration: Duration,
        outcome: crate::HostPerformanceOutcome,
    ) {
        self.shared
            .app_performance_telemetry()
            .record_host_performance(operation, duration, outcome);
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
        let previous = self.accounts.app.audit_log_settings().ok();
        let stored = self.accounts.app.set_audit_log_settings(settings)?;
        let enabled_changed = previous.as_ref().map(|s| s.enabled) != Some(stored.enabled);
        let mode_changed = previous.as_ref().map(|s| s.data_mode) != Some(stored.data_mode);
        if enabled_changed {
            // Toggling recording rebuilds the recorder, which opens in the
            // currently-persisted data mode — so this also applies a concurrent
            // mode change when enabling.
            self.accounts
                .apply_audit_recording_to_workers(stored.enabled)
                .await;
        } else if mode_changed && stored.enabled {
            // Recording stayed on but the mode changed: rotate the live
            // recorder so the file gets a clean mode boundary.
            self.accounts
                .apply_audit_data_mode_to_workers(stored.data_mode)
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
        self.accounts.app.set_audit_log_tracker_config(config)
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

    pub fn set_chat_muted(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        muted_until_ms: Option<i64>,
    ) -> Result<ChatNotificationSettings, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let settings =
            self.accounts
                .app
                .set_chat_muted(&account.label, group_id_hex, muted_until_ms)?;
        let row = self
            .accounts
            .app
            .refresh_chat_list_row(&account.label, group_id_hex)?;
        self.publish_chat_list_projection_update(
            account.account_id_hex,
            account.label,
            group_id_hex.to_owned(),
            row,
            ChatListUpdateTrigger::MuteChanged,
        );
        Ok(settings)
    }

    pub fn clear_chat_muted(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<ChatNotificationSettings, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let settings = self
            .accounts
            .app
            .clear_chat_muted(&account.label, group_id_hex)?;
        let row = self
            .accounts
            .app
            .refresh_chat_list_row(&account.label, group_id_hex)?;
        self.publish_chat_list_projection_update(
            account.account_id_hex,
            account.label,
            group_id_hex.to_owned(),
            row,
            ChatListUpdateTrigger::MuteChanged,
        );
        Ok(settings)
    }

    pub async fn set_native_push_enabled(
        &self,
        account_ref: &str,
        enabled: bool,
    ) -> Result<NotificationSettings, AppError> {
        self.accounts
            .set_native_push_enabled(account_ref, enabled)
            .await
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
    ) -> Result<PushRegistrationSyncResult, AppError> {
        self.accounts
            .upsert_push_registration(
                account_ref,
                platform,
                raw_token,
                server_pubkey_hex,
                relay_hint,
            )
            .await
    }

    pub async fn clear_push_registration(
        &self,
        account_ref: &str,
    ) -> Result<PushRegistrationShareOutcome, AppError> {
        self.accounts.clear_push_registration(account_ref).await
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
        self.unreact_from_message_matching(account_ref, group_id, target_message_id, None)
            .await
    }

    pub async fn unreact_from_message_matching(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        target_message_id: &str,
        emoji: Option<&str>,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group_id,
                AppMessageIntent::Unreact {
                    target_message_id: target_message_id.to_owned(),
                    emoji: emoji.map(str::to_owned),
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

    /// Build an authenticated `imeta` tag for an optimistic host-side record
    /// without publishing it. The account worker derives the target group's
    /// media profile and rejects a reference from the other media version.
    pub async fn build_media_imeta_tag(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        reference: MediaAttachmentReference,
    ) -> Result<Vec<String>, AppError> {
        self.accounts
            .build_media_imeta_tag(account_ref, group_id, reference)
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

    /// Securely scrub and prune expired disappearing-message plaintext for this
    /// group. The returned media hashes are the encrypted blob identifiers from
    /// pruned media messages, for host-side decrypted-cache purges.
    pub async fn secure_delete_expired_plaintext(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<SecureDeleteExpiredResult, AppError> {
        self.accounts
            .secure_delete_expired_plaintext(account_ref, group_id)
            .await
    }

    /// Apply the engine-owned disappearing-message sweep policy to every
    /// retention-enabled group in one account. `now_ms` is supplied by the host
    /// scheduler so skew handling and tests use one deterministic clock value.
    pub async fn sweep_expired_retention(
        &self,
        account_ref: &str,
        now_ms: u64,
    ) -> Result<RetentionSweepReport, AppError> {
        self.accounts
            .sweep_expired_retention(account_ref, now_ms)
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

    /// Welcomes a confirmed create/invite could not deliver and that still await
    /// re-delivery for `account_ref` (mdk#352), oldest first.
    pub async fn pending_welcome_deliveries(
        &self,
        account_ref: &str,
    ) -> Result<Vec<PendingWelcomeDelivery>, AppError> {
        self.accounts.pending_welcome_deliveries(account_ref).await
    }

    /// Re-publish a previously undelivered welcome (identified by its stored MLS
    /// message id) without re-committing (mdk#352). Clears the pending record on
    /// success; a repeated failure leaves it queued.
    pub async fn redeliver_welcome(
        &self,
        account_ref: &str,
        message_id_hex: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .redeliver_welcome(account_ref, message_id_hex)
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
        created_at: u64,
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.start_agent_text_stream_with_parent(
            account_ref,
            group_id,
            stream_id,
            created_at,
            None,
            quic_candidates,
        )
        .await
    }

    /// Anchor a kind-1200 agent text stream start, optionally threading it to the
    /// inbound message that triggered the agent turn.
    pub async fn start_agent_text_stream_with_parent(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        stream_id: &[u8],
        _created_at: u64,
        parent_message_id: Option<String>,
        quic_candidates: Vec<String>,
    ) -> Result<(MarmotInnerEvent, SendSummary), AppError> {
        self.accounts
            .start_agent_text_stream(
                account_ref,
                group_id,
                stream_id.to_vec(),
                parent_message_id,
                quic_candidates,
            )
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

    pub async fn key_package_maintenance_status(
        &self,
        account_ref: &str,
    ) -> Result<Option<cgka_traits::KeyPackageLifecycleState>, AppError> {
        self.accounts
            .key_package_maintenance_status(account_ref)
            .await
    }

    pub async fn durably_owned_key_packages(
        &self,
        account_ref: &str,
    ) -> Result<Vec<cgka_traits::engine::KeyPackage>, AppError> {
        self.accounts.durably_owned_key_packages(account_ref).await
    }

    pub async fn publish_new_key_package(&self, account_ref: &str) -> Result<usize, AppError> {
        self.rotate_key_package(account_ref).await
    }

    pub async fn maintenance_status(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<cgka_traits::GroupMaintenanceStatus, AppError> {
        self.accounts
            .maintenance_status(account_ref, group_id)
            .await
    }

    pub async fn schedule_manual_self_update(
        &self,
        account_ref: &str,
        group_id: &GroupId,
    ) -> Result<String, AppError> {
        self.accounts
            .schedule_manual_self_update(account_ref, group_id)
            .await
    }

    pub async fn periodic_maintenance_policy(
        &self,
        account_ref: &str,
    ) -> Result<cgka_traits::PeriodicMaintenancePolicy, AppError> {
        self.accounts.periodic_maintenance_policy(account_ref).await
    }

    pub async fn set_periodic_maintenance_policy(
        &self,
        account_ref: &str,
        policy: cgka_traits::PeriodicMaintenancePolicy,
    ) -> Result<(), AppError> {
        self.accounts
            .set_periodic_maintenance_policy(account_ref, policy)
            .await
    }

    pub async fn pause_maintenance(&self, account_ref: &str) -> Result<(), AppError> {
        self.accounts.pause_maintenance(account_ref).await
    }

    pub async fn resume_maintenance(&self, account_ref: &str) -> Result<(), AppError> {
        self.accounts.resume_maintenance(account_ref).await
    }

    pub async fn run_due_maintenance(
        &self,
        account_ref: &str,
    ) -> Result<crate::MaintenanceRunSummary, AppError> {
        self.accounts.run_due_maintenance(account_ref).await
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

    async fn delete_relay_key_packages(
        &self,
        account_label: &str,
        packages: Vec<AccountKeyPackageRecord>,
    ) -> (u32, Vec<RelayFailure>) {
        let targets = packages
            .into_iter()
            .filter(|package| package.relay)
            .map(|package| KeyPackageDeletionTarget {
                event_id_hex: package.key_package_event_id,
                source_relays: package
                    .source_relays
                    .into_iter()
                    .map(TransportEndpoint)
                    .collect(),
            })
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return (0, Vec::new());
        }
        let event_ids = targets
            .iter()
            .map(|target| target.event_id_hex.clone())
            .collect::<Vec<_>>();
        let results = match self
            .accounts
            .app
            .delete_key_package_events(account_label, targets)
            .await
        {
            Ok(results) => results,
            Err(error) => {
                let reason = wipe_failure_reason(&error);
                return (
                    0,
                    event_ids
                        .into_iter()
                        .map(|event_id_hex| RelayFailure {
                            event_id_hex,
                            reason: reason.clone(),
                        })
                        .collect(),
                );
            }
        };

        relay_failures_from_key_package_deletion_results(results)
    }

    /// Non-destructive sign-out: deactivate the account on this device and
    /// (optionally) clean up its relay-published KeyPackages, while keeping all
    /// local state so the same identity can be signed back in later.
    ///
    /// This is the reversible counterpart to [`sign_out_and_wipe`]. It
    /// implements the engine half of the "Sign Out" action in
    /// mdk#477 / parent mdk-android#347.
    ///
    /// Steps:
    /// 1. **Local teardown (always).** Shut the managed account worker down
    ///    (which deactivates its transport subscriptions) and evict the
    ///    account's in-memory storage/directory caches. This mirrors what
    ///    today's logout already does. It does **NOT** call `remove_account`,
    ///    so the SQLCipher session database (MLS state + projections), the
    ///    cached media/source-epoch secrets, the on-disk KeyPackage material,
    ///    the SQL account record, and the secret-store nsec all stay on disk.
    ///    The account remains a live record in the picker and can be
    ///    re-activated with its groups, message history, and drafts intact.
    /// 2. **KeyPackage hygiene (when `delete_key_packages`).** Enumerate every
    ///    relay-published KeyPackage for this account and publish a kind:5
    ///    deletion to each one's source relays, mirroring the
    ///    [`delete_key_package`](Self::delete_key_package) path. This stops
    ///    strangers from pulling a stale KeyPackage and gift-wrapping a Welcome
    ///    into a new group while the account is signed out.
    ///
    /// # Invariants
    /// - The MLS state DB is never touched — that is the "sign back in and
    ///   resume" contract.
    /// - KeyPackage cleanup is best-effort and per-relay: a failure is recorded
    ///   in [`SignOutOutcome::key_package_failures`] and never blocks the local
    ///   teardown. The runtime does not persist a remote-deletion retry queue.
    /// - A discovery failure (could not enumerate KeyPackages) is recorded as a
    ///   single failure with an empty `event_id_hex`, not silently treated as
    ///   "no KeyPackages".
    /// - The KeyPackage step runs **before** the worker teardown so it can use
    ///   the account's live state; neither step depends on a running worker for
    ///   the publish itself.
    /// - The account ref stays valid after this returns (unlike a wipe).
    ///
    /// [`sign_out_and_wipe`]: Self::sign_out_and_wipe
    pub async fn sign_out(
        &self,
        account_ref: &str,
        options: SignOutOptions,
    ) -> Result<SignOutOutcome, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        if !account.local_signing {
            // Publishing kind:5 KeyPackage deletions requires signing with this
            // account's key, which a tracked-only (npub) account cannot do.
            // Surface the same error the worker path uses. (A tracked account
            // also never published KeyPackages from this device, so there is
            // nothing remote to clean up.)
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex).into());
        }

        let mut outcome = SignOutOutcome::default();

        // Step 1 (KeyPackage hygiene): delete every relay-published KeyPackage
        // before tearing the worker down, while the account is still fully
        // live. Discovery itself is network-bound; a discovery failure is
        // recorded as a single failure (no event id) and must not abort the
        // sign-out. This mirrors stage 2 of `sign_out_and_wipe`.
        if options.delete_key_packages {
            match self.account_key_packages(account_ref, Vec::new()).await {
                Ok(packages) => {
                    let (deleted, failures) = self
                        .delete_relay_key_packages(&account.label, packages)
                        .await;
                    outcome.key_packages_deleted += deleted;
                    outcome.key_package_failures.extend(failures);
                }
                Err(err) => outcome.key_package_failures.push(RelayFailure {
                    event_id_hex: String::new(),
                    reason: format!(
                        "key package discovery failed: {}",
                        wipe_failure_reason(&err)
                    ),
                }),
            }
        }

        // Step 2 (local teardown): shut the worker down (deactivating its
        // subscriptions) and drop in-memory caches. Crucially this does NOT
        // remove the account directory, so all on-disk state survives for a
        // later sign-in. Teardown is treated as completed whenever it runs; the
        // rare error path records a privacy-safe reason without aborting.
        match self.accounts.deactivate_account(account_ref).await {
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

    /// Destructive sign-out: fully remove the account's footprint from this
    /// device and from the relays the engine controls publishing to.
    ///
    /// Stages run in the order the spec (mdk#478) mandates:
    /// 1. Best-effort leave for every active MLS group. Failures are collected
    ///    per group and do not abort the wipe. This MUST happen while MLS state
    ///    still exists — once the session DB is wiped the engine can no longer
    ///    sign leave messages. "Active" here means *locally MLS-joined*, which
    ///    in mdk includes groups still marked `pending_confirmation`: an
    ///    incoming Welcome auto-joins MLS state before the user accepts, so a
    ///    pending invite is a real committed membership this device must leave
    ///    (the decline path leaves such groups too). Group-enumeration failures
    ///    are surfaced as a recorded failure rather than silently dropped.
    /// 2. Best-effort delete of every relay-published KeyPackage event, always
    ///    (no toggle), mirroring the `delete_key_package` path.
    /// 3. Local cleanup (stages 3-5 of the spec): tear down the managed worker
    ///    and in-memory caches, then remove the account directory. In mdk
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
        // mdk an incoming Welcome auto-joins MLS state while the app
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
                let (deleted, failures) = self
                    .delete_relay_key_packages(&account.label, packages)
                    .await;
                outcome.key_packages_deleted += deleted;
                outcome.key_package_failures.extend(failures);
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

    /// Read the selected account's current published kind-0 profile through the
    /// same validated directory path used by app clients. Relay failures remain
    /// errors so callers can distinguish them from a confirmed absence.
    pub async fn fetch_current_user_profile_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: Vec<TransportEndpoint>,
    ) -> Result<Option<UserProfileMetadata>, AppError> {
        self.accounts
            .app
            .fetch_current_user_profile_for_account_id(account_id_hex, source_relays)
            .await
    }

    pub async fn publish_user_profile(
        &self,
        account_ref: &str,
        mut profile: UserProfileMetadata,
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<UserProfileMetadata, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        if let Some(current) = self
            .latest_known_user_profile_for_publish(&account.account_id_hex, &bootstrap)
            .await?
        {
            profile = merge_user_profile_update(current, profile);
        }
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

    pub async fn upload_profile_image(
        &self,
        account_ref: &str,
        data: Vec<u8>,
        media_type: &str,
        blossom_server: Option<&str>,
    ) -> Result<String, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let signer = self.accounts.app.account_signer_for_summary(&account)?;
        let signer = signer.as_nostr_signer();
        let configured_server = self
            .accounts
            .app
            .service_endpoints()
            .profile_image_blob_endpoint
            .as_deref();
        crate::media::upload_profile_image_with_policy(
            &data,
            media_type,
            blossom_server.or(configured_server),
            signer.as_ref(),
            self.accounts.app.allow_loopback_blob_endpoints(),
        )
        .await
    }

    async fn latest_known_user_profile_for_publish(
        &self,
        account_id_hex: &str,
        bootstrap: &AccountRelayListBootstrap,
    ) -> Result<Option<UserProfileMetadata>, AppError> {
        let cached = self
            .accounts
            .app
            .directory_entry_for_account_id(account_id_hex)?
            .and_then(|entry| entry.profile);
        match self
            .accounts
            .app
            .fetch_current_user_profile_for_account_id(
                account_id_hex,
                bootstrap.bootstrap_relays.clone(),
            )
            .await
        {
            Ok(fetched) => Ok(newest_user_profile(cached, fetched)),
            Err(error) => {
                tracing::debug!(
                    target: "marmot_app::runtime",
                    method = "latest_known_user_profile_for_publish",
                    error_kind = error.privacy_safe_kind(),
                    "falling back to cached profile before publish"
                );
                Ok(cached)
            }
        }
    }

    pub async fn publish_account_follow_list(
        &self,
        account_ref: &str,
        follows: &[String],
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<(), AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let update_lock = self.follow_list_update_lock(&account.account_id_hex).await;
        let _update_guard = update_lock.lock().await;
        self.publish_account_follow_list_unlocked(&account, follows, bootstrap)
            .await
    }

    async fn publish_account_follow_list_unlocked(
        &self,
        account: &AccountSummary,
        follows: &[String],
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<(), AppError> {
        let follow_refs = follows.iter().map(String::as_str).collect::<Vec<_>>();
        self.accounts
            .app
            .publish_account_follow_list(&account.label, &follow_refs, bootstrap)
            .await
    }

    /// Return the locally cached kind-3 follow list for a local account.
    ///
    /// This is intentionally network-free for profile/search-row rendering.
    /// Successful directory refreshes and follow-list publishes update the
    /// cache before returning.
    pub fn account_follows(&self, account_ref: &str) -> Result<Vec<String>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let mut follows = self
            .accounts
            .app
            .directory_entry_for_account_id(&account.account_id_hex)?
            .map(|entry| entry.follows)
            .unwrap_or_default();
        follows.sort();
        follows.dedup();
        Ok(follows)
    }

    /// Fast, network-free membership check against [`Self::account_follows`].
    pub fn is_following(
        &self,
        account_ref: &str,
        user_account_id_hex: &str,
    ) -> Result<bool, AppError> {
        Ok(self
            .account_follows(account_ref)?
            .binary_search_by(|follow| follow.as_str().cmp(user_account_id_hex))
            .is_ok())
    }

    /// Add one account to the current kind-3 list without replacing unrelated
    /// follows.
    pub async fn follow_user(
        &self,
        account_ref: &str,
        user_account_id_hex: &str,
    ) -> Result<Vec<String>, AppError> {
        self.set_following(account_ref, user_account_id_hex, true)
            .await
    }

    /// Remove one account from the current kind-3 list without replacing
    /// unrelated follows.
    pub async fn unfollow_user(
        &self,
        account_ref: &str,
        user_account_id_hex: &str,
    ) -> Result<Vec<String>, AppError> {
        self.set_following(account_ref, user_account_id_hex, false)
            .await
    }

    async fn set_following(
        &self,
        account_ref: &str,
        user_account_id_hex: &str,
        following: bool,
    ) -> Result<Vec<String>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        // Kind-3 is a whole-list replaceable event. Serialize updates for
        // this account so two local actions cannot both fetch the same
        // snapshot and then overwrite one another.
        let update_lock = self.follow_list_update_lock(&account.account_id_hex).await;
        let _update_guard = update_lock.lock().await;
        let status = self
            .accounts
            .app
            .account_relay_list_status_for_account_id(&account.account_id_hex)?;
        let mut source_relays = status
            .nip65
            .relays
            .into_iter()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        for endpoint in self.accounts.app.directory_source_relays(&[]) {
            if !source_relays.contains(&endpoint) {
                source_relays.push(endpoint);
            }
        }
        let mut follows = self
            .accounts
            .app
            .fetch_current_follow_list_for_account_id(&account.account_id_hex, source_relays)
            .await?
            .ok_or(AppError::FollowListUnavailable)?;

        let changed = if following {
            if follows.iter().any(|follow| follow == user_account_id_hex) {
                false
            } else {
                follows.push(user_account_id_hex.to_owned());
                true
            }
        } else {
            let previous_len = follows.len();
            follows.retain(|follow| follow != user_account_id_hex);
            follows.len() != previous_len
        };
        follows.sort();
        follows.dedup();

        if changed {
            let fallback = self.accounts.app.directory_source_relays(&[]);
            self.publish_account_follow_list_unlocked(
                &account,
                &follows,
                AccountRelayListBootstrap::new(fallback.clone(), fallback),
            )
            .await?;
        }
        Ok(follows)
    }

    async fn follow_list_update_lock(&self, account_id_hex: &str) -> Arc<Mutex<()>> {
        let mut locks = self.follow_list_updates.lock().await;
        locks
            .entry(account_id_hex.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
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

    pub async fn publish_account_nip65_relay_set(
        &self,
        account_ref: &str,
        read_relays: Vec<TransportEndpoint>,
        write_relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .publish_account_nip65_relay_set(
                &account.label,
                read_relays,
                write_relays,
                bootstrap_relays,
            )
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

    pub fn message_by_id(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> Result<Option<AppMessageRecord>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .message_by_id(&account.label, group_id_hex, message_id_hex)
    }

    pub fn message_target(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> Result<Option<storage_sqlite::TimelineMessageTarget>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .reaction_target(&account.label, group_id_hex, message_id_hex)
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

    pub fn timeline_message(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> Result<Option<TimelineMessageRecord>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .timeline_message(&account.label, group_id_hex, message_id_hex)
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

    /// Read the durable chat-list projection row for a single group (unread
    /// state, last-message preview, last-read marker). Read-only counterpart to
    /// [`Self::chat_list`], used to enrich the per-group `chats subscribe`
    /// snapshot and update feed without re-querying the whole list.
    pub fn chat_list_row(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<Option<ChatListRow>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .chat_list_row(&account.label, group_id_hex)
    }

    /// Pin or unpin one unarchived chat in an account-device's local store.
    ///
    /// Returns the complete authoritative pin order after the transaction and
    /// publishes an atomic chat-list snapshot to live subscribers.
    pub fn set_chat_pinned(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        pinned: bool,
    ) -> Result<ChatPinState, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let group_id_hex = normalize_group_id_hex_app(group_id_hex)?;
        let state = self
            .accounts
            .app
            .set_chat_pinned(&account.label, &group_id_hex, pinned)?;
        let row = self
            .accounts
            .app
            .chat_list_row(&account.label, &group_id_hex)?;
        self.publish_chat_list_projection_update(
            account.account_id_hex,
            account.label,
            group_id_hex,
            row,
            ChatListUpdateTrigger::PinOrderChanged,
        );
        Ok(state)
    }

    /// Atomically replace an account-device's complete pinned chat order.
    ///
    /// The input must contain every currently pinned group exactly once.
    /// Successful mutations publish an atomic chat-list snapshot.
    pub fn set_pinned_chat_order(
        &self,
        account_ref: &str,
        ordered_group_ids: Vec<String>,
    ) -> Result<ChatPinState, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let ordered_group_ids = ordered_group_ids
            .into_iter()
            .map(|group_id_hex| normalize_group_id_hex_app(&group_id_hex))
            .collect::<Result<Vec<_>, _>>()?;
        let state = self
            .accounts
            .app
            .set_pinned_chat_order(&account.label, &ordered_group_ids)?;
        if let Some(group_id_hex) = ordered_group_ids.first() {
            let row = self
                .accounts
                .app
                .chat_list_row(&account.label, group_id_hex)?;
            self.publish_chat_list_projection_update(
                account.account_id_hex,
                account.label,
                group_id_hex.clone(),
                row,
                ChatListUpdateTrigger::PinOrderChanged,
            );
        }
        Ok(state)
    }

    /// Per-account unread aggregate for the account-switcher badge
    /// (mdk#461). Computed from each account's materialized chat-list
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
        // it on the next inbound delivery's `save_state`. See mdk#178.
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

    pub fn set_chat_manually_unread(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        manually_unread: bool,
    ) -> Result<Option<ChatListRow>, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let row = self.accounts.app.set_chat_manually_unread(
            &account.label,
            group_id_hex,
            manually_unread,
        )?;
        if row.is_some() {
            self.publish_chat_list_projection_update(
                account.account_id_hex,
                account.label,
                group_id_hex.to_owned(),
                row.clone(),
                ChatListUpdateTrigger::ManualUnreadChanged,
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
        validate_account_setup_request(&request, AccountSetupOperation::CreateIdentityOnly)?;
        request.identity = None;
        self.accounts.create_or_import_account(request).await
    }

    pub async fn login(
        &self,
        identity: impl Into<String>,
        mut request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        let identity = identity.into();
        if crate::is_nostr_secret(&identity) {
            return Err(AppError::UnexpectedPrivateKey);
        }
        request.identity = Some(identity);
        validate_account_setup_request(&request, AccountSetupOperation::Login)?;
        self.accounts.create_or_import_account(request).await
    }

    pub async fn login_external_signer<S>(
        &self,
        public_key: impl Into<String>,
        signer: S,
        request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError>
    where
        S: crate::ExternalAccountSigner + 'static,
    {
        self.accounts
            .login_external_signer(public_key.into(), signer, request)
            .await
    }

    pub async fn register_external_signer<S>(
        &self,
        account_ref: impl AsRef<str>,
        signer: S,
    ) -> Result<(), AppError>
    where
        S: crate::ExternalAccountSigner + 'static,
    {
        self.accounts
            .register_external_signer(account_ref.as_ref(), signer)
            .await
    }

    pub async fn create_or_import_account(
        &self,
        request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        self.accounts.create_or_import_account(request).await
    }

    pub async fn reset_incomplete_account_setup(
        &self,
        nsec: &str,
        acknowledge_possible_key_package_orphan: bool,
    ) -> Result<(), AppError> {
        self.accounts
            .reset_incomplete_account_setup(nsec, acknowledge_possible_key_package_orphan)
            .await
    }

    /// Consent-gated compatibility recovery followed by an immediate retry of
    /// the same setup request. Keeping both operations inside the runtime
    /// prevents a host crash from turning reset into a separate manual step.
    pub async fn recover_incomplete_account_setup(
        &self,
        request: AccountSetupRequest,
        acknowledge_possible_key_package_orphan: bool,
    ) -> Result<AccountSetupResult, AppError> {
        let nsec = request
            .import_nsec
            .as_deref()
            .ok_or(AppError::UnexpectedPrivateKey)?;
        self.accounts
            .reset_incomplete_account_setup(nsec, acknowledge_possible_key_package_orphan)
            .await?;
        self.accounts.create_or_import_account(request).await
    }

    pub async fn shutdown(&self) {
        let started_at = Instant::now();
        self.shared.lifecycle().begin_shutdown();
        self.shared.stop_relay_telemetry_exporter();
        if let Some(directory_sync) = self.directory_sync.lock().await.take() {
            directory_sync.shutdown().await;
        }
        if let Some(initial_directory_sync) = self.initial_directory_sync.lock().await.take() {
            let _ = initial_directory_sync.await;
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

    /// [`Self::shutdown`], then close every SQLite database and release the
    /// root runtime lease — so when this returns, nothing this process owns
    /// holds a file lock inside the Marmot root.
    ///
    /// This is the operation a host needs before its process can be suspended.
    /// [`Self::shutdown`] alone is not enough: it stops workers but takes
    /// `&self`, so it cannot drop anything, and the databases live behind
    /// `Arc`s shared by the engine, the OpenMLS adapter, and app projections.
    /// A WAL connection holds a lock on its `-shm` sidecar for its entire
    /// lifetime, so "the workers stopped" and "the store is unlocked" are
    /// different facts, and only the second one keeps an iOS app alive across
    /// suspension (`0xdead10cc`, raised for holding a lock in a shared App
    /// Group container).
    ///
    /// Ordering is the point of this method: workers drain first, so the
    /// databases close under quiesced state rather than out from under live
    /// engine work.
    ///
    /// **Terminal.** This runtime and the [`MarmotApp`] it came from are done:
    /// every later database access fails with
    /// [`StorageError::Closed`][cgka_traits::storage::StorageError::Closed]
    /// rather than reopening, because reopening would re-lock the container the
    /// host has just been told is clear. Build a fresh `MarmotApp` and runtime
    /// to use the root again — which is what a foregrounding app does anyway.
    ///
    /// Safe to call twice, and safe to call with or without a preceding
    /// [`Self::shutdown`]. Worker drain is bounded by
    /// `APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT`; the close itself waits only for
    /// whatever SQLite statement is executing.
    pub async fn shutdown_and_close(&self) -> Result<(), AppError> {
        self.shutdown().await;
        let app = self.accounts.app.clone();
        blocking_app_task(move || app.close_storage()).await
    }

    /// Whether this runtime's storage has been closed by
    /// [`Self::shutdown_and_close`].
    #[must_use]
    pub fn storage_is_closed(&self) -> bool {
        self.accounts.app.storage_is_closed()
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
            tearing_down: Arc::new(StdMutex::new(HashSet::new())),
            worker_transactions: Arc::new(Mutex::new(())),
            #[cfg(test)]
            reconcile_rollback_waiters: Arc::new(StdMutex::new(Vec::new())),
            invite_catch_up_tasks: Arc::new(StdMutex::new(InviteCatchUpTasks {
                accepting: true,
                handles: Vec::new(),
            })),
        }
    }

    #[cfg(test)]
    pub(crate) fn register_reconcile_rollback_waiter(&self, notify: std::sync::mpsc::Sender<()>) {
        self.reconcile_rollback_waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(notify);
    }

    #[cfg(test)]
    fn signal_reconcile_rollback(&self) {
        let mut waiters = self
            .reconcile_rollback_waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for notify in waiters.drain(..) {
            let _ = notify.send(());
        }
    }

    fn set_account_tearing_down(&self, account_id_hex: &str, tearing_down: bool) {
        let mut accounts = self
            .tearing_down
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if tearing_down {
            accounts.insert(account_id_hex.to_owned());
        } else {
            accounts.remove(account_id_hex);
        }
    }

    fn account_is_tearing_down(&self, account_id_hex: &str) -> bool {
        self.tearing_down
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(account_id_hex)
    }

    async fn shutdown_workers_for_account_ids(&self, account_ids: &[String]) {
        let workers = {
            let mut workers = self.workers.lock().await;
            account_ids
                .iter()
                .filter_map(|account_id| workers.remove(account_id))
                .collect::<Vec<_>>()
        };
        #[cfg(test)]
        self.signal_reconcile_rollback();
        let mut shutdowns = JoinSet::new();
        for worker in workers {
            shutdowns.spawn(async move {
                worker.shutdown().await;
            });
        }
        while shutdowns.join_next().await.is_some() {}
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
            .filter(|account| account.can_sign())
            .map(|account| ManagedAccount {
                running: running.contains(&account.account_id_hex),
                label: account.label,
                account_id_hex: account.account_id_hex,
                local_signing: account.local_signing,
                external_signing: account.external_signing,
                signed_out: account.signed_out,
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
        let _worker_transaction = self.worker_transactions.lock().await;
        self.shared.lifecycle().ensure_running()?;
        let account = self.app.account_home().account(account_ref)?;
        self.set_account_tearing_down(&account.account_id_hex, true);
        let result = async {
            let worker = self.workers.lock().await.remove(&account.account_id_hex);
            if let Some(worker) = worker {
                worker.shutdown().await;
            }
            // Evict every in-memory handle and warm flag for this label BEFORE
            // the account directory is deleted. Otherwise the cached account
            // storage connection (and directory cache) keeps pointing at the
            // unlinked inode and a later re-import silently splits writes
            // across a stale handle.
            self.app.drop_account_caches(&account.label);
            self.app
                .remove_account_key_package_artifacts(&account.label)?;
            self.app.account_home().remove_account(&account.label)?;
            Ok(())
        }
        .await;
        self.set_account_tearing_down(&account.account_id_hex, false);
        result
    }

    /// Explicit recovery for an account created before durable setup journals.
    ///
    /// This is intentionally not automatic: without a lifecycle/legacy slot,
    /// local files cannot prove that an old KeyPackage was never exposed. The
    /// caller must present the matching nsec and explicitly acknowledge that
    /// resetting can orphan such an unknown publication. The credential is
    /// retained so the next `create_or_import_account` reuses it rather than
    /// creating a duplicate keychain entry.
    pub async fn reset_incomplete_account_setup(
        &self,
        nsec: &str,
        acknowledge_possible_key_package_orphan: bool,
    ) -> Result<(), AppError> {
        let _worker_transaction = self.worker_transactions.lock().await;
        self.shared.lifecycle().ensure_running()?;
        if !acknowledge_possible_key_package_orphan {
            return Err(AppError::AccountSetupRecoveryRequired);
        }
        let account_id = AccountHome::account_id_for_secret(nsec)?;
        let account = self.app.account_home().account(&account_id)?;
        if !account.local_signing
            || self
                .app
                .account_home()
                .load_signing_keys(&account.label)?
                .public_key()
                .to_hex()
                != account_id
        {
            return Err(AppError::IdentityKeyMismatch);
        }
        if self
            .app
            .account_home()
            .account_setup_state(&account.label)?
            .is_some()
        {
            return Err(AppError::AccountSetupRetryRequired);
        }
        if !self
            .app
            .key_package_cutover_replacement_pending(&account.label)
        {
            return Err(AppError::AccountSetupResetNotApplicable);
        }
        let storage = self.app.account_storage(&account.label)?;
        if storage.key_package_lifecycle()?.is_some()
            || !storage.stored_key_package_bundles()?.is_empty()
            || self.app.key_package_record_path(&account.label).exists()
        {
            return Err(AppError::AccountSetupKeyPackageRecoveryAvailable);
        }

        self.set_account_tearing_down(&account.account_id_hex, true);
        let result = async {
            if let Some(worker) = self.workers.lock().await.remove(&account.account_id_hex) {
                worker.shutdown().await;
            }
            self.app.drop_account_caches(&account.label);
            self.app
                .remove_account_key_package_artifacts(&account.label)?;
            self.app
                .account_home()
                .reset_incomplete_setup_preserving_credential(&account.label)?;
            Ok(())
        }
        .await;
        self.set_account_tearing_down(&account.account_id_hex, false);
        result
    }

    /// Non-destructive deactivation of an account on this device: persist a
    /// signed-out marker, shut its managed worker down (which deactivates the
    /// worker's transport subscriptions), and evict its in-memory
    /// storage/directory caches, but leave every byte of on-disk state in place.
    ///
    /// This is the teardown half of [`MarmotAppRuntime::sign_out`]. Unlike
    /// [`remove_account`](Self::remove_account) it does **not** call
    /// `account_home().remove_account`, so the account directory — the
    /// SQLCipher session database (MLS state + projections), cached
    /// media/source-epoch secrets, on-disk KeyPackage material, the SQL account
    /// record, and the secret-store nsec — survives. The durable signed-out
    /// marker prevents later [`reconcile`](Self::reconcile) /
    /// [`restart_account`](Self::restart_account) calls from recreating the
    /// worker until an explicit sign-in clears it.
    ///
    /// Dropping the in-memory caches is harmless when the directory is kept: a
    /// later sign-in simply re-warms them from the unchanged on-disk database.
    pub async fn deactivate_account(&self, account_ref: &str) -> Result<(), AppError> {
        let _worker_transaction = self.worker_transactions.lock().await;
        self.shared.lifecycle().ensure_running()?;
        let account = self.app.account_home().account(account_ref)?;
        self.set_account_tearing_down(&account.account_id_hex, true);
        let result = async {
            self.app
                .account_home()
                .set_account_signed_out(&account.label, true)?;
            let worker = self.workers.lock().await.remove(&account.account_id_hex);
            if let Some(worker) = worker {
                worker.shutdown().await;
            }
            self.app.drop_account_caches(&account.label);
            Ok(())
        }
        .await;
        self.set_account_tearing_down(&account.account_id_hex, false);
        result
    }

    /// Explicitly re-activate a reversibly signed-out local account.
    pub async fn sign_in_account(&self, account_ref: &str) -> Result<ManagedAccount, AppError> {
        let _worker_transaction = self.worker_transactions.lock().await;
        self.shared.lifecycle().ensure_running()?;
        let account = self
            .app
            .account_home()
            .set_account_signed_out(account_ref, false)?;
        self.reconcile_locked().await?;
        let running = self
            .workers
            .lock()
            .await
            .contains_key(&account.account_id_hex);
        Ok(ManagedAccount {
            label: account.label,
            account_id_hex: account.account_id_hex,
            local_signing: account.local_signing,
            external_signing: account.external_signing,
            signed_out: account.signed_out,
            running,
        })
    }

    pub async fn reconcile(&self) -> Result<(), AppError> {
        let _worker_transaction = self.worker_transactions.lock().await;
        self.reconcile_locked().await
    }

    async fn reconcile_locked(&self) -> Result<(), AppError> {
        let started_at = Instant::now();
        let result = async {
            self.shared.lifecycle().ensure_running()?;
            let accounts = self
                .app
                .account_home()
                .accounts()?
                .into_iter()
                .filter(|account| {
                    !self.account_is_tearing_down(&account.account_id_hex)
                        && (account.is_active_local_signing()
                            || (account.external_signing
                                && !account.signed_out
                                && self.app.has_external_signer(&account.account_id_hex)))
                })
                .collect::<Vec<_>>();
            let active_account_ids = accounts
                .iter()
                .map(|account| account.account_id_hex.clone())
                .collect::<HashSet<_>>();

            let (existing_account_ids, stale_workers) = {
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
                let stale_workers = stale_account_ids
                    .into_iter()
                    .filter_map(|account_id| workers.remove(&account_id))
                    .collect::<Vec<_>>();
                (
                    workers.keys().cloned().collect::<HashSet<_>>(),
                    stale_workers,
                )
            };
            // Worker task teardown releases AppClient's account-session guard.
            // Reap stale tasks before opening replacements for the same labels.
            for worker in stale_workers {
                worker.shutdown().await;
            }

            let pending = accounts
                .into_iter()
                .filter(|account| !existing_account_ids.contains(&account.account_id_hex))
                .collect::<Vec<_>>();

            let mut ready_receivers = Vec::new();
            let mut spawned_account_ids = Vec::new();
            {
                let mut workers = self.workers.lock().await;
                for account in pending {
                    if workers.contains_key(&account.account_id_hex)
                        || self.account_is_tearing_down(&account.account_id_hex)
                    {
                        continue;
                    }
                    spawned_account_ids.push(account.account_id_hex.clone());
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
                        command_tx.clone(),
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
                let (account_open_elapsed, ready_result) = match joined {
                    Ok(joined) => joined,
                    Err(err) => {
                        self.shutdown_workers_for_account_ids(&spawned_account_ids)
                            .await;
                        return Err(AppError::BlockingTask(format!(
                            "account worker readiness wait failed: {err}"
                        )));
                    }
                };
                self.shared.app_performance_telemetry().record(
                    AppPerformanceOperation::AccountOpen,
                    account_open_elapsed,
                    matches!(ready_result, Ok(Ok(Ok(())))),
                );
                match ready_result {
                    Ok(Ok(Ok(()))) => {}
                    Ok(Ok(Err(error))) => {
                        self.shutdown_workers_for_account_ids(&spawned_account_ids)
                            .await;
                        return Err(error);
                    }
                    Ok(Err(_closed)) => {
                        self.shutdown_workers_for_account_ids(&spawned_account_ids)
                            .await;
                        return Err(AppError::TransportClosed);
                    }
                    Err(_elapsed) => {
                        self.shutdown_workers_for_account_ids(&spawned_account_ids)
                            .await;
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
        let _worker_transaction = self.worker_transactions.lock().await;
        self.shared.lifecycle().ensure_running()?;
        let worker = self.workers.lock().await.remove(account_id_hex);
        if let Some(worker) = worker {
            // The worker owns the AppClient and its account-session guard.
            // Await teardown before reconcile opens the replacement.
            worker.shutdown().await;
        }
        self.reconcile_locked().await
    }

    pub async fn catch_up_accounts(&self) -> Result<(), AppError> {
        let started_at = Instant::now();
        let result = async {
            self.shared.lifecycle().ensure_running()?;
            self.reconcile().await?;
            let commands = self.running_account_commands().await;
            self.catch_up_account_commands(commands).await
        }
        .await;
        self.shared.app_performance_telemetry().record(
            AppPerformanceOperation::AccountCatchUp,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
    }

    async fn running_account_commands(&self) -> Vec<mpsc::Sender<AccountWorkerCommand>> {
        self.workers
            .lock()
            .await
            .values()
            .map(|worker| worker.commands.clone())
            .collect()
    }

    async fn catch_up_account_commands(
        &self,
        commands: Vec<mpsc::Sender<AccountWorkerCommand>>,
    ) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
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
                Ok(Ok(Err(message))) => return Err(AppError::AccountCatchUp(message)),
                Ok(Err(_)) => return Err(AppError::TransportClosed),
                Err(_) => {
                    return Err(AppError::AccountCatchUp(
                        "account worker catch-up timed out".into(),
                    ));
                }
            }
        }
        Ok(())
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

    /// Apply an audit data-mode change to every running account worker by
    /// rotating its live recorder in place, so each file carries a single mode
    /// with a clear `audit_data_mode_changed` boundary.
    ///
    /// Best-effort, mirroring [`apply_audit_recording_to_workers`]: non-running
    /// workers pick the mode up at their next open (the recorder opens in the
    /// persisted mode), and per-worker failures are ignored. The mode is already
    /// persisted by the caller; this only updates live sessions.
    async fn apply_audit_data_mode_to_workers(&self, mode: marmot_forensics::AuditDataMode) {
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
                .send(AccountWorkerCommand::SetAuditDataMode {
                    mode,
                    reason: "settings_changed".to_owned(),
                    respond,
                })
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
        if account.can_sign() && !account.signed_out {
            // Unlike local runtime reads, this API reports relay visibility.
            // Wait for the managed worker's initial activation, catch-up, and
            // open maintenance before issuing the directory query.
            self.wait_for_account_network_startup_to_settle(&account.label)
                .await?;
        }
        let owned = cgka_engine::key_package::durably_owned_key_packages(
            &self.app.account_storage(&account.label)?,
            cgka_traits::group::ProtocolProfile::Current,
        )
        .map_err(cgka_session::SessionError::from)?;
        self.app
            .account_key_package_records(&account.label, bootstrap_relays, owned)
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
        if !account.can_sign() {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex).into());
        }
        if account.signed_out {
            return Err(AppError::RelayDirectory("account is signed out".into()));
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
        validate_account_setup_request(&request, AccountSetupOperation::CreateOrImport)?;
        let imports_private_key = request.import_nsec.is_some();
        let creates_new_private_key = request.identity.is_none() && request.import_nsec.is_none();
        let directory_bootstrap_relays = directory_bootstrap_relays_for_setup(&request);
        if let Some(nsec) = request.import_nsec.as_deref()
            && self.legacy_incomplete_account_for_import(nsec)?
        {
            return Err(AppError::AccountSetupRecoveryRequired);
        }
        let identity_key: Option<&str> = request
            .import_nsec
            .as_ref()
            .map(|value| value.as_str())
            .or(request.identity.as_deref());
        let (mut account, private_key_import) = if let Some(identity) = identity_key {
            match self.signed_out_account_for_identity(identity)? {
                Some(account) => (account, None),
                None => self.create_nostr_account_from_setup(&request)?,
            }
        } else {
            self.create_nostr_account_from_setup(&request)?
        };
        let reactivating_existing = account.signed_out;
        let setup_already_reached_publication = self
            .app
            .account_home()
            .account_setup_state(&account.label)?
            .is_some_and(|state| state.phase != AccountSetupPhase::LocalStateCreated);
        let rollback_on_setup_failure =
            !reactivating_existing && !setup_already_reached_publication;

        if imports_private_key || reactivating_existing || !account.local_signing {
            // Resolve a pre-existing identity's profile from public indexers, not
            // the app's own messaging relays, where its outbox metadata does not
            // live. Runs before the relay-list setup below so discovery never
            // clobbers, or is clobbered by, the publish-missing-relay-lists step.
            // Advisory: bounded so a stalled indexer cannot hang import or
            // reactivation, exactly like the external-signer login path.
            let _ = bounded_advisory_step(
                &self.shared.app_performance_telemetry(),
                ACCOUNT_SETUP_ADVISORY_WAIT,
                "import_directory_preflight",
                self.preflight_existing_account_directory(
                    &account.account_id_hex,
                    directory_discovery_relays_for_setup(&request),
                ),
            )
            .await;
        }

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
                if rollback_on_setup_failure {
                    return self.rollback_import_after_setup_failure(
                        &account,
                        private_key_import.as_ref(),
                        err,
                    );
                }
                return Err(err);
            }
        };

        if creates_new_private_key && account.local_signing {
            self.shared.lifecycle().ensure_running()?;
            if let Err(err) = self
                .app
                .publish_account_follow_list(
                    &account.label,
                    &[],
                    AccountRelayListBootstrap::new(
                        request.default_relays.clone(),
                        request.bootstrap_relays.clone(),
                    ),
                )
                .await
            {
                if rollback_on_setup_failure {
                    return self.rollback_import_after_setup_failure(
                        &account,
                        private_key_import.as_ref(),
                        err,
                    );
                }
                return Err(err);
            }
        }

        let profile = if creates_new_private_key && account.local_signing {
            self.shared.lifecycle().ensure_running()?;
            match self
                .publish_default_profile_for_account(&account, &request)
                .await
            {
                Ok(profile) => Some(profile),
                Err(err) => {
                    if rollback_on_setup_failure {
                        return self.rollback_import_after_setup_failure(
                            &account,
                            private_key_import.as_ref(),
                            err,
                        );
                    }
                    return Err(err);
                }
            }
        } else {
            None
        };

        let key_package_bytes = if request.publish_initial_key_package && account.local_signing {
            let setup_phase = self
                .app
                .account_home()
                .account_setup_state(&account.label)?
                .map(|state| state.phase);
            let confirmed_bytes =
                if setup_phase == Some(AccountSetupPhase::KeyPackagePublicationConfirmed) {
                    self.confirmed_setup_key_package_bytes(&account.label)?
                } else {
                    None
                };
            if let Some(bytes) = confirmed_bytes {
                Some(bytes)
            } else {
                self.shared.lifecycle().ensure_running()?;
                if setup_phase.is_some()
                    && let Err(err) = self.app.account_home().set_account_setup_phase(
                        &account.label,
                        AccountSetupPhase::KeyPackagePublicationStarted,
                    )
                {
                    if rollback_on_setup_failure {
                        return self.rollback_import_after_setup_failure(
                            &account,
                            private_key_import.as_ref(),
                            err.into(),
                        );
                    }
                    return Err(err.into());
                }
                match self.publish_initial_key_package_for_account(&account).await {
                    Ok(bytes) => {
                        self.app.account_home().set_account_setup_phase(
                            &account.label,
                            AccountSetupPhase::KeyPackagePublicationConfirmed,
                        )?;
                        Some(bytes)
                    }
                    Err(err) => {
                        // Publication-started state plus the SQLCipher lifecycle
                        // is sufficient to retry safely after any ordinary error
                        // or task cancellation. Never delete possibly exposed
                        // exact bytes/private material here.
                        return Err(err);
                    }
                }
            }
        } else {
            None
        };

        self.shared.lifecycle().ensure_running()?;
        // Advisory refresh, bounded like the matching step in
        // login_external_signer.
        let _ = bounded_advisory_step(
            &self.shared.app_performance_telemetry(),
            ACCOUNT_SETUP_ADVISORY_WAIT,
            "import_directory_refresh",
            self.app.refresh_user_directory_for_account_id(
                &account.account_id_hex,
                directory_bootstrap_relays.clone(),
            ),
        )
        .await;
        if account.signed_out {
            account = self
                .app
                .account_home()
                .set_account_signed_out(&account.label, false)?;
        }
        self.reconcile().await?;
        self.app
            .account_home()
            .complete_account_setup(&account.label)?;

        Ok(AccountSetupResult {
            account,
            relay_lists,
            key_package_bytes,
            profile,
        })
    }

    async fn wait_for_account_network_startup_to_settle(
        &self,
        account_ref: &str,
    ) -> Result<(), AppError> {
        let commands = self.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::NetworkStartupSettled { respond })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        match timeout(APP_RUNTIME_ACCOUNT_READY_WAIT, response).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(AppError::TransportClosed),
            Err(_) => Err(AppError::BlockingTask(
                "account worker startup settlement timed out".into(),
            )),
        }
    }

    pub async fn login_external_signer<S>(
        &self,
        public_key: String,
        signer: S,
        request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError>
    where
        S: crate::ExternalAccountSigner + 'static,
    {
        self.shared.lifecycle().ensure_running()?;
        let signer_public_key = signer
            .get_public_key()
            .await
            .map_err(crate::external_signer_public_key_error)?;
        let account_id_hex = AccountHome::account_id_for_public_key(&public_key)?;
        if signer_public_key.to_hex() != account_id_hex {
            return Err(AppError::ExternalSignerMismatch);
        }
        let existing_account = self.app.account_home().account(&account_id_hex).ok();
        let created_account = existing_account.is_none();
        // add_external_signer_account below promotes a pre-existing tracked
        // (public) account to external_signing, so a later setup failure must
        // revert that promotion — not skip cleanup and leave a torn account.
        // Created accounts are deleted, already-external accounts are left as-is.
        let upgraded_public_account = existing_account
            .is_some_and(|account| !account.external_signing && !account.local_signing);
        let mut account = self
            .app
            .account_home()
            .add_external_signer_account(&public_key)?;
        if let Err(err) = self
            .app
            .register_external_signer(&account.account_id_hex, signer)
            .await
        {
            return self.rollback_external_signer_setup(
                &account.label,
                created_account,
                upgraded_public_account,
                err,
            );
        }
        if self
            .app
            .account_home()
            .account_setup_state(&account.label)?
            .is_none()
        {
            self.app.account_home().begin_account_setup_with(
                &account,
                false,
                AccountSetupKind::ExternalSigner,
                AccountSetupPhase::LocalStateCreated,
            )?;
        }
        let setup_already_reached_publication = self
            .app
            .account_home()
            .account_setup_state(&account.label)?
            .is_some_and(|state| state.phase != AccountSetupPhase::LocalStateCreated);

        let directory_bootstrap_relays = directory_bootstrap_relays_for_setup(&request);
        // An external-signer account is pre-existing by definition, so resolve
        // its profile from public indexers (its outbox metadata does not live on
        // the app's messaging relays). Runs before the relay-list setup so
        // discovery keeps its anti-clobber ordering.
        // Discovery is advisory (its error path already proceeds without it),
        // so a stalled indexer must not hold the whole login hostage.
        let _ = bounded_advisory_step(
            &self.shared.app_performance_telemetry(),
            ACCOUNT_SETUP_ADVISORY_WAIT,
            "login_directory_preflight",
            self.preflight_existing_account_directory(
                &account.account_id_hex,
                directory_discovery_relays_for_setup(&request),
            ),
        )
        .await;

        let relay_lists = match self
            .setup_relay_lists_for_account(&account, &request, true, false)
            .await
        {
            Ok(relay_lists) => relay_lists,
            Err(err) => {
                if setup_already_reached_publication {
                    return Err(err);
                }
                return self.rollback_external_signer_setup(
                    &account.label,
                    created_account,
                    upgraded_public_account,
                    err,
                );
            }
        };

        let key_package_bytes = if request.publish_initial_key_package {
            self.app.account_home().set_account_setup_phase(
                &account.label,
                AccountSetupPhase::KeyPackagePublicationStarted,
            )?;
            match self.publish_initial_key_package_for_account(&account).await {
                Ok(bytes) => {
                    self.app.account_home().set_account_setup_phase(
                        &account.label,
                        AccountSetupPhase::KeyPackagePublicationConfirmed,
                    )?;
                    Some(bytes)
                }
                // Session lifecycle state owns exact signed bytes and private
                // material before network exposure. Once KeyPackage setup has
                // started, deleting a freshly-added external account could
                // orphan an ambiguously accepted publication; keep it for an
                // exact-byte retry instead.
                Err(err) => return Err(err),
            }
        } else {
            None
        };

        // Advisory refresh, same bound as the preflight above.
        let _ = bounded_advisory_step(
            &self.shared.app_performance_telemetry(),
            ACCOUNT_SETUP_ADVISORY_WAIT,
            "login_directory_refresh",
            self.app.refresh_user_directory_for_account_id(
                &account.account_id_hex,
                directory_bootstrap_relays,
            ),
        )
        .await;
        if account.signed_out {
            account = self
                .app
                .account_home()
                .set_account_signed_out(&account.label, false)?;
        }
        self.reconcile().await?;
        self.app
            .account_home()
            .complete_account_setup(&account.label)?;

        Ok(AccountSetupResult {
            account,
            relay_lists,
            key_package_bytes,
            profile: None,
        })
    }

    pub async fn register_external_signer<S>(
        &self,
        account_ref: &str,
        signer: S,
    ) -> Result<(), AppError>
    where
        S: crate::ExternalAccountSigner + 'static,
    {
        self.shared.lifecycle().ensure_running()?;
        self.app
            .register_external_signer(account_ref, signer)
            .await?;
        self.reconcile().await
    }

    async fn preflight_existing_account_directory(
        &self,
        account_id_hex: &str,
        discovery_relays: Vec<TransportEndpoint>,
    ) -> Option<AccountRelayListStatus> {
        let status = match self
            .app
            .fetch_account_relay_list_status_for_account_id(account_id_hex, discovery_relays)
            .await
        {
            Ok(status) => status,
            Err(err) => {
                tracing::debug!(
                    target: "marmot_app::runtime",
                    method = "preflight_existing_account_directory",
                    error_kind = err.privacy_safe_kind(),
                    "existing account relay discovery failed during setup preflight"
                );
                return None;
            }
        };

        let profile_relays = status
            .nip65
            .relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        if profile_relays.is_empty() {
            return Some(status);
        }
        if let Err(err) = self
            .app
            .refresh_profile_for_account_id(account_id_hex, profile_relays)
            .await
        {
            tracing::debug!(
                target: "marmot_app::runtime",
                method = "preflight_existing_account_directory",
                error_kind = err.privacy_safe_kind(),
                "existing account profile discovery failed during setup preflight"
            );
        }

        Some(status)
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
        if account.can_sign() {
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
        if self
            .app
            .legacy_incomplete_setup_requires_recovery(&account.label)?
        {
            let _ = self
                .app
                .mark_key_package_cutover_replacement_pending(&account.label);
            return Err(AppError::AccountSetupRecoveryRequired);
        }
        self.app.status(&account.label)?;
        let mut client = self.app.client(&account.label).await?;
        let key_package = client.publish_key_package().await?;
        Ok(key_package.bytes().len())
    }

    fn confirmed_setup_key_package_bytes(&self, label: &str) -> Result<Option<usize>, AppError> {
        Ok(self
            .app
            .account_storage(label)?
            .key_package_lifecycle()?
            .and_then(|lifecycle| lifecycle.current_key_package)
            .map(|key_package| key_package.bytes().len()))
    }

    fn signed_out_account_for_identity(
        &self,
        identity: &str,
    ) -> Result<Option<AccountSummary>, AppError> {
        let account_id = if crate::is_nostr_secret(identity) {
            AccountHome::account_id_for_secret(identity)?
        } else {
            AccountHome::account_id_for_public_key(identity)?
        };
        match self.app.account_home().account(&account_id) {
            Ok(account) if account.local_signing && account.signed_out => Ok(Some(account)),
            Ok(_) => Ok(None),
            Err(AccountHomeError::UnknownAccount(_)) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn legacy_incomplete_account_for_import(&self, nsec: &str) -> Result<bool, AppError> {
        let account_id = AccountHome::account_id_for_secret(nsec)?;
        let account = match self.app.account_home().account(&account_id) {
            Ok(account) if account.local_signing && !account.signed_out => account,
            Ok(_) | Err(AccountHomeError::UnknownAccount(_)) => return Ok(false),
            Err(err) => return Err(err.into()),
        };
        if self
            .app
            .account_home()
            .account_setup_state(&account.label)?
            .is_none()
            && self.app.account_storage_path(&account.label).exists()
            && self
                .app
                .account_storage(&account.label)?
                .key_package_lifecycle()?
                .is_some_and(|lifecycle| lifecycle.pending_replacement.is_some())
        {
            // Pre-journal MDK could strand an account after persisting the exact
            // replacement but before returning from setup. Adopt that durable
            // attempt into the journal so same-nsec login resumes its bytes.
            // Validate the credential before changing any provenance state.
            if self
                .app
                .account_home()
                .load_signing_keys(&account.label)?
                .public_key()
                .to_hex()
                != account_id
            {
                return Err(AppError::IdentityKeyMismatch);
            }
            self.app.account_home().begin_account_setup_with(
                &account,
                false,
                AccountSetupKind::ImportedIdentity,
                AccountSetupPhase::KeyPackagePublicationStarted,
            )?;
            return Ok(false);
        }
        if !self
            .app
            .legacy_incomplete_setup_requires_recovery(&account.label)?
        {
            return Ok(false);
        }
        let _ = self
            .app
            .mark_key_package_cutover_replacement_pending(&account.label);
        Ok(true)
    }

    fn create_nostr_account_from_setup(
        &self,
        request: &AccountSetupRequest,
    ) -> Result<(AccountSummary, Option<NostrAccountImport>), AppError> {
        let account_home = self.app.account_home();
        if let Some(nsec) = request.import_nsec.as_deref() {
            let imported = account_home.import_nostr_account_idempotent(nsec)?;
            return Ok((imported.account().clone(), Some(imported)));
        }
        match request.identity.as_deref() {
            Some(value) => {
                let account = account_home.add_public_account(value)?;
                if let Err(error) = account_home.begin_account_setup_with(
                    &account,
                    false,
                    AccountSetupKind::PublicIdentity,
                    AccountSetupPhase::LocalStateCreated,
                ) {
                    let _ = account_home.remove_account(&account.label);
                    return Err(error.into());
                }
                Ok((account, None))
            }
            None => {
                let account = match account_home.resumable_generated_account_setup()? {
                    Some(account) => account,
                    None => account_home.create_nostr_account_for_setup()?,
                };
                Ok((account, None))
            }
        }
    }

    /// Undo a failed external-signer setup — delete a freshly created account, or
    /// revert the external_signing promotion on a pre-existing tracked account,
    /// then surface the original error. Without this, a failed public→external
    /// login leaves a torn account: the promotion applied, but the relay-list and
    /// KeyPackage setup that should follow it did not.
    fn rollback_external_signer_setup<T>(
        &self,
        label: &str,
        created_account: bool,
        upgraded_public_account: bool,
        err: AppError,
    ) -> Result<T, AppError> {
        if created_account {
            return self.rollback_account_after_setup_failure(label, err);
        }
        if upgraded_public_account {
            let _ = self.app.account_home().complete_account_setup(label);
            let _ = self
                .app
                .account_home()
                .revert_external_signer_upgrade(label);
        }
        Err(err)
    }

    fn rollback_account_after_setup_failure<T>(
        &self,
        account: &str,
        source: AppError,
    ) -> Result<T, AppError> {
        // Setup probes (e.g. `status()`) may have already cached this account's
        // storage/directory handles. Evict them before the directory is deleted
        // so a later re-import does not reuse a handle bound to the now-unlinked
        // inode. See `drop_account_caches` and mdk#220.
        self.app.drop_account_caches(account);
        if let Err(rollback) = self.app.remove_account_key_package_artifacts(account) {
            return Err(AppError::RelayDirectory(format!(
                "failed to roll back account after setup failure: {source}; rollback error: {rollback}"
            )));
        }
        match self.app.account_home().remove_account(account) {
            Ok(()) => Err(source),
            Err(rollback) => Err(AppError::RelayDirectory(format!(
                "failed to roll back account after setup failure: {source}; rollback error: {rollback}"
            ))),
        }
    }

    fn rollback_import_after_setup_failure<T>(
        &self,
        account: &AccountSummary,
        private_key_import: Option<&NostrAccountImport>,
        source: AppError,
    ) -> Result<T, AppError> {
        let Some(imported) = private_key_import else {
            return self.rollback_account_after_setup_failure(&account.label, source);
        };

        self.app.drop_account_caches(&account.label);
        if let Err(rollback) = self
            .app
            .remove_account_key_package_artifacts(&account.label)
        {
            return Err(AppError::RelayDirectory(format!(
                "failed to roll back account after setup failure: {source}; rollback error: {rollback}"
            )));
        }
        match self
            .app
            .account_home()
            .rollback_nostr_account_import(imported)
        {
            Ok(()) => Err(source),
            Err(rollback) => Err(AppError::RelayDirectory(format!(
                "failed to roll back account after setup failure: {source}; rollback error: {rollback}"
            ))),
        }
    }

    pub async fn shutdown(&self) {
        self.shared.lifecycle().begin_shutdown();
        let invite_catch_up_tasks = {
            let mut tasks = self
                .invite_catch_up_tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            tasks.accepting = false;
            std::mem::take(&mut tasks.handles)
        };
        // A catch-up may already have passed reconcile's lifecycle check and
        // still be replacing a stale worker. Reap every tracked catch-up
        // before the final worker-map drain so no replacement can escape
        // shutdown. This must run *before* taking `worker_transactions`:
        // catch-up tasks call `catch_up_accounts` -> `reconcile`, which
        // acquires that lock, so awaiting them while holding it would
        // deadlock.
        for task in invite_catch_up_tasks {
            let _ = task.await;
        }
        let _worker_transaction = self.worker_transactions.lock().await;
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

fn debug_identity_field(identity: &Option<String>) -> Option<&str> {
    identity.as_ref().map(|value| {
        if crate::is_nostr_secret(value) {
            "**redacted**"
        } else {
            value.as_str()
        }
    })
}

enum AccountSetupOperation {
    CreateOrImport,
    CreateIdentityOnly,
    Login,
}

fn validate_account_setup_request(
    request: &AccountSetupRequest,
    operation: AccountSetupOperation,
) -> Result<(), AppError> {
    if let Some(identity) = request.identity.as_deref()
        && crate::is_nostr_secret(identity)
    {
        return Err(AppError::UnexpectedPrivateKey);
    }

    match operation {
        AccountSetupOperation::CreateIdentityOnly | AccountSetupOperation::Login => {
            if request.import_nsec.is_some() {
                return Err(AppError::UnexpectedPrivateKey);
            }
        }
        AccountSetupOperation::CreateOrImport => {}
    }

    if let (Some(identity), Some(nsec)) =
        (request.identity.as_deref(), request.import_nsec.as_deref())
    {
        let from_identity = AccountHome::account_id_for_public_key(identity)?;
        let from_secret = AccountHome::account_id_for_secret(nsec)?;
        if from_identity != from_secret {
            return Err(AppError::IdentityKeyMismatch);
        }
    }

    Ok(())
}

fn directory_bootstrap_relays_for_setup(request: &AccountSetupRequest) -> Vec<TransportEndpoint> {
    if request.bootstrap_relays.is_empty() {
        request.default_relays.clone()
    } else {
        request.bootstrap_relays.clone()
    }
}

/// Public indexer relays used to resolve a pre-existing identity's outbox
/// metadata during setup.
///
/// A brand-new external-signer account (or an imported nsec) keeps its NIP-65
/// relay list (kind:10002) and profile (kind:0) on public indexers, not on the
/// app's own messaging relays. Discovering an existing profile against the
/// app's relays therefore finds nothing and the display name never resolves —
/// the exact bug the external-signer work exists to fix. These indexers give
/// the directory preflight a discovery set distinct from the operational
/// messaging relays. They are used only to read the outbox list and profile,
/// they are never adopted as the account's messaging relays.
pub(crate) const VERTEX_DIRECTORY_RELAY: &str = "wss://relay.vertexlab.io";

const DEFAULT_DISCOVERY_INDEXER_RELAYS: &[&str] = &[
    "wss://purplepag.es",
    VERTEX_DIRECTORY_RELAY,
    "wss://nos.lol",
];

pub fn default_directory_discovery_relays() -> Vec<TransportEndpoint> {
    DEFAULT_DISCOVERY_INDEXER_RELAYS
        .iter()
        .map(|relay| TransportEndpoint((*relay).to_string()))
        .collect()
}

/// Discovery relay set for the existing-account directory preflight.
///
/// Unions the caller-supplied setup relays with an explicit discovery set so
/// discovery reaches wherever a pre-existing identity actually published its
/// kind:10002/kind:0, without dropping any indexers a caller passes explicitly.
fn directory_discovery_relays_for_setup(request: &AccountSetupRequest) -> Vec<TransportEndpoint> {
    let mut relays = directory_bootstrap_relays_for_setup(request);
    for endpoint in &request.discovery_relays {
        if !relays.contains(endpoint) {
            relays.push(endpoint.clone());
        }
    }
    relays
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

struct WakeNotificationDrain {
    events: Vec<MarmotAppEvent>,
    lagged: bool,
}

async fn drain_wake_notification_events(
    events: &mut broadcast::Receiver<MarmotAppEvent>,
    remaining: Duration,
) -> WakeNotificationDrain {
    let mut drained = Vec::new();
    let mut lagged = false;
    let drain_until = Instant::now() + remaining;
    loop {
        match events.try_recv() {
            Ok(event) => drained.push(event),
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
                    Ok(Ok(event)) => drained.push(event),
                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => {
                        lagged = true;
                        continue;
                    }
                    Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => break,
                }
            }
            Err(broadcast::error::TryRecvError::Lagged(_)) => {
                lagged = true;
                continue;
            }
            Err(broadcast::error::TryRecvError::Closed) => break,
        }
    }
    WakeNotificationDrain {
        events: drained,
        lagged,
    }
}

async fn project_wake_notification_events(
    app: MarmotApp,
    drain: WakeNotificationDrain,
    min_observed_at: Option<u64>,
) -> Result<Vec<NotificationUpdate>, AppError> {
    blocking_app_task(move || {
        // #639: one resolver shared across the drained batch so repeated
        // settings/group/directory-user lookups are memoized instead of
        // re-opening SQLCipher / directory caches per event.
        let mut resolver = notifications::NotificationResolver::default();
        let mut notifications = Vec::new();
        for event in &drain.events {
            collect_notification_update_from_event(&app, &mut resolver, event, &mut notifications);
        }
        if drain.lagged {
            notifications.extend(notifications::recover_notification_updates(
                &app,
                min_observed_at,
            )?);
        }
        Ok(notifications::dedupe_notification_updates(notifications))
    })
    .await
}

fn collect_notification_update_from_event(
    app: &MarmotApp,
    resolver: &mut notifications::NotificationResolver,
    event: &MarmotAppEvent,
    notifications: &mut Vec<NotificationUpdate>,
) {
    match notifications::notification_update_from_event_cached(app, resolver, event) {
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

fn newest_user_profile(
    cached: Option<UserProfileMetadata>,
    fetched: Option<UserProfileMetadata>,
) -> Option<UserProfileMetadata> {
    match (cached, fetched) {
        (Some(cached), Some(fetched)) if cached.created_at >= fetched.created_at => Some(cached),
        (_, Some(fetched)) => Some(fetched),
        (cached, None) => cached,
    }
}

fn merge_user_profile_update(
    mut current: UserProfileMetadata,
    update: UserProfileMetadata,
) -> UserProfileMetadata {
    current.name = update.name;
    current.display_name = update.display_name;
    current.about = update.about;
    current.picture = update.picture;
    if update.banner.is_some() {
        current.banner = update.banner;
    }
    current.nip05 = update.nip05;
    current.lud16 = update.lud16;
    current.created_at = update.created_at;
    current.source_relays = update.source_relays;
    if !update.extra.is_empty() {
        current.extra = update.extra;
    }
    current
}

#[cfg(test)]
mod tests;

/// Whether a group's membership counts as social proximity for user search.
///
/// A group only speaks for who you know while you are actually in it: an
/// invite you have not accepted is not a relationship yet, and one you left or
/// were removed from has stopped being one. A group the engine froze cannot
/// answer for its membership at all.
fn group_contributes_co_members(group: &AppGroupRecord) -> bool {
    !group.pending_confirmation
        && !group.unrecoverable
        && matches!(group.self_membership, crate::SelfMembership::Member)
}
