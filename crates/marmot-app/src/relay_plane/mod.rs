use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::{
    Arc, RwLock, RwLockReadGuard, RwLockWriteGuard,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cgka_traits::transport::Timestamp;
use cgka_traits::{
    MemberId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportDelivery, TransportEndpoint, TransportGroupSubscription, TransportGroupSync,
    TransportPublishReport, TransportPublishRequest,
};
use futures::{Stream, StreamExt};
use nostr_sdk::NotificationUpdate;
use nostr_sdk::prelude::{
    Client as NostrSdkClient, ClientNotification, Filter, Kind, PublicKey, RelayMessage, RelayUrl,
    SubscriptionId, Timestamp as NostrTimestamp,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use transport_nostr_adapter::{
    AccountSubscriptionEose, NostrAcquisitionCancellation, NostrAcquisitionError,
    NostrAcquisitionRequest, NostrAcquisitionResult, NostrPublishOutcome, NostrReconciliationItem,
    NostrReconciliationSummary, NostrRelayClient, NostrSdkRelayClient, NostrSdkRelayHealth,
    NostrSubscription, NostrTransportAdapter, RelayExportConsent, RelayLabelResolution,
    RelayRegistrationOutcome, SubscriptionAttempt,
};

use crate::config::RelayTelemetryExportConfig;
use transport_nostr_peeler::NostrTransportEvent;

use crate::directory::DirectorySyncPlan;

mod directory;
mod safety;
mod telemetry;

pub use safety::{RelayEndpointClassification, RelayEndpointPolicy, retired_relay_hosts};
pub use telemetry::{
    EngineReorgMetrics, RelayRollupEntry, RelayTelemetryRollup, RelayTelemetrySnapshot,
};

pub(crate) use directory::{
    DirectoryEventQuery, DirectoryFetchOutcome, DirectoryFetchRequest, DirectoryInspectionError,
    DirectoryRelayEventRecord, DirectoryRelayFetcher, DirectoryRelayPlane, DirectoryRelayStats,
    DirectorySubscriptionFilter, DirectorySubscriptionSyncSummary, NostrSdkDirectoryRelayFetcher,
};
pub(crate) use safety::RelaySafetyPolicy;
pub(crate) use telemetry::rollup_from_snapshots;

// Re-exported so the in-tree `tests` module (which uses `super::*`) keeps
// reaching these names unchanged after the split moved their only non-test
// uses into the submodules above.
#[cfg(test)]
pub(crate) use cgka_traits::TransportPublishTarget;
#[cfg(test)]
pub(crate) use transport_nostr_adapter::{
    DurationHistogramSnapshot, NostrAdapterMetrics, RelayDeliverySpread, RelaySyncSnapshot,
};

pub(crate) const ACCOUNT_DELIVERY_BUFFER: usize = 1024;
const DIRECTORY_EVENT_BUFFER: usize = 1024;
pub(crate) const DIRECTORY_RELAY_CONNECT_WAIT: Duration = Duration::from_secs(5);
const RELAY_PLANE_SHUTDOWN_WAIT: Duration = Duration::from_secs(2);
const RELAY_PLANE_TASK_ABORT_WAIT: Duration = Duration::from_millis(250);
const RELAY_NOTIFICATION_RESTART_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const RELAY_NOTIFICATION_RESTART_MAX_BACKOFF: Duration = Duration::from_secs(30);
const RELAY_NOTIFICATION_RESTART_HEALTHY_RUNTIME: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct MarmotRelayPlane {
    inner: Arc<MarmotRelayPlaneInner>,
}

struct MarmotRelayPlaneInner {
    subscription_rebuild_lookback: Option<Duration>,
    relay_safety: RelaySafetyPolicy,
    transport: Arc<RelayPlaneTransport>,
    directory: DirectoryRelayPlane,
    directory_subscription_sync: Mutex<()>,
}

struct RelayPlaneTransport {
    adapter: NostrTransportAdapter,
    sdk_relay_client: Option<NostrSdkRelayClient>,
    directory_client: Option<NostrSdkClient>,
    directory_events: broadcast::Sender<DirectoryRelayPlaneEvent>,
    account_deliveries: RwLock<HashMap<MemberId, AccountDeliveryRoute>>,
    account_delivery_metrics: Arc<AccountDeliveryMetrics>,
    router: Mutex<Option<JoinHandle<()>>>,
    notification_forwarder: Mutex<Option<JoinHandle<()>>>,
    account_notification_forwarders: Mutex<HashMap<MemberId, JoinHandle<()>>>,
    directory_notification_forwarder: Mutex<Option<JoinHandle<()>>>,
    notification_forwarder_health: Arc<RelayNotificationForwarderHealth>,
    shutting_down: AtomicBool,
}

#[derive(Clone, Debug)]
pub(crate) enum DirectoryRelayPlaneEvent {
    Record(DirectoryRelayEventRecord),
    RecoveryRequired,
}

#[derive(Default)]
struct RelayNotificationForwarderHealth {
    running_count: AtomicU64,
    restarts: AtomicU64,
    lag_incidents: AtomicU64,
    lagged_notifications: AtomicU64,
    panics: AtomicU64,
    unexpected_exits: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RelayNotificationForwarderHealthSnapshot {
    running: bool,
    restarts: u64,
    lag_incidents: u64,
    lagged_notifications: u64,
    panics: u64,
    unexpected_exits: u64,
}

#[derive(PartialEq, Eq)]
struct IncrementalActivation {
    inbox_endpoints: Vec<TransportEndpoint>,
    since: Timestamp,
}

#[derive(Clone)]
pub struct MarmotRelayPlaneAccountAdapter {
    account_id: MemberId,
    relay_plane: MarmotRelayPlane,
    publish_client: Arc<dyn NostrRelayClient>,
    delivery_rx: Arc<Mutex<mpsc::Receiver<AccountDeliveryEvent>>>,
    delivery_overflow: Arc<AccountDeliveryOverflowState>,
    incremental_activation: Arc<Mutex<Option<IncrementalActivation>>>,
}

#[derive(Clone)]
struct AccountDeliveryRoute {
    sender: mpsc::Sender<AccountDeliveryEvent>,
    overflow: Arc<AccountDeliveryOverflowState>,
    recovery_marker: Option<AccountDeliveryRecoveryMarker>,
}

pub(crate) type AccountDeliveryRecoveryMarker =
    Arc<dyn Fn(u64, u64) -> Result<(), AccountDeliveryRecoveryMarkerError> + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountDeliveryRecoveryMarkerError {
    Retryable,
    Closed,
}

#[derive(Debug)]
enum AccountDeliveryEvent {
    Delivery(Box<TransportDelivery>),
    Overflow { generation: u64 },
}

/// Aggregate, privacy-safe description of one unresolved per-account queue
/// overflow generation. The account identity never leaves the private route
/// registry; callers see only counts, queue depth, and elapsed time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AccountDeliveryOverflow {
    pub(crate) generation: u64,
    pub(crate) marker_token: u64,
    pub(crate) dropped: u64,
    pub(crate) notification_losses: u64,
    pub(crate) notification_token: u64,
    pub(crate) queue_depth: usize,
    pub(crate) elapsed_ms: u64,
}

#[derive(Debug)]
pub(crate) enum AccountDeliveryReceive {
    Delivery(Box<TransportDelivery>),
    Overflow(AccountDeliveryOverflow),
}

#[derive(Default)]
struct AccountDeliveryOverflowState {
    inner: std::sync::Mutex<AccountDeliveryOverflowInner>,
    metrics: Arc<AccountDeliveryMetrics>,
}

#[derive(Default)]
struct AccountDeliveryOverflowInner {
    generation: u64,
    pending: bool,
    signal_queued: bool,
    marker_signal_pending: bool,
    recovery_in_progress: bool,
    dropped: u64,
    notification_losses: u64,
    notification_token: u64,
    notification_imported: u64,
    queue_depth: usize,
    started_at: Option<Instant>,
    recovery_started_at: Option<Instant>,
    marker_token: u64,
    marker_in_progress: bool,
    marker_durable: bool,
    marker_closed: bool,
}

#[derive(Default)]
struct AccountDeliveryMetrics {
    max_queue_depth: AtomicU64,
    dropped: AtomicU64,
    recovery_attempts: AtomicU64,
    recovery_successes: AtomicU64,
    recovery_failures: AtomicU64,
    recovery_elapsed_ms: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AccountDeliveryMetricsSnapshot {
    queue_depth: usize,
    max_queue_depth: u64,
    dropped: u64,
    recovery_attempts: u64,
    recovery_successes: u64,
    recovery_failures: u64,
    recovery_elapsed_ms: u64,
}

impl AccountDeliveryMetrics {
    fn snapshot(
        &self,
        routes: &RwLock<HashMap<MemberId, AccountDeliveryRoute>>,
    ) -> AccountDeliveryMetricsSnapshot {
        let queue_depth = account_deliveries_read(routes)
            .values()
            .map(|route| {
                route
                    .sender
                    .max_capacity()
                    .saturating_sub(route.sender.capacity())
            })
            .fold(0_usize, usize::saturating_add);
        AccountDeliveryMetricsSnapshot {
            queue_depth,
            max_queue_depth: self.max_queue_depth.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            recovery_attempts: self.recovery_attempts.load(Ordering::Relaxed),
            recovery_successes: self.recovery_successes.load(Ordering::Relaxed),
            recovery_failures: self.recovery_failures.load(Ordering::Relaxed),
            recovery_elapsed_ms: self.recovery_elapsed_ms.load(Ordering::Relaxed),
        }
    }
}

impl AccountDeliveryOverflowState {
    fn observe_queue_depth(&self, queue_depth: usize) {
        let depth = u64::try_from(queue_depth).unwrap_or(u64::MAX);
        self.metrics
            .max_queue_depth
            .fetch_max(depth, Ordering::Relaxed);
    }

    /// Record an omitted delivery and return the generation only when this
    /// caller must enqueue the generation's control record.
    fn record_drop(&self, queue_depth: usize) -> Option<u64> {
        self.record_loss(queue_depth, false)
    }

    fn record_notification_loss(&self) -> Option<u64> {
        self.record_loss(0, true)
    }

    fn record_loss(&self, queue_depth: usize, notification: bool) -> Option<u64> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.pending {
            state.generation = state.generation.saturating_add(1);
            state.pending = true;
            state.dropped = 0;
            state.notification_losses = 0;
            state.notification_token = 0;
            state.notification_imported = 0;
            state.started_at = Some(Instant::now());
            state.marker_token = rand::rngs::OsRng.next_u64() & i64::MAX as u64;
            state.marker_in_progress = false;
            state.marker_durable = false;
            state.marker_closed = false;
        }
        if notification {
            state.notification_losses = state.notification_losses.saturating_add(1);
            state.notification_token = rand::rngs::OsRng.next_u64() & i64::MAX as u64;
        } else {
            state.dropped = state.dropped.saturating_add(1);
            state.marker_durable = false;
            RelayNotificationForwarderHealth::increment(&self.metrics.dropped, 1);
        }
        state.queue_depth = state.queue_depth.max(queue_depth);
        self.observe_queue_depth(queue_depth);
        if state.signal_queued {
            None
        } else {
            state.signal_queued = true;
            Some(state.generation)
        }
    }

    fn cancel_signal(&self, generation: u64) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.generation == generation {
            state.signal_queued = false;
            state.marker_signal_pending = false;
        }
    }

    fn defer_marker_signal(&self, generation: u64) {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if state.generation == generation {
            state.marker_signal_pending = true;
        }
    }

    fn take_durable_marker_signal(&self, generation: u64) -> bool {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if state.generation == generation
            && state.marker_signal_pending
            && (state.marker_durable || state.marker_closed)
            && !state.marker_in_progress
        {
            state.marker_signal_pending = false;
            true
        } else {
            false
        }
    }

    /// Claim the one account-local marker worker for the current generation.
    /// Each increased queue count must become durable. One writer aggregates
    /// changes while active; notification incidents belong to the account worker.
    fn start_marker_persistence(&self) -> bool {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.dropped == 0
            || state.marker_durable
            || state.marker_closed
            || state.marker_in_progress
        {
            return false;
        }
        state.marker_in_progress = true;
        true
    }

    #[cfg(test)]
    fn marker_barrier_complete(&self) -> bool {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.dropped == 0 || state.marker_durable || state.marker_closed
    }

    /// Persist the generation marker on one account-local blocking worker while
    /// the shared relay router continues serving every other route. Retryable
    /// failures retain only this task and aggregate later omissions into the
    /// generation counter; terminal storage closure releases the task.
    async fn persist_marker_before_drop(&self, marker: AccountDeliveryRecoveryMarker) {
        let generation = {
            let state = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.generation
        };
        loop {
            let (marker_token, dropped) = {
                let state = self
                    .inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                (state.marker_token, state.dropped)
            };
            let marker = marker.clone();
            match tokio::task::spawn_blocking(move || marker(marker_token, dropped)).await {
                Ok(Ok(())) => {
                    let mut state = self
                        .inner
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if state.generation == generation {
                        if state.dropped != dropped {
                            continue;
                        }
                        state.marker_in_progress = false;
                        state.marker_durable = true;
                    }
                    return;
                }
                Ok(Err(AccountDeliveryRecoveryMarkerError::Closed)) => {
                    let mut state = self
                        .inner
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if state.generation == generation {
                        state.marker_in_progress = false;
                        state.marker_closed = true;
                        tracing::debug!(
                            target: "marmot_app::relay_plane",
                            method = "persist_marker_before_drop",
                            error_kind = "storage_closed",
                            "account delivery overflow marker worker stopped after storage closure",
                        );
                    }
                    return;
                }
                Ok(Err(AccountDeliveryRecoveryMarkerError::Retryable)) | Err(_) => {
                    tracing::warn!(
                        target: "marmot_app::relay_plane",
                        method = "persist_marker_before_drop",
                        error_kind = "overflow_marker_persist_failed",
                        "durable account delivery overflow marker write failed; retrying",
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            let state = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.generation != generation {
                return;
            }
        }
    }

    fn notification_persisted(&self, observed: AccountDeliveryOverflow) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.generation == observed.generation
            && state.notification_token == observed.notification_token
        {
            state.notification_imported = observed.notification_losses;
        }
    }

    fn pending_snapshot(&self) -> Option<AccountDeliveryOverflow> {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (state.pending && !state.recovery_in_progress).then(|| Self::snapshot(&state))
    }

    fn consume_signal(&self, generation: u64) -> AccountDeliveryOverflow {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.generation == generation {
            state.signal_queued = false;
        }
        Self::snapshot(&state)
    }

    fn start_recovery(&self, durable_marker_token: u64) -> AccountDeliveryOverflow {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A durable marker can outlive the process-local route that detected
        // it. Recreate a synthetic pending generation on reopen so completion
        // still has a compare-and-clear guard against new local overflow.
        if !state.pending {
            state.generation = state.generation.saturating_add(1);
            state.pending = true;
            state.dropped = 0;
            state.queue_depth = 0;
            state.started_at = Some(Instant::now());
            // This path exists only because the durable database marker was
            // loaded after a restart; the process-local generation is already
            // covered before its first recovery subscription is issued.
            state.marker_token = durable_marker_token;
            state.marker_durable = true;
            state.marker_closed = false;
        }
        state.recovery_in_progress = true;
        state.recovery_started_at = Some(Instant::now());
        RelayNotificationForwarderHealth::increment(&self.metrics.recovery_attempts, 1);
        Self::snapshot(&state)
    }

    fn restore_recovery_guard(&self, durable_marker_token: u64) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.pending {
            state.generation = state.generation.saturating_add(1);
            state.pending = true;
            state.dropped = 0;
            state.notification_losses = 0;
            state.notification_token = 0;
            state.notification_imported = 0;
            state.queue_depth = 0;
            state.started_at = Some(Instant::now());
            state.marker_token = durable_marker_token;
            state.marker_durable = true;
            state.marker_closed = false;
            state.recovery_in_progress = false;
        }
    }

    fn finish_recovery(&self, attempt: AccountDeliveryOverflow) -> Option<u64> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let resolved = state.pending
            && state.generation == attempt.generation
            && state.marker_token == attempt.marker_token
            && state.dropped == attempt.dropped
            && state.notification_losses == attempt.notification_losses
            && state.notification_imported == state.notification_losses
            && (state.dropped == 0 || state.marker_durable)
            && !state.marker_in_progress
            && !state.marker_closed
            && !state.signal_queued;
        if resolved {
            state.pending = false;
            state.recovery_in_progress = false;
            state.marker_in_progress = false;
            state.marker_durable = false;
            state.marker_closed = false;
            state.started_at = None;
            let elapsed_ms = state
                .recovery_started_at
                .take()
                .map(|started| started.elapsed().as_millis() as u64)
                .unwrap_or_default();
            return Some(elapsed_ms);
        }
        None
    }

    fn record_recovery_success(&self, elapsed_ms: u64) {
        RelayNotificationForwarderHealth::increment(&self.metrics.recovery_successes, 1);
        RelayNotificationForwarderHealth::increment(&self.metrics.recovery_elapsed_ms, elapsed_ms);
    }

    fn fail_recovery(&self) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.recovery_in_progress = false;
        let elapsed_ms = state
            .recovery_started_at
            .take()
            .map(|started| started.elapsed().as_millis() as u64)
            .unwrap_or_default();
        RelayNotificationForwarderHealth::increment(&self.metrics.recovery_failures, 1);
        RelayNotificationForwarderHealth::increment(&self.metrics.recovery_elapsed_ms, elapsed_ms);
    }

    fn blocks_ordinary_eose(&self) -> bool {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.pending && !state.recovery_in_progress
    }

    fn snapshot(state: &AccountDeliveryOverflowInner) -> AccountDeliveryOverflow {
        AccountDeliveryOverflow {
            generation: state.generation,
            marker_token: state.marker_token,
            dropped: state.dropped,
            notification_losses: state.notification_losses,
            notification_token: state.notification_token,
            queue_depth: state.queue_depth,
            elapsed_ms: state
                .started_at
                .map(|started| started.elapsed().as_millis() as u64)
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPlaneHealth {
    pub sdk_backed: bool,
    pub total_relays: usize,
    pub initialized: usize,
    pub pending: usize,
    pub connecting: usize,
    pub connected: usize,
    pub disconnected: usize,
    pub terminated: usize,
    pub banned: usize,
    pub sleeping: usize,
    pub connection_attempts: usize,
    pub connection_successes: usize,
    pub notification_forwarder_running: bool,
    pub notification_forwarder_restarts: u64,
    pub notification_forwarder_lag_incidents: u64,
    pub notification_forwarder_lagged_notifications: u64,
    pub notification_forwarder_panics: u64,
    pub notification_forwarder_unexpected_exits: u64,
    /// Current queued account-delivery records across active accounts.
    #[serde(default)]
    pub account_delivery_queue_depth: usize,
    /// High-water queue depth for any account since this plane started.
    #[serde(default)]
    pub account_delivery_max_queue_depth: u64,
    /// Deliveries omitted from full per-account queues and covered by an
    /// explicit recovery generation.
    #[serde(default)]
    pub account_delivery_dropped: u64,
    #[serde(default)]
    pub account_delivery_recovery_attempts: u64,
    #[serde(default)]
    pub account_delivery_recovery_successes: u64,
    #[serde(default)]
    pub account_delivery_recovery_failures: u64,
    /// Aggregate wall-clock time spent in completed/failed recovery attempts.
    #[serde(default)]
    pub account_delivery_recovery_elapsed_ms: u64,
    pub directory_inflight_fetches: usize,
    pub directory_active_subscriptions: usize,
    #[serde(default)]
    pub directory_auth_required_routes: usize,
    pub directory_completed_fetches: usize,
    pub directory_coalesced_waiters: usize,
    pub directory_failed_fetches: usize,
    pub directory_completed_subscription_syncs: usize,
    pub directory_subscriptions_created: usize,
    pub directory_subscriptions_removed: usize,
}

impl MarmotRelayPlane {
    pub fn runtime_default(subscription_rebuild_lookback: Duration) -> Self {
        Self::from_sdk(Some(subscription_rebuild_lookback), false)
    }

    /// Production runtime plane whose relay-safety chokepoint admits loopback
    /// endpoints only when `allow_loopback` is set
    /// (`MarmotAppConfig::allow_loopback_relay_endpoints`, off by default).
    pub fn runtime_default_with_loopback(
        subscription_rebuild_lookback: Duration,
        allow_loopback: bool,
    ) -> Self {
        Self::from_sdk(Some(subscription_rebuild_lookback), allow_loopback)
    }

    pub fn full_history() -> Self {
        Self::from_sdk(None, false)
    }

    /// Full-history plane whose relay-safety chokepoint admits loopback
    /// endpoints only when `allow_loopback` is set
    /// (`MarmotAppConfig::allow_loopback_relay_endpoints`, off by default).
    pub fn full_history_with_loopback(allow_loopback: bool) -> Self {
        Self::from_sdk(None, allow_loopback)
    }

    pub fn with_subscription_rebuild_lookback(lookback: Duration) -> Self {
        Self::from_sdk(Some(lookback), false)
    }

    pub fn new(
        subscription_rebuild_lookback: Option<Duration>,
        relay_client: Arc<dyn NostrRelayClient>,
    ) -> Self {
        Self::new_with_loopback(subscription_rebuild_lookback, relay_client, false)
    }

    pub(crate) fn new_with_loopback(
        subscription_rebuild_lookback: Option<Duration>,
        relay_client: Arc<dyn NostrRelayClient>,
        allow_loopback: bool,
    ) -> Self {
        let adapter = NostrTransportAdapter::new(relay_client);
        Self::from_adapter(
            subscription_rebuild_lookback,
            adapter,
            None,
            None,
            Arc::new(NostrSdkDirectoryRelayFetcher::standalone()),
            allow_loopback,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_directory_fetcher_for_test(
        subscription_rebuild_lookback: Option<Duration>,
        relay_client: Arc<dyn NostrRelayClient>,
        directory_fetcher: Arc<dyn DirectoryRelayFetcher>,
        allow_loopback: bool,
    ) -> Self {
        Self::from_adapter(
            subscription_rebuild_lookback,
            NostrTransportAdapter::new(relay_client),
            None,
            None,
            directory_fetcher,
            allow_loopback,
        )
    }

    fn from_sdk(subscription_rebuild_lookback: Option<Duration>, allow_loopback: bool) -> Self {
        let directory_client = directory::anonymous_directory_client();
        let relay_client = NostrSdkRelayClient::multi_account();
        let adapter = NostrTransportAdapter::new(Arc::new(relay_client.clone()));
        Self::from_adapter(
            subscription_rebuild_lookback,
            adapter,
            Some(relay_client),
            Some(directory_client.clone()),
            Arc::new(NostrSdkDirectoryRelayFetcher::standalone()),
            allow_loopback,
        )
    }

    fn from_adapter(
        subscription_rebuild_lookback: Option<Duration>,
        adapter: NostrTransportAdapter,
        sdk_relay_client: Option<NostrSdkRelayClient>,
        directory_client: Option<NostrSdkClient>,
        directory_fetcher: Arc<dyn DirectoryRelayFetcher>,
        allow_loopback: bool,
    ) -> Self {
        let transport = Arc::new(RelayPlaneTransport {
            adapter,
            sdk_relay_client,
            directory_client,
            directory_events: broadcast::channel(DIRECTORY_EVENT_BUFFER).0,
            account_deliveries: RwLock::new(HashMap::new()),
            account_delivery_metrics: Arc::new(AccountDeliveryMetrics::default()),
            router: Mutex::new(None),
            notification_forwarder: Mutex::new(None),
            account_notification_forwarders: Mutex::new(HashMap::new()),
            directory_notification_forwarder: Mutex::new(None),
            notification_forwarder_health: Arc::new(RelayNotificationForwarderHealth::default()),
            shutting_down: AtomicBool::new(false),
        });
        let this = Self {
            inner: Arc::new(MarmotRelayPlaneInner {
                subscription_rebuild_lookback,
                relay_safety: RelaySafetyPolicy::with_allow_loopback(allow_loopback),
                transport,
                directory: DirectoryRelayPlane::new(directory_fetcher),
                directory_subscription_sync: Mutex::new(()),
            }),
        };
        this.spawn_router();
        this
    }

    /// Build an account adapter without durable queue-overflow recovery.
    ///
    /// Production callers must use `account_adapter_with_recovery_marker` with
    /// a marker. This compatibility constructor is retained for tests and
    /// embedders that do not persist account projection state.
    pub fn account_adapter(
        &self,
        account_id: MemberId,
        publish_client: Arc<dyn NostrRelayClient>,
    ) -> MarmotRelayPlaneAccountAdapter {
        self.account_adapter_with_recovery_marker(account_id, publish_client, None)
    }

    pub(crate) fn account_adapter_with_recovery_marker(
        &self,
        account_id: MemberId,
        publish_client: Arc<dyn NostrRelayClient>,
        recovery_marker: Option<AccountDeliveryRecoveryMarker>,
    ) -> MarmotRelayPlaneAccountAdapter {
        self.spawn_router();
        // Keep one slot reserved for the overflow control record. Ordinary
        // deliveries stop at ACCOUNT_DELIVERY_BUFFER, so a full account queue
        // can always carry the explicit recovery signal without awaiting the
        // slow consumer or blocking the shared router.
        let (delivery_tx, delivery_rx) = mpsc::channel(ACCOUNT_DELIVERY_BUFFER + 1);
        let mut routes = account_deliveries_write(&self.inner.transport.account_deliveries);
        let delivery_overflow = routes
            .get(&account_id)
            .map(|route| route.overflow.clone())
            .unwrap_or_else(|| {
                Arc::new(AccountDeliveryOverflowState {
                    inner: std::sync::Mutex::new(AccountDeliveryOverflowInner::default()),
                    metrics: self.inner.transport.account_delivery_metrics.clone(),
                })
            });
        routes.insert(
            account_id.clone(),
            AccountDeliveryRoute {
                sender: delivery_tx,
                overflow: delivery_overflow.clone(),
                recovery_marker,
            },
        );
        MarmotRelayPlaneAccountAdapter {
            account_id,
            relay_plane: self.clone(),
            publish_client,
            delivery_rx: Arc::new(Mutex::new(delivery_rx)),
            delivery_overflow,
            incremental_activation: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn inject_delivery_for_test(&self, delivery: TransportDelivery) -> bool {
        let sender = account_deliveries_read(&self.inner.transport.account_deliveries)
            .get(&delivery.account_id)
            .cloned();
        match sender {
            Some(route) => route
                .sender
                .send(AccountDeliveryEvent::Delivery(Box::new(delivery)))
                .await
                .is_ok(),
            None => false,
        }
    }

    pub(crate) fn sanitize_relay_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Result<Vec<TransportEndpoint>, String> {
        self.inner
            .relay_safety
            .sanitize_endpoints(endpoints, context)
    }

    /// Check the production relay dial policy before a history request may
    /// register an endpoint absent from this account's current SDK pool.
    pub async fn acquire_history(
        &self,
        request: NostrAcquisitionRequest,
        cancellation: NostrAcquisitionCancellation,
    ) -> Result<NostrAcquisitionResult, NostrAcquisitionError> {
        request.validate()?;
        let checked = self
            .inner
            .relay_safety
            .sanitize_endpoints(request.endpoints.clone(), "history acquisition")
            .map_err(|_| NostrAcquisitionError::InvalidRequest)?;
        if checked.len() != request.endpoints.len() {
            return Err(NostrAcquisitionError::InvalidRequest);
        }
        self.inner
            .transport
            .adapter
            .acquire_history(request, cancellation)
            .await
    }

    /// Classify caller-owned relay URLs under the exact policy used at every
    /// relay-plane dial boundary. Results preserve input order and cardinality.
    pub fn classify_relay_endpoints(
        &self,
        endpoints: Vec<String>,
    ) -> Vec<RelayEndpointClassification> {
        self.inner.relay_safety.classify_endpoints(endpoints)
    }

    pub fn subscription_rebuild_since(
        &self,
        last_transport_timestamp: Option<u64>,
    ) -> Option<Timestamp> {
        let lookback = self.inner.subscription_rebuild_lookback?;
        let last_transport_timestamp = last_transport_timestamp?;
        // The persisted cursor is advanced from the sender-controlled inbound
        // `created_at`; a far-future value would push `since` past the present,
        // so relays return no present-dated events and reception silently halts
        // forever (the cursor is persisted and monotonic, so it survives
        // restarts — mdk#182).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // A cursor detectably in the future is corrupted, not authoritative.
        // Merely clamping it to wall-clock would yield `since = now - lookback`
        // and permanently skip any valid backlog older than the (short,
        // production-default 120s) lookback for an account whose cursor was
        // poisoned before the write-side clamp existed. Treat it as untrusted
        // and request a full-history replay (`None`) so the catch-up range is
        // never silently dropped; the write side then heals the stored value
        // back below wall-clock. A cursor at or behind wall-clock is trusted
        // and used as-is.
        if last_transport_timestamp > now {
            return None;
        }
        Some(Timestamp(
            last_transport_timestamp.saturating_sub(lookback.as_secs()),
        ))
    }

    /// The subscription-rebuild lookback in seconds, if this plane rebuilds
    /// from the durable cursor. `None` means the plane rebuilds with full
    /// history (no `since` floor). Surfaced for the `subscription_rebuild`
    /// forensic audit row so an analyzer sees the window subtracted from the
    /// cursor to derive the `since` floor.
    pub fn subscription_rebuild_lookback_secs(&self) -> Option<u64> {
        self.inner
            .subscription_rebuild_lookback
            .map(|lookback| lookback.as_secs())
    }

    /// Drain the per-relay subscription-registration outcomes `account`
    /// accumulated since its previous drain, for its `subscription_rebuild`
    /// forensic audit row.
    ///
    /// Delegates to the SDK relay client, which records each subscribe's
    /// per-endpoint acceptance bucketed by account. The drain is account-scoped
    /// so concurrent account workers sharing this one relay plane each attribute
    /// their own registrations to their own audit row; a group shared across
    /// accounts registers once, attributed to whichever account's client
    /// subscribed (an acceptable diagnostic attribution). A plane built on a
    /// custom (non-SDK) relay client does not track registration outcomes, so
    /// this returns empty for it — the audit row then carries `since`/`lookback`
    /// without relay rows.
    pub async fn take_subscription_registrations(
        &self,
        account: &MemberId,
    ) -> Vec<RelayRegistrationOutcome> {
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
            return sdk_relay_client
                .take_subscription_registrations(account)
                .await;
        }
        Vec::new()
    }

    /// Register the immutable NIP-42 context before any account subscription.
    /// A custom injected relay client owns its own authentication behavior.
    pub async fn set_transport_signer(
        &self,
        account_id: &MemberId,
        signer: Arc<dyn transport_nostr_peeler::MarmotNostrSigner>,
    ) -> Result<(), TransportAdapterError> {
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
            let account_client = sdk_relay_client
                .register_account(account_id.clone(), signer)
                .await?;
            let mut forwarders = self
                .inner
                .transport
                .account_notification_forwarders
                .lock()
                .await;
            if forwarders
                .get(account_id)
                .is_none_or(JoinHandle::is_finished)
                && !self.inner.transport.shutting_down.load(Ordering::SeqCst)
            {
                if forwarders.remove(account_id).is_some() {
                    recover_relay_notification_forwarder_scoped(
                        &self.inner.transport,
                        RelayNotificationConsumerExit::Closed,
                        Some(account_id),
                    );
                }
                forwarders.insert(
                    account_id.clone(),
                    spawn_relay_notification_forwarder_scoped(
                        account_client,
                        self.inner.transport.clone(),
                        Some(account_id.clone()),
                    ),
                );
            }
        }
        Ok(())
    }

    /// Retire a stopped account worker's subscriptions and immutable SDK
    /// authenticator before a replacement worker can register a fresh signer.
    pub(crate) async fn deactivate_account_context(
        &self,
        account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        account_deliveries_write(&self.inner.transport.account_deliveries).remove(account_id);
        self.inner
            .transport
            .adapter
            .deactivate_account(account_id)
            .await?;
        if let Some(sdk) = &self.inner.transport.sdk_relay_client {
            sdk.remove_account(account_id).await;
        }
        if let Some(handle) = self
            .inner
            .transport
            .account_notification_forwarders
            .lock()
            .await
            .remove(account_id)
        {
            handle.abort();
        }
        Ok(())
    }

    pub async fn relay_health(&self) -> RelayPlaneHealth {
        let directory = self.inner.directory.stats().await;
        let forwarder = self
            .inner
            .transport
            .notification_forwarder_health
            .snapshot();
        let account_delivery = self
            .inner
            .transport
            .account_delivery_metrics
            .snapshot(&self.inner.transport.account_deliveries);
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
            return RelayPlaneHealth::from_sdk(
                sdk_relay_client.relay_health().await,
                directory,
                forwarder,
                account_delivery,
            );
        }
        RelayPlaneHealth::from_directory(directory, account_delivery)
    }

    /// Snapshot the device-local relay telemetry for local inspection.
    ///
    /// Aggregate and privacy-safe: counts, millisecond histogram buckets, and
    /// opaque relay indices only. There is a single shared adapter per device,
    /// so these counters already span every local account. Resolving the opaque
    /// indices to relay URLs is reserved for the opt-in export path.
    pub async fn relay_telemetry(&self) -> RelayTelemetrySnapshot {
        let adapter = &self.inner.transport.adapter;
        RelayTelemetrySnapshot {
            metrics: adapter.metrics().await,
            delivery_spread: adapter.delivery_spread().await,
            sync: adapter.relay_sync().await,
            health: self.relay_health().await,
        }
    }

    /// Resolve opaque relay indices to relay endpoints — the export label
    /// boundary.
    ///
    /// Crate-private and reachable only through the exporter. It returns `None`
    /// unless [`RelayTelemetryExportConfig::export_allowed`] holds (the same
    /// gate as [`MarmotRelayPlane::telemetry_exporter`]); only then does it mint
    /// a [`RelayExportConsent`] and ask the adapter to reverse-map indices to
    /// relay URLs. No other code path turns a device-local index into a relay
    /// URL. See the privacy contract in `relay-observability.md`.
    pub(crate) async fn resolve_relay_labels(
        &self,
        config: &RelayTelemetryExportConfig,
    ) -> Option<RelayLabelResolution> {
        // Same gate as `telemetry_exporter`: resolution cannot happen unless
        // export is opted in with a TLS/loopback endpoint, auth, and resource
        // metadata.
        if !config.export_allowed() {
            return None;
        }
        let consent = RelayExportConsent::affirm();
        Some(
            self.inner
                .transport
                .adapter
                .resolve_relay_labels(consent)
                .await,
        )
    }

    /// Aggregate the device-local per-relay telemetry into one export-ready
    /// rollup, optionally folding in engine-side reorg metrics.
    ///
    /// Keyed by opaque relay index — no relay URLs. The single shared adapter
    /// already merges across local accounts, so today this is a near-passthrough
    /// reshaping; it is the seam where multi-account dedup and engine metrics are
    /// combined for export. `engine` is `None` until the parallel
    /// `observed_reorg_rate` workstream lands.
    pub async fn telemetry_rollup(
        &self,
        engine: Option<EngineReorgMetrics>,
    ) -> RelayTelemetryRollup {
        let adapter = &self.inner.transport.adapter;
        let spread = adapter.delivery_spread().await;
        let sync = adapter.relay_sync().await;
        let metrics = adapter.metrics().await;
        let health = self.relay_health().await;
        rollup_from_snapshots(spread, sync, metrics, health, engine)
    }

    pub(crate) async fn fetch_directory_events(
        &self,
        endpoints: Vec<TransportEndpoint>,
        queries: Vec<DirectoryEventQuery>,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let endpoints = self
            .inner
            .relay_safety
            .sanitize_endpoints(endpoints, "directory fetch")?;
        self.inner
            .directory
            .fetch_events(DirectoryFetchRequest::new(endpoints, queries)?)
            .await
    }

    pub(crate) async fn fetch_directory_events_with_completion(
        &self,
        endpoints: Vec<TransportEndpoint>,
        queries: Vec<DirectoryEventQuery>,
    ) -> Result<DirectoryFetchOutcome, String> {
        let endpoints = self
            .inner
            .relay_safety
            .sanitize_endpoints(endpoints, "directory fetch")?;
        self.inner
            .directory
            .fetch_events_with_completion(DirectoryFetchRequest::new(endpoints, queries)?)
            .await
    }

    pub(crate) async fn inspect_directory_events(
        &self,
        endpoint: TransportEndpoint,
        query: DirectoryEventQuery,
        signer: Option<Arc<dyn transport_nostr_peeler::MarmotNostrSigner>>,
    ) -> Result<Vec<DirectoryRelayEventRecord>, directory::DirectoryInspectionError> {
        let endpoints = self
            .inner
            .relay_safety
            .sanitize_endpoints(vec![endpoint], "onboarding inspection")
            .map_err(|_| directory::DirectoryInspectionError::InvalidRequest)?;
        self.inner
            .directory
            .inspect_events(
                DirectoryFetchRequest::new(endpoints, vec![query])
                    .map_err(|_| directory::DirectoryInspectionError::InvalidRequest)?,
                signer,
            )
            .await
    }

    /// Narrow discovered relay endpoints to the safe ones, dropping the rest.
    ///
    /// Unlike the fail-closed sanitize on the dial path, this is for endpoints
    /// another account published; see
    /// [`RelaySafetyPolicy::retain_safe_endpoints`]. What survives is still
    /// sanitized at the dial chokepoint.
    pub(crate) fn retain_safe_discovered_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Vec<TransportEndpoint> {
        self.inner
            .relay_safety
            .retain_safe_endpoints(endpoints, context)
    }

    pub(crate) fn subscribe_directory_events(
        &self,
    ) -> broadcast::Receiver<DirectoryRelayPlaneEvent> {
        self.inner.transport.directory_events.subscribe()
    }

    pub(crate) async fn sync_directory_user_subscriptions(
        &self,
        plan: DirectorySyncPlan,
        force_rebuild: bool,
    ) -> Result<DirectorySubscriptionSyncSummary, String> {
        let _sync_guard = self.inner.directory_subscription_sync.lock().await;
        self.spawn_router();
        let endpoints = self
            .inner
            .relay_safety
            .sanitize_endpoints(plan.endpoints, "directory subscription")?;
        if plan.batches.is_empty() || endpoints.is_empty() {
            if let Some(client) = &self.inner.transport.directory_client {
                let (_, stale) = self
                    .inner
                    .directory
                    .subscription_diff(&HashSet::new())
                    .await;
                for subscription_id in stale {
                    client
                        .unsubscribe(&SubscriptionId::new(subscription_id))
                        .await
                        .map_err(|_| "directory unsubscribe failed".to_owned())?;
                }
            }
            return self
                .inner
                .directory
                .replace_subscriptions(HashMap::new())
                .await;
        }
        let directory_client = self
            .inner
            .transport
            .directory_client
            .as_ref()
            .ok_or_else(|| "directory subscription requires SDK relay plane".to_owned())?;
        let relay_urls = endpoints
            .iter()
            .map(|endpoint| {
                RelayUrl::parse(endpoint.as_str())
                    .map_err(|_| "directory subscription: invalid relay endpoint".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        for relay_url in &relay_urls {
            directory_client
                .add_relay(relay_url.clone())
                .await
                .map_err(|_| "directory subscription add relay failed".to_owned())?;
            timeout(
                DIRECTORY_RELAY_CONNECT_WAIT,
                directory_client.connect_relay(relay_url.clone()),
            )
            .await
            .map_err(|_| "directory subscription connect relay timed out".to_owned())?
            .map_err(|_| "directory subscription connect relay failed".to_owned())?;
        }
        let endpoints_changed = self
            .inner
            .directory
            .set_subscription_endpoints(&relay_urls)
            .await;

        let desired_ids = plan
            .batches
            .iter()
            .map(|batch| batch.subscription_id.clone())
            .collect::<HashSet<_>>();
        let (mut to_add, to_remove) = self.inner.directory.subscription_diff(&desired_ids).await;
        if force_rebuild || endpoints_changed {
            to_add = desired_ids;
            self.inner.directory.mark_rebuild_pending(&to_add).await;
        }
        for subscription_id in &to_remove {
            directory_client
                .unsubscribe(&SubscriptionId::new(subscription_id.clone()))
                .await
                .map_err(|_| "directory unsubscribe failed".to_owned())?;
        }
        if force_rebuild || endpoints_changed {
            for subscription_id in &to_add {
                directory_client
                    .unsubscribe(&SubscriptionId::new(subscription_id.clone()))
                    .await
                    .map_err(|_| "directory unsubscribe failed".to_owned())?;
            }
        }
        // The validation filter persisted for every batch (added or already
        // active) is keyed on the same canonical-hex authors and kinds the SDK
        // subscription is issued with, so a live notification is only forwarded
        // into the directory cache when it matches an active subscription's
        // requested authors and kinds (mdk#709).
        let mut desired = HashMap::with_capacity(plan.batches.len());
        let mut subscriptions_created = 0;
        for batch in &plan.batches {
            let authors = batch
                .authors
                .iter()
                .map(|author| PublicKey::parse(author).map_err(|_| "invalid directory author"))
                .collect::<Result<Vec<_>, _>>()?;
            let kinds = batch
                .kinds
                .iter()
                .map(|kind| {
                    u16::try_from(*kind)
                        .map(Kind::from)
                        .map_err(|_| format!("unsupported Nostr kind {kind}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            // Canonical lowercase hex matches the `event.pubkey` form a forwarded
            // SDK event carries, so the membership check is exact.
            let filter_authors = authors.iter().map(PublicKey::to_hex).collect::<Vec<_>>();
            let validation_filter =
                DirectorySubscriptionFilter::new(filter_authors, batch.kinds.clone());
            desired.insert(batch.subscription_id.clone(), validation_filter.clone());
            if !to_add.contains(&batch.subscription_id) {
                continue;
            }
            self.inner
                .directory
                .clear_auth_required(&batch.subscription_id)
                .await;
            let mut filter = Filter::new()
                .authors(authors)
                .kinds(kinds)
                .limit(batch.authors.len().saturating_mul(batch.kinds.len()).max(1));
            if let Some(since) = batch.since {
                filter = filter.since(NostrTimestamp::from_secs(since));
            }
            let previous = self
                .inner
                .directory
                .record_subscription_filter(batch.subscription_id.clone(), validation_filter)
                .await;
            let subscription = directory_client
                .subscribe(nostr_sdk::prelude::ReqTarget::manual(
                    relay_urls
                        .iter()
                        .cloned()
                        .map(|url| (url, vec![filter.clone()])),
                ))
                .with_id(SubscriptionId::new(batch.subscription_id.clone()))
                .await;
            if !subscription.is_ok_and(|output| !output.success.is_empty()) {
                self.inner
                    .directory
                    .restore_failed_subscription_filter(&batch.subscription_id, previous)
                    .await;
                return Err("directory subscription registered on no relays".to_owned());
            }
            subscriptions_created += usize::from(previous.is_none());
            self.inner
                .directory
                .mark_subscription_installed(&batch.subscription_id)
                .await;
        }

        self.inner
            .directory
            .complete_subscription_sync(desired, subscriptions_created)
            .await
    }

    pub async fn shutdown(&self) {
        self.inner
            .transport
            .shutting_down
            .store(true, Ordering::SeqCst);
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
            let _ = timeout(
                RELAY_PLANE_SHUTDOWN_WAIT,
                sdk_relay_client.shutdown_accounts(),
            )
            .await;
            let timed_out = timeout(
                RELAY_PLANE_SHUTDOWN_WAIT,
                sdk_relay_client.client().shutdown(),
            )
            .await
            .is_err();
            if timed_out {
                tracing::warn!(
                    target: "marmot_app::relay_plane",
                    method = "shutdown",
                    "SDK relay pool shutdown timed out",
                );
            }
        }
        if let Some(directory_client) = &self.inner.transport.directory_client {
            let _ = timeout(RELAY_PLANE_SHUTDOWN_WAIT, directory_client.shutdown()).await;
        }
        account_deliveries_write(&self.inner.transport.account_deliveries).clear();
        if let Some(handle) = self.inner.transport.router.lock().await.take() {
            let mut handle = handle;
            handle.abort();
            let _ = timeout(RELAY_PLANE_TASK_ABORT_WAIT, &mut handle).await;
        }
        if let Some(handle) = self
            .inner
            .transport
            .notification_forwarder
            .lock()
            .await
            .take()
        {
            let mut handle = handle;
            handle.abort();
            let _ = timeout(RELAY_PLANE_TASK_ABORT_WAIT, &mut handle).await;
        }
        let account_forwarders = self
            .inner
            .transport
            .account_notification_forwarders
            .lock()
            .await
            .drain()
            .map(|(_, handle)| handle)
            .collect::<Vec<_>>();
        for mut handle in account_forwarders {
            handle.abort();
            let _ = timeout(RELAY_PLANE_TASK_ABORT_WAIT, &mut handle).await;
        }
        if let Some(handle) = self
            .inner
            .transport
            .directory_notification_forwarder
            .lock()
            .await
            .take()
        {
            let mut handle = handle;
            handle.abort();
            let _ = timeout(RELAY_PLANE_TASK_ABORT_WAIT, &mut handle).await;
        }
        self.inner
            .transport
            .notification_forwarder_health
            .running_count
            .store(0, Ordering::SeqCst);
    }

    fn spawn_router(&self) {
        if self.inner.transport.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if let Ok(mut notification_forwarder) =
            self.inner.transport.notification_forwarder.try_lock()
        {
            let needs_forwarder = match notification_forwarder.as_ref() {
                None => true,
                Some(forwarder) => forwarder.is_finished(),
            };
            if needs_forwarder
                && let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client
                && !sdk_relay_client.is_multi_account()
            {
                if sdk_relay_client.client().is_shutdown() {
                    notification_forwarder.take();
                } else {
                    if notification_forwarder.take().is_some() {
                        recover_relay_notification_forwarder(
                            &self.inner.transport,
                            RelayNotificationConsumerExit::Closed,
                        );
                    }
                    *notification_forwarder = Some(spawn_relay_notification_forwarder(
                        sdk_relay_client.clone(),
                        self.inner.transport.clone(),
                    ));
                }
            }
        }
        if let Ok(mut forwarder) = self
            .inner
            .transport
            .directory_notification_forwarder
            .try_lock()
            && forwarder.as_ref().is_none_or(JoinHandle::is_finished)
            && let Some(client) = &self.inner.transport.directory_client
            && !client.is_shutdown()
        {
            if forwarder.take().is_some() {
                let _ = self
                    .inner
                    .transport
                    .directory_events
                    .send(DirectoryRelayPlaneEvent::RecoveryRequired);
            }
            *forwarder = Some(spawn_directory_notification_forwarder(
                Arc::new(SdkRelayNotificationSource {
                    client: client.clone(),
                    loss: None,
                }),
                self.inner.transport.directory_events.clone(),
                self.inner.directory.clone(),
            ));
        }
        let Ok(mut router) = self.inner.transport.router.try_lock() else {
            return;
        };
        if router.is_some() {
            return;
        }
        let transport = self.inner.transport.clone();
        let adapter = transport.adapter.clone();
        let handle = handle.spawn(async move {
            while let Ok(Some(delivery)) = adapter.receive().await {
                let sender = account_deliveries_read(&transport.account_deliveries)
                    .get(&delivery.account_id)
                    .cloned();
                if let Some(route) = sender {
                    // Fan out without awaiting the per-account queue: a single
                    // account whose receiver has stalled (full buffer) must not
                    // block this shared router and back-pressure delivery for
                    // every other account (and, upstream, the relay notification
                    // pipeline). The extra channel slot is reserved for one
                    // overflow record. Once ordinary capacity is exhausted,
                    // every omitted delivery belongs to that explicit recovery
                    // generation; the account cannot trust EOSE or its cursor
                    // again until an unfloored replay resolves the generation.
                    let queue_depth = route
                        .sender
                        .max_capacity()
                        .saturating_sub(route.sender.capacity());
                    route.overflow.observe_queue_depth(queue_depth);
                    if route.sender.capacity() <= 1 {
                        let signal_generation = route.overflow.record_drop(queue_depth);
                        if let Some(marker) = route.recovery_marker.clone() {
                            persist_queue_loss(&route.sender, &route.overflow, marker, signal_generation);
                        } else if let Some(generation) = signal_generation {
                            enqueue_account_delivery_overflow_signal(&route.sender, &route.overflow, generation);
                        }
                        tracing::warn!(
                            target: "marmot_app::relay_plane",
                            method = "spawn_router",
                            queue_depth,
                            "omitting transport delivery: account delivery queue overflow recovery required",
                        );
                        continue;
                    }
                    match route
                        .sender
                        .try_send(AccountDeliveryEvent::Delivery(Box::new(delivery)))
                    {
                        Ok(()) => {
                            let queue_depth = route
                                .sender
                                .max_capacity()
                                .saturating_sub(route.sender.capacity());
                            route.overflow.observe_queue_depth(queue_depth);
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // Only this router writes the route, and it reserves
                            // one control slot above, so reaching Full here
                            // indicates a violated queue invariant rather than
                            // ordinary backpressure.
                            tracing::warn!(
                                target: "marmot_app::relay_plane",
                                method = "spawn_router",
                                error_kind = "reserved_overflow_slot_unavailable",
                                "account delivery queue invariant failed",
                            );
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {}
                    }
                }
            }
        });
        *router = Some(handle);
    }

    #[cfg(test)]
    pub(crate) async fn handle_relay_event_for_test(
        &self,
        relay_event: transport_nostr_adapter::NostrRelayEvent,
    ) -> Result<usize, TransportAdapterError> {
        self.inner
            .transport
            .adapter
            .handle_relay_event(relay_event)
            .await
    }

    #[cfg(test)]
    pub(crate) fn set_account_delivery_recovery_marker_for_test(
        &self,
        account_id: &MemberId,
        marker: AccountDeliveryRecoveryMarker,
    ) -> bool {
        let mut routes = account_deliveries_write(&self.inner.transport.account_deliveries);
        let Some(route) = routes.get_mut(account_id) else {
            return false;
        };
        route.recovery_marker = Some(marker);
        true
    }

    /// Report end-of-stored-events for one subscription on one endpoint, the
    /// way [`handle_relay_notification`] does for an SDK-backed plane. An
    /// injected relay client produces no relay messages of its own, so tests
    /// that need an EOSE-gated drain to complete drive this seam instead.
    #[cfg(test)]
    pub(crate) async fn handle_relay_eose_for_test(
        &self,
        endpoint: TransportEndpoint,
        subscription_id: String,
    ) {
        self.inner
            .transport
            .adapter
            .handle_relay_eose(endpoint, subscription_id)
            .await;
    }

    /// Drive the managed account worker through its receive-error reconnect path
    /// by closing inbound delivery, matching relay-notification recovery.
    #[cfg(test)]
    pub(crate) fn simulate_notification_recovery_for_test(&self, skipped_notifications: u64) {
        recover_relay_notification_forwarder(
            &self.inner.transport,
            RelayNotificationConsumerExit::Lagged(skipped_notifications),
        );
    }
}

impl RelayPlaneHealth {
    fn from_sdk(
        health: NostrSdkRelayHealth,
        directory: DirectoryRelayStats,
        forwarder: RelayNotificationForwarderHealthSnapshot,
        account_delivery: AccountDeliveryMetricsSnapshot,
    ) -> Self {
        Self {
            sdk_backed: true,
            total_relays: health.total_relays,
            initialized: health.initialized,
            pending: health.pending,
            connecting: health.connecting,
            connected: health.connected,
            disconnected: health.disconnected,
            terminated: health.terminated,
            banned: health.banned,
            sleeping: health.sleeping,
            connection_attempts: health.connection_attempts,
            connection_successes: health.connection_successes,
            notification_forwarder_running: forwarder.running,
            notification_forwarder_restarts: forwarder.restarts,
            notification_forwarder_lag_incidents: forwarder.lag_incidents,
            notification_forwarder_lagged_notifications: forwarder.lagged_notifications,
            notification_forwarder_panics: forwarder.panics,
            notification_forwarder_unexpected_exits: forwarder.unexpected_exits,
            account_delivery_queue_depth: account_delivery.queue_depth,
            account_delivery_max_queue_depth: account_delivery.max_queue_depth,
            account_delivery_dropped: account_delivery.dropped,
            account_delivery_recovery_attempts: account_delivery.recovery_attempts,
            account_delivery_recovery_successes: account_delivery.recovery_successes,
            account_delivery_recovery_failures: account_delivery.recovery_failures,
            account_delivery_recovery_elapsed_ms: account_delivery.recovery_elapsed_ms,
            directory_inflight_fetches: directory.inflight_fetches,
            directory_active_subscriptions: directory.active_subscriptions,
            directory_auth_required_routes: directory.auth_required_routes,
            directory_completed_fetches: directory.completed_fetches,
            directory_coalesced_waiters: directory.coalesced_waiters,
            directory_failed_fetches: directory.failed_fetches,
            directory_completed_subscription_syncs: directory.completed_subscription_syncs,
            directory_subscriptions_created: directory.subscriptions_created,
            directory_subscriptions_removed: directory.subscriptions_removed,
        }
    }

    fn from_directory(
        directory: DirectoryRelayStats,
        account_delivery: AccountDeliveryMetricsSnapshot,
    ) -> Self {
        Self {
            account_delivery_queue_depth: account_delivery.queue_depth,
            account_delivery_max_queue_depth: account_delivery.max_queue_depth,
            account_delivery_dropped: account_delivery.dropped,
            account_delivery_recovery_attempts: account_delivery.recovery_attempts,
            account_delivery_recovery_successes: account_delivery.recovery_successes,
            account_delivery_recovery_failures: account_delivery.recovery_failures,
            account_delivery_recovery_elapsed_ms: account_delivery.recovery_elapsed_ms,
            directory_inflight_fetches: directory.inflight_fetches,
            directory_active_subscriptions: directory.active_subscriptions,
            directory_auth_required_routes: directory.auth_required_routes,
            directory_completed_fetches: directory.completed_fetches,
            directory_coalesced_waiters: directory.coalesced_waiters,
            directory_failed_fetches: directory.failed_fetches,
            directory_completed_subscription_syncs: directory.completed_subscription_syncs,
            directory_subscriptions_created: directory.subscriptions_created,
            directory_subscriptions_removed: directory.subscriptions_removed,
            ..Self::default()
        }
    }
}

impl RelayNotificationForwarderHealth {
    fn snapshot(&self) -> RelayNotificationForwarderHealthSnapshot {
        RelayNotificationForwarderHealthSnapshot {
            running: self.running_count.load(Ordering::Relaxed) > 0,
            restarts: self.restarts.load(Ordering::Relaxed),
            lag_incidents: self.lag_incidents.load(Ordering::Relaxed),
            lagged_notifications: self.lagged_notifications.load(Ordering::Relaxed),
            panics: self.panics.load(Ordering::Relaxed),
            unexpected_exits: self.unexpected_exits.load(Ordering::Relaxed),
        }
    }

    fn increment(counter: &AtomicU64, value: u64) {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(value))
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayNotificationConsumerExit {
    Shutdown,
    Lagged(u64),
    Closed,
}

type RelayNotificationStream =
    Pin<Box<dyn Stream<Item = NotificationUpdate<ClientNotification>> + Send>>;

struct RelayNotificationConsumerOutcome {
    receiver: RelayNotificationStream,
    exit: RelayNotificationConsumerExit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RelayNotificationRestartBackoff {
    next: Duration,
}

impl Default for RelayNotificationRestartBackoff {
    fn default() -> Self {
        Self {
            next: RELAY_NOTIFICATION_RESTART_INITIAL_BACKOFF,
        }
    }
}

impl RelayNotificationRestartBackoff {
    fn delay_after_failure(&mut self, consumer_runtime: Duration) -> Duration {
        if consumer_runtime >= RELAY_NOTIFICATION_RESTART_HEALTHY_RUNTIME {
            self.next = RELAY_NOTIFICATION_RESTART_INITIAL_BACKOFF;
        }
        let delay = self.next;
        self.next = self
            .next
            .saturating_mul(2)
            .min(RELAY_NOTIFICATION_RESTART_MAX_BACKOFF);
        delay
    }
}

trait RelayNotificationSource: Send + Sync {
    fn notifications(&self) -> RelayNotificationStream;
    fn is_shutdown(&self) -> bool;
    fn record_loss(&self, _skipped: u64) {}
    fn receiver_replaced(&self) {}
    #[cfg(test)]
    fn worker_failure_hook(&self) -> Option<Arc<NotificationWorkerFailureHook>> {
        None
    }
    #[cfg(test)]
    fn notification_queued(&self) {}
}

#[cfg(test)]
struct NotificationWorkerFailureHook {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    fail_once: AtomicBool,
}

struct SdkRelayNotificationSource {
    client: NostrSdkClient,
    loss: Option<NostrSdkRelayClient>,
}

impl RelayNotificationSource for SdkRelayNotificationSource {
    fn notifications(&self) -> RelayNotificationStream {
        self.client.notifications_with_gaps()
    }

    fn is_shutdown(&self) -> bool {
        self.client.is_shutdown()
    }

    fn record_loss(&self, skipped: u64) {
        if let Some(loss) = &self.loss {
            loss.record_notification_gap(skipped);
        }
    }

    fn receiver_replaced(&self) {
        if let Some(loss) = &self.loss {
            loss.notification_receiver_replaced();
        }
    }
}

fn spawn_relay_notification_forwarder(
    sdk_relay_client: NostrSdkRelayClient,
    transport: Arc<RelayPlaneTransport>,
) -> JoinHandle<()> {
    spawn_relay_notification_forwarder_scoped(sdk_relay_client, transport, None)
}

fn spawn_relay_notification_forwarder_scoped(
    sdk_relay_client: NostrSdkRelayClient,
    transport: Arc<RelayPlaneTransport>,
    account_id: Option<MemberId>,
) -> JoinHandle<()> {
    let source: Arc<dyn RelayNotificationSource> = Arc::new(SdkRelayNotificationSource {
        client: sdk_relay_client.client().clone(),
        loss: Some(sdk_relay_client),
    });
    spawn_relay_notification_supervisor_scoped(source, transport, account_id)
}

/// Public directory interests have their own unauthenticated SDK client and
/// receiver. A gap here invalidates directory coverage without interrupting
/// an account's live delivery or attributing the loss to an account.
fn spawn_directory_notification_forwarder(
    source: Arc<dyn RelayNotificationSource>,
    events: broadcast::Sender<DirectoryRelayPlaneEvent>,
    directory: DirectoryRelayPlane,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut receiver = source.notifications();
        loop {
            match receiver.next().await {
                Some(NotificationUpdate::Notification(ClientNotification::Event {
                    relay_url,
                    subscription_id,
                    event,
                })) => {
                    let subscription_id = subscription_id.to_string();
                    if let Ok(event) = NostrTransportEvent::from_nostr_event(&event)
                        && directory
                            .accepts_live_event_from(
                                &subscription_id,
                                relay_url.as_str(),
                                &event.pubkey,
                                event.kind,
                            )
                            .await
                    {
                        let _ = events.send(DirectoryRelayPlaneEvent::Record(
                            DirectoryRelayEventRecord {
                                endpoints: vec![TransportEndpoint(relay_url.to_string())],
                                event,
                            },
                        ));
                    }
                }
                Some(NotificationUpdate::Notification(ClientNotification::Message {
                    relay_url,
                    message,
                })) => {
                    if let RelayMessage::Closed {
                        subscription_id,
                        message,
                    } = *message
                        && message.starts_with("auth-required:")
                        && directory
                            .mark_auth_required(subscription_id.as_str(), relay_url.as_str())
                            .await
                    {
                        let count = directory.stats().await.auth_required_routes;
                        tracing::warn!(
                            target: "marmot_app::relay_plane",
                            method = "spawn_directory_notification_forwarder",
                            auth_required_routes = count,
                            "anonymous directory request requires authentication",
                        );
                    }
                }
                Some(NotificationUpdate::Notification(ClientNotification::Shutdown)) => break,
                Some(NotificationUpdate::Lagged { skipped }) => {
                    tracing::warn!(
                        target: "marmot_app::relay_plane",
                        method = "spawn_directory_notification_forwarder",
                        skipped_notifications = skipped,
                        "directory SDK receiver lost notifications",
                    );
                    let _ = events.send(DirectoryRelayPlaneEvent::RecoveryRequired);
                }
                None => {
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
fn spawn_relay_notification_supervisor(
    source: Arc<dyn RelayNotificationSource>,
    transport: Arc<RelayPlaneTransport>,
) -> JoinHandle<()> {
    spawn_relay_notification_supervisor_scoped(source, transport, None)
}

fn spawn_relay_notification_supervisor_scoped(
    source: Arc<dyn RelayNotificationSource>,
    transport: Arc<RelayPlaneTransport>,
    account_id: Option<MemberId>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _running = RunningSupervisorGuard::new(transport.notification_forwarder_health.clone());
        let mut receiver = None;
        let mut restart_backoff = RelayNotificationRestartBackoff::default();
        loop {
            let adapter = transport.adapter.clone();
            let source_for_consumer = source.clone();
            let next_receiver = receiver.take();
            let consumer_started_at = Instant::now();
            if next_receiver.is_none() {
                source.receiver_replaced();
            }
            let consumer_account_id = account_id.clone();
            let mut consumer = tokio::spawn(async move {
                let receiver = next_receiver.unwrap_or_else(|| source_for_consumer.notifications());
                run_relay_notification_consumer_scoped(
                    receiver,
                    adapter,
                    consumer_account_id,
                    source_for_consumer,
                )
                .await
            });
            let abort_on_drop = AbortTaskOnDrop(consumer.abort_handle());
            match (&mut consumer).await {
                Ok(outcome) => {
                    drop(abort_on_drop);
                    receiver = Some(outcome.receiver);
                    if outcome.exit == RelayNotificationConsumerExit::Shutdown
                        || transport.shutting_down.load(Ordering::SeqCst)
                        || source.is_shutdown()
                    {
                        if matches!(outcome.exit, RelayNotificationConsumerExit::Lagged(_)) {
                            recover_relay_notification_forwarder_scoped(
                                &transport,
                                outcome.exit,
                                account_id.as_ref(),
                            );
                        }
                        break;
                    }
                    recover_relay_notification_forwarder_scoped(
                        &transport,
                        outcome.exit,
                        account_id.as_ref(),
                    );
                    if outcome.exit == RelayNotificationConsumerExit::Closed {
                        receiver = None;
                        tokio::time::sleep(
                            restart_backoff.delay_after_failure(consumer_started_at.elapsed()),
                        )
                        .await;
                    }
                }
                Err(join_error) => {
                    drop(abort_on_drop);
                    if transport.shutting_down.load(Ordering::SeqCst) || source.is_shutdown() {
                        break;
                    }
                    RelayNotificationForwarderHealth::increment(
                        &transport.notification_forwarder_health.panics,
                        u64::from(join_error.is_panic()),
                    );
                    receiver = None;
                    recover_relay_notification_forwarder_scoped(
                        &transport,
                        RelayNotificationConsumerExit::Closed,
                        account_id.as_ref(),
                    );
                    tokio::time::sleep(
                        restart_backoff.delay_after_failure(consumer_started_at.elapsed()),
                    )
                    .await;
                }
            }
        }
    })
}

struct RunningSupervisorGuard(Arc<RelayNotificationForwarderHealth>);

impl RunningSupervisorGuard {
    fn new(health: Arc<RelayNotificationForwarderHealth>) -> Self {
        health.running_count.fetch_add(1, Ordering::SeqCst);
        Self(health)
    }
}

impl Drop for RunningSupervisorGuard {
    fn drop(&mut self) {
        // Terminal shutdown may already have reset the aggregate to zero.
        let _ = self
            .0
            .running_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                Some(count.saturating_sub(1))
            });
    }
}

struct AbortTaskOnDrop(tokio::task::AbortHandle);

impl Drop for AbortTaskOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
async fn run_relay_notification_consumer(
    mut receiver: RelayNotificationStream,
    adapter: NostrTransportAdapter,
) -> RelayNotificationConsumerOutcome {
    loop {
        match receiver.next().await {
            Some(NotificationUpdate::Notification(notification)) => {
                let should_shutdown = handle_relay_notification(notification, &adapter, None).await;
                if should_shutdown {
                    return RelayNotificationConsumerOutcome {
                        receiver,
                        exit: RelayNotificationConsumerExit::Shutdown,
                    };
                }
            }
            Some(NotificationUpdate::Lagged { skipped }) => {
                return RelayNotificationConsumerOutcome {
                    receiver,
                    exit: RelayNotificationConsumerExit::Lagged(skipped),
                };
            }
            None => {
                return RelayNotificationConsumerOutcome {
                    receiver,
                    exit: RelayNotificationConsumerExit::Closed,
                };
            }
        }
    }
}

/// Keep reading the SDK receiver while account delivery or telemetry awaits.
/// The bounded queue is an event lane; a full queue becomes a typed gap before
/// the reader can block, and the watch control lane advances independently.
fn abandoned_notification_lane(
    pending: &AtomicU64,
    source: &dyn RelayNotificationSource,
) -> RelayNotificationConsumerExit {
    let abandoned = pending.load(Ordering::SeqCst);
    if abandoned > 0 {
        source.record_loss(abandoned);
        RelayNotificationConsumerExit::Lagged(abandoned)
    } else {
        RelayNotificationConsumerExit::Closed
    }
}

async fn run_relay_notification_consumer_scoped(
    mut receiver: RelayNotificationStream,
    adapter: NostrTransportAdapter,
    account_id: Option<MemberId>,
    source: Arc<dyn RelayNotificationSource>,
) -> RelayNotificationConsumerOutcome {
    const EVENT_QUEUE_CAPACITY: usize = 256;
    let (sender, mut event_rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
    // Channel capacity returns to its maximum when a panicked worker drops
    // the receiver, even though queued work was discarded. Count admitted
    // items independently until each worker operation actually finishes.
    let pending = Arc::new(AtomicU64::new(0));
    let worker_pending = pending.clone();
    #[cfg(test)]
    let worker_failure_hook = source.worker_failure_hook();
    let mut worker = tokio::spawn(async move {
        while let Some(notification) = event_rx.recv().await {
            #[cfg(test)]
            if let Some(hook) = &worker_failure_hook
                && hook.fail_once.swap(false, Ordering::SeqCst)
            {
                hook.entered.notify_one();
                hook.release.notified().await;
                panic!("injected relay notification worker failure");
            }
            if handle_relay_notification(notification, &adapter, account_id.as_ref()).await {
                worker_pending.fetch_sub(1, Ordering::SeqCst);
                return true;
            }
            worker_pending.fetch_sub(1, Ordering::SeqCst);
        }
        false
    });
    let abort_on_drop = AbortTaskOnDrop(worker.abort_handle());
    loop {
        tokio::select! {
            worker_result = &mut worker => {
                drop(abort_on_drop);
                let exit = abandoned_notification_lane(&pending, source.as_ref());
                return RelayNotificationConsumerOutcome {
                    receiver,
                    exit: if exit == RelayNotificationConsumerExit::Closed && matches!(worker_result, Ok(true)) {
                        RelayNotificationConsumerExit::Shutdown
                    } else {
                        exit
                    },
                };
            }
            update = receiver.next() => match update {
                Some(NotificationUpdate::Notification(notification)) => {
                    if matches!(notification, ClientNotification::Shutdown) {
                        let abandoned = pending.load(Ordering::SeqCst);
                        if abandoned > 0 {
                            source.record_loss(abandoned);
                        }
                        return RelayNotificationConsumerOutcome {
                            receiver,
                            exit: if abandoned > 0 {
                                RelayNotificationConsumerExit::Lagged(abandoned)
                            } else {
                                RelayNotificationConsumerExit::Shutdown
                            },
                        };
                    }
                    pending.fetch_add(1, Ordering::SeqCst);
                    if let Err(error) = sender.try_send(notification) {
                        pending.fetch_sub(1, Ordering::SeqCst);
                        let skipped = match error {
                            mpsc::error::TrySendError::Full(_) => {
                                1 + pending.load(Ordering::SeqCst)
                            }
                            mpsc::error::TrySendError::Closed(_) => 1,
                        };
                        source.record_loss(skipped);
                        return RelayNotificationConsumerOutcome {
                            receiver,
                            exit: RelayNotificationConsumerExit::Lagged(skipped),
                        };
                    }
                    #[cfg(test)]
                    source.notification_queued();
                }
                Some(NotificationUpdate::Lagged { skipped }) => {
                    let abandoned = skipped
                        .saturating_add(pending.load(Ordering::SeqCst));
                    source.record_loss(abandoned);
                    return RelayNotificationConsumerOutcome {
                        receiver,
                        exit: RelayNotificationConsumerExit::Lagged(abandoned),
                    };
                }
                None => {
                    let abandoned = pending.load(Ordering::SeqCst);
                    if abandoned > 0 {
                        source.record_loss(abandoned);
                    }
                    return RelayNotificationConsumerOutcome {
                        receiver,
                        exit: if abandoned > 0 {
                            RelayNotificationConsumerExit::Lagged(abandoned)
                        } else {
                            RelayNotificationConsumerExit::Closed
                        },
                    };
                }
            }
        }
    }
}

async fn handle_relay_notification(
    notification: ClientNotification,
    adapter: &NostrTransportAdapter,
    account_id: Option<&MemberId>,
) -> bool {
    match notification {
        ClientNotification::Event {
            relay_url,
            subscription_id,
            event,
        } => {
            if let Ok(event) = NostrTransportEvent::from_nostr_event(&event) {
                tracing::trace!(
                    target: "marmot_app::relay_plane",
                    method = "handle_relay_notification",
                    "forwarding SDK relay event"
                );
                let endpoint = TransportEndpoint(relay_url.to_string());
                let subscription_id = subscription_id.to_string();
                let relay_event = transport_nostr_adapter::NostrRelayEvent {
                    endpoint,
                    subscription_id: Some(subscription_id),
                    event,
                };
                // Account notifications feed only account/group delivery.
                // Public directory interests use the anonymous receiver.
                let _ = if let Some(account_id) = account_id {
                    adapter
                        .handle_reconciled_event(account_id, relay_event)
                        .await
                } else {
                    adapter.handle_relay_event(relay_event).await
                };
            }
            false
        }
        ClientNotification::Message { relay_url, message } => {
            match *message {
                RelayMessage::Event {
                    subscription_id,
                    event,
                } => {
                    // Raw per-relay copy is telemetry only. Delivery uses the
                    // deduplicated Event notification above.
                    if let Ok(event) = NostrTransportEvent::from_nostr_event(&event) {
                        adapter
                            .observe_relay_event(transport_nostr_adapter::NostrRelayEvent {
                                endpoint: TransportEndpoint(relay_url.to_string()),
                                subscription_id: Some(subscription_id.to_string()),
                                event,
                            })
                            .await;
                    }
                }
                RelayMessage::EndOfStoredEvents(subscription_id) => {
                    adapter
                        .handle_relay_eose(
                            TransportEndpoint(relay_url.to_string()),
                            subscription_id.to_string(),
                        )
                        .await;
                }
                _ => {}
            }
            false
        }
        ClientNotification::Shutdown => {
            tracing::debug!(
                target: "marmot_app::relay_plane",
                method = "handle_relay_notification",
                "SDK relay pool shutdown observed"
            );
            true
        }
    }
}

fn recover_relay_notification_forwarder(
    transport: &RelayPlaneTransport,
    exit: RelayNotificationConsumerExit,
) {
    recover_relay_notification_forwarder_scoped(transport, exit, None);
}

fn recover_relay_notification_forwarder_scoped(
    transport: &RelayPlaneTransport,
    exit: RelayNotificationConsumerExit,
    account_id: Option<&MemberId>,
) {
    let account_count = match account_id {
        Some(account_id) => usize::from(
            account_deliveries_read(&transport.account_deliveries).contains_key(account_id),
        ),
        None => account_deliveries_read(&transport.account_deliveries).len(),
    };
    // Latch account-local evidence before closing receivers. Keep each loss
    // handle in the existing account registry so replacement adapters inherit
    // the fence; the shared router never awaits account database I/O.
    if !matches!(exit, RelayNotificationConsumerExit::Shutdown) {
        let mut routes = account_deliveries_write(&transport.account_deliveries);
        for (route_account_id, route) in routes.iter_mut() {
            if account_id.is_some_and(|account_id| account_id != route_account_id) {
                continue;
            }
            if matches!(exit, RelayNotificationConsumerExit::Lagged(_)) {
                route.overflow.record_notification_loss();
            }
            // The typed lag is latched across receiver replacement. Only the
            // account worker may persist it, before returning the close signal.
            let generation = route
                .overflow
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .generation;
            route.overflow.cancel_signal(generation);
            let (closed_sender, closed_receiver) = mpsc::channel(1);
            drop(closed_receiver);
            route.sender = closed_sender;
        }
    }
    RelayNotificationForwarderHealth::increment(
        &transport.notification_forwarder_health.restarts,
        1,
    );
    match exit {
        RelayNotificationConsumerExit::Lagged(skipped) => {
            RelayNotificationForwarderHealth::increment(
                &transport.notification_forwarder_health.lag_incidents,
                1,
            );
            RelayNotificationForwarderHealth::increment(
                &transport.notification_forwarder_health.lagged_notifications,
                skipped,
            );
            tracing::warn!(
                target: "marmot_app::relay_plane",
                method = "recover_relay_notification_forwarder",
                skipped_notifications = skipped,
                affected_accounts = account_count,
                "relay notification consumer lagged; restarting inbound delivery",
            );
        }
        RelayNotificationConsumerExit::Closed => {
            RelayNotificationForwarderHealth::increment(
                &transport.notification_forwarder_health.unexpected_exits,
                1,
            );
            tracing::warn!(
                target: "marmot_app::relay_plane",
                method = "recover_relay_notification_forwarder",
                affected_accounts = account_count,
                "relay notification consumer exited unexpectedly; restarting inbound delivery",
            );
        }
        RelayNotificationConsumerExit::Shutdown => {}
    }
}

impl MarmotRelayPlaneAccountAdapter {
    /// Explicit catch-up must reissue even settled, matching subscriptions.
    /// Cancellation leaves reuse disabled until an activation succeeds.
    pub(crate) async fn require_fresh_activation(&self) {
        *self.incremental_activation.lock().await = None;
    }

    /// The account this adapter is bound to — the `MemberId` every subscription
    /// issued through it carries (activation and group sync reject any other
    /// id), and the key its registrations bucket under on the shared relay
    /// plane. Draining the `subscription_rebuild` row uses this so a rebuild is
    /// attributed to exactly the account whose subscribes produced it.
    pub(crate) fn account_id(&self) -> &MemberId {
        &self.account_id
    }

    pub(crate) async fn reconcile_inbox_history(
        &self,
        endpoints: Vec<TransportEndpoint>,
        local_items: &[NostrReconciliationItem],
        reconcile_since: u64,
        reconcile_until: u64,
        progress: &dyn transport_nostr_adapter::NostrReconciliationProgress,
    ) -> Result<Option<NostrReconciliationSummary>, TransportAdapterError> {
        let Some(client) = &self.relay_plane.inner.transport.sdk_relay_client else {
            return Ok(None);
        };
        let activation = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_activation(TransportAccountActivation {
                account_id: self.account_id.clone(),
                inbox_endpoints: endpoints,
                group_subscriptions: Vec::new(),
                since: None,
            })
            .map_err(TransportAdapterError::Subscription)?;
        let result = client
            .reconcile_subscription(
                NostrSubscription::AccountInbox {
                    account_id: self.account_id.clone(),
                    endpoints: activation.inbox_endpoints,
                    since: None,
                    // A one-shot reconciliation REQ is not owned by an account
                    // activation and never feeds the replay-coverage gate.
                    attempt: SubscriptionAttempt::INITIAL,
                },
                local_items,
                reconcile_since,
                reconcile_until,
                progress,
            )
            .await;
        let metric = result
            .as_ref()
            .map(|(summary, _)| summary.clone())
            .unwrap_or_default();
        self.relay_plane
            .inner
            .transport
            .adapter
            .record_reconciliation(&metric)
            .await;
        let (summary, events) = result?;
        for event in events {
            self.relay_plane
                .inner
                .transport
                .adapter
                .handle_reconciled_event(&self.account_id, event)
                .await?;
        }
        Ok(Some(summary))
    }

    pub(crate) async fn reconcile_group_history(
        &self,
        group: TransportGroupSubscription,
        local_items: &[NostrReconciliationItem],
        reconcile_since: u64,
        reconcile_until: u64,
        progress: &dyn transport_nostr_adapter::NostrReconciliationProgress,
    ) -> Result<Option<NostrReconciliationSummary>, TransportAdapterError> {
        let Some(client) = &self.relay_plane.inner.transport.sdk_relay_client else {
            return Ok(None);
        };
        let sync = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_group_sync(TransportGroupSync {
                account_id: self.account_id.clone(),
                group_subscriptions: vec![group],
                since: None,
            })
            .map_err(TransportAdapterError::Subscription)?;
        let group = sync.group_subscriptions.into_iter().next().ok_or_else(|| {
            TransportAdapterError::Subscription(
                "reconciliation group subscription was empty".to_owned(),
            )
        })?;
        let result = client
            .reconcile_subscription(
                NostrSubscription::Group {
                    account_id: self.account_id.clone(),
                    group_id: group.group_id,
                    transport_group_id: group.transport_group_id,
                    endpoints: group.endpoints,
                    since: None,
                    // A one-shot reconciliation REQ is not owned by an account
                    // activation and never feeds the replay-coverage gate.
                    attempt: SubscriptionAttempt::INITIAL,
                },
                local_items,
                reconcile_since,
                reconcile_until,
                progress,
            )
            .await;
        let metric = result
            .as_ref()
            .map(|(summary, _)| summary.clone())
            .unwrap_or_default();
        self.relay_plane
            .inner
            .transport
            .adapter
            .record_reconciliation(&metric)
            .await;
        let (summary, events) = result?;
        for event in events {
            self.relay_plane
                .inner
                .transport
                .adapter
                .handle_reconciled_event(&self.account_id, event)
                .await?;
        }
        Ok(Some(summary))
    }

    pub(crate) async fn install_group_maintenance_subscription(
        &self,
        group: TransportGroupSubscription,
        recovery_attempt: u64,
    ) -> Result<String, TransportAdapterError> {
        let sync = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_group_sync(TransportGroupSync {
                account_id: self.account_id.clone(),
                group_subscriptions: vec![group],
                since: None,
            })
            .map_err(TransportAdapterError::Subscription)?;
        let group = sync.group_subscriptions.into_iter().next().ok_or_else(|| {
            TransportAdapterError::Subscription(
                "maintenance group subscription was empty".to_owned(),
            )
        })?;
        self.relay_plane
            .inner
            .transport
            .adapter
            .install_group_maintenance_recovery_subscription(
                &self.account_id,
                &group,
                recovery_attempt,
            )
            .await
    }

    pub(crate) async fn group_maintenance_any_eose(&self, subscription_id: &str) -> Option<bool> {
        self.relay_plane
            .inner
            .transport
            .adapter
            .subscription_any_eose(subscription_id)
            .await
    }

    /// Operational capability identity only; SDK presence proves neither
    /// endpoint availability nor exhaustive historical coverage.
    pub(crate) fn recovery_comparison_capability_key(&self) -> &'static [u8] {
        if self.relay_plane.inner.transport.sdk_relay_client.is_some() {
            b"sdk-bounded-comparison-v1"
        } else {
            b"no-sdk-reconciliation-v1"
        }
    }

    pub(crate) fn recovery_admitted_endpoints(
        &self,
        endpoints: &[TransportEndpoint],
    ) -> Vec<String> {
        if self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_endpoints(endpoints.to_vec(), "recovery scope")
            .is_err()
        {
            return Vec::new();
        }
        // Preserve signed spelling in the frozen goal. Membership queries use
        // the adapter's forward canonical identity lookup, never URL rewrites.
        let mut result = endpoints
            .iter()
            .map(|endpoint| endpoint.0.clone())
            .collect::<Vec<_>>();
        result.sort();
        result.dedup();
        result
    }

    pub(crate) async fn group_maintenance_endpoint_eose(
        &self,
        subscription_id: &str,
        endpoint: &TransportEndpoint,
    ) -> Option<bool> {
        self.relay_plane
            .inner
            .transport
            .adapter
            .subscription_endpoint_eose(subscription_id, endpoint)
            .await
    }

    /// End-of-stored-events progress across this account activation's frozen
    /// endpoint coverage snapshot.
    ///
    /// The epoch-gap backfill drain reads this to tell a relay that has
    /// finished replaying stored history from one that has simply gone quiet.
    pub(crate) async fn account_subscription_eose(&self) -> AccountSubscriptionEose {
        let mut eose = self
            .relay_plane
            .inner
            .transport
            .adapter
            .account_subscription_eose(&self.account_id)
            .await;
        if self.delivery_overflow.blocks_ordinary_eose() {
            eose.with_eose = 0;
        }
        eose
    }

    pub(crate) async fn receive_account_delivery(
        &self,
    ) -> Result<Option<AccountDeliveryReceive>, TransportAdapterError> {
        let event = self.delivery_rx.lock().await.recv().await;
        Ok(event.map(|event| match event {
            AccountDeliveryEvent::Delivery(delivery) => AccountDeliveryReceive::Delivery(delivery),
            AccountDeliveryEvent::Overflow { generation } => {
                AccountDeliveryReceive::Overflow(self.delivery_overflow.consume_signal(generation))
            }
        }))
    }

    /// Process-local overflow evidence becomes visible at the exact omission,
    /// before marker I/O or the queued control record can complete.
    pub(crate) fn notification_loss_persisted(&self, observed: AccountDeliveryOverflow) {
        self.delivery_overflow.notification_persisted(observed);
    }

    /// A running attempt has not acknowledged loss and cannot advance a cursor.
    pub(crate) fn delivery_loss_blocks_cursor(&self) -> bool {
        self.delivery_overflow
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending
    }

    pub(crate) fn unpersisted_notification_loss(&self) -> Option<AccountDeliveryOverflow> {
        let state = self
            .delivery_overflow
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        (state.pending && state.notification_losses > state.notification_imported)
            .then(|| AccountDeliveryOverflowState::snapshot(&state))
    }

    pub(crate) fn pending_delivery_overflow(&self) -> Option<AccountDeliveryOverflow> {
        self.delivery_overflow.pending_snapshot()
    }

    /// Begin (or resume after process restart) the unfloored replay required by
    /// a durable account-delivery overflow marker.
    pub(crate) fn start_delivery_overflow_recovery(
        &self,
        durable_marker_token: u64,
    ) -> AccountDeliveryOverflow {
        self.delivery_overflow.start_recovery(durable_marker_token)
    }

    /// Resolve only the exact overflow prefix the replay started against. A
    /// newer omitted delivery keeps the generation pending and forces another
    /// unfloored attempt.
    pub(crate) fn finish_delivery_overflow_recovery(
        &self,
        attempt: AccountDeliveryOverflow,
    ) -> Option<u64> {
        self.delivery_overflow.finish_recovery(attempt)
    }

    pub(crate) fn restore_delivery_overflow_guard(&self, durable_marker_token: u64) {
        self.delivery_overflow
            .restore_recovery_guard(durable_marker_token);
    }

    pub(crate) fn record_delivery_overflow_recovery_success(&self, elapsed_ms: u64) {
        self.delivery_overflow.record_recovery_success(elapsed_ms);
    }

    pub(crate) fn fail_delivery_overflow_recovery(&self) {
        self.delivery_overflow.fail_recovery();
    }

    pub(crate) async fn remove_group_maintenance_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<(), TransportAdapterError> {
        self.relay_plane
            .inner
            .transport
            .adapter
            .remove_group_maintenance_recovery_subscription(&self.account_id, subscription_id)
            .await
    }
}

#[async_trait]
impl TransportAdapter for MarmotRelayPlaneAccountAdapter {
    async fn activate_account(
        &self,
        activation: TransportAccountActivation,
    ) -> Result<(), TransportAdapterError> {
        if activation.account_id != self.account_id {
            return Err(TransportAdapterError::AccountNotActive(
                activation.account_id,
            ));
        }
        let activation = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_activation(activation)
            .map_err(TransportAdapterError::Subscription)?;
        let incremental = activation.since.map(|since| IncrementalActivation {
            inbox_endpoints: activation.inbox_endpoints.clone(),
            since,
        });
        let mut previous = self.incremental_activation.lock().await;
        let reuse = incremental.is_some()
            && *previous == incremental
            && self.account_subscription_eose().await.complete();
        // Cancellation or failure must force the next call through activation's
        // unconditional orphan-REQ cleanup. None always requests full history.
        *previous = None;
        let adapter = &self.relay_plane.inner.transport.adapter;
        if reuse {
            adapter
                .sync_account_groups(TransportGroupSync {
                    account_id: activation.account_id,
                    group_subscriptions: activation.group_subscriptions,
                    since: activation.since,
                })
                .await?;
        } else {
            adapter.activate_account(activation).await?;
        }
        *previous = incremental;
        Ok(())
    }

    async fn sync_account_groups(
        &self,
        sync: TransportGroupSync,
    ) -> Result<(), TransportAdapterError> {
        if sync.account_id != self.account_id {
            return Err(TransportAdapterError::AccountNotActive(sync.account_id));
        }
        let sync = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_group_sync(sync)
            .map_err(TransportAdapterError::Subscription)?;
        self.relay_plane
            .inner
            .transport
            .adapter
            .sync_account_groups(sync)
            .await
    }

    async fn deactivate_account(&self, account_id: &MemberId) -> Result<(), TransportAdapterError> {
        if account_id != &self.account_id {
            return Err(TransportAdapterError::AccountNotActive(account_id.clone()));
        }
        let mut activation = self.incremental_activation.lock().await;
        *activation = None;
        self.relay_plane
            .deactivate_account_context(account_id)
            .await
    }

    async fn publish(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        if request.account_id != self.account_id {
            return Err(TransportAdapterError::AccountNotActive(request.account_id));
        }
        let request = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_publish_request(request)
            .map_err(TransportAdapterError::Publish)?;
        request.validate_envelope_matches_target()?;
        let event = NostrTransportEvent::from_transport_message(&request.message)
            .map_err(|e| TransportAdapterError::Publish(format!("Nostr payload: {e}")))?;
        let outcome = self
            .publish_client
            .publish_event_for_account(
                &request.account_id,
                request.target.endpoints(),
                &event,
                request.required_acks,
            )
            .await?;
        let local_fanout_endpoints = if !outcome.accepted.is_empty() {
            outcome
                .accepted
                .iter()
                .map(|receipt| receipt.endpoint.clone())
                .collect::<Vec<_>>()
        } else if outcome.failed.is_empty() {
            request.target.endpoints().to_vec()
        } else {
            Vec::new()
        };
        if !local_fanout_endpoints.is_empty() {
            let mut local_message = request.message.clone();
            if let Some(message_id) = outcome.message_id.clone() {
                local_message.id = message_id;
            }
            self.relay_plane
                .inner
                .transport
                .adapter
                .deliver_local_publish(&local_message, &local_fanout_endpoints)
                .await?;
        }
        Ok(publish_report_from_outcome(outcome, request))
    }

    async fn receive(&self) -> Result<Option<TransportDelivery>, TransportAdapterError> {
        match self.receive_account_delivery().await? {
            Some(AccountDeliveryReceive::Delivery(delivery)) => Ok(Some(*delivery)),
            Some(AccountDeliveryReceive::Overflow(_)) => Err(TransportAdapterError::Other(
                "account delivery overflow recovery required".to_owned(),
            )),
            None => Ok(None),
        }
    }
}

/// Count persistence is independent of whether a control record is already
/// queued. The one writer takes any deferred signal only after its latest
/// watermark is durable, including signals requested while that writer ran.
fn persist_queue_loss(
    sender: &mpsc::Sender<AccountDeliveryEvent>,
    overflow: &Arc<AccountDeliveryOverflowState>,
    marker: AccountDeliveryRecoveryMarker,
    signal: Option<u64>,
) {
    let generation = overflow
        .inner
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .generation;
    if let Some(generation) = signal {
        overflow.defer_marker_signal(generation);
    }
    if overflow.start_marker_persistence() {
        let sender = sender.clone();
        let overflow = overflow.clone();
        tokio::spawn(async move {
            overflow.persist_marker_before_drop(marker).await;
            if overflow.take_durable_marker_signal(generation) {
                enqueue_account_delivery_overflow_signal(&sender, &overflow, generation);
            }
        });
    } else if overflow.take_durable_marker_signal(generation) {
        enqueue_account_delivery_overflow_signal(sender, overflow, generation);
    }
}

fn enqueue_account_delivery_overflow_signal(
    sender: &mpsc::Sender<AccountDeliveryEvent>,
    overflow: &AccountDeliveryOverflowState,
    generation: u64,
) {
    match sender.try_send(AccountDeliveryEvent::Overflow { generation }) {
        Ok(()) => {}
        Err(error) => {
            overflow.cancel_signal(generation);
            tracing::warn!(
                target: "marmot_app::relay_plane",
                method = "spawn_router",
                error_kind = match error {
                    mpsc::error::TrySendError::Full(_) => "queue_full",
                    mpsc::error::TrySendError::Closed(_) => "queue_closed",
                },
                "could not enqueue account delivery overflow recovery signal",
            );
        }
    }
}

fn account_deliveries_read(
    deliveries: &RwLock<HashMap<MemberId, AccountDeliveryRoute>>,
) -> RwLockReadGuard<'_, HashMap<MemberId, AccountDeliveryRoute>> {
    deliveries
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn account_deliveries_write(
    deliveries: &RwLock<HashMap<MemberId, AccountDeliveryRoute>>,
) -> RwLockWriteGuard<'_, HashMap<MemberId, AccountDeliveryRoute>> {
    deliveries
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn publish_report_from_outcome(
    outcome: NostrPublishOutcome,
    request: TransportPublishRequest,
) -> TransportPublishReport {
    TransportPublishReport {
        message_id: outcome.message_id.unwrap_or(request.message.id),
        accepted: outcome.accepted,
        failed: outcome.failed,
        required_acks: request.required_acks,
    }
}

#[cfg(test)]
mod tests;
