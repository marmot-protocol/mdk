use std::collections::{HashMap, HashSet};
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
use nostr_sdk::prelude::{
    Client as NostrSdkClient, Filter, Kind, PublicKey, RelayMessage, RelayPoolNotification,
    RelayUrl, SubscriptionId, Timestamp as NostrTimestamp,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use transport_nostr_adapter::{
    AccountSubscriptionEose, NostrPublishOutcome, NostrReconciliationItem,
    NostrReconciliationSummary, NostrRelayClient, NostrSdkRelayClient, NostrSdkRelayHealth,
    NostrSubscription, NostrTransportAdapter, RelayExportConsent, RelayLabelResolution,
    RelayRegistrationOutcome,
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
    DirectoryEventQuery, DirectoryFetchRequest, DirectoryRelayEventRecord, DirectoryRelayFetcher,
    DirectoryRelayPlane, DirectoryRelayStats, DirectorySubscriptionFilter,
    DirectorySubscriptionSyncSummary, NostrSdkDirectoryRelayFetcher,
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
    directory_events: broadcast::Sender<DirectoryRelayPlaneEvent>,
    account_deliveries: RwLock<HashMap<MemberId, AccountDeliveryRoute>>,
    account_delivery_metrics: Arc<AccountDeliveryMetrics>,
    router: Mutex<Option<JoinHandle<()>>>,
    notification_forwarder: Mutex<Option<JoinHandle<()>>>,
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
    running: AtomicBool,
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

#[derive(Clone)]
pub struct MarmotRelayPlaneAccountAdapter {
    account_id: MemberId,
    relay_plane: MarmotRelayPlane,
    publish_client: Arc<dyn NostrRelayClient>,
    delivery_rx: Arc<Mutex<mpsc::Receiver<AccountDeliveryEvent>>>,
    delivery_overflow: Arc<AccountDeliveryOverflowState>,
    /// Revocable capability shared by every clone of one account session's
    /// adapter. Teardown flips it under `activity` before returning so a stale
    /// AppClient cannot reactivate subscriptions or publish afterward.
    active: Arc<AtomicBool>,
    /// Linearize teardown revocation with subscription and publish I/O. A
    /// writer waits for already-started outbound work; later readers observe
    /// `active = false` and fail without reaching the relay.
    activity: Arc<tokio::sync::RwLock<()>>,
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
    recovery_in_progress: bool,
    dropped: u64,
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
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.pending {
            state.generation = state.generation.saturating_add(1);
            state.pending = true;
            state.dropped = 0;
            state.started_at = Some(Instant::now());
            state.marker_token = rand::rngs::OsRng.next_u64() & i64::MAX as u64;
            state.marker_in_progress = false;
            state.marker_durable = false;
            state.marker_closed = false;
        }
        state.dropped = state.dropped.saturating_add(1);
        state.queue_depth = state.queue_depth.max(queue_depth);
        RelayNotificationForwarderHealth::increment(&self.metrics.dropped, 1);
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
        }
    }

    /// Claim the one account-local marker worker for the current generation.
    /// Once the marker is durable (or storage has closed), later omissions need
    /// only update the bounded counter and reuse the existing control record.
    fn start_marker_persistence(&self) -> bool {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.marker_durable || state.marker_closed || state.marker_in_progress {
            return false;
        }
        state.marker_in_progress = true;
        true
    }

    fn marker_barrier_complete(&self) -> bool {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.marker_durable || state.marker_closed
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

    fn finish_recovery(&self, attempt: AccountDeliveryOverflow) -> Option<u64> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let resolved = state.pending
            && state.generation == attempt.generation
            && state.dropped == attempt.dropped
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
        relay_client: Arc<dyn NostrRelayClient>,
        directory_fetcher: Arc<dyn DirectoryRelayFetcher>,
    ) -> Self {
        Self::from_adapter(
            Some(Duration::from_secs(120)),
            NostrTransportAdapter::new(relay_client),
            None,
            None,
            directory_fetcher,
            false,
        )
    }

    fn from_sdk(subscription_rebuild_lookback: Option<Duration>, allow_loopback: bool) -> Self {
        let client = NostrSdkClient::builder().build();
        let relay_client = NostrSdkRelayClient::new(client.clone());
        let adapter = NostrTransportAdapter::new(Arc::new(relay_client.clone()));
        Self::from_adapter(
            subscription_rebuild_lookback,
            adapter,
            Some(relay_client),
            None,
            Arc::new(NostrSdkDirectoryRelayFetcher::new(client)),
            allow_loopback,
        )
    }

    fn from_adapter(
        subscription_rebuild_lookback: Option<Duration>,
        adapter: NostrTransportAdapter,
        sdk_relay_client: Option<NostrSdkRelayClient>,
        notification_forwarder: Option<JoinHandle<()>>,
        directory_fetcher: Arc<dyn DirectoryRelayFetcher>,
        allow_loopback: bool,
    ) -> Self {
        let transport = Arc::new(RelayPlaneTransport {
            adapter,
            sdk_relay_client,
            directory_events: broadcast::channel(DIRECTORY_EVENT_BUFFER).0,
            account_deliveries: RwLock::new(HashMap::new()),
            account_delivery_metrics: Arc::new(AccountDeliveryMetrics::default()),
            router: Mutex::new(None),
            notification_forwarder: Mutex::new(notification_forwarder),
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
        let delivery_overflow = Arc::new(AccountDeliveryOverflowState {
            inner: std::sync::Mutex::new(AccountDeliveryOverflowInner::default()),
            metrics: self.inner.transport.account_delivery_metrics.clone(),
        });
        account_deliveries_write(&self.inner.transport.account_deliveries).insert(
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
            active: Arc::new(AtomicBool::new(true)),
            activity: Arc::new(tokio::sync::RwLock::new(())),
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

    /// Remove one account's local delivery route and transport subscriptions.
    /// Account teardown calls this independently of whether a managed worker or
    /// a temporary client was able to open, so no-group and degraded-open paths
    /// cannot leave a signed-out identity active in the shared relay plane.
    pub(crate) async fn deactivate_account(
        &self,
        account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        account_deliveries_write(&self.inner.transport.account_deliveries).remove(account_id);
        self.inner
            .transport
            .adapter
            .deactivate_account(account_id)
            .await
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

    /// Attach an account's signing keys to the shared transport client so it
    /// can answer NIP-42 AUTH challenges. Auth-gated relays withhold
    /// gift-wrapped welcomes from unauthenticated subscribers without
    /// surfacing an error — the events are simply absent — so an inbox
    /// subscription issued before a signer is set never sees the invites
    /// those relays hold. The SDK client (and the directory fetcher sharing
    /// it) is one per plane: with multiple accounts the most recently opened
    /// account's keys win, which matches the one-account-per-process apps.
    /// No-op for planes built on a custom relay client.
    pub async fn set_transport_signer(&self, signer: Arc<dyn nostr::NostrSigner>) {
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
            sdk_relay_client.client().set_signer(signer).await;
        }
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

    /// Fetch a finite directory page with explicit per-relay EOSE completion.
    /// Silence, disconnect, notification loss, and the deadline are errors.
    pub(crate) async fn fetch_directory_events_strict(
        &self,
        endpoints: Vec<TransportEndpoint>,
        queries: Vec<DirectoryEventQuery>,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let endpoints = self
            .inner
            .relay_safety
            .sanitize_endpoints(endpoints, "strict directory fetch")?;
        self.inner
            .directory
            .fetch_events_strict(DirectoryFetchRequest::new(endpoints, queries)?)
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
            return self
                .inner
                .directory
                .replace_subscriptions(HashMap::new())
                .await;
        }
        let sdk_relay_client = self
            .inner
            .transport
            .sdk_relay_client
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
            sdk_relay_client
                .client()
                .add_relay(relay_url.clone())
                .await
                .map_err(|_| "directory subscription add relay failed".to_owned())?;
            timeout(
                DIRECTORY_RELAY_CONNECT_WAIT,
                sdk_relay_client.client().connect_relay(relay_url.clone()),
            )
            .await
            .map_err(|_| "directory subscription connect relay timed out".to_owned())?
            .map_err(|_| "directory subscription connect relay failed".to_owned())?;
        }

        let desired_ids = plan
            .batches
            .iter()
            .map(|batch| batch.subscription_id.clone())
            .collect::<HashSet<_>>();
        let (mut to_add, to_remove) = self.inner.directory.subscription_diff(&desired_ids).await;
        if force_rebuild {
            to_add = desired_ids;
        }
        for subscription_id in &to_remove {
            sdk_relay_client
                .client()
                .unsubscribe(&SubscriptionId::new(subscription_id.clone()))
                .await;
        }
        // The validation filter persisted for every batch (added or already
        // active) is keyed on the same canonical-hex authors and kinds the SDK
        // subscription is issued with, so a live notification is only forwarded
        // into the directory cache when it matches an active subscription's
        // requested authors and kinds (mdk#709).
        let mut desired = HashMap::with_capacity(plan.batches.len());
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
            desired.insert(
                batch.subscription_id.clone(),
                DirectorySubscriptionFilter::new(filter_authors, batch.kinds.clone()),
            );
            if !to_add.contains(&batch.subscription_id) {
                continue;
            }
            let mut filter = Filter::new()
                .authors(authors)
                .kinds(kinds)
                .limit(batch.authors.len().saturating_mul(batch.kinds.len()).max(1));
            if let Some(since) = batch.since {
                filter = filter.since(NostrTimestamp::from_secs(since));
            }
            sdk_relay_client
                .client()
                .subscribe_with_id_to(
                    relay_urls.clone(),
                    SubscriptionId::new(batch.subscription_id.clone()),
                    filter,
                    None,
                )
                .await
                .map_err(|err| format!("directory subscription subscribe: {err}"))?;
        }

        self.inner.directory.replace_subscriptions(desired).await
    }

    pub async fn shutdown(&self) {
        self.inner
            .transport
            .shutting_down
            .store(true, Ordering::SeqCst);
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
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
        self.inner
            .transport
            .notification_forwarder_health
            .running
            .store(false, Ordering::SeqCst);
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
            {
                if sdk_relay_client.client().pool().is_shutdown() {
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
                        self.inner.directory.clone(),
                    ));
                }
            }
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
                        if let Some(generation) = signal_generation {
                            if let Some(marker) = route.recovery_marker.clone() {
                                if route.overflow.marker_barrier_complete() {
                                    enqueue_account_delivery_overflow_signal(
                                        &route.sender,
                                        &route.overflow,
                                        generation,
                                    );
                                } else if route.overflow.start_marker_persistence() {
                                    // One account-local task owns this generation's
                                    // persistence. The omitted payload is dropped
                                    // here; later omissions update only the bounded
                                    // counter while the shared router keeps serving
                                    // every other account.
                                    let sender = route.sender.clone();
                                    let overflow_state = route.overflow.clone();
                                    tokio::spawn(async move {
                                        overflow_state.persist_marker_before_drop(marker).await;
                                        enqueue_account_delivery_overflow_signal(
                                            &sender,
                                            &overflow_state,
                                            generation,
                                        );
                                    });
                                }
                            } else {
                                enqueue_account_delivery_overflow_signal(
                                    &route.sender,
                                    &route.overflow,
                                    generation,
                                );
                            }
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
            running: self.running.load(Ordering::Relaxed),
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

struct RelayNotificationConsumerOutcome {
    receiver: broadcast::Receiver<RelayPoolNotification>,
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
    fn notifications(&self) -> broadcast::Receiver<RelayPoolNotification>;
    fn is_shutdown(&self) -> bool;
}

struct SdkRelayNotificationSource {
    client: NostrSdkClient,
}

impl RelayNotificationSource for SdkRelayNotificationSource {
    fn notifications(&self) -> broadcast::Receiver<RelayPoolNotification> {
        self.client.notifications()
    }

    fn is_shutdown(&self) -> bool {
        self.client.pool().is_shutdown()
    }
}

fn spawn_relay_notification_forwarder(
    sdk_relay_client: NostrSdkRelayClient,
    transport: Arc<RelayPlaneTransport>,
    directory: DirectoryRelayPlane,
) -> JoinHandle<()> {
    let source: Arc<dyn RelayNotificationSource> = Arc::new(SdkRelayNotificationSource {
        client: sdk_relay_client.client().clone(),
    });
    spawn_relay_notification_supervisor(source, transport, directory)
}

fn spawn_relay_notification_supervisor(
    source: Arc<dyn RelayNotificationSource>,
    transport: Arc<RelayPlaneTransport>,
    directory: DirectoryRelayPlane,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        transport
            .notification_forwarder_health
            .running
            .store(true, Ordering::SeqCst);
        let mut receiver = None;
        let mut restart_backoff = RelayNotificationRestartBackoff::default();
        loop {
            let adapter = transport.adapter.clone();
            let directory_events = transport.directory_events.clone();
            let directory = directory.clone();
            let source_for_consumer = source.clone();
            let next_receiver = receiver.take();
            let consumer_started_at = Instant::now();
            let mut consumer = tokio::spawn(async move {
                let receiver = next_receiver.unwrap_or_else(|| source_for_consumer.notifications());
                run_relay_notification_consumer(receiver, adapter, directory_events, directory)
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
                        break;
                    }
                    recover_relay_notification_forwarder(&transport, outcome.exit);
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
                    recover_relay_notification_forwarder(
                        &transport,
                        RelayNotificationConsumerExit::Closed,
                    );
                    tokio::time::sleep(
                        restart_backoff.delay_after_failure(consumer_started_at.elapsed()),
                    )
                    .await;
                }
            }
        }
        transport
            .notification_forwarder_health
            .running
            .store(false, Ordering::SeqCst);
    })
}

struct AbortTaskOnDrop(tokio::task::AbortHandle);

impl Drop for AbortTaskOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn run_relay_notification_consumer(
    mut receiver: broadcast::Receiver<RelayPoolNotification>,
    adapter: NostrTransportAdapter,
    directory_events: broadcast::Sender<DirectoryRelayPlaneEvent>,
    directory: DirectoryRelayPlane,
) -> RelayNotificationConsumerOutcome {
    loop {
        match receiver.recv().await {
            Ok(notification) => {
                let should_shutdown = handle_relay_notification(
                    notification,
                    &adapter,
                    &directory_events,
                    &directory,
                )
                .await;
                if should_shutdown {
                    return RelayNotificationConsumerOutcome {
                        receiver,
                        exit: RelayNotificationConsumerExit::Shutdown,
                    };
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                return RelayNotificationConsumerOutcome {
                    receiver,
                    exit: RelayNotificationConsumerExit::Lagged(skipped),
                };
            }
            Err(broadcast::error::RecvError::Closed) => {
                return RelayNotificationConsumerOutcome {
                    receiver,
                    exit: RelayNotificationConsumerExit::Closed,
                };
            }
        }
    }
}

async fn handle_relay_notification(
    notification: RelayPoolNotification,
    adapter: &NostrTransportAdapter,
    directory_events: &broadcast::Sender<DirectoryRelayPlaneEvent>,
    directory: &DirectoryRelayPlane,
) -> bool {
    match notification {
        RelayPoolNotification::Event {
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
                    endpoint: endpoint.clone(),
                    subscription_id: Some(subscription_id.clone()),
                    event: event.clone(),
                };
                // The transport adapter path is unchanged: every
                // SDK event still feeds account/group delivery
                // and telemetry. Only the directory cache path is
                // gated, so an unsolicited or filter-mismatched
                // event from a malicious or buggy relay cannot
                // create persistent directory search-graph writes
                // (mdk#709).
                let _ = adapter.handle_relay_event(relay_event).await;
                if directory
                    .accepts_live_event(&subscription_id, &event.pubkey, event.kind)
                    .await
                {
                    let _ = directory_events.send(DirectoryRelayPlaneEvent::Record(
                        DirectoryRelayEventRecord {
                            endpoints: vec![endpoint],
                            event,
                        },
                    ));
                } else {
                    tracing::trace!(
                        target: "marmot_app::relay_plane",
                        method = "handle_relay_notification",
                        "dropping directory relay event: no matching active directory subscription"
                    );
                }
            }
            false
        }
        RelayPoolNotification::Message {
            relay_url,
            message:
                RelayMessage::Event {
                    subscription_id,
                    event,
                },
        } => {
            // Raw per-relay copy (not deduplicated): telemetry
            // only, so cross-relay arrival spread and per-relay
            // first-event timing see every relay's copy. Delivery
            // happens on the deduplicated `Event` arm above. Keep
            // this in sync with the relay plane's own tap; the
            // SDK client's standalone forwarder is unused here.
            if let Ok(event) = NostrTransportEvent::from_nostr_event(&event) {
                tracing::trace!(
                    target: "marmot_app::relay_plane",
                    method = "handle_relay_notification",
                    "observing per-relay event copy"
                );
                adapter
                    .observe_relay_event(transport_nostr_adapter::NostrRelayEvent {
                        endpoint: TransportEndpoint(relay_url.to_string()),
                        subscription_id: Some(subscription_id.to_string()),
                        event,
                    })
                    .await;
            }
            false
        }
        RelayPoolNotification::Message {
            relay_url,
            message: RelayMessage::EndOfStoredEvents(subscription_id),
        } => {
            // EOSE tap: advances the per-relay initial-sync gate
            // and records EOSE latency. No delivery.
            tracing::trace!(
                target: "marmot_app::relay_plane",
                method = "handle_relay_notification",
                "forwarding SDK relay end-of-stored-events"
            );
            adapter
                .handle_relay_eose(
                    TransportEndpoint(relay_url.to_string()),
                    subscription_id.to_string(),
                )
                .await;
            false
        }
        RelayPoolNotification::Shutdown => {
            tracing::debug!(
                target: "marmot_app::relay_plane",
                method = "handle_relay_notification",
                "SDK relay pool shutdown observed"
            );
            true
        }
        _ => false,
    }
}

fn recover_relay_notification_forwarder(
    transport: &RelayPlaneTransport,
    exit: RelayNotificationConsumerExit,
) {
    let account_count = account_deliveries_read(&transport.account_deliveries).len();
    account_deliveries_write(&transport.account_deliveries).clear();
    let _ = transport
        .directory_events
        .send(DirectoryRelayPlaneEvent::RecoveryRequired);
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
    fn ensure_active(&self, account_id: &MemberId) -> Result<(), TransportAdapterError> {
        if account_id == &self.account_id && self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(TransportAdapterError::AccountNotActive(account_id.clone()))
        }
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
                },
                local_items,
                reconcile_since,
                reconcile_until,
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
                },
                local_items,
                reconcile_since,
                reconcile_until,
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
    ) -> Result<String, TransportAdapterError> {
        let _activity = self.activity.read().await;
        self.ensure_active(&self.account_id)?;
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
            .install_group_maintenance_subscription(&self.account_id, &group)
            .await
    }

    pub(crate) async fn group_maintenance_any_eose(&self, subscription_id: &str) -> Option<bool> {
        let _activity = self.activity.read().await;
        if self.ensure_active(&self.account_id).is_err() {
            return None;
        }
        self.relay_plane
            .inner
            .transport
            .adapter
            .subscription_any_eose(subscription_id)
            .await
    }

    /// End-of-stored-events progress across this account activation's frozen
    /// endpoint coverage snapshot.
    ///
    /// The epoch-gap backfill drain reads this to tell a relay that has
    /// finished replaying stored history from one that has simply gone quiet.
    pub(crate) async fn account_subscription_eose(&self) -> AccountSubscriptionEose {
        let _activity = self.activity.read().await;
        if self.ensure_active(&self.account_id).is_err() {
            return AccountSubscriptionEose::default();
        }
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

    pub(crate) fn record_delivery_overflow_recovery_success(&self, elapsed_ms: u64) {
        self.delivery_overflow.record_recovery_success(elapsed_ms);
    }

    pub(crate) fn fail_delivery_overflow_recovery(&self) {
        self.delivery_overflow.fail_recovery();
    }

    pub(crate) async fn remove_group_maintenance_subscription(
        &self,
        group: &TransportGroupSubscription,
    ) -> Result<(), TransportAdapterError> {
        let _activity = self.activity.read().await;
        self.ensure_active(&self.account_id)?;
        let sync = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_group_sync(TransportGroupSync {
                account_id: self.account_id.clone(),
                group_subscriptions: vec![group.clone()],
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
            .remove_group_maintenance_subscription(NostrSubscription::GroupMaintenance {
                account_id: self.account_id.clone(),
                group_id: group.group_id,
                transport_group_id: group.transport_group_id,
                endpoints: group.endpoints,
            })
            .await
    }
}

#[async_trait]
impl TransportAdapter for MarmotRelayPlaneAccountAdapter {
    async fn activate_account(
        &self,
        activation: TransportAccountActivation,
    ) -> Result<(), TransportAdapterError> {
        let _activity = self.activity.read().await;
        self.ensure_active(&activation.account_id)?;
        let activation = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_activation(activation)
            .map_err(TransportAdapterError::Subscription)?;
        self.relay_plane
            .inner
            .transport
            .adapter
            .activate_account(activation)
            .await
    }

    async fn sync_account_groups(
        &self,
        sync: TransportGroupSync,
    ) -> Result<(), TransportAdapterError> {
        let _activity = self.activity.read().await;
        self.ensure_active(&sync.account_id)?;
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
        let _activity = self.activity.write().await;
        // Revoke before network cleanup. Even when unsubscribe fails, this
        // session can no longer recreate its subscriptions or publish.
        self.active.store(false, Ordering::Release);
        self.relay_plane.deactivate_account(account_id).await
    }

    async fn publish(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        let _activity = self.activity.read().await;
        self.ensure_active(&request.account_id)?;
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
            .publish_event(request.target.endpoints(), &event, request.required_acks)
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
        self.ensure_active(&self.account_id)?;
        match self.receive_account_delivery().await? {
            Some(AccountDeliveryReceive::Delivery(delivery)) => {
                self.ensure_active(&self.account_id)?;
                Ok(Some(*delivery))
            }
            Some(AccountDeliveryReceive::Overflow(_)) => Err(TransportAdapterError::Other(
                "account delivery overflow recovery required".to_owned(),
            )),
            None => Ok(None),
        }
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
