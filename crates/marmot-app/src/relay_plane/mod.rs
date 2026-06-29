use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cgka_traits::transport::Timestamp;
use cgka_traits::{
    MemberId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportDelivery, TransportEndpoint, TransportGroupSync, TransportPublishReport,
    TransportPublishRequest,
};
use nostr_sdk::prelude::{
    Client as NostrSdkClient, Filter, Kind, PublicKey, RelayMessage, RelayPoolNotification,
    RelayUrl, SubscriptionId, Timestamp as NostrTimestamp,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use transport_nostr_adapter::{
    NostrPublishOutcome, NostrRelayClient, NostrSdkRelayClient, NostrSdkRelayHealth,
    NostrTransportAdapter, RelayExportConsent, RelayLabelResolution,
};

use crate::config::RelayTelemetryExportConfig;
use transport_nostr_peeler::NostrTransportEvent;

use crate::directory::DirectorySyncPlan;

mod directory;
mod safety;
mod telemetry;

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

const ACCOUNT_DELIVERY_BUFFER: usize = 1024;
const DIRECTORY_EVENT_BUFFER: usize = 1024;
pub(crate) const DIRECTORY_RELAY_CONNECT_WAIT: Duration = Duration::from_secs(5);
const RELAY_PLANE_SHUTDOWN_WAIT: Duration = Duration::from_secs(2);
const RELAY_PLANE_TASK_ABORT_WAIT: Duration = Duration::from_millis(250);

#[derive(Clone)]
pub struct MarmotRelayPlane {
    inner: Arc<MarmotRelayPlaneInner>,
}

struct MarmotRelayPlaneInner {
    subscription_rebuild_lookback: Option<Duration>,
    relay_safety: RelaySafetyPolicy,
    transport: Arc<RelayPlaneTransport>,
    directory: DirectoryRelayPlane,
}

struct RelayPlaneTransport {
    adapter: NostrTransportAdapter,
    sdk_relay_client: Option<NostrSdkRelayClient>,
    directory_events: broadcast::Sender<DirectoryRelayEventRecord>,
    account_deliveries: RwLock<HashMap<MemberId, mpsc::Sender<TransportDelivery>>>,
    router: Mutex<Option<JoinHandle<()>>>,
    notification_forwarder: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct MarmotRelayPlaneAccountAdapter {
    account_id: MemberId,
    relay_plane: MarmotRelayPlane,
    publish_client: Arc<dyn NostrRelayClient>,
    delivery_rx: Arc<Mutex<mpsc::Receiver<TransportDelivery>>>,
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
        Self::from_sdk(Some(subscription_rebuild_lookback))
    }

    pub fn full_history() -> Self {
        Self::from_sdk(None)
    }

    pub fn with_subscription_rebuild_lookback(lookback: Duration) -> Self {
        Self::from_sdk(Some(lookback))
    }

    pub fn new(
        subscription_rebuild_lookback: Option<Duration>,
        relay_client: Arc<dyn NostrRelayClient>,
    ) -> Self {
        let adapter = NostrTransportAdapter::new(relay_client);
        Self::from_adapter(
            subscription_rebuild_lookback,
            adapter,
            None,
            None,
            Arc::new(NostrSdkDirectoryRelayFetcher::standalone()),
        )
    }

    fn from_sdk(subscription_rebuild_lookback: Option<Duration>) -> Self {
        let client = NostrSdkClient::builder().build();
        let relay_client = NostrSdkRelayClient::new(client.clone());
        let adapter = NostrTransportAdapter::new(Arc::new(relay_client.clone()));
        Self::from_adapter(
            subscription_rebuild_lookback,
            adapter,
            Some(relay_client),
            None,
            Arc::new(NostrSdkDirectoryRelayFetcher::new(client)),
        )
    }

    fn from_adapter(
        subscription_rebuild_lookback: Option<Duration>,
        adapter: NostrTransportAdapter,
        sdk_relay_client: Option<NostrSdkRelayClient>,
        notification_forwarder: Option<JoinHandle<()>>,
        directory_fetcher: Arc<dyn DirectoryRelayFetcher>,
    ) -> Self {
        let transport = Arc::new(RelayPlaneTransport {
            adapter,
            sdk_relay_client,
            directory_events: broadcast::channel(DIRECTORY_EVENT_BUFFER).0,
            account_deliveries: RwLock::new(HashMap::new()),
            router: Mutex::new(None),
            notification_forwarder: Mutex::new(notification_forwarder),
        });
        let this = Self {
            inner: Arc::new(MarmotRelayPlaneInner {
                subscription_rebuild_lookback,
                relay_safety: RelaySafetyPolicy::default(),
                transport,
                directory: DirectoryRelayPlane::new(directory_fetcher),
            }),
        };
        this.spawn_router();
        this
    }

    pub fn account_adapter(
        &self,
        account_id: MemberId,
        publish_client: Arc<dyn NostrRelayClient>,
    ) -> MarmotRelayPlaneAccountAdapter {
        self.spawn_router();
        let (delivery_tx, delivery_rx) = mpsc::channel(ACCOUNT_DELIVERY_BUFFER);
        account_deliveries_write(&self.inner.transport.account_deliveries)
            .insert(account_id.clone(), delivery_tx);
        MarmotRelayPlaneAccountAdapter {
            account_id,
            relay_plane: self.clone(),
            publish_client,
            delivery_rx: Arc::new(Mutex::new(delivery_rx)),
        }
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
        // restarts — darkmatter#182).
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

    /// Attach an account's signing keys to the shared transport client so it
    /// can answer NIP-42 AUTH challenges. Auth-gated relays withhold
    /// gift-wrapped welcomes from unauthenticated subscribers without
    /// surfacing an error — the events are simply absent — so an inbox
    /// subscription issued before a signer is set never sees the invites
    /// those relays hold. The SDK client (and the directory fetcher sharing
    /// it) is one per plane: with multiple accounts the most recently opened
    /// account's keys win, which matches the one-account-per-process apps.
    /// No-op for planes built on a custom relay client.
    pub async fn set_transport_signer(&self, keys: nostr::Keys) {
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
            sdk_relay_client.client().set_signer(keys).await;
        }
    }

    pub async fn relay_health(&self) -> RelayPlaneHealth {
        let directory = self.inner.directory.stats().await;
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
            return RelayPlaneHealth::from_sdk(sdk_relay_client.relay_health().await, directory);
        }
        RelayPlaneHealth::from_directory(directory)
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

    pub(crate) fn subscribe_directory_events(
        &self,
    ) -> broadcast::Receiver<DirectoryRelayEventRecord> {
        self.inner.transport.directory_events.subscribe()
    }

    pub(crate) async fn sync_directory_user_subscriptions(
        &self,
        plan: DirectorySyncPlan,
    ) -> Result<DirectorySubscriptionSyncSummary, String> {
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
                    .map_err(|err| format!("directory subscription: invalid relay endpoint: {err}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for relay_url in &relay_urls {
            sdk_relay_client
                .client()
                .add_relay(relay_url.clone())
                .await
                .map_err(|err| format!("directory subscription add relay: {err}"))?;
            timeout(
                DIRECTORY_RELAY_CONNECT_WAIT,
                sdk_relay_client.client().connect_relay(relay_url.clone()),
            )
            .await
            .map_err(|_| "directory subscription connect relay timed out".to_owned())?
            .map_err(|err| format!("directory subscription connect relay: {err}"))?;
        }

        let desired_ids = plan
            .batches
            .iter()
            .map(|batch| batch.subscription_id.clone())
            .collect::<HashSet<_>>();
        let (to_add, to_remove) = self.inner.directory.subscription_diff(&desired_ids).await;
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
        // requested authors and kinds (darkmatter#709).
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
    }

    fn spawn_router(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Ok(mut router) = self.inner.transport.router.try_lock() else {
            return;
        };
        if router.is_some() {
            return;
        }
        if let Ok(mut notification_forwarder) =
            self.inner.transport.notification_forwarder.try_lock()
            && notification_forwarder.is_none()
            && let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client
        {
            *notification_forwarder = Some(spawn_relay_notification_forwarder(
                sdk_relay_client.clone(),
                self.inner.transport.adapter.clone(),
                self.inner.transport.directory_events.clone(),
                self.inner.directory.clone(),
            ));
        }
        let transport = self.inner.transport.clone();
        let adapter = transport.adapter.clone();
        let handle = handle.spawn(async move {
            while let Ok(Some(delivery)) = adapter.receive().await {
                let sender = account_deliveries_read(&transport.account_deliveries)
                    .get(&delivery.account_id)
                    .cloned();
                if let Some(sender) = sender {
                    // Fan out without awaiting the per-account queue: a single
                    // account whose receiver has stalled (full buffer) must not
                    // block this shared router and back-pressure delivery for
                    // every other account (and, upstream, the relay notification
                    // pipeline). Drop the delivery for the lagging account
                    // instead; it recovers on the next subscription catch-up.
                    match sender.try_send(delivery) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                target: "marmot_app::relay_plane",
                                method = "spawn_router",
                                "dropping transport delivery: account delivery queue full",
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
}

impl RelayPlaneHealth {
    fn from_sdk(health: NostrSdkRelayHealth, directory: DirectoryRelayStats) -> Self {
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

    fn from_directory(directory: DirectoryRelayStats) -> Self {
        Self {
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

fn spawn_relay_notification_forwarder(
    sdk_relay_client: NostrSdkRelayClient,
    adapter: NostrTransportAdapter,
    directory_events: broadcast::Sender<DirectoryRelayEventRecord>,
    directory: DirectoryRelayPlane,
) -> JoinHandle<()> {
    let client = sdk_relay_client.client().clone();
    tokio::spawn(async move {
        let _ = client
            .handle_notifications(move |notification| {
                let adapter = adapter.clone();
                let directory_events = directory_events.clone();
                let directory = directory.clone();
                async move {
                    match notification {
                        RelayPoolNotification::Event {
                            relay_url,
                            subscription_id,
                            event,
                        } => {
                            if let Ok(event) = NostrTransportEvent::from_nostr_event(&event) {
                                tracing::trace!(
                                    target: "marmot_app::relay_plane",
                                    method = "spawn_relay_notification_forwarder",
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
                                // (darkmatter#709).
                                let _ = adapter.handle_relay_event(relay_event).await;
                                if directory
                                    .accepts_live_event(
                                        &subscription_id,
                                        &event.pubkey,
                                        event.kind,
                                    )
                                    .await
                                {
                                    let _ = directory_events.send(DirectoryRelayEventRecord {
                                        endpoints: vec![endpoint],
                                        event,
                                    });
                                } else {
                                    tracing::trace!(
                                        target: "marmot_app::relay_plane",
                                        method = "spawn_relay_notification_forwarder",
                                        "dropping directory relay event: no matching active directory subscription"
                                    );
                                }
                            }
                            Ok(false)
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
                                    method = "spawn_relay_notification_forwarder",
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
                            Ok(false)
                        }
                        RelayPoolNotification::Message {
                            relay_url,
                            message: RelayMessage::EndOfStoredEvents(subscription_id),
                        } => {
                            // EOSE tap: advances the per-relay initial-sync gate
                            // and records EOSE latency. No delivery.
                            tracing::trace!(
                                target: "marmot_app::relay_plane",
                                method = "spawn_relay_notification_forwarder",
                                "forwarding SDK relay end-of-stored-events"
                            );
                            adapter
                                .handle_relay_eose(
                                    TransportEndpoint(relay_url.to_string()),
                                    subscription_id.to_string(),
                                )
                                .await;
                            Ok(false)
                        }
                        RelayPoolNotification::Shutdown => {
                            tracing::debug!(
                                target: "marmot_app::relay_plane",
                                method = "spawn_relay_notification_forwarder",
                                "SDK relay pool shutdown observed"
                            );
                            Ok(true)
                        }
                        _ => Ok(false),
                    }
                }
            })
            .await;
    })
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
        account_deliveries_write(&self.relay_plane.inner.transport.account_deliveries)
            .remove(account_id);
        self.relay_plane
            .inner
            .transport
            .adapter
            .deactivate_account(account_id)
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
        Ok(self.delivery_rx.lock().await.recv().await)
    }
}

fn account_deliveries_read(
    deliveries: &RwLock<HashMap<MemberId, mpsc::Sender<TransportDelivery>>>,
) -> RwLockReadGuard<'_, HashMap<MemberId, mpsc::Sender<TransportDelivery>>> {
    deliveries
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn account_deliveries_write(
    deliveries: &RwLock<HashMap<MemberId, mpsc::Sender<TransportDelivery>>>,
) -> RwLockWriteGuard<'_, HashMap<MemberId, mpsc::Sender<TransportDelivery>>> {
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
