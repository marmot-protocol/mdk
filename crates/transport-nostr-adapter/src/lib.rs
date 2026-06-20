//! Concrete Nostr transport adapter core.
//!
//! This crate implements the shared [`cgka_traits::TransportAdapter`] boundary
//! for Nostr-shaped Marmot messages. It owns account-aware subscription state,
//! endpoint routing, publish target validation, and conversion between
//! [`transport_nostr_peeler::NostrTransportEvent`] and
//! [`cgka_traits::TransportMessage`].
//!
//! Real relay sockets are deliberately behind [`NostrRelayClient`]. That keeps
//! the adapter testable while preserving the production boundary where a
//! `nostr-sdk` client can plug in.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use cgka_traits::MessageId;
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::{
    GroupId, MemberId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportDelivery, TransportDeliveryPlane, TransportDeliverySource, TransportEndpoint,
    TransportEndpointFailure, TransportEndpointReceipt, TransportGroupSubscription,
    TransportGroupSync, TransportPublishReport, TransportPublishRequest,
};
use nostr::RelayUrl;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task::JoinSet;
use transport_nostr_peeler::{NOSTR_SOURCE, NostrTransportEvent};

mod key_package;
mod relay_list;
#[cfg(feature = "sdk")]
mod sdk_client;
mod telemetry;

pub use key_package::{
    KIND_MARMOT_KEY_PACKAGE, NostrKeyPackagePublication, NostrKeyPackagePublisher,
};
pub use relay_list::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_NIP65_RELAY_LIST, NostrAccountRelayListKind,
    NostrAccountRelayListPublication,
};
#[cfg(feature = "sdk")]
pub use sdk_client::{NostrSdkRelayClient, NostrSdkRelayHealth, NostrSdkSubscriptionPlan};
pub use telemetry::{
    DurationHistogramSnapshot, HistogramBucket, RelayDeliverySpread, RelayDeliveryStats,
    RelayDeliveryTelemetry, RelayExportConsent, RelayIndex, RelayIndexRegistry,
    RelayLabelResolution, RelayLatencyStats, RelaySyncSnapshot, RelaySyncTelemetry,
};

const DELIVERY_BUFFER: usize = 1024;
/// Low-level relay subscription request emitted by [`NostrTransportAdapter`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NostrSubscription {
    AccountInbox {
        account_id: MemberId,
        endpoints: Vec<TransportEndpoint>,
        since: Option<Timestamp>,
    },
    Group {
        account_id: MemberId,
        group_id: GroupId,
        transport_group_id: Vec<u8>,
        endpoints: Vec<TransportEndpoint>,
        since: Option<Timestamp>,
    },
}

impl NostrSubscription {
    pub fn subscription_id(&self) -> String {
        match self {
            Self::AccountInbox {
                account_id,
                endpoints,
                ..
            } => compact_subscription_id(
                "inbox",
                &[
                    account_id.as_slice(),
                    endpoint_set_digest(endpoints).as_bytes(),
                ],
            ),
            Self::Group {
                account_id,
                group_id,
                transport_group_id,
                endpoints,
                ..
            } => {
                let h_tag = hex::encode(transport_group_id);
                compact_subscription_id(
                    "group",
                    &[
                        account_id.as_slice(),
                        group_id.as_slice(),
                        h_tag.as_bytes(),
                        endpoint_set_digest(endpoints).as_bytes(),
                    ],
                )
            }
        }
    }

    /// Relay endpoints this subscription was issued to.
    pub fn endpoints(&self) -> &[TransportEndpoint] {
        match self {
            Self::AccountInbox { endpoints, .. } | Self::Group { endpoints, .. } => endpoints,
        }
    }

    fn route_key(&self) -> NostrSubscriptionRouteKey {
        match self {
            Self::AccountInbox {
                account_id,
                endpoints,
                ..
            } => NostrSubscriptionRouteKey::AccountInbox {
                account_id: account_id.clone(),
                endpoints: normalized_endpoints(endpoints),
            },
            Self::Group {
                account_id,
                group_id,
                transport_group_id,
                endpoints,
                ..
            } => NostrSubscriptionRouteKey::Group {
                account_id: account_id.clone(),
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: normalized_endpoints(endpoints),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum NostrSubscriptionRouteKey {
    AccountInbox {
        account_id: MemberId,
        endpoints: Vec<TransportEndpoint>,
    },
    Group {
        account_id: MemberId,
        group_id: GroupId,
        transport_group_id: Vec<u8>,
        endpoints: Vec<TransportEndpoint>,
    },
}

/// Snapshot of adapter-local lifecycle counters.
///
/// These counters are diagnostic. They must not feed convergence or branch
/// selection.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NostrAdapterMetrics {
    pub active_accounts: usize,
    pub active_group_subscriptions: usize,
    pub subscriptions_created: usize,
    pub subscriptions_removed: usize,
    pub inbound_events_seen: usize,
    pub inbound_events_delivered: usize,
    pub inbound_events_dropped: usize,
    pub publish_attempts: usize,
    pub publish_successes: usize,
    pub publish_failures: usize,
}

/// Successful/failed endpoint-level result from a relay client publish.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NostrPublishOutcome {
    pub message_id: Option<MessageId>,
    pub accepted: Vec<TransportEndpointReceipt>,
    pub failed: Vec<TransportEndpointFailure>,
}

impl NostrPublishOutcome {
    pub fn accepted(endpoints: impl IntoIterator<Item = TransportEndpoint>) -> Self {
        Self {
            message_id: None,
            accepted: endpoints
                .into_iter()
                .map(|endpoint| TransportEndpointReceipt {
                    endpoint,
                    accepted_at: None,
                })
                .collect(),
            failed: Vec::new(),
        }
    }
}

/// Relay event as observed by the Nostr relay client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrRelayEvent {
    pub endpoint: TransportEndpoint,
    pub subscription_id: Option<String>,
    pub event: NostrTransportEvent,
}

/// Boundary between this adapter and the actual Nostr relay implementation.
#[async_trait]
pub trait NostrRelayClient: Send + Sync {
    async fn subscribe(&self, subscription: NostrSubscription)
    -> Result<(), TransportAdapterError>;

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError>;

    async fn unsubscribe_account(&self, account_id: &MemberId)
    -> Result<(), TransportAdapterError>;

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError>;
}

/// Nostr implementation of the shared transport adapter boundary.
#[derive(Clone)]
pub struct NostrTransportAdapter {
    relay_client: Arc<dyn NostrRelayClient>,
    state: Arc<RwLock<AdapterState>>,
    delivery_tx: mpsc::Sender<TransportDelivery>,
    delivery_rx: Arc<Mutex<mpsc::Receiver<TransportDelivery>>>,
    /// Local monotonic origin for delivery telemetry. Never `created_at`.
    monotonic_start: std::time::Instant,
}

impl NostrTransportAdapter {
    pub fn new(relay_client: Arc<dyn NostrRelayClient>) -> Self {
        let (delivery_tx, delivery_rx) = mpsc::channel(DELIVERY_BUFFER);
        Self {
            relay_client,
            state: Arc::new(RwLock::new(AdapterState::default())),
            delivery_tx,
            delivery_rx: Arc::new(Mutex::new(delivery_rx)),
            monotonic_start: std::time::Instant::now(),
        }
    }

    pub async fn metrics(&self) -> NostrAdapterMetrics {
        tracing::trace!(
            target: "transport_nostr_adapter::adapter",
            method = "metrics",
            "snapshotting adapter metrics"
        );
        let state = self.state.read().await;
        let mut metrics = state.metrics.clone();
        metrics.active_accounts = state.accounts.len();
        metrics.active_group_subscriptions = state
            .accounts
            .values()
            .map(|account| account.groups.len())
            .sum();
        metrics
    }

    async fn subscribe_all(
        &self,
        caller: &'static str,
        subscriptions: &[NostrSubscription],
    ) -> Result<(), TransportAdapterError> {
        let mut tasks = JoinSet::new();
        for (sub_index, subscription) in subscriptions.iter().cloned().enumerate() {
            let relay_client = self.relay_client.clone();
            tasks.spawn(async move { (sub_index, relay_client.subscribe(subscription).await) });
        }

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((_sub_index, Ok(()))) => {}
                Ok((sub_index, Err(err))) => {
                    tasks.abort_all();
                    tracing::warn!(
                        target: "transport_nostr_adapter::adapter",
                        method = caller,
                        sub_index,
                        issued_count = subscriptions.len(),
                        "transport subscription failed"
                    );
                    return Err(err);
                }
                Err(err) => {
                    tasks.abort_all();
                    return Err(TransportAdapterError::Subscription(format!(
                        "subscription task failed: {err}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Aggregate cross-relay arrival-spread snapshot for diagnostics and
    /// quiescence tuning. Privacy-safe: counts and millisecond buckets only.
    pub async fn delivery_spread(&self) -> RelayDeliverySpread {
        tracing::trace!(
            target: "transport_nostr_adapter::adapter",
            method = "delivery_spread",
            "snapshotting delivery spread"
        );
        self.state.read().await.telemetry.snapshot()
    }

    /// Aggregate subscription sync-timing snapshot (first-event and EOSE
    /// latencies, initial-sync completion counts). Privacy-safe.
    pub async fn relay_sync(&self) -> RelaySyncSnapshot {
        tracing::trace!(
            target: "transport_nostr_adapter::adapter",
            method = "relay_sync",
            "snapshotting relay sync timing"
        );
        self.state.read().await.sync.snapshot()
    }

    /// Initial-sync gate: whether every endpoint of `subscription_id` has
    /// reached EOSE. `None` for an unknown subscription.
    pub async fn subscription_synced(&self, subscription_id: &str) -> Option<bool> {
        self.state
            .read()
            .await
            .sync
            .subscription_synced(subscription_id)
    }

    /// Resolve opaque relay indices to relay endpoints for the opt-in export
    /// label boundary.
    ///
    /// This is the ONLY path that turns a device-local [`RelayIndex`] into a
    /// relay URL. It requires a [`RelayExportConsent`], which must be minted
    /// only where the user has opted in to relay telemetry export. Privacy
    /// contract: `docs/marmot-architecture/relay-observability.md`.
    pub async fn resolve_relay_labels(&self, _consent: RelayExportConsent) -> RelayLabelResolution {
        let state = self.state.read().await;
        RelayLabelResolution::from_pairs(state.relay_index.resolutions())
    }

    /// Local monotonic timestamp in milliseconds for delivery telemetry. Never
    /// the publisher-controlled `created_at`.
    fn now_ms(&self) -> u64 {
        self.monotonic_start.elapsed().as_millis() as u64
    }

    /// Convert a relay event into zero or more account-scoped deliveries.
    ///
    /// Invalid Nostr DTOs fail closed before the engine sees them. Valid but
    /// unsubscribed messages are dropped with `Ok(0)`.
    pub async fn handle_relay_event(
        &self,
        relay_event: NostrRelayEvent,
    ) -> Result<usize, TransportAdapterError> {
        let message = relay_event
            .event
            .to_transport_message()
            .map_err(|e| TransportAdapterError::Backend(format!("Nostr event mapping: {e}")))?;
        let now = Timestamp(relay_event.event.created_at);
        let routes = {
            let state = self.state.read().await;
            state.routes_for(&message, &relay_event.endpoint)
        };

        let mut delivered = 0;
        for route in routes {
            self.delivery_tx
                .send(TransportDelivery {
                    account_id: route.account_id,
                    group_id_hint: route.group_id_hint,
                    message: message.clone(),
                    received_at: now,
                    source: TransportDeliverySource {
                        transport: TransportSource(NOSTR_SOURCE.into()),
                        plane: route.plane,
                        endpoint: Some(relay_event.endpoint.clone()),
                        subscription_id: relay_event.subscription_id.clone(),
                    },
                })
                .await
                .map_err(|_| TransportAdapterError::Backend("delivery queue closed".into()))?;
            delivered += 1;
        }

        // Delivery only. The relay pool emits one deduplicated `Event` per
        // message, so this path counts delivered copies for routing metrics but
        // MUST NOT record cross-relay spread or per-relay first-event timing:
        // those need every relay's copy, which arrives on the raw per-relay
        // stream via `observe_relay_event`, not this deduplicated path.
        self.state.write().await.record_inbound_event(delivered);
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "handle_relay_event",
            delivered,
            "handled relay event"
        );
        Ok(delivered)
    }

    /// Record telemetry for one relay's copy of an event, taken from the raw
    /// per-relay stream.
    ///
    /// Unlike [`Self::handle_relay_event`], this performs no delivery. It exists
    /// to observe every relay copy — including duplicates the delivery path
    /// deduplicates away — so cross-relay arrival spread and per-relay
    /// first-event timing can be measured. Timing uses the adapter's monotonic
    /// clock, never the publisher-controlled `created_at`. Events that fail to
    /// map to a transport message are ignored.
    pub async fn observe_relay_event(&self, relay_event: NostrRelayEvent) {
        let Ok(message) = relay_event.event.to_transport_message() else {
            return;
        };
        let now_ms = self.now_ms();
        let mut state = self.state.write().await;
        state.record_delivery_timing(&message.id, &relay_event.endpoint, now_ms);
        if let Some(subscription_id) = &relay_event.subscription_id {
            state.record_subscription_first_event(subscription_id, &relay_event.endpoint, now_ms);
        }
    }

    /// Record an end-of-stored-events signal for a subscription on one relay
    /// endpoint. This advances the initial-sync gate; it produces no delivery.
    pub async fn handle_relay_eose(&self, endpoint: TransportEndpoint, subscription_id: String) {
        let now_ms = self.now_ms();
        self.state
            .write()
            .await
            .record_subscription_eose(&subscription_id, &endpoint, now_ms);
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "handle_relay_eose",
            "handled relay eose"
        );
    }
}

#[async_trait]
impl TransportAdapter for NostrTransportAdapter {
    async fn activate_account(
        &self,
        activation: TransportAccountActivation,
    ) -> Result<(), TransportAdapterError> {
        let account_id = activation.account_id.clone();
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "activate_account",
            inbox_endpoint_count = activation.inbox_endpoints.len(),
            group_subscription_count = activation.group_subscriptions.len(),
            "activating transport account"
        );
        let replaced_count = {
            let state = self.state.read().await;
            state
                .accounts
                .get(&account_id)
                .map(|routes| 1 + routes.groups.len())
                .unwrap_or_default()
        };
        if replaced_count > 0 {
            self.relay_client.unsubscribe_account(&account_id).await?;
        }

        let mut issued = Vec::with_capacity(1 + activation.group_subscriptions.len());
        issued.push(NostrSubscription::AccountInbox {
            account_id: account_id.clone(),
            endpoints: activation.inbox_endpoints.clone(),
            since: inbox_since(activation.since),
        });
        for group in &activation.group_subscriptions {
            issued.push(group_subscription(&account_id, group, activation.since));
        }
        self.subscribe_all("activate_account", &issued).await?;
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "activate_account",
            issued_count = issued.len(),
            "all transport subscriptions issued"
        );

        let now_ms = self.now_ms();
        let mut state = self.state.write().await;
        state.record_subscription_starts(&issued, now_ms);
        state.activate(activation, replaced_count);
        Ok(())
    }

    async fn sync_account_groups(
        &self,
        sync: TransportGroupSync,
    ) -> Result<(), TransportAdapterError> {
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "sync_account_groups",
            desired_group_subscription_count = sync.group_subscriptions.len(),
            "syncing transport group subscriptions"
        );
        {
            let state = self.state.read().await;
            if !state.accounts.contains_key(&sync.account_id) {
                return Err(TransportAdapterError::AccountNotActive(
                    sync.account_id.clone(),
                ));
            }
        }

        let (to_add, to_remove) = {
            let state = self.state.read().await;
            let current_groups = state
                .accounts
                .get(&sync.account_id)
                .map(|routes| routes.groups.as_slice())
                .unwrap_or_default();
            diff_group_subscriptions(
                &sync.account_id,
                current_groups,
                &sync.group_subscriptions,
                sync.since,
            )
        };

        self.subscribe_all("sync_account_groups", &to_add).await?;
        for subscription in &to_remove {
            self.relay_client.unsubscribe(subscription.clone()).await?;
        }

        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "sync_account_groups",
            subscriptions_created = to_add.len(),
            subscriptions_removed = to_remove.len(),
            "applied transport group subscription diff"
        );
        let now_ms = self.now_ms();
        let mut state = self.state.write().await;
        state.record_subscription_starts(&to_add, now_ms);
        state.sync_groups(sync, to_add.len(), to_remove.len());
        Ok(())
    }

    async fn deactivate_account(&self, account_id: &MemberId) -> Result<(), TransportAdapterError> {
        let removed_count = {
            let state = self.state.read().await;
            state
                .accounts
                .get(account_id)
                .map(|routes| 1 + routes.groups.len())
                .unwrap_or_default()
        };
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "deactivate_account",
            subscriptions_removed = removed_count,
            "deactivating transport account"
        );
        self.relay_client.unsubscribe_account(account_id).await?;
        let mut state = self.state.write().await;
        state.deactivate(account_id, removed_count);
        Ok(())
    }

    async fn publish(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "publish",
            endpoint_count = request.target.endpoints().len(),
            required_acks = request.required_acks,
            "publishing transport message"
        );
        request.validate_envelope_matches_target()?;
        {
            let state = self.state.read().await;
            if !state.accounts.contains_key(&request.account_id) {
                return Err(TransportAdapterError::AccountNotActive(
                    request.account_id.clone(),
                ));
            }
        }

        let event = NostrTransportEvent::from_transport_message(&request.message)
            .map_err(|e| TransportAdapterError::Publish(format!("Nostr payload: {e}")))?;
        self.state.write().await.record_publish_attempt();
        let outcome = match self
            .relay_client
            .publish_event(request.target.endpoints(), &event, request.required_acks)
            .await
        {
            Ok(outcome) => {
                self.state.write().await.record_publish_success();
                tracing::debug!(
                    target: "transport_nostr_adapter::adapter",
                    method = "publish",
                    accepted_count = outcome.accepted.len(),
                    failed_count = outcome.failed.len(),
                    "transport publish completed"
                );
                outcome
            }
            Err(e) => {
                self.state.write().await.record_publish_failure();
                tracing::warn!(
                    target: "transport_nostr_adapter::adapter",
                    method = "publish",
                    "transport publish failed"
                );
                return Err(e);
            }
        };

        Ok(TransportPublishReport {
            message_id: outcome.message_id.unwrap_or(request.message.id),
            accepted: outcome.accepted,
            failed: outcome.failed,
            required_acks: request.required_acks,
        })
    }

    async fn receive(&self) -> Result<Option<TransportDelivery>, TransportAdapterError> {
        Ok(self.delivery_rx.lock().await.recv().await)
    }
}

impl NostrTransportAdapter {
    pub async fn deliver_local_publish(
        &self,
        message: &TransportMessage,
        endpoints: &[TransportEndpoint],
    ) -> Result<usize, TransportAdapterError> {
        let mut delivered = 0;
        let mut seen_routes = HashSet::new();
        for endpoint in endpoints {
            let routes = {
                let state = self.state.read().await;
                state.routes_for(message, endpoint)
            };
            for route in routes {
                let key = (
                    route.account_id.clone(),
                    route.group_id_hint.clone(),
                    route.plane,
                );
                if !seen_routes.insert(key) {
                    continue;
                }
                self.delivery_tx
                    .send(TransportDelivery {
                        account_id: route.account_id,
                        group_id_hint: route.group_id_hint,
                        message: message.clone(),
                        received_at: message.timestamp,
                        source: TransportDeliverySource {
                            transport: TransportSource(NOSTR_SOURCE.into()),
                            plane: route.plane,
                            endpoint: Some(endpoint.clone()),
                            subscription_id: Some("local-publish".to_owned()),
                        },
                    })
                    .await
                    .map_err(|_| TransportAdapterError::Backend("delivery queue closed".into()))?;
                delivered += 1;
            }
        }
        Ok(delivered)
    }
}

#[derive(Clone)]
struct DeliveryRoute {
    account_id: MemberId,
    group_id_hint: Option<GroupId>,
    plane: TransportDeliveryPlane,
}

#[derive(Clone, Default)]
struct AccountRoutes {
    inbox_endpoints: Vec<TransportEndpoint>,
    groups: Vec<TransportGroupSubscription>,
}

#[derive(Default)]
struct AdapterState {
    accounts: HashMap<MemberId, AccountRoutes>,
    metrics: NostrAdapterMetrics,
    relay_index: RelayIndexRegistry,
    telemetry: RelayDeliveryTelemetry,
    sync: RelaySyncTelemetry,
}

/// Compare a stored route endpoint against the endpoint an inbound event
/// arrived on, normalization-safe.
///
/// Routing must not depend on callers pre-canonicalizing relay URLs. Inbound
/// endpoints are built from a parsed nostr `RelayUrl` (`sdk_client`), while
/// stored group/inbox endpoints carry the verbatim signed routing strings
/// (`marmot.transport.nostr.routing.v1`), which are intentionally never
/// rewritten. A raw `==` therefore drops events whenever the two differ only
/// by a `url`-canonicalizable detail (trailing slash, host case, default
/// port, percent-encoding) — see darkmatter#482.
///
/// Fast path is byte equality. Otherwise both sides are parsed as `RelayUrl`
/// and compared by value, which folds those canonicalization differences
/// together. If either side fails to parse as a relay URL (e.g. a non-Nostr
/// transport endpoint), fall back to the byte comparison so behavior is never
/// looser than exact match. This is a read-side comparison only; stored
/// endpoints are left untouched, preserving the signed-routing invariant.
fn endpoints_match(candidate: &TransportEndpoint, endpoint: &TransportEndpoint) -> bool {
    if candidate == endpoint {
        return true;
    }
    match (
        RelayUrl::parse(candidate.as_str()),
        RelayUrl::parse(endpoint.as_str()),
    ) {
        (Ok(candidate), Ok(endpoint)) => candidate == endpoint,
        _ => false,
    }
}

impl AdapterState {
    fn activate(&mut self, activation: TransportAccountActivation, replaced: usize) {
        self.metrics.subscriptions_created += 1 + activation.group_subscriptions.len();
        self.metrics.subscriptions_removed += replaced;
        self.accounts.insert(
            activation.account_id,
            AccountRoutes {
                inbox_endpoints: activation.inbox_endpoints,
                groups: activation.group_subscriptions,
            },
        );
    }

    fn sync_groups(&mut self, sync: TransportGroupSync, created: usize, removed: usize) {
        if let Some(account) = self.accounts.get_mut(&sync.account_id) {
            account.groups = sync.group_subscriptions;
            self.metrics.subscriptions_created += created;
            self.metrics.subscriptions_removed += removed;
        }
    }

    fn deactivate(&mut self, account_id: &MemberId, removed_count: usize) {
        self.accounts.remove(account_id);
        self.metrics.subscriptions_removed += removed_count;
    }

    fn record_inbound_event(&mut self, delivered: usize) {
        self.metrics.inbound_events_seen += 1;
        self.metrics.inbound_events_delivered += delivered;
        if delivered == 0 {
            self.metrics.inbound_events_dropped += 1;
        }
    }

    fn record_delivery_timing(
        &mut self,
        message_id: &MessageId,
        endpoint: &TransportEndpoint,
        now_ms: u64,
    ) {
        let relay = self.relay_index.index_for(endpoint);
        self.telemetry.record_sighting(message_id, relay, now_ms);
    }

    fn record_subscription_starts(&mut self, subscriptions: &[NostrSubscription], now_ms: u64) {
        for subscription in subscriptions {
            let relays: Vec<RelayIndex> = subscription
                .endpoints()
                .iter()
                .map(|endpoint| self.relay_index.index_for(endpoint))
                .collect();
            self.sync
                .record_subscription_start(&subscription.subscription_id(), &relays, now_ms);
        }
    }

    fn record_subscription_first_event(
        &mut self,
        subscription_id: &str,
        endpoint: &TransportEndpoint,
        now_ms: u64,
    ) {
        let relay = self.relay_index.index_for(endpoint);
        self.sync.record_first_event(subscription_id, relay, now_ms);
    }

    fn record_subscription_eose(
        &mut self,
        subscription_id: &str,
        endpoint: &TransportEndpoint,
        now_ms: u64,
    ) {
        let relay = self.relay_index.index_for(endpoint);
        self.sync.record_eose(subscription_id, relay, now_ms);
    }

    fn record_publish_attempt(&mut self) {
        self.metrics.publish_attempts += 1;
    }

    fn record_publish_success(&mut self) {
        self.metrics.publish_successes += 1;
    }

    fn record_publish_failure(&mut self) {
        self.metrics.publish_failures += 1;
    }

    fn routes_for(
        &self,
        message: &TransportMessage,
        endpoint: &TransportEndpoint,
    ) -> Vec<DeliveryRoute> {
        match &message.envelope {
            TransportEnvelope::GroupMessage { transport_group_id } => self
                .accounts
                .iter()
                .flat_map(|(account_id, routes)| {
                    routes
                        .groups
                        .iter()
                        .filter(move |group| {
                            group.transport_group_id == *transport_group_id
                                && group
                                    .endpoints
                                    .iter()
                                    .any(|candidate| endpoints_match(candidate, endpoint))
                        })
                        .map(move |group| DeliveryRoute {
                            account_id: account_id.clone(),
                            group_id_hint: Some(group.group_id.clone()),
                            plane: TransportDeliveryPlane::Group,
                        })
                })
                .collect(),
            TransportEnvelope::Welcome { recipient } => self
                .accounts
                .iter()
                .filter(|(account_id, routes)| {
                    *account_id == recipient
                        && routes
                            .inbox_endpoints
                            .iter()
                            .any(|candidate| endpoints_match(candidate, endpoint))
                })
                .map(|(account_id, _)| DeliveryRoute {
                    account_id: account_id.clone(),
                    group_id_hint: None,
                    plane: TransportDeliveryPlane::AccountInbox,
                })
                .collect(),
        }
    }
}

/// NIP-59 gift wraps (welcomes) randomize the wrapper's `created_at` up to two
/// days into the past to resist timing analysis. A catch-up `since` derived
/// from the last-seen transport timestamp would therefore permanently skip any
/// welcome published while this device was offline whose tweak landed before
/// the cursor. Widen the inbox window by the full tweak range; re-delivered
/// wraps are deduplicated by seen-event ids downstream, and only welcomes
/// travel as gift wraps so the re-fetch volume stays small.
pub const NIP59_TIMESTAMP_TWEAK_SECS: u64 = 172_800;

fn inbox_since(since: Option<Timestamp>) -> Option<Timestamp> {
    since.map(|since| Timestamp(since.0.saturating_sub(NIP59_TIMESTAMP_TWEAK_SECS)))
}

fn group_subscription(
    account_id: &MemberId,
    group: &TransportGroupSubscription,
    since: Option<Timestamp>,
) -> NostrSubscription {
    NostrSubscription::Group {
        account_id: account_id.clone(),
        group_id: group.group_id.clone(),
        transport_group_id: group.transport_group_id.clone(),
        endpoints: group.endpoints.clone(),
        since,
    }
}

fn diff_group_subscriptions(
    account_id: &MemberId,
    current: &[TransportGroupSubscription],
    desired: &[TransportGroupSubscription],
    since: Option<Timestamp>,
) -> (Vec<NostrSubscription>, Vec<NostrSubscription>) {
    let current_subscriptions = current
        .iter()
        .map(|group| group_subscription(account_id, group, None))
        .collect::<Vec<_>>();
    let desired_subscriptions = desired
        .iter()
        .map(|group| group_subscription(account_id, group, since))
        .collect::<Vec<_>>();
    let current_keys = current_subscriptions
        .iter()
        .map(NostrSubscription::route_key)
        .collect::<HashSet<_>>();
    let desired_keys = desired_subscriptions
        .iter()
        .map(NostrSubscription::route_key)
        .collect::<HashSet<_>>();

    let to_add = desired_subscriptions
        .into_iter()
        .filter(|subscription| !current_keys.contains(&subscription.route_key()))
        .collect();
    let to_remove = current_subscriptions
        .into_iter()
        .filter(|subscription| !desired_keys.contains(&subscription.route_key()))
        .collect();

    (to_add, to_remove)
}

fn normalized_endpoints(endpoints: &[TransportEndpoint]) -> Vec<TransportEndpoint> {
    let mut endpoints = endpoints.to_vec();
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

fn endpoint_set_digest(endpoints: &[TransportEndpoint]) -> String {
    let mut values = endpoints
        .iter()
        .map(TransportEndpoint::as_str)
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();

    let mut hasher = Sha256::new();
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn compact_subscription_id(kind: &str, components: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hash_component(&mut hasher, kind.as_bytes());
    for component in components {
        hash_component(&mut hasher, component);
    }
    let digest = hex::encode(hasher.finalize());
    format!("marmot:{kind}:{}", &digest[..32])
}

fn hash_component(hasher: &mut Sha256, component: &[u8]) {
    hasher.update((component.len() as u64).to_be_bytes());
    hasher.update(component);
}
