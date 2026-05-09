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
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::{
    GroupId, MemberId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportDelivery, TransportDeliveryPlane, TransportDeliverySource, TransportEndpoint,
    TransportEndpointFailure, TransportEndpointReceipt, TransportGroupSubscription,
    TransportGroupSync, TransportPublishReport, TransportPublishRequest,
};
use tokio::sync::{Mutex, RwLock, mpsc};
use transport_nostr_peeler::{NOSTR_SOURCE, NostrTransportEvent};

#[cfg(feature = "sdk")]
mod sdk_client;

#[cfg(feature = "sdk")]
pub use sdk_client::{NostrSdkRelayClient, NostrSdkSubscriptionPlan};

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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
    pub accepted: Vec<TransportEndpointReceipt>,
    pub failed: Vec<TransportEndpointFailure>,
}

impl NostrPublishOutcome {
    pub fn accepted(endpoints: impl IntoIterator<Item = TransportEndpoint>) -> Self {
        Self {
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
}

impl NostrTransportAdapter {
    pub fn new(relay_client: Arc<dyn NostrRelayClient>) -> Self {
        let (delivery_tx, delivery_rx) = mpsc::channel(DELIVERY_BUFFER);
        Self {
            relay_client,
            state: Arc::new(RwLock::new(AdapterState::default())),
            delivery_tx,
            delivery_rx: Arc::new(Mutex::new(delivery_rx)),
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

        self.state.write().await.record_inbound_event(delivered);
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "handle_relay_event",
            delivered,
            "handled relay event"
        );
        Ok(delivered)
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

        self.relay_client
            .subscribe(NostrSubscription::AccountInbox {
                account_id: account_id.clone(),
                endpoints: activation.inbox_endpoints.clone(),
                since: activation.since,
            })
            .await?;
        for group in &activation.group_subscriptions {
            self.relay_client
                .subscribe(group_subscription(&account_id, group, activation.since))
                .await?;
        }

        self.state
            .write()
            .await
            .activate(activation, replaced_count);
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

        for subscription in &to_add {
            self.relay_client.subscribe(subscription.clone()).await?;
        }
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
        self.state
            .write()
            .await
            .sync_groups(sync, to_add.len(), to_remove.len());
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
        state.accounts.remove(account_id);
        state.metrics.subscriptions_removed += removed_count;
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
            message_id: request.message.id,
            accepted: outcome.accepted,
            failed: outcome.failed,
            required_acks: request.required_acks,
        })
    }

    async fn receive(&self) -> Result<Option<TransportDelivery>, TransportAdapterError> {
        Ok(self.delivery_rx.lock().await.recv().await)
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

    fn record_inbound_event(&mut self, delivered: usize) {
        self.metrics.inbound_events_seen += 1;
        self.metrics.inbound_events_delivered += delivered;
        if delivered == 0 {
            self.metrics.inbound_events_dropped += 1;
        }
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
                                    .any(|candidate| candidate == endpoint)
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
                            .any(|candidate| candidate == endpoint)
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
