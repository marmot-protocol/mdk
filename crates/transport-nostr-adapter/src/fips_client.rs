//! FIPS-backed Nostr relay semantics.
//!
//! This module intentionally defines a typed boundary rather than a wire
//! protocol. A concrete backend owns the local socket, FIPS framing, retries,
//! and connection lifecycle. MDK hands that boundary signed Nostr events and
//! REQ-like filters; it never performs a WebSocket handshake for `fips://`
//! endpoints.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use cgka_traits::{
    MemberId, MessageId, TransportAdapterError, TransportEndpoint, TransportEndpointFailure,
    TransportEndpointReceipt, TransportEndpointRejectionCategory, TransportPublishFailure,
    collapse_publish_failure_summaries,
};
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinSet;
use transport_nostr_peeler::NostrTransportEvent;

use crate::{
    FipsRelayEndpoint, NostrEventPublishRequest, NostrPublishOutcome, NostrRelayClient,
    NostrRelayEndpoint, NostrSubscription,
};

const FIPS_NOTIFICATION_BUFFER: usize = 1024;

type AccountSubscriptions = HashMap<String, Vec<FipsRelayEndpoint>>;
type SubscriptionRegistry = HashMap<MemberId, AccountSubscriptions>;

/// REQ-like filter sent to a FIPS-addressed Nostr relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FipsNostrFilter {
    AccountInbox {
        recipient: [u8; 32],
        since: Option<u64>,
    },
    Group {
        transport_group_id: Vec<u8>,
        since: Option<u64>,
    },
}

/// Backend-neutral subscription request for a FIPS relay API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FipsRelaySubscription {
    pub subscription_id: String,
    pub filter: FipsNostrFilter,
}

/// Inbound relay semantics surfaced by `fips-api` without prescribing its
/// transport framing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FipsRelayNotification {
    Event {
        endpoint: FipsRelayEndpoint,
        subscription_id: String,
        event: NostrTransportEvent,
    },
    EndOfStoredEvents {
        endpoint: FipsRelayEndpoint,
        subscription_id: String,
    },
    Shutdown,
}

/// Privacy-safe failure classes returned by the FIPS relay API boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FipsRelayApiError {
    Unavailable,
    Rejected,
    InvalidResponse,
    Closed,
}

/// Privacy-safe health snapshot for an injected FIPS relay backend.
///
/// Endpoint identities, socket paths, subscription ids, event ids, and
/// payloads deliberately stay out of this boundary. An enabled backend can be
/// idle (zero active endpoints) before an account has registered any FIPS
/// subscriptions or publications.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FipsRelayApiDiagnostics {
    pub enabled: bool,
    pub active_endpoints: u64,
    pub connected_endpoints: u64,
    pub reconnecting_endpoints: u64,
}

impl FipsRelayApiError {
    fn publish_reason(self) -> &'static str {
        match self {
            Self::Unavailable => "FIPS relay unavailable",
            Self::Rejected => "FIPS relay rejected event",
            Self::InvalidResponse => "FIPS relay returned an invalid response",
            Self::Closed => "FIPS relay connection closed",
        }
    }

    fn rejection_category(self) -> Option<TransportEndpointRejectionCategory> {
        match self {
            Self::Rejected => Some(TransportEndpointRejectionCategory::Restricted),
            Self::InvalidResponse => Some(TransportEndpointRejectionCategory::Invalid),
            Self::Unavailable | Self::Closed => None,
        }
    }
}

impl fmt::Display for FipsRelayApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.publish_reason())
    }
}

impl std::error::Error for FipsRelayApiError {}

/// Semantic boundary implemented by a concrete FIPS relay backend.
///
/// The endpoint identifies the remote FIPS node. Implementations must obtain
/// their local socket/configuration independently; the endpoint must never be
/// interpreted as a filesystem path or conventional network host.
#[async_trait]
pub trait FipsRelayApi: Send + Sync {
    async fn subscribe(
        &self,
        endpoint: &FipsRelayEndpoint,
        subscription: &FipsRelaySubscription,
    ) -> Result<(), FipsRelayApiError>;

    async fn unsubscribe(
        &self,
        endpoint: &FipsRelayEndpoint,
        subscription_id: &str,
    ) -> Result<(), FipsRelayApiError>;

    async fn publish_event(
        &self,
        endpoint: &FipsRelayEndpoint,
        event: &NostrTransportEvent,
    ) -> Result<(), FipsRelayApiError>;

    fn notifications(&self) -> broadcast::Receiver<FipsRelayNotification>;

    /// Return aggregate backend health without exposing endpoint identity.
    fn diagnostics(&self) -> FipsRelayApiDiagnostics {
        FipsRelayApiDiagnostics::default()
    }
}

/// Default implementation when no native FIPS backend is injected. It fails
/// explicitly and never attempts a socket or network dial.
#[derive(Clone)]
pub struct DisabledFipsRelayApi {
    notifications: broadcast::Sender<FipsRelayNotification>,
}

impl Default for DisabledFipsRelayApi {
    fn default() -> Self {
        Self {
            notifications: broadcast::channel(FIPS_NOTIFICATION_BUFFER).0,
        }
    }
}

#[async_trait]
impl FipsRelayApi for DisabledFipsRelayApi {
    async fn subscribe(
        &self,
        _endpoint: &FipsRelayEndpoint,
        _subscription: &FipsRelaySubscription,
    ) -> Result<(), FipsRelayApiError> {
        Err(FipsRelayApiError::Unavailable)
    }

    async fn unsubscribe(
        &self,
        _endpoint: &FipsRelayEndpoint,
        _subscription_id: &str,
    ) -> Result<(), FipsRelayApiError> {
        Err(FipsRelayApiError::Unavailable)
    }

    async fn publish_event(
        &self,
        _endpoint: &FipsRelayEndpoint,
        _event: &NostrTransportEvent,
    ) -> Result<(), FipsRelayApiError> {
        Err(FipsRelayApiError::Unavailable)
    }

    fn notifications(&self) -> broadcast::Receiver<FipsRelayNotification> {
        self.notifications.subscribe()
    }
}

/// Nostr relay-client implementation backed by [`FipsRelayApi`].
#[derive(Clone)]
pub struct FipsNostrRelayClient {
    api: Arc<dyn FipsRelayApi>,
    subscriptions: Arc<RwLock<SubscriptionRegistry>>,
}

impl FipsNostrRelayClient {
    pub fn new(api: Arc<dyn FipsRelayApi>) -> Self {
        Self {
            api,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn notifications(&self) -> broadcast::Receiver<FipsRelayNotification> {
        self.api.notifications()
    }

    pub fn diagnostics(&self) -> FipsRelayApiDiagnostics {
        self.api.diagnostics()
    }

    fn plan_subscription(
        subscription: &NostrSubscription,
    ) -> Result<(MemberId, FipsRelaySubscription, Vec<FipsRelayEndpoint>), TransportAdapterError>
    {
        let endpoints = fips_endpoints(subscription.endpoints())?;
        let (account_id, filter) = match subscription {
            NostrSubscription::AccountInbox {
                account_id, since, ..
            } => {
                let recipient: [u8; 32] = account_id.as_slice().try_into().map_err(|_| {
                    TransportAdapterError::Subscription(
                        "account inbox subscription: member id is not a Nostr pubkey".to_owned(),
                    )
                })?;
                (
                    account_id.clone(),
                    FipsNostrFilter::AccountInbox {
                        recipient,
                        since: since.map(|value| value.0),
                    },
                )
            }
            NostrSubscription::Group {
                account_id,
                transport_group_id,
                since,
                ..
            } => (
                account_id.clone(),
                FipsNostrFilter::Group {
                    transport_group_id: transport_group_id.clone(),
                    since: since.map(|value| value.0),
                },
            ),
            NostrSubscription::GroupMaintenance {
                account_id,
                transport_group_id,
                ..
            } => (
                account_id.clone(),
                FipsNostrFilter::Group {
                    transport_group_id: transport_group_id.clone(),
                    since: None,
                },
            ),
        };
        Ok((
            account_id,
            FipsRelaySubscription {
                subscription_id: subscription.subscription_id(),
                filter,
            },
            endpoints,
        ))
    }

    fn finish_publish(
        message_id: MessageId,
        accepted: Vec<TransportEndpointReceipt>,
        failed: Vec<TransportEndpointFailure>,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        let required_acks = required_acks.max(1);
        if accepted.len() >= required_acks {
            return Ok(NostrPublishOutcome {
                message_id: Some(message_id),
                accepted,
                failed,
            });
        }
        let summary = if accepted.is_empty() && !failed.is_empty() {
            collapse_publish_failure_summaries(failed.iter().map(|failure| failure.reason.as_str()))
        } else {
            format!(
                "insufficient publish acknowledgements: accepted {} of required {}",
                accepted.len(),
                required_acks
            )
        };
        if failed.is_empty() {
            Err(TransportAdapterError::Publish(summary))
        } else {
            Err(TransportAdapterError::PublishEndpoints(
                TransportPublishFailure::with_endpoint_failures(summary, failed),
            ))
        }
    }
}

#[async_trait]
impl NostrRelayClient for FipsNostrRelayClient {
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        let (account_id, plan, endpoints) = Self::plan_subscription(&subscription)?;
        if endpoints.is_empty() {
            return Err(TransportAdapterError::Subscription(
                "subscription contains no FIPS endpoints".to_owned(),
            ));
        }

        let mut tasks = JoinSet::new();
        for endpoint in endpoints {
            let api = self.api.clone();
            let plan = plan.clone();
            tasks.spawn(async move {
                let result = api.subscribe(&endpoint, &plan).await;
                (endpoint, result)
            });
        }
        let mut accepted = Vec::new();
        while let Some(result) = tasks.join_next().await {
            if let Ok((endpoint, Ok(()))) = result {
                accepted.push(endpoint);
            }
        }
        if accepted.is_empty() {
            return Err(TransportAdapterError::Subscription(
                "FIPS subscription registered on zero endpoints".to_owned(),
            ));
        }
        self.subscriptions
            .write()
            .await
            .entry(account_id)
            .or_default()
            .insert(plan.subscription_id, accepted);
        Ok(())
    }

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        let (account_id, plan, offered_endpoints) = Self::plan_subscription(&subscription)?;
        let endpoints = self
            .subscriptions
            .write()
            .await
            .get_mut(&account_id)
            .and_then(|subscriptions| subscriptions.remove(&plan.subscription_id))
            .unwrap_or(offered_endpoints);
        unsubscribe_fips_endpoints(self.api.clone(), endpoints, &plan.subscription_id).await
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        let subscriptions = self
            .subscriptions
            .write()
            .await
            .remove(account_id)
            .unwrap_or_default();
        for (subscription_id, endpoints) in subscriptions {
            unsubscribe_fips_endpoints(self.api.clone(), endpoints, &subscription_id).await?;
        }
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        let parsed = fips_endpoints(endpoints)?;
        if parsed.is_empty() {
            return Err(TransportAdapterError::Publish(
                "publish contains no FIPS endpoints".to_owned(),
            ));
        }
        let message_id = MessageId::new(hex::decode(&event.id).map_err(|_| {
            TransportAdapterError::Publish("Nostr event has invalid message id".to_owned())
        })?);
        let mut tasks = JoinSet::new();
        for endpoint in parsed {
            let api = self.api.clone();
            let event = event.clone();
            tasks.spawn(async move {
                let result = api.publish_event(&endpoint, &event).await;
                (endpoint, result)
            });
        }
        let mut accepted = Vec::new();
        let mut failed = Vec::new();
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((endpoint, Ok(()))) => accepted.push(TransportEndpointReceipt {
                    endpoint: endpoint.transport_endpoint(),
                    accepted_at: None,
                }),
                Ok((endpoint, Err(error))) => failed.push(TransportEndpointFailure {
                    endpoint: endpoint.transport_endpoint(),
                    reason: error.publish_reason().to_owned(),
                    rejection_category: error.rejection_category(),
                }),
                Err(_) => {}
            }
        }
        Self::finish_publish(message_id, accepted, failed, required_acks)
    }

    async fn publish_events(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        let mut outcomes = Vec::with_capacity(requests.len());
        for request in requests {
            outcomes.push(
                self.publish_event(&request.endpoints, &request.event, request.required_acks)
                    .await,
            );
        }
        outcomes
    }
}

fn fips_endpoints(
    endpoints: &[TransportEndpoint],
) -> Result<Vec<FipsRelayEndpoint>, TransportAdapterError> {
    let mut parsed = Vec::new();
    for endpoint in endpoints {
        match NostrRelayEndpoint::parse(endpoint.as_str()) {
            Ok(NostrRelayEndpoint::Fips(endpoint)) => parsed.push(endpoint),
            Ok(NostrRelayEndpoint::WebSocket(_)) => {}
            Err(_) => {
                return Err(TransportAdapterError::Subscription(
                    "invalid relay endpoint".to_owned(),
                ));
            }
        }
    }
    Ok(parsed)
}

async fn unsubscribe_fips_endpoints(
    api: Arc<dyn FipsRelayApi>,
    endpoints: Vec<FipsRelayEndpoint>,
    subscription_id: &str,
) -> Result<(), TransportAdapterError> {
    let mut tasks = JoinSet::new();
    for endpoint in endpoints {
        let api = api.clone();
        let subscription_id = subscription_id.to_owned();
        tasks.spawn(async move { api.unsubscribe(&endpoint, &subscription_id).await });
    }
    let mut failed = false;
    while let Some(result) = tasks.join_next().await {
        if !matches!(result, Ok(Ok(()))) {
            failed = true;
        }
    }
    if failed {
        Err(TransportAdapterError::Subscription(
            "FIPS unsubscribe failed".to_owned(),
        ))
    } else {
        Ok(())
    }
}
