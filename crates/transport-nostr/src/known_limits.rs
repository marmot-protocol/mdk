//! Known relay event limits (mdk#2334): no account publish sends an event to
//! a relay over that relay's known limit.
//!
//! [`refuse_over_known_limits`] decides which relays are refused. The account
//! adapter applies it to the group events and Welcomes it publishes, and
//! [`KnownLimitPublishClient`] to everything else an account signs and
//! publishes: profiles, follow and relay lists, KeyPackages and their
//! deletions, the block list, stickers, the backup pointer.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{
    EventSizeClass, MemberId, MessageId, TransportAdapterError, TransportEndpoint,
    TransportEndpointFailure, TransportPublishFailure,
};
use transport_nostr_adapter::{
    NostrAcquisitionCancellation, NostrAcquisitionError, NostrAcquisitionRequest,
    NostrAcquisitionResult, NostrEventPublishRequest, NostrNotificationLoss, NostrPublishBatch,
    NostrPublishOutcome, NostrRelayClient, NostrRelayNotificationSource, NostrSubscribeReport,
    NostrSubscription, RelayConnection,
};
use transport_nostr_peeler::NostrTransportEvent;

/// The largest event each relay is known to accept (mdk#2334). No account
/// publish sends an event over an endpoint's known limit.
#[async_trait]
pub trait RelayEventLimits: Send + Sync {
    /// The endpoint's limit in serialized event JSON bytes, or `None` when
    /// unknown. `event_bytes` is the event about to be sent, so a source can
    /// skip a lookup no known limit could change.
    async fn max_event_bytes(
        &self,
        endpoint: &TransportEndpoint,
        event_bytes: usize,
    ) -> Option<usize>;
}

/// `,"sig":"` and a 64-byte hex signature with its closing quote: what
/// signing adds to an unsigned event's JSON.
const SIGNATURE_FIELD_BYTES: usize = 137;

/// An event's size as a relay receives it: its serialized JSON, signed. This
/// is the measure relay size refusals are classed by.
pub(crate) fn event_json_bytes(event: &NostrTransportEvent) -> usize {
    let unsigned_extra = if event.sig.is_some() {
        0
    } else {
        SIGNATURE_FIELD_BYTES
    };
    serde_json::to_vec(event).map_or(0, |json| json.len() + unsigned_extra)
}

/// Splits `endpoints` into those the event may fit and a refusal for each
/// whose known limit it exceeds. An unknown limit may fit, and so does every
/// endpoint when no limits are known. Limits are looked up concurrently,
/// since a lookup may fetch a relay document.
pub(crate) async fn refuse_over_known_limits(
    limits: Option<&dyn RelayEventLimits>,
    endpoints: &[TransportEndpoint],
    event_bytes: usize,
) -> (Vec<TransportEndpoint>, Vec<TransportEndpointFailure>) {
    let Some(limits) = limits else {
        return (endpoints.to_vec(), Vec::new());
    };
    let known = futures::future::join_all(
        endpoints
            .iter()
            .map(|endpoint| limits.max_event_bytes(endpoint, event_bytes)),
    )
    .await;
    let mut sendable = Vec::with_capacity(endpoints.len());
    let mut refused = Vec::new();
    for (endpoint, limit) in endpoints.iter().zip(known) {
        if limit.is_some_and(|limit| event_bytes > limit) {
            refused.push(TransportEndpointFailure::over_known_limit(
                endpoint.clone(),
                event_bytes,
            ));
        } else {
            sendable.push(endpoint.clone());
        }
    }
    if !refused.is_empty() {
        tracing::debug!(
            target: "marmot_app::relay_plane",
            method = "refuse_over_known_limits",
            refused_endpoint_count = refused.len(),
            sendable_endpoint_count = sendable.len(),
            "event exceeds known relay limits; not sent there"
        );
    }
    (sendable, refused)
}

/// The failure of an event refused on every endpoint of `targets`. It was
/// sent nowhere, and it proves its size as relays' own refusals would.
pub(crate) fn refused_everywhere(
    targets: &[TransportEndpoint],
    refused: Vec<TransportEndpointFailure>,
    event: &NostrTransportEvent,
) -> TransportAdapterError {
    let mut failure = TransportPublishFailure::with_endpoint_failures(
        TransportEndpointFailure::OVER_KNOWN_LIMIT_REASON.to_owned(),
        refused,
    );
    failure.event_size_class =
        EventSizeClass::from_rejected_targets(targets, &failure.endpoint_failures);
    failure.message_id = hex::decode(&event.id).ok().map(MessageId::new);
    TransportAdapterError::PublishEndpoints(failure)
}

/// A publish that failed on the relays it was sent to, joined by the relays
/// refused unsent. Their size proof extends to all of `targets` only with
/// every refusal.
pub(crate) fn join_refusals(
    error: TransportAdapterError,
    targets: &[TransportEndpoint],
    refused: Vec<TransportEndpointFailure>,
) -> TransportAdapterError {
    match error {
        TransportAdapterError::PublishEndpoints(mut failure) if !refused.is_empty() => {
            failure.endpoint_failures.extend(refused);
            failure.event_size_class = failure.event_size_class.and_then(|_| {
                EventSizeClass::from_rejected_targets(targets, &failure.endpoint_failures)
            });
            TransportAdapterError::PublishEndpoints(failure)
        }
        error => error,
    }
}

/// An account publish client that sends no event to a relay over its known
/// limit (mdk#2334). A refused relay joins the publish's result as a relay
/// that refused the event, and counts against its required acknowledgements
/// like one; an event every relay refuses is sent nowhere and fails as too
/// large. Every account publisher `marmot-app` builds wraps its client in
/// one.
pub struct KnownLimitPublishClient {
    inner: Arc<dyn NostrRelayClient>,
    limits: Arc<dyn RelayEventLimits>,
}

/// One request of a batch: refused everywhere, or sent with these refusals.
enum BatchSlot {
    Refused(TransportAdapterError),
    Sent(Vec<TransportEndpointFailure>),
}

impl KnownLimitPublishClient {
    pub fn new(inner: Arc<dyn NostrRelayClient>, limits: Arc<dyn RelayEventLimits>) -> Self {
        Self { inner, limits }
    }

    async fn split(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
    ) -> (Vec<TransportEndpoint>, Vec<TransportEndpointFailure>) {
        refuse_over_known_limits(
            Some(self.limits.as_ref()),
            endpoints,
            event_json_bytes(event),
        )
        .await
    }

    /// Send one event with `send` to the endpoints it may fit, and join the
    /// refusals of the rest to the result.
    async fn publish_one<F, Fut>(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        send: F,
    ) -> Result<NostrPublishOutcome, TransportAdapterError>
    where
        F: FnOnce(Vec<TransportEndpoint>) -> Fut,
        Fut: Future<Output = Result<NostrPublishOutcome, TransportAdapterError>>,
    {
        let (sendable, refused) = self.split(endpoints, event).await;
        if refused.is_empty() {
            return send(sendable).await;
        }
        if sendable.is_empty() {
            return Err(refused_everywhere(endpoints, refused, event));
        }
        join_outcome(send(sendable).await, endpoints, refused)
    }

    /// Send a batch with `send`, each request to the endpoints its event may
    /// fit. A request refused everywhere is answered unsent, with no
    /// duration; the rest go out together, in order.
    async fn publish_batch<F, Fut>(
        &self,
        requests: &[NostrEventPublishRequest],
        send: F,
    ) -> NostrPublishBatch
    where
        F: FnOnce(Vec<NostrEventPublishRequest>) -> Fut,
        Fut: Future<Output = NostrPublishBatch>,
    {
        let splits = futures::future::join_all(
            requests
                .iter()
                .map(|request| self.split(&request.endpoints, &request.event)),
        )
        .await;
        let mut slots = Vec::with_capacity(requests.len());
        let mut sent = Vec::with_capacity(requests.len());
        for (request, (sendable, refused)) in requests.iter().zip(splits) {
            if sendable.is_empty() && !refused.is_empty() {
                slots.push(BatchSlot::Refused(refused_everywhere(
                    &request.endpoints,
                    refused,
                    &request.event,
                )));
                continue;
            }
            slots.push(BatchSlot::Sent(refused));
            sent.push(NostrEventPublishRequest {
                endpoints: sendable,
                event: request.event.clone(),
                required_acks: request.required_acks,
            });
        }
        let batch = if sent.is_empty() {
            NostrPublishBatch {
                outcomes: Vec::new(),
                request_durations: Vec::new(),
            }
        } else {
            send(sent).await
        };
        let mut outcomes = batch.outcomes.into_iter();
        let mut durations = batch.request_durations.into_iter();
        let mut joined = NostrPublishBatch {
            outcomes: Vec::with_capacity(requests.len()),
            request_durations: Vec::with_capacity(requests.len()),
        };
        for (request, slot) in requests.iter().zip(slots) {
            let (outcome, duration) = match slot {
                BatchSlot::Refused(error) => (Err(error), Duration::ZERO),
                BatchSlot::Sent(refused) => {
                    let outcome = outcomes.next().unwrap_or_else(|| {
                        Err(TransportAdapterError::Publish(
                            "publish batch returned no outcome".to_owned(),
                        ))
                    });
                    let duration = durations.next().unwrap_or_default();
                    if refused.is_empty() {
                        (outcome, duration)
                    } else {
                        (join_outcome(outcome, &request.endpoints, refused), duration)
                    }
                }
            };
            joined.outcomes.push(outcome);
            joined.request_durations.push(duration);
        }
        joined
    }
}

/// A publish's result on the relays it was sent to, joined by the relays
/// refused unsent.
fn join_outcome(
    result: Result<NostrPublishOutcome, TransportAdapterError>,
    targets: &[TransportEndpoint],
    refused: Vec<TransportEndpointFailure>,
) -> Result<NostrPublishOutcome, TransportAdapterError> {
    match result {
        Ok(mut outcome) => {
            outcome.failed.extend(refused);
            Ok(outcome)
        }
        Err(error) => Err(join_refusals(error, targets, refused)),
    }
}

/// Only publishes change; everything else is the inner client's.
#[async_trait]
impl NostrRelayClient for KnownLimitPublishClient {
    fn relay_notification_source(&self) -> Option<Arc<dyn NostrRelayNotificationSource>> {
        self.inner.relay_notification_source()
    }

    fn relay_connection(
        &self,
        account: &MemberId,
        endpoint: &TransportEndpoint,
    ) -> Option<RelayConnection> {
        self.inner.relay_connection(account, endpoint)
    }

    async fn reply_sent_nothing(
        &self,
        account: Option<&MemberId>,
        endpoint: &TransportEndpoint,
        subscription_id: &str,
    ) -> bool {
        self.inner
            .reply_sent_nothing(account, endpoint, subscription_id)
            .await
    }

    async fn acquire_history(
        &self,
        request: NostrAcquisitionRequest,
        cancellation: NostrAcquisitionCancellation,
    ) -> Result<NostrAcquisitionResult, NostrAcquisitionError> {
        self.inner.acquire_history(request, cancellation).await
    }

    fn notification_loss(
        &self,
    ) -> Result<tokio::sync::watch::Receiver<Option<NostrNotificationLoss>>, NostrAcquisitionError>
    {
        self.inner.notification_loss()
    }

    async fn notification_loss_for_account(
        &self,
        account_id: &MemberId,
    ) -> Result<tokio::sync::watch::Receiver<Option<NostrNotificationLoss>>, NostrAcquisitionError>
    {
        self.inner.notification_loss_for_account(account_id).await
    }

    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        self.inner.subscribe(subscription).await
    }

    async fn subscribe_reporting(
        &self,
        subscription: NostrSubscription,
    ) -> Result<NostrSubscribeReport, TransportAdapterError> {
        self.inner.subscribe_reporting(subscription).await
    }

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        self.inner.unsubscribe(subscription).await
    }

    fn supports_scoped_subscriptions(&self) -> bool {
        self.inner.supports_scoped_subscriptions()
    }

    async fn subscribe_scoped(
        &self,
        subscription: NostrSubscription,
        subscription_id: String,
    ) -> Result<(), TransportAdapterError> {
        self.inner
            .subscribe_scoped(subscription, subscription_id)
            .await
    }

    async fn unsubscribe_scoped(
        &self,
        subscription: NostrSubscription,
        subscription_id: String,
    ) -> Result<(), TransportAdapterError> {
        self.inner
            .unsubscribe_scoped(subscription, subscription_id)
            .await
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
        replacements: &[NostrSubscription],
    ) -> Result<(), TransportAdapterError> {
        self.inner
            .unsubscribe_account(account_id, replacements)
            .await
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        self.publish_one(endpoints, event, |sendable| async move {
            self.inner
                .publish_event(&sendable, event, required_acks)
                .await
        })
        .await
    }

    async fn publish_event_for_account(
        &self,
        account_id: &MemberId,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        self.publish_one(endpoints, event, |sendable| async move {
            self.inner
                .publish_event_for_account(account_id, &sendable, event, required_acks)
                .await
        })
        .await
    }

    async fn publish_events_for_account(
        &self,
        account_id: &MemberId,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        self.publish_batch(requests, |sent| async move {
            let outcomes = self
                .inner
                .publish_events_for_account(account_id, &sent)
                .await;
            NostrPublishBatch {
                request_durations: vec![Duration::ZERO; outcomes.len()],
                outcomes,
            }
        })
        .await
        .outcomes
    }

    async fn publish_events_for_account_with_timings(
        &self,
        account_id: &MemberId,
        requests: &[NostrEventPublishRequest],
    ) -> NostrPublishBatch {
        self.publish_batch(requests, |sent| async move {
            self.inner
                .publish_events_for_account_with_timings(account_id, &sent)
                .await
        })
        .await
    }

    async fn publish_events(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        self.publish_batch(requests, |sent| async move {
            let outcomes = self.inner.publish_events(&sent).await;
            NostrPublishBatch {
                request_durations: vec![Duration::ZERO; outcomes.len()],
                outcomes,
            }
        })
        .await
        .outcomes
    }

    async fn publish_events_with_timings(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> NostrPublishBatch {
        self.publish_batch(requests, |sent| async move {
            self.inner.publish_events_with_timings(&sent).await
        })
        .await
    }
}
