//! Known relay event limits (mdk#2334): no account publish sends an event to
//! a relay over that relay's known limit.
//!
//! [`refuse_over_known_limits`] decides which relays are refused. The account
//! adapter applies it to the group events and Welcomes it publishes, and
//! [`KnownLimitPublishClient`] to everything else an account signs and
//! publishes: profiles, follow and relay lists, KeyPackages and their
//! deletions, the block list, stickers, the backup pointer.
//!
//! A commit also meets [`COMMIT_SIZE_FLOOR_BYTES`] at a relay whose limit is
//! unknown (mdk#2332): [`admit_commit`].

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{
    EventSizeClass, MemberId, MessageId, TransportAdapterError, TransportEndpoint,
    TransportEndpointFailure, TransportEndpointFailureKind, TransportPublishFailure,
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

/// The largest commit sent to a relay whose event limit is unknown
/// (mdk#2332). A frame over a relay's limit closes the socket mid-send, which
/// leaves the commit possibly seen and so pending for good; refused before
/// sending, it rolls back instead. 64 KiB is strfry's default
/// `events.maxEventSize`, the smallest event limit relays use.
pub const COMMIT_SIZE_FLOOR_BYTES: usize = 64 * 1024;

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

/// Where a commit of `event_bytes` may go: the endpoints it is sent to, a
/// refusal for each whose limit it exceeds, and a hold for each it cannot be
/// judged at yet (mdk#2332).
///
/// A known limit judges as for any event. An unknown limit allows
/// [`COMMIT_SIZE_FLOOR_BYTES`], if the relay can be reached: whether a relay
/// is offline is judged by connecting to it, not by its relay document. One
/// that cannot be connected to is held, a failure that proves nothing was
/// sent, so an offline device or a down relay never makes a commit look too
/// large. With no limits source the adapter enforces no limit, the floor
/// included.
pub(crate) async fn admit_commit(
    limits: Option<&dyn RelayEventLimits>,
    connections: &dyn NostrRelayClient,
    endpoints: &[TransportEndpoint],
    event_bytes: usize,
) -> CommitAdmission {
    let mut admission = CommitAdmission::default();
    let Some(limits) = limits else {
        admission.sendable = endpoints.to_vec();
        return admission;
    };
    let verdicts = futures::future::join_all(
        endpoints
            .iter()
            .map(|endpoint| commit_size_verdict(limits, connections, endpoint, event_bytes)),
    )
    .await;
    for (endpoint, verdict) in endpoints.iter().zip(verdicts) {
        match verdict {
            CommitSizeVerdict::Send => admission.sendable.push(endpoint.clone()),
            CommitSizeVerdict::Refuse => {
                admission
                    .refused
                    .push(TransportEndpointFailure::over_known_limit(
                        endpoint.clone(),
                        event_bytes,
                    ))
            }
            CommitSizeVerdict::Hold(failure) => admission.held.push(failure),
        }
    }
    if !admission.refused.is_empty() || !admission.held.is_empty() {
        tracing::debug!(
            target: "marmot_app::relay_plane",
            method = "admit_commit",
            refused_endpoint_count = admission.refused.len(),
            held_endpoint_count = admission.held.len(),
            sendable_endpoint_count = admission.sendable.len(),
            "commit not sent to relays it may exceed"
        );
    }
    admission
}

/// [`admit_commit`]'s split of a commit's endpoints.
#[derive(Default)]
pub(crate) struct CommitAdmission {
    pub(crate) sendable: Vec<TransportEndpoint>,
    pub(crate) refused: Vec<TransportEndpointFailure>,
    pub(crate) held: Vec<TransportEndpointFailure>,
}

/// How a commit's size stands at one relay.
pub(crate) enum CommitSizeVerdict {
    Send,
    Refuse,
    /// No connection to the relay, so its unknown limit cannot be judged.
    Hold(TransportEndpointFailure),
}

/// [`admit_commit`]'s rule for one endpoint.
pub(crate) async fn commit_size_verdict(
    limits: &dyn RelayEventLimits,
    connections: &dyn NostrRelayClient,
    endpoint: &TransportEndpoint,
    event_bytes: usize,
) -> CommitSizeVerdict {
    match limits.max_event_bytes(endpoint, event_bytes).await {
        Some(limit) if event_bytes > limit => CommitSizeVerdict::Refuse,
        Some(_) => CommitSizeVerdict::Send,
        None if event_bytes <= COMMIT_SIZE_FLOOR_BYTES => CommitSizeVerdict::Send,
        None => match connections.connect_for_publish(endpoint).await {
            Ok(()) => CommitSizeVerdict::Refuse,
            // A connect sends no event, so whatever the client reports, the
            // hold proves nothing was sent.
            Err(failure) => CommitSizeVerdict::Hold(TransportEndpointFailure {
                endpoint: endpoint.clone(),
                reason: failure.reason,
                kind: TransportEndpointFailureKind::RetryableUnavailable,
                rejection_category: None,
                size_class: None,
                pre_send: true,
            }),
        },
    }
}

/// The failure of a commit sent nowhere: refused or held at every endpoint,
/// with at least one held. A hold proves no size, so neither does the
/// failure.
pub(crate) fn held_everywhere(
    failures: Vec<TransportEndpointFailure>,
    event: &NostrTransportEvent,
) -> TransportAdapterError {
    let mut failure =
        TransportPublishFailure::with_endpoint_failures(COMMIT_HELD_REASON.to_owned(), failures);
    failure.message_id = hex::decode(&event.id).ok().map(MessageId::new);
    TransportAdapterError::PublishEndpoints(failure)
}

const COMMIT_HELD_REASON: &str = "commit held until its relays can be reached";

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
    async fn connect_for_publish(
        &self,
        endpoint: &TransportEndpoint,
    ) -> Result<(), TransportEndpointFailure> {
        self.inner.connect_for_publish(endpoint).await
    }

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
