//! The publish gate of an account whose device group unlinked this device
//! (mdk#2628 D67).
//!
//! Every account-signed publication this crate makes goes through
//! [`crate::MarmotApp::relay_client_for_account_id`], the account adapter's
//! included. The client it hands out refuses every publish once the account
//! is unlinked here, whichever path the publish came from: a retained
//! client, a catch-up still admitting input, or maintenance. Subscriptions
//! and reads still pass, so the account's transport can be torn down.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use cgka_traits::{MemberId, TransportAdapterError, TransportEndpoint};
use transport_nostr_adapter::{
    NostrAcquisitionCancellation, NostrAcquisitionError, NostrAcquisitionRequest,
    NostrAcquisitionResult, NostrEventPublishRequest, NostrNotificationLoss, NostrPublishBatch,
    NostrPublishOutcome, NostrRelayClient, NostrSubscribeReport, NostrSubscription,
    RelayConnection,
};
use transport_nostr_peeler::NostrTransportEvent;

/// An account publisher that refuses to publish once `unlinked` is set.
pub(crate) struct UnlinkedPublishGate {
    inner: Arc<dyn NostrRelayClient>,
    unlinked: Arc<AtomicBool>,
}

impl UnlinkedPublishGate {
    pub(crate) fn new(inner: Arc<dyn NostrRelayClient>, unlinked: Arc<AtomicBool>) -> Self {
        Self { inner, unlinked }
    }

    fn refusal(&self) -> Option<TransportAdapterError> {
        self.unlinked
            .load(Ordering::Acquire)
            .then(|| TransportAdapterError::Publish("this device is unlinked".to_owned()))
    }
}

#[async_trait]
impl NostrRelayClient for UnlinkedPublishGate {
    fn relay_connection(
        &self,
        account: &MemberId,
        endpoint: &TransportEndpoint,
    ) -> Option<RelayConnection> {
        self.inner.relay_connection(account, endpoint)
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
        if let Some(refusal) = self.refusal() {
            return Err(refusal);
        }
        self.inner
            .publish_event(endpoints, event, required_acks)
            .await
    }

    async fn publish_event_for_account(
        &self,
        account_id: &MemberId,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        if let Some(refusal) = self.refusal() {
            return Err(refusal);
        }
        self.inner
            .publish_event_for_account(account_id, endpoints, event, required_acks)
            .await
    }

    async fn publish_events_for_account(
        &self,
        account_id: &MemberId,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        if self.refusal().is_some() {
            return refuse_all(self, requests);
        }
        self.inner
            .publish_events_for_account(account_id, requests)
            .await
    }

    async fn publish_events_for_account_with_timings(
        &self,
        account_id: &MemberId,
        requests: &[NostrEventPublishRequest],
    ) -> NostrPublishBatch {
        if self.refusal().is_some() {
            return refused_batch(self, requests);
        }
        self.inner
            .publish_events_for_account_with_timings(account_id, requests)
            .await
    }

    async fn publish_events(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        if self.refusal().is_some() {
            return refuse_all(self, requests);
        }
        self.inner.publish_events(requests).await
    }

    async fn publish_events_with_timings(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> NostrPublishBatch {
        if self.refusal().is_some() {
            return refused_batch(self, requests);
        }
        self.inner.publish_events_with_timings(requests).await
    }
}

fn refuse_all(
    gate: &UnlinkedPublishGate,
    requests: &[NostrEventPublishRequest],
) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
    requests
        .iter()
        .map(|_| Err(gate.refusal().expect("the gate is closed for good")))
        .collect()
}

fn refused_batch(
    gate: &UnlinkedPublishGate,
    requests: &[NostrEventPublishRequest],
) -> NostrPublishBatch {
    NostrPublishBatch {
        request_durations: vec![std::time::Duration::ZERO; requests.len()],
        outcomes: refuse_all(gate, requests),
    }
}
