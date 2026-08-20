//! Scheme-dispatching Nostr relay client.

use std::sync::Arc;

use async_trait::async_trait;
use cgka_traits::{
    MemberId, MessageId, TransportAdapterError, TransportEndpoint, TransportEndpointFailure,
    TransportPublishFailure, collapse_publish_failure_summaries,
};
use tokio::task::JoinSet;
use transport_nostr_peeler::NostrTransportEvent;

use crate::{
    FipsNostrRelayClient, NostrEventPublishRequest, NostrPublishOutcome, NostrRelayClient,
    NostrRelayEndpoint, NostrSubscription,
};

/// Dispatches one logical Nostr relay route across WebSocket and direct-FIPS
/// backends. Signed events and subscription meaning stay the same; only the
/// relay connection mechanism changes.
#[derive(Clone)]
pub struct HybridNostrRelayClient {
    websocket: Arc<dyn NostrRelayClient>,
    fips: FipsNostrRelayClient,
}

impl HybridNostrRelayClient {
    pub fn new(websocket: Arc<dyn NostrRelayClient>, fips: FipsNostrRelayClient) -> Self {
        Self { websocket, fips }
    }

    pub fn fips_client(&self) -> &FipsNostrRelayClient {
        &self.fips
    }

    async fn apply_subscription(
        &self,
        subscription: NostrSubscription,
        unsubscribe: bool,
    ) -> Result<(), TransportAdapterError> {
        let (has_websocket, has_fips) = endpoint_backends(subscription.endpoints(), true)?;
        if !has_websocket && !has_fips {
            return Err(TransportAdapterError::Subscription(
                "subscription contains no relay endpoints".to_owned(),
            ));
        }

        let websocket = self.websocket.clone();
        let fips = self.fips.clone();
        let websocket_subscription = subscription.clone();
        let websocket_call = async move {
            if !has_websocket {
                return None;
            }
            Some(if unsubscribe {
                websocket.unsubscribe(websocket_subscription).await
            } else {
                websocket.subscribe(websocket_subscription).await
            })
        };
        let fips_call = async move {
            if !has_fips {
                return None;
            }
            Some(if unsubscribe {
                fips.unsubscribe(subscription).await
            } else {
                fips.subscribe(subscription).await
            })
        };
        let (websocket_result, fips_result) = tokio::join!(websocket_call, fips_call);
        let attempted =
            usize::from(websocket_result.is_some()) + usize::from(fips_result.is_some());
        let succeeded = usize::from(matches!(websocket_result, Some(Ok(()))))
            + usize::from(matches!(fips_result, Some(Ok(()))));
        if succeeded > 0 {
            if succeeded != attempted {
                tracing::warn!(
                    target: "transport_nostr_adapter::hybrid_client",
                    method = "apply_subscription",
                    backend_count = attempted,
                    successful_backend_count = succeeded,
                    "relay subscription only partially applied"
                );
            }
            return Ok(());
        }
        websocket_result
            .and_then(Result::err)
            .or_else(|| fips_result.and_then(Result::err))
            .map_or_else(
                || {
                    Err(TransportAdapterError::Subscription(
                        "relay subscription failed".to_owned(),
                    ))
                },
                Err,
            )
    }

    async fn publish_one_endpoint(
        &self,
        endpoint: TransportEndpoint,
        event: NostrTransportEvent,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        match NostrRelayEndpoint::parse(endpoint.as_str()) {
            Ok(NostrRelayEndpoint::WebSocket(_)) => {
                self.websocket.publish_event(&[endpoint], &event, 1).await
            }
            Ok(NostrRelayEndpoint::Fips(_)) => {
                self.fips.publish_event(&[endpoint], &event, 1).await
            }
            Err(_) => Err(TransportAdapterError::Publish(
                "invalid relay endpoint".to_owned(),
            )),
        }
    }
}

#[async_trait]
impl NostrRelayClient for HybridNostrRelayClient {
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        self.apply_subscription(subscription, false).await
    }

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        self.apply_subscription(subscription, true).await
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        let (websocket, fips) = tokio::join!(
            self.websocket.unsubscribe_account(account_id),
            self.fips.unsubscribe_account(account_id)
        );
        match (websocket, fips) {
            (Ok(()), Ok(())) => Ok(()),
            (Ok(()), Err(_)) | (Err(_), Ok(())) => {
                tracing::warn!(
                    target: "transport_nostr_adapter::hybrid_client",
                    method = "unsubscribe_account",
                    "account unsubscribe only partially applied"
                );
                Ok(())
            }
            (Err(error), Err(_)) => Err(error),
        }
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        if endpoints.is_empty() {
            return Err(TransportAdapterError::Publish(
                "publish contains no relay endpoints".to_owned(),
            ));
        }
        let (has_websocket, has_fips) = endpoint_backends(endpoints, false)?;
        match (has_websocket, has_fips) {
            (true, false) => {
                return self
                    .websocket
                    .publish_event(endpoints, event, required_acks)
                    .await;
            }
            (false, true) => {
                return self
                    .fips
                    .publish_event(endpoints, event, required_acks)
                    .await;
            }
            (false, false) => {
                return Err(TransportAdapterError::Publish(
                    "publish contains no relay endpoints".to_owned(),
                ));
            }
            (true, true) => {}
        }
        let message_id = MessageId::new(hex::decode(&event.id).map_err(|_| {
            TransportAdapterError::Publish("Nostr event has invalid message id".to_owned())
        })?);
        let mut tasks = JoinSet::new();
        for endpoint in endpoints.iter().cloned() {
            let client = self.clone();
            let event = event.clone();
            tasks.spawn(async move {
                let outcome = client.publish_one_endpoint(endpoint.clone(), event).await;
                (endpoint, outcome)
            });
        }

        let mut accepted = Vec::new();
        let mut failed = Vec::new();
        let required_acks = required_acks.max(1);
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((_endpoint, Ok(mut outcome))) => {
                    accepted.append(&mut outcome.accepted);
                    failed.append(&mut outcome.failed);
                }
                Ok((endpoint, Err(error))) => {
                    if let Some(endpoint_failure) = error.publish_endpoint_failures().first() {
                        failed.push(endpoint_failure.clone());
                    } else {
                        failed.push(TransportEndpointFailure {
                            endpoint,
                            reason: "relay backend publish failed".to_owned(),
                            rejection_category: None,
                        });
                    }
                }
                Err(_) => {}
            }
            if accepted.len() >= required_acks {
                tasks.abort_all();
                break;
            }
        }

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

    async fn publish_events(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        if requests.iter().all(|request| {
            !request.endpoints.is_empty()
                && request.endpoints.iter().all(|endpoint| {
                    matches!(
                        NostrRelayEndpoint::parse(endpoint.as_str()),
                        Ok(NostrRelayEndpoint::WebSocket(_))
                    )
                })
        }) {
            return self.websocket.publish_events(requests).await;
        }
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

fn endpoint_backends(
    endpoints: &[TransportEndpoint],
    subscription: bool,
) -> Result<(bool, bool), TransportAdapterError> {
    let mut has_websocket = false;
    let mut has_fips = false;
    for endpoint in endpoints {
        match NostrRelayEndpoint::parse(endpoint.as_str()) {
            Ok(NostrRelayEndpoint::WebSocket(_)) => has_websocket = true,
            Ok(NostrRelayEndpoint::Fips(_)) => has_fips = true,
            Err(_) if subscription => {
                return Err(TransportAdapterError::Subscription(
                    "invalid relay endpoint".to_owned(),
                ));
            }
            Err(_) => {
                return Err(TransportAdapterError::Publish(
                    "invalid relay endpoint".to_owned(),
                ));
            }
        }
    }
    Ok((has_websocket, has_fips))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use cgka_traits::TransportEndpointReceipt;
    use cgka_traits::transport::Timestamp;
    use nostr::{Keys, ToBech32};
    use tokio::sync::broadcast;

    use super::*;
    use crate::{
        FipsRelayApi, FipsRelayApiError, FipsRelayEndpoint, FipsRelayNotification,
        FipsRelaySubscription,
    };

    #[derive(Default)]
    struct RecordingWebsocketClient {
        subscriptions: Mutex<Vec<NostrSubscription>>,
        publications: Mutex<Vec<TransportEndpoint>>,
        batch_publications: AtomicUsize,
    }

    #[async_trait]
    impl NostrRelayClient for RecordingWebsocketClient {
        async fn subscribe(
            &self,
            subscription: NostrSubscription,
        ) -> Result<(), TransportAdapterError> {
            self.subscriptions.lock().unwrap().push(subscription);
            Ok(())
        }

        async fn unsubscribe(
            &self,
            _subscription: NostrSubscription,
        ) -> Result<(), TransportAdapterError> {
            Ok(())
        }

        async fn unsubscribe_account(
            &self,
            _account_id: &MemberId,
        ) -> Result<(), TransportAdapterError> {
            Ok(())
        }

        async fn publish_event(
            &self,
            endpoints: &[TransportEndpoint],
            _event: &NostrTransportEvent,
            _required_acks: usize,
        ) -> Result<NostrPublishOutcome, TransportAdapterError> {
            self.publications
                .lock()
                .unwrap()
                .extend_from_slice(endpoints);
            Ok(NostrPublishOutcome {
                message_id: None,
                accepted: endpoints
                    .iter()
                    .cloned()
                    .map(|endpoint| TransportEndpointReceipt {
                        endpoint,
                        accepted_at: None,
                    })
                    .collect(),
                failed: Vec::new(),
            })
        }

        async fn publish_events(
            &self,
            requests: &[NostrEventPublishRequest],
        ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
            self.batch_publications.fetch_add(1, Ordering::SeqCst);
            requests
                .iter()
                .map(|request| Ok(NostrPublishOutcome::accepted(request.endpoints.clone())))
                .collect()
        }
    }

    struct RecordingFipsApi {
        subscriptions: Mutex<Vec<(FipsRelayEndpoint, FipsRelaySubscription)>>,
        publications: Mutex<Vec<FipsRelayEndpoint>>,
        notifications: broadcast::Sender<FipsRelayNotification>,
    }

    impl Default for RecordingFipsApi {
        fn default() -> Self {
            Self {
                subscriptions: Mutex::new(Vec::new()),
                publications: Mutex::new(Vec::new()),
                notifications: broadcast::channel(16).0,
            }
        }
    }

    #[async_trait]
    impl FipsRelayApi for RecordingFipsApi {
        async fn subscribe(
            &self,
            endpoint: &FipsRelayEndpoint,
            subscription: &FipsRelaySubscription,
        ) -> Result<(), FipsRelayApiError> {
            self.subscriptions
                .lock()
                .unwrap()
                .push((endpoint.clone(), subscription.clone()));
            Ok(())
        }

        async fn unsubscribe(
            &self,
            _endpoint: &FipsRelayEndpoint,
            _subscription_id: &str,
        ) -> Result<(), FipsRelayApiError> {
            Ok(())
        }

        async fn publish_event(
            &self,
            endpoint: &FipsRelayEndpoint,
            _event: &NostrTransportEvent,
        ) -> Result<(), FipsRelayApiError> {
            self.publications.lock().unwrap().push(endpoint.clone());
            Ok(())
        }

        fn notifications(&self) -> broadcast::Receiver<FipsRelayNotification> {
            self.notifications.subscribe()
        }
    }

    fn fips_endpoint() -> TransportEndpoint {
        let npub = Keys::generate().public_key().to_bech32().unwrap();
        TransportEndpoint(format!("fips://{npub}"))
    }

    fn event() -> NostrTransportEvent {
        NostrTransportEvent::new_unsigned("11".repeat(32), 445, Vec::new(), "payload".into())
    }

    #[tokio::test]
    async fn mixed_subscription_reaches_both_backends_with_one_logical_id() {
        let websocket = Arc::new(RecordingWebsocketClient::default());
        let fips_api = Arc::new(RecordingFipsApi::default());
        let client = HybridNostrRelayClient::new(
            websocket.clone(),
            FipsNostrRelayClient::new(fips_api.clone()),
        );
        let subscription = NostrSubscription::Group {
            account_id: MemberId::new(vec![0x11; 32]),
            group_id: cgka_traits::GroupId::new(vec![0x22; 16]),
            transport_group_id: vec![0x33; 32],
            endpoints: vec![
                TransportEndpoint("wss://relay.example".into()),
                fips_endpoint(),
            ],
            since: Some(Timestamp(42)),
        };
        let expected_id = subscription.subscription_id();

        client.subscribe(subscription).await.unwrap();

        let websocket_subscriptions = websocket.subscriptions.lock().unwrap();
        assert_eq!(websocket_subscriptions.len(), 1);
        assert_eq!(websocket_subscriptions[0].subscription_id(), expected_id);
        let fips_subscriptions = fips_api.subscriptions.lock().unwrap();
        assert_eq!(fips_subscriptions.len(), 1);
        assert_eq!(fips_subscriptions[0].1.subscription_id, expected_id);
    }

    #[tokio::test]
    async fn mixed_publish_counts_acknowledgements_across_backends() {
        let websocket = Arc::new(RecordingWebsocketClient::default());
        let fips_api = Arc::new(RecordingFipsApi::default());
        let client = HybridNostrRelayClient::new(
            websocket.clone(),
            FipsNostrRelayClient::new(fips_api.clone()),
        );
        let endpoints = vec![
            TransportEndpoint("wss://relay.example".into()),
            fips_endpoint(),
        ];

        let outcome = client.publish_event(&endpoints, &event(), 2).await.unwrap();

        assert_eq!(outcome.accepted.len(), 2);
        assert_eq!(websocket.publications.lock().unwrap().len(), 1);
        assert_eq!(fips_api.publications.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn websocket_only_batch_keeps_the_backend_batch_lifecycle() {
        let websocket = Arc::new(RecordingWebsocketClient::default());
        let fips_api = Arc::new(RecordingFipsApi::default());
        let client =
            HybridNostrRelayClient::new(websocket.clone(), FipsNostrRelayClient::new(fips_api));
        let requests = vec![NostrEventPublishRequest {
            endpoints: vec![TransportEndpoint("wss://relay.example".into())],
            event: event(),
            required_acks: 1,
        }];

        let outcomes = client.publish_events(&requests).await;

        assert!(outcomes[0].is_ok());
        assert_eq!(websocket.batch_publications.load(Ordering::SeqCst), 1);
        assert!(websocket.publications.lock().unwrap().is_empty());
    }
}
