use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{MemberId, TransportAdapterError, TransportEndpoint};
use tokio::sync::{Mutex, mpsc, watch};
use transport_nostr_adapter::{
    NostrAcquisitionCancellation, NostrAcquisitionCorrelation, NostrAcquisitionEnd,
    NostrAcquisitionEndpoint, NostrAcquisitionError, NostrAcquisitionLimits,
    NostrAcquisitionRequest, NostrAcquisitionResult, NostrAcquisitionScope, NostrAcquisitionStats,
    NostrNotificationLoss, NostrNotificationLossScope, NostrPublishOutcome, NostrRelayClient,
    NostrSubscription, NostrTransportAdapter, SubscriptionAttempt,
};
use transport_nostr_peeler::NostrTransportEvent;

fn request() -> NostrAcquisitionRequest {
    NostrAcquisitionRequest {
        correlation: NostrAcquisitionCorrelation {
            account_id: MemberId::new(vec![7; 32]),
            attempt_serial: 42,
            obligation_id: [8; 16],
            scope_id: 9,
            scope_revision: 4,
            subscription_attempt: SubscriptionAttempt::INITIAL,
        },
        scope: NostrAcquisitionScope::KnownEventIds(vec![[3; 32]]),
        endpoints: vec![
            TransportEndpoint("wss://first.example".into()),
            TransportEndpoint("wss://second.example".into()),
        ],
        limits: NostrAcquisitionLimits {
            max_endpoints: 2,
            max_received_items_per_endpoint: 3,
            max_serialized_event_bytes_per_endpoint: 4096,
            max_duration: Duration::from_secs(2),
        },
    }
}

fn event() -> NostrTransportEvent {
    NostrTransportEvent {
        id: "03".repeat(32),
        pubkey: "04".repeat(32),
        created_at: 1,
        kind: 445,
        tags: vec![],
        content: "partial ciphertext".into(),
        sig: None,
    }
}

struct FakeRelay {
    live: Mutex<HashSet<String>>,
    loss: watch::Sender<Option<NostrNotificationLoss>>,
    // Deliberately bounded data path. Loss uses `watch`, independent of it.
    data: mpsc::Sender<NostrTransportEvent>,
}

#[async_trait]
impl NostrRelayClient for FakeRelay {
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        self.live
            .lock()
            .await
            .insert(subscription.subscription_id());
        Ok(())
    }

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        self.live
            .lock()
            .await
            .remove(&subscription.subscription_id());
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        self.live.lock().await.clear();
        Ok(())
    }

    async fn publish_event(
        &self,
        _endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        Ok(NostrPublishOutcome::default())
    }

    async fn acquire_history(
        &self,
        request: NostrAcquisitionRequest,
        cancellation: NostrAcquisitionCancellation,
    ) -> Result<NostrAcquisitionResult, NostrAcquisitionError> {
        request.validate()?;
        Ok(NostrAcquisitionResult {
            correlation: request.correlation,
            endpoints: request
                .endpoints
                .into_iter()
                .enumerate()
                .map(|(index, endpoint)| {
                    let ordinary = event();
                    let oversized = NostrTransportEvent {
                        content: "x".repeat(5000),
                        ..event()
                    };
                    let input = if index == 0 {
                        vec![ordinary.clone(), ordinary, oversized]
                    } else {
                        vec![ordinary]
                    };
                    let mut stats = NostrAcquisitionStats::default();
                    let mut events = Vec::new();
                    let mut seen = HashSet::new();
                    let mut end = if index == 0 {
                        NostrAcquisitionEnd::RequestPolicySatisfied
                    } else {
                        NostrAcquisitionEnd::RelayClosed
                    };
                    for item in input {
                        stats.received_items += 1;
                        stats.serialized_event_bytes += serde_json::to_vec(&item).unwrap().len();
                        if stats.received_items > request.limits.max_received_items_per_endpoint {
                            end = NostrAcquisitionEnd::ItemLimitReached;
                            break;
                        }
                        if stats.serialized_event_bytes
                            > request.limits.max_serialized_event_bytes_per_endpoint
                        {
                            end = NostrAcquisitionEnd::ByteLimitReached;
                            break;
                        }
                        if !seen.insert(item.id.clone()) {
                            stats.duplicates += 1;
                            continue;
                        }
                        events.push(item);
                        stats.retained_high_water_items = events.len();
                        stats.retained_high_water_event_bytes = stats.serialized_event_bytes;
                    }
                    if cancellation.is_cancelled() {
                        end = NostrAcquisitionEnd::Cancelled;
                    }
                    NostrAcquisitionEndpoint {
                        endpoint,
                        session_generation: Some(12),
                        events,
                        end,
                        stats,
                    }
                })
                .collect(),
        })
    }

    fn notification_loss(
        &self,
    ) -> Result<watch::Receiver<Option<NostrNotificationLoss>>, NostrAcquisitionError> {
        Ok(self.loss.subscribe())
    }
}

#[tokio::test]
async fn partial_endpoint_results_are_owned_and_keep_correlation() {
    let (loss, _) = watch::channel(None);
    let (data, _) = mpsc::channel(1);
    let fake = Arc::new(FakeRelay {
        live: Mutex::new(HashSet::new()),
        loss,
        data,
    });
    let adapter = NostrTransportAdapter::new(fake);
    let expected = request().correlation;
    let result = adapter
        .acquire_history(request(), NostrAcquisitionCancellation::new())
        .await
        .unwrap();
    assert_eq!(result.correlation, expected);
    assert_eq!(result.endpoints.len(), 2);
    assert_eq!(
        result.endpoints[0].end,
        NostrAcquisitionEnd::ByteLimitReached
    );
    assert_eq!(result.endpoints[1].end, NostrAcquisitionEnd::RelayClosed);
    assert_eq!(result.endpoints[0].events, vec![event()]);
    assert!(result.endpoints[0].stats.serialized_event_bytes > 4096);
    assert_eq!(result.endpoints[0].stats.received_items, 3);
    assert_eq!(result.endpoints[0].stats.duplicates, 1);
    assert_eq!(result.endpoints[0].stats.retained_high_water_items, 1);
    assert_eq!(result.endpoints[0].session_generation, Some(12));
    // A future worker can admit owned events; only the existing recovery owner
    // may decide whether the attempt/frozen scope still authorizes completion.
    let worker_input = result
        .endpoints
        .into_iter()
        .flat_map(|endpoint| endpoint.events)
        .collect::<Vec<_>>();
    assert_eq!(worker_input.len(), 2);

    let mut item_limited = request();
    item_limited.limits.max_received_items_per_endpoint = 1;
    item_limited.limits.max_serialized_event_bytes_per_endpoint = 10_000;
    let result = adapter
        .acquire_history(item_limited, NostrAcquisitionCancellation::new())
        .await
        .unwrap();
    assert_eq!(
        result.endpoints[0].end,
        NostrAcquisitionEnd::ItemLimitReached
    );
    assert_eq!(result.endpoints[0].events, vec![event()]);
    assert_eq!(result.endpoints[0].stats.received_items, 2);
}

#[tokio::test]
async fn cancellation_is_request_scoped_and_loss_survives_data_saturation() {
    let (loss, _) = watch::channel(None);
    let (data, mut data_rx) = mpsc::channel(1);
    let fake = Arc::new(FakeRelay {
        live: Mutex::new(HashSet::new()),
        loss,
        data,
    });
    let adapter = NostrTransportAdapter::new(fake.clone());
    let live = NostrSubscription::AccountInbox {
        account_id: MemberId::new(vec![7; 32]),
        endpoints: request().endpoints,
        since: None,
        attempt: SubscriptionAttempt::INITIAL,
    };
    fake.subscribe(live.clone()).await.unwrap();
    fake.data.try_send(event()).unwrap();
    assert!(fake.data.try_send(event()).is_err());
    let mut loss_rx = adapter.notification_loss().unwrap();
    fake.loss.send_replace(Some(NostrNotificationLoss {
        scope: NostrNotificationLossScope::SharedReceiver,
        receiver_generation: 3,
        cumulative_skipped: 2,
    }));
    fake.loss.send_replace(Some(NostrNotificationLoss {
        scope: NostrNotificationLossScope::SharedReceiver,
        receiver_generation: 4,
        cumulative_skipped: 5,
    }));
    loss_rx.changed().await.unwrap();
    assert_eq!(loss_rx.borrow().as_ref().unwrap().cumulative_skipped, 5);
    let cancellation = NostrAcquisitionCancellation::new();
    cancellation.cancel();
    let result = adapter
        .acquire_history(request(), cancellation)
        .await
        .unwrap();
    assert!(
        result
            .endpoints
            .iter()
            .all(|endpoint| endpoint.end == NostrAcquisitionEnd::Cancelled)
    );
    assert!(fake.live.lock().await.contains(&live.subscription_id()));
    assert_eq!(data_rx.try_recv().unwrap(), event());
}

#[tokio::test]
async fn invalid_limits_and_default_unsupported_fail_without_work() {
    let (loss, _) = watch::channel(None);
    let (data, _) = mpsc::channel(1);
    let fake = Arc::new(FakeRelay {
        live: Mutex::new(HashSet::new()),
        loss,
        data,
    });
    let adapter = NostrTransportAdapter::new(fake.clone());
    let mut invalid = request();
    invalid.limits.max_serialized_event_bytes_per_endpoint = 0;
    assert_eq!(
        adapter
            .acquire_history(invalid, NostrAcquisitionCancellation::new())
            .await
            .unwrap_err(),
        NostrAcquisitionError::InvalidRequest
    );
    assert!(fake.live.lock().await.is_empty());
    let mut too_many_endpoints = request();
    too_many_endpoints.limits.max_endpoints = 1;
    assert_eq!(
        adapter
            .acquire_history(too_many_endpoints, NostrAcquisitionCancellation::new())
            .await
            .unwrap_err(),
        NostrAcquisitionError::InvalidRequest
    );
    let mut repeated_endpoint = request();
    repeated_endpoint.endpoints[1] = repeated_endpoint.endpoints[0].clone();
    assert_eq!(
        repeated_endpoint.validate(),
        Err(NostrAcquisitionError::InvalidRequest)
    );

    // A legacy implementation inherits the trait's explicit unsupported result.
    struct Legacy;
    #[async_trait]
    impl NostrRelayClient for Legacy {
        async fn subscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
            Ok(())
        }
        async fn unsubscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
            Ok(())
        }
        async fn unsubscribe_account(&self, _: &MemberId) -> Result<(), TransportAdapterError> {
            Ok(())
        }
        async fn publish_event(
            &self,
            _: &[TransportEndpoint],
            _: &NostrTransportEvent,
            _: usize,
        ) -> Result<NostrPublishOutcome, TransportAdapterError> {
            Ok(NostrPublishOutcome::default())
        }
    }
    assert_eq!(
        Legacy
            .acquire_history(request(), NostrAcquisitionCancellation::new())
            .await
            .unwrap_err(),
        NostrAcquisitionError::Unsupported
    );
    assert!(matches!(
        Legacy.notification_loss(),
        Err(NostrAcquisitionError::Unsupported)
    ));
}

// Compile-checked projection of every terminal in the qualified #1995 SDK
// report. The production SDK implementation must replace this test-only input
// with actual typed SDK variants and retain the same incomplete distinctions.
#[test]
fn qualified_outcomes_have_an_exhaustive_projection() {
    #[allow(dead_code)]
    enum QualifiedEnd {
        Completed,
        ExitLimitReached,
        ItemBudgetExceeded,
        ByteBudgetExceeded,
        Cancelled,
        TimedOut,
        Disconnected,
        ReceiveLoss,
        ReceiverClosed,
        AuthenticationFailed,
        Rejected,
        RelayClosed,
        Failed,
    }
    fn map(end: QualifiedEnd) -> NostrAcquisitionEnd {
        match end {
            QualifiedEnd::Completed => NostrAcquisitionEnd::RequestPolicySatisfied,
            QualifiedEnd::ExitLimitReached => NostrAcquisitionEnd::ExitCountReached,
            QualifiedEnd::ItemBudgetExceeded => NostrAcquisitionEnd::ItemLimitReached,
            QualifiedEnd::ByteBudgetExceeded => NostrAcquisitionEnd::ByteLimitReached,
            QualifiedEnd::Cancelled => NostrAcquisitionEnd::Cancelled,
            QualifiedEnd::TimedOut => NostrAcquisitionEnd::Deadline,
            QualifiedEnd::Disconnected => NostrAcquisitionEnd::Disconnected,
            QualifiedEnd::ReceiveLoss => NostrAcquisitionEnd::ReceiveLoss,
            QualifiedEnd::ReceiverClosed => NostrAcquisitionEnd::ReceiverClosed,
            QualifiedEnd::AuthenticationFailed => NostrAcquisitionEnd::AuthenticationFailed,
            QualifiedEnd::Rejected => NostrAcquisitionEnd::Rejected,
            QualifiedEnd::RelayClosed => NostrAcquisitionEnd::RelayClosed,
            QualifiedEnd::Failed => NostrAcquisitionEnd::BackendFailed,
        }
    }
    assert_eq!(
        map(QualifiedEnd::Completed),
        NostrAcquisitionEnd::RequestPolicySatisfied
    );
}
