//! Interface-shape tests. Real SDK limits, cleanup and loss delivery need the
//! production backend conformance tests in #1358.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{MemberId, TransportAdapterError, TransportEndpoint};
use tokio::sync::watch;
use transport_nostr_adapter::{
    NostrAcquisitionCancellation, NostrAcquisitionEnd, NostrAcquisitionEndpoint,
    NostrAcquisitionError, NostrAcquisitionLimits, NostrAcquisitionRequest, NostrAcquisitionResult,
    NostrAcquisitionScope, NostrAcquisitionStats, NostrNotificationLoss,
    NostrNotificationLossScope, NostrPublishOutcome, NostrRelayClient, NostrSubscription,
    NostrTransportAdapter,
};
use transport_nostr_peeler::NostrTransportEvent;

fn request() -> NostrAcquisitionRequest {
    NostrAcquisitionRequest {
        account_id: MemberId::new(vec![7; 32]),
        scope: NostrAcquisitionScope::KnownEventIds(vec![[3; 32]]),
        endpoints: vec![
            TransportEndpoint("wss://first.example".into()),
            TransportEndpoint("wss://second.example".into()),
        ],
        limits: NostrAcquisitionLimits {
            max_endpoints: 2,
            max_requested_event_ids: 2,
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
    calls: AtomicUsize,
    loss: watch::Sender<Option<NostrNotificationLoss>>,
}

#[async_trait]
impl NostrRelayClient for FakeRelay {
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

    async fn acquire_history(
        &self,
        request: NostrAcquisitionRequest,
        _: NostrAcquisitionCancellation,
    ) -> Result<NostrAcquisitionResult, NostrAcquisitionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(NostrAcquisitionResult {
            endpoints: request
                .endpoints
                .into_iter()
                .enumerate()
                .map(|(index, endpoint)| NostrAcquisitionEndpoint {
                    endpoint,
                    session_generation: Some(12),
                    events: vec![event()],
                    end: if index == 0 {
                        NostrAcquisitionEnd::ByteLimitReached
                    } else {
                        NostrAcquisitionEnd::RelayClosed
                    },
                    stats: NostrAcquisitionStats::default(),
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

#[test]
fn request_validation_rejects_invalid_inputs() {
    let mut invalid = request();
    invalid.limits.max_received_items_per_endpoint = 0;
    assert_eq!(
        invalid.validate(),
        Err(NostrAcquisitionError::InvalidRequest)
    );
    let mut invalid = request();
    invalid.limits.max_requested_event_ids = 0;
    assert_eq!(
        invalid.validate(),
        Err(NostrAcquisitionError::InvalidRequest)
    );
    let mut invalid = request();
    invalid.scope = NostrAcquisitionScope::KnownEventIds(vec![[1; 32], [2; 32], [3; 32]]);
    assert_eq!(
        invalid.validate(),
        Err(NostrAcquisitionError::InvalidRequest)
    );
    let mut invalid = request();
    invalid.endpoints[1] = invalid.endpoints[0].clone();
    assert_eq!(
        invalid.validate(),
        Err(NostrAcquisitionError::InvalidRequest)
    );
    let mut invalid = request();
    invalid.scope = NostrAcquisitionScope::AccountInboxWindow {
        since: 10,
        until: 9,
    };
    assert_eq!(
        invalid.validate(),
        Err(NostrAcquisitionError::InvalidRequest)
    );
    invalid.scope = NostrAcquisitionScope::AccountInboxWindow {
        since: 9,
        until: 10,
    };
    invalid.limits.max_requested_event_ids = 0;
    assert_eq!(invalid.validate(), Ok(()));
    assert_eq!(request().validate(), Ok(()));
}

#[tokio::test]
async fn adapter_rejects_invalid_request_before_backend_and_preserves_owned_partial_results() {
    let (loss, _) = watch::channel(None);
    let fake = Arc::new(FakeRelay {
        calls: AtomicUsize::new(0),
        loss,
    });
    let adapter = NostrTransportAdapter::new(fake.clone());
    let mut invalid = request();
    invalid.limits.max_duration = Duration::ZERO;
    assert_eq!(
        adapter
            .acquire_history(invalid, NostrAcquisitionCancellation::new())
            .await
            .unwrap_err(),
        NostrAcquisitionError::InvalidRequest
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);

    // The caller retains its actual grant/fence/scope token next to this await;
    // the transport result remains owned and keeps each endpoint distinct.
    let result = adapter
        .acquire_history(request(), NostrAcquisitionCancellation::new())
        .await
        .unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.endpoints.len(), 2);
    assert_eq!(
        result.endpoints[0].end,
        NostrAcquisitionEnd::ByteLimitReached
    );
    assert_eq!(result.endpoints[1].end, NostrAcquisitionEnd::RelayClosed);
    assert_eq!(result.endpoints[0].events, vec![event()]);
    assert_eq!(result.endpoints[0].session_generation, Some(12));
}

#[tokio::test]
async fn loss_control_receiver_is_available_independently_of_acquisition() {
    let (loss, _) = watch::channel(None);
    let fake = Arc::new(FakeRelay {
        calls: AtomicUsize::new(0),
        loss,
    });
    let adapter = NostrTransportAdapter::new(fake.clone());
    let mut observed = adapter.notification_loss().unwrap();
    fake.loss.send_replace(Some(NostrNotificationLoss {
        scope: NostrNotificationLossScope::SharedReceiver,
        receiver_generation: 2,
        cumulative_skipped: 5,
    }));
    observed.changed().await.unwrap();
    assert_eq!(observed.borrow().as_ref().unwrap().cumulative_skipped, 5);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn legacy_client_reports_unsupported_without_network_work() {
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
    let adapter = NostrTransportAdapter::new(Arc::new(Legacy));
    assert_eq!(
        adapter
            .acquire_history(request(), NostrAcquisitionCancellation::new())
            .await
            .unwrap_err(),
        NostrAcquisitionError::Unsupported
    );
    assert!(matches!(
        adapter.notification_loss(),
        Err(NostrAcquisitionError::Unsupported)
    ));
}
