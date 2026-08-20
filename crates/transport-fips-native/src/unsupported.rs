use async_trait::async_trait;
use tokio::sync::broadcast;
use transport_nostr_adapter::{
    FipsRelayApi, FipsRelayApiError, FipsRelayEndpoint, FipsRelayNotification,
    FipsRelaySubscription,
};
use transport_nostr_peeler::NostrTransportEvent;

use crate::NativeFipsRelayConfig;

/// Cross-platform placeholder for hosts where the FIPS native API is absent.
#[derive(Clone)]
pub struct NativeFipsRelayApi {
    notifications: broadcast::Sender<FipsRelayNotification>,
}

impl NativeFipsRelayApi {
    pub fn new(_config: NativeFipsRelayConfig) -> Self {
        Self {
            notifications: broadcast::channel(1).0,
        }
    }
}

#[async_trait]
impl FipsRelayApi for NativeFipsRelayApi {
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
