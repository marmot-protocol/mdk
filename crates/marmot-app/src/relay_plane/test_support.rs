//! Shared publish-accounting fixture: an activated account adapter over a
//! scripted relay client. The plane's publish-accounting tests and the app's
//! relay-telemetry export tests both use it; once the plane is its own crate
//! it sits behind that crate's `test-support` feature (relay-plane brief, PR 3).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::transport::TransportMessage;
use cgka_traits::{
    GroupId, MemberId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportEndpoint, TransportGroupSubscription, TransportPublishReport, TransportPublishRequest,
    TransportPublishTarget,
};
use tokio::sync::oneshot;
use transport_nostr_adapter::{NostrPublishOutcome, NostrRelayClient};
use transport_nostr_peeler::{KIND_MARMOT_GROUP_MESSAGE, NostrTransportEvent};

use super::*;

/// Matches `transport_nostr_adapter`'s private delivery channel capacity.
pub(crate) const SHARED_DELIVERY_BUFFER: usize = 1024;

pub(crate) enum PublishScript {
    Accept,
    Empty,
    Error,
    Outcome(NostrPublishOutcome),
    Wait,
}

pub(crate) struct CountingClient {
    pub calls: AtomicUsize,
    pub(crate) accounts: StdMutex<Vec<MemberId>>,
    script: StdMutex<PublishScript>,
    entered: StdMutex<Option<oneshot::Sender<()>>>,
    release: StdMutex<Option<oneshot::Receiver<()>>>,
}

impl CountingClient {
    pub(crate) fn new(script: PublishScript) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            accounts: StdMutex::new(Vec::new()),
            script: StdMutex::new(script),
            entered: StdMutex::new(None),
            release: StdMutex::new(None),
        })
    }

    pub(crate) fn set_script(&self, script: PublishScript) {
        *self.script.lock().expect("script lock") = script;
    }

    pub(crate) fn arm_wait(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        *self.entered.lock().expect("entered lock") = Some(entered_tx);
        *self.release.lock().expect("release lock") = Some(release_rx);
        self.set_script(PublishScript::Wait);
        (entered_rx, release_tx)
    }
}

#[async_trait]
impl NostrRelayClient for CountingClient {
    async fn subscribe(
        &self,
        _subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe(
        &self,
        _subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn publish_event_for_account(
        &self,
        account_id: &MemberId,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        self.accounts
            .lock()
            .expect("accounts lock")
            .push(account_id.clone());
        self.publish_event(endpoints, event, required_acks).await
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let entered = self.entered.lock().expect("entered lock").take();
        let release = self.release.lock().expect("release lock").take();
        if let Some(tx) = entered {
            let _ = tx.send(());
        }
        if let Some(rx) = release {
            let _ = rx.await;
        }
        let script = self.script.lock().expect("script lock");
        match &*script {
            PublishScript::Accept => Ok(NostrPublishOutcome::accepted(endpoints.to_vec())),
            PublishScript::Empty => Ok(NostrPublishOutcome::default()),
            PublishScript::Error => Err(TransportAdapterError::Publish("scripted".to_owned())),
            PublishScript::Outcome(outcome) => Ok(outcome.clone()),
            PublishScript::Wait => Ok(NostrPublishOutcome::accepted(endpoints.to_vec())),
        }
    }
}

pub(crate) fn group_event(content: &str, transport_group_id: &[u8]) -> NostrTransportEvent {
    let mut event = NostrTransportEvent {
        id: String::new(),
        pubkey: "33".repeat(32),
        created_at: 1_700_000_020,
        kind: KIND_MARMOT_GROUP_MESSAGE,
        tags: vec![vec!["h".into(), hex::encode(transport_group_id)]],
        content: content.to_owned(),
        sig: None,
    };
    event.id = event.computed_id();
    event
}

pub(crate) struct AccountPublishFixture {
    pub plane: MarmotRelayPlane,
    pub adapter: MarmotRelayPlaneAccountAdapter,
    pub client: Arc<CountingClient>,
    pub account_id: MemberId,
    pub transport_group_id: Vec<u8>,
    pub endpoint: TransportEndpoint,
    pub message: TransportMessage,
}

impl AccountPublishFixture {
    pub(crate) async fn activate() -> Self {
        let client = CountingClient::new(PublishScript::Accept);
        let plane = MarmotRelayPlane::new(Some(Duration::from_secs(30)), client.clone());
        let account_id = MemberId::new(vec![0xA1; 32]);
        let transport_group_id = vec![0xD4; 32];
        let endpoint = TransportEndpoint("wss://relay.example".into());
        let adapter = plane.account_adapter(account_id.clone(), client.clone());
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account_id.clone(),
                inbox_endpoints: vec![endpoint.clone()],
                group_subscriptions: vec![TransportGroupSubscription {
                    group_id: GroupId::new(vec![0xC3; 32]),
                    transport_group_id: transport_group_id.clone(),
                    endpoints: vec![endpoint.clone()],
                    retained_since: None,
                }],
                since: None,
            })
            .await
            .expect("account activation");
        let message = group_event("account-publish", &transport_group_id)
            .to_transport_message()
            .expect("event maps");
        Self {
            plane,
            adapter,
            client,
            account_id,
            transport_group_id,
            endpoint,
            message,
        }
    }

    pub(crate) fn request(&self, required_acks: usize) -> TransportPublishRequest {
        TransportPublishRequest {
            account_id: self.account_id.clone(),
            message: self.message.clone(),
            target: TransportPublishTarget::Group {
                group_id: GroupId::new(vec![0xC3; 32]),
                transport_group_id: self.transport_group_id.clone(),
                endpoints: vec![self.endpoint.clone()],
            },
            required_acks,
        }
    }

    pub(crate) async fn publish(
        &self,
        script: PublishScript,
        required_acks: usize,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        self.client.set_script(script);
        self.adapter.publish(self.request(required_acks)).await
    }

    /// Start one account publish, wait until it is inside the relay client,
    /// then drop it.
    pub(crate) async fn cancel_in_flight(&self) {
        let (entered, _release) = self.client.arm_wait();
        let adapter = self.adapter.clone();
        let request = self.request(1);
        let task = tokio::spawn(async move { adapter.publish(request).await });
        entered.await.expect("account client entered");
        task.abort();
        let _ = task.await;
    }
}
