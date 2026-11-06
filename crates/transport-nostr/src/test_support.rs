//! Shared publish-accounting fixture: an activated account adapter over a
//! scripted relay client. The plane's publish-accounting tests and the app's
//! relay-telemetry export tests both use it; once the plane is its own crate
//! it sits behind that crate's `test-support` feature (relay-plane brief, PR 3).
//! [`ScriptedRelayMessages`] carries an injected test client's relay messages
//! to its plane.

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
pub const SHARED_DELIVERY_BUFFER: usize = 1024;

pub enum PublishScript {
    Accept,
    Empty,
    Error,
    Outcome(NostrPublishOutcome),
    Wait,
}

pub struct CountingClient {
    pub calls: AtomicUsize,
    pub accounts: StdMutex<Vec<MemberId>>,
    /// What its relays send: an EOSE for each accepted REQ on each relay.
    pub messages: Arc<ScriptedRelayMessages>,
    script: StdMutex<PublishScript>,
    entered: StdMutex<Option<oneshot::Sender<()>>>,
    release: StdMutex<Option<oneshot::Receiver<()>>>,
}

impl CountingClient {
    pub fn new(script: PublishScript) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            accounts: StdMutex::new(Vec::new()),
            messages: Arc::default(),
            script: StdMutex::new(script),
            entered: StdMutex::new(None),
            release: StdMutex::new(None),
        })
    }

    pub fn set_script(&self, script: PublishScript) {
        *self.script.lock().expect("script lock") = script;
    }

    pub fn arm_wait(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
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
    fn relay_notification_source(&self) -> Option<Arc<dyn NostrRelayNotificationSource>> {
        Some(self.messages.clone())
    }

    async fn reply_sent_nothing(
        &self,
        _account: Option<&MemberId>,
        _endpoint: &TransportEndpoint,
        subscription_id: &str,
    ) -> bool {
        self.messages.reply_sent_nothing(subscription_id)
    }

    async fn subscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        let id = subscription.subscription_id();
        for endpoint in subscription.endpoints() {
            self.messages.eose(endpoint, &id);
        }
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
        _replacements: &[transport_nostr_adapter::NostrSubscription],
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

pub fn group_event(content: &str, transport_group_id: &[u8]) -> NostrTransportEvent {
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

pub struct AccountPublishFixture {
    pub plane: MarmotRelayPlane,
    pub adapter: MarmotRelayPlaneAccountAdapter,
    pub client: Arc<CountingClient>,
    pub account_id: MemberId,
    pub transport_group_id: Vec<u8>,
    pub endpoint: TransportEndpoint,
    pub message: TransportMessage,
}

impl AccountPublishFixture {
    pub async fn activate() -> Self {
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

    pub fn request(&self, required_acks: usize) -> TransportPublishRequest {
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

    pub async fn publish(
        &self,
        script: PublishScript,
        required_acks: usize,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        self.client.set_script(script);
        self.adapter.publish(self.request(required_acks)).await
    }

    /// Start one account publish, wait until it is inside the relay client,
    /// then drop it.
    pub async fn cancel_in_flight(&self) {
        let (entered, _release) = self.client.arm_wait();
        let adapter = self.adapter.clone();
        let request = self.request(1);
        let task = tokio::spawn(async move { adapter.publish(request).await });
        entered.await.expect("account client entered");
        task.abort();
        let _ = task.await;
    }
}

/// A scripted relay pool's own messages, which an injected test client hands
/// its plane through [`NostrRelayClient::relay_notification_source`], so they
/// reach the adapter through the dispatch the SDK pool's take. Each relay has
/// one connection, which opens before the first REQ the client sends it
/// ([`Self::connect`]); as the SDK's frontier does, every receiver hears that
/// connection's boundary before any of its messages. Every receiver gets every
/// message sent after it subscribed, in order, and none is ever dropped: a
/// scripted pool never shows its plane a lag.
///
/// One pool shared by several planes reaches all of them, as an SDK pool
/// would; each adapter heeds only the REQ ids it has live.
///
/// A client using it delegates [`NostrRelayClient::reply_sent_nothing`] to
/// [`Self::reply_sent_nothing`], which [`Self::handled`] needs.
#[derive(Default)]
pub struct ScriptedRelayMessages {
    pool: StdMutex<ScriptedPool>,
    flushes: AtomicUsize,
    /// The flush EOSEs a plane has dispatched.
    flushed: StdMutex<HashSet<String>>,
}

#[derive(Default)]
struct ScriptedPool {
    receivers: Vec<mpsc::UnboundedSender<NotificationUpdate<NostrSdkNotification>>>,
    /// The relays connected so far, in the order they connected.
    connected: Vec<TransportEndpoint>,
}

impl ScriptedPool {
    /// Send `update` to every receiver still reading.
    fn broadcast(&mut self, update: NotificationUpdate<NostrSdkNotification>) {
        self.receivers
            .retain(|receiver| receiver.send(update.clone()).is_ok());
    }

    fn connect(&mut self, endpoint: &TransportEndpoint) {
        if !self.connected.contains(endpoint) {
            self.connected.push(endpoint.clone());
            self.broadcast(ScriptedRelayMessages::boundary(endpoint));
        }
    }
}

/// The wire id of a flush's EOSE, which no REQ carries.
const FLUSH_ID_PREFIX: &str = "scripted-relay-flush-";

impl ScriptedRelayMessages {
    /// The pool's one reader, and each relay's one connection.
    const EPOCH: [u64; 2] = [1, 1];

    /// The relay at `endpoint` is connected: every plane hears its connection
    /// open, ahead of the REQs the client is about to send it. A relay
    /// connects once; later calls change nothing.
    pub fn connect(&self, endpoint: &TransportEndpoint) {
        self.pool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .connect(endpoint);
    }

    /// `endpoint` ended its stored events for the REQ `subscription_id`.
    pub fn eose(&self, endpoint: &TransportEndpoint, subscription_id: &str) {
        self.send(endpoint, Self::eose_message(subscription_id));
    }

    /// `endpoint` closed the REQ `subscription_id`, giving `reason`.
    pub fn closed(&self, endpoint: &TransportEndpoint, subscription_id: &str, reason: &str) {
        self.send(
            endpoint,
            RelayMessage::Closed {
                subscription_id: std::borrow::Cow::Owned(SubscriptionId::new(subscription_id)),
                message: std::borrow::Cow::Owned(reason.to_owned()),
            },
        );
    }

    /// `endpoint` sent `event` for the REQ `subscription_id`: the pool's raw
    /// copy off the wire, which counts in the REQ's reply. A group message
    /// goes on to admission; anything else is counted and not delivered, as
    /// an event the pool had already seen.
    pub fn event(
        &self,
        endpoint: &TransportEndpoint,
        subscription_id: &str,
        event: nostr_sdk::prelude::Event,
    ) {
        self.send(
            endpoint,
            RelayMessage::Event {
                subscription_id: std::borrow::Cow::Owned(SubscriptionId::new(subscription_id)),
                event: std::borrow::Cow::Owned(event),
            },
        );
    }

    /// Wait until every plane reading this pool has handled every message
    /// sent before the call, as a test that once called the adapter itself
    /// had. Each receiver gets one more EOSE, for an id no REQ carries, on a
    /// relay it has heard from; the dispatcher asks
    /// [`NostrRelayClient::reply_sent_nothing`] about each EOSE in order, so
    /// once a plane asks about that one, everything before it is handled.
    pub async fn handled(&self) {
        let pending = {
            let pool = self
                .pool
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match pool.connected.first() {
                // No relay has connected, so no plane has anything to handle.
                None => Vec::new(),
                Some(endpoint) => pool
                    .receivers
                    .iter()
                    .filter_map(|receiver| {
                        let flush = self.flushes.fetch_add(1, Ordering::SeqCst);
                        let id = format!("{FLUSH_ID_PREFIX}{flush}");
                        let sent = receiver
                            .send(Self::notification(endpoint, Self::eose_message(&id)))
                            .is_ok();
                        sent.then(|| (id, receiver.clone()))
                    })
                    .collect::<Vec<_>>(),
            }
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            for spin in 0usize.. {
                let flushed = self
                    .flushed
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                // A plane that shut down meanwhile handles nothing more.
                if pending
                    .iter()
                    .all(|(id, sender)| flushed.contains(id) || sender.is_closed())
                {
                    return;
                }
                drop(flushed);
                // Yield first: a paused clock must not move while the plane
                // catches up.
                if spin < 10_000 {
                    tokio::task::yield_now().await;
                } else {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        })
        .await
        .expect("every plane handles the scripted relay messages");
    }

    /// The answer a scripted relay gives: it does not read its own wire, so
    /// it never vouches that a relay sent nothing. Notes a flush's EOSE.
    pub fn reply_sent_nothing(&self, subscription_id: &str) -> bool {
        if subscription_id.starts_with(FLUSH_ID_PREFIX) {
            self.flushed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(subscription_id.to_owned());
        }
        false
    }

    fn eose_message(subscription_id: &str) -> RelayMessage<'static> {
        RelayMessage::EndOfStoredEvents(std::borrow::Cow::Owned(SubscriptionId::new(
            subscription_id,
        )))
    }

    fn notification(
        endpoint: &TransportEndpoint,
        message: RelayMessage<'static>,
    ) -> NotificationUpdate<NostrSdkNotification> {
        let relay_url = RelayUrl::parse(endpoint.as_str())
            .expect("a scripted relay answers only on an endpoint the plane accepted");
        NotificationUpdate::Notification(NostrSdkNotification::Payload {
            notification: ClientNotification::Message {
                relay_url,
                message: Box::new(message),
            },
            epoch: Self::EPOCH,
            reason: transport_nostr_adapter::ReplayRestart::Connection,
        })
    }

    fn boundary(endpoint: &TransportEndpoint) -> NotificationUpdate<NostrSdkNotification> {
        NotificationUpdate::Notification(NostrSdkNotification::Replay {
            endpoint: endpoint.clone(),
            epoch: Self::EPOCH,
            reason: transport_nostr_adapter::ReplayRestart::Connection,
            connected_at: None,
        })
    }

    fn send(&self, endpoint: &TransportEndpoint, message: RelayMessage<'static>) {
        let mut pool = self
            .pool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A relay that answers is connected.
        pool.connect(endpoint);
        pool.broadcast(Self::notification(endpoint, message));
    }
}

impl NostrRelayNotificationSource for ScriptedRelayMessages {
    fn notifications(&self) -> transport_nostr_adapter::NostrSdkNotificationStream {
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut pool = self
            .pool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A new reader hears each open connection's boundary first.
        for endpoint in &pool.connected {
            let _ = sender.send(Self::boundary(endpoint));
        }
        pool.receivers.push(sender);
        Box::pin(futures::stream::unfold(
            receiver,
            |mut receiver| async move { receiver.recv().await.map(|update| (update, receiver)) },
        ))
    }
}
