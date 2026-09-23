//! Test-only 0.45 relay implementation of MDK's existing adapter seam.
//! It covers inbox subscriptions and publication; recovery evidence is mapped
//! separately because the current seam has no acquisition or gap operation.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{
    MemberId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportEndpoint, TransportEndpointFailure, TransportEndpointFailureKind,
    TransportEndpointReceipt,
};
use futures_util::StreamExt;
use nostr_sdk::NotificationUpdate;
use nostr_sdk::authenticator::SignerAuthenticator;
use nostr_sdk::local_relay::{QueryPolicy, QueryPolicyResult};
use nostr_sdk::prelude::*;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use transport_nostr_adapter::{
    NostrPublishOutcome, NostrRelayClient, NostrSubscription, NostrTransportAdapter,
};
use transport_nostr_peeler::NostrTransportEvent;

const DEADLINE: Duration = Duration::from_secs(3);

fn loopback_url(endpoint: &TransportEndpoint) -> Option<RelayUrl> {
    let url = RelayUrl::parse(endpoint.as_str()).ok()?;
    matches!(url.host(), Some(Host::Ipv4(address)) if address.is_loopback()).then_some(url)
}

type AccountSubscriptions = Arc<Mutex<HashMap<MemberId, Vec<(RelayUrl, SubscriptionId)>>>>;

#[derive(Clone)]
struct CandidateRelay {
    accounts: Arc<HashMap<MemberId, Client>>,
    subscriptions: AccountSubscriptions,
    publisher: Client,
}

impl CandidateRelay {
    fn new(accounts: impl IntoIterator<Item = Keys>) -> Self {
        let accounts = accounts
            .into_iter()
            .map(|keys| {
                (
                    MemberId::new(keys.public_key().to_bytes().to_vec()),
                    Client::builder()
                        .authenticator(SignerAuthenticator::new(keys))
                        .build(),
                )
            })
            .collect();
        Self {
            accounts: Arc::new(accounts),
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            publisher: Client::default(),
        }
    }

    fn account(&self, id: &MemberId) -> &Client {
        &self.accounts[id]
    }

    fn plan(subscription: &NostrSubscription) -> (MemberId, Vec<TransportEndpoint>, Filter) {
        match subscription {
            NostrSubscription::AccountInbox {
                account_id,
                endpoints,
                since,
                ..
            } => {
                let pubkey = PublicKey::from_slice(account_id.as_slice()).unwrap();
                let mut filter = Filter::new().kind(Kind::GiftWrap).pubkey(pubkey);
                if let Some(since) = since {
                    filter = filter.since(Timestamp::from_secs(since.0));
                }
                (account_id.clone(), endpoints.clone(), filter)
            }
            NostrSubscription::Group {
                account_id,
                endpoints,
                transport_group_id,
                since,
                ..
            } => {
                let mut filter = Filter::new().kind(Kind::MlsGroupMessage).custom_tags(
                    SingleLetterTag::from_char('h').unwrap(),
                    [hex::encode(transport_group_id)],
                );
                if let Some(since) = since {
                    filter = filter.since(Timestamp::from_secs(since.0));
                }
                (account_id.clone(), endpoints.clone(), filter)
            }
            NostrSubscription::GroupMaintenance {
                account_id,
                endpoints,
                transport_group_id,
                ..
            } => (
                account_id.clone(),
                endpoints.clone(),
                Filter::new().kind(Kind::MlsGroupMessage).custom_tags(
                    SingleLetterTag::from_char('h').unwrap(),
                    [hex::encode(transport_group_id)],
                ),
            ),
        }
    }

    async fn stop_subscription(&self, account: &MemberId, id: &SubscriptionId) {
        if let Some(client) = self.accounts.get(account) {
            let mut subscriptions = self.subscriptions.lock().await;
            if let Some(active) = subscriptions.get_mut(account) {
                for (url, saved_id) in active.iter().filter(|(_, saved_id)| saved_id == id) {
                    if let Ok(Some(relay)) = client.relay(url).await {
                        let _ = relay.unsubscribe(saved_id).await;
                    }
                }
                active.retain(|(_, saved_id)| saved_id != id);
            }
        }
    }
}

#[async_trait]
impl NostrRelayClient for CandidateRelay {
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        let id = subscription.subscription_id();
        self.subscribe_scoped(subscription, id).await
    }

    fn supports_scoped_subscriptions(&self) -> bool {
        true
    }

    async fn subscribe_scoped(
        &self,
        subscription: NostrSubscription,
        subscription_id: String,
    ) -> Result<(), TransportAdapterError> {
        let (account_id, endpoints, filter) = Self::plan(&subscription);
        if endpoints.is_empty() || endpoints.len() > 2 {
            return Err(TransportAdapterError::Subscription(
                "probe endpoint limit".to_owned(),
            ));
        }
        let client = self
            .accounts
            .get(&account_id)
            .ok_or_else(|| TransportAdapterError::Subscription("unknown account".to_owned()))?;
        for endpoint in endpoints {
            let url = loopback_url(&endpoint).ok_or_else(|| {
                TransportAdapterError::Subscription("non-loopback probe endpoint".to_owned())
            })?;
            client
                .add_relay(&url)
                .await
                .map_err(|_| TransportAdapterError::Subscription("add relay failed".to_owned()))?;
            client
                .try_connect_relay(&url, DEADLINE)
                .await
                .map_err(|_| TransportAdapterError::Subscription("connect failed".to_owned()))?;
            let relay = client.relay(&url).await.unwrap().unwrap();
            let id = SubscriptionId::new(subscription_id.clone());
            relay
                .subscribe(filter.clone())
                .with_id(id.clone())
                .await
                .map_err(|_| TransportAdapterError::Subscription("subscribe failed".to_owned()))?;
            self.subscriptions
                .lock()
                .await
                .entry(account_id.clone())
                .or_default()
                .push((url, id));
        }
        Ok(())
    }

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        let id = subscription.subscription_id();
        self.unsubscribe_scoped(subscription, id).await
    }

    async fn unsubscribe_scoped(
        &self,
        subscription: NostrSubscription,
        subscription_id: String,
    ) -> Result<(), TransportAdapterError> {
        let (account_id, _, _) = Self::plan(&subscription);
        self.stop_subscription(&account_id, &SubscriptionId::new(subscription_id))
            .await;
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        let saved = self
            .subscriptions
            .lock()
            .await
            .remove(account_id)
            .unwrap_or_default();
        if let Some(client) = self.accounts.get(account_id) {
            for (url, id) in saved {
                if let Ok(Some(relay)) = client.relay(&url).await {
                    let _ = relay.unsubscribe(&id).await;
                }
            }
        }
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        if endpoints.len() != 1 || required_acks != 1 {
            return Err(TransportAdapterError::Publish(
                "probe supports one endpoint and one acknowledgement".to_owned(),
            ));
        }
        let event: Event = serde_json::from_value(serde_json::to_value(event).unwrap())
            .map_err(|_| TransportAdapterError::Publish("invalid signed event".to_owned()))?;
        event
            .verify()
            .map_err(|_| TransportAdapterError::Publish("invalid signed event".to_owned()))?;
        let mut outcome = NostrPublishOutcome::default();
        for endpoint in endpoints {
            let url = loopback_url(endpoint).ok_or_else(|| {
                TransportAdapterError::Publish("non-loopback probe endpoint".to_owned())
            })?;
            if self
                .publisher
                .add_relay(&url)
                .capabilities(RelayCapabilities::WRITE)
                .await
                .is_err()
            {
                outcome.failed.push(TransportEndpointFailure {
                    endpoint: endpoint.clone(),
                    reason: "add relay failed".to_owned(),
                    kind: TransportEndpointFailureKind::RetryableUnavailable,
                    rejection_category: None,
                });
                continue;
            }
            if self
                .publisher
                .try_connect_relay(&url, DEADLINE)
                .await
                .is_err()
            {
                outcome.failed.push(TransportEndpointFailure {
                    endpoint: endpoint.clone(),
                    reason: "connect failed".to_owned(),
                    kind: TransportEndpointFailureKind::RetryableUnavailable,
                    rejection_category: None,
                });
                continue;
            }
            let relay = self.publisher.relay(&url).await.unwrap().unwrap();
            match relay
                .send_event(&event)
                .ok_timeout(Duration::from_millis(150))
                .await
            {
                Ok(output) if matches!(output.status(), EventSendStatus::Ack(_)) => {
                    outcome.accepted.push(TransportEndpointReceipt {
                        endpoint: endpoint.clone(),
                        accepted_at: None,
                    });
                }
                Ok(_) => outcome.failed.push(TransportEndpointFailure {
                    endpoint: endpoint.clone(),
                    reason: "acknowledgement unknown".to_owned(),
                    kind: TransportEndpointFailureKind::PossiblyExposed,
                    rejection_category: None,
                }),
                Err(error) => outcome.failed.push(TransportEndpointFailure {
                    endpoint: endpoint.clone(),
                    reason: if error.kind() == ErrorKind::Rejected {
                        "relay rejected"
                    } else {
                        "acknowledgement unknown"
                    }
                    .to_owned(),
                    kind: if error.kind() == ErrorKind::Rejected {
                        TransportEndpointFailureKind::TerminalRejected
                    } else {
                        TransportEndpointFailureKind::PossiblyExposed
                    },
                    rejection_category: None,
                }),
            }
        }
        Ok(outcome)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adapter_boundary_keeps_account_sessions_distinct() {
    let relay = LocalRelay::builder().auth_dm(true).build();
    relay.run().await.unwrap();
    let url = relay.url().await;
    let alice = Keys::generate();
    let bob = Keys::generate();
    let sender = Keys::generate();
    for keys in [&alice, &bob] {
        relay
            .add_event(
                EventBuilder::new(Kind::GiftWrap, "synthetic inbox")
                    .tag(Tag::public_key(keys.public_key()))
                    .finalize(&sender)
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let a_id = MemberId::new(alice.public_key().to_bytes().to_vec());
    let b_id = MemberId::new(bob.public_key().to_bytes().to_vec());
    let candidate = Arc::new(CandidateRelay::new([alice.clone(), bob.clone()]));
    let adapter = NostrTransportAdapter::new(candidate.clone());
    for id in [&a_id, &b_id] {
        adapter
            .activate_account(TransportAccountActivation {
                account_id: id.clone(),
                inbox_endpoints: vec![TransportEndpoint(url.to_string())],
                group_subscriptions: Vec::new(),
                since: None,
            })
            .await
            .unwrap();
    }
    assert_eq!(
        candidate
            .account(&a_id)
            .fetch_events(
                Filter::new()
                    .kind(Kind::GiftWrap)
                    .pubkey(alice.public_key())
            )
            .timeout(DEADLINE)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        candidate
            .account(&b_id)
            .fetch_events(Filter::new().kind(Kind::GiftWrap).pubkey(bob.public_key()))
            .timeout(DEADLINE)
            .await
            .unwrap()
            .len(),
        1
    );

    // Retire Alice's connection generation and reissue her adapter activation.
    // Bob's subscribed connection stays in place throughout the handoff.
    let a_client = candidate.account(&a_id);
    let a_relay = a_client.relay(&url).await.unwrap().unwrap();
    let mut lifecycle = a_relay.notifications();
    a_client.disconnect_relay(&url).await.unwrap();
    tokio::time::timeout(DEADLINE, async {
        while let Some(notification) = lifecycle.next().await {
            if matches!(
                notification,
                RelayNotification::RelayStatus {
                    status: RelayStatus::Terminated
                }
            ) {
                break;
            }
        }
    })
    .await
    .unwrap();
    a_client.remove_relay(&url).force().await.unwrap();
    adapter
        .activate_account(TransportAccountActivation {
            account_id: a_id.clone(),
            inbox_endpoints: vec![TransportEndpoint(url.to_string())],
            group_subscriptions: Vec::new(),
            since: None,
        })
        .await
        .unwrap();
    let a_live_id = candidate.subscriptions.lock().await[&a_id][0].1.clone();
    let b_live_id = candidate.subscriptions.lock().await[&b_id][0].1.clone();
    let mut a_notifications = a_client.notifications_with_gaps();
    let mut b_notifications = candidate.account(&b_id).notifications_with_gaps();
    let after_reconnect_a = EventBuilder::new(Kind::GiftWrap, "after Alice reconnect")
        .tag(Tag::public_key(alice.public_key()))
        .finalize(&sender)
        .unwrap();
    let after_reconnect_b = EventBuilder::new(Kind::GiftWrap, "while Alice reconnects")
        .tag(Tag::public_key(bob.public_key()))
        .finalize(&sender)
        .unwrap();
    relay.add_event(after_reconnect_a.clone()).await.unwrap();
    relay.add_event(after_reconnect_b.clone()).await.unwrap();
    for (stream, expected_id, expected_event) in [
        (&mut a_notifications, &a_live_id, after_reconnect_a.id),
        (&mut b_notifications, &b_live_id, after_reconnect_b.id),
    ] {
        tokio::time::timeout(DEADLINE, async {
            loop {
                if let Some(NotificationUpdate::Notification(ClientNotification::Event {
                    subscription_id,
                    event,
                    ..
                })) = stream.next().await
                    && &subscription_id == expected_id
                    && event.id == expected_event
                {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }

    let history = a_client
        .acquire_events(
            ReqTarget::single(&url, [Filter::new().kind(Kind::TextNote)]),
            AcquisitionLimits::new(1, 16, 64 * 1024, DEADLINE)
                .policy(ReqExitPolicy::WaitDurationAfterEOSE(Duration::from_secs(2))),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    history.cancel();
    let history = tokio::time::timeout(DEADLINE, history.finish())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        history.relays[&url].end,
        AcquisitionEnd::Cancelled
    ));
    let after_cancel = EventBuilder::new(Kind::GiftWrap, "live after history cancellation")
        .tag(Tag::public_key(alice.public_key()))
        .finalize(&sender)
        .unwrap();
    relay.add_event(after_cancel.clone()).await.unwrap();
    tokio::time::timeout(DEADLINE, async {
        loop {
            if let Some(NotificationUpdate::Notification(ClientNotification::Event {
                subscription_id,
                event,
                ..
            })) = a_notifications.next().await
                && subscription_id == a_live_id
                && event.id == after_cancel.id
            {
                break;
            }
        }
    })
    .await
    .unwrap();

    adapter.deactivate_account(&a_id).await.unwrap();
    candidate.account(&a_id).shutdown().await;
    assert_eq!(
        candidate
            .account(&b_id)
            .fetch_events(Filter::new().kind(Kind::GiftWrap).pubkey(bob.public_key()))
            .timeout(DEADLINE)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(!candidate.subscriptions.lock().await.contains_key(&a_id));
    assert!(candidate.subscriptions.lock().await.contains_key(&b_id));
    candidate.account(&b_id).shutdown().await;
}

#[derive(Clone, Debug)]
struct QueryCount(Arc<AtomicUsize>);

impl QueryPolicy for QueryCount {
    fn admit_query<'a>(
        &'a self,
        _query: &'a mut Filter,
        _addr: &'a SocketAddr,
    ) -> Pin<Box<dyn Future<Output = QueryPolicyResult> + Send + 'a>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { QueryPolicyResult::Accept })
    }
}

fn transport_event(event: &Event) -> NostrTransportEvent {
    serde_json::from_str(&event.as_json()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_shot_publication_maps_accept_reject_and_unknown_without_read_filters() {
    let query_count = Arc::new(AtomicUsize::new(0));
    let accepted_relay = LocalRelay::builder()
        .query_policy(QueryCount(query_count.clone()))
        .build();
    accepted_relay.run().await.unwrap();
    let accepted_url = accepted_relay.url().await;
    let rejected_relay = LocalRelay::builder()
        .query_policy(QueryCount(query_count.clone()))
        .blacklist_kinds(&[Kind::TextNote])
        .build();
    rejected_relay.run().await.unwrap();
    let rejected_url = rejected_relay.url().await;
    let event = EventBuilder::new(Kind::TextNote, "one-shot publish")
        .finalize(&Keys::generate())
        .unwrap();
    let candidate = CandidateRelay::new([]);
    let accepted = candidate
        .publish_event(
            &[TransportEndpoint(accepted_url.to_string())],
            &transport_event(&event),
            1,
        )
        .await
        .unwrap();
    assert_eq!(accepted.accepted.len(), 1);
    assert!(accepted.failed.is_empty());
    let rejected = candidate
        .publish_event(
            &[TransportEndpoint(rejected_url.to_string())],
            &transport_event(&event),
            1,
        )
        .await
        .unwrap();
    assert!(rejected.accepted.is_empty());
    assert_eq!(rejected.failed.len(), 1);
    assert_eq!(
        rejected.failed[0].kind,
        TransportEndpointFailureKind::TerminalRejected
    );
    assert_eq!(
        query_count.load(Ordering::SeqCst),
        0,
        "publish-only connections issued a read filter"
    );

    let unavailable_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_url = RelayUrl::parse(&format!(
        "ws://{}",
        unavailable_listener.local_addr().unwrap()
    ))
    .unwrap();
    let unavailable = candidate
        .publish_event(
            &[TransportEndpoint(unavailable_url.to_string())],
            &transport_event(&event),
            1,
        )
        .await
        .unwrap();
    drop(unavailable_listener);
    assert!(unavailable.accepted.is_empty());
    assert_eq!(unavailable.failed.len(), 1);
    assert_eq!(
        unavailable.failed[0].kind,
        TransportEndpointFailureKind::RetryableUnavailable
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_url = RelayUrl::parse(&format!("ws://{}", listener.local_addr().unwrap())).unwrap();
    let (seen_tx, seen_rx) = oneshot::channel();
    let silent = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(frame)) = socket.next().await {
            if frame.is_text() && frame.to_text().unwrap().starts_with("[\"EVENT\"") {
                let _ = seen_tx.send(());
                tokio::time::sleep(Duration::from_millis(500)).await;
                return;
            }
        }
    });
    let unknown = candidate
        .publish_event(
            &[TransportEndpoint(silent_url.to_string())],
            &transport_event(&event),
            1,
        )
        .await
        .unwrap();
    tokio::time::timeout(DEADLINE, seen_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(unknown.accepted.is_empty());
    assert_eq!(unknown.failed.len(), 1);
    assert_eq!(
        unknown.failed[0].kind,
        TransportEndpointFailureKind::PossiblyExposed
    );
    silent.await.unwrap();
    candidate.publisher.shutdown().await;
}
