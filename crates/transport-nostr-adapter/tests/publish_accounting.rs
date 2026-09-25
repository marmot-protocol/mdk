//! Direct-adapter publish accounting: admission, classification, cancellation.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::{
    GroupId, MemberId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportEndpoint, TransportGroupSubscription, TransportPublishRequest, TransportPublishTarget,
};
use tokio::sync::oneshot;
use transport_nostr_adapter::{NostrPublishOutcome, NostrRelayClient, NostrTransportAdapter};
use transport_nostr_peeler::{KIND_MARMOT_GROUP_MESSAGE, NOSTR_SOURCE, NostrTransportEvent};

#[derive(Clone, Copy)]
enum Mode {
    Accept,
    Empty,
    Error,
    Wait,
}

struct CountingClient {
    calls: AtomicUsize,
    accounts: Mutex<Vec<MemberId>>,
    mode: Mutex<Mode>,
    entered: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
}

impl CountingClient {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            accounts: Mutex::new(Vec::new()),
            mode: Mutex::new(mode),
            entered: Mutex::new(None),
            release: Mutex::new(None),
        })
    }

    fn arm_wait(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        *self.entered.lock().expect("entered lock") = Some(entered_tx);
        *self.release.lock().expect("release lock") = Some(release_rx);
        *self.mode.lock().expect("mode lock") = Mode::Wait;
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
        match *self.mode.lock().expect("mode lock") {
            Mode::Accept => Ok(NostrPublishOutcome::accepted(endpoints.to_vec())),
            Mode::Empty => Ok(NostrPublishOutcome::default()),
            Mode::Error => Err(TransportAdapterError::Publish("scripted".to_owned())),
            Mode::Wait => Ok(NostrPublishOutcome::accepted(endpoints.to_vec())),
        }
    }
}

fn group_event(content: &str, transport_group_id: &[u8]) -> NostrTransportEvent {
    let mut event = NostrTransportEvent {
        id: String::new(),
        pubkey: "22".repeat(32),
        created_at: 1_700_000_010,
        kind: KIND_MARMOT_GROUP_MESSAGE,
        tags: vec![vec!["h".into(), hex::encode(transport_group_id)]],
        content: content.to_owned(),
        sig: None,
    };
    event.id = event.computed_id();
    event
}

fn request(
    account_id: MemberId,
    message: TransportMessage,
    transport_group_id: Vec<u8>,
    endpoint: TransportEndpoint,
    required_acks: usize,
) -> TransportPublishRequest {
    TransportPublishRequest {
        account_id,
        message,
        target: TransportPublishTarget::Group {
            group_id: GroupId::new(vec![0xB2; 16]),
            transport_group_id,
            endpoints: vec![endpoint],
        },
        required_acks,
    }
}

async fn activated(
    client: Arc<CountingClient>,
) -> (NostrTransportAdapter, MemberId, Vec<u8>, TransportEndpoint) {
    let adapter = NostrTransportAdapter::new(client);
    let account_id = MemberId::new(vec![0xA1; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: GroupId::new(vec![0xB2; 16]),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");
    (adapter, account_id, transport_group_id, endpoint)
}

/// `(attempts, successes, failures, cancellations)`.
async fn counts(adapter: &NostrTransportAdapter) -> (usize, usize, usize, usize) {
    let metrics = adapter.metrics().await;
    (
        metrics.publish_attempts,
        metrics.publish_successes,
        metrics.publish_failures,
        metrics.publish_cancellations,
    )
}

#[tokio::test]
async fn direct_publish_classifies_success_threshold_and_errors() {
    let client = CountingClient::new(Mode::Accept);
    let (adapter, account_id, transport_group_id, endpoint) = activated(client.clone()).await;
    let message = group_event("accepted", &transport_group_id)
        .to_transport_message()
        .expect("event maps");
    let report = adapter
        .publish(request(
            account_id.clone(),
            message.clone(),
            transport_group_id.clone(),
            endpoint.clone(),
            1,
        ))
        .await
        .expect("accepted publish");
    assert!(report.met_required_acks());
    assert_eq!(counts(&adapter).await, (1, 1, 0, 0));

    *client.mode.lock().expect("mode") = Mode::Empty;
    let empty = adapter
        .publish(request(
            account_id.clone(),
            message.clone(),
            transport_group_id.clone(),
            endpoint.clone(),
            0,
        ))
        .await
        .expect("empty outcome still returns Ok");
    assert!(!empty.met_required_acks());
    assert_eq!(counts(&adapter).await, (2, 1, 1, 0));

    *client.mode.lock().expect("mode") = Mode::Accept;
    let below = adapter
        .publish(request(
            account_id.clone(),
            message.clone(),
            transport_group_id.clone(),
            endpoint.clone(),
            2,
        ))
        .await
        .expect("one acceptance is still Ok");
    assert_eq!(below.accepted.len(), 1);
    assert!(!below.met_required_acks());
    assert_eq!(counts(&adapter).await, (3, 1, 2, 0));

    *client.mode.lock().expect("mode") = Mode::Error;
    let error = adapter
        .publish(request(
            account_id.clone(),
            message,
            transport_group_id,
            endpoint,
            1,
        ))
        .await
        .expect_err("client error is preserved");
    assert!(matches!(error, TransportAdapterError::Publish(message) if message == "scripted"));
    assert_eq!(counts(&adapter).await, (4, 1, 3, 0));
    assert_eq!(client.calls.load(Ordering::SeqCst), 4);
    let accounts = client.accounts.lock().expect("accounts lock");
    assert_eq!(accounts.len(), 4, "every publish is account scoped");
    assert!(accounts.iter().all(|account| *account == account_id));
}

#[tokio::test]
async fn direct_publish_admission_and_unpolled_future_do_not_count() {
    let client = CountingClient::new(Mode::Accept);
    let adapter = NostrTransportAdapter::new(client.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    let message = group_event("inactive", &transport_group_id)
        .to_transport_message()
        .expect("event maps");
    let inactive = adapter
        .publish(request(
            account_id.clone(),
            message.clone(),
            transport_group_id.clone(),
            endpoint.clone(),
            1,
        ))
        .await
        .expect_err("inactive account");
    assert!(matches!(
        inactive,
        TransportAdapterError::AccountNotActive(_)
    ));

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![endpoint.clone()],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .expect("activation");
    let mut mismatched = message.clone();
    mismatched.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: vec![0xEE; 32],
    };
    let mismatch = adapter
        .publish(request(
            account_id.clone(),
            mismatched,
            transport_group_id.clone(),
            endpoint.clone(),
            1,
        ))
        .await
        .expect_err("envelope mismatch");
    assert!(matches!(
        mismatch,
        TransportAdapterError::PublishTargetMismatch { .. }
    ));

    let mut malformed = message.clone();
    malformed.payload = b"not-json".to_vec();
    malformed.timestamp = Timestamp(1);
    malformed.source = TransportSource(NOSTR_SOURCE.into());
    let malformed = adapter
        .publish(request(
            account_id.clone(),
            malformed,
            transport_group_id.clone(),
            endpoint.clone(),
            1,
        ))
        .await
        .expect_err("malformed payload");
    assert!(matches!(malformed, TransportAdapterError::Publish(_)));

    let pending = adapter.publish(request(
        account_id,
        message,
        transport_group_id,
        endpoint,
        1,
    ));
    drop(pending);
    assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    assert_eq!(counts(&adapter).await, (0, 0, 0, 0));
}

#[tokio::test]
async fn direct_publish_drop_after_client_entry_counts_one_cancellation() {
    let client = CountingClient::new(Mode::Wait);
    let (adapter, account_id, transport_group_id, endpoint) = activated(client.clone()).await;
    let (entered, _release) = client.arm_wait();
    let message = group_event("cancel", &transport_group_id)
        .to_transport_message()
        .expect("event maps");
    let adapter_task = adapter.clone();
    let task = tokio::spawn(async move {
        adapter_task
            .publish(request(
                account_id,
                message,
                transport_group_id,
                endpoint,
                1,
            ))
            .await
    });
    entered.await.expect("client entered");
    assert_eq!(counts(&adapter).await, (1, 0, 0, 0));
    task.abort();
    let _ = task.await;
    assert_eq!(counts(&adapter).await, (1, 0, 0, 1));
    assert_eq!(client.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cloned_adapters_share_publish_counters() {
    let client = CountingClient::new(Mode::Accept);
    let (adapter, account_id, transport_group_id, endpoint) = activated(client).await;
    let message = group_event("clone", &transport_group_id)
        .to_transport_message()
        .expect("event maps");
    let clone = adapter.clone();
    let first = adapter.publish(request(
        account_id.clone(),
        message.clone(),
        transport_group_id.clone(),
        endpoint.clone(),
        1,
    ));
    let second = clone.publish(request(
        account_id,
        message,
        transport_group_id,
        endpoint,
        1,
    ));
    let (left, right) = tokio::join!(first, second);
    left.expect("first publish");
    right.expect("second publish");
    assert_eq!(counts(&adapter).await, (2, 2, 0, 0));
}
