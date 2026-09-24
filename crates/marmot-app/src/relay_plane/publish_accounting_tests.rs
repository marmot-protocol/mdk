//! Account-adapter publish accounting, fanout, and shared counter ownership.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::transport::{TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::{
    GroupId, MemberId, MessageId, TransportAccountActivation, TransportAdapter,
    TransportAdapterError, TransportEndpoint, TransportEndpointFailure, TransportEndpointReceipt,
    TransportGroupSubscription, TransportPublishReport, TransportPublishRequest,
    TransportPublishTarget,
};
use tokio::sync::oneshot;
use tokio::time::timeout;
use transport_nostr_adapter::{NostrPublishOutcome, NostrRelayClient};
use transport_nostr_peeler::{KIND_MARMOT_GROUP_MESSAGE, NOSTR_SOURCE, NostrTransportEvent};

use super::*;

/// Matches `transport_nostr_adapter`'s private delivery channel capacity.
const SHARED_DELIVERY_BUFFER: usize = 1024;

pub(crate) enum PublishScript {
    Accept,
    Empty,
    Error,
    Outcome(NostrPublishOutcome),
    Wait,
}

pub(crate) struct CountingClient {
    pub calls: AtomicUsize,
    script: StdMutex<PublishScript>,
    entered: StdMutex<Option<oneshot::Sender<()>>>,
    release: StdMutex<Option<oneshot::Receiver<()>>>,
}

impl CountingClient {
    pub(crate) fn new(script: PublishScript) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            script: StdMutex::new(script),
            entered: StdMutex::new(None),
            release: StdMutex::new(None),
        })
    }

    pub(crate) fn set_script(&self, script: PublishScript) {
        *self.script.lock().expect("script lock") = script;
    }

    fn arm_wait(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
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

fn group_event(content: &str, transport_group_id: &[u8]) -> NostrTransportEvent {
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

    fn request(&self, required_acks: usize) -> TransportPublishRequest {
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
}

async fn counts(plane: &MarmotRelayPlane) -> (usize, usize, usize) {
    let metrics = plane.relay_telemetry().await.metrics;
    (
        metrics.publish_attempts,
        metrics.publish_successes,
        metrics.publish_failures,
    )
}

fn receipt(endpoint: &TransportEndpoint) -> TransportEndpointReceipt {
    TransportEndpointReceipt {
        endpoint: endpoint.clone(),
        accepted_at: None,
    }
}

fn failure(endpoint: &TransportEndpoint) -> TransportEndpointFailure {
    TransportEndpointFailure {
        endpoint: endpoint.clone(),
        reason: "rejected".to_owned(),
        kind: Default::default(),
        rejection_category: None,
    }
}

#[tokio::test]
async fn account_publish_classifies_against_met_required_acks() {
    let fixture = AccountPublishFixture::activate().await;
    let admitted = fixture
        .publish(PublishScript::Accept, 1)
        .await
        .expect("admitted publish");
    assert!(admitted.met_required_acks());
    assert_eq!(counts(&fixture.plane).await, (1, 1, 0));
    let rollup = fixture.plane.telemetry_rollup(None).await;
    assert_eq!(
        (
            rollup.publish_attempts,
            rollup.publish_successes,
            rollup.publish_failures
        ),
        (1, 1, 0)
    );

    let rejected = fixture
        .publish(PublishScript::Empty, 1)
        .await
        .expect("all-rejected style empty acceptance still returns Ok");
    assert!(!rejected.met_required_acks());
    assert!(rejected.accepted.is_empty());

    let endpoint_b = TransportEndpoint("wss://other.example".into());
    let partial_miss = NostrPublishOutcome {
        message_id: None,
        accepted: vec![receipt(&fixture.endpoint)],
        failed: vec![failure(&endpoint_b)],
    };
    let missed = fixture
        .publish(PublishScript::Outcome(partial_miss), 2)
        .await
        .expect("partial outcome is returned unchanged");
    assert_eq!(missed.accepted.len(), 1);
    assert_eq!(missed.failed.len(), 1);
    assert!(!missed.met_required_acks());

    let partial_hit = NostrPublishOutcome {
        message_id: None,
        accepted: vec![receipt(&fixture.endpoint), receipt(&endpoint_b)],
        failed: vec![failure(&TransportEndpoint("wss://third.example".into()))],
    };
    let hit = fixture
        .publish(PublishScript::Outcome(partial_hit), 2)
        .await
        .expect("threshold met despite another failure");
    assert!(hit.met_required_acks());

    let none = fixture
        .publish(PublishScript::Empty, 0)
        .await
        .expect("required_acks 0 still returns the empty outcome");
    assert!(!none.met_required_acks());
    let one = fixture
        .publish(PublishScript::Accept, 0)
        .await
        .expect("one acceptance satisfies required_acks 0");
    assert!(one.met_required_acks());

    let error = fixture
        .publish(PublishScript::Error, 1)
        .await
        .expect_err("client error is unchanged");
    assert!(matches!(error, TransportAdapterError::Publish(message) if message == "scripted"));
    assert_eq!(counts(&fixture.plane).await, (7, 3, 4));
}

#[tokio::test]
async fn account_admission_and_unpolled_future_do_not_publish() {
    let fixture = AccountPublishFixture::activate().await;
    let wrong = fixture
        .adapter
        .publish(TransportPublishRequest {
            account_id: MemberId::new(vec![0xB2; 32]),
            message: fixture.message.clone(),
            target: TransportPublishTarget::Group {
                group_id: GroupId::new(vec![0xC3; 32]),
                transport_group_id: fixture.transport_group_id.clone(),
                endpoints: vec![fixture.endpoint.clone()],
            },
            required_acks: 1,
        })
        .await
        .expect_err("wrong account");
    assert!(matches!(wrong, TransportAdapterError::AccountNotActive(_)));

    let unsafe_request = TransportPublishRequest {
        account_id: fixture.account_id.clone(),
        message: fixture.message.clone(),
        target: TransportPublishTarget::Group {
            group_id: GroupId::new(vec![0xC3; 32]),
            transport_group_id: fixture.transport_group_id.clone(),
            endpoints: vec![TransportEndpoint("wss://10.1.1.1".into())],
        },
        required_acks: 1,
    };
    let unsafe_endpoint = fixture
        .adapter
        .publish(unsafe_request)
        .await
        .expect_err("private endpoint");
    assert!(matches!(unsafe_endpoint, TransportAdapterError::Publish(_)));

    let mut mismatched = fixture.message.clone();
    mismatched.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: vec![0xEE; 32],
    };
    let mismatch = fixture
        .adapter
        .publish(TransportPublishRequest {
            account_id: fixture.account_id.clone(),
            message: mismatched,
            target: TransportPublishTarget::Group {
                group_id: GroupId::new(vec![0xC3; 32]),
                transport_group_id: fixture.transport_group_id.clone(),
                endpoints: vec![fixture.endpoint.clone()],
            },
            required_acks: 1,
        })
        .await
        .expect_err("envelope mismatch");
    assert!(matches!(
        mismatch,
        TransportAdapterError::PublishTargetMismatch { .. }
    ));

    let mut malformed = fixture.message.clone();
    malformed.payload = b"not-json".to_vec();
    malformed.source = TransportSource(NOSTR_SOURCE.into());
    let malformed = fixture
        .adapter
        .publish(TransportPublishRequest {
            account_id: fixture.account_id.clone(),
            message: malformed,
            target: TransportPublishTarget::Group {
                group_id: GroupId::new(vec![0xC3; 32]),
                transport_group_id: fixture.transport_group_id.clone(),
                endpoints: vec![fixture.endpoint.clone()],
            },
            required_acks: 1,
        })
        .await
        .expect_err("malformed payload");
    assert!(matches!(malformed, TransportAdapterError::Publish(_)));

    let pending = fixture.adapter.publish(fixture.request(1));
    drop(pending);
    assert_eq!(fixture.client.calls.load(Ordering::SeqCst), 0);
    assert_eq!(counts(&fixture.plane).await, (0, 0, 0));
}

#[tokio::test]
async fn account_and_direct_cancellation_finalize_without_double_counting() {
    let fixture = AccountPublishFixture::activate().await;
    let (entered, _release) = fixture.client.arm_wait();
    let adapter = fixture.adapter.clone();
    let request = fixture.request(1);
    let task = tokio::spawn(async move { adapter.publish(request).await });
    entered.await.expect("account client entered");
    assert_eq!(counts(&fixture.plane).await, (1, 0, 0));
    task.abort();
    let _ = task.await;
    assert_eq!(counts(&fixture.plane).await, (1, 0, 1));

    let (entered, _release) = fixture.client.arm_wait();
    let direct = fixture.plane.inner.transport.adapter.clone();
    let request = fixture.request(1);
    let task = tokio::spawn(async move { direct.publish(request).await });
    entered.await.expect("direct client entered");
    assert_eq!(counts(&fixture.plane).await, (2, 0, 1));
    task.abort();
    let _ = task.await;
    assert_eq!(counts(&fixture.plane).await, (2, 0, 2));
    assert_eq!(fixture.client.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cancellation_during_local_fanout_keeps_the_success() {
    let fixture = AccountPublishFixture::activate().await;
    let handle = {
        let mut router = fixture.plane.inner.transport.router.lock().await;
        router.take()
    };
    if let Some(handle) = handle {
        handle.abort();
        let _ = handle.await;
    }
    for _ in 0..SHARED_DELIVERY_BUFFER {
        let delivered = fixture
            .plane
            .inner
            .transport
            .adapter
            .deliver_local_publish(&fixture.message, std::slice::from_ref(&fixture.endpoint))
            .await
            .expect("filler delivery");
        assert_eq!(delivered, 1);
    }
    fixture.client.set_script(PublishScript::Accept);
    let adapter = fixture.adapter.clone();
    let request = fixture.request(1);
    let task = tokio::spawn(async move { adapter.publish(request).await });
    timeout(Duration::from_secs(2), async {
        loop {
            let (attempts, successes, failures) = counts(&fixture.plane).await;
            if attempts == 1 && successes == 1 && failures == 0 && !task.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("network accounting completed while local fanout is blocked");
    task.abort();
    let _ = task.await;
    assert_eq!(counts(&fixture.plane).await, (1, 1, 0));
}

#[tokio::test]
async fn successful_fanout_delivers_once_per_route_and_keeps_the_message_id() {
    let client = CountingClient::new(PublishScript::Accept);
    let plane = MarmotRelayPlane::new(Some(Duration::from_secs(30)), client.clone());
    let alice_id = MemberId::new(vec![0xA1; 32]);
    let bob_id = MemberId::new(vec![0xB2; 32]);
    let group_id = GroupId::new(vec![0xC3; 32]);
    let transport_group_id = vec![0xD4; 32];
    let endpoint_a = TransportEndpoint("wss://a.example".into());
    let endpoint_b = TransportEndpoint("wss://b.example".into());
    let alice = plane.account_adapter(alice_id.clone(), client.clone());
    let bob = plane.account_adapter(bob_id.clone(), client.clone());
    let subscription = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: transport_group_id.clone(),
        endpoints: vec![endpoint_a.clone(), endpoint_b.clone()],
    };
    for (adapter, account_id) in [(&alice, alice_id.clone()), (&bob, bob_id.clone())] {
        adapter
            .activate_account(TransportAccountActivation {
                account_id,
                inbox_endpoints: vec![endpoint_a.clone()],
                group_subscriptions: vec![subscription.clone()],
                since: None,
            })
            .await
            .expect("activation");
    }
    let message = group_event("fanout", &transport_group_id)
        .to_transport_message()
        .expect("event maps");
    let canonical = MessageId::new(vec![0x44; 32]);
    client.set_script(PublishScript::Outcome(NostrPublishOutcome {
        message_id: Some(canonical.clone()),
        accepted: vec![receipt(&endpoint_a), receipt(&endpoint_b)],
        failed: vec![],
    }));
    let report = alice
        .publish(TransportPublishRequest {
            account_id: alice_id.clone(),
            message: message.clone(),
            target: TransportPublishTarget::Group {
                group_id: group_id.clone(),
                transport_group_id,
                endpoints: vec![endpoint_a, endpoint_b],
            },
            required_acks: 1,
        })
        .await
        .expect("overlapping publish");
    assert_eq!(report.message_id, canonical);
    assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    assert_eq!(counts(&plane).await, (1, 1, 0));

    for (adapter, account_id) in [(alice, alice_id), (bob, bob_id)] {
        let delivery = timeout(Duration::from_secs(1), adapter.receive())
            .await
            .expect("local delivery")
            .expect("receive")
            .expect("delivery");
        assert_eq!(delivery.account_id, account_id);
        assert_eq!(delivery.group_id_hint, Some(group_id.clone()));
        assert_eq!(delivery.message.id, canonical);
        assert!(
            timeout(Duration::from_millis(50), adapter.receive())
                .await
                .is_err(),
            "overlapping endpoints must not queue a second delivery"
        );
    }
}

#[tokio::test]
async fn rejected_and_failed_publishes_do_not_invent_local_delivery() {
    let fixture = AccountPublishFixture::activate().await;
    let bob_id = MemberId::new(vec![0xB2; 32]);
    let bob = fixture
        .plane
        .account_adapter(bob_id.clone(), fixture.client.clone());
    bob.activate_account(TransportAccountActivation {
        account_id: bob_id,
        inbox_endpoints: vec![fixture.endpoint.clone()],
        group_subscriptions: vec![TransportGroupSubscription {
            group_id: GroupId::new(vec![0xC3; 32]),
            transport_group_id: fixture.transport_group_id.clone(),
            endpoints: vec![fixture.endpoint.clone()],
        }],
        since: None,
    })
    .await
    .expect("bob activation");

    let rejected = fixture
        .publish(
            PublishScript::Outcome(NostrPublishOutcome {
                message_id: None,
                accepted: Vec::new(),
                failed: vec![failure(&fixture.endpoint)],
            }),
            1,
        )
        .await
        .expect("all-rejected outcome");
    assert!(!rejected.met_required_acks());
    assert!(rejected.failed.len() == 1);
    let error = fixture
        .publish(PublishScript::Error, 1)
        .await
        .expect_err("publish error");
    assert!(matches!(error, TransportAdapterError::Publish(message) if message == "scripted"));
    assert_eq!(counts(&fixture.plane).await, (2, 0, 2));
    assert!(
        timeout(Duration::from_millis(50), bob.receive())
            .await
            .is_err(),
        "rejected and failed publishes must not deliver locally"
    );
}

#[tokio::test]
async fn account_and_direct_clones_share_one_counter() {
    let fixture = AccountPublishFixture::activate().await;
    let bob_id = MemberId::new(vec![0xB2; 32]);
    let bob = fixture
        .plane
        .account_adapter(bob_id.clone(), fixture.client.clone());
    bob.activate_account(TransportAccountActivation {
        account_id: bob_id.clone(),
        inbox_endpoints: vec![fixture.endpoint.clone()],
        group_subscriptions: vec![TransportGroupSubscription {
            group_id: GroupId::new(vec![0xC3; 32]),
            transport_group_id: fixture.transport_group_id.clone(),
            endpoints: vec![fixture.endpoint.clone()],
        }],
        since: None,
    })
    .await
    .expect("bob activation");
    fixture.client.set_script(PublishScript::Accept);
    let direct_a = fixture.plane.inner.transport.adapter.clone();
    let direct_b = direct_a.clone();
    let alice_request = fixture.request(1);
    let mut bob_request = fixture.request(1);
    bob_request.account_id = bob_id;
    let direct_request = fixture.request(1);
    let direct_request_b = fixture.request(1);
    let alice = fixture.adapter.clone();
    let (a, b, c, d) = tokio::join!(
        alice.publish(alice_request),
        bob.publish(bob_request),
        direct_a.publish(direct_request),
        direct_b.publish(direct_request_b),
    );
    a.expect("alice");
    b.expect("bob");
    c.expect("direct a");
    d.expect("direct b");
    assert_eq!(fixture.client.calls.load(Ordering::SeqCst), 4);
    assert_eq!(counts(&fixture.plane).await, (4, 4, 0));

    let (entered, release) = fixture.client.arm_wait();
    let pending_adapter = fixture.adapter.clone();
    let pending_request = fixture.request(1);
    let task = tokio::spawn(async move { pending_adapter.publish(pending_request).await });
    entered.await.expect("pending publish entered");
    assert_eq!(counts(&fixture.plane).await, (5, 4, 0));
    release.send(()).expect("release pending publish");
    task.await.expect("join").expect("pending publish");
    assert_eq!(counts(&fixture.plane).await, (5, 5, 0));
}
