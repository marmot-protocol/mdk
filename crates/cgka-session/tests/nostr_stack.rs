use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cgka_session::{AccountDeviceSession, PublishWork, SessionConfig};
use cgka_traits::engine::{CreateGroupRequest, GroupEvent, SendIntent};
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::{
    MemberId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportEndpoint, TransportGroupSubscription, TransportGroupSync, TransportPublishRequest,
    TransportPublishTarget,
};
use sha2::{Digest, Sha256};
use storage_sqlite::SqlCipherKey;
use transport_nostr_adapter::{
    NostrPublishOutcome, NostrRelayClient, NostrRelayEvent, NostrTransportAdapter,
};
use transport_nostr_peeler::NostrMlsPeeler;

#[derive(Default)]
struct FakeRelayClient {
    published: Mutex<
        Vec<(
            Vec<TransportEndpoint>,
            transport_nostr_peeler::NostrTransportEvent,
            usize,
        )>,
    >,
}

#[async_trait]
impl NostrRelayClient for FakeRelayClient {
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
        event: &transport_nostr_peeler::NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        self.published
            .lock()
            .unwrap()
            .push((endpoints.to_vec(), event.clone(), required_acks));
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

impl FakeRelayClient {
    fn take_one_published(
        &self,
    ) -> (
        Vec<TransportEndpoint>,
        transport_nostr_peeler::NostrTransportEvent,
        usize,
    ) {
        let mut published = self.published.lock().unwrap();
        assert_eq!(published.len(), 1, "expected one relay publication");
        published.remove(0)
    }
}

#[tokio::test]
async fn nostr_adapter_peeler_and_session_deliver_welcome_and_group_message() {
    let dir = tempfile::tempdir().unwrap();
    let database_key = SqlCipherKey::new("nostr stack integration key").unwrap();
    let alice_keys = deterministic_nostr_keys(b"alice");
    let bob_keys = deterministic_nostr_keys(b"bob");
    let alice_account = member_id(&alice_keys);
    let bob_account = member_id(&bob_keys);
    let alice_inbox = TransportEndpoint("wss://alice-inbox.example".into());
    let bob_inbox = TransportEndpoint("wss://bob-inbox.example".into());
    let group_endpoint = TransportEndpoint("wss://group.example".into());
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());

    let mut alice = AccountDeviceSession::open(config(
        dir.path().join("alice.sqlite"),
        &database_key,
        alice_keys,
    ))
    .unwrap();
    let mut bob = AccountDeviceSession::open(config(
        dir.path().join("bob.sqlite"),
        &database_key,
        bob_keys,
    ))
    .unwrap();

    adapter
        .activate_account(TransportAccountActivation {
            account_id: alice_account.clone(),
            inbox_endpoints: vec![alice_inbox],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    adapter
        .activate_account(TransportAccountActivation {
            account_id: bob_account.clone(),
            inbox_endpoints: vec![bob_inbox.clone()],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();

    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "nostr-stack".into(),
            description: "session adapter peeler integration".into(),
            members: vec![bob_key_package],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("expected group creation publish work, got {other:?}"),
    };

    let welcome_report = adapter
        .publish(TransportPublishRequest {
            account_id: alice_account.clone(),
            message: welcome,
            target: TransportPublishTarget::Inbox {
                recipient: bob_account.clone(),
                endpoints: vec![bob_inbox.clone()],
            },
            required_acks: 1,
        })
        .await
        .unwrap();
    assert!(welcome_report.met_required_acks());
    alice.confirm_published(pending).await.unwrap();

    let (welcome_endpoints, welcome_event, welcome_acks) = relay.take_one_published();
    assert_eq!(welcome_endpoints, vec![bob_inbox.clone()]);
    assert_eq!(welcome_acks, 1);
    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: bob_inbox,
            subscription_id: Some("bob-inbox".into()),
            event: welcome_event,
        })
        .await
        .unwrap();
    assert_eq!(delivered, 1);
    let welcome_delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(welcome_delivery.account_id, bob_account.clone());
    let joined = bob.ingest(welcome_delivery.message).await.unwrap();
    assert_eq!(
        joined.effects.events,
        vec![GroupEvent::GroupJoined {
            group_id: created.group_id.clone(),
            via_welcome: welcome_report.message_id
        }]
    );

    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: bob_account.clone(),
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: created.group_id.clone(),
                transport_group_id: created.group_id.as_slice().to_vec(),
                endpoints: vec![group_endpoint.clone()],
            }],
            since: None,
        })
        .await
        .unwrap();

    let sent = alice
        .send(SendIntent::AppMessage {
            group_id: created.group_id.clone(),
            payload: b"hello through the nostr stack".to_vec(),
        })
        .await
        .unwrap();
    let app_message = match &sent.publish[0] {
        PublishWork::ApplicationMessage { msg } => msg.clone(),
        other => panic!("expected application message publish work, got {other:?}"),
    };
    let app_report = adapter
        .publish(TransportPublishRequest {
            account_id: alice_account.clone(),
            message: app_message,
            target: TransportPublishTarget::Group {
                group_id: created.group_id.clone(),
                transport_group_id: created.group_id.as_slice().to_vec(),
                endpoints: vec![group_endpoint.clone()],
            },
            required_acks: 1,
        })
        .await
        .unwrap();
    assert!(app_report.met_required_acks());

    let (group_endpoints, group_event, group_acks) = relay.take_one_published();
    assert_eq!(group_endpoints, vec![group_endpoint.clone()]);
    assert_eq!(group_acks, 1);
    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: group_endpoint,
            subscription_id: Some("bob-group".into()),
            event: group_event,
        })
        .await
        .unwrap();
    assert_eq!(delivered, 1);
    let group_delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(group_delivery.account_id, bob_account);

    let received = bob.ingest(group_delivery.message).await.unwrap();
    assert_eq!(received.outcome, IngestOutcome::Processed);
    assert_eq!(
        received.effects.events,
        vec![GroupEvent::MessageReceived {
            group_id: created.group_id,
            sender: alice.self_id(),
            payload: b"hello through the nostr stack".to_vec(),
        }]
    );
}

fn config(
    path: impl Into<std::path::PathBuf>,
    database_key: &SqlCipherKey,
    keys: nostr::Keys,
) -> SessionConfig {
    SessionConfig::new(
        path,
        database_key.clone(),
        keys.public_key().to_bytes().to_vec(),
        Box::new(NostrMlsPeeler::new(keys.public_key().to_hex()).with_welcome_signer(keys)),
    )
}

fn member_id(keys: &nostr::Keys) -> MemberId {
    MemberId::new(keys.public_key().to_bytes().to_vec())
}

fn deterministic_nostr_keys(seed: &[u8]) -> nostr::Keys {
    let mut counter = 0_u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"marmot-cgka-session-nostr-stack-test-key-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let secret = hasher.finalize();
        if let Ok(keys) = nostr::Keys::parse(&hex::encode(secret)) {
            return keys;
        }
        counter = counter
            .checked_add(1)
            .expect("deterministic Nostr key search exhausted");
    }
}
