#![allow(dead_code)]
//! Shared no-network Nostr stack harness for session integration tests.
//!
//! Each integration test binary compiles this module independently, so some
//! public helpers are intentionally used by only one sibling test file.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_session::{
    AccountDeviceSession, CreateGroupEffects, IngestEffects, PublishWork, SessionConfig,
};
use cgka_traits::app_components::{
    AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, decode_nostr_routing_v1,
    default_group_components, encode_nostr_routing_v1,
};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::{
    GroupId, MemberId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportEndpoint, TransportEndpointFailure, TransportEndpointReceipt,
    TransportGroupSubscription, TransportGroupSync, TransportMessage, TransportPublishReport,
    TransportPublishRequest, TransportPublishTarget,
};
use sha2::{Digest, Sha256};
use storage_sqlite::SqlCipherKey;
use tempfile::TempDir;
use transport_nostr_adapter::{
    NostrPublishOutcome, NostrRelayClient, NostrRelayEvent, NostrTransportAdapter,
};
use transport_nostr_peeler::{NostrMlsPeeler, NostrTransportEvent};

pub struct NostrStackHarness {
    _dir: TempDir,
    database_key_material: &'static str,
    relay: Arc<FakeRelayClient>,
    adapter: NostrTransportAdapter,
    group_endpoint: TransportEndpoint,
}

pub struct StackClient {
    pub account_id: MemberId,
    pub inbox_endpoint: TransportEndpoint,
    pub session: AccountDeviceSession,
}

pub struct CreatedGroup {
    pub group_id: GroupId,
    pub pending: PendingStateRef,
    pub welcome: TransportMessage,
}

pub struct PublishedEvent {
    pub endpoints: Vec<TransportEndpoint>,
    pub event: NostrTransportEvent,
    pub required_acks: usize,
}

#[derive(Default)]
pub struct FakeRelayClient {
    published: Mutex<Vec<PublishedEvent>>,
    accepted_limit: Mutex<Option<usize>>,
    fail_next_publish: Mutex<Option<String>>,
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
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        if let Some(reason) = self.fail_next_publish.lock().unwrap().take() {
            return Err(TransportAdapterError::Publish(reason));
        }

        self.published.lock().unwrap().push(PublishedEvent {
            endpoints: endpoints.to_vec(),
            event: event.clone(),
            required_acks,
        });

        let accepted_limit = self
            .accepted_limit
            .lock()
            .unwrap()
            .take()
            .unwrap_or(endpoints.len());
        Ok(NostrPublishOutcome {
            message_id: None,
            accepted: endpoints
                .iter()
                .take(accepted_limit)
                .cloned()
                .map(|endpoint| TransportEndpointReceipt {
                    endpoint,
                    accepted_at: None,
                })
                .collect(),
            failed: endpoints
                .iter()
                .skip(accepted_limit)
                .cloned()
                .map(|endpoint| TransportEndpointFailure {
                    endpoint,
                    reason: "not accepted by in-memory relay".into(),
                })
                .collect(),
        })
    }
}

impl NostrStackHarness {
    pub fn new() -> Self {
        let relay = Arc::new(FakeRelayClient::default());
        let adapter = NostrTransportAdapter::new(relay.clone());
        Self {
            _dir: tempfile::tempdir().unwrap(),
            database_key_material: "nostr stack integration key",
            relay,
            adapter,
            group_endpoint: TransportEndpoint(default_group_endpoint()),
        }
    }

    pub async fn client(&self, label: &str) -> StackClient {
        let keys = deterministic_nostr_keys(label.as_bytes());
        let account_id = member_id(&keys);
        let inbox_endpoint = TransportEndpoint(format!("wss://{label}-inbox.example"));
        let session = AccountDeviceSession::open(
            SessionConfig::new(
                self._dir.path().join(format!("{label}.sqlite")),
                SqlCipherKey::new(self.database_key_material).unwrap(),
                keys.public_key().to_bytes().to_vec(),
                Box::new(NostrMlsPeeler::new().with_welcome_signer(keys.clone())),
            )
            .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
                keys: keys.clone(),
            }))
            .supported_app_components(supported_app_components()),
        )
        .unwrap();
        self.adapter
            .activate_account(TransportAccountActivation {
                account_id: account_id.clone(),
                inbox_endpoints: vec![inbox_endpoint.clone()],
                group_subscriptions: vec![],
                since: None,
            })
            .await
            .unwrap();
        StackClient {
            account_id,
            inbox_endpoint,
            session,
        }
    }

    pub fn accept_only_next_publish(&self, accepted_count: usize) {
        *self.relay.accepted_limit.lock().unwrap() = Some(accepted_count);
    }

    pub fn fail_next_publish(&self, reason: impl Into<String>) {
        *self.relay.fail_next_publish.lock().unwrap() = Some(reason.into());
    }

    pub async fn sync_group(&self, client: &StackClient, group_id: &GroupId) {
        let transport_group_id = transport_group_id_for_session(client, group_id);
        self.adapter
            .sync_account_groups(TransportGroupSync {
                account_id: client.account_id.clone(),
                group_subscriptions: vec![TransportGroupSubscription {
                    group_id: group_id.clone(),
                    transport_group_id,
                    endpoints: vec![self.group_endpoint.clone()],
                }],
                since: None,
            })
            .await
            .unwrap();
    }

    pub async fn publish_welcome(
        &self,
        sender: &StackClient,
        recipient: &StackClient,
        message: TransportMessage,
        required_acks: usize,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        self.publish_welcome_to_endpoints(
            sender,
            recipient,
            message,
            vec![recipient.inbox_endpoint.clone()],
            required_acks,
        )
        .await
    }

    pub async fn publish_welcome_to_endpoints(
        &self,
        sender: &StackClient,
        recipient: &StackClient,
        message: TransportMessage,
        endpoints: Vec<TransportEndpoint>,
        required_acks: usize,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        self.adapter
            .publish(TransportPublishRequest {
                account_id: sender.account_id.clone(),
                message,
                target: TransportPublishTarget::Inbox {
                    recipient: recipient.account_id.clone(),
                    endpoints,
                },
                required_acks,
            })
            .await
    }

    pub async fn publish_group(
        &self,
        sender: &StackClient,
        group_id: &GroupId,
        message: TransportMessage,
        required_acks: usize,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        let transport_group_id = transport_group_id_for_session(sender, group_id);
        self.adapter
            .publish(TransportPublishRequest {
                account_id: sender.account_id.clone(),
                message,
                target: TransportPublishTarget::Group {
                    group_id: group_id.clone(),
                    transport_group_id,
                    endpoints: vec![self.group_endpoint.clone()],
                },
                required_acks,
            })
            .await
    }

    pub fn take_one_published(&self) -> PublishedEvent {
        self.relay.take_one_published()
    }

    pub fn take_next_published(&self) -> PublishedEvent {
        self.relay.take_next_published()
    }

    pub async fn deliver_next_to_inbox_session(
        &self,
        recipient: &mut StackClient,
    ) -> Option<IngestEffects> {
        let published = self.take_one_published();
        assert_eq!(published.endpoints, vec![recipient.inbox_endpoint.clone()]);
        assert_eq!(published.required_acks, 1);
        let endpoint = recipient.inbox_endpoint.clone();
        self.deliver_event_to_session(recipient, endpoint, "inbox", published.event)
            .await
    }

    pub async fn deliver_next_to_group_session(
        &self,
        recipient: &mut StackClient,
    ) -> Option<IngestEffects> {
        let published = self.take_one_published();
        assert_eq!(published.endpoints, vec![self.group_endpoint.clone()]);
        assert_eq!(published.required_acks, 1);
        self.deliver_event_to_session(
            recipient,
            self.group_endpoint.clone(),
            "group",
            published.event,
        )
        .await
    }

    pub async fn deliver_event_to_session(
        &self,
        recipient: &mut StackClient,
        endpoint: TransportEndpoint,
        subscription_id: impl Into<String>,
        event: NostrTransportEvent,
    ) -> Option<IngestEffects> {
        let mut routed = self
            .deliver_event_to_sessions(&mut [recipient], endpoint, subscription_id, event)
            .await;
        routed.pop().map(|(_, effects)| effects)
    }

    pub async fn deliver_event_to_sessions(
        &self,
        recipients: &mut [&mut StackClient],
        endpoint: TransportEndpoint,
        subscription_id: impl Into<String>,
        event: NostrTransportEvent,
    ) -> Vec<(MemberId, IngestEffects)> {
        let delivered = self
            .adapter
            .handle_relay_event(NostrRelayEvent {
                endpoint,
                subscription_id: Some(subscription_id.into()),
                event,
            })
            .await
            .unwrap();
        if delivered == 0 {
            return Vec::new();
        }

        let mut effects = Vec::with_capacity(delivered);
        for _ in 0..delivered {
            let delivery = self.adapter.receive().await.unwrap().unwrap();
            let recipient = recipients
                .iter_mut()
                .find(|recipient| recipient.account_id == delivery.account_id)
                .expect("relay event delivered to an unexpected account");
            let account_id = recipient.account_id.clone();
            let ingest = recipient.session.ingest(delivery.message).await.unwrap();
            effects.push((account_id, ingest));
        }
        effects
    }

    pub fn group_endpoint(&self) -> TransportEndpoint {
        self.group_endpoint.clone()
    }

    pub fn nostr_routing_component(&self, seed: &[u8]) -> AppComponentData {
        nostr_routing_component(seed)
    }
}

pub fn nostr_routing_component(seed: &[u8]) -> AppComponentData {
    let routing = NostrRoutingV1::new(
        deterministic_nostr_group_id(seed),
        vec![default_group_endpoint()],
    )
    .unwrap();
    AppComponentData {
        component_id: NOSTR_ROUTING_COMPONENT_ID,
        data: encode_nostr_routing_v1(&routing).unwrap(),
    }
}

impl CreatedGroup {
    pub fn from_effects(created: CreateGroupEffects) -> Self {
        let (pending, welcome) = match &created.effects.publish[0] {
            PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
            other => panic!("expected group creation publish work, got {other:?}"),
        };
        Self {
            group_id: created.group_id,
            pending,
            welcome,
        }
    }
}

impl FakeRelayClient {
    fn take_one_published(&self) -> PublishedEvent {
        let mut published = self.published.lock().unwrap();
        assert_eq!(published.len(), 1, "expected one relay publication");
        published.remove(0)
    }

    fn take_next_published(&self) -> PublishedEvent {
        let mut published = self.published.lock().unwrap();
        assert!(
            !published.is_empty(),
            "expected at least one relay publication"
        );
        published.remove(0)
    }
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

#[derive(Clone)]
struct NostrAccountIdentityProofSigner {
    keys: nostr::Keys,
}

impl AccountIdentityProofSigner for NostrAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.keys.public_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match Nostr stack key".into());
        }
        let message = nostr::secp256k1::Message::from_digest(request.signing_digest());
        Ok(self.keys.sign_schnorr(&message).serialize())
    }
}

fn default_group_endpoint() -> String {
    "wss://group.example".into()
}

fn supported_app_components() -> Vec<u16> {
    let mut components = default_group_components();
    components.insert(NOSTR_ROUTING_COMPONENT_ID);
    components.into_iter().collect()
}

fn transport_group_id_for_session(client: &StackClient, group_id: &GroupId) -> Vec<u8> {
    client
        .session
        .app_component(group_id, NOSTR_ROUTING_COMPONENT_ID)
        .unwrap()
        .and_then(|bytes| decode_nostr_routing_v1(&bytes).ok())
        .map(|routing| routing.nostr_group_id.to_vec())
        .unwrap_or_else(|| group_id.as_slice().to_vec())
}

fn deterministic_nostr_group_id(seed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-cgka-session-nostr-group-id-v1");
    hasher.update(seed);
    hasher.finalize().into()
}
