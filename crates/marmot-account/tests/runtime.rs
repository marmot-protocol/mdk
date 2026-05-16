use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_session::{AccountDeviceSession, SessionConfig};
use cgka_traits::engine::{CreateGroupRequest, GroupEvent};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::{
    MemberId, MessageId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportDelivery, TransportEndpoint, TransportEndpointReceipt, TransportGroupSync,
    TransportPublishReport, TransportPublishRequest,
};
use marmot_account::{
    AccountDeviceRuntime, KeyPackagePublication, KeyPackagePublishError, KeyPackagePublisher,
    PendingResolution, StaticTransportRouting,
};
use storage_sqlite::SqlCipherKey;

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

struct MockPeeler;

#[async_trait]
impl TransportPeeler for MockPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::Welcome {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("marmot-account-test".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("marmot-account-test".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

fn session(
    path: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    identity: &[u8],
) -> AccountDeviceSession {
    AccountDeviceSession::open(
        SessionConfig::new(path, key.clone(), pad32(identity), Box::new(MockPeeler))
            .feature_registry(FeatureRegistry::new()),
    )
    .unwrap()
}

#[derive(Clone, Default)]
struct RecordingAdapter {
    inner: Arc<RecordingAdapterInner>,
}

#[derive(Default)]
struct RecordingAdapterInner {
    activations: Mutex<Vec<TransportAccountActivation>>,
    syncs: Mutex<Vec<TransportGroupSync>>,
    publishes: Mutex<Vec<TransportPublishRequest>>,
    accepted_count: Mutex<Option<usize>>,
}

impl RecordingAdapter {
    fn accept_only_next(&self, accepted_count: usize) {
        *self.inner.accepted_count.lock().unwrap() = Some(accepted_count);
    }

    fn activations(&self) -> Vec<TransportAccountActivation> {
        self.inner.activations.lock().unwrap().clone()
    }

    fn publishes(&self) -> Vec<TransportPublishRequest> {
        self.inner.publishes.lock().unwrap().clone()
    }
}

#[async_trait]
impl TransportAdapter for RecordingAdapter {
    async fn activate_account(
        &self,
        activation: TransportAccountActivation,
    ) -> Result<(), TransportAdapterError> {
        self.inner.activations.lock().unwrap().push(activation);
        Ok(())
    }

    async fn sync_account_groups(
        &self,
        sync: TransportGroupSync,
    ) -> Result<(), TransportAdapterError> {
        self.inner.syncs.lock().unwrap().push(sync);
        Ok(())
    }

    async fn deactivate_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn publish(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        self.inner.publishes.lock().unwrap().push(request.clone());
        let accepted_count = self
            .inner
            .accepted_count
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| request.target.endpoints().len());
        Ok(TransportPublishReport {
            message_id: request.message.id,
            accepted: request
                .target
                .endpoints()
                .iter()
                .take(accepted_count)
                .cloned()
                .map(|endpoint| TransportEndpointReceipt {
                    endpoint,
                    accepted_at: None,
                })
                .collect(),
            failed: Vec::new(),
            required_acks: request.required_acks,
        })
    }

    async fn receive(&self) -> Result<Option<TransportDelivery>, TransportAdapterError> {
        Ok(None)
    }
}

#[derive(Clone, Default)]
struct RecordingKeyPackages {
    publications: Arc<Mutex<Vec<KeyPackagePublication>>>,
}

#[async_trait]
impl KeyPackagePublisher for RecordingKeyPackages {
    async fn publish_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<(), KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication);
        Ok(())
    }
}

impl RecordingKeyPackages {
    fn publications(&self) -> Vec<KeyPackagePublication> {
        self.publications.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn activate_transport_uses_session_identity_and_policy() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot account activation key").unwrap();
    let session = session(dir.path().join("alice.sqlite"), &key, b"alice");
    let adapter = RecordingAdapter::default();
    let policy = StaticTransportRouting::new(vec![TransportEndpoint("wss://inbox.example".into())]);
    let runtime = AccountDeviceRuntime::new(
        session,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    runtime
        .activate_transport(Some(Timestamp(10)))
        .await
        .unwrap();

    let activations = adapter.activations();
    assert_eq!(activations.len(), 1);
    assert_eq!(activations[0].account_id, runtime.session().self_id());
    assert_eq!(
        activations[0].inbox_endpoints,
        vec![TransportEndpoint("wss://inbox.example".into())]
    );
    assert_eq!(activations[0].since, Some(Timestamp(10)));
}

#[tokio::test]
async fn publish_fresh_key_package_uses_directory_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot key package key").unwrap();
    let session = session(dir.path().join("alice.sqlite"), &key, b"alice");
    let publisher = RecordingKeyPackages::default();
    let policy = StaticTransportRouting::new(vec![TransportEndpoint("wss://inbox.example".into())])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        session,
        RecordingAdapter::default(),
        policy,
        publisher.clone(),
    );

    let key_package = runtime.publish_fresh_key_package().await.unwrap();

    assert!(!key_package.0.is_empty());
    let publications = publisher.publications();
    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0].account_id, runtime.session().self_id());
    assert_eq!(publications[0].key_package, key_package);
    assert_eq!(
        publications[0].endpoints,
        vec![TransportEndpoint("wss://keys.example".into())]
    );
}

#[tokio::test]
async fn create_group_publishes_welcome_and_confirms_pending_on_ack() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot create group key").unwrap();
    let mut bob_session = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let bob_kp = bob_session.fresh_key_package().await.unwrap();
    let bob_id = bob_session.self_id();
    let session = session(dir.path().join("alice.sqlite"), &key, b"alice");
    let adapter = RecordingAdapter::default();
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_inbox_route(
                bob_id,
                vec![TransportEndpoint("wss://bob-inbox.example".into())],
            );
    let mut runtime = AccountDeviceRuntime::new(
        session,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    let (group_id, effects) = runtime
        .create_group(CreateGroupRequest {
            name: "runtime group".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    assert_eq!(effects.failures, Vec::new());
    assert_eq!(effects.pending.len(), 1);
    assert!(matches!(
        effects.pending[0],
        PendingResolution::Confirmed { .. }
    ));
    assert_eq!(
        effects.events,
        vec![GroupEvent::GroupCreated {
            group_id: group_id.clone()
        }]
    );
    assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 1);
    let publishes = adapter.publishes();
    assert_eq!(publishes.len(), 1);
    assert_eq!(
        publishes[0].target.endpoints(),
        &[TransportEndpoint("wss://bob-inbox.example".into())]
    );
}

#[tokio::test]
async fn create_group_rolls_back_pending_when_publish_acks_are_insufficient() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot rollback key").unwrap();
    let mut bob_session = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let bob_kp = bob_session.fresh_key_package().await.unwrap();
    let bob_id = bob_session.self_id();
    let session = session(dir.path().join("alice.sqlite"), &key, b"alice");
    let adapter = RecordingAdapter::default();
    adapter.accept_only_next(0);
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_inbox_route(
                bob_id,
                vec![TransportEndpoint("wss://bob-inbox.example".into())],
            );
    let mut runtime =
        AccountDeviceRuntime::new(session, adapter, policy, RecordingKeyPackages::default());

    let (group_id, effects) = runtime
        .create_group(CreateGroupRequest {
            name: "runtime rollback".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    assert_eq!(effects.pending.len(), 1);
    assert!(matches!(
        effects.pending[0],
        PendingResolution::RolledBack { .. }
    ));
    assert_eq!(effects.failures.len(), 1);
    assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 0);
    assert_eq!(runtime.session().members(&group_id).unwrap().len(), 1);
}
