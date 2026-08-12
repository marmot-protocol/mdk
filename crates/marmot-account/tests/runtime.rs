use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_session::{AccountDeviceSession, PublishWork, SessionConfig};
use cgka_traits::app_components::{
    AppComponentData, GROUP_MESSAGE_RETENTION_COMPONENT_ID, default_group_components,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CreateGroupRequest, GroupEvent, SendIntent};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{KeyPackageBundleStorage, MaintenanceStorage, OutboundFanoutStorage};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::{
    EpochId, FanoutMlsState, FanoutTargetStatus, GroupId, MemberId, MessageId, OutboundFanout,
    TransportAccountActivation, TransportAdapter, TransportAdapterError, TransportDelivery,
    TransportDeliveryPlane, TransportDeliverySource, TransportEndpoint, TransportEndpointReceipt,
    TransportGroupSync, TransportPublishReport, TransportPublishRequest, TransportPublishTarget,
};
use marmot_account::{
    AccountDeviceRuntime, AccountError, KeyPackagePublication, KeyPackagePublishError,
    KeyPackagePublishReceipt, KeyPackagePublisher, MaintenanceRandom, MonotonicClock,
    NoopKeyPackagePublisher, PendingResolution, PublishedApplicationMessage,
    StaticTransportRouting, TransportRoutingError, TransportRoutingPolicy, WallClock,
};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

fn pad32(name: &[u8]) -> Vec<u8> {
    deterministic_nostr_keys(name)
        .public_key()
        .to_bytes()
        .to_vec()
}

fn deterministic_nostr_keys(name: &[u8]) -> nostr::Keys {
    use sha2::{Digest, Sha256};
    let mut counter = 0u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"marmot-account-runtime-test-key-v1");
        hasher.update(name);
        hasher.update(counter.to_be_bytes());
        let secret = hasher.finalize();
        if let Ok(keys) = nostr::Keys::parse(&hex::encode(secret)) {
            return keys;
        }
        counter += 1;
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
            return Err("request account identity does not match marmot-account test key".into());
        }
        let event = request.proof_event().and_then(|event| {
            event
                .sign_with_keys(&self.keys)
                .map_err(|err| err.to_string())
        })?;
        request.signature_from_signed_event(event)
    }
}

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

struct MockPeeler;

#[derive(Debug)]
struct TestWallClock(AtomicU64);

impl TestWallClock {
    fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    fn set(&self, now: u64) {
        self.0.store(now, Ordering::Relaxed);
    }
}

impl WallClock for TestWallClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.0.load(Ordering::Relaxed))
    }

    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed).saturating_mul(1_000)
    }
}

#[derive(Debug, Default)]
struct TestMonotonicClock(AtomicU64);

impl TestMonotonicClock {
    fn set_millis(&self, elapsed: u64) {
        self.0.store(elapsed, Ordering::Relaxed);
    }
}

impl MonotonicClock for TestMonotonicClock {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::Relaxed))
    }
}

#[derive(Debug)]
struct TestRandom(AtomicU64);

impl TestRandom {
    fn new(next: u64) -> Self {
        Self(AtomicU64::new(next))
    }
}

impl MaintenanceRandom for TestRandom {
    fn next_u64(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

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
        let mut id_material = payload.ciphertext.clone();
        id_material.extend_from_slice(recipient.as_slice());
        Ok(TransportMessage {
            id: hash_id(&id_material),
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
    session_with_registry(path, key, identity, FeatureRegistry::new())
}

fn current_session(
    path: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    identity: &[u8],
) -> AccountDeviceSession {
    let keys = deterministic_nostr_keys(identity);
    AccountDeviceSession::open(
        SessionConfig::new(
            path,
            SqlCipherKey::new(key.as_secret_str()).unwrap(),
            pad32(identity),
            Box::new(MockPeeler),
        )
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner { keys }))
        .protocol_profile(ProtocolProfile::Current),
    )
    .unwrap()
}

fn session_with_registry(
    path: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    identity: &[u8],
    registry: FeatureRegistry,
) -> AccountDeviceSession {
    session_with_registry_and_components(path, key, identity, registry, default_group_components())
}

fn session_with_registry_and_components(
    path: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    identity: &[u8],
    registry: FeatureRegistry,
    supported_app_components: std::collections::BTreeSet<
        cgka_traits::app_components::AppComponentId,
    >,
) -> AccountDeviceSession {
    let keys = deterministic_nostr_keys(identity);
    AccountDeviceSession::open(
        SessionConfig::new(
            path,
            SqlCipherKey::new(key.as_secret_str()).unwrap(),
            pad32(identity),
            Box::new(MockPeeler),
        )
        .legacy_compatibility_profile()
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner { keys }))
        .feature_registry(registry)
        .supported_app_components(supported_app_components),
    )
    .unwrap()
}

async fn welcome_for_key_package(
    inviter: &mut AccountDeviceSession,
    recipient: &MemberId,
    key_package: cgka_traits::engine::KeyPackage,
    name: &str,
) -> TransportMessage {
    let created = inviter
        .create_group(CreateGroupRequest {
            name: name.into(),
            description: String::new(),
            members: vec![key_package],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    match &created.effects.publish[0] {
        PublishWork::GroupCreated { welcomes, pending } => {
            inviter.confirm_published(*pending).await.unwrap();
            welcomes
                .iter()
                .find(|message| {
                    matches!(
                        &message.envelope,
                        TransportEnvelope::Welcome { recipient: addressed } if addressed == recipient
                    )
                })
                .expect("welcome addressed to key package owner")
                .clone()
        }
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    }
}

/// MIP-03 self-remove feature registration, mirroring the cgka-session
/// lifecycle test. Sending `SendIntent::Leave` as a non-last-admin produces a
/// remove **proposal**; when the admin ingests it, the engine auto-commits the
/// removal and emits a `PublishWork::AutoPublish` carrying a real pending ref.
fn selfremove_registry() -> FeatureRegistry {
    let mut registry = FeatureRegistry::new();
    registry.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    registry
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
    accepted_counts: Mutex<VecDeque<usize>>,
    publish_errors: Mutex<VecDeque<bool>>,
    reported_message_ids: Mutex<VecDeque<MessageId>>,
    timeout_pattern: Mutex<VecDeque<bool>>,
    welcome_gate: Mutex<Option<Arc<WelcomePublishGate>>>,
}

struct WelcomePublishGate {
    active: AtomicUsize,
    max_active: AtomicUsize,
    release: tokio::sync::Semaphore,
}

impl Default for WelcomePublishGate {
    fn default() -> Self {
        Self {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}

impl RecordingAdapter {
    fn gate_welcome_publishes(&self) -> Arc<WelcomePublishGate> {
        let gate = Arc::new(WelcomePublishGate::default());
        *self.inner.welcome_gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    fn accept_only_next(&self, accepted_count: usize) {
        self.accept_next(accepted_count);
    }

    fn accept_next(&self, accepted_count: usize) {
        self.inner
            .accepted_counts
            .lock()
            .unwrap()
            .push_back(accepted_count);
    }

    fn report_message_id_next(&self, message_id: MessageId) {
        self.inner
            .reported_message_ids
            .lock()
            .unwrap()
            .push_back(message_id);
    }

    fn timeout_pattern(&self, pattern: impl IntoIterator<Item = bool>) {
        self.inner.timeout_pattern.lock().unwrap().extend(pattern);
    }

    fn error_next(&self) {
        self.inner.publish_errors.lock().unwrap().push_back(true);
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
        let welcome_gate = if matches!(&request.message.envelope, TransportEnvelope::Welcome { .. })
        {
            self.inner.welcome_gate.lock().unwrap().clone()
        } else {
            None
        };
        if let Some(gate) = welcome_gate {
            let active = gate.active.fetch_add(1, Ordering::SeqCst) + 1;
            gate.max_active.fetch_max(active, Ordering::SeqCst);
            let permit = gate.release.acquire().await.unwrap();
            permit.forget();
            gate.active.fetch_sub(1, Ordering::SeqCst);
        }
        let timed_out = self
            .inner
            .timeout_pattern
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(false);
        let ambiguous_error = self
            .inner
            .publish_errors
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(false);
        if timed_out || ambiguous_error {
            return Err(TransportAdapterError::Publish(
                if timed_out {
                    "simulated timeout"
                } else {
                    "injected ambiguous adapter failure"
                }
                .into(),
            ));
        }
        let accepted_count = self
            .inner
            .accepted_counts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| request.target.endpoints().len());
        Ok(TransportPublishReport {
            message_id: self
                .inner
                .reported_message_ids
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(request.message.id),
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

#[derive(Clone)]
struct MismatchedPendingGroupRouting {
    wrong_group_id: GroupId,
    endpoint: TransportEndpoint,
}

impl TransportRoutingPolicy for MismatchedPendingGroupRouting {
    fn local_inbox_endpoints(&self) -> Vec<TransportEndpoint> {
        vec![self.endpoint.clone()]
    }

    fn key_package_endpoints(&self) -> Vec<TransportEndpoint> {
        vec![self.endpoint.clone()]
    }

    fn group_subscriptions(&self) -> Vec<cgka_traits::TransportGroupSubscription> {
        Vec::new()
    }

    fn publish_target(
        &self,
        message: &TransportMessage,
    ) -> Result<TransportPublishTarget, TransportRoutingError> {
        let transport_group_id = match &message.envelope {
            TransportEnvelope::GroupMessage { transport_group_id } => transport_group_id.clone(),
            TransportEnvelope::Welcome { .. } => {
                return Err(TransportRoutingError::MissingInboxRoute);
            }
        };
        Ok(TransportPublishTarget::Group {
            group_id: self.wrong_group_id.clone(),
            transport_group_id,
            endpoints: vec![self.endpoint.clone()],
        })
    }

    fn required_acks(&self, _target: &TransportPublishTarget) -> usize {
        1
    }
}

include!("runtime/frozen_fanout.rs");

#[derive(Clone, Default)]
struct RecordingKeyPackages {
    publications: Arc<Mutex<Vec<KeyPackagePublication>>>,
}

#[async_trait]
impl KeyPackagePublisher for RecordingKeyPackages {
    fn legacy_slot_id(
        &self,
        account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        Ok(Some(test_key_package_slot(account_id)))
    }

    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<cgka_traits::SignedPublicationArtifact, KeyPackagePublishError> {
        Ok(test_key_package_artifact(&publication))
    }

    async fn publish_prepared_key_package(
        &self,
        publication: &KeyPackagePublication,
        _artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication.clone());
        Ok(KeyPackagePublishReceipt {
            accepted: publication.endpoints.clone(),
            failed: Vec::new(),
        })
    }
}

impl RecordingKeyPackages {
    fn publications(&self) -> Vec<KeyPackagePublication> {
        self.publications.lock().unwrap().clone()
    }
}

#[derive(Clone, Default)]
struct PartialFanoutKeyPackages {
    publications: Arc<
        Mutex<
            Vec<(
                KeyPackagePublication,
                cgka_traits::SignedPublicationArtifact,
            )>,
        >,
    >,
}

impl PartialFanoutKeyPackages {
    fn publications(
        &self,
    ) -> Vec<(
        KeyPackagePublication,
        cgka_traits::SignedPublicationArtifact,
    )> {
        self.publications.lock().unwrap().clone()
    }
}

#[async_trait]
impl KeyPackagePublisher for PartialFanoutKeyPackages {
    fn legacy_slot_id(
        &self,
        account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        Ok(Some(test_key_package_slot(account_id)))
    }

    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<cgka_traits::SignedPublicationArtifact, KeyPackagePublishError> {
        Ok(test_key_package_artifact(&publication))
    }

    async fn publish_prepared_key_package(
        &self,
        publication: &KeyPackagePublication,
        artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        let call_index = self.publications.lock().unwrap().len();
        self.publications
            .lock()
            .unwrap()
            .push((publication.clone(), artifact.clone()));
        if call_index == 0 {
            Ok(KeyPackagePublishReceipt {
                accepted: publication.endpoints.iter().take(1).cloned().collect(),
                failed: publication.endpoints.iter().skip(1).cloned().collect(),
            })
        } else {
            Ok(KeyPackagePublishReceipt {
                accepted: publication.endpoints.clone(),
                failed: Vec::new(),
            })
        }
    }
}

#[derive(Clone, Default)]
struct PrepareFailsKeyPackages {
    preparations: Arc<Mutex<Vec<KeyPackagePublication>>>,
}

impl PrepareFailsKeyPackages {
    fn preparations(&self) -> Vec<KeyPackagePublication> {
        self.preparations.lock().unwrap().clone()
    }
}

#[async_trait]
impl KeyPackagePublisher for PrepareFailsKeyPackages {
    fn legacy_slot_id(
        &self,
        account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        Ok(Some(test_key_package_slot(account_id)))
    }

    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<cgka_traits::SignedPublicationArtifact, KeyPackagePublishError> {
        self.preparations.lock().unwrap().push(publication);
        Err(KeyPackagePublishError::unexposed(
            "injected pre-signing failure",
        ))
    }

    async fn publish_prepared_key_package(
        &self,
        _publication: &KeyPackagePublication,
        _artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        panic!("an unsigned replacement must never reach the network")
    }
}

/// Publisher that fails the first `fail_first` publish attempts, then succeeds,
/// recording every publication it is asked to send (including failed ones).
#[derive(Clone)]
struct FlakyKeyPackages {
    publications: Arc<Mutex<Vec<KeyPackagePublication>>>,
    remaining_failures: Arc<Mutex<usize>>,
}

impl FlakyKeyPackages {
    fn new(fail_first: usize) -> Self {
        Self {
            publications: Arc::new(Mutex::new(Vec::new())),
            remaining_failures: Arc::new(Mutex::new(fail_first)),
        }
    }

    fn publications(&self) -> Vec<KeyPackagePublication> {
        self.publications.lock().unwrap().clone()
    }
}

#[async_trait]
impl KeyPackagePublisher for FlakyKeyPackages {
    fn legacy_slot_id(
        &self,
        account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        Ok(Some(test_key_package_slot(account_id)))
    }

    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<cgka_traits::SignedPublicationArtifact, KeyPackagePublishError> {
        Ok(test_key_package_artifact(&publication))
    }

    async fn publish_prepared_key_package(
        &self,
        publication: &KeyPackagePublication,
        _artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication.clone());
        let mut remaining = self.remaining_failures.lock().unwrap();
        if *remaining > 0 {
            *remaining -= 1;
            return Err(KeyPackagePublishError::unexposed(
                "injected publish failure",
            ));
        }
        Ok(KeyPackagePublishReceipt {
            accepted: publication.endpoints.clone(),
            failed: Vec::new(),
        })
    }
}

/// Publisher that simulates the production `AppKeyPackagePublisher` failure
/// shape: it "publishes" to an external transport first and only then performs
/// a local step that fails. The returned error is therefore `externally_exposed`
/// — the KeyPackage may already be discoverable on a relay, so the runtime must
/// NOT prune the private bundle (mdk#160 adversarial review).
#[derive(Clone, Default)]
struct ExposedThenFailsKeyPackages {
    publications: Arc<Mutex<Vec<KeyPackagePublication>>>,
}

impl ExposedThenFailsKeyPackages {
    fn publications(&self) -> Vec<KeyPackagePublication> {
        self.publications.lock().unwrap().clone()
    }
}

#[async_trait]
impl KeyPackagePublisher for ExposedThenFailsKeyPackages {
    fn legacy_slot_id(
        &self,
        account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        Ok(Some(test_key_package_slot(account_id)))
    }

    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<cgka_traits::SignedPublicationArtifact, KeyPackagePublishError> {
        Ok(test_key_package_artifact(&publication))
    }

    async fn publish_prepared_key_package(
        &self,
        publication: &KeyPackagePublication,
        _artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication.clone());
        // External publish succeeded; a subsequent local step (e.g. cache write)
        // failed. The KeyPackage is already exposed.
        Err(KeyPackagePublishError::exposed(
            "injected post-exposure failure (e.g. local cache write)",
        ))
    }
}

fn test_key_package_artifact(
    publication: &KeyPackagePublication,
) -> cgka_traits::SignedPublicationArtifact {
    use sha2::{Digest, Sha256};
    let mut bytes = publication.key_package.bytes().to_vec();
    bytes.extend_from_slice(publication.slot_id.as_bytes());
    bytes.extend_from_slice(&publication.created_at.0.to_be_bytes());
    cgka_traits::SignedPublicationArtifact {
        id: MessageId::new(Sha256::digest(&bytes).to_vec()),
        created_at: publication.created_at,
        bytes,
    }
}

fn test_key_package_slot(account_id: &MemberId) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-account-test-key-package-slot-v1");
    hasher.update(account_id.as_slice());
    hex::encode(hasher.finalize())
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

    assert!(!key_package.bytes().is_empty());
    let publications = publisher.publications();
    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0].account_id, runtime.session().self_id());
    assert_eq!(publications[0].key_package, key_package);
    assert_eq!(
        publications[0].endpoints,
        vec![TransportEndpoint("wss://keys.example".into())]
    );
    assert_eq!(
        runtime.durably_owned_key_packages().unwrap(),
        vec![key_package],
        "a generated package is local only when its OpenMLS private bundle is present"
    );
}

#[tokio::test]
async fn automatic_maintenance_publication_preserves_private_material_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot automatic kp ownership key").unwrap();
    let publisher = RecordingKeyPackages::default();
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        publisher.clone(),
    );

    runtime.run_due_maintenance().await.unwrap();

    let published = publisher.publications();
    assert_eq!(published.len(), 1);
    assert_eq!(
        runtime.durably_owned_key_packages().unwrap(),
        vec![published[0].key_package.clone()]
    );
}

#[tokio::test]
async fn publication_without_durable_slot_authority_fails_before_bundle_generation() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot missing slot key").unwrap();
    let session = session(database.clone(), &key, b"alice");
    let policy = StaticTransportRouting::new(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        session,
        RecordingAdapter::default(),
        policy,
        NoopKeyPackagePublisher,
    );

    let error = runtime.publish_fresh_key_package().await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("provision a durable slot before publication")
    );
    drop(runtime);

    let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
    assert!(storage.stored_key_package_bundles().unwrap().is_empty());
    assert!(storage.key_package_lifecycle().unwrap().is_none());
}

#[tokio::test]
async fn publish_fresh_key_package_retries_the_same_durable_replacement() {
    // A prepared replacement is a durable publication obligation. A failed
    // attempt retains both the exact artifact and its private init key so a
    // retry cannot create a different externally visible package.
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp cleanup key").unwrap();
    let session = session(dir.path().join("alice.sqlite"), &key, b"alice");
    // Fail the first attempt, succeed thereafter.
    let publisher = FlakyKeyPackages::new(1);
    let policy = StaticTransportRouting::new(vec![TransportEndpoint("wss://inbox.example".into())])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        session,
        RecordingAdapter::default(),
        policy,
        publisher.clone(),
    );

    // First attempt: publisher fails, error propagates.
    let err = runtime
        .publish_fresh_key_package()
        .await
        .expect_err("publish failure must propagate");
    assert!(matches!(err, AccountError::KeyPackage(_)), "got {err:?}");

    // Retry: publication succeeds with the same prepared package.
    let key_package = runtime
        .publish_fresh_key_package()
        .await
        .expect("retry should publish successfully");
    assert!(!key_package.bytes().is_empty());

    let publications = publisher.publications();
    // One failed attempt + one successful attempt carry the same package,
    // slot, timestamp, and therefore the same signed artifact identity.
    assert_eq!(publications.len(), 2);
    assert_eq!(publications[0], publications[1]);
    assert_eq!(publications[1].key_package, key_package);
    assert_eq!(
        runtime.durably_owned_key_packages().unwrap(),
        vec![key_package],
        "publish failure and retry must retain the staged private bundle"
    );
}

#[tokio::test]
async fn unsigned_key_package_replacement_recovers_after_restart_without_changing_authorship() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot kp unsigned crash key").unwrap();
    let failing = PrepareFailsKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(10_000));
    let monotonic = Arc::new(TestMonotonicClock::default());
    let random = Arc::new(TestRandom::new(7));
    let policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        policy.clone(),
        failing.clone(),
    )
    .with_maintenance_sources(wall.clone(), monotonic.clone(), random.clone());

    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("injected signing failure must propagate");
    let prepared_before_crash = failing.preparations();
    assert_eq!(prepared_before_crash.len(), 1);
    let pending_before_crash = runtime
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .pending_replacement
        .unwrap();
    assert_eq!(
        runtime.durably_owned_key_packages().unwrap(),
        vec![pending_before_crash.key_package.clone()],
        "a failed publication remains locally owned"
    );
    assert!(pending_before_crash.signed_event.is_none());
    assert_eq!(
        pending_before_crash.authored_created_at,
        prepared_before_crash[0].created_at
    );
    drop(runtime);

    let succeeding = RecordingKeyPackages::default();
    let mut restarted = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        policy,
        succeeding.clone(),
    )
    .with_maintenance_sources(wall, monotonic, random);
    restarted
        .publish_fresh_key_package()
        .await
        .expect("restart must sign and publish the durable pending replacement");

    let published = succeeding.publications();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0], prepared_before_crash[0]);
    assert!(
        restarted
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .pending_replacement
            .is_none()
    );
    assert_eq!(
        restarted.durably_owned_key_packages().unwrap(),
        vec![published[0].key_package.clone()],
        "restart must preserve the private bundle used by the published event"
    );
}

#[tokio::test]
async fn missing_or_corrupt_private_bundle_is_not_reported_as_owned() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot missing private bundle key").unwrap();
    let mut runtime = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        RecordingKeyPackages::default(),
    );
    runtime.publish_fresh_key_package().await.unwrap();
    assert_eq!(runtime.durably_owned_key_packages().unwrap().len(), 1);
    drop(runtime);

    let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
    let bundles = storage.stored_key_package_bundles().unwrap();
    assert_eq!(bundles.len(), 1);
    storage
        .delete_stored_key_package_bundle(&bundles[0].storage_key)
        .unwrap();
    drop(storage);

    let reopened = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        RecordingKeyPackages::default(),
    );
    assert!(
        reopened.durably_owned_key_packages().unwrap().is_empty(),
        "lifecycle metadata alone must not imply local ownership"
    );

    let corrupt_database = dir.path().join("corrupt.sqlite");
    let corrupt_key_text = "marmot corrupt private bundle key";
    let corrupt_key = SqlCipherKey::new(corrupt_key_text).unwrap();
    let mut corrupt_runtime = AccountDeviceRuntime::new(
        session(corrupt_database.clone(), &corrupt_key, b"corrupt-alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        RecordingKeyPackages::default(),
    );
    corrupt_runtime.publish_fresh_key_package().await.unwrap();
    assert_eq!(
        corrupt_runtime.durably_owned_key_packages().unwrap().len(),
        1
    );
    drop(corrupt_runtime);

    let connection = rusqlite::Connection::open(&corrupt_database).unwrap();
    connection
        .pragma_update(None, "key", corrupt_key_text)
        .unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE openmls_values
                 SET value = x'00'
                 WHERE label = x'4b65795061636b616765'",
                [],
            )
            .unwrap(),
        1
    );
    drop(connection);

    let reopened_corrupt = AccountDeviceRuntime::new(
        session(corrupt_database, &corrupt_key, b"corrupt-alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        RecordingKeyPackages::default(),
    );
    assert!(
        reopened_corrupt
            .durably_owned_key_packages()
            .unwrap()
            .is_empty(),
        "corrupt private material must fail closed instead of inheriting lifecycle ownership"
    );
}

#[tokio::test]
async fn key_package_rotation_reuses_stable_slot_and_monotonically_advances_created_at() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp stable slot key").unwrap();
    let publisher = RecordingKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(20_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(11)),
    );

    let first = runtime.publish_fresh_key_package().await.unwrap();
    let second = runtime.publish_fresh_key_package().await.unwrap();
    let publications = publisher.publications();
    assert_eq!(publications.len(), 2);
    assert_eq!(publications[0].slot_id, publications[1].slot_id);
    assert_eq!(
        publications[1].created_at.0,
        publications[0].created_at.0 + 1
    );
    assert_ne!(first, second);

    let lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(lifecycle.retained_private_material.len(), 1);
    assert_eq!(
        lifecycle.retained_private_material[0].key_package,
        publications[0].key_package
    );
}

#[tokio::test]
async fn key_package_first_ack_promotes_then_paused_maintenance_finishes_exact_fanout() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp independent fanout key").unwrap();
    let database = dir.path().join("alice.sqlite");
    let publisher = PartialFanoutKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(70_000));
    let routing = StaticTransportRouting::new(vec![]).key_package_endpoints(vec![
        TransportEndpoint("wss://keys-a.example".into()),
        TransportEndpoint("wss://keys-b.example".into()),
    ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(23)),
    );

    runtime
        .publish_fresh_key_package()
        .await
        .expect("first relay acknowledgement promotes the replacement");
    let promoted = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(promoted.pending_replacement.is_none());
    assert_eq!(
        promoted
            .publication_targets
            .iter()
            .filter(|target| { target.state == cgka_traits::TransportFanoutAttemptState::Accepted })
            .count(),
        1
    );
    assert_eq!(
        promoted
            .publication_targets
            .iter()
            .filter(|target| {
                target.state == cgka_traits::TransportFanoutAttemptState::AttemptedFailed
            })
            .count(),
        1
    );

    drop(runtime);
    let mut restarted = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        routing,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(23)),
    );
    restarted.pause_maintenance();
    wall.set(70_030);
    restarted.run_due_maintenance().await.unwrap();
    let calls = publisher.publications();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].1, calls[1].1);
    assert_eq!(calls[0].0.slot_id, calls[1].0.slot_id);
    assert_eq!(calls[0].0.created_at, calls[1].0.created_at);
    assert_eq!(
        calls[1].0.endpoints,
        vec![TransportEndpoint("wss://keys-b.example".into())]
    );
    let completed = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(completed.phase, cgka_traits::MaintenancePhase::Complete);
    assert!(
        completed
            .publication_targets
            .iter()
            .all(|target| { target.state == cgka_traits::TransportFanoutAttemptState::Accepted })
    );
}

#[tokio::test]
async fn republish_key_package_resends_exact_authored_event_and_finishes_partial_fanout() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp republish key").unwrap();
    let database = dir.path().join("alice.sqlite");
    let publisher = PartialFanoutKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(70_000));
    let routing = StaticTransportRouting::new(vec![]).key_package_endpoints(vec![
        TransportEndpoint("wss://keys-a.example".into()),
        TransportEndpoint("wss://keys-b.example".into()),
    ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(23)),
    );

    runtime
        .publish_fresh_key_package()
        .await
        .expect("initial rotation promotes a current package");
    let promoted = runtime.key_package_maintenance_status().unwrap().unwrap();
    let authored_event = promoted.authored_signed_event.clone().unwrap();
    let current_ref = promoted.current_key_package_ref.clone().unwrap();
    let durable_bundle_count = runtime.durably_owned_key_packages().unwrap().len();
    wall.set(promoted.current_not_before.unwrap().0);

    runtime
        .republish_key_package()
        .await
        .expect("explicit republish must reuse the current authored event");
    let after_republish = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(after_republish.stable_slot_id, promoted.stable_slot_id);
    assert_eq!(
        after_republish.authored_signed_event,
        Some(authored_event.clone())
    );
    assert_eq!(
        after_republish.authored_event_id,
        promoted.authored_event_id
    );
    assert_eq!(
        after_republish.authored_event_created_at,
        promoted.authored_event_created_at
    );
    assert_eq!(
        after_republish.current_key_package_ref,
        Some(current_ref.clone())
    );
    assert!(after_republish.pending_replacement.is_none());
    assert_eq!(
        after_republish.retained_private_material,
        promoted.retained_private_material
    );
    assert_eq!(
        runtime.durably_owned_key_packages().unwrap().len(),
        durable_bundle_count,
        "republish must not mint or prune durable private bundles"
    );

    let calls = publisher.publications();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].1, calls[1].1);
    assert_eq!(calls[0].0.slot_id, calls[1].0.slot_id);
    assert_eq!(calls[0].0.created_at, calls[1].0.created_at);
    assert_eq!(
        calls[1].0.endpoints,
        vec![
            TransportEndpoint("wss://keys-a.example".into()),
            TransportEndpoint("wss://keys-b.example".into()),
        ]
    );
    let completed = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(completed.phase, cgka_traits::MaintenancePhase::Complete);
    assert!(
        completed
            .publication_targets
            .iter()
            .all(|target| { target.state == cgka_traits::TransportFanoutAttemptState::Accepted })
    );

    drop(runtime);
    let mut restarted = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        routing,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(23)),
    );
    restarted
        .republish_key_package()
        .await
        .expect("restart republish must reuse the durable authored event");
    let calls = publisher.publications();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[2].1, authored_event);
    assert_eq!(
        calls[2].0.endpoints,
        vec![
            TransportEndpoint("wss://keys-a.example".into()),
            TransportEndpoint("wss://keys-b.example".into()),
        ]
    );
    let after_restart = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(after_restart.stable_slot_id, promoted.stable_slot_id);
    assert_eq!(after_restart.authored_signed_event, Some(authored_event));
    assert_eq!(after_restart.authored_event_id, promoted.authored_event_id);
    assert_eq!(
        after_restart.authored_event_created_at,
        promoted.authored_event_created_at
    );
    assert_eq!(after_restart.current_key_package_ref, Some(current_ref));
    assert_eq!(
        after_restart.retained_private_material,
        promoted.retained_private_material
    );
    assert_eq!(
        restarted.durably_owned_key_packages().unwrap().len(),
        durable_bundle_count,
        "restart republish must not mint or prune durable private bundles"
    );
}

#[tokio::test]
async fn republish_key_package_rejects_pending_replacement_without_publishing() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot kp pending republish key").unwrap();
    let policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let initial_publisher = RecordingKeyPackages::default();
    let mut initial = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        policy.clone(),
        initial_publisher,
    );
    initial.publish_fresh_key_package().await.unwrap();
    drop(initial);

    let flaky = FlakyKeyPackages::new(1);
    let mut runtime = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        policy,
        flaky.clone(),
    );
    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("replacement attempt must fail before acknowledgement");
    let before = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(before.pending_replacement.is_some());
    let durable_before = runtime.durably_owned_key_packages().unwrap();

    let error = runtime
        .republish_key_package()
        .await
        .expect_err("republish must not advance a pending replacement");
    assert!(matches!(error, AccountError::KeyPackageRotationInProgress));
    assert_eq!(
        flaky.publications().len(),
        1,
        "only the failed rotation attempt may publish"
    );
    let after = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(after, before);
    assert_eq!(
        runtime.durably_owned_key_packages().unwrap(),
        durable_before
    );
}

#[tokio::test]
async fn republish_key_package_falls_back_when_no_current_artifact_exists() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot kp no artifact republish key").unwrap();
    let publisher = RecordingKeyPackages::default();
    let policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let session = session(database, &key, b"alice");
    let slot = publisher
        .legacy_slot_id(&session.self_id())
        .unwrap()
        .unwrap();
    session
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(slot))
        .unwrap();
    let mut runtime = AccountDeviceRuntime::new(
        session,
        RecordingAdapter::default(),
        policy,
        publisher.clone(),
    );

    let key_package = runtime
        .republish_key_package()
        .await
        .expect("republish must fall back to fresh publication");
    assert!(!key_package.bytes().is_empty());
    let publications = publisher.publications();
    assert_eq!(publications.len(), 1);
    let lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        lifecycle.current_key_package_ref,
        Some(
            hex::decode(
                cgka_engine::key_package::key_package_metadata(&key_package)
                    .unwrap()
                    .key_package_ref_hex
            )
            .unwrap()
        )
    );
    assert!(lifecycle.pending_replacement.is_none());
    assert!(lifecycle.authored_signed_event.is_some());
}

#[tokio::test]
async fn republish_key_package_reuses_current_artifact_when_refresh_is_due() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp refresh due republish key").unwrap();
    let publisher = RecordingKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(90_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(17)),
    );

    let first = runtime.publish_fresh_key_package().await.unwrap();
    let before = runtime.key_package_maintenance_status().unwrap().unwrap();
    let durable_before = runtime.durably_owned_key_packages().unwrap();
    let refresh_at = before.refresh_at.unwrap();
    wall.set(refresh_at.0);

    let second = runtime.republish_key_package().await.unwrap();
    let publications = publisher.publications();
    assert_eq!(publications.len(), 2);
    assert_eq!(first, second);
    assert_eq!(publications[0], publications[1]);
    let after = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        after.current_key_package_ref,
        before.current_key_package_ref
    );
    assert_eq!(after.authored_event_id, before.authored_event_id);
    assert_eq!(
        after.authored_event_created_at,
        before.authored_event_created_at
    );
    assert_eq!(after.authored_signed_event, before.authored_signed_event);
    assert_eq!(
        after.retained_private_material,
        before.retained_private_material
    );
    assert_eq!(
        runtime.durably_owned_key_packages().unwrap(),
        durable_before,
        "refresh-due republish must not mint or prune durable private bundles"
    );
}

#[tokio::test]
async fn republish_key_package_falls_back_when_current_ref_is_consumed() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp consumed republish key").unwrap();
    let publisher = RecordingKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(90_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(17)),
    );

    let first = runtime.publish_fresh_key_package().await.unwrap();
    let mut lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    let consumed_ref = lifecycle.current_key_package_ref.clone().unwrap();
    lifecycle.last_consumed_key_package_ref = Some(consumed_ref.clone());
    lifecycle.last_consumed_at = Some(Timestamp(42));
    runtime
        .session()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    wall.set(lifecycle.current_not_before.unwrap().0);

    let second = runtime.republish_key_package().await.unwrap();
    let publications = publisher.publications();
    assert_eq!(publications.len(), 2);
    assert_ne!(first, second);
    let after = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_ne!(after.current_key_package_ref, Some(consumed_ref));
    assert!(after.last_consumed_key_package_ref.is_none());
    assert_eq!(after.retained_private_material.len(), 0);
}

#[tokio::test]
async fn republish_key_package_reconciles_authoritative_targets_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp routing reconcile key").unwrap();
    let database = dir.path().join("alice.sqlite");
    let publisher = PartialFanoutKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(70_000));
    let initial_routing = StaticTransportRouting::new(vec![]).key_package_endpoints(vec![
        TransportEndpoint("wss://keys-a.example".into()),
        TransportEndpoint("wss://keys-b.example".into()),
    ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        initial_routing,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(23)),
    );

    runtime.publish_fresh_key_package().await.unwrap();
    let promoted = runtime.key_package_maintenance_status().unwrap().unwrap();
    wall.set(promoted.current_not_before.unwrap().0);
    let authored_event = promoted.authored_signed_event.clone().unwrap();
    drop(runtime);

    let updated_routing = StaticTransportRouting::new(vec![]).key_package_endpoints(vec![
        TransportEndpoint("wss://keys-a.example".into()),
        TransportEndpoint("wss://keys-c.example".into()),
    ]);
    let mut restarted = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        updated_routing,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(23)),
    );
    restarted.republish_key_package().await.unwrap();

    let calls = publisher.publications();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].1, authored_event);
    assert_eq!(
        calls[1].0.endpoints,
        vec![
            TransportEndpoint("wss://keys-a.example".into()),
            TransportEndpoint("wss://keys-c.example".into()),
        ]
    );
    let completed = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(completed.phase, cgka_traits::MaintenancePhase::Complete);
    let removed = completed
        .publication_targets
        .iter()
        .find(|target| target.endpoint == TransportEndpoint("wss://keys-b.example".into()))
        .expect("removed endpoint history must be retained");
    assert_eq!(
        removed.state,
        cgka_traits::TransportFanoutAttemptState::PolicyProhibited
    );
    let reauthorized = completed
        .publication_targets
        .iter()
        .find(|target| target.endpoint == TransportEndpoint("wss://keys-c.example".into()))
        .expect("new authoritative endpoint must be tracked");
    assert_eq!(
        reauthorized.state,
        cgka_traits::TransportFanoutAttemptState::Accepted
    );
}

#[tokio::test]
async fn republish_key_package_reauthorizes_previously_removed_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp routing reauthorize key").unwrap();
    let database = dir.path().join("alice.sqlite");
    let publisher = RecordingKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(70_000));
    let two_targets = StaticTransportRouting::new(vec![]).key_package_endpoints(vec![
        TransportEndpoint("wss://keys-a.example".into()),
        TransportEndpoint("wss://keys-b.example".into()),
    ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        two_targets,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(23)),
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let promoted = runtime.key_package_maintenance_status().unwrap().unwrap();
    wall.set(promoted.current_not_before.unwrap().0);
    drop(runtime);

    let one_target = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys-a.example".into())]);
    let mut removed = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        one_target,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(23)),
    );
    removed.republish_key_package().await.unwrap();
    let prohibited = removed
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .publication_targets
        .iter()
        .find(|target| target.endpoint == TransportEndpoint("wss://keys-b.example".into()))
        .expect("removed endpoint must remain durable")
        .state;
    assert_eq!(
        prohibited,
        cgka_traits::TransportFanoutAttemptState::PolicyProhibited
    );
    drop(removed);

    let mut restored = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![
            TransportEndpoint("wss://keys-a.example".into()),
            TransportEndpoint("wss://keys-b.example".into()),
        ]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(23)),
    );
    restored.republish_key_package().await.unwrap();
    let restored_lifecycle = restored.key_package_maintenance_status().unwrap().unwrap();
    let reauthorized = restored_lifecycle
        .publication_targets
        .iter()
        .find(|target| target.endpoint == TransportEndpoint("wss://keys-b.example".into()))
        .expect("reauthorized endpoint must be retained");
    assert_eq!(
        reauthorized.state,
        cgka_traits::TransportFanoutAttemptState::Accepted
    );
    assert_eq!(reauthorized.attempt_count, 1);
    assert!(reauthorized.failure_code.is_none());
}

#[tokio::test]
async fn republish_key_package_persists_policy_removal_when_no_targets_remain() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp empty routing republish key").unwrap();
    let database = dir.path().join("alice.sqlite");
    let publisher = RecordingKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(70_000));
    let initial_routing = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        initial_routing,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(23)),
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let promoted = runtime.key_package_maintenance_status().unwrap().unwrap();
    wall.set(promoted.current_not_before.unwrap().0);
    drop(runtime);

    let mut no_targets = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(23)),
    );

    no_targets
        .republish_key_package()
        .await
        .expect_err("republish without authoritative targets must fail");
    assert_eq!(
        publisher.publications().len(),
        1,
        "empty policy must not trigger a publication"
    );
    let lifecycle = no_targets
        .key_package_maintenance_status()
        .unwrap()
        .unwrap();
    assert!(lifecycle.publication_targets.iter().all(|target| {
        target.state == cgka_traits::TransportFanoutAttemptState::PolicyProhibited
            && target.failure_code.as_deref() == Some("endpoint_removed_from_policy")
    }));
}

#[tokio::test]
async fn key_package_expiry_sweep_deletes_private_material_while_network_maintenance_is_paused() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp paused expiry key").unwrap();
    let wall = Arc::new(TestWallClock::new(80_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(29)),
    );

    runtime.publish_fresh_key_package().await.unwrap();
    let not_after = runtime
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .current_not_after
        .unwrap();

    runtime.pause_maintenance();
    wall.set(not_after.0);
    assert_eq!(
        runtime
            .sweep_expired_key_package_private_material()
            .unwrap(),
        1
    );

    let expired = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(expired.current_key_package.is_none());
    assert!(expired.current_key_package_ref.is_none());
    assert!(expired.authored_signed_event.is_none());
    assert!(expired.publication_targets.is_empty());
    assert!(runtime.key_package_network_maintenance_due().unwrap());
}

#[tokio::test]
async fn key_package_rotation_blocks_when_clock_rollback_exceeds_future_skew_allowance() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp rollback key").unwrap();
    let publisher = RecordingKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(50_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(19)),
    );

    runtime.publish_fresh_key_package().await.unwrap();
    wall.set(1);
    let error = runtime
        .publish_fresh_key_package()
        .await
        .expect_err("large rollback must not escape through a new routine slot");
    assert!(matches!(error, AccountError::ClockSkewBlocked));
    assert_eq!(publisher.publications().len(), 1);
    let lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        lifecycle.phase,
        cgka_traits::MaintenancePhase::ClockSkewBlocked
    );
    assert!(lifecycle.pending_replacement.is_none());
}

#[tokio::test]
async fn consumed_last_resort_private_material_survives_pending_replacement_then_deletes_on_ack() {
    let dir = tempfile::tempdir().unwrap();
    let alice_database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot consumed kp lifecycle key").unwrap();
    let initial_publisher = RecordingKeyPackages::default();
    let initial_policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut initial = AccountDeviceRuntime::new(
        session(alice_database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        initial_policy.clone(),
        initial_publisher.clone(),
    );
    let old_key_package = initial.publish_fresh_key_package().await.unwrap();
    let alice_id = initial.session().self_id();
    drop(initial);

    // These invites are all prepared while the old last-resort KeyPackage is
    // still publicly discoverable.
    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let mut carol = session(dir.path().join("carol.sqlite"), &key, b"carol");
    let mut dave = session(dir.path().join("dave.sqlite"), &key, b"dave");
    let bob_welcome =
        welcome_for_key_package(&mut bob, &alice_id, old_key_package.clone(), "bob invite").await;
    let carol_welcome = welcome_for_key_package(
        &mut carol,
        &alice_id,
        old_key_package.clone(),
        "carol invite",
    )
    .await;
    let dave_welcome =
        welcome_for_key_package(&mut dave, &alice_id, old_key_package.clone(), "dave invite").await;

    let replacement_publisher = FlakyKeyPackages::new(1);
    let mut runtime = AccountDeviceRuntime::new(
        session(alice_database, &key, b"alice"),
        RecordingAdapter::default(),
        initial_policy,
        replacement_publisher,
    );
    runtime.session_mut().ingest(bob_welcome).await.unwrap();
    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("first replacement attempt is intentionally unacknowledged");

    // A Welcome already in flight remains processable for as long as the
    // replacement publication has not been acknowledged.
    runtime
        .session_mut()
        .ingest(carol_welcome)
        .await
        .expect("old private material must survive a pending replacement");

    runtime
        .publish_fresh_key_package()
        .await
        .expect("replacement acknowledgement must promote atomically");
    let lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(lifecycle.last_consumed_key_package_ref.is_none());
    assert!(
        lifecycle
            .retained_private_material
            .iter()
            .all(|material| material.key_package != old_key_package)
    );

    // Once the replacement is acknowledged the old init key is gone, so a
    // third prebuilt Welcome cannot consume it.
    let rejected = runtime
        .session_mut()
        .ingest(dave_welcome)
        .await
        .expect("missing private material is a classified rejection");
    assert!(matches!(
        rejected.outcome,
        cgka_traits::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::InvalidEncoding
        }
    ));
}

#[tokio::test]
async fn publish_fresh_key_package_retains_bundle_when_publish_fails_after_exposure() {
    // mdk#160 adversarial review: the orphan-cleanup must NOT prune the
    // private bundle when the publisher fails *after* the KeyPackage may already
    // be externally exposed (e.g. the production AppKeyPackagePublisher publishes
    // to a relay first, then fails on a local cache write). Pruning there would
    // leave a remotely discoverable but unjoinable KeyPackage: an inviter could
    // build a Welcome against the published event, but this account could never
    // join because the matching private bundle was deleted.
    //
    // This test proves retention end-to-end: after an exposed publish failure,
    // a peer builds a real group + Welcome against the just-generated KeyPackage,
    // and the account successfully joins it — which is only possible if the
    // private bundle survived in storage.
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot kp exposed retain key").unwrap();
    let publisher = ExposedThenFailsKeyPackages::default();
    let policy = StaticTransportRouting::new(vec![TransportEndpoint("wss://inbox.example".into())])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let mut alice_runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        policy,
        publisher.clone(),
    );

    // Publication fails after exposure; the error propagates but the bundle is
    // retained rather than pruned.
    let err = alice_runtime
        .publish_fresh_key_package()
        .await
        .expect_err("exposed publish failure must propagate");
    assert!(matches!(err, AccountError::KeyPackage(_)), "got {err:?}");

    // Recover the exact KeyPackage that was generated (and exposed). The
    // publisher recorded it on the failed attempt.
    let publications = publisher.publications();
    assert_eq!(publications.len(), 1);
    let alice_kp = publications[0].key_package.clone();

    // A peer builds a real group + Welcome against Alice's published KeyPackage.
    let mut bob_session = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let created = bob_session
        .create_group(CreateGroupRequest {
            name: "retained-bundle group".into(),
            description: "".into(),
            members: vec![alice_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match &created.effects.publish[0] {
        PublishWork::GroupCreated { welcomes, pending } => {
            bob_session.confirm_published(*pending).await.unwrap();
            welcomes
                .iter()
                .find(|msg| {
                    matches!(
                        &msg.envelope,
                        TransportEnvelope::Welcome { recipient }
                            if recipient == &alice_runtime.session().self_id()
                    )
                })
                .cloned()
                .expect("welcome addressed to alice")
        }
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };

    // Alice joins via the Welcome. This succeeds ONLY because the private bundle
    // was retained: if the cleanup had pruned it, OpenMLS would find no matching
    // KeyPackage for the Welcome's hash ref and the join would fail.
    let joined = alice_runtime
        .session_mut()
        .ingest(welcome)
        .await
        .expect("join must succeed because the private bundle was retained");
    assert!(
        joined.effects.events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupJoined { group_id, .. } if group_id == &created.group_id
        )),
        "expected GroupJoined event, got {:?}",
        joined.effects.events
    );
    assert_eq!(
        alice_runtime
            .session()
            .members(&created.group_id)
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn post_join_rotation_does_not_block_application_send_and_returns_disposition() {
    let dir = tempfile::tempdir().unwrap();
    let alice_database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot post join send key").unwrap();
    let mut alice = session(alice_database.clone(), &key, b"alice");
    let alice_kp = alice.fresh_key_package().await.unwrap();
    let alice_id = alice.self_id();
    let alice_hex = hex::encode(alice_id.as_slice());
    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let created = bob
        .create_group(CreateGroupRequest {
            name: "post-join pending send".into(),
            description: String::new(),
            members: vec![alice_kp],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let welcome = match &created.effects.publish[0] {
        PublishWork::GroupCreated { welcomes, pending } => {
            bob.confirm_published(*pending).await.unwrap();
            welcomes
                .iter()
                .find(|message| {
                    matches!(
                        &message.envelope,
                        TransportEnvelope::Welcome { recipient } if recipient == &alice_id
                    )
                })
                .unwrap()
                .clone()
        }
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.ingest(welcome.clone()).await.unwrap();
    alice
        .ingest(welcome)
        .await
        .expect("Welcome replay is classified without duplicating maintenance");
    let group_id = created.group_id;
    let obligations = alice.maintenance_obligations().unwrap();
    assert_eq!(obligations.len(), 1);
    assert_eq!(
        obligations[0].trigger,
        cgka_traits::MaintenanceTrigger::PostJoin
    );
    assert_eq!(obligations[0].phase, cgka_traits::MaintenancePhase::CatchUp);
    let joined_at = obligations[0].created_at.0;
    drop(alice);

    let wall = Arc::new(TestWallClock::new(joined_at.saturating_add(1)));
    let monotonic = Arc::new(TestMonotonicClock::default());
    let mut runtime = AccountDeviceRuntime::new(
        session(alice_database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![TransportEndpoint("wss://group.example".into())],
        ),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        monotonic.clone(),
        Arc::new(TestRandom::new(31)),
    );
    runtime
        .mark_post_join_subscription_installed(&group_id)
        .unwrap();
    let first_deadline = runtime.maintenance_status(&group_id).unwrap().obligations[0]
        .eose_deadline_at
        .unwrap();
    wall.set(joined_at.saturating_add(100));
    runtime
        .mark_post_join_subscription_installed(&group_id)
        .unwrap();
    assert_eq!(
        runtime.maintenance_status(&group_id).unwrap().obligations[0].eose_deadline_at,
        Some(first_deadline),
        "restart/reinstallation must not extend the persisted EOSE deadline"
    );

    wall.set(first_deadline.0);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        runtime.maintenance_status(&group_id).unwrap().obligations[0].phase,
        cgka_traits::MaintenancePhase::EoseTimeout
    );

    let effects = runtime
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice_hex, b"send while rotation is pending"),
        })
        .await
        .expect("post-join maintenance must not block application sends");
    assert_eq!(
        effects.maintenance_disposition,
        cgka_traits::SendMaintenanceDisposition::PostJoinRotationPendingRetryable
    );
    assert_eq!(effects.published_app_messages.len(), 1);

    runtime.mark_post_join_eose(&group_id).unwrap();
    let grace = runtime.maintenance_status(&group_id).unwrap().obligations[0].clone();
    assert_eq!(grace.phase, cgka_traits::MaintenancePhase::Grace);
    wall.set(grace.grace_until.unwrap().0);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        runtime.maintenance_status(&group_id).unwrap().obligations[0].phase,
        cgka_traits::MaintenancePhase::Quiet
    );

    monotonic.set_millis(60_000);
    wall.set(wall.now().0.saturating_add(60));
    runtime.run_due_maintenance().await.unwrap();
    let jitter = runtime.maintenance_status(&group_id).unwrap().obligations[0].clone();
    assert_eq!(jitter.phase, cgka_traits::MaintenancePhase::Jitter);
    wall.set(jitter.not_before.unwrap().0);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        runtime.maintenance_status(&group_id).unwrap().obligations[0].phase,
        cgka_traits::MaintenancePhase::Complete
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
    assert_eq!(runtime.own_leaf_index(&group_id).unwrap(), 0);
    let publishes = adapter.publishes();
    assert_eq!(publishes.len(), 1);
    assert_eq!(
        publishes[0].target.endpoints(),
        &[TransportEndpoint("wss://bob-inbox.example".into())]
    );
}

#[tokio::test]
async fn manual_self_update_confirms_on_first_ack_and_finishes_exact_event_fanout() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot manual maintenance key").unwrap();
    let initial_runtime = AccountDeviceRuntime::new(
        current_session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        RecordingKeyPackages::default(),
    );
    let mut initial_runtime = initial_runtime;
    let (group_id, created) = initial_runtime
        .create_group(CreateGroupRequest {
            name: "manual-only group".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    assert!(created.failures.is_empty());
    let mut maintenance_state = initial_runtime
        .session()
        .group_maintenance(&group_id)
        .unwrap()
        .unwrap();
    maintenance_state.periodic_enrolled = false;
    maintenance_state.next_periodic_rotation_at = None;
    initial_runtime
        .session()
        .put_group_maintenance(&maintenance_state)
        .unwrap();
    let source_epoch = initial_runtime.session().epoch(&group_id).unwrap();
    drop(initial_runtime);

    let adapter = RecordingAdapter::default();
    adapter.accept_only_next(1);
    let wall = Arc::new(TestWallClock::new(100_000));
    let monotonic = Arc::new(TestMonotonicClock::default());
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database, &key, b"alice"),
        adapter.clone(),
        StaticTransportRouting::new(vec![])
            .required_acks(2)
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![
                    TransportEndpoint("wss://group-a.example".into()),
                    TransportEndpoint("wss://group-b.example".into()),
                ],
            ),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        monotonic.clone(),
        Arc::new(TestRandom::new(0)),
    );

    let obligation_id = runtime.schedule_manual_self_update(&group_id).unwrap();
    assert_eq!(
        runtime.schedule_manual_self_update(&group_id).unwrap(),
        obligation_id,
        "an active semantic leaf-rotation obligation must coalesce manual requests"
    );
    assert_eq!(
        runtime
            .maintenance_status(&group_id)
            .unwrap()
            .obligations
            .len(),
        1
    );
    runtime.pause_maintenance();
    assert_eq!(
        runtime.maintenance_status(&group_id).unwrap().obligations[0].phase,
        cgka_traits::MaintenancePhase::Paused
    );
    runtime.resume_maintenance();
    assert_eq!(
        runtime.maintenance_status(&group_id).unwrap().obligations[0].phase,
        cgka_traits::MaintenancePhase::Quiet,
        "pause projection must not overwrite the durable resumable phase"
    );
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(runtime.session().epoch(&group_id).unwrap(), source_epoch);

    monotonic.set_millis(60_000);
    wall.set(100_060);
    runtime.run_due_maintenance().await.unwrap();
    let jittered = runtime
        .session()
        .maintenance_obligation(&obligation_id)
        .unwrap()
        .unwrap();
    assert_eq!(jittered.phase, cgka_traits::MaintenancePhase::Jitter);
    wall.set(jittered.not_before.unwrap().0);

    let effects = runtime.run_due_maintenance().await.unwrap();
    assert!(
        effects
            .pending
            .iter()
            .any(|resolution| matches!(resolution, PendingResolution::Confirmed { .. }))
    );
    assert_eq!(
        runtime.session().epoch(&group_id).unwrap().0,
        source_epoch.0 + 1
    );
    assert_eq!(
        runtime
            .session()
            .maintenance_obligation(&obligation_id)
            .unwrap()
            .unwrap()
            .phase,
        cgka_traits::MaintenancePhase::Complete
    );
    assert!(
        !runtime
            .session()
            .group_maintenance(&group_id)
            .unwrap()
            .unwrap()
            .periodic_enrolled,
        "manual success must not enroll an existing/manual-only group"
    );

    wall.set(wall.now().0.saturating_add(30));
    runtime.run_due_maintenance().await.unwrap();
    let publishes = adapter.publishes();
    assert_eq!(publishes.len(), 2);
    assert_eq!(publishes[0].message, publishes[1].message);
    assert_eq!(publishes[0].target.endpoints().len(), 2);
    assert_eq!(publishes[1].target.endpoints().len(), 1);
    let fanout = runtime
        .session()
        .transport_fanouts()
        .unwrap()
        .into_iter()
        .find(|fanout| fanout.id == publishes[0].message.id)
        .unwrap();
    assert!(fanout.evolution_confirmed);
    assert!(
        fanout
            .targets
            .iter()
            .all(|target| { target.state == cgka_traits::TransportFanoutAttemptState::Accepted })
    );
}

#[tokio::test]
async fn ambiguous_self_update_exposure_survives_restart_and_respects_retry_backoff() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot ambiguous self update key").unwrap();
    let database = dir.path().join("alice.sqlite");
    let mut initial = current_session(database.clone(), &key, b"alice");
    let created = initial
        .create_group(CreateGroupRequest {
            name: "ambiguous self update".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let source_epoch = initial.epoch(&group_id).unwrap();
    drop(initial);

    let adapter = RecordingAdapter::default();
    adapter.error_next();
    let routing =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://inbox.example".into())])
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![TransportEndpoint("wss://group.example".into())],
            );
    let wall = Arc::new(TestWallClock::new(120_000));
    let monotonic = Arc::new(TestMonotonicClock::default());
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database.clone(), &key, b"alice"),
        adapter.clone(),
        routing.clone(),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        monotonic.clone(),
        Arc::new(TestRandom::new(0)),
    );

    let obligation_id = runtime.schedule_manual_self_update(&group_id).unwrap();
    runtime.run_due_maintenance().await.unwrap();
    monotonic.set_millis(60_000);
    wall.set(120_060);
    runtime.run_due_maintenance().await.unwrap();
    let jittered = runtime
        .session()
        .maintenance_obligation(&obligation_id)
        .unwrap()
        .unwrap();
    wall.set(jittered.not_before.unwrap().0);
    let effects = runtime.run_due_maintenance().await.unwrap();

    assert_eq!(adapter.publishes().len(), 1);
    let fanout = runtime.session().transport_fanouts().unwrap().remove(0);
    assert!(fanout.possible_exposure);
    assert!(!fanout.evolution_confirmed);
    assert_eq!(
        fanout.targets[0].state,
        cgka_traits::TransportFanoutAttemptState::AttemptedFailed
    );
    assert_eq!(
        runtime
            .session()
            .maintenance_obligation(&obligation_id)
            .unwrap()
            .unwrap()
            .phase,
        cgka_traits::MaintenancePhase::PendingPublication
    );
    let summary = runtime.maintenance_run_summary(&effects).unwrap();
    assert_eq!(summary.deferred, 1);
    assert_eq!(summary.ambiguous_exposure, 1);
    runtime.note_valid_state_bearing_input(&group_id).unwrap();
    assert_eq!(
        runtime
            .session()
            .maintenance_obligation(&obligation_id)
            .unwrap()
            .unwrap()
            .phase,
        cgka_traits::MaintenancePhase::PendingPublication,
        "valid inbound state must not demote exact-event recovery to a fresh quiet window"
    );
    drop(runtime);

    let mut restarted = AccountDeviceRuntime::new(
        current_session(database, &key, b"alice"),
        adapter.clone(),
        routing,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );

    restarted.run_due_maintenance().await.unwrap();
    assert_eq!(
        adapter.publishes().len(),
        1,
        "persisted backoff must prevent an immediate restart retry"
    );
    let fanout = restarted.session().transport_fanouts().unwrap().remove(0);
    assert!(fanout.possible_exposure);
    assert!(!fanout.evolution_confirmed);

    wall.set(wall.now().0.saturating_add(30));
    restarted.run_due_maintenance().await.unwrap();
    let publishes = adapter.publishes();
    assert_eq!(publishes.len(), 2);
    assert_eq!(publishes[0].message, publishes[1].message);
    assert_eq!(
        restarted.session().epoch(&group_id).unwrap().0,
        source_epoch.0 + 1
    );
    assert_eq!(
        restarted
            .session()
            .maintenance_obligation(&obligation_id)
            .unwrap()
            .unwrap()
            .phase,
        cgka_traits::MaintenancePhase::Complete
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

// A "best effort" routing policy (`required_acks == 0`) must still fail a
// publish that no endpoint accepted: confirming it would advance the local
// epoch/membership past a welcome that reached no relay (#375).
#[tokio::test]
async fn create_group_with_best_effort_acks_rolls_back_when_nothing_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot best effort key").unwrap();
    let mut bob_session = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let bob_kp = bob_session.fresh_key_package().await.unwrap();
    let bob_id = bob_session.self_id();
    let session = session(dir.path().join("alice.sqlite"), &key, b"alice");
    let adapter = RecordingAdapter::default();
    adapter.accept_only_next(0);
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .required_acks(0)
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
            name: "runtime best effort".into(),
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
    assert_eq!(effects.reports.len(), 1);
    assert_eq!(effects.reports[0].accepted_count(), 0);
    assert!(!effects.reports[0].met_required_acks());
    assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 0);
    assert_eq!(runtime.session().members(&group_id).unwrap().len(), 1);
}

#[tokio::test]
async fn create_group_stops_welcome_publish_after_unexposed_failure() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot create stop key").unwrap();
    let mut bob_session = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let mut carol_session = session(dir.path().join("carol.sqlite"), &key, b"carol");
    let bob_kp = bob_session.fresh_key_package().await.unwrap();
    let carol_kp = carol_session.fresh_key_package().await.unwrap();
    let bob_id = bob_session.self_id();
    let carol_id = carol_session.self_id();
    let session = session(dir.path().join("alice.sqlite"), &key, b"alice");
    let adapter = RecordingAdapter::default();
    adapter.accept_only_next(0);
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_inbox_route(
                bob_id,
                vec![TransportEndpoint("wss://bob-inbox.example".into())],
            )
            .with_inbox_route(
                carol_id,
                vec![TransportEndpoint("wss://carol-inbox.example".into())],
            );
    let mut runtime = AccountDeviceRuntime::new(
        session,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    let (group_id, effects) = runtime
        .create_group(CreateGroupRequest {
            name: "runtime unexposed failure".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
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
    assert_eq!(effects.reports.len(), 1);
    assert_eq!(effects.reports[0].accepted_count(), 0);
    assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 0);
    assert_eq!(runtime.session().members(&group_id).unwrap().len(), 1);
    assert_eq!(adapter.publishes().len(), 1);
}

#[tokio::test]
async fn current_founding_welcomes_publish_with_bounded_concurrency() {
    for recipient_count in [1usize, 5, 20] {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new(format!("bounded Welcome key {recipient_count}")).unwrap();
        let mut members = Vec::with_capacity(recipient_count);
        let mut policy = StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://alice-inbox.example".into(),
        )]);
        for index in 0..recipient_count {
            let identity = format!("recipient-{recipient_count}-{index}");
            let mut recipient = current_session(
                dir.path().join(format!("recipient-{index}.sqlite")),
                &key,
                identity.as_bytes(),
            );
            members.push(recipient.fresh_key_package().await.unwrap());
            policy = policy.with_inbox_route(
                recipient.self_id(),
                vec![TransportEndpoint(format!(
                    "wss://recipient-{index}.example"
                ))],
            );
        }
        let adapter = RecordingAdapter::default();
        let gate = adapter.gate_welcome_publishes();
        let session = current_session(
            dir.path().join("alice.sqlite"),
            &key,
            format!("alice-{recipient_count}").as_bytes(),
        );
        let mut runtime = AccountDeviceRuntime::new(
            session,
            adapter.clone(),
            policy,
            RecordingKeyPackages::default(),
        );
        let create = tokio::spawn(async move {
            runtime
                .create_group(CreateGroupRequest {
                    name: format!("bounded {recipient_count}"),
                    description: String::new(),
                    members,
                    required_features: Vec::new(),
                    app_components: Vec::new(),
                    initial_admins: Vec::new(),
                })
                .await
        });

        let expected_parallelism = recipient_count.min(8);
        tokio::time::timeout(Duration::from_secs(5), async {
            while gate.max_active.load(Ordering::SeqCst) < expected_parallelism {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Welcome publishes should fill the bounded worker set");
        assert_eq!(gate.max_active.load(Ordering::SeqCst), expected_parallelism);
        gate.release.add_permits(recipient_count);

        let (_, effects) = create.await.unwrap().unwrap();
        assert_eq!(effects.reports.len(), recipient_count);
        assert_eq!(adapter.publishes().len(), recipient_count);
        assert!(gate.max_active.load(Ordering::SeqCst) <= 8);
    }
}

#[tokio::test]
async fn current_founding_welcomes_survive_restart_before_publication() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot current founding prepare crash key").unwrap();
    let mut bob_session =
        current_session(dir.path().join("bob-prepare.sqlite"), &key, b"bob-prepare");
    let mut carol_session = current_session(
        dir.path().join("carol-prepare.sqlite"),
        &key,
        b"carol-prepare",
    );
    let bob_kp = bob_session.fresh_key_package().await.unwrap();
    let carol_kp = carol_session.fresh_key_package().await.unwrap();
    let alice_path = dir.path().join("alice-prepare.sqlite");
    let session = current_session(&alice_path, &key, b"alice-prepare");
    let adapter = RecordingAdapter::default();
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        session,
        adapter,
        policy.clone(),
        RecordingKeyPackages::default(),
    );

    let prepared = runtime
        .session_mut()
        .create_group(CreateGroupRequest {
            name: "prepared current founding".into(),
            description: String::new(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let expected_ids = match &prepared.effects.publish[..] {
        [PublishWork::FoundingGroupCreated { welcomes }] => welcomes
            .iter()
            .map(|welcome| welcome.id.clone())
            .collect::<Vec<_>>(),
        other => panic!("expected founding Welcome work, got {other:?}"),
    };
    assert_eq!(expected_ids.len(), 2);
    drop(runtime);

    let restarted = AccountDeviceRuntime::new(
        current_session(&alice_path, &key, b"alice-prepare"),
        RecordingAdapter::default(),
        policy,
        RecordingKeyPackages::default(),
    );
    let mut recovered_ids = restarted
        .outstanding_welcome_deliveries()
        .unwrap()
        .into_iter()
        .map(|(_, welcome)| welcome.id)
        .collect::<Vec<_>>();
    recovered_ids.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    let mut expected_ids = expected_ids;
    expected_ids.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    assert_eq!(recovered_ids, expected_ids);
    assert_eq!(
        restarted.session().epoch(&prepared.group_id).unwrap().0,
        1,
        "recovery discovers delivery work without creating or merging the group again"
    );
}

#[tokio::test]
async fn current_founding_create_keeps_group_when_every_welcome_delivery_fails() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot current founding delivery key").unwrap();
    let mut bob_session = current_session(dir.path().join("bob.sqlite"), &key, b"bob-current");
    let mut carol_session =
        current_session(dir.path().join("carol.sqlite"), &key, b"carol-current");
    let bob_kp = bob_session.fresh_key_package().await.unwrap();
    let carol_kp = carol_session.fresh_key_package().await.unwrap();
    let bob_id = bob_session.self_id();
    let carol_id = carol_session.self_id();
    let alice_path = dir.path().join("alice.sqlite");
    let session = current_session(&alice_path, &key, b"alice-current");
    let adapter = RecordingAdapter::default();
    adapter.accept_next(0);
    adapter.accept_next(0);
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_inbox_route(
                bob_id.clone(),
                vec![TransportEndpoint("wss://bob-inbox.example".into())],
            )
            .with_inbox_route(
                carol_id.clone(),
                vec![TransportEndpoint("wss://carol-inbox.example".into())],
            );
    let mut runtime = AccountDeviceRuntime::new(
        session,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    let (group_id, effects) = runtime
        .create_group(CreateGroupRequest {
            name: "canonical current founding".into(),
            description: String::new(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    assert!(
        effects.pending.is_empty(),
        "founding creation has no transport-gated pending commit"
    );
    assert!(matches!(
        effects.events.as_slice(),
        [GroupEvent::GroupCreated { group_id: created }] if created == &group_id
    ));
    assert_eq!(effects.reports.len(), 2);
    assert_eq!(effects.failures.len(), 2);
    assert_eq!(effects.welcome_failures.len(), 2);
    assert_eq!(adapter.publishes().len(), 2);
    assert!(
        adapter
            .publishes()
            .iter()
            .all(|request| matches!(request.message.envelope, TransportEnvelope::Welcome { .. })),
        "founding creation must not publish an ordinary group commit"
    );
    assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 1);
    assert_eq!(runtime.session().members(&group_id).unwrap().len(), 3);

    let mut failed_recipients = effects
        .welcome_failures
        .iter()
        .map(|failure| failure.recipient.clone())
        .collect::<Vec<_>>();
    failed_recipients.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    let mut expected_recipients = vec![bob_id.clone(), carol_id.clone()];
    expected_recipients.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    assert_eq!(failed_recipients, expected_recipients);
    assert_ne!(
        effects.welcome_failures[0].message_id, effects.welcome_failures[1].message_id,
        "each invitee has an independent durable Welcome artifact"
    );
    for failure in &effects.welcome_failures {
        assert_eq!(failure.group_id, Some(group_id.clone()));
        let (stored_group, stored_welcome) = runtime
            .session()
            .stored_sent_welcome(&failure.message_id)
            .unwrap();
        assert_eq!(stored_group, group_id);
        assert_eq!(stored_welcome.id, failure.message_id);
    }
    assert_eq!(
        runtime.outstanding_welcome_deliveries().unwrap().len(),
        2,
        "both failed founding Welcomes remain discoverable without in-process failure handles"
    );

    // Restart before retrying exactly one stored Welcome. It succeeds without
    // merging or publishing another commit, and leaves the other failed
    // delivery independently addressable by its own message id.
    drop(runtime);
    let restarted_adapter = RecordingAdapter::default();
    let restarted_policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_inbox_route(
                bob_id,
                vec![TransportEndpoint("wss://bob-inbox.example".into())],
            )
            .with_inbox_route(
                carol_id,
                vec![TransportEndpoint("wss://carol-inbox.example".into())],
            );
    let mut runtime = AccountDeviceRuntime::new(
        current_session(&alice_path, &key, b"alice-current"),
        restarted_adapter.clone(),
        restarted_policy,
        RecordingKeyPackages::default(),
    );
    let retried = runtime
        .redeliver_welcome(&effects.welcome_failures[0].message_id)
        .await
        .unwrap();
    assert!(retried.failures.is_empty());
    assert!(retried.welcome_failures.is_empty());
    assert_eq!(retried.reports.len(), 1);
    assert_eq!(adapter.publishes().len(), 2);
    assert_eq!(restarted_adapter.publishes().len(), 1);
    assert_eq!(
        restarted_adapter.publishes()[0].message.id,
        effects.welcome_failures[0].message_id
    );
    let outstanding_after_retry = runtime.outstanding_welcome_deliveries().unwrap();
    assert_eq!(outstanding_after_retry.len(), 1);
    assert_eq!(
        outstanding_after_retry[0].1.id,
        effects.welcome_failures[1].message_id
    );
    assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 1);
}

#[tokio::test]
async fn current_founding_welcome_finish_failure_still_reconciles_later_recipients() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot current founding finish failure key").unwrap();
    let mut bob_session =
        current_session(dir.path().join("bob-finish.sqlite"), &key, b"bob-finish");
    let mut carol_session = current_session(
        dir.path().join("carol-finish.sqlite"),
        &key,
        b"carol-finish",
    );
    let bob_kp = bob_session.fresh_key_package().await.unwrap();
    let carol_kp = carol_session.fresh_key_package().await.unwrap();
    let bob_id = bob_session.self_id();
    let carol_id = carol_session.self_id();
    let alice_path = dir.path().join("alice-finish.sqlite");
    let session = current_session(&alice_path, &key, b"alice-finish");
    let adapter = RecordingAdapter::default();
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_inbox_route(
                bob_id.clone(),
                vec![TransportEndpoint("wss://bob-inbox.example".into())],
            )
            .with_inbox_route(
                carol_id.clone(),
                vec![TransportEndpoint("wss://carol-inbox.example".into())],
            );
    let mut runtime = AccountDeviceRuntime::new(
        session,
        adapter.clone(),
        policy.clone(),
        RecordingKeyPackages::default(),
    );

    // Prepare the founding create without transport side effects so the
    // finish-stage failure can be armed for exactly one exposed Welcome.
    let prepared = runtime
        .session_mut()
        .create_group(CreateGroupRequest {
            name: "founding finish failure".into(),
            description: String::new(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcomes = match &prepared.effects.publish[..] {
        [PublishWork::FoundingGroupCreated { welcomes }] => welcomes.clone(),
        other => panic!("expected founding Welcome work, got {other:?}"),
    };
    assert_eq!(welcomes.len(), 2);
    let welcome_id_for = |recipient: &MemberId| {
        welcomes
            .iter()
            .find(|welcome| {
                matches!(
                    &welcome.envelope,
                    TransportEnvelope::Welcome { recipient: addressed } if addressed == recipient
                )
            })
            .map(|welcome| welcome.id.clone())
            .expect("welcome addressed to recipient")
    };
    let bob_welcome_id = welcome_id_for(&bob_id);
    let carol_welcome_id = welcome_id_for(&carol_id);

    // Bob's Welcome is published to the network, but its completion
    // bookkeeping fails as if the durable fanout persist lost the database
    // lock. Carol's identical work must still be reconciled.
    runtime.arm_finish_stage_failure(bob_welcome_id.clone());
    let error = runtime
        .publish_session_effects(prepared.effects)
        .await
        .expect_err("the armed finish-stage failure must surface");
    assert!(
        matches!(error, AccountError::Session(_)),
        "expected the injected session failure, got {error:?}"
    );
    assert_eq!(
        adapter.publishes().len(),
        2,
        "both Welcomes were exposed to the network before the failure"
    );

    // Carol's completion bookkeeping still ran: her fanout record carries the
    // delivered acknowledgement instead of the pre-publication snapshot.
    let carol_fanout = runtime
        .session()
        .transport_fanout(&carol_welcome_id)
        .unwrap()
        .expect("carol fanout persisted");
    assert!(
        carol_fanout.targets.iter().all(|target| matches!(
            target.state,
            cgka_traits::maintenance::TransportFanoutAttemptState::Accepted
        )),
        "carol's exposed Welcome retained its delivered fanout state"
    );
    let bob_fanout = runtime
        .session()
        .transport_fanout(&bob_welcome_id)
        .unwrap()
        .expect("bob fanout persisted");
    assert!(
        bob_fanout.targets.iter().all(|target| matches!(
            target.state,
            cgka_traits::maintenance::TransportFanoutAttemptState::Unattempted
        )),
        "bob's failed finish leaves the pre-publication fanout snapshot retryable"
    );

    // Across a restart only bob's Welcome remains an outstanding delivery
    // obligation; carol's already-delivered Welcome is not republished.
    drop(runtime);
    let restarted = AccountDeviceRuntime::new(
        current_session(&alice_path, &key, b"alice-finish"),
        RecordingAdapter::default(),
        policy,
        RecordingKeyPackages::default(),
    );
    let outstanding = restarted.outstanding_welcome_deliveries().unwrap();
    assert_eq!(outstanding.len(), 1);
    assert_eq!(outstanding[0].0, prepared.group_id);
    assert_eq!(outstanding[0].1.id, bob_welcome_id);
}

#[tokio::test]
async fn create_group_confirms_pending_when_welcome_was_partially_exposed() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot partial create key").unwrap();
    let mut bob_session = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let bob_kp = bob_session.fresh_key_package().await.unwrap();
    let bob_id = bob_session.self_id();
    let session = session(dir.path().join("alice.sqlite"), &key, b"alice");
    let adapter = RecordingAdapter::default();
    adapter.accept_only_next(1);
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .required_acks(2)
            .with_inbox_route(
                bob_id.clone(),
                vec![
                    TransportEndpoint("wss://bob-inbox-a.example".into()),
                    TransportEndpoint("wss://bob-inbox-b.example".into()),
                ],
            );
    let mut runtime = AccountDeviceRuntime::new(
        session,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    let (group_id, effects) = runtime
        .create_group(CreateGroupRequest {
            name: "runtime partial create".into(),
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
        PendingResolution::Confirmed { .. }
    ));
    assert_eq!(effects.failures.len(), 1);
    assert_eq!(effects.reports.len(), 1);
    assert_eq!(effects.reports[0].accepted_count(), 1);
    assert!(!effects.reports[0].met_required_acks());
    // The confirmed create left bob's welcome under-acked: the structured
    // record pairs the failure with its recipient and group for re-delivery
    // (mdk#352).
    assert_eq!(effects.welcome_failures.len(), 1);
    assert_eq!(effects.welcome_failures[0].recipient, bob_id);
    assert_eq!(
        effects.welcome_failures[0].message_id,
        effects.failures[0].message_id
    );
    assert_eq!(effects.welcome_failures[0].group_id, Some(group_id.clone()));
    assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 1);
    assert_eq!(runtime.session().members(&group_id).unwrap().len(), 2);

    let publishes = adapter.publishes();
    assert_eq!(publishes.len(), 1);
    assert!(matches!(
        publishes[0].message.envelope,
        TransportEnvelope::Welcome { .. }
    ));
}

#[tokio::test]
async fn group_evolution_confirms_commit_when_welcome_publish_fails() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot evolution partial publish key").unwrap();
    let mut alice_session = session(dir.path().join("alice.sqlite"), &key, b"alice");
    let mut bob_session = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let mut carol_session = session(dir.path().join("carol.sqlite"), &key, b"carol");
    let bob_kp = bob_session.fresh_key_package().await.unwrap();
    let carol_kp = carol_session.fresh_key_package().await.unwrap();
    let carol_id = carol_session.self_id();

    let created = alice_session
        .create_group(CreateGroupRequest {
            name: "runtime evolution".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let create_pending = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, .. } => *pending,
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice_session
        .confirm_published(create_pending)
        .await
        .unwrap();

    let adapter = RecordingAdapter::default();
    adapter.accept_next(1);
    adapter.accept_next(0);
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_group_route(
                created.group_id.clone(),
                created.group_id.as_slice().to_vec(),
                vec![TransportEndpoint("wss://group.example".into())],
            )
            .with_inbox_route(
                carol_id.clone(),
                vec![TransportEndpoint("wss://carol-inbox.example".into())],
            );
    let mut runtime = AccountDeviceRuntime::new(
        alice_session,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    let effects = runtime
        .send(SendIntent::Invite {
            group_id: created.group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();

    assert_eq!(effects.pending.len(), 1);
    assert!(matches!(
        effects.pending[0],
        PendingResolution::Confirmed { .. }
    ));
    assert_eq!(effects.failures.len(), 1);
    // The commit is confirmed, so carol's undelivered welcome surfaces as a
    // structured re-delivery handle rather than only a flat failure string
    // (mdk#352).
    assert_eq!(effects.welcome_failures.len(), 1);
    assert_eq!(effects.welcome_failures[0].recipient, carol_id);
    assert_eq!(
        effects.welcome_failures[0].message_id,
        effects.failures[0].message_id
    );
    assert_eq!(
        effects.welcome_failures[0].group_id,
        Some(created.group_id.clone())
    );
    assert_eq!(runtime.session().epoch(&created.group_id).unwrap().0, 2);
    assert_eq!(
        runtime.session().members(&created.group_id).unwrap().len(),
        3
    );

    let publishes = adapter.publishes();
    assert_eq!(publishes.len(), 2);
    assert!(matches!(
        publishes[0].message.envelope,
        TransportEnvelope::GroupMessage { .. }
    ));
    assert!(matches!(
        publishes[1].message.envelope,
        TransportEnvelope::Welcome { .. }
    ));

    // Re-delivery repairs carol's join from the stored welcome: the adapter
    // (now accepting) receives the same welcome id again and the epoch does
    // not advance — no re-commit.
    let redelivered = runtime
        .redeliver_welcome(&effects.welcome_failures[0].message_id)
        .await
        .unwrap();
    assert_eq!(redelivered.reports.len(), 1);
    assert!(redelivered.reports[0].met_required_acks());
    assert!(redelivered.failures.is_empty());
    assert!(redelivered.welcome_failures.is_empty());
    let publishes = adapter.publishes();
    assert_eq!(publishes.len(), 3);
    assert!(matches!(
        publishes[2].message.envelope,
        TransportEnvelope::Welcome { .. }
    ));
    assert_eq!(
        publishes[2].message.id,
        effects.welcome_failures[0].message_id
    );
    assert_eq!(runtime.session().epoch(&created.group_id).unwrap().0, 2);

    // A non-welcome message id is rejected without publishing anything.
    let commit_id = publishes[0].message.id.clone();
    assert!(runtime.redeliver_welcome(&commit_id).await.is_err());
    assert_eq!(adapter.publishes().len(), 3);
}

// mdk#499 regression: an explicit group-evolution commit that a relay
// accepted but that missed `required_acks` has already been exposed to peers.
// Rolling it back locally diverges the sender from recipients; mirror the
// `publish_pending`/group-created exposure rule and keep the commit, then still
// publish the invite welcome.
#[tokio::test]
async fn group_evolution_confirms_pending_when_commit_was_partially_exposed() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot evolution partial commit key").unwrap();
    let mut alice_session = session(dir.path().join("alice.sqlite"), &key, b"alice");
    let mut bob_session = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let mut carol_session = session(dir.path().join("carol.sqlite"), &key, b"carol");
    let bob_kp = bob_session.fresh_key_package().await.unwrap();
    let carol_kp = carol_session.fresh_key_package().await.unwrap();
    let carol_id = carol_session.self_id();

    let created = alice_session
        .create_group(CreateGroupRequest {
            name: "runtime partial evolution commit".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let create_pending = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, .. } => *pending,
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice_session
        .confirm_published(create_pending)
        .await
        .unwrap();

    let adapter = RecordingAdapter::default();
    adapter.accept_next(1);
    adapter.accept_next(0);
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .required_acks(2)
            .with_group_route(
                created.group_id.clone(),
                created.group_id.as_slice().to_vec(),
                vec![
                    TransportEndpoint("wss://group-a.example".into()),
                    TransportEndpoint("wss://group-b.example".into()),
                ],
            )
            .with_inbox_route(
                carol_id,
                vec![
                    TransportEndpoint("wss://carol-inbox-a.example".into()),
                    TransportEndpoint("wss://carol-inbox-b.example".into()),
                ],
            );
    let mut runtime = AccountDeviceRuntime::new(
        alice_session,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    let effects = runtime
        .send(SendIntent::Invite {
            group_id: created.group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();

    assert_eq!(effects.pending.len(), 1);
    assert!(
        matches!(effects.pending[0], PendingResolution::Confirmed { .. }),
        "relay-accepted group evolution commit must be confirmed, got {:?}",
        effects.pending[0]
    );
    assert_eq!(effects.failures.len(), 1);
    assert_eq!(effects.reports.len(), 2);
    assert_eq!(effects.reports[0].accepted_count(), 1);
    assert!(!effects.reports[0].met_required_acks());
    assert_eq!(effects.reports[1].accepted_count(), 2);
    assert!(effects.reports[1].met_required_acks());
    // The under-acked message here is the commit, not the welcome — the
    // commit's ack-miss must not be misclassified as a welcome-delivery
    // failure.
    assert!(effects.welcome_failures.is_empty());
    assert_eq!(runtime.session().epoch(&created.group_id).unwrap().0, 2);
    assert_eq!(
        runtime.session().members(&created.group_id).unwrap().len(),
        3
    );

    let publishes = adapter.publishes();
    assert_eq!(publishes.len(), 3);
    assert!(matches!(
        publishes[0].message.envelope,
        TransportEnvelope::GroupMessage { .. }
    ));
    assert!(matches!(
        publishes[1].message.envelope,
        TransportEnvelope::GroupMessage { .. }
    ));
    assert!(matches!(
        publishes[2].message.envelope,
        TransportEnvelope::Welcome { .. }
    ));
}

// mdk#426 regression: hydration-quarantine events must reach the
// app/account layer through the no-inbound `drain()` path, not only when an
// unrelated relay delivery happens to trigger an engine drain. Build a session
// DB with a group whose Marmot metadata exists but whose OpenMLS state is
// missing, reopen it (which quarantines the group during hydration), and assert
// `AccountDeviceRuntime::drain()` surfaces `GroupHydrationQuarantined` with no
// inbound traffic at all.
#[tokio::test]
async fn drain_surfaces_hydration_quarantine_without_inbound_delivery() {
    use cgka_traits::engine::GroupHydrationQuarantineReason;
    use cgka_traits::group::Group;
    use cgka_traits::types::{EpochId, GroupId};
    use cgka_traits::{GroupCapabilities, GroupStorage};
    use storage_sqlite::SqliteAccountStorage;

    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot drain quarantine key").unwrap();
    let db_path = dir.path().join("alice.sqlite");

    // Create a healthy account DB so the schema exists, then close it.
    drop(session(&db_path, &key, b"alice"));

    // Inject a Marmot group record with no backing OpenMLS state directly into
    // the same encrypted DB. On reopen this group is quarantined with
    // `OpenMlsGroupMissing` instead of aborting account open (#151 / #417).
    let broken_group = GroupId::new(b"missing-openmls-state".to_vec());
    {
        let storage = SqliteAccountStorage::open_encrypted(&db_path, &key).unwrap();
        storage
            .put_group(&Group {
                id: broken_group.clone(),
                name: "broken".into(),
                description: String::new(),
                members: Vec::new(),
                epoch: EpochId(9),
                required_capabilities: GroupCapabilities::default(),
                protocol_profile: cgka_traits::group::ProtocolProfile::Legacy,
                removed: false,
                unrecoverable: false,
                disbanded: None,
                join_epoch: EpochId(0),
            })
            .unwrap();
    }

    // Reopen the session (hydration quarantines the bad group) and wrap it in a
    // runtime. No transport delivery is ingested.
    let reopened = session(&db_path, &key, b"alice");
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        policy,
        RecordingKeyPackages::default(),
    );

    // The group is queryable via the recovery surface...
    let quarantined = runtime.quarantined_groups();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].0, broken_group);
    assert_eq!(
        quarantined[0].1,
        GroupHydrationQuarantineReason::OpenMlsGroupMissing
    );

    // ...and the typed event reaches subscribers through drain() with no
    // inbound relay traffic — the bug this fixes.
    let effects = runtime.drain().await.unwrap();
    assert!(
        effects.events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupHydrationQuarantined {
                group_id,
                reason: GroupHydrationQuarantineReason::OpenMlsGroupMissing,
            } if group_id == &broken_group
        )),
        "quarantine event missing from drain(): {:?}",
        effects.events
    );

    // A second drain is empty: the queued event was consumed, not replayed.
    let drained_again = runtime.drain().await.unwrap();
    assert!(
        !drained_again
            .events
            .iter()
            .any(|event| matches!(event, GroupEvent::GroupHydrationQuarantined { .. })),
        "quarantine event should not replay on a second drain: {:?}",
        drained_again.events
    );
}

// mdk#483 regression: an auto-published commit (here, the admin's
// auto-commit of a peer self-remove proposal) that a relay *accepted* but that
// did not meet `required_acks` must be CONFIRMED, not rolled back. Rolling it
// back leaves the sender's local row falsely failed while peers already have
// the message — a resend then duplicates it in-group and convergence retry is a
// no-op. This mirrors the welcome-exposure handling already covered by
// `create_group_confirms_pending_when_welcome_was_partially_exposed`, but for
// the `PublishWork::AutoPublish` path through `publish_pending`.
#[tokio::test]
async fn auto_publish_confirms_pending_when_commit_was_partially_exposed() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot auto publish partial key").unwrap();

    // Build alice (admin) and bob with the MIP-03 self-remove feature so a
    // `Leave` from bob becomes a remove *proposal* that alice auto-commits.
    let mut alice = session_with_registry(
        dir.path().join("alice.sqlite"),
        &key,
        b"alice",
        selfremove_registry(),
    );
    let mut bob = session_with_registry(
        dir.path().join("bob.sqlite"),
        &key,
        b"bob",
        selfremove_registry(),
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();

    // Create the group through the raw session and confirm the welcome so alice
    // is at a clean, settled epoch before the proposal arrives.
    let created = alice
        .create_group(CreateGroupRequest {
            name: "auto publish partial".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let group_id = created.group_id.clone();
    let (create_pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();

    // Bob leaves -> remove proposal that alice will auto-commit on ingest.
    let leave = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let proposal = match &leave.publish[0] {
        PublishWork::Proposal { msg, .. } => msg.clone(),
        other => panic!("expected proposal publish work, got {other:?}"),
    };

    // Wrap alice's session in a runtime whose adapter accepts the auto-published
    // commit on only ONE of the group's two endpoints, with required_acks=2.
    // That is "accepted by a relay but below the ack threshold": the bug rolled
    // this back; the fix must confirm it.
    let adapter = RecordingAdapter::default();
    adapter.accept_only_next(1);
    adapter.accept_next(0);
    let alice_id = alice.self_id();
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .required_acks(2)
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![
                    TransportEndpoint("wss://group-a.example".into()),
                    TransportEndpoint("wss://group-b.example".into()),
                ],
            );
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    let delivery = TransportDelivery {
        account_id: alice_id,
        group_id_hint: Some(group_id.clone()),
        message: proposal,
        received_at: Timestamp(0),
        source: TransportDeliverySource {
            transport: TransportSource("marmot-account-test".into()),
            plane: TransportDeliveryPlane::Group,
            endpoint: None,
            subscription_id: None,
            wire: None,
        },
    };

    let ingested = runtime.ingest_delivery(delivery).await.unwrap();
    assert_eq!(ingested.effects.pending_convergence, vec![group_id.clone()]);
    assert!(
        ingested.effects.pending.is_empty(),
        "ingest should schedule the delayed auto-commit, not publish it immediately"
    );

    tokio::time::sleep(std::time::Duration::from_millis(75)).await;
    let advanced = runtime.advance_convergence(&group_id).await.unwrap();

    // The auto-published commit was accepted by a relay but missed required_acks
    // — it must be confirmed (kept), not rolled back.
    assert_eq!(advanced.pending.len(), 1);
    assert!(
        matches!(advanced.pending[0], PendingResolution::Confirmed { .. }),
        "relay-accepted auto-publish must be confirmed, got {:?}",
        advanced.pending[0]
    );
    // The commit publish was attempted and reported under-threshold acceptance.
    assert_eq!(advanced.reports.len(), 1);
    assert_eq!(advanced.reports[0].accepted_count(), 1);
    assert!(!advanced.reports[0].met_required_acks());
    // The removal was applied locally: epoch advanced and bob is gone.
    assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 2);
    assert_eq!(runtime.session().members(&group_id).unwrap().len(), 1);
}

fn app_payload_for(sender_hex: &str, payload: impl AsRef<[u8]>) -> Vec<u8> {
    MarmotAppEvent::new(
        sender_hex,
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        String::from_utf8(payload.as_ref().to_vec()).expect("test app payload is utf8"),
    )
    .encode()
    .expect("test app event encodes")
}

#[tokio::test]
async fn published_app_messages_carry_exact_source_state_and_adapter_identity() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot published app metadata key").unwrap();
    let mut supported = default_group_components();
    supported.insert(GROUP_MESSAGE_RETENTION_COMPONENT_ID);
    let mut alice = session_with_registry_and_components(
        dir.path().join("alice-published-app.sqlite"),
        &key,
        b"alice-published-app",
        selfremove_registry(),
        supported.clone(),
    );
    let mut bob = session_with_registry_and_components(
        dir.path().join("bob-published-app.sqlite"),
        &key,
        b"bob-published-app",
        selfremove_registry(),
        supported,
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let alice_hex = hex::encode(alice.self_id().as_slice());
    let created = alice
        .create_group(CreateGroupRequest {
            name: "published app metadata".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
                data: 90u64.to_be_bytes().to_vec(),
            }],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let group_id = created.group_id.clone();
    let (create_pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();

    let adapter = RecordingAdapter::default();
    let reported_message_id = MessageId::new(b"adapter-visible-app-message".to_vec());
    adapter.report_message_id_next(reported_message_id.clone());
    let adapter_handle = adapter.clone();
    let policy = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://published-app-inbox.example".into(),
    )])
    .with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![TransportEndpoint(
            "wss://published-app-group.example".into(),
        )],
    );
    let mut runtime =
        AccountDeviceRuntime::new(alice, adapter, policy, RecordingKeyPackages::default());

    let payload = app_payload_for(&alice_hex, b"typed metadata");
    let app_event_id = MarmotAppEvent::decode(&payload).unwrap().id;
    let effects = runtime
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
        })
        .await
        .unwrap();
    assert_ne!(
        effects.reports[0].message_id,
        adapter_handle.publishes()[0].message.id,
        "test adapter must exercise transport id replacement"
    );
    assert_eq!(
        effects.published_app_messages,
        vec![PublishedApplicationMessage {
            group_id: group_id.clone(),
            app_event_id,
            message_id: reported_message_id,
            source_epoch: EpochId(1),
            retention: cgka_traits::AppMessageRetentionDecision::new(1_700_000_000, 90),
        }]
    );

    let leave = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let proposal = match &leave.publish[0] {
        PublishWork::Proposal { msg, .. } => msg.clone(),
        other => panic!("expected Proposal publish work, got {other:?}"),
    };
    let proposal_effects = runtime
        .publish_session_effects(cgka_session::SessionEffects {
            events: Vec::new(),
            publish: vec![PublishWork::Proposal {
                msg: proposal,
                queued_intent: None,
            }],
            queued: Vec::new(),
            pending_convergence: Vec::new(),
        })
        .await
        .unwrap();
    assert!(
        proposal_effects.published_app_messages.is_empty(),
        "proposal reports must not be mislabeled as application publications"
    );
}

#[tokio::test]
async fn fanout_staging_failure_rolls_back_pending_mls_state() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot fanout staging rollback key").unwrap();
    let mut alice = session(
        dir.path().join("alice-stage-rollback.sqlite"),
        &key,
        b"alice-stage-rollback",
    );
    let created = alice
        .create_group(CreateGroupRequest {
            name: "before failed staging".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let group_id = created.group_id.clone();
    let create_pending = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, .. } => *pending,
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();
    let baseline_epoch = alice.epoch(&group_id).unwrap();

    let adapter = RecordingAdapter::default();
    let routing = MismatchedPendingGroupRouting {
        wrong_group_id: GroupId::new(b"wrong-pending-group".to_vec()),
        endpoint: TransportEndpoint("wss://stage-rollback.example".into()),
    };
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        routing,
        RecordingKeyPackages::default(),
    );

    let error = runtime
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("must roll back".into()),
            description: None,
        })
        .await
        .expect_err("mismatched pending group must fail fanout staging");
    assert!(matches!(
        error,
        AccountError::Transport(TransportAdapterError::PublishTargetMismatch { .. })
    ));
    assert!(
        adapter.publishes().is_empty(),
        "staging failure happens before any transport side effect"
    );
    assert_eq!(runtime.session().epoch(&group_id).unwrap(), baseline_epoch);
    assert_eq!(
        runtime.session().group_record(&group_id).unwrap().name,
        "before failed staging",
        "failed pre-publish staging must roll back the projected group update"
    );

    // A second commit can stage and reaches the same routing validation,
    // proving the first pending state did not wedge the group.
    assert!(matches!(
        runtime
            .send(SendIntent::UpdateGroupData {
                group_id,
                name: Some("second attempt".into()),
                description: None,
            })
            .await,
        Err(AccountError::Transport(
            TransportAdapterError::PublishTargetMismatch { .. }
        ))
    ));
}

#[tokio::test]
async fn rejected_self_update_publication_rolls_back_instead_of_holding_pending_publish() {
    // Field incidents blamed a stalled self-update publication for wedging a
    // group in `PendingPublish` (and, before app payloads were retained across
    // that state, for failing user sends). This pins the bound that makes the
    // rejection case terminal: one complete attempt where every endpoint
    // rejected the event is an unambiguous all-failed publication, so the
    // pending publish rolls back on that attempt rather than waiting out the
    // 30s→1h per-target backoff — which never terminates on its own.
    //
    // Its counterpart is
    // `ambiguous_self_update_exposure_survives_restart_and_respects_retry_backoff`:
    // when the adapter *errors*, a relay may hold the event, so the same staged
    // commit deliberately keeps its obligation instead of risking a fork.
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot rejected self update key").unwrap();
    let database = dir.path().join("alice.sqlite");
    let mut initial = current_session(database.clone(), &key, b"alice");
    let created = initial
        .create_group(CreateGroupRequest {
            name: "rejected self update".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let source_epoch = initial.epoch(&group_id).unwrap();
    drop(initial);

    let adapter = RecordingAdapter::default();
    // Every endpoint rejects: an `Ok` report with zero acknowledgements, which
    // is precisely what a relay refusal looks like to the account runtime.
    adapter.accept_next(0);
    let routing =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://inbox.example".into())])
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![TransportEndpoint("wss://group.example".into())],
            );
    let wall = Arc::new(TestWallClock::new(120_000));
    let monotonic = Arc::new(TestMonotonicClock::default());
    let mut runtime = AccountDeviceRuntime::new(
        current_session(database, &key, b"alice"),
        adapter.clone(),
        routing,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        monotonic.clone(),
        Arc::new(TestRandom::new(0)),
    );

    let obligation_id = runtime.schedule_manual_self_update(&group_id).unwrap();
    runtime.run_due_maintenance().await.unwrap();
    monotonic.set_millis(60_000);
    wall.set(120_060);
    runtime.run_due_maintenance().await.unwrap();
    let jittered = runtime
        .session()
        .maintenance_obligation(&obligation_id)
        .unwrap()
        .unwrap();
    wall.set(jittered.not_before.unwrap().0);
    let effects = runtime.run_due_maintenance().await.unwrap();

    assert_eq!(adapter.publishes().len(), 1);
    let fanout = runtime.session().transport_fanouts().unwrap().remove(0);
    assert!(
        !fanout.possible_exposure,
        "a rejection is a definite non-delivery, not an ambiguous exposure"
    );
    assert!(
        effects
            .pending
            .iter()
            .any(|resolution| matches!(resolution, PendingResolution::RolledBack { .. })),
        "a completely rejected publication must resolve its pending publish, not defer it; got {:?}",
        effects.pending
    );
    assert_eq!(
        runtime.session().epoch(&group_id).unwrap(),
        source_epoch,
        "rollback must restore the epoch the self-update was staged from"
    );
    // Rollback compensated the staged evolution in the same transaction, so the
    // obligation has nothing left to re-publish and must re-stage rather than
    // cling to an event that reached no one. That is the liveness half of the
    // bound: without it a rejected publication leaves the rotation permanently
    // owed.
    //
    // The very next maintenance run must do it, with the clock exactly where
    // the rejection left it, and asserting that is the point. Nothing on this
    // path can legitimately delay the re-stage: `not_before` is only written by
    // the quiet-period arm, which a due obligation in `PendingPublication` never
    // reaches, and the re-staged commit gets a fresh fanout whose targets have
    // no `last_attempt_at`, so the 30s→1h per-target retry backoff has nothing
    // to measure from. Pinning the immediate re-stage means any future backoff
    // introduced here fails loudly instead of hiding behind a clock the test
    // advanced for it.
    adapter.accept_next(1);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        runtime.session().epoch(&group_id).unwrap().0,
        source_epoch.0 + 1,
        "the obligation must re-stage and land a fresh self-update after the rejected one rolled back"
    );
    assert_eq!(
        runtime
            .session()
            .maintenance_obligation(&obligation_id)
            .unwrap()
            .unwrap()
            .phase,
        cgka_traits::MaintenancePhase::Complete,
        "the rotation the rejected publication owed must end up satisfied"
    );
}
