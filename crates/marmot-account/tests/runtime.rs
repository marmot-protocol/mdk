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
use cgka_traits::storage::{
    KeyPackageBundleStorage, LeaveRequestStorage, MaintenanceStorage, MessageStorage,
    OutboundFanoutStorage,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::{
    EpochId, FanoutMlsState, FanoutTargetStatus, GroupId, MemberId, MessageId, OutboundFanout,
    RetiredKeyPackagePublication, TransportAccountActivation, TransportAdapter,
    TransportAdapterError, TransportDelivery, TransportDeliveryPlane, TransportDeliverySource,
    TransportEndpoint, TransportEndpointFailure, TransportEndpointFailureKind,
    TransportEndpointReceipt, TransportEndpointRejectionCategory, TransportFanoutAttemptState,
    TransportFanoutTarget, TransportGroupSync, TransportPublishFailure, TransportPublishReport,
    TransportPublishRequest, TransportPublishTarget,
};
use marmot_account::{
    AccountDeviceEffects, AccountDeviceRuntime, AccountError, AccountVisibilityBatch,
    AccountVisibilityOutboundAction, AccountVisibilitySource,
    DetailedKeyPackagePublishReceipt as KeyPackagePublishReceipt, KeyPackagePublication,
    KeyPackagePublishError, KeyPackagePublishReceipt as LegacyKeyPackagePublishReceipt,
    KeyPackagePublisher, MaintenanceRandom, MonotonicClock, NoopKeyPackagePublisher,
    PendingResolution, PublishedApplicationMessage, StaticTransportRouting, TransportRoutingError,
    TransportRoutingPolicy, WallClock,
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

fn flatten_visibility_batches(batches: &[AccountVisibilityBatch]) -> AccountDeviceEffects {
    let mut effects = AccountDeviceEffects::default();
    for batch in batches {
        effects.events.extend(batch.effects.events.clone());
        effects.queued.extend(batch.effects.queued.clone());
        effects
            .pending_convergence
            .extend(batch.effects.pending_convergence.clone());
        effects.reports.extend(batch.effects.reports.clone());
        effects.fanout.extend(batch.effects.fanout.clone());
        effects.failures.extend(batch.effects.failures.clone());
        effects
            .action_outcomes
            .extend(batch.effects.action_outcomes.clone());
        effects
            .published_app_messages
            .extend(batch.effects.published_app_messages.clone());
        effects
            .welcome_failures
            .extend(batch.effects.welcome_failures.clone());
        effects.pending.extend(batch.effects.pending.clone());
        effects.maintenance_disposition = batch.effects.maintenance_disposition;
    }
    effects
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

async fn joined_selfremove_member(
    directory: &std::path::Path,
    key: &SqlCipherKey,
    tag: &str,
) -> (AccountDeviceSession, std::path::PathBuf, Vec<u8>, GroupId) {
    let alice_identity = format!("alice-{tag}").into_bytes();
    let bob_identity = format!("bob-{tag}").into_bytes();
    let alice_path = directory.join(format!("alice-{tag}.sqlite"));
    let bob_path = directory.join(format!("bob-{tag}.sqlite"));
    let mut alice = session_with_registry(alice_path, key, &alice_identity, selfremove_registry());
    let mut bob = session_with_registry(&bob_path, key, &bob_identity, selfremove_registry());
    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: format!("selfremove {tag}"),
            description: String::new(),
            members: vec![bob_key_package],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let (pending, welcome) = match created.effects.publish.as_slice() {
        [PublishWork::GroupCreated { pending, welcomes }] => (*pending, welcomes[0].clone()),
        other => panic!("expected one GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();
    (bob, bob_path, bob_identity, group_id)
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
    accept_policy: Mutex<Option<Vec<TransportEndpoint>>>,
    error_endpoints: Mutex<Vec<TransportEndpoint>>,
    error_kind: Mutex<Option<TransportEndpointFailureKind>>,
    publish_errors: Mutex<VecDeque<bool>>,
    reported_message_ids: Mutex<VecDeque<MessageId>>,
    welcome_gate: Mutex<Option<Arc<WelcomePublishGate>>>,
    all_publish_gate: Mutex<Option<Arc<WelcomePublishGate>>>,
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

    fn gate_all_publishes(&self) -> Arc<WelcomePublishGate> {
        let gate = Arc::new(WelcomePublishGate::default());
        *self.inner.all_publish_gate.lock().unwrap() = Some(gate.clone());
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

    /// Persistent endpoint accept policy: every publish call accepts exactly
    /// the intersection of its target endpoints with this set. Deterministic
    /// under concurrent single-endpoint publishes, unlike the FIFO knobs.
    fn accept_only_endpoints(&self, endpoints: Vec<TransportEndpoint>) {
        *self.inner.accept_policy.lock().unwrap() = Some(endpoints);
    }

    /// Persistent whole-call error policy: a publish call whose target
    /// endpoints all sit in this set returns `Err` instead of a report.
    fn error_for_endpoints(&self, endpoints: Vec<TransportEndpoint>) {
        *self.inner.error_endpoints.lock().unwrap() = endpoints;
        *self.inner.error_kind.lock().unwrap() = None;
    }

    fn fail_endpoints_as(
        &self,
        endpoints: Vec<TransportEndpoint>,
        kind: TransportEndpointFailureKind,
    ) {
        *self.inner.error_endpoints.lock().unwrap() = endpoints;
        *self.inner.error_kind.lock().unwrap() = Some(kind);
    }

    fn report_message_id_next(&self, message_id: MessageId) {
        self.inner
            .reported_message_ids
            .lock()
            .unwrap()
            .push_back(message_id);
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
        let publish_gate = self
            .inner
            .all_publish_gate
            .lock()
            .unwrap()
            .clone()
            .or_else(|| {
                matches!(&request.message.envelope, TransportEnvelope::Welcome { .. })
                    .then(|| self.inner.welcome_gate.lock().unwrap().clone())
                    .flatten()
            });
        if let Some(gate) = publish_gate {
            let active = gate.active.fetch_add(1, Ordering::SeqCst) + 1;
            gate.max_active.fetch_max(active, Ordering::SeqCst);
            let permit = gate.release.acquire().await.unwrap();
            permit.forget();
            gate.active.fetch_sub(1, Ordering::SeqCst);
        }
        let ambiguous_error = self
            .inner
            .publish_errors
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(false);
        if ambiguous_error {
            return Err(TransportAdapterError::Publish(
                "injected ambiguous adapter failure".into(),
            ));
        }
        {
            let error_endpoints = self.inner.error_endpoints.lock().unwrap();
            if !error_endpoints.is_empty()
                && request
                    .target
                    .endpoints()
                    .iter()
                    .all(|endpoint| error_endpoints.contains(endpoint))
            {
                if let Some(kind) = *self.inner.error_kind.lock().unwrap() {
                    let failures = request
                        .target
                        .endpoints()
                        .iter()
                        .cloned()
                        .map(|endpoint| TransportEndpointFailure {
                            endpoint,
                            reason: "injected typed endpoint failure".into(),
                            kind,
                            rejection_category: None,
                        })
                        .collect();
                    let message_id = self
                        .inner
                        .reported_message_ids
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or(request.message.id);
                    return Err(TransportAdapterError::PublishEndpoints(
                        TransportPublishFailure::with_endpoint_failures(
                            "injected typed endpoint failure",
                            failures,
                        )
                        .with_message_id(message_id),
                    ));
                }
                return Err(TransportAdapterError::Publish(
                    "endpoint-policy adapter error".into(),
                ));
            }
        }
        let accepted_endpoints = self.inner.accept_policy.lock().unwrap().clone();
        if let Some(accepted_endpoints) = accepted_endpoints {
            return Ok(TransportPublishReport {
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
                    .filter(|endpoint| accepted_endpoints.contains(endpoint))
                    .cloned()
                    .map(|endpoint| TransportEndpointReceipt {
                        endpoint,
                        accepted_at: None,
                    })
                    .collect(),
                failed: request
                    .target
                    .endpoints()
                    .iter()
                    .filter(|endpoint| !accepted_endpoints.contains(endpoint))
                    .cloned()
                    .map(|endpoint| TransportEndpointFailure {
                        endpoint,
                        reason: "injected explicit relay rejection".into(),
                        kind: TransportEndpointFailureKind::TerminalRejected,
                        rejection_category: Some(TransportEndpointRejectionCategory::Blocked),
                    })
                    .collect(),
                required_acks: request.required_acks,
            });
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
    ) -> Result<LegacyKeyPackagePublishReceipt, KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication.clone());
        Ok(LegacyKeyPackagePublishReceipt {
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
    reauthor_after_secs: Option<u64>,
}

impl PartialFanoutKeyPackages {
    fn reauthor_after_secs(mut self, seconds: u64) -> Self {
        self.reauthor_after_secs = Some(seconds);
        self
    }

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

    fn signed_artifact_reauthor_at_age_secs(&self) -> Option<u64> {
        self.reauthor_after_secs
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
    ) -> Result<LegacyKeyPackagePublishReceipt, KeyPackagePublishError> {
        let call_index = self.publications.lock().unwrap().len();
        self.publications
            .lock()
            .unwrap()
            .push((publication.clone(), artifact.clone()));
        if call_index == 0 {
            Ok(LegacyKeyPackagePublishReceipt {
                accepted: publication.endpoints.iter().take(1).cloned().collect(),
                failed: publication.endpoints.iter().skip(1).cloned().collect(),
            })
        } else {
            Ok(LegacyKeyPackagePublishReceipt {
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
    ) -> Result<LegacyKeyPackagePublishReceipt, KeyPackagePublishError> {
        panic!("an unsigned replacement must never reach the network")
    }
}

#[derive(Clone, Default)]
struct ReauthorPrepareFailsKeyPackages {
    preparations: Arc<Mutex<Vec<KeyPackagePublication>>>,
    publications: Arc<Mutex<Vec<KeyPackagePublication>>>,
}

#[async_trait]
impl KeyPackagePublisher for ReauthorPrepareFailsKeyPackages {
    fn legacy_slot_id(
        &self,
        account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        Ok(Some(test_key_package_slot(account_id)))
    }

    fn signed_artifact_reauthor_at_age_secs(&self) -> Option<u64> {
        Some(600)
    }

    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<cgka_traits::SignedPublicationArtifact, KeyPackagePublishError> {
        let mut preparations = self.preparations.lock().unwrap();
        preparations.push(publication.clone());
        if preparations.len() > 1 {
            return Err(KeyPackagePublishError::unexposed(
                "injected reauthor signing failure",
            ));
        }
        Ok(test_key_package_artifact(&publication))
    }

    async fn publish_prepared_key_package(
        &self,
        publication: &KeyPackagePublication,
        _artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<LegacyKeyPackagePublishReceipt, KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication.clone());
        Err(KeyPackagePublishError::unexposed(
            "injected initial publish failure",
        ))
    }
}

/// Publisher that fails the first `fail_first` publish attempts, then succeeds,
/// recording every publication it is asked to send (including failed ones).
#[derive(Clone)]
struct FlakyKeyPackages {
    publications: Arc<Mutex<Vec<KeyPackagePublication>>>,
    artifacts: Arc<Mutex<Vec<cgka_traits::SignedPublicationArtifact>>>,
    remaining_failures: Arc<Mutex<usize>>,
    reauthor_after_secs: Option<u64>,
}

impl FlakyKeyPackages {
    fn new(fail_first: usize) -> Self {
        Self {
            publications: Arc::new(Mutex::new(Vec::new())),
            artifacts: Arc::new(Mutex::new(Vec::new())),
            remaining_failures: Arc::new(Mutex::new(fail_first)),
            reauthor_after_secs: None,
        }
    }

    fn reauthor_after_secs(mut self, seconds: u64) -> Self {
        self.reauthor_after_secs = Some(seconds);
        self
    }

    fn publications(&self) -> Vec<KeyPackagePublication> {
        self.publications.lock().unwrap().clone()
    }

    fn artifacts(&self) -> Vec<cgka_traits::SignedPublicationArtifact> {
        self.artifacts.lock().unwrap().clone()
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

    fn signed_artifact_reauthor_at_age_secs(&self) -> Option<u64> {
        self.reauthor_after_secs
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
    ) -> Result<LegacyKeyPackagePublishReceipt, KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication.clone());
        self.artifacts.lock().unwrap().push(artifact.clone());
        let mut remaining = self.remaining_failures.lock().unwrap();
        if *remaining > 0 {
            *remaining -= 1;
            return Err(KeyPackagePublishError::unexposed(
                "injected publish failure",
            ));
        }
        Ok(LegacyKeyPackagePublishReceipt {
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
    ) -> Result<LegacyKeyPackagePublishReceipt, KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication.clone());
        // External publish succeeded; a subsequent local step (e.g. cache write)
        // failed. The KeyPackage is already exposed.
        Err(KeyPackagePublishError::exposed(
            "injected post-exposure failure (e.g. local cache write)",
        ))
    }
}

/// Publisher that crosses the external-send boundary and then deliberately
/// remains pending. Dropping the caller future deterministically models task
/// cancellation between socket I/O and receipt persistence.
#[derive(Clone)]
struct BlockingAfterSendKeyPackages {
    sent: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
    publications: Arc<Mutex<Vec<KeyPackagePublication>>>,
    artifacts: Arc<Mutex<Vec<cgka_traits::SignedPublicationArtifact>>>,
}

impl Default for BlockingAfterSendKeyPackages {
    fn default() -> Self {
        Self {
            sent: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
            publications: Arc::new(Mutex::new(Vec::new())),
            artifacts: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl KeyPackagePublisher for BlockingAfterSendKeyPackages {
    fn legacy_slot_id(
        &self,
        account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        Ok(Some(test_key_package_slot(account_id)))
    }

    fn signed_artifact_reauthor_at_age_secs(&self) -> Option<u64> {
        Some(600)
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
    ) -> Result<LegacyKeyPackagePublishReceipt, KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication.clone());
        self.artifacts.lock().unwrap().push(artifact.clone());
        self.sent.add_permits(1);
        let permit = self
            .release
            .acquire()
            .await
            .expect("test release semaphore remains open");
        permit.forget();
        Ok(LegacyKeyPackagePublishReceipt {
            accepted: publication.endpoints.clone(),
            failed: Vec::new(),
        })
    }
}

/// Scriptable transport boundary for privacy-journal recovery tests. Empty
/// receipt queues default to successful endpoint acknowledgements.
type KeyPackageDeletionCall = (MessageId, Vec<TransportEndpoint>);

#[derive(Clone, Default)]
struct JournalKeyPackages {
    publications: Arc<Mutex<Vec<KeyPackagePublication>>>,
    artifacts: Arc<Mutex<Vec<cgka_traits::SignedPublicationArtifact>>>,
    publication_receipts: Arc<Mutex<VecDeque<KeyPackagePublishReceipt>>>,
    deletions: Arc<Mutex<Vec<KeyPackageDeletionCall>>>,
    deletion_receipts: Arc<Mutex<VecDeque<KeyPackagePublishReceipt>>>,
    reauthor_after_secs: Option<u64>,
    reject_empty_prepares: bool,
}

impl JournalKeyPackages {
    fn reauthor_after_secs(mut self, seconds: u64) -> Self {
        self.reauthor_after_secs = Some(seconds);
        self
    }

    fn reject_empty_prepares(mut self) -> Self {
        self.reject_empty_prepares = true;
        self
    }

    fn with_publication_receipts(self, receipts: Vec<KeyPackagePublishReceipt>) -> Self {
        *self.publication_receipts.lock().unwrap() = receipts.into();
        self
    }

    fn with_deletion_receipts(self, receipts: Vec<KeyPackagePublishReceipt>) -> Self {
        *self.deletion_receipts.lock().unwrap() = receipts.into();
        self
    }

    fn artifacts(&self) -> Vec<cgka_traits::SignedPublicationArtifact> {
        self.artifacts.lock().unwrap().clone()
    }

    fn publications(&self) -> Vec<KeyPackagePublication> {
        self.publications.lock().unwrap().clone()
    }

    fn deletions(&self) -> Vec<KeyPackageDeletionCall> {
        self.deletions.lock().unwrap().clone()
    }
}

#[async_trait]
impl KeyPackagePublisher for JournalKeyPackages {
    fn legacy_slot_id(
        &self,
        account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        Ok(Some(test_key_package_slot(account_id)))
    }

    fn signed_artifact_reauthor_at_age_secs(&self) -> Option<u64> {
        self.reauthor_after_secs
    }

    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<cgka_traits::SignedPublicationArtifact, KeyPackagePublishError> {
        if self.reject_empty_prepares && publication.endpoints.is_empty() {
            return Err(KeyPackagePublishError::unexposed(
                "test publisher refuses to sign an empty relay fanout",
            ));
        }
        Ok(test_key_package_artifact(&publication))
    }

    async fn publish_prepared_key_package(
        &self,
        publication: &KeyPackagePublication,
        artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<LegacyKeyPackagePublishReceipt, KeyPackagePublishError> {
        self.publish_prepared_key_package_detailed(publication, artifact)
            .await
            .map(Into::into)
    }

    async fn publish_prepared_key_package_detailed(
        &self,
        publication: &KeyPackagePublication,
        artifact: &cgka_traits::SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication.clone());
        self.artifacts.lock().unwrap().push(artifact.clone());
        Ok(self
            .publication_receipts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| KeyPackagePublishReceipt {
                accepted: publication.endpoints.clone(),
                rejected: Vec::new(),
                confirmed_absent: Vec::new(),
                failed: Vec::new(),
            }))
    }

    async fn delete_key_package_revision(
        &self,
        event_id: &MessageId,
        endpoints: &[TransportEndpoint],
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        self.deletions
            .lock()
            .unwrap()
            .push((event_id.clone(), endpoints.to_vec()));
        Ok(self
            .deletion_receipts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| KeyPackagePublishReceipt {
                accepted: endpoints.to_vec(),
                rejected: Vec::new(),
                confirmed_absent: Vec::new(),
                failed: Vec::new(),
            }))
    }
}

fn deletion_target(endpoint: &TransportEndpoint) -> TransportFanoutTarget {
    TransportFanoutTarget {
        endpoint: endpoint.clone(),
        state: TransportFanoutAttemptState::Unattempted,
        attempt_count: 0,
        last_attempt_at: None,
        failure_code: None,
    }
}

fn retired_revision(
    event_id: MessageId,
    authored_created_at: Timestamp,
    endpoints: &[TransportEndpoint],
) -> RetiredKeyPackagePublication {
    RetiredKeyPackagePublication {
        event_id,
        authored_created_at,
        key_package_ref: None,
        package_not_after: None,
        delete_without_successor: true,
        deletion_targets: endpoints.iter().map(deletion_target).collect(),
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
async fn durable_cutover_gate_blocks_manual_and_automatic_publication_but_not_exact_deletion() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot durable cutover publication gate key").unwrap();
    let endpoint_a = TransportEndpoint("wss://keys-a.example".into());
    let endpoint_b = TransportEndpoint("wss://keys-b.example".into());
    let routing = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![endpoint_a.clone(), endpoint_b.clone()]);
    let publisher = JournalKeyPackages::default().with_publication_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: vec![endpoint_a.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: vec![endpoint_b.clone()],
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoint_b.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let wall = Arc::new(TestWallClock::new(10_000));
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

    runtime.publish_fresh_key_package().await.unwrap();
    let deletion_id = MessageId::new(vec![0x81; 32]);
    runtime
        .prepare_key_package_deletion_recovery(&deletion_id, vec![endpoint_a.clone()])
        .unwrap();
    runtime
        .set_key_package_cutover_publication_blocked(true)
        .unwrap();
    assert!(!runtime.key_package_network_maintenance_due().unwrap());
    assert!(!runtime.key_package_has_pending_fanout().unwrap());

    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(publisher.publications().len(), 1);
    assert_eq!(
        publisher.deletions(),
        vec![(deletion_id, vec![endpoint_a.clone()])],
        "the publication gate must not suppress durable exact deletion retry"
    );
    for error in [
        runtime.republish_key_package().await.unwrap_err(),
        runtime.publish_fresh_key_package().await.unwrap_err(),
    ] {
        assert!(error.to_string().contains("cutover discovery"));
    }
    assert_eq!(publisher.publications().len(), 1);
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
    assert!(
        restarted
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .cutover_publication_blocked
    );
    assert!(
        restarted.publish_fresh_key_package().await.is_err(),
        "restart must not clear the durable cutover interlock"
    );

    wall.set(10_031);
    restarted
        .set_key_package_cutover_publication_blocked(false)
        .unwrap();
    assert!(restarted.key_package_has_pending_fanout().unwrap());
    restarted.run_due_maintenance().await.unwrap();
    let publications = publisher.publications();
    assert_eq!(publications.len(), 2);
    assert_eq!(publications[1].endpoints, vec![endpoint_b]);
}

#[tokio::test]
async fn observing_exact_live_revision_preserves_relay_ordering_high_water() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot live revision high-water key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let publisher = JournalKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(10_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(29)),
    );

    runtime.publish_fresh_key_package().await.unwrap();
    runtime
        .set_key_package_cutover_publication_blocked(true)
        .unwrap();
    let lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    let live_event_id = lifecycle.authored_event_id.unwrap();
    let stable_slot_id = lifecycle.stable_slot_id;
    let observed_created_at = Timestamp(10_025);
    let observed_endpoint = TransportEndpoint("wss://historical-keys.example".into());
    assert!(
        runtime
            .observe_live_key_package_publication(
                stable_slot_id.clone(),
                &MessageId::new(vec![0xa1; 32]),
                observed_created_at,
                vec![observed_endpoint.clone()],
            )
            .is_err(),
        "an unrelated same-slot event may not rewrite live lifecycle metadata"
    );
    let (admitted, deferred) = runtime
        .observe_live_key_package_publication(
            stable_slot_id,
            &live_event_id,
            observed_created_at,
            vec![observed_endpoint.clone()],
        )
        .unwrap();
    assert_eq!(admitted, vec![observed_endpoint.clone()]);
    assert!(deferred.is_empty());
    let observed = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        observed.authored_event_created_at,
        Some(observed_created_at)
    );
    assert!(observed.publication_targets.iter().any(|target| {
        target.endpoint == observed_endpoint
            && target.state == TransportFanoutAttemptState::Accepted
    }));

    runtime
        .set_key_package_cutover_publication_blocked(false)
        .unwrap();
    runtime.publish_fresh_key_package().await.unwrap();
    assert_eq!(publisher.artifacts()[1].created_at, Timestamp(10_026));
}

#[tokio::test]
async fn unparsed_same_slot_discovery_preserves_ordering_high_water_with_failed_deletion() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot unparsed discovery high-water key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let publisher =
        JournalKeyPackages::default().with_deletion_receipts(vec![KeyPackagePublishReceipt {
            accepted: Vec::new(),
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: vec![endpoint.clone()],
        }]);
    let wall = Arc::new(TestWallClock::new(10_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(31)),
    );

    runtime.publish_fresh_key_package().await.unwrap();
    runtime
        .set_key_package_cutover_publication_blocked(true)
        .unwrap();
    let lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    let stable_slot_id = lifecycle.stable_slot_id;
    let discovered_id = MessageId::new(vec![0x91; 32]);
    let discovered_created_at = Timestamp(10_025);
    let (admitted, deferred) = runtime
        .journal_discovered_unparsed_key_package_publication(
            stable_slot_id,
            discovered_id.clone(),
            discovered_created_at,
            vec![endpoint.clone()],
        )
        .unwrap();
    assert_eq!(admitted, vec![endpoint.clone()]);
    assert!(deferred.is_empty());
    assert_eq!(
        runtime
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .authored_event_created_at,
        Some(discovered_created_at)
    );

    runtime
        .set_key_package_cutover_publication_blocked(false)
        .unwrap();
    runtime.publish_fresh_key_package().await.unwrap();
    let artifacts = publisher.artifacts();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(artifacts[1].created_at, Timestamp(10_026));
    let repaired = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(
        repaired
            .retired_publications_pending_deletion
            .iter()
            .any(|retired| retired.event_id == discovered_id
                && retired.authored_created_at == discovered_created_at
                && retired.deletion_targets.len() == 1),
        "an ambiguous deletion keeps the exact discovered liability durable"
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
async fn stale_pending_key_package_is_reauthored_once_and_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot stale pending key package key").unwrap();
    let wall = Arc::new(TestWallClock::new(10_000));
    let policy = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]);
    let publisher = FlakyKeyPackages::new(3).reauthor_after_secs(600);
    let mut runtime = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        policy.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(31)),
    );

    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("first publication is intentionally unacknowledged");
    wall.set(10_599);
    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("an artifact younger than the policy boundary stays exact");
    wall.set(10_600);
    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("the first publication of the reauthored revision is injected to fail");

    let publications = publisher.publications();
    let artifacts = publisher.artifacts();
    assert_eq!(publications.len(), 3);
    assert_eq!(artifacts.len(), 3);
    assert_eq!(publications[0], publications[1]);
    assert_eq!(artifacts[0], artifacts[1]);
    assert_eq!(publications[2].key_package, publications[0].key_package);
    assert_eq!(publications[2].slot_id, publications[0].slot_id);
    assert_eq!(publications[2].created_at, Timestamp(10_600));
    assert_ne!(artifacts[2], artifacts[0]);

    let pending = runtime
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .pending_replacement
        .expect("failed reauthored publication remains durable");
    assert_eq!(pending.authored_created_at, Timestamp(10_600));
    assert_eq!(pending.signed_event, Some(artifacts[2].clone()));
    assert_eq!(pending.targets[0].attempt_count, 1);
    drop(runtime);

    wall.set(10_601);
    let mut restarted = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        policy,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(31)),
    );
    restarted
        .publish_fresh_key_package()
        .await
        .expect("restart retries the durable reauthored revision exactly");

    let publications = publisher.publications();
    let artifacts = publisher.artifacts();
    assert_eq!(publications.len(), 4);
    assert_eq!(publications[3], publications[2]);
    assert_eq!(artifacts[3], artifacts[2]);
    let current = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert!(current.pending_replacement.is_none());
    assert_eq!(current.authored_event_id, Some(artifacts[2].id.clone()));
    assert_eq!(current.authored_event_created_at, Some(Timestamp(10_600)));
    assert_eq!(current.authored_signed_event, Some(artifacts[2].clone()));
}

#[tokio::test]
async fn cancelled_key_package_send_keeps_possible_exposure_and_retires_old_revision_after_restart()
{
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot cancelled key package send key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let routing = StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]);
    let wall = Arc::new(TestWallClock::new(10_000));
    let blocking = BlockingAfterSendKeyPackages::default();
    let sent = blocking.sent.clone();
    let mut runtime = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        blocking.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(53)),
    );

    let mut publish = Box::pin(runtime.publish_fresh_key_package());
    let sent_permit = tokio::select! {
        permit = sent.acquire() => permit.expect("send marker semaphore remains open"),
        result = &mut publish => panic!("publisher returned before cancellation boundary: {result:?}"),
    };
    sent_permit.forget();
    drop(publish);

    let old_artifact = blocking.artifacts.lock().unwrap()[0].clone();
    let after_cancel = runtime.key_package_maintenance_status().unwrap().unwrap();
    let pending = after_cancel
        .pending_replacement
        .expect("cancelled send retains its durable pending replacement");
    assert_eq!(pending.signed_event, Some(old_artifact.clone()));
    assert_eq!(pending.targets.len(), 1);
    assert_eq!(
        pending.targets[0].state,
        TransportFanoutAttemptState::AttemptedFailed
    );
    assert_eq!(pending.targets[0].attempt_count, 1);
    assert_eq!(
        pending.targets[0].failure_code.as_deref(),
        Some("possible_exposure")
    );
    drop(runtime);

    wall.set(10_600);
    let succeeding = JournalKeyPackages::default().reauthor_after_secs(600);
    let mut restarted = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        succeeding.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(53)),
    );
    restarted
        .publish_fresh_key_package()
        .await
        .expect("stale cancelled revision is reauthored and published");
    let reauthored = succeeding.artifacts();
    assert_eq!(reauthored.len(), 1);
    assert_ne!(reauthored[0].id, old_artifact.id);
    let lifecycle = restarted.key_package_maintenance_status().unwrap().unwrap();
    let retired = lifecycle
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == old_artifact.id)
        .expect("old ambiguously exposed event remains a durable deletion obligation");
    assert_eq!(retired.deletion_targets.len(), 1);
    assert_eq!(retired.deletion_targets[0].endpoint, endpoint);
    drop(restarted);

    let reopened = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        routing,
        succeeding,
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(53)),
    );
    let after_second_restart = reopened.key_package_maintenance_status().unwrap().unwrap();
    assert!(
        after_second_restart
            .retired_publications_pending_deletion
            .iter()
            .any(|retired| {
                retired.event_id == old_artifact.id
                    && retired
                        .deletion_targets
                        .iter()
                        .any(|target| target.endpoint == endpoint)
            })
    );
}

#[tokio::test]
async fn publication_negative_ack_never_proves_the_signed_event_absent() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot publication negative ack key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let wall = Arc::new(TestWallClock::new(20_000));
    let publisher = JournalKeyPackages::default()
        .reauthor_after_secs(600)
        .with_publication_receipts(vec![
            KeyPackagePublishReceipt {
                accepted: Vec::new(),
                rejected: vec![endpoint.clone()],
                confirmed_absent: Vec::new(),
                failed: Vec::new(),
            },
            KeyPackagePublishReceipt {
                accepted: vec![endpoint.clone()],
                rejected: Vec::new(),
                confirmed_absent: Vec::new(),
                failed: Vec::new(),
            },
        ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(59)),
    );

    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("a negative publication acknowledgement accepts no endpoint");
    let old_artifact = publisher.artifacts()[0].clone();
    let after_negative = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        after_negative.pending_replacement.as_ref().unwrap().targets[0]
            .failure_code
            .as_deref(),
        Some("transport_rejected"),
        "normal publication cannot distinguish a truly first attempt from legacy possible exposure"
    );

    wall.set(20_600);
    runtime
        .publish_fresh_key_package()
        .await
        .expect("a stale negatively acknowledged revision may be replaced");
    assert!(
        runtime
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .retired_publications_pending_deletion
            .iter()
            .any(|retired| {
                retired.event_id == old_artifact.id
                    && retired
                        .deletion_targets
                        .iter()
                        .any(|target| target.endpoint == endpoint)
            }),
        "the negative acknowledgement cannot erase possible pre-upgrade relay exposure"
    );
}

#[tokio::test]
async fn fresh_publication_ignores_extraneous_acceptance_and_retries_deletion_only_absence_claim() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot scoped fresh publication receipt key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let extraneous = TransportEndpoint("wss://not-attempted.example".into());
    let wall = Arc::new(TestWallClock::new(21_000));
    let publisher = JournalKeyPackages::default().with_publication_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: vec![extraneous.clone(), extraneous],
            rejected: Vec::new(),
            confirmed_absent: vec![endpoint.clone(), endpoint.clone()],
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoint.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(60)),
    );

    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("an acceptance outside the attempted fanout cannot promote a replacement");
    let pending = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(pending.current_key_package.is_none());
    let target = &pending.pending_replacement.as_ref().unwrap().targets[0];
    assert_eq!(target.endpoint, endpoint);
    assert_eq!(target.state, TransportFanoutAttemptState::AttemptedFailed);
    assert_eq!(target.failure_code.as_deref(), Some("possible_exposure"));
    assert_ne!(target.failure_code.as_deref(), Some("confirmed_absent"));

    runtime.pause_maintenance();
    wall.set(21_030);
    runtime
        .run_due_maintenance()
        .await
        .expect("the pending revision remains automatically retryable");
    let promoted = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(promoted.pending_replacement.is_none());
    assert!(promoted.current_key_package.is_some());
    assert_eq!(publisher.publications().len(), 2);
    assert_eq!(publisher.publications()[1].endpoints, vec![endpoint]);
}

#[tokio::test]
async fn current_republication_ignores_extraneous_acceptance_and_retries_absence_claim() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot scoped current publication receipt key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let extraneous = TransportEndpoint("wss://not-attempted.example".into());
    let wall = Arc::new(TestWallClock::new(22_000));
    let publisher = JournalKeyPackages::default().with_publication_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: vec![endpoint.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: vec![extraneous],
            rejected: Vec::new(),
            confirmed_absent: vec![endpoint.clone()],
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoint.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(62)),
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let mut lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    let artifact = lifecycle.authored_signed_event.clone().unwrap();
    let republish_at = lifecycle.current_not_before.unwrap().0;
    lifecycle.publication_targets[0].state = TransportFanoutAttemptState::Unattempted;
    lifecycle.publication_targets[0].attempt_count = 0;
    lifecycle.publication_targets[0].last_attempt_at = None;
    lifecycle.publication_targets[0].failure_code = None;
    runtime
        .session()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    wall.set(republish_at);

    runtime
        .republish_key_package()
        .await
        .expect_err("an out-of-scope acceptance cannot make republication succeed");
    let retrying = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(retrying.authored_signed_event, Some(artifact.clone()));
    assert_eq!(
        (
            retrying.publication_targets[0].state,
            retrying.publication_targets[0].failure_code.as_deref(),
        ),
        (
            TransportFanoutAttemptState::AttemptedFailed,
            Some("possible_exposure"),
        )
    );
    assert_ne!(
        retrying.publication_targets[0].failure_code.as_deref(),
        Some("confirmed_absent")
    );

    runtime.pause_maintenance();
    wall.set(republish_at.saturating_add(30));
    runtime
        .run_due_maintenance()
        .await
        .expect("the current exact revision remains automatically retryable");
    let completed = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(completed.authored_signed_event, Some(artifact));
    assert_eq!(
        completed.publication_targets[0].state,
        TransportFanoutAttemptState::Accepted
    );
    assert_eq!(publisher.publications().len(), 3);
    assert_eq!(publisher.publications()[2].endpoints, vec![endpoint]);
}

#[tokio::test]
async fn legacy_signed_unattempted_revision_negative_retry_remains_deletable_after_reauthor() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot legacy unattempted upgrade key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let routing = StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]);
    let wall = Arc::new(TestWallClock::new(30_000));

    let mut legacy = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        JournalKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(61)),
    );
    legacy
        .prepare_fresh_key_package(vec![endpoint.clone()])
        .await
        .expect("legacy fixture has a durable signed revision before network I/O");
    let legacy_lifecycle = legacy.key_package_maintenance_status().unwrap().unwrap();
    let legacy_pending = legacy_lifecycle.pending_replacement.unwrap();
    let old_artifact = legacy_pending.signed_event.unwrap();
    assert_eq!(legacy_pending.targets.len(), 1);
    assert_eq!(
        legacy_pending.targets[0].state,
        TransportFanoutAttemptState::Unattempted
    );
    assert_eq!(legacy_pending.targets[0].attempt_count, 0);
    assert!(legacy_pending.targets[0].last_attempt_at.is_none());
    drop(legacy);

    let upgraded_publisher = JournalKeyPackages::default()
        .reauthor_after_secs(600)
        .with_publication_receipts(vec![
            KeyPackagePublishReceipt {
                accepted: Vec::new(),
                rejected: vec![endpoint.clone()],
                confirmed_absent: Vec::new(),
                failed: Vec::new(),
            },
            KeyPackagePublishReceipt {
                accepted: vec![endpoint.clone()],
                rejected: Vec::new(),
                confirmed_absent: Vec::new(),
                failed: Vec::new(),
            },
        ]);
    let mut upgraded = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        upgraded_publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(61)),
    );
    upgraded
        .publish_fresh_key_package()
        .await
        .expect_err("the legacy revision retry is negatively acknowledged");
    let after_negative = upgraded.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        after_negative
            .pending_replacement
            .as_ref()
            .unwrap()
            .signed_event,
        Some(old_artifact.clone())
    );
    assert_eq!(
        after_negative.pending_replacement.as_ref().unwrap().targets[0]
            .failure_code
            .as_deref(),
        Some("transport_rejected")
    );
    drop(upgraded);

    wall.set(30_600);
    let mut restarted = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        upgraded_publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(61)),
    );
    restarted
        .publish_fresh_key_package()
        .await
        .expect("the stale legacy revision is reauthored after restart");
    let upgraded_artifacts = upgraded_publisher.artifacts();
    assert_eq!(upgraded_artifacts[0], old_artifact);
    assert_ne!(upgraded_artifacts[1].id, old_artifact.id);
    let retired = restarted
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .retired_publications_pending_deletion
        .into_iter()
        .find(|retired| retired.event_id == old_artifact.id)
        .expect("legacy possibly exposed event id remains durably deletable");
    assert_eq!(retired.deletion_targets.len(), 1);
    assert_eq!(retired.deletion_targets[0].endpoint, endpoint);
    drop(restarted);

    let reopened = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        routing,
        upgraded_publisher,
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(61)),
    );
    assert!(
        reopened
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .retired_publications_pending_deletion
            .iter()
            .any(|retired| {
                retired.event_id == old_artifact.id
                    && retired
                        .deletion_targets
                        .iter()
                        .any(|target| target.endpoint == endpoint)
            })
    );
}

#[tokio::test]
async fn due_maintenance_retries_all_rejected_pending_key_package_after_backoff() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot all rejected worker retry key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let wall = Arc::new(TestWallClock::new(35_000));
    let publisher = JournalKeyPackages::default().with_publication_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: Vec::new(),
            rejected: vec![endpoint.clone()],
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoint.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(63)),
    );
    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("the first normal publication is rejected everywhere");
    let first = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        first.pending_replacement.as_ref().unwrap().targets[0]
            .failure_code
            .as_deref(),
        Some("transport_rejected")
    );
    runtime.pause_maintenance();

    wall.set(35_030);
    runtime
        .run_due_maintenance()
        .await
        .expect("worker-shaped maintenance retries the durable pending revision");
    let artifacts = publisher.artifacts();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(artifacts[0], artifacts[1]);
    let recovered = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(recovered.pending_replacement.is_none());
    assert_eq!(recovered.authored_signed_event, Some(artifacts[0].clone()));
    assert!(recovered.publication_targets.iter().all(|target| {
        target.endpoint == endpoint
            && target.state == TransportFanoutAttemptState::Accepted
            && target.failure_code.is_none()
    }));
}

#[tokio::test]
async fn due_maintenance_finishes_partially_accepted_key_package_fanout_after_backoff() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot partial worker fanout key").unwrap();
    let endpoint_a = TransportEndpoint("wss://keys-a.example".into());
    let endpoint_b = TransportEndpoint("wss://keys-b.example".into());
    let wall = Arc::new(TestWallClock::new(36_000));
    let publisher = JournalKeyPackages::default().with_publication_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: vec![endpoint_a.clone()],
            rejected: vec![endpoint_b.clone()],
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoint_b.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![endpoint_a.clone(), endpoint_b.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(65)),
    );
    runtime
        .publish_fresh_key_package()
        .await
        .expect("one accepted endpoint promotes the current key package");
    let partial = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(partial.phase, cgka_traits::MaintenancePhase::Fanout);
    let rejected = partial
        .publication_targets
        .iter()
        .find(|target| target.endpoint == endpoint_b)
        .unwrap();
    assert_eq!(rejected.failure_code.as_deref(), Some("transport_rejected"));
    runtime.pause_maintenance();

    wall.set(36_030);
    runtime
        .run_due_maintenance()
        .await
        .expect("worker-shaped maintenance retries only the rejected endpoint");
    let publications = publisher.publications();
    assert_eq!(publications.len(), 2);
    assert_eq!(publications[1].endpoints, vec![endpoint_b.clone()]);
    let artifacts = publisher.artifacts();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(artifacts[0], artifacts[1]);
    let completed = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(completed.phase, cgka_traits::MaintenancePhase::Complete);
    assert!(completed.publication_targets.iter().all(|target| {
        (target.endpoint == endpoint_a || target.endpoint == endpoint_b)
            && target.state == TransportFanoutAttemptState::Accepted
            && target.failure_code.is_none()
    }));
}

#[tokio::test]
async fn due_maintenance_reconciles_current_fanout_to_authoritative_routes_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot current fanout route reconcile key").unwrap();
    let endpoint_a = TransportEndpoint("wss://keys-a.example".into());
    let removed_endpoint = TransportEndpoint("wss://keys-b.example".into());
    let added_endpoint = TransportEndpoint("wss://keys-c.example".into());
    let wall = Arc::new(TestWallClock::new(36_500));
    let publisher = PartialFanoutKeyPackages::default();

    let original_artifact;
    {
        let mut runtime = AccountDeviceRuntime::new(
            session(&database, &key, b"alice"),
            RecordingAdapter::default(),
            StaticTransportRouting::new(vec![])
                .key_package_endpoints(vec![endpoint_a.clone(), removed_endpoint.clone()]),
            publisher.clone(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(67)),
        );
        runtime.publish_fresh_key_package().await.unwrap();
        let partial = runtime.key_package_maintenance_status().unwrap().unwrap();
        original_artifact = partial.authored_signed_event.unwrap();
        assert!(partial.publication_targets.iter().any(|target| {
            target.endpoint == removed_endpoint
                && target.state == TransportFanoutAttemptState::AttemptedFailed
        }));
    }

    wall.set(36_530);
    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![])
            .key_package_endpoints(vec![endpoint_a.clone(), added_endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(67)),
    );
    restarted.pause_maintenance();
    restarted.run_due_maintenance().await.unwrap();

    let publications = publisher.publications();
    assert_eq!(publications.len(), 2);
    assert_eq!(publications[1].0.endpoints, vec![added_endpoint.clone()]);
    assert_eq!(publications[1].1, original_artifact);
    assert!(!publications[1].0.endpoints.contains(&removed_endpoint));

    let reconciled = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert!(reconciled.publication_targets.iter().any(|target| {
        target.endpoint == removed_endpoint
            && target.state == TransportFanoutAttemptState::PolicyProhibited
    }));
    assert!(reconciled.publication_targets.iter().any(|target| {
        target.endpoint == added_endpoint && target.state == TransportFanoutAttemptState::Accepted
    }));
}

#[tokio::test]
async fn pending_replacement_reconciles_a_to_b_policy_and_cannot_promote_from_stale_a_ack() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot pending route switch key").unwrap();
    let endpoint_a = TransportEndpoint("wss://keys-a.example".into());
    let endpoint_b = TransportEndpoint("wss://keys-b.example".into());
    let publisher = JournalKeyPackages::default().with_publication_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: Vec::new(),
            rejected: vec![endpoint_a.clone()],
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoint_a.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: vec![endpoint_b.clone()],
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoint_b.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    {
        let mut runtime = AccountDeviceRuntime::new(
            session(&database, &key, b"alice"),
            RecordingAdapter::default(),
            StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint_a.clone()]),
            publisher.clone(),
        );
        runtime
            .publish_fresh_key_package()
            .await
            .expect_err("the original A-only route rejects the pending revision");
    }

    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint_b.clone()]),
        publisher.clone(),
    );
    restarted
        .publish_fresh_key_package()
        .await
        .expect_err("an acknowledgement for removed A is outside the B-only attempted fanout");
    let pending = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert!(pending.current_key_package.is_none());
    let pending = pending.pending_replacement.unwrap();
    let removed_a = pending
        .targets
        .iter()
        .find(|target| target.endpoint == endpoint_a)
        .unwrap();
    assert_eq!(
        removed_a.state,
        TransportFanoutAttemptState::PolicyProhibited
    );
    let live_b = pending
        .targets
        .iter()
        .find(|target| target.endpoint == endpoint_b)
        .unwrap();
    assert_eq!(live_b.state, TransportFanoutAttemptState::AttemptedFailed);
    assert_eq!(live_b.failure_code.as_deref(), Some("possible_exposure"));

    restarted
        .publish_fresh_key_package()
        .await
        .expect("the pending revision promotes only after authoritative B acknowledges");
    let promoted = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert!(promoted.pending_replacement.is_none());
    assert!(promoted.publication_targets.iter().any(|target| {
        target.endpoint == endpoint_b && target.state == TransportFanoutAttemptState::Accepted
    }));
    assert_eq!(
        publisher
            .publications()
            .into_iter()
            .map(|publication| publication.endpoints)
            .collect::<Vec<_>>(),
        vec![vec![endpoint_a], vec![endpoint_b.clone()], vec![endpoint_b]]
    );
}

#[tokio::test]
async fn zero_target_pending_replacement_publishes_when_an_authoritative_route_appears() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot pending zero route recovery key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let publisher = JournalKeyPackages::default().reject_empty_prepares();
    {
        let mut runtime = AccountDeviceRuntime::new(
            session(&database, &key, b"alice"),
            RecordingAdapter::default(),
            StaticTransportRouting::new(vec![]),
            publisher.clone(),
        );
        runtime
            .publish_fresh_key_package()
            .await
            .expect_err("a prepared zero-target revision cannot yet be acknowledged");
        let pending = runtime.key_package_maintenance_status().unwrap().unwrap();
        assert!(
            pending
                .pending_replacement
                .as_ref()
                .unwrap()
                .targets
                .is_empty()
        );
        assert!(
            pending
                .pending_replacement
                .as_ref()
                .unwrap()
                .signed_event
                .is_none(),
            "the transport-like empty-route failure must leave an unsigned durable draft"
        );
    }

    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    );
    restarted
        .publish_fresh_key_package()
        .await
        .expect("the newly authoritative route is persisted and receives the exact pending event");
    assert!(
        restarted
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .pending_replacement
            .is_none()
    );
    assert_eq!(
        publisher
            .publications()
            .into_iter()
            .map(|publication| publication.endpoints)
            .collect::<Vec<_>>(),
        vec![vec![endpoint]]
    );
}

#[tokio::test]
async fn saturated_pending_route_addition_fails_without_persisting_the_257th_pair() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot pending route capacity key").unwrap();
    let endpoint = TransportEndpoint("wss://new.example".into());
    let publisher = JournalKeyPackages::default();
    {
        let mut runtime = AccountDeviceRuntime::new(
            session(&database, &key, b"alice"),
            RecordingAdapter::default(),
            StaticTransportRouting::new(vec![]),
            publisher.clone(),
        );
        runtime.prepare_fresh_key_package(Vec::new()).await.unwrap();
        let mut lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
        let full_endpoints = (0..256)
            .map(|index| TransportEndpoint(format!("wss://retired-{index}.example")))
            .collect::<Vec<_>>();
        lifecycle
            .retired_publications_pending_deletion
            .push(RetiredKeyPackagePublication {
                event_id: MessageId::new(vec![0x7d; 32]),
                authored_created_at: Timestamp(u64::MAX),
                key_package_ref: None,
                package_not_after: None,
                delete_without_successor: false,
                deletion_targets: full_endpoints.iter().map(deletion_target).collect(),
            });
        runtime
            .session()
            .put_key_package_lifecycle(&lifecycle)
            .unwrap();
    }

    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint]),
        publisher.clone(),
    );
    let error = restarted
        .publish_fresh_key_package()
        .await
        .expect_err("adding a distinct pending endpoint above the global cap must fail");
    assert!(
        error
            .to_string()
            .contains("signed-publication endpoint-liability journal is full")
    );
    let unchanged = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert!(
        unchanged
            .pending_replacement
            .as_ref()
            .unwrap()
            .targets
            .is_empty(),
        "the over-cap authoritative endpoint must not partially persist"
    );
    assert!(publisher.publications().is_empty());
}

#[test]
fn discovered_retired_key_package_admission_is_idempotent_bounded_and_io_free() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot discovered revision admission key").unwrap();
    let publisher = JournalKeyPackages::default();
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only("stable-slot".into());
    lifecycle
        .retired_publications_pending_deletion
        .push(RetiredKeyPackagePublication {
            event_id: MessageId::new(vec![0x81; 32]),
            authored_created_at: Timestamp(1),
            key_package_ref: None,
            package_not_after: None,
            delete_without_successor: false,
            deletion_targets: (0
                ..cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES - 1)
                .map(|index| {
                    deletion_target(&TransportEndpoint(format!(
                        "wss://existing-{index}.example"
                    )))
                })
                .collect(),
        });
    session(&database, &key, b"alice")
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();

    let event_id = MessageId::new(vec![0x82; 32]);
    let key_package_ref = vec![0x83; 32];
    let endpoint_a = TransportEndpoint("wss://discovered-a.example".into());
    let endpoint_b = TransportEndpoint("wss://discovered-b.example".into());
    let mut runtime = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        publisher.clone(),
    );
    let (admitted, deferred) = runtime
        .journal_discovered_retired_key_package_publication(
            "stable-slot".into(),
            event_id.clone(),
            Timestamp(200),
            key_package_ref.clone(),
            Timestamp(900),
            vec![endpoint_b.clone(), endpoint_a.clone(), endpoint_a.clone()],
        )
        .unwrap();
    assert_eq!(admitted, vec![endpoint_a.clone()]);
    assert_eq!(deferred, vec![endpoint_b.clone()]);
    let journaled = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        journaled.authored_event_created_at,
        Some(Timestamp(200)),
        "relay-discovered same-slot revisions advance the authoring high-water"
    );
    let discovered = journaled
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == event_id)
        .unwrap();
    assert_eq!(discovered.authored_created_at, Timestamp(200));
    assert_eq!(discovered.key_package_ref, Some(key_package_ref.clone()));
    assert_eq!(discovered.package_not_after, Some(Timestamp(900)));
    assert!(!discovered.delete_without_successor);
    assert_eq!(discovered.deletion_targets.len(), 1);
    assert_eq!(discovered.deletion_targets[0].endpoint, endpoint_a);
    assert!(publisher.publications().is_empty());
    assert!(publisher.deletions().is_empty());
    drop(runtime);

    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        publisher.clone(),
    );
    let (admitted, deferred) = restarted
        .journal_discovered_retired_key_package_publication(
            "stable-slot".into(),
            event_id.clone(),
            Timestamp(200),
            key_package_ref,
            Timestamp(900),
            vec![endpoint_b.clone(), endpoint_a.clone()],
        )
        .unwrap();
    assert_eq!(admitted, vec![endpoint_a]);
    assert_eq!(deferred, vec![endpoint_b.clone()]);

    let wrong_slot_error = restarted
        .journal_discovered_retired_key_package_publication(
            "sibling-device-slot".into(),
            MessageId::new(vec![0x86; 32]),
            Timestamp(201),
            vec![0x87; 32],
            Timestamp(901),
            vec![endpoint_b.clone()],
        )
        .expect_err("a sibling-device stable slot must never enter the local deletion journal");
    assert!(wrong_slot_error.to_string().contains("local stable slot"));

    let live_event_id = MessageId::new(vec![0x84; 32]);
    let mut live = restarted.key_package_maintenance_status().unwrap().unwrap();
    live.authored_event_id = Some(live_event_id.clone());
    restarted
        .session()
        .put_key_package_lifecycle(&live)
        .unwrap();
    let error = restarted
        .journal_discovered_retired_key_package_publication(
            "stable-slot".into(),
            live_event_id,
            Timestamp(201),
            vec![0x85; 32],
            Timestamp(901),
            vec![endpoint_b],
        )
        .expect_err("a selected live revision cannot be imported as retired");
    assert!(error.to_string().contains("live key package revision"));
    assert!(publisher.publications().is_empty());
    assert!(publisher.deletions().is_empty());
}

#[tokio::test]
async fn discovered_consumed_revision_is_deletable_without_a_successor_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot consumed discovered revision key").unwrap();
    let event_id = MessageId::new(vec![0x88; 32]);
    let key_package_ref = vec![0x89; 32];
    let endpoint = TransportEndpoint("wss://consumed-discovered.example".into());
    let publisher = JournalKeyPackages::default();
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only("stable-slot".into());
    lifecycle.cutover_publication_blocked = true;
    lifecycle.consumed_key_package_refs = vec![key_package_ref.clone()];
    session(&database, &key, b"alice")
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();

    let mut runtime = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        publisher.clone(),
    );
    runtime
        .journal_discovered_retired_key_package_publication(
            "stable-slot".into(),
            event_id.clone(),
            Timestamp(300),
            key_package_ref,
            Timestamp(900),
            vec![endpoint.clone()],
        )
        .unwrap();
    let admitted = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(
        admitted
            .retired_publications_pending_deletion
            .iter()
            .find(|retired| retired.event_id == event_id)
            .unwrap()
            .delete_without_successor,
        "durable Welcome evidence must transfer onto the exact relay revision"
    );
    assert!(publisher.deletions().is_empty());
    drop(runtime);

    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        publisher.clone(),
    );
    restarted
        .retry_retired_key_package_deletions_once()
        .await
        .unwrap();
    assert_eq!(
        publisher.deletions(),
        vec![(event_id.clone(), vec![endpoint])]
    );
    assert!(publisher.publications().is_empty());
    assert!(
        restarted
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .retired_publications_pending_deletion
            .iter()
            .all(|retired| retired.event_id != event_id),
        "the exact accepted deletion acknowledgement must settle the liability"
    );
}

#[tokio::test]
async fn live_revision_deletion_uses_only_the_bounded_atomic_overflow_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot live deletion atomic capacity key").unwrap();
    let live_event_id = MessageId::new(vec![0xa1; 32]);
    let existing_event_id = MessageId::new(vec![0xa2; 32]);
    let mut live_endpoints = (0
        ..=cgka_traits::maintenance::MAX_KEY_PACKAGE_LIVE_DELETION_OVERFLOW_LIABILITIES)
        .map(|index| TransportEndpoint(format!("wss://live-{index}.example")))
        .collect::<Vec<_>>();
    live_endpoints.sort();
    let existing_endpoints = (0
        ..cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES)
        .map(|index| TransportEndpoint(format!("wss://existing-{index}.example")))
        .collect::<Vec<_>>();
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only("stable-slot".into());
    lifecycle.authored_event_id = Some(live_event_id.clone());
    lifecycle
        .retired_publications_pending_deletion
        .push(RetiredKeyPackagePublication {
            event_id: existing_event_id.clone(),
            authored_created_at: Timestamp(1),
            key_package_ref: None,
            package_not_after: None,
            delete_without_successor: true,
            deletion_targets: existing_endpoints.iter().map(deletion_target).collect(),
        });
    session(&database, &key, b"alice")
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    let admitted_live_endpoints = live_endpoints
        [..cgka_traits::maintenance::MAX_KEY_PACKAGE_LIVE_DELETION_OVERFLOW_LIABILITIES]
        .to_vec();
    let publisher =
        JournalKeyPackages::default().with_deletion_receipts(vec![KeyPackagePublishReceipt {
            accepted: Vec::new(),
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: admitted_live_endpoints.clone(),
        }]);
    let mut runtime = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        publisher.clone(),
    );

    let (admitted, deferred) = runtime
        .prepare_key_package_deletion_recovery(&live_event_id, live_endpoints.clone())
        .unwrap();
    assert!(admitted.is_empty());
    assert_eq!(deferred, live_endpoints);
    let before_admission = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(
        !before_admission
            .deleted_live_revision_event_ids
            .contains(&live_event_id)
    );
    assert!(
        before_admission
            .retired_publications_pending_deletion
            .iter()
            .all(|retired| retired.event_id != live_event_id),
        "a request larger than the reserve must not admit a live endpoint subset"
    );

    let (receipt, deferred) = runtime
        .delete_key_package_revision_durably(&live_event_id, admitted_live_endpoints.clone())
        .await
        .unwrap();
    assert_eq!(receipt.failed, admitted_live_endpoints);
    assert!(deferred.is_empty());
    assert_eq!(publisher.deletions().len(), 1);
    assert_eq!(publisher.deletions()[0].0, live_event_id);
    let retained = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(
        retained
            .deleted_live_revision_event_ids
            .contains(&live_event_id)
    );
    let live_retired = retained
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == live_event_id)
        .expect("every failed live endpoint remains durably retryable");
    assert_eq!(
        live_retired.deletion_targets.len(),
        cgka_traits::maintenance::MAX_KEY_PACKAGE_LIVE_DELETION_OVERFLOW_LIABILITIES
    );
    assert_eq!(
        retained
            .retired_publications_pending_deletion
            .iter()
            .map(|retired| retired.deletion_targets.len())
            .sum::<usize>(),
        cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES_WITH_LIVE_DELETION_OVERFLOW
    );
    assert_eq!(
        retained.deletion_overflow_owner_event_id,
        Some(live_event_id.clone())
    );

    drop(runtime);
    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        publisher,
    );
    let (admitted, deferred) = restarted
        .prepare_key_package_deletion_recovery(
            &live_event_id,
            vec![live_endpoints.last().unwrap().clone()],
        )
        .unwrap();
    assert!(admitted.is_empty());
    assert_eq!(deferred, vec![live_endpoints.last().unwrap().clone()]);
    let restarted_status = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert!(
        restarted_status
            .deleted_live_revision_event_ids
            .contains(&live_event_id),
        "restart must retain both the live-delete marker and the full reserve"
    );
    assert_eq!(
        restarted_status.deletion_overflow_owner_event_id,
        Some(live_event_id),
        "the full reserve must retain its exact owner after restart"
    );
}

#[tokio::test]
async fn unknown_exact_deletion_uses_the_reserve_instead_of_partial_admission() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot unknown exact deletion reserve key").unwrap();
    let existing_event_id = MessageId::new(vec![0xb1; 32]);
    let deleting_event_id = MessageId::new(vec![0xb2; 32]);
    let existing_endpoints = (0
        ..cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES - 1)
        .map(|index| TransportEndpoint(format!("wss://existing-{index}.example")))
        .collect::<Vec<_>>();
    let mut deleting_endpoints = vec![
        TransportEndpoint("wss://delete-b.example".into()),
        TransportEndpoint("wss://delete-a.example".into()),
    ];
    deleting_endpoints.sort();
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only("stable-slot".into());
    lifecycle
        .retired_publications_pending_deletion
        .push(RetiredKeyPackagePublication {
            event_id: existing_event_id,
            authored_created_at: Timestamp(1),
            key_package_ref: None,
            package_not_after: None,
            delete_without_successor: true,
            deletion_targets: existing_endpoints.iter().map(deletion_target).collect(),
        });
    session(&database, &key, b"alice")
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    let mut runtime = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        JournalKeyPackages::default(),
    );

    let (admitted, deferred) = runtime
        .prepare_key_package_deletion_recovery(&deleting_event_id, deleting_endpoints.clone())
        .unwrap();
    assert_eq!(admitted, deleting_endpoints);
    assert!(deferred.is_empty());
    let retained = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        retained
            .retired_publications_pending_deletion
            .iter()
            .map(|retired| retired.deletion_targets.len())
            .sum::<usize>(),
        cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES + 1
    );
    assert_eq!(
        retained
            .retired_publications_pending_deletion
            .iter()
            .find(|retired| retired.event_id == deleting_event_id)
            .unwrap()
            .deletion_targets
            .len(),
        2,
        "an unprojected id can still be an older same-slot revision, so its relay set is atomic"
    );
    assert_eq!(
        retained.deletion_overflow_owner_event_id,
        Some(deleting_event_id.clone()),
        "the exact event that crossed the ordinary bound must durably own the reserve"
    );
    drop(runtime);

    let restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        JournalKeyPackages::default(),
    );
    let restarted = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        restarted
            .retired_publications_pending_deletion
            .iter()
            .find(|retired| retired.event_id == deleting_event_id)
            .unwrap()
            .deletion_targets
            .len(),
        2
    );
    assert_eq!(
        restarted.deletion_overflow_owner_event_id,
        Some(deleting_event_id),
        "reserve ownership must survive reopening the account database"
    );
}

#[tokio::test]
async fn exact_deletion_overflow_owner_blocks_siblings_until_all_targets_are_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot exact deletion reserve owner key").unwrap();
    let existing_event_id = MessageId::new(vec![0xc1; 32]);
    let owner_event_id = MessageId::new(vec![0xc2; 32]);
    let sibling_event_id = MessageId::new(vec![0xc3; 32]);
    let existing_endpoints = (0
        ..cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES - 1)
        .map(|index| TransportEndpoint(format!("wss://existing-owner-{index}.example")))
        .collect::<Vec<_>>();
    let owner_a = TransportEndpoint("wss://owner-a.example".into());
    let owner_b = TransportEndpoint("wss://owner-b.example".into());
    let owner_c = TransportEndpoint("wss://owner-c.example".into());
    let sibling_a = TransportEndpoint("wss://sibling-a.example".into());
    let sibling_b = TransportEndpoint("wss://sibling-b.example".into());
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only("stable-slot".into());
    lifecycle
        .retired_publications_pending_deletion
        .push(RetiredKeyPackagePublication {
            event_id: existing_event_id,
            authored_created_at: Timestamp(1),
            key_package_ref: None,
            package_not_after: None,
            delete_without_successor: true,
            deletion_targets: existing_endpoints.iter().map(deletion_target).collect(),
        });
    session(&database, &key, b"alice")
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    let publisher = JournalKeyPackages::default().with_deletion_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: vec![owner_a.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: vec![owner_b.clone(), owner_c.clone()],
        },
        KeyPackagePublishReceipt {
            accepted: vec![owner_b.clone(), owner_c.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        publisher.clone(),
    );

    let (admitted, deferred) = runtime
        .prepare_key_package_deletion_recovery(
            &owner_event_id,
            vec![owner_b.clone(), owner_a.clone()],
        )
        .unwrap();
    assert_eq!(admitted, vec![owner_a.clone(), owner_b.clone()]);
    assert!(deferred.is_empty());
    assert_eq!(
        runtime
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .deletion_overflow_owner_event_id,
        Some(owner_event_id.clone())
    );
    drop(runtime);

    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        publisher.clone(),
    );
    let (admitted, deferred) = restarted
        .prepare_key_package_deletion_recovery(
            &owner_event_id,
            vec![owner_c.clone(), owner_b.clone(), owner_a.clone()],
        )
        .unwrap();
    assert_eq!(
        admitted,
        vec![owner_a.clone(), owner_b.clone(), owner_c.clone()],
        "same-event retries must return already durable targets and atomically add new ones"
    );
    assert!(deferred.is_empty());

    let (admitted, deferred) = restarted
        .prepare_key_package_deletion_recovery(&sibling_event_id, vec![sibling_a.clone()])
        .unwrap();
    assert!(admitted.is_empty());
    assert_eq!(deferred, vec![sibling_a.clone()]);

    let (receipt, deferred) = restarted
        .delete_key_package_revision_durably(
            &owner_event_id,
            vec![owner_c.clone(), owner_b.clone(), owner_a.clone()],
        )
        .await
        .unwrap();
    assert_eq!(receipt.accepted, vec![owner_a.clone()]);
    assert_eq!(receipt.failed, vec![owner_b.clone(), owner_c.clone()]);
    assert!(deferred.is_empty());
    assert_eq!(
        restarted
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .deletion_overflow_owner_event_id,
        Some(owner_event_id.clone()),
        "partial terminal receipts must not release the reserve owner"
    );
    let (admitted, deferred) = restarted
        .prepare_key_package_deletion_recovery(&sibling_event_id, vec![sibling_a.clone()])
        .unwrap();
    assert!(admitted.is_empty());
    assert_eq!(deferred, vec![sibling_a.clone()]);

    let (receipt, deferred) = restarted
        .delete_key_package_revision_durably(
            &owner_event_id,
            vec![owner_c.clone(), owner_b.clone()],
        )
        .await
        .unwrap();
    assert_eq!(receipt.accepted, vec![owner_b.clone(), owner_c.clone()]);
    assert!(deferred.is_empty());
    assert!(
        restarted
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .deletion_overflow_owner_event_id
            .is_none(),
        "the final terminal receipt must release the durable owner"
    );

    let (admitted, deferred) = restarted
        .prepare_key_package_deletion_recovery(
            &sibling_event_id,
            vec![sibling_b.clone(), sibling_a.clone()],
        )
        .unwrap();
    assert_eq!(admitted, vec![sibling_a, sibling_b]);
    assert!(deferred.is_empty());
    assert_eq!(
        restarted
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .deletion_overflow_owner_event_id,
        Some(sibling_event_id),
        "a later exact deletion may claim the reserve only after release"
    );
}

#[tokio::test]
async fn maintenance_retry_releases_the_overflow_owner_after_its_terminal_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot maintenance deletion reserve release key").unwrap();
    let owner_event_id = MessageId::new(vec![0xd1; 32]);
    let ordinary_event_id = MessageId::new(vec![0xd2; 32]);
    let owner_endpoint = TransportEndpoint("wss://maintenance-owner.example".into());
    let ordinary_endpoints = (0
        ..cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES)
        .map(|index| TransportEndpoint(format!("wss://maintenance-ordinary-{index}.example")))
        .collect::<Vec<_>>();
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only("stable-slot".into());
    lifecycle.deletion_overflow_owner_event_id = Some(owner_event_id.clone());
    lifecycle
        .retired_publications_pending_deletion
        .push(retired_revision(
            owner_event_id.clone(),
            Timestamp(0),
            std::slice::from_ref(&owner_endpoint),
        ));
    lifecycle
        .retired_publications_pending_deletion
        .push(retired_revision(
            ordinary_event_id,
            Timestamp(1),
            &ordinary_endpoints,
        ));
    session(&database, &key, b"alice")
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    let publisher = JournalKeyPackages::default();
    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        publisher.clone(),
    );

    restarted
        .retry_retired_key_package_deletions_once()
        .await
        .unwrap();
    assert_eq!(
        publisher.deletions(),
        vec![(owner_event_id.clone(), vec![owner_endpoint])]
    );
    let settled = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert!(settled.deletion_overflow_owner_event_id.is_none());
    assert!(
        settled
            .retired_publications_pending_deletion
            .iter()
            .all(|retired| retired.event_id != owner_event_id)
    );
    assert_eq!(
        settled
            .retired_publications_pending_deletion
            .iter()
            .map(|retired| retired.deletion_targets.len())
            .sum::<usize>(),
        cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES
    );
}

#[test]
fn unparsed_exact_discovery_claims_the_overflow_and_blocks_another_exact_event() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot unparsed deletion reserve owner key").unwrap();
    let existing_event_id = MessageId::new(vec![0xe1; 32]);
    let owner_event_id = MessageId::new(vec![0xe2; 32]);
    let sibling_event_id = MessageId::new(vec![0xe3; 32]);
    let existing_endpoints = (0
        ..cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES)
        .map(|index| TransportEndpoint(format!("wss://unparsed-existing-{index}.example")))
        .collect::<Vec<_>>();
    let owner_endpoint = TransportEndpoint("wss://unparsed-owner.example".into());
    let sibling_endpoint = TransportEndpoint("wss://unparsed-sibling.example".into());
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only("stable-slot".into());
    lifecycle
        .retired_publications_pending_deletion
        .push(retired_revision(
            existing_event_id,
            Timestamp(1),
            &existing_endpoints,
        ));
    session(&database, &key, b"alice")
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    let mut runtime = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        JournalKeyPackages::default(),
    );

    let (admitted, deferred) = runtime
        .journal_discovered_unparsed_key_package_publication(
            "stable-slot".into(),
            owner_event_id.clone(),
            Timestamp(2),
            vec![owner_endpoint.clone()],
        )
        .unwrap();
    assert_eq!(admitted, vec![owner_endpoint]);
    assert!(deferred.is_empty());
    assert_eq!(
        runtime
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .deletion_overflow_owner_event_id,
        Some(owner_event_id)
    );

    let (admitted, deferred) = runtime
        .journal_discovered_unparsed_key_package_publication(
            "stable-slot".into(),
            sibling_event_id.clone(),
            Timestamp(3),
            vec![sibling_endpoint.clone()],
        )
        .unwrap();
    assert!(admitted.is_empty());
    assert_eq!(deferred, vec![sibling_endpoint]);
    let retained = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(retained.authored_event_created_at, Some(Timestamp(3)));
    assert!(
        retained
            .retired_publications_pending_deletion
            .iter()
            .all(|retired| retired.event_id != sibling_event_id),
        "a sibling exact set must remain wholly outside the durable journal"
    );
}

#[test]
fn active_overflow_owner_allows_only_ordinary_refill_to_the_base_bound() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot ordinary refill with reserve owner key").unwrap();
    let owner_event_id = MessageId::new(vec![0xf1; 32]);
    let existing_event_id = MessageId::new(vec![0xf2; 32]);
    let ordinary_event_id = MessageId::new(vec![0xf3; 32]);
    let sibling_exact_event_id = MessageId::new(vec![0xf4; 32]);
    let existing_endpoints = (0..250)
        .map(|index| TransportEndpoint(format!("wss://refill-existing-{index}.example")))
        .collect::<Vec<_>>();
    let owner_endpoints = (0..4)
        .map(|index| TransportEndpoint(format!("wss://refill-owner-{index}.example")))
        .collect::<Vec<_>>();
    let mut ordinary_endpoints = vec![
        TransportEndpoint("wss://refill-ordinary-c.example".into()),
        TransportEndpoint("wss://refill-ordinary-a.example".into()),
        TransportEndpoint("wss://refill-ordinary-b.example".into()),
    ];
    ordinary_endpoints.sort();
    let sibling_endpoint = TransportEndpoint("wss://refill-sibling-exact.example".into());
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only("stable-slot".into());
    lifecycle.deletion_overflow_owner_event_id = Some(owner_event_id.clone());
    lifecycle
        .retired_publications_pending_deletion
        .push(retired_revision(
            owner_event_id.clone(),
            Timestamp(0),
            &owner_endpoints,
        ));
    lifecycle
        .retired_publications_pending_deletion
        .push(retired_revision(
            existing_event_id,
            Timestamp(1),
            &existing_endpoints,
        ));
    session(&database, &key, b"alice")
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    let mut runtime = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        JournalKeyPackages::default(),
    );

    let (admitted, deferred) = runtime
        .journal_discovered_retired_key_package_publication(
            "stable-slot".into(),
            ordinary_event_id,
            Timestamp(2),
            vec![0x55; 32],
            Timestamp(900),
            ordinary_endpoints.clone(),
        )
        .unwrap();
    assert_eq!(admitted, ordinary_endpoints[..2]);
    assert_eq!(deferred, ordinary_endpoints[2..]);
    let retained = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        retained.deletion_overflow_owner_event_id,
        Some(owner_event_id)
    );
    assert_eq!(
        retained
            .retired_publications_pending_deletion
            .iter()
            .map(|retired| retired.deletion_targets.len())
            .sum::<usize>(),
        cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES
    );

    let (admitted, deferred) = runtime
        .prepare_key_package_deletion_recovery(
            &sibling_exact_event_id,
            vec![sibling_endpoint.clone()],
        )
        .unwrap();
    assert!(admitted.is_empty());
    assert_eq!(deferred, vec![sibling_endpoint]);
}

#[tokio::test]
async fn discovered_high_water_forces_pending_revision_strictly_newer_before_retry() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot discovered high-water pending key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let publisher = JournalKeyPackages::default().with_publication_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: Vec::new(),
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: vec![endpoint.clone()],
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoint.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let wall = Arc::new(TestWallClock::new(10_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(103)),
    );

    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("the first pending revision remains ambiguously exposed");
    let original = runtime.key_package_maintenance_status().unwrap().unwrap();
    let original_pending = original.pending_replacement.as_ref().unwrap();
    let original_artifact = original_pending.signed_event.clone().unwrap();
    let discovered_event_id = MessageId::new(vec![0x91; 32]);
    let discovered_created_at = Timestamp(original_artifact.created_at.0 + 25);
    runtime
        .journal_discovered_retired_key_package_publication(
            original.stable_slot_id,
            discovered_event_id.clone(),
            discovered_created_at,
            vec![0x92; 32],
            Timestamp(20_000),
            vec![endpoint.clone()],
        )
        .unwrap();
    assert!(
        runtime.key_package_network_maintenance_due().unwrap(),
        "ordering repair must not wait for the failed target's ordinary backoff"
    );

    runtime
        .run_due_maintenance()
        .await
        .expect("maintenance must supersede the relay-discovered high-water");
    runtime
        .retry_retired_key_package_deletions_once()
        .await
        .expect("the bounded follow-up pass deletes the second eligible predecessor");

    let artifacts = publisher.artifacts();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(artifacts[0], original_artifact);
    assert!(artifacts[1].created_at > discovered_created_at);
    assert_ne!(artifacts[1].id, original_artifact.id);
    let repaired = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(repaired.pending_replacement.is_none());
    assert_eq!(repaired.authored_signed_event, Some(artifacts[1].clone()));
    assert_eq!(
        repaired.authored_event_created_at,
        Some(artifacts[1].created_at)
    );
    assert!(
        repaired
            .retired_publications_pending_deletion
            .iter()
            .all(|retired| retired.event_id != discovered_event_id),
        "the accepted strictly newer successor makes the discovered revision deletable"
    );
    assert!(
        publisher
            .deletions()
            .iter()
            .any(|(event_id, endpoints)| event_id == &discovered_event_id
                && endpoints == std::slice::from_ref(&endpoint))
    );
}

#[tokio::test]
async fn repeated_ambiguous_stale_retries_keep_every_predecessor_and_continue_forward() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot ambiguous stale chain key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let failed_receipt = || KeyPackagePublishReceipt {
        accepted: Vec::new(),
        rejected: Vec::new(),
        confirmed_absent: Vec::new(),
        failed: vec![endpoint.clone()],
    };
    let publisher = JournalKeyPackages::default()
        .reauthor_after_secs(600)
        .with_publication_receipts(vec![failed_receipt(), failed_receipt(), failed_receipt()]);
    let wall = Arc::new(TestWallClock::new(40_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(67)),
    );

    for now in [40_000, 40_600, 41_200] {
        wall.set(now);
        runtime
            .publish_fresh_key_package()
            .await
            .expect_err("each ambiguous relay attempt remains unacknowledged");
    }

    let artifacts = publisher.artifacts();
    assert_eq!(artifacts.len(), 3);
    assert_ne!(artifacts[0].id, artifacts[1].id);
    assert_ne!(artifacts[1].id, artifacts[2].id);
    let lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    let retired_ids = lifecycle
        .retired_publications_pending_deletion
        .iter()
        .map(|retired| retired.event_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        retired_ids,
        vec![artifacts[0].id.clone(), artifacts[1].id.clone()]
    );
    assert!(
        lifecycle
            .retired_publications_pending_deletion
            .iter()
            .all(|retired| retired.deletion_targets.len() == 1
                && retired.deletion_targets[0].endpoint == endpoint)
    );
    assert_eq!(
        lifecycle
            .pending_replacement
            .as_ref()
            .and_then(|pending| pending.signed_event.as_ref())
            .map(|artifact| artifact.id.clone()),
        Some(artifacts[2].id.clone())
    );
}

#[tokio::test]
async fn stale_pending_reauthor_prepare_failure_keeps_prior_lifecycle_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot failed pending reauthor key").unwrap();
    let wall = Arc::new(TestWallClock::new(20_000));
    let publisher = ReauthorPrepareFailsKeyPackages::default();
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
        Arc::new(TestRandom::new(47)),
    );

    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("initial publication is injected to fail");
    let before = runtime.key_package_maintenance_status().unwrap().unwrap();
    wall.set(20_600);
    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("reauthor signing failure must propagate before network exposure");

    assert_eq!(
        runtime.key_package_maintenance_status().unwrap(),
        Some(before),
        "signing precedes mutation, so the old durable revision remains exactly retryable"
    );
    assert_eq!(publisher.preparations.lock().unwrap().len(), 2);
    assert_eq!(
        publisher.publications.lock().unwrap().len(),
        1,
        "a failed replacement signature must never reach the transport"
    );
}

#[tokio::test]
async fn opted_in_pending_key_package_retry_blocks_on_large_clock_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot pending retry rollback key").unwrap();
    let wall = Arc::new(TestWallClock::new(50_000));
    let publisher = FlakyKeyPackages::new(1).reauthor_after_secs(600);
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
        Arc::new(TestRandom::new(37)),
    );

    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("first publication is intentionally unacknowledged");
    let original = runtime
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .pending_replacement
        .unwrap()
        .signed_event
        .unwrap();
    wall.set(1);
    let error = runtime
        .publish_fresh_key_package()
        .await
        .expect_err("a far-future durable artifact must not be sent after clock rollback");
    assert!(matches!(error, AccountError::ClockSkewBlocked));
    assert_eq!(publisher.publications().len(), 1);
    let lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        lifecycle.phase,
        cgka_traits::MaintenancePhase::ClockSkewBlocked
    );
    assert_eq!(
        lifecycle.pending_replacement.unwrap().signed_event,
        Some(original)
    );
}

#[tokio::test]
async fn publisher_without_reauthor_policy_preserves_exact_retry_across_clock_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot exact retry rollback key").unwrap();
    let wall = Arc::new(TestWallClock::new(50_000));
    let publisher = FlakyKeyPackages::new(1);
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
        Arc::new(TestRandom::new(41)),
    );

    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("first publication is intentionally unacknowledged");
    wall.set(1);
    runtime
        .publish_fresh_key_package()
        .await
        .expect("a publisher that did not opt in retains legacy exact-retry behavior");

    let publications = publisher.publications();
    let artifacts = publisher.artifacts();
    assert_eq!(publications.len(), 2);
    assert_eq!(publications[0], publications[1]);
    assert_eq!(artifacts[0], artifacts[1]);
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
    let first_event_id = test_key_package_artifact(&publications[0]).id;
    let retired = lifecycle
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == first_event_id)
        .expect("routine rotation retains the superseded signed event id");
    assert_eq!(
        retired
            .deletion_targets
            .iter()
            .map(|target| target.endpoint.clone())
            .collect::<Vec<_>>(),
        publications[0].endpoints
    );
    assert_eq!(lifecycle.retained_private_material.len(), 1);
    assert_eq!(
        lifecycle.retained_private_material[0].key_package,
        publications[0].key_package
    );
}

#[tokio::test]
async fn legacy_current_without_signed_bytes_is_retired_across_partial_rotation_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot legacy current rotation journal key").unwrap();
    let endpoint_a = TransportEndpoint("wss://keys-a.example".into());
    let endpoint_b = TransportEndpoint("wss://keys-b.example".into());
    let routing = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![endpoint_a.clone(), endpoint_b.clone()]);
    let wall = Arc::new(TestWallClock::new(23_000));
    let publisher = JournalKeyPackages::default().with_publication_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: vec![endpoint_a.clone(), endpoint_b.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoint_a.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: vec![endpoint_b.clone()],
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoint_b.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let old_event_id;
    let old_created_at;
    let old_key_package_ref;
    {
        let mut runtime = AccountDeviceRuntime::new(
            session(&database, &key, b"alice"),
            RecordingAdapter::default(),
            routing.clone(),
            publisher.clone(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(12)),
        );
        runtime.publish_fresh_key_package().await.unwrap();
        let mut legacy = runtime.key_package_maintenance_status().unwrap().unwrap();
        old_event_id = legacy.authored_event_id.clone().unwrap();
        old_created_at = legacy.authored_event_created_at.unwrap();
        old_key_package_ref = legacy.current_key_package_ref.clone().unwrap();
        legacy.authored_signed_event = None;
        runtime
            .session()
            .put_key_package_lifecycle(&legacy)
            .unwrap();

        runtime
            .publish_fresh_key_package()
            .await
            .expect("one successor ACK promotes despite partial fanout");
        let rotated = runtime.key_package_maintenance_status().unwrap().unwrap();
        let retired = rotated
            .retired_publications_pending_deletion
            .iter()
            .find(|retired| retired.event_id == old_event_id)
            .expect("legacy authored id is snapshotted before promotion overwrites it");
        assert_eq!(retired.authored_created_at, old_created_at);
        assert_eq!(retired.key_package_ref, Some(old_key_package_ref.clone()));
        assert!(!retired.delete_without_successor);
        assert_eq!(
            retired
                .deletion_targets
                .iter()
                .map(|target| target.endpoint.clone())
                .collect::<Vec<_>>(),
            vec![endpoint_a.clone(), endpoint_b.clone()]
        );
    }

    wall.set(23_030);
    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(12)),
    );
    restarted.pause_maintenance();
    restarted.run_due_maintenance().await.unwrap();
    assert_eq!(
        publisher.deletions(),
        vec![(old_event_id.clone(), vec![endpoint_a.clone()])],
        "the replacement first completes fanout, then one old endpoint drains per call"
    );
    let after_first = restarted.key_package_maintenance_status().unwrap().unwrap();
    let retired = after_first
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == old_event_id)
        .expect("the second endpoint remains durable across the restarted call boundary");
    assert_eq!(retired.deletion_targets.len(), 1);
    assert_eq!(retired.deletion_targets[0].endpoint, endpoint_b);
    restarted.run_due_maintenance().await.unwrap();
    assert_eq!(
        publisher.deletions()[1],
        (old_event_id.clone(), vec![endpoint_b])
    );
    assert!(
        restarted
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .retired_publications_pending_deletion
            .iter()
            .all(|retired| retired.event_id != old_event_id)
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
async fn stale_current_key_package_reauthor_resets_and_fans_out_to_every_live_target() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot stale current fanout key").unwrap();
    let database = dir.path().join("alice.sqlite");
    let publisher = PartialFanoutKeyPackages::default().reauthor_after_secs(600);
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
        Arc::new(TestRandom::new(43)),
    );

    runtime
        .publish_fresh_key_package()
        .await
        .expect("one acknowledgement promotes the first revision");
    let before = runtime.key_package_maintenance_status().unwrap().unwrap();
    let before_artifact = before.authored_signed_event.clone().unwrap();
    assert_eq!(
        before
            .publication_targets
            .iter()
            .filter(|target| target.state == cgka_traits::TransportFanoutAttemptState::Accepted)
            .count(),
        1
    );
    drop(runtime);

    wall.set(70_600);
    let mut restarted = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        routing,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(43)),
    );
    restarted.pause_maintenance();
    restarted
        .run_due_maintenance()
        .await
        .expect("stale current revision is reauthored and fanned out");

    let calls = publisher.publications();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].0.key_package, calls[0].0.key_package);
    assert_eq!(calls[1].0.slot_id, calls[0].0.slot_id);
    assert_eq!(calls[1].0.created_at, Timestamp(70_600));
    assert_ne!(calls[1].1, before_artifact);
    assert_eq!(
        calls[1].0.endpoints,
        vec![
            TransportEndpoint("wss://keys-a.example".into()),
            TransportEndpoint("wss://keys-b.example".into()),
        ],
        "a newer replaceable revision must supersede the old event on every live relay"
    );
    let after = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(after.authored_event_id, Some(calls[1].1.id.clone()));
    assert_eq!(after.authored_event_created_at, Some(Timestamp(70_600)));
    assert_eq!(after.authored_signed_event, Some(calls[1].1.clone()));
    assert!(after.publication_targets.iter().all(|target| {
        target.state == cgka_traits::TransportFanoutAttemptState::Accepted
            && target.attempt_count == 1
            && target.failure_code.is_none()
    }));
}

#[tokio::test]
async fn retired_deletion_prunes_only_acked_endpoint_and_restart_retries_the_failed_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot retired endpoint deletion key").unwrap();
    let endpoint_a = TransportEndpoint("wss://keys-a.example".into());
    let endpoint_b = TransportEndpoint("wss://keys-b.example".into());
    let unknown_provenance_id = MessageId::new(vec![0x70; 32]);
    let retired_id = MessageId::new(vec![0x71; 32]);
    let wall = Arc::new(TestWallClock::new(50_000));
    let publisher = JournalKeyPackages::default().with_deletion_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: vec![endpoint_a.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: Vec::new(),
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: vec![endpoint_b.clone()],
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoint_b.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let routing = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![endpoint_a.clone(), endpoint_b.clone()]);
    let mut runtime = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(71)),
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let mut lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    lifecycle
        .retired_publications_pending_deletion
        .push(retired_revision(
            unknown_provenance_id.clone(),
            Timestamp(48_000),
            &[],
        ));
    lifecycle
        .retired_publications_pending_deletion
        .push(retired_revision(
            retired_id.clone(),
            Timestamp(49_000),
            &[endpoint_a.clone(), endpoint_b.clone()],
        ));
    runtime
        .session()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    runtime.pause_maintenance();

    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        publisher.deletions(),
        vec![(retired_id.clone(), vec![endpoint_a.clone()])],
        "one maintenance call is bounded to one endpoint deletion attempt"
    );
    let after_a = runtime.key_package_maintenance_status().unwrap().unwrap();
    let retained = after_a
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == retired_id)
        .unwrap();
    assert_eq!(retained.deletion_targets.len(), 1);
    assert_eq!(retained.deletion_targets[0].endpoint, endpoint_b);

    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        publisher.deletions()[1],
        (retired_id.clone(), vec![endpoint_b.clone()])
    );
    let after_failure = runtime.key_package_maintenance_status().unwrap().unwrap();
    let failed_target = &after_failure
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == retired_id)
        .unwrap()
        .deletion_targets[0];
    assert_eq!(
        failed_target.state,
        TransportFanoutAttemptState::AttemptedFailed
    );
    assert_eq!(failed_target.attempt_count, 1);
    assert_eq!(
        failed_target.failure_code.as_deref(),
        Some("possible_exposure")
    );
    drop(runtime);

    wall.set(50_030);
    let mut restarted = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        routing,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(71)),
    );
    restarted.pause_maintenance();
    restarted.run_due_maintenance().await.unwrap();
    assert_eq!(
        publisher.deletions()[2],
        (retired_id.clone(), vec![endpoint_b])
    );
    assert!(
        restarted
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .retired_publications_pending_deletion
            .iter()
            .all(|retired| retired.event_id != retired_id)
    );
    let unknown_provenance = restarted
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .retired_publications_pending_deletion
        .into_iter()
        .find(|retired| retired.event_id == unknown_provenance_id)
        .expect("unrelated deletion ACKs must preserve unknown-provenance evidence across restart");
    assert!(unknown_provenance.deletion_targets.is_empty());
}

#[tokio::test]
async fn retired_deletion_confirmed_absent_is_terminal_and_cleanup_calls_drain_one_target_each() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot retired deletion budget key").unwrap();
    let endpoints = (0..3)
        .map(|index| TransportEndpoint(format!("wss://keys-{index}.example")))
        .collect::<Vec<_>>();
    let retired_id = MessageId::new(vec![0x72; 32]);
    let wall = Arc::new(TestWallClock::new(60_000));
    let publisher = JournalKeyPackages::default().with_deletion_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: Vec::new(),
            rejected: Vec::new(),
            confirmed_absent: vec![endpoints[0].clone()],
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoints[1].clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: vec![endpoints[2].clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(endpoints.clone()),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(73)),
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let mut lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    lifecycle
        .retired_publications_pending_deletion
        .push(retired_revision(
            retired_id.clone(),
            Timestamp(59_000),
            &endpoints,
        ));
    runtime
        .session()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    runtime.pause_maintenance();

    for expected_call_count in 1..=3 {
        runtime.run_due_maintenance().await.unwrap();
        let calls = publisher.deletions();
        assert_eq!(calls.len(), expected_call_count);
        assert_eq!(calls.last().unwrap().1.len(), 1);
        assert_eq!(
            calls.last().unwrap().1[0],
            endpoints[expected_call_count - 1]
        );
        let remaining = runtime
            .key_package_maintenance_status()
            .unwrap()
            .unwrap()
            .retired_publications_pending_deletion
            .iter()
            .find(|retired| retired.event_id == retired_id)
            .map(|retired| retired.deletion_targets.len())
            .unwrap_or(0);
        assert_eq!(remaining, 3 - expected_call_count);
    }
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
    assert_ne!(after.current_key_package_ref, Some(consumed_ref.clone()));
    assert_eq!(
        after.last_consumed_key_package_ref,
        Some(consumed_ref.clone()),
        "legacy-only consumption evidence stays durable until strict relay cutover transfers it"
    );
    assert!(after.consumed_key_package_refs.contains(&consumed_ref));
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
    assert_eq!(
        reauthorized.attempt_count, 2,
        "the first attempt plus the conservative pre-I/O reauthorization marker are durable"
    );
    assert!(reauthorized.failure_code.is_none());
}

#[tokio::test]
async fn accepted_endpoint_removed_then_readded_keeps_exposure_after_negative_ack() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot readded endpoint exposure key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let wall = Arc::new(TestWallClock::new(70_000));
    let publisher = JournalKeyPackages::default().with_publication_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: vec![endpoint.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: Vec::new(),
            rejected: vec![endpoint.clone()],
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let mut initial = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(79)),
    );
    initial.publish_fresh_key_package().await.unwrap();
    let current_not_before = initial
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .current_not_before
        .unwrap();
    wall.set(current_not_before.0);
    drop(initial);

    let mut removed = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(79)),
    );
    removed
        .republish_key_package()
        .await
        .expect_err("removed policy has no authoritative endpoint");
    let prohibited = removed.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        prohibited.publication_targets[0].state,
        TransportFanoutAttemptState::PolicyProhibited
    );
    assert_eq!(prohibited.publication_targets[0].attempt_count, 1);
    drop(removed);

    let mut restored = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher,
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(79)),
    );
    restored
        .republish_key_package()
        .await
        .expect_err("negative acknowledgement has no accepted endpoint");
    let target = restored
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .publication_targets
        .into_iter()
        .find(|target| target.endpoint == endpoint)
        .unwrap();
    assert_eq!(target.state, TransportFanoutAttemptState::AttemptedFailed);
    assert_eq!(target.attempt_count, 2);
    assert_eq!(target.failure_code.as_deref(), Some("transport_rejected"));
    assert_ne!(target.failure_code.as_deref(), Some("confirmed_absent"));
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
    let mut before_expiry = runtime.key_package_maintenance_status().unwrap().unwrap();
    let not_after = before_expiry.current_not_after.unwrap();
    let expired_event_id = before_expiry.authored_event_id.clone().unwrap();
    let authored_created_at = before_expiry.authored_event_created_at.unwrap();
    before_expiry.authored_signed_event = None;
    runtime
        .session()
        .put_key_package_lifecycle(&before_expiry)
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
    let retired = expired
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == expired_event_id)
        .expect("expiry retains a legacy authored id even when signed bytes are unavailable");
    assert_eq!(retired.authored_created_at, authored_created_at);
    assert!(retired.delete_without_successor);
    assert_eq!(retired.package_not_after, Some(not_after));
    assert_eq!(retired.deletion_targets.len(), 1);
    assert!(runtime.key_package_network_maintenance_due().unwrap());
}

#[tokio::test]
async fn paused_maintenance_still_reauthors_a_deleted_live_current_revision() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot paused deleted current recovery key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let wall = Arc::new(TestWallClock::new(82_000));
    let publisher = JournalKeyPackages::default();
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(31)),
    );

    let current_key_package = runtime.publish_fresh_key_package().await.unwrap();
    let mut before_delete = runtime.key_package_maintenance_status().unwrap().unwrap();
    let unknown_provenance_event_id = MessageId::new(vec![0x75; 32]);
    before_delete
        .retired_publications_pending_deletion
        .push(retired_revision(
            unknown_provenance_event_id.clone(),
            Timestamp(81_000),
            &[],
        ));
    runtime
        .session()
        .put_key_package_lifecycle(&before_delete)
        .unwrap();
    wall.set(
        before_delete
            .current_not_before
            .expect("published current KeyPackage must persist its validity start")
            .0,
    );
    let deleted_event_id = before_delete.authored_event_id.clone().unwrap();
    runtime.pause_maintenance();
    let (deletion, deferred) = runtime
        .delete_key_package_revision_durably(&deleted_event_id, vec![endpoint.clone()])
        .await
        .unwrap();
    assert_eq!(deletion.accepted, vec![endpoint]);
    assert!(deferred.is_empty());
    assert!(runtime.key_package_network_maintenance_due().unwrap());

    runtime
        .run_due_maintenance()
        .await
        .expect("privacy recovery must cross the process-local maintenance pause");

    let publications = publisher.publications();
    let artifacts = publisher.artifacts();
    assert_eq!(publications.len(), 2);
    assert_eq!(artifacts.len(), 2);
    assert_eq!(publications[1].key_package, current_key_package);
    assert_ne!(artifacts[1].id, deleted_event_id);
    assert!(artifacts[1].created_at > artifacts[0].created_at);
    let recovered = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(recovered.authored_event_id, Some(artifacts[1].id.clone()));
    assert!(recovered.deleted_live_revision_event_ids.is_empty());
    assert!(
        recovered
            .retired_publications_pending_deletion
            .iter()
            .any(|retired| retired.event_id == unknown_provenance_event_id
                && retired.deletion_targets.is_empty())
    );
    assert!(runtime.maintenance_is_paused());
}

#[tokio::test]
async fn paused_maintenance_reauthors_a_deleted_live_current_revision_after_refresh_is_due() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot paused overdue deleted current recovery key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let wall = Arc::new(TestWallClock::new(83_000));
    let publisher = JournalKeyPackages::default();
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(33)),
    );

    let current_key_package = runtime.publish_fresh_key_package().await.unwrap();
    let before_delete = runtime.key_package_maintenance_status().unwrap().unwrap();
    wall.set(before_delete.refresh_at.unwrap().0);
    let deleted_event_id = before_delete.authored_event_id.clone().unwrap();
    runtime.pause_maintenance();
    let (deletion, deferred) = runtime
        .delete_key_package_revision_durably(&deleted_event_id, vec![endpoint.clone()])
        .await
        .unwrap();
    assert_eq!(deletion.accepted, vec![endpoint]);
    assert!(deferred.is_empty());

    runtime
        .run_due_maintenance()
        .await
        .expect("deleted-revision recovery must override pause even after refresh is due");

    let publications = publisher.publications();
    let artifacts = publisher.artifacts();
    assert_eq!(publications.len(), 2);
    assert_eq!(artifacts.len(), 2);
    assert_eq!(publications[1].key_package, current_key_package);
    assert_ne!(artifacts[1].id, deleted_event_id);
    assert!(artifacts[1].created_at > artifacts[0].created_at);
    let recovered = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(recovered.authored_event_id, Some(artifacts[1].id.clone()));
    assert!(recovered.deleted_live_revision_event_ids.is_empty());
    assert!(runtime.maintenance_is_paused());
    assert!(runtime.key_package_network_maintenance_due().unwrap());
}

#[tokio::test]
async fn pending_key_package_expiry_retains_signed_event_deletion_obligation() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot pending key package expiry key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let wall = Arc::new(TestWallClock::new(85_000));
    let publisher = FlakyKeyPackages::new(1);
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(83)),
    );
    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("pending publication is intentionally unacknowledged");
    let pending = runtime
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .pending_replacement
        .unwrap();
    let pending_event_id = pending.signed_event.unwrap().id;
    wall.set(pending.not_after.0);

    assert_eq!(
        runtime
            .sweep_expired_key_package_private_material()
            .unwrap(),
        1
    );
    let expired = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(expired.pending_replacement.is_none());
    let retired = expired
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == pending_event_id)
        .expect("expired pending signed event remains durably deletable");
    assert!(retired.delete_without_successor);
    assert_eq!(retired.package_not_after, Some(pending.not_after));
    assert_eq!(retired.deletion_targets[0].endpoint, endpoint);
}

#[tokio::test]
async fn deleted_current_expiry_prunes_exact_marker_before_fresh_129_endpoint_publication() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot expired deleted current marker key").unwrap();
    let endpoints = (0..129)
        .map(|index| TransportEndpoint(format!("wss://fresh-{index}.example")))
        .collect::<Vec<_>>();
    let publisher = JournalKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(150_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(endpoints.clone()),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(101)),
    );

    runtime.publish_fresh_key_package().await.unwrap();
    for cycle in 0..3 {
        let before_delete = runtime.key_package_maintenance_status().unwrap().unwrap();
        let deleted_event_id = before_delete.authored_event_id.clone().unwrap();
        let deleted_key_package = before_delete.current_key_package.clone().unwrap();
        let (deletion, deferred) = runtime
            .delete_key_package_revision_durably(&deleted_event_id, endpoints.clone())
            .await
            .unwrap();
        let mut expected_deleted_endpoints = endpoints.clone();
        expected_deleted_endpoints.sort();
        assert_eq!(deletion.accepted, expected_deleted_endpoints);
        assert!(deferred.is_empty());

        // Model terminal deletion acknowledgements from all 129 relays. The
        // exact-id marker still exists until the corresponding live artifact
        // is expired and removed by the account sweep.
        let mut marked = runtime.key_package_maintenance_status().unwrap().unwrap();
        assert_eq!(
            marked.deleted_live_revision_event_ids,
            vec![deleted_event_id.clone()]
        );
        assert!(marked.publication_targets.iter().all(|target| {
            target.state == TransportFanoutAttemptState::AttemptedFailed
                && target.failure_code.as_deref() == Some("confirmed_absent")
        }));
        let expires_at = Timestamp(150_001 + cycle);
        marked.current_not_after = Some(expires_at);
        runtime
            .session()
            .put_key_package_lifecycle(&marked)
            .unwrap();
        wall.set(expires_at.0);

        assert_eq!(
            runtime
                .sweep_expired_key_package_private_material()
                .unwrap(),
            1
        );
        let expired = runtime.key_package_maintenance_status().unwrap().unwrap();
        assert!(expired.current_key_package.is_none());
        assert!(expired.deleted_live_revision_event_ids.is_empty());
        assert!(
            expired
                .retired_publications_pending_deletion
                .iter()
                .all(|retired| retired.event_id != deleted_event_id),
            "confirmed deletion must not leave a phantom endpoint liability"
        );

        let fresh = runtime
            .publish_fresh_key_package()
            .await
            .expect("the first genuinely fresh 129-endpoint event must fit below the cap");
        assert_ne!(fresh, deleted_key_package);
        let replacement = runtime.key_package_maintenance_status().unwrap().unwrap();
        assert!(replacement.deleted_live_revision_event_ids.is_empty());
        assert_eq!(replacement.publication_targets.len(), 129);
    }
    assert_eq!(publisher.publications().len(), 4);
    assert_eq!(publisher.artifacts().len(), 4);
}

#[tokio::test]
async fn deleted_current_survives_failed_forced_pending_until_expiry_recovery_publishes_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot deleted current pending expiry recovery key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let wall = Arc::new(TestWallClock::new(160_000));
    let accepted = || KeyPackagePublishReceipt {
        accepted: vec![endpoint.clone()],
        rejected: Vec::new(),
        confirmed_absent: Vec::new(),
        failed: Vec::new(),
    };
    let failed = || KeyPackagePublishReceipt {
        accepted: Vec::new(),
        rejected: Vec::new(),
        confirmed_absent: Vec::new(),
        failed: vec![endpoint.clone()],
    };
    let publisher = JournalKeyPackages::default().with_publication_receipts(vec![
        accepted(),
        failed(),
        failed(),
        accepted(),
    ]);
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(103)),
    );

    let current_key_package = runtime.publish_fresh_key_package().await.unwrap();
    let current = runtime.key_package_maintenance_status().unwrap().unwrap();
    let current_event_id = current.authored_event_id.clone().unwrap();
    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("the pending semantic successor never acknowledges");
    let mut with_pending = runtime.key_package_maintenance_status().unwrap().unwrap();
    let pending = with_pending.pending_replacement.as_ref().unwrap();
    let pending_key_package = pending.key_package.clone();
    let pending_event_id = pending.signed_event.as_ref().unwrap().id.clone();
    with_pending.pending_replacement.as_mut().unwrap().not_after = Timestamp(160_060);
    runtime
        .session()
        .put_key_package_lifecycle(&with_pending)
        .unwrap();
    let (current_admitted, current_deferred) = runtime
        .prepare_key_package_deletion_recovery(&current_event_id, vec![endpoint.clone()])
        .unwrap();
    let (pending_admitted, pending_deferred) = runtime
        .prepare_key_package_deletion_recovery(&pending_event_id, vec![endpoint])
        .unwrap();
    assert_eq!(current_admitted.len(), 1);
    assert!(current_deferred.is_empty());
    assert_eq!(pending_admitted.len(), 1);
    assert!(pending_deferred.is_empty());
    let both_deleted = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(
        both_deleted
            .deleted_live_revision_event_ids
            .contains(&current_event_id)
    );
    assert!(
        both_deleted
            .deleted_live_revision_event_ids
            .contains(&pending_event_id)
    );

    runtime.run_due_maintenance().await.unwrap();
    let forced = runtime.key_package_maintenance_status().unwrap().unwrap();
    let forced_pending = forced.pending_replacement.as_ref().unwrap();
    let forced_pending_event_id = forced_pending.signed_event.as_ref().unwrap().id.clone();
    assert_ne!(forced_pending_event_id, pending_event_id);
    assert_eq!(forced_pending.key_package, pending_key_package);
    assert!(
        forced
            .deleted_live_revision_event_ids
            .contains(&current_event_id),
        "forcing the exact pending successor must not erase the deleted-current recovery marker"
    );
    assert!(
        !forced
            .deleted_live_revision_event_ids
            .contains(&pending_event_id)
    );
    assert_eq!(publisher.publications().len(), 3);

    wall.set(160_060);
    assert_eq!(
        runtime
            .sweep_expired_key_package_private_material()
            .unwrap(),
        1
    );
    let after_pending_expiry = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(after_pending_expiry.pending_replacement.is_none());
    assert_eq!(
        after_pending_expiry.current_key_package,
        Some(current_key_package.clone())
    );
    assert!(
        after_pending_expiry
            .deleted_live_revision_event_ids
            .contains(&current_event_id),
        "pending expiry must retain the independent exact current recovery marker"
    );

    runtime.run_due_maintenance().await.unwrap();
    let publications = publisher.publications();
    let artifacts = publisher.artifacts();
    assert_eq!(publications.len(), 4);
    assert_eq!(artifacts.len(), 4);
    assert_ne!(publications[3].key_package, pending_key_package);
    assert_ne!(publications[3].key_package, current_key_package);
    assert!(artifacts[3].created_at > artifacts[2].created_at);
    let recovered = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert!(recovered.pending_replacement.is_none());
    assert_eq!(recovered.authored_event_id, Some(artifacts[3].id.clone()));
    assert!(recovered.deleted_live_revision_event_ids.is_empty());
}

#[tokio::test]
async fn legacy_deleted_current_id_without_signed_bytes_restarts_into_fresh_semantic_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot legacy deleted current recovery key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let wall = Arc::new(TestWallClock::new(170_000));
    let publisher = JournalKeyPackages::default();

    let original_key_package;
    let deleted_event_id;
    {
        let mut runtime = AccountDeviceRuntime::new(
            session(&database, &key, b"alice"),
            RecordingAdapter::default(),
            StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]),
            publisher.clone(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(107)),
        );
        original_key_package = runtime.publish_fresh_key_package().await.unwrap();
        let mut lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
        deleted_event_id = lifecycle.authored_event_id.clone().unwrap();

        // Model a pre-artifact upgrade row, then exercise the durable deletion
        // path so its terminal ACK must match the authored-id fallback rather
        // than signed bytes that this legacy row does not contain.
        lifecycle.authored_signed_event = None;
        lifecycle.refresh_at = Some(Timestamp(180_000));
        lifecycle.upgrade_rotation_recorded = true;
        runtime
            .session()
            .put_key_package_lifecycle(&lifecycle)
            .unwrap();
        let (deletion, deferred) = runtime
            .delete_key_package_revision_durably(&deleted_event_id, vec![endpoint.clone()])
            .await
            .unwrap();
        assert_eq!(deletion.accepted, vec![endpoint.clone()]);
        assert!(deferred.is_empty());
        let marked = runtime.key_package_maintenance_status().unwrap().unwrap();
        assert_eq!(
            marked.deleted_live_revision_event_ids,
            vec![deleted_event_id.clone()]
        );
        assert_eq!(
            marked.publication_targets[0].failure_code.as_deref(),
            Some("confirmed_absent")
        );
    }

    let mut reopened = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(109)),
    );
    assert!(
        reopened.key_package_network_maintenance_due().unwrap(),
        "authored_event_id must keep a deleted pre-artifact current revision due after restart"
    );
    reopened.run_due_maintenance().await.unwrap();

    let publications = publisher.publications();
    let artifacts = publisher.artifacts();
    assert_eq!(publications.len(), 2);
    assert_eq!(artifacts.len(), 2);
    assert_ne!(publications[1].key_package, original_key_package);
    assert_ne!(artifacts[1].id, deleted_event_id);
    let recovered = reopened.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        recovered.current_key_package,
        Some(publications[1].key_package.clone())
    );
    assert_eq!(recovered.authored_event_id, Some(artifacts[1].id.clone()));
    assert_eq!(
        recovered
            .authored_signed_event
            .as_ref()
            .map(|artifact| artifact.id.clone()),
        Some(artifacts[1].id.clone())
    );
    assert!(recovered.pending_replacement.is_none());
    assert!(
        recovered.deleted_live_revision_event_ids.is_empty(),
        "successful semantic replacement must clear the deleted-live upgrade marker"
    );
}

#[tokio::test]
async fn key_package_endpoint_liability_limit_blocks_new_signature_without_evicting_deletions() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot key package liability bound key").unwrap();
    let endpoints = (0..256)
        .map(|index| TransportEndpoint(format!("wss://liability-{index}.example")))
        .collect::<Vec<_>>();
    let publisher =
        JournalKeyPackages::default().with_deletion_receipts(vec![KeyPackagePublishReceipt {
            accepted: Vec::new(),
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: vec![endpoints[0].clone()],
        }]);
    let session = session(dir.path().join("alice.sqlite"), &key, b"alice");
    let slot = publisher
        .legacy_slot_id(&session.self_id())
        .unwrap()
        .unwrap();
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only(slot);
    lifecycle
        .retired_publications_pending_deletion
        .push(retired_revision(
            MessageId::new(vec![0x73; 32]),
            Timestamp(1),
            &endpoints,
        ));
    session.put_key_package_lifecycle(&lifecycle).unwrap();
    let mut runtime = AccountDeviceRuntime::new(
        session,
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        publisher,
    );
    let durable_before = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        durable_before
            .retired_publications_pending_deletion
            .iter()
            .map(|retired| retired.deletion_targets.len())
            .sum::<usize>(),
        256
    );

    let result = runtime
        .prepare_fresh_key_package(vec![TransportEndpoint("wss://new.example".into())])
        .await;
    let blocked = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        blocked
            .pending_replacement
            .as_ref()
            .map(|pending| pending.targets.len()),
        Some(1)
    );
    assert_eq!(
        blocked
            .retired_publications_pending_deletion
            .iter()
            .map(|retired| retired.deletion_targets.len())
            .sum::<usize>(),
        256,
        "staging must preserve every existing privacy obligation"
    );
    let error = result.expect_err("the 257th endpoint liability must not be signed");
    assert!(
        error
            .to_string()
            .contains("signed-publication endpoint-liability journal is full"),
        "unexpected capacity error: {error:?}"
    );
    assert_eq!(
        blocked
            .retired_publications_pending_deletion
            .iter()
            .map(|retired| retired.deletion_targets.len())
            .sum::<usize>(),
        256,
        "privacy obligations must never be evicted to make capacity"
    );
    assert!(
        blocked
            .pending_replacement
            .as_ref()
            .is_some_and(|pending| pending.signed_event.is_none()),
        "capacity is checked before signing the newly staged package"
    );
}

#[tokio::test]
async fn stale_current_reauthor_projects_exact_pair_cap_when_live_targets_are_duplicated() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot duplicate current reauthor cap key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let other_endpoints = (0..255)
        .map(|index| TransportEndpoint(format!("wss://retired-{index}.example")))
        .collect::<Vec<_>>();
    let wall = Arc::new(TestWallClock::new(175_000));
    let publisher = JournalKeyPackages::default().reauthor_after_secs(600);
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(111)),
    );
    runtime.publish_fresh_key_package().await.unwrap();
    let mut lifecycle = runtime.key_package_maintenance_status().unwrap().unwrap();
    let old_artifact = lifecycle.authored_signed_event.clone().unwrap();
    let duplicate = lifecycle.publication_targets[0].clone();
    lifecycle.publication_targets.push(duplicate);
    lifecycle
        .retired_publications_pending_deletion
        .push(RetiredKeyPackagePublication {
            event_id: MessageId::new(vec![0x74; 32]),
            // A current publication at the same timestamp is not a strictly
            // newer successor, so the pre-reauthor cleanup cannot free one of
            // these 255 liabilities before the projection check.
            authored_created_at: old_artifact.created_at,
            key_package_ref: None,
            package_not_after: None,
            delete_without_successor: false,
            deletion_targets: other_endpoints.iter().map(deletion_target).collect(),
        });
    runtime
        .session()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();

    wall.set(175_600);
    let error = runtime
        .republish_key_package()
        .await
        .expect_err("retired old(A) plus new(A) would exceed the exact-pair cap");
    assert!(
        error
            .to_string()
            .contains("signed-publication endpoint-liability journal is full"),
        "unexpected capacity error: {error:?}"
    );
    assert_eq!(
        publisher.artifacts(),
        vec![old_artifact.clone()],
        "capacity must be checked before signing a replacement revision"
    );
    let blocked = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(blocked.authored_signed_event, Some(old_artifact));
    assert_eq!(blocked.publication_targets.len(), 2);
    assert_eq!(
        blocked.retired_publications_pending_deletion.len(),
        1,
        "the rejected projection must not partially retire the current revision"
    );
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
async fn consumed_ambiguous_pending_is_swept_across_restart_without_exact_republication() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot consumed ambiguous pending key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let routing = StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint.clone()]);
    let wall = Arc::new(TestWallClock::new(100_000));
    let exposed = ExposedThenFailsKeyPackages::default();
    let mut runtime = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        exposed,
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(89)),
    );

    runtime
        .publish_fresh_key_package()
        .await
        .expect_err("the pending KeyPackage is exposed before transport returns ambiguously");
    let pending_before_welcome = runtime
        .key_package_maintenance_status()
        .unwrap()
        .unwrap()
        .pending_replacement
        .unwrap();
    let consumed_ref = pending_before_welcome.key_package_ref.clone();
    let consumed_key_package = pending_before_welcome.key_package.clone();
    let consumed_artifact = pending_before_welcome.signed_event.clone().unwrap();
    let alice_id = runtime.session().self_id();
    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let welcome = welcome_for_key_package(
        &mut bob,
        &alice_id,
        consumed_key_package.clone(),
        "ambiguous pending invite",
    )
    .await;
    runtime
        .session_mut()
        .ingest(welcome)
        .await
        .expect("the ambiguously published pending private bundle remains joinable");
    let consumed = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        consumed.consumed_key_package_refs,
        vec![consumed_ref.clone()]
    );
    assert_eq!(
        consumed.last_consumed_key_package_ref,
        Some(consumed_ref.clone())
    );
    drop(runtime);

    let cleanup =
        JournalKeyPackages::default().with_deletion_receipts(vec![KeyPackagePublishReceipt {
            accepted: Vec::new(),
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: vec![endpoint.clone()],
        }]);
    let mut restarted = AccountDeviceRuntime::new(
        session(database.clone(), &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        cleanup.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(89)),
    );
    restarted.pause_maintenance();
    restarted.run_due_maintenance().await.unwrap();

    assert!(
        cleanup.publications().is_empty(),
        "paused cleanup must never republish the exact consumed pending artifact"
    );
    let swept = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert!(swept.pending_replacement.is_none());
    assert!(swept.current_key_package.is_none());
    assert_eq!(
        swept.authored_event_created_at,
        Some(consumed_artifact.created_at),
        "the consumed pending revision remains the stable-slot authoring high-water"
    );
    assert!(swept.consumed_key_package_refs.is_empty());
    assert!(swept.last_consumed_key_package_ref.is_none());
    let retired = swept
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == consumed_artifact.id)
        .expect("possible relay exposure remains durably deletable after the bundle is consumed");
    assert!(retired.delete_without_successor);
    assert_eq!(retired.key_package_ref, Some(consumed_ref));
    assert_eq!(retired.deletion_targets.len(), 1);
    assert!(restarted.durably_owned_key_packages().unwrap().is_empty());
    drop(restarted);

    let mut reopened = AccountDeviceRuntime::new(
        session(database, &key, b"alice"),
        RecordingAdapter::default(),
        routing,
        cleanup.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(89)),
    );
    reopened.pause_maintenance();
    reopened.run_due_maintenance().await.unwrap();
    assert!(
        cleanup.publications().is_empty(),
        "restart while paused must not resurrect the consumed exact revision"
    );

    reopened.resume_maintenance();
    wall.set(100_030);
    reopened.run_due_maintenance().await.unwrap();
    let recovery_publications = cleanup.publications();
    let recovery_artifacts = cleanup.artifacts();
    assert_eq!(recovery_publications.len(), 1);
    assert_ne!(recovery_publications[0].key_package, consumed_key_package);
    assert_eq!(recovery_artifacts.len(), 1);
    assert_ne!(recovery_artifacts[0].id, consumed_artifact.id);
    assert!(recovery_artifacts[0].created_at > consumed_artifact.created_at);
}

#[tokio::test]
async fn welcome_without_legacy_lifecycle_row_preserves_consumed_ref_in_synthesized_state() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot legacy lifecycle-less Welcome key").unwrap();
    let mut alice = session(&database, &key, b"alice");
    let alice_id = alice.self_id();
    let key_package = alice.fresh_key_package().await.unwrap();
    let key_package_ref = hex::decode(
        alice
            .key_package_metadata(&key_package)
            .unwrap()
            .key_package_ref_hex,
    )
    .unwrap();
    assert!(alice.key_package_lifecycle().unwrap().is_none());

    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let welcome = welcome_for_key_package(
        &mut bob,
        &alice_id,
        key_package.clone(),
        "legacy lifecycle-less invite",
    )
    .await;
    alice.ingest(welcome).await.unwrap();

    let lifecycle = alice
        .key_package_lifecycle()
        .unwrap()
        .expect("Welcome ingest synthesizes compatibility lifecycle state");
    assert!(lifecycle.stable_slot_id.is_empty());
    assert_eq!(
        lifecycle.consumed_key_package_refs,
        vec![key_package_ref.clone()],
        "newly proven legacy consumption must survive even without a projected current/pending row"
    );
    assert_eq!(
        lifecycle.last_consumed_key_package_ref,
        Some(key_package_ref.clone())
    );
    assert!(
        alice
            .durably_owned_key_packages()
            .unwrap()
            .contains(&key_package)
    );
    drop(alice);

    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]),
        JournalKeyPackages::default(),
    );
    assert_eq!(
        restarted
            .sweep_expired_key_package_private_material()
            .unwrap(),
        1,
        "the lifecycle-less consumed bundle is correlated and deleted after restart"
    );
    assert!(restarted.durably_owned_key_packages().unwrap().is_empty());
    let swept = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert!(swept.consumed_key_package_refs.is_empty());
    assert!(swept.last_consumed_key_package_ref.is_none());
}

#[tokio::test]
async fn welcome_fails_closed_when_consumed_ref_journal_is_full_without_evicting_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot full consumed ref journal key").unwrap();
    let mut alice = session(dir.path().join("alice.sqlite"), &key, b"alice");
    let alice_id = alice.self_id();
    let key_package = alice.fresh_key_package().await.unwrap();
    let key_package_ref = hex::decode(
        alice
            .key_package_metadata(&key_package)
            .unwrap()
            .key_package_ref_hex,
    )
    .unwrap();
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only("stable-slot".into());
    lifecycle.consumed_key_package_refs = (0
        ..cgka_traits::maintenance::MAX_CONSUMED_KEY_PACKAGE_REFS_PENDING_CLEANUP)
        .map(|index| u64::try_from(index).unwrap().to_be_bytes().to_vec())
        .collect();
    let evidence_before = lifecycle.consumed_key_package_refs.clone();
    assert!(!evidence_before.contains(&key_package_ref));
    alice.put_key_package_lifecycle(&lifecycle).unwrap();

    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let welcome = welcome_for_key_package(
        &mut bob,
        &alice_id,
        key_package.clone(),
        "full consumed journal invite",
    )
    .await;
    let error = alice
        .ingest(welcome)
        .await
        .expect_err("the 257th unswept consumption ref must fail the Welcome transaction");
    assert!(
        error
            .to_string()
            .contains("consumed KeyPackage cleanup journal is full"),
        "unexpected capacity error: {error:?}"
    );

    let after = alice.key_package_lifecycle().unwrap().unwrap();
    assert_eq!(after.consumed_key_package_refs, evidence_before);
    assert!(
        alice
            .durably_owned_key_packages()
            .unwrap()
            .contains(&key_package),
        "transaction rollback must retain the private bundle when consumption evidence cannot commit"
    );
}

#[tokio::test]
async fn legacy_overwritten_consumption_marker_is_swept_before_startup_transport() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot overwritten consumed marker key").unwrap();
    let relay_a = TransportEndpoint("wss://a.keys.example".into());
    let relay_b = TransportEndpoint("wss://b.keys.example".into());
    let routing = StaticTransportRouting::new(vec![])
        .key_package_endpoints(vec![relay_a.clone(), relay_b.clone()]);
    let publisher = JournalKeyPackages::default().with_publication_receipts(vec![
        KeyPackagePublishReceipt {
            accepted: vec![relay_a.clone(), relay_b.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
        KeyPackagePublishReceipt {
            accepted: vec![relay_a.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: vec![relay_b.clone()],
        },
        KeyPackagePublishReceipt {
            accepted: vec![relay_a.clone(), relay_b.clone()],
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        },
    ]);
    let wall = Arc::new(TestWallClock::new(130_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        routing.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(101)),
    );

    // This package predates lifecycle projection entirely. A schema-51
    // writer could overwrite its consumption marker with a later Welcome, so
    // upgrade recovery must not limit conservative retirement to current /
    // retained lifecycle fields.
    let unprojected_key_package = runtime.session_mut().fresh_key_package().await.unwrap();
    let unprojected_ref = hex::decode(
        runtime
            .session()
            .key_package_metadata(&unprojected_key_package)
            .unwrap()
            .key_package_ref_hex,
    )
    .unwrap();
    let retained_key_package = runtime.publish_fresh_key_package().await.unwrap();
    let retained = runtime.key_package_maintenance_status().unwrap().unwrap();
    let retained_ref = retained.current_key_package_ref.clone().unwrap();
    let current_key_package = runtime.publish_fresh_key_package().await.unwrap();
    let current = runtime.key_package_maintenance_status().unwrap().unwrap();
    let current_ref = current.current_key_package_ref.clone().unwrap();
    let current_artifact = current.authored_signed_event.clone().unwrap();
    assert_ne!(retained_ref, current_ref);
    assert_eq!(current.retained_private_material.len(), 1);
    assert!(
        current
            .publication_targets
            .iter()
            .any(|target| target.endpoint == relay_b
                && target.state == TransportFanoutAttemptState::AttemptedFailed),
        "the live exact revision must retain a partial-relay retry before consumption"
    );

    let alice_id = runtime.session().self_id();
    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let mut carol = session(dir.path().join("carol.sqlite"), &key, b"carol");
    let mut dave = session(dir.path().join("dave.sqlite"), &key, b"dave");
    // This third Welcome is already in flight when the upgraded process starts.
    // Its pre-lifecycle package is intentionally not consumed yet: startup must
    // retire it before transport can deliver this message and overwrite the
    // legacy-only ambiguity sentinel.
    let startup_welcome = welcome_for_key_package(
        &mut bob,
        &alice_id,
        unprojected_key_package.clone(),
        "unprojected startup Welcome",
    )
    .await;
    let current_welcome = welcome_for_key_package(
        &mut carol,
        &alice_id,
        current_key_package.clone(),
        "current consumed first",
    )
    .await;
    let retained_welcome = welcome_for_key_package(
        &mut dave,
        &alice_id,
        retained_key_package.clone(),
        "retained consumed last",
    )
    .await;
    runtime.session_mut().ingest(current_welcome).await.unwrap();
    runtime
        .session_mut()
        .ingest(retained_welcome)
        .await
        .unwrap();

    let mut legacy = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        legacy.consumed_key_package_refs,
        vec![current_ref.clone(), retained_ref.clone()]
    );
    assert_eq!(
        legacy.last_consumed_key_package_ref,
        Some(retained_ref.clone())
    );
    assert_eq!(
        runtime.durably_owned_key_packages().unwrap().len(),
        3,
        "OpenMLS intentionally retains lifecycle-less and projected last-resort bundles"
    );
    // Simulate the pre-journal serialized shape: only the legacy last marker
    // survives, so the first consumed current ref has been overwritten.
    legacy.consumed_key_package_refs.clear();
    runtime
        .session()
        .put_key_package_lifecycle(&legacy)
        .unwrap();
    drop(runtime);

    let adapter = RecordingAdapter::default();
    let mut restarted = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        adapter.clone(),
        routing.clone(),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(101)),
    );
    assert!(
        adapter.activations().is_empty(),
        "transport must still be unopened at the synchronous startup sweep boundary"
    );
    assert!(adapter.publishes().is_empty());
    let publications_before_sweep = publisher.publications().len();
    assert_eq!(
        restarted
            .sweep_expired_key_package_private_material()
            .unwrap(),
        3,
        "legacy-only evidence conservatively retires every possibly consumed durable bundle"
    );
    assert!(
        adapter.activations().is_empty(),
        "private-material startup reconciliation performs no transport I/O"
    );
    assert!(adapter.publishes().is_empty());
    assert_eq!(publisher.publications().len(), publications_before_sweep);
    let swept = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert!(swept.current_key_package.is_none());
    assert!(swept.current_key_package_ref.is_none());
    assert!(swept.authored_event_id.is_none());
    assert!(swept.authored_signed_event.is_none());
    assert!(swept.publication_targets.is_empty());
    assert!(swept.retained_private_material.is_empty());
    assert!(swept.pending_replacement.is_none());
    let mut expected_consumed_refs = vec![
        unprojected_ref.clone(),
        current_ref.clone(),
        retained_ref.clone(),
    ];
    expected_consumed_refs.sort();
    assert_eq!(swept.consumed_key_package_refs, expected_consumed_refs);
    assert_eq!(swept.last_consumed_key_package_ref, Some(retained_ref));
    assert_eq!(
        swept.authored_event_created_at,
        Some(current_artifact.created_at),
        "the unusable live revision remains the stable-slot authoring high-water"
    );
    let retired_current = swept
        .retired_publications_pending_deletion
        .iter()
        .find(|retired| retired.event_id == current_artifact.id)
        .expect("the exact partially published current revision remains durably deletable");
    assert!(retired_current.delete_without_successor);
    assert_eq!(retired_current.key_package_ref, Some(current_ref));
    assert_eq!(retired_current.deletion_targets.len(), 2);
    assert_eq!(
        publisher.publications().len(),
        2,
        "the atomic sentinel transition performs no exact network retry"
    );
    restarted.activate_transport(None).await.unwrap();
    assert_eq!(adapter.activations().len(), 1);
    let rejected = restarted
        .session_mut()
        .ingest(startup_welcome)
        .await
        .expect("missing private material is a classified rejection");
    assert!(matches!(
        rejected.outcome,
        cgka_traits::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::InvalidEncoding
        }
    ));
    assert_eq!(
        restarted.key_package_maintenance_status().unwrap(),
        Some(swept.clone()),
        "failed startup Welcome ingest must not overwrite the reconciled lifecycle"
    );
    assert!(restarted.durably_owned_key_packages().unwrap().is_empty());
    restarted
        .finalize_key_package_cutover_consumption_evidence()
        .unwrap();
    let finalized = restarted.key_package_maintenance_status().unwrap().unwrap();
    assert!(finalized.consumed_key_package_refs.is_empty());
    assert!(finalized.last_consumed_key_package_ref.is_none());
    drop(restarted);

    let mut recovered = AccountDeviceRuntime::new(
        session(&database, &key, b"alice"),
        RecordingAdapter::default(),
        routing,
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(101)),
    );
    let recovered_state = recovered.key_package_maintenance_status().unwrap().unwrap();
    assert!(recovered_state.last_consumed_key_package_ref.is_none());
    assert!(recovered_state.current_key_package.is_none());
    recovered.run_due_maintenance().await.unwrap();
    let publications = publisher.publications();
    let artifacts = publisher.artifacts();
    assert_eq!(publications.len(), 3);
    assert_eq!(artifacts.len(), 3);
    assert_ne!(publications[2].key_package, current_key_package);
    assert_ne!(publications[2].key_package, retained_key_package);
    assert_ne!(publications[2].key_package, unprojected_key_package);
    assert_ne!(artifacts[2].id, current_artifact.id);
    assert!(artifacts[2].created_at > current_artifact.created_at);
}

#[tokio::test]
async fn two_welcome_refs_survive_until_one_sweep_and_prune_only_removed_private_material() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot two consumed welcome refs key").unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let publisher = JournalKeyPackages::default();
    let wall = Arc::new(TestWallClock::new(120_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![]).key_package_endpoints(vec![endpoint]),
        publisher.clone(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(97)),
    );

    let first_key_package = runtime.publish_fresh_key_package().await.unwrap();
    let first = runtime.key_package_maintenance_status().unwrap().unwrap();
    let first_ref = first.current_key_package_ref.clone().unwrap();
    let first_event_id = first.authored_event_id.clone().unwrap();
    let second_key_package = runtime.publish_fresh_key_package().await.unwrap();
    let mut second = runtime.key_package_maintenance_status().unwrap().unwrap();
    let second_ref = second.current_key_package_ref.clone().unwrap();
    let second_event_id = second.authored_event_id.clone().unwrap();
    assert_ne!(first_ref, second_ref);
    assert_ne!(first_event_id, second_event_id);
    assert_eq!(second.retained_private_material.len(), 1);
    second.authored_signed_event = None;
    runtime
        .session()
        .put_key_package_lifecycle(&second)
        .unwrap();

    let alice_id = runtime.session().self_id();
    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let mut carol = session(dir.path().join("carol.sqlite"), &key, b"carol");
    let first_welcome =
        welcome_for_key_package(&mut bob, &alice_id, first_key_package, "first consumed ref").await;
    let second_welcome = welcome_for_key_package(
        &mut carol,
        &alice_id,
        second_key_package.clone(),
        "second consumed ref",
    )
    .await;
    runtime.session_mut().ingest(first_welcome).await.unwrap();
    runtime.session_mut().ingest(second_welcome).await.unwrap();

    let before_sweep = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        before_sweep.consumed_key_package_refs,
        vec![first_ref.clone(), second_ref.clone()],
        "a second Welcome must append instead of overwriting unswept evidence"
    );
    assert_eq!(
        before_sweep.last_consumed_key_package_ref,
        Some(second_ref.clone())
    );

    assert_eq!(
        runtime
            .sweep_expired_key_package_private_material()
            .unwrap(),
        1,
        "the consumed retained package is deleted while the consumed current remains blocked"
    );
    let after_sweep = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_eq!(
        after_sweep.current_key_package_ref,
        Some(second_ref.clone())
    );
    assert!(after_sweep.retained_private_material.is_empty());
    assert_eq!(
        after_sweep.consumed_key_package_refs,
        vec![second_ref.clone()]
    );
    assert_eq!(
        after_sweep.last_consumed_key_package_ref,
        Some(second_ref.clone())
    );
    for event_id in [&first_event_id, &second_event_id] {
        let retired = after_sweep
            .retired_publications_pending_deletion
            .iter()
            .find(|retired| &retired.event_id == event_id)
            .expect("each consumed signed revision remains durably deletable");
        assert!(retired.delete_without_successor);
    }
    assert!(runtime.key_package_network_maintenance_due().unwrap());
    assert!(!runtime.key_package_has_pending_fanout().unwrap());

    runtime
        .republish_key_package()
        .await
        .expect("a consumed current reference must force semantic replacement");
    let replacement = runtime.key_package_maintenance_status().unwrap().unwrap();
    assert_ne!(replacement.current_key_package_ref, Some(second_ref));
    assert!(replacement.consumed_key_package_refs.is_empty());
    assert!(replacement.last_consumed_key_package_ref.is_none());
    assert_eq!(publisher.publications().len(), 3);
    assert_ne!(publisher.publications()[2].key_package, second_key_package);
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
    adapter.accept_only_endpoints(Vec::new());
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
    adapter.accept_only_endpoints(Vec::new());
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
    adapter.accept_only_endpoints(Vec::new());
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
    adapter.accept_only_endpoints(vec![TransportEndpoint("wss://bob-inbox-a.example".into())]);
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
    assert_eq!(publishes.len(), 2);
    assert!(
        publishes
            .iter()
            .all(|publish| matches!(publish.message.envelope, TransportEnvelope::Welcome { .. }))
    );
    assert_eq!(publishes[0].message, publishes[1].message);
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

#[tokio::test]
async fn cancelled_post_confirmation_welcome_publish_replays_nested_session_events() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot nested visibility cancellation key").unwrap();
    let mut alice = session(
        dir.path().join("alice.sqlite"),
        &key,
        b"alice-nested-visibility",
    );
    let mut bob = session(
        dir.path().join("bob.sqlite"),
        &key,
        b"bob-nested-visibility",
    );
    let mut carol = session(
        dir.path().join("carol.sqlite"),
        &key,
        b"carol-nested-visibility",
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let carol_id = carol.self_id();

    let created = alice
        .create_group(CreateGroupRequest {
            name: "nested visibility".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let create_pending = match created.effects.publish.as_slice() {
        [PublishWork::GroupCreated { pending, .. }] => *pending,
        other => panic!("expected one GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();

    let adapter = RecordingAdapter::default();
    let gate = adapter.gate_welcome_publishes();
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://nested-inbox.example".into())])
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![TransportEndpoint("wss://nested-group.example".into())],
            )
            .with_inbox_route(
                carol_id,
                vec![TransportEndpoint("wss://nested-carol.example".into())],
            );
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    // The group commit publishes first and is confirmed locally. Confirmation
    // drains EpochChanged into the account output, then the recipient Welcome
    // crosses the blocking adapter await. Cancelling there used to discard the
    // only live copy of that newly generated event.
    let mut cancelled = Box::pin(runtime.send(SendIntent::Invite {
        group_id: group_id.clone(),
        key_packages: vec![carol_kp],
        initial_admins: Vec::new(),
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut cancelled => {
                panic!("invite returned before Welcome cancellation boundary: {result:?}")
            }
            () = async {
                while adapter.publishes().len() < 2 {
                    tokio::task::yield_now().await;
                }
            } => {}
        }
    })
    .await
    .expect("invite reaches the blocking Welcome publish");
    drop(cancelled);
    let commit_id = adapter.publishes()[0].message.id.clone();

    gate.release.add_permits(1);
    let recovered = tokio::time::timeout(Duration::from_secs(5), runtime.drain())
        .await
        .expect("retained runtime drain completes")
        .unwrap();
    assert!(recovered.events.iter().any(|event| matches!(
        event,
        GroupEvent::EpochChanged { group_id: changed, .. } if changed == &group_id
    )));
    assert!(
        recovered
            .pending
            .iter()
            .any(|resolution| matches!(resolution, PendingResolution::Confirmed { .. }))
    );
    assert_eq!(
        recovered
            .reports
            .iter()
            .filter(|report| report.message_id == commit_id)
            .count(),
        1,
        "the completed commit report must survive cancellation inside its Welcome loop"
    );
    assert_eq!(
        adapter
            .publishes()
            .iter()
            .filter(|request| request.message.id == commit_id)
            .count(),
        1,
        "visibility replay must not publish the already-confirmed commit again"
    );

    let handed_off = runtime.drain().await.unwrap();
    assert!(!handed_off.events.iter().any(|event| matches!(
        event,
        GroupEvent::EpochChanged { group_id: changed, .. } if changed == &group_id
    )));
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
    // Endpoint policy: group-a accepts the commit, group-b does not, and both
    // carol inbox endpoints accept the welcome.
    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group-a.example".into()),
        TransportEndpoint("wss://carol-inbox-a.example".into()),
        TransportEndpoint("wss://carol-inbox-b.example".into()),
    ]);
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
            initial_admins: vec![],
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

#[tokio::test]
async fn visibility_lease_replays_drain_in_order_through_maintenance_until_acknowledged() {
    use cgka_traits::GroupStorage;
    use cgka_traits::engine::GroupHydrationQuarantineReason;
    use cgka_traits::group::Group;

    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot leased visibility key").unwrap();
    let db_path = dir.path().join("alice-leased.sqlite");
    drop(session(&db_path, &key, b"alice-leased"));

    let broken_groups = [
        GroupId::new(b"leased-broken-a".to_vec()),
        GroupId::new(b"leased-broken-b".to_vec()),
    ];
    {
        let storage = SqliteAccountStorage::open_encrypted(&db_path, &key).unwrap();
        for group_id in &broken_groups {
            storage
                .put_group(&Group {
                    id: group_id.clone(),
                    name: "broken".into(),
                    description: String::new(),
                    members: Vec::new(),
                    epoch: EpochId(9),
                    required_capabilities: cgka_traits::GroupCapabilities::default(),
                    protocol_profile: ProtocolProfile::Legacy,
                    removed: false,
                    unrecoverable: false,
                    disbanded: None,
                    join_epoch: EpochId(0),
                })
                .unwrap();
        }
    }

    let reopened = session(&db_path, &key, b"alice-leased");
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://leased-inbox.example".into())]);
    let mut runtime = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        policy,
        RecordingKeyPackages::default(),
    );
    runtime.pause_maintenance();

    let first = runtime.drain_leased().await.unwrap();
    let quarantine_order = |effects: &marmot_account::AccountDeviceEffects| {
        effects
            .events
            .iter()
            .filter_map(|event| match event {
                GroupEvent::GroupHydrationQuarantined {
                    group_id,
                    reason: GroupHydrationQuarantineReason::OpenMlsGroupMissing,
                } => Some(group_id.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let first_order = quarantine_order(&first.effects);
    assert_eq!(first_order.len(), 2);

    // Maintenance itself has no new work while paused. Older unacknowledged
    // visibility is source-attributed in `batches`, while the command-local
    // `effects` remains empty and cannot inherit an old command's failures.
    let replayed = runtime.run_due_maintenance_leased().await.unwrap();
    assert!(quarantine_order(&replayed.effects).is_empty());
    assert_eq!(
        quarantine_order(&flatten_visibility_batches(&replayed.batches)),
        first_order
    );
    assert!(!runtime.acknowledge_visibility_lease(first.lease));
    assert!(runtime.acknowledge_visibility_lease(replayed.lease));

    let after_ack = runtime.drain_leased().await.unwrap();
    assert!(quarantine_order(&after_ack.effects).is_empty());
    assert!(runtime.acknowledge_visibility_lease(after_ack.lease));
}

#[tokio::test]
async fn durably_acknowledged_visibility_lease_advances_after_storage_closes() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot post-commit visibility lease key").unwrap();
    let database = dir.path().join("alice-post-commit-visibility.sqlite");
    let account = session(&database, &key, b"alice-post-commit-visibility");
    let mut runtime = AccountDeviceRuntime::new(
        account,
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://post-commit-visibility.example".into(),
        )]),
        RecordingKeyPackages::default(),
    );
    runtime.pause_maintenance();

    let leased = runtime.drain_leased().await.unwrap();
    let batch_ids = runtime
        .visibility_lease_batch_ids(leased.lease)
        .expect("the returned visibility rows remain leased until app commit");
    assert!(!batch_ids.is_empty());
    let storage = runtime.session().storage_handle();
    assert_eq!(
        storage
            .delete_account_visibility_journal_batches(&batch_ids)
            .unwrap(),
        batch_ids.len(),
        "the app-side transaction must delete every leased row before advancing memory",
    );

    // Terminal shutdown may close the shared handle immediately after the app
    // projection transaction commits. Lease advancement is therefore a pure
    // in-memory post-commit step and must not attempt another storage read.
    storage.close().unwrap();
    assert!(
        runtime
            .forget_durably_acknowledged_visibility_batches(leased.lease, &batch_ids)
            .unwrap(),
        "the matching fully acknowledged lease must advance after storage closes",
    );
    assert_eq!(runtime.visibility_lease_batch_ids(leased.lease), None);
}

#[tokio::test]
async fn rejected_leave_header_replays_without_false_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot rejected leave source key").unwrap();
    let database = dir.path().join("rejected-leave-source.sqlite");
    let unknown_group = GroupId::new(b"unknown-leave-source".to_vec());
    let account = session(&database, &key, b"rejected-leave-source");
    let adapter = RecordingAdapter::default();
    let mut runtime = AccountDeviceRuntime::new(
        account,
        adapter.clone(),
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://rejected-leave-source.example".into(),
        )]),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        Arc::new(TestWallClock::new(31337)),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    runtime.pause_maintenance();

    assert!(
        runtime
            .send_leased(SendIntent::Leave {
                group_id: unknown_group.clone(),
            })
            .await
            .is_err(),
        "an unknown-group Leave must fail before engine acceptance"
    );
    assert!(adapter.publishes().is_empty());
    drop(runtime);

    let reopened = session(&database, &key, b"rejected-leave-source");
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://rejected-leave-source.example".into(),
        )]),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    let replayed = restarted
        .replay_visibility_leased()
        .unwrap()
        .expect("the pre-acceptance Header remains crash-visible");
    assert!(!replayed.batches.is_empty());
    assert!(replayed.batches.iter().all(|batch| {
        batch.source
            == (AccountVisibilitySource::Outbound {
                group_id: Some(unknown_group.clone()),
                observed_at: Timestamp(31337),
                action: Some(AccountVisibilityOutboundAction::Leave),
                action_message_id: None,
            })
    }));
    assert!(restarted.acknowledge_visibility_lease(replayed.lease));
}

#[tokio::test]
async fn leave_visibility_source_survives_restart_until_acknowledged() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot leave visibility source key").unwrap();
    let alice_path = dir.path().join("alice-leave-source.sqlite");
    let bob_path = dir.path().join("bob-leave-source.sqlite");
    let mut alice = session_with_registry(
        &alice_path,
        &key,
        b"alice-leave-source",
        selfremove_registry(),
    );
    let mut bob =
        session_with_registry(&bob_path, &key, b"bob-leave-source", selfremove_registry());
    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "leave visibility source".into(),
            description: String::new(),
            members: vec![bob_key_package],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let (pending, welcome) = match created.effects.publish.as_slice() {
        [PublishWork::GroupCreated { pending, welcomes }] => (*pending, welcomes[0].clone()),
        other => panic!("expected one GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();

    let route = || {
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://leave-source-inbox.example".into(),
        )])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![TransportEndpoint("wss://leave-source-group.example".into())],
        )
    };
    let mut runtime = AccountDeviceRuntime::new(
        bob,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        Arc::new(TestWallClock::new(4242)),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    runtime.pause_maintenance();

    let leased = runtime
        .send_leased(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert!(leased.current_operation_id.is_some());
    assert!(!leased.batches.is_empty());
    let action_outcome = leased
        .effects
        .action_outcomes
        .as_slice()
        .first()
        .expect("a terminal Leave publish emits its typed action outcome");
    assert_eq!(leased.effects.action_outcomes.len(), 1);
    assert_eq!(
        action_outcome.operation_id,
        leased.current_operation_id.clone().unwrap()
    );
    assert_eq!(action_outcome.group_id, group_id);
    assert_eq!(
        action_outcome.action,
        AccountVisibilityOutboundAction::Leave
    );
    assert!(action_outcome.published);
    let leave_message_id = action_outcome.message_id.clone();
    assert!(leased.batches.iter().all(|batch| {
        batch.source
            == (AccountVisibilitySource::Outbound {
                group_id: Some(group_id.clone()),
                observed_at: Timestamp(4242),
                action: Some(AccountVisibilityOutboundAction::Leave),
                action_message_id: Some(leave_message_id.clone()),
            })
    }));
    let original_batch_ids = leased
        .batches
        .iter()
        .map(|batch| batch.batch_id.clone())
        .collect::<Vec<_>>();
    drop(runtime);

    let restarted_adapter = RecordingAdapter::default();
    let reopened =
        session_with_registry(&bob_path, &key, b"bob-leave-source", selfremove_registry());
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        restarted_adapter.clone(),
        route(),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    let replayed = restarted
        .replay_visibility_leased()
        .unwrap()
        .expect("unacknowledged Leave visibility replays after restart");
    assert_eq!(replayed.current_operation_id, None);
    assert_eq!(
        replayed
            .batches
            .iter()
            .map(|batch| batch.batch_id.clone())
            .collect::<Vec<_>>(),
        original_batch_ids
    );
    assert!(replayed.batches.iter().all(|batch| {
        batch.source
            == (AccountVisibilitySource::Outbound {
                group_id: Some(group_id.clone()),
                observed_at: Timestamp(4242),
                action: Some(AccountVisibilityOutboundAction::Leave),
                action_message_id: Some(leave_message_id.clone()),
            })
    }));
    assert_eq!(
        flatten_visibility_batches(&replayed.batches).action_outcomes,
        vec![action_outcome.clone()]
    );
    assert!(
        restarted_adapter.publishes().is_empty(),
        "visibility replay must not repeat the already-completed Leave publish"
    );
    assert!(restarted.acknowledge_visibility_lease(replayed.lease));
    assert!(restarted.replay_visibility_leased().unwrap().is_none());
}

#[tokio::test]
async fn terminal_leave_publish_failure_is_durable_and_does_not_authorize_left() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot failed leave outcome key").unwrap();
    let (bob, bob_path, bob_identity, group_id) =
        joined_selfremove_member(dir.path(), &key, "failed-leave-outcome").await;
    let adapter = RecordingAdapter::default();
    let group_endpoint = TransportEndpoint("wss://failed-leave-group.example".into());
    adapter.fail_endpoints_as(
        vec![group_endpoint.clone()],
        TransportEndpointFailureKind::TerminalRejected,
    );
    let route = || {
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://failed-leave-inbox.example".into(),
        )])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![group_endpoint.clone()],
        )
    };
    let mut runtime =
        AccountDeviceRuntime::new(bob, adapter, route(), RecordingKeyPackages::default());
    runtime.pause_maintenance();
    let leased = runtime
        .send_leased(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(leased.effects.action_outcomes.len(), 1);
    let outcome = leased.effects.action_outcomes[0].clone();
    assert_eq!(outcome.operation_id, leased.current_operation_id.unwrap());
    assert_eq!(outcome.group_id, group_id);
    assert_eq!(outcome.action, AccountVisibilityOutboundAction::Leave);
    assert!(
        !outcome.published,
        "an unmet required-ACK policy must not authorize the app's Left tail"
    );
    assert!(!leased.effects.failures.is_empty());
    drop(runtime);

    let reopened = session_with_registry(&bob_path, &key, &bob_identity, selfremove_registry());
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    let replayed = restarted
        .replay_visibility_leased()
        .unwrap()
        .expect("terminal failed Leave outcome survives restart");
    assert_eq!(
        flatten_visibility_batches(&replayed.batches).action_outcomes,
        vec![outcome]
    );
    assert!(restarted.acknowledge_visibility_lease(replayed.lease));
}

#[tokio::test]
async fn zero_accept_best_effort_leave_does_not_publish_on_restart() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot zero ack leave key").unwrap();
    let (bob, bob_path, bob_identity, group_id) =
        joined_selfremove_member(dir.path(), &key, "zero-ack-leave").await;
    let adapter = RecordingAdapter::default();
    let group_endpoint = TransportEndpoint("wss://zero-ack-leave-group.example".into());
    adapter.fail_endpoints_as(
        vec![group_endpoint.clone()],
        TransportEndpointFailureKind::TerminalRejected,
    );
    let route = || {
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://zero-ack-leave-inbox.example".into(),
        )])
        .required_acks(0)
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![group_endpoint.clone()],
        )
    };
    let mut runtime =
        AccountDeviceRuntime::new(bob, adapter, route(), RecordingKeyPackages::default());
    runtime.pause_maintenance();
    let leased = runtime
        .send_leased(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert!(
        leased
            .effects
            .action_outcomes
            .iter()
            .all(|outcome| !outcome.published),
        "required_acks=0 still needs at least one accept"
    );
    drop(runtime);

    let reopened = session_with_registry(&bob_path, &key, &bob_identity, selfremove_registry());
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    if let Some(replayed) = restarted.replay_visibility_leased().unwrap() {
        assert!(
            flatten_visibility_batches(&replayed.batches)
                .action_outcomes
                .iter()
                .all(|outcome| !outcome.published),
            "restart must not upgrade a zero-accept Leave to published:true"
        );
        assert!(restarted.acknowledge_visibility_lease(replayed.lease));
    }
    let drained = restarted.drain_leased().await.unwrap();
    assert!(
        drained
            .effects
            .action_outcomes
            .iter()
            .all(|outcome| !outcome.published),
        "resuming a terminal zero-accept Leave must not authorize Left"
    );
}

#[tokio::test]
async fn leave_m1_to_m2_repair_persists_every_row_so_cleared_request_does_not_split_source() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot torn leave source key").unwrap();
    let (bob, bob_path, bob_identity, group_id) =
        joined_selfremove_member(dir.path(), &key, "torn-leave-source").await;
    let route = || {
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://torn-leave-inbox.example".into(),
        )])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![TransportEndpoint("wss://torn-leave-group.example".into())],
        )
    };
    let mut runtime = AccountDeviceRuntime::new(
        bob,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    runtime.pause_maintenance();
    let _leased = runtime
        .send_leased(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let later_id = MessageId::new(b"leave-m2-torn-source".to_vec());
    let mut request = runtime
        .session()
        .storage_handle()
        .leave_request(&group_id)
        .unwrap()
        .expect("accepted Leave writes a durable request");
    request.last_proposed_message_id = Some(later_id);
    runtime
        .session()
        .storage_handle()
        .put_leave_request(&request)
        .unwrap();
    drop(runtime);

    let reopened = session_with_registry(&bob_path, &key, &bob_identity, selfremove_registry());
    let mut repaired = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    repaired.pause_maintenance();
    let replayed = repaired
        .replay_visibility_leased()
        .unwrap()
        .expect("unacked Leave remains crash-visible for M1→M2 repair");
    drop(replayed);
    drop(repaired);

    let storage_session =
        session_with_registry(&bob_path, &key, &bob_identity, selfremove_registry());
    storage_session
        .storage_handle()
        .clear_leave_request(&group_id)
        .unwrap();
    drop(storage_session);

    let reopened = session_with_registry(&bob_path, &key, &bob_identity, selfremove_registry());
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    restarted
        .replay_visibility_leased()
        .expect("Header+suffix M2 repair must persist every row so reopen cannot split source");
}

#[tokio::test]
async fn terminal_m1_failure_ack_then_engine_m2_records_published_true() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot m1 ack engine m2 leave key").unwrap();
    let tag = "engine-m2-leave";
    let (bob, bob_path, bob_identity, group_id) =
        joined_selfremove_member(dir.path(), &key, tag).await;
    let bob_id = bob.self_id();
    let adapter = RecordingAdapter::default();
    let group_endpoint = TransportEndpoint("wss://engine-m2-group.example".into());
    adapter.fail_endpoints_as(
        vec![group_endpoint.clone()],
        TransportEndpointFailureKind::TerminalRejected,
    );
    let route = || {
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://engine-m2-inbox.example".into(),
        )])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![group_endpoint.clone()],
        )
    };
    let mut runtime =
        AccountDeviceRuntime::new(bob, adapter, route(), RecordingKeyPackages::default());
    runtime.pause_maintenance();
    let leased = runtime
        .send_leased(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert!(
        leased
            .effects
            .action_outcomes
            .iter()
            .all(|outcome| !outcome.published)
    );
    assert!(runtime.acknowledge_visibility_lease(leased.lease));
    drop(runtime);

    let alice_identity = format!("alice-{tag}").into_bytes();
    let alice_path = dir.path().join(format!("alice-{tag}.sqlite"));
    let alice = session_with_registry(&alice_path, &key, &alice_identity, selfremove_registry());
    let alice_adapter = RecordingAdapter::default();
    let mut alice_runtime = AccountDeviceRuntime::new(
        alice,
        alice_adapter.clone(),
        route(),
        RecordingKeyPackages::default(),
    );
    alice_runtime.pause_maintenance();
    alice_runtime
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("engine m2 epoch".to_owned()),
            description: None,
        })
        .await
        .expect("alice must advance the epoch so Bob's LeaveRequest can auto-repropose");
    let commit = alice_adapter
        .publishes()
        .into_iter()
        .map(|publish| publish.message)
        .find(|message| matches!(message.envelope, TransportEnvelope::GroupMessage { .. }))
        .expect("alice epoch-advancing commit is published");
    let commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit
    };
    drop(alice_runtime);

    let reopened = session_with_registry(&bob_path, &key, &bob_identity, selfremove_registry());
    let recovered_adapter = RecordingAdapter::default();
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        recovered_adapter.clone(),
        route(),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    assert!(
        restarted.replay_visibility_leased().unwrap().is_none(),
        "terminal M1 Header ACK must drop Leave provenance from the journal"
    );
    let ingested = restarted
        .ingest_delivery_leased(TransportDelivery {
            account_id: bob_id,
            group_id_hint: Some(group_id.clone()),
            message: commit,
            received_at: Timestamp(0),
            source: TransportDeliverySource {
                transport: TransportSource("marmot-account-test".into()),
                plane: TransportDeliveryPlane::Group,
                endpoint: None,
                subscription_id: None,
                wire: None,
            },
        })
        .await
        .expect("bob must ingest alice's epoch-advancing commit");
    let mut published = ingested
        .effects
        .action_outcomes
        .iter()
        .any(|outcome| outcome.published);
    if matches!(
        ingested.outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ) || restarted.has_pending_convergence_inputs(&group_id).unwrap()
        || ingested
            .effects
            .pending_convergence
            .iter()
            .any(|pending| pending == &group_id)
    {
        tokio::time::sleep(Duration::from_millis(
            cgka_engine::canonicalization::V1_SETTLEMENT_QUIESCENCE_MS + 50,
        ))
        .await;
        let converged = restarted
            .advance_convergence_leased(&group_id)
            .await
            .expect("buffered epoch-advancing commit must converge");
        published |= converged
            .effects
            .action_outcomes
            .iter()
            .any(|outcome| outcome.published);
    }
    let drained = restarted.drain_leased().await.unwrap();
    published |= drained
        .effects
        .action_outcomes
        .iter()
        .any(|outcome| outcome.published);
    assert!(
        published,
        "engine-driven M2 success must record published:true even with no surviving M1 Header"
    );
}

#[tokio::test]
async fn mixed_leave_headers_select_one_owner_without_duplicate_bind() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot mixed leave header key").unwrap();
    let (bob, bob_path, bob_identity, group_id) =
        joined_selfremove_member(dir.path(), &key, "mixed-leave-header").await;
    let route = || {
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://mixed-leave-inbox.example".into(),
        )])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![TransportEndpoint("wss://mixed-leave-group.example".into())],
        )
    };
    let mut runtime = AccountDeviceRuntime::new(
        bob,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    runtime.pause_maintenance();
    let first = runtime
        .send_leased(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let first_id = first.effects.action_outcomes[0].message_id.clone();
    let second = runtime
        .send_leased(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await;
    assert!(
        second.is_err(),
        "a second Leave in the same epoch must fail closed as already requested"
    );
    drop(runtime);

    let reopened = session_with_registry(&bob_path, &key, &bob_identity, selfremove_registry());
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    let replayed = restarted
        .replay_visibility_leased()
        .unwrap()
        .expect("mixed Leave Headers remain crash-visible");
    let leave_bindings = replayed
        .batches
        .iter()
        .filter_map(|batch| match &batch.source {
            AccountVisibilitySource::Outbound {
                group_id: Some(source_group),
                action: Some(AccountVisibilityOutboundAction::Leave),
                action_message_id,
                ..
            } if source_group == &group_id => {
                Some((batch.operation_id.clone(), action_message_id.clone()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let bound_operations = leave_bindings
        .iter()
        .filter(|(_, bound)| bound.as_ref() == Some(&first_id))
        .map(|(operation_id, _)| operation_id.clone())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        bound_operations.len(),
        1,
        "exactly one visibility operation may own the live Leave id; mixed Some(M1)+None must not duplicate: {leave_bindings:?}"
    );
    let recovered = restarted
        .drain_leased()
        .await
        .expect("mixed Some(M1)+None Headers must not hard-fail terminal outcome recording");
    assert!(restarted.acknowledge_visibility_lease(recovered.lease));
}

#[tokio::test]
async fn cancelled_leave_fanout_recovery_emits_outcome_for_original_operation() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot cancelled leave outcome key").unwrap();
    let (bob, bob_path, bob_identity, group_id) =
        joined_selfremove_member(dir.path(), &key, "cancelled-leave-outcome").await;
    let adapter = RecordingAdapter::default();
    let gate = adapter.gate_all_publishes();
    let route = || {
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://cancelled-leave-inbox.example".into(),
        )])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![TransportEndpoint(
                "wss://cancelled-leave-group.example".into(),
            )],
        )
    };
    let mut runtime = AccountDeviceRuntime::new(
        bob,
        adapter.clone(),
        route(),
        RecordingKeyPackages::default(),
    );
    runtime.pause_maintenance();
    let mut cancelled = Box::pin(runtime.send_leased(SendIntent::Leave {
        group_id: group_id.clone(),
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut cancelled => panic!("Leave returned before cancellation boundary: {result:?}"),
            () = async {
                while adapter.publishes().is_empty() {
                    tokio::task::yield_now().await;
                }
            } => {}
        }
    })
    .await
    .expect("Leave reaches the blocked relay publish");
    let leave_message_id = adapter.publishes()[0].message.id.clone();
    drop(cancelled);
    drop(runtime);
    gate.release.add_permits(1);

    let reopened = session_with_registry(&bob_path, &key, &bob_identity, selfremove_registry());
    let recovered_adapter = RecordingAdapter::default();
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        recovered_adapter.clone(),
        route(),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    let pending = restarted
        .replay_visibility_leased()
        .unwrap()
        .expect("bound original Leave Header survives cancellation");
    assert!(
        flatten_visibility_batches(&pending.batches)
            .action_outcomes
            .is_empty(),
        "an unresolved Attempting fanout must not invent a terminal action outcome"
    );
    let original_operation_id = pending
        .batches
        .iter()
        .find_map(|batch| match &batch.source {
            AccountVisibilitySource::Outbound {
                group_id: Some(source_group),
                action: Some(AccountVisibilityOutboundAction::Leave),
                action_message_id: Some(source_message),
                ..
            } if source_group == &group_id && source_message == &leave_message_id => {
                Some(batch.operation_id.clone())
            }
            _ => None,
        })
        .expect("original Header binds the exact SelfRemove message");

    let recovered = restarted.drain_leased().await.unwrap();
    assert_eq!(recovered.effects.action_outcomes.len(), 1);
    assert_eq!(
        recovered.effects.action_outcomes[0],
        marmot_account::AccountVisibilityActionOutcome {
            operation_id: original_operation_id,
            group_id: group_id.clone(),
            message_id: leave_message_id,
            action: AccountVisibilityOutboundAction::Leave,
            published: true,
        }
    );
    assert_eq!(recovered_adapter.publishes().len(), 1);
    assert!(
        !restarted.acknowledge_visibility_lease(pending.lease),
        "the recovery lease supersedes the pre-recovery generation"
    );
    assert!(restarted.acknowledge_visibility_lease(recovered.lease));
    assert!(restarted.replay_visibility_leased().unwrap().is_none());
}

#[tokio::test]
async fn legacy_cancelled_operation_drain_acks_recovered_rows_so_reopen_does_not_redeliver() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot cancelled drain ack key").unwrap();
    let (bob, bob_path, bob_identity, group_id) =
        joined_selfremove_member(dir.path(), &key, "cancelled-drain-ack").await;
    let adapter = RecordingAdapter::default();
    let gate = adapter.gate_all_publishes();
    let route = || {
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://cancelled-drain-inbox.example".into(),
        )])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![TransportEndpoint(
                "wss://cancelled-drain-group.example".into(),
            )],
        )
    };
    let mut runtime = AccountDeviceRuntime::new(
        bob,
        adapter.clone(),
        route(),
        RecordingKeyPackages::default(),
    );
    runtime.pause_maintenance();
    let mut cancelled = Box::pin(runtime.send_leased(SendIntent::Leave {
        group_id: group_id.clone(),
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut cancelled => panic!("Leave returned before cancellation boundary: {result:?}"),
            () = async {
                while adapter.publishes().is_empty() {
                    tokio::task::yield_now().await;
                }
            } => {}
        }
    })
    .await
    .expect("Leave reaches the blocked relay publish");
    drop(cancelled);
    gate.release.add_permits(1);
    let drained = runtime.drain().await.unwrap();
    assert!(
        !drained.events.is_empty()
            || !drained.action_outcomes.is_empty()
            || !drained.reports.is_empty(),
        "legacy drain must hand off the cancelled Leave effects"
    );
    drop(runtime);

    let reopened = session_with_registry(&bob_path, &key, &bob_identity, selfremove_registry());
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    assert!(
        restarted.replay_visibility_leased().unwrap().is_none(),
        "legacy drain must ACK every handed-off cancelled operation"
    );
    let second = restarted.drain().await.unwrap();
    assert!(
        second.action_outcomes.is_empty(),
        "reopen must not redeliver a cancelled Leave already returned by drain"
    );
}

#[tokio::test]
async fn legacy_ingest_delivery_acks_engine_outbox_so_reopen_does_not_redeliver() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot legacy ingest ack key").unwrap();
    let alice_path = dir.path().join("alice-legacy-ingest.sqlite");
    let bob_path = dir.path().join("bob-legacy-ingest.sqlite");
    let mut alice = session_with_registry(
        &alice_path,
        &key,
        b"alice-legacy-ingest",
        selfremove_registry(),
    );
    let mut bob =
        session_with_registry(&bob_path, &key, b"bob-legacy-ingest", selfremove_registry());
    let bob_id = bob.self_id();
    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "legacy ingest ack".into(),
            description: String::new(),
            members: vec![bob_key_package],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let (pending, welcome) = match created.effects.publish.as_slice() {
        [PublishWork::GroupCreated { pending, welcomes }] => (*pending, welcomes[0].clone()),
        other => panic!("expected one GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let mut runtime = AccountDeviceRuntime::new(
        bob,
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://legacy-ingest-inbox.example".into(),
        )]),
        RecordingKeyPackages::default(),
    );
    runtime.pause_maintenance();
    let ingested = runtime
        .ingest_delivery(TransportDelivery {
            account_id: bob_id,
            group_id_hint: None,
            message: welcome,
            received_at: Timestamp(0),
            source: TransportDeliverySource {
                transport: TransportSource("marmot-account-test".into()),
                plane: TransportDeliveryPlane::AccountInbox,
                endpoint: None,
                subscription_id: None,
                wire: None,
            },
        })
        .await
        .unwrap();
    assert!(
        ingested
            .effects
            .events
            .iter()
            .any(|event| matches!(event, GroupEvent::GroupJoined { .. })),
        "legacy ingest must return the Welcome application event"
    );
    assert!(
        runtime
            .session()
            .storage_handle()
            .list_pending_application_events()
            .unwrap()
            .is_empty(),
        "legacy ingest must ACK engine outbox ids with the visibility discard"
    );
    drop(runtime);

    let reopened =
        session_with_registry(&bob_path, &key, b"bob-legacy-ingest", selfremove_registry());
    assert!(
        reopened
            .storage_handle()
            .list_pending_application_events()
            .unwrap()
            .is_empty(),
        "reopen must not hydrate a returned Welcome back into the engine outbox"
    );
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://legacy-ingest-inbox.example".into(),
        )]),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    let drained = restarted.drain().await.unwrap();
    assert!(
        drained
            .events
            .iter()
            .all(|event| !matches!(event, GroupEvent::GroupJoined { .. })),
        "a returned GroupJoined must not reappear after every reopen"
    );
}

#[tokio::test]
async fn leave_quorum_records_published_true_while_optional_target_stays_retryable() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot leave quorum outcome key").unwrap();
    let (bob, bob_path, bob_identity, group_id) =
        joined_selfremove_member(dir.path(), &key, "leave-quorum-outcome").await;
    let required = TransportEndpoint("wss://leave-quorum-required.example".into());
    let optional = TransportEndpoint("wss://leave-quorum-optional.example".into());
    let adapter = RecordingAdapter::default();
    adapter.fail_endpoints_as(
        vec![optional.clone()],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    let route = || {
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://leave-quorum-inbox.example".into(),
        )])
        .required_acks(1)
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![required.clone(), optional.clone()],
        )
    };
    let mut runtime =
        AccountDeviceRuntime::new(bob, adapter, route(), RecordingKeyPackages::default());
    runtime.pause_maintenance();
    let leased = runtime
        .send_leased(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(leased.effects.action_outcomes.len(), 1);
    assert!(
        leased.effects.action_outcomes[0].published,
        "meeting required ACKs must authorize Left even if an optional target is still retryable"
    );
    assert!(
        leased
            .effects
            .fanout
            .iter()
            .any(|outcome| outcome.outstanding_targets > 0 && !outcome.fanout_complete),
        "the optional target must remain outstanding so this is not the complete-fanout path"
    );
    drop(runtime);

    let reopened = session_with_registry(&bob_path, &key, &bob_identity, selfremove_registry());
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    let replayed = restarted
        .replay_visibility_leased()
        .unwrap()
        .expect("quorum Leave outcome survives restart");
    assert_eq!(
        flatten_visibility_batches(&replayed.batches)
            .action_outcomes
            .iter()
            .filter(|outcome| outcome.published)
            .count(),
        1
    );
    assert!(restarted.acknowledge_visibility_lease(replayed.lease));
}

#[tokio::test]
async fn leave_reproposal_rebinds_header_to_the_new_self_remove() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot leave reproposal provenance key").unwrap();
    let (bob, bob_path, bob_identity, group_id) =
        joined_selfremove_member(dir.path(), &key, "leave-reproposal-provenance").await;
    let route = || {
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://leave-reproposal-inbox.example".into(),
        )])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![TransportEndpoint(
                "wss://leave-reproposal-group.example".into(),
            )],
        )
    };
    let mut runtime = AccountDeviceRuntime::new(
        bob,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    runtime.pause_maintenance();
    let leased = runtime
        .send_leased(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let original = leased
        .effects
        .action_outcomes
        .first()
        .expect("the original Leave binds an exact SelfRemove");
    let first_id = original.message_id.clone();
    let later_id = MessageId::new(b"leave-reproposal-m2".to_vec());
    assert_ne!(first_id, later_id);
    let mut request = runtime
        .session()
        .storage_handle()
        .leave_request(&group_id)
        .unwrap()
        .expect("accepted Leave writes a durable request");
    request.last_proposed_message_id = Some(later_id.clone());
    runtime
        .session()
        .storage_handle()
        .put_leave_request(&request)
        .unwrap();
    drop(runtime);

    let reopened = session_with_registry(&bob_path, &key, &bob_identity, selfremove_registry());
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    let replayed = restarted
        .replay_visibility_leased()
        .unwrap()
        .expect("Leave Header survives the message-id move");
    assert!(replayed.batches.iter().any(|batch| {
        matches!(
            &batch.source,
            AccountVisibilitySource::Outbound {
                group_id: Some(source_group),
                action: Some(AccountVisibilityOutboundAction::Leave),
                action_message_id: Some(bound),
                ..
            } if source_group == &group_id && bound == &later_id
        )
    }));
    assert!(restarted.acknowledge_visibility_lease(replayed.lease));
}

#[tokio::test]
async fn older_pre_acceptance_leave_header_does_not_bind_a_later_leave_id() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot stale leave header key").unwrap();
    let database = dir.path().join("stale-leave-header.sqlite");
    let mut alice = session_with_registry(
        &database,
        &key,
        b"stale-leave-header",
        selfremove_registry(),
    );
    let created = alice
        .create_group(CreateGroupRequest {
            name: "stale leave header".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let pending = match created.effects.publish.as_slice() {
        [PublishWork::GroupCreated { pending, .. }] => *pending,
        other => panic!("expected one GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    let route = || {
        StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://stale-leave-header.example".into(),
        )])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![TransportEndpoint(
                "wss://stale-leave-header-group.example".into(),
            )],
        )
    };
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    runtime.pause_maintenance();
    assert!(
        runtime
            .send_leased(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await
            .is_err(),
        "an admin SelfRemove must fail before engine acceptance"
    );
    assert!(
        runtime
            .send_leased(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await
            .is_err(),
        "a second pre-acceptance Leave must leave a newer Header"
    );
    let later_id = MessageId::new(b"later-leave".to_vec());
    runtime
        .session()
        .storage_handle()
        .put_leave_request(&cgka_traits::storage::LeaveRequest {
            group_id: group_id.clone(),
            requested_at_ms: 1,
            last_proposed_epoch: None,
            last_proposed_message_id: Some(later_id.clone()),
        })
        .unwrap();
    drop(runtime);

    let reopened = session_with_registry(
        &database,
        &key,
        b"stale-leave-header",
        selfremove_registry(),
    );
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        RecordingAdapter::default(),
        route(),
        RecordingKeyPackages::default(),
    );
    restarted.pause_maintenance();
    let replayed = restarted
        .replay_visibility_leased()
        .unwrap()
        .expect("both pre-acceptance Headers remain crash-visible");
    let leave_headers = replayed
        .batches
        .iter()
        .filter_map(|batch| match &batch.source {
            AccountVisibilitySource::Outbound {
                group_id: Some(source_group),
                action: Some(AccountVisibilityOutboundAction::Leave),
                action_message_id,
                ..
            } if source_group == &group_id => Some((batch.sequence, action_message_id.clone())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(leave_headers.len(), 2);
    let max_seq = leave_headers
        .iter()
        .map(|(sequence, _)| *sequence)
        .max()
        .unwrap();
    for (sequence, bound) in &leave_headers {
        if *sequence == max_seq {
            assert_eq!(bound.as_ref(), Some(&later_id));
        } else {
            assert_eq!(
                bound, &None,
                "an older unacknowledged pre-acceptance Header must not inherit a later Leave id"
            );
        }
    }
    assert!(restarted.acknowledge_visibility_lease(replayed.lease));
}

// A startup drain can contain both a one-shot hydration/application event and
// restored durable publish work. Cancelling while that publish is in flight
// must not require rebuilding the whole AccountDeviceRuntime to see the event
// again: the retained runtime's following no-inbound drain is the handoff
// recovery surface.
#[tokio::test]
async fn cancelled_drain_replays_visibility_after_restored_publish_blocks() {
    use cgka_traits::GroupStorage;
    use cgka_traits::engine::GroupHydrationQuarantineReason;
    use cgka_traits::group::Group;

    let dir = tempfile::tempdir().unwrap();
    let key_text = "marmot cancelled drain visibility key";
    let key = SqlCipherKey::new(key_text).unwrap();
    let db_path = dir.path().join("alice.sqlite");
    let mut alice = session(&db_path, &key, b"alice-cancelled-drain");

    let created = alice
        .create_group(CreateGroupRequest {
            name: "cancelled drain source".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let create_pending = match created.effects.publish.as_slice() {
        [PublishWork::GroupCreated { pending, .. }] => *pending,
        other => panic!("expected one GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();

    // Leave an exact signed evolution and its frozen fanout durable but
    // unpublished. Reopening recovers the pending evolution, and `drain()`
    // resumes that fanout in the same call as the hydration event below.
    let staged = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("restored publish".into()),
            description: None,
        })
        .await
        .unwrap();
    let (message, pending) = match staged.publish.as_slice() {
        [PublishWork::GroupEvolution { msg, pending, .. }] => (msg.clone(), *pending),
        other => panic!("expected one GroupEvolution publish work, got {other:?}"),
    };
    let transport_group_id = match &message.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => transport_group_id.clone(),
        other => panic!("expected group-message evolution, got {other:?}"),
    };
    let group_endpoint = TransportEndpoint("wss://cancelled-drain-group.example".into());
    let frozen_request = TransportPublishRequest {
        account_id: alice.self_id().clone(),
        message,
        target: TransportPublishTarget::Group {
            group_id: group_id.clone(),
            transport_group_id,
            endpoints: vec![group_endpoint.clone()],
        },
        required_acks: 1,
    };
    let frozen_fanout =
        OutboundFanout::stage(frozen_request, Some(pending), Some(group_id.clone()), 0).unwrap();
    alice.put_outbound_fanout(&frozen_fanout).unwrap();
    drop(alice);

    let broken_group = GroupId::new(b"cancelled-drain-broken-group".to_vec());
    {
        let storage =
            SqliteAccountStorage::open_encrypted(&db_path, &SqlCipherKey::new(key_text).unwrap())
                .unwrap();
        storage
            .put_group(&Group {
                id: broken_group.clone(),
                name: "broken".into(),
                description: String::new(),
                members: Vec::new(),
                epoch: EpochId(9),
                required_capabilities: cgka_traits::GroupCapabilities::default(),
                protocol_profile: ProtocolProfile::Legacy,
                removed: false,
                unrecoverable: false,
                disbanded: None,
                join_epoch: EpochId(0),
            })
            .unwrap();
    }

    let reopened = session(
        &db_path,
        &SqlCipherKey::new(key_text).unwrap(),
        b"alice-cancelled-drain",
    );
    let adapter = RecordingAdapter::default();
    let gate = adapter.gate_all_publishes();
    let policy = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://cancelled-drain-inbox.example".into(),
    )])
    .with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![group_endpoint],
    );
    let mut runtime = AccountDeviceRuntime::new(
        reopened,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    let mut cancelled = Box::pin(runtime.drain());
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut cancelled => {
                panic!("startup publish returned before cancellation boundary: {result:?}")
            }
            () = async {
                while adapter.publishes().is_empty() {
                    tokio::task::yield_now().await;
                }
            } => {}
        }
    })
    .await
    .expect("restored publish reaches the blocking adapter");
    drop(cancelled);

    // The first blocked adapter future was dropped with the drain. Let its
    // durable exact fanout retry complete on the next call.
    gate.release.add_permits(1);
    let recovered = tokio::time::timeout(Duration::from_secs(5), runtime.drain())
        .await
        .expect("retained runtime drain completes")
        .unwrap();
    assert!(recovered.events.iter().any(|event| matches!(
        event,
        GroupEvent::GroupHydrationQuarantined {
            group_id,
            reason: GroupHydrationQuarantineReason::OpenMlsGroupMissing,
        } if group_id == &broken_group
    )));

    let handed_off = runtime.drain().await.unwrap();
    assert!(!handed_off.events.iter().any(|event| matches!(
        event,
        GroupEvent::GroupHydrationQuarantined { group_id, .. } if group_id == &broken_group
    )));
}

#[tokio::test]
async fn cancelled_later_publish_work_replays_completed_application_effects_without_republishing() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot multi-work visibility key").unwrap();
    let mut alice = session(
        dir.path().join("alice-multi-work.sqlite"),
        &key,
        b"alice-multi-work",
    );
    let created = alice
        .create_group(CreateGroupRequest {
            name: "multi-work visibility".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let create_pending = match created.effects.publish.as_slice() {
        [PublishWork::GroupCreated { pending, .. }] => *pending,
        other => panic!("expected one GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();

    let mut combined = alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&hex::encode(alice.self_id().as_slice()), "first"),
        })
        .await
        .unwrap();
    let second = alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&hex::encode(alice.self_id().as_slice()), "second"),
        })
        .await
        .unwrap();
    combined.events.extend(second.events);
    combined.publish.extend(second.publish);
    combined.queued.extend(second.queued);
    combined
        .pending_convergence
        .extend(second.pending_convergence);

    let (first_message_id, first_app_event_id) = match &combined.publish[0] {
        PublishWork::ApplicationMessage {
            msg, app_event_id, ..
        } => (msg.id.clone(), app_event_id.clone()),
        other => panic!("expected first ApplicationMessage, got {other:?}"),
    };
    let second_message_id = match &combined.publish[1] {
        PublishWork::ApplicationMessage { msg, .. } => msg.id.clone(),
        other => panic!("expected second ApplicationMessage, got {other:?}"),
    };

    let adapter = RecordingAdapter::default();
    let gate = adapter.gate_all_publishes();
    gate.release.add_permits(1);
    let endpoint = TransportEndpoint("wss://multi-work-group.example".into());
    let routing = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://multi-work-inbox.example".into(),
    )])
    .with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![endpoint],
    );
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        routing,
        RecordingKeyPackages::default(),
    );

    let mut cancelled = Box::pin(runtime.publish_session_effects(combined));
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut cancelled => {
                panic!("both publish work items completed before cancellation: {result:?}")
            }
            () = async {
                while adapter.publishes().len() < 2 {
                    tokio::task::yield_now().await;
                }
            } => {}
        }
    })
    .await
    .expect("second application publish reaches its blocking adapter");
    drop(cancelled);

    // The second exact fanout remains durable and retryable. Completing it may
    // not re-run the first PublishWork; its report and app-acceptance metadata
    // must instead come from the runtime visibility journal.
    gate.release.add_permits(1);
    let recovered = tokio::time::timeout(Duration::from_secs(5), runtime.drain_leased())
        .await
        .expect("durable second fanout retry completes")
        .unwrap();
    let recovered_visibility = flatten_visibility_batches(&recovered.batches);
    assert_eq!(
        recovered_visibility
            .reports
            .iter()
            .filter(|report| report.message_id == first_message_id)
            .count(),
        1
    );
    assert_eq!(
        recovered_visibility
            .published_app_messages
            .iter()
            .filter(|published| published.app_event_id == first_app_event_id)
            .count(),
        1
    );
    let publishes = adapter.publishes();
    assert_eq!(
        publishes
            .iter()
            .filter(|request| request.message.id == first_message_id)
            .count(),
        1,
        "replay must not publish the completed first item again"
    );
    assert_eq!(
        publishes
            .iter()
            .filter(|request| request.message.id == second_message_id)
            .count(),
        2,
        "only the cancelled second fanout should retry"
    );

    let replayed = runtime.drain_leased().await.unwrap();
    let replayed_visibility = flatten_visibility_batches(&replayed.batches);
    assert_eq!(
        replayed_visibility
            .published_app_messages
            .iter()
            .filter(|published| published.app_event_id == first_app_event_id)
            .count(),
        1,
        "an unacknowledged full-effects lease must replay without duplication"
    );
    assert!(!runtime.acknowledge_visibility_lease(recovered.lease));
    assert!(runtime.acknowledge_visibility_lease(replayed.lease));

    let after_ack = runtime.drain_leased().await.unwrap();
    assert!(after_ack.effects.published_app_messages.is_empty());
    assert!(runtime.acknowledge_visibility_lease(after_ack.lease));
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

    let ingested = runtime.ingest_delivery_leased(delivery).await.unwrap();
    assert_eq!(ingested.effects.pending_convergence, vec![group_id.clone()]);
    assert!(
        ingested.effects.pending.is_empty(),
        "ingest should schedule the delayed auto-commit, not publish it immediately"
    );

    tokio::time::sleep(std::time::Duration::from_millis(75)).await;
    let advanced = runtime.advance_convergence_leased(&group_id).await.unwrap();

    assert_eq!(
        flatten_visibility_batches(&advanced.batches).pending_convergence,
        vec![group_id.clone()],
        "the unacknowledged ingest visibility must precede convergence output"
    );
    assert!(
        !runtime.acknowledge_visibility_lease(ingested.lease),
        "a later lease supersedes the ingest generation"
    );

    // The auto-published commit was accepted by a relay but missed required_acks
    // — it must be confirmed (kept), not rolled back.
    assert_eq!(advanced.effects.pending.len(), 1);
    assert!(
        matches!(
            advanced.effects.pending[0],
            PendingResolution::Confirmed { .. }
        ),
        "relay-accepted auto-publish must be confirmed, got {:?}",
        advanced.effects.pending[0]
    );
    // The commit publish was attempted and reported under-threshold acceptance.
    assert_eq!(advanced.effects.reports.len(), 1);
    assert_eq!(advanced.effects.reports[0].accepted_count(), 1);
    assert!(!advanced.effects.reports[0].met_required_acks());
    assert!(runtime.acknowledge_visibility_lease(advanced.lease));

    let after_ack = runtime.drain_leased().await.unwrap();
    assert!(after_ack.effects.pending_convergence.is_empty());
    assert!(after_ack.effects.pending.is_empty());
    assert!(after_ack.effects.reports.is_empty());
    assert!(runtime.acknowledge_visibility_lease(after_ack.lease));
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
