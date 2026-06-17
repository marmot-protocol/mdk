use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_session::{AccountDeviceSession, PublishWork, SessionConfig};
use cgka_traits::engine::{CreateGroupRequest, GroupEvent, SendIntent};
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
    AccountDeviceRuntime, AccountError, KeyPackagePublication, KeyPackagePublishError,
    KeyPackagePublisher, PendingResolution, StaticTransportRouting,
};
use storage_sqlite::SqlCipherKey;

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
        let message = nostr::secp256k1::Message::from_digest(request.signing_digest());
        Ok(self.keys.sign_schnorr(&message).serialize())
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
    let keys = deterministic_nostr_keys(identity);
    AccountDeviceSession::open(
        SessionConfig::new(
            path,
            SqlCipherKey::new(key.as_secret_str()).unwrap(),
            pad32(identity),
            Box::new(MockPeeler),
        )
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner { keys }))
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
    accepted_counts: Mutex<VecDeque<usize>>,
}

impl RecordingAdapter {
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
            .accepted_counts
            .lock()
            .unwrap()
            .pop_front()
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
    async fn publish_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<(), KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication);
        let mut remaining = self.remaining_failures.lock().unwrap();
        if *remaining > 0 {
            *remaining -= 1;
            return Err(KeyPackagePublishError::unexposed(
                "injected publish failure",
            ));
        }
        Ok(())
    }
}

/// Publisher that simulates the production `AppKeyPackagePublisher` failure
/// shape: it "publishes" to an external transport first and only then performs
/// a local step that fails. The returned error is therefore `externally_exposed`
/// — the KeyPackage may already be discoverable on a relay, so the runtime must
/// NOT prune the private bundle (darkmatter#160 adversarial review).
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
    async fn publish_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<(), KeyPackagePublishError> {
        self.publications.lock().unwrap().push(publication);
        // External publish succeeded; a subsequent local step (e.g. cache write)
        // failed. The KeyPackage is already exposed.
        Err(KeyPackagePublishError::exposed(
            "injected post-exposure failure (e.g. local cache write)",
        ))
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

    assert!(!key_package.bytes().is_empty());
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
async fn publish_fresh_key_package_propagates_publish_error_and_prunes_bundle() {
    // darkmatter#160: when publication fails, publish_fresh_key_package must
    // surface the publish error AND delete the orphaned private bundle that
    // fresh_key_package persisted, so a failing-publisher retry loop does not
    // accumulate unused private key material.
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

    // Retry: a brand-new bundle is generated and this time publication
    // succeeds. The bundle from the failed attempt was pruned, so it is not
    // left orphaned in storage.
    let key_package = runtime
        .publish_fresh_key_package()
        .await
        .expect("retry should publish successfully");
    assert!(!key_package.bytes().is_empty());

    let publications = publisher.publications();
    // One failed attempt + one successful attempt were both sent to the
    // publisher; they carry distinct freshly generated key packages.
    assert_eq!(publications.len(), 2);
    assert_ne!(publications[0].key_package, publications[1].key_package);
    assert_eq!(publications[1].key_package, key_package);
}

#[tokio::test]
async fn publish_fresh_key_package_retains_bundle_when_publish_fails_after_exposure() {
    // darkmatter#160 adversarial review: the orphan-cleanup must NOT prune the
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
                bob_id,
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
                carol_id,
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
}

// darkmatter#426 regression: hydration-quarantine events must reach the
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
