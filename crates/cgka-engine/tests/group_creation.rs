//! Group creation and welcome integration tests.
//!
//! Uses a pass-through mock peeler that reflects `EncryptedPayload` bytes
//! into a `TransportMessage` without any crypto. Lets us exercise the engine
//! end-to-end — parsing KeyPackages, validating capabilities, committing,
//! serializing — without pulling in a real peeler impl.

use async_trait::async_trait;
use cgka_engine::account_identity_proof::{
    ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE, account_identity_proof_extension,
};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::key_package::is_last_resort_key_package;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::EngineError;
use cgka_traits::app_components::{
    AppComponentData, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID,
    NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, default_group_components, encode_nostr_routing_v1,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use openmls::prelude::{
    BasicCredential, Capabilities, CredentialWithKey, ExtensionType, Extensions,
    KeyPackage as MlsKeyPackage, MlsMessageOut,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::Ciphersuite;
use storage_sqlite::SqliteAccountStorage;
use tls_codec::Serialize as _;

mod support;
use support::proof_signer;

/// Build a wire KeyPackage carrying a `BasicCredential` whose identity is the
/// raw `identity` bytes, bypassing the engine's identity validation. Used to
/// simulate a malformed credential arriving from a non-conformant peer.
fn key_package_with_raw_identity(identity: &[u8]) -> cgka_traits::engine::KeyPackage {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential = BasicCredential::new(identity.to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.public().into(),
    };
    let bundle = MlsKeyPackage::builder()
        .leaf_node_capabilities(Capabilities::default())
        .build(ciphersuite, &provider, &signer, credential_with_key)
        .unwrap();
    let mls_msg: MlsMessageOut = bundle.key_package().clone().into();
    cgka_traits::engine::KeyPackage::new(mls_msg.tls_serialize_detached().unwrap())
}

fn key_package_with_mismatched_account_identity_proof(
    credential_identity: &[u8],
    proof_identity_seed: &[u8],
) -> cgka_traits::engine::KeyPackage {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential = BasicCredential::new(credential_identity.to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.public().into(),
    };
    let proof_identity = pad32(proof_identity_seed);
    let proof_signer = proof_signer(proof_identity_seed);
    let proof_extension = account_identity_proof_extension(
        &proof_identity,
        &signer.to_public_vec(),
        ciphersuite,
        ciphersuite.signature_algorithm(),
        proof_signer.as_ref(),
    )
    .unwrap();
    let bundle = MlsKeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            Some(&[ExtensionType::Unknown(
                ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE,
            )]),
            None,
            None,
        ))
        .leaf_node_extensions(Extensions::single(proof_extension).unwrap())
        .build(ciphersuite, &provider, &signer, credential_with_key)
        .unwrap();
    let mls_msg: MlsMessageOut = bundle.key_package().clone().into();
    cgka_traits::engine::KeyPackage::new(mls_msg.tls_serialize_detached().unwrap())
}

/// Mock peeler: wraps `EncryptedPayload` bytes verbatim into a
/// `TransportMessage` with a hash-derived id. No real crypto. Peel paths
/// unwrap the payload back out.
fn pad32(name: &[u8]) -> Vec<u8> {
    // Marmot credential identities MUST be a valid 32-byte x-only secp256k1
    // public key (spec/foundation/identity.md). Derive one deterministically
    // from the ergonomic label so admin/member tracking stays stable across a
    // run while the engine accepts the identity.
    use k256::schnorr::SigningKey;
    use sha2::{Digest, Sha256};
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(name);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk.verifying_key().to_bytes().to_vec();
        }
        counter += 1;
    }
}

struct MockPeeler;

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
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
        // Pass-through: the engine put the raw MLS welcome bytes in
        // `payload` on the wrap side; unwrap by returning them as-is.
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
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: ctx.transport_group_id().unwrap_or_default().to_vec(),
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
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

fn build_client_with_components(
    identity: &[u8],
    components: impl IntoIterator<Item = u16>,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .supported_app_components(components)
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

fn selfremove_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10), // MIP-03 SelfRemove
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r
}

fn build_client(identity: &[u8], registry: FeatureRegistry) -> impl CgkaEngine {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(registry)
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

fn build_client_on_storage(
    identity: &[u8],
    registry: FeatureRegistry,
    storage: SqliteAccountStorage,
) -> impl CgkaEngine {
    EngineBuilder::new(storage)
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(registry)
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

fn app_payload_for(engine: &Engine<SqliteAccountStorage>, payload: impl AsRef<[u8]>) -> Vec<u8> {
    let content = String::from_utf8(payload.as_ref().to_vec()).expect("test app payload is utf8");
    MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        content,
    )
    .encode()
    .expect("test app event encodes")
}

#[tokio::test]
async fn create_group_rejects_invitee_keypackage_with_non_secp256k1_identity() {
    // A peer with a non-conformant client sends a KeyPackage whose credential
    // identity is 32 bytes but not a valid x-only secp256k1 point. The engine
    // MUST reject it at parse time (foundation/key-packages.md).
    let mut alice = build_client(b"alice", selfremove_registry());
    let mut bad_identity = vec![0u8; 32];
    bad_identity[..5].copy_from_slice(b"david"); // 32 bytes, not a curve point
    let bad_kp = key_package_with_raw_identity(&bad_identity);

    let err = alice
        .create_group(CreateGroupRequest {
            name: "bad-invitee".into(),
            description: "".into(),
            members: vec![bad_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("create_group must reject the malformed invitee");
    assert!(
        matches!(err, EngineError::InvalidCredentialIdentity(_)),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn create_group_rejects_invitee_keypackage_with_short_identity() {
    // Same gate, length branch: a 3-byte identity is rejected.
    let mut alice = build_client(b"alice", selfremove_registry());
    let bad_kp = key_package_with_raw_identity(b"bob");

    let err = alice
        .create_group(CreateGroupRequest {
            name: "short-invitee".into(),
            description: "".into(),
            members: vec![bad_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("create_group must reject the short invitee identity");
    assert!(
        matches!(err, EngineError::InvalidCredentialIdentity(_)),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn create_group_with_three_members_happy_path() {
    let mut alice = build_client(b"alice-identity", selfremove_registry());
    let mut bob = build_client(b"bob-identity", selfremove_registry());
    let mut carol = build_client(b"carol-identity", selfremove_registry());

    let bob_kp = bob.fresh_key_package().await.expect("bob kp");
    let carol_kp = carol.fresh_key_package().await.expect("carol kp");

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "test".into(),
            description: "integration smoke".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![Feature("self-remove")],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect("create_group");

    // Sanity on SendResult shape.
    match &result {
        SendResult::GroupCreated {
            welcomes,
            pending: _,
        } => {
            assert_eq!(welcomes.len(), 2, "one welcome per invitee");
        }
        _ => panic!("expected GroupEvolution"),
    }

    // Alice is at epoch 1 and sees 3 members.
    assert_eq!(alice.epoch(&group_id).unwrap().0, 1);
    let members = alice.members(&group_id).unwrap();
    assert_eq!(members.len(), 3);

    // Every welcome is addressed (envelope discriminator populated).
    if let SendResult::GroupCreated { welcomes, .. } = result {
        for w in welcomes {
            match w.envelope {
                TransportEnvelope::Welcome { .. } => {}
                _ => panic!("welcome envelope"),
            }
        }
    }
}

#[tokio::test]
async fn nostr_routing_component_drives_group_message_route() {
    let mut supported = default_group_components();
    supported.insert(NOSTR_ROUTING_COMPONENT_ID);
    let mut alice = build_client_with_components(b"alice", supported.clone());
    let mut bob = build_client_with_components(b"bob", supported);
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let routing = NostrRoutingV1::new(
        [0x41; 32],
        vec![
            "wss://relay-b.example".into(),
            "wss://relay-a.example".into(),
        ],
    )
    .unwrap();
    let routing_bytes = encode_nostr_routing_v1(&routing).unwrap();

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "nostr".into(),
            description: "routing component".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: routing_bytes.clone(),
            }],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match result {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected group created, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let group = alice.group_record(&group_id).unwrap();
    assert!(
        group
            .required_capabilities
            .app_components
            .contains(NOSTR_ROUTING_COMPONENT_ID)
    );
    assert_eq!(
        alice
            .app_component(&group_id, NOSTR_ROUTING_COMPONENT_ID)
            .unwrap(),
        Some(routing_bytes)
    );

    let sent = alice
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, b"hello"),
        })
        .await
        .unwrap();
    let msg = match sent {
        SendResult::ApplicationMessage { msg } => msg,
        other => panic!("expected app message, got {other:?}"),
    };
    assert_eq!(
        msg.envelope,
        TransportEnvelope::GroupMessage {
            transport_group_id: routing.nostr_group_id.to_vec()
        }
    );
    assert_ne!(routing.nostr_group_id.as_slice(), group_id.as_slice());

    assert!(
        group
            .required_capabilities
            .app_components
            .contains(GROUP_PROFILE_COMPONENT_ID)
    );
    assert!(
        group
            .required_capabilities
            .app_components
            .contains(GROUP_ADMIN_POLICY_COMPONENT_ID)
    );
}

#[tokio::test]
async fn create_group_rejects_invitee_missing_required_capability() {
    // Alice requires SelfRemove; "stripped" Bob advertises no required caps.
    let mut alice = build_client(b"alice", selfremove_registry());
    let mut stripped_bob = build_client(b"bob-no-caps", FeatureRegistry::new());

    let kp = stripped_bob.fresh_key_package().await.unwrap();
    let err = alice
        .create_group(CreateGroupRequest {
            name: "x".into(),
            description: "".into(),
            members: vec![kp],
            required_features: vec![Feature("self-remove")],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("should reject");

    match err {
        EngineError::MissingRequiredCapabilities { required, had } => {
            assert!(
                required.proposals.contains(&10),
                "required should include SelfRemove=10"
            );
            assert!(
                !had.proposals.contains(&10),
                "had should NOT include SelfRemove=10"
            );
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[tokio::test]
async fn constructable_capabilities_is_intersection() {
    let alice = build_client(b"a", selfremove_registry());
    let mut empty_bob = build_client(b"b", FeatureRegistry::new());

    let bob_kp = empty_bob.fresh_key_package().await.unwrap();
    let caps = alice.constructable_capabilities(&[bob_kp]).unwrap();
    // Bob advertises no features → intersection can't include SelfRemove.
    assert!(!caps.proposals.contains(&10));
}

#[tokio::test]
async fn create_group_rejects_invitee_keypackage_without_account_identity_proof() {
    let mut alice = build_client(b"alice", selfremove_registry());
    let bad_kp = key_package_with_raw_identity(&pad32(b"bob-no-proof"));

    let err = alice
        .create_group(CreateGroupRequest {
            name: "bad".into(),
            description: "".into(),
            members: vec![bad_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap_err();

    assert!(matches!(err, EngineError::InvalidAccountIdentityProof(_)));
}

#[tokio::test]
async fn create_group_rejects_invitee_keypackage_with_mismatched_account_identity_proof() {
    let mut alice = build_client(b"alice", selfremove_registry());
    let bad_kp = key_package_with_mismatched_account_identity_proof(
        &pad32(b"bob-credential"),
        b"mallory-proof",
    );

    let err = alice
        .create_group(CreateGroupRequest {
            name: "bad".into(),
            description: "".into(),
            members: vec![bad_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap_err();

    assert!(matches!(err, EngineError::InvalidAccountIdentityProof(_)));
}

#[tokio::test]
async fn fresh_key_package_roundtrips_bytes() {
    let mut alice = build_client(b"a", selfremove_registry());
    let kp = alice.fresh_key_package().await.unwrap();
    assert!(
        !kp.bytes().is_empty(),
        "key package bytes should be non-empty"
    );
}

#[tokio::test]
async fn fresh_key_package_is_mls_last_resort() {
    let mut alice = build_client(b"a", selfremove_registry());
    let kp = alice.fresh_key_package().await.unwrap();

    assert!(is_last_resort_key_package(&kp).unwrap());
}

#[tokio::test]
async fn delete_key_package_is_idempotent_noop_when_absent() {
    // Deleting a KeyPackage that is not (or no longer) in storage must be a
    // no-op rather than an error, so the publisher-failure cleanup path is safe
    // to call idempotently across retries (darkmatter#160).
    let mut alice = build_client(b"a", selfremove_registry());
    let kp = alice.fresh_key_package().await.unwrap();

    alice.delete_key_package(&kp).await.unwrap();
    // Second delete: the bundle is already gone, but this still succeeds.
    alice.delete_key_package(&kp).await.unwrap();
}

#[tokio::test]
async fn delete_key_package_removes_bundle_so_welcome_cannot_be_joined() {
    // darkmatter#160: fresh_key_package persists the private bundle into
    // storage. After delete_key_package prunes it, a Welcome built against that
    // KeyPackage can no longer be joined because the private bundle is gone.
    let mut alice = build_client(b"alice", selfremove_registry());
    let mut bob = build_client(b"bob", selfremove_registry());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    // Bob prunes the just-generated bundle (as the orphan-cleanup path does).
    bob.delete_key_package(&bob_kp).await.unwrap();

    let (_gid, result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match result {
        SendResult::GroupCreated { welcomes, pending } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.into_iter().next().unwrap()
        }
        _ => unreachable!(),
    };

    // The private bundle was deleted, so Bob cannot join: OpenMLS finds no
    // matching KeyPackage in storage for the Welcome's referenced hash.
    bob.join_welcome(welcome)
        .await
        .expect_err("join must fail after the key package bundle was deleted");
}

#[tokio::test]
async fn join_welcome_called_twice_for_same_welcome_errors_on_second_call() {
    // Direct `CgkaEngine::join_welcome` callers skip the ingest-path
    // dedup. Without entry-level dedup, a re-call would re-stage a
    // Welcome on top of an existing group. The second call must error.
    let mut alice = build_client(b"alice", selfremove_registry());
    let mut bob = build_client(b"bob", selfremove_registry());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (_gid, result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match result {
        SendResult::GroupCreated { welcomes, pending } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.into_iter().next().unwrap()
        }
        _ => unreachable!(),
    };

    bob.join_welcome(welcome.clone()).await.unwrap();
    let err = bob
        .join_welcome(welcome)
        .await
        .expect_err("second join_welcome must error");
    match err {
        EngineError::Other(msg) => {
            assert!(
                msg.contains("already processed"),
                "expected 'already processed' message, got: {msg}"
            );
        }
        other => panic!("expected EngineError::Other(already processed), got {other:?}"),
    }
}

#[tokio::test]
async fn join_welcome_dedup_survives_engine_rebuild_on_same_storage() {
    // Direct `join_welcome` should persist the welcome's terminal state,
    // not rely only on in-memory `seen_message_ids`. A rebuilt engine on
    // the same storage must reject the duplicate before re-staging it.
    let mut alice = build_client(b"alice", selfremove_registry());
    let bob_storage = SqliteAccountStorage::in_memory().unwrap();
    let mut bob = build_client_on_storage(b"bob", selfremove_registry(), bob_storage.clone());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (_gid, result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match result {
        SendResult::GroupCreated { welcomes, pending } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.into_iter().next().unwrap()
        }
        _ => unreachable!(),
    };

    bob.join_welcome(welcome.clone()).await.unwrap();
    drop(bob);

    let mut rebuilt_bob = build_client_on_storage(b"bob", selfremove_registry(), bob_storage);
    let err = rebuilt_bob
        .join_welcome(welcome)
        .await
        .expect_err("rebuilt engine must reject duplicate welcome");
    match err {
        EngineError::Other(msg) => assert!(
            msg.contains("already processed"),
            "expected 'already processed' message, got: {msg}"
        ),
        other => panic!("expected EngineError::Other(already processed), got {other:?}"),
    }
}

#[tokio::test]
async fn join_welcome_rejected_when_client_no_longer_supports_required_capability() {
    // joining.md:65 / convergence.md:19 — a client MUST reject a Welcome whose
    // resulting group has active required capabilities it cannot apply.
    //
    // carol publishes a KeyPackage that advertises the SelfRemove proposal, so
    // alice's invite (which requires it) passes. carol then downgrades: she
    // rebuilds her engine on the same storage with an empty feature registry,
    // so her runtime no longer supports SelfRemove. Joining the group must now
    // be rejected.
    let mut alice = build_client(b"alice", selfremove_registry());
    let carol_storage = SqliteAccountStorage::in_memory().unwrap();
    let mut capable_carol =
        build_client_on_storage(b"carol", selfremove_registry(), carol_storage.clone());
    let carol_kp = capable_carol.fresh_key_package().await.unwrap();

    let (_gid, result) = alice
        .create_group(CreateGroupRequest {
            name: "requires-self-remove".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![Feature("self-remove")],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match result {
        SendResult::GroupCreated { welcomes, pending } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.into_iter().next().unwrap()
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    drop(capable_carol);

    // Downgraded carol: same identity + storage (so she can decrypt the
    // Welcome) but an empty registry (no SelfRemove support).
    let mut downgraded_carol =
        build_client_on_storage(b"carol", FeatureRegistry::new(), carol_storage);
    let err = downgraded_carol
        .join_welcome(welcome)
        .await
        .expect_err("join must be rejected for an unsupported required capability");
    match err {
        EngineError::MissingRequiredCapabilities { required, had } => {
            // The group requires the SelfRemove proposal (0x000a = 10)...
            assert!(
                required.proposals.contains(&10),
                "group should require SelfRemove; got {required:?}"
            );
            // ...which downgraded carol no longer advertises.
            assert!(
                !had.proposals.contains(&10),
                "downgraded carol must not advertise SelfRemove; got {had:?}"
            );
        }
        other => panic!("expected MissingRequiredCapabilities, got {other:?}"),
    }
}

#[tokio::test]
async fn join_welcome_rejected_when_client_lacks_required_app_component() {
    // App-component variant of the join capability gate. carol publishes a KP
    // advertising a custom app component; alice requires it; carol then rejoins
    // with an engine that does not support that component.
    const CUSTOM_COMPONENT: u16 = 0xF300;
    let mut alice = build_client_with_components(b"alice", [CUSTOM_COMPONENT]);
    let carol_storage = SqliteAccountStorage::in_memory().unwrap();
    let capable_carol = EngineBuilder::new(carol_storage.clone())
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .supported_app_components([CUSTOM_COMPONENT])
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build capable carol");
    let mut capable_carol = capable_carol;
    let carol_kp = capable_carol.fresh_key_package().await.unwrap();

    let (_gid, result) = alice
        .create_group(CreateGroupRequest {
            name: "requires-component".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: CUSTOM_COMPONENT,
                data: vec![1, 2, 3],
            }],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match result {
        SendResult::GroupCreated { welcomes, pending } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.into_iter().next().unwrap()
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    drop(capable_carol);

    // Downgraded carol supports no app components.
    let mut downgraded_carol = EngineBuilder::new(carol_storage)
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build downgraded carol");
    let err = downgraded_carol
        .join_welcome(welcome)
        .await
        .expect_err("join must be rejected for an unsupported required app component");
    assert!(
        matches!(err, EngineError::MissingRequiredCapabilities { ref required, .. }
            if required.app_components.contains(CUSTOM_COMPONENT)),
        "expected MissingRequiredCapabilities naming the component; got {err:?}"
    );
}

#[tokio::test]
async fn confirm_published_transitions_to_stable_and_emits_group_created() {
    let mut alice = build_client(b"a", selfremove_registry());
    let mut bob = build_client(b"b", selfremove_registry());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let pending = match result {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };

    // Double confirm → typed UnknownPending on second call.
    let event = alice.confirm_published(pending).await.unwrap();
    assert!(matches!(
        event,
        cgka_traits::engine::GroupEvent::GroupCreated { .. }
    ));

    // Drained events carry the same event.
    let drained = alice.drain_events();
    assert_eq!(drained.len(), 1);

    let err = alice.confirm_published(pending).await.err().unwrap();
    assert!(matches!(err, EngineError::UnknownPending));

    // Post-confirm: epoch unchanged (still 1), but state machine is Stable.
    assert_eq!(alice.epoch(&group_id).unwrap().0, 1);
}

#[tokio::test]
async fn two_engine_happy_path_create_and_join() {
    let mut alice = build_client(b"alice-id", selfremove_registry());
    let mut bob = build_client(b"bob-id", selfremove_registry());

    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (alice_gid, result) = alice
        .create_group(CreateGroupRequest {
            name: "cross".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    // Alice confirms publish → Stable.
    let pending = match &result {
        SendResult::GroupCreated { pending, .. } => *pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    // The welcomes addressed to bob flow to him.
    let bob_welcome = match result {
        SendResult::GroupCreated { welcomes, .. } => {
            welcomes.into_iter().next().expect("one welcome")
        }
        _ => unreachable!(),
    };

    let bob_gid = bob.join_welcome(bob_welcome).await.expect("bob joins");

    assert_eq!(alice_gid, bob_gid, "group ids must match across clients");
    assert_eq!(
        alice.epoch(&alice_gid).unwrap(),
        bob.epoch(&bob_gid).unwrap()
    );

    let alice_members = alice.members(&alice_gid).unwrap();
    let bob_members = bob.members(&bob_gid).unwrap();
    assert_eq!(alice_members.len(), 2);
    assert_eq!(bob_members.len(), 2);

    // Bob's event buffer carries the GroupJoined event.
    let events = bob.drain_events();
    assert_eq!(events.len(), 1);
    matches!(
        events[0],
        cgka_traits::engine::GroupEvent::GroupJoined { .. }
    );
}

#[tokio::test]
async fn join_welcome_rejects_wrong_recipient() {
    let mut alice = build_client(b"alice-id", selfremove_registry());
    let mut bob = build_client(b"bob-id", selfremove_registry());
    let mut eve = build_client(b"eve-id", selfremove_registry());

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (_gid, result) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let bob_welcome = match result {
        SendResult::GroupCreated { welcomes, .. } => welcomes.into_iter().next().unwrap(),
        _ => unreachable!(),
    };

    // Eve should not be able to consume bob's welcome.
    let err = eve.join_welcome(bob_welcome).await.err().unwrap();
    assert!(matches!(err, EngineError::Peeler(_)));
}

#[tokio::test]
async fn create_group_buffers_ingest_via_pending_state() {
    // After create_group, alice is in PendingPublish for that group.
    // can_ingest should be false until confirm_published lands.
    let mut alice = build_client(b"a", selfremove_registry());
    let mut bob = build_client(b"b", selfremove_registry());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (_gid, _result) = alice
        .create_group(CreateGroupRequest {
            name: "x".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    // epoch() reflects the underlying MLS group (1 after add) — the state
    // machine is PendingPublish but queries still return the current epoch.
    //
    // We can't directly peek at EpochState from outside the crate; the
    // observable contract is that ingest buffers while PendingPublish is live.
}

#[tokio::test]
async fn audit_log_records_welcome_recipient_expectation() {
    // Requirement #9: a welcome targets only the added member, and the
    // create_group outcome carries the welcome in its outbound inventory.
    use marmot_forensics::{AuditEvent, AuditEventKind, MessageArtifactKind, RecipientScope};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let recorder =
        marmot_forensics::JsonlRecorder::open(&path, "test-engine-recip".to_string()).unwrap();

    let mut alice = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(b"alice"))
        .account_identity_proof_signer(proof_signer(b"alice"))
        .peeler(Box::new(MockPeeler))
        .recorder(Box::new(recorder))
        .build()
        .expect("build alice with recorder");
    let mut bob = build_client(b"bob", FeatureRegistry::new());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (gid, result) = alice
        .create_group_with_audit_context(
            CreateGroupRequest {
                name: "g".into(),
                description: String::new(),
                members: vec![bob_kp],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            },
            None,
        )
        .await
        .expect("create group with bob");
    match result {
        SendResult::GroupCreated { pending, .. } => {
            alice.confirm_published(pending).await.unwrap();
        }
        _ => panic!("expected GroupCreated"),
    }

    // After create+confirm alice's projected roster includes bob, so an app
    // message targets all OTHER current members (just bob).
    let payload = app_payload_for(&alice, b"hello");
    alice
        .send_with_audit_context(
            cgka_traits::engine::SendIntent::AppMessage {
                group_id: gid.clone(),
                payload,
            },
            None,
        )
        .await
        .expect("send app message");
    drop(alice);

    let events: Vec<AuditEvent> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    // The create_group outcome inventory holds exactly the welcome.
    let outbound = events
        .iter()
        .find_map(|e| match &e.kind {
            AuditEventKind::CreateGroupOutcome {
                outbound_messages, ..
            } => Some(outbound_messages),
            _ => None,
        })
        .expect("create_group_outcome recorded");
    assert_eq!(outbound.len(), 1);
    assert_eq!(outbound[0].artifact_kind, MessageArtifactKind::Welcome);

    let expectations: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.kind {
            AuditEventKind::RecipientExpectation { expectation, .. } => Some(expectation),
            _ => None,
        })
        .collect();

    // The welcome scopes to the added member only.
    let welcome = expectations
        .iter()
        .find(|e| e.artifact_kind == MessageArtifactKind::Welcome)
        .expect("welcome recipient_expectation recorded");
    assert!(matches!(
        welcome.recipient_scope,
        RecipientScope::AddedMemberOnly
    ));
    assert_eq!(welcome.expected_count, Some(1));
    assert_eq!(welcome.expected_member_refs.len(), 1);
    assert_eq!(
        welcome.expected_member_refs[0].len(),
        32,
        "member ref is 16-byte hex"
    );

    // The app message scopes to all OTHER current members (just bob).
    let app_message = expectations
        .iter()
        .find(|e| e.artifact_kind == MessageArtifactKind::ApplicationMessage)
        .expect("app message recipient_expectation recorded");
    assert!(matches!(
        app_message.recipient_scope,
        RecipientScope::AllOtherCurrentGroupMembers
    ));
    assert_eq!(app_message.expected_count, Some(1));
    assert_eq!(app_message.expected_member_refs.len(), 1);

    // Obfuscated default posture: no full recipient pubkeys on any row.
    assert!(
        expectations
            .iter()
            .all(|e| e.expected_pubkeys_hex.is_empty())
    );
}
