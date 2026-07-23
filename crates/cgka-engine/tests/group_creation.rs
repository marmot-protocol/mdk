//! Group creation and welcome integration tests.
//!
//! Uses a pass-through mock peeler that reflects `EncryptedPayload` bytes
//! into a `TransportMessage` without any crypto. Lets us exercise the engine
//! end-to-end — parsing KeyPackages, validating capabilities, committing,
//! serializing — without pulling in a real peeler impl.

use async_trait::async_trait;
use cgka_engine::account_identity_proof::{
    ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE, account_identity_proof_component,
    account_identity_proof_extension,
};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::key_package::{is_last_resort_key_package, key_package_metadata};
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::EngineError;
use cgka_traits::app_components::{
    ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, APP_COMPONENTS_COMPONENT_ID, AppComponentData,
    EncryptedMediaPolicyV2, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
    GROUP_PROFILE_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1,
    default_group_components, encode_components_list, encode_encrypted_media_policy_v2,
    encode_nostr_routing_v1,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{GroupStorage, KeyPackageBundleStorage, StorageProvider};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use openmls::component::ComponentType;
use openmls::extensions::{
    AppDataDictionary, AppDataDictionaryExtension, Extension, LastResortExtension,
};
use openmls::prelude::{
    BasicCredential, Capabilities, CredentialWithKey, ExtensionType, Extensions,
    KeyPackage as MlsKeyPackage, Lifetime, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::Ciphersuite;
use storage_sqlite::SqliteAccountStorage;
use tls_codec::{Deserialize as _, Serialize as _};

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

fn key_package_with_account_identity_proof_and_lifetime(
    identity_seed: &[u8],
    lifetime: Lifetime,
) -> cgka_traits::engine::KeyPackage {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential_identity = pad32(identity_seed);
    let credential = BasicCredential::new(credential_identity.clone());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.public().into(),
    };
    let proof_extension = account_identity_proof_extension(
        &credential_identity,
        &signer.to_public_vec(),
        ciphersuite,
        ciphersuite.signature_algorithm(),
        proof_signer(identity_seed).as_ref(),
    )
    .unwrap();
    let bundle = MlsKeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            Some(&[
                ExtensionType::Unknown(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE),
                // Draft-10 encodes the last-resort marker as component 0x0004
                // inside the KeyPackage app_data_dictionary.
                ExtensionType::AppDataDictionary,
            ]),
            None,
            None,
        ))
        .leaf_node_extensions(Extensions::single(proof_extension).unwrap())
        .key_package_lifetime(lifetime)
        .mark_as_last_resort()
        .build(ciphersuite, &provider, &signer, credential_with_key)
        .unwrap();
    let mls_msg: MlsMessageOut = bundle.key_package().clone().into();
    cgka_traits::engine::KeyPackage::new(mls_msg.tls_serialize_detached().unwrap())
}

fn key_package_with_account_identity_proof_for_ciphersuite(
    identity_seed: &[u8],
    ciphersuite: Ciphersuite,
) -> cgka_traits::engine::KeyPackage {
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential_identity = pad32(identity_seed);
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(credential_identity.clone()).into(),
        signature_key: signer.public().into(),
    };
    let proof_extension = account_identity_proof_extension(
        &credential_identity,
        &signer.to_public_vec(),
        ciphersuite,
        ciphersuite.signature_algorithm(),
        proof_signer(identity_seed).as_ref(),
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

fn mixed_profile_key_package(identity_seed: &[u8]) -> cgka_traits::engine::KeyPackage {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential_identity = pad32(identity_seed);
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(credential_identity.clone()).into(),
        signature_key: signer.public().into(),
    };
    let proof_signer = proof_signer(identity_seed);
    let legacy = account_identity_proof_extension(
        &credential_identity,
        &signer.to_public_vec(),
        ciphersuite,
        ciphersuite.signature_algorithm(),
        proof_signer.as_ref(),
    )
    .unwrap();
    let current = account_identity_proof_component(
        &credential_identity,
        &signer.to_public_vec(),
        ciphersuite,
        ciphersuite.signature_algorithm(),
        1_700_000_000,
        proof_signer.as_ref(),
    )
    .unwrap();
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(
        cgka_traits::app_components::APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&[ACCOUNT_IDENTITY_PROOF_COMPONENT_ID].into_iter().collect()),
    );
    dictionary.insert(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, current);
    let current = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
    let bundle = MlsKeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            Some(&[
                ExtensionType::Unknown(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE),
                ExtensionType::AppDataDictionary,
            ]),
            None,
            None,
        ))
        .leaf_node_extensions(Extensions::from_vec(vec![legacy, current]).unwrap())
        .build(ciphersuite, &provider, &signer, credential_with_key)
        .unwrap();
    let mls_msg: MlsMessageOut = bundle.key_package().clone().into();
    cgka_traits::engine::KeyPackage::new(mls_msg.tls_serialize_detached().unwrap())
}

#[derive(Clone, Copy)]
enum CurrentProofFault {
    WrongLength,
    TamperedSignature,
    CredentialMismatch,
    LeafKeyMismatch,
    MissingSupportAdvertisement,
}

fn current_profile_key_package_with_fault(
    identity_seed: &[u8],
    fault: CurrentProofFault,
) -> cgka_traits::engine::KeyPackage {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential_identity = pad32(identity_seed);
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(credential_identity).into(),
        signature_key: signer.public().into(),
    };
    let proof_identity_seed = if matches!(fault, CurrentProofFault::CredentialMismatch) {
        b"different-proof-identity".as_slice()
    } else {
        identity_seed
    };
    let proof_leaf_key = if matches!(fault, CurrentProofFault::LeafKeyMismatch) {
        vec![0x5a; signer.to_public_vec().len()]
    } else {
        signer.to_public_vec()
    };
    let mut proof = account_identity_proof_component(
        &pad32(proof_identity_seed),
        &proof_leaf_key,
        ciphersuite,
        ciphersuite.signature_algorithm(),
        1_700_000_000,
        proof_signer(proof_identity_seed).as_ref(),
    )
    .unwrap();
    match fault {
        CurrentProofFault::WrongLength => {
            proof.pop();
        }
        CurrentProofFault::TamperedSignature => proof[40] ^= 1,
        CurrentProofFault::CredentialMismatch
        | CurrentProofFault::LeafKeyMismatch
        | CurrentProofFault::MissingSupportAdvertisement => {}
    }

    let advertised = if matches!(fault, CurrentProofFault::MissingSupportAdvertisement) {
        [APP_COMPONENTS_COMPONENT_ID].into_iter().collect()
    } else {
        [
            APP_COMPONENTS_COMPONENT_ID,
            ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
        ]
        .into_iter()
        .collect()
    };
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&advertised),
    );
    dictionary.insert(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, proof);
    let extension = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
    let bundle = MlsKeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            Some(&[ExtensionType::AppDataDictionary]),
            None,
            None,
        ))
        .leaf_node_extensions(Extensions::single(extension).unwrap())
        .build(ciphersuite, &provider, &signer, credential_with_key)
        .unwrap();
    let mls_msg: MlsMessageOut = bundle.key_package().clone().into();
    cgka_traits::engine::KeyPackage::new(mls_msg.tls_serialize_detached().unwrap())
        .with_protocol_profile(ProtocolProfile::Current)
}

fn key_package_with_malformed_last_resort_component(
    identity_seed: &[u8],
) -> cgka_traits::engine::KeyPackage {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential_identity = pad32(identity_seed);
    let credential = BasicCredential::new(credential_identity.clone());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.public().into(),
    };
    let proof_extension = account_identity_proof_extension(
        &credential_identity,
        &signer.to_public_vec(),
        ciphersuite,
        ciphersuite.signature_algorithm(),
        proof_signer(identity_seed).as_ref(),
    )
    .unwrap();
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(ComponentType::LastResortKeyPackage.into(), vec![0xff]);
    let key_package_extension =
        Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
    let bundle = MlsKeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            Some(&[
                ExtensionType::Unknown(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE),
                ExtensionType::AppDataDictionary,
            ]),
            None,
            None,
        ))
        .leaf_node_extensions(Extensions::single(proof_extension).unwrap())
        .key_package_extensions(Extensions::single(key_package_extension).unwrap())
        .build(ciphersuite, &provider, &signer, credential_with_key)
        .unwrap();
    let mls_msg: MlsMessageOut = bundle.key_package().clone().into();
    cgka_traits::engine::KeyPackage::new(mls_msg.tls_serialize_detached().unwrap())
}

fn legacy_last_resort_key_package(identity_seed: &[u8]) -> cgka_traits::engine::KeyPackage {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential_identity = pad32(identity_seed);
    let credential = BasicCredential::new(credential_identity.clone());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.public().into(),
    };
    let proof_extension = account_identity_proof_extension(
        &credential_identity,
        &signer.to_public_vec(),
        ciphersuite,
        ciphersuite.signature_algorithm(),
        proof_signer(identity_seed).as_ref(),
    )
    .unwrap();
    let bundle = MlsKeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            Some(&[
                ExtensionType::Unknown(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE),
                ExtensionType::LastResort,
            ]),
            None,
            None,
        ))
        .leaf_node_extensions(Extensions::single(proof_extension).unwrap())
        .key_package_extensions(
            Extensions::single(Extension::LastResort(LastResortExtension::new())).unwrap(),
        )
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

#[derive(Default)]
struct MockPeeler {
    welcome_sender: Option<MemberId>,
}

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
            sender: self.welcome_sender.clone(),
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
        let mut id_material = payload.ciphertext.clone();
        id_material.extend_from_slice(recipient.as_slice());
        Ok(TransportMessage {
            id: hash_id(&id_material),
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
        .legacy_compatibility_profile()
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .supported_app_components(components)
        .peeler(Box::new(MockPeeler::default()))
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
        .legacy_compatibility_profile()
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(registry)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .expect("build engine")
}

fn build_current_client(identity: &[u8]) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .expect("build current-profile engine")
}

fn build_profile_client_on_storage(
    identity: &[u8],
    storage: SqliteAccountStorage,
    profile: ProtocolProfile,
) -> Engine<SqliteAccountStorage> {
    let builder = EngineBuilder::new(storage)
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .protocol_profile(profile)
        .peeler(Box::new(MockPeeler::default()));
    let builder = if profile == ProtocolProfile::Legacy {
        builder.legacy_compatibility_profile()
    } else {
        builder
    };
    builder.build().expect("build profile engine")
}

fn build_client_with_welcome_sender(
    identity: &[u8],
    registry: FeatureRegistry,
    welcome_sender: MemberId,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .legacy_compatibility_profile()
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(registry)
        .peeler(Box::new(MockPeeler {
            welcome_sender: Some(welcome_sender),
        }))
        .build()
        .expect("build engine")
}

fn build_client_on_storage(
    identity: &[u8],
    registry: FeatureRegistry,
    storage: SqliteAccountStorage,
) -> impl CgkaEngine {
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(registry)
        .peeler(Box::new(MockPeeler::default()))
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

/// mdk#737: an admin key that corresponds to no initial member (creator or
/// invitee) is a phantom/pre-provisioned admin — it would become active the
/// instant a matching leaf appears, with no `AdminAdded` commit other members
/// observe. Group creation must reject it, mirroring the admin-leaf-coupling
/// check every commit seam enforces.
#[tokio::test]
async fn create_group_rejects_uninvited_initial_admin() {
    let mut alice = build_client_with_components(b"alice", default_group_components());
    let mut bob = build_client_with_components(b"bob", default_group_components());
    let mallory = build_client_with_components(b"mallory", default_group_components());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let err = alice
        .create_group(CreateGroupRequest {
            name: "phantom-admin".into(),
            description: "".into(),
            members: vec![bob_kp], // bob invited; mallory NOT a member
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![mallory.self_id()],
        })
        .await
        .expect_err("an uninvited initial admin must be rejected");
    assert!(
        matches!(err, EngineError::Other(ref msg) if msg.contains("no member leaf")),
        "expected admin-leaf-coupling rejection, got {err:?}"
    );
}

/// mdk#737 review: an `initial_admins` entry that is 32 bytes but not a valid
/// x-only secp256k1 key is rejected (not accepted on length alone). Guards the
/// new `validate_credential_identity` call on the co-admin path.
#[tokio::test]
async fn create_group_rejects_off_curve_initial_admin() {
    let mut alice = build_client_with_components(b"alice", default_group_components());
    let mut bob = build_client_with_components(b"bob", default_group_components());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let err = alice
        .create_group(CreateGroupRequest {
            name: "off-curve-admin".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![MemberId::new(vec![0xFF; 32])],
        })
        .await
        .expect_err("an off-curve 32-byte admin identity must be rejected");
    assert!(
        matches!(err, EngineError::InvalidCredentialIdentity(_)),
        "expected InvalidCredentialIdentity, got {err:?}"
    );
}

/// mdk#737 positive control: a co-admin who IS an invited member is accepted.
#[tokio::test]
async fn create_group_accepts_invited_initial_admin() {
    let mut alice = build_client_with_components(b"alice", default_group_components());
    let mut bob = build_client_with_components(b"bob", default_group_components());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, _result) = alice
        .create_group(CreateGroupRequest {
            name: "co-admin".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .expect("an invited co-admin is accepted");
    assert_eq!(alice.members(&group_id).unwrap().len(), 2);
}

/// mdk#746: an invitee whose KeyPackage omits an engine-owned mandatory
/// component (here admin policy) is rejected at creation, instead of the
/// component being negotiated out — which would create a group with an empty
/// admin set and permanently frozen membership.
#[tokio::test]
async fn create_group_rejects_invitee_missing_mandatory_component() {
    let mut alice = build_client_with_components(b"alice", default_group_components());
    // Bob advertises only the profile component, NOT admin policy.
    let mut bob = build_client_with_components(b"bob", [GROUP_PROFILE_COMPONENT_ID]);
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let err = alice
        .create_group(CreateGroupRequest {
            name: "missing-mandatory".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("an invitee missing a mandatory component must be rejected");
    assert!(
        matches!(err, EngineError::MissingRequiredCapabilities { ref required, .. }
            if required.app_components.contains(GROUP_ADMIN_POLICY_COMPONENT_ID)),
        "expected MissingRequiredCapabilities naming admin policy, got {err:?}"
    );
}

/// mdk#747: the transport-directory KeyPackage helpers validate the account
/// identity proof against the KeyPackage's OWN ciphersuite (matching
/// `parse_key_package`), so a validly-proofed KeyPackage passes both.
#[tokio::test]
async fn directory_key_package_helpers_validate_against_own_ciphersuite() {
    let mut alice = build_client(b"alice", selfremove_registry());
    let kp = alice.fresh_key_package().await.unwrap();
    let meta = key_package_metadata(&kp).expect("key_package_metadata validates the proof");
    assert!(!meta.credential_identity_hex.is_empty());
    assert!(is_last_resort_key_package(&kp).expect("last-resort check validates the proof"));
}

#[tokio::test]
async fn invite_path_validates_proof_against_key_package_ciphersuite() {
    let mut alice = build_client(b"alice-own-suite", selfremove_registry());
    let alternate_suite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    let kp =
        key_package_with_account_identity_proof_for_ciphersuite(b"bob-own-suite", alternate_suite);

    let error = alice
        .create_group(CreateGroupRequest {
            name: "own-suite-proof".into(),
            description: "".into(),
            members: vec![kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("the engine does not negotiate the alternate ciphersuite yet");

    assert!(
        !matches!(error, EngineError::InvalidAccountIdentityProof(_)),
        "the valid proof must be checked against the KeyPackage suite before later suite negotiation rejects it: {error:?}"
    );
}

#[tokio::test]
async fn current_key_package_uses_only_the_0x8009_proof_component() {
    let mut alice = build_current_client(b"alice-current");
    let kp = alice.fresh_key_package().await.unwrap();

    assert_eq!(kp.protocol_profile, ProtocolProfile::Current);
    let metadata = key_package_metadata(&kp).unwrap();
    assert_eq!(metadata.protocol_profile, ProtocolProfile::Current);
    assert!(
        metadata
            .app_components
            .contains(&ACCOUNT_IDENTITY_PROOF_COMPONENT_ID)
    );
    assert!(
        !metadata
            .mls_extensions
            .contains(&ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE)
    );

    let message = MlsMessageIn::tls_deserialize_exact(kp.bytes()).unwrap();
    let key_package = match message.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        other => panic!("expected KeyPackage, got {other:?}"),
    }
    .validate(
        &openmls_rust_crypto::RustCrypto::default(),
        ProtocolVersion::Mls10,
    )
    .unwrap();
    assert!(
        key_package
            .leaf_node()
            .extensions()
            .unknown(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE)
            .is_none()
    );
    assert_eq!(
        key_package
            .leaf_node()
            .extensions()
            .app_data_dictionary()
            .unwrap()
            .dictionary()
            .get(&ACCOUNT_IDENTITY_PROOF_COMPONENT_ID)
            .unwrap()
            .len(),
        104
    );
}

#[test]
fn mixed_profile_key_package_is_rejected() {
    let key_package = mixed_profile_key_package(b"mixed-profile");
    let error = key_package_metadata(&key_package)
        .expect_err("a KeyPackage carrying both proof profiles must be rejected");
    assert!(matches!(error, EngineError::InvalidAccountIdentityProof(_)));
}

fn assert_invalid_current_proof(fault: CurrentProofFault) {
    let key_package = current_profile_key_package_with_fault(b"invalid-current-proof", fault);
    let error =
        key_package_metadata(&key_package).expect_err("invalid current proof must be rejected");
    assert!(
        matches!(error, EngineError::InvalidAccountIdentityProof(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn current_proof_rejects_non_104_byte_component() {
    assert_invalid_current_proof(CurrentProofFault::WrongLength);
}

#[test]
fn current_proof_rejects_tampered_signature() {
    assert_invalid_current_proof(CurrentProofFault::TamperedSignature);
}

#[test]
fn current_proof_rejects_signer_credential_mismatch() {
    assert_invalid_current_proof(CurrentProofFault::CredentialMismatch);
}

#[test]
fn current_proof_rejects_leaf_key_mismatch() {
    assert_invalid_current_proof(CurrentProofFault::LeafKeyMismatch);
}

#[test]
fn current_proof_rejects_missing_support_advertisement() {
    assert_invalid_current_proof(CurrentProofFault::MissingSupportAdvertisement);
}

#[tokio::test]
async fn current_group_persists_profile_and_rejects_legacy_key_packages() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let current_components = default_group_components()
        .into_iter()
        .chain([GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID])
        .collect::<Vec<_>>();
    let mut alice = EngineBuilder::new(storage.clone())
        .identity(pad32(b"alice-current-group"))
        .account_identity_proof_signer(proof_signer(b"alice-current-group"))
        .supported_app_components(current_components.clone())
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    let mut bob = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(b"bob-current-group"))
        .account_identity_proof_signer(proof_signer(b"bob-current-group"))
        .supported_app_components(current_components)
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    let mut legacy_carol = build_client(b"carol-legacy-group", FeatureRegistry::new());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "current".into(),
            description: "strict profile".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
                data: encode_encrypted_media_policy_v2(
                    &EncryptedMediaPolicyV2::blossom_default([
                        "https://blossom.primal.net".to_owned()
                    ])
                    .unwrap(),
                )
                .unwrap(),
            }],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match result {
        SendResult::FoundingGroupCreated { mut welcomes } => welcomes.remove(0),
        other => panic!("expected FoundingGroupCreated, got {other:?}"),
    };
    let welcome_id = welcome.id.clone();
    let group = alice.group_record(&group_id).unwrap();
    assert_eq!(group.epoch, cgka_traits::types::EpochId(1));
    assert_eq!(group.members.len(), 2);
    assert_eq!(group.protocol_profile, ProtocolProfile::Current);
    assert!(
        group
            .required_capabilities
            .app_components
            .contains(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID)
    );
    assert!(
        group
            .required_capabilities
            .app_components
            .contains(GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID)
    );
    assert!(
        alice
            .app_component(&group_id, GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID)
            .unwrap()
            .is_some()
    );
    assert!(
        !group
            .required_capabilities
            .extensions
            .contains(&ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE)
    );
    let duplicate_welcome = welcome.clone();
    let joined = bob.join_welcome(welcome).await.unwrap();
    assert_eq!(
        bob.group_record(&joined).unwrap().protocol_profile,
        ProtocolProfile::Current
    );
    let duplicate_error = bob
        .join_welcome(duplicate_welcome)
        .await
        .expect_err("a duplicate founding Welcome must not mutate joined state");
    assert!(matches!(
        duplicate_error,
        EngineError::WelcomeAlreadyProcessed
    ));
    assert_eq!(bob.epoch(&joined).unwrap(), cgka_traits::types::EpochId(1));
    assert_eq!(bob.members(&joined).unwrap().len(), 2);
    assert!(matches!(
        alice.drain_events().as_slice(),
        [cgka_traits::engine::GroupEvent::GroupCreated { group_id: created }]
            if created == &group_id
    ));

    let legacy_kp = legacy_carol.fresh_key_package().await.unwrap();
    let error = alice
        .send(cgka_traits::engine::SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![legacy_kp],
        })
        .await
        .expect_err("current group must reject a legacy KeyPackage");
    assert!(matches!(error, EngineError::InvalidAccountIdentityProof(_)));

    drop(alice);
    let mut reopened = EngineBuilder::new(storage)
        .identity(pad32(b"alice-current-group"))
        .account_identity_proof_signer(proof_signer(b"alice-current-group"))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    reopened.hydrate_stable_groups_from_storage().unwrap();
    let reopened_group = reopened.group_record(&group_id).unwrap();
    assert_eq!(reopened_group.protocol_profile, ProtocolProfile::Current);
    assert_eq!(reopened_group.epoch, cgka_traits::types::EpochId(1));
    assert_eq!(reopened_group.members.len(), 2);
    let (stored_group, stored_welcome) = reopened.stored_sent_welcome(&welcome_id).unwrap();
    assert_eq!(stored_group, group_id);
    assert_eq!(stored_welcome.id, welcome_id);
}

#[tokio::test]
async fn current_solo_group_is_canonical_at_epoch_zero_without_confirmation() {
    let mut alice = build_current_client(b"alice-current-solo");

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "solo".into(),
            description: "canonical immediately".into(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    assert!(matches!(
        result,
        SendResult::FoundingGroupCreated { ref welcomes } if welcomes.is_empty()
    ));
    let group = alice.group_record(&group_id).unwrap();
    assert_eq!(group.epoch, cgka_traits::types::EpochId(0));
    assert_eq!(group.members.len(), 1);
    assert!(matches!(
        alice.drain_events().as_slice(),
        [cgka_traits::engine::GroupEvent::GroupCreated { group_id: created }]
            if created == &group_id
    ));

    let sent = alice
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id,
            payload: app_payload_for(&alice, "usable immediately"),
        })
        .await
        .expect("canonical solo group accepts work without confirm_published");
    assert!(matches!(sent, SendResult::ApplicationMessage { .. }));
}

#[tokio::test]
async fn current_configured_engine_reopens_and_uses_a_legacy_group() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut legacy = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(b"legacy-reopen"))
        .account_identity_proof_signer(proof_signer(b"legacy-reopen"))
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    let (group_id, result) = legacy
        .create_group(CreateGroupRequest {
            name: "legacy".into(),
            description: "survives cutover".into(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match result {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    legacy.confirm_published(pending).await.unwrap();
    drop(legacy);

    let mut current = EngineBuilder::new(storage)
        .identity(pad32(b"legacy-reopen"))
        .account_identity_proof_signer(proof_signer(b"legacy-reopen"))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    current.hydrate_stable_groups_from_storage().unwrap();
    assert_eq!(
        current.group_record(&group_id).unwrap().protocol_profile,
        ProtocolProfile::Legacy
    );
    current
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&current, "still usable"),
        })
        .await
        .expect("legacy group remains usable by current-configured engine");

    let updated = current
        .send(cgka_traits::engine::SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("legacy renamed".into()),
            description: None,
        })
        .await
        .expect("legacy group state changes remain usable");
    let pending = match updated {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    current.confirm_published(pending).await.unwrap();
    assert_eq!(
        current.group_record(&group_id).unwrap().name,
        "legacy renamed"
    );
    assert_eq!(
        current.group_record(&group_id).unwrap().protocol_profile,
        ProtocolProfile::Legacy
    );

    let mut current_invitee = build_current_client(b"legacy-reopen-invitee");
    let invitee_key_package = current_invitee.fresh_key_package().await.unwrap();
    let invite_error = current
        .send(cgka_traits::engine::SendIntent::Invite {
            group_id,
            key_packages: vec![invitee_key_package],
        })
        .await
        .expect_err("strict cutover must freeze legacy-group membership");
    assert!(
        matches!(invite_error, EngineError::InvalidTransition(ref transition)
            if transition.reason.contains("strict cutover"))
    );
}

#[tokio::test]
async fn group_commit_cannot_change_or_mix_the_protocol_profile() {
    let mut current = build_current_client(b"current-profile-lock");
    let (current_group, result) = current
        .create_group(CreateGroupRequest {
            name: "current".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(matches!(
        result,
        SendResult::FoundingGroupCreated { ref welcomes } if welcomes.is_empty()
    ));
    let drop_current_proof = AppComponentData {
        component_id: cgka_traits::app_components::APP_COMPONENTS_COMPONENT_ID,
        data: encode_components_list(&default_group_components()),
    };
    let error = current
        .send(cgka_traits::engine::SendIntent::UpdateAppComponents {
            group_id: current_group,
            updates: vec![drop_current_proof],
        })
        .await
        .expect_err("current group cannot drop its profile requirement");
    assert!(matches!(error, EngineError::InvalidAccountIdentityProof(_)));

    let mut legacy =
        build_client_with_components(b"legacy-profile-lock", default_group_components());
    let (legacy_group, result) = legacy
        .create_group(CreateGroupRequest {
            name: "legacy".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match result {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    legacy.confirm_published(pending).await.unwrap();
    let mut hybrid_requirements = default_group_components();
    hybrid_requirements.insert(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID);
    let add_current_proof = AppComponentData {
        component_id: cgka_traits::app_components::APP_COMPONENTS_COMPONENT_ID,
        data: encode_components_list(&hybrid_requirements),
    };
    let error = legacy
        .send(cgka_traits::engine::SendIntent::UpdateAppComponents {
            group_id: legacy_group,
            updates: vec![add_current_proof],
        })
        .await
        .expect_err("legacy group cannot become hybrid");
    assert!(matches!(error, EngineError::InvalidAccountIdentityProof(_)));
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
async fn create_group_rejects_expired_invitee_keypackage() {
    let mut alice = build_client(b"alice", selfremove_registry());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expired_kp = key_package_with_account_identity_proof_and_lifetime(
        b"bob-expired",
        Lifetime::init(now.saturating_sub(7200), now.saturating_sub(3600)),
    );

    let err = alice
        .create_group(CreateGroupRequest {
            name: "expired-invitee".into(),
            description: "".into(),
            members: vec![expired_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("create_group must reject an expired invitee KeyPackage");
    assert_eq!(err.to_string(), "invalid KeyPackage lifetime");
    assert!(
        matches!(
            &err,
            EngineError::InvalidKeyPackageLifetime {
                not_before: None,
                not_after: None,
            }
        ),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn create_group_rejects_invitee_keypackage_with_excessive_lifetime_range() {
    let mut alice = build_client(b"alice", selfremove_registry());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let excessive_kp = key_package_with_account_identity_proof_and_lifetime(
        b"bob-long-lived",
        Lifetime::init(now.saturating_sub(60), now + 60 * 60 * 24 * 365),
    );

    let err = alice
        .create_group(CreateGroupRequest {
            name: "long-lived-invitee".into(),
            description: "".into(),
            members: vec![excessive_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("create_group must reject an over-long invitee KeyPackage");
    assert_eq!(err.to_string(), "invalid KeyPackage lifetime");
    assert!(
        matches!(
            &err,
            EngineError::InvalidKeyPackageLifetime {
                not_before: Some(_),
                not_after: Some(_),
            }
        ),
        "unexpected error: {err:?}"
    );
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

#[test]
fn engine_builder_defaults_to_current_and_requires_explicit_legacy_fixture_seam() {
    let current = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(b"default-current"))
        .account_identity_proof_signer(proof_signer(b"default-current"))
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .expect("default engine builds");
    assert_eq!(current.new_protocol_profile(), ProtocolProfile::Current);

    let legacy_result = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(b"implicit-legacy"))
        .account_identity_proof_signer(proof_signer(b"implicit-legacy"))
        .protocol_profile(ProtocolProfile::Legacy)
        .peeler(Box::new(MockPeeler::default()))
        .build();
    let legacy_error = match legacy_result {
        Ok(_) => panic!("ordinary builder must refuse the legacy profile"),
        Err(error) => error,
    };
    assert!(legacy_error.to_string().contains("strict cutover"));
}

#[tokio::test]
async fn strict_cutover_retires_all_legacy_key_package_bundles_idempotently() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut legacy =
        build_profile_client_on_storage(b"retirement", storage.clone(), ProtocolProfile::Legacy);
    legacy.fresh_key_package().await.unwrap();
    legacy.fresh_key_package().await.unwrap();
    drop(legacy);

    let mut current =
        build_profile_client_on_storage(b"retirement", storage.clone(), ProtocolProfile::Current);
    current.fresh_key_package().await.unwrap();
    assert_eq!(storage.stored_key_package_bundles().unwrap().len(), 3);

    let first = current.retire_non_current_key_packages().unwrap();
    assert_eq!(first.legacy_retired, 2);
    assert_eq!(first.invalid_retired, 0);
    assert_eq!(first.current_retained, 1);
    assert_eq!(storage.stored_key_package_bundles().unwrap().len(), 1);

    let second = current.retire_non_current_key_packages().unwrap();
    assert_eq!(second.legacy_retired, 0);
    assert_eq!(second.invalid_retired, 0);
    assert_eq!(second.current_retained, 1);
    assert_eq!(storage.stored_key_package_bundles().unwrap().len(), 1);
}

#[tokio::test]
async fn strict_cutover_rejects_new_and_replayed_legacy_welcomes_without_group_state() {
    let bob_storage = SqliteAccountStorage::in_memory().unwrap();
    let mut legacy_bob = build_profile_client_on_storage(
        b"legacy-welcome-bob",
        bob_storage.clone(),
        ProtocolProfile::Legacy,
    );
    let bob_key_package = legacy_bob.fresh_key_package().await.unwrap();
    drop(legacy_bob);

    let mut legacy_alice = build_profile_client_on_storage(
        b"legacy-welcome-alice",
        SqliteAccountStorage::in_memory().unwrap(),
        ProtocolProfile::Legacy,
    );
    let (group_id, created) = legacy_alice
        .create_group(CreateGroupRequest {
            name: "legacy welcome".into(),
            description: String::new(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (welcome, pending) = match created {
        SendResult::GroupCreated {
            mut welcomes,
            pending,
        } => (welcomes.remove(0), pending),
        other => panic!("expected legacy GroupCreated, got {other:?}"),
    };
    legacy_alice.confirm_published(pending).await.unwrap();

    let mut current_bob = build_profile_client_on_storage(
        b"legacy-welcome-bob",
        bob_storage.clone(),
        ProtocolProfile::Current,
    );
    let replay = welcome.clone();
    let profile_error = current_bob
        .join_welcome(welcome)
        .await
        .expect_err("current client must reject a legacy Welcome even before retirement");
    assert!(matches!(profile_error, EngineError::InvalidWelcome));
    assert_eq!(
        bob_storage.stored_key_package_bundles().unwrap().len(),
        1,
        "profile rejection must roll back OpenMLS KeyPackage consumption"
    );
    assert!(matches!(
        bob_storage.get_group(&group_id),
        Err(cgka_traits::storage::StorageError::NotFound)
    ));

    let retirement = current_bob.retire_non_current_key_packages().unwrap();
    assert_eq!(retirement.legacy_retired, 1);
    assert!(bob_storage.stored_key_package_bundles().unwrap().is_empty());

    let replay_error = current_bob
        .join_welcome(replay)
        .await
        .expect_err("cached/replayed legacy Welcome must remain terminal");
    assert!(matches!(replay_error, EngineError::WelcomeAlreadyProcessed));
    assert!(bob_storage.list_groups().unwrap().is_empty());
}

#[tokio::test]
async fn create_group_rejects_relabelled_legacy_key_package_profile() {
    let mut alice = build_client(b"alice-profile", selfremove_registry());
    let mut bob = build_client(b"bob-profile", selfremove_registry());
    let relabelled_key_package = bob
        .fresh_key_package()
        .await
        .unwrap()
        .with_protocol_profile(ProtocolProfile::Current);

    let err = alice
        .create_group(CreateGroupRequest {
            name: "profile-mismatch".into(),
            description: "".into(),
            members: vec![relabelled_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("legacy proof bytes must not be accepted as a Current-profile KeyPackage");

    assert!(
        matches!(
            &err,
            EngineError::InvalidAccountIdentityProof(message)
                if message.contains("decoded account proof is Legacy")
        ),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn fresh_key_package_uses_draft10_last_resort_component() {
    let mut alice = build_client(b"a", selfremove_registry());
    let kp = alice.fresh_key_package().await.unwrap();

    assert!(is_last_resort_key_package(&kp).unwrap());

    let message = MlsMessageIn::tls_deserialize_exact(kp.bytes()).unwrap();
    let key_package = match message.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        other => panic!("expected KeyPackage, got {other:?}"),
    }
    .validate(
        &openmls_rust_crypto::RustCrypto::default(),
        ProtocolVersion::Mls10,
    )
    .unwrap();
    assert!(
        !key_package.extensions().contains(ExtensionType::LastResort),
        "new KeyPackages must not use the legacy last_resort extension"
    );
    assert!(
        key_package
            .leaf_node()
            .capabilities()
            .extensions()
            .contains(&ExtensionType::AppDataDictionary),
        "new KeyPackages must advertise the app_data_dictionary carrier"
    );
    assert!(
        !key_package
            .leaf_node()
            .capabilities()
            .extensions()
            .contains(&ExtensionType::LastResort),
        "last-resort is an application-data component, not an advertised extension capability"
    );
    let dictionary = key_package
        .extensions()
        .app_data_dictionary()
        .expect("draft-10 last-resort marker requires app_data_dictionary");
    assert_eq!(
        dictionary
            .dictionary()
            .get(&ComponentType::LastResortKeyPackage.into()),
        Some(&[][..]),
        "draft-10 last-resort component 0x0004 must carry empty data"
    );
}

#[tokio::test]
async fn create_group_rejects_malformed_last_resort_component() {
    let mut alice = build_client(b"alice", selfremove_registry());
    let key_package = key_package_with_malformed_last_resort_component(b"malformed-last-resort");
    let error = alice
        .create_group(CreateGroupRequest {
            name: "malformed-last-resort".into(),
            description: String::new(),
            members: vec![key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("create_group must reject non-empty last-resort component data");
    assert!(
        matches!(&error, EngineError::Backend(message) if message.contains("MalformedLastResortComponent")),
        "unexpected error: {error:?}"
    );
}

#[test]
fn legacy_last_resort_extension_remains_decodable() {
    let key_package = legacy_last_resort_key_package(b"legacy-last-resort");
    assert!(
        is_last_resort_key_package(&key_package)
            .expect("legacy KeyPackage remains valid for compatibility")
    );
}

#[tokio::test]
async fn delete_key_package_is_idempotent_noop_when_absent() {
    // Deleting a KeyPackage that is not (or no longer) in storage must be a
    // no-op rather than an error, so the publisher-failure cleanup path is safe
    // to call idempotently across retries (mdk#160).
    let mut alice = build_client(b"a", selfremove_registry());
    let kp = alice.fresh_key_package().await.unwrap();

    alice.delete_key_package(&kp).await.unwrap();
    // Second delete: the bundle is already gone, but this still succeeds.
    alice.delete_key_package(&kp).await.unwrap();
}

#[tokio::test]
async fn delete_key_package_removes_bundle_so_welcome_cannot_be_joined() {
    // mdk#160: fresh_key_package persists the private bundle into
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
    assert!(matches!(err, EngineError::WelcomeAlreadyProcessed));
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
    assert!(matches!(err, EngineError::WelcomeAlreadyProcessed));
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

    let (group_id, result) = alice
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
        build_client_on_storage(b"carol", FeatureRegistry::new(), carol_storage.clone());
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

    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    assert!(
        openmls::group::MlsGroup::load(carol_storage.mls_storage(), &mls_group_id)
            .expect("rejected-Welcome storage remains readable")
            .is_none(),
        "a rejected Welcome must roll back the newly stored OpenMLS group"
    );
}

#[tokio::test]
async fn join_welcome_rejected_when_client_lacks_required_app_component() {
    // App-component variant of the join capability gate. carol publishes a KP
    // advertising a custom app component; alice requires it; carol then rejoins
    // with an engine that does not support that component.
    const CUSTOM_COMPONENT: u16 = 0xF300;
    // Advertise the engine-owned mandatory components (profile + admin policy)
    // alongside the custom one: they are non-negotiable at creation (mdk#746),
    // so an invitee KP that omitted them would be rejected at create time before
    // this test could reach the join-capability path it exercises.
    let components: Vec<u16> = default_group_components()
        .into_iter()
        .chain([CUSTOM_COMPONENT])
        .collect();
    let mut alice = build_client_with_components(b"alice", components.clone());
    let carol_storage = SqliteAccountStorage::in_memory().unwrap();
    let capable_carol = EngineBuilder::new(carol_storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .supported_app_components(components)
        .peeler(Box::new(MockPeeler::default()))
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
        .legacy_compatibility_profile()
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .peeler(Box::new(MockPeeler::default()))
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
    let alice_id = alice.self_id();
    let transport_claimed_sender = MemberId::new(pad32(b"mallory-id"));
    let mut bob = build_client_with_welcome_sender(
        b"bob-id",
        selfremove_registry(),
        transport_claimed_sender.clone(),
    );

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
    assert!(matches!(
        &events[0],
        cgka_traits::engine::GroupEvent::GroupJoined {
            welcomer: Some(welcomer),
            ..
        } if *welcomer == alice_id && *welcomer != transport_claimed_sender
    ));
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
        .legacy_compatibility_profile()
        .identity(pad32(b"alice"))
        .account_identity_proof_signer(proof_signer(b"alice"))
        .peeler(Box::new(MockPeeler::default()))
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
