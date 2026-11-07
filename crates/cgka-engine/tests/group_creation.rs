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
use cgka_engine::{Engine, EngineBuilder, ManualConvergenceClock};
use cgka_traits::EngineError;
use cgka_traits::app_components::{
    ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, APP_COMPONENTS_COMPONENT_ID, AppComponentData,
    EncryptedMediaPolicyV2, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
    GROUP_LIFECYCLE_COMPONENT_ID, GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID,
    GroupLifecycleV1, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, decode_group_lifecycle_v1,
    default_group_components, encode_components_list, encode_encrypted_media_policy_v2,
    encode_nostr_routing_v1,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    ConvergencePassStorage, GroupStorage, KeyPackageBundleStorage, MessageStorage, StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{GroupId, MemberId, MessageId};
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
use std::sync::Arc;
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};
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
        if let Ok(sk) = SigningKey::from_slice(&material) {
            return sk.verifying_key().to_bytes().to_vec();
        }
        counter += 1;
    }
}

#[derive(Default)]
struct MockPeeler {
    welcome_sender: Option<MemberId>,
    collide_welcome_ids: bool,
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
                created_at: None,
                bytes: msg.payload.clone(),
                key_package_event_id: None,
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
            id: if self.collide_welcome_ids {
                MessageId::new(b"colliding-founding-welcome-id".to_vec())
            } else {
                hash_id(&id_material)
            },
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

struct BlockingWelcomePeeler {
    inner: MockPeeler,
    started: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl TransportPeeler for BlockingWelcomePeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        self.inner.peel_group_message(msg, ctx).await
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        self.inner.peel_welcome(msg).await
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        self.inner.wrap_group_message(payload, ctx).await
    }

    async fn wrap_welcome(
        &self,
        _payload: &EncryptedPayload,
        _recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        self.started.notify_one();
        std::future::pending().await
    }
}

fn build_client_with_components(
    identity: &[u8],
    components: impl IntoIterator<Item = u16>,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
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
    EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
        .legacy_compatibility_profile()
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(registry)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .expect("build engine")
}

fn build_current_client(identity: &[u8]) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
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
    EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
        .legacy_compatibility_profile()
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(registry)
        .peeler(Box::new(MockPeeler {
            welcome_sender: Some(welcome_sender),
            collide_welcome_ids: false,
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
    // The refusal names the phantom admin rather than landing in
    // `EngineError::Other`, the unclassified bucket that gave this policy
    // refusal a generic fault's shape at every surface downstream.
    match err {
        EngineError::UnknownMember { member, .. } => {
            assert_eq!(member, mallory.self_id());
        }
        other => panic!("expected UnknownMember naming mallory, got {other:?}"),
    }
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
    let mut expected_admins = vec![
        <[u8; 32]>::try_from(alice.self_id().as_slice()).unwrap(),
        <[u8; 32]>::try_from(bob.self_id().as_slice()).unwrap(),
    ];
    expected_admins.sort();
    assert_eq!(alice.admin_pubkeys(&group_id).unwrap(), expected_admins);
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
    let alternate = key_package_with_account_identity_proof_for_ciphersuite(
        b"directory-own-suite",
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    );
    for (package, suite, identity, last_resort) in [
        (kp, 0x0001, alice.self_id().as_slice().to_vec(), true),
        (alternate, 0x0003, pad32(b"directory-own-suite"), false),
    ] {
        let meta = key_package_metadata(&package).expect("metadata validates the package's proof");
        assert_eq!(meta.ciphersuite, suite);
        assert_eq!(meta.credential_identity_hex, hex::encode(identity));
        assert_eq!(
            is_last_resort_key_package(&package)
                .expect("last-resort validates the package's proof"),
            last_resort
        );
    }
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
        .expect_err("the fixture does not advertise all required capabilities");

    assert!(
        matches!(
            &error,
            EngineError::MissingRequiredCapabilities { required, had }
                if required.proposals.contains(&10) && !had.proposals.contains(&10)
        ),
        "the valid alternate-suite proof reaches capability admission: {error:?}"
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
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
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
    let mut bob = EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
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
    let stored = storage.get_message(&welcome_id).unwrap();
    assert!(
        StoredMessagePayload::decode(&stored.payload)
            .unwrap()
            .as_outbound_welcome()
            .is_some(),
        "new outbound Welcomes must carry an explicit recoverable-delivery tag"
    );
    assert_eq!(alice.outstanding_sent_welcomes().unwrap().len(), 1);
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
    let mut duplicate_welcome = welcome.clone();
    duplicate_welcome.id = MessageId::new(b"distinct-transport-id-same-welcome".to_vec());
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
            initial_admins: vec![],
        })
        .await
        .expect_err("current group must reject a legacy KeyPackage");
    assert!(matches!(error, EngineError::InvalidAccountIdentityProof(_)));

    drop(alice);

    // Upgrade compatibility: historical versions stored outbound Welcomes as
    // raw `Sent` rows but did not persist their acknowledgement completion.
    // A known id remains re-deliverable, while cold-restart discovery must not
    // resurrect such an old row after it may already have reached its recipient.
    let mut historical = storage.get_message(&welcome_id).unwrap();
    let message = StoredMessagePayload::decode(&historical.payload)
        .unwrap()
        .into_message()
        .unwrap();
    historical.payload = StoredMessagePayload::raw_transport(message)
        .encode()
        .unwrap();
    storage.put_message(&historical).unwrap();

    let mut reopened = EngineBuilder::new(storage)
        .identity(pad32(b"alice-current-group"))
        .account_identity_proof_signer(proof_signer(b"alice-current-group"))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    reopened.hydrate_all_stored_groups().unwrap();
    let reopened_group = reopened.group_record(&group_id).unwrap();
    assert_eq!(reopened_group.protocol_profile, ProtocolProfile::Current);
    assert_eq!(reopened_group.epoch, cgka_traits::types::EpochId(1));
    assert_eq!(reopened_group.members.len(), 2);
    assert!(
        reopened.outstanding_sent_welcomes().unwrap().is_empty(),
        "historical raw Sent Welcomes have unknown ack state and must not be rediscovered"
    );
    let (stored_group, stored_welcome) = reopened.stored_sent_welcome(&welcome_id).unwrap();
    assert_eq!(stored_group, group_id);
    assert_eq!(stored_welcome.id, welcome_id);
}

#[tokio::test]
async fn welcome_scan_filters_rows() {
    use rusqlite::trace::{TraceEvent, TraceEventCodes};
    use std::cell::Cell;

    thread_local! {
        static MESSAGE_READS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    }

    fn measure<T>(storage: &SqliteAccountStorage, read: impl FnOnce() -> T) -> (T, (usize, usize)) {
        MESSAGE_READS.set((0, 0));
        storage
            .trace_queries_for_test(
                TraceEventCodes::SQLITE_TRACE_STMT | TraceEventCodes::SQLITE_TRACE_ROW,
                Some(|event| {
                    let (statement, is_row) = match event {
                        TraceEvent::Stmt(statement, _) => (statement, false),
                        TraceEvent::Row(statement) => (statement, true),
                        _ => return,
                    };
                    let sql = statement.sql();
                    // Count executed message SELECTs, not group-liveness reads or
                    // the nested SELECT inside a state-filtered statement.
                    if sql.starts_with("SELECT") && sql.contains("FROM cgka_messages") {
                        let (queries, rows) = MESSAGE_READS.get();
                        MESSAGE_READS
                            .set((queries + usize::from(!is_row), rows + usize::from(is_row)));
                    }
                }),
            )
            .unwrap();
        let result = read();
        storage
            .trace_queries_for_test(TraceEventCodes::empty(), None)
            .unwrap();
        (result, MESSAGE_READS.get())
    }

    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut alice = build_profile_client_on_storage(
        b"alice-welcome-scan",
        storage.clone(),
        ProtocolProfile::Current,
    );
    let mut bob = build_current_client(b"bob-welcome-scan");
    let mut carol = build_current_client(b"carol-welcome-scan");
    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "welcome scan history".into(),
            description: String::new(),
            members: vec![
                bob.fresh_key_package().await.unwrap(),
                carol.fresh_key_package().await.unwrap(),
            ],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcomes = match result {
        SendResult::FoundingGroupCreated { welcomes } => welcomes,
        other => panic!("expected founding Welcomes, got {other:?}"),
    };
    assert_eq!(welcomes.len(), 2);
    // An empty live group still needs one message scan in the combined index.
    alice
        .create_group(CreateGroupRequest {
            name: "empty welcome scan".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let application = match alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, "retained application history"),
            expected_epoch: None,
        })
        .await
        .unwrap()
    {
        SendResult::ApplicationMessage { msg, .. } => msg,
        other => panic!("expected application message, got {other:?}"),
    };
    let mut record = storage.get_message(&application.id).unwrap();
    // Sending also persists a raw content-dedup marker. It is not part of
    // this fixture's 500 application rows and two Welcome obligations.
    for row in storage
        .list_messages(&group_id, cgka_traits::EpochId(0))
        .unwrap()
    {
        if StoredMessagePayload::decode(&row.payload)
            .unwrap()
            .as_raw_transport()
            .is_some()
        {
            storage.delete_message(&row.id).unwrap();
        }
    }
    // Reuse real application bytes; these are storage-history fixtures, not
    // additional ratchet advances. Keep exactly 500 Processed application rows.
    for n in 0..500 {
        let mut message = application.clone();
        if n != 0 {
            message.id = MessageId::new(format!("processed-application-{n}").into_bytes());
        }
        record.id = message.id.clone();
        record.state = MessageState::Processed;
        record.payload = StoredMessagePayload::openmls_wire(message)
            .encode()
            .unwrap();
        storage.put_message(&record).unwrap();
    }
    for (n, state) in [
        MessageState::Created,
        MessageState::Retryable,
        MessageState::ConvergenceDeferred,
        MessageState::PeelDeferred,
        MessageState::EpochInvalidated,
    ]
    .into_iter()
    .enumerate()
    {
        record.id = MessageId::new(format!("non-target-state-{n}").into_bytes());
        record.state = state;
        storage.put_message(&record).unwrap();
    }

    let (outstanding, reads) = measure(&storage, || alice.outstanding_sent_welcomes().unwrap());
    assert_eq!(
        reads,
        (2, 2),
        "outstanding discovery must fetch only Sent rows"
    );
    let expected = welcomes
        .iter()
        .cloned()
        .map(|welcome| (group_id.clone(), welcome))
        .collect::<Vec<_>>();
    assert_eq!(outstanding, expected);

    let (tracked_ids, reads) = measure(&storage, || alice.tracked_outbound_welcome_ids().unwrap());
    assert_eq!(
        reads,
        (2, 502),
        "tracking must exclude non-target states in storage"
    );
    assert_eq!(
        tracked_ids,
        welcomes
            .iter()
            .map(|welcome| welcome.id.clone())
            .collect::<Vec<_>>()
    );

    let (index, reads) = measure(&storage, || alice.welcome_delivery_index().unwrap());
    assert_eq!(
        reads,
        (2, 502),
        "combined discovery must scan each live group once"
    );
    assert_eq!(index.outstanding, expected);
    assert_eq!(index.tracked_ids, tracked_ids);
}

#[tokio::test]
async fn welcome_index_keeps_lifecycle() {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut alice = build_profile_client_on_storage(
        b"alice-welcome-lifecycle",
        storage.clone(),
        ProtocolProfile::Current,
    );
    let mut bob = build_current_client(b"bob-welcome-lifecycle");
    let mut carol = build_current_client(b"carol-welcome-lifecycle");
    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "welcome delivery lifecycle".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let completed = match result {
        SendResult::FoundingGroupCreated { mut welcomes } => welcomes.remove(0),
        other => panic!("expected founding Welcome, got {other:?}"),
    };
    alice.mark_sent_welcome_delivered(&completed.id).unwrap();
    assert_eq!(
        storage.get_message(&completed.id).unwrap().state,
        MessageState::Processed
    );

    let (pending, staged) = match alice
        .send(SendIntent::Invite {
            group_id,
            key_packages: vec![carol.fresh_key_package().await.unwrap()],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution {
            pending,
            mut welcomes,
            ..
        } => (pending, welcomes.remove(0)),
        other => panic!("expected staged invite, got {other:?}"),
    };
    assert_eq!(
        storage.get_message(&staged.id).unwrap().state,
        MessageState::Sent
    );
    let expected_ids = vec![completed.id.clone(), staged.id.clone()];
    let index = alice.welcome_delivery_index().unwrap();
    assert!(
        index.outstanding.is_empty(),
        "a Sent staged invite is not deliverable"
    );
    assert_eq!(index.tracked_ids, expected_ids);
    assert!(alice.outstanding_sent_welcomes().unwrap().is_empty());
    assert_eq!(alice.tracked_outbound_welcome_ids().unwrap(), expected_ids);

    alice.publish_failed(pending).await.unwrap();
    let canceled = storage.get_message(&staged.id).unwrap();
    assert_eq!(canceled.state, MessageState::Failed);
    assert!(
        StoredMessagePayload::decode(&canceled.payload)
            .unwrap()
            .as_outbound_welcome()
            .is_some()
    );

    // Historical raw Welcomes and malformed payloads are never cold-discovered,
    // including after completed and canceled obligations survive a restart.
    let mut excluded = storage.get_message(&completed.id).unwrap();
    let mut raw = completed.clone();
    raw.id = MessageId::new(b"historical-raw-welcome".to_vec());
    excluded.id = raw.id.clone();
    excluded.state = MessageState::Sent;
    excluded.payload = StoredMessagePayload::raw_transport(raw).encode().unwrap();
    storage.put_message(&excluded).unwrap();
    excluded.id = MessageId::new(b"malformed-welcome-payload".to_vec());
    excluded.payload = vec![0xff];
    storage.put_message(&excluded).unwrap();
    drop(alice);

    let mut reopened = build_profile_client_on_storage(
        b"alice-welcome-lifecycle",
        storage,
        ProtocolProfile::Current,
    );
    reopened.hydrate_all_stored_groups().unwrap();
    let index = reopened.welcome_delivery_index().unwrap();
    assert!(index.outstanding.is_empty());
    assert_eq!(
        index.tracked_ids, expected_ids,
        "completed and canceled ids remain tracked"
    );
    assert!(reopened.outstanding_sent_welcomes().unwrap().is_empty());
    assert_eq!(
        reopened.tracked_outbound_welcome_ids().unwrap(),
        expected_ids
    );
}

#[tokio::test]
async fn current_group_initial_retention_is_canonical_for_creator_invitee_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("founding-retention.sqlite");
    let database_key = SqlCipherKey::raw([0x42; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&database, &database_key).unwrap();
    let supported = default_group_components()
        .into_iter()
        .chain([GROUP_MESSAGE_RETENTION_COMPONENT_ID])
        .collect::<Vec<_>>();
    let mut alice = EngineBuilder::new(storage)
        .identity(pad32(b"alice-founding-retention"))
        .account_identity_proof_signer(proof_signer(b"alice-founding-retention"))
        .supported_app_components(supported.clone())
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    let mut bob = EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
        .identity(pad32(b"bob-founding-retention"))
        .account_identity_proof_signer(proof_signer(b"bob-founding-retention"))
        .supported_app_components(supported.clone())
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "founding retention".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
                data: 300u64.to_be_bytes().to_vec(),
            }],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match created {
        SendResult::FoundingGroupCreated { mut welcomes } => welcomes.remove(0),
        other => panic!("expected one canonical founding result, got {other:?}"),
    };

    assert_eq!(
        alice
            .app_component(&group_id, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .unwrap(),
        Some(300u64.to_be_bytes().to_vec())
    );
    let joined = bob.join_welcome(welcome).await.unwrap();
    assert_eq!(joined, group_id);
    assert_eq!(
        bob.app_component(&joined, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .unwrap(),
        Some(300u64.to_be_bytes().to_vec()),
        "the Welcome must carry the founding retention state"
    );

    drop(alice);
    let reopened_storage = SqliteAccountStorage::open_encrypted(&database, &database_key).unwrap();
    let mut reopened = EngineBuilder::new(reopened_storage)
        .identity(pad32(b"alice-founding-retention"))
        .account_identity_proof_signer(proof_signer(b"alice-founding-retention"))
        .supported_app_components(supported)
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    reopened.hydrate_all_stored_groups().unwrap();
    assert_eq!(
        reopened
            .app_component(&group_id, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .unwrap(),
        Some(300u64.to_be_bytes().to_vec())
    );
}

#[tokio::test]
async fn current_group_initial_retention_rejects_unsupported_invitee_before_state() {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let supported = default_group_components()
        .into_iter()
        .chain([GROUP_MESSAGE_RETENTION_COMPONENT_ID])
        .collect::<Vec<_>>();
    let mut alice = EngineBuilder::new(storage)
        .identity(pad32(b"alice-unsupported-retention"))
        .account_identity_proof_signer(proof_signer(b"alice-unsupported-retention"))
        .supported_app_components(supported)
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    let mut bob = build_current_client(b"bob-unsupported-retention");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let error = alice
        .create_group(CreateGroupRequest {
            name: "unsupported retention".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
                data: 300u64.to_be_bytes().to_vec(),
            }],
            initial_admins: vec![],
        })
        .await
        .expect_err("retention must be supported by every founding member");

    assert!(matches!(
        error,
        EngineError::MissingRequiredCapabilities { ref required, .. }
            if required
                .app_components
                .contains(GROUP_MESSAGE_RETENTION_COMPONENT_ID)
    ));
    assert!(alice.live_group_ids().unwrap().is_empty());
}

/// Cancelling the real wrapping await must clean up provisional MLS state in
/// either profile without dropping the engine that owns it (mdk#3061).
#[tokio::test]
async fn cancelling_founding_retention_before_canonicalization_leaves_no_group() {
    for profile in [ProtocolProfile::Current, ProtocolProfile::Legacy] {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("cancelled-creation.sqlite");
        let database_key = SqlCipherKey::raw([0x61; 32]);
        let storage = SqliteAccountStorage::open_encrypted(&database, &database_key).unwrap();
        let supported = default_group_components()
            .into_iter()
            .chain([GROUP_MESSAGE_RETENTION_COMPONENT_ID])
            .collect::<Vec<_>>();
        let build_client = |identity: &[u8], storage, peeler: Box<dyn TransportPeeler>| {
            let builder = EngineBuilder::new(storage)
                .identity(pad32(identity))
                .account_identity_proof_signer(proof_signer(identity))
                .supported_app_components(supported.clone())
                .protocol_profile(profile)
                .peeler(peeler);
            if profile == ProtocolProfile::Legacy {
                builder.legacy_compatibility_profile().build().unwrap()
            } else {
                builder.build().unwrap()
            }
        };
        let mut bob = build_client(
            b"bob-cancel-founding-retention",
            SqliteAccountStorage::in_memory_for_test().unwrap(),
            Box::<MockPeeler>::default(),
        );
        let bob_kp = bob.fresh_key_package().await.unwrap();
        let request = CreateGroupRequest {
            name: "cancel founding retention".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: if profile == ProtocolProfile::Current {
                vec![AppComponentData {
                    component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
                    data: 300u64.to_be_bytes().to_vec(),
                }]
            } else {
                vec![]
            },
            initial_admins: vec![],
        };
        let started = Arc::new(tokio::sync::Notify::new());
        let mut alice = build_client(
            b"alice-cancel-founding-retention",
            storage.clone(),
            Box::new(BlockingWelcomePeeler {
                inner: MockPeeler::default(),
                started: started.clone(),
            }),
        );
        let before = encrypted_openmls_rows(&database, &database_key);
        assert!(!before.is_empty(), "retain the creator's identity keys");
        {
            let creation = alice.create_group(request.clone());
            tokio::pin!(creation);
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::select! {
                    _ = started.notified() => {},
                    result = &mut creation => panic!("wrapping must still be pending: {result:?}"),
                }
            })
            .await
            .expect("creation must reach its Welcome wrapping await");
            assert!(
                encrypted_openmls_rows(&database, &database_key) != before,
                "{profile:?}: cancellation must happen after OpenMLS wrote group state"
            );
        }
        assert!(storage.list_groups().unwrap().is_empty(), "{profile:?}");
        assert!(alice.live_group_ids().unwrap().is_empty(), "{profile:?}");
        assert!(alice.drain_events().is_empty(), "{profile:?}");
        assert!(
            encrypted_openmls_rows(&database, &database_key) == before,
            "{profile:?}: cancellation left orphaned OpenMLS state"
        );
        drop(alice);
        drop(storage);

        let storage = SqliteAccountStorage::open_encrypted(&database, &database_key).unwrap();
        assert!(
            encrypted_openmls_rows(&database, &database_key) == before,
            "{profile:?}: orphaned state survived encrypted reopen"
        );
        let mut reopened = build_client(
            b"alice-cancel-founding-retention",
            storage,
            Box::<MockPeeler>::default(),
        );
        reopened.hydrate_all_stored_groups().unwrap();
        assert!(reopened.live_group_ids().unwrap().is_empty());
        let (group_id, result) = reopened.create_group(request).await.unwrap();
        let mut welcomes = match result {
            SendResult::GroupCreated { pending, welcomes } => {
                reopened.confirm_published(pending).await.unwrap();
                welcomes
            }
            SendResult::FoundingGroupCreated { welcomes } => welcomes,
            other => panic!("expected founding creation, got {other:?}"),
        };
        assert_eq!(welcomes.len(), 1);
        assert_eq!(
            bob.join_welcome(welcomes.remove(0)).await.unwrap(),
            group_id
        );
        assert_eq!(
            reopened.epoch(&group_id).unwrap(),
            bob.epoch(&group_id).unwrap()
        );
        assert_eq!(reopened.members(&group_id).unwrap().len(), 2);
        if profile == ProtocolProfile::Current {
            assert_eq!(
                bob.app_component(&group_id, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
                    .unwrap(),
                Some(300u64.to_be_bytes().to_vec()),
            );
        }
    }
}

/// A second Welcome write fails only after the first Welcome, group projection
/// and (on Legacy) route were persisted. No unfinished state survives the
/// returned error or encrypted reopen, and the same creator can retry (mdk#3077).
#[tokio::test]
async fn late_founding_welcome_write_failure_restores_state_and_allows_retry() {
    for profile in [ProtocolProfile::Current, ProtocolProfile::Legacy] {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("late-founding-welcome.sqlite");
        let key = SqlCipherKey::raw([0x77; 32]);
        let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
        let supported = default_group_components()
            .into_iter()
            .chain([NOSTR_ROUTING_COMPONENT_ID])
            .collect::<Vec<_>>();
        let build = |identity: &[u8], storage| {
            let builder = EngineBuilder::new(storage)
                .identity(pad32(identity))
                .account_identity_proof_signer(proof_signer(identity))
                .supported_app_components(supported.clone())
                .protocol_profile(profile)
                .peeler(Box::<MockPeeler>::default());
            if profile == ProtocolProfile::Legacy {
                builder.legacy_compatibility_profile().build().unwrap()
            } else {
                builder.build().unwrap()
            }
        };
        let mut alice = build(b"late-founding-alice", storage.clone());
        let mut bob = build(
            b"late-founding-bob",
            SqliteAccountStorage::in_memory_for_test().unwrap(),
        );
        let mut carol = build(
            b"late-founding-carol",
            SqliteAccountStorage::in_memory_for_test().unwrap(),
        );
        let request = CreateGroupRequest {
            name: "late founding Welcome".into(),
            description: String::new(),
            members: vec![
                bob.fresh_key_package().await.unwrap(),
                carol.fresh_key_package().await.unwrap(),
            ],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: encode_nostr_routing_v1(
                    &NostrRoutingV1::new([0x77; 32], vec!["wss://relay.example".into()]).unwrap(),
                )
                .unwrap(),
            }],
            initial_admins: vec![],
        };
        let mls_before = encrypted_openmls_rows(&database, &key);
        let observer = rusqlite::Connection::open(&database).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &observer,
            &key,
            storage_sqlite::SqlCipherHardening::live_cache(),
        )
        .unwrap();
        let late_route = if profile == ProtocolProfile::Legacy {
            "AND EXISTS(SELECT 1 FROM cgka_transport_group_routes WHERE group_id = NEW.group_id)"
        } else {
            ""
        };
        observer.execute_batch(&format!(
            "CREATE TRIGGER fail_second_founding_welcome BEFORE INSERT ON cgka_messages
             WHEN (SELECT COUNT(*) FROM cgka_messages WHERE group_id = NEW.group_id) = 1
              AND (SELECT json_array_length(json_extract(record, '$.members')) FROM cgka_groups WHERE id = NEW.group_id) = 3
              {late_route}
             BEGIN SELECT RAISE(ABORT, 'second-founding-welcome-fault'); END;",
        )).unwrap();
        let failed = alice.create_group(request.clone()).await;
        assert!(
            matches!(&failed, Err(EngineError::Storage(cgka_traits::storage::StorageError::Backend(detail)))
                if detail.contains("second-founding-welcome-fault")),
            "{profile:?}: the second Welcome write must be the failing step: {failed:?}"
        );
        assert!(
            storage.list_groups().unwrap().is_empty(),
            "{profile:?}: failed creation left its group record"
        );
        assert!(alice.live_group_ids().unwrap().is_empty(), "{profile:?}");
        assert!(alice.drain_events().is_empty(), "{profile:?}");
        assert!(alice.outstanding_sent_welcomes().unwrap().is_empty());
        assert!(
            encrypted_openmls_rows(&database, &key) == mls_before,
            "{profile:?}: unfinished MLS state remained"
        );
        for table in [
            "cgka_groups",
            "cgka_messages",
            "cgka_transport_group_routes",
        ] {
            let count: i64 = observer
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{profile:?}: failed creation left {table} rows");
        }
        observer
            .execute_batch("DROP TRIGGER fail_second_founding_welcome")
            .unwrap();
        let (group_id, retry) = alice.create_group(request).await.unwrap();
        let mut welcomes = match retry {
            SendResult::GroupCreated { pending, welcomes } => {
                alice.confirm_published(pending).await.unwrap();
                welcomes
            }
            SendResult::FoundingGroupCreated { welcomes } => welcomes,
            other => panic!("expected founding result: {other:?}"),
        };
        assert_eq!(welcomes.len(), 2);
        assert_eq!(
            bob.join_welcome(welcomes.remove(0)).await.unwrap(),
            group_id
        );
        assert_eq!(
            carol.join_welcome(welcomes.remove(0)).await.unwrap(),
            group_id
        );
        let sent = bob
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&bob, b"routing after late creation failure"),
                expected_epoch: None,
            })
            .await
            .unwrap();
        let SendResult::ApplicationMessage { msg, .. } = sent else {
            panic!("expected peer application: {sent:?}")
        };
        assert_eq!(
            alice.ingest(msg).await.unwrap(),
            cgka_traits::ingest::IngestOutcome::Processed
        );
        drop(alice);
        drop(observer);
        storage.close().unwrap();
        drop(storage);
        let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
        let mut reopened = build(b"late-founding-alice", storage);
        reopened.hydrate_all_stored_groups().unwrap();
        assert_eq!(reopened.live_group_ids().unwrap(), vec![group_id.clone()]);
        assert_eq!(reopened.members(&group_id).unwrap().len(), 3);
        assert_eq!(
            reopened.epoch(&group_id).unwrap(),
            bob.epoch(&group_id).unwrap()
        );
    }
}

/// Independent reads include orphaned rows that group hydration cannot find.
fn encrypted_openmls_rows(
    database: &std::path::Path,
    database_key: &SqlCipherKey,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let connection = rusqlite::Connection::open(database).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        database_key,
        storage_sqlite::SqlCipherHardening::live_cache(),
    )
    .unwrap();
    connection
        .prepare("SELECT storage_key, value FROM openmls_values ORDER BY storage_key")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// A legacy-profile create whose Welcome cannot be wrapped is refused before
/// the group record or any Welcome is written. Its provisional OpenMLS state
/// must also be removed, including after encrypted reopen (mdk#2808).
#[tokio::test]
async fn legacy_create_whose_welcome_cannot_be_wrapped_writes_no_group() {
    struct RefusingWelcomes(MockPeeler);
    #[async_trait]
    impl TransportPeeler for RefusingWelcomes {
        async fn peel_group_message(
            &self,
            msg: &TransportMessage,
            ctx: &GroupContextSnapshot,
        ) -> Result<PeeledMessage, PeelerError> {
            self.0.peel_group_message(msg, ctx).await
        }

        async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
            self.0.peel_welcome(msg).await
        }

        async fn wrap_group_message(
            &self,
            payload: &EncryptedPayload,
            ctx: &GroupContextSnapshot,
        ) -> Result<TransportMessage, PeelerError> {
            self.0.wrap_group_message(payload, ctx).await
        }

        async fn wrap_welcome(
            &self,
            _payload: &EncryptedPayload,
            _recipient: &MemberId,
        ) -> Result<TransportMessage, PeelerError> {
            Err(PeelerError::MissingContext {
                label: "welcome_metadata".into(),
            })
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("refused-legacy-create.sqlite");
    let database_key = SqlCipherKey::raw([0x28; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&database, &database_key).unwrap();
    let mls_rows = || encrypted_openmls_rows(&database, &database_key);
    let mut alice = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(b"alice-unwrappable-welcome"))
        .account_identity_proof_signer(proof_signer(b"alice-unwrappable-welcome"))
        .peeler(Box::new(RefusingWelcomes(MockPeeler::default())))
        .build()
        .unwrap();
    let mut bob = build_client(b"bob-unwrappable-welcome", FeatureRegistry::new());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let before = mls_rows();
    assert!(
        !before.is_empty(),
        "retain the creator identity key material"
    );
    let refused = alice
        .create_group(CreateGroupRequest {
            name: "unwrappable welcome".into(),
            description: String::new(),
            members: vec![bob_kp.clone()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await;
    assert!(
        matches!(
            refused,
            Err(EngineError::Peeler(PeelerError::MissingContext { ref label }))
                if label == "welcome_metadata"
        ),
        "{refused:?}"
    );
    assert!(storage.list_groups().unwrap().is_empty());
    assert!(alice.drain_events().is_empty());
    assert!(
        mls_rows() == before,
        "refused create left orphaned OpenMLS state"
    );
    drop(alice);
    drop(storage);

    let storage = SqliteAccountStorage::open_encrypted(&database, &database_key).unwrap();
    assert!(
        mls_rows() == before,
        "orphaned state survived encrypted reopen"
    );
    let mut alice = build_profile_client_on_storage(
        b"alice-unwrappable-welcome",
        storage,
        ProtocolProfile::Legacy,
    );
    alice.hydrate_all_stored_groups().unwrap();
    assert!(alice.live_group_ids().unwrap().is_empty());
    // The same creator and unconsumed recipient package remain usable after
    // cleanup; success must hand its pending commit to normal confirmation.
    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "retry legacy create".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, mut welcomes) = match result {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("legacy creation must await confirmation: {other:?}"),
    };
    assert_eq!(welcomes.len(), 1);
    alice.confirm_published(pending).await.unwrap();
    assert_eq!(
        bob.join_welcome(welcomes.remove(0)).await.unwrap(),
        group_id
    );
    assert_eq!(
        alice.epoch(&group_id).unwrap(),
        bob.epoch(&group_id).unwrap()
    );
    assert_eq!(alice.members(&group_id).unwrap().len(), 2);
    drop(alice);
    let storage = SqliteAccountStorage::open_encrypted(&database, &database_key).unwrap();
    let mut reopened = build_profile_client_on_storage(
        b"alice-unwrappable-welcome",
        storage,
        ProtocolProfile::Legacy,
    );
    reopened.hydrate_all_stored_groups().unwrap();
    assert_eq!(reopened.live_group_ids().unwrap(), vec![group_id.clone()]);
    assert_eq!(reopened.members(&group_id).unwrap().len(), 2);
}

#[tokio::test]
async fn current_group_rejects_colliding_founding_welcome_ids_atomically() {
    let mut alice = EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
        .identity(pad32(b"alice-colliding-welcomes"))
        .account_identity_proof_signer(proof_signer(b"alice-colliding-welcomes"))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler {
            welcome_sender: None,
            collide_welcome_ids: true,
        }))
        .build()
        .unwrap();
    let mut bob = build_current_client(b"bob-colliding-welcomes");
    let mut carol = build_current_client(b"carol-colliding-welcomes");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let error = alice
        .create_group(CreateGroupRequest {
            name: "colliding founding welcomes".into(),
            description: String::new(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("two invitees must not share a Welcome delivery id");

    assert!(matches!(
        error,
        EngineError::Backend(ref message)
            if message == "founding creation did not produce one distinct Welcome per invitee"
    ));
    assert!(
        alice.live_group_ids().unwrap().is_empty(),
        "the failed founding transaction must leave no live group"
    );
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
    assert!(
        group
            .required_capabilities
            .app_components
            .contains(GROUP_LIFECYCLE_COMPONENT_ID)
    );
    assert_eq!(
        decode_group_lifecycle_v1(
            &alice
                .app_component(&group_id, GROUP_LIFECYCLE_COMPONENT_ID)
                .unwrap()
                .expect("new current group has lifecycle-v1"),
        )
        .unwrap(),
        GroupLifecycleV1::Active
    );
    assert!(matches!(
        alice.drain_events().as_slice(),
        [cgka_traits::engine::GroupEvent::GroupCreated { group_id: created }]
            if created == &group_id
    ));

    let sent = alice
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id,
            payload: app_payload_for(&alice, "usable immediately"),
            expected_epoch: None,
        })
        .await
        .expect("canonical solo group accepts work without confirm_published");
    assert!(matches!(sent, SendResult::ApplicationMessage { .. }));
}

#[tokio::test]
async fn solo_disband_is_durable_convergent_terminal_and_restart_safe() {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let identity = b"alice-current-solo-disband";
    let clock = ManualConvergenceClock::new(0, 10_000);
    let mut alice = EngineBuilder::new(storage.clone())
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .convergence_clock(Arc::new(clock.clone()))
        .build()
        .expect("build current-profile engine");
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "terminal solo".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(matches!(
        created,
        SendResult::FoundingGroupCreated { ref welcomes } if welcomes.is_empty()
    ));
    alice.drain_events();

    let requested = alice
        .send(cgka_traits::engine::SendIntent::Disband {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert!(matches!(requested, SendResult::DisbandRequested { .. }));
    assert!(matches!(
        alice.disband_request(&group_id).unwrap().unwrap().status,
        cgka_traits::DisbandRequestStatus::Pending
    ));
    assert!(
        alice.disbanding_in_progress(&group_id).unwrap(),
        "the client-facing gate becomes visible with the durable request"
    );
    let refused = alice
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, "must be gated"),
            expected_epoch: None,
        })
        .await;
    assert!(
        matches!(refused, Err(EngineError::InvalidTransition(transition))
        if transition.from == "Disbanding" && transition.to == "app_message")
    );

    let prepared = alice.advance_convergence(&group_id).await.unwrap();
    let pending = match prepared.as_slice() {
        [
            SendResult::GroupEvolution {
                pending, welcomes, ..
            },
        ] => {
            assert!(welcomes.is_empty());
            *pending
        }
        other => panic!("expected one prepared disband commit, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    assert!(
        !matches!(
            alice.epoch_state(&group_id),
            Some(cgka_traits::EpochState::Disbanded(_))
        ),
        "publish confirmation alone must not terminalize before convergence"
    );

    assert!(
        alice
            .advance_convergence(&group_id)
            .await
            .unwrap()
            .is_empty(),
        "the post-confirmation tick opens the collecting pass"
    );
    clock.advance_ms(1_000);
    assert!(
        alice
            .advance_convergence(&group_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        matches!(
            alice.epoch_state(&group_id),
            Some(cgka_traits::EpochState::Disbanded(_))
        ),
        "disband did not settle within the bounded convergence pass: state={:?}, pass={:?}",
        alice.epoch_state(&group_id),
        storage.convergence_pass(&group_id).unwrap()
    );
    let terminal = alice.group_record(&group_id).unwrap();
    assert!(terminal.disbanded.is_some());
    assert_eq!(
        terminal.members.len(),
        1,
        "historical pre-disband account roster is retained"
    );
    assert!(alice.disband_request(&group_id).unwrap().is_none());
    assert!(
        !alice.disbanding_in_progress(&group_id).unwrap(),
        "terminal state is reported by the lifecycle, not as pending work"
    );
    let late_message_id = MessageId::new(b"late-terminal-group-traffic".to_vec());
    let late = TransportMessage {
        id: late_message_id.clone(),
        payload: b"never peel terminal traffic".to_vec(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("mock".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    };
    assert!(matches!(
        alice.ingest(late).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::UnknownGroup,
        }
    ));
    assert!(
        matches!(
            storage.get_message(&late_message_id),
            Err(cgka_traits::storage::StorageError::NotFound)
        ),
        "late terminal traffic must not become a retryable message row"
    );
    let state_changes = alice
        .drain_events()
        .into_iter()
        .filter_map(|event| match event {
            cgka_traits::engine::GroupEvent::GroupStateChanged { change, .. } => Some(change),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        state_changes,
        vec![cgka_traits::engine::GroupStateChange::GroupDisbanded],
        "the terminal commit suppresses member/admin removal changes"
    );

    drop(alice);
    let mut reopened =
        build_profile_client_on_storage(identity, storage.clone(), ProtocolProfile::Current);
    reopened.hydrate_all_stored_groups().unwrap();
    assert!(matches!(
        reopened.epoch_state(&group_id),
        Some(cgka_traits::EpochState::Disbanded(_))
    ));
    assert!(
        reopened
            .group_record(&group_id)
            .unwrap()
            .disbanded
            .is_some()
    );
    assert!(reopened.quarantined_groups().is_empty());

    drop(reopened);
    assert!(
        storage
            .delete_local_group_data(&hex::encode(group_id.as_slice()))
            .unwrap()
            .did_delete(),
        "terminal local deletion should remove history and the full group row"
    );
    let mut tombstone_only =
        build_profile_client_on_storage(identity, storage, ProtocolProfile::Current);
    tombstone_only.hydrate_all_stored_groups().unwrap();
    assert!(matches!(
        tombstone_only.epoch_state(&group_id),
        Some(cgka_traits::EpochState::Disbanded(_))
    ));
    assert!(
        tombstone_only.live_group_ids().unwrap().is_empty(),
        "a tombstone-only group is terminal but never live/routable"
    );
    assert!(tombstone_only.quarantined_groups().is_empty());
    assert!(
        matches!(
            tombstone_only.group_record(&group_id),
            Err(EngineError::Storage(
                cgka_traits::storage::StorageError::NotFound
            ))
        ),
        "full group metadata is optional after the user deletes local history"
    );
}

/// The convergence pass that settles a device's own disband has no rival
/// branch to materialize: the disband commit is already applied, so the pass
/// selects nothing. The device's own sends retained in that pass's window must
/// not be judged against a canonical state nobody selected — they were
/// published long before and must neither be withdrawn from the application
/// nor stamped terminal.
#[tokio::test]
async fn own_sends_survive_the_pass_that_settles_their_senders_disband() {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let identity = b"alice-own-sends-before-disband";
    let clock = ManualConvergenceClock::new(0, 10_000);
    let mut alice = EngineBuilder::new(storage.clone())
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .convergence_clock(Arc::new(clock.clone()))
        .build()
        .expect("build current-profile engine");
    let (group_id, _) = alice
        .create_group(CreateGroupRequest {
            name: "own sends then disband".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let mut own_sends = Vec::new();
    for body in ["first", "second", "third"] {
        match alice
            .send(cgka_traits::engine::SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&alice, body),
                expected_epoch: None,
            })
            .await
            .unwrap()
        {
            SendResult::ApplicationMessage { msg, .. } => own_sends.push(msg.id),
            other => panic!("expected an application message, got {other:?}"),
        }
    }
    alice.drain_events();

    alice
        .send(cgka_traits::engine::SendIntent::Disband {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let pending = match alice
        .advance_convergence(&group_id)
        .await
        .unwrap()
        .as_slice()
    {
        [SendResult::GroupEvolution { pending, .. }] => *pending,
        other => panic!("expected one prepared disband commit, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    alice.advance_convergence(&group_id).await.unwrap();
    clock.advance_ms(1_000);
    alice.advance_convergence(&group_id).await.unwrap();
    assert!(
        matches!(
            alice.epoch_state(&group_id),
            Some(cgka_traits::EpochState::Disbanded(_))
        ),
        "the disband must settle through its convergence pass"
    );

    let events = alice.drain_events();
    assert!(
        !events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::AppMessageInvalidated { message_id, .. }
                if own_sends.contains(message_id)
        )),
        "a pass that selected no branch withdrew the sender's own messages: {events:?}"
    );
    for id in &own_sends {
        assert_ne!(
            storage.get_message(id).unwrap().state,
            cgka_traits::message::MessageState::EpochInvalidated,
            "a pass that selected no branch stamped an own send terminal"
        );
    }
}

/// Helper for the announce-once tests: drive one solo group all the way to a
/// settled, durable disband and hand back the storage that outlives the engine.
async fn settle_solo_disband(identity: &[u8]) -> (SqliteAccountStorage, cgka_traits::GroupId) {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let clock = ManualConvergenceClock::new(0, 10_000);
    let mut alice = EngineBuilder::new(storage.clone())
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .convergence_clock(Arc::new(clock.clone()))
        .build()
        .expect("build current-profile engine");
    let (group_id, _) = alice
        .create_group(CreateGroupRequest {
            name: "announce once".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    alice.drain_events();

    alice
        .send(cgka_traits::engine::SendIntent::Disband {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let prepared = alice.advance_convergence(&group_id).await.unwrap();
    let pending = match prepared.as_slice() {
        [SendResult::GroupEvolution { pending, .. }] => *pending,
        other => panic!("expected one prepared disband commit, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    assert!(
        alice
            .advance_convergence(&group_id)
            .await
            .unwrap()
            .is_empty()
    );
    clock.advance_ms(1_000);
    assert!(
        alice
            .advance_convergence(&group_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        matches!(
            alice.epoch_state(&group_id),
            Some(cgka_traits::EpochState::Disbanded(_))
        ),
        "disband did not settle within the bounded convergence pass"
    );
    // The live delivery the application receives in-session. Everything after
    // this point is hydration's belt-and-braces reconciliation.
    assert_eq!(
        disband_replays(&mut alice),
        1,
        "the settling session owes exactly one live GroupDisbanded"
    );
    drop(alice);
    (storage, group_id)
}

/// Count the terminal `GroupDisbanded` events one engine session hands the
/// application.
fn disband_replays(engine: &mut Engine<SqliteAccountStorage>) -> usize {
    engine
        .drain_events()
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                cgka_traits::engine::GroupEvent::GroupStateChanged {
                    change: cgka_traits::engine::GroupStateChange::GroupDisbanded,
                    ..
                }
            )
        })
        .count()
}

/// A disband tombstone is immortal, but its announcement is not: hydration
/// owes the application exactly one belt-and-braces replay of `GroupDisbanded`
/// — the reconciler for a live delivery the application never projected — and
/// silence on every open after that.
///
/// Without the marker every open re-emits, and the application's terminal arm
/// forces a no-op route-refreshing sync for every disbanded group, forever.
#[tokio::test]
async fn a_disbanded_group_announces_itself_once_across_repeated_opens() {
    let identity = b"alice-announce-once-record";
    let (storage, group_id) = settle_solo_disband(identity).await;

    let mut first =
        build_profile_client_on_storage(identity, storage.clone(), ProtocolProfile::Current);
    first.hydrate_all_stored_groups().unwrap();
    assert!(matches!(
        first.epoch_state(&group_id),
        Some(cgka_traits::EpochState::Disbanded(_))
    ));
    assert_eq!(
        disband_replays(&mut first),
        1,
        "the first open owes the one reconciling replay"
    );
    drop(first);

    for open in 2..=3 {
        let mut later =
            build_profile_client_on_storage(identity, storage.clone(), ProtocolProfile::Current);
        later.hydrate_all_stored_groups().unwrap();
        assert!(
            matches!(
                later.epoch_state(&group_id),
                Some(cgka_traits::EpochState::Disbanded(_))
            ),
            "open {open} must still restore the terminal epoch entry"
        );
        assert_eq!(
            disband_replays(&mut later),
            0,
            "open {open} must not re-announce an already announced disband"
        );
        assert!(later.quarantined_groups().is_empty());
        drop(later);
    }
}

/// Same contract on the orphan-tombstone path: after the user deletes local
/// history the group record is gone and only the anti-resurrection guard
/// remains, so hydration reaches the tombstone through the orphan sweep rather
/// than through a stored group record. Both hydration call sites must agree.
#[tokio::test]
async fn a_tombstone_only_group_announces_itself_once_across_repeated_opens() {
    let identity = b"alice-announce-once-orphan";
    let (storage, group_id) = settle_solo_disband(identity).await;
    assert!(
        storage
            .delete_local_group_data(&hex::encode(group_id.as_slice()))
            .unwrap()
            .did_delete(),
        "terminal local deletion should remove history and the full group row"
    );

    let mut first =
        build_profile_client_on_storage(identity, storage.clone(), ProtocolProfile::Current);
    first.hydrate_all_stored_groups().unwrap();
    assert_eq!(
        disband_replays(&mut first),
        1,
        "the orphan sweep owes the same single reconciling replay"
    );
    assert!(first.live_group_ids().unwrap().is_empty());
    drop(first);

    for open in 2..=3 {
        let mut later =
            build_profile_client_on_storage(identity, storage.clone(), ProtocolProfile::Current);
        later.hydrate_all_stored_groups().unwrap();
        assert!(
            matches!(
                later.epoch_state(&group_id),
                Some(cgka_traits::EpochState::Disbanded(_))
            ),
            "open {open} must still restore the terminal epoch entry from the guard alone"
        );
        assert_eq!(
            disband_replays(&mut later),
            0,
            "open {open} must not re-announce an already announced orphan tombstone"
        );
        drop(later);
    }
}

#[tokio::test]
async fn current_configured_engine_reopens_and_uses_a_legacy_group() {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
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
    current.hydrate_all_stored_groups().unwrap();
    assert_eq!(
        current.group_record(&group_id).unwrap().protocol_profile,
        ProtocolProfile::Legacy
    );
    current
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&current, "still usable"),
            expected_epoch: None,
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

            initial_admins: vec![],
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
            expected_epoch: None,
        })
        .await
        .unwrap();
    let msg = match sent {
        SendResult::ApplicationMessage { msg, .. } => msg,
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
async fn fresh_key_package_lasts_thirty_days_and_invitees_may_last_eighty_four() {
    let mut bob = build_client(b"bob", selfremove_registry());
    // The publishing target: 30 days plus an hour of clock-skew margin
    // (foundation/key-packages.md, "Refreshing a slot").
    let published = key_package_metadata(&bob.fresh_key_package().await.unwrap()).unwrap();
    assert_eq!(published.not_after - published.not_before, 2_595_600);

    // A receiver keeps the 84-day validity limit, so a longer range from
    // another client still validates.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let longest = key_package_with_account_identity_proof_and_lifetime(
        b"carol-84-days",
        Lifetime::init(now - 3_600, now - 3_600 + 7_261_200),
    );
    let accepted = key_package_metadata(&longest).expect("a KeyPackage at the validity limit");
    assert_eq!(accepted.not_after - accepted.not_before, 7_261_200);
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

#[test]
fn engine_builder_defaults_to_current_and_requires_explicit_legacy_fixture_seam() {
    let current = EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
        .identity(pad32(b"default-current"))
        .account_identity_proof_signer(proof_signer(b"default-current"))
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .expect("default engine builds");
    assert_eq!(current.new_protocol_profile(), ProtocolProfile::Current);

    let legacy_result = EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
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
async fn freshly_generated_key_package_is_durably_owned_before_publication() {
    let mut engine = build_current_client(b"fresh-owned-package");
    let generated = engine.fresh_key_package().await.unwrap();

    assert_eq!(
        engine.durably_owned_key_packages().unwrap(),
        vec![generated],
        "generation must durably persist the private OpenMLS bundle before returning"
    );
}

#[tokio::test]
async fn strict_cutover_retires_all_legacy_key_package_bundles_idempotently() {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
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

/// mdk#2628 D40: a legacy create holds its Welcomes with its pending commit,
/// which keeps no delivery deadline, so a legacy engine never creates under a
/// chosen id, and the refusal writes nothing.
#[tokio::test]
async fn a_legacy_engine_refuses_a_chosen_group_id() {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut legacy =
        build_profile_client_on_storage(b"legacy-chosen", storage.clone(), ProtocolProfile::Legacy);
    let chosen = GroupId::new(vec![0x42; 16]);
    let refused = legacy
        .create_group_with_chosen_id_and_audit_context(
            CreateGroupRequest {
                name: String::new(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            },
            chosen.clone(),
            None,
            Timestamp(u64::MAX),
            None,
        )
        .await;
    assert!(
        refused
            .expect_err("a legacy engine refuses a chosen id")
            .to_string()
            .contains("only a current-profile group is created under a chosen id")
    );
    assert!(matches!(
        storage.get_group(&chosen),
        Err(cgka_traits::storage::StorageError::NotFound)
    ));
}

#[tokio::test]
async fn missing_welcome_key_package() {
    use cgka_traits::ingest::{IngestOutcome, InputRejectionCategory};
    use marmot_forensics::{AuditEvent, AuditEventKind, JsonlRecorder};

    let mut alice = build_current_client(b"alice");
    let mut bob = build_current_client(b"bob");
    let (_, created) = alice
        .create_group(CreateGroupRequest {
            name: "missing key package".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { mut welcomes } = created else {
        panic!("expected founding welcome");
    };
    let welcome = welcomes.remove(0);

    // The account identity matches, but these fresh stores lack Bob's bundle.
    let error = build_current_client(b"bob")
        .join_welcome(welcome.clone())
        .await
        .unwrap_err();
    assert!(matches!(error, EngineError::MissingWelcomeKeyPackage));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut missing = EngineBuilder::new(storage.clone())
        .identity(pad32(b"bob"))
        .account_identity_proof_signer(proof_signer(b"bob"))
        .peeler(Box::new(MockPeeler::default()))
        .recorder(Box::new(
            JsonlRecorder::open(&path, "missing-kp".into()).unwrap(),
        ))
        .build()
        .unwrap();
    assert!(matches!(
        missing.ingest(welcome.clone()).await.unwrap(),
        IngestOutcome::Ignored {
            category: InputRejectionCategory::MissingWelcomeKeyPackage
        }
    ));
    assert!(storage.list_groups().unwrap().is_empty());
    assert!(storage.has_ingress_dedup_marker(&welcome.id).unwrap());
    drop(missing);
    let audit = std::fs::read_to_string(path).unwrap();
    assert!(audit.lines().any(|line| {
        let event: AuditEvent = serde_json::from_str(line).unwrap();
        matches!(event.kind, AuditEventKind::IngestOutcome { stale_reason: Some(reason), .. }
            if reason == "missing_welcome_key_package")
    }));

    let mut reopened = build_profile_client_on_storage(b"bob", storage, ProtocolProfile::Current);
    assert!(matches!(
        reopened.ingest(welcome.clone()).await.unwrap(),
        IngestOutcome::Ignored {
            category: InputRejectionCategory::Duplicate
        }
    ));
    assert!(matches!(
        bob.ingest(welcome).await.unwrap(),
        IngestOutcome::Processed
    ));
}

#[tokio::test]
async fn strict_cutover_rejects_new_and_replayed_legacy_welcomes_without_group_state() {
    let bob_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut legacy_bob = build_profile_client_on_storage(
        b"legacy-welcome-bob",
        bob_storage.clone(),
        ProtocolProfile::Legacy,
    );
    let bob_key_package = legacy_bob.fresh_key_package().await.unwrap();
    drop(legacy_bob);

    let mut legacy_alice = build_profile_client_on_storage(
        b"legacy-welcome-alice",
        SqliteAccountStorage::in_memory_for_test().unwrap(),
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

/// Build a correctly signed package so a rejection proves semantic validation,
/// rather than a broken signature caused by editing serialized bytes.
fn key_package_with_advertised_capabilities(
    profile: ProtocolProfile,
    extra_extensions: &[u16],
    extra_proposals: &[u16],
) -> cgka_traits::engine::KeyPackage {
    let identity_seed = b"capability-invitee";
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let identity = pad32(identity_seed);
    let credential = CredentialWithKey {
        credential: BasicCredential::new(identity.clone()).into(),
        signature_key: signer.public().into(),
    };
    let mut dictionary = AppDataDictionary::new();
    let mut components = default_group_components();
    components.insert(APP_COMPONENTS_COMPONENT_ID);
    let mut extensions = Vec::new();
    let mut extension_types = vec![ExtensionType::AppDataDictionary];
    if profile == ProtocolProfile::Current {
        components.insert(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID);
        dictionary.insert(
            ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
            account_identity_proof_component(
                &identity,
                &signer.to_public_vec(),
                ciphersuite,
                ciphersuite.signature_algorithm(),
                1_700_000_000,
                proof_signer(identity_seed).as_ref(),
            )
            .unwrap(),
        );
    } else {
        extensions.push(
            account_identity_proof_extension(
                &identity,
                &signer.to_public_vec(),
                ciphersuite,
                ciphersuite.signature_algorithm(),
                proof_signer(identity_seed).as_ref(),
            )
            .unwrap(),
        );
        extension_types.push(ExtensionType::from(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE));
    }
    dictionary.insert(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&components),
    );
    extensions.push(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    ));
    extension_types.extend(extra_extensions.iter().copied().map(ExtensionType::from));
    let mut proposals = vec![openmls::prelude::ProposalType::AppDataUpdate];
    proposals.extend(
        extra_proposals
            .iter()
            .copied()
            .map(openmls::prelude::ProposalType::from),
    );
    let bundle = MlsKeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[ciphersuite]),
            Some(&extension_types),
            Some(&proposals),
            None,
        ))
        .leaf_node_extensions(Extensions::from_vec(extensions).unwrap())
        .build(ciphersuite, &provider, &signer, credential)
        .unwrap();
    let message: MlsMessageOut = bundle.key_package().clone().into();
    cgka_traits::engine::KeyPackage::new(message.tls_serialize_detached().unwrap())
        .with_protocol_profile(profile)
}

#[tokio::test]
async fn create_and_invite_reject_explicit_default_key_package_capabilities() {
    for profile in [ProtocolProfile::Current, ProtocolProfile::Legacy] {
        let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
        let mut alice = build_profile_client_on_storage(b"alice", storage.clone(), profile);
        let mut bob = build_profile_client_on_storage(
            b"valid-first-invitee",
            SqliteAccountStorage::in_memory_for_test().unwrap(),
            profile,
        );
        let valid_first = bob.fresh_key_package().await.unwrap();
        let rejected_member = MemberId::new(pad32(b"capability-invitee"));
        // Test every forbidden id separately, including the historical 0x0003
        // RequiredCapabilities advertisement. Directory metadata stays usable
        // for discovery and private-bundle maintenance.
        for (extensions, proposals) in (1..=5)
            .map(|id| (vec![id], vec![]))
            .chain((1..=7).map(|id| (vec![], vec![id])))
        {
            let kp = key_package_with_advertised_capabilities(profile, &extensions, &proposals);
            key_package_metadata(&kp).expect("valid signatures, identity, and lifetime");
            let error = alice
                .create_group(CreateGroupRequest {
                    name: "invalid-capabilities".into(),
                    description: String::new(),
                    members: vec![valid_first.clone(), kp],
                    required_features: vec![],
                    app_components: vec![],
                    initial_admins: vec![],
                })
                .await
                .expect_err("forbidden advertisement must fail before group creation");
            assert!(
                matches!(error, EngineError::InvalidKeyPackageCapabilities { ref member }
                    if member == &rejected_member),
                "{error:?}"
            );
            assert!(storage.list_groups().unwrap().is_empty());
        }
        let (group_id, result) = alice
            .create_group(CreateGroupRequest {
                name: "existing".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        if let SendResult::GroupCreated { pending, .. } = result {
            alice.confirm_published(pending).await.unwrap();
        }
        let epoch = alice.epoch(&group_id).unwrap();
        let members = alice.members(&group_id).unwrap();
        for (extensions, proposals) in (1..=5)
            .map(|id| (vec![id], vec![]))
            .chain((1..=7).map(|id| (vec![], vec![id])))
        {
            let kp = key_package_with_advertised_capabilities(profile, &extensions, &proposals);
            let error = alice
                .send(SendIntent::Invite {
                    group_id: group_id.clone(),
                    key_packages: vec![valid_first.clone(), kp],
                    initial_admins: vec![],
                })
                .await
                .expect_err("forbidden advertisement must fail before an Add commit");
            assert!(
                matches!(error, EngineError::InvalidKeyPackageCapabilities { ref member }
                    if member == &rejected_member),
                "{error:?}"
            );
            assert_eq!(alice.epoch(&group_id).unwrap(), epoch);
            assert_eq!(alice.members(&group_id).unwrap(), members);
        }
        // RFC 9420 section 7.2 requires unknown capability values to be ignored.
        // A valid retry also proves rejection left no pending commit behind.
        let kp = key_package_with_advertised_capabilities(profile, &[0x0a0a], &[0x0a0a]);
        let result = alice
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![kp],
                initial_admins: vec![],
            })
            .await
            .expect("unknown capabilities remain usable");
        let SendResult::GroupEvolution { pending, .. } = result else {
            panic!("expected invite")
        };
        alice.confirm_published(pending).await.unwrap();
        assert_eq!(alice.members(&group_id).unwrap().len(), 2);
    }
}

#[tokio::test]
async fn fresh_key_packages_omit_default_mls_capabilities() {
    for profile in [ProtocolProfile::Current, ProtocolProfile::Legacy] {
        let mut alice = build_profile_client_on_storage(
            b"alice",
            SqliteAccountStorage::in_memory_for_test().unwrap(),
            profile,
        );
        let kp = alice.fresh_key_package().await.unwrap();
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
        assert_non_default_mls_capabilities(key_package.leaf_node().capabilities());
        assert_eq!(
            key_package
                .leaf_node()
                .capabilities()
                .extensions()
                .contains(&ExtensionType::from(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE)),
            profile == ProtocolProfile::Legacy,
        );
    }
}

#[tokio::test]
async fn registry_defaults_are_implicit_for_key_packages_and_group_membership() {
    for profile in [ProtocolProfile::Current, ProtocolProfile::Legacy] {
        let mut registry = FeatureRegistry::new();
        for (index, name) in [
            "application-id",
            "ratchet-tree",
            "required-capabilities",
            "external-pub",
            "external-senders",
        ]
        .into_iter()
        .enumerate()
        {
            registry.register(
                Feature(name),
                CapabilityRequirement {
                    requires: Capability::Extension(index as u16 + 1),
                    level: RequirementLevel::Required,
                    description: "implicit MLS extension support",
                },
            );
        }
        for (index, name) in [
            "add",
            "update",
            "remove",
            "psk",
            "reinit",
            "external-init",
            "group-context-extensions",
        ]
        .into_iter()
        .enumerate()
        {
            registry.register(
                Feature(name),
                CapabilityRequirement {
                    requires: Capability::Proposal(index as u16 + 1),
                    level: RequirementLevel::Required,
                    description: "implicit MLS proposal support",
                },
            );
        }
        for (name, capability) in [
            ("custom-extension", Capability::Extension(0xff01)),
            ("custom-proposal", Capability::Proposal(0xff02)),
        ] {
            registry.register(
                Feature(name),
                CapabilityRequirement {
                    requires: capability,
                    level: RequirementLevel::Optional,
                    description: "non-default advertisement control",
                },
            );
        }
        let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
        let builder = EngineBuilder::new(storage.clone())
            .identity(pad32(b"alice"))
            .account_identity_proof_signer(proof_signer(b"alice"))
            .protocol_profile(profile)
            .feature_registry(registry)
            .peeler(Box::new(MockPeeler::default()));
        let builder = if profile == ProtocolProfile::Legacy {
            builder.legacy_compatibility_profile()
        } else {
            builder
        };
        let mut alice = builder.build().unwrap();
        let kp = alice.fresh_key_package().await.unwrap();
        let metadata = key_package_metadata(&kp).unwrap();
        assert!(
            metadata
                .mls_extensions
                .iter()
                .all(|id| !(1..=5).contains(id))
        );
        assert!(
            metadata
                .mls_proposals
                .iter()
                .all(|id| !(1..=7).contains(id))
        );
        assert!(metadata.mls_extensions.contains(&0xff01));
        assert!(metadata.mls_proposals.contains(&0xff02));
        let message = MlsMessageIn::tls_deserialize_exact(kp.bytes()).unwrap();
        let MlsMessageBodyIn::KeyPackage(kp) = message.extract() else {
            panic!("expected KeyPackage")
        };
        let kp = kp
            .validate(
                &openmls_rust_crypto::RustCrypto::default(),
                ProtocolVersion::Mls10,
            )
            .unwrap();
        assert_non_default_mls_capabilities(kp.leaf_node().capabilities());

        // Peers have no registry entries for defaults and do not advertise
        // them, but must be accepted when GroupContext explicitly requires them.
        let mut bob = build_profile_client_on_storage(
            b"bob",
            SqliteAccountStorage::in_memory_for_test().unwrap(),
            profile,
        );
        let bob_kp = bob.fresh_key_package().await.unwrap();
        let constructable = alice
            .constructable_capabilities(std::slice::from_ref(&bob_kp))
            .unwrap();
        assert!((1..=5).all(|id| constructable.extensions.contains(&id)));
        assert!((1..=7).all(|id| constructable.proposals.contains(&id)));
        let (group_id, result) = alice
            .create_group(CreateGroupRequest {
                name: "explicit default requirements".into(),
                description: String::new(),
                members: vec![bob_kp],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let welcomes = match result {
            SendResult::FoundingGroupCreated { welcomes } => welcomes,
            SendResult::GroupCreated { welcomes, pending } => {
                alice.confirm_published(pending).await.unwrap();
                welcomes
            }
            other => panic!("expected founding result, got {other:?}"),
        };
        bob.join_welcome(welcomes.into_iter().next().unwrap())
            .await
            .unwrap();
        let group = openmls::group::MlsGroup::load(
            storage.mls_storage(),
            &openmls::group::GroupId::from_slice(group_id.as_slice()),
        )
        .unwrap()
        .unwrap();
        assert_non_default_mls_capabilities(group.own_leaf_node().unwrap().capabilities());
        let required = group.extensions().required_capabilities().unwrap();
        assert!((1..=5).all(|id| {
            required
                .extension_types()
                .contains(&ExtensionType::from(id))
        }));
        assert!((1..=7).all(|id| {
            required
                .proposal_types()
                .contains(&openmls::prelude::ProposalType::from(id))
        }));
        let mut carol = build_profile_client_on_storage(
            b"carol",
            SqliteAccountStorage::in_memory_for_test().unwrap(),
            profile,
        );
        let result = alice
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![carol.fresh_key_package().await.unwrap()],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let SendResult::GroupEvolution {
            welcomes, pending, ..
        } = result
        else {
            panic!("expected invite")
        };
        alice.confirm_published(pending).await.unwrap();
        carol
            .join_welcome(welcomes.into_iter().next().unwrap())
            .await
            .unwrap();
        assert_eq!(carol.members(&group_id).unwrap().len(), 3);
    }
}

#[tokio::test]
async fn founding_leaves_omit_default_mls_capabilities() {
    for profile in [ProtocolProfile::Current, ProtocolProfile::Legacy] {
        let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
        let mut alice = build_profile_client_on_storage(b"alice", storage.clone(), profile);
        let (group_id, _) = alice
            .create_group(CreateGroupRequest {
                name: "capability advertisement".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let group = openmls::group::MlsGroup::load(
            storage.mls_storage(),
            &openmls::group::GroupId::from_slice(group_id.as_slice()),
        )
        .unwrap()
        .unwrap();
        assert_non_default_mls_capabilities(group.own_leaf_node().unwrap().capabilities());
        assert_eq!(
            group
                .own_leaf_node()
                .unwrap()
                .capabilities()
                .extensions()
                .contains(&ExtensionType::from(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE)),
            profile == ProtocolProfile::Legacy,
        );
        // RequiredCapabilities remains a valid GroupContext extension even
        // though its default type must not be advertised in LeafNode capabilities.
        let required = group.extensions().required_capabilities().unwrap();
        assert!(
            required
                .extension_types()
                .contains(&ExtensionType::AppDataDictionary)
        );
        assert!(
            required
                .proposal_types()
                .contains(&openmls::prelude::ProposalType::AppDataUpdate)
        );
    }
}

fn assert_non_default_mls_capabilities(capabilities: &Capabilities) {
    // RFC 9420 section 7.2: default extension ids 1..=5 and proposal ids
    // 1..=7 MUST NOT appear in the signed LeafNode capability lists.
    for extension in capabilities.extensions() {
        assert!(
            !(1..=5).contains(&u16::from(*extension)),
            "default extension {extension:?}"
        );
    }
    for proposal in capabilities.proposals() {
        assert!(
            !(1..=7).contains(&u16::from(*proposal)),
            "default proposal {proposal:?}"
        );
    }
    assert!(
        capabilities
            .extensions()
            .contains(&ExtensionType::AppDataDictionary)
    );
    assert!(
        capabilities
            .proposals()
            .contains(&openmls::prelude::ProposalType::AppDataUpdate)
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
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut alice = build_profile_client_on_storage(b"a", storage.clone(), ProtocolProfile::Legacy);
    let kp = alice.fresh_key_package().await.unwrap();
    let kept = alice.fresh_key_package().await.unwrap();

    alice.delete_key_package(&kp).await.unwrap();
    // Second delete: the bundle is already gone, but this still succeeds.
    alice.delete_key_package(&kp).await.unwrap();
    let owned =
        cgka_engine::key_package::durably_owned_key_packages(&storage, ProtocolProfile::Legacy)
            .unwrap();
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].bytes(), kept.bytes());
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
    let error = bob
        .join_welcome(welcome)
        .await
        .expect_err("join must fail after the key package bundle was deleted");
    assert!(matches!(error, EngineError::MissingWelcomeKeyPackage));
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
    let bob_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
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
    // Direct refusal marks its content terminal, so each route needs its own
    // genuine Welcome and KeyPackage rather than replaying the other refusal.
    for through_ingest in [false, true] {
        assert_required_capability_welcome_refusal(through_ingest).await;
    }
}

async fn assert_required_capability_welcome_refusal(through_ingest: bool) {
    // joining.md:65 / convergence.md:19 — a client MUST reject a Welcome whose
    // resulting group has active required capabilities it cannot apply.
    //
    // carol publishes a KeyPackage that advertises the SelfRemove proposal, so
    // alice's invite (which requires it) passes. carol then downgrades: she
    // rebuilds her engine on the same storage with an empty feature registry,
    // so her runtime no longer supports SelfRemove. Joining the group must now
    // be rejected.
    let mut alice = build_client(b"alice", selfremove_registry());
    let carol_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
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
    if through_ingest {
        assert!(matches!(
            downgraded_carol.ingest(welcome.clone()).await.unwrap(),
            cgka_traits::ingest::IngestOutcome::Ignored {
                category: cgka_traits::ingest::InputRejectionCategory::UnsupportedRequiredFeature
            }
        ));
        assert!(carol_storage.has_ingress_dedup_marker(&welcome.id).unwrap());
        assert!(matches!(
            downgraded_carol.ingest(welcome).await.unwrap(),
            cgka_traits::ingest::IngestOutcome::Ignored {
                category: cgka_traits::ingest::InputRejectionCategory::Duplicate
            }
        ));
        assert!(
            downgraded_carol
                .drain_events()
                .iter()
                .all(|event| !matches!(event, cgka_traits::engine::GroupEvent::GroupJoined { .. }))
        );
    } else {
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
    let carol_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
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
    let event = alice.confirm_published(pending).await.unwrap();
    assert!(matches!(
        event,
        cgka_traits::engine::GroupEvent::GroupCreated { .. }
    ));
    assert_eq!(alice.drain_events().len(), 1);
    assert_eq!(alice.epoch(&alice_gid).unwrap().0, 1);

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
            explicitly_confirmed: false,
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
    assert!(
        matches!(err, EngineError::Peeler(PeelerError::Malformed(reason))
        if reason == "welcome not addressed to this client")
    );
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

    let mut alice = EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
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
                expected_epoch: None,
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
}

/// An account with several devices is one recipient of the main message: its
/// ref appears once and the count is of accounts, not leaves.
#[tokio::test]
async fn audit_log_recipient_expectation_counts_each_account_once() {
    use marmot_forensics::{AuditEvent, AuditEventKind, MessageArtifactKind};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let recorder =
        marmot_forensics::JsonlRecorder::open(&path, "test-engine-devices".to_string()).unwrap();
    let mut alice = EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
        .legacy_compatibility_profile()
        .identity(pad32(b"alice"))
        .account_identity_proof_signer(proof_signer(b"alice"))
        .peeler(Box::new(MockPeeler::default()))
        .recorder(Box::new(recorder))
        .build()
        .expect("build alice with recorder");
    let mut bob_phone = build_client(b"bob", FeatureRegistry::new());
    let mut bob_laptop = build_client(b"bob", FeatureRegistry::new());
    let (gid, result) = alice
        .create_group_with_audit_context(
            CreateGroupRequest {
                name: "g".into(),
                description: String::new(),
                members: vec![
                    bob_phone.fresh_key_package().await.unwrap(),
                    bob_laptop.fresh_key_package().await.unwrap(),
                ],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            },
            None,
        )
        .await
        .expect("create group with both of bob's devices");
    let SendResult::GroupCreated { pending, welcomes } = result else {
        panic!("expected GroupCreated")
    };
    assert_eq!(welcomes.len(), 2);
    alice.confirm_published(pending).await.unwrap();
    let payload = app_payload_for(&alice, b"hello");
    alice
        .send_with_audit_context(
            cgka_traits::engine::SendIntent::AppMessage {
                group_id: gid.clone(),
                payload,
                expected_epoch: None,
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
    let expectations: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.kind {
            AuditEventKind::RecipientExpectation { expectation, .. } => Some(expectation),
            _ => None,
        })
        .collect();
    assert_eq!(
        expectations
            .iter()
            .filter(|e| e.artifact_kind == MessageArtifactKind::Welcome)
            .count(),
        2
    );
    let app_message = expectations
        .iter()
        .find(|e| e.artifact_kind == MessageArtifactKind::ApplicationMessage)
        .expect("app message recipient_expectation recorded");
    assert_eq!(app_message.expected_count, Some(1));
    assert_eq!(app_message.expected_member_refs.len(), 1);
}

/// The strict-cutover Invite gate reads the durable group record to check its
/// profile. With no record (`get_group` -> `NotFound`) the gate must fail
/// with that storage error rather than fall through to later stages.
#[tokio::test]
async fn current_invite_to_unknown_group_fails_on_missing_record() {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut current = build_profile_client_on_storage(
        b"missing-record-invite",
        storage.clone(),
        ProtocolProfile::Current,
    );
    let unknown = GroupId::new(vec![0xAB; 16]);
    assert!(matches!(
        storage.get_group(&unknown),
        Err(cgka_traits::storage::StorageError::NotFound)
    ));

    let error = current
        .send(SendIntent::Invite {
            group_id: unknown,
            key_packages: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("invite to an unknown group must fail");
    assert!(
        matches!(
            error,
            EngineError::Storage(cgka_traits::storage::StorageError::NotFound)
        ),
        "expected missing-record error, got {error:?}"
    );
}

/// A recipient replays both authenticated commits in one pass, including the
/// earlier activity after the closing disband deletes live MLS state.
#[tokio::test]
async fn one_convergence_pass_preserves_rename_before_disband() {
    use cgka_traits::engine::{GroupEvent, GroupStateChange};
    use cgka_traits::types::EpochId;
    use sha2::{Digest, Sha256};

    let clock = ManualConvergenceClock::new(0, 10_000);
    let build = |seed: &[u8]| {
        EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
            .identity(pad32(seed))
            .account_identity_proof_signer(proof_signer(seed))
            .protocol_profile(ProtocolProfile::Current)
            .peeler(Box::new(MockPeeler::default()))
    };
    let mut alice = build(b"alice-one-pass-disband")
        .convergence_clock(Arc::new(clock.clone()))
        .build()
        .unwrap();
    let mut bob = build(b"bob-one-pass-disband").build().unwrap();
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "before rename".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match created {
        SendResult::FoundingGroupCreated { mut welcomes } => welcomes.remove(0),
        other => panic!("expected founding Welcome, got {other:?}"),
    };
    assert_eq!(bob.join_welcome(welcome).await.unwrap(), group_id);
    alice.drain_events();
    bob.drain_events();
    let (mut rename, pending) = match alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("after rename".into()),
            description: None,
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected rename, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    let author_events = alice.drain_events();
    let author_rename = author_events
        .iter()
        .find_map(|event| match event {
            GroupEvent::GroupStateChanged {
                group_id,
                epoch,
                actor,
                change,
                ..
            } if matches!(change, GroupStateChange::GroupRenamed { .. }) => Some(
                cgka_traits::app_event::group_system_event_material(
                    group_id,
                    epoch.0,
                    actor.as_ref(),
                    change,
                )
                .unwrap()
                .message_id_hex,
            ),
            _ => None,
        })
        .unwrap();
    alice
        .send(SendIntent::Disband {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let mut prepared = None;
    for _ in 0..8 {
        let sends = alice.advance_convergence(&group_id).await.unwrap();
        match sends.as_slice() {
            [] => clock.advance_ms(1_000),
            [
                SendResult::GroupEvolution {
                    msg,
                    pending,
                    welcomes,
                },
            ] => {
                assert!(welcomes.is_empty());
                prepared = Some((msg.clone(), *pending));
                break;
            }
            other => panic!("unexpected sends: {other:?}"),
        }
    }
    let (mut disband, pending) = prepared.expect("scheduler prepared disband");
    alice.confirm_published(pending).await.unwrap();
    for msg in [&mut rename, &mut disband] {
        msg.envelope = TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        };
    }
    let rename_id = MessageId::new(Sha256::digest(&rename.payload).to_vec());
    let disband_id = MessageId::new(Sha256::digest(&disband.payload).to_vec());
    bob.buffer_openmls_convergence_message_at(&group_id, disband, 1_000)
        .unwrap();
    bob.buffer_openmls_convergence_message_at(&group_id, rename, 1_000)
        .unwrap();
    assert_eq!(bob.epoch(&group_id).unwrap(), EpochId(1));
    assert!(bob.drain_events().is_empty());
    let result = bob
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    assert_eq!(
        result.accepted_commits,
        vec![
            hex::encode(rename_id.as_slice()),
            hex::encode(disband_id.as_slice())
        ]
    );
    let events = bob.drain_events();
    let changes = events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::GroupStateChanged {
                group_id,
                epoch,
                actor,
                change,
                origin_commit_id,
            } => Some((group_id, epoch, actor, change, origin_commit_id)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(changes.len(), 2, "unexpected activity: {events:?}");
    for (index, (group, epoch, actor, change, origin)) in changes.iter().enumerate() {
        assert_eq!(*group, &group_id);
        assert_eq!(**epoch, EpochId(2 + index as u64));
        assert_eq!(actor.as_ref(), Some(&alice.self_id()));
        assert_eq!(
            origin.as_ref(),
            Some(if index == 0 { &rename_id } else { &disband_id })
        );
        if index == 0 {
            assert!(matches!(change, GroupStateChange::GroupRenamed { .. }));
            assert_eq!(
                cgka_traits::app_event::group_system_event_material(
                    group,
                    epoch.0,
                    actor.as_ref(),
                    change
                )
                .unwrap()
                .message_id_hex,
                author_rename
            );
        } else {
            assert_eq!(**change, GroupStateChange::GroupDisbanded);
        }
    }
    assert!(!events.iter().any(|event| matches!(
        event,
        GroupEvent::LocalGroupCopyTerminated { .. }
            | GroupEvent::LocalGroupCopyRestored { .. }
            | GroupEvent::GroupMemberLeavesRemoved { .. }
    )));
    let terminal = bob.group_record(&group_id).unwrap();
    assert_eq!(terminal.name, "after rename");
    assert!(terminal.disbanded.is_some());
    assert!(!terminal.removed);
    assert_eq!(terminal.members.len(), 2);
    assert!(bob.advance_convergence(&group_id).await.unwrap().is_empty());
    assert!(bob.drain_events().is_empty());
}

#[tokio::test]
async fn exporter_secret_returns_full_cached_secret_at_exact_length() {
    let mut alice = build_profile_client_on_storage(
        b"alice-context-view",
        SqliteAccountStorage::in_memory_for_test().unwrap(),
        ProtocolProfile::Legacy,
    );
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, .. } = created else {
        panic!("expected a legacy creation");
    };
    alice.confirm_published(pending).await.unwrap();
    let ctx = alice.group_context(&group_id).unwrap();
    let secret = ctx
        .exporter_secret("marmot/group-event", 32)
        .expect("32-byte cached exporter");
    assert_eq!(secret.len(), 32);
}

#[tokio::test]
async fn snapshot_names_do_not_embed_plaintext_group_id() {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut alice = build_client_on_storage(b"alice", FeatureRegistry::new(), storage.clone());
    let mut bob = build_client(b"bob", FeatureRegistry::new());
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, created) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, .. } = created else {
        panic!("expected a legacy creation");
    };
    alice.confirm_published(pending).await.unwrap();

    // Exercise snapshot creation on founding, invitation and profile update.
    let mut carol = build_client(b"carol", FeatureRegistry::new());
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invited = alice
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupEvolution { pending, .. } = invited else {
        panic!("expected an invitation commit");
    };
    alice.confirm_published(pending).await.unwrap();
    let updated = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("renamed".into()),
            description: None,
        })
        .await
        .unwrap();
    let SendResult::GroupEvolution { pending, .. } = updated else {
        panic!("expected a profile commit");
    };
    alice.confirm_published(pending).await.unwrap();
    let snapshots = storage.list_group_snapshots(&gid).unwrap();
    assert!(
        !snapshots.is_empty(),
        "we expect at least one retained-anchor snapshot"
    );
    let plaintext_id = hex::encode(gid.as_slice());
    for name in &snapshots {
        assert!(
            !name.contains(&plaintext_id),
            "snapshot name must not embed plaintext group id"
        );
    }
}

#[tokio::test]
async fn group_context_exports_the_staged_source_then_confirmation_or_rollback() {
    use cgka_traits::types::EpochId;
    const DOMAINS: [(&str, &[u8]); 3] = [
        ("marmot/group-event", b"group-event"),
        ("marmot/encrypted-media", b"encrypted-media"),
        ("marmot/agent-text-stream-quic", b"agent-text-stream-quic"),
    ];
    fn checked_context(
        engine: &Engine<SqliteAccountStorage>,
        storage: &SqliteAccountStorage,
        group_id: &GroupId,
        epoch: u64,
        pending: bool,
        route: &[u8],
    ) -> GroupContextSnapshot {
        let group = openmls::group::MlsGroup::load(
            storage.mls_storage(),
            &openmls::group::GroupId::from_slice(group_id.as_slice()),
        )
        .unwrap()
        .unwrap();
        let crypto = openmls_rust_crypto::RustCrypto::default();
        let context = engine.group_context(group_id).unwrap();
        assert_eq!(context.epoch(), EpochId(epoch));
        assert_eq!(context.transport_group_id().as_deref(), Some(route));
        for (label, exporter_context) in DOMAINS {
            let expected = if pending {
                group.pending_commit().unwrap().export_secret(
                    &crypto,
                    "marmot",
                    exporter_context,
                    32,
                )
            } else {
                group.export_secret(&crypto, "marmot", exporter_context, 32)
            }
            .unwrap();
            let actual = context
                .exporter_secret(label, 32)
                .expect("every exporter domain is present");
            assert!(
                actual.as_slice() == expected,
                "{label} must use its specified MLS source and domain"
            );
        }
        let snapshot =
            GroupContextSnapshot::from_context(context.as_ref(), &DOMAINS.map(|(label, _)| label));
        for (i, (left, _)) in DOMAINS.iter().enumerate() {
            for (right, _) in DOMAINS.iter().skip(i + 1) {
                assert!(snapshot.exporter_secret(left) != snapshot.exporter_secret(right));
            }
        }
        snapshot
    }
    for confirm in [false, true] {
        let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
        let components = default_group_components()
            .into_iter()
            .chain([NOSTR_ROUTING_COMPONENT_ID])
            .collect::<Vec<_>>();
        let mut alice = EngineBuilder::new(storage.clone())
            .legacy_compatibility_profile()
            .identity(pad32(b"context-source-alice"))
            .account_identity_proof_signer(proof_signer(b"context-source-alice"))
            .supported_app_components(components.clone())
            .peeler(Box::new(MockPeeler::default()))
            .build()
            .unwrap();
        let mut bob = build_client_with_components(b"context-source-bob", components);
        let route = [0x5a; 32];
        let (group_id, created) = alice
            .create_group(CreateGroupRequest {
                name: "context sources".into(),
                description: String::new(),
                members: vec![bob.fresh_key_package().await.unwrap()],
                required_features: vec![],
                app_components: vec![AppComponentData {
                    component_id: NOSTR_ROUTING_COMPONENT_ID,
                    data: encode_nostr_routing_v1(
                        &NostrRoutingV1::new(route, vec!["wss://relay.example".into()]).unwrap(),
                    )
                    .unwrap(),
                }],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let SendResult::GroupCreated {
            pending,
            mut welcomes,
        } = created
        else {
            panic!("expected a legacy founding publication");
        };
        alice.confirm_published(pending).await.unwrap();
        assert_eq!(
            bob.join_welcome(welcomes.remove(0)).await.unwrap(),
            group_id
        );
        assert_ne!(group_id.as_slice(), route);
        let before = checked_context(&alice, &storage, &group_id, 1, false, &route);
        let bob_context = bob.group_context(&group_id).unwrap();
        assert_eq!(
            GroupContextSnapshot::from_context(
                bob_context.as_ref(),
                &DOMAINS.map(|(label, _)| label)
            ),
            before
        );
        drop(bob_context);
        let SendResult::GroupEvolution { pending, .. } = alice
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("self update must stage an MLS commit");
        };
        let staged = checked_context(&alice, &storage, &group_id, 2, true, &route);
        for (label, _) in DOMAINS {
            assert!(before.exporter_secret(label) != staged.exporter_secret(label));
        }
        if confirm {
            alice.confirm_published(pending).await.unwrap();
            assert_eq!(
                checked_context(&alice, &storage, &group_id, 2, false, &route),
                staged
            );
        } else {
            alice.publish_failed(pending).await.unwrap();
            assert_eq!(
                checked_context(&alice, &storage, &group_id, 1, false, &route),
                before
            );
        }
    }
}

#[tokio::test]
async fn creator_refuses_unsupported_required_and_optional_components_before_state() {
    const UNSUPPORTED: u16 = 0xf411;
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut alice = build_profile_client_on_storage(
        b"creator-admission",
        storage.clone(),
        ProtocolProfile::Current,
    );
    let retained = alice.fresh_key_package().await.unwrap();
    for optional in [false, true] {
        let component = AppComponentData {
            component_id: UNSUPPORTED,
            data: vec![1],
        };
        let request = CreateGroupRequest {
            name: "refused".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: if optional {
                vec![]
            } else {
                vec![component.clone()]
            },
            initial_admins: vec![],
        };
        let result = alice
            .create_group_with_optional_app_components(
                request,
                if optional { vec![component] } else { vec![] },
            )
            .await;
        assert!(
            matches!(result, Err(EngineError::MissingRequiredCapabilities { required, had })
            if required.app_components.contains(UNSUPPORTED) && !had.app_components.contains(UNSUPPORTED))
        );
        assert!(storage.list_groups().unwrap().is_empty());
        assert!(alice.live_group_ids().unwrap().is_empty());
        assert!(alice.outstanding_sent_welcomes().unwrap().is_empty());
        assert!(alice.drain_events().is_empty());
        let owned = cgka_engine::key_package::durably_owned_key_packages(
            &storage,
            ProtocolProfile::Current,
        )
        .unwrap();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].bytes(), retained.bytes());
    }
    let chosen = GroupId::new(vec![0x61, 0x62, 0x63]);
    let (group_id, result) = alice
        .create_group_with_chosen_id_and_audit_context(
            CreateGroupRequest {
                name: "valid retry".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            },
            chosen.clone(),
            None,
            Timestamp(u64::MAX),
            None,
        )
        .await
        .unwrap();
    assert_eq!(group_id, chosen);
    assert!(matches!(result, SendResult::FoundingGroupCreated { welcomes } if welcomes.is_empty()));
    assert_eq!(alice.group_record(&group_id).unwrap().epoch.0, 0);
}

#[tokio::test]
async fn encrypted_engine_reopen_reuses_identity_proof_in_fresh_key_packages() {
    use cgka_engine::account_identity_proof::{
        AccountIdentityProofRequest, AccountIdentityProofSigner,
    };
    use cgka_traits::storage::AccountDeviceSignerStorage;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct SignOnce {
        inner: Arc<dyn AccountIdentityProofSigner>,
        calls: AtomicUsize,
    }
    impl AccountIdentityProofSigner for SignOnce {
        fn sign_account_identity_proof(
            &self,
            request: &AccountIdentityProofRequest,
        ) -> Result<[u8; 64], String> {
            if self.calls.fetch_add(1, Ordering::SeqCst) != 0 {
                return Err("EXTERNAL_SIGNER_REJECTED: unexpected second proof request".into());
            }
            self.inner.sign_account_identity_proof(request)
        }
    }
    fn proof_from_key_package(kp: &cgka_traits::engine::KeyPackage) -> Vec<u8> {
        let message = MlsMessageIn::tls_deserialize_exact(kp.bytes()).unwrap();
        let MlsMessageBodyIn::KeyPackage(key_package) = message.extract() else {
            panic!("expected KeyPackage");
        };
        let key_package = key_package
            .validate(
                &openmls_rust_crypto::RustCrypto::default(),
                ProtocolVersion::Mls10,
            )
            .unwrap();
        key_package
            .leaf_node()
            .extensions()
            .app_data_dictionary()
            .unwrap()
            .dictionary()
            .get(&ACCOUNT_IDENTITY_PROOF_COMPONENT_ID)
            .unwrap()
            .to_vec()
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::new("engine proof reopen test").unwrap();
    let seed = b"proof-reopen";
    let signer = Arc::new(SignOnce {
        inner: proof_signer(seed),
        calls: AtomicUsize::new(0),
    });
    let original = {
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let mut engine = EngineBuilder::new(storage.clone())
            .identity(pad32(seed))
            .account_identity_proof_signer(signer.clone())
            .peeler(Box::new(MockPeeler::default()))
            .build()
            .unwrap();
        let proof = proof_from_key_package(&engine.fresh_key_package().await.unwrap());
        drop(engine);
        storage.close().unwrap();
        proof
    };
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let binding = storage
        .account_device_signer(&MemberId::new(pad32(seed)))
        .unwrap()
        .unwrap();
    assert_eq!(
        binding.account_identity_proof.as_deref(),
        Some(original.as_slice())
    );
    let mut engine = EngineBuilder::new(storage.clone())
        .identity(pad32(seed))
        .account_identity_proof_signer(signer.clone())
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    let fresh = engine.fresh_key_package().await.unwrap();
    assert_eq!(proof_from_key_package(&fresh), original);
    assert_eq!(
        key_package_metadata(&fresh).unwrap().protocol_profile,
        ProtocolProfile::Current
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
}

/// Failed founding must not steal an existing group's transport route, even
/// when the failed request names that already-used, valid routing handle.
#[tokio::test]
async fn failed_legacy_founding_preserves_an_existing_live_route() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("founding-route-rollback.sqlite");
    let key = SqlCipherKey::raw([0x86; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
    let supported = default_group_components()
        .into_iter()
        .chain([NOSTR_ROUTING_COMPONENT_ID])
        .collect::<Vec<_>>();
    let build = |identity: &[u8], storage| {
        EngineBuilder::new(storage)
            .identity(pad32(identity))
            .account_identity_proof_signer(proof_signer(identity))
            .supported_app_components(supported.clone())
            .protocol_profile(ProtocolProfile::Legacy)
            .legacy_compatibility_profile()
            .peeler(Box::<MockPeeler>::default())
            .build()
            .unwrap()
    };
    let mut alice = build(b"route-rollback-alice", storage.clone());
    let mut bob = build(
        b"route-rollback-bob",
        SqliteAccountStorage::in_memory_for_test().unwrap(),
    );
    let mut carol = build(
        b"route-rollback-carol",
        SqliteAccountStorage::in_memory_for_test().unwrap(),
    );
    let mut dave = build(
        b"route-rollback-dave",
        SqliteAccountStorage::in_memory_for_test().unwrap(),
    );
    let route = [0x86; 32];
    let component = AppComponentData {
        component_id: NOSTR_ROUTING_COMPONENT_ID,
        data: encode_nostr_routing_v1(
            &NostrRoutingV1::new(route, vec!["wss://relay.example".into()]).unwrap(),
        )
        .unwrap(),
    };
    let (existing_group, created) = alice
        .create_group(CreateGroupRequest {
            name: "existing routed group".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![component.clone()],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated {
        pending,
        mut welcomes,
    } = created
    else {
        panic!("expected legacy group")
    };
    alice.confirm_published(pending).await.unwrap();
    assert_eq!(
        bob.join_welcome(welcomes.remove(0)).await.unwrap(),
        existing_group
    );
    alice.drain_events();
    let observer = rusqlite::Connection::open(&database).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &observer,
        &key,
        storage_sqlite::SqlCipherHardening::live_cache(),
    )
    .unwrap();
    let routes = || {
        observer.prepare("SELECT transport_group_id, group_id, source_epoch FROM cgka_transport_group_routes ORDER BY transport_group_id").unwrap()
            .query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?))).unwrap()
            .collect::<Result<Vec<_>, _>>().unwrap()
    };
    let routes_before = routes();
    assert_eq!(routes_before.len(), 1);
    assert_eq!(routes_before[0].0, route);
    assert_eq!(routes_before[0].1, existing_group.as_slice());
    observer.execute_batch(
        "CREATE TRIGGER fail_second_route_welcome BEFORE INSERT ON cgka_messages
         WHEN (SELECT COUNT(*) FROM cgka_messages WHERE group_id = NEW.group_id) = 1
          AND (SELECT json_array_length(json_extract(record, '$.members')) FROM cgka_groups WHERE id = NEW.group_id) = 3
         BEGIN SELECT RAISE(ABORT, 'founding-route-welcome-fault'); END;"
    ).unwrap();
    let failed = alice
        .create_group(CreateGroupRequest {
            name: "failed routed group".into(),
            description: String::new(),
            members: vec![
                carol.fresh_key_package().await.unwrap(),
                dave.fresh_key_package().await.unwrap(),
            ],
            required_features: vec![],
            app_components: vec![component],
            initial_admins: vec![],
        })
        .await;
    assert!(
        matches!(&failed, Err(EngineError::Storage(cgka_traits::storage::StorageError::Backend(detail)))
        if detail.contains("founding-route-welcome-fault")),
        "wrong failure: {failed:?}"
    );
    assert_eq!(
        alice.live_group_ids().unwrap(),
        vec![existing_group.clone()]
    );
    assert_eq!(storage.list_groups().unwrap().len(), 1);
    assert!(alice.drain_events().is_empty());
    // This input is real peer traffic from the surviving group. No failed
    // operation's unreturned Welcome or private cache contents are fabricated.
    let sent = bob
        .send(SendIntent::AppMessage {
            group_id: existing_group.clone(),
            payload: app_payload_for(&bob, b"live route after failed creation"),
            expected_epoch: None,
        })
        .await
        .unwrap();
    let SendResult::ApplicationMessage { msg, .. } = sent else {
        panic!("expected application")
    };
    assert!(
        matches!(&msg.envelope, TransportEnvelope::GroupMessage {transport_group_id} if transport_group_id == &route)
    );
    assert_eq!(
        alice.ingest(msg).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Processed,
        "failed creation displaced a live group's route"
    );
    assert_eq!(
        routes(),
        routes_before,
        "failed creation replaced the existing durable route"
    );
    drop(alice);
    drop(observer);
    storage.close().unwrap();
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
    let mut reopened = build(b"route-rollback-alice", storage);
    reopened.hydrate_all_stored_groups().unwrap();
    assert_eq!(
        reopened.live_group_ids().unwrap(),
        vec![existing_group.clone()]
    );
    let sent = bob
        .send(SendIntent::AppMessage {
            group_id: existing_group,
            payload: app_payload_for(&bob, b"live route after encrypted reopen"),
            expected_epoch: None,
        })
        .await
        .unwrap();
    let SendResult::ApplicationMessage { msg, .. } = sent else {
        panic!("expected application")
    };
    assert_eq!(
        reopened.ingest(msg).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Processed
    );
}
