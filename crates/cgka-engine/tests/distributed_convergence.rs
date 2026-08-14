//! Engine integration for stored-message distributed convergence.

use async_trait::async_trait;
use cgka_engine::canonicalization::{
    CanonicalizationError, CanonicalizationPolicy, ConvergenceStatus, DeferredMessageReason,
    DroppedMessageReason, InvalidatedAppMessageReason, MessageKind, V1_MAX_CONVERGENCE_PASS_MS,
    V1_SETTLEMENT_QUIESCENCE_MS,
};
use cgka_engine::convergence::{ConvergencePolicy, ConvergencePolicyError};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::openmls_projection::{OpenMlsProjectionError, project_mls_message};
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_engine::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder, ManualConvergenceClock};
use cgka_traits::app_components::{AppComponentId, GROUP_ADMIN_POLICY_COMPONENT_ID};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{
    AppMessageInvalidationReason, CgkaEngine, CreateGroupRequest, GroupEvent, SendIntent,
    SendResult,
};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerStorage, ConvergencePassStorage, GroupStorage, MessageStorage,
    OutboundIntentStorage, QueuedOutboundIntent, StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use marmot_forensics::{AuditEvent, AuditEventKind, JsonlRecorder};
use openmls::component::ComponentData;
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension, Extension, Extensions};
use openmls::group::{
    AppDataUpdateValidationError, CreateCommitError, CreateGroupContextExtProposalError, MlsGroup,
};
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::BasicCredential;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use storage_sqlite::SqliteAccountStorage;
use tls_codec::Serialize as _;

mod support;
use support::proof_signer;

fn pad32(name: &[u8]) -> Vec<u8> {
    // Marmot credential identities MUST be a valid 32-byte x-only secp256k1
    // public key (spec/foundation/identity.md). Derive one deterministically
    // from the ergonomic label so admin/member tracking stays stable across a
    // run while the engine accepts the identity.
    use k256::schnorr::SigningKey;
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
struct EpochGatePeeler;

fn commit_tiebreak_winner_index(first: &MemberId, second: &MemberId) -> usize {
    if first.as_slice() < second.as_slice() {
        0
    } else {
        1
    }
}

fn committer_wins(challenger: &MemberId, incumbent: &MemberId) -> bool {
    challenger.as_slice() < incumbent.as_slice()
}

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

fn encode_admin_policy_for_test(admins: &[MemberId]) -> Vec<u8> {
    let mut admins = admins
        .iter()
        .map(|admin| admin.as_slice().to_vec())
        .collect::<Vec<_>>();
    admins.sort();
    admins.dedup();
    let mut admin_bytes = Vec::with_capacity(admins.len() * 32);
    for admin in admins {
        assert_eq!(admin.len(), 32);
        admin_bytes.extend_from_slice(&admin);
    }
    let mut out = Vec::new();
    cgka_traits::app_components::encode_quic_varint(admin_bytes.len() as u64, &mut out);
    out.extend_from_slice(&admin_bytes);
    out
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
            source: TransportSource("mock".into()),
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
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

#[async_trait]
impl TransportPeeler for EpochGatePeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        if let Ok(projection) = project_mls_message(&msg.payload)
            && let Some(source_epoch) = projection.source_epoch
            && ctx.epoch().0 < source_epoch
        {
            return Err(PeelerError::DecryptFailed);
        }
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
            source: TransportSource("mock".into()),
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
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

fn selfremove_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r
}

fn build_client(id: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = build_client_with_storage(id, storage.clone());
    (engine, storage)
}

fn build_epoch_gate_client(id: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(EpochGatePeeler))
        .build()
        .unwrap();
    (engine, storage)
}

fn build_client_with_storage(
    id: &[u8],
    storage: SqliteAccountStorage,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

fn build_client_with_storage_and_recorder(
    id: &[u8],
    storage: SqliteAccountStorage,
    recorder: JsonlRecorder,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .recorder(Box::new(recorder))
        .build()
        .unwrap()
}

fn build_client_with_storage_and_clock(
    id: &[u8],
    storage: SqliteAccountStorage,
    clock: ManualConvergenceClock,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .convergence_clock(Arc::new(clock))
        .build()
        .unwrap()
}

fn build_client_with_max_past_epochs(
    id: &[u8],
    storage: SqliteAccountStorage,
    max_past_epochs: usize,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .max_past_epochs(max_past_epochs)
        .build()
        .unwrap()
}

fn raw_remove_members_commit(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    targets: &[MemberId],
) -> TransportMessage {
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load sender MLS group")
        .expect("sender joined group");
    let binding = storage
        .account_device_signer(sender)
        .expect("load signer binding")
        .expect("signer binding exists");
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .expect("MLS signer exists");

    let mut leaf_indices = Vec::new();
    for member in mls_group.members() {
        let credential =
            BasicCredential::try_from(member.credential).expect("member uses BasicCredential");
        if targets
            .iter()
            .any(|target| target.as_slice() == credential.identity())
        {
            leaf_indices.push(member.index);
        }
    }
    assert_eq!(
        leaf_indices.len(),
        targets.len(),
        "raw test commit must find every removal target"
    );

    let (commit, _welcome, _group_info) = mls_group
        .remove_members(&provider, &signer, &leaf_indices)
        .expect("raw OpenMLS remove commit");
    let payload = commit
        .tls_serialize_detached()
        .expect("serialize raw remove commit");
    TransportMessage {
        id: hash_id(&payload),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("raw-openmls-remove".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

/// Raw OpenMLS application message from `sender`'s current group state whose
/// inner payload the test controls entirely — the engine `send` path would
/// refuse a payload whose `MarmotAppEvent.pubkey` differs from the sender's
/// own id, so forged-attribution payloads must be built at the OpenMLS layer.
fn raw_app_message_with_payload(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    payload: &[u8],
) -> TransportMessage {
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load sender MLS group")
        .expect("sender joined group");
    let binding = storage
        .account_device_signer(sender)
        .expect("load signer binding")
        .expect("signer binding exists");
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .expect("MLS signer exists");
    let msg = mls_group
        .create_message(&provider, &signer, payload)
        .expect("raw OpenMLS application message");
    let payload = msg
        .tls_serialize_detached()
        .expect("serialize raw app message");
    TransportMessage {
        id: hash_id(&payload),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("raw-openmls-app".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

/// Assert that OpenMLS rejects a commit that removes `targets` and ALSO replaces the
/// GroupContext extensions with a copy that drops the `app_data_dictionary`
/// entirely, so the resulting epoch carries no admin-policy bytes at all.
///
/// This used to construct a malicious wire commit for the MDK receive seams.
/// OpenMLS upstream commit 34222ef6 now enforces the draft rule during both
/// construction and receive-side staging, so the public API can no longer
/// produce that fixture.
fn assert_openmls_rejects_remove_members_commit_dropping_app_data_dictionary(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    targets: &[MemberId],
) {
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load sender MLS group")
        .expect("sender joined group");
    let binding = storage
        .account_device_signer(sender)
        .expect("load signer binding")
        .expect("signer binding exists");
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .expect("MLS signer exists");

    let mut leaf_indices = Vec::new();
    for member in mls_group.members() {
        let credential =
            BasicCredential::try_from(member.credential).expect("member uses BasicCredential");
        if targets
            .iter()
            .any(|target| target.as_slice() == credential.identity())
        {
            leaf_indices.push(member.index);
        }
    }
    assert_eq!(
        leaf_indices.len(),
        targets.len(),
        "raw test commit must find every removal target"
    );

    let mut stripped_extensions = mls_group.extensions().clone();
    stripped_extensions.remove(openmls::extensions::ExtensionType::AppDataDictionary);
    let result = mls_group
        .commit_builder()
        .propose_removals(leaf_indices)
        .propose_group_context_extensions(stripped_extensions)
        .expect("propose GCE without app_data_dictionary")
        .load_psks(provider.storage())
        .expect("load PSKs")
        .build(provider.rand(), provider.crypto(), &signer, |_| true);
    let error = match result {
        Ok(_) => panic!("OpenMLS accepted remove+GCE commit that drops app_data_dictionary"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        CreateCommitError::AppDataUpdateValidationError(
            AppDataUpdateValidationError::CannotUpdateDictionaryDirectly
        )
    );
}

fn raw_remove_members_commit_with_admin_policy(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    targets: &[MemberId],
    resulting_admins: &[MemberId],
) -> TransportMessage {
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load sender MLS group")
        .expect("sender joined group");
    let binding = storage
        .account_device_signer(sender)
        .expect("load signer binding")
        .expect("signer binding exists");
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .expect("MLS signer exists");

    let mut leaf_indices = Vec::new();
    for member in mls_group.members() {
        let credential =
            BasicCredential::try_from(member.credential).expect("member uses BasicCredential");
        if targets
            .iter()
            .any(|target| target.as_slice() == credential.identity())
        {
            leaf_indices.push(member.index);
        }
    }
    assert_eq!(
        leaf_indices.len(),
        targets.len(),
        "raw test commit must find every removal target"
    );

    let admin_update = Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
        GROUP_ADMIN_POLICY_COMPONENT_ID,
        encode_admin_policy_for_test(resulting_admins),
    )));
    let mut builder = mls_group
        .commit_builder()
        .propose_removals(leaf_indices)
        .add_proposal(admin_update)
        .load_psks(provider.storage())
        .expect("load PSKs");
    let mut app_data = builder.app_data_dictionary_updater();
    for proposal in builder.app_data_update_proposals() {
        if let AppDataUpdateOperation::Update(data) = proposal.operation() {
            app_data.set(ComponentData::from_parts(
                proposal.component_id(),
                data.clone(),
            ));
        }
    }
    builder.with_app_data_dictionary_updates(app_data.changes());
    let commit_bundle = builder
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .expect("build raw remove+admin-policy commit")
        .stage_commit(&provider)
        .expect("stage raw remove+admin-policy commit");
    let (commit, _welcome, _group_info) = commit_bundle.into_contents();
    let payload = commit
        .tls_serialize_detached()
        .expect("serialize raw remove+admin-policy commit");
    TransportMessage {
        id: hash_id(&payload),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("raw-openmls-remove-admin-policy".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

/// How a GroupContextExtensions commit attempts to tamper with the group's
/// `app_data_dictionary`.
enum GceDictionaryTamper {
    /// Replace the extensions with a set omitting the dictionary entirely.
    StripDictionary,
    /// Keep the dictionary but omit one component's entry.
    DropEntry(AppComponentId),
    /// Keep the dictionary and every entry present, but rewrite one
    /// component's bytes — no `AppDataUpdate` proposal carries the change.
    ReplaceEntry(AppComponentId, Vec<u8>),
}

/// Assert that OpenMLS rejects a GroupContextExtensions-only commit (no member
/// changes) that tampers with the app-data dictionary.
fn assert_openmls_rejects_group_context_extensions_tamper(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    tamper: GceDictionaryTamper,
) {
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load sender MLS group")
        .expect("sender joined group");
    let binding = storage
        .account_device_signer(sender)
        .expect("load signer binding")
        .expect("signer binding exists");
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .expect("MLS signer exists");

    let mut new_extensions: Vec<Extension> = mls_group
        .extensions()
        .iter()
        .filter(|ext| !matches!(ext, Extension::AppDataDictionary(_)))
        .cloned()
        .collect();
    match &tamper {
        GceDictionaryTamper::StripDictionary => {}
        GceDictionaryTamper::DropEntry(target) | GceDictionaryTamper::ReplaceEntry(target, _) => {
            let current = mls_group
                .extensions()
                .app_data_dictionary()
                .expect("group carries app_data_dictionary");
            let mut dict = AppDataDictionary::new();
            for entry in current.dictionary().entries() {
                if entry.id() == *target {
                    if let GceDictionaryTamper::ReplaceEntry(_, data) = &tamper {
                        dict.insert(entry.id(), data.clone());
                    }
                    continue;
                }
                dict.insert(entry.id(), entry.data().to_vec());
            }
            new_extensions.push(Extension::AppDataDictionary(
                AppDataDictionaryExtension::new(dict),
            ));
        }
    }
    let new_extensions = Extensions::from_vec(new_extensions).expect("tampered extensions build");

    let error = match mls_group.update_group_context_extensions(&provider, new_extensions, &signer)
    {
        Ok(_) => panic!("OpenMLS accepted direct app_data_dictionary tamper"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CreateGroupContextExtProposalError::CreateCommitError(
            CreateCommitError::AppDataUpdateValidationError(
                AppDataUpdateValidationError::CannotUpdateDictionaryDirectly
            )
        )
    ));
}

#[tokio::test]
async fn engine_converges_stored_openmls_messages_to_selected_branch() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = evolution(alice_invite);
    let (bob_commit, bob_pending) = evolution(bob_invite);
    let commit_messages = [
        route(alice_commit.clone(), &group_id),
        route(bob_commit.clone(), &group_id),
    ];

    // Give the app witness to the branch that would otherwise lose the
    // same-epoch authenticated committer tie-break, proving witnesses still
    // override the final tie-breaker.
    let app_branch_index = 1 - commit_tiebreak_winner_index(&alice.self_id(), &bob.self_id());
    let quiet_branch_index = 1 - app_branch_index;

    let app_msg = if app_branch_index == 0 {
        alice.confirm_published(alice_pending).await.unwrap();
        send_app(&mut alice, &group_id, b"engine witness from alice".to_vec()).await
    } else {
        bob.confirm_published(bob_pending).await.unwrap();
        send_app(&mut bob, &group_id, b"engine witness from bob".to_vec()).await
    };

    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_messages[0].clone(), 1_000)
        .expect("first commit buffered");
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_messages[1].clone(), 1_000)
        .expect("second commit buffered");
    carol
        .buffer_openmls_convergence_message_at(&group_id, app_msg.clone(), 1_000)
        .expect("app witness buffered");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("stored OpenMLS messages converge");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_eq!(
        carol_storage
            .get_group(&group_id)
            .expect("group stored")
            .epoch,
        EpochId(2)
    );
    assert_eq!(
        result.accepted_commits,
        vec![content_hex(&commit_messages[app_branch_index])]
    );
    assert_message_state(
        &carol_storage,
        &commit_messages[app_branch_index],
        MessageState::Processed,
    );
    assert_message_state(
        &carol_storage,
        &commit_messages[quiet_branch_index],
        MessageState::ConvergenceDeferred,
    );
    assert_message_state(&carol_storage, &app_msg, MessageState::Processed);

    let members = carol.members(&group_id).unwrap();
    let selected_invitee = if app_branch_index == 0 {
        MemberId::new(pad32(b"david"))
    } else {
        MemberId::new(pad32(b"eve"))
    };
    let losing_invitee = if app_branch_index == 0 {
        MemberId::new(pad32(b"eve"))
    } else {
        MemberId::new(pad32(b"david"))
    };
    assert!(members.iter().any(|member| member.id == selected_invitee));
    assert!(!members.iter().any(|member| member.id == losing_invitee));

    let repeated = carol
        .converge_stored_openmls_messages_at(&group_id, 3_000)
        .expect("repeated convergence after applying is a no-op");
    assert!(repeated.accepted_commits.is_empty());
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));

    let completed_pass = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("completed witness pass remains durable");
    assert_eq!(
        completed_pass.phase,
        cgka_traits::ConvergencePassPhase::Completed
    );
    let post_race_app = if app_branch_index == 0 {
        send_app(
            &mut alice,
            &group_id,
            b"ordinary app after settled race".to_vec(),
        )
        .await
    } else {
        send_app(
            &mut bob,
            &group_id,
            b"ordinary app after settled race".to_vec(),
        )
        .await
    };
    assert!(matches!(
        carol.ingest(post_race_app.clone()).await.unwrap(),
        IngestOutcome::Processed
    ));
    assert_message_state(&carol_storage, &post_race_app, MessageState::Processed);
    let pass_after_app = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("ordinary app does not replace the completed pass");
    assert_eq!(pass_after_app.generation, completed_pass.generation);
    assert_eq!(
        pass_after_app.phase,
        cgka_traits::ConvergencePassPhase::Completed
    );
    assert!(
        !carol
            .has_pending_convergence_inputs(&group_id)
            .expect("pending convergence query succeeds"),
        "the epoch-invalidated loser must not keep gating ordinary app traffic"
    );
}

/// A late application from common history can enter convergence while a newer
/// epoch is contested. Every candidate path starts at the fork epoch, so the
/// application predates the first commit in every path. It must still be
/// authenticated against the retained base state and delivered after branch
/// selection rather than being invalidated without a decryption attempt.
#[tokio::test]
async fn contested_fork_delivers_late_pre_fork_application() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut common_invitee, _common_invitee_storage) = build_client(b"common-invitee");
    let (mut alice_invitee, _alice_invitee_storage) = build_client(b"alice-invitee");
    let (mut bob_invitee, _bob_invitee_storage) = build_client(b"bob-invitee");

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "late-pre-fork-application".into(),
            description: "".into(),
            members: vec![
                bob.fresh_key_package().await.unwrap(),
                carol.fresh_key_package().await.unwrap(),
            ],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    // Hold this epoch-1 application until after the shared group has advanced
    // and epoch 2 has forked.
    let late_app = send_app(
        &mut alice,
        &group_id,
        b"late shared-history application".to_vec(),
    )
    .await;

    let common_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![common_invitee.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (common_commit, common_pending) = evolution(common_invite);
    alice.confirm_published(common_pending).await.unwrap();
    let common_commit = route(common_commit, &group_id);
    assert!(matches!(
        bob.ingest(common_commit.clone()).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    bob.converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("Bob applies the shared commit");
    assert!(matches!(
        carol.ingest(common_commit).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("Carol applies the shared commit");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    carol.drain_events();

    let alice_fork = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![alice_invitee.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let bob_fork = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![bob_invitee.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (alice_commit, _alice_pending) = evolution(alice_fork);
    let (bob_commit, _bob_pending) = evolution(bob_fork);
    for message in [
        route(alice_commit, &group_id),
        route(bob_commit, &group_id),
        late_app.clone(),
    ] {
        carol
            .buffer_openmls_convergence_message_at(&group_id, message, 1_000)
            .unwrap();
    }

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("contested fork converges with late shared-history evidence");
    let late_app_id = content_hex(&late_app);

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
    assert_eq!(result.accepted_app_messages, vec![late_app_id.clone()]);
    assert!(
        result
            .invalidated_app_messages
            .iter()
            .all(|invalidated| invalidated.message_id != late_app_id)
    );
    assert_message_state(&carol_storage, &late_app, MessageState::Processed);

    let events = carol.drain_events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                GroupEvent::MessageReceived { payload, .. }
                    if app_content(payload) == b"late shared-history application"
            ))
            .count(),
        1,
        "late shared-history application must be delivered exactly once: {events:?}"
    );
    assert!(!events.iter().any(|event| matches!(
        event,
        GroupEvent::AppMessageInvalidated { message_id, .. }
            if *message_id == content_id(&late_app)
    )));
}

/// Regression for the Android-visible "This message is no longer valid"
/// banner on a device's own sent message. OpenMLS cannot decrypt an own
/// private-message ciphertext during candidate replay, so convergence must use
/// the authenticated send-time stamp retained with the `Sent` row instead of
/// classifying the message as undecryptable.
#[tokio::test]
async fn rebuilt_sender_keeps_own_sent_app_valid_through_convergence() {
    let audit_dir = tempfile::TempDir::new().unwrap();
    let audit_path = audit_dir.path().join("own-sent-convergence.jsonl");
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "own-sent-app-convergence".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    let own_app = send_app(
        &mut carol,
        &group_id,
        b"must remain valid on the sender".to_vec(),
    )
    .await;
    let stored_before_restart = carol_storage
        .get_message(&own_app.id)
        .expect("own sent row is durable");
    assert_eq!(stored_before_restart.state, MessageState::Sent);
    let payload = StoredMessagePayload::decode(&stored_before_restart.payload)
        .expect("own sent payload decodes");
    assert!(
        payload.own_application_stamp().is_some(),
        "own application provenance must survive in the durable Sent row"
    );

    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    carol
        .buffer_openmls_convergence_message_at(&group_id, route(commit, &group_id), 1_000)
        .expect("commit buffered alongside own Sent row");

    drop(carol);
    let recorder = JsonlRecorder::open(&audit_path, "own-sent-regression".into()).unwrap();
    let mut restarted =
        build_client_with_storage_and_recorder(b"carol", carol_storage.clone(), recorder);
    restarted
        .hydrate_stable_groups_from_storage()
        .expect("restart hydrates the persisted group");
    let result = restarted
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("rebuilt sender converges stored messages");

    let own_app_id = hex::encode(own_app.id.as_slice());
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        result.accepted_app_messages,
        vec![own_app_id.clone()],
        "own app was not credited to its branch: {result:?}"
    );
    assert!(
        result
            .invalidated_app_messages
            .iter()
            .all(|invalidated| invalidated.message_id != own_app_id),
        "own sent message must not be invalidated: {:?}",
        result.invalidated_app_messages
    );
    assert_eq!(
        carol_storage
            .get_message(&own_app.id)
            .expect("own sent row remains stored")
            .state,
        MessageState::Processed
    );
    let events = restarted.drain_events();
    assert!(
        events.iter().all(|event| !matches!(
            event,
            GroupEvent::AppMessageInvalidated { message_id, .. } if *message_id == own_app.id
        )),
        "sender must not receive an invalidation for its own message: {events:?}"
    );
    assert!(
        events.iter().all(|event| !matches!(
            event,
            GroupEvent::MessageReceived { group_id: event_group, .. } if *event_group == group_id
        )),
        "convergence must not echo the sender's own app back as received: {events:?}"
    );
    drop(restarted);
    let audit_events: Vec<AuditEvent> = std::fs::read_to_string(&audit_path)
        .expect("read convergence audit")
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse convergence audit event"))
        .collect();
    assert!(
        audit_events.iter().any(|event| matches!(
            &event.kind,
            AuditEventKind::MessageStateChanged {
                previous_state: Some(previous_state),
                new_state,
                reason,
                ..
            } if previous_state == "sent"
                && new_state == "processed"
                && reason == "canonicalization_accepted"
        )),
        "forensic audit must expose the atomic Sent -> Processed convergence disposition"
    );
}

/// A locally authored app is a witness only for the branch whose authenticated
/// source state created it. Choose the branch that would lose the deterministic
/// commit tie-break, then prove the own-message stamp credits only that branch
/// and lets its real app witness win selection.
#[tokio::test]
async fn own_sent_app_witnesses_only_its_matching_fork_branch() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, bob_storage) = build_client(b"bob");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "own-app-fork-provenance".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();

    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = evolution(alice_invite);
    let (bob_commit, bob_pending) = evolution(bob_invite);
    let commits = [route(alice_commit, &group_id), route(bob_commit, &group_id)];
    let own_branch = 1 - commit_tiebreak_winner_index(&alice.self_id(), &bob.self_id());

    let (own_app, sender_storage, events) = if own_branch == 0 {
        alice.confirm_published(alice_pending).await.unwrap();
        let own_app = send_app(
            &mut alice,
            &group_id,
            b"alice own app selects matching branch".to_vec(),
        )
        .await;
        alice
            .buffer_openmls_convergence_message_at(&group_id, commits[1].clone(), 1_000)
            .expect("competing Bob commit buffered");
        let result = alice
            .converge_stored_openmls_messages_at(&group_id, u64::MAX)
            .expect("Alice converges the fork");
        let events = alice.drain_events();
        (own_app, alice_storage, (result, events))
    } else {
        bob.confirm_published(bob_pending).await.unwrap();
        let own_app = send_app(
            &mut bob,
            &group_id,
            b"bob own app selects matching branch".to_vec(),
        )
        .await;
        bob.buffer_openmls_convergence_message_at(&group_id, commits[0].clone(), 1_000)
            .expect("competing Alice commit buffered");
        let result = bob
            .converge_stored_openmls_messages_at(&group_id, u64::MAX)
            .expect("Bob converges the fork");
        let events = bob.drain_events();
        (own_app, bob_storage, (result, events))
    };
    let (result, events) = events;
    let own_app_id = hex::encode(own_app.id.as_slice());

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        result.accepted_app_messages,
        vec![own_app_id.clone()],
        "own app was not credited to its branch: {result:?}"
    );
    assert!(
        result
            .accepted_commits
            .iter()
            .any(|message_id| message_id == &hex::encode(commits[own_branch].id.as_slice())),
        "the own app witness must select its matching branch: {result:?}"
    );
    assert!(result.invalidated_app_messages.iter().all(|invalidated| {
        invalidated.message_id != own_app_id
            && invalidated.reason != InvalidatedAppMessageReason::UndecryptableInCanonicalState
    }));
    assert_eq!(
        sender_storage
            .get_message(&own_app.id)
            .expect("own app remains durable")
            .state,
        MessageState::Processed
    );
    assert!(events.iter().all(|event| !matches!(
        event,
        GroupEvent::AppMessageInvalidated { message_id, .. } if *message_id == own_app.id
    )));
}

#[tokio::test]
async fn convergence_rejects_remove_that_leaves_orphan_admin_key() {
    // Regression coverage for the admin-policy resulting-epoch invariant on the
    // stored convergence replay path. Bob is a co-admin; his raw OpenMLS Remove
    // commit removes Alice's last member leaf but leaves the signed admin-policy
    // component as {Alice, Bob}. Direct ingest already rejects this shape before
    // merge. Stored convergence must classify the same commit as invalid rather
    // than materializing epoch 2 with an orphan admin key.
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let bob_id = bob.self_id();
    let alice_id = alice.self_id();
    let carol_id = carol.self_id();
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "convergence-orphan-admin".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob_id.clone()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let invalid_remove = route(
        raw_remove_members_commit(
            &bob_storage,
            &bob.self_id(),
            &group_id,
            std::slice::from_ref(&alice_id),
        ),
        &group_id,
    );
    carol
        .buffer_openmls_convergence_message_at(&group_id, invalid_remove.clone(), 1_000)
        .expect("invalid remove commit buffered");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("stored OpenMLS messages converge");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert!(
        result.accepted_commits.is_empty(),
        "orphan-admin remove must not be accepted: {result:?}"
    );
    assert!(
        result.dropped_messages.iter().any(|dropped| {
            dropped.kind == MessageKind::Commit
                && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
                && dropped.message_id == content_hex(&invalid_remove)
        }),
        "expected invalid remove dropped as InvalidAgainstCandidateState, got {:?}",
        result.dropped_messages
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    let stored_group = carol_storage.get_group(&group_id).expect("group stored");
    assert_eq!(stored_group.epoch, EpochId(1));
    assert_eq!(
        stored_group.members.len(),
        3,
        "invalid convergence commit must not change stored member count"
    );
    let projected_members = carol.members(&group_id).expect("members projected");
    assert_eq!(
        projected_members.len(),
        3,
        "invalid convergence commit must not change projected member count"
    );
    for expected in [&alice_id, &bob_id, &carol_id] {
        assert!(
            projected_members
                .iter()
                .any(|member| member.id == *expected),
            "projected members should still contain {expected:?}: {projected_members:?}"
        );
    }
    assert_message_state(
        &carol_storage,
        &invalid_remove,
        MessageState::EpochInvalidated,
    );
}

#[tokio::test]
async fn openmls_rejects_remove_commit_dropping_app_data_dictionary_at_construction() {
    // OpenMLS upstream commit 34222ef6 moved this draft invariant into the
    // shared validation used by commit construction and receive-side staging.
    // Pin the construction seam here: a malicious wire fixture can no longer
    // be produced through the public API, and the same validation method runs
    // before an inbound commit is staged.
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, bob_storage) = build_client(b"bob");
    let bob_id = bob.self_id();
    let alice_id = alice.self_id();
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "openmls-rejects-dictionary-drop".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob_id.clone()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();

    assert_openmls_rejects_remove_members_commit_dropping_app_data_dictionary(
        &bob_storage,
        &bob.self_id(),
        &group_id,
        std::slice::from_ref(&alice_id),
    );
}

#[tokio::test]
async fn convergence_accepts_remove_when_admin_policy_drops_removed_admin() {
    // Positive control for the same invariant: a commit may remove an admin's
    // last member leaf if the same resulting epoch's signed admin-policy drops
    // that admin key. This proves the convergence check accepts the legal
    // Remove+AppDataUpdate shape instead of rejecting removals broadly.
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let bob_id = bob.self_id();
    let alice_id = alice.self_id();
    let carol_id = carol.self_id();
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "convergence-valid-admin-removal".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob_id.clone()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let valid_remove = route(
        raw_remove_members_commit_with_admin_policy(
            &bob_storage,
            &bob.self_id(),
            &group_id,
            std::slice::from_ref(&alice_id),
            std::slice::from_ref(&bob_id),
        ),
        &group_id,
    );
    carol
        .buffer_openmls_convergence_message_at(&group_id, valid_remove.clone(), 1_000)
        .expect("valid remove commit buffered");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("stored OpenMLS messages converge");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(result.accepted_commits, vec![content_hex(&valid_remove)]);
    assert!(
        result.dropped_messages.is_empty(),
        "valid remove should not drop messages: {:?}",
        result.dropped_messages
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    let stored_group = carol_storage.get_group(&group_id).expect("group stored");
    assert_eq!(stored_group.epoch, EpochId(2));
    assert_eq!(stored_group.members.len(), 2);
    let projected_members = carol.members(&group_id).expect("members projected");
    assert_eq!(projected_members.len(), 2);
    assert!(!projected_members.iter().any(|member| member.id == alice_id));
    for expected in [&bob_id, &carol_id] {
        assert!(
            projected_members
                .iter()
                .any(|member| member.id == *expected),
            "projected members should contain {expected:?}: {projected_members:?}"
        );
    }
    let bob_admin: [u8; 32] = bob_id
        .as_slice()
        .try_into()
        .expect("test identities are 32-byte account keys");
    assert_eq!(carol.admin_pubkeys(&group_id).unwrap(), vec![bob_admin]);
    assert_message_state(&carol_storage, &valid_remove, MessageState::Processed);
}

/// Two-member bootstrap for the GCE tamper regressions: `creator` creates the
/// group (sole admin), confirms, and `joiner` joins via welcome.
async fn bootstrap_gce_tamper_group(
    creator: &mut Engine<SqliteAccountStorage>,
    joiner: &mut Engine<SqliteAccountStorage>,
    joiner_name: &[u8],
    group_name: &str,
) -> GroupId {
    let joiner_kp = joiner.fresh_key_package().await.unwrap();
    let (group_id, create) = creator
        .create_group(CreateGroupRequest {
            name: group_name.into(),
            description: "".into(),
            members: vec![joiner_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    creator.confirm_published(pending).await.unwrap();
    joiner
        .join_welcome(welcome_for(&welcomes, joiner_name))
        .await
        .unwrap();
    group_id
}

#[tokio::test]
async fn openmls_rejects_bare_gce_dictionary_tampering_at_construction() {
    // OpenMLS upstream commit 34222ef6 closes the bare-GCE bypass before the
    // no-AppDataUpdate early return. The same validator is called by inbound
    // staged-commit processing, while this test pins all three mutations at
    // the public construction seam available to MDK integration tests.
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let alice_id = alice.self_id();
    let bob_id = bob.self_id();
    let group_id = bootstrap_gce_tamper_group(
        &mut alice,
        &mut bob,
        b"bob",
        "openmls-rejects-bare-gce-tamper",
    )
    .await;

    assert_openmls_rejects_group_context_extensions_tamper(
        &alice_storage,
        &alice_id,
        &group_id,
        GceDictionaryTamper::StripDictionary,
    );
    assert_openmls_rejects_group_context_extensions_tamper(
        &alice_storage,
        &alice_id,
        &group_id,
        GceDictionaryTamper::DropEntry(GROUP_ADMIN_POLICY_COMPONENT_ID),
    );
    assert_openmls_rejects_group_context_extensions_tamper(
        &alice_storage,
        &alice_id,
        &group_id,
        GceDictionaryTamper::ReplaceEntry(
            GROUP_ADMIN_POLICY_COMPONENT_ID,
            encode_admin_policy_for_test(std::slice::from_ref(&bob_id)),
        ),
    );
}

/// mdk#286: a commit applied through STORED CONVERGENCE that later loses
/// a same-epoch fork must (a) attribute its winning-branch group-system rows to
/// the accepted commit via `origin_commit_id`, and (b) emit
/// `GroupEvent::CommitRolledBack` for the losing commit so the app can tombstone
/// the kind-1210 rows that losing commit synthesized.
///
/// This path routes commits into convergence (`msg_epoch >= current_epoch`),
/// so before this fix the losing branch's synthesized rows had
/// `origin_commit_id = NULL` and no event ever targeted them — leaving stale
/// contradictory history.
#[tokio::test]
async fn convergence_rollback_emits_commit_rolled_back_for_losing_branch() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-rollback".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    // Two same-epoch invite commits fork the epoch: Alice invites David, Bob
    // invites Eve. Only one wins branch selection on Carol's convergence pass.
    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = evolution(alice_invite);
    let (bob_commit, bob_pending) = evolution(bob_invite);
    let commit_messages = [
        route(alice_commit.clone(), &group_id),
        route(bob_commit.clone(), &group_id),
    ];

    // Use an app-message witness to deterministically pick which branch wins,
    // independent of the authenticated committer tie-break.
    let app_branch_index = 1 - commit_tiebreak_winner_index(&alice.self_id(), &bob.self_id());
    let quiet_branch_index = 1 - app_branch_index;

    let app_msg = if app_branch_index == 0 {
        alice.confirm_published(alice_pending).await.unwrap();
        send_app(
            &mut alice,
            &group_id,
            b"rollback witness from alice".to_vec(),
        )
        .await
    } else {
        bob.confirm_published(bob_pending).await.unwrap();
        send_app(&mut bob, &group_id, b"rollback witness from bob".to_vec()).await
    };

    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_messages[0].clone(), 1_000)
        .expect("first commit buffered");
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_messages[1].clone(), 1_000)
        .expect("second commit buffered");
    carol
        .buffer_openmls_convergence_message_at(&group_id, app_msg.clone(), 1_000)
        .expect("app witness buffered");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("stored OpenMLS messages converge");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    // Exactly one commit was accepted; the eligible sibling is deferred so a
    // later pass can reconsider it if new retained evidence changes selection.
    assert_eq!(
        result.accepted_commits,
        vec![content_hex(&commit_messages[app_branch_index])]
    );
    let losing_commit = &commit_messages[quiet_branch_index];
    assert!(
        result.deferred_messages.iter().any(|deferred| {
            deferred.kind == MessageKind::Commit
                && deferred.reason == DeferredMessageReason::NonSelectedEligibleBranch
                && deferred.message_id == content_hex(losing_commit)
        }),
        "expected eligible losing commit deferred for a later pass, got {:?}",
        result.deferred_messages
    );
    assert_message_state(
        &carol_storage,
        losing_commit,
        MessageState::ConvergenceDeferred,
    );

    let winning_commit_id = content_id(&commit_messages[app_branch_index]);
    let losing_commit_id = content_id(losing_commit);
    let events = carol.drain_events();

    // (b) The losing commit emits CommitRolledBack so the app can tombstone the
    // kind-1210 rows it synthesized.
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::CommitRolledBack { group_id: g, invalidated_commit_id }
                if g == &group_id && *invalidated_commit_id == losing_commit_id
        )),
        "expected CommitRolledBack for the losing commit, got {events:?}"
    );
    // (b') Issue #363 / spec convergence.md "Applying the selected branch": the
    // stored-convergence seam must also emit the explicit state-notification
    // withdrawal naming the superseded commit, so every `GroupStateChanged`
    // attributed to it is treated as not having happened.
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupStateInvalidated {
                group_id: g,
                epoch,
                invalidated_commit_id,
                reason: cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection,
            } if g == &group_id
                && *invalidated_commit_id == losing_commit_id
                && epoch.0 == 1
        )),
        "expected GroupStateInvalidated for the losing commit, got {events:?}"
    );
    // The winning (accepted) commit's notifications are never withdrawn.
    assert!(
        !events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupStateInvalidated { invalidated_commit_id, .. }
                if *invalidated_commit_id == winning_commit_id
        )),
        "the accepted commit must not be named by a withdrawal, got {events:?}"
    );
    // (a) The winning branch's MemberAdded row is attributed to the accepted
    // commit, so a later rollback of *that* commit could tombstone it too.
    let selected_invitee = if app_branch_index == 0 {
        MemberId::new(pad32(b"david"))
    } else {
        MemberId::new(pad32(b"eve"))
    };
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupStateChanged {
                group_id: g,
                change: cgka_traits::engine::GroupStateChange::MemberAdded { member },
                origin_commit_id: Some(origin),
                ..
            } if g == &group_id
                && *member == selected_invitee
                && *origin == winning_commit_id
        )),
        "expected MemberAdded row attributed to the winning commit, got {events:?}"
    );
}

/// A commit that removes the LOCAL member's own leaf is applied (realizing
/// removal: `Group.removed` set, send gate closed, group presented as
/// removed), then LOSES branch selection to a same-epoch sibling through
/// stored convergence. The realized removal was never canonically applied,
/// so it "MUST NOT remain visible to the application as a completed change"
/// (convergence.md, "Applying the selected branch") — member-departure.md's
/// terminal-marker rule presumes removal evidence "on the selected canonical
/// branch". This test pins the whole resulting view of that supersession:
/// the withdrawal names the superseded removal in the id space the
/// self-removed notification was stamped with, the copy stops
/// self-quarantining (marker cleared, membership and the winner's rename
/// presented), and the send gate reopens.
#[tokio::test]
async fn superseded_self_removal_clears_removed_marker_and_restores_send() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-superseded-self-removal".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");
    carol.drain_events();

    // Same-epoch fork by the two admins: one removes Carol, the other renames
    // the group. Both commit shapes are admin-gated (Privileged), so the
    // authenticated committer tie-break decides branch selection — give the
    // rename to the winning committer so the REMOVAL deterministically loses.
    let (mut renamer, mut remover) =
        if commit_tiebreak_winner_index(&alice.self_id(), &bob.self_id()) == 0 {
            (alice, bob)
        } else {
            (bob, alice)
        };
    let remove_res = remover
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![carol.self_id()],
        })
        .await
        .unwrap();
    let (remove_commit, remove_pending) = evolution(remove_res);
    remover.confirm_published(remove_pending).await.unwrap();
    let rename_res = renamer
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("name after reorg".into()),
            description: None,
        })
        .await
        .unwrap();
    let (rename_commit, rename_pending) = evolution(rename_res);
    renamer.confirm_published(rename_pending).await.unwrap();
    let remove_commit = route(remove_commit, &group_id);
    let rename_commit = route(rename_commit, &group_id);

    // Carol's copy applies the removal: the inbound commit is buffered for the
    // convergence quiescence window, then the convergence apply realizes the
    // removal (marker + self-removed notification, the seam #703 added at
    // `emit_convergence_events`).
    let outcome = carol.ingest(remove_commit.clone()).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "removal commit buffers for convergence, got {outcome:?}"
    );
    let applied = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("removal branch applies");
    assert_eq!(applied.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(applied.accepted_commits, vec![content_hex(&remove_commit)]);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    let removal_events = carol.drain_events();
    let self_removed_origin = removal_events
        .iter()
        .find_map(|event| match event {
            GroupEvent::GroupStateChanged {
                change: cgka_traits::engine::GroupStateChange::MemberRemoved { member },
                origin_commit_id,
                ..
            } if *member == carol.self_id() => origin_commit_id.clone(),
            _ => None,
        })
        .expect("self-removed state notification carries an origin commit");
    assert_eq!(self_removed_origin, content_id(&remove_commit));
    assert!(
        carol_storage.get_group(&group_id).unwrap().removed,
        "applying the removal marks the local copy removed"
    );
    // The removed-copy send gate quarantines outbound work.
    let payload = app_payload_for(&carol, b"blocked while removed");
    let gate = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
        })
        .await;
    assert!(
        matches!(
            &gate,
            Err(cgka_traits::error::EngineError::InvalidTransition(t)) if t.from == "Removed"
        ),
        "removed copy must reject sends, got {gate:?}"
    );

    // The winning same-epoch sibling arrives through stored convergence: the
    // direct seam classifies every further input `SelfEvicted` once the copy
    // is removed, so this is the stored-message path (e.g. a session-layer
    // replay after restart).
    carol
        .buffer_openmls_convergence_message_at(&group_id, rename_commit.clone(), 1_001_000)
        .expect("sibling rename commit buffered");
    let result = carol
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("reorg over the superseded removal");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(result.accepted_commits, vec![content_hex(&rename_commit)]);
    assert_message_state(
        &carol_storage,
        &remove_commit,
        MessageState::ConvergenceDeferred,
    );

    // Final presented state: the removal never canonically happened. The copy
    // is a member again, presents the winner's rename, and is NOT removed.
    let group = carol_storage.get_group(&group_id).unwrap();
    assert!(
        !group.removed,
        "superseded removal must clear the removed marker"
    );
    assert_eq!(group.name, "name after reorg");
    assert_eq!(group.epoch, EpochId(2));
    assert!(group.members.iter().any(|m| m.id == carol.self_id()));
    assert!(
        carol
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|m| m.id == carol.self_id())
    );

    let events = carol.drain_events();
    // The withdrawal names the superseded removal in the SAME id space the
    // self-removed notification was stamped with, so the app tombstones that
    // row: the removal is treated as not having happened.
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupStateInvalidated {
                group_id: g,
                epoch,
                invalidated_commit_id,
                reason: cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection,
            } if g == &group_id && *invalidated_commit_id == self_removed_origin && epoch.0 == 1
        )),
        "expected withdrawal naming the superseded removal, got {events:?}"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::CommitRolledBack { group_id: g, invalidated_commit_id }
                if g == &group_id && *invalidated_commit_id == content_id(&remove_commit)
        )),
        "expected CommitRolledBack for the superseded removal, got {events:?}"
    );
    // The winning rename is never withdrawn.
    assert!(
        !events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupStateInvalidated { invalidated_commit_id, .. }
                if *invalidated_commit_id == content_id(&rename_commit)
        )),
        "the accepted rename must not be withdrawn, got {events:?}"
    );
    // Roster correction: the reorg diff re-announces our membership relative
    // to the previously presented (removed) roster, attributed to the
    // accepted commit that drove the pass.
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupStateChanged {
                group_id: g,
                change: cgka_traits::engine::GroupStateChange::MemberAdded { member },
                origin_commit_id: Some(origin),
                ..
            } if g == &group_id
                && *member == carol.self_id()
                && *origin == content_id(&rename_commit)
        )),
        "expected roster-correction MemberAdded for self, got {events:?}"
    );

    // Send eligibility is restored: the intent the removed-copy gate rejected
    // above now succeeds.
    send_app(&mut carol, &group_id, b"post-reorg send".to_vec()).await;
}

/// State-derived inverse of `realize_self_eviction`: a `removed` marker that
/// survives WITHOUT canonical evidence — the selected canonical branch
/// records our membership — is reconciled by the next convergence apply. The
/// marker is forced directly on the record to simulate the pathological
/// copy: a real supersession reorg already restores the pre-removal record
/// from the retained anchor (covered by
/// `superseded_self_removal_clears_removed_marker_and_restores_send`); this
/// pins the explicit guard for a marker no anchor restore can see.
#[tokio::test]
async fn convergence_apply_clears_removed_marker_without_canonical_evidence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-heal-removed-marker".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    // Pathological copy: marker set while canonical state (active MLS group,
    // roster with our leaf) records membership — no removal was ever applied.
    let mut record = carol_storage.get_group(&group_id).unwrap();
    record.removed = true;
    carol_storage.put_group(&record).unwrap();
    let payload = app_payload_for(&carol, b"blocked by pathological marker");
    let gate = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
        })
        .await;
    assert!(
        matches!(
            &gate,
            Err(cgka_traits::error::EngineError::InvalidTransition(t)) if t.from == "Removed"
        ),
        "marked copy must reject sends, got {gate:?}"
    );

    // An ordinary accepted commit converges (forward apply, no reorg): the
    // selected canonical branch still records our membership, so the apply
    // reconciles the marker.
    let rename_res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("healed".into()),
            description: None,
        })
        .await
        .unwrap();
    let (rename_commit, rename_pending) = evolution(rename_res);
    alice.confirm_published(rename_pending).await.unwrap();
    let rename_commit = route(rename_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, rename_commit.clone(), 1_000)
        .expect("rename commit buffered");
    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("forward apply converges");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(result.accepted_commits, vec![content_hex(&rename_commit)]);

    let group = carol_storage.get_group(&group_id).unwrap();
    assert!(
        !group.removed,
        "convergence apply must clear a marker the canonical roster contradicts"
    );
    assert_eq!(group.name, "healed");
    assert!(group.members.iter().any(|m| m.id == carol.self_id()));
    send_app(&mut carol, &group_id, b"send after healing".to_vec()).await;
}

/// Sibling of the test above with the FULL post-`realize_self_eviction`
/// record shape: `removed = true` AND self stripped from `Group.members`,
/// while the live MLS state (the canonical evidence) still records our
/// active leaf. The convergence apply rebuilds the roster from the replayed
/// MLS state and the reconciliation guard clears the marker, so the heal
/// works even when the record looked fully evicted before the replay
/// refreshed it.
#[tokio::test]
async fn convergence_apply_heals_fully_evicted_shaped_record() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-heal-evicted-record".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    // Pathological copy mirroring the shape `realize_self_eviction` writes
    // (marker + roster reconciliation in one record), but WITHOUT any
    // removal in MLS state: the canonical evidence still records our leaf.
    let mut record = carol_storage.get_group(&group_id).unwrap();
    record.removed = true;
    let self_id = carol.self_id();
    record.members.retain(|member| member.id != self_id);
    carol_storage.put_group(&record).unwrap();
    let payload = app_payload_for(&carol, b"blocked by evicted-shaped record");
    let gate = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
        })
        .await;
    assert!(
        matches!(
            &gate,
            Err(cgka_traits::error::EngineError::InvalidTransition(t)) if t.from == "Removed"
        ),
        "marked copy must reject sends, got {gate:?}"
    );

    let rename_res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("healed from evicted shape".into()),
            description: None,
        })
        .await
        .unwrap();
    let (rename_commit, rename_pending) = evolution(rename_res);
    alice.confirm_published(rename_pending).await.unwrap();
    let rename_commit = route(rename_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, rename_commit.clone(), 1_000)
        .expect("rename commit buffered");
    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("forward apply converges");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(result.accepted_commits, vec![content_hex(&rename_commit)]);

    let group = carol_storage.get_group(&group_id).unwrap();
    assert!(
        !group.removed,
        "convergence apply must clear a marker the canonical MLS state contradicts"
    );
    assert_eq!(group.name, "healed from evicted shape");
    assert!(
        group.members.iter().any(|m| m.id == carol.self_id()),
        "replay must rebuild the roster from canonical MLS state"
    );
    // The stale record presented us as absent, so the apply re-announces our
    // membership as a roster-correction row.
    let events = carol.drain_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupStateChanged {
                group_id: g,
                change: cgka_traits::engine::GroupStateChange::MemberAdded { member },
                ..
            } if g == &group_id && *member == carol.self_id()
        )),
        "expected roster-correction MemberAdded for self, got {events:?}"
    );
    send_app(
        &mut carol,
        &group_id,
        b"send after evicted-shape heal".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn engine_does_not_apply_stored_branch_before_stability_gate() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-syncing".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit.clone(), 1_000)
        .expect("commit buffered");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_500)
        .expect("stored OpenMLS messages canonicalize while syncing");

    assert_eq!(result.convergence_status, ConvergenceStatus::Syncing);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(
        carol_storage
            .get_group(&group_id)
            .expect("group stored")
            .epoch,
        EpochId(1)
    );
    assert_message_state(&carol_storage, &commit, MessageState::Created);
}

#[tokio::test]
async fn engine_ingest_buffers_commit_for_convergence_before_quiescence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-ingest-convergence-buffer".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);

    let outcome = carol.ingest(commit.clone()).await.unwrap();

    assert!(matches!(
        outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_message_state(&carol_storage, &commit, MessageState::Created);

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("stored commit applies after quiescence");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
}

#[tokio::test]
async fn engine_materializes_multi_commit_path_from_stored_commits() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-chain".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_eve, pending_eve) = evolution(invite_eve);
    alice.confirm_published(pending_eve).await.unwrap();
    let app_msg = send_app(
        &mut alice,
        &group_id,
        b"multi commit canonical payload".to_vec(),
    )
    .await;

    let commit_eve = route(commit_eve, &group_id);
    let commit_david = route(commit_david, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_eve.clone(), 1_000)
        .expect("child commit buffered first");
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_david.clone(), 1_000)
        .expect("parent commit buffered second");
    carol
        .buffer_openmls_convergence_message_at(&group_id, app_msg.clone(), 1_000)
        .expect("app message buffered after child and parent");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("stored parent and child commits converge as one path");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
    assert_eq!(
        result.accepted_commits,
        vec![content_hex(&commit_david), content_hex(&commit_eve)]
    );
    assert_eq!(result.accepted_app_messages, vec![content_hex(&app_msg)]);
    assert_message_state(&carol_storage, &commit_david, MessageState::Processed);
    assert_message_state(&carol_storage, &commit_eve, MessageState::Processed);
    assert_message_state(&carol_storage, &app_msg, MessageState::Processed);
    let members = carol.members(&group_id).unwrap();
    assert!(members.iter().any(|member| member.id == david.self_id()));
    assert!(members.iter().any(|member| member.id == eve.self_id()));
    let events = carol.drain_events();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                GroupEvent::MessageReceived { group_id: event_group, payload, .. }
                    if *event_group == group_id
                        && app_content(payload) == b"multi commit canonical payload"
            )
        }),
        "expected multi-commit canonical app payload event, got {events:?}"
    );
}

/// Application observations and the accepted-message result are canonical
/// even when peers admit the same source-epoch applications in opposite
/// transport order. Exercise the retained base, each commit edge, and the
/// selected tip so every application replay bucket uses the same ordering.
#[tokio::test]
async fn application_replay_is_invariant_to_opposite_arrival_order() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut forward, _forward_storage) = build_client(b"forward");
    let (mut reverse, _reverse_storage) = build_client(b"reverse");

    let forward_kp = forward.fresh_key_package().await.unwrap();
    let reverse_kp = reverse.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "canonical-application-arrival-order".into(),
            description: "".into(),
            members: vec![forward_kp, reverse_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    forward
        .join_welcome(welcome_for(&welcomes, b"forward"))
        .await
        .unwrap();
    reverse
        .join_welcome(welcome_for(&welcomes, b"reverse"))
        .await
        .unwrap();
    forward.drain_events();
    reverse.drain_events();

    let base_apps = [
        send_app(&mut alice, &group_id, b"base-a".to_vec()).await,
        send_app(&mut alice, &group_id, b"base-b".to_vec()).await,
    ];
    let (mut david, _david_storage) = build_client(b"arrival-order-david");
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (commit_david, pending) = evolution(invite_david);
    alice.confirm_published(pending).await.unwrap();
    let edge_apps = [
        send_app(&mut alice, &group_id, b"edge-a".to_vec()).await,
        send_app(&mut alice, &group_id, b"edge-b".to_vec()).await,
    ];
    let (mut eve, _eve_storage) = build_client(b"arrival-order-eve");
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (commit_eve, pending) = evolution(invite_eve);
    alice.confirm_published(pending).await.unwrap();
    let tip_apps = [
        send_app(&mut alice, &group_id, b"tip-a".to_vec()).await,
        send_app(&mut alice, &group_id, b"tip-b".to_vec()).await,
    ];
    let commit_david = route(commit_david, &group_id);
    let commit_eve = route(commit_eve, &group_id);

    for apps in [&base_apps, &edge_apps, &tip_apps] {
        for app in apps {
            forward
                .buffer_openmls_convergence_message_at(&group_id, app.clone(), 1_000)
                .unwrap();
        }
    }
    for commit in [&commit_david, &commit_eve] {
        forward
            .buffer_openmls_convergence_message_at(&group_id, commit.clone(), 1_000)
            .unwrap();
        reverse
            .buffer_openmls_convergence_message_at(&group_id, commit.clone(), 1_000)
            .unwrap();
    }
    for apps in [&tip_apps, &edge_apps, &base_apps] {
        for app in apps.iter().rev() {
            reverse
                .buffer_openmls_convergence_message_at(&group_id, app.clone(), 1_000)
                .unwrap();
        }
    }

    let forward_result = forward
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    let reverse_result = reverse
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();

    let expected_app_messages = [&base_apps, &edge_apps, &tip_apps]
        .into_iter()
        .flatten()
        .map(content_hex)
        .collect::<Vec<_>>();
    let mut expected_app_messages = expected_app_messages;
    expected_app_messages.sort();
    assert_eq!(forward_result.accepted_app_messages, expected_app_messages);
    assert_eq!(reverse_result.accepted_app_messages, expected_app_messages);
    let received_payloads = |events: Vec<GroupEvent>| {
        events
            .into_iter()
            .filter_map(|event| match event {
                GroupEvent::MessageReceived { payload, .. } => Some(app_content(&payload).to_vec()),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let canonical_payloads = |apps: &[TransportMessage; 2], payloads: [&[u8]; 2]| {
        let mut keyed_payloads = apps
            .iter()
            .zip(payloads)
            .map(|(app, payload)| (content_hex(app), payload.to_vec()))
            .collect::<Vec<_>>();
        keyed_payloads.sort_by(|left, right| left.0.cmp(&right.0));
        keyed_payloads
            .into_iter()
            .map(|(_, payload)| payload)
            .collect::<Vec<_>>()
    };
    let expected_payloads = canonical_payloads(&base_apps, [b"base-a", b"base-b"])
        .into_iter()
        .chain(canonical_payloads(&edge_apps, [b"edge-a", b"edge-b"]))
        .chain(canonical_payloads(&tip_apps, [b"tip-a", b"tip-b"]))
        .collect::<Vec<_>>();
    assert_eq!(received_payloads(forward.drain_events()), expected_payloads);
    assert_eq!(received_payloads(reverse.drain_events()), expected_payloads);
}

/// A frozen convergence pass already owns a bounded retained-anchor snapshot.
/// Application inputs admitted while they are inside the app window must use
/// that source-epoch state before later commits in the same pass advance far
/// enough to prune it. Dividing the same retained input across passes must not
/// decide whether the application is delivered (mdk#1171).
#[tokio::test]
async fn retained_application_delivery_is_invariant_to_convergence_pass_partition() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut one_pass, one_pass_storage) = build_client(b"one-pass");
    let (mut split_pass, split_pass_storage) = build_client(b"split-pass");

    let one_pass_kp = one_pass.fresh_key_package().await.unwrap();
    let split_pass_kp = split_pass.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "retained-app-pass-partition".into(),
            description: "".into(),
            members: vec![one_pass_kp, split_pass_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    one_pass
        .join_welcome(welcome_for(&welcomes, b"one-pass"))
        .await
        .unwrap();
    split_pass
        .join_welcome(welcome_for(&welcomes, b"split-pass"))
        .await
        .unwrap();
    one_pass.drain_events();
    split_pass.drain_events();

    let app = send_app(
        &mut alice,
        &group_id,
        b"retained across active convergence".to_vec(),
    )
    .await;
    let retention_limit =
        usize::try_from(CanonicalizationPolicy::default().app_message_past_epoch_limit)
            .expect("pinned application-retention limit fits usize");
    let commit_count = retention_limit + 1;
    let expected_tip = EpochId(1 + commit_count as u64);
    let mut commits = Vec::new();
    for index in 0..commit_count {
        let identity = format!("partition-invitee-{index}");
        let (mut invitee, _invitee_storage) = build_client(identity.as_bytes());
        let invite = alice
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![invitee.fresh_key_package().await.unwrap()],
            })
            .await
            .unwrap();
        let (commit, pending) = evolution(invite);
        alice.confirm_published(pending).await.unwrap();
        commits.push(route(commit, &group_id));
    }

    for message in commits.iter().chain([&app]) {
        one_pass
            .buffer_openmls_convergence_message_at(&group_id, message.clone(), 1_000)
            .unwrap();
    }
    // Inbound contested-pass handoff can retain a past-epoch wire message in
    // a row stamped with the receiver's newer current epoch. Final apply must
    // order by the authenticated wire source epoch, not this row metadata.
    let mut one_pass_app_record = one_pass_storage.get_message(&content_id(&app)).unwrap();
    one_pass_app_record.epoch = expected_tip;
    one_pass_storage.put_message(&one_pass_app_record).unwrap();
    let one_pass_result = one_pass
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();

    for message in commits[..retention_limit].iter().chain([&app]) {
        split_pass
            .buffer_openmls_convergence_message_at(&group_id, message.clone(), 1_000)
            .unwrap();
    }
    let split_first_result = split_pass
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    split_pass
        .buffer_openmls_convergence_message_at(
            &group_id,
            commits[retention_limit].clone(),
            2_000_000,
        )
        .unwrap();
    split_pass
        .converge_stored_openmls_messages_at(&group_id, 3_000_000)
        .unwrap();

    assert_eq!(one_pass.epoch(&group_id).unwrap(), expected_tip);
    assert_eq!(split_pass.epoch(&group_id).unwrap(), expected_tip);
    assert_eq!(one_pass_result.accepted_commits.len(), commit_count);
    assert_eq!(
        one_pass_result.accepted_app_messages,
        vec![content_hex(&app)]
    );
    assert_eq!(
        split_first_result.accepted_app_messages,
        vec![content_hex(&app)]
    );
    assert_eq!(
        one_pass_storage
            .get_message(&content_id(&app))
            .unwrap()
            .state,
        MessageState::Processed
    );
    assert_eq!(
        split_pass_storage
            .get_message(&content_id(&app))
            .unwrap()
            .state,
        MessageState::Processed
    );

    for events in [one_pass.drain_events(), split_pass.drain_events()] {
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event,
                    GroupEvent::MessageReceived { payload, .. }
                        if app_content(payload) == b"retained across active convergence"
                ))
                .count(),
            1,
            "the admitted application must be delivered exactly once: {events:?}"
        );
        assert!(!events.iter().any(|event| matches!(
            event,
            GroupEvent::AppMessageInvalidated { message_id, .. }
                if *message_id == content_id(&app)
        )));
    }
}

/// Reuse-path sibling of `engine_materializes_multi_commit_path_from_stored_commits`: the same
/// multi-commit chain but with NO pending application message buffered, so canonicalization takes
/// the #635 reuse branch (BFS-materialized candidates are reused instead of re-materialized). The
/// canonical commits and resulting epoch must match the fresh path exactly.
#[tokio::test]
async fn engine_reuses_bfs_materialized_candidates_when_no_pending_app_messages() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-chain-app-free".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_eve, pending_eve) = evolution(invite_eve);
    alice.confirm_published(pending_eve).await.unwrap();

    let commit_eve = route(commit_eve, &group_id);
    let commit_david = route(commit_david, &group_id);
    // Buffer the child before the parent, and crucially NO app message — this keeps the
    // canonicalization pass free of pending application messages so the reuse branch fires.
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_eve.clone(), 1_000)
        .expect("child commit buffered first");
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_david.clone(), 1_000)
        .expect("parent commit buffered second");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("stored parent and child commits converge as one reused path");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
    assert_eq!(
        result.accepted_commits,
        vec![content_hex(&commit_david), content_hex(&commit_eve)]
    );
    assert!(result.accepted_app_messages.is_empty());
    assert_message_state(&carol_storage, &commit_david, MessageState::Processed);
    assert_message_state(&carol_storage, &commit_eve, MessageState::Processed);
    let members = carol.members(&group_id).unwrap();
    assert!(members.iter().any(|member| member.id == david.self_id()));
    assert!(members.iter().any(|member| member.id == eve.self_id()));
}

#[tokio::test]
async fn engine_defers_child_commit_until_parent_arrives() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-missing-parent".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![carol.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();
    let commit_david = route(commit_david, &group_id);

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_eve, _pending_eve) = evolution(invite_eve);
    let commit_eve = route(commit_eve, &group_id);

    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_eve.clone(), 1_000)
        .expect("child commit buffered without parent");
    let queued_intent_id = MessageId::new(b"fairness-before-generation-one".to_vec());
    carol_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: queued_intent_id.clone(),
            group_id: group_id.clone(),
            intent: SendIntent::UpdateGroupData {
                group_id: group_id.clone(),
                name: Some("fairness before generation one".into()),
                description: None,
            },
            created_at_ms: 1_001,
        })
        .expect("persist already-queued admin group-state intent");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("missing parent is deferred graph input, not a hard error");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert!(result.accepted_commits.is_empty());
    assert!(result.dropped_messages.is_empty());
    assert!(result.deferred_messages.iter().any(|deferred| {
        deferred.message_id == content_hex(&commit_eve)
            && deferred.kind == MessageKind::Commit
            && deferred.reason == DeferredMessageReason::MissingCandidateParent
    }));
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_message_state(
        &carol_storage,
        &commit_eve,
        MessageState::ConvergenceDeferred,
    );
    let first_pass = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("first frozen pass persisted");
    assert_eq!(first_pass.generation, 0);
    assert_eq!(
        first_pass.phase,
        cgka_traits::ConvergencePassPhase::Completed
    );
    assert_eq!(first_pass.members.len(), 1);

    // The missing parent arrives only after generation 0 froze. It must not
    // mutate that completed membership set; generation 1 seeds both retained
    // inputs and resolves the fixed batch.
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_david.clone(), 1_000_001)
        .expect("late parent retained for next pass");
    let fairness_turn = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_002_000)
        .await
        .expect("completed pass grants one queued user-intent turn");
    assert_eq!(fairness_turn.len(), 1);
    let fairness_pending = match fairness_turn[0] {
        SendResult::GroupEvolution { pending, .. } => pending,
        ref other => panic!("expected queued group-state evolution, got {other:?}"),
    };
    let after_fairness = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("completed pass remains until its fairness slot is consumed");
    assert_eq!(after_fairness.generation, 0);
    assert_eq!(
        after_fairness.phase,
        cgka_traits::ConvergencePassPhase::Completed
    );
    assert!(!after_fairness.fairness_slot_available);
    assert_message_state(&carol_storage, &commit_david, MessageState::Created);
    carol
        .confirm_published(fairness_pending)
        .await
        .expect("published fairness evolution leaves the durable queue");
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .iter()
            .all(|record| record.id != queued_intent_id)
    );

    let collecting_second = carol
        .converge_stored_openmls_messages_at(&group_id, 1_002_000)
        .expect("next generation opens only after the fairness turn");
    assert_eq!(
        collecting_second.convergence_status,
        ConvergenceStatus::Syncing
    );
    let second = carol
        .converge_stored_openmls_messages_at(&group_id, 1_003_000)
        .expect("next frozen generation resolves parent and child");
    assert_eq!(second.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        second.accepted_commits,
        vec![content_hex(&commit_david), content_hex(&commit_eve)]
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
    let second_pass = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("second pass persisted");
    assert_eq!(second_pass.generation, 1);
    assert!(second_pass.members.len() >= 2);
}

#[tokio::test]
async fn deferred_commit_ages_out_when_it_falls_below_retained_anchor() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-deferred-commit-retirement".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![carol.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");

    // Alice creates a competing source-epoch-1 commit while Carol advances her
    // canonical copy to epoch 3. At that point Carol's retained floor is epoch
    // 2, so Alice's previously deferred commit can never re-enter a pass.
    let old_update = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("old competing branch".into()),
            description: None,
        })
        .await
        .unwrap();
    let (old_commit, _old_pending) = evolution(old_update);
    let old_commit = route(old_commit, &group_id);

    let mut active_commit = None;
    for index in 0..2 {
        let update = carol
            .send(SendIntent::UpdateGroupData {
                group_id: group_id.clone(),
                name: Some(format!("canonical advance {index}")),
                description: None,
            })
            .await
            .unwrap();
        let (message, pending) = evolution(update);
        carol.confirm_published(pending).await.unwrap();
        active_commit = Some(route(message, &group_id));
    }
    let active_commit = active_commit.expect("second canonical commit exists");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
    assert_eq!(
        project_mls_message(&old_commit.payload)
            .unwrap()
            .source_epoch,
        Some(1)
    );
    assert_eq!(
        project_mls_message(&active_commit.payload)
            .unwrap()
            .source_epoch,
        Some(2)
    );

    let store_deferred = |message: &TransportMessage, epoch: EpochId| {
        let id = content_id(message);
        carol_storage
            .put_message(&MessageRecord {
                id: id.clone(),
                group_id: group_id.clone(),
                epoch,
                state: MessageState::ConvergenceDeferred,
                payload: StoredMessagePayload::openmls_wire(message.clone())
                    .encode()
                    .unwrap(),
                deferred_peel: None,
            })
            .unwrap();
        id
    };
    let stale_id = store_deferred(&old_commit, EpochId(1));
    let active_id = store_deferred(&active_commit, EpochId(2));

    // Pass preparation owns the admission boundary. It must terminally retire
    // work below that boundary while preserving deferred work still inside it.
    carol
        .prepare_convergence_cutoff_delay_ms(&group_id)
        .expect("convergence preparation succeeds");
    assert_eq!(
        carol_storage.get_message(&stale_id).unwrap().state,
        MessageState::EpochInvalidated
    );
    assert_eq!(
        carol_storage.get_message(&active_id).unwrap().state,
        MessageState::ConvergenceDeferred
    );
}

/// Create a two-member group (alice creator/admin, carol member+admin) and
/// return its id with carol joined. Shared setup for the scoped-reservation
/// tests below.
async fn create_reservation_test_group(
    alice: &mut Engine<SqliteAccountStorage>,
    carol: &mut Engine<SqliteAccountStorage>,
    name: &str,
) -> GroupId {
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: name.into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![carol.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    group_id
}

/// Produce one confirmed linear group-state commit from `alice` (a profile
/// rename), routed for convergence delivery. Each call advances alice by one
/// epoch, so repeated calls model continuous inbound commit traffic.
async fn alice_rename_commit(
    alice: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    name: &str,
) -> TransportMessage {
    let result = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some(name.into()),
            description: None,
        })
        .await
        .unwrap();
    let (commit, pending) = evolution(result);
    alice.confirm_published(pending).await.unwrap();
    route(commit, group_id)
}

fn queue_intent(
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
    id: &[u8],
    intent: SendIntent,
    created_at_ms: u64,
) {
    storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: MessageId::new(id.to_vec()),
            group_id: group_id.clone(),
            intent,
            created_at_ms,
        })
        .expect("persist queued outbound intent");
}

/// Regression test for the settling fix: a queued ordinary app message must
/// never hold the completed-pass boundary — retained inbound opens the next
/// generation immediately, with the dormant reservation consumed.
#[tokio::test]
async fn pass_opens_while_app_message_intents_are_queued() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let group_id =
        create_reservation_test_group(&mut alice, &mut carol, "app-queue-never-parks").await;
    let commit_one = alice_rename_commit(&mut alice, &group_id, "one").await;
    let commit_two = alice_rename_commit(&mut alice, &group_id, "two").await;

    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_one.clone(), 1_000)
        .unwrap();
    let settled = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    assert_eq!(settled.convergence_status, ConvergenceStatus::Settled);
    let completed = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("generation 0 completed");
    assert_eq!(
        completed.phase,
        cgka_traits::ConvergencePassPhase::Completed
    );
    assert!(completed.fairness_slot_available);

    queue_intent(
        &carol_storage,
        &group_id,
        b"queued-app-message",
        SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: b"queued-chat".to_vec(),
        },
        1_000_001,
    );

    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_two.clone(), 1_000_100)
        .unwrap();
    let pass = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("next generation opened despite the queued app message");
    assert_eq!(pass.generation, 1);
    assert_eq!(pass.phase, cgka_traits::ConvergencePassPhase::Collecting);
    assert!(!pass.fairness_slot_available);

    let second = carol
        .converge_stored_openmls_messages_at(&group_id, 2_000_000)
        .unwrap();
    assert_eq!(second.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
}

/// The spec's one-attempt rule (convergence.md, marmot#375): a queued
/// admin-authorized group-state intent holds the completed-pass boundary and
/// gets exactly one preparation attempt before the next inbound-only pass.
#[tokio::test]
async fn admin_group_state_intent_gets_one_attempt_before_next_inbound_generation() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "admin-one-attempt").await;
    let commit_one = alice_rename_commit(&mut alice, &group_id, "one").await;
    let commit_two = alice_rename_commit(&mut alice, &group_id, "two").await;

    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_one.clone(), 1_000)
        .unwrap();
    let settled = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    assert_eq!(settled.convergence_status, ConvergenceStatus::Settled);

    queue_intent(
        &carol_storage,
        &group_id,
        b"queued-admin-evolution",
        SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("held for one attempt".into()),
            description: None,
        },
        1_000_001,
    );

    // Retained inbound arrives while the admin intent holds the boundary:
    // admission stays parked on the completed generation.
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_two.clone(), 1_000_100)
        .unwrap();
    let parked = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("completed pass holds the boundary for the admin intent");
    assert_eq!(parked.generation, 0);
    assert_eq!(parked.phase, cgka_traits::ConvergencePassPhase::Completed);
    assert!(parked.fairness_slot_available);

    let drained = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_200)
        .await
        .unwrap();
    assert_eq!(drained.len(), 1);
    let pending = match drained[0] {
        SendResult::GroupEvolution { pending, .. } => pending,
        ref other => panic!("expected the admin evolution attempt, got {other:?}"),
    };
    let consumed = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("pass survives the attempt");
    assert_eq!(consumed.generation, 0);
    assert!(!consumed.fairness_slot_available);

    // The attempt failed to publish: roll it back. The reservation stays
    // consumed and retained inbound proceeds into generation 1.
    carol.publish_failed(pending).await.unwrap();
    let syncing = carol
        .converge_stored_openmls_messages_at(&group_id, 1_100_000)
        .unwrap();
    assert_eq!(syncing.convergence_status, ConvergenceStatus::Syncing);
    let second = carol
        .converge_stored_openmls_messages_at(&group_id, 1_200_000)
        .unwrap();
    assert_eq!(second.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
}

/// A failing preparation consumes the one-attempt reservation (spec: "the
/// scheduler proceeds rather than waiting indefinitely") and retained inbound
/// convergence continues.
#[tokio::test]
async fn admin_attempt_failure_consumes_reservation_and_inbound_proceeds() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let group_id =
        create_reservation_test_group(&mut alice, &mut carol, "admin-attempt-failure").await;
    let commit_one = alice_rename_commit(&mut alice, &group_id, "one").await;
    let commit_two = alice_rename_commit(&mut alice, &group_id, "two").await;

    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_one.clone(), 1_000)
        .unwrap();
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();

    // An Invite whose KeyPackage bytes cannot parse fails preparation
    // deterministically.
    queue_intent(
        &carol_storage,
        &group_id,
        b"queued-broken-invite",
        SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![cgka_traits::engine::KeyPackage::new(b"garbage".to_vec())],
        },
        1_000_001,
    );
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_two.clone(), 1_000_100)
        .unwrap();

    let drained = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_200)
        .await
        .expect("a failed reservation attempt is not a drain error");
    assert!(drained.is_empty());
    let consumed = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("pass survives the failed attempt");
    assert!(!consumed.fairness_slot_available);
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1,
        "the durable intent stays queued after its failed attempt"
    );

    let syncing = carol
        .converge_stored_openmls_messages_at(&group_id, 1_100_000)
        .unwrap();
    assert_eq!(syncing.convergence_status, ConvergenceStatus::Syncing);
    let second = carol
        .converge_stored_openmls_messages_at(&group_id, 1_200_000)
        .unwrap();
    assert_eq!(second.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
}

/// The marmot#375 starvation property: continuous inbound commits keep
/// restarting quiescence, but the absolute deadline freezes the pass and the
/// queued admin intent gets its preparation attempt at the generation
/// boundary.
#[tokio::test]
async fn continuous_inbound_cannot_starve_admin_attempt() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let group_id =
        create_reservation_test_group(&mut alice, &mut carol, "no-admin-starvation").await;

    let mut commits = Vec::new();
    for index in 0..7 {
        commits.push(alice_rename_commit(&mut alice, &group_id, &format!("flood-{index}")).await);
    }

    // Admissions arrive faster than the quiescence window so each one
    // restarts it; only the absolute deadline can freeze the pass. Derive the
    // cadence from the pinned v1 constants so a policy change re-derives the
    // flood shape instead of silently invalidating it.
    let flood_interval_ms = V1_SETTLEMENT_QUIESCENCE_MS * 4 / 5;
    let opened_at = 10_000u64;
    for (index, commit) in commits.iter().take(6).enumerate() {
        carol
            .buffer_openmls_convergence_message_at(
                &group_id,
                commit.clone(),
                opened_at + flood_interval_ms * index as u64,
            )
            .unwrap();
    }
    queue_intent(
        &carol_storage,
        &group_id,
        b"queued-admin-remediation",
        SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("admin remediation".into()),
            description: None,
        },
        opened_at + 1,
    );

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, opened_at + V1_MAX_CONVERGENCE_PASS_MS + 50)
        .unwrap();
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(7));
    let completed = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("flooded pass completed");
    assert_eq!(
        completed.cutoff_cause,
        Some(cgka_traits::ConvergenceCutoffCause::AbsoluteDeadline),
        "continuous admissions must be cut off by the absolute deadline"
    );

    // The flood continues, but the boundary now belongs to the admin intent.
    carol
        .buffer_openmls_convergence_message_at(
            &group_id,
            commits[6].clone(),
            opened_at + V1_MAX_CONVERGENCE_PASS_MS + 100,
        )
        .unwrap();
    let parked = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("boundary held for the admin intent");
    assert_eq!(parked.generation, 0);
    assert!(parked.fairness_slot_available);

    let drained = carol
        .converge_and_drain_queued_outbound_intents(
            &group_id,
            opened_at + V1_MAX_CONVERGENCE_PASS_MS + 200,
        )
        .await
        .unwrap();
    assert_eq!(drained.len(), 1);
    assert!(
        matches!(drained[0], SendResult::GroupEvolution { .. }),
        "the admin intent gets its one attempt despite continuous inbound"
    );
}

/// Restart must not erase the durable one-attempt reservation: the queued
/// admin intent still gets its boundary attempt on the rebuilt engine.
#[tokio::test]
async fn restart_preserves_admin_reservation() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let group_id =
        create_reservation_test_group(&mut alice, &mut carol, "restart-keeps-reservation").await;
    let commit_one = alice_rename_commit(&mut alice, &group_id, "one").await;
    let commit_two = alice_rename_commit(&mut alice, &group_id, "two").await;

    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_one.clone(), 1_000)
        .unwrap();
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    queue_intent(
        &carol_storage,
        &group_id,
        b"queued-admin-survives-restart",
        SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("after restart".into()),
            description: None,
        },
        1_000_001,
    );
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_two.clone(), 1_000_100)
        .unwrap();
    drop(carol);

    let mut restarted = build_client_with_storage(b"carol", carol_storage.clone());
    restarted
        .hydrate_all_stored_groups()
        .expect("session-open hydration succeeds");
    let preserved = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("completed pass survives restart");
    assert!(
        preserved.fairness_slot_available,
        "hydration must not consume the durable reservation"
    );

    let drained = restarted
        .converge_and_drain_queued_outbound_intents(&group_id, 2_000_000)
        .await
        .unwrap();
    assert_eq!(drained.len(), 1);
    assert!(
        matches!(drained[0], SendResult::GroupEvolution { .. }),
        "the restarted engine still grants the one boundary attempt"
    );
}

/// Restart with only app messages queued must not manufacture a boundary
/// hold: retained inbound opens the next generation without extra delay.
#[tokio::test]
async fn restart_with_only_app_messages_opens_pass_without_delay() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let group_id =
        create_reservation_test_group(&mut alice, &mut carol, "restart-app-queue-no-delay").await;
    let commit_one = alice_rename_commit(&mut alice, &group_id, "one").await;
    let commit_two = alice_rename_commit(&mut alice, &group_id, "two").await;

    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_one.clone(), 1_000)
        .unwrap();
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    queue_intent(
        &carol_storage,
        &group_id,
        b"queued-app-survives-restart",
        SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: b"queued-chat".to_vec(),
        },
        1_000_001,
    );
    drop(carol);

    let mut restarted = build_client_with_storage(b"carol", carol_storage.clone());
    restarted
        .hydrate_all_stored_groups()
        .expect("session-open hydration succeeds");

    restarted
        .buffer_openmls_convergence_message_at(&group_id, commit_two.clone(), 2_000_000)
        .unwrap();
    let pass = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("next generation opened on the restarted engine");
    assert_eq!(pass.generation, 1);
    assert_eq!(pass.phase, cgka_traits::ConvergencePassPhase::Collecting);

    let second = restarted
        .converge_stored_openmls_messages_at(&group_id, 3_000_000)
        .unwrap();
    assert_eq!(second.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(restarted.epoch(&group_id).unwrap(), EpochId(3));
}

/// Consuming the reservation schedules the group for another convergence
/// drain immediately, so the next retained generation is not discovered one
/// scheduler cycle late.
#[tokio::test]
async fn reservation_consumption_schedules_next_generation_immediately() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let group_id =
        create_reservation_test_group(&mut alice, &mut carol, "reservation-reschedules").await;
    let commit_one = alice_rename_commit(&mut alice, &group_id, "one").await;
    let commit_two = alice_rename_commit(&mut alice, &group_id, "two").await;

    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_one.clone(), 1_000)
        .unwrap();
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    queue_intent(
        &carol_storage,
        &group_id,
        b"queued-admin-reschedules",
        SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("reschedule".into()),
            description: None,
        },
        1_000_001,
    );
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_two.clone(), 1_000_100)
        .unwrap();
    // Clear scheduling noise from setup so the assertion isolates the
    // consumption edge.
    let _ = carol.drain_pending_convergence_groups();

    let drained = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_200)
        .await
        .unwrap();
    assert_eq!(drained.len(), 1);

    assert!(
        carol.drain_pending_convergence_groups().contains(&group_id),
        "consuming the reservation must schedule the next generation immediately"
    );
}

#[tokio::test]
async fn engine_replays_late_same_epoch_commit_from_retained_anchor() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-retained-anchor".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");

    let david_kp = david.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (alice_commit, _alice_pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, alice_commit.clone(), 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("alice branch applies and retains epoch 1 anchor");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    let bob_commit = route(bob_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, bob_commit.clone(), 2_000)
        .expect("late bob commit buffered");

    let bob_wins = committer_wins(&bob.self_id(), &alice.self_id());

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 3_000_000)
        .expect("late same-epoch commit replays from retained anchor");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_ne!(
        carol_storage
            .get_message(&content_id(&bob_commit))
            .unwrap()
            .state,
        MessageState::Created,
        "late commit should be resolved once the retained anchor is available"
    );
    if bob_wins {
        assert_eq!(result.accepted_commits, vec![content_hex(&bob_commit)]);
        assert_message_state(&carol_storage, &bob_commit, MessageState::Processed);
    } else {
        assert_eq!(result.accepted_commits, vec![content_hex(&alice_commit)]);
        assert_message_state(&carol_storage, &bob_commit, MessageState::EpochInvalidated);
    }
    let members = carol.members(&group_id).unwrap();
    assert_eq!(
        members.iter().any(|member| member.id == eve.self_id()),
        bob_wins
    );
    assert_eq!(
        members.iter().any(|member| member.id == david.self_id()),
        !bob_wins
    );
}

#[tokio::test]
async fn engine_ingest_buffers_late_same_epoch_commit_within_rewind_horizon() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-inline-late-commit".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");

    let david_kp = david.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (alice_commit, _alice_pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, alice_commit.clone(), 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("alice branch applies via convergence");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    let bob_commit = route(bob_commit, &group_id);
    let bob_wins = committer_wins(&bob.self_id(), &alice.self_id());

    let outcome = carol.ingest(bob_commit.clone()).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "past-epoch competing commit inside the rewind horizon must enter convergence, got {outcome:?}"
    );
    assert_message_state(&carol_storage, &bob_commit, MessageState::Created);

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 3_000_000)
        .expect("late same-epoch commit ingested through the inline path converges");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    if bob_wins {
        assert_eq!(result.accepted_commits, vec![content_hex(&bob_commit)]);
        assert_message_state(&carol_storage, &bob_commit, MessageState::Processed);
    } else {
        assert_eq!(result.accepted_commits, vec![content_hex(&alice_commit)]);
        assert_message_state(&carol_storage, &bob_commit, MessageState::EpochInvalidated);
    }
    let members = carol.members(&group_id).unwrap();
    assert_eq!(
        members.iter().any(|member| member.id == eve.self_id()),
        bob_wins
    );
    assert_eq!(
        members.iter().any(|member| member.id == david.self_id()),
        !bob_wins
    );
}

#[tokio::test]
async fn engine_metrics_count_post_settle_reorg_from_late_same_epoch_commit() {
    // End-to-end check that the diagnostic reorg telemetry
    // (`docs/marmot-architecture/relay-delivery-telemetry.md` §"Validation:
    // post-settle reorg rate") is wired to the convergence apply site: the
    // first settle is never a reorg, and a late same-epoch commit that flips
    // the selected branch below the applied tip is counted as one.
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-reorg-metrics".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");

    // Carol settles on Alice's commit (epoch 1 -> 2) and retains the epoch-1
    // anchor. This is the first settle for the group: not a reorg.
    let david_kp = david.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (alice_commit, _alice_pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, alice_commit.clone(), 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 3_000)
        .expect("alice branch applies and retains epoch 1 anchor");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));

    let after_first_settle = carol.engine_metrics();
    assert_eq!(after_first_settle.settles, 1, "first settle counts");
    assert_eq!(
        after_first_settle.post_settle_reorgs, 0,
        "a first settle is never a reorg"
    );
    assert_eq!(after_first_settle.observed_reorg_rate(), Some(0.0));

    // A competing same-epoch commit arrives after the settle. Convergence
    // rolls back to the retained anchor and re-selects; whether it reorgs
    // depends on the content-derived branch tiebreak.
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    let bob_commit = route(bob_commit, &group_id);

    let bob_wins = committer_wins(&bob.self_id(), &alice.self_id());

    carol
        .buffer_openmls_convergence_message_at(&group_id, bob_commit.clone(), 3_100)
        .expect("late bob commit buffered");
    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 4_500)
        .expect("late same-epoch commit replays from retained anchor");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);

    let after_late_commit = carol.engine_metrics();
    assert_eq!(
        after_late_commit.settles, 2,
        "the second applied settle is counted"
    );
    if bob_wins {
        // The selection flipped to a different branch that forks below the
        // previously-applied tip (epoch 2): a post-settle reorg.
        assert_eq!(after_late_commit.post_settle_reorgs, 1);
        assert_eq!(after_late_commit.observed_reorg_rate(), Some(0.5));
        // Rewind depth = previous_applied_tip (2) - new_fork_epoch (1) = 1.
        assert_eq!(after_late_commit.reorg_rewind_depth.sample_count(), 1);
        let depth_one = after_late_commit
            .reorg_rewind_depth
            .buckets
            .iter()
            .find(|bucket| bucket.upper_bound == 1)
            .expect("depth-1 bucket");
        assert_eq!(depth_one.count, 1);
        // Lateness = reorg time (4_500) - superseded settle time (3_000) =
        // 1_500ms.
        assert_eq!(after_late_commit.reorg_lateness_ms.sample_count(), 1);
        let lateness = after_late_commit
            .reorg_lateness_ms
            .buckets
            .iter()
            .find(|bucket| bucket.upper_bound == 1_500)
            .expect("1500ms bucket");
        assert_eq!(lateness.count, 1);
    } else {
        // Alice's branch wins again: re-selecting the same branch is a settle
        // but not a reorg.
        assert_eq!(after_late_commit.post_settle_reorgs, 0);
        assert_eq!(after_late_commit.observed_reorg_rate(), Some(0.0));
        assert_eq!(after_late_commit.reorg_rewind_depth.sample_count(), 0);
        assert_eq!(after_late_commit.reorg_lateness_ms.sample_count(), 0);
    }
}

#[tokio::test]
async fn rebuilt_engine_replays_late_same_epoch_commit_from_retained_anchor() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");
    let policy = CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    };

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-retained-anchor-restart".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_group_convergence_policy(&group_id, policy.clone())
        .expect("group convergence policy persisted");

    let david_kp = david.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (alice_commit, _alice_pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, alice_commit.clone(), 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("alice branch applies and retains epoch 1 anchor");
    assert_eq!(
        carol_storage.get_group(&group_id).unwrap().epoch,
        EpochId(2)
    );
    drop(carol);

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    let bob_commit = route(bob_commit, &group_id);
    let bob_wins = committer_wins(&bob.self_id(), &alice.self_id());

    let mut carol = build_client_with_storage(b"carol", carol_storage.clone());
    carol
        .buffer_openmls_convergence_message_at(&group_id, bob_commit.clone(), 2_000)
        .expect("late bob commit buffered after restart");
    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 3_000_000)
        .expect("rebuilt engine replays late same-epoch commit from retained anchor");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_ne!(
        carol_storage
            .get_message(&content_id(&bob_commit))
            .unwrap()
            .state,
        MessageState::Created,
        "late commit should be resolved after engine rebuild"
    );
    if bob_wins {
        assert_message_state(&carol_storage, &bob_commit, MessageState::Processed);
    } else {
        assert_message_state(&carol_storage, &bob_commit, MessageState::EpochInvalidated);
    }
    let members = carol.members(&group_id).unwrap();
    assert_eq!(
        members.iter().any(|member| member.id == eve.self_id()),
        bob_wins
    );
    assert_eq!(
        members.iter().any(|member| member.id == david.self_id()),
        !bob_wins
    );
}

/// U6 resolution (option-c plan): the historical-rewind route and the
/// no-rewind route agree — a within-horizon losing commit is deferred as
/// `ConvergenceDeferred` / `NonSelectedEligibleBranch` on BOTH, so a later
/// pass can reconsider it. There is no third terminality asymmetry.
///
/// The three rewind tests above
/// (`engine_replays_late_same_epoch_commit_from_retained_anchor`,
/// `engine_ingest_buffers_late_same_epoch_commit_within_rewind_horizon`,
/// `rebuilt_engine_replays_late_same_epoch_commit_from_retained_anchor`)
/// *appear* to pin `EpochInvalidated` for the same shape, but their
/// `bob_wins == false` arms are dead: `committer_wins(&bob, &alice)` is
/// deterministically true for the label-derived identities, so the late
/// commit always WINS there and the terminal expectation never executes
/// (verified empirically by tracing every `EpochInvalidated` write site —
/// none fires during those tests). This test exercises the mirrored,
/// previously uncovered arm: the deterministic tiebreak WINNER is applied
/// first, and the LOSER arrives late within the rewind horizon.
#[tokio::test]
async fn rewind_and_no_rewind_routes_agree_on_losing_commit_disposition() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "u6-probe".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");

    // Bob is the deterministic tiebreak winner against Alice.
    assert!(committer_wins(&bob.self_id(), &alice.self_id()));

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    let bob_commit = route(bob_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, bob_commit.clone(), 1_000)
        .expect("bob commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("bob branch applies and retains epoch 1 anchor");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));

    let david_kp = david.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (alice_commit, _alice_pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, alice_commit.clone(), 2_000)
        .expect("late alice commit buffered");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 3_000_000)
        .expect("late losing commit resolves");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);

    // The rewind route defers the within-horizon loser exactly like the
    // no-rewind route (`convergence_rollback_emits_commit_rolled_back_for_
    // losing_branch` above): reconsiderable, not terminal.
    assert!(
        result.deferred_messages.iter().any(|deferred| {
            deferred.kind == MessageKind::Commit
                && deferred.reason == DeferredMessageReason::NonSelectedEligibleBranch
                && deferred.message_id == content_hex(&alice_commit)
        }),
        "expected the late losing commit deferred as NonSelectedEligibleBranch, got {:?}",
        result.deferred_messages
    );
    assert_message_state(
        &carol_storage,
        &alice_commit,
        MessageState::ConvergenceDeferred,
    );
    assert_message_state(&carol_storage, &bob_commit, MessageState::Processed);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    let members = carol.members(&group_id).unwrap();
    assert!(members.iter().any(|member| member.id == eve.self_id()));
    assert!(!members.iter().any(|member| member.id == david.self_id()));
}

#[tokio::test]
async fn engine_reports_missing_retained_anchor_without_mutating_late_commit() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-missing-anchor".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");

    let david_kp = david.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (alice_commit, _alice_pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, alice_commit, 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("alice branch applies and retains epoch 1 anchor");
    carol_storage
        .release_group_snapshot(&group_id, "openmls-retained-anchor-1")
        .expect("test removes retained anchor");

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    let bob_commit = route(bob_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, bob_commit.clone(), 2_000)
        .expect("late bob commit buffered");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 3_000_000)
        .expect("missing retained anchor is reported as a local result");

    assert_eq!(
        result.errors,
        vec![CanonicalizationError::MissingRetainedAnchor]
    );
    assert_eq!(result.convergence_status, ConvergenceStatus::Blocked);
    // retained-history.md:30-31 — canonical state is left unchanged...
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &bob_commit, MessageState::Created);
    assert!(
        !carol
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == eve.self_id())
    );
    // ...and the group moves to Unrecoverable, which the engine surfaces via a
    // GroupUnrecoverable event.
    assert!(
        carol.drain_events().iter().any(|e| matches!(
            e,
            GroupEvent::GroupUnrecoverable { group_id: g } if g == &group_id
        )),
        "engine must emit GroupUnrecoverable on MissingRetainedAnchor"
    );

    // group-state.md:50-51,65 — while Unrecoverable, the client MUST stop
    // applying group-state changes. A second convergence pass still reports
    // MissingRetainedAnchor and applies nothing.
    let second = carol
        .converge_stored_openmls_messages_at(&group_id, 4_000_000)
        .expect("convergence on an unrecoverable group is a no-op result");
    assert_eq!(
        second.errors,
        vec![CanonicalizationError::MissingRetainedAnchor]
    );
    assert_eq!(second.convergence_status, ConvergenceStatus::Blocked);
    assert!(second.selected_tip.is_none());
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &bob_commit, MessageState::Created);

    // Inbound ingest is halted too: a fresh inbound group message is retained
    // (buffered), not applied, until a verified repair path.
    let outcome = carol
        .ingest(bob_commit.clone())
        .await
        .expect("ingest does not error on an unrecoverable group");
    assert!(
        matches!(
            outcome,
            IngestOutcome::Buffered { .. } | IngestOutcome::Stale { .. }
        ),
        "inbound must not be applied while Unrecoverable; got {outcome:?}"
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
}

#[tokio::test]
async fn durable_unrecoverable_halt_blocks_queued_drain_without_rehydration() {
    let (mut alice, storage) = build_client(b"alice");
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "queued-unrecoverable".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: MessageId::new(b"queued-before-durable-halt".to_vec()),
            group_id: group_id.clone(),
            intent: SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&alice, b"must remain queued"),
            },
            created_at_ms: 1,
        })
        .unwrap();
    let mut stored_group = storage.get_group(&group_id).unwrap();
    stored_group.unrecoverable = true;
    storage.put_group(&stored_group).unwrap();

    let drained = alice
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .expect("durable halt pauses queued drain");
    assert!(drained.is_empty());
    assert_eq!(
        storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1,
        "halted queued work must remain available after verified repair"
    );
}

#[tokio::test]
async fn unrecoverable_halt_survives_engine_restart_until_verified_repair() {
    // mdk#971: Unrecoverable must persist across restart; hydration must not
    // silently set_stable over an unrepaired base.
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-unrecoverable-restart".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");

    let david_kp = david.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = evolution(alice_invite);
    alice.confirm_published(alice_pending).await.unwrap();
    let alice_commit = route(alice_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, alice_commit, 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("alice branch applies and retains epoch 1 anchor");
    carol_storage
        .release_group_snapshot(&group_id, "openmls-retained-anchor-1")
        .expect("test removes retained anchor");

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    let bob_commit = route(bob_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, bob_commit.clone(), 2_000)
        .expect("late bob commit buffered");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 3_000_000)
        .expect("missing retained anchor is reported as a local result");
    assert_eq!(
        result.errors,
        vec![CanonicalizationError::MissingRetainedAnchor]
    );
    assert!(
        carol_storage.get_group(&group_id).unwrap().unrecoverable,
        "MissingRetainedAnchor must persist Unrecoverable on the group record"
    );
    drop(carol);

    let mut restarted = build_client_with_storage(b"carol", carol_storage.clone());
    restarted
        .hydrate_all_stored_groups()
        .expect("session-open hydration succeeds");
    let hydration_events = restarted.drain_events();
    assert!(
        hydration_events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupUnrecoverable { group_id: halted } if halted == &group_id
        )),
        "restart must re-surface the durable repair requirement; got {hydration_events:?}"
    );
    assert!(
        carol_storage.get_group(&group_id).unwrap().unrecoverable,
        "durable Unrecoverable marker must survive restart"
    );

    let after_restart = restarted
        .converge_stored_openmls_messages_at(&group_id, 4_000_000)
        .expect("convergence on a restarted unrecoverable group is a no-op result");
    assert_eq!(
        after_restart.errors,
        vec![CanonicalizationError::MissingRetainedAnchor]
    );
    assert_eq!(after_restart.convergence_status, ConvergenceStatus::Blocked);
    assert!(after_restart.selected_tip.is_none());
    assert_eq!(restarted.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &bob_commit, MessageState::Created);
    assert!(
        !restarted
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == eve.self_id())
    );

    let outcome = restarted
        .ingest(bob_commit.clone())
        .await
        .expect("ingest does not error on a restarted unrecoverable group");
    assert!(
        matches!(
            outcome,
            IngestOutcome::Buffered { .. } | IngestOutcome::Stale { .. }
        ),
        "inbound must stay halted after restart; got {outcome:?}"
    );
    assert_eq!(restarted.epoch(&group_id).unwrap(), EpochId(2));

    let send_err = restarted
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&restarted, b"must not send while halted"),
        })
        .await
        .expect_err("send must refuse Unrecoverable after restart");
    assert!(
        matches!(
            send_err,
            cgka_traits::error::EngineError::InvalidTransition(ref t)
                if t.from == "Unrecoverable"
        ),
        "send must report Unrecoverable; got {send_err:?}"
    );

    // The durable-retention path observes the same terminal boundary: a halted
    // group accepts no *new* work. That is a narrower claim than it looks —
    // intents accepted before the halt are held for the one legal exit and are
    // delivered after a verified repair, which
    // `intent_retained_before_a_halt_is_delivered_after_a_verified_repair`
    // pins. Refusing here keeps the queue to work the engine accepted while it
    // still had a live epoch to accept it against.
    //
    // The whole gate is pinned, not just `from`. `queue_app_message` passes two
    // gates that both report `from: "Unrecoverable"` — the durable halt sync in
    // `validate_send_acceptance` and the retention-boundary check after it — so
    // matching `from` alone cannot tell which one fired, and reordering them
    // would keep this test green while moving the refusal behind the retention
    // check. Pinning `to` and `reason` makes that reordering fail loudly.
    let queue_err = restarted
        .queue_app_message(
            group_id.clone(),
            app_payload_for(&restarted, b"must not be retained while halted"),
        )
        .await
        .expect_err("queue_app_message must refuse Unrecoverable");
    let cgka_traits::error::EngineError::InvalidTransition(queue_transition) = queue_err else {
        panic!("queue_app_message must report an illegal transition; got {queue_err:?}")
    };
    assert_eq!(
        (
            queue_transition.from,
            queue_transition.to,
            queue_transition.reason
        ),
        (
            "Unrecoverable",
            "app_message",
            "group is Unrecoverable pending verified repair"
        ),
        "the durable halt sync must be the gate that refuses, ahead of the retention boundary"
    );

    // A verified replacement Welcome must be able to repair a frozen active
    // record. Alice removes Carol from the live branch and re-adds her with a
    // fresh KeyPackage; Carol intentionally never ingests the removal, so her
    // frozen record still lists herself when the repair Welcome arrives.
    let repair_kp = restarted.fresh_key_package().await.unwrap();
    let remove = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![restarted.self_id()],
        })
        .await
        .unwrap();
    let (_remove_commit, remove_pending) = evolution(remove);
    alice.confirm_published(remove_pending).await.unwrap();
    let readd = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![repair_kp],
        })
        .await
        .unwrap();
    let (repair_pending, repair_welcome) = match readd {
        SendResult::GroupEvolution {
            pending,
            mut welcomes,
            ..
        } => (pending, welcomes.remove(0)),
        other => panic!("expected repair GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(repair_pending).await.unwrap();
    restarted
        .join_welcome(repair_welcome)
        .await
        .expect("authenticated replacement Welcome repairs Unrecoverable");
    assert!(
        !carol_storage.get_group(&group_id).unwrap().unrecoverable,
        "verified repair must clear the durable marker"
    );
    assert_eq!(
        restarted.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap(),
        "replacement Welcome must install the verified live state"
    );
    restarted
        .send(SendIntent::AppMessage {
            group_id,
            payload: app_payload_for(&restarted, b"send resumes after verified repair"),
        })
        .await
        .expect("verified repair returns the group to Stable");
}

/// A group that accepted an app message and then halted `Unrecoverable`, with
/// the verified repair Welcome staged but not yet joined — the shared starting
/// point for both halves of the mdk#1106 hold-through-repair promise. Each test
/// joins the Welcome itself, because *when* the repair lands is what they
/// differ on.
struct HaltedAwaitingRepair {
    alice: Engine<SqliteAccountStorage>,
    carol: Engine<SqliteAccountStorage>,
    carol_storage: SqliteAccountStorage,
    group_id: cgka_traits::GroupId,
    intent_id: cgka_traits::MessageId,
    /// The epoch the intent was accepted at. The repair moves the group past
    /// it, so a drain at the post-repair epoch proves re-encryption.
    queue_time_epoch: cgka_traits::EpochId,
    repair_welcome: cgka_traits::transport::TransportMessage,
}

async fn retain_intent_then_halt_awaiting_repair() -> HaltedAwaitingRepair {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "retained-across-repair".into(),
            description: String::new(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    // Carol's message is accepted and retained before anything goes wrong.
    let queue_time_epoch = carol.epoch(&group_id).unwrap();
    let payload = app_payload_for(&carol, b"typed before the halt");
    let intent_id = match carol
        .queue_app_message(group_id.clone(), payload.clone())
        .await
        .expect("a non-terminal group retains an app message")
    {
        SendResult::Queued { intent_id, .. } => intent_id,
        other => panic!("expected durable retention, got {other:?}"),
    };

    // The group then halts Unrecoverable durably (mdk#971).
    let mut halted_record = carol_storage.get_group(&group_id).unwrap();
    halted_record.unrecoverable = true;
    carol_storage.put_group(&halted_record).unwrap();

    let blocked = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .expect("the durable halt pauses the drain");
    assert!(blocked.is_empty(), "nothing may publish while halted");
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .iter()
            .map(|queued| queued.id.clone())
            .collect::<Vec<_>>(),
        vec![intent_id.clone()],
        "already-accepted work must survive the halt for its one legal exit"
    );

    // The one legal exit: Alice removes Carol from the live branch and re-adds
    // her with a fresh KeyPackage. Carol never ingests the removal, so her
    // frozen record still lists her when the repair Welcome arrives.
    let repair_kp = carol.fresh_key_package().await.unwrap();
    let (_remove_commit, remove_pending) = evolution(
        alice
            .send(SendIntent::RemoveMembers {
                group_id: group_id.clone(),
                members: vec![carol.self_id()],
            })
            .await
            .unwrap(),
    );
    alice.confirm_published(remove_pending).await.unwrap();
    let (repair_pending, repair_welcome) = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![repair_kp],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution {
            pending,
            mut welcomes,
            ..
        } => (pending, welcomes.remove(0)),
        other => panic!("expected repair GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(repair_pending).await.unwrap();

    HaltedAwaitingRepair {
        alice,
        carol,
        carol_storage,
        group_id,
        intent_id,
        queue_time_epoch,
        repair_welcome,
    }
}

#[tokio::test]
async fn intent_retained_before_a_halt_is_delivered_after_a_verified_repair() {
    // mdk#1106 pins that a halted group's queued work "must remain available
    // after verified repair". This is the other half of that promise: the
    // retained intent must actually reach the group once the repair lands.
    //
    // It can, because retention holds an *intent*, not ciphertext. The drain
    // re-prepares the payload against whatever canonical state the group ended
    // up on, so a message accepted before the halt is encrypted under the
    // post-repair epoch and every current member can read it. Holding across
    // the halt therefore promises a delivery the engine can keep.
    //
    // This half covers the restart shape; the no-restart shape is
    // `a_verified_repair_schedules_the_drain_for_retained_intents_without_a_restart`.
    let HaltedAwaitingRepair {
        mut alice,
        mut carol,
        carol_storage,
        group_id,
        intent_id,
        queue_time_epoch,
        repair_welcome,
    } = retain_intent_then_halt_awaiting_repair().await;

    carol
        .join_welcome(repair_welcome)
        .await
        .expect("an authenticated replacement Welcome repairs Unrecoverable");
    assert!(
        !carol_storage.get_group(&group_id).unwrap().unrecoverable,
        "verified repair must clear the durable marker"
    );

    // A restart is the realistic shape: the repair may well land in a later
    // session than the halt. Hydration must put the group back on the drain
    // schedule because it still holds durable intents.
    drop(carol);
    let mut repaired = build_client_with_storage(b"carol", carol_storage.clone());
    repaired
        .hydrate_all_stored_groups()
        .expect("session-open hydration succeeds after repair");
    assert!(
        repaired
            .drain_pending_convergence_groups()
            .contains(&group_id),
        "hydration must re-schedule a repaired group that still holds intents"
    );

    let repaired_epoch = repaired.epoch(&group_id).unwrap();
    assert_eq!(
        repaired_epoch,
        alice.epoch(&group_id).unwrap(),
        "the replacement Welcome installs the verified live state"
    );
    assert!(
        repaired_epoch > queue_time_epoch,
        "the repair must move the epoch, or re-encryption proves nothing: \
         {queue_time_epoch:?} -> {repaired_epoch:?}"
    );

    let mut drained = repaired
        .converge_and_drain_queued_outbound_intents(&group_id, 2_000_000)
        .await
        .expect("a repaired group drains its retained work");
    assert_eq!(
        drained.len(),
        1,
        "expected exactly the retained message, got {drained:?}"
    );
    let SendResult::ApplicationMessage {
        msg, source_epoch, ..
    } = drained.remove(0)
    else {
        panic!("a retained app-message intent drains as an application message")
    };
    assert_eq!(
        source_epoch, repaired_epoch,
        "the retained intent must be encrypted under the post-repair epoch"
    );

    // And that is delivery, not bookkeeping: Alice, on the repaired branch,
    // decrypts the message Carol wrote before the halt.
    assert!(matches!(
        alice.ingest(route(msg, &group_id)).await.unwrap(),
        IngestOutcome::Processed
    ));
    let received = alice
        .drain_events()
        .into_iter()
        .find_map(|event| match event {
            GroupEvent::MessageReceived {
                sender, payload, ..
            } => Some((sender, payload)),
            _ => None,
        })
        .expect("alice observes the retained message");
    assert_eq!(received.0, repaired.self_id());
    assert_eq!(app_content(&received.1), b"typed before the halt");

    // The durable intent is retired only once the app confirms publication.
    repaired
        .confirm_queued_outbound_intent(&intent_id)
        .expect("the drained intent is the one that was queued before the halt");
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_verified_repair_schedules_the_drain_for_retained_intents_without_a_restart() {
    // The restart half above passes because session-open hydration re-arms the
    // drain from the durable queue. That hides the case a live client actually
    // hits: the repair Welcome arrives in the same session as the halt.
    //
    // A running host releases retained work by draining
    // `drain_pending_convergence_groups` after each engine call. If the repair
    // does not put the group on that list, the message the user typed before
    // the halt sits durable and unsent until unrelated traffic happens to
    // schedule the group or the process restarts — the same reason a publish
    // outcome schedules the drain.
    let HaltedAwaitingRepair {
        mut alice,
        mut carol,
        carol_storage,
        group_id,
        intent_id,
        queue_time_epoch,
        repair_welcome,
    } = retain_intent_then_halt_awaiting_repair().await;

    // Everything scheduled before the repair has already been taken by the
    // host's drain, so what remains is what the repair itself scheduled.
    let scheduled_before_repair = carol.drain_pending_convergence_groups();

    carol
        .join_welcome(repair_welcome)
        .await
        .expect("an authenticated replacement Welcome repairs Unrecoverable");
    assert!(
        !carol_storage.get_group(&group_id).unwrap().unrecoverable,
        "verified repair must clear the durable marker"
    );

    assert!(
        carol.drain_pending_convergence_groups().contains(&group_id),
        "a verified repair must schedule the drain for a group that still holds \
         retained intents; scheduled before the repair: {scheduled_before_repair:?}"
    );

    let repaired_epoch = carol.epoch(&group_id).unwrap();
    assert!(
        repaired_epoch > queue_time_epoch,
        "the repair must move the epoch, or re-encryption proves nothing: \
         {queue_time_epoch:?} -> {repaired_epoch:?}"
    );

    let mut drained = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 2_000_000)
        .await
        .expect("a repaired group drains its retained work");
    assert_eq!(
        drained.len(),
        1,
        "expected exactly the retained message, got {drained:?}"
    );
    let SendResult::ApplicationMessage {
        msg, source_epoch, ..
    } = drained.remove(0)
    else {
        panic!("a retained app-message intent drains as an application message")
    };
    assert_eq!(
        source_epoch, repaired_epoch,
        "the retained intent must be encrypted under the post-repair epoch"
    );

    // Delivery, not bookkeeping: Alice decrypts what Carol typed before the halt.
    assert!(matches!(
        alice.ingest(route(msg, &group_id)).await.unwrap(),
        IngestOutcome::Processed
    ));
    let received = alice
        .drain_events()
        .into_iter()
        .find_map(|event| match event {
            GroupEvent::MessageReceived {
                sender, payload, ..
            } => Some((sender, payload)),
            _ => None,
        })
        .expect("alice observes the retained message");
    assert_eq!(received.0, carol.self_id());
    assert_eq!(app_content(&received.1), b"typed before the halt");

    carol
        .confirm_queued_outbound_intent(&intent_id)
        .expect("the drained intent is the one that was queued before the halt");
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

#[cfg(feature = "test-conformance-snapshot")]
#[tokio::test]
async fn a_settled_convergence_pass_leaves_no_unscheduled_retained_intent() {
    // Retention across a halt is the dramatic case; this is the ordinary one.
    // A `Stable` observer inside an open convergence pass also retains an app
    // message, and the same promise applies: something must bring the drain
    // back, and the engine's own progress projection must say so.
    //
    // Two signals carry that, and a host needs both. The schedule edge tells a
    // running host to drain now; the structural-progress projection is the
    // level state a scheduler re-reads after it has consumed that edge. A drain
    // that consumes the edge without releasing the intent — because the pass
    // had not settled yet — must not leave the projection claiming the group is
    // idle while a user's message is still durable and unsent.
    let (mut alice, _alice_storage) = build_client(b"alice");
    let carol_storage = SqliteAccountStorage::in_memory().unwrap();
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let mut carol =
        build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock.clone());
    let mut david = build_client(b"david").0;

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "queued-intent-scheduling".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (commit, invite_pending) = evolution(invite);
    alice.confirm_published(invite_pending).await.unwrap();
    assert!(matches!(
        carol.ingest(route(commit, &group_id)).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    assert_eq!(
        carol_storage
            .convergence_pass(&group_id)
            .unwrap()
            .expect("the buffered commit opens a pass")
            .cutoff_monotonic_ms(),
        2_000
    );

    // A running host has already taken everything the ingest produced, so what
    // the assertions below observe is what the send itself left behind.
    carol.drain_events();
    let scheduled_before_send = carol.drain_pending_convergence_groups();

    let queued = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"typed inside the pass window"),
        })
        .await
        .unwrap();
    let intent_id = match queued {
        SendResult::Queued { intent_id, .. } => intent_id,
        other => panic!("an unsettled pass retains the send, got {other:?}"),
    };
    assert!(
        carol.drain_pending_convergence_groups().contains(&group_id),
        "queueing a durable outbound intent must schedule the drain that releases \
         it; scheduled before the send: {scheduled_before_send:?}"
    );

    // The pass is still inside its quiescence window, so the intent's exit is
    // the cutoff, not a drain that can run now.
    let waiting = carol
        .conformance_structural_progress_snapshot(&group_id)
        .expect("read-only conformance progress");
    assert_eq!(waiting.pending_work.queued_outbound_intents, 1);
    assert_eq!(waiting.earliest_next_wake_monotonic_ms, Some(2_000));
    assert_eq!(
        waiting.runnable_work, 0,
        "an intent waiting on an open pass rides the cutoff wake and must not \
         report work a drain would refuse: {waiting:?}"
    );

    // The host wakes at the cutoff and settles the pass — the ordinary prepass a
    // runtime runs before it drains. That settles convergence without releasing
    // the intent, and the schedule edge above has already been consumed.
    clock.advance_ms(1_500);
    assert!(
        carol
            .advance_convergence_inputs_until_settled(&group_id, 2_500)
            .await
            .unwrap(),
        "the cutoff has passed, so the pass settles"
    );
    carol.drain_events();

    let settled = carol
        .conformance_structural_progress_snapshot(&group_id)
        .expect("read-only conformance progress");
    assert_eq!(settled.pending_work.queued_outbound_intents, 1);
    assert!(
        settled.runnable_work > 0 || settled.earliest_next_wake_monotonic_ms.is_some(),
        "a durable intent nobody has published yet must keep the group armed, \
         not report an idle group: {settled:?}"
    );

    // And that is a message, not bookkeeping: the drain publishes it under the
    // post-settlement epoch and Alice reads it.
    let mut drained = carol
        .advance_convergence(&group_id)
        .await
        .expect("the armed drain releases the retained intent");
    assert_eq!(
        drained.len(),
        1,
        "expected exactly the retained message, got {drained:?}"
    );
    let SendResult::ApplicationMessage {
        msg, source_epoch, ..
    } = drained.remove(0)
    else {
        panic!("a retained app-message intent drains as an application message")
    };
    assert_eq!(source_epoch, carol.epoch(&group_id).unwrap());
    assert!(matches!(
        alice.ingest(route(msg, &group_id)).await.unwrap(),
        IngestOutcome::Processed
    ));
    let received = alice
        .drain_events()
        .into_iter()
        .find_map(|event| match event {
            GroupEvent::MessageReceived {
                sender, payload, ..
            } => Some((sender, payload)),
            _ => None,
        })
        .expect("alice observes the retained message");
    assert_eq!(received.0, carol.self_id());
    assert_eq!(app_content(&received.1), b"typed inside the pass window");

    carol
        .confirm_queued_outbound_intent(&intent_id)
        .expect("the drained intent is the one the pass window retained");
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn engine_prunes_retained_anchor_snapshots_to_rewind_horizon() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-retained-anchor-prune".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();
    let commit_david = route(commit_david, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_david, 1_000)
        .expect("david commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("david branch applies");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_eve, _pending_eve) = evolution(invite_eve);
    let commit_eve = route(commit_eve, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_eve, 2_000)
        .expect("eve commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 3_000_000)
        .expect("eve branch applies");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));

    let snapshots = carol_storage
        .list_group_snapshots(&group_id)
        .expect("snapshots list");
    assert!(
        !snapshots.contains(&"openmls-retained-anchor-1".to_string()),
        "epoch 1 anchor should be pruned once max rewind is 1 at epoch 3: {snapshots:?}"
    );
    assert!(snapshots.contains(&"openmls-retained-anchor-2".to_string()));
    assert!(snapshots.contains(&"openmls-retained-anchor-3".to_string()));
}

#[tokio::test]
async fn engine_does_not_reseed_commit_older_than_retained_anchor() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");
    let (mut frank, _frank_storage) = build_client(b"frank");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-old-commit-invalidated".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");

    let frank_kp = frank.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
        })
        .await
        .unwrap();
    let (stale_bob_commit, _bob_pending) = evolution(bob_invite);
    let stale_bob_commit = route(stale_bob_commit, &group_id);

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();
    let commit_david = route(commit_david, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_david, 1_000)
        .expect("david commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("david branch applies");

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_eve, _pending_eve) = evolution(invite_eve);
    let commit_eve = route(commit_eve, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_eve, 2_000)
        .expect("eve commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 3_000_000)
        .expect("eve branch applies");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));

    carol
        .buffer_openmls_convergence_message_at(&group_id, stale_bob_commit.clone(), 4_000)
        .expect("stale bob commit buffered");
    let result = carol
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("stale commit outside the retained horizon is ignored");

    assert!(result.dropped_messages.is_empty());
    assert_message_state(&carol_storage, &stale_bob_commit, MessageState::Created);
    assert!(
        carol_storage
            .convergence_pass(&group_id)
            .unwrap()
            .is_some_and(|pass| {
                pass.members
                    .iter()
                    .all(|member| member.message_id != content_id(&stale_bob_commit))
            }),
        "below-anchor history must not be copied into the durable pass"
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
    assert!(
        !carol
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == frank.self_id())
    );
}

#[tokio::test]
async fn rebuilt_engine_does_not_reseed_commit_older_than_retained_anchor() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");
    let (mut frank, _frank_storage) = build_client(b"frank");
    let policy = CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    };

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-old-commit-invalidated-restart".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_group_convergence_policy(&group_id, policy.clone())
        .expect("group convergence policy persisted");

    let frank_kp = frank.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
        })
        .await
        .unwrap();
    let (stale_bob_commit, _bob_pending) = evolution(bob_invite);
    let stale_bob_commit = route(stale_bob_commit, &group_id);

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();
    let commit_david = route(commit_david, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_david, 1_000)
        .expect("david commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("david branch applies");

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_eve, _pending_eve) = evolution(invite_eve);
    let commit_eve = route(commit_eve, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit_eve, 2_000)
        .expect("eve commit buffered");
    carol
        .converge_stored_openmls_messages_at(&group_id, 3_000_000)
        .expect("eve branch applies");
    assert_eq!(
        carol_storage.get_group(&group_id).unwrap().epoch,
        EpochId(3)
    );
    drop(carol);

    let mut carol = build_client_with_storage(b"carol", carol_storage.clone());
    carol
        .buffer_openmls_convergence_message_at(&group_id, stale_bob_commit.clone(), 4_000)
        .expect("stale bob commit buffered after restart");
    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 5_000_000)
        .expect("rebuilt engine ignores input outside the retained horizon");

    assert!(result.dropped_messages.is_empty());
    assert_message_state(&carol_storage, &stale_bob_commit, MessageState::Created);
    assert_eq!(
        carol_storage.get_group(&group_id).unwrap().epoch,
        EpochId(3)
    );
    assert!(
        !carol
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == frank.self_id())
    );
}

#[tokio::test]
async fn engine_ingest_buffers_future_epoch_app_message_as_convergence_witness() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-ingest-app-witness".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, pending) = evolution(invite);
    alice.confirm_published(pending).await.unwrap();
    let app_msg = send_app(&mut alice, &group_id, b"future epoch witness".to_vec()).await;

    let outcome = carol.ingest(app_msg.clone()).await.unwrap();

    assert!(matches!(
        outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_message_state(&carol_storage, &app_msg, MessageState::Created);

    carol
        .ingest(route(commit, &group_id))
        .await
        .expect("commit is buffered by ingest");
    // `carol` buffered these messages through `ingest`, which stamps the
    // convergence input time with the engine's real monotonic clock
    // (`convergence_now_ms`). Pass a logical `now_ms` far past the quiescence
    // window (matching the other ingest-then-converge tests in this file) so the
    // settle is deterministic: a small value like 2_000 races the real elapsed
    // time under parallel load and only intermittently clears quiescence.
    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("future app witness applies after selected commit");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(result.accepted_app_messages, vec![content_hex(&app_msg)]);
    assert_message_state(&carol_storage, &app_msg, MessageState::Processed);

    let events = carol.drain_events();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                GroupEvent::MessageReceived { group_id: event_group, payload, .. }
                    if *event_group == group_id && app_content(payload) == b"future epoch witness"
            )
        }),
        "expected accepted app message event after canonical convergence, got {events:?}"
    );
}

#[tokio::test]
async fn future_app_without_reachable_commit_is_retained_without_gating_sends() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "future-app-no-candidate".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (_withheld_commit, pending) = evolution(invite);
    alice.confirm_published(pending).await.unwrap();
    let future_app = send_app(&mut alice, &group_id, b"waiting for parent".to_vec()).await;

    assert!(matches!(
        carol.ingest(future_app.clone()).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    assert_message_state(&carol_storage, &future_app, MessageState::Created);
    assert!(
        carol_storage.convergence_pass(&group_id).unwrap().is_none(),
        "an app payload without a reachable candidate branch must not open a pass"
    );
    assert!(
        !carol.has_pending_convergence_inputs(&group_id).unwrap(),
        "an unresolved payload disposition alone must not make group state ambiguous"
    );

    let sent = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"current branch remains usable"),
        })
        .await
        .unwrap();
    assert!(
        matches!(sent, SendResult::ApplicationMessage { .. }),
        "future app without a candidate commit must not gate sends, got {sent:?}"
    );
}

/// Regression for mdk#383 (audit item S3 on the convergence/replay seam): a
/// replayed application message whose attribution fails validation is never
/// surfaced as `MessageReceived` and lands in a terminal state, exactly as on
/// the direct ingest seam.
///
/// The exploit payload is a `MarmotAppEvent` whose `pubkey` is the empty
/// string. Pre-fix, the replay arm validated it against raw sender bytes that
/// default to empty when the MLS sender leaf does not resolve to a validated
/// member id — `hex::encode([]) == ""` matched the forged `pubkey` and the
/// message surfaced with a blank, unauthenticated author. A truly
/// unresolvable in-tree sender cannot be constructed end-to-end (every
/// credential ingress validates identities — this fix is defense-in-depth),
/// so this test drives the forged payload through the real
/// ingest → stored-convergence → replay path from a resolvable sender and
/// pins the seam behavior: no `MessageReceived` for the forged payload, no
/// `MessageReceived` with an empty `MemberId` ever, and a terminal stored
/// state. The unresolvable-sender half of the guard is pinned by the
/// `app_payload` unit tests (empty `MemberId` rejected outright) and the
/// emit-side backstop in `emit_application_replay_events`.
#[tokio::test]
async fn terminal_undecryptable_app_emits_invalidation_without_message_received() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-forged-sender-app".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    // Alice advances the group epoch 1 -> 2, then authors an application
    // message at epoch 2 whose inner event claims an empty author.
    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, pending) = evolution(invite);
    alice.confirm_published(pending).await.unwrap();
    let forged_payload = MarmotAppEvent::new(
        "",
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "forged",
    )
    .encode()
    .expect("forged app event encodes");
    let forged_msg =
        raw_app_message_with_payload(&alice_storage, &alice.self_id(), &group_id, &forged_payload);

    // Carol buffers the future-epoch app message as a convergence witness,
    // then the commit, and converges — the forged message replays through the
    // stored-convergence seam at epoch 2.
    let outcome = carol.ingest(forged_msg.clone()).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    carol
        .ingest(route(commit, &group_id))
        .await
        .expect("commit is buffered by ingest");
    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("convergence settles despite forged app message");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert!(
        !result
            .accepted_app_messages
            .contains(&content_hex(&forged_msg)),
        "forged-attribution app message must not be accepted"
    );
    assert!(result.invalidated_app_messages.iter().any(|invalidated| {
        invalidated.message_id == content_hex(&forged_msg)
            && invalidated.reason == InvalidatedAppMessageReason::UndecryptableInCanonicalState
    }));
    // Message epoch (2) is at the settled tip (2): the failed validation is
    // terminal, not retryable — the message cannot re-enter convergence.
    assert_message_state(&carol_storage, &forged_msg, MessageState::EpochInvalidated);

    let events = carol.drain_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::AppMessageInvalidated {
                group_id: event_group,
                message_id,
                epoch: EpochId(2),
                reason: AppMessageInvalidationReason::UndecryptableInCanonicalState,
                ..
            } if *event_group == group_id && *message_id == content_id(&forged_msg)
        )),
        "terminal at-tip decrypt miss must emit AppMessageInvalidated, got {events:?}"
    );
    for event in &events {
        if let GroupEvent::MessageReceived {
            sender, payload, ..
        } = event
        {
            assert!(
                !sender.as_slice().is_empty(),
                "no MessageReceived may carry an empty MemberId, got {events:?}"
            );
            assert_ne!(
                payload, &forged_payload,
                "forged app message must not surface, got {events:?}"
            );
        }
    }
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
}

/// Regression for mdk#144: a future-epoch app message whose advancing commit
/// has not arrived receives the explicit `deferred` disposition and must not
/// emit `AppMessageInvalidated`. Otherwise the buffered message can never
/// re-enter convergence and is silently dropped once that commit arrives.
///
/// To reach the stored-convergence persistence path the pass must settle on a
/// tip: here convergence selects the epoch-2 commit while the app message
/// lives at epoch 3 (its commit withheld), so the message is deferred and
/// persisted alongside the applied branch.
///
/// An undecryptable message at or below the settled tip is instead stranded:
/// the awaited commit already passed on a branch it does not belong to, so it
/// remains terminal `EpochInvalidated`. That at/below-tip path is covered
/// end-to-end by the CLI test
/// `three_user_message_lifecycle_covers_invite_remove_and_later_delivery`.
#[tokio::test]
async fn future_epoch_app_message_stays_deferred_until_commit_arrives() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-future-epoch-retryable".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    // Alice advances the group epoch 1 -> 2 (invite david).
    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_to_epoch2, pending) = evolution(invite_david);
    alice.confirm_published(pending).await.unwrap();

    // Alice advances the group epoch 2 -> 3 (invite eve), then sends an app
    // message at epoch 3.
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_to_epoch3, pending) = evolution(invite_eve);
    alice.confirm_published(pending).await.unwrap();
    let app_msg = send_app(&mut alice, &group_id, b"future epoch payload".to_vec()).await;

    // Carol buffers the epoch-2 commit and the epoch-3 app message, but NOT
    // the epoch-3 commit. Convergence settles on epoch 2; the app message has
    // no candidate branch that decrypts it (it targets epoch 3), so it is
    // explicitly deferred as future-epoch input.
    carol
        .buffer_openmls_convergence_message_at(&group_id, route(commit_to_epoch2, &group_id), 1_000)
        .expect("epoch-2 commit buffered");
    carol
        .buffer_openmls_convergence_message_at(&group_id, app_msg.clone(), 1_000)
        .expect("future app message buffered");
    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("convergence settles on the epoch-2 commit");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert!(
        result.deferred_messages.iter().any(|deferred| {
            deferred.message_id == content_hex(&app_msg)
                && deferred.kind == MessageKind::AppMessage
                && deferred.reason == DeferredMessageReason::FutureEpoch
        }),
        "future-epoch app message should be explicitly deferred, got {:?}",
        result.deferred_messages
    );
    // The fix: durably deferred, not terminal. Pre-fix this was
    // EpochInvalidated and the message could never re-enter convergence.
    assert_message_state(&carol_storage, &app_msg, MessageState::ConvergenceDeferred);

    // The app must NOT have been told the message is permanently invalidated.
    let events = carol.drain_events();
    assert!(
        !events.iter().any(|event| matches!(
            event,
            GroupEvent::AppMessageInvalidated { message_id, .. } if *message_id == content_id(&app_msg)
        )),
        "retryable future-epoch app message must not emit AppMessageInvalidated, got {events:?}"
    );

    // Now the awaited epoch-3 commit arrives. Convergence must re-feed the
    // buffered app message (it was kept Retryable and not marked seen) and
    // apply it on the canonical branch.
    carol
        .buffer_openmls_convergence_message_at(&group_id, route(commit_to_epoch3, &group_id), 2_000)
        .expect("epoch-3 commit buffered");
    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 2_000_000)
        .expect("convergence applies the re-fed app message after the commit lands");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(result.accepted_app_messages, vec![content_hex(&app_msg)]);
    assert_message_state(&carol_storage, &app_msg, MessageState::Processed);

    let events = carol.drain_events();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                GroupEvent::MessageReceived { group_id: event_group, payload, .. }
                    if *event_group == group_id && app_content(payload) == b"future epoch payload"
            )
        }),
        "expected the previously-buffered app message to be delivered after the commit, got {events:?}"
    );
}

#[tokio::test]
async fn engine_emits_only_canonical_branch_app_messages_after_convergence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-canonical-app-output".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = evolution(alice_invite);
    let (bob_commit, bob_pending) = evolution(bob_invite);
    let commit_messages = [
        route(alice_commit.clone(), &group_id),
        route(bob_commit.clone(), &group_id),
    ];

    alice.confirm_published(alice_pending).await.unwrap();
    bob.confirm_published(bob_pending).await.unwrap();
    let alice_app = send_app(&mut alice, &group_id, b"alice branch payload".to_vec()).await;
    let bob_app = send_app(&mut bob, &group_id, b"bob branch payload".to_vec()).await;
    let app_messages = [alice_app, bob_app];

    let selected_index = commit_tiebreak_winner_index(&alice.self_id(), &bob.self_id());
    let losing_index = 1 - selected_index;

    for message in commit_messages.iter().chain(app_messages.iter()) {
        carol
            .buffer_openmls_convergence_message_at(&group_id, message.clone(), 1_000)
            .expect("message buffered");
    }

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("stored OpenMLS messages converge");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        result.accepted_app_messages,
        vec![content_hex(&app_messages[selected_index])]
    );
    assert!(result.invalidated_app_messages.iter().any(|invalidated| {
        invalidated.message_id == content_hex(&app_messages[losing_index])
            && invalidated.reason == InvalidatedAppMessageReason::LosingBranch
    }));
    assert_message_state(
        &carol_storage,
        &app_messages[selected_index],
        MessageState::Processed,
    );
    assert_message_state(
        &carol_storage,
        &app_messages[losing_index],
        MessageState::EpochInvalidated,
    );

    let events = carol.drain_events();
    let received_payloads: Vec<Vec<u8>> = events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { payload, .. } => Some(app_content(payload)),
            _ => None,
        })
        .collect();
    assert_eq!(
        received_payloads,
        vec![if selected_index == 0 {
            b"alice branch payload".to_vec()
        } else {
            b"bob branch payload".to_vec()
        }]
    );
    assert!(events.iter().any(|event| {
        matches!(
            event,
            GroupEvent::AppMessageInvalidated {
                group_id: event_group,
                message_id,
                epoch,
                reason: AppMessageInvalidationReason::LosingBranch,
                decrypted_payload_ref: Some(_),
            } if *event_group == group_id
                && *message_id == content_id(&app_messages[losing_index])
                && *epoch == EpochId(2)
        )
    }));
}

/// mdk#965: an app message delivered from the initially-selected branch must
/// be withdrawn if a later-arriving competing commit wins a reorg.
#[tokio::test]
async fn late_reorg_invalidates_an_already_delivered_losing_branch_message() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "already-delivered-reorg".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = evolution(alice_invite);
    let (bob_commit, bob_pending) = evolution(bob_invite);
    let commits = [route(alice_commit, &group_id), route(bob_commit, &group_id)];
    alice.confirm_published(alice_pending).await.unwrap();
    bob.confirm_published(bob_pending).await.unwrap();
    let apps = [
        send_app(&mut alice, &group_id, b"late reorg alice".to_vec()).await,
        send_app(&mut bob, &group_id, b"late reorg bob".to_vec()).await,
    ];
    let winning_index = commit_tiebreak_winner_index(&alice.self_id(), &bob.self_id());
    let losing_index = 1 - winning_index;

    // Settle and deliver the branch that will lose once the deterministic
    // winner arrives late.
    carol
        .buffer_openmls_convergence_message_at(&group_id, commits[losing_index].clone(), 1_000)
        .unwrap();
    carol
        .buffer_openmls_convergence_message_at(&group_id, apps[losing_index].clone(), 1_000)
        .unwrap();
    let first = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    assert_eq!(
        first.accepted_app_messages,
        vec![content_hex(&apps[losing_index])]
    );
    assert!(carol.drain_events().iter().any(|event| {
        matches!(
            event,
            GroupEvent::MessageReceived { payload, .. }
                if app_content(payload)
                    == if losing_index == 0 {
                        b"late reorg alice".as_slice()
                    } else {
                        b"late reorg bob".as_slice()
                    }
        )
    }));

    carol
        .buffer_openmls_convergence_message_at(&group_id, commits[winning_index].clone(), 2_000)
        .unwrap();
    carol
        .buffer_openmls_convergence_message_at(&group_id, apps[winning_index].clone(), 2_000)
        .unwrap();
    let second = carol
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .unwrap();

    assert!(second.invalidated_app_messages.iter().any(|invalidated| {
        invalidated.message_id == content_hex(&apps[losing_index])
            && invalidated.reason == InvalidatedAppMessageReason::LosingBranch
    }));
    assert_message_state(
        &carol_storage,
        &apps[losing_index],
        MessageState::EpochInvalidated,
    );
    let losing_id = content_id(&apps[losing_index]);
    assert!(carol.drain_events().iter().any(|event| {
        matches!(
            event,
            GroupEvent::AppMessageInvalidated {
                message_id,
                reason: AppMessageInvalidationReason::LosingBranch,
                ..
            } if *message_id == losing_id
        )
    }));
}

#[tokio::test]
async fn rebuilt_engine_emits_canonical_app_message_after_convergence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-restart-app-output".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, pending) = evolution(invite);
    alice.confirm_published(pending).await.unwrap();
    let app_msg = send_app(&mut alice, &group_id, b"restart canonical payload".to_vec()).await;

    carol
        .ingest(app_msg.clone())
        .await
        .expect("future app message is stored");
    carol
        .ingest(route(commit, &group_id))
        .await
        .expect("commit is stored");
    let mut frozen_pass = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("collecting pass persisted before restart");
    frozen_pass.phase = cgka_traits::ConvergencePassPhase::Frozen;
    frozen_pass.frozen_at_wall_ms = Some(frozen_pass.cutoff_wall_ms());
    frozen_pass.cutoff_cause = Some(cgka_traits::ConvergenceCutoffCause::Quiescence);
    carol_storage.put_convergence_pass(&frozen_pass).unwrap();

    let mut restarted = EngineBuilder::new(carol_storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();

    let result = restarted
        .converge_stored_openmls_messages_at(&group_id, 2_000)
        .expect("rebuilt engine converges stored OpenMLS messages");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(restarted.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &app_msg, MessageState::Processed);
    let events = restarted.drain_events();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                GroupEvent::MessageReceived { group_id: event_group, payload, .. }
                    if *event_group == group_id
                        && app_content(payload) == b"restart canonical payload"
            )
        }),
        "expected rebuilt engine to emit canonical app payload, got {events:?}"
    );
}

#[tokio::test]
async fn collecting_pass_restart_preserves_remaining_window_and_backward_clock_fails_closed() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let carol_storage = SqliteAccountStorage::in_memory().unwrap();
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let mut carol =
        build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock.clone());
    let mut david = build_client(b"david").0;

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-collecting-restart".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (commit, _) = evolution(invite);
    carol
        .buffer_openmls_convergence_message(&group_id, route(commit, &group_id))
        .unwrap();

    clock.set_wall_ms(10_400);
    let mut restarted =
        build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock.clone());
    let remaining = restarted
        .prepare_convergence_cutoff_delay_ms(&group_id)
        .unwrap()
        .expect("collecting pass remains active");
    assert_eq!(
        remaining, 600,
        "restart must preserve the original 600ms remainder"
    );

    clock.set_wall_ms(20_000);
    let mut forwards =
        build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock.clone());
    assert_eq!(
        forwards
            .prepare_convergence_cutoff_delay_ms(&group_id)
            .unwrap(),
        Some(0),
        "a forward wall-clock jump past the persisted cutoff must make it immediately due"
    );

    clock.set_wall_ms(9_000);
    let mut backwards = build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock);
    assert_eq!(
        backwards
            .prepare_convergence_cutoff_delay_ms(&group_id)
            .unwrap(),
        Some(0),
        "a backward wall-clock jump in a new clock domain must make cutoff immediately due"
    );
}

#[cfg(all(
    feature = "test-conformance-snapshot",
    feature = "test-policy-overrides"
))]
#[tokio::test]
async fn conformance_progress_uses_the_schedulers_effective_policy_deadline() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let carol_storage = SqliteAccountStorage::in_memory().unwrap();
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let mut carol =
        build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock.clone());
    let mut david = build_client(b"david").0;

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "conformance-effective-deadline".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (commit, _) = evolution(invite);
    carol
        .buffer_openmls_convergence_message(&group_id, route(commit, &group_id))
        .unwrap();

    let persisted = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("collecting pass persisted with the original policy");
    assert_eq!(persisted.cutoff_monotonic_ms(), 2_000);
    drop(carol);
    clock.set_wall_ms(10_400);
    let mut restarted = build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock);
    restarted
        .hydrate_all_stored_groups()
        .expect("restart hydrates the persisted group");
    restarted
        .set_convergence_policy(CanonicalizationPolicy {
            settlement_quiescence_ms: 0,
            ..CanonicalizationPolicy::default()
        })
        .expect("test policy override accepted");

    let snapshot = restarted
        .conformance_structural_progress_snapshot(&group_id)
        .expect("read-only conformance progress");
    assert_eq!(snapshot.current_monotonic_ms, 1_000);
    assert_eq!(snapshot.earliest_next_wake_monotonic_ms, None);
    assert!(snapshot.runnable_work > 0);
    assert_eq!(
        carol_storage
            .convergence_pass(&group_id)
            .unwrap()
            .expect("snapshot does not rewrite storage")
            .cutoff_monotonic_ms(),
        2_000
    );
    assert_eq!(
        restarted
            .prepare_convergence_cutoff_delay_ms(&group_id)
            .expect("production scheduler prepares the same pass"),
        Some(0)
    );
    let normalized = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("restart rebase persists the normalized pass");
    assert_eq!(normalized.opened_monotonic_ms, 600);
    assert_eq!(
        normalized.quiescence_deadline_wall_ms,
        normalized.opened_wall_ms
    );
    assert_eq!(normalized.quiescence_deadline_monotonic_ms, 1_000);
    assert_eq!(
        normalized.absolute_deadline_wall_ms,
        normalized
            .opened_wall_ms
            .saturating_add(V1_MAX_CONVERGENCE_PASS_MS)
    );
    assert_eq!(normalized.absolute_deadline_monotonic_ms, 5_600);
}

#[tokio::test]
async fn rebuilt_engine_emits_losing_branch_app_invalidation_after_convergence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let carol_storage = SqliteAccountStorage::in_memory().unwrap();
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let mut carol =
        build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock.clone());
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-restart-app-invalidation".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = evolution(alice_invite);
    let (bob_commit, bob_pending) = evolution(bob_invite);
    let commit_messages = [
        route(alice_commit.clone(), &group_id),
        route(bob_commit.clone(), &group_id),
    ];

    alice.confirm_published(alice_pending).await.unwrap();
    bob.confirm_published(bob_pending).await.unwrap();
    let app_messages = [
        send_app(&mut alice, &group_id, b"restart alice branch".to_vec()).await,
        send_app(&mut bob, &group_id, b"restart bob branch".to_vec()).await,
    ];

    let selected_index = commit_tiebreak_winner_index(&alice.self_id(), &bob.self_id());
    let losing_index = 1 - selected_index;

    for message in commit_messages.iter().chain(app_messages.iter()) {
        carol
            .buffer_openmls_convergence_message_at(&group_id, message.clone(), 1_000)
            .expect("message buffered");
    }

    clock.set_wall_ms(12_000);
    let mut restarted = build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock);

    let result = restarted
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("rebuilt engine converges stored OpenMLS messages");

    assert_eq!(
        result.accepted_app_messages,
        vec![content_hex(&app_messages[selected_index])]
    );
    assert_message_state(
        &carol_storage,
        &app_messages[losing_index],
        MessageState::EpochInvalidated,
    );
    let losing_content_id = content_id(&app_messages[losing_index]);
    let events = restarted.drain_events();
    assert!(events.iter().any(|event| {
        matches!(
            event,
            GroupEvent::AppMessageInvalidated {
                group_id: event_group,
                message_id,
                reason: AppMessageInvalidationReason::LosingBranch,
                ..
            } if *event_group == group_id && *message_id == losing_content_id
        )
    }));
    let received_payloads: Vec<Vec<u8>> = events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { payload, .. } => Some(app_content(payload)),
            _ => None,
        })
        .collect();
    assert_eq!(
        received_payloads,
        vec![if selected_index == 0 {
            b"restart alice branch".to_vec()
        } else {
            b"restart bob branch".to_vec()
        }]
    );
}

#[tokio::test]
async fn engine_ingest_retains_proposal_until_canonical_commit_consumes_it() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-ingest-proposal-convergence".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let proposal = proposal(
        bob.send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap(),
    );
    let proposal = route(proposal, &group_id);

    let carol_outcome = carol.ingest(proposal.clone()).await.unwrap();

    assert!(matches!(
        carol_outcome,
        cgka_traits::ingest::IngestOutcome::Processed
    ));
    assert!(
        carol.drain_auto_publish().is_empty(),
        "carol should schedule before staging the SelfRemove-only commit"
    );
    tokio::time::sleep(std::time::Duration::from_millis(75)).await;
    let advanced = carol.advance_convergence(&group_id).await.unwrap();
    assert!(advanced.is_empty());
    let mut carol_auto = carol.drain_auto_publish();
    assert_eq!(
        carol_auto.len(),
        1,
        "carol should attempt a SelfRemove-only commit when she sees the proposal"
    );
    assert_message_state(&carol_storage, &proposal, MessageState::Created);
    carol
        .publish_failed(carol_auto.remove(0).pending)
        .await
        .unwrap();
    assert_message_state(&carol_storage, &proposal, MessageState::Created);

    let alice_outcome = alice.ingest(proposal.clone()).await.unwrap();
    assert!(matches!(
        alice_outcome,
        cgka_traits::ingest::IngestOutcome::Processed
    ));
    tokio::time::sleep(std::time::Duration::from_millis(75)).await;
    let advanced = alice.advance_convergence(&group_id).await.unwrap();
    assert!(advanced.is_empty());
    let auto_commit = alice
        .drain_auto_publish()
        .into_iter()
        .next()
        .expect("alice auto-commits bob's self-remove");
    alice.confirm_published(auto_commit.pending).await.unwrap();
    assert_message_state(&alice_storage, &proposal, MessageState::Processed);
    assert!(
        !alice.drain_valid_proposal_groups().contains(&group_id),
        "confirming the proposal-consuming commit retires the obsolete proposal schedule signal"
    );

    let mut restarted_alice = build_client_with_storage(b"alice", alice_storage.clone());
    restarted_alice
        .hydrate_all_stored_groups()
        .expect("rebuild after proposal-consuming commit");
    assert_message_state(&alice_storage, &proposal, MessageState::Processed);
    assert!(
        restarted_alice
            .drain_pending_convergence_groups()
            .is_empty(),
        "processed consumed proposals must not recreate convergence scheduling work after restart"
    );

    let commit = route(auto_commit.msg, &group_id);
    let commit_outcome = carol.ingest(commit.clone()).await.unwrap();
    assert!(matches!(
        commit_outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("proposal-consuming commit converges");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(result.accepted_proposals, vec![content_hex(&proposal)]);
    assert_message_state(&carol_storage, &proposal, MessageState::Processed);
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert!(
        !carol
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == bob.self_id())
    );
}

/// mdk#963: an unconsumed proposal is scoped to its source epoch. It must not
/// be replayed before every later candidate commit, where OpenMLS rejects it as
/// WrongEpoch and prunes every candidate path.
#[tokio::test]
async fn stale_unconsumed_proposal_does_not_poison_later_candidate_paths() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "stale-proposal-replay".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let stale_proposal = route(
        proposal(
            bob.send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
        ),
        &group_id,
    );

    // Alice never sees Bob's proposal, so this epoch-1 commit cannot consume
    // it. Carol observes both through stored convergence.
    let first_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (first_commit, first_pending) = evolution(first_invite);
    alice.confirm_published(first_pending).await.unwrap();
    let first_commit = route(first_commit, &group_id);

    carol
        .buffer_openmls_convergence_message_at(&group_id, stale_proposal.clone(), 1_000)
        .unwrap();
    carol
        .buffer_openmls_convergence_message_at(&group_id, first_commit.clone(), 1_000)
        .unwrap();
    let first = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    assert_eq!(first.accepted_commits, vec![content_hex(&first_commit)]);
    assert!(first.dropped_messages.iter().any(|dropped| {
        dropped.message_id == content_hex(&stale_proposal)
            && dropped.kind == MessageKind::Proposal
            && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
    }));
    assert_message_state(
        &carol_storage,
        &stale_proposal,
        MessageState::EpochInvalidated,
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));

    // A later epoch-2 commit must materialize normally. Before the fix the
    // stale epoch-1 proposal was prepended and every replay failed WrongEpoch.
    let second_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (second_commit, second_pending) = evolution(second_invite);
    alice.confirm_published(second_pending).await.unwrap();
    let second_commit = route(second_commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, second_commit.clone(), 2_000)
        .unwrap();
    let second = carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();

    assert_eq!(second.accepted_commits, vec![content_hex(&second_commit)]);
    assert_message_state(&carol_storage, &second_commit, MessageState::Processed);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
}

#[tokio::test]
async fn engine_duplicate_convergence_input_does_not_reset_quiescence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let carol_storage = SqliteAccountStorage::in_memory().unwrap();
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let mut carol =
        build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock.clone());
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-duplicate".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);

    carol
        .buffer_openmls_convergence_message(&group_id, commit.clone())
        .expect("commit buffered");
    let opened = carol_storage.convergence_pass(&group_id).unwrap().unwrap();
    assert_eq!(opened.opened_monotonic_ms, 1_000);
    assert_eq!(opened.opened_wall_ms, 10_000);
    assert_eq!(opened.quiescence_deadline_monotonic_ms, 2_000);
    assert_eq!(opened.quiescence_deadline_wall_ms, 11_000);
    assert_eq!(opened.absolute_deadline_monotonic_ms, 6_000);
    assert_eq!(opened.absolute_deadline_wall_ms, 15_000);
    clock.advance_ms(900);
    carol
        .buffer_openmls_convergence_message(&group_id, commit.clone())
        .expect("duplicate commit ignored");

    assert_eq!(
        carol
            .converge_stored_openmls_messages(&group_id)
            .expect("the instant before quiescence remains open")
            .convergence_status,
        ConvergenceStatus::Syncing
    );
    clock.advance_ms(100);
    let result = carol
        .converge_stored_openmls_messages(&group_id)
        .expect("duplicate should not pin syncing");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
}

#[tokio::test]
async fn application_input_does_not_reset_convergence_quiescence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-app-quiescence".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let rename = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("selection-relevant commit".into()),
            description: None,
        })
        .await
        .unwrap();
    let (commit, pending) = evolution(rename);
    alice.confirm_published(pending).await.unwrap();
    carol
        .buffer_openmls_convergence_message_at(&group_id, route(commit, &group_id), 1_000)
        .unwrap();
    let app = send_app(&mut alice, &group_id, b"ordinary application".to_vec()).await;
    carol
        .buffer_openmls_convergence_message_at(&group_id, app, 1_900)
        .unwrap();

    let pass = carol_storage.convergence_pass(&group_id).unwrap().unwrap();
    assert_eq!(pass.quiescence_deadline_monotonic_ms, 2_000);
    assert_eq!(
        carol
            .converge_stored_openmls_messages_at(&group_id, 2_000)
            .unwrap()
            .convergence_status,
        ConvergenceStatus::Settled
    );
}

#[tokio::test]
async fn app_witness_beside_competing_commits_resets_convergence_quiescence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "selection-relevant-app-quiescence".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = evolution(alice_invite);
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    alice.confirm_published(alice_pending).await.unwrap();
    let app = send_app(&mut alice, &group_id, b"branch witness".to_vec()).await;

    carol
        .buffer_openmls_convergence_message_at(&group_id, route(alice_commit, &group_id), 1_000)
        .unwrap();
    carol
        .buffer_openmls_convergence_message_at(&group_id, route(bob_commit, &group_id), 1_000)
        .unwrap();
    carol
        .buffer_openmls_convergence_message_at(&group_id, app, 1_900)
        .unwrap();

    let pass = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("competing commits open a pass");
    assert_eq!(
        pass.quiescence_deadline_monotonic_ms, 2_900,
        "a potential witness that can change the branch score is selection-relevant"
    );
    assert_eq!(
        pass.absolute_deadline_monotonic_ms, 6_000,
        "witness traffic must never move the absolute pass boundary"
    );
}

#[tokio::test]
async fn far_future_app_is_not_admitted_to_an_active_pass() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "active-pass-future-horizon".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .unwrap();

    let first_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (first_commit, pending) = evolution(first_invite);
    alice.confirm_published(pending).await.unwrap();
    let second_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (_withheld_second_commit, pending) = evolution(second_invite);
    alice.confirm_published(pending).await.unwrap();
    let far_future_app = send_app(&mut alice, &group_id, b"outside active horizon".to_vec()).await;

    carol
        .buffer_openmls_convergence_message_at(&group_id, route(first_commit, &group_id), 1_000)
        .unwrap();
    carol
        .buffer_openmls_convergence_message_at(&group_id, far_future_app.clone(), 1_900)
        .unwrap();

    let pass = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("first commit opens a pass");
    assert_eq!(pass.members.len(), 1);
    assert!(
        pass.members
            .iter()
            .all(|member| member.message_id != content_id(&far_future_app)),
        "outside-horizon input must be retained outside the active frozen batch"
    );
    assert_eq!(pass.quiescence_deadline_monotonic_ms, 2_000);
    assert_message_state(&carol_storage, &far_future_app, MessageState::Created);
}

#[tokio::test]
async fn convergence_pass_freezes_at_absolute_cap_under_continuous_selection_input() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let carol_storage = SqliteAccountStorage::in_memory().unwrap();
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let mut carol =
        build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock.clone());

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-absolute-cap".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    for index in 0..6 {
        let update = alice
            .send(SendIntent::UpdateGroupData {
                group_id: group_id.clone(),
                name: Some(format!("continuous selection {index}")),
                description: None,
            })
            .await
            .unwrap();
        let (message, pending) = evolution(update);
        alice.confirm_published(pending).await.unwrap();
        carol
            .buffer_openmls_convergence_message(&group_id, route(message, &group_id))
            .unwrap();
        if index < 5 {
            clock.advance_ms(900);
        }
    }

    let pass = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("collecting pass persisted");
    assert_eq!(pass.quiescence_deadline_monotonic_ms, 6_500);
    assert_eq!(pass.absolute_deadline_monotonic_ms, 6_000);
    assert_eq!(pass.members.len(), 6);
    clock.advance_ms(499);
    assert_eq!(
        carol
            .converge_stored_openmls_messages(&group_id)
            .unwrap()
            .convergence_status,
        ConvergenceStatus::Syncing
    );
    clock.advance_ms(1);
    assert_eq!(
        carol
            .converge_stored_openmls_messages(&group_id)
            .unwrap()
            .convergence_status,
        ConvergenceStatus::Settled
    );
    let frozen = carol_storage.convergence_pass(&group_id).unwrap().unwrap();
    assert_eq!(
        frozen.cutoff_cause,
        Some(cgka_traits::ConvergenceCutoffCause::AbsoluteDeadline)
    );
}

#[tokio::test]
async fn input_at_effective_cutoff_is_retained_for_the_next_generation() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-exact-cutoff".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let first_update = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("before cutoff".into()),
            description: None,
        })
        .await
        .unwrap();
    let (first, pending) = evolution(first_update);
    alice.confirm_published(pending).await.unwrap();
    let first = route(first, &group_id);
    let cutoff_update = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("at cutoff".into()),
            description: None,
        })
        .await
        .unwrap();
    let (at_cutoff, pending) = evolution(cutoff_update);
    alice.confirm_published(pending).await.unwrap();
    let at_cutoff = route(at_cutoff, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, first.clone(), 1_000)
        .unwrap();
    carol
        .buffer_openmls_convergence_message_at(&group_id, at_cutoff.clone(), 2_000)
        .unwrap();

    let collecting = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("generation zero freezes durably at admission cutoff");
    assert_eq!(collecting.generation, 0);
    assert_eq!(collecting.phase, cgka_traits::ConvergencePassPhase::Frozen);
    assert_eq!(
        collecting.cutoff_cause,
        Some(cgka_traits::ConvergenceCutoffCause::Quiescence)
    );
    assert_eq!(collecting.members.len(), 1);
    assert_eq!(collecting.members[0].message_id, content_id(&first));
    assert!(
        !collecting
            .members
            .iter()
            .any(|member| member.message_id == content_id(&at_cutoff)),
        "admission at the cutoff must not mutate the frozen generation"
    );

    carol
        .converge_stored_openmls_messages_at(&group_id, 2_000)
        .expect("generation zero freezes and resolves at the exact cutoff");
    let completed = carol_storage.convergence_pass(&group_id).unwrap().unwrap();
    assert_eq!(completed.generation, 0);
    assert_eq!(completed.members.len(), 1);
    assert_eq!(
        carol_storage
            .get_message(&content_id(&at_cutoff))
            .unwrap()
            .state,
        MessageState::Created,
        "the cutoff input remains durable for the next generation"
    );

    carol
        .prepare_convergence_cutoff_delay_ms(&group_id)
        .expect("next generation opens")
        .expect("cutoff input starts the next collecting pass");
    let next = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("generation one is durable");
    assert_eq!(next.generation, 1);
    assert_eq!(next.phase, cgka_traits::ConvergencePassPhase::Collecting);
    assert!(
        next.members
            .iter()
            .any(|member| member.message_id == content_id(&at_cutoff)),
        "input retained at generation-zero cutoff must join generation one"
    );
}

/// One buffered inbound commit on `carol`, so she holds an active convergence
/// pass opened at her current tip, with a forensic recorder attached.
///
/// The base-epoch discard tests differ only in the shape they then stamp onto
/// that durable pass, so they share the arrival path.
struct BufferedPassFixture {
    carol: Engine<SqliteAccountStorage>,
    storage: SqliteAccountStorage,
    group_id: GroupId,
    commit: TransportMessage,
    tip: EpochId,
    audit_path: std::path::PathBuf,
    /// Owns the audit file for the lifetime of the fixture.
    _audit_dir: tempfile::TempDir,
}

impl BufferedPassFixture {
    /// The durable pass as convergence last persisted it.
    fn pass(&self) -> cgka_traits::convergence_pass::DurableConvergencePass {
        self.storage
            .convergence_pass(&self.group_id)
            .unwrap()
            .expect("a buffered commit leaves a durable pass")
    }

    fn put_pass(&self, pass: &cgka_traits::convergence_pass::DurableConvergencePass) {
        self.storage.put_convergence_pass(pass).unwrap();
    }

    /// Every `convergence_pass_discarded` row the recorder wrote. Consumes the
    /// engine so the recorder flushes first.
    fn discard_audit_rows(self) -> Vec<(u64, u64, u64)> {
        use marmot_forensics::{AuditEvent, AuditEventKind};

        drop(self.carol);
        std::fs::read_to_string(&self.audit_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<AuditEvent>(line).unwrap())
            .filter_map(|event| match event.kind {
                AuditEventKind::ConvergencePassDiscarded {
                    stale_base_epoch,
                    current_tip_epoch,
                    generation,
                } => Some((stale_base_epoch, current_tip_epoch, generation)),
                _ => None,
            })
            .collect()
    }
}

async fn buffered_convergence_pass_fixture(group_name: &str) -> BufferedPassFixture {
    use marmot_forensics::JsonlRecorder;

    let audit_dir = tempfile::tempdir().unwrap();
    let audit_path = audit_dir.path().join("audit.jsonl");
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut david, _david_storage) = build_client(b"david");
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut carol = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .recorder(Box::new(
            JsonlRecorder::open(&audit_path, "carol-engine".to_string()).unwrap(),
        ))
        .build()
        .unwrap();

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: group_name.into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (commit, _) = evolution(invite);
    let commit = route(commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit.clone(), 1_000)
        .unwrap();

    let tip = carol.epoch(&group_id).unwrap();
    let fixture = BufferedPassFixture {
        carol,
        storage,
        group_id,
        commit,
        tip,
        audit_path,
        _audit_dir: audit_dir,
    };
    assert_eq!(
        fixture.pass().base_epoch,
        tip,
        "pass opens at the current tip"
    );
    fixture
}

#[tokio::test]
async fn stale_pass_base_epoch_reopens_at_the_current_tip_instead_of_halting() {
    // A durable pass whose base epoch disagrees with the tip is stale local
    // scheduling state, not corruption: convergence must discard it, reopen at
    // the tip, and keep converging. The disagreement is inherited rather than
    // reachable live — a base epoch stamped from the durable group record while
    // the tip was read from the epoch manager, two stores that can split across a
    // restart — so the test installs that shape on the durable record directly.
    // The live engine cannot produce it: an open pass gates outbound work and
    // re-routes inbound commits back through convergence. Halting on it durably
    // wedged a field device six epochs behind, and every later send failed
    // against the halt.
    let mut fixture = buffered_convergence_pass_fixture("engine-convergence-stale-pass-base").await;
    let tip = fixture.tip;
    let stale_base = EpochId(tip.0.checked_sub(1).expect("the tip is past epoch zero"));
    let mut stale = fixture.pass();
    // Install the inherited shape: a durable pass whose base epoch trails the
    // tip the rest of convergence reads.
    stale.base_epoch = stale_base;
    fixture.put_pass(&stale);

    let compensated = fixture
        .carol
        .converge_stored_openmls_messages_at(&fixture.group_id, 2_000)
        .expect("a stale pass base is compensated, not fatal");
    assert_ne!(
        compensated.convergence_status,
        ConvergenceStatus::Blocked,
        "a stale pass base must not block the run"
    );
    assert!(
        !fixture
            .storage
            .get_group(&fixture.group_id)
            .unwrap()
            .unrecoverable,
        "a stale pass base must not durably wedge the group"
    );
    assert!(
        !fixture
            .carol
            .drain_events()
            .iter()
            .any(|event| matches!(event, GroupEvent::GroupUnrecoverable { .. }))
    );

    let reopened = fixture.pass();
    assert_eq!(reopened.base_epoch, tip);
    assert_eq!(reopened.generation, stale.generation + 1);

    let settled = fixture
        .carol
        .converge_stored_openmls_messages_at(&fixture.group_id, 3_000)
        .expect("the reopened pass converges at the current tip");
    assert_eq!(settled.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        fixture.carol.epoch(&fixture.group_id).unwrap(),
        EpochId(tip.0 + 1)
    );
    assert_message_state(&fixture.storage, &fixture.commit, MessageState::Processed);

    assert_eq!(
        fixture.discard_audit_rows(),
        vec![(stale_base.0, tip.0, stale.generation)],
        "the compensation is diagnosable from a forensic export, exactly once"
    );
}

#[tokio::test]
async fn frozen_stale_pass_base_epoch_reopens_at_the_current_tip_instead_of_halting() {
    // Frozen passes are deliberately inside the discard, not carved out of it. A
    // frozen batch has fixed its membership, but it is still scheduling state for
    // one base epoch, and an inherited base epoch is no more trustworthy frozen
    // than collecting. The frozen-member integrity check remains the only thing
    // that halts, and it only ever runs against a pass convergence keeps — never
    // against one it is about to drop.
    let mut fixture =
        buffered_convergence_pass_fixture("engine-convergence-frozen-stale-pass-base").await;
    let tip = fixture.tip;
    let stale_base = EpochId(tip.0.checked_sub(1).expect("the tip is past epoch zero"));
    let mut stale = fixture.pass();
    stale.base_epoch = stale_base;
    stale.phase = cgka_traits::ConvergencePassPhase::Frozen;
    stale.frozen_at_wall_ms = Some(1_500);
    stale.cutoff_cause = Some(cgka_traits::ConvergenceCutoffCause::Quiescence);
    assert!(stale.is_active(), "a frozen pass is still an active pass");
    fixture.put_pass(&stale);

    let compensated = fixture
        .carol
        .converge_stored_openmls_messages_at(&fixture.group_id, 2_000)
        .expect("a frozen stale pass base is compensated, not fatal");
    assert_ne!(
        compensated.convergence_status,
        ConvergenceStatus::Blocked,
        "a frozen stale pass base must not block the run"
    );
    assert!(
        !fixture
            .storage
            .get_group(&fixture.group_id)
            .unwrap()
            .unrecoverable,
        "a frozen stale pass base must not durably wedge the group"
    );
    assert!(
        !fixture
            .carol
            .drain_events()
            .iter()
            .any(|event| matches!(event, GroupEvent::GroupUnrecoverable { .. })),
        "the frozen phase must not route the discard into the integrity halt"
    );

    let reopened = fixture.pass();
    assert_eq!(reopened.base_epoch, tip);
    assert_eq!(reopened.generation, stale.generation + 1);
    assert_eq!(
        reopened.phase,
        cgka_traits::ConvergencePassPhase::Collecting,
        "the replacement pass collects afresh rather than inheriting the frozen batch"
    );

    let settled = fixture
        .carol
        .converge_stored_openmls_messages_at(&fixture.group_id, 3_000)
        .expect("the reopened pass converges at the current tip");
    assert_eq!(settled.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        fixture.carol.epoch(&fixture.group_id).unwrap(),
        EpochId(tip.0 + 1)
    );
    assert_message_state(&fixture.storage, &fixture.commit, MessageState::Processed);

    assert_eq!(
        fixture.discard_audit_rows(),
        vec![(stale_base.0, tip.0, stale.generation)],
        "one discard row, reporting the frozen pass that was dropped"
    );
}

#[tokio::test]
async fn future_pass_base_epoch_reopens_at_the_current_tip_instead_of_halting() {
    // The other direction of the same inherited split: a base epoch *ahead* of
    // the tip. Fork rollback reaches this shape on shipped code, because
    // recovering to a pre-commit snapshot moves the in-memory tip backwards while
    // the durable pass keeps the base it was stamped with. It is exactly as
    // benign as a trailing base — the pass still holds no canonical state — so
    // discarding on `!=` rather than `<` is load-bearing. A directional guard
    // would leave this direction halting the group.
    let mut fixture =
        buffered_convergence_pass_fixture("engine-convergence-future-pass-base").await;
    let tip = fixture.tip;
    let future_base = EpochId(tip.0 + 1);
    let mut stale = fixture.pass();
    stale.base_epoch = future_base;
    fixture.put_pass(&stale);

    let compensated = fixture
        .carol
        .converge_stored_openmls_messages_at(&fixture.group_id, 2_000)
        .expect("a future pass base is compensated, not fatal");
    assert_ne!(
        compensated.convergence_status,
        ConvergenceStatus::Blocked,
        "a future pass base must not block the run"
    );
    assert!(
        !fixture
            .storage
            .get_group(&fixture.group_id)
            .unwrap()
            .unrecoverable,
        "a future pass base must not durably wedge the group"
    );
    assert!(
        !fixture
            .carol
            .drain_events()
            .iter()
            .any(|event| matches!(event, GroupEvent::GroupUnrecoverable { .. }))
    );

    let reopened = fixture.pass();
    assert_eq!(
        reopened.base_epoch, tip,
        "the replacement pass is scheduled at the tip, not at the base it inherited"
    );
    assert_eq!(reopened.generation, stale.generation + 1);

    let settled = fixture
        .carol
        .converge_stored_openmls_messages_at(&fixture.group_id, 3_000)
        .expect("the reopened pass converges at the current tip");
    assert_eq!(settled.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        fixture.carol.epoch(&fixture.group_id).unwrap(),
        EpochId(tip.0 + 1)
    );
    assert_message_state(&fixture.storage, &fixture.commit, MessageState::Processed);

    assert_eq!(
        fixture.discard_audit_rows(),
        vec![(future_base.0, tip.0, stale.generation)],
        "one discard row, reporting a base epoch ahead of the tip"
    );
}

#[tokio::test]
async fn frozen_pass_member_tampering_fails_closed_to_unrecoverable() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-member-integrity".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (commit, _) = evolution(invite);
    let commit = route(commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit.clone(), 1_000)
        .unwrap();

    let id = content_id(&commit);
    let mut record = carol_storage.get_message(&id).unwrap();
    record.payload = vec![0xff];
    carol_storage.put_message(&record).unwrap();

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 2_000)
        .expect("integrity failure is a classified halt");
    assert_eq!(result.convergence_status, ConvergenceStatus::Blocked);
    assert!(carol_storage.get_group(&group_id).unwrap().unrecoverable);
    assert!(carol.drain_events().iter().any(|event| matches!(
        event,
        GroupEvent::GroupUnrecoverable { group_id: halted } if halted == &group_id
    )));
}

#[tokio::test]
async fn missing_frozen_pass_member_fails_closed_to_unrecoverable() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-missing-member".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (commit, _) = evolution(invite);
    carol
        .buffer_openmls_convergence_message_at(&group_id, route(commit, &group_id), 1_000)
        .unwrap();

    let mut pass = carol_storage.convergence_pass(&group_id).unwrap().unwrap();
    pass.phase = cgka_traits::ConvergencePassPhase::Frozen;
    pass.frozen_at_wall_ms = Some(pass.cutoff_wall_ms());
    pass.cutoff_cause = Some(cgka_traits::ConvergenceCutoffCause::Quiescence);
    pass.members[0].message_id = MessageId::new(b"missing-frozen-member".to_vec());
    carol_storage.put_convergence_pass(&pass).unwrap();

    let drained = carol
        .advance_convergence(&group_id)
        .await
        .expect("production advance classifies the missing member as a fail-closed halt");
    assert!(drained.is_empty());
    assert!(carol_storage.get_group(&group_id).unwrap().unrecoverable);
    assert!(carol.drain_events().iter().any(|event| matches!(
        event,
        GroupEvent::GroupUnrecoverable { group_id: halted } if halted == &group_id
    )));
}

#[tokio::test]
async fn malformed_convergence_input_does_not_reset_quiescence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-malformed".into(),
            description: "".into(),
            members: vec![
                bob.fresh_key_package().await.unwrap(),
                carol.fresh_key_package().await.unwrap(),
            ],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david.fresh_key_package().await.unwrap()],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    carol
        .buffer_openmls_convergence_message_at(&group_id, commit.clone(), 1_000)
        .expect("valid commit buffered");

    let mut malformed = commit.clone();
    malformed.payload = b"not an OpenMLS message".to_vec();
    carol
        .buffer_openmls_convergence_message_at(&group_id, malformed, 1_900)
        .expect_err("malformed input must fail before touching quiescence");

    let result = carol
        .converge_stored_openmls_messages_at(&group_id, 2_000)
        .expect("malformed input should not pin syncing");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
}

#[tokio::test]
async fn engine_queues_app_send_until_convergence_is_settled() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-queued-send".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    assert!(matches!(
        carol.ingest(commit.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let queued = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"queued until stable"),
        })
        .await
        .unwrap();

    let intent_id = match queued {
        SendResult::Queued { intent_id, .. } => intent_id,
        other => panic!("expected Queued, got {other:?}"),
    };
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_message_state(&carol_storage, &commit, MessageState::Created);
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    let early = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 500)
        .await
        .unwrap();
    assert!(early.is_empty());
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    let drained = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();

    assert_eq!(drained.len(), 1);
    let sent_app = match &drained[0] {
        SendResult::ApplicationMessage { msg, .. } => route(msg.clone(), &group_id),
        other => panic!("expected ApplicationMessage, got {other:?}"),
    };
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
    assert_eq!(
        project_mls_message(&sent_app.payload)
            .expect("queued app projects")
            .source_epoch,
        Some(2)
    );
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1,
        "regeneration keeps the intent until transport acceptance"
    );
    carol.confirm_queued_outbound_intent(&intent_id).unwrap();
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

/// mdk#736: a convergence input whose source epoch is beyond the FUTURE horizon
/// (`current_tip + max_rewind_commits`) can never chain from the tip, so it is
/// not resolvable convergence work and MUST NOT gate outbound sends. Before the
/// fix, a single member could forge one far-future-epoch plaintext message whose
/// buffered `Created`/`Retryable` row was never materialized and never given a
/// terminal disposition, so `has_unresolved_convergence_inputs` reported the
/// group unsettled forever and every send was queued and never drained — a
/// durable, whole-group denial of service from one insider.
#[tokio::test]
async fn far_future_convergence_input_beyond_ceiling_does_not_gate_sends() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-future-horizon-gate".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    // Tight horizon so a small real epoch is already "far future": with the tip
    // at epoch 1 and `max_rewind_commits = 1`, the ceiling is epoch 2.
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 1,
                ..ConvergencePolicy::default()
            },
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");
    carol.drain_events();
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));

    // Alice advances her own copy to epoch 3 (Carol never ingests these), then
    // frames an application message at epoch 3 — source_epoch 3, beyond Carol's
    // ceiling of 2.
    for invitee in [&mut david, &mut eve] {
        let invitee_kp = invitee.fresh_key_package().await.unwrap();
        let invite = alice
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![invitee_kp],
            })
            .await
            .unwrap();
        let (_commit, pending) = evolution(invite);
        alice.confirm_published(pending).await.unwrap();
    }
    let far_future_msg = send_app(&mut alice, &group_id, b"far future payload".to_vec()).await;
    assert_eq!(
        project_mls_message(&far_future_msg.payload)
            .expect("far-future app projects")
            .source_epoch,
        Some(3)
    );

    carol
        .buffer_openmls_convergence_message_at(&group_id, far_future_msg.clone(), 1_000)
        .expect("far-future message buffered");

    // Convergence is not perpetually unsettled on account of the beyond-ceiling
    // row — this distinguishes "send gate fixed" from "convergence loop still
    // wedged on the same forged input", which was the original failure mode.
    assert!(
        carol
            .advance_convergence_inputs_until_settled(&group_id, 1_000_000)
            .await
            .unwrap(),
        "beyond-ceiling row must not leave convergence perpetually unsettled"
    );

    // The fix: the beyond-ceiling row does not gate, so Carol can still send.
    // Pre-fix this returned `SendResult::Queued` forever.
    let sent = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"still able to send"),
        })
        .await
        .unwrap();
    assert!(
        matches!(sent, SendResult::ApplicationMessage { .. }),
        "beyond-ceiling convergence input must not gate the send, got {sent:?}"
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
    // The forged row is NOT dropped — it stays retained so it would gate again
    // (correctly) once the tip advances into `[anchor, ceiling]`.
    assert_message_state(&carol_storage, &far_future_msg, MessageState::Created);
}

/// mdk#962: a commit that parses structurally but fails OpenMLS validation
/// against every reachable parent is terminal convergence input. Before the
/// fix the replay bridge returned no candidate and no disposition, leaving the
/// stored row `Created` and permanently gating every subsequent send.
#[tokio::test]
async fn never_validating_commit_is_terminal_and_does_not_gate_sends() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, bob_storage) = build_client(b"bob");
    let (mut carol, _carol_storage) = build_client(b"carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "never-validating-commit".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();
    let (mut invalid_commit, _pending) = evolution(invite);
    invalid_commit = route(invalid_commit, &group_id);
    let last = invalid_commit
        .payload
        .last_mut()
        .expect("commit wire payload is non-empty");
    *last ^= 0x01;
    assert_eq!(
        project_mls_message(&invalid_commit.payload)
            .expect("signature-corrupted commit remains structurally projectable")
            .source_epoch,
        Some(1)
    );

    bob.buffer_openmls_convergence_message_at(&group_id, invalid_commit.clone(), 1_000)
        .expect("invalid commit buffered");
    let result = bob
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("invalid commit classified");

    assert!(result.dropped_messages.iter().any(|dropped| {
        dropped.message_id == content_hex(&invalid_commit)
            && dropped.kind == MessageKind::Commit
            && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
    }));
    assert_message_state(
        &bob_storage,
        &invalid_commit,
        MessageState::EpochInvalidated,
    );
    assert!(!bob.has_pending_convergence_inputs(&group_id).unwrap());

    let sent = bob
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&bob, b"send after invalid commit"),
        })
        .await
        .unwrap();
    assert!(matches!(sent, SendResult::ApplicationMessage { .. }));
}

/// mdk#736 (related hardening): a `Created`/`Retryable` convergence row that
/// cannot be decoded / is not an openmls-wire payload / fails projection is NOT
/// resolvable convergence work and must fail OPEN (not gate sends). Before the
/// fix, `has_unresolved_convergence_inputs` returned `true` on any such row,
/// permanently gating sends with no recovery path.
#[tokio::test]
async fn undecodable_convergence_row_does_not_gate_sends() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-fail-open-gate".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    // Inject a garbage convergence row within the gate's scan window (epoch 1)
    // whose payload cannot be decoded as a stored message.
    let garbage_id = MessageId::new(b"garbage-convergence-row".to_vec());
    carol_storage
        .put_message(&MessageRecord {
            id: garbage_id.clone(),
            group_id: group_id.clone(),
            epoch: EpochId(1),
            state: MessageState::Created,
            payload: b"not-a-valid-stored-message-payload".to_vec(),
            deferred_peel: None,
        })
        .unwrap();
    assert!(
        StoredMessagePayload::decode(&carol_storage.get_message(&garbage_id).unwrap().payload)
            .is_err(),
        "garbage row must fail to decode for this test to exercise the fail-open path"
    );

    // The fix: an undecodable row does not gate. Pre-fix this returned Queued.
    let sent = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"send despite garbage row"),
        })
        .await
        .unwrap();
    assert!(
        matches!(sent, SendResult::ApplicationMessage { .. }),
        "an undecodable convergence row must not gate the send, got {sent:?}"
    );
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

/// mdk#752 review: the fail-open gate has three branches — decode failure
/// (covered by `undecodable_convergence_row_does_not_gate_sends`), a decodable
/// payload that is NOT openmls-wire, and an openmls-wire payload whose inner
/// bytes do not project. The latter two are the branches an adversary is more
/// likely to craft (a well-formed stored envelope wrapping non-MLS bytes), so
/// pin them too.
#[tokio::test]
async fn non_wire_and_unprojectable_convergence_rows_do_not_gate_sends() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-fail-open-branches".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    let tm = |payload: Vec<u8>| TransportMessage {
        id: MessageId::new(b"inner".to_vec()),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("fail-open-branch".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    };

    // Branch 2: a decodable stored payload that is NOT openmls-wire.
    carol_storage
        .put_message(&MessageRecord {
            id: MessageId::new(b"not-openmls-wire-row".to_vec()),
            group_id: group_id.clone(),
            epoch: EpochId(1),
            state: MessageState::Created,
            payload: StoredMessagePayload::raw_transport(tm(b"raw-transport-bytes".to_vec()))
                .encode()
                .unwrap(),
            deferred_peel: None,
        })
        .unwrap();

    // Branch 3: an openmls-wire payload whose inner bytes do not project as MLS.
    carol_storage
        .put_message(&MessageRecord {
            id: MessageId::new(b"unprojectable-wire-row".to_vec()),
            group_id: group_id.clone(),
            epoch: EpochId(1),
            state: MessageState::Retryable,
            payload: StoredMessagePayload::openmls_wire(tm(b"not-mls-bytes".to_vec()))
                .encode()
                .unwrap(),
            deferred_peel: None,
        })
        .unwrap();

    let sent = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"send despite fail-open rows"),
        })
        .await
        .unwrap();
    assert!(
        matches!(sent, SendResult::ApplicationMessage { .. }),
        "neither a non-wire nor an unprojectable convergence row may gate the send, got {sent:?}"
    );
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn send_preflight_retries_deferred_peels_after_convergence_apply() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_epoch_gate_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "send-preflight-retries-deferred".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_to_epoch2, pending_david) = evolution(invite_david);
    let commit_to_epoch2 = route(commit_to_epoch2, &group_id);
    alice.confirm_published(pending_david).await.unwrap();

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_to_epoch3, _pending_eve) = evolution(invite_eve);
    let commit_to_epoch3 = route(commit_to_epoch3, &group_id);

    assert!(matches!(
        carol.ingest(commit_to_epoch2.clone()).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    assert!(matches!(
        carol.ingest(commit_to_epoch3.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(
        carol_storage
            .get_message(&commit_to_epoch3.id)
            .expect("raw deferred message stored")
            .state,
        MessageState::PeelDeferred
    );

    carol
        .set_convergence_policy(CanonicalizationPolicy {
            settlement_quiescence_ms: 0,
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");
    let sent = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"send after full catch-up"),
        })
        .await
        .unwrap();

    let sent_app = match sent {
        SendResult::ApplicationMessage { msg, .. } => route(msg, &group_id),
        other => panic!("expected ApplicationMessage after catch-up, got {other:?}"),
    };
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
    assert_message_state(&carol_storage, &commit_to_epoch2, MessageState::Processed);
    assert_message_state(&carol_storage, &commit_to_epoch3, MessageState::Processed);
    assert_eq!(
        project_mls_message(&sent_app.payload)
            .expect("sent app projects")
            .source_epoch,
        Some(3)
    );
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

/// Regression for mdk#707 review finding 2: a raw `PeelDeferred` row
/// that becomes peelable but whose content is terminally rejected (here a
/// forged, unattributable application payload) must be retired from the
/// deferred queue — marked terminal and released from the retry lifecycle —
/// not left durably `PeelDeferred` holding a per-group cap slot. Without the
/// fix, `retry_deferred_peels` treats the post-peel terminal rejection
/// like "still cannot peel" and leaves the raw row deferred forever.
#[tokio::test]
async fn deferred_row_terminally_rejected_after_peel_leaves_the_deferred_queue() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_epoch_gate_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "deferred-terminal-after-peel".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    // Alice advances to epoch 2 and forges an unattributable app message
    // there (inner `pubkey: ""`), which validation must reject.
    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_to_epoch2, pending) = evolution(invite);
    let commit_to_epoch2 = route(commit_to_epoch2, &group_id);
    alice.confirm_published(pending).await.unwrap();
    let forged_payload = MarmotAppEvent::new(
        "",
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "forged",
    )
    .encode()
    .expect("forged app event encodes");
    let forged =
        raw_app_message_with_payload(&alice_storage, &alice.self_id(), &group_id, &forged_payload);

    // Carol is at epoch 1: the epoch-gate peeler cannot peel an epoch-2
    // message, so it is retained as a PeelDeferred raw row.
    assert!(matches!(
        carol.ingest(forged.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    assert_eq!(
        carol_storage.get_message(&forged.id).unwrap().state,
        MessageState::PeelDeferred
    );

    // Deliver the epoch-2 commit and converge: carol catches up, re-peels the
    // forged message, and terminally rejects it. The raw deferred row must be
    // retired (terminal `Failed`), not left `PeelDeferred`.
    carol
        .ingest(commit_to_epoch2)
        .await
        .expect("commit buffered");
    carol
        .set_convergence_policy(CanonicalizationPolicy {
            settlement_quiescence_ms: 0,
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();

    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_eq!(
        carol_storage.get_message(&forged.id).unwrap().state,
        MessageState::Failed,
        "a deferred row terminally rejected after peel must leave the deferred queue"
    );
    for event in carol.drain_events() {
        if let GroupEvent::MessageReceived {
            sender, payload, ..
        } = event
        {
            assert!(!sender.as_slice().is_empty());
            assert_ne!(payload, forged_payload);
        }
    }
}

#[tokio::test]
async fn send_preflight_terminally_retires_deferred_app_message_outside_past_epoch_window() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let bob_storage = SqliteAccountStorage::in_memory().unwrap();
    let mut bob = build_client_with_max_past_epochs(b"bob", bob_storage.clone(), 1);

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "send-preflight-terminal-past-decrypt".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    bob.set_convergence_policy(CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        // Keep the app window aligned with bob's MLS `max_past_epochs = 1`.
        app_message_past_epoch_limit: 1,
        ..CanonicalizationPolicy::default()
    })
    .expect("convergence policy accepted");

    let old_app = send_app(&mut alice, &group_id, b"outside past window".to_vec()).await;

    for invitee_name in [b"carol".as_slice(), b"david".as_slice(), b"eve".as_slice()] {
        let (mut invitee, _invitee_storage) = build_client(invitee_name);
        let invitee_kp = invitee.fresh_key_package().await.unwrap();
        let invite = alice
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![invitee_kp],
            })
            .await
            .unwrap();
        let (commit, pending) = evolution(invite);
        alice.confirm_published(pending).await.unwrap();
        bob.ingest(route(commit, &group_id)).await.unwrap();
        assert!(
            bob.advance_convergence_inputs_until_settled(&group_id, 1_000_000)
                .await
                .unwrap()
        );
    }
    assert_eq!(bob.epoch(&group_id).unwrap(), EpochId(4));

    bob_storage
        .put_message(&MessageRecord {
            id: old_app.id.clone(),
            group_id: group_id.clone(),
            epoch: EpochId(0),
            state: MessageState::PeelDeferred,
            payload: StoredMessagePayload::raw_transport(old_app.clone())
                .encode()
                .unwrap(),
            deferred_peel: None,
        })
        .unwrap();

    let sent = bob
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&bob, b"send after terminal stale"),
        })
        .await
        .unwrap();

    assert!(
        matches!(sent, SendResult::ApplicationMessage { .. }),
        "send should proceed after retiring stale deferred app message: {sent:?}"
    );
    assert_eq!(
        bob_storage.get_message(&old_app.id).unwrap().state,
        MessageState::Failed
    );
    assert_message_state(&bob_storage, &old_app, MessageState::Failed);
}

#[tokio::test]
async fn engine_queues_group_evolution_until_convergence_is_settled() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-queued-commit".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![carol.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (alice_commit, _pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    assert!(matches!(
        carol.ingest(alice_commit.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let queued = carol
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();

    assert!(matches!(queued, SendResult::Queued { .. }));
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    let drained = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();

    assert_eq!(drained.len(), 1);
    let (queued_commit, queued_pending) = match &drained[0] {
        SendResult::GroupEvolution {
            msg,
            welcomes,
            pending,
        } => {
            assert_eq!(welcomes.len(), 1);
            (route(msg.clone(), &group_id), *pending)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    assert_message_state(&carol_storage, &alice_commit, MessageState::Processed);
    assert_eq!(
        project_mls_message(&queued_commit.payload)
            .expect("queued commit projects")
            .source_epoch,
        Some(2)
    );
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1,
        "regeneration alone must not delete the durable intent"
    );
    carol.confirm_published(queued_pending).await.unwrap();
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty(),
        "confirming the externally visible evolution retires its intent"
    );
}

#[tokio::test]
async fn trait_advance_convergence_drains_queued_outbound_intent() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "trait-advance-convergence".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    assert!(matches!(
        carol.ingest(commit.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let queued = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"queued through trait lifecycle"),
        })
        .await
        .unwrap();
    let intent_id = match queued {
        SendResult::Queued { intent_id, .. } => intent_id,
        other => panic!("expected Queued, got {other:?}"),
    };

    let policy = CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    };
    carol
        .set_convergence_policy(policy)
        .expect("convergence policy accepted");

    let mut engine: Box<dyn CgkaEngine> = Box::new(carol);
    let drained = engine.advance_convergence(&group_id).await.unwrap();

    assert_eq!(drained.len(), 1);
    let sent_app = match &drained[0] {
        SendResult::ApplicationMessage { msg, .. } => route(msg.clone(), &group_id),
        other => panic!("expected ApplicationMessage, got {other:?}"),
    };
    assert_eq!(engine.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
    assert_eq!(
        project_mls_message(&sent_app.payload)
            .expect("trait-drained app projects")
            .source_epoch,
        Some(2)
    );
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1,
        "standalone publish work remains queued until transport acceptance"
    );
    engine
        .confirm_queued_outbound_intent(&intent_id)
        .expect("simulated transport acceptance retires the intent");
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn advance_convergence_retains_queued_intent_when_regeneration_fails() {
    let (mut alice, alice_storage) = build_client(b"alice");

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "failed-regeneration".into(),
            description: "".into(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let intent_id = MessageId::new(b"invalid-update".to_vec());
    alice_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: intent_id.clone(),
            group_id: group_id.clone(),
            intent: SendIntent::UpdateGroupData {
                group_id: group_id.clone(),
                name: None,
                description: None,
            },
            created_at_ms: 0,
        })
        .unwrap();

    let err = alice.advance_convergence(&group_id).await.err().unwrap();
    assert!(
        matches!(err, cgka_traits::EngineError::Other(ref msg) if msg.contains("no fields")),
        "expected validation error from queued intent regeneration, got {err:?}"
    );
    let queued = alice_storage
        .list_queued_outbound_intents(&group_id)
        .unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].id, intent_id);
}

#[tokio::test]
async fn restart_schedules_groups_with_durable_queued_intents() {
    let (mut alice, alice_storage) = build_client(b"alice-restart-queued");
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "restart queued".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    alice_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: MessageId::new(b"durable-restart-intent".to_vec()),
            group_id: group_id.clone(),
            intent: SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&alice, b"send after restart"),
            },
            created_at_ms: 1,
        })
        .unwrap();
    drop(alice);

    let mut restarted = build_client_with_storage(b"alice-restart-queued", alice_storage);
    restarted
        .hydrate_all_stored_groups()
        .expect("session-open hydration succeeds");
    let scheduled = restarted.drain_pending_convergence_groups();
    assert!(
        scheduled.contains(&group_id),
        "hydration must schedule durable queued work without new traffic; got {scheduled:?}"
    );
}

#[tokio::test]
async fn queued_group_evolution_pauses_later_queued_intents_until_publish_resolves() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, _carol_storage) = build_client(b"carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "queued-evolution-pause".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite_intent_id = MessageId::new(b"invite-carol".to_vec());
    alice_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: invite_intent_id,
            group_id: group_id.clone(),
            intent: SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![carol_kp],
            },
            created_at_ms: 0,
        })
        .unwrap();
    let app_intent_id = MessageId::new(b"later-app".to_vec());
    alice_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: app_intent_id.clone(),
            group_id: group_id.clone(),
            intent: SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&alice, b"after invite publish resolves"),
            },
            created_at_ms: 1,
        })
        .unwrap();

    let drained = alice.advance_convergence(&group_id).await.unwrap();
    assert_eq!(drained.len(), 1);
    let pending_invite = match &drained[0] {
        SendResult::GroupEvolution { pending, .. } => *pending,
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    assert_eq!(
        alice_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        2
    );

    let paused = alice.advance_convergence(&group_id).await.unwrap();
    assert!(
        paused.is_empty(),
        "pending publish should pause queued lifecycle, got {paused:?}"
    );
    assert_eq!(
        alice_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        2
    );

    alice.publish_failed(pending_invite).await.unwrap();
    let drained_after_failure = alice.advance_convergence(&group_id).await.unwrap();
    assert_eq!(drained_after_failure.len(), 1);
    let retry_pending = match drained_after_failure[0] {
        SendResult::GroupEvolution { pending, .. } => pending,
        ref other => panic!("failed evolution must retry before later work, got {other:?}"),
    };
    assert_eq!(
        alice_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        2,
        "publish failure must retain the evolution intent"
    );
    alice.confirm_published(retry_pending).await.unwrap();
    assert_eq!(
        alice_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1,
        "evolution confirmation retires only that intent"
    );

    let later = alice.advance_convergence(&group_id).await.unwrap();
    assert!(
        matches!(later.as_slice(), [SendResult::ApplicationMessage { .. }]),
        "later app intent should run after evolution confirmation, got {later:?}"
    );
    alice
        .confirm_queued_outbound_intent(&app_intent_id)
        .unwrap();
    assert!(
        alice_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn queued_outbound_intent_survives_engine_rebuild() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let carol_storage = SqliteAccountStorage::in_memory().unwrap();
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let mut carol =
        build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock.clone());
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-queued-restart".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    assert!(matches!(
        carol.ingest(commit.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let queued = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"queued across restart"),
        })
        .await
        .unwrap();
    let intent_id = match queued {
        SendResult::Queued { intent_id, .. } => intent_id,
        other => panic!("expected Queued, got {other:?}"),
    };
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    clock.set_wall_ms(12_000);
    let mut restarted = build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock);
    let drained = restarted
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();

    assert_eq!(drained.len(), 1);
    let sent_app = match &drained[0] {
        SendResult::ApplicationMessage { msg, .. } => route(msg.clone(), &group_id),
        other => panic!("expected ApplicationMessage, got {other:?}"),
    };
    assert_eq!(restarted.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
    assert_eq!(
        project_mls_message(&sent_app.payload)
            .expect("restarted queued app projects")
            .source_epoch,
        Some(2)
    );
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1,
        "restart regeneration keeps the intent until transport acceptance"
    );
    restarted
        .confirm_queued_outbound_intent(&intent_id)
        .unwrap();
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

fn evolution(result: SendResult) -> (TransportMessage, cgka_traits::engine_state::PendingStateRef) {
    match result {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    }
}

fn proposal(result: SendResult) -> TransportMessage {
    match result {
        SendResult::Proposal { msg } => msg,
        other => panic!("expected Proposal, got {other:?}"),
    }
}

fn welcome_for(welcomes: &[TransportMessage], name: &[u8]) -> TransportMessage {
    let recipient = MemberId::new(pad32(name));
    welcomes
        .iter()
        .find(|message| {
            matches!(
                &message.envelope,
                TransportEnvelope::Welcome { recipient: actual } if *actual == recipient
            )
        })
        .expect("welcome exists")
        .clone()
}

async fn send_app(
    engine: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    payload: Vec<u8>,
) -> TransportMessage {
    let result = engine
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(engine, payload),
        })
        .await
        .expect("send app");
    match result {
        SendResult::ApplicationMessage { msg, .. } => route(msg, group_id),
        other => panic!("expected app message, got {other:?}"),
    }
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

fn app_content(payload: &[u8]) -> Vec<u8> {
    MarmotAppEvent::decode(payload)
        .expect("test app event decodes")
        .content
        .into_bytes()
}

fn route(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    match msg.envelope {
        TransportEnvelope::Welcome { .. } => msg,
        TransportEnvelope::GroupMessage { .. } => TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        },
    }
}

/// Content-derived dedup id of a group message (#238). Inbound / buffered
/// group messages are stored and reported under SHA-256 of the recovered MLS
/// bytes, not the outer transport id. Under the pass-through `MockPeeler` the
/// recovered MLS bytes are exactly `msg.payload`.
fn content_id(msg: &TransportMessage) -> MessageId {
    MessageId::new(Sha256::digest(&msg.payload).to_vec())
}

/// Hex form of [`content_id`], for comparing against canonicalization-result
/// message ids.
fn content_hex(msg: &TransportMessage) -> String {
    hex::encode(content_id(msg).as_slice())
}

fn assert_message_state(
    storage: &SqliteAccountStorage,
    msg: &TransportMessage,
    expected: MessageState,
) {
    let record = storage
        .get_message(&content_id(msg))
        .expect("message remains stored");
    assert_eq!(record.state, expected);
}

// --- #113: witness-override policy bound -----------------------------------

#[test]
fn convergence_policy_default_satisfies_witness_override_bound() {
    assert!(ConvergencePolicy::default().validate().is_ok());
}

#[test]
fn convergence_policy_allows_witness_override_equal_to_rewind_horizon() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 5,
        max_witness_override_depth: 5,
        ..ConvergencePolicy::default()
    };
    assert!(policy.validate().is_ok());
}

#[test]
fn convergence_policy_rejects_witness_override_exceeding_rewind_horizon() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 5,
        max_witness_override_depth: 1000,
        ..ConvergencePolicy::default()
    };
    assert_eq!(
        policy.validate(),
        Err(ConvergencePolicyError::WitnessOverrideExceedsRewind {
            max_witness_override_depth: 1000,
            max_rewind_commits: 5,
        })
    );
}

#[test]
fn set_group_convergence_policy_rejects_witness_override_exceeding_rewind() {
    let (mut alice, _storage) = build_client(b"alice");
    let group_id = GroupId::new(vec![0u8; 32]);
    let bad_policy = CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 5,
            max_witness_override_depth: 1000,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    };

    let err = alice
        .set_group_convergence_policy(&group_id, bad_policy)
        .expect_err("policy violating the witness-override bound must be rejected");
    assert!(
        matches!(err, OpenMlsProjectionError::InvalidPolicy(_)),
        "expected InvalidPolicy, got {err:?}"
    );
}

#[test]
fn set_convergence_policy_rejects_app_window_mismatch() {
    let (mut alice, _storage) = build_client(b"alice");
    let err = alice
        .set_convergence_policy(CanonicalizationPolicy {
            app_message_past_epoch_limit: 1,
            ..CanonicalizationPolicy::default()
        })
        .expect_err("app window must match engine max_past_epochs");
    assert!(
        matches!(err, OpenMlsProjectionError::InvalidPolicy(_)),
        "expected InvalidPolicy, got {err:?}"
    );
}

#[test]
fn set_convergence_policy_accepts_pinned_v1_baseline() {
    let (mut alice, _storage) = build_client(b"alice");
    alice
        .set_convergence_policy(CanonicalizationPolicy::default())
        .expect("pinned v1 baseline must be accepted");
}

#[test]
fn non_pinned_policy_fails_ensure_pinned_v1_helper() {
    // Pure helper coverage. The engine reject arm under
    // `#[cfg(not(debug_assertions))]` is proven by
    // `just test-convergence-policy-pin` (tests/convergence_policy_pin.rs).
    let policy = CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    };
    assert!(
        !policy.is_pinned_v1(),
        "fixture must differ from the pinned baseline"
    );
    assert_eq!(
        policy.ensure_pinned_v1(),
        Err(cgka_engine::canonicalization::CanonicalizationPolicyError::NotPinnedV1)
    );
}

#[tokio::test]
async fn convergence_emits_run_state_and_decision_with_run_id_context() {
    // Requirement #10: a convergence run emits a convergence_run_state(started)
    // lifecycle row and a convergence_decision, correlated by a stable run_id on
    // the convergence context.
    use marmot_forensics::{AuditEvent, AuditEventKind, JsonlRecorder};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let recorder = JsonlRecorder::open(&path, "test-engine-conv".to_string()).unwrap();
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(b"alice"))
        .account_identity_proof_signer(proof_signer(b"alice"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .recorder(Box::new(recorder))
        .build()
        .unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "conv".into(),
            description: "".into(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    if let SendResult::GroupCreated { pending, .. } = create {
        alice.confirm_published(pending).await.unwrap();
    }

    alice
        .converge_stored_openmls_messages_at(&group_id, 2_000)
        .expect("converge");
    drop(alice);

    let events: Vec<AuditEvent> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    let started = events
        .iter()
        .find(|e| {
            matches!(
                &e.kind,
                AuditEventKind::ConvergenceRunState {
                    phase: marmot_forensics::ConvergencePhase::Started,
                    ..
                }
            )
        })
        .expect("convergence_run_state(started) recorded");
    let decision = events
        .iter()
        .find(|e| matches!(e.kind, AuditEventKind::ConvergenceDecision { .. }))
        .expect("convergence_decision recorded");

    // Both rows carry the convergence run id, and it is the same run.
    let run_id_of = |event: &AuditEvent| {
        event
            .context
            .as_ref()
            .and_then(|ctx| ctx.convergence.as_ref())
            .map(|c| c.run_id.clone())
    };
    let started_run = run_id_of(started).expect("started carries a run_id");
    let decision_run = run_id_of(decision).expect("decision carries a run_id");
    assert_eq!(started_run, decision_run, "rows share one run_id");
    assert!(started_run.starts_with("conv-"));
}

// --- Phase 6: full-data decoded message content (req #6, #7) -------------------

async fn ingest_app_and_read_audit(
    data_mode: marmot_forensics::AuditDataMode,
    path: &std::path::Path,
) -> Vec<marmot_forensics::AuditEvent> {
    // Receiver (bob) records; sender (alice) does not need a recorder.
    let bob_storage = SqliteAccountStorage::in_memory().unwrap();
    let bob_recorder = marmot_forensics::JsonlRecorder::open_with_data_mode(
        path,
        "bob-engine".into(),
        None,
        data_mode,
    )
    .unwrap();
    let mut bob = EngineBuilder::new(bob_storage)
        .legacy_compatibility_profile()
        .identity(pad32(b"bob"))
        .account_identity_proof_signer(proof_signer(b"bob"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .recorder(Box::new(bob_recorder))
        .build()
        .unwrap();
    let (mut alice, _alice_storage) = build_client(b"alice");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "decode".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();

    let app_msg = send_app(&mut alice, &group_id, b"secret hello".to_vec()).await;
    let outcome = bob.ingest(app_msg).await.expect("bob ingests app message");
    assert!(matches!(outcome, IngestOutcome::Processed));
    drop(bob);

    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn full_data_ingest_logs_decoded_message_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let events = ingest_app_and_read_audit(marmot_forensics::AuditDataMode::FullData, &path).await;

    let decoded = events
        .iter()
        .find_map(|e| match &e.kind {
            marmot_forensics::AuditEventKind::MessageContentDecoded {
                author,
                decoded_app_event,
                ..
            } => Some((author, decoded_app_event)),
            _ => None,
        })
        .expect("full_data ingest records message_content_decoded");
    let (author, decoded_app_event) = decoded;
    // The decrypted content is present.
    let app = decoded_app_event
        .as_ref()
        .expect("decoded app event present");
    assert_eq!(app.content.as_deref(), Some("secret hello"));
    // The authenticated author carries a full member pubkey in full-data mode.
    assert!(author.member_ref.is_some());
    assert!(
        author.member_pubkey_hex.is_some(),
        "full-data author has a full member pubkey"
    );
    // Every line is stamped full_data.
    assert!(
        events
            .iter()
            .all(|e| e.audit_data_mode == marmot_forensics::AuditDataMode::FullData)
    );
}

#[tokio::test]
async fn obfuscated_ingest_does_not_log_decoded_message_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let events = ingest_app_and_read_audit(
        marmot_forensics::AuditDataMode::ObfuscatedSensitiveData,
        &path,
    )
    .await;

    // The message is still ingested (an ingest_outcome row exists)...
    assert!(
        events.iter().any(|e| matches!(
            e.kind,
            marmot_forensics::AuditEventKind::IngestOutcome { .. }
        )),
        "obfuscated ingest still records the ingest outcome"
    );
    // ...but decrypted content is never decoded or logged.
    assert!(
        !events.iter().any(|e| matches!(
            e.kind,
            marmot_forensics::AuditEventKind::MessageContentDecoded { .. }
        )),
        "obfuscated mode must not log decoded message content"
    );
}
