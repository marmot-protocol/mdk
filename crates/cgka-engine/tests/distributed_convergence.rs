//! Engine integration for stored-message distributed convergence.

use async_trait::async_trait;
use cgka_engine::canonicalization::{
    CanonicalizationError, CanonicalizationPolicy, ConvergenceStatus, DroppedMessageReason,
    InvalidatedAppMessageReason, MessageKind,
};
use cgka_engine::convergence::{ConvergencePolicy, ConvergencePolicyError};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::openmls_projection::{OpenMlsProjectionError, project_mls_message};
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_engine::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
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
    AccountDeviceSignerStorage, GroupStorage, MessageStorage, OutboundIntentStorage,
    QueuedOutboundIntent, StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::component::ComponentData;
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension, Extension, Extensions};
use openmls::group::MlsGroup;
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::BasicCredential;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
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
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

fn build_client_with_max_past_epochs(
    id: &[u8],
    storage: SqliteAccountStorage,
    max_past_epochs: usize,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
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

/// Raw OpenMLS commit that removes `targets` and ALSO replaces the
/// GroupContext extensions with a copy that drops the `app_data_dictionary`
/// entirely, so the resulting epoch carries no admin-policy bytes at all.
/// OpenMLS accepts this shape (its draft-08 dictionary guard only applies to
/// commits that carry AppDataUpdate proposals), so the Marmot engine must
/// evaluate the admin/leaf coupling against the carried-forward admin set
/// (admin-policy-v1.md "Validation") instead of skipping the check.
fn raw_remove_members_commit_dropping_app_data_dictionary(
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

    let mut stripped_extensions = mls_group.extensions().clone();
    stripped_extensions.remove(openmls::extensions::ExtensionType::AppDataDictionary);
    let commit_bundle = mls_group
        .commit_builder()
        .propose_removals(leaf_indices)
        .propose_group_context_extensions(stripped_extensions)
        .expect("propose GCE without app_data_dictionary")
        .load_psks(provider.storage())
        .expect("load PSKs")
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .expect("build raw remove+GCE commit")
        .stage_commit(&provider)
        .expect("stage raw remove+GCE commit");
    let (commit, _welcome, _group_info) = commit_bundle.into_contents();
    let payload = commit
        .tls_serialize_detached()
        .expect("serialize raw remove+GCE commit");
    TransportMessage {
        id: hash_id(&payload),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("raw-openmls-remove-drop-dict".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
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

/// How a raw GroupContextExtensions commit tampers with the group's
/// `app_data_dictionary` (see [`raw_group_context_extensions_tamper_commit`]).
enum GceDictionaryTamper {
    /// Replace the extensions with a set omitting the dictionary entirely.
    StripDictionary,
    /// Keep the dictionary but omit one component's entry.
    DropEntry(AppComponentId),
    /// Keep the dictionary and every entry present, but rewrite one
    /// component's bytes — no `AppDataUpdate` proposal carries the change.
    ReplaceEntry(AppComponentId, Vec<u8>),
}

/// Build a raw OpenMLS GroupContextExtensions-only commit (no member changes)
/// that tampers with the Marmot component state in the resulting GroupContext.
/// OpenMLS's draft-08 dictionary guard only runs when a commit carries
/// `AppDataUpdate` proposals, so every tamper here builds and stages cleanly —
/// only the engine's app-component integrity check can reject it.
fn raw_group_context_extensions_tamper_commit(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    tamper: GceDictionaryTamper,
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

    let (commit, _welcome, _group_info) = mls_group
        .update_group_context_extensions(&provider, new_extensions, &signer)
        .expect("raw OpenMLS GroupContextExtensions tamper commit");
    let payload = commit
        .tls_serialize_detached()
        .expect("serialize raw GCE tamper commit");
    TransportMessage {
        id: hash_id(&payload),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("raw-openmls-gce-tamper".to_string()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
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
        .buffer_openmls_convergence_message(&group_id, commit_messages[0].clone(), 1_000)
        .expect("first commit buffered");
    carol
        .buffer_openmls_convergence_message(&group_id, commit_messages[1].clone(), 1_000)
        .expect("second commit buffered");
    carol
        .buffer_openmls_convergence_message(&group_id, app_msg.clone(), 1_000)
        .expect("app witness buffered");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        MessageState::EpochInvalidated,
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
        .converge_stored_openmls_messages(&group_id, 3_000)
        .expect("repeated convergence after applying is a no-op");
    assert!(repeated.accepted_commits.is_empty());
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
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
        .buffer_openmls_convergence_message(&group_id, invalid_remove.clone(), 1_000)
        .expect("invalid remove commit buffered");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
async fn convergence_rejects_remove_whose_context_carries_no_admin_policy_bytes() {
    // mdk#393 / admin-policy-v1.md "Validation": the cross-component
    // check runs on every commit that changes the member leaf set, whether or
    // not the commit carries admin-policy bytes. Bob's raw commit removes
    // Alice's last member leaf and swaps in GroupContext extensions with no
    // app_data_dictionary, so the staged context has no admin-policy entry to
    // read. The resulting epoch's admin set is the prior set carried forward
    // ({Alice, Bob}), so the commit must be rejected instead of skipping the
    // check on the missing bytes.
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
            name: "convergence-carried-forward-admins".into(),
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
        raw_remove_members_commit_dropping_app_data_dictionary(
            &bob_storage,
            &bob.self_id(),
            &group_id,
            std::slice::from_ref(&alice_id),
        ),
        &group_id,
    );
    carol
        .buffer_openmls_convergence_message(&group_id, invalid_remove.clone(), 1_000)
        .expect("invalid remove commit buffered");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("stored OpenMLS messages converge");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert!(
        result.accepted_commits.is_empty(),
        "remove with no admin-policy bytes must not be accepted: {result:?}"
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
async fn live_ingest_rejects_remove_whose_context_carries_no_admin_policy_bytes() {
    // Sibling of the stored-convergence test above, pushed through the live
    // `ingest` entry point instead of pre-buffering — pinning the hot path a
    // relay-delivered commit takes. The invalid remove must never be applied:
    // the outcome is terminal, and Carol's epoch, membership, and admin view
    // stay untouched.
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let bob_id = bob.self_id();
    let alice_id = alice.self_id();
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "live-ingest-carried-forward-admins".into(),
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
        raw_remove_members_commit_dropping_app_data_dictionary(
            &bob_storage,
            &bob.self_id(),
            &group_id,
            std::slice::from_ref(&alice_id),
        ),
        &group_id,
    );

    let outcome = carol.ingest(invalid_remove.clone()).await.unwrap();
    assert!(
        !matches!(outcome, IngestOutcome::Processed),
        "invalid remove must not be applied via live ingest, got {outcome:?}"
    );
    // Drive convergence to quiescence in case the inline pass left the commit
    // pending; the commit must still never be accepted.
    let result = carol
        .converge_stored_openmls_messages(&group_id, u64::MAX)
        .expect("stored OpenMLS messages converge");
    assert!(
        result.accepted_commits.is_empty(),
        "invalid remove must not be accepted after quiescence: {result:?}"
    );

    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    let stored_group = carol_storage.get_group(&group_id).expect("group stored");
    assert_eq!(stored_group.epoch, EpochId(1));
    assert_eq!(stored_group.members.len(), 3);
    let projected_members = carol.members(&group_id).expect("members projected");
    assert_eq!(projected_members.len(), 3);
    assert!(
        projected_members.iter().any(|member| member.id == alice_id),
        "alice must remain a member on carol's view: {projected_members:?}"
    );
    let alice_admin: [u8; 32] = alice_id.as_slice().try_into().unwrap();
    let bob_admin: [u8; 32] = bob_id.as_slice().try_into().unwrap();
    let mut expected_admins = vec![alice_admin, bob_admin];
    expected_admins.sort();
    assert_eq!(
        carol.admin_pubkeys(&group_id).unwrap(),
        expected_admins,
        "carol's admin view must be unchanged"
    );
    assert_message_state(
        &carol_storage,
        &invalid_remove,
        MessageState::EpochInvalidated,
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
        .buffer_openmls_convergence_message(&group_id, valid_remove.clone(), 1_000)
        .expect("valid remove commit buffered");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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

fn admin_key(member: &MemberId) -> [u8; 32] {
    member
        .as_slice()
        .try_into()
        .expect("test identities are 32-byte account keys")
}

/// Ingest `tampered` on `recipient` and assert the GCE tamper commit is
/// rejected: outcome `Stale`, epoch and sole admin unchanged, and the stored
/// message never `Processed`. Inbound same-epoch commits route through
/// convergence, and the ingest-driven pass runs inside the input window, so
/// the terminal disposition may not be persisted yet — the pinned invariant is
/// that the tamper commit is never applied.
async fn assert_gce_tamper_rejected_by_ingest(
    recipient: &mut Engine<SqliteAccountStorage>,
    recipient_storage: &SqliteAccountStorage,
    group_id: &GroupId,
    tampered: &TransportMessage,
    expected_admin: &MemberId,
) {
    let outcome = recipient
        .ingest(tampered.clone())
        .await
        .expect("ingest completes");
    assert!(
        matches!(outcome, IngestOutcome::Stale { .. }),
        "GCE tamper commit must not be processed: {outcome:?}"
    );
    assert_eq!(recipient.epoch(group_id).unwrap(), EpochId(1));
    assert_eq!(
        recipient.admin_pubkeys(group_id).unwrap(),
        vec![admin_key(expected_admin)],
        "the tampered component state must not take effect"
    );
    let record = recipient_storage
        .get_message(&content_id(tampered))
        .expect("tamper commit remains stored");
    assert_ne!(record.state, MessageState::Processed);
}

/// Buffer `tampered` into STORED CONVERGENCE on `recipient` and converge with
/// a closed input window; assert the pass settles with the commit dropped as
/// `InvalidAgainstCandidateState`, epoch and sole admin unchanged, and the
/// message `EpochInvalidated`.
fn assert_gce_tamper_rejected_by_convergence(
    recipient: &mut Engine<SqliteAccountStorage>,
    recipient_storage: &SqliteAccountStorage,
    group_id: &GroupId,
    tampered: &TransportMessage,
    expected_admin: &MemberId,
) {
    recipient
        .buffer_openmls_convergence_message(group_id, tampered.clone(), 1_000)
        .expect("GCE tamper commit buffered");
    let result = recipient
        .converge_stored_openmls_messages(group_id, 1_000_000)
        .expect("stored OpenMLS messages converge");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert!(
        result.accepted_commits.is_empty(),
        "GCE tamper commit must not be accepted: {result:?}"
    );
    assert!(
        result.dropped_messages.iter().any(|dropped| {
            dropped.kind == MessageKind::Commit
                && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
                && dropped.message_id == content_hex(tampered)
        }),
        "expected GCE tamper commit dropped as InvalidAgainstCandidateState, got {:?}",
        result.dropped_messages
    );
    assert_eq!(recipient.epoch(group_id).unwrap(), EpochId(1));
    assert_eq!(
        recipient_storage
            .get_group(group_id)
            .expect("group stored")
            .epoch,
        EpochId(1)
    );
    assert_eq!(
        recipient.admin_pubkeys(group_id).unwrap(),
        vec![admin_key(expected_admin)],
        "the tampered component state must not take effect"
    );
    assert_message_state(recipient_storage, tampered, MessageState::EpochInvalidated);
}

#[tokio::test]
async fn ingest_rejects_group_context_commit_stripping_app_data_dictionary() {
    // Regression: OpenMLS's draft-08 dictionary guard only validates the
    // GroupContext against a commit's AppDataUpdate proposals, so an
    // admin-authored GroupContextExtensions-only commit could replace the
    // extensions with a set that omits the app_data_dictionary entirely.
    // Merging it cannot orphan an admin key (the absent component is the empty
    // admin set), but it silently makes the group admin-less and freezes every
    // admin-gated operation. `ingest` must classify the strip commit invalid
    // instead of materializing the admin-less epoch.
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, bob_storage) = build_client(b"bob");
    let alice_id = alice.self_id();
    let group_id =
        bootstrap_gce_tamper_group(&mut alice, &mut bob, b"bob", "ingest-gce-dictionary-strip")
            .await;

    let strip = route(
        raw_group_context_extensions_tamper_commit(
            &alice_storage,
            &alice_id,
            &group_id,
            GceDictionaryTamper::StripDictionary,
        ),
        &group_id,
    );
    assert_gce_tamper_rejected_by_ingest(&mut bob, &bob_storage, &group_id, &strip, &alice_id)
        .await;
}

#[tokio::test]
async fn ingest_rejects_group_context_commit_dropping_required_component_entry() {
    // Entry-level variant of the dictionary strip: the GroupContextExtensions
    // commit keeps the app_data_dictionary but replaces it with one that omits
    // the required admin-policy component's state. validate_app_component_remove
    // only sees AppDataUpdate::Remove operations, so without the staged-commit
    // integrity check this strip would also merge.
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, bob_storage) = build_client(b"bob");
    let alice_id = alice.self_id();
    let group_id = bootstrap_gce_tamper_group(
        &mut alice,
        &mut bob,
        b"bob",
        "ingest-gce-admin-policy-strip",
    )
    .await;

    let strip = route(
        raw_group_context_extensions_tamper_commit(
            &alice_storage,
            &alice_id,
            &group_id,
            GceDictionaryTamper::DropEntry(GROUP_ADMIN_POLICY_COMPONENT_ID),
        ),
        &group_id,
    );
    assert_gce_tamper_rejected_by_ingest(&mut bob, &bob_storage, &group_id, &strip, &alice_id)
        .await;
}

#[tokio::test]
async fn convergence_rejects_group_context_commit_stripping_app_data_dictionary() {
    // The same dictionary-strip commit through STORED CONVERGENCE. Before the
    // integrity check, a GCE-only strip commit with no member removals was
    // ACCEPTED here — convergence materialized the admin-less epoch. It must
    // classify the commit as invalid instead.
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let alice_id = alice.self_id();
    let group_id = bootstrap_gce_tamper_group(
        &mut alice,
        &mut carol,
        b"carol",
        "convergence-gce-dictionary-strip",
    )
    .await;

    let strip = route(
        raw_group_context_extensions_tamper_commit(
            &alice_storage,
            &alice_id,
            &group_id,
            GceDictionaryTamper::StripDictionary,
        ),
        &group_id,
    );
    assert_gce_tamper_rejected_by_convergence(
        &mut carol,
        &carol_storage,
        &group_id,
        &strip,
        &alice_id,
    );
}

#[tokio::test]
async fn ingest_rejects_group_context_commit_rewriting_admin_policy_bytes() {
    // Content-integrity variant: the GroupContextExtensions commit keeps the
    // app_data_dictionary and every required entry PRESENT, but rewrites the
    // admin-policy bytes to a different (well-formed) admin set — with no
    // AppDataUpdate proposal carrying the change. The rewritten set names a
    // member with a leaf, so the admin-leaf coupling check passes, and the
    // presence rules pass too; only the AppDataUpdate attribution rule can
    // reject it. Without it, an admin could rewrite any required component's
    // bytes (admin set, profile, routing, retention) bypassing the component
    // validators entirely.
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, bob_storage) = build_client(b"bob");
    let alice_id = alice.self_id();
    let bob_id = bob.self_id();
    let group_id = bootstrap_gce_tamper_group(
        &mut alice,
        &mut bob,
        b"bob",
        "ingest-gce-admin-policy-rewrite",
    )
    .await;

    let rewrite = route(
        raw_group_context_extensions_tamper_commit(
            &alice_storage,
            &alice_id,
            &group_id,
            GceDictionaryTamper::ReplaceEntry(
                GROUP_ADMIN_POLICY_COMPONENT_ID,
                encode_admin_policy_for_test(std::slice::from_ref(&bob_id)),
            ),
        ),
        &group_id,
    );
    assert_gce_tamper_rejected_by_ingest(&mut bob, &bob_storage, &group_id, &rewrite, &alice_id)
        .await;
}

#[tokio::test]
async fn convergence_rejects_group_context_commit_rewriting_admin_policy_bytes() {
    // The same admin-policy byte rewrite through STORED CONVERGENCE with a
    // closed input window: the commit must be classified invalid, not
    // materialize an epoch whose admin set was swapped outside AppDataUpdate.
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let alice_id = alice.self_id();
    let carol_id = carol.self_id();
    let group_id = bootstrap_gce_tamper_group(
        &mut alice,
        &mut carol,
        b"carol",
        "convergence-gce-admin-policy-rewrite",
    )
    .await;

    let rewrite = route(
        raw_group_context_extensions_tamper_commit(
            &alice_storage,
            &alice_id,
            &group_id,
            GceDictionaryTamper::ReplaceEntry(
                GROUP_ADMIN_POLICY_COMPONENT_ID,
                encode_admin_policy_for_test(std::slice::from_ref(&carol_id)),
            ),
        ),
        &group_id,
    );
    assert_gce_tamper_rejected_by_convergence(
        &mut carol,
        &carol_storage,
        &group_id,
        &rewrite,
        &alice_id,
    );
}

/// mdk#286: a commit applied through STORED CONVERGENCE that later loses
/// a same-epoch fork must (a) attribute its winning-branch group-system rows to
/// the accepted commit via `origin_commit_id`, and (b) emit
/// `GroupEvent::CommitRolledBack` for the losing commit so the app can tombstone
/// the kind-1210 rows that losing commit synthesized.
///
/// Unlike the direct staged-commit seam (which fires `ForkRecovered`), this path
/// routes commits into convergence (`msg_epoch >= current_epoch`), so before
/// this fix the losing branch's synthesized rows had `origin_commit_id = NULL`
/// and no event ever targeted them — leaving stale contradictory history.
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
        .buffer_openmls_convergence_message(&group_id, commit_messages[0].clone(), 1_000)
        .expect("first commit buffered");
    carol
        .buffer_openmls_convergence_message(&group_id, commit_messages[1].clone(), 1_000)
        .expect("second commit buffered");
    carol
        .buffer_openmls_convergence_message(&group_id, app_msg.clone(), 1_000)
        .expect("app witness buffered");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("stored OpenMLS messages converge");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    // Exactly one commit was accepted; the sibling is dropped as a losing
    // branch (`InvalidAgainstCandidateState`).
    assert_eq!(
        result.accepted_commits,
        vec![content_hex(&commit_messages[app_branch_index])]
    );
    let losing_commit = &commit_messages[quiet_branch_index];
    assert!(
        result.dropped_messages.iter().any(|dropped| {
            dropped.kind == MessageKind::Commit
                && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
                && dropped.message_id == content_hex(losing_commit)
        }),
        "expected losing commit dropped as InvalidAgainstCandidateState, got {:?}",
        result.dropped_messages
    );
    assert_message_state(
        &carol_storage,
        losing_commit,
        MessageState::EpochInvalidated,
    );

    let winning_commit_id = content_id(&commit_messages[app_branch_index]);
    let losing_commit_id = content_id(losing_commit);
    let events = carol.drain_events();

    // (b) The losing commit emits CommitRolledBack so the app can tombstone the
    // kind-1210 rows it synthesized — there is no ForkRecovered on this path.
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
    // No ForkRecovered fires here: this is the convergence path, not the direct
    // staged-commit seam.
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, GroupEvent::ForkRecovered { .. })),
        "convergence path must not emit ForkRecovered, got {events:?}"
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
    carol.set_convergence_policy(CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    });
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
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, rename_commit.clone(), 1_001_000)
        .expect("sibling rename commit buffered");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
        .expect("reorg over the superseded removal");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(result.accepted_commits, vec![content_hex(&rename_commit)]);
    assert_message_state(
        &carol_storage,
        &remove_commit,
        MessageState::EpochInvalidated,
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
    // The winning rename is never withdrawn, and no direct-seam ForkRecovered
    // fires on the stored-convergence path.
    assert!(
        !events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupStateInvalidated { invalidated_commit_id, .. }
                if *invalidated_commit_id == content_id(&rename_commit)
        )),
        "the accepted rename must not be withdrawn, got {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, GroupEvent::ForkRecovered { .. })),
        "stored convergence must not emit ForkRecovered, got {events:?}"
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
        .buffer_openmls_convergence_message(&group_id, rename_commit.clone(), 1_000)
        .expect("rename commit buffered");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, rename_commit.clone(), 1_000)
        .expect("rename commit buffered");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, commit.clone(), 1_000)
        .expect("commit buffered");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_500)
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
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, commit_eve.clone(), 1_000)
        .expect("child commit buffered first");
    carol
        .buffer_openmls_convergence_message(&group_id, commit_david.clone(), 1_000)
        .expect("parent commit buffered second");
    carol
        .buffer_openmls_convergence_message(&group_id, app_msg.clone(), 1_000)
        .expect("app message buffered after child and parent");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, commit_eve.clone(), 1_000)
        .expect("child commit buffered first");
    carol
        .buffer_openmls_convergence_message(&group_id, commit_david.clone(), 1_000)
        .expect("parent commit buffered second");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
async fn engine_keeps_child_commit_pending_until_parent_arrives() {
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
    let (_commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();

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
        .buffer_openmls_convergence_message(&group_id, commit_eve.clone(), 1_000)
        .expect("child commit buffered without parent");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("missing parent is a pending graph input, not a hard error");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert!(result.accepted_commits.is_empty());
    assert!(result.dropped_messages.is_empty());
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_message_state(&carol_storage, &commit_eve, MessageState::Created);
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
    carol.set_convergence_policy(CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    });

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
        .buffer_openmls_convergence_message(&group_id, alice_commit.clone(), 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, bob_commit.clone(), 2_000)
        .expect("late bob commit buffered");

    let bob_wins = committer_wins(&bob.self_id(), &alice.self_id());

    let result = carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
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
    carol.set_convergence_policy(CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    });

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
        .buffer_openmls_convergence_message(&group_id, alice_commit.clone(), 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .converge_stored_openmls_messages(&group_id, 3_000_000)
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
    carol.set_convergence_policy(CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    });

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
        .buffer_openmls_convergence_message(&group_id, alice_commit.clone(), 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 3_000)
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
        .buffer_openmls_convergence_message(&group_id, bob_commit.clone(), 3_100)
        .expect("late bob commit buffered");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 4_500)
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
        .buffer_openmls_convergence_message(&group_id, alice_commit.clone(), 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, bob_commit.clone(), 2_000)
        .expect("late bob commit buffered after restart");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
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
    carol.set_convergence_policy(CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    });

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
        .buffer_openmls_convergence_message(&group_id, alice_commit, 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, bob_commit.clone(), 2_000)
        .expect("late bob commit buffered");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
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
        .converge_stored_openmls_messages(&group_id, 4_000_000)
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
    carol.set_convergence_policy(CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    });

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
        .buffer_openmls_convergence_message(&group_id, commit_david, 1_000)
        .expect("david commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, commit_eve, 2_000)
        .expect("eve commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
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
async fn engine_invalidates_commit_older_than_retained_anchor() {
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
    carol.set_convergence_policy(CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    });

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
        .buffer_openmls_convergence_message(&group_id, commit_david, 1_000)
        .expect("david commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, commit_eve, 2_000)
        .expect("eve commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
        .expect("eve branch applies");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));

    carol
        .buffer_openmls_convergence_message(&group_id, stale_bob_commit.clone(), 4_000)
        .expect("stale bob commit buffered");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 5_000_000)
        .expect("stale commit is resolved without historical replay");

    assert!(result.dropped_messages.iter().any(|dropped| {
        dropped.message_id == content_hex(&stale_bob_commit)
            && dropped.kind == MessageKind::Commit
            && dropped.reason == DroppedMessageReason::BeyondAnchor
    }));
    assert_message_state(
        &carol_storage,
        &stale_bob_commit,
        MessageState::EpochInvalidated,
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
async fn rebuilt_engine_invalidates_commit_older_than_retained_anchor() {
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
        .buffer_openmls_convergence_message(&group_id, commit_david, 1_000)
        .expect("david commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, commit_eve, 2_000)
        .expect("eve commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
        .expect("eve branch applies");
    assert_eq!(
        carol_storage.get_group(&group_id).unwrap().epoch,
        EpochId(3)
    );
    drop(carol);

    let mut carol = build_client_with_storage(b"carol", carol_storage.clone());
    carol
        .buffer_openmls_convergence_message(&group_id, stale_bob_commit.clone(), 4_000)
        .expect("stale bob commit buffered after restart");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 5_000_000)
        .expect("rebuilt engine resolves stale commit without historical replay");

    assert!(result.dropped_messages.iter().any(|dropped| {
        dropped.message_id == content_hex(&stale_bob_commit)
            && dropped.kind == MessageKind::Commit
            && dropped.reason == DroppedMessageReason::BeyondAnchor
    }));
    assert_message_state(
        &carol_storage,
        &stale_bob_commit,
        MessageState::EpochInvalidated,
    );
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
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
async fn convergence_app_message_with_unresolvable_sender_emits_no_event_and_lands_terminal() {
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
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("convergence settles despite forged app message");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert!(
        !result
            .accepted_app_messages
            .contains(&content_hex(&forged_msg)),
        "forged-attribution app message must not be accepted"
    );
    // Message epoch (2) is at the settled tip (2): the failed validation is
    // terminal, not retryable — the message cannot re-enter convergence.
    assert_message_state(&carol_storage, &forged_msg, MessageState::EpochInvalidated);

    let events = carol.drain_events();
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

/// Regression for mdk#144: a future-epoch app message that is
/// canonicalized as `UndecryptableInCanonicalState` (the retryable case — the
/// commit advancing the group to the message's epoch has not been selected
/// yet) must NOT be persisted as the terminal `EpochInvalidated`, and must not
/// emit `AppMessageInvalidated`. Otherwise the buffered message can never
/// re-enter convergence and is silently dropped once that commit arrives.
///
/// To reach the stored-convergence persistence path the pass must settle on a
/// tip: here convergence selects the epoch-2 commit while the app message
/// lives at epoch 3 (its commit withheld), so the message is classified
/// `UndecryptableInCanonicalState` and persisted alongside the applied branch.
///
/// Note the retryable mapping is scoped to messages whose epoch is *beyond* the
/// settled tip (here msg epoch 3 > tip 2). An `UndecryptableInCanonicalState`
/// message at or below the settled tip is instead stranded — the awaited commit
/// already passed on a branch it does not belong to — and stays terminal
/// `EpochInvalidated`; mapping that case to `Retryable` would wedge convergence
/// (it never clears, so the group reports perpetually unsettled and all later
/// sends stall). That at/below-tip path is covered end-to-end by the CLI test
/// `three_user_message_lifecycle_covers_invite_remove_and_later_delivery`.
#[tokio::test]
async fn future_epoch_app_message_stays_retryable_until_commit_arrives() {
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
    // classified UndecryptableInCanonicalState — the retryable case.
    carol
        .buffer_openmls_convergence_message(&group_id, route(commit_to_epoch2, &group_id), 1_000)
        .expect("epoch-2 commit buffered");
    carol
        .buffer_openmls_convergence_message(&group_id, app_msg.clone(), 1_000)
        .expect("future app message buffered");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("convergence settles on the epoch-2 commit");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert!(
        result.invalidated_app_messages.iter().any(|invalidated| {
            invalidated.message_id == content_hex(&app_msg)
                && invalidated.reason == InvalidatedAppMessageReason::UndecryptableInCanonicalState
        }),
        "future-epoch app message should be UndecryptableInCanonicalState, got {:?}",
        result.invalidated_app_messages
    );
    // The fix: retryable, not terminal. Pre-fix this was EpochInvalidated and
    // the message could never re-enter convergence.
    assert_message_state(&carol_storage, &app_msg, MessageState::Retryable);

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
        .buffer_openmls_convergence_message(&group_id, route(commit_to_epoch3, &group_id), 2_000)
        .expect("epoch-3 commit buffered");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 2_000_000)
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
            .buffer_openmls_convergence_message(&group_id, message.clone(), 1_000)
            .expect("message buffered");
    }

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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

    let mut restarted = EngineBuilder::new(carol_storage.clone())
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();

    let result = restarted
        .converge_stored_openmls_messages(&group_id, 2_000)
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
async fn rebuilt_engine_emits_losing_branch_app_invalidation_after_convergence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
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
            .buffer_openmls_convergence_message(&group_id, message.clone(), 1_000)
            .expect("message buffered");
    }

    let mut restarted = EngineBuilder::new(carol_storage.clone())
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();

    let result = restarted
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
    let (mut alice, _alice_storage) = build_client(b"alice");
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

    let commit = route(auto_commit.msg, &group_id);
    let commit_outcome = carol.ingest(commit.clone()).await.unwrap();
    assert!(matches!(
        commit_outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, stale_proposal.clone(), 1_000)
        .unwrap();
    carol
        .buffer_openmls_convergence_message(&group_id, first_commit.clone(), 1_000)
        .unwrap();
    let first = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        .buffer_openmls_convergence_message(&group_id, second_commit.clone(), 2_000)
        .unwrap();
    let second = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .unwrap();

    assert_eq!(second.accepted_commits, vec![content_hex(&second_commit)]);
    assert_message_state(&carol_storage, &second_commit, MessageState::Processed);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
}

#[tokio::test]
async fn engine_duplicate_convergence_input_does_not_reset_quiescence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
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
        .buffer_openmls_convergence_message(&group_id, commit.clone(), 1_000)
        .expect("commit buffered");
    carol
        .buffer_openmls_convergence_message(&group_id, commit.clone(), 1_900)
        .expect("duplicate commit ignored");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 2_000)
        .expect("duplicate should not pin syncing");

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

    assert!(matches!(queued, SendResult::Queued { .. }));
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
        SendResult::ApplicationMessage { msg } => route(msg.clone(), &group_id),
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
    carol.set_convergence_policy(CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    });
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
        .buffer_openmls_convergence_message(&group_id, far_future_msg.clone(), 1_000)
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

    bob.buffer_openmls_convergence_message(&group_id, invalid_commit.clone(), 1_000)
        .expect("invalid commit buffered");
    let result = bob
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        IngestOutcome::Stale {
            reason: cgka_traits::ingest::StaleReason::PeelFailed
        }
    ));
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(
        carol_storage
            .get_message(&commit_to_epoch3.id)
            .expect("raw deferred message stored")
            .state,
        MessageState::PeelDeferred
    );

    carol.set_convergence_policy(CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    });
    let sent = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"send after full catch-up"),
        })
        .await
        .unwrap();

    let sent_app = match sent {
        SendResult::ApplicationMessage { msg } => route(msg, &group_id),
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
/// fix, `retry_deferred_peels` treats the post-peel terminal `PeelFailed`
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
        IngestOutcome::Stale {
            reason: cgka_traits::ingest::StaleReason::PeelFailed
        }
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
    carol.set_convergence_policy(CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    });
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
        ..CanonicalizationPolicy::default()
    });

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
    let queued_commit = match &drained[0] {
        SendResult::GroupEvolution { msg, welcomes, .. } => {
            assert_eq!(welcomes.len(), 1);
            route(msg.clone(), &group_id)
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
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
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
    assert!(matches!(queued, SendResult::Queued { .. }));

    let policy = CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    };
    carol.set_convergence_policy(policy);

    let mut engine: Box<dyn CgkaEngine> = Box::new(carol);
    let drained = engine.advance_convergence(&group_id).await.unwrap();

    assert_eq!(drained.len(), 1);
    let sent_app = match &drained[0] {
        SendResult::ApplicationMessage { msg } => route(msg.clone(), &group_id),
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
    alice_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: MessageId::new(b"invite-carol".to_vec()),
            group_id: group_id.clone(),
            intent: SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![carol_kp],
            },
            created_at_ms: 0,
        })
        .unwrap();
    alice_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: MessageId::new(b"later-app".to_vec()),
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
        1
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
        1
    );

    alice.publish_failed(pending_invite).await.unwrap();
    let drained_after_failure = alice.advance_convergence(&group_id).await.unwrap();
    assert_eq!(drained_after_failure.len(), 1);
    assert!(
        matches!(
            drained_after_failure[0],
            SendResult::ApplicationMessage { .. }
        ),
        "expected later app intent after publish failure, got {drained_after_failure:?}"
    );
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
    let (mut carol, carol_storage) = build_client(b"carol");
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
    assert!(matches!(queued, SendResult::Queued { .. }));
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    let mut restarted = EngineBuilder::new(carol_storage.clone())
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    let drained = restarted
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();

    assert_eq!(drained.len(), 1);
    let sent_app = match &drained[0] {
        SendResult::ApplicationMessage { msg } => route(msg.clone(), &group_id),
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
        SendResult::ApplicationMessage { msg } => route(msg, group_id),
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
        .converge_stored_openmls_messages(&group_id, 2_000)
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
