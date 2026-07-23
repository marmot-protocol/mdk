//! Standalone MLS proposal authorization (mdk#1053).
//!
//! Non-admin members may send only SelfRemove as standalone proposals. Privileged
//! or unsupported standalone proposals must be rejected before queueing,
//! auto-commit scheduling, or convergence replay.

use async_trait::async_trait;
use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_engine::convergence::ConvergencePolicy;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_engine::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{
    IngestOutcome, PeeledContent, PeeledMessage, ProposalRejectionCategory, StaleReason,
};
use cgka_traits::message::MessageState;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{AccountDeviceSignerStorage, MessageStorage, StorageProvider};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::component::ComponentData;
use openmls::group::MlsGroup;
use openmls::messages::external_proposals::JoinProposal;
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::{BasicCredential, CredentialWithKey, LeafNodeParameters};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::OpenMlsProvider;
use storage_sqlite::SqliteAccountStorage;
use tls_codec::{Deserialize as _, Serialize as _};

mod support;
use support::proof_signer;

fn pad32(name: &[u8]) -> Vec<u8> {
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

fn hash_id(b: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    b.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

fn canonicalization_message_id(msg: &TransportMessage) -> String {
    // Stored OpenMLS canonicalization keys messages by MLS payload digest, not
    // by the transport envelope id used on the live ingest path.
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(&msg.payload))
}

fn content_dedup_message_id(msg: &TransportMessage) -> MessageId {
    use sha2::{Digest, Sha256};
    MessageId::new(Sha256::digest(&msg.payload).to_vec())
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

fn registry() -> FeatureRegistry {
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

fn build(id: &[u8]) -> impl CgkaEngine {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

fn build_with_storage(id: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = EngineBuilder::new(storage.clone())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    (engine, storage)
}

fn load_group_and_signer<'a>(
    storage: &'a SqliteAccountStorage,
    crypto: &'a RustCrypto,
    member: &MemberId,
    group_id: &GroupId,
) -> (MlsGroup, SignatureKeyPair) {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load group")
        .expect("group present");
    let binding = storage
        .account_device_signer(member)
        .expect("signer binding")
        .expect("signer binding present");
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .expect("signer present");
    (mls_group, signer)
}

fn app_payload_for(engine: &Engine<SqliteAccountStorage>, content: &str) -> Vec<u8> {
    use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
    MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        content.to_string(),
    )
    .encode()
    .expect("test app event encodes")
}

fn non_admin_self_update_proposal(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    sender: &MemberId,
    group_id: &GroupId,
) -> TransportMessage {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut mls_group, signer) = load_group_and_signer(storage, crypto, sender, group_id);
    let credential = CredentialWithKey {
        credential: BasicCredential::new(sender.as_slice().to_vec()).into(),
        signature_key: signer.public().into(),
    };
    let leaf_node_parameters = LeafNodeParameters::builder()
        .with_credential_with_key(credential)
        .build();
    let (proposal_out, _proposal_ref) = mls_group
        .propose_self_update(&provider, &signer, leaf_node_parameters)
        .expect("non-admin can build self-update proposal at OpenMLS layer");
    let proposal_bytes = proposal_out
        .tls_serialize_detached()
        .expect("serialize self-update proposal");

    TransportMessage {
        id: hash_id(&proposal_bytes),
        payload: proposal_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("standalone-update-proposal".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

fn store_pending_proposal(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    member: &MemberId,
    group_id: &GroupId,
    proposal: &TransportMessage,
) {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut mls_group, _) = load_group_and_signer(storage, crypto, member, group_id);
    let proposal_in = openmls::prelude::MlsMessageIn::tls_deserialize_exact(&proposal.payload)
        .expect("deserialize standalone proposal");
    let protocol: openmls::framing::ProtocolMessage = match proposal_in.extract() {
        openmls::prelude::MlsMessageBodyIn::PrivateMessage(message) => message.into(),
        openmls::prelude::MlsMessageBodyIn::PublicMessage(message) => message.into(),
        other => panic!("expected proposal protocol message, got {other:?}"),
    };
    let processed = mls_group
        .process_message(&provider, protocol)
        .expect("process standalone proposal");
    match processed.into_content() {
        openmls::prelude::ProcessedMessageContent::ProposalMessage(queued) => mls_group
            .store_pending_proposal(provider.storage(), *queued)
            .expect("store pending proposal"),
        other => panic!("expected proposal content, got {other:?}"),
    }
}

fn commit_pending_proposals(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    committer: &MemberId,
    group_id: &GroupId,
) -> TransportMessage {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut mls_group, signer) = load_group_and_signer(storage, crypto, committer, group_id);
    let (commit_out, _, _) = mls_group
        .commit_to_pending_proposals(&provider, &signer)
        .expect("commit pending proposals");
    let commit_bytes = commit_out
        .tls_serialize_detached()
        .expect("serialize by-reference commit");
    TransportMessage {
        id: hash_id(&commit_bytes),
        payload: commit_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("by-reference-update-commit".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

#[tokio::test]
async fn non_admin_standalone_update_proposal_is_rejected_at_ingest() {
    // spec/protocol-core/group-messaging.md:57-59 — v1 allows only SelfRemove as
    // a standalone proposal from non-admins. A by-reference Update proposal must
    // not be accepted into pending state or schedule auto-commit work.
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let mut carol = build(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "proposal-auth".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![Feature("self-remove")],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (welcome_for_bob, welcome_for_carol) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            (welcomes.remove(0), welcomes.remove(0))
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    carol.join_welcome(welcome_for_carol).await.unwrap();

    let crypto = RustCrypto::default();
    let proposal = non_admin_self_update_proposal(&bob_storage, &crypto, &bob.self_id(), &group_id);
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..proposal
    };

    let outcome = alice.ingest(routed.clone()).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Rejected {
                category: ProposalRejectionCategory::AuthorizationFailed
            }
        ),
        "privileged standalone Update must be rejected, got {outcome:?}"
    );
    assert!(
        alice.drain_auto_publish().is_empty(),
        "rejected proposal must not schedule auto-commit"
    );
    assert!(
        carol.drain_auto_publish().is_empty(),
        "rejected proposal must not schedule auto-commit on other members"
    );

    // Local outbound work must remain unblocked.
    let app = alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, "still works"),
        })
        .await
        .unwrap();
    assert!(
        matches!(app, SendResult::ApplicationMessage { .. }),
        "rejected inbound proposal must not block later local sends"
    );

    // OpenMLS pending proposal store must stay empty on the recipient.
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, _alice_storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load alice group")
        .expect("alice group present");
    assert!(
        mls_group.pending_proposals().next().is_none(),
        "rejected proposal must not enter OpenMLS pending state"
    );

    // Re-ingest after restart must not resurrect the proposal as pending.
    let mut alice_restarted = EngineBuilder::new(_alice_storage.clone())
        .identity(pad32(b"alice"))
        .account_identity_proof_signer(proof_signer(b"alice"))
        .feature_registry(registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    let restart_outcome = alice_restarted.ingest(routed).await.unwrap();
    assert!(
        matches!(
            restart_outcome,
            IngestOutcome::Stale {
                reason: StaleReason::AlreadySeen
            } | IngestOutcome::Rejected {
                category: ProposalRejectionCategory::AuthorizationFailed
            }
        ),
        "restarted ingest must not hydrate rejected proposal, got {restart_outcome:?}"
    );
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, _alice_storage.mls_storage());
    let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("reload alice group")
        .expect("alice group still present");
    assert!(
        mls_group.pending_proposals().next().is_none(),
        "restart must not reintroduce rejected proposal into pending state"
    );
}

async fn three_member_group(
    alice: &mut Engine<SqliteAccountStorage>,
    bob: &mut impl CgkaEngine,
    carol: &mut impl CgkaEngine,
) -> GroupId {
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "proposal-auth".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![Feature("self-remove")],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (welcome_for_bob, welcome_for_carol) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            (welcomes.remove(0), welcomes.remove(0))
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    carol.join_welcome(welcome_for_carol).await.unwrap();
    group_id
}

#[tokio::test]
async fn by_reference_non_admin_update_is_rejected_when_revalidated_at_commit() {
    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let (mut carol, carol_storage) = build_with_storage(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let crypto = RustCrypto::default();
    let proposal = non_admin_self_update_proposal(&bob_storage, &crypto, &bob.self_id(), &group_id);

    // Simulate a proposal retained before this authorization rule existed. Both
    // the admin committer and recipient have the proposal needed to resolve the
    // by-reference Commit. Commit-time revalidation must still reject Bob's
    // admin-gated standalone Update proposal against the candidate parent.
    store_pending_proposal(
        &alice_storage,
        &crypto,
        &alice.self_id(),
        &group_id,
        &proposal,
    );
    store_pending_proposal(
        &carol_storage,
        &crypto,
        &carol.self_id(),
        &group_id,
        &proposal,
    );
    let commit = commit_pending_proposals(&alice_storage, &crypto, &alice.self_id(), &group_id);
    let before_epoch = carol.epoch(&group_id).expect("carol has group");

    let outcome = carol.ingest(commit).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Rejected {
                category: ProposalRejectionCategory::AuthorizationFailed
            }
        ),
        "commit-time revalidation must reject non-admin by-reference Update, got {outcome:?}"
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), before_epoch);
}

fn standalone_app_data_update_proposal(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    sender: &MemberId,
    group_id: &GroupId,
    component_id: cgka_traits::app_components::AppComponentId,
    data: Vec<u8>,
) -> TransportMessage {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut mls_group, signer) = load_group_and_signer(storage, crypto, sender, group_id);
    let (proposal_out, _) = mls_group
        .propose_app_data_update(
            &provider,
            &signer,
            component_id,
            AppDataUpdateOperation::Update(data.into()),
        )
        .expect("build standalone AppDataUpdate proposal");
    let proposal_bytes = proposal_out
        .tls_serialize_detached()
        .expect("serialize AppDataUpdate proposal");
    TransportMessage {
        id: hash_id(&proposal_bytes),
        payload: proposal_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("standalone-app-data-update".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

#[tokio::test]
async fn non_admin_standalone_app_data_update_is_rejected() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let mut carol = build(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let crypto = RustCrypto::default();
    use cgka_traits::app_components::GROUP_PROFILE_COMPONENT_ID;
    let proposal = standalone_app_data_update_proposal(
        &bob_storage,
        &crypto,
        &bob.self_id(),
        &group_id,
        GROUP_PROFILE_COMPONENT_ID,
        b"not-admin".to_vec(),
    );
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..proposal
    };
    let outcome = alice.ingest(routed).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Rejected {
            category: ProposalRejectionCategory::AuthorizationFailed
        }
    ));
}

#[tokio::test]
async fn admin_self_remove_standalone_is_rejected() {
    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let (mut bob, _bob_storage) = build_with_storage(b"bob");
    let (mut carol, _carol_storage) = build_with_storage(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;

    let leave = alice
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        leave,
        cgka_traits::EngineError::AdminCannotSelfRemove { .. }
    ));

    // Build the proposal directly at the OpenMLS layer to exercise ingest auth.
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, alice_storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load")
        .expect("present");
    let binding = alice_storage
        .account_device_signer(&alice.self_id())
        .unwrap()
        .unwrap();
    let signer = SignatureKeyPair::read(
        alice_storage.mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .unwrap();
    let proposal_out = mls_group
        .leave_group_via_self_remove(&provider, &signer)
        .expect("admin can still build SelfRemove at OpenMLS layer");
    let proposal_bytes = proposal_out.tls_serialize_detached().unwrap();
    let routed = TransportMessage {
        id: hash_id(&proposal_bytes),
        payload: proposal_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("admin-self-remove".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    };

    let outcome = carol.ingest(routed).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Rejected {
            category: ProposalRejectionCategory::InvalidSelfRemove
        }
    ));
    assert!(carol.drain_auto_publish().is_empty());
}

#[tokio::test]
async fn convergence_rejects_unauthorized_standalone_proposal_before_pending_store() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let (mut carol, carol_storage) = build_with_storage(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let crypto = RustCrypto::default();
    let proposal = non_admin_self_update_proposal(&bob_storage, &crypto, &bob.self_id(), &group_id);
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..proposal
    };
    let proposal_id = canonicalization_message_id(&routed);
    let proposal_message_id = content_dedup_message_id(&routed);
    carol
        .buffer_openmls_convergence_message(&group_id, routed, 1_000)
        .expect("buffer unauthorized proposal for convergence replay");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("convergence run");
    assert!(result.accepted_proposals.is_empty());
    assert!(
        result.dropped_messages.iter().any(|dropped| {
            dropped.message_id == proposal_id
                && dropped.kind == cgka_engine::canonicalization::MessageKind::Proposal
                && dropped.reason
                    == cgka_engine::canonicalization::DroppedMessageReason::InvalidAgainstCandidateState
                && dropped.rejection_category
                    == Some(ProposalRejectionCategory::AuthorizationFailed)
        }),
        "rejected proposal must appear in dropped_messages: {:?}",
        result.dropped_messages
    );
    let record = carol_storage
        .get_message(&proposal_message_id)
        .expect("durable proposal row");
    assert_eq!(
        record.state,
        cgka_traits::message::MessageState::Failed,
        "rejected proposal durable row must be terminal"
    );
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, carol_storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load carol group")
        .expect("carol group present");
    assert!(
        mls_group.pending_proposals().next().is_none(),
        "convergence replay must not store unauthorized proposal"
    );
}

#[tokio::test]
async fn admin_standalone_update_is_unsupported() {
    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let (mut bob, _bob_storage) = build_with_storage(b"bob");
    let mut carol = build(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let crypto = RustCrypto::default();
    let proposal =
        non_admin_self_update_proposal(&alice_storage, &crypto, &alice.self_id(), &group_id);
    let outcome = carol.ingest(proposal).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Rejected {
            category: ProposalRejectionCategory::UnsupportedProposal
        }
    ));
}

#[tokio::test]
async fn admin_standalone_invalid_app_data_update_encoding_is_rejected() {
    use cgka_traits::app_components::GROUP_PROFILE_COMPONENT_ID;

    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let (mut bob, _bob_storage) = build_with_storage(b"bob");
    let mut carol = build(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let crypto = RustCrypto::default();
    let proposal = standalone_app_data_update_proposal(
        &alice_storage,
        &crypto,
        &alice.self_id(),
        &group_id,
        GROUP_PROFILE_COMPONENT_ID,
        vec![0xff, 0x00],
    );
    let outcome = carol.ingest(proposal).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Rejected {
            category: ProposalRejectionCategory::InvalidEncoding
        }
    ));
}

fn standalone_app_data_remove_proposal(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    sender: &MemberId,
    group_id: &GroupId,
    component_id: cgka_traits::app_components::AppComponentId,
) -> TransportMessage {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut mls_group, signer) = load_group_and_signer(storage, crypto, sender, group_id);
    let (proposal_out, _) = mls_group
        .propose_app_data_update(
            &provider,
            &signer,
            component_id,
            AppDataUpdateOperation::Remove,
        )
        .expect("build standalone AppDataUpdate remove proposal");
    let proposal_bytes = proposal_out
        .tls_serialize_detached()
        .expect("serialize AppDataUpdate remove proposal");
    TransportMessage {
        id: hash_id(&proposal_bytes),
        payload: proposal_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("standalone-app-data-remove".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

fn by_value_invalid_app_data_update_commit(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    committer: &MemberId,
    group_id: &GroupId,
    component_id: cgka_traits::app_components::AppComponentId,
    data: Vec<u8>,
) -> TransportMessage {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut mls_group, signer) = load_group_and_signer(storage, crypto, committer, group_id);
    let proposals = vec![Proposal::AppDataUpdate(Box::new(
        AppDataUpdateProposal::update(component_id, data),
    ))];
    let mut builder = mls_group
        .commit_builder()
        .add_proposals(proposals)
        .load_psks(provider.storage())
        .expect("load psks");
    let mut app_data = builder.app_data_dictionary_updater();
    for proposal in builder.app_data_update_proposals() {
        if let AppDataUpdateOperation::Update(bytes) = proposal.operation() {
            app_data.set(ComponentData::from_parts(
                proposal.component_id(),
                bytes.clone(),
            ));
        }
    }
    builder.with_app_data_dictionary_updates(app_data.changes());
    let commit_bundle = builder
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .expect("build by-value invalid app-data commit")
        .stage_commit(&provider)
        .expect("stage by-value invalid app-data commit");
    let (commit_out, _welcome_opt, _group_info) = commit_bundle.into_contents();
    let commit_bytes = commit_out
        .tls_serialize_detached()
        .expect("serialize by-value invalid app-data commit");
    TransportMessage {
        id: hash_id(&commit_bytes),
        payload: commit_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("by-value-invalid-commit".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

async fn bump_group_epoch(
    alice: &mut Engine<SqliteAccountStorage>,
    bob: &mut impl CgkaEngine,
    carol: &mut impl CgkaEngine,
    group_id: &GroupId,
) -> EpochId {
    let bump = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("epoch-bump".into()),
            description: None,
        })
        .await
        .unwrap();
    let (commit_msg, pending) = match bump {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit_msg
    };
    bob.ingest(routed.clone()).await.unwrap();
    carol.ingest(routed).await.unwrap();
    alice.epoch(group_id).expect("alice epoch after bump")
}

#[tokio::test]
async fn admin_standalone_invalid_app_data_remove_is_rejected() {
    use cgka_traits::app_components::APP_COMPONENTS_COMPONENT_ID;

    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let (mut bob, _bob_storage) = build_with_storage(b"bob");
    let mut carol = build(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let crypto = RustCrypto::default();
    let proposal = standalone_app_data_remove_proposal(
        &alice_storage,
        &crypto,
        &alice.self_id(),
        &group_id,
        APP_COMPONENTS_COMPONENT_ID,
    );
    let outcome = carol.ingest(proposal).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Rejected {
            category: ProposalRejectionCategory::InvalidEncoding
        }
    ));
}

#[tokio::test]
async fn wrong_epoch_standalone_proposal_returns_already_at_epoch() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let mut carol = build(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let crypto = RustCrypto::default();
    let stale_proposal =
        non_admin_self_update_proposal(&bob_storage, &crypto, &bob.self_id(), &group_id);
    let epoch_before = alice.epoch(&group_id).unwrap();
    let epoch_after = bump_group_epoch(&mut alice, &mut bob, &mut carol, &group_id).await;
    assert!(
        epoch_after > epoch_before,
        "epoch must advance for stale test"
    );

    let outcome = alice.ingest(stale_proposal).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::AlreadyAtEpoch { .. }
            }
        ),
        "wrong-epoch standalone proposal must be AlreadyAtEpoch, got {outcome:?}"
    );
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, _alice_storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load alice group")
        .expect("alice group present");
    assert!(
        mls_group.pending_proposals().next().is_none(),
        "wrong-epoch proposal must not enter pending state"
    );
}

#[tokio::test]
async fn by_value_commit_with_invalid_proposal_is_rejected_before_merge() {
    use cgka_traits::app_components::GROUP_PROFILE_COMPONENT_ID;

    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let (mut bob, _bob_storage) = build_with_storage(b"bob");
    let mut carol = build(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let crypto = RustCrypto::default();
    let before_epoch = carol.epoch(&group_id).unwrap();
    let commit = by_value_invalid_app_data_update_commit(
        &alice_storage,
        &crypto,
        &alice.self_id(),
        &group_id,
        GROUP_PROFILE_COMPONENT_ID,
        vec![0xff, 0x00],
    );
    let outcome = carol.ingest(commit).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Rejected {
                category: ProposalRejectionCategory::InvalidEncoding
            }
        ),
        "by-value commit with invalid proposal must reject before merge, got {outcome:?}"
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), before_epoch);
}

#[tokio::test]
async fn rejected_proposal_does_not_block_or_alter_later_valid_commit() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let (mut carol, _carol_storage) = build_with_storage(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let epoch_before = carol.epoch(&group_id).unwrap();
    let crypto = RustCrypto::default();
    let rejected = non_admin_self_update_proposal(&bob_storage, &crypto, &bob.self_id(), &group_id);
    let reject_outcome = carol.ingest(rejected).await.unwrap();
    assert!(matches!(
        reject_outcome,
        IngestOutcome::Rejected {
            category: ProposalRejectionCategory::AuthorizationFailed
        }
    ));

    let bump = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("after-reject".into()),
            description: None,
        })
        .await
        .unwrap();
    let (commit_msg, pending) = match bump {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit_msg
    };
    let valid_outcome = carol.ingest(routed).await.unwrap();
    assert!(
        matches!(
            valid_outcome,
            IngestOutcome::Processed | IngestOutcome::Buffered { .. }
        ),
        "valid commit after rejected proposal must apply, got {valid_outcome:?}"
    );
    if matches!(valid_outcome, IngestOutcome::Buffered { .. }) {
        carol
            .converge_stored_openmls_messages(&group_id, 1_000_000)
            .expect("convergence must apply buffered commit");
    }
    assert!(
        carol.epoch(&group_id).unwrap() > epoch_before,
        "valid commit must advance epoch after prior proposal rejection"
    );
}

#[tokio::test]
async fn invalid_external_join_signature_returns_invalid_signature_rejection() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, _bob_storage) = build_with_storage(b"bob");
    let mut carol = build(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let epoch = alice.epoch(&group_id).unwrap().0;
    let proposal = external_join_proposal_with_signature(&group_id, epoch, false);
    let outcome = alice.ingest(proposal).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Rejected {
                category: ProposalRejectionCategory::InvalidSignature
            }
        ),
        "cryptographic proposal-signature failure must map to InvalidSignature, got {outcome:?}"
    );
}

fn evolution(msg: SendResult) -> (TransportMessage, cgka_traits::engine_state::PendingStateRef) {
    match msg {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    }
}

fn proposal(msg: SendResult) -> TransportMessage {
    match msg {
        SendResult::Proposal { msg } => msg,
        other => panic!("expected Proposal, got {other:?}"),
    }
}

fn route(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    }
}

fn fresh_openmls_key_package(
    identity: &[u8],
    signer: &SignatureKeyPair,
) -> openmls::prelude::KeyPackage {
    let provider = OpenMlsRustCrypto::default();
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(pad32(identity)).into(),
        signature_key: signer.public().into(),
    };
    openmls::key_packages::KeyPackage::builder()
        .leaf_node_capabilities(openmls::prelude::Capabilities::default())
        .build(DEFAULT_CIPHERSUITE, &provider, signer, credential_with_key)
        .expect("build openmls key package")
        .key_package()
        .clone()
}

fn external_join_proposal(group_id: &GroupId, epoch: u64) -> TransportMessage {
    external_join_proposal_with_signature(group_id, epoch, true)
}

fn external_join_proposal_with_signature(
    group_id: &GroupId,
    epoch: u64,
    valid_signature: bool,
) -> TransportMessage {
    let key_package_signer = SignatureKeyPair::new(DEFAULT_CIPHERSUITE.signature_algorithm())
        .expect("external join key package signer");
    let other_signer = SignatureKeyPair::new(DEFAULT_CIPHERSUITE.signature_algorithm())
        .expect("alternate external join signer");
    let proposal_signer = if valid_signature {
        &key_package_signer
    } else {
        &other_signer
    };
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let proposal_out =
        JoinProposal::new::<<OpenMlsRustCrypto as OpenMlsProvider>::StorageProvider>(
            fresh_openmls_key_package(b"external-joiner", &key_package_signer),
            mls_gid,
            openmls::group::GroupEpoch::from(epoch),
            proposal_signer,
        )
        .expect("build external join proposal");
    let proposal_bytes = proposal_out
        .tls_serialize_detached()
        .expect("serialize external join proposal");
    TransportMessage {
        id: hash_id(&proposal_bytes),
        payload: proposal_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("external-join-proposal".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

#[tokio::test]
async fn direct_ingest_rejects_external_join_proposal() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, _bob_storage) = build_with_storage(b"bob");
    let mut carol = build(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let epoch = alice.epoch(&group_id).unwrap().0;
    let proposal = external_join_proposal(&group_id, epoch);

    let outcome = alice.ingest(proposal).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Rejected {
                category: ProposalRejectionCategory::UnsupportedProposal
            }
        ),
        "external join must be rejected before pending state, got {outcome:?}"
    );
    assert!(alice.drain_auto_publish().is_empty());

    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, _alice_storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load alice group")
        .expect("alice group present");
    assert!(
        mls_group.pending_proposals().next().is_none(),
        "external join must not enter OpenMLS pending state"
    );
}

#[tokio::test]
async fn convergence_rejects_external_join_proposal_before_pending_store() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, _bob_storage) = build_with_storage(b"bob");
    let (mut carol, carol_storage) = build_with_storage(b"carol");
    let group_id = three_member_group(&mut alice, &mut bob, &mut carol).await;
    let epoch = carol.epoch(&group_id).unwrap().0;
    let proposal = external_join_proposal(&group_id, epoch);
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..proposal
    };
    let proposal_id = canonicalization_message_id(&routed);
    let proposal_message_id = content_dedup_message_id(&routed);
    carol
        .buffer_openmls_convergence_message(&group_id, routed, 1_000)
        .expect("buffer external join for convergence replay");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("convergence run");
    assert!(result.accepted_proposals.is_empty());
    assert!(
        result.dropped_messages.iter().any(|dropped| {
            dropped.message_id == proposal_id
                && dropped.kind == cgka_engine::canonicalization::MessageKind::Proposal
                && dropped.reason
                    == cgka_engine::canonicalization::DroppedMessageReason::InvalidAgainstCandidateState
                && dropped.rejection_category
                    == Some(ProposalRejectionCategory::UnsupportedProposal)
        }),
        "external join must be dropped through typed rejection: {:?}",
        result.dropped_messages
    );
    let record = carol_storage
        .get_message(&proposal_message_id)
        .expect("durable proposal row");
    assert_eq!(
        record.state,
        MessageState::Failed,
        "rejected external join durable row must be terminal"
    );
}

#[tokio::test]
async fn parent_dependent_proposal_auth_deferred_until_retained_fork_replay() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, _bob_storage) = build_with_storage(b"bob");
    let (mut carol, carol_storage) = build_with_storage(b"carol");
    let (mut david, _david_storage) = build_with_storage(b"david");
    let (mut eve, _eve_storage) = build_with_storage(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "parent-dependent-proposal".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![Feature("self-remove")],
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
    bob.join_welcome(welcomes[0].clone()).await.unwrap();
    carol.join_welcome(welcomes[1].clone()).await.unwrap();
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
    let (alice_commit, alice_pending) = evolution(alice_invite);
    alice.confirm_published(alice_pending).await.unwrap();
    let alice_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..alice_commit
    };
    carol
        .buffer_openmls_convergence_message(&group_id, alice_commit.clone(), 1_000)
        .expect("buffer alice branch commit");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("alice branch settles and retains epoch-1 anchor");
    assert_eq!(carol.epoch(&group_id).unwrap().0, 2);

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, bob_pending, bob_welcomes) = match bob_invite {
        SendResult::GroupEvolution {
            msg,
            pending,
            welcomes,
        } => (msg, pending, welcomes),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    bob.confirm_published(bob_pending).await.unwrap();
    let bob_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..bob_commit
    };
    let eve_welcome = bob_welcomes
        .into_iter()
        .find(|welcome| {
            matches!(
                &welcome.envelope,
                TransportEnvelope::Welcome { recipient } if recipient == &eve.self_id()
            )
        })
        .expect("bob welcome for eve");
    eve.join_welcome(eve_welcome).await.unwrap();

    let fork_proposal = route(
        proposal(
            eve.send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
        ),
        &group_id,
    );
    let proposal_message_id = content_dedup_message_id(&fork_proposal);
    let proposal_id = canonicalization_message_id(&fork_proposal);

    // The proposal deliberately arrives before the commit that creates its
    // source-epoch parent. The current canonical state cannot authenticate it,
    // but that is not proof of an invalid signature.
    let ingest_outcome = carol.ingest(fork_proposal.clone()).await.unwrap();
    assert!(
        matches!(ingest_outcome, IngestOutcome::Buffered { .. }),
        "parent-dependent auth must defer while its candidate parent is absent, got {ingest_outcome:?}"
    );
    let record = carol_storage
        .get_message(&proposal_message_id)
        .expect("proposal durable row");
    assert_ne!(
        record.state,
        MessageState::Failed,
        "proposal must stay retryable while its candidate parent is absent"
    );

    carol
        .buffer_openmls_convergence_message(&group_id, bob_commit.clone(), 2_000)
        .expect("buffer competing fork commit");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("retained replay with alternate parent");
    assert!(
        !result.dropped_messages.iter().any(|dropped| {
            dropped.message_id == proposal_id
                && dropped.rejection_category == Some(ProposalRejectionCategory::InvalidSignature)
        }),
        "alternate-parent replay must not classify the proposal as an invalid signature: {:?}",
        result.dropped_messages
    );
    let record = carol_storage
        .get_message(&proposal_message_id)
        .expect("proposal durable row");
    assert_ne!(
        record.state,
        MessageState::Failed,
        "proposal must stay retryable until retained fork replay authenticates a parent"
    );
}
