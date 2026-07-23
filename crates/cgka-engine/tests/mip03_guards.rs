//! MIP-03 policy guards.
//!
//! Engine-layer guards the engine can enforce directly:
//! - Committer-MUST-NOT-be-leaver (RFC 9420 §12.2)
//!
//! Admin-related guards are enforced through Marmot group data and capability
//! tracking rather than by OpenMLS alone.

use async_trait::async_trait;
use cgka_engine::app_components::staged_commit_requires_admin;
use cgka_engine::canonicalization::{CanonicalizationPolicy, DroppedMessageReason};
use cgka_engine::convergence::ConvergencePolicy;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_engine::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
use cgka_traits::app_components::{GROUP_PROFILE_COMPONENT_ID, encode_component_vectors};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage, ProposalRejectionCategory};
use cgka_traits::message::MessageState;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{AccountDeviceSignerStorage, MessageStorage, StorageProvider};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use openmls::group::MlsGroup;
use openmls::messages::external_proposals::JoinProposal;
use openmls::messages::proposals::{AppDataUpdateOperation, PreSharedKeyProposal, Proposal};
use openmls::prelude::{
    BasicCredential, CredentialWithKey, LeafNodeParameters, MlsMessageBodyIn, MlsMessageIn,
    MlsMessageOut, ProcessedMessageContent,
};
use openmls::schedule::PreSharedKeyId;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::OpenMlsProvider as _;
use sha2::Digest as _;
use storage_sqlite::SqliteAccountStorage;
use tls_codec::{Deserialize as _, Serialize as _};

mod support;
use support::proof_signer;

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

fn hash_id(b: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    b.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

fn canonicalization_message_id(msg: &TransportMessage) -> String {
    // Stored OpenMLS canonicalization keys commit candidates by MLS payload
    // digest, not by the transport envelope id used by the live ingest path.
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(&msg.payload))
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

fn build_current_with_storage(id: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = EngineBuilder::new(storage.clone())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .protocol_profile(ProtocolProfile::Current)
        .feature_registry(registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    (engine, storage)
}

fn proposal_transport(
    message: MlsMessageOut,
    group_id: &GroupId,
    source: &str,
) -> TransportMessage {
    let payload = message
        .tls_serialize_detached()
        .expect("serialize raw proposal");
    TransportMessage {
        id: hash_id(&payload),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource(source.into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

fn self_update_proposal(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    sender: &MemberId,
    group_id: &GroupId,
) -> TransportMessage {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut group, signer) = load_group_and_signer(storage, crypto, sender, group_id);
    let (message, _) = group
        .propose_self_update(&provider, &signer, LeafNodeParameters::default())
        .expect("build valid self-update proposal");
    proposal_transport(message, group_id, "raw-self-update")
}

fn app_data_update_proposal(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    sender: &MemberId,
    group_id: &GroupId,
    data: Vec<u8>,
) -> TransportMessage {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut group, signer) = load_group_and_signer(storage, crypto, sender, group_id);
    let (message, _) = group
        .propose_app_data_update(
            &provider,
            &signer,
            GROUP_PROFILE_COMPONENT_ID,
            AppDataUpdateOperation::Update(data.into()),
        )
        .expect("build AppDataUpdate proposal");
    proposal_transport(message, group_id, "raw-app-data-update")
}

fn unsupported_psk_proposal(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    sender: &MemberId,
    group_id: &GroupId,
) -> TransportMessage {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut group, signer) = load_group_and_signer(storage, crypto, sender, group_id);
    let psk_id = PreSharedKeyId::external(vec![9u8; 32], vec![0u8; 32]);
    let (message, _) = group
        .propose_pre_shared_key(&provider, &signer, psk_id)
        .expect("build unsupported PSK proposal");
    proposal_transport(message, group_id, "raw-psk")
}

fn raw_self_remove_proposal(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    sender: &MemberId,
    group_id: &GroupId,
) -> TransportMessage {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut group, signer) = load_group_and_signer(storage, crypto, sender, group_id);
    let message = group
        .leave_group_via_self_remove(&provider, &signer)
        .expect("build raw SelfRemove proposal");
    proposal_transport(message, group_id, "raw-self-remove")
}

async fn establish_current_group(
    creator: &mut Engine<SqliteAccountStorage>,
    invitee: &mut Engine<SqliteAccountStorage>,
    invitee_is_admin: bool,
    name: &str,
) -> GroupId {
    let invitee_id = invitee.self_id();
    let invitee_kp = invitee.fresh_key_package().await.unwrap();
    let (group_id, create) = creator
        .create_group(CreateGroupRequest {
            name: name.into(),
            description: String::new(),
            members: vec![invitee_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: invitee_is_admin.then_some(invitee_id).into_iter().collect(),
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::FoundingGroupCreated { mut welcomes } => welcomes.remove(0),
        other => panic!("expected FoundingGroupCreated, got {other:?}"),
    };
    invitee.join_welcome(welcome).await.unwrap();
    group_id
}

/// Load the engine's underlying OpenMLS group + signer for `member` so a test
/// can construct raw commits of arbitrary shape against the real group state.
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

/// Stage a commit carrying exactly `proposals` (by value) against `mls_group`
/// using `signer`, then return whether the engine's allowlist would require the
/// committer to be an admin. The pending commit is cleared afterward so the
/// group can be reused.
fn requires_admin_for_proposals(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    mls_group: &mut MlsGroup,
    signer: &SignatureKeyPair,
    proposals: Vec<Proposal>,
) -> bool {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    mls_group
        .commit_builder()
        .add_proposals(proposals)
        .load_psks(provider.storage())
        .expect("load psks")
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .expect("build commit")
        .stage_commit(&provider)
        .expect("stage commit");
    let staged = mls_group.pending_commit().expect("pending commit staged");
    let requires_admin = staged_commit_requires_admin(staged);
    mls_group
        .clear_pending_commit(provider.storage())
        .expect("clear pending commit");
    requires_admin
}

fn spoofed_self_update_commit(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    attacker: &MemberId,
    victim: &MemberId,
    group_id: &GroupId,
) -> TransportMessage {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut mls_group, signer) = load_group_and_signer(storage, crypto, attacker, group_id);
    let spoofed_credential = CredentialWithKey {
        credential: BasicCredential::new(victim.as_slice().to_vec()).into(),
        signature_key: signer.public().into(),
    };
    let leaf_node_parameters = LeafNodeParameters::builder()
        .with_credential_with_key(spoofed_credential)
        .build();
    let commit_bundle = mls_group
        .self_update(&provider, &signer, leaf_node_parameters)
        .expect("attacker can build spoofed self-update at OpenMLS layer");
    let (commit_out, _welcome_opt, _group_info) = commit_bundle.into_contents();
    let commit_bytes = commit_out
        .tls_serialize_detached()
        .expect("serialize spoofed self-update commit");

    TransportMessage {
        id: hash_id(&commit_bytes),
        payload: commit_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("malicious-openmls".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

fn spoofed_update_proposal(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    attacker: &MemberId,
    victim: &MemberId,
    group_id: &GroupId,
) -> TransportMessage {
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut mls_group, signer) = load_group_and_signer(storage, crypto, attacker, group_id);
    let spoofed_credential = CredentialWithKey {
        credential: BasicCredential::new(victim.as_slice().to_vec()).into(),
        signature_key: signer.public().into(),
    };
    let leaf_node_parameters = LeafNodeParameters::builder()
        .with_credential_with_key(spoofed_credential)
        .build();
    let (proposal_out, _proposal_ref) = mls_group
        .propose_self_update(&provider, &signer, leaf_node_parameters)
        .expect("attacker can build spoofed update proposal at OpenMLS layer");
    let proposal_bytes = proposal_out
        .tls_serialize_detached()
        .expect("serialize spoofed update proposal");

    TransportMessage {
        id: hash_id(&proposal_bytes),
        payload: proposal_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("malicious-openmls-proposal".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

fn commit_pending_proposals(
    storage: &SqliteAccountStorage,
    crypto: &RustCrypto,
    committer: &MemberId,
    group_id: &GroupId,
    proposal: &TransportMessage,
) -> TransportMessage {
    store_pending_proposal(storage, crypto, committer, group_id, proposal);
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(crypto, storage.mls_storage());
    let (mut mls_group, signer) = load_group_and_signer(storage, crypto, committer, group_id);
    let (commit_out, _welcome_opt, _group_info) = mls_group
        .commit_to_pending_proposals(&provider, &signer)
        .expect("committer can build by-reference update commit");
    let commit_bytes = commit_out
        .tls_serialize_detached()
        .expect("serialize by-reference update commit");

    TransportMessage {
        id: hash_id(&commit_bytes),
        payload: commit_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("raw-openmls-commit".into()),
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
    // Re-process and store the by-reference proposal into the committer's live
    // OpenMLS proposal store so `commit_to_pending_proposals` can pick it up.
    //
    // The engine no longer leaves an observed proposal in a non-committing
    // member's live OpenMLS store (mdk#154): doing so tripped OpenMLS's
    // `create_message` PendingProposal guard and blocked all outbound app
    // payloads. The engine never commits received Update proposals by reference
    // (only the SelfRemove auto-committer commits received proposals), so this
    // test stages the by-reference commit explicitly here, exactly as a
    // hypothetical malicious/legacy committer would have, instead of relying on
    // an engine side-effect that no longer exists.
    let proposal_in = MlsMessageIn::tls_deserialize_exact(proposal.payload.as_slice())
        .expect("deserialize by-reference proposal");
    let protocol = match proposal_in.extract() {
        MlsMessageBodyIn::PrivateMessage(p) => openmls::framing::ProtocolMessage::from(p),
        MlsMessageBodyIn::PublicMessage(p) => openmls::framing::ProtocolMessage::from(p),
        other => panic!("expected a protocol message proposal, got {other:?}"),
    };
    let processed = mls_group
        .process_message(&provider, protocol)
        .expect("committer processes the by-reference proposal");
    match processed.into_content() {
        ProcessedMessageContent::ProposalMessage(queued) => {
            mls_group
                .store_pending_proposal(provider.storage(), *queued)
                .expect("committer stores the by-reference proposal");
        }
        other => panic!("expected a proposal message, got {other:?}"),
    }
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
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(pad32(b"external-joiner")).into(),
        signature_key: key_package_signer.public().into(),
    };
    let key_package = openmls::key_packages::KeyPackage::builder()
        .leaf_node_capabilities(openmls::prelude::Capabilities::default())
        .build(
            DEFAULT_CIPHERSUITE,
            &OpenMlsRustCrypto::default(),
            &key_package_signer,
            credential_with_key,
        )
        .expect("build external join key package")
        .key_package()
        .clone();
    let proposal_out = JoinProposal::new::<
        <OpenMlsRustCrypto as openmls_traits::OpenMlsProvider>::StorageProvider,
    >(
        key_package,
        openmls::group::GroupId::from_slice(group_id.as_slice()),
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
async fn inbound_self_update_rejects_account_identity_spoofing() {
    // A non-admin self-update is an allowed commit shape, but the new update
    // path leaf must still prove and preserve the committer's account identity.
    // Without Marmot's per-update validation, OpenMLS accepts a self-update that
    // keeps Bob's MLS signature key while changing the credential identity to
    // Alice's admin account pubkey.
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "spoofed-self-update".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome_for_bob = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();

    let before_epoch = alice.epoch(&group_id).expect("alice has group");
    let crypto = RustCrypto::default();
    let spoofed = spoofed_self_update_commit(
        &bob_storage,
        &crypto,
        &bob.self_id(),
        &alice.self_id(),
        &group_id,
    );

    let spoofed_id = canonicalization_message_id(&spoofed);

    let outcome = alice.ingest(spoofed).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: cgka_traits::ingest::StaleReason::PeelFailed
            }
        ),
        "terminally invalid same-epoch commits should not remain buffered, got {outcome:?}"
    );
    let result = alice
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("convergence should classify spoofed update");
    assert!(
        result.accepted_commits.is_empty(),
        "spoofed self-update must not be accepted, got {result:?}"
    );
    assert!(
        result.dropped_messages.iter().any(|dropped| {
            dropped.message_id == spoofed_id
                && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
        }),
        "spoofed self-update must be terminally invalidated, got {result:?}"
    );
    assert_eq!(alice.epoch(&group_id).unwrap(), before_epoch);
}

#[tokio::test]
async fn inbound_by_reference_update_rejects_account_identity_spoofing() {
    // Lock the `staged.update_proposals()` arm independently from the direct
    // update-path test above: Bob first queues a spoofed Update proposal, then
    // Alice commits it by reference. Recipients must validate Bob's proposed new
    // leaf against Bob's pre-merge account identity before applying the commit.
    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let (mut carol, carol_storage) = build_with_storage(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "spoofed-by-reference-update".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    let spoofed_proposal = spoofed_update_proposal(
        &bob_storage,
        &crypto,
        &bob.self_id(),
        &alice.self_id(),
        &group_id,
    );
    let rejected_proposal_id =
        MessageId::new(sha2::Sha256::digest(&spoofed_proposal.payload).to_vec());

    for outcome in [
        alice.ingest(spoofed_proposal.clone()).await.unwrap(),
        carol.ingest(spoofed_proposal.clone()).await.unwrap(),
    ] {
        assert!(
            matches!(
                outcome,
                IngestOutcome::Rejected {
                    category: ProposalRejectionCategory::InvalidEncoding
                }
            ),
            "invalid standalone Update must be rejected before pending storage, got {outcome:?}"
        );
    }
    assert_eq!(
        carol_storage
            .get_message(&rejected_proposal_id)
            .expect("rejected proposal remains diagnosable")
            .state,
        cgka_traits::message::MessageState::Failed
    );
    assert!(
        carol.drain_auto_publish().is_empty(),
        "a rejected proposal cannot schedule auto-commit work"
    );

    let before_epoch = carol.epoch(&group_id).expect("carol has group");
    let by_reference_commit = commit_pending_proposals(
        &alice_storage,
        &crypto,
        &alice.self_id(),
        &group_id,
        &spoofed_proposal,
    );
    let commit_id = canonicalization_message_id(&by_reference_commit);

    let outcome = carol.ingest(by_reference_commit).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: cgka_traits::ingest::StaleReason::PeelFailed
            }
        ),
        "terminally invalid by-reference Update commits should not remain buffered, got {outcome:?}"
    );
    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("convergence should classify spoofed by-reference update");
    assert!(
        result.accepted_commits.is_empty(),
        "spoofed by-reference Update must not be accepted, got {result:?}"
    );
    assert!(
        result.dropped_messages.iter().any(|dropped| {
            dropped.message_id == commit_id
                && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
        }),
        "spoofed by-reference Update must be terminally invalidated, got {result:?}"
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), before_epoch);

    // A rejected proposal is terminal durable input, not pending work that a
    // restart can accidentally hydrate or schedule.
    drop(carol);
    let mut reopened = EngineBuilder::new(carol_storage.clone())
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .feature_registry(registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    reopened
        .hydrate_stable_groups_from_storage()
        .expect("reopen after rejected proposal");
    assert!(reopened.drain_auto_publish().is_empty());
    assert_eq!(
        carol_storage
            .get_message(&rejected_proposal_id)
            .expect("rejected proposal remains failed after reopen")
            .state,
        cgka_traits::message::MessageState::Failed
    );
}

#[tokio::test]
async fn current_by_reference_non_admin_update_is_rejected_at_commit() {
    let (mut alice, alice_storage) = build_current_with_storage(b"alice-by-ref-current");
    let (mut bob, bob_storage) = build_current_with_storage(b"bob-by-ref-current");
    let (mut carol, carol_storage) = build_current_with_storage(b"carol-by-ref-current");
    let group_id =
        establish_current_group(&mut alice, &mut bob, false, "current-by-reference").await;
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();
    let (commit, pending, mut welcomes) = match invite {
        SendResult::GroupEvolution {
            msg,
            pending,
            welcomes,
        } => (msg, pending, welcomes),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.ingest(commit).await.unwrap();
    bob.converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("bob applies Carol's invite");
    carol.join_welcome(welcomes.remove(0)).await.unwrap();

    let crypto = RustCrypto::default();
    let proposal = self_update_proposal(&bob_storage, &crypto, &bob.self_id(), &group_id);
    store_pending_proposal(
        &carol_storage,
        &crypto,
        &carol.self_id(),
        &group_id,
        &proposal,
    );
    let commit = commit_pending_proposals(
        &alice_storage,
        &crypto,
        &alice.self_id(),
        &group_id,
        &proposal,
    );
    let before_epoch = carol.epoch(&group_id).expect("carol has current group");

    let outcome = carol.ingest(commit).await.unwrap();
    assert_eq!(
        outcome,
        IngestOutcome::Rejected {
            category: ProposalRejectionCategory::AuthorizationFailed,
        },
        "commit-time revalidation must reject a non-admin by-reference Update"
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), before_epoch);
}

#[tokio::test]
async fn standalone_update_authorization_is_profile_specific() {
    let (mut alice, _alice_storage) = build_current_with_storage(b"alice-current");
    let (mut bob, bob_storage) = build_current_with_storage(b"bob-current");
    let group_id =
        establish_current_group(&mut alice, &mut bob, false, "current-proposal-policy").await;

    let crypto = RustCrypto::default();
    let current_update = self_update_proposal(&bob_storage, &crypto, &bob.self_id(), &group_id);
    let outcome = alice.ingest(current_update).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Rejected {
                category: ProposalRejectionCategory::AuthorizationFailed
            }
        ),
        "current-profile non-admin standalone Update must be unauthorized, got {outcome:?}"
    );
    assert!(alice.drain_auto_publish().is_empty());

    // Existing legacy groups keep the deployed ordinary MLS member-update
    // proposal flow. This is deliberately not inferred from the new-engine
    // default; it follows the group's independently classified wire profile.
    let (mut legacy_alice, _legacy_alice_storage) = build_with_storage(b"alice-legacy");
    let (mut legacy_bob, legacy_bob_storage) = build_with_storage(b"bob-legacy");
    let legacy_bob_kp = legacy_bob.fresh_key_package().await.unwrap();
    let (legacy_group_id, create) = legacy_alice
        .create_group(CreateGroupRequest {
            name: "legacy-proposal-policy".into(),
            description: String::new(),
            members: vec![legacy_bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            legacy_alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    legacy_bob.join_welcome(welcome).await.unwrap();
    let legacy_update = self_update_proposal(
        &legacy_bob_storage,
        &crypto,
        &legacy_bob.self_id(),
        &legacy_group_id,
    );
    assert!(matches!(
        legacy_alice.ingest(legacy_update).await.unwrap(),
        IngestOutcome::Processed
    ));
}

#[tokio::test]
async fn standalone_proposal_gate_distinguishes_authorization_encoding_support_and_signature() {
    use marmot_forensics::{AuditEvent, AuditEventKind, JsonlRecorder};

    let audit_dir = tempfile::TempDir::new().unwrap();
    let audit_path = audit_dir.path().join("proposal-rejections.jsonl");
    let recorder = JsonlRecorder::open(&audit_path, "proposal-gate-test".to_string()).unwrap();
    let alice_storage = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = EngineBuilder::new(alice_storage.clone())
        .identity(pad32(b"alice-proposal-gate"))
        .account_identity_proof_signer(proof_signer(b"alice-proposal-gate"))
        .protocol_profile(ProtocolProfile::Current)
        .feature_registry(registry())
        .peeler(Box::new(MockPeeler))
        .recorder(Box::new(recorder))
        .build()
        .unwrap();
    let (mut bob, bob_storage) = build_current_with_storage(b"bob-proposal-gate");
    let (mut carol, carol_storage) = build_current_with_storage(b"carol-proposal-gate");
    let (mut dave, dave_storage) = build_current_with_storage(b"dave-proposal-gate");
    let (mut frank, frank_storage) = build_current_with_storage(b"frank-proposal-gate");
    let invalid_group =
        establish_current_group(&mut alice, &mut bob, true, "invalid-component").await;
    let unauthorized_group =
        establish_current_group(&mut alice, &mut carol, false, "unauthorized-component").await;
    let unsupported_group =
        establish_current_group(&mut alice, &mut dave, false, "unsupported-proposal").await;
    let self_remove_group =
        establish_current_group(&mut alice, &mut frank, true, "invalid-self-remove").await;

    let crypto = RustCrypto::default();
    let invalid_component = app_data_update_proposal(
        &bob_storage,
        &crypto,
        &bob.self_id(),
        &invalid_group,
        vec![0xff],
    );
    let unauthorized_component = app_data_update_proposal(
        &carol_storage,
        &crypto,
        &carol.self_id(),
        &unauthorized_group,
        encode_component_vectors(&[b"new name", b"description"]),
    );
    let unsupported =
        unsupported_psk_proposal(&dave_storage, &crypto, &dave.self_id(), &unsupported_group);
    let invalid_signature = external_join_proposal_with_signature(
        &unauthorized_group,
        alice.epoch(&unauthorized_group).unwrap().0,
        false,
    );
    let invalid_self_remove = raw_self_remove_proposal(
        &frank_storage,
        &crypto,
        &frank.self_id(),
        &self_remove_group,
    );

    for (proposal, expected_category) in [
        (
            invalid_component,
            ProposalRejectionCategory::InvalidEncoding,
        ),
        (
            unauthorized_component,
            ProposalRejectionCategory::AuthorizationFailed,
        ),
        (unsupported, ProposalRejectionCategory::UnsupportedProposal),
        (
            invalid_signature,
            ProposalRejectionCategory::InvalidSignature,
        ),
        (
            invalid_self_remove,
            ProposalRejectionCategory::InvalidSelfRemove,
        ),
    ] {
        let outcome = alice.ingest(proposal).await.unwrap();
        assert_eq!(
            outcome,
            IngestOutcome::Rejected {
                category: expected_category,
            },
            "proposal rejection must be terminal, got {outcome:?}"
        );
    }
    assert!(alice.drain_auto_publish().is_empty());

    drop(alice);
    let events: Vec<AuditEvent> = std::fs::read_to_string(&audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let rejection_classes = events
        .iter()
        .filter_map(|event| match &event.kind {
            AuditEventKind::Rejection { reason, .. } => Some(reason.as_str()),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    for expected in [
        "authorization_failed",
        "invalid_encoding",
        "unsupported_proposal",
        "invalid_signature",
        "invalid_self_remove",
    ] {
        assert!(
            rejection_classes.contains(expected),
            "missing privacy-safe rejection class {expected}: {rejection_classes:?}"
        );
    }
}

#[tokio::test]
async fn external_join_proposal_is_rejected_before_pending_state() {
    let (mut alice, alice_storage) = build_with_storage(b"alice-external-join");
    let mut bob = build(b"bob-external-join");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "external-join-rejection".into(),
            description: String::new(),
            members: vec![bob_kp],
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

    let proposal =
        external_join_proposal_with_signature(&group_id, alice.epoch(&group_id).unwrap().0, true);
    assert_eq!(
        alice.ingest(proposal).await.unwrap(),
        IngestOutcome::Rejected {
            category: ProposalRejectionCategory::UnsupportedProposal,
        }
    );
    assert!(alice.drain_auto_publish().is_empty());

    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, alice_storage.mls_storage());
    let mls_group = MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .expect("load group")
    .expect("group present");
    assert!(mls_group.pending_proposals().next().is_none());
}

#[tokio::test]
async fn stale_standalone_proposal_never_schedules_or_reenters_pending_state() {
    let (mut alice, _alice_storage) = build_current_with_storage(b"alice-stale-proposal");
    let (mut bob, bob_storage) = build_current_with_storage(b"bob-stale-proposal");
    let group_id = establish_current_group(&mut alice, &mut bob, false, "stale-proposal").await;
    let crypto = RustCrypto::default();
    let stale_self_remove =
        raw_self_remove_proposal(&bob_storage, &crypto, &bob.self_id(), &group_id);

    let update = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("advanced".into()),
            description: None,
        })
        .await
        .unwrap();
    let pending = match update {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let outcome = alice.ingest(stale_self_remove).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: cgka_traits::ingest::StaleReason::AlreadyAtEpoch {
                    current: cgka_traits::types::EpochId(2),
                    msg_epoch: cgka_traits::types::EpochId(1),
                }
            }
        ),
        "wrong-epoch proposal should retain the stale distinction, got {outcome:?}"
    );
    assert!(alice.drain_auto_publish().is_empty());
}

#[tokio::test]
async fn parent_dependent_proposal_waits_for_retained_fork_parent() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice-parent-dependent");
    let (mut bob, _bob_storage) = build_with_storage(b"bob-parent-dependent");
    let (mut carol, carol_storage) = build_with_storage(b"carol-parent-dependent");
    let (mut david, _david_storage) = build_with_storage(b"david-parent-dependent");
    let (mut eve, _eve_storage) = build_with_storage(b"eve-parent-dependent");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "parent-dependent-proposal".into(),
            description: String::new(),
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
    let (alice_commit, alice_pending) = match alice_invite {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(alice_pending).await.unwrap();
    carol
        .buffer_openmls_convergence_message(&group_id, alice_commit, 1_000)
        .expect("buffer alice branch commit");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("settle alice branch and retain the epoch-one anchor");
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

    let fork_proposal = match eve
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    {
        SendResult::Proposal { msg } => msg,
        other => panic!("expected Proposal, got {other:?}"),
    };
    let proposal_message_id = MessageId::new(sha2::Sha256::digest(&fork_proposal.payload).to_vec());
    let proposal_id = canonicalization_message_id(&fork_proposal);

    let ingest_outcome = carol.ingest(fork_proposal).await.unwrap();
    assert!(
        matches!(ingest_outcome, IngestOutcome::Buffered { .. }),
        "parent-dependent authentication must defer until the candidate parent arrives, got {ingest_outcome:?}"
    );
    assert_ne!(
        carol_storage
            .get_message(&proposal_message_id)
            .expect("proposal durable row")
            .state,
        MessageState::Failed
    );

    carol
        .buffer_openmls_convergence_message(&group_id, bob_commit, 2_000)
        .expect("buffer competing fork commit");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("replay with retained alternate parent");
    assert!(
        !result.dropped_messages.iter().any(|dropped| {
            dropped.message_id == proposal_id
                && dropped.rejection_category == Some(ProposalRejectionCategory::InvalidSignature)
        }),
        "alternate-parent replay must not misclassify the proposal signature: {:?}",
        result.dropped_messages
    );
    assert_ne!(
        carol_storage
            .get_message(&proposal_message_id)
            .expect("proposal durable row after replay")
            .state,
        MessageState::Failed
    );
}

#[tokio::test]
async fn non_admin_commit_allowlist_accepts_only_self_update_and_self_remove() {
    // spec/protocol-core/group-messaging.md:46-53 — a non-admin may commit
    // ONLY a pure self-update or a SelfRemove-only commit. Every other shape
    // (PSK, GCE, Add, Remove, AppDataUpdate, combinations) requires admin.
    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let mut bob = build(b"bob");
    let mut carol = build(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "allowlist".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![Feature("self-remove")],
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

    let crypto = RustCrypto::default();
    let (mut group, signer) =
        load_group_and_signer(&alice_storage, &crypto, &alice.self_id(), &group_id);

    // (a) Pure self-update: no by-reference proposals, just a path. ACCEPTED.
    assert!(
        !requires_admin_for_proposals(&alice_storage, &crypto, &mut group, &signer, vec![]),
        "a pure self-update commit must be allowed for non-admins"
    );

    // PSK-only commit. REJECTED (requires admin).
    let psk_id = PreSharedKeyId::external(vec![7u8; 32], vec![0u8; 32]);
    psk_id
        .store(
            &EngineOpenMlsProvider::<SqliteAccountStorage>::new(
                &crypto,
                alice_storage.mls_storage(),
            ),
            &[9u8; 32],
        )
        .expect("store psk secret");
    let psk_proposal = Proposal::PreSharedKey(Box::new(PreSharedKeyProposal::new(psk_id)));
    assert!(
        requires_admin_for_proposals(
            &alice_storage,
            &crypto,
            &mut group,
            &signer,
            vec![psk_proposal.clone()],
        ),
        "a PreSharedKey commit must require admin"
    );

    // Combination: self-update path + a PSK proposal. REJECTED.
    assert!(
        requires_admin_for_proposals(
            &alice_storage,
            &crypto,
            &mut group,
            &signer,
            vec![psk_proposal],
        ),
        "a commit combining a path with a non-allowed proposal must require admin"
    );
}

#[tokio::test]
async fn non_admin_commit_allowlist_accepts_self_remove_only_commit() {
    // spec/protocol-core/group-messaging.md:46-53 shape (b): a SelfRemove-only
    // commit that processes a pending SelfRemove proposal by reference is
    // allowed for non-admins. We drive the engine's real auto-commit (bob, a
    // non-admin, self-removes; a remaining member stages a SelfRemove-only
    // commit) and assert the allowlist classifies that staged commit as
    // not-admin-required.
    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let mut bob = build(b"bob");
    let mut carol = build(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "self-remove-only".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![Feature("self-remove")],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, mut welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    let welcome_bob = welcomes.remove(0);
    bob.join_welcome(welcome_bob).await.unwrap();

    // Bob (non-admin) self-removes -> SelfRemove proposal.
    let leave = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let proposal = match leave {
        SendResult::Proposal { msg } => msg,
        other => panic!("expected SelfRemove proposal, got {other:?}"),
    };
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..proposal
    };
    // Alice ingests bob's SelfRemove and schedules the deferred auto-commit.
    let outcome = alice.ingest(routed).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Processed));
    tokio::time::sleep(std::time::Duration::from_millis(75)).await;
    let advanced = alice.advance_convergence(&group_id).await.unwrap();
    assert!(advanced.is_empty());

    // The staged commit on alice's group is a SelfRemove-only commit. The
    // allowlist must classify it as a shape a non-admin is permitted to make.
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, alice_storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load alice group")
        .expect("alice group present");
    let staged = mls_group
        .pending_commit()
        .expect("alice staged a SelfRemove auto-commit");
    assert!(
        staged.queued_proposals().count() >= 1
            && staged
                .queued_proposals()
                .all(|q| matches!(q.proposal(), Proposal::SelfRemove)),
        "the staged commit should consume only SelfRemove proposals"
    );
    assert!(
        !staged_commit_requires_admin(staged),
        "a SelfRemove-only commit must be allowed for non-admins"
    );
}

#[tokio::test]
async fn committer_must_not_be_leaver_holds_for_self_proposal() {
    // RFC 9420 §12.2 — when bob (non-admin) produces his own SelfRemove
    // proposal, his engine should NOT auto-commit it (he's the target).
    // The auto_committer policy returns Observe in this case; this test
    // exercises the boundary by ingesting bob's own proposal back at bob
    // and verifying he does NOT auto-commit.
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");
    let mut carol = build(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "guards".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (welcome_for_bob, _welcome_for_carol) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            (welcomes.remove(0), welcomes.remove(0))
        }
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();

    // Bob produces his own SelfRemove proposal.
    let proposal = match bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    {
        SendResult::Proposal { msg } => msg,
        _ => unreachable!(),
    };

    // Bob ingests his own proposal (e.g. transport echo). The OwnEcho
    // path takes precedence (we filter via sent_message_ids before MLS
    // sees it). No commit should be produced.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..proposal
    };
    let outcome = bob.ingest(routed).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: cgka_traits::ingest::StaleReason::OwnEcho
            }
        ),
        "bob should classify his own proposal as OwnEcho"
    );
    let auto = bob.drain_auto_publish();
    assert!(
        auto.is_empty(),
        "bob must not produce a commit for his own SelfRemove"
    );
    let _ = carol;
}

// Admin cannot self-remove when they are the only admin.

#[tokio::test]
async fn admin_cannot_self_remove_when_only_admin() {
    // Alice creates a group with Bob. Alice is sole admin by creator policy,
    // so her attempt to leave is rejected.
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "alone".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    match create {
        SendResult::GroupCreated { pending, .. } => {
            alice.confirm_published(pending).await.unwrap();
        }
        _ => unreachable!(),
    }
    let err = alice
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .err()
        .unwrap();
    match err {
        cgka_traits::EngineError::AdminCannotSelfRemove { group_id: gid } => {
            assert_eq!(gid, group_id);
        }
        other => panic!("expected AdminCannotSelfRemove, got {other:?}"),
    }
}

#[tokio::test]
async fn admin_cannot_self_remove_even_when_co_admin_present() {
    // Alice creates a group with bob, bootstrapping bob as a co-admin.
    // The Marmot admin policy now requires admins to leave the admin set
    // before sending a SelfRemove proposal.
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");
    let mut carol = build(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let bob_id = bob.self_id();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "co-admins".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob_id],
        })
        .await
        .unwrap();

    let (welcome_for_bob, _welcome_for_carol) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            (welcomes.remove(0), welcomes.remove(0))
        }
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();

    let res = alice
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await;
    match res {
        Err(cgka_traits::EngineError::AdminCannotSelfRemove {
            group_id: err_group,
        }) => {
            assert_eq!(err_group, group_id)
        }
        other => panic!("expected AdminCannotSelfRemove, got {other:?}"),
    }
}

#[tokio::test]
async fn auto_committer_never_sees_locally_blocked_admin_self_remove() {
    // Alice + bob both admins; carol is non-admin.
    // Alice's local engine rejects the admin SelfRemove before a proposal
    // exists, so there is nothing for bob to auto-commit.
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");
    let mut carol = build(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let bob_id = bob.self_id();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "co-admin-leave".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob_id],
        })
        .await
        .unwrap();
    let (welcome_for_bob, _welcome_for_carol) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            (welcomes.remove(0), welcomes.remove(0))
        }
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();

    // Alice leaves.
    let res = alice
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await;
    assert!(matches!(
        res,
        Err(cgka_traits::EngineError::AdminCannotSelfRemove { .. })
    ));
    assert_eq!(bob.epoch(&group_id).unwrap().0, 1);
    assert!(bob.drain_auto_publish().is_empty());
    let _ = carol;
}

#[tokio::test]
async fn non_admin_can_self_remove_freely() {
    // Bob (non-admin) leaves: succeeds.
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "free".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        _ => unreachable!(),
    };
    bob.join_welcome(welcome).await.unwrap();
    let res = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert!(matches!(res, SendResult::Proposal { .. }));
}
