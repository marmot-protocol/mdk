//! `SendIntent::UpdateGroupData` round trips.
//!
//! Covers:
//! - Happy path: alice updates name + description; bob ingests + sees the
//!   change after the commit lands.
//! - Projection during PendingPublish: alice sees the new name immediately
//!   via her storage even before confirm.
//! - Rollback: `publish_failed` restores the previous name + description.
//! - Validation: empty intent (no fields) errors with `EngineError::Other`.
//! - State guard: not allowed during PendingPublish.

use async_trait::async_trait;
use cgka_engine::DEFAULT_CIPHERSUITE;
use cgka_engine::canonicalization::{ConvergenceStatus, DroppedMessageReason};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::EngineError;
use cgka_traits::app_components::{
    AppComponentData, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GroupAvatarUrlV1, NOSTR_ROUTING_COMPONENT_ID,
    NostrRoutingV1, default_group_components, encode_group_avatar_url_v1, encode_nostr_routing_v1,
};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::message::MessageState;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerStorage, GroupStorage, MessageStorage, StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use openmls::component::ComponentData;
use openmls::group::MlsGroup;
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use storage_sqlite::SqliteAccountStorage;
use tls_codec::Serialize as _;

mod support;
use support::proof_signer;

/// Content-derived dedup id of a group message (#238). Inbound group messages
/// are stored and reported under SHA-256 of the recovered MLS bytes, which the
/// pass-through `MockPeeler` makes equal to `msg.payload`.
fn content_id(msg: &TransportMessage) -> MessageId {
    MessageId::new(Sha256::digest(&msg.payload).to_vec())
}

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

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

fn encode_admin_policy_for_test(admins: &[Vec<u8>]) -> Vec<u8> {
    let mut admins = admins.to_vec();
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

fn build(id: &[u8]) -> Engine<SqliteAccountStorage> {
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

fn converge_buffered_commit(engine: &mut Engine<SqliteAccountStorage>, group_id: &GroupId) {
    let result = engine
        .converge_stored_openmls_messages(group_id, 1_000_000)
        .expect("buffered commit converges");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
}

/// Engine that supports the Nostr routing component (the default component set
/// does not), so a group can carry — and later rotate — a `nostr_group_id`.
fn build_with_routing(id: &[u8]) -> Engine<SqliteAccountStorage> {
    let mut components: Vec<_> = default_group_components().into_iter().collect();
    components.push(NOSTR_ROUTING_COMPONENT_ID);
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(registry())
        .supported_app_components(components)
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

/// #740 rotation regression: after a Nostr routing-component update commit is
/// applied, the engine's `transport_group_id_index` must self-heal so inbound
/// messages addressed to the NEW `nostr_group_id` still resolve to the group.
/// Before the fix the index was populated only at hydrate/create/join and went
/// stale on rotation, stranding the group until restart. Exercises the
/// convergence-apply reindex site on the recipient; `confirm_published` and the
/// direct remote-commit-apply path call the same `reindex_transport_group_id`.
#[tokio::test]
async fn routing_rotation_reindexes_inbound_transport_group_id() {
    let mut alice = build_with_routing(b"alice");
    let mut bob = build_with_routing(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    // Create with routing X and invite bob.
    let routing_x = NostrRoutingV1::new([0x41; 32], vec!["wss://x.example".into()]).unwrap();
    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "orig".into(),
            description: "d".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: encode_nostr_routing_v1(&routing_x).unwrap(),
            }],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcomes.into_iter().next().unwrap())
        .await
        .unwrap();

    // Alice rotates the routing X -> Y and confirms locally.
    let routing_y = NostrRoutingV1::new([0x59; 32], vec!["wss://y.example".into()]).unwrap();
    let res = alice
        .send(SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: encode_nostr_routing_v1(&routing_y).unwrap(),
            }],
        })
        .await
        .unwrap();
    let (rotate_commit, rotate_pending) = match res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(rotate_pending).await.unwrap();

    // Bob receives the rotation commit. Per the overlap model it is published to
    // the PRIOR routing address X (peers still address the old id until they
    // apply the rotation); bob resolves X (indexed at join) and applies it.
    let routed_rotation = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: routing_x.nostr_group_id.to_vec(),
        },
        ..rotate_commit
    };
    bob.ingest(routed_rotation).await.unwrap();
    converge_buffered_commit(&mut bob, &gid);

    // Alice now renames the group; this commit is published to the NEW routing
    // address Y. Bob can only apply it if his transport-id index self-healed to
    // map Y -> group when he applied the rotation. A stale index would resolve Y
    // to a phantom direct GroupId and drop the commit as unknown.
    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("after-rotation".into()),
            description: None,
        })
        .await
        .unwrap();
    let (rename_commit, rename_pending) = match res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(rename_pending).await.unwrap();

    let routed_rename = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: routing_y.nostr_group_id.to_vec(),
        },
        ..rename_commit
    };
    // Resolves to bob's real group (buffered for convergence), not dropped.
    assert!(matches!(
        bob.ingest(routed_rename).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));
    converge_buffered_commit(&mut bob, &gid);

    // Bob followed the post-rotation commit addressed to the NEW nostr_group_id.
    assert_eq!(bob.group_record(&gid).unwrap().name, "after-rotation");
    assert_eq!(bob.epoch(&gid).unwrap().0, alice.epoch(&gid).unwrap().0);
}

fn malicious_app_component_commit(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    updates: Vec<AppComponentData>,
) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load attacker's MLS group")
        .expect("attacker joined group");
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

    let proposals = updates
        .iter()
        .map(|update| {
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
                update.component_id,
                update.data.clone(),
            )))
        })
        .collect::<Vec<_>>();
    let mut builder = mls_group
        .commit_builder()
        .add_proposals(proposals)
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
        .expect("build malicious app-data commit")
        .stage_commit(&provider)
        .expect("stage malicious app-data commit");
    let (commit_out, _welcome_opt, _group_info) = commit_bundle.into_contents();
    let commit_bytes = commit_out
        .tls_serialize_detached()
        .expect("serialize malicious app-data commit");

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

async fn create_pair() -> (
    Engine<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    GroupId,
) {
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "original".into(),
            description: "orig description".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    let welcome = welcomes.into_iter().next().unwrap();
    bob.join_welcome(welcome).await.unwrap();
    (alice, bob, gid)
}

// ── Happy path ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_group_data_renames_group_and_advances_epoch() {
    let (mut alice, mut bob, gid) = create_pair().await;
    assert_eq!(alice.epoch(&gid).unwrap().0, 1);

    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("new name".into()),
            description: Some("new desc".into()),
        })
        .await
        .unwrap();
    let (commit, pending) = match res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };

    // Alice's projected epoch is 2 already (PendingPublish).
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);

    alice.confirm_published(pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);

    // Bob ingests the commit and his epoch + name follow.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..commit
    };
    let outcome = bob.ingest(routed).await.unwrap();
    assert!(matches!(
        outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));
    converge_buffered_commit(&mut bob, &gid);
    assert_eq!(bob.epoch(&gid).unwrap().0, 2);
}

#[tokio::test]
async fn non_admin_cannot_update_group_data() {
    let (_alice, mut bob, gid) = create_pair().await;

    let err = bob
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("mallory edit".into()),
            description: None,
        })
        .await
        .err()
        .unwrap();

    assert!(matches!(err, EngineError::NotGroupAdmin { .. }));
}

#[tokio::test]
async fn admin_policy_update_promotes_member_who_can_update_group_data() {
    let (mut alice, mut bob, gid) = create_pair().await;
    let alice_id = pad32(b"alice");
    let bob_id = pad32(b"bob");

    let res = alice
        .send(SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![AppComponentData {
                component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
                data: encode_admin_policy_for_test(&[alice_id, bob_id]),
            }],
        })
        .await
        .unwrap();
    let (commit, pending) = match res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..commit
    };
    bob.ingest(routed).await.unwrap();
    converge_buffered_commit(&mut bob, &gid);

    assert_eq!(bob.admin_pubkeys(&gid).unwrap().len(), 2);

    let bob_update = bob
        .send(SendIntent::UpdateGroupData {
            group_id: gid,
            name: Some("bob can rename".into()),
            description: None,
        })
        .await;
    assert!(
        matches!(bob_update, Ok(SendResult::GroupEvolution { .. })),
        "promoted Bob should be allowed to update admin-gated group data: {bob_update:?}"
    );
}

#[tokio::test]
async fn promoted_member_group_data_update_converges_for_original_admin() {
    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let (mut bob, _bob_storage) = build_with_storage(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let alice_id = pad32(b"alice");
    let bob_id = pad32(b"bob");

    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "original".into(),
            description: "orig description".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    let welcome = welcomes.into_iter().next().unwrap();
    bob.join_welcome(welcome).await.unwrap();

    let promoted = alice
        .send(SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![AppComponentData {
                component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
                data: encode_admin_policy_for_test(&[alice_id, bob_id]),
            }],
        })
        .await
        .unwrap();
    let (promote_commit, pending) = match promoted {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.ingest(TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..promote_commit
    })
    .await
    .unwrap();
    converge_buffered_commit(&mut bob, &gid);

    let bob_update = bob
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("bob rename".into()),
            description: None,
        })
        .await
        .unwrap();
    let (bob_commit, pending) = match bob_update {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        _ => unreachable!(),
    };
    bob.confirm_published(pending).await.unwrap();
    let routed_bob_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..bob_commit
    };
    alice.ingest(routed_bob_commit).await.unwrap();
    converge_buffered_commit(&mut alice, &gid);

    let alice_group = alice_storage.get_group(&gid).unwrap();
    assert_eq!(alice_group.name, "bob rename");
}

#[tokio::test]
async fn convergence_rejects_non_admin_admin_policy_update() {
    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let alice_id = pad32(b"alice");
    let alice_admin: [u8; 32] = alice_id.clone().try_into().unwrap();
    let bob_id = pad32(b"bob");

    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "original".into(),
            description: "orig description".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    let welcome = welcomes.into_iter().next().unwrap();
    bob.join_welcome(welcome).await.unwrap();

    let malicious = malicious_app_component_commit(
        &bob_storage,
        &bob.self_id(),
        &gid,
        vec![AppComponentData {
            component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
            data: encode_admin_policy_for_test(&[alice_id.clone(), bob_id]),
        }],
    );
    // The convergence layer keys the unauthorized commit on its content-derived
    // dedup id (#238), not the outer transport id.
    let malicious_id = hex::encode(content_id(&malicious).as_slice());

    alice
        .ingest(malicious.clone())
        .await
        .expect("malicious commit enters convergence");
    let result = alice
        .converge_stored_openmls_messages(&gid, 1_000_000)
        .expect("convergence should reject unauthorized commit without failing");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert!(
        result.accepted_commits.is_empty(),
        "non-admin commit must not be selected"
    );
    assert!(
        result.dropped_messages.iter().any(|dropped| {
            dropped.message_id == malicious_id
                && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
        }),
        "unauthorized commit should receive a terminal dropped disposition: {result:?}"
    );
    assert_eq!(alice.epoch(&gid).unwrap().0, 1);
    assert_eq!(alice.admin_pubkeys(&gid).unwrap(), vec![alice_admin]);
    assert_eq!(
        alice_storage
            .get_message(&content_id(&malicious))
            .expect("malicious message was stored")
            .state,
        MessageState::EpochInvalidated
    );
}

#[tokio::test]
async fn non_admin_cannot_update_admin_policy_component() {
    let (_alice, mut bob, gid) = create_pair().await;
    let alice_id = pad32(b"alice");
    let bob_id = pad32(b"bob");

    let err = bob
        .send(SendIntent::UpdateAppComponents {
            group_id: gid,
            updates: vec![AppComponentData {
                component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
                data: encode_admin_policy_for_test(&[alice_id, bob_id]),
            }],
        })
        .await
        .err()
        .unwrap();

    assert!(matches!(err, EngineError::NotGroupAdmin { .. }));
}

#[tokio::test]
async fn invalid_admin_policy_component_is_rejected() {
    let (mut alice, _bob, gid) = create_pair().await;
    let mut empty_admin_policy = Vec::new();
    cgka_traits::app_components::encode_quic_varint(0, &mut empty_admin_policy);

    let err = alice
        .send(SendIntent::UpdateAppComponents {
            group_id: gid,
            updates: vec![AppComponentData {
                component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
                data: empty_admin_policy,
            }],
        })
        .await
        .err()
        .unwrap();

    assert!(matches!(err, EngineError::Serialize(_)));
}

#[tokio::test]
async fn admin_policy_update_listing_non_member_is_rejected() {
    // admin-policy-v1.md: every admin key must correspond to an account with a
    // member leaf in the resulting epoch. Alice stays an admin (so this is not a
    // last-admin removal), but `carol` is not a member, so the update is invalid.
    let (mut alice, _bob, gid) = create_pair().await;
    let alice_id = pad32(b"alice");
    let carol_non_member = pad32(b"carol");

    let err = alice
        .send(SendIntent::UpdateAppComponents {
            group_id: gid,
            updates: vec![AppComponentData {
                component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
                data: encode_admin_policy_for_test(&[alice_id, carol_non_member]),
            }],
        })
        .await
        .expect_err("admin-policy listing a non-member must be rejected");

    assert!(matches!(err, EngineError::Other(_)), "got {err:?}");
}

// ── Partial update ──────────────────────────────────────────────────────────

#[tokio::test]
async fn update_group_data_with_only_name_preserves_description() {
    let (mut alice, _bob, gid) = create_pair().await;
    alice.drain_events();

    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("renamed".into()),
            description: None,
        })
        .await
        .unwrap();
    let pending = match res {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);

    let events = alice.drain_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                change: cgka_traits::engine::GroupStateChange::GroupRenamed {
                    name,
                    previous_name: Some(previous_name),
                },
                ..
            } if name == "renamed" && previous_name == "original"
        )),
        "local rename must carry the previous group name, got: {events:?}",
    );
}

// ── Rollback ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_group_data_publish_failed_rolls_back() {
    let (mut alice, _bob, gid) = create_pair().await;

    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("doomed".into()),
            description: Some("never published".into()),
        })
        .await
        .unwrap();
    let pending = match res {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => unreachable!(),
    };

    alice.publish_failed(pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 1);

    // The group is immediately re-usable.
    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("kept".into()),
            description: None,
        })
        .await
        .expect("post-rollback update must succeed");
    if let SendResult::GroupEvolution { pending, .. } = res {
        alice.confirm_published(pending).await.unwrap();
    }
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
}

// ── Validation ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_group_data_with_no_fields_errors() {
    let (mut alice, _bob, gid) = create_pair().await;
    let err = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid,
            name: None,
            description: None,
        })
        .await
        .err()
        .unwrap();
    assert!(matches!(err, EngineError::Other(_)));
}

// ── Multi-client convergence: B1 regression ─────────────────────────────────

/// Convergence-side application of a `update_group_data` commit must
/// refresh the recipient's Marmot record `name` and `description` to
/// match the post-merge MlsGroup state. Before this fix the convergence
/// path only refreshed `epoch` and `members`, leaving the Marmot record's
/// human-readable fields stale.
#[tokio::test]
async fn convergence_refreshes_recipient_marmot_record_name_and_description() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "original-name".into(),
            description: "original-description".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (alice_pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        _ => unreachable!(),
    };
    alice.confirm_published(alice_pending).await.unwrap();
    let welcome = welcomes.into_iter().next().unwrap();
    bob.join_welcome(welcome).await.unwrap();

    // Bob's record reflects the create-time name.
    let bob_group = bob_storage.get_group(&gid).unwrap();
    assert_eq!(bob_group.name, "original-name");
    assert_eq!(bob_group.description, "original-description");

    // Alice renames the group.
    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("new-renamed".into()),
            description: Some("new-described".into()),
        })
        .await
        .unwrap();
    let (commit, alice_pending) = match res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        _ => unreachable!(),
    };
    alice.confirm_published(alice_pending).await.unwrap();

    // Bob ingests via convergence — NOT via `confirm_published`.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..commit
    };
    bob.ingest(routed).await.unwrap();
    converge_buffered_commit(&mut bob, &gid);

    // Bob's epoch advanced (this already worked).
    assert_eq!(bob.epoch(&gid).unwrap().0, 2);

    // Bob's Marmot record reflects the new name + description.
    // Pre-fix: this was still "original-name" / "original-description".
    let bob_group = bob_storage.get_group(&gid).unwrap();
    assert_eq!(
        bob_group.name, "new-renamed",
        "convergence MUST refresh recipient name"
    );
    assert_eq!(
        bob_group.description, "new-described",
        "convergence MUST refresh recipient description"
    );
}

#[tokio::test]
async fn convergence_emits_unattributed_profile_change_events() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, _bob_storage) = build_with_storage(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "original-name".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (alice_pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        _ => unreachable!(),
    };
    alice.confirm_published(alice_pending).await.unwrap();
    bob.join_welcome(welcomes.into_iter().next().unwrap())
        .await
        .unwrap();

    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("new-renamed".into()),
            description: None,
        })
        .await
        .unwrap();
    let (commit, alice_pending) = match res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        _ => unreachable!(),
    };
    alice.confirm_published(alice_pending).await.unwrap();

    // Bob applies the rename via the convergence path, not the direct seam.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..commit
    };
    bob.ingest(routed).await.unwrap();
    bob.drain_events();
    converge_buffered_commit(&mut bob, &gid);

    // The reorg seam must surface the same profile diff the direct seam
    // emits, unattributed — otherwise the rename never becomes a kind-1210
    // row for members that applied the commit through convergence.
    let events = bob.drain_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                actor: None,
                change: cgka_traits::engine::GroupStateChange::GroupRenamed {
                    name,
                    previous_name: Some(previous_name),
                },
                ..
            } if name == "new-renamed" && previous_name == "original-name"
        )),
        "convergence apply must emit an unattributed GroupRenamed, got: {events:?}",
    );
}

#[tokio::test]
async fn convergence_emits_attributed_message_retention_change_events() {
    let (mut alice, mut bob, gid) = create_pair().await;
    let alice_id = alice.self_id();

    let res = alice
        .send(SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![AppComponentData {
                component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
                data: 60u64.to_be_bytes().to_vec(),
            }],
        })
        .await
        .unwrap();
    let (commit, pending) = match res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..commit
    };
    bob.ingest(routed).await.unwrap();
    bob.drain_events();
    converge_buffered_commit(&mut bob, &gid);

    let events = bob.drain_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                actor: Some(actor),
                change: cgka_traits::engine::GroupStateChange::MessageRetentionChanged {
                    old_seconds: 0,
                    new_seconds: 60,
                },
                ..
            } if actor == &alice_id
        )),
        "convergence apply must emit an attributed MessageRetentionChanged for alice, got: {events:?}",
    );
}

// ── State guard ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_group_data_during_pending_publish_is_rejected() {
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");
    let mut carol = build(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, create) = alice
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
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    // Start an invite (PendingPublish).
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let _invite = alice
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();

    // Now try update — must reject.
    let err = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid,
            name: Some("x".into()),
            description: None,
        })
        .await
        .err()
        .unwrap();
    assert!(matches!(err, EngineError::InvalidTransition(_)));
}

// ── #105 group avatar-url component ──────────────────────────────────────────

#[tokio::test]
async fn valid_group_avatar_url_component_is_accepted_and_stored() {
    let (mut alice, _bob, gid) = create_pair().await;
    let data = encode_group_avatar_url_v1(&GroupAvatarUrlV1 {
        url: "https://cdn.example.com/avatar.png".to_owned(),
        dim: Some("512x512".to_owned()),
        thumbhash: None,
    })
    .unwrap();

    let res = alice
        .send(SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![AppComponentData {
                component_id: GROUP_AVATAR_URL_COMPONENT_ID,
                data: data.clone(),
            }],
        })
        .await
        .unwrap();
    let pending = match res {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
    let stored = alice
        .app_component(&gid, GROUP_AVATAR_URL_COMPONENT_ID)
        .unwrap()
        .expect("avatar-url component is stored");
    assert_eq!(stored, data);
}

#[tokio::test]
async fn invalid_group_avatar_url_component_is_rejected() {
    let (mut alice, _bob, gid) = create_pair().await;
    // http:// (not https) is rejected by the component validator.
    let mut bad = Vec::new();
    cgka_traits::app_components::encode_quic_varint(
        "http://cdn.example.com/a.png".len() as u64,
        &mut bad,
    );
    bad.extend_from_slice(b"http://cdn.example.com/a.png");
    cgka_traits::app_components::encode_quic_varint(0, &mut bad); // empty dim
    cgka_traits::app_components::encode_quic_varint(0, &mut bad); // empty thumbhash

    let err = alice
        .send(SendIntent::UpdateAppComponents {
            group_id: gid,
            updates: vec![AppComponentData {
                component_id: GROUP_AVATAR_URL_COMPONENT_ID,
                data: bad,
            }],
        })
        .await
        .err()
        .unwrap();

    assert!(matches!(err, EngineError::Serialize(_)), "got {err:?}");
}
