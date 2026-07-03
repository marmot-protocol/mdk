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

/// Production-shaped peeler: a pass-through for MLS bytes like [`MockPeeler`],
/// but every wrap mints a FRESH transport id — as the Nostr adapter does,
/// where the outer kind-445 event id depends on the ephemeral key and nonce —
/// so a wrap-time transport id NEVER equals the content dedup id
/// (`SHA-256(mls_bytes)`). `MockPeeler` hides that split (`hash_id(payload)`
/// on both sides), so tests built on it cannot catch a cross-id attribution
/// bug between `confirm_published`-stamped rows and rollback events.
struct EphemeralIdPeeler(std::sync::atomic::AtomicU64);

impl EphemeralIdPeeler {
    fn new() -> Self {
        Self(std::sync::atomic::AtomicU64::new(0))
    }

    fn fresh_id(&self, payload: &[u8]) -> MessageId {
        let seq = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut hasher = Sha256::new();
        hasher.update(b"ephemeral-transport-id/v1");
        hasher.update(seq.to_be_bytes());
        hasher.update(payload);
        MessageId::new(hasher.finalize().to_vec())
    }
}

#[async_trait]
impl TransportPeeler for EphemeralIdPeeler {
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
            id: self.fresh_id(&payload.ciphertext),
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
            id: self.fresh_id(&payload.ciphertext),
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

fn mock_peeler() -> Box<dyn TransportPeeler> {
    Box::new(MockPeeler)
}

fn ephemeral_peeler() -> Box<dyn TransportPeeler> {
    Box::new(EphemeralIdPeeler::new())
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

/// Build an engine over an EXISTING storage handle (an engine "restart": the
/// durable state survives, all in-memory engine state — `committed_from`,
/// fork-recovery incumbents, seen/sent sets — is rebuilt from storage).
fn build_with_storage_and_peeler(
    id: &[u8],
    storage: SqliteAccountStorage,
    peeler: Box<dyn TransportPeeler>,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(registry())
        .peeler(peeler)
        .build()
        .unwrap()
}

/// Like [`create_pair`] but with storage handles and BOTH members as group
/// admins, so either side can publish an admin-gated `UpdateGroupData` /
/// `UpdateAppComponents` commit (the concurrent-committer fork scenarios).
async fn create_admin_pair_with_storage() -> (
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    GroupId,
) {
    create_admin_pair_with_peeler(mock_peeler).await
}

/// [`create_admin_pair_with_storage`] with an explicit peeler per engine, so
/// scenarios can run against production-shaped ids ([`EphemeralIdPeeler`]).
async fn create_admin_pair_with_peeler(
    make_peeler: fn() -> Box<dyn TransportPeeler>,
) -> (
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    GroupId,
) {
    let alice_storage = SqliteAccountStorage::in_memory().unwrap();
    let bob_storage = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = build_with_storage_and_peeler(b"alice", alice_storage.clone(), make_peeler());
    let mut bob = build_with_storage_and_peeler(b"bob", bob_storage.clone(), make_peeler());
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "original".into(),
            description: "orig description".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
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
    (alice, alice_storage, bob, bob_storage, gid)
}

fn route_to_group(msg: &TransportMessage, gid: &GroupId) -> TransportMessage {
    TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..msg.clone()
    }
}

/// The `(change, origin_commit_id)` of every `GroupStateChanged` in `events`.
/// Asserts each commit-derived notification carries an attribution — without
/// it the notification could never be withdrawn by origin commit.
fn attributed_state_changes(
    events: &[cgka_traits::engine::GroupEvent],
) -> Vec<(cgka_traits::engine::GroupStateChange, MessageId)> {
    events
        .iter()
        .filter_map(|event| match event {
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                change,
                origin_commit_id,
                ..
            } => Some((
                change.clone(),
                origin_commit_id
                    .clone()
                    .expect("commit-derived GroupStateChanged must carry origin_commit_id"),
            )),
            _ => None,
        })
        .collect()
}

/// Every `(invalidated_commit_id, epoch)` named by a `GroupStateInvalidated`
/// withdrawal in `events`.
fn state_invalidations(
    events: &[cgka_traits::engine::GroupEvent],
) -> Vec<(MessageId, cgka_traits::EpochId)> {
    events
        .iter()
        .filter_map(|event| match event {
            cgka_traits::engine::GroupEvent::GroupStateInvalidated {
                invalidated_commit_id,
                epoch,
                reason:
                    cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection,
                ..
            } => Some((invalidated_commit_id.clone(), *epoch)),
            _ => None,
        })
        .collect()
}

/// The state notifications still in effect after applying every withdrawal in
/// `invalidations` to the accumulated `notifications` — the spec's "resulting
/// view" (convergence.md "Applying the selected branch"): once convergence is
/// settled this must equal exactly the notifications derivable from accepted
/// commits on the selected branch.
fn surviving_state_changes(
    notifications: &[(cgka_traits::engine::GroupStateChange, MessageId)],
    invalidations: &[(MessageId, cgka_traits::EpochId)],
) -> Vec<(cgka_traits::engine::GroupStateChange, MessageId)> {
    notifications
        .iter()
        .filter(|(_, origin)| {
            !invalidations
                .iter()
                .any(|(invalidated, _)| invalidated == origin)
        })
        .cloned()
        .collect()
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

// ── Concurrent-rename supersession (issue #363) ─────────────────────────────

/// Issue #363 regression: two admins rename concurrently; branch selection
/// picks one commit. The losing committer previously kept its own
/// `GroupStateChanged { GroupRenamed }` as a completed change ("B renamed the
/// group to X" with no retraction) while the canonical name held the winner's
/// value. Per spec (marmot-protocol/marmot#171, convergence.md "Applying the
/// selected branch") the engine MUST withdraw every state notification
/// attributed to the superseded commit via an explicit
/// `GroupStateInvalidated` naming that commit — including the client's own
/// published-and-confirmed commit.
#[tokio::test]
async fn concurrent_rename_withdraws_losing_committers_state_notification() {
    let (alice, alice_storage, bob, bob_storage, gid) = create_admin_pair_with_storage().await;
    assert_concurrent_rename_withdrawal(alice, alice_storage, bob, bob_storage, gid, false).await;
}

/// Same scenario with PRODUCTION-shaped ids: every wrap mints a fresh
/// transport id (`EphemeralIdPeeler`), so the wrap-time transport id the
/// committer's own rows are stamped with is DISTINCT from the content dedup
/// id inbound processing rebinds to — exactly the split the Nostr adapter
/// produces. The withdrawal must still name the id the rows were stamped
/// with, or the tombstone is a silent no-op.
#[tokio::test]
async fn concurrent_rename_withdrawal_survives_distinct_transport_and_content_ids() {
    let (alice, alice_storage, bob, bob_storage, gid) =
        create_admin_pair_with_peeler(ephemeral_peeler).await;
    assert_concurrent_rename_withdrawal(alice, alice_storage, bob, bob_storage, gid, true).await;
}

async fn assert_concurrent_rename_withdrawal(
    mut alice: Engine<SqliteAccountStorage>,
    alice_storage: SqliteAccountStorage,
    mut bob: Engine<SqliteAccountStorage>,
    bob_storage: SqliteAccountStorage,
    gid: GroupId,
    expect_distinct_transport_ids: bool,
) {
    use cgka_traits::engine::{GroupStateChange, GroupStateInvalidationReason};
    use cgka_traits::ingest::{IngestOutcome, StaleReason};

    alice.drain_events();
    bob.drain_events();

    // Same epoch window: neither has seen the other's commit yet.
    let alice_res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("New name from A".into()),
            description: None,
        })
        .await
        .unwrap();
    let bob_res = bob
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("New name from B".into()),
            description: None,
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = match alice_res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let (bob_commit, bob_pending) = match bob_res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(alice_pending).await.unwrap();
    bob.confirm_published(bob_pending).await.unwrap();

    // Each committer's own confirmed rename surfaced as an ATTRIBUTED state
    // notification — the attribution is what makes withdrawal targetable.
    let alice_own = attributed_state_changes(&alice.drain_events());
    let bob_own = attributed_state_changes(&bob.drain_events());
    let (alice_origin, bob_origin) = match (alice_own.as_slice(), bob_own.as_slice()) {
        (
            [(GroupStateChange::GroupRenamed { name: a_name, .. }, a_origin)],
            [(GroupStateChange::GroupRenamed { name: b_name, .. }, b_origin)],
        ) => {
            assert_eq!(a_name, "New name from A");
            assert_eq!(b_name, "New name from B");
            (a_origin.clone(), b_origin.clone())
        }
        other => panic!("expected exactly one attributed rename per committer, got {other:?}"),
    };
    if expect_distinct_transport_ids {
        // Prove the production id split is actually exercised: the stamped
        // attribution (wrap-time transport id) differs from the content dedup
        // id inbound peers rebind the same commit to.
        assert_ne!(
            alice_origin,
            content_id(&alice_commit),
            "ephemeral peeler must split transport id from content id"
        );
        assert_ne!(
            bob_origin,
            content_id(&bob_commit),
            "ephemeral peeler must split transport id from content id"
        );
    }

    // Deliver both commits to both members.
    let alice_outcome = alice
        .ingest(route_to_group(&bob_commit, &gid))
        .await
        .unwrap();
    let bob_outcome = bob
        .ingest(route_to_group(&alice_commit, &gid))
        .await
        .unwrap();
    let alice_after = alice.drain_events();
    let bob_after = bob.drain_events();

    // Convergence settles to one canonical name on both devices.
    let canonical_name = alice_storage.get_group(&gid).unwrap().name;
    assert_eq!(
        canonical_name,
        bob_storage.get_group(&gid).unwrap().name,
        "both devices must converge to the same canonical name"
    );
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
    assert_eq!(bob.epoch(&gid).unwrap().0, 2);

    // Exactly one committer lost. Identify it from the canonical name so the
    // test does not depend on which authenticated ordering key sorts first.
    // On the losing device the winner's inbound commit is keyed by its
    // content-derived id, so the surviving notification's attribution is
    // `content_id(winning commit)` there (attribution only has to be
    // deterministic per device across the emit and withdraw paths).
    let (loser_after, loser_origin, loser_own, loser_outcome, winner_after, winner_outcome) =
        if canonical_name == "New name from A" {
            (
                bob_after,
                bob_origin,
                bob_own,
                bob_outcome,
                alice_after,
                alice_outcome,
            )
        } else {
            assert_eq!(canonical_name, "New name from B");
            (
                alice_after,
                alice_origin,
                alice_own,
                alice_outcome,
                bob_after,
                bob_outcome,
            )
        };
    let winner_commit_id_on_loser = if canonical_name == "New name from A" {
        content_id(&alice_commit)
    } else {
        content_id(&bob_commit)
    };

    // The losing committer applied the winner's commit over its own.
    assert!(
        !matches!(loser_outcome, IngestOutcome::Stale { .. }),
        "loser must apply the winning commit, got {loser_outcome:?}"
    );
    // The winner classifies the losing commit as stale — no rollback, no
    // withdrawal of its own (canonical) rename.
    assert!(
        matches!(
            winner_outcome,
            IngestOutcome::Stale {
                reason: StaleReason::AlreadyAtEpoch { .. }
            }
        ),
        "winner must not roll back to the losing commit, got {winner_outcome:?}"
    );
    assert!(
        state_invalidations(&winner_after).is_empty(),
        "winner must not withdraw any state notification, got {winner_after:?}"
    );

    // The losing committer MUST emit the explicit invalidation naming its own
    // superseded commit, in the same identifier space as the notification's
    // origin_commit_id (spec: "the client MUST emit a group-state-change
    // invalidation naming the superseded commit").
    let loser_invalidations = state_invalidations(&loser_after);
    assert_eq!(
        loser_invalidations.len(),
        1,
        "expected exactly one withdrawal on the losing committer, got {loser_after:?}"
    );
    assert_eq!(
        loser_invalidations[0].0, loser_origin,
        "withdrawal must name the superseded commit that produced the rename"
    );
    assert_eq!(
        loser_invalidations[0].1,
        cgka_traits::EpochId(1),
        "withdrawal carries the fork's source epoch"
    );
    assert!(
        loser_after.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupStateInvalidated {
                group_id: g,
                reason: GroupStateInvalidationReason::SupersededByBranchSelection,
                ..
            } if g == &gid
        )),
        "withdrawal must carry the losing-branch reason, got {loser_after:?}"
    );

    // Resulting view (the conformance requirement): the notifications still in
    // effect on the losing device are exactly those derivable from accepted
    // commits on the selected branch — one rename, the winner's, attributed to
    // the winner's commit. The loser's own rename is withdrawn.
    let mut loser_notifications = loser_own;
    loser_notifications.extend(attributed_state_changes(&loser_after));
    let surviving = surviving_state_changes(&loser_notifications, &loser_invalidations);
    match surviving.as_slice() {
        [(GroupStateChange::GroupRenamed { name, .. }, origin)] => {
            assert_eq!(
                name, &canonical_name,
                "surviving rename must match canonical state"
            );
            assert_eq!(
                origin, &winner_commit_id_on_loser,
                "surviving rename must be attributed to the winning commit"
            );
        }
        other => panic!(
            "resulting view must hold exactly the winner's rename, got {other:?} \
             (invalidations {loser_invalidations:?})"
        ),
    }
}

/// Stored-convergence variant of the issue #363 scenario, with
/// PRODUCTION-shaped ids: the losing committer's own published-and-confirmed
/// rename is superseded by a rewind/replay reorg, not the direct
/// staged-commit seam. The loser restarts after confirming (an engine rebuild
/// drops the in-memory `committed_from` set, so the sibling commit routes
/// into stored convergence — there is no direct-seam `ForkRecovered` on this
/// path), then converges over the winner's commit.
///
/// The correctness core: the withdrawal on the losing device must name the
/// SAME id its confirm-time rows were stamped with (the wrap-time transport
/// id of its own commit — preserved by the stored wire record), even though
/// every inbound commit is keyed by the content dedup id.
#[tokio::test]
async fn rebuilt_engine_convergence_withdraws_own_confirmed_rename_by_stamped_origin() {
    use cgka_traits::engine::{CommitOrderingKey, CommitOrderingPriority, GroupStateChange};
    use cgka_traits::ingest::{IngestOutcome, StaleReason};

    let (mut alice, alice_storage, mut bob, bob_storage, gid) =
        create_admin_pair_with_peeler(ephemeral_peeler).await;
    alice.drain_events();
    bob.drain_events();

    // Concurrent renames in the same epoch window; both confirmed locally.
    let alice_res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("New name from A".into()),
            description: None,
        })
        .await
        .unwrap();
    let bob_res = bob
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("New name from B".into()),
            description: None,
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = match alice_res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let (bob_commit, bob_pending) = match bob_res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(alice_pending).await.unwrap();
    bob.confirm_published(bob_pending).await.unwrap();

    let alice_own = attributed_state_changes(&alice.drain_events());
    let bob_own = attributed_state_changes(&bob.drain_events());
    let (alice_origin, bob_origin) = match (alice_own.as_slice(), bob_own.as_slice()) {
        (
            [(GroupStateChange::GroupRenamed { .. }, a_origin)],
            [(GroupStateChange::GroupRenamed { .. }, b_origin)],
        ) => (a_origin.clone(), b_origin.clone()),
        other => panic!("expected exactly one attributed rename per committer, got {other:?}"),
    };
    // Production id split in effect on both committers.
    assert_ne!(alice_origin, content_id(&alice_commit));
    assert_ne!(bob_origin, content_id(&bob_commit));

    // Determine the deterministic branch-selection loser up front. Both
    // UpdateGroupData commits are admin-gated (Privileged), so the
    // authenticated ordering key decides: committer id, then digest.
    let alice_key = CommitOrderingKey::from_commit_bytes(
        cgka_traits::EpochId(1),
        CommitOrderingPriority::Privileged,
        alice.self_id(),
        &alice_commit.payload,
    );
    let bob_key = CommitOrderingKey::from_commit_bytes(
        cgka_traits::EpochId(1),
        CommitOrderingPriority::Privileged,
        bob.self_id(),
        &bob_commit.payload,
    );
    assert_ne!(alice_key, bob_key);
    let alice_wins = alice_key < bob_key;
    #[allow(clippy::type_complexity)]
    let (
        mut winner,
        winner_commit,
        winner_name,
        winner_storage,
        loser_engine,
        loser_storage,
        loser_commit,
        loser_origin,
        loser_own,
        loser_id,
    ): (
        Engine<SqliteAccountStorage>,
        TransportMessage,
        &str,
        SqliteAccountStorage,
        Engine<SqliteAccountStorage>,
        SqliteAccountStorage,
        TransportMessage,
        MessageId,
        Vec<(GroupStateChange, MessageId)>,
        &[u8],
    ) = if alice_wins {
        (
            alice,
            alice_commit,
            "New name from A",
            alice_storage,
            bob,
            bob_storage,
            bob_commit,
            bob_origin,
            bob_own,
            b"bob",
        )
    } else {
        (
            bob,
            bob_commit,
            "New name from B",
            bob_storage,
            alice,
            alice_storage,
            alice_commit,
            alice_origin,
            alice_own,
            b"alice",
        )
    };

    // The winner never restarts: it classifies the losing commit as stale on
    // the direct seam (its own confirmed commit stays the incumbent) and
    // withdraws nothing.
    let winner_outcome = winner
        .ingest(route_to_group(&loser_commit, &gid))
        .await
        .unwrap();
    assert!(
        matches!(
            winner_outcome,
            IngestOutcome::Stale {
                reason: StaleReason::AlreadyAtEpoch { .. }
            }
        ),
        "winner must keep its incumbent commit, got {winner_outcome:?}"
    );
    assert!(state_invalidations(&winner.drain_events()).is_empty());

    // The LOSER restarts. Durable state survives; the in-memory
    // `committed_from` set does not, so the winner's sibling commit is
    // buffered for stored convergence instead of hitting the direct
    // fork-recovery seam — the reorg path issue #363's own-commit withdrawal
    // must also cover.
    drop(loser_engine);
    let mut loser =
        build_with_storage_and_peeler(loser_id, loser_storage.clone(), ephemeral_peeler());
    loser.drain_events();
    loser
        .buffer_openmls_convergence_message(&gid, route_to_group(&winner_commit, &gid), 1_000)
        .expect("winning sibling commit buffered on the restarted loser");
    let result = loser
        .converge_stored_openmls_messages(&gid, 1_000_000)
        .expect("loser converges over the fork");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    let loser_after = loser.drain_events();

    // Both devices settle on the winner's canonical name.
    assert_eq!(loser_storage.get_group(&gid).unwrap().name, winner_name);
    assert_eq!(winner_storage.get_group(&gid).unwrap().name, winner_name);

    // This is the convergence path: no ForkRecovered fires.
    assert!(
        !loser_after
            .iter()
            .any(|event| matches!(event, cgka_traits::engine::GroupEvent::ForkRecovered { .. })),
        "stored convergence must not emit ForkRecovered, got {loser_after:?}"
    );

    // The correctness core: the withdrawal names the stamped origin of the
    // loser's OWN confirmed commit (its wrap-time transport id, preserved by
    // the stored wire record) — not the content dedup id — so the
    // confirm-time rows are actually tombstoned despite the id split.
    let loser_invalidations = state_invalidations(&loser_after);
    assert!(
        loser_invalidations
            .iter()
            .any(|(id, epoch)| id == &loser_origin && *epoch == cgka_traits::EpochId(1)),
        "loser must withdraw its own confirmed commit by its stamped origin id, \
         got {loser_invalidations:?} (stamped {loser_origin:?})"
    );
    assert!(
        !loser_invalidations
            .iter()
            .any(|(id, _)| id == &content_id(&winner_commit)),
        "loser must not withdraw the winning commit's notifications"
    );

    // Resulting view on the losing device: exactly the winner's rename,
    // attributed to the id the winner's commit carries on THIS device (its
    // content dedup id).
    let mut loser_notifications = loser_own;
    loser_notifications.extend(attributed_state_changes(&loser_after));
    let surviving = surviving_state_changes(&loser_notifications, &loser_invalidations);
    match surviving.as_slice() {
        [(GroupStateChange::GroupRenamed { name, .. }, origin)] => {
            assert_eq!(name, winner_name);
            assert_eq!(origin, &content_id(&winner_commit));
        }
        other => panic!(
            "resulting view must hold exactly the winner's rename, got {other:?} \
             (invalidations {loser_invalidations:?})"
        ),
    }
}

/// Restart-WINNER variant of the stored-convergence fork: the committer whose
/// authenticated ordering key WINS branch selection restarts, so the losing
/// sibling commit routes into stored convergence instead of the direct seam.
///
/// The own published-and-confirmed commit cannot be replayed through
/// `process_message` (MLS refuses own commits), so before the confirm-time
/// convergence stamp + retained-anchor rollforward existed, the winner's own
/// branch never materialized as a candidate: the losing sibling was the ONLY
/// candidate, branch selection picked it, and the restarted device was
/// reorged OFF the canonical branch its ordering key had won — withdrawing
/// its own rename and diverging from every peer that resolved the same fork
/// correctly on the direct seam.
#[tokio::test]
async fn rebuilt_engine_convergence_keeps_own_confirmed_rename_when_it_wins_selection() {
    use cgka_traits::engine::{CommitOrderingKey, CommitOrderingPriority, GroupStateChange};
    use cgka_traits::ingest::IngestOutcome;

    let (mut alice, alice_storage, mut bob, bob_storage, gid) =
        create_admin_pair_with_peeler(ephemeral_peeler).await;
    alice.drain_events();
    bob.drain_events();

    // Concurrent renames in the same epoch window; both confirmed locally.
    let alice_res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("New name from A".into()),
            description: None,
        })
        .await
        .unwrap();
    let bob_res = bob
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("New name from B".into()),
            description: None,
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = match alice_res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let (bob_commit, bob_pending) = match bob_res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(alice_pending).await.unwrap();
    bob.confirm_published(bob_pending).await.unwrap();
    let alice_own = attributed_state_changes(&alice.drain_events());
    let bob_own = attributed_state_changes(&bob.drain_events());

    // Deterministic branch-selection winner (both commits are admin-gated,
    // so Privileged; the authenticated committer id then decides).
    let alice_key = CommitOrderingKey::from_commit_bytes(
        cgka_traits::EpochId(1),
        CommitOrderingPriority::Privileged,
        alice.self_id(),
        &alice_commit.payload,
    );
    let bob_key = CommitOrderingKey::from_commit_bytes(
        cgka_traits::EpochId(1),
        CommitOrderingPriority::Privileged,
        bob.self_id(),
        &bob_commit.payload,
    );
    let alice_wins = alice_key < bob_key;
    #[allow(clippy::type_complexity)]
    let (
        winner,
        winner_storage,
        winner_commit,
        winner_name,
        winner_own,
        winner_id,
        mut loser,
        loser_storage,
        loser_commit,
    ): (
        Engine<SqliteAccountStorage>,
        SqliteAccountStorage,
        TransportMessage,
        &str,
        Vec<(GroupStateChange, MessageId)>,
        &[u8],
        Engine<SqliteAccountStorage>,
        SqliteAccountStorage,
        TransportMessage,
    ) = if alice_wins {
        (
            alice,
            alice_storage,
            alice_commit,
            "New name from A",
            alice_own,
            b"alice",
            bob,
            bob_storage,
            bob_commit,
        )
    } else {
        (
            bob,
            bob_storage,
            bob_commit,
            "New name from B",
            bob_own,
            b"bob",
            alice,
            alice_storage,
            alice_commit,
        )
    };
    let winner_origin = match winner_own.as_slice() {
        [(GroupStateChange::GroupRenamed { .. }, origin)] => origin.clone(),
        other => panic!("expected exactly one attributed rename on the winner, got {other:?}"),
    };

    // The WINNER restarts: durable state survives, the in-memory
    // `committed_from` guard does not, so the losing sibling commit routes
    // into stored convergence. Its own confirmed commit must still compete
    // there — realized from the confirm-time stamp + retained anchor — and
    // win by the same authenticated ordering key the direct seam would use.
    drop(winner);
    let mut winner =
        build_with_storage_and_peeler(winner_id, winner_storage.clone(), ephemeral_peeler());
    winner.drain_events();
    winner
        .buffer_openmls_convergence_message(&gid, route_to_group(&loser_commit, &gid), 1_000)
        .expect("losing sibling commit buffered on the restarted winner");
    let result = winner
        .converge_stored_openmls_messages(&gid, 1_000_000)
        .expect("winner converges over the fork");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    let winner_after = winner.drain_events();

    // The winner's own branch was selected: canonical name and epoch are
    // unchanged, and the losing sibling was dropped against the candidate
    // state rather than applied.
    assert_eq!(
        winner_storage.get_group(&gid).unwrap().name,
        winner_name,
        "restarted winner must keep its own canonical rename, not be reorged \
         onto the losing sibling"
    );
    assert_eq!(winner.epoch(&gid).unwrap().0, 2);
    assert!(
        result.dropped_messages.iter().any(|dropped| {
            dropped.message_id == hex::encode(content_id(&loser_commit).as_slice())
                && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
        }),
        "losing sibling must be dropped against the selected candidate state, \
         got {:?}",
        result.dropped_messages
    );

    // No withdrawal may name the winner's own confirmed commit: its rename is
    // canonical. (A withdrawal naming the never-applied sibling is fine —
    // the app-side tombstone is a no-op there.)
    let winner_invalidations = state_invalidations(&winner_after);
    assert!(
        !winner_invalidations
            .iter()
            .any(|(id, _)| id == &winner_origin),
        "winner must not withdraw its own canonical rename, got {winner_invalidations:?} \
         (own origin {winner_origin:?})"
    );

    // Resulting view on the winner: exactly its own rename, still attributed
    // to the confirm-time stamped origin.
    let mut winner_notifications = winner_own;
    winner_notifications.extend(attributed_state_changes(&winner_after));
    let surviving = surviving_state_changes(&winner_notifications, &winner_invalidations);
    match surviving.as_slice() {
        [(GroupStateChange::GroupRenamed { name, .. }, origin)] => {
            assert_eq!(name, winner_name);
            assert_eq!(origin, &winner_origin);
        }
        other => panic!(
            "resulting view must hold exactly the winner's own rename, got {other:?} \
             (invalidations {winner_invalidations:?})"
        ),
    }

    // The never-restarted loser resolves the same fork on the direct seam and
    // lands on the same canonical branch — no group-level fork.
    let loser_outcome = loser
        .ingest(route_to_group(&winner_commit, &gid))
        .await
        .unwrap();
    assert!(
        !matches!(loser_outcome, IngestOutcome::Stale { .. }),
        "loser must apply the winning commit, got {loser_outcome:?}"
    );
    assert_eq!(loser_storage.get_group(&gid).unwrap().name, winner_name);
    assert_eq!(
        winner_storage.get_group(&gid).unwrap().name,
        loser_storage.get_group(&gid).unwrap().name,
        "both devices must converge to the same canonical branch"
    );
}

/// Mutual-restart variant: BOTH concurrent committers restart before seeing
/// each other's commit, so BOTH resolve the same-epoch fork through stored
/// convergence with no in-memory state at all.
///
/// Before own confirmed commits could compete in branch selection, each
/// device saw exactly one materializable candidate — the OTHER device's
/// branch — so each deterministically reorged onto the other's commit and the
/// group forked permanently (A ends on B's rename, B on A's). With the
/// confirm-time stamp both devices score the same two candidates, pick the
/// same winner by the authenticated ordering key, and converge.
#[tokio::test]
async fn mutually_rebuilt_engines_converge_on_same_branch_after_concurrent_renames() {
    use cgka_traits::engine::{CommitOrderingKey, CommitOrderingPriority, GroupStateChange};

    let (mut alice, alice_storage, mut bob, bob_storage, gid) =
        create_admin_pair_with_peeler(ephemeral_peeler).await;
    alice.drain_events();
    bob.drain_events();

    // Concurrent renames in the same epoch window; both confirmed locally.
    let alice_res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("New name from A".into()),
            description: None,
        })
        .await
        .unwrap();
    let bob_res = bob
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("New name from B".into()),
            description: None,
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = match alice_res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let (bob_commit, bob_pending) = match bob_res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(alice_pending).await.unwrap();
    bob.confirm_published(bob_pending).await.unwrap();
    let alice_own = attributed_state_changes(&alice.drain_events());
    let bob_own = attributed_state_changes(&bob.drain_events());
    let (alice_origin, bob_origin) = match (alice_own.as_slice(), bob_own.as_slice()) {
        (
            [(GroupStateChange::GroupRenamed { .. }, a_origin)],
            [(GroupStateChange::GroupRenamed { .. }, b_origin)],
        ) => (a_origin.clone(), b_origin.clone()),
        other => panic!("expected exactly one attributed rename per committer, got {other:?}"),
    };

    let alice_key = CommitOrderingKey::from_commit_bytes(
        cgka_traits::EpochId(1),
        CommitOrderingPriority::Privileged,
        alice.self_id(),
        &alice_commit.payload,
    );
    let bob_key = CommitOrderingKey::from_commit_bytes(
        cgka_traits::EpochId(1),
        CommitOrderingPriority::Privileged,
        bob.self_id(),
        &bob_commit.payload,
    );
    let alice_wins = alice_key < bob_key;
    let winner_name = if alice_wins {
        "New name from A"
    } else {
        "New name from B"
    };

    // BOTH committers restart, then each learns of the other's commit only
    // through stored convergence.
    drop(alice);
    drop(bob);
    let mut alice =
        build_with_storage_and_peeler(b"alice", alice_storage.clone(), ephemeral_peeler());
    let mut bob = build_with_storage_and_peeler(b"bob", bob_storage.clone(), ephemeral_peeler());
    alice.drain_events();
    bob.drain_events();
    alice
        .buffer_openmls_convergence_message(&gid, route_to_group(&bob_commit, &gid), 1_000)
        .expect("bob's sibling commit buffered on restarted alice");
    bob.buffer_openmls_convergence_message(&gid, route_to_group(&alice_commit, &gid), 1_000)
        .expect("alice's sibling commit buffered on restarted bob");
    let alice_result = alice
        .converge_stored_openmls_messages(&gid, 1_000_000)
        .expect("alice converges over the fork");
    let bob_result = bob
        .converge_stored_openmls_messages(&gid, 1_000_000)
        .expect("bob converges over the fork");
    assert_eq!(alice_result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(bob_result.convergence_status, ConvergenceStatus::Settled);
    let alice_after = alice.drain_events();
    let bob_after = bob.drain_events();

    // The permanent-fork regression core: both devices settle on the SAME
    // canonical branch — the deterministic ordering-key winner — instead of
    // each selecting the other's branch.
    assert_eq!(
        alice_storage.get_group(&gid).unwrap().name,
        bob_storage.get_group(&gid).unwrap().name,
        "mutually restarted committers must converge on one canonical branch, \
         not swap onto each other's"
    );
    assert_eq!(alice_storage.get_group(&gid).unwrap().name, winner_name);
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
    assert_eq!(bob.epoch(&gid).unwrap().0, 2);

    // Exactly the losing committer withdraws its own confirmed rename, by the
    // id its confirm-time rows were stamped with.
    let (
        loser_after,
        loser_origin,
        loser_own_notifications,
        winner_after,
        winner_origin,
        winner_own_notifications,
    ) = if alice_wins {
        (
            bob_after,
            bob_origin,
            bob_own,
            alice_after,
            alice_origin,
            alice_own,
        )
    } else {
        (
            alice_after,
            alice_origin,
            alice_own,
            bob_after,
            bob_origin,
            bob_own,
        )
    };
    let loser_invalidations = state_invalidations(&loser_after);
    assert!(
        loser_invalidations
            .iter()
            .any(|(id, epoch)| id == &loser_origin && *epoch == cgka_traits::EpochId(1)),
        "loser must withdraw its own confirmed commit by its stamped origin id, \
         got {loser_invalidations:?} (stamped {loser_origin:?})"
    );
    let winner_invalidations = state_invalidations(&winner_after);
    assert!(
        !winner_invalidations
            .iter()
            .any(|(id, _)| id == &winner_origin),
        "winner must not withdraw its own canonical rename, got {winner_invalidations:?} \
         (own origin {winner_origin:?})"
    );

    // Resulting views: the winner keeps exactly its own rename; the loser
    // ends with exactly the winner's rename (attributed to the winning
    // commit's content id on the losing device).
    let mut winner_notifications = winner_own_notifications;
    winner_notifications.extend(attributed_state_changes(&winner_after));
    let winner_surviving = surviving_state_changes(&winner_notifications, &winner_invalidations);
    match winner_surviving.as_slice() {
        [(GroupStateChange::GroupRenamed { name, .. }, origin)] => {
            assert_eq!(name, winner_name);
            assert_eq!(origin, &winner_origin);
        }
        other => panic!(
            "winner's resulting view must hold exactly its own rename, got {other:?} \
             (invalidations {winner_invalidations:?})"
        ),
    }
    let winning_commit_content_id = if alice_wins {
        content_id(&alice_commit)
    } else {
        content_id(&bob_commit)
    };
    let mut loser_notifications = loser_own_notifications;
    loser_notifications.extend(attributed_state_changes(&loser_after));
    let loser_surviving = surviving_state_changes(&loser_notifications, &loser_invalidations);
    match loser_surviving.as_slice() {
        [(GroupStateChange::GroupRenamed { name, .. }, origin)] => {
            assert_eq!(name, winner_name);
            assert_eq!(origin, &winning_commit_content_id);
        }
        other => panic!(
            "loser's resulting view must hold exactly the winner's rename, got {other:?} \
             (invalidations {loser_invalidations:?})"
        ),
    }
}

/// Sequential control: when the second rename builds on the first commit
/// (no fork), both notifications are accurate history — two
/// `GroupStateChanged` events, and no `GroupStateInvalidated` anywhere.
#[tokio::test]
async fn sequential_renames_emit_two_notifications_without_invalidation() {
    use cgka_traits::engine::GroupStateChange;

    let (mut alice, alice_storage, mut bob, bob_storage, gid) =
        create_admin_pair_with_storage().await;
    alice.drain_events();
    bob.drain_events();

    // A renames; the commit converges everywhere before B renames.
    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("first rename".into()),
            description: None,
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = match res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(alice_pending).await.unwrap();
    bob.ingest(route_to_group(&alice_commit, &gid))
        .await
        .unwrap();
    converge_buffered_commit(&mut bob, &gid);

    // Now B renames on top of A's accepted commit.
    let res = bob
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("second rename".into()),
            description: None,
        })
        .await
        .unwrap();
    let (bob_commit, bob_pending) = match res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    bob.confirm_published(bob_pending).await.unwrap();
    alice
        .ingest(route_to_group(&bob_commit, &gid))
        .await
        .unwrap();
    converge_buffered_commit(&mut alice, &gid);

    assert_eq!(alice_storage.get_group(&gid).unwrap().name, "second rename");
    assert_eq!(bob_storage.get_group(&gid).unwrap().name, "second rename");

    for (who, events) in [("alice", alice.drain_events()), ("bob", bob.drain_events())] {
        assert!(
            state_invalidations(&events).is_empty(),
            "{who}: sequential renames must not withdraw anything, got {events:?}"
        );
        let renames: Vec<&str> = events
            .iter()
            .filter_map(|event| match event {
                cgka_traits::engine::GroupEvent::GroupStateChanged {
                    change: GroupStateChange::GroupRenamed { name, .. },
                    ..
                } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            renames,
            vec!["first rename", "second rename"],
            "{who}: both sequential renames must remain in effect, in order"
        );
    }
}

/// Cross-contamination guard: a concurrent rename racing a DIFFERENT losing
/// change type (message-retention update) must only withdraw the
/// notifications attributed to the superseded commit; the winning commit's
/// notification survives untouched.
#[tokio::test]
async fn concurrent_rename_and_retention_change_withdraw_only_superseded_commit() {
    use cgka_traits::engine::GroupStateChange;
    use cgka_traits::ingest::IngestOutcome;

    let (mut alice, alice_storage, mut bob, bob_storage, gid) =
        create_admin_pair_with_storage().await;
    alice.drain_events();
    bob.drain_events();

    // Alice renames while Bob concurrently changes message retention.
    let alice_res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("renamed while racing".into()),
            description: None,
        })
        .await
        .unwrap();
    let bob_res = bob
        .send(SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![AppComponentData {
                component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
                data: 60u64.to_be_bytes().to_vec(),
            }],
        })
        .await
        .unwrap();
    let (alice_commit, alice_pending) = match alice_res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let (bob_commit, bob_pending) = match bob_res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(alice_pending).await.unwrap();
    bob.confirm_published(bob_pending).await.unwrap();

    let alice_own = attributed_state_changes(&alice.drain_events());
    let bob_own = attributed_state_changes(&bob.drain_events());
    let alice_origin = match alice_own.as_slice() {
        [(GroupStateChange::GroupRenamed { .. }, origin)] => origin.clone(),
        other => panic!("expected alice's attributed rename, got {other:?}"),
    };
    let bob_origin = match bob_own.as_slice() {
        [(GroupStateChange::MessageRetentionChanged { .. }, origin)] => origin.clone(),
        other => panic!("expected bob's attributed retention change, got {other:?}"),
    };

    let alice_outcome = alice
        .ingest(route_to_group(&bob_commit, &gid))
        .await
        .unwrap();
    let bob_outcome = bob
        .ingest(route_to_group(&alice_commit, &gid))
        .await
        .unwrap();
    let alice_after = alice.drain_events();
    let bob_after = bob.drain_events();

    // Identify the loser from canonical state: exactly one change took effect.
    let alice_group = alice_storage.get_group(&gid).unwrap();
    let bob_group = bob_storage.get_group(&gid).unwrap();
    assert_eq!(alice_group.name, bob_group.name);
    let rename_won = alice_group.name == "renamed while racing";

    let (loser_after, loser_origin, loser_own, winner_after, winner_commit_id_on_loser) =
        if rename_won {
            assert!(!matches!(bob_outcome, IngestOutcome::Stale { .. }));
            (
                bob_after,
                bob_origin,
                bob_own,
                alice_after,
                content_id(&alice_commit),
            )
        } else {
            assert!(!matches!(alice_outcome, IngestOutcome::Stale { .. }));
            (
                alice_after,
                alice_origin,
                alice_own,
                bob_after,
                content_id(&bob_commit),
            )
        };

    // Only the superseded commit's notification is withdrawn.
    let loser_invalidations = state_invalidations(&loser_after);
    assert_eq!(
        loser_invalidations.len(),
        1,
        "expected exactly one withdrawal on the losing committer, got {loser_after:?}"
    );
    assert_eq!(loser_invalidations[0].0, loser_origin);
    assert_ne!(
        loser_invalidations[0].0, winner_commit_id_on_loser,
        "the winning commit's notifications must not be withdrawn"
    );
    assert!(
        state_invalidations(&winner_after).is_empty(),
        "winner must not withdraw anything, got {winner_after:?}"
    );

    // Resulting view on the losing device: exactly the winner's change type,
    // attributed to the winner's commit.
    let mut loser_notifications = loser_own;
    loser_notifications.extend(attributed_state_changes(&loser_after));
    let surviving = surviving_state_changes(&loser_notifications, &loser_invalidations);
    assert_eq!(
        surviving.len(),
        1,
        "resulting view must hold exactly the winner's notification, got {surviving:?}"
    );
    let (surviving_change, surviving_origin) = &surviving[0];
    assert_eq!(surviving_origin, &winner_commit_id_on_loser);
    if rename_won {
        assert!(
            matches!(surviving_change, GroupStateChange::GroupRenamed { name, .. } if name == "renamed while racing")
        );
    } else {
        assert!(matches!(
            surviving_change,
            GroupStateChange::MessageRetentionChanged {
                old_seconds: 0,
                new_seconds: 60,
            }
        ));
    }
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
