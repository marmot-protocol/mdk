//! Invite and MIP-03 SelfRemove round trips.

use async_trait::async_trait;
use cgka_engine::canonicalization::ConvergenceStatus;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_engine::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
use cgka_traits::EngineError;
use cgka_traits::app_components::{
    AppComponentData, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID,
    NostrRoutingV1, encode_component_vectors, encode_nostr_routing_v1,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, KeyPackage, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage, StaleReason};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerStorage, GroupStorage, LeaveRequestStorage, OutboundIntentStorage,
    StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use openmls::component::ComponentData;
use openmls::group::MlsGroup;
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::{BasicCredential, MlsMessageBodyIn, MlsMessageIn, ProtocolVersion};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider as _;
use storage_sqlite::SqliteAccountStorage;
use tls_codec::{Deserialize as _, Serialize as _};

mod support;
use support::proof_signer;

async fn advance_selfremove_auto_commit<E: CgkaEngine>(engine: &mut E, group_id: &GroupId) {
    tokio::time::sleep(std::time::Duration::from_millis(75)).await;
    let results = engine.advance_convergence(group_id).await.unwrap();
    assert!(
        results.is_empty(),
        "SelfRemove auto-commit should drain through auto-publish, got {results:?}"
    );
}

/// True if `events` contains a `GroupStateChanged` departure (removed or left)
/// for `member`. Accepts either variant because the leave/removed distinction
/// is path-dependent: the direct inbound seam classifies a SelfRemove as
/// `MemberLeft`, while a convergence reorg surfaces it as an unattributed
/// `MemberRemoved`.
fn emits_departure_of(events: &[cgka_traits::engine::GroupEvent], member: &MemberId) -> bool {
    events.iter().any(|event| {
        matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                change:
                    cgka_traits::engine::GroupStateChange::MemberRemoved { member: m }
                    | cgka_traits::engine::GroupStateChange::MemberLeft { member: m },
                ..
            } if m == member
        )
    })
}

/// Strict matcher for an admin-driven removal: only `MemberRemoved` (never
/// `MemberLeft`), so a misclassified self-leave can't pass an admin-remove test.
fn emits_removed_of(events: &[cgka_traits::engine::GroupEvent], member: &MemberId) -> bool {
    events.iter().any(|event| {
        matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                change: cgka_traits::engine::GroupStateChange::MemberRemoved { member: m },
                ..
            } if m == member
        )
    })
}

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

/// Encode a `marmot.group.admin-policy.v1` state from raw 32-byte account keys,
/// sorted + deduped per the component rules. Mirrors the same-named helper in
/// `tests/update_group_data.rs`; kept file-local so this test file stays
/// self-contained like the others.
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

fn build_client(id: &[u8]) -> Engine<SqliteAccountStorage> {
    build_with_storage(id).0
}

fn build_client_on_storage(
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

fn build_with_storage(id: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = build_client_on_storage(id, storage.clone());
    (engine, storage)
}

fn clone_key_package_for_invite(kp: &KeyPackage) -> openmls::prelude::KeyPackage {
    let msg = MlsMessageIn::tls_deserialize_exact(kp.bytes())
        .expect("deserialize KeyPackage MLS message");
    let kp_in = match msg.extract() {
        MlsMessageBodyIn::KeyPackage(kp) => kp,
        _ => panic!("expected MLS KeyPackage message"),
    };
    let crypto = RustCrypto::default();
    kp_in
        .validate(&crypto, ProtocolVersion::Mls10)
        .expect("validate KeyPackage")
}

fn welcome_from_existing_non_admin(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    invitee_key_package: &KeyPackage,
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
    let invitee = clone_key_package_for_invite(invitee_key_package);
    let recipient = BasicCredential::try_from(invitee.leaf_node().credential().clone())
        .expect("invitee uses BasicCredential");
    let (_commit_out, welcome_out, _group_info) = mls_group
        .add_members(&provider, &signer, &[invitee])
        .expect("non-admin can build raw OpenMLS Add+Welcome fork");
    let welcome_bytes = welcome_out
        .tls_serialize_detached()
        .expect("serialize malicious Welcome");

    TransportMessage {
        id: hash_id(&welcome_bytes),
        payload: welcome_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("malicious-openmls".into()),
        envelope: TransportEnvelope::Welcome {
            recipient: MemberId::new(recipient.identity().to_vec()),
        },
    }
}

/// Like [`welcome_from_existing_non_admin`], but the malicious non-admin's
/// forked commit *also* rewrites the admin policy in the same commit so the
/// forger lands in `admins`. The one-shot `add_members` the sibling helper uses
/// cannot carry an extra proposal, so this builds `Add` + `AppDataUpdate` in a
/// single commit through the OpenMLS commit builder (same mechanics as
/// `tests/update_group_data.rs`). The Welcome it produces embeds the fork's
/// self-authored admin set, so the join-time `require_admin` check validates the
/// author against an admin set the author controls.
fn welcome_from_fork_with_self_promoted_admin(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    invitee_key_package: &KeyPackage,
    forged_admin_policy: Vec<u8>,
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
    let invitee = clone_key_package_for_invite(invitee_key_package);
    // Capture the recipient identity before `propose_adds` consumes the KP.
    let recipient = BasicCredential::try_from(invitee.leaf_node().credential().clone())
        .expect("invitee uses BasicCredential");
    let recipient_id = MemberId::new(recipient.identity().to_vec());

    // One commit: Add(invitee) + AppDataUpdate(admin-policy -> includes forger).
    let admin_update = Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
        GROUP_ADMIN_POLICY_COMPONENT_ID,
        forged_admin_policy,
    )));
    let mut builder = mls_group
        .commit_builder()
        .propose_adds(std::iter::once(invitee))
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
        .expect("non-admin can build Add+AppDataUpdate fork")
        .stage_commit(&provider)
        .expect("stage malicious Add+AppDataUpdate fork");
    let welcome_msg = commit_bundle
        .into_welcome_msg()
        .expect("an Add commit produces a Welcome");
    let welcome_bytes = welcome_msg
        .tls_serialize_detached()
        .expect("serialize malicious Welcome");

    TransportMessage {
        id: hash_id(&welcome_bytes),
        payload: welcome_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("malicious-openmls".into()),
        envelope: TransportEnvelope::Welcome {
            recipient: recipient_id,
        },
    }
}

fn welcome_from_admin_with_component_update(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    invitee_key_package: &KeyPackage,
    update: AppComponentData,
) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load admin's MLS group")
        .expect("admin created group");
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
    let invitee = clone_key_package_for_invite(invitee_key_package);
    let recipient = BasicCredential::try_from(invitee.leaf_node().credential().clone())
        .expect("invitee uses BasicCredential");
    let recipient_id = MemberId::new(recipient.identity().to_vec());

    let proposal = Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
        update.component_id,
        update.data,
    )));
    let mut builder = mls_group
        .commit_builder()
        .propose_adds(std::iter::once(invitee))
        .add_proposal(proposal)
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
    let welcome_msg = builder
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .expect("build Add+AppDataUpdate commit")
        .stage_commit(&provider)
        .expect("stage Add+AppDataUpdate commit")
        .into_welcome_msg()
        .expect("an Add commit produces a Welcome");
    let welcome_bytes = welcome_msg
        .tls_serialize_detached()
        .expect("serialize malformed-state Welcome");

    TransportMessage {
        id: hash_id(&welcome_bytes),
        payload: welcome_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("malformed-component-welcome".into()),
        envelope: TransportEnvelope::Welcome {
            recipient: recipient_id,
        },
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

fn try_build_raw_identity_client(id: &[u8]) -> Result<Engine<SqliteAccountStorage>, EngineError> {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(id.to_vec())
        .account_identity_proof_signer(proof_signer(b"raw-identity"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
}

fn converge_buffered_commit(engine: &mut Engine<SqliteAccountStorage>, group_id: &GroupId) {
    let result = engine
        .converge_stored_openmls_messages(group_id, 1_000_000)
        .expect("buffered commit converges");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
}

// ── Invite ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn invite_adds_third_member_and_advances_epoch() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");

    // Create a(lice)+b(ob) group.
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create_result) = alice
        .create_group(CreateGroupRequest {
            name: "test".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let pending = match &create_result {
        SendResult::GroupCreated { pending, .. } => *pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    let welcome_for_bob = match create_result {
        SendResult::GroupCreated { mut welcomes, .. } => welcomes.remove(0),
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();

    // Now alice invites carol.
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite_result = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();

    let (commit, carol_welcome, inv_pending) = match invite_result {
        SendResult::GroupEvolution {
            msg,
            mut welcomes,
            pending,
        } => (msg, welcomes.remove(0), pending),
        _ => panic!("expected GroupEvolution"),
    };
    assert_eq!(alice.epoch(&group_id).unwrap().0, 2);

    // Alice confirms.
    alice.confirm_published(inv_pending).await.unwrap();

    // Carol joins.
    carol.join_welcome(carol_welcome).await.unwrap();
    assert_eq!(carol.epoch(&group_id).unwrap().0, 2);

    // Bob ingests the commit → epoch advances; MemberAdded fires.
    let routed_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit
    };
    let outcome = bob.ingest(routed_commit).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut bob, &group_id);
    assert_eq!(bob.epoch(&group_id).unwrap().0, 2);

    let events = bob.drain_events();
    let has_epoch_change = events.iter().any(|e| {
        matches!(
            e,
            cgka_traits::engine::GroupEvent::EpochChanged {
                from: cgka_traits::EpochId(1),
                to: cgka_traits::EpochId(2),
                ..
            }
        )
    });
    assert!(
        has_epoch_change,
        "bob should see EpochChanged; events: {events:?}"
    );

    // All three engines converge.
    assert_eq!(alice.members(&group_id).unwrap().len(), 3);
    assert_eq!(bob.members(&group_id).unwrap().len(), 3);
    assert_eq!(carol.members(&group_id).unwrap().len(), 3);
}

#[tokio::test]
async fn invite_rejects_invitee_missing_required_capability() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut stripped = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(b"stripped"))
        .account_identity_proof_signer(proof_signer(b"stripped"))
        .feature_registry(FeatureRegistry::new())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
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
    if let SendResult::GroupCreated { pending, .. } = create {
        alice.confirm_published(pending).await.unwrap();
    }

    let stripped_kp = stripped.fresh_key_package().await.unwrap();
    let err = alice
        .send(SendIntent::Invite {
            group_id,
            key_packages: vec![stripped_kp],
        })
        .await
        .err()
        .unwrap();
    assert!(matches!(
        err,
        EngineError::MissingRequiredCapabilities { .. }
    ));
}

#[tokio::test]
async fn admin_remove_members_publishes_commit_and_updates_membership() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "remove".into(),
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    carol.join_welcome(welcome_for_carol).await.unwrap();

    let remove = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (commit, pending) = match remove {
        SendResult::GroupEvolution {
            msg,
            welcomes,
            pending,
        } => {
            assert!(welcomes.is_empty());
            (msg, pending)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    assert_eq!(
        alice.members(&group_id).unwrap().len(),
        2,
        "pending remove should project immediately"
    );

    alice.confirm_published(pending).await.unwrap();
    let alice_events = alice.drain_events();
    assert!(
        emits_removed_of(&alice_events, &bob.self_id()),
        "alice should emit MemberRemoved for bob after confirm; got {alice_events:?}"
    );

    let routed_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit
    };
    let outcome = carol.ingest(routed_commit).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut carol, &group_id);
    let carol_members = carol.members(&group_id).unwrap();
    assert_eq!(carol_members.len(), 2);
    assert!(
        !carol_members
            .iter()
            .any(|member| member.id == bob.self_id()),
        "carol should converge to a group without bob; got {carol_members:?}"
    );
}

/// Shared setup for the self-eviction realization tests (#376): alice (admin)
/// creates a group with bob, bob joins, alice removes bob and confirms the
/// publish. Returns the engines, bob's storage handle, the group id, and the
/// removal commit routed for group ingestion (NOT yet delivered to bob).
async fn setup_removed_member(
    tag: &[u8],
) -> (
    Engine<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    GroupId,
    TransportMessage,
) {
    let mut alice = build_client(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: String::from_utf8_lossy(tag).into_owned(),
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

    let remove = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (commit, pending) = match remove {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    alice.drain_events();

    let routed_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit
    };
    (alice, bob, bob_storage, group_id, routed_commit)
}

/// Send a post-eviction application message from `alice` and route it for
/// group ingestion.
async fn post_eviction_app_message(
    alice: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    payload: &[u8],
) -> TransportMessage {
    let payload = app_payload_for(alice, payload);
    let sent = alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
        })
        .await
        .unwrap();
    let msg = match sent {
        SendResult::ApplicationMessage { msg } => msg,
        other => panic!("expected ApplicationMessage, got {other:?}"),
    };
    TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    }
}

/// #376 realization marker: when the removed member applies the removal
/// commit, the local group copy is marked removed alongside the self-removed
/// notification, so later `SelfEvicted` input does not re-notify.
#[tokio::test]
async fn removed_member_applying_removal_commit_marks_local_copy_removed() {
    let (_alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-marks-removed").await;

    let outcome = bob.ingest(routed_commit).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "removal commit enters convergence; got {outcome:?}"
    );
    converge_buffered_commit(&mut bob, &group_id);

    let bob_events = bob.drain_events();
    assert!(
        emits_departure_of(&bob_events, &bob.self_id()),
        "bob should observe his own removal; got {bob_events:?}"
    );
    let record = bob_storage.get_group(&group_id).unwrap();
    assert!(
        record.removed,
        "applying the removal commit must mark the local group copy removed"
    );
}

/// #376 regression (silent eviction): later group input for a group whose
/// retained canonical state records our own removal classifies as
/// `Stale {{ SelfEvicted }}` and performs "realizing removal"
/// (member-departure.md) when the local copy is not yet marked removed —
/// emitting the self-removed notification and marking the copy removed —
/// instead of failing silently as generic `PeelFailed` stale traffic.
#[tokio::test]
async fn post_eviction_message_realizes_self_removal_and_returns_self_evicted() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-realize").await;

    // Bob's MLS state records the eviction (the removal commit applied)...
    let outcome = bob.ingest(routed_commit).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    // ...but simulate the silent-eviction client state the issue describes: a
    // local copy that never realized the removal (no notification observed,
    // record not marked removed, self still presented as a member). This is
    // the persisted state of a pre-fix client — or one whose removal
    // notification was lost — that only ever sees post-eviction traffic.
    let mut record = bob_storage.get_group(&group_id).unwrap();
    record.removed = false;
    record.members = vec![cgka_traits::group::Member {
        id: bob.self_id(),
        credential: bob.self_id().as_slice().to_vec(),
    }];
    bob_storage.put_group(&record).unwrap();

    // A later post-eviction message must surface the removal, not vanish.
    let routed_app = post_eviction_app_message(&mut alice, &group_id, b"post-eviction").await;
    let outcome = bob.ingest(routed_app).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::SelfEvicted
            }
        ),
        "post-eviction input must classify SelfEvicted; got {outcome:?}"
    );
    let bob_events = bob.drain_events();
    assert!(
        emits_removed_of(&bob_events, &bob.self_id()),
        "realization must emit the self-removed notification; got {bob_events:?}"
    );
    let record = bob_storage.get_group(&group_id).unwrap();
    assert!(
        record.removed,
        "realization must mark the local group copy removed"
    );
    assert!(
        !record.members.iter().any(|m| m.id == bob.self_id()),
        "realization must reconcile the roster: a removed copy must not keep \
         presenting self as a member; got {:?}",
        record.members
    );
}

/// #376 attribution: OpenMLS's Inactive state does not record WHY the local
/// leaf left the tree, but a durable leave request is authenticated local
/// intent to leave. When one is pending, realization attributes the departure
/// as `MemberLeft` (actor = self) — "you left" — instead of an involuntary
/// `MemberRemoved` with an unknown actor.
#[tokio::test]
async fn realization_with_pending_leave_request_attributes_member_left() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-left").await;

    let outcome = bob.ingest(routed_commit).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    // Silent-eviction copy again, but this time the durable state also holds
    // a leave request: the member had asked to leave before the eviction was
    // realized.
    let mut record = bob_storage.get_group(&group_id).unwrap();
    record.removed = false;
    record.members = vec![cgka_traits::group::Member {
        id: bob.self_id(),
        credential: bob.self_id().as_slice().to_vec(),
    }];
    bob_storage.put_group(&record).unwrap();
    bob_storage
        .put_leave_request(&cgka_traits::storage::LeaveRequest {
            group_id: group_id.clone(),
            requested_at_ms: 1,
            last_proposed_epoch: None,
        })
        .unwrap();

    let routed_app = post_eviction_app_message(&mut alice, &group_id, b"after-leave").await;
    let outcome = bob.ingest(routed_app).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::SelfEvicted
        }
    ));
    let bob_events = bob.drain_events();
    let bob_id = bob.self_id();
    assert!(
        bob_events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                change: cgka_traits::engine::GroupStateChange::MemberLeft { member },
                actor: Some(actor),
                ..
            } if member == &bob_id && actor == &bob_id
        )),
        "a pending leave request must attribute realization as MemberLeft by self; got {bob_events:?}"
    );
    assert!(
        !emits_removed_of(&bob_events, &bob_id),
        "no involuntary MemberRemoved when the departure was our own leave; got {bob_events:?}"
    );
    assert!(bob_storage.get_group(&group_id).unwrap().removed);
    assert!(
        bob_storage.leave_request(&group_id).unwrap().is_none(),
        "realization consumes the leave request"
    );
}

/// #376 outbound terminal semantics: a copy marked removed must not prepare
/// or publish anything (member-departure.md). Sends fail with a deterministic
/// terminal `InvalidTransition` — not an opaque backend error from OpenMLS's
/// `UseAfterEviction`.
#[tokio::test]
async fn send_after_realized_eviction_is_rejected_terminally() {
    let (_alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-send-gate").await;

    let outcome = bob.ingest(routed_commit).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();
    assert!(bob_storage.get_group(&group_id).unwrap().removed);

    let payload = app_payload_for(&bob, b"after eviction");
    let blocked = bob
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
        })
        .await;
    assert!(
        matches!(blocked, Err(EngineError::InvalidTransition(_))),
        "send on a removed copy must fail terminally, got {blocked:?}"
    );

    // Leave is equally pointless on a removed copy: same terminal error.
    let blocked = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await;
    assert!(
        matches!(blocked, Err(EngineError::InvalidTransition(_))),
        "leave on a removed copy must fail terminally, got {blocked:?}"
    );
}

/// Durably queue an app-message intent for `group_id`, simulating a send the
/// engine accepted mid-convergence (`SendResult::Queued`) that has not been
/// drained yet.
fn queue_app_message_intent(
    storage: &SqliteAccountStorage,
    engine: &Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    tag: u8,
) -> MessageId {
    let id = MessageId::new(vec![tag; 32]);
    storage
        .put_queued_outbound_intent(&cgka_traits::storage::QueuedOutboundIntent {
            id: id.clone(),
            group_id: group_id.clone(),
            intent: SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(engine, b"queued before removal"),
            },
            created_at_ms: 1,
        })
        .expect("queue outbound intent");
    id
}

/// #376 review follow-up: an outbound intent durably queued before the
/// removal is applied must be discarded when the copy becomes removed —
/// applying the removal commit purges the queue, so later drains have nothing
/// to perpetually re-fail against the removed-copy send gate.
#[tokio::test]
async fn applying_removal_commit_purges_queued_outbound_intents() {
    let (_alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-purge-queue").await;

    queue_app_message_intent(&bob_storage, &bob, &group_id, 0x51);
    assert_eq!(
        bob_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    let outcome = bob.ingest(routed_commit).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut bob, &group_id);
    assert!(bob_storage.get_group(&group_id).unwrap().removed);
    assert!(
        bob_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty(),
        "marking the copy removed must discard queued outbound intents"
    );
}

/// #376 review follow-up: realization itself purges queued intents, and the
/// drain path treats a removed copy as terminal — it discards any remaining
/// queued records and reports nothing to drain instead of returning the
/// removed-copy send error forever (which the app-layer scheduler would
/// retry for the lifetime of the account).
#[tokio::test]
async fn drain_on_removed_copy_discards_queued_intents_without_error() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-drain-queue").await;

    let outcome = bob.ingest(routed_commit).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    // Realization-side purge: recreate the silent copy with an undrained
    // queued intent, then let a post-eviction message trigger realization.
    let mut record = bob_storage.get_group(&group_id).unwrap();
    record.removed = false;
    bob_storage.put_group(&record).unwrap();
    queue_app_message_intent(&bob_storage, &bob, &group_id, 0x52);
    let routed_app = post_eviction_app_message(&mut alice, &group_id, b"trigger realize").await;
    let outcome = bob.ingest(routed_app).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::SelfEvicted
        }
    ));
    assert!(
        bob_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty(),
        "realization must discard queued outbound intents"
    );

    // Drain-side defense in depth: an intent queued after the copy is already
    // marked removed (any ordering the marker-site purges missed) is
    // discarded by the drain itself — no error, nothing drained, queue empty.
    queue_app_message_intent(&bob_storage, &bob, &group_id, 0x53);
    let drained = bob
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .expect("drain on a removed copy must not error");
    assert!(
        drained.is_empty(),
        "nothing may be published for a removed copy; got {drained:?}"
    );
    assert!(
        bob_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty(),
        "drain must discard queued intents for a removed copy"
    );
}

/// #376 idempotence: realization is a state-derived obligation. A second
/// post-eviction message still classifies `SelfEvicted`, but the already-
/// marked-removed copy suppresses a duplicate self-removed notification.
#[tokio::test]
async fn second_post_eviction_message_is_self_evicted_without_duplicate_notification() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-idempotent").await;

    let outcome = bob.ingest(routed_commit).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();
    assert!(
        bob_storage.get_group(&group_id).unwrap().removed,
        "precondition: the copy is already marked removed"
    );

    for round in 0..2u8 {
        let routed_app =
            post_eviction_app_message(&mut alice, &group_id, format!("again-{round}").as_bytes())
                .await;
        let outcome = bob.ingest(routed_app).await.unwrap();
        assert!(
            matches!(
                outcome,
                IngestOutcome::Stale {
                    reason: StaleReason::SelfEvicted
                }
            ),
            "round {round}: post-eviction input stays SelfEvicted; got {outcome:?}"
        );
        let bob_events = bob.drain_events();
        assert!(
            !emits_departure_of(&bob_events, &bob.self_id()),
            "round {round}: an already-realized removal must not re-notify; got {bob_events:?}"
        );
    }
}

/// #376 guard: failure to decrypt alone is NOT evidence of removal
/// (member-departure.md). A member that merely missed the removal commit has
/// no authenticated evidence, so post-eviction traffic stays a
/// missing-history/repair condition (buffered) — it must NOT map to
/// `SelfEvicted` and must NOT fabricate a removal notification.
#[tokio::test]
async fn missed_removal_commit_without_evidence_is_not_self_evicted() {
    let (mut alice, mut bob, bob_storage, group_id, _undelivered_commit) =
        setup_removed_member(b"evict-no-evidence").await;

    // Bob never sees the removal commit; only later traffic arrives.
    let routed_app = post_eviction_app_message(&mut alice, &group_id, b"future-epoch").await;
    let outcome = bob.ingest(routed_app).await.unwrap();
    assert!(
        !matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::SelfEvicted
            }
        ),
        "undecryptable input without authenticated evidence must not be SelfEvicted; got {outcome:?}"
    );
    let bob_events = bob.drain_events();
    assert!(
        !emits_departure_of(&bob_events, &bob.self_id()),
        "no removal notification without authenticated evidence; got {bob_events:?}"
    );
    assert!(
        !bob_storage.get_group(&group_id).unwrap().removed,
        "the local copy must not be marked removed without authenticated evidence"
    );
}

#[tokio::test]
async fn remove_co_admin_couples_admin_policy_update_in_same_commit() {
    // admin-policy-v1.md: a commit that removes an account's last member leaf
    // MUST also remove that account's key from `admins` in the same resulting
    // epoch. The public RemoveMembers path builds that coupled
    // Remove + AppDataUpdate commit itself, so removing a listed co-admin
    // succeeds, the commit publishes, and the resulting admin set no longer
    // lists the removed account — locally and for a member ingesting it.
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");
    let alice_id = alice.self_id();
    let bob_id = bob.self_id();
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "remove-co-admin".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob_id.clone()],
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

    let alice_admin: [u8; 32] = alice_id.as_slice().try_into().unwrap();
    let bob_admin: [u8; 32] = bob_id.as_slice().try_into().unwrap();
    let mut initial_admins = vec![alice_admin, bob_admin];
    initial_admins.sort();
    assert_eq!(alice.admin_pubkeys(&group_id).unwrap(), initial_admins);

    let remove = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob_id.clone()],
        })
        .await
        .expect("removing a co-admin stages a coupled Remove+AppDataUpdate commit");
    let (commit, pending) = match remove {
        SendResult::GroupEvolution {
            msg,
            welcomes,
            pending,
        } => {
            assert!(welcomes.is_empty());
            (msg, pending)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    // The author's confirm-published events must carry BOTH the membership
    // change and the coupled admin revocation, matching what receivers derive
    // from their before/after admin snapshot.
    let alice_events = alice.drain_events();
    assert!(
        emits_removed_of(&alice_events, &bob_id),
        "alice should emit MemberRemoved for bob after confirm; got {alice_events:?}"
    );
    assert!(
        alice_events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                change: cgka_traits::engine::GroupStateChange::AdminRemoved { member },
                ..
            } if member == &bob_id
        )),
        "alice should emit AdminRemoved for bob after confirm; got {alice_events:?}"
    );

    assert_eq!(alice.epoch(&group_id).unwrap().0, 2);
    let alice_members = alice.members(&group_id).unwrap();
    assert_eq!(alice_members.len(), 2);
    assert!(
        !alice_members.iter().any(|member| member.id == bob_id),
        "bob must be removed from alice's membership; got {alice_members:?}"
    );
    assert_eq!(
        alice.admin_pubkeys(&group_id).unwrap(),
        vec![alice_admin],
        "the same commit must drop bob from the admin set"
    );

    // A second member ingesting the commit accepts it and sees the same
    // membership and admin-set change.
    let routed_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit
    };
    let outcome = carol.ingest(routed_commit).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut carol, &group_id);
    assert_eq!(carol.epoch(&group_id).unwrap().0, 2);
    let carol_members = carol.members(&group_id).unwrap();
    assert_eq!(carol_members.len(), 2);
    assert!(
        !carol_members.iter().any(|member| member.id == bob_id),
        "carol must converge to a group without bob; got {carol_members:?}"
    );
    assert_eq!(
        carol.admin_pubkeys(&group_id).unwrap(),
        vec![alice_admin],
        "carol's admin view must drop bob after ingesting the commit"
    );
}

/// Regression for mdk#557: re-adding a previously removed member to the
/// SAME group must produce a fresh Welcome the receiver decrypts and acts on,
/// with no special-casing between "first add" and "re-add after removal".
///
/// Before the fix, when B applied the inbound commit that removed B, the engine
/// merged the staged commit but left B's stale OpenMLS group state in storage.
/// A later re-add Welcome was staged on top of that corrupt leftover state, so B
/// never ended up with a usable group — the silent no-op the issue describes.
/// The fix preserves B's tombstoned Marmot/convergence state and clears only
/// stale live OpenMLS state before a re-join Welcome restages, so the re-add
/// lands as a clean first-join.
#[tokio::test]
async fn readd_after_remove_produces_fresh_welcome_join() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");

    // 1. Alice creates an alice+bob group; bob joins via the first Welcome.
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "readd".into(),
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    bob.drain_events();
    assert!(
        bob.members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == bob.self_id()),
        "bob should be a member after the first join"
    );

    // 2. Alice removes bob (admin Remove) and publishes the commit.
    let remove = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (remove_commit, remove_pending) = match remove {
        SendResult::GroupEvolution {
            msg,
            welcomes,
            pending,
        } => {
            assert!(welcomes.is_empty());
            (msg, pending)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(remove_pending).await.unwrap();

    // Bob ingests his own removal commit and observes that he is removed.
    let routed_remove = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..remove_commit
    };
    let outcome = bob.ingest(routed_remove).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut bob, &group_id);
    let bob_remove_events = bob.drain_events();
    assert!(
        emits_departure_of(&bob_remove_events, &bob.self_id()),
        "bob should observe his own removal; got {bob_remove_events:?}"
    );
    // After being removed, bob retains a tombstoned local record of the group
    // (the engine does NOT eagerly destroy local state on removal — retaining
    // it preserves the convergence artifacts a late winning branch needs to
    // invalidate a losing removal branch within `max_rewind_commits`). Bob is
    // no longer listed as a member of his own retained record.
    let bob_after_remove = bob
        .members(&group_id)
        .expect("bob should retain a tombstoned group record after removal");
    assert!(
        !bob_after_remove
            .iter()
            .any(|member| member.id == bob.self_id()),
        "bob should no longer be a member of his retained record; got {bob_after_remove:?}"
    );

    // 3. Alice re-adds bob with a brand-new KeyPackage (never reuse the first).
    let bob_kp_2 = bob.fresh_key_package().await.unwrap();
    let readd = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![bob_kp_2],
        })
        .await
        .unwrap();
    let (readd_pending, re_welcome) = match readd {
        SendResult::GroupEvolution {
            mut welcomes,
            pending,
            ..
        } => (pending, welcomes.remove(0)),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(readd_pending).await.unwrap();

    // 4. Bob ingests the NEW Welcome and must successfully re-join: emit
    //    GroupJoined, the group is visible again, and bob is a member. Before
    //    the fix this was a silent no-op / error on stale leftover state.
    bob.join_welcome(re_welcome).await.unwrap();
    let rejoin_events = bob.drain_events();
    assert!(
        rejoin_events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupJoined { group_id: g, .. } if g == &group_id
        )),
        "bob should emit GroupJoined on the re-add Welcome; got {rejoin_events:?}"
    );
    let bob_members = bob.members(&group_id).unwrap();
    assert!(
        bob_members.iter().any(|member| member.id == bob.self_id()),
        "bob should be a member again after the re-add; got {bob_members:?}"
    );
    assert!(
        bob_members
            .iter()
            .any(|member| member.id == alice.self_id()),
        "alice should still be in bob's re-joined group; got {bob_members:?}"
    );
    assert_eq!(
        alice.members(&group_id).unwrap().len(),
        bob_members.len(),
        "alice and bob should agree on the re-added group's membership"
    );
}

#[tokio::test]
async fn own_leaf_index_reports_mls_index_after_blank_leaf() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "own leaf index".into(),
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    carol.join_welcome(welcome_for_carol).await.unwrap();

    assert_eq!(alice.own_leaf_index(&group_id).unwrap(), 0);
    assert_eq!(bob.own_leaf_index(&group_id).unwrap(), 1);
    assert_eq!(carol.own_leaf_index(&group_id).unwrap(), 2);

    let remove = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let (commit, pending) = match remove {
        SendResult::GroupEvolution {
            msg,
            welcomes,
            pending,
        } => {
            assert!(welcomes.is_empty());
            (msg, pending)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let routed_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit
    };
    let outcome = carol.ingest(routed_commit).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut carol, &group_id);

    let carol_roster_index = carol
        .members(&group_id)
        .unwrap()
        .into_iter()
        .position(|member| member.id == carol.self_id())
        .unwrap() as u32;
    assert_eq!(
        carol_roster_index, 1,
        "bob's blanked leaf is skipped by roster enumeration"
    );
    assert_eq!(carol.own_leaf_index(&group_id).unwrap(), 2);
}

#[tokio::test]
async fn non_admin_cannot_remove_members() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "remove".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();

    let err = bob
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![carol.self_id()],
        })
        .await
        .err()
        .unwrap();
    assert!(matches!(err, EngineError::NotGroupAdmin { .. }));
}

#[tokio::test]
async fn non_admin_cannot_invite_members() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (_group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "invite-policy".into(),
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
        _ => unreachable!(),
    };
    let group_id = bob.join_welcome(welcome_for_bob).await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let err = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .err()
        .unwrap();

    assert!(matches!(err, EngineError::NotGroupAdmin { .. }));
}

#[tokio::test]
async fn join_rejects_welcome_authored_by_existing_non_admin() {
    let mut alice = build_client(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let mut carol = build_client(b"carol");
    let mut david = build_client(b"david");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "welcome-policy".into(),
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    carol.join_welcome(welcome_for_carol).await.unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let malicious_welcome =
        welcome_from_existing_non_admin(&bob_storage, &bob.self_id(), &group_id, &david_kp);

    let err = david
        .join_welcome(malicious_welcome)
        .await
        .expect_err("non-admin-authored Welcome must be rejected");
    assert!(
        matches!(err, EngineError::NotGroupAdmin { .. }),
        "expected NotGroupAdmin for non-admin Welcome signer, got {err:?}"
    );
}

#[tokio::test]
async fn join_rejects_welcome_with_invalid_known_app_component_state() {
    let blossom = encode_component_vectors(&[
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 12],
        &[0x44; 32],
        b"IMAGE/PNG",
    ]);
    let mut routing = encode_nostr_routing_v1(
        &NostrRoutingV1::new([0x55; 32], vec!["wss://relay.example".into()]).unwrap(),
    )
    .unwrap();
    routing.push(0);

    let invalid_components = [
        (
            "profile",
            AppComponentData {
                component_id: GROUP_PROFILE_COMPONENT_ID,
                // A zero-length name encoded with a non-minimal two-byte QUIC varint.
                data: vec![0x40, 0x00, 0x00],
            },
        ),
        (
            "blossom",
            AppComponentData {
                component_id: GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
                // Structurally complete, but media type is not canonical lowercase.
                data: blossom,
            },
        ),
        (
            "avatar",
            AppComponentData {
                component_id: GROUP_AVATAR_URL_COMPONENT_ID,
                // The WHATWG serializer lowercases this host, so these stored bytes are noncanonical.
                data: encode_component_vectors(&[b"https://EXAMPLE.com/avatar.png", &[], &[]]),
            },
        ),
        (
            "routing",
            AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                // A canonical routing value followed by forbidden trailing bytes.
                data: routing,
            },
        ),
    ];

    for (case, invalid_component) in invalid_components {
        let (mut alice, alice_storage) = build_with_storage(b"welcome-component-admin");
        let mut invitee = build_client(case.as_bytes());
        let (group_id, created) = alice
            .create_group(CreateGroupRequest {
                name: "welcome component validation".into(),
                description: "".into(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let pending = match created {
            SendResult::GroupCreated { pending, .. } => pending,
            other => panic!("expected GroupCreated, got {other:?}"),
        };
        alice.confirm_published(pending).await.unwrap();

        let invitee_kp = invitee.fresh_key_package().await.unwrap();
        let welcome = welcome_from_admin_with_component_update(
            &alice_storage,
            &alice.self_id(),
            &group_id,
            &invitee_kp,
            invalid_component,
        );
        let err = invitee
            .join_welcome(welcome)
            .await
            .expect_err("invalid known component state must reject the Welcome");
        assert!(
            matches!(err, EngineError::InvalidWelcome),
            "{case}: expected InvalidWelcome, got {err:?}"
        );
        assert!(
            invitee.members(&group_id).is_err(),
            "{case}: rejected Welcome must not persist joined state"
        );
    }
}

#[tokio::test]
async fn join_accepts_welcome_from_fork_with_self_promoted_admin() {
    // Boundary pinned: the join-time admin-authored-Welcome check (`require_admin`
    // on the welcome path) validates the Welcome author against the admin set of
    // the *joined* group state, and in a fork that admin set is author-controlled.
    // A non-admin member who forks with a single commit that BOTH adds the invitee
    // AND rewrites the admin policy to list itself defeats the check: the join
    // SUCCEEDS, because the author is an admin of the fork it just authored. This
    // is the sibling of `join_rejects_welcome_authored_by_existing_non_admin`,
    // which forks with a plain Add (no self-promotion) and is correctly rejected.
    //
    // This is the documented limit of Welcome-bootstrap trust, not a defect the
    // engine fixes here: see spec/protocol-core/joining.md ("Welcome-bootstrap
    // trust") and issue #275. The corroboration mitigation (treat a freshly
    // joined group as unverified until an application message from another member
    // account authenticates on the branch) is an application-layer concern, not an
    // engine-side join check.
    let mut alice = build_client(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let mut carol = build_client(b"carol");
    let mut david = build_client(b"david");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "welcome-fork-self-promote".into(),
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    carol.join_welcome(welcome_for_carol).await.unwrap();

    // Alice is the sole (implicit) admin. Bob (non-admin) forks: in ONE commit he
    // adds david AND rewrites the admin policy from {alice} to {alice, bob},
    // sorted/valid per marmot.group.admin-policy.v1, promoting himself.
    let forged_admins = encode_admin_policy_for_test(&[
        alice.self_id().as_slice().to_vec(),
        bob.self_id().as_slice().to_vec(),
    ]);
    let david_kp = david.fresh_key_package().await.unwrap();
    let malicious_welcome = welcome_from_fork_with_self_promoted_admin(
        &bob_storage,
        &bob.self_id(),
        &group_id,
        &david_kp,
        forged_admins,
    );

    // The join SUCCEEDS: `require_admin` checks the Welcome author (bob) against
    // the fork's admin set, which bob just authored to include himself.
    let joined_group_id = david
        .join_welcome(malicious_welcome)
        .await
        .expect("fork that self-promotes its author into admins currently passes the join check");
    assert_eq!(
        joined_group_id, group_id,
        "david joins the forked group (same group id)"
    );
    assert!(
        david.members(&group_id).is_ok(),
        "david should hold the joined (forked) group state"
    );
}

#[tokio::test]
async fn join_rejects_welcome_whose_admin_set_lists_a_phantom_admin() {
    // mdk#737: welcome-join runs the admin-leaf-coupling check (step 5e). A fork
    // whose rewritten admin policy lists a pubkey with NO ratchet-tree leaf — a
    // phantom/pre-provisioned admin — is rejected at join, before any group
    // record is persisted. This is distinct from the self-promotion case in
    // `join_accepts_welcome_from_fork_with_self_promoted_admin`, where the forger
    // holds a real leaf (coupling satisfied) and the residual gap is a documented
    // Welcome-bootstrap-trust limit, not a coupling violation.
    let mut alice = build_client(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let mut carol = build_client(b"carol");
    let mut david = build_client(b"david");
    let mallory = build_client(b"mallory"); // valid account key, never a member
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "welcome-fork-phantom-admin".into(),
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    carol.join_welcome(welcome_for_carol).await.unwrap();

    // Bob forks: ONE commit adds david AND rewrites admin policy to
    // {alice, bob, mallory}. Bob is included so the fork passes the join-time
    // `require_admin` author check (5d) and reaches the coupling check (5e);
    // mallory is a valid account key with NO leaf — the phantom that 5e rejects.
    // Deterministic Welcome validation failures are surfaced as InvalidWelcome
    // so transport ingest can terminalize poisoned input (#967).
    let forged_admins = encode_admin_policy_for_test(&[
        alice.self_id().as_slice().to_vec(),
        bob.self_id().as_slice().to_vec(),
        mallory.self_id().as_slice().to_vec(),
    ]);
    let david_kp = david.fresh_key_package().await.unwrap();
    let malicious_welcome = welcome_from_fork_with_self_promoted_admin(
        &bob_storage,
        &bob.self_id(),
        &group_id,
        &david_kp,
        forged_admins,
    );

    let err = david
        .join_welcome(malicious_welcome)
        .await
        .expect_err("a Welcome whose admin set lists a phantom admin must be rejected");
    assert!(
        matches!(err, EngineError::InvalidWelcome),
        "expected terminal invalid-Welcome rejection, got {err:?}"
    );
    assert!(
        david.members(&group_id).is_err(),
        "david must not hold any joined group state after a rejected join"
    );
}

#[tokio::test]
async fn engine_rejects_malformed_local_credential_identity_at_build() {
    // foundation/identity.md: a Marmot credential identity MUST be a valid
    // 32-byte x-only secp256k1 public key. A short, non-curve identity is
    // rejected at identity creation, so a member with a malformed identity can
    // never enter a group in the first place.
    let err = try_build_raw_identity_client(b"bob")
        .err()
        .expect("building an engine with a 3-byte identity must fail");
    let message = err.to_string();
    assert!(
        message.contains("invalid credential identity"),
        "unexpected error: {message}"
    );

    // A 32-byte value that is not a valid curve point is also rejected.
    let mut not_a_point = vec![0u8; 32];
    not_a_point[..5].copy_from_slice(b"david");
    assert!(
        try_build_raw_identity_client(&not_a_point).is_err(),
        "a 32-byte non-curve identity must be rejected"
    );
}

// ── Leave (MIP-03 SelfRemove) ───────────────────────────────────────────────

#[tokio::test]
async fn selfremove_full_flow_with_auto_commit() {
    // MIP-03 end-to-end (post-§149):
    //   alice creates group with bob + carol, confirms; both join via welcome
    //   bob (non-admin) sends SelfRemove → Proposal
    //   alice ingests bob's proposal → schedules a delayed SelfRemove commit
    //   drain_auto_publish yields the commit + pending ref
    //   alice confirms publish → epoch 2 applies locally
    //   bob ingests alice's commit → bob's epoch advances, sees himself
    //                                removed
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "mip03".into(),
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    carol.join_welcome(welcome_for_carol).await.unwrap();

    // Bob (non-admin) leaves.
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

    let blocked = bob
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&bob, b"should not send after leave"),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(blocked, EngineError::InvalidTransition(_)),
        "leaver must not send app data after SelfRemove proposal; got {blocked:?}"
    );

    // Alice ingests bob's proposal and schedules a delayed SelfRemove-only
    // commit.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..proposal
    };
    let outcome = alice.ingest(routed).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Processed));
    let alice_events = alice.drain_events();
    assert!(
        !emits_departure_of(&alice_events, &bob.self_id()),
        "alice must not emit a departure until auto-commit publish is confirmed; got {alice_events:?}"
    );
    assert_eq!(alice.epoch(&group_id).unwrap().0, 1);
    assert_eq!(alice.members(&group_id).unwrap().len(), 3);
    assert!(
        alice.drain_auto_publish().is_empty(),
        "auto-commit should not be staged until the jitter timer fires"
    );
    assert_eq!(
        alice.drain_pending_convergence_groups(),
        vec![group_id.clone()]
    );

    advance_selfremove_auto_commit(&mut alice, &group_id).await;

    // Alice has a projected pending epoch/member set, but the group is not
    // Stable/applied yet. New sends must wait for publish confirmation.
    assert_eq!(alice.epoch(&group_id).unwrap().0, 2);
    let alice_members = alice.members(&group_id).unwrap();
    assert_eq!(
        alice_members.len(),
        2,
        "bob should be removed; got {alice_members:?}"
    );
    let pending_send = alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, b"wait for auto confirm"),
        })
        .await;
    assert!(
        matches!(pending_send, Err(EngineError::InvalidTransition(_))),
        "auto-commit should leave alice in PendingPublish until confirmed"
    );

    // drain_auto_publish yields the commit alice produced.
    let mut auto_msgs = alice.drain_auto_publish();
    assert_eq!(auto_msgs.len(), 1);
    let auto = auto_msgs.remove(0);
    alice.confirm_published(auto.pending).await.unwrap();
    let alice_events = alice.drain_events();
    assert!(
        emits_departure_of(&alice_events, &bob.self_id()),
        "alice should emit a departure for bob after confirm; got {alice_events:?}"
    );

    // Bob ingests alice's commit — his epoch advances and he sees himself
    // removed. The engine retains his (tombstoned) local group state on removal
    // so the convergence artifacts needed to invalidate a losing removal branch
    // survive (mdk#557 keeps re-add working via a lazy teardown at
    // re-join time, not an eager destroy here).
    let commit = auto.msg;
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit
    };
    let outcome = bob.ingest(routed).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut bob, &group_id);
    assert_eq!(bob.epoch(&group_id).unwrap().0, 2);
    let bob_events = bob.drain_events();
    assert!(
        emits_departure_of(&bob_events, &bob.self_id()),
        "bob should emit a departure for himself; got {bob_events:?}"
    );
}

#[tokio::test]
async fn selfremove_leaving_gate_survives_engine_rebuild() {
    let mut alice = build_client(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let mut carol = build_client(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "mip03".into(),
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    carol.join_welcome(welcome_for_carol).await.unwrap();

    let leave = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert!(
        matches!(leave, SendResult::Proposal { .. }),
        "leave should publish a SelfRemove proposal, got {leave:?}"
    );
    let blocked = bob
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&bob, b"blocked before restart"),
        })
        .await;
    assert!(
        matches!(blocked, Err(EngineError::InvalidTransition(_))),
        "leaver must be blocked before restart; got {blocked:?}"
    );

    drop(bob);
    let mut bob = build_client_on_storage(b"bob", bob_storage);
    bob.hydrate_stable_groups_from_storage().unwrap();
    let blocked = bob
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&bob, b"blocked after restart"),
        })
        .await;
    assert!(
        matches!(blocked, Err(EngineError::InvalidTransition(_))),
        "leaver must still be blocked after restart; got {blocked:?}"
    );
}

#[tokio::test]
async fn selfremove_leave_request_reproposes_when_later_epoch_keeps_member() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "mip03".into(),
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();

    let leave = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    assert!(
        matches!(leave, SendResult::Proposal { .. }),
        "leave should publish a SelfRemove proposal, got {leave:?}"
    );
    let blocked = bob
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&bob, b"blocked while leave is current"),
        })
        .await;
    assert!(
        matches!(blocked, Err(EngineError::InvalidTransition(_))),
        "leaver must be blocked while SelfRemove is current; got {blocked:?}"
    );

    // Alice never saw Bob's SelfRemove. She advances the epoch with a
    // non-removing commit, which makes Bob's epoch-1 SelfRemove stale.
    let rename = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("still includes bob".into()),
            description: None,
        })
        .await
        .unwrap();
    let (commit, pending) = match rename {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit
    };
    let outcome = bob.ingest(routed).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut bob, &group_id);
    let drained = bob.advance_convergence(&group_id).await.unwrap();
    assert!(
        drained.is_empty(),
        "durable leave request should not release ordinary queued sends"
    );
    assert_eq!(bob.epoch(&group_id).unwrap().0, 2);
    assert!(
        bob.members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == bob.self_id()),
        "bob should still be a member after the non-removing commit"
    );

    let reproposals = bob.drain_auto_proposals();
    assert_eq!(
        reproposals.len(),
        1,
        "stale SelfRemove should produce one fresh proposal for the new epoch"
    );

    let app_send = bob
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&bob, b"still blocked after stale self-remove"),
        })
        .await;
    assert!(
        matches!(app_send, Err(EngineError::InvalidTransition(_))),
        "durable leave request must keep app sends blocked; got {app_send:?}"
    );

    let leave_again = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await;
    assert!(
        matches!(leave_again, Err(EngineError::InvalidTransition(_))),
        "bob should not duplicate a SelfRemove proposal for the same new epoch; got {leave_again:?}"
    );
}

/// A remaining member that observes a peer SelfRemove proposal schedules its
/// own SelfRemove-only commit. The observer remains sendable until the delayed
/// commit is staged; after staging, publish-before-apply blocks new sends.
#[tokio::test]
async fn observed_selfremove_proposal_delays_commit_then_blocks_outbound_app_messages() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "mip03".into(),
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    carol.join_welcome(welcome_for_carol).await.unwrap();

    // Bob (non-admin) leaves, producing a standalone SelfRemove proposal.
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

    // Carol ingests bob's proposal. Even though Alice has a lower leaf index,
    // Carol is a remaining non-target member and may schedule a SelfRemove-only
    // commit. Convergence handles any race if Alice does the same.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..proposal
    };
    let outcome = carol.ingest(routed).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Processed));

    assert!(
        carol.drain_auto_publish().is_empty(),
        "observing a SelfRemove should schedule, not immediately stage"
    );
    assert_eq!(carol.epoch(&group_id).unwrap().0, 1);

    // Observers remain sendable until their delayed auto-commit is actually
    // staged.
    let send_result = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"hello before selfremove commit"),
        })
        .await
        .unwrap();
    assert!(matches!(send_result, SendResult::ApplicationMessage { .. }));

    advance_selfremove_auto_commit(&mut carol, &group_id).await;

    // Carol now has a projected pending epoch/member set, but the commit is not
    // canonical until its publish obligation is confirmed.
    assert_eq!(carol.epoch(&group_id).unwrap().0, 2);
    let auto = carol.drain_auto_publish();
    assert_eq!(auto.len(), 1, "carol should stage a SelfRemove-only commit");

    // Carol cannot send application data while her SelfRemove-only commit is
    // pending publication.
    let blocked = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"hello after observing a proposal"),
        })
        .await;
    assert!(
        matches!(blocked, Err(EngineError::InvalidTransition(_))),
        "observing a SelfRemove must block outbound app messages until commit publish resolves; got {blocked:?}"
    );

    let auto = auto.into_iter().next().unwrap();
    carol.confirm_published(auto.pending).await.unwrap();
    let send_result = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"after confirm"),
        })
        .await
        .unwrap();
    assert!(matches!(send_result, SendResult::ApplicationMessage { .. }));
}

#[tokio::test]
async fn leave_requires_stable_epoch_state() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create_result) = alice
        .create_group(CreateGroupRequest {
            name: "leave-stable-guard".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create_result {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected group created, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let pending_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();
    assert!(matches!(pending_invite, SendResult::GroupEvolution { .. }));

    let err = alice
        .send(SendIntent::Leave { group_id })
        .await
        .unwrap_err();
    assert!(matches!(err, EngineError::InvalidTransition(_)));
}

#[tokio::test]
async fn selfremove_auto_commit_publish_failed_rolls_back_projection() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "mip03 rollback".into(),
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
        _ => unreachable!(),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    carol.join_welcome(welcome_for_carol).await.unwrap();

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
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..proposal
    };
    alice.ingest(routed).await.unwrap();
    assert!(alice.drain_auto_publish().is_empty());
    advance_selfremove_auto_commit(&mut alice, &group_id).await;

    assert_eq!(alice.epoch(&group_id).unwrap().0, 2);
    assert_eq!(alice.members(&group_id).unwrap().len(), 2);
    let mut auto = alice.drain_auto_publish();
    assert_eq!(auto.len(), 1);

    alice.publish_failed(auto.remove(0).pending).await.unwrap();

    assert_eq!(alice.epoch(&group_id).unwrap().0, 1);
    let members = alice.members(&group_id).unwrap();
    assert_eq!(members.len(), 3, "publish_failed should restore bob");
    let events = alice.drain_events();
    assert!(
        !emits_departure_of(&events, &bob.self_id()),
        "failed auto-publish must not emit a departure; got {events:?}"
    );
}

#[tokio::test]
async fn leave_produces_selfremove_proposal() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
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

    // Bob (non-admin) leaves — should produce SendResult::Proposal, NOT
    // GroupEvolution.
    let res = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    match &res {
        SendResult::Proposal { .. } => {} // expected
        other => panic!("expected Proposal, got {other:?}"),
    }

    // Alice ingests the proposal — classifies as Processed and schedules a
    // delayed SelfRemove-only commit.
    let proposal_msg = match res {
        SendResult::Proposal { msg } => TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        },
        _ => unreachable!(),
    };
    let outcome = alice.ingest(proposal_msg).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Processed));
}

// ── Grep invariant: no non-SelfRemove leave path ────────────────────────────

/// Load-bearing comment: `leave_group_via_self_remove` is the ONLY leave
/// path the engine exposes. This test is effectively a grep guard — if
/// anyone adds `mls_group.leave_group(` anywhere in cgka-engine/, CI should
/// fail. Marmot leave is represented as a SelfRemove proposal, never through
/// OpenMLS's legacy direct leave path.
#[test]
fn no_legacy_leave_group_call_in_engine_source() {
    use std::fs;
    use std::path::PathBuf;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("src");
    for entry in walk(&src) {
        let text = fs::read_to_string(&entry).unwrap();
        for line in text.lines() {
            // Allow the comment that explicitly names the legacy call.
            if line.trim_start().starts_with("//") {
                continue;
            }
            assert!(
                !line.contains(".leave_group("),
                "found legacy leave_group() in {entry:?}: {line}"
            );
        }
    }
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    out
}
