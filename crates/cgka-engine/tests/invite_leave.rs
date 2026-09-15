//! Invite and MIP-03 SelfRemove round trips.

use async_trait::async_trait;
use cgka_engine::canonicalization::ConvergenceStatus;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_engine::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
use cgka_traits::EngineError;
use cgka_traits::app_components::GROUP_ADMIN_POLICY_COMPONENT_ID;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, KeyPackage, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, LocalIngestState, PeeledContent, PeeledMessage};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerStorage, ConvergencePassStorage, GroupStorage, LeaveRequestStorage,
    MessageStorage, OutboundIntentStorage, StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use openmls::component::ComponentData;
use openmls::group::MlsGroup;
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::{
    BasicCredential, LeafNodeParameters, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    ProcessedMessageContent, ProtocolMessage, ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider as _;
use sha2::Digest as _;
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

fn content_id(msg: &TransportMessage) -> MessageId {
    use sha2::{Digest, Sha256};

    MessageId::new(Sha256::digest(&msg.payload).to_vec())
}

fn take_welcome_for(
    welcomes: &mut Vec<TransportMessage>,
    recipient: &MemberId,
) -> TransportMessage {
    let index = welcomes
        .iter()
        .position(|welcome| {
            matches!(
                &welcome.envelope,
                TransportEnvelope::Welcome { recipient: target } if target == recipient
            )
        })
        .expect("welcome for recipient");
    welcomes.remove(index)
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
                created_at: None,
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
        .legacy_compatibility_profile()
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

fn load_group_and_signer(
    storage: &SqliteAccountStorage,
    member: &MemberId,
    group_id: &GroupId,
) -> (MlsGroup, SignatureKeyPair) {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
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
    .expect("MLS signer present");
    (mls_group, signer)
}

fn proposal_transport(message: MlsMessageOut, group_id: &GroupId) -> TransportMessage {
    let payload = message
        .tls_serialize_detached()
        .expect("serialize proposal MLSMessage");
    TransportMessage {
        id: MessageId::new(sha2::Sha256::digest(&payload).to_vec()),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("raw-proposal".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

fn raw_self_remove_proposal(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    aad: &[u8],
) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let (mut group, signer) = load_group_and_signer(storage, sender, group_id);
    group.set_aad(aad.to_vec());
    let message = group
        .leave_group_via_self_remove(&provider, &signer)
        .expect("build SelfRemove proposal");
    proposal_transport(message, group_id)
}

fn raw_self_update_proposal(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let (mut group, signer) = load_group_and_signer(storage, sender, group_id);
    let (message, _) = group
        .propose_self_update(&provider, &signer, LeafNodeParameters::default())
        .expect("build self-update proposal");
    proposal_transport(message, group_id)
}

fn proposal_reference_for(
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
    proposal: &TransportMessage,
) -> Vec<u8> {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load observer group")
        .expect("observer group present");
    let message = MlsMessageIn::tls_deserialize_exact(proposal.payload.as_slice())
        .expect("deserialize proposal");
    let protocol: ProtocolMessage = match message.extract() {
        MlsMessageBodyIn::PrivateMessage(private) => private.into(),
        MlsMessageBodyIn::PublicMessage(public) => public.into(),
        other => panic!("expected handshake message, got {other:?}"),
    };
    let processed = group
        .process_message(&provider, protocol)
        .expect("process proposal");
    let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content() else {
        panic!("expected queued proposal");
    };
    queued
        .proposal_reference_ref()
        .tls_serialize_detached()
        .expect("serialize proposal ref")
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

fn add_proposal_from_member(
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
        .expect("load proposal sender's MLS group")
        .expect("proposal sender joined group");
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
    let (proposal, _) = mls_group
        .propose_add_member(&provider, &signer, &invitee)
        .expect("member can build a standalone Add proposal");
    let payload = proposal
        .tls_serialize_detached()
        .expect("serialize standalone Add proposal");
    TransportMessage {
        id: hash_id(&payload),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("standalone-add".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
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
        .legacy_compatibility_profile()
        .identity(id.to_vec())
        .account_identity_proof_signer(proof_signer(b"raw-identity"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
}

fn converge_buffered_commit(engine: &mut Engine<SqliteAccountStorage>, group_id: &GroupId) {
    let result = engine
        .converge_stored_openmls_messages_at(group_id, 1_000_000)
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
            initial_admins: vec![],
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

/// mdk#1298: inviting a member as admin is one GroupEvolution, one epoch
/// bump, and the invitee is an admin after confirm — not invite then promote.
#[tokio::test]
async fn invite_with_initial_admin_grants_admin_in_the_invite_commit() {
    let mut alice = build_client(b"invite-admin-alice");
    let mut bob = build_client(b"invite-admin-bob");
    let mut carol = build_client(b"invite-admin-carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create_result) = alice
        .create_group(CreateGroupRequest {
            name: "invite-with-admin".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (welcome_for_bob, create_pending) = match create_result {
        SendResult::GroupCreated {
            mut welcomes,
            pending,
        } => (welcomes.remove(0), pending),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();
    bob.join_welcome(welcome_for_bob).await.unwrap();
    let epoch_before_invite = alice.epoch(&group_id).unwrap();
    let alice_admin: [u8; 32] = alice
        .self_id()
        .as_slice()
        .try_into()
        .expect("alice identity is 32 bytes");
    assert_eq!(alice.admin_pubkeys(&group_id).unwrap(), vec![alice_admin]);

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite_result = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![carol.self_id()],
        })
        .await
        .unwrap();
    let (commit, carol_welcome, inv_pending) = match invite_result {
        SendResult::GroupEvolution {
            msg,
            mut welcomes,
            pending,
        } => (msg, welcomes.remove(0), pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    assert_eq!(
        alice.epoch(&group_id).unwrap().0,
        epoch_before_invite.0.saturating_add(1),
        "invite-with-admin must be a single epoch transition"
    );

    alice.confirm_published(inv_pending).await.unwrap();
    let carol_admin: [u8; 32] = carol
        .self_id()
        .as_slice()
        .try_into()
        .expect("carol identity is 32 bytes");
    let mut expected_admins = vec![alice_admin, carol_admin];
    expected_admins.sort();
    let mut alice_admins = alice.admin_pubkeys(&group_id).unwrap();
    alice_admins.sort();
    assert_eq!(
        alice_admins, expected_admins,
        "carol must be an admin after the invite commit confirms"
    );
    let events = alice.drain_events();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                cgka_traits::engine::GroupEvent::GroupStateChanged {
                    change: cgka_traits::engine::GroupStateChange::AdminAdded { member },
                    ..
                } if member == &carol.self_id()
            )
        }),
        "confirm should emit AdminAdded for the invited admin; events: {events:?}"
    );

    carol.join_welcome(carol_welcome).await.unwrap();
    let mut carol_admins = carol.admin_pubkeys(&group_id).unwrap();
    carol_admins.sort();
    assert_eq!(carol_admins, expected_admins);

    let routed_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit
    };
    let outcome = bob.ingest(routed_commit).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    converge_buffered_commit(&mut bob, &group_id);
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap()
    );
    let mut bob_admins = bob.admin_pubkeys(&group_id).unwrap();
    bob_admins.sort();
    assert_eq!(bob_admins, expected_admins);
    assert_eq!(alice.members(&group_id).unwrap().len(), 3);
    assert_eq!(bob.members(&group_id).unwrap().len(), 3);
    assert_eq!(carol.members(&group_id).unwrap().len(), 3);
}

#[tokio::test]
async fn invite_rejects_initial_admin_who_is_not_an_invitee() {
    let mut alice = build_client(b"invite-admin-reject-alice");
    let mut bob = build_client(b"invite-admin-reject-bob");
    let mut carol = build_client(b"invite-admin-reject-carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create_result) = alice
        .create_group(CreateGroupRequest {
            name: "invite-admin-reject".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create_result {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let err = alice
        .send(SendIntent::Invite {
            group_id,
            key_packages: vec![carol_kp],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .expect_err("existing member who is not an invitee cannot be an invite initial admin");
    assert!(
        matches!(err, EngineError::Other(ref message) if message.contains("invited members")),
        "expected invited-members coupling error, got {err:?}"
    );
}

#[tokio::test]
async fn strict_cutover_rejects_inbound_adds_to_legacy_groups_during_convergence() {
    let mut alice = build_client(b"strict-inbound-alice");
    let (mut bob, bob_storage) = build_with_storage(b"strict-inbound-bob");
    let mut carol = build_client(b"strict-inbound-carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "frozen legacy membership".into(),
            description: String::new(),
            members: vec![bob_kp],
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
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome).await.unwrap();
    drop(bob);

    let mut bob = EngineBuilder::new(bob_storage)
        .identity(pad32(b"strict-inbound-bob"))
        .account_identity_proof_signer(proof_signer(b"strict-inbound-bob"))
        .feature_registry(selfremove_registry())
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    bob.hydrate_all_stored_groups().unwrap();
    assert_eq!(
        bob.group_record(&group_id).unwrap().protocol_profile,
        ProtocolProfile::Legacy
    );
    let frozen_epoch = bob.epoch(&group_id).unwrap();
    let frozen_members = bob.members(&group_id).unwrap();
    let precursor = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("legacy update before Add".into()),
            description: None,
        })
        .await
        .expect("non-membership changes remain allowed in a legacy group");
    let (precursor_commit, precursor_pending) = match precursor {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected precursor GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(precursor_pending).await.unwrap();

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invited = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (commit, pending) = match invited {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected legacy GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let routed_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit
    };
    let outcome = bob.ingest(routed_commit).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "expected buffered legacy Add commit, got {outcome:?}"
    );
    let routed_precursor = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..precursor_commit
    };
    let outcome = bob.ingest(routed_precursor).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));

    let convergence = bob
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("strict cutover should reject the branch without failing convergence");
    assert_eq!(convergence.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        bob.epoch(&group_id).unwrap().0,
        frozen_epoch.0.saturating_add(1)
    );
    assert_eq!(bob.members(&group_id).unwrap(), frozen_members);
    assert!(
        convergence
            .dropped_messages
            .iter()
            .any(|drop| {
                drop.kind == cgka_engine::canonicalization::MessageKind::Commit
                    && drop.reason
                        == cgka_engine::canonicalization::DroppedMessageReason::InvalidAgainstCandidateState
            }),
        "legacy Add commit must be terminally rejected: {convergence:?}"
    );
}

#[tokio::test]
async fn strict_cutover_add_replay_retires_raw_and_content_rows() {
    let (mut alice, alice_storage) = build_with_storage(b"strict-replay-alice");
    let (mut bob, bob_storage) = build_with_storage(b"strict-replay-bob");
    let mut carol = build_client(b"strict-replay-carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "frozen replay membership".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id().clone()],
        })
        .await
        .unwrap();
    let (welcome, create_pending) = match created {
        SendResult::GroupCreated {
            mut welcomes,
            pending,
        } => (welcomes.remove(0), pending),
        other => panic!("expected legacy GroupCreated, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();
    bob.join_welcome(welcome).await.unwrap();
    drop(bob);

    let mut bob = EngineBuilder::new(bob_storage.clone())
        .identity(pad32(b"strict-replay-bob"))
        .account_identity_proof_signer(proof_signer(b"strict-replay-bob"))
        .feature_registry(selfremove_registry())
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    bob.hydrate_all_stored_groups().unwrap();

    let local_pending = match bob
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("pending local change".into()),
            description: None,
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected pending non-membership update, got {other:?}"),
    };

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let add_proposal =
        add_proposal_from_member(&alice_storage, &alice.self_id(), &group_id, &carol_kp);
    let raw_id = add_proposal.id.clone();
    let content_id = content_id(&add_proposal);

    let buffered = bob.ingest(add_proposal).await.unwrap();
    assert!(matches!(buffered, IngestOutcome::Buffered { .. }));
    assert_eq!(
        bob_storage.get_message(&raw_id).unwrap().state,
        MessageState::Retryable
    );

    bob.publish_failed(local_pending).await.unwrap();
    assert_eq!(
        bob_storage.get_message(&raw_id).unwrap().state,
        MessageState::Failed,
        "strict-cutover replay must retire the raw transport row"
    );
    assert_eq!(
        bob_storage.get_message(&content_id).unwrap().state,
        MessageState::Failed,
        "strict-cutover replay must terminalize the content-derived row"
    );
    assert_eq!(bob.members(&group_id).unwrap().len(), 2);
}

#[tokio::test]
async fn invite_rejects_invitee_missing_required_capability() {
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut stripped = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .legacy_compatibility_profile()
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

            initial_admins: vec![],
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
            expected_epoch: None,
        })
        .await
        .unwrap();
    let msg = match sent {
        SendResult::ApplicationMessage { msg, .. } => msg,
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
/// instead of failing silently as generic stale traffic.
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
            IngestOutcome::LocalState {
                state: LocalIngestState::Removed
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
        IngestOutcome::LocalState {
            state: LocalIngestState::Removed
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
            expected_epoch: None,
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
                expected_epoch: None,
            },
            created_at_ms: 1,
            reissue_attempts: 0,
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
    let payload = app_payload_for(&bob, b"must not queue after removal");
    let error = bob
        .queue_app_message(group_id.clone(), payload)
        .await
        .expect_err("authoritative removal must reject forced local queueing");
    assert!(
        matches!(
            error,
            EngineError::InvalidTransition(ref transition)
                if transition.from == "Removed"
        ),
        "removed copy should fail through the authoritative gate, got {error:?}"
    );
    assert!(
        bob_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty(),
        "a rejected post-removal send must not recreate queued plaintext"
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
        IngestOutcome::LocalState {
            state: LocalIngestState::Removed
        }
    ));
    assert!(
        bob_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty(),
        "realization must discard queued outbound intents"
    );

    // Convergence-only defense in depth: an intent queued after the copy is
    // already marked removed (any ordering the marker-site purges missed) is
    // discarded before protocol settlement can touch the removed copy.
    queue_app_message_intent(&bob_storage, &bob, &group_id, 0x53);
    assert!(
        !bob.advance_convergence_inputs(&group_id)
            .await
            .expect("convergence-only advance on a removed copy must not error")
    );
    assert!(
        bob_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty(),
        "convergence-only advance must discard queued intents for a removed copy"
    );

    // The ordinary drain retains the same defense.
    queue_app_message_intent(&bob_storage, &bob, &group_id, 0x54);
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
                IngestOutcome::LocalState {
                    state: LocalIngestState::Removed
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
            IngestOutcome::LocalState {
                state: LocalIngestState::Removed
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
            initial_admins: vec![],
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

/// A delayed Welcome can install an apparently active local view after the
/// rest of the group has already removed that identity. A fresh re-add Welcome
/// must wait for the trusted removal commit instead of replacing active state
/// based on its uncorroborated epoch, and an older Welcome must never downgrade
/// an already-current client.
#[tokio::test]
async fn readd_welcome_waits_for_trusted_removal_across_pending_publish_restart() {
    let mut alice = build_client(b"alice-stale-welcome");
    let mut bob = build_client(b"bob-stale-welcome");
    let (mut carol, carol_storage) = build_with_storage(b"carol-stale-welcome");
    let mut david = build_client(b"david-stale-welcome");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "stale Welcome re-entry".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let bob_welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(bob_welcome).await.unwrap();

    // Alice adds Carol and David at epoch 2, but both Welcomes are delayed.
    let carol_id = carol.self_id().clone();
    let david_id = david.self_id().clone();
    let initial_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![
                carol.fresh_key_package().await.unwrap(),
                david.fresh_key_package().await.unwrap(),
            ],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (initial_pending, mut stale_welcomes) = match initial_invite {
        SendResult::GroupEvolution {
            pending, welcomes, ..
        } => (pending, welcomes),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(initial_pending).await.unwrap();
    let stale_carol_welcome = take_welcome_for(&mut stale_welcomes, &carol_id);
    let stale_david_welcome = take_welcome_for(&mut stale_welcomes, &david_id);
    assert_eq!(alice.epoch(&group_id).unwrap().0, 2);

    // The canonical group removes both identities at epoch 3 before either
    // delayed Welcome is delivered.
    let remove = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![carol_id.clone(), david_id.clone()],
        })
        .await
        .unwrap();
    let (remove_commit, remove_pending) = match remove {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(remove_pending).await.unwrap();
    assert_eq!(alice.epoch(&group_id).unwrap().0, 3);

    // Carol now accepts the delayed epoch-2 Welcome. Her local record says
    // she is active even though the canonical group removed her at epoch 3.
    carol.join_welcome(stale_carol_welcome).await.unwrap();
    assert_eq!(carol.epoch(&group_id).unwrap().0, 2);
    // A legitimate re-add advances the canonical group to epoch 4. Its epoch
    // alone cannot prove that it descends from Carol's trusted local branch.
    let readd = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![
                carol.fresh_key_package().await.unwrap(),
                david.fresh_key_package().await.unwrap(),
            ],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (readd_pending, mut fresh_welcomes) = match readd {
        SendResult::GroupEvolution {
            pending, welcomes, ..
        } => (pending, welcomes),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(readd_pending).await.unwrap();
    let fresh_carol_welcome = take_welcome_for(&mut fresh_welcomes, &carol_id);
    let fresh_david_welcome = take_welcome_for(&mut fresh_welcomes, &david_id);

    // Carol can still stage work against her stale active view. Drop the engine
    // with that publication unresolved, then rebuild without hydration to pin
    // the cold-start path: the durable active record must close the replacement
    // window even while the epoch manager is empty.
    let held_update = carol
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let _held_pending = match held_update {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let stale_record = carol_storage.get_group(&group_id).unwrap();
    drop(carol);
    let mut carol = build_client_on_storage(b"carol-stale-welcome", carol_storage.clone());
    assert!(
        load_group_and_signer(&carol_storage, &carol.self_id(), &group_id)
            .0
            .pending_commit()
            .is_some(),
        "the staged self-update must survive restart before hydration"
    );

    let cold_start_error = carol
        .join_welcome(fresh_carol_welcome.clone())
        .await
        .expect_err("an unhydrated restart must not replace active state");
    assert!(matches!(
        cold_start_error,
        EngineError::InvalidTransition(ref error)
            if error.from == "ActiveMember" && error.to == "JoinWelcome"
    ));
    assert_eq!(
        carol_storage.get_group(&group_id).unwrap(),
        stale_record,
        "cold-start refusal must leave the durable active view intact"
    );
    assert!(
        load_group_and_signer(&carol_storage, &carol.self_id(), &group_id)
            .0
            .pending_commit()
            .is_some(),
        "cold-start refusal must not orphan or discard the pending commit"
    );

    // Hydration restores the publication obligation. Resolve it, then prove
    // that even Stable active state cannot be replaced without continuity.
    carol.hydrate_all_stored_groups().unwrap();
    let restored = carol.drain_auto_publish();
    assert_eq!(
        restored.len(),
        1,
        "hydrate must restore the staged publication"
    );
    carol.publish_failed(restored[0].pending).await.unwrap();
    assert_eq!(carol.epoch(&group_id).unwrap(), stale_record.epoch);
    let active_error = carol
        .join_welcome(fresh_carol_welcome.clone())
        .await
        .expect_err("a newer epoch is not trusted branch continuity");
    assert!(matches!(
        active_error,
        EngineError::InvalidTransition(ref error)
            if error.from == "ActiveMember" && error.to == "JoinWelcome"
    ));

    assert!(
        cgka_traits::storage::WelcomeStorage::list_welcomes(&carol_storage)
            .unwrap()
            .iter()
            .any(|candidate| candidate.message_id == fresh_carol_welcome.id),
        "a validated replacement must remain available for explicit recipient confirmation"
    );

    // Once Carol processes the removal from her trusted epoch-2 branch, the
    // exact same Welcome is a legitimate retry and installs the epoch-4 rejoin.
    let routed_remove = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..remove_commit
    };
    assert!(matches!(
        carol.ingest(routed_remove).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    converge_buffered_commit(&mut carol, &group_id);
    assert!(
        !carol
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == carol_id),
        "trusted removal must clear Carol's active membership before re-entry"
    );
    // A malformed offer and an unhydratable removed group precede the valid
    // recovery in storage order. Neither may abort the account-wide sweep.
    use cgka_traits::storage::WelcomeStorage;
    let owned_offer = carol_storage.take_welcome(&fresh_carol_welcome.id).unwrap();
    let mut malformed = owned_offer.clone();
    malformed.message_id = cgka_traits::MessageId::new(vec![0xe1; 32]);
    malformed.welcome_bytes = vec![0xff];
    carol_storage.put_welcome(&malformed).unwrap();
    let mut missing_mls_group = carol_storage.get_group(&group_id).unwrap();
    missing_mls_group.id = GroupId::new(vec![0xe2; 16]);
    carol_storage.put_group(&missing_mls_group).unwrap();
    let mut blocked = owned_offer.clone();
    blocked.message_id = cgka_traits::MessageId::new(vec![0xe3; 32]);
    blocked.group_id = missing_mls_group.id.clone();
    carol_storage.put_welcome(&blocked).unwrap();
    carol_storage.put_welcome(&owned_offer).unwrap();
    carol.hydrate_stable_groups_from_storage().unwrap();
    assert!(
        carol.retry_rejoins_after_trusted_removal().await.unwrap(),
        "owned Welcome must recover past bad candidates without another relay delivery"
    );
    let retained_offers = carol_storage.list_welcomes().unwrap();
    assert!(
        !retained_offers
            .iter()
            .any(|offer| offer.message_id == malformed.message_id),
        "undecodable bytes must not poison every later maintenance pass"
    );
    assert!(
        retained_offers
            .iter()
            .any(|offer| offer.message_id == blocked.message_id),
        "an unhydratable group's otherwise valid material stays owned for repair"
    );
    assert!(
        !carol.retry_rejoins_after_trusted_removal().await.unwrap(),
        "an already quarantined group must remain isolated on later sweeps too"
    );
    assert!(matches!(
        carol.join_welcome(fresh_carol_welcome).await,
        Err(EngineError::WelcomeAlreadyProcessed)
    ));
    assert_eq!(carol.epoch(&group_id).unwrap().0, 4);
    assert_eq!(
        carol.members(&group_id).unwrap(),
        alice.members(&group_id).unwrap()
    );

    // David takes the fresh Welcome first. His still-unconsumed epoch-2
    // Welcome is distinct valid MLS material, but cannot replace epoch 4
    // without explicit recipient consent, even though a lower-epoch offer is retained.
    david.join_welcome(fresh_david_welcome).await.unwrap();
    let downgrade_error = david
        .join_welcome(stale_david_welcome)
        .await
        .expect_err("an older Welcome must not downgrade active group state");
    assert!(matches!(downgrade_error, EngineError::InvalidTransition(_)));
    assert_eq!(david.epoch(&group_id).unwrap().0, 4);
    assert_eq!(
        david.members(&group_id).unwrap(),
        alice.members(&group_id).unwrap()
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
            initial_admins: vec![],
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
async fn active_group_rejects_newer_welcome_from_self_promoted_fork() {
    let mut alice = build_client(b"alice-active-replacement");
    let (mut bob, bob_storage) = build_with_storage(b"bob-active-replacement");
    let (mut carol, carol_storage) = build_with_storage(b"carol-active-replacement");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "active replacement rollback".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (bob_welcome, carol_welcome) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            (
                take_welcome_for(&mut welcomes, &bob.self_id()),
                take_welcome_for(&mut welcomes, &carol.self_id()),
            )
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(bob_welcome).await.unwrap();
    carol.join_welcome(carol_welcome).await.unwrap();

    // Alice removes Carol and Bob applies that commit, while Carol deliberately
    // retains her epoch-1 active view. Bob can now fork from that newer state,
    // add Carol, and self-promote in the same commit. The sibling bootstrap test
    // proves this Welcome passes the incoming branch's admin check.
    let remove = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![carol.self_id().clone()],
        })
        .await
        .unwrap();
    let (remove_commit, remove_pending) = match remove {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(remove_pending).await.unwrap();
    let routed_remove = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..remove_commit
    };
    assert!(matches!(
        bob.ingest(routed_remove).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    converge_buffered_commit(&mut bob, &group_id);
    assert_eq!(bob.epoch(&group_id).unwrap().0, 2);
    assert_eq!(carol.epoch(&group_id).unwrap().0, 1);

    let before = carol_storage.get_group(&group_id).unwrap();
    let carol_replacement_kp = carol.fresh_key_package().await.unwrap();
    let forged_admins = encode_admin_policy_for_test(&[
        alice.self_id().as_slice().to_vec(),
        bob.self_id().as_slice().to_vec(),
    ]);
    let unauthorized_newer_welcome = welcome_from_fork_with_self_promoted_admin(
        &bob_storage,
        &bob.self_id(),
        &group_id,
        &carol_replacement_kp,
        forged_admins,
    );

    let error = carol
        .join_welcome(unauthorized_newer_welcome.clone())
        .await
        .expect_err("a newer self-promoted fork must not replace active state");
    assert!(
        matches!(
            error,
            EngineError::InvalidTransition(ref error)
                if error.from == "ActiveMember" && error.to == "JoinWelcome"
        ),
        "expected active-state continuity refusal, got {error:?}"
    );
    assert_eq!(
        carol_storage.get_group(&group_id).unwrap(),
        before,
        "failed replacement must restore the original Marmot group record"
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), before.epoch);
    let offer = carol
        .pending_group_rejoins_for(Some(&group_id))
        .unwrap()
        .remove(0);
    assert_eq!(offer.rejoin.as_ref().unwrap().welcomer, bob.self_id());
    let mut rewrapped = unauthorized_newer_welcome.clone();
    rewrapped.id = cgka_traits::MessageId::new(vec![0x91; 32]);
    assert!(carol.join_welcome(rewrapped.clone()).await.is_err());
    assert_eq!(
        carol
            .pending_group_rejoins_for(Some(&group_id))
            .unwrap()
            .len(),
        1
    );
    carol.decline_group_rejoin(&offer.message_id).unwrap();
    assert!(
        carol
            .pending_group_rejoins_for(Some(&group_id))
            .unwrap()
            .is_empty()
    );
    rewrapped.id = cgka_traits::MessageId::new(vec![0x92; 32]);
    assert!(matches!(
        carol.join_welcome(rewrapped).await,
        Err(EngineError::WelcomeAlreadyProcessed)
    ));
    assert!(
        carol
            .pending_group_rejoins_for(Some(&group_id))
            .unwrap()
            .is_empty()
    );
    let payload = app_payload_for(&carol, b"original state remains usable");
    carol
        .send(SendIntent::AppMessage {
            group_id,
            payload,
            expected_epoch: None,
        })
        .await
        .expect("failed replacement must leave the original live group usable");
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
async fn selfremove_local_selection_uses_lowest_complete_message_digest_after_restart() {
    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let (mut carol, carol_storage) = build_with_storage(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "selfremove digest selection".into(),
            description: String::new(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let mut welcomes = match create {
        SendResult::GroupCreated { pending, welcomes } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcomes.remove(0)).await.unwrap();
    carol.join_welcome(welcomes.remove(0)).await.unwrap();

    // Distinct authenticated-data bytes produce distinct complete serialized
    // handshake MLSMessages carrying the same leaf-scoped SelfRemove.
    let first = raw_self_remove_proposal(&bob_storage, &bob.self_id(), &group_id, b"variant-a");
    let second = raw_self_remove_proposal(&bob_storage, &bob.self_id(), &group_id, b"variant-b");
    assert_ne!(first.payload, second.payload);
    let (lowest, highest) =
        if sha2::Sha256::digest(&first.payload) < sha2::Sha256::digest(&second.payload) {
            (&first, &second)
        } else {
            (&second, &first)
        };
    let expected_ref = proposal_reference_for(&carol_storage, &group_id, lowest);

    // Deliberately ingest the higher digest first. Startup must reconstruct the
    // scheduling edge from durable rows and make the same local choice.
    for proposal in [highest, lowest] {
        assert!(matches!(
            alice.ingest(proposal.clone()).await.unwrap(),
            IngestOutcome::Processed
        ));
    }
    assert!(matches!(
        alice.ingest(highest.clone()).await.unwrap(),
        IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::Duplicate
        }
    ));
    drop(alice);
    let mut alice = build_client_on_storage(b"alice", alice_storage.clone());
    alice.hydrate_all_stored_groups().unwrap();
    advance_selfremove_auto_commit(&mut alice, &group_id).await;

    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, alice_storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let group = MlsGroup::load(provider.storage(), &mls_gid)
        .unwrap()
        .unwrap();
    let staged = group.pending_commit().expect("SelfRemove commit staged");
    let refs: Vec<_> = staged
        .queued_proposals()
        .map(|queued| {
            queued
                .proposal_reference_ref()
                .tls_serialize_detached()
                .unwrap()
        })
        .collect();
    assert_eq!(refs, vec![expected_ref]);
    assert_eq!(alice.drain_auto_publish().len(), 1);
    assert!(
        alice
            .advance_convergence(&group_id)
            .await
            .unwrap()
            .is_empty(),
        "pending local selection must not produce a duplicate commit"
    );
}

#[tokio::test]
async fn non_selected_selfremove_alternative_remains_processable_by_peer_commit() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let mut carol = build_client(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "selfremove alternative retention".into(),
            description: String::new(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let mut welcomes = match create {
        SendResult::GroupCreated { pending, welcomes } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcomes.remove(0)).await.unwrap();
    carol.join_welcome(welcomes.remove(0)).await.unwrap();

    let first = raw_self_remove_proposal(&bob_storage, &bob.self_id(), &group_id, b"variant-a");
    let second = raw_self_remove_proposal(&bob_storage, &bob.self_id(), &group_id, b"variant-b");
    let (lowest, alternative) =
        if sha2::Sha256::digest(&first.payload) < sha2::Sha256::digest(&second.payload) {
            (&first, &second)
        } else {
            (&second, &first)
        };
    assert!(matches!(
        alice.ingest(lowest.clone()).await.unwrap(),
        IngestOutcome::Processed
    ));
    assert!(matches!(
        alice.ingest(alternative.clone()).await.unwrap(),
        IngestOutcome::Processed
    ));

    // Carol sees only the higher-digest alternative and validly references it.
    assert!(matches!(
        carol.ingest(alternative.clone()).await.unwrap(),
        IngestOutcome::Processed
    ));
    advance_selfremove_auto_commit(&mut carol, &group_id).await;
    let mut peer_publish = carol.drain_auto_publish();
    assert_eq!(peer_publish.len(), 1);
    let peer_publish = peer_publish.remove(0);
    let peer_commit = peer_publish.msg.clone();
    carol.confirm_published(peer_publish.pending).await.unwrap();

    // Alice's own local rule would choose `lowest`, but the peer's valid
    // alternative remains retained for proposal-reference replay.
    assert!(matches!(
        alice.ingest(peer_commit).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    converge_buffered_commit(&mut alice, &group_id);
    assert!(
        alice
            .members(&group_id)
            .unwrap()
            .iter()
            .all(|member| member.id != bob.self_id()),
        "peer commit referencing the non-selected alternative must remove bob"
    );
}

#[tokio::test]
async fn multiple_leavers_stage_one_selfremove_only_commit_excluding_unrelated_proposals() {
    let (mut alice, alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let (mut carol, carol_storage) = build_with_storage(b"carol");
    let (mut dave, dave_storage) = build_with_storage(b"dave");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let dave_kp = dave.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "selfremove multiple leaves".into(),
            description: String::new(),
            members: vec![bob_kp, carol_kp, dave_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let mut welcomes = match create {
        SendResult::GroupCreated { pending, welcomes } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcomes.remove(0)).await.unwrap();
    carol.join_welcome(welcomes.remove(0)).await.unwrap();
    dave.join_welcome(welcomes.remove(0)).await.unwrap();

    let unrelated = raw_self_update_proposal(&dave_storage, &dave.self_id(), &group_id);
    let bob_leave = raw_self_remove_proposal(&bob_storage, &bob.self_id(), &group_id, b"bob-leave");
    let carol_leave =
        raw_self_remove_proposal(&carol_storage, &carol.self_id(), &group_id, b"carol-leave");
    for proposal in [unrelated, bob_leave, carol_leave] {
        assert!(matches!(
            alice.ingest(proposal).await.unwrap(),
            IngestOutcome::Processed
        ));
    }
    advance_selfremove_auto_commit(&mut alice, &group_id).await;

    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, alice_storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let group = MlsGroup::load(provider.storage(), &mls_gid)
        .unwrap()
        .unwrap();
    let staged = group.pending_commit().expect("SelfRemove commit staged");
    let proposals: Vec<_> = staged.queued_proposals().collect();
    assert_eq!(proposals.len(), 2);
    assert!(
        proposals
            .iter()
            .all(|queued| matches!(queued.proposal(), Proposal::SelfRemove))
    );
}

#[tokio::test]
async fn selfremove_runtime_deadline_survives_encrypted_reopen_and_clears_after_publish() {
    for reopen in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("alice.sqlite3");
        let key = storage_sqlite::SqlCipherKey::new("synthetic leave deadline key").unwrap();
        let clock = cgka_engine::ManualConvergenceClock::new(1_000, 10_000);
        let build = |storage| {
            EngineBuilder::new(storage)
                .legacy_compatibility_profile()
                .identity(pad32(b"alice"))
                .account_identity_proof_signer(proof_signer(b"alice"))
                .feature_registry(selfremove_registry())
                .peeler(Box::new(MockPeeler))
                .convergence_clock(std::sync::Arc::new(clock.clone()))
                .build()
                .unwrap()
        };
        let mut alice = build(SqliteAccountStorage::open_encrypted(&database, &key).unwrap());
        let mut bob = build_client(b"bob");
        let (group_id, created) = alice
            .create_group(CreateGroupRequest {
                name: "leave deadline".into(),
                description: String::new(),
                members: vec![bob.fresh_key_package().await.unwrap()],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let SendResult::GroupCreated {
            pending,
            mut welcomes,
        } = created
        else {
            panic!("expected group creation");
        };
        alice.confirm_published(pending).await.unwrap();
        bob.join_welcome(welcomes.remove(0)).await.unwrap();
        assert_eq!(
            alice
                .scheduled_self_remove_auto_commit_delay_ms(&group_id)
                .unwrap(),
            None
        );
        let SendResult::Proposal { mut msg } = bob
            .send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("expected SelfRemove proposal");
        };
        msg.envelope = TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        };
        assert_eq!(
            bob.scheduled_self_remove_auto_commit_delay_ms(&group_id)
                .unwrap(),
            None,
            "the leaving device cannot commit its own departure"
        );
        alice.ingest(msg).await.unwrap();
        if reopen {
            // Drop the sole database owner; a clone would not test SQLCipher reopen.
            drop(alice);
            alice = build(SqliteAccountStorage::open_encrypted(&database, &key).unwrap());
            alice.hydrate_all_stored_groups().unwrap();
        }
        assert_eq!(
            alice.drain_pending_convergence_groups(),
            vec![group_id.clone()]
        );
        let delay = alice
            .scheduled_self_remove_auto_commit_delay_ms(&group_id)
            .unwrap()
            .expect("a processed SelfRemove must keep the runtime timer armed");
        assert!((10..=50).contains(&delay));
        clock.advance_ms(delay - 1);
        assert_eq!(
            alice
                .scheduled_self_remove_auto_commit_delay_ms(&group_id)
                .unwrap(),
            Some(1)
        );
        clock.advance_ms(1);
        assert_eq!(
            alice
                .scheduled_self_remove_auto_commit_delay_ms(&group_id)
                .unwrap(),
            Some(0)
        );
        alice.advance_convergence(&group_id).await.unwrap();
        let mut publications = alice.drain_auto_publish();
        assert_eq!(publications.len(), 1);
        assert_eq!(
            alice
                .scheduled_self_remove_auto_commit_delay_ms(&group_id)
                .unwrap(),
            None,
            "a staged auto-commit now awaits publication, not another lifecycle wakeup"
        );
        alice
            .confirm_published(publications.remove(0).pending)
            .await
            .unwrap();
        assert_eq!(alice.members(&group_id).unwrap().len(), 1);
        assert_eq!(
            alice
                .scheduled_self_remove_auto_commit_delay_ms(&group_id)
                .unwrap(),
            None
        );
    }
}

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
            expected_epoch: None,
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
    // Stable/applied yet. New sends wait for publish confirmation — retained,
    // not refused: `PendingPublish` owes its exit to a publish outcome, and a
    // relay that stalls that outcome must not make alice's message vanish.
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
            expected_epoch: None,
        })
        .await;
    assert!(
        matches!(pending_send, Ok(SendResult::Queued { .. })),
        "auto-commit leaves alice in PendingPublish, so the app message is retained; got {pending_send:?}"
    );

    // drain_auto_publish yields the commit alice produced.
    let mut auto_msgs = alice.drain_auto_publish();
    assert_eq!(auto_msgs.len(), 1);
    let auto = auto_msgs.remove(0);
    alice.confirm_published(auto.pending).await.unwrap();

    // Confirmation is what releases the retained message, and it is prepared
    // against the epoch the confirm established.
    let mut released = alice.advance_convergence(&group_id).await.unwrap();
    assert_eq!(
        released.len(),
        1,
        "the retained app message should be released once the group is Stable again; got {released:?}"
    );
    assert!(
        matches!(
            released.remove(0),
            SendResult::ApplicationMessage { source_epoch, .. } if source_epoch.0 == 2
        ),
        "the released message must be encrypted under the confirmed epoch"
    );
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
            expected_epoch: None,
        })
        .await;
    assert!(
        matches!(blocked, Err(EngineError::InvalidTransition(_))),
        "leaver must be blocked before restart; got {blocked:?}"
    );

    drop(bob);
    let mut bob = build_client_on_storage(b"bob", bob_storage);
    bob.hydrate_all_stored_groups().unwrap();
    let blocked = bob
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&bob, b"blocked after restart"),
            expected_epoch: None,
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
            expected_epoch: None,
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
            expected_epoch: None,
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
    // Typed, not `InvalidTransition`: a repeat leave is routine user input (a
    // double tap), not the engine bug that `InvalidTransition` denotes, and
    // callers above the engine need the reason by name. Note the contrast with
    // the app send just above, which stays `InvalidTransition` because a blocked
    // ordinary send really is an illegal transition out of the leaving state.
    assert!(
        matches!(
            leave_again,
            Err(EngineError::LeaveAlreadyRequested { group_id: ref g }) if *g == group_id
        ),
        "bob should not duplicate a SelfRemove proposal for the same new epoch; got {leave_again:?}"
    );
}

/// The already-requested verdict is decided inside the engine, under the same
/// lock as the durable read and write, so it cannot be raced past.
///
/// Callers above the engine (`Marmot::leave_group`) precheck a pending flag for
/// fast UX, but that read and the send that follows it are not atomic: two
/// concurrent leaves can both observe "not pending". Whichever one the engine
/// serializes second must still learn the real reason from here, by name, rather
/// than getting an opaque failure. Guards the error contract this exposes to the
/// bindings.
#[tokio::test]
async fn repeat_leave_in_the_same_epoch_is_classified_by_the_engine() {
    let mut alice = build_client(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "leave-classification".into(),
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

    // First leave records the durable request and mints the proposal.
    let first = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await;
    assert!(
        matches!(first, Ok(SendResult::Proposal { .. })),
        "the first leave should mint a SelfRemove proposal; got {first:?}"
    );
    let recorded = bob_storage
        .leave_request(&group_id)
        .unwrap()
        .expect("the first leave records a durable request");
    assert!(
        recorded.last_proposed_epoch.is_some(),
        "the durable request must record the epoch it proposed for"
    );

    // Every subsequent leave in the same epoch is refused by name, repeatably —
    // a host retrying must keep getting the same answer, never an opaque one.
    for attempt in 0..3 {
        let repeat = bob
            .send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await;
        match repeat {
            Err(EngineError::LeaveAlreadyRequested { group_id: ref got }) => {
                assert_eq!(*got, group_id, "the error must name the group it refused")
            }
            other => {
                panic!("repeat leave {attempt} must be typed as already-requested; got {other:?}")
            }
        }
    }

    // Refusing a duplicate must not disturb the durable request it protects.
    assert_eq!(
        bob_storage.leave_request(&group_id).unwrap(),
        Some(recorded),
        "refused duplicates must leave the durable request byte-identical"
    );
}

/// A remaining member that observes a peer SelfRemove proposal schedules its
/// own SelfRemove-only commit. The observer remains sendable until the delayed
/// commit is staged; after staging, publish-before-apply blocks new sends.
#[tokio::test]
async fn observed_selfremove_proposal_delays_commit_then_retains_outbound_app_messages() {
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
            expected_epoch: None,
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

    // Carol cannot *publish* application data while her SelfRemove-only commit
    // is pending publication, but the payload is retained rather than refused:
    // she observed someone else's departure, and that must not cost her the
    // message she is typing.
    let retained = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"hello after observing a proposal"),
            expected_epoch: None,
        })
        .await;
    assert!(
        matches!(retained, Ok(SendResult::Queued { .. })),
        "observing a SelfRemove must retain outbound app messages until commit publish resolves; got {retained:?}"
    );

    let auto = auto.into_iter().next().unwrap();
    carol.confirm_published(auto.pending).await.unwrap();

    // Resolving the publish releases the retained payload.
    let released = carol.advance_convergence(&group_id).await.unwrap();
    assert!(
        matches!(released.as_slice(), [SendResult::ApplicationMessage { .. }]),
        "the retained message should be released after confirm; got {released:?}"
    );

    let send_result = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"after confirm"),
            expected_epoch: None,
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
            initial_admins: vec![],
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

    advance_selfremove_auto_commit(&mut alice, &group_id).await;
    assert_eq!(
        alice.drain_auto_publish().len(),
        1,
        "publish failure must leave the retained SelfRemove eligible for retry"
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

#[tokio::test]
async fn forgotten_group_rejects_welcome_without_authenticated_creation_time() {
    let mut alice = build_client(b"alice");
    let (mut bob, storage) = build_with_storage(b"bob");
    let key_package = bob.fresh_key_package().await.unwrap();
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "missing invitation time".into(),
            description: String::new(),
            members: vec![key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated {
        pending,
        mut welcomes,
    } = created
    else {
        panic!("group creation");
    };
    alice.confirm_published(pending).await.unwrap();
    assert!(bob.forget_group_local(&group_id).unwrap());
    let cutoff = storage.group_local_reset_cutoff(&group_id).unwrap();
    let mut welcome = welcomes.remove(0);
    // The mock transport supplies no authenticated inner time. A later outer
    // time must not substitute for it, even though the MLS Welcome is valid.
    welcome.timestamp = Timestamp(u64::MAX);
    assert!(matches!(
        bob.join_welcome(welcome).await,
        Err(cgka_traits::EngineError::InvalidWelcome)
    ));
    assert!(storage.is_group_forgotten(&group_id).unwrap());
    assert_eq!(storage.group_local_reset_cutoff(&group_id).unwrap(), cutoff);
    assert!(storage.list_groups().unwrap().is_empty());
    assert!(bob.drain_events().is_empty());
}

/// A removed copy retains inbound traffic, bounded by the ring.
///
/// #1840's objection was to UNBOUNDED growth: the pre-#1840 `!is_active()` arm
/// wrote one `Failed` row per post-removal message, which under sustained
/// traffic is storage growth with no ceiling for a group this device left. The
/// answer is a ceiling, not amnesia — each message still reports `Removed` and
/// is retained for the re-join, and the ledger never passes
/// `MAX_RETAINED_ROWS_PER_REMOVED_GROUP` raw rows.
#[tokio::test]
async fn removed_copy_ingest_stays_removed_and_retains_within_the_ring_bound() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-no-ledger-growth").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();
    assert!(
        bob_storage.get_group(&group_id).unwrap().removed,
        "precondition: the copy is realized removed"
    );

    let rows_before = bob_storage
        .list_messages(&group_id, cgka_traits::EpochId(0))
        .unwrap()
        .len();

    for round in 0..4u8 {
        let routed_app =
            post_eviction_app_message(&mut alice, &group_id, format!("flood-{round}").as_bytes())
                .await;
        let outcome = bob.ingest(routed_app).await.unwrap();
        assert!(
            matches!(
                outcome,
                IngestOutcome::LocalState {
                    state: LocalIngestState::Removed
                }
            ),
            "round {round}: a removed copy reports Removed; got {outcome:?}"
        );
    }

    let rows_after = bob_storage
        .list_messages(&group_id, cgka_traits::EpochId(0))
        .unwrap()
        .len();
    assert_eq!(
        rows_after,
        rows_before + 4,
        "each refused message is retained for the re-join, exactly once"
    );
    assert_eq!(
        retained_raw_rows(&bob_storage, &group_id),
        4,
        "all four are raw rows retained for the re-join; the ceiling that keeps \
         this a ring rather than a ledger that grows is pinned by \
         `the_removed_copys_retained_rows_are_a_newest_wins_ring`"
    );
}

/// The gate is on the durable record, not on OpenMLS liveness.
///
/// A copy whose record says removed while its OpenMLS state is still active is
/// pathological — a crash between the marker write and the MLS advance, or a
/// removal realized through convergence — but it is exactly the shape that
/// must not fall through to the peel and apply group state the record says this
/// device has no part in. The record is the terminal fact the send gates
/// already read; ingest reads it the same way, and the input joins the ring
/// rather than the group.
#[tokio::test]
async fn removed_record_with_live_mls_state_is_refused_and_retained() {
    let (mut alice, mut bob, bob_storage, group_id, _undelivered_commit) =
        setup_removed_member(b"evict-record-only").await;

    // Bob never applies the removal commit, so his OpenMLS copy stays active;
    // only the durable record carries the terminal marker.
    let mut record = bob_storage.get_group(&group_id).unwrap();
    assert!(!record.removed, "precondition: not yet marked");
    record.removed = true;
    bob_storage.put_group(&record).unwrap();

    let rows_before = bob_storage
        .list_messages(&group_id, cgka_traits::EpochId(0))
        .unwrap()
        .len();

    let routed_app = post_eviction_app_message(&mut alice, &group_id, b"record-only").await;
    let outcome = bob.ingest(routed_app.clone()).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::LocalState {
                state: LocalIngestState::Removed
            }
        ),
        "a removed record is terminal for ingest whatever OpenMLS still holds; got {outcome:?}"
    );
    assert_eq!(
        bob_storage
            .list_messages(&group_id, cgka_traits::EpochId(0))
            .unwrap()
            .len(),
        rows_before + 1,
        "the record gate retains the refused input, and only once"
    );
    assert_eq!(
        bob_storage.get_message(&routed_app.id).unwrap().state,
        MessageState::Retryable,
        "retained in the state the re-join's replay admits"
    );
}

/// A redelivery after the re-join is a duplicate of a message already applied.
///
/// #1840 left the refused id no durable trace so that an eventual relay
/// redelivery would not be answered `Duplicate`. Nothing re-fetches such an id
/// in production, so that hope was never collected on; retention pays the debt
/// directly, from the copy the device already holds. The redelivery, if it ever
/// comes, is then a duplicate in the honest sense — the message is APPLIED, the
/// device is already converged, and the second copy changes nothing.
#[tokio::test]
async fn a_redelivered_refused_commit_duplicates_one_the_rejoin_already_applied() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-rejoin-redelivery").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();
    assert!(bob_storage.get_group(&group_id).unwrap().removed);

    // The admin re-adds bob, and the group keeps committing: this one races
    // ahead of the Welcome.
    let (rejoin_welcome, routed_later) =
        readd_bob_then_commit_ahead_of_the_welcome(&mut alice, &mut bob, &group_id).await;

    // It reaches bob while he is still removed: refused, and retained.
    let outcome = bob.ingest(routed_later.clone()).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::LocalState {
                state: LocalIngestState::Removed
            }
        ),
        "a commit arriving before the Welcome is refused on the record; got {outcome:?}"
    );

    // The Welcome lands and the copy is live again; its own replay applies the
    // retained commit.
    bob.join_welcome(rejoin_welcome).await.unwrap();
    bob.drain_events();
    converge_buffered_commit(&mut bob, &group_id);

    // Reopen over the same storage before the redelivery. Without this the
    // in-process caches alone could carry the assertions; the claim under test
    // is about what the refusal and the replay wrote durably, so the durable
    // state must be the only thing left to answer it.
    drop(bob);
    let mut bob = build_client_on_storage(b"bob", bob_storage.clone());
    bob.hydrate_all_stored_groups().unwrap();
    bob.drain_events();
    let converged = alice.epoch(&group_id).unwrap();
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        converged,
        "the join's replay already applied the retained commit"
    );

    // The relay eventually redelivers that exact id. It is now a duplicate in
    // the honest sense, and it moves nothing.
    let outcome = bob.ingest(routed_later).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Ignored {
                category: cgka_traits::ingest::InputRejectionCategory::Duplicate
            }
        ),
        "a redelivery of an applied message is a duplicate; got {outcome:?}"
    );
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        converged,
        "and it leaves the converged copy exactly where the join left it"
    );
}
/// The re-join replays what the removed copy refused — no relay involved.
///
/// The bytes already reached this device: retaining them is the only thing
/// that makes the catch-up independent of the relay. Nothing re-fetches a
/// refused id in production — the relay SDK marks an event seen on first
/// arrival whatever the engine answered, the app's backfill is unfloored, the
/// transport cursor is account-wide and advances anyway, and the join arms no
/// fetch — so a commit published between the re-add Welcome's minting and its
/// arrival is this device's only copy. `do_join_welcome`'s
/// `replay_buffered_messages` must apply it from storage alone.
#[tokio::test]
async fn a_commit_refused_while_removed_is_replayed_by_the_rejoin_without_redelivery() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-retain-replay").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();
    assert!(bob_storage.get_group(&group_id).unwrap().removed);

    let (rejoin_welcome, routed_later) =
        readd_bob_then_commit_ahead_of_the_welcome(&mut alice, &mut bob, &group_id).await;

    // The raced-ahead commit reaches bob while he is still removed.
    let outcome = bob.ingest(routed_later).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::LocalState {
                state: LocalIngestState::Removed
            }
        ),
        "a commit arriving before the Welcome is refused on the record; got {outcome:?}"
    );

    // Restart over the same storage before the Welcome: durable state is the
    // only thing that can carry the raced commit across, and the in-process
    // caches must not be able to stand in for it.
    drop(bob);
    let mut bob = build_client_on_storage(b"bob", bob_storage.clone());
    bob.hydrate_all_stored_groups().unwrap();
    bob.drain_events();

    // The Welcome lands. Nothing is redelivered, ever.
    bob.join_welcome(rejoin_welcome).await.unwrap();
    bob.drain_events();
    converge_buffered_commit(&mut bob, &group_id);

    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap(),
        "the join's replay must apply the retained commit: a re-added device \
         has no re-fetch to fall back on"
    );
}

/// The message that REALIZES the removal is retained on the same terms.
///
/// It is the first post-removal message on a copy the marker has not reached
/// yet, and the likeliest shape for it is exactly the commit that raced ahead
/// of a re-add Welcome. Refusing it without a row would lose it outright: the
/// realizing arm is reached once per copy, so nothing brings it back.
#[tokio::test]
async fn the_commit_that_realizes_the_removal_is_replayed_by_the_rejoin() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-retain-realizing").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    // The silent-eviction shape: OpenMLS records the eviction, the durable
    // record does not, so the next message reaches the realizing arm rather
    // than the record gate.
    let mut record = bob_storage.get_group(&group_id).unwrap();
    record.removed = false;
    record.members = vec![cgka_traits::group::Member {
        id: bob.self_id(),
        credential: bob.self_id().as_slice().to_vec(),
    }];
    bob_storage.put_group(&record).unwrap();

    let (rejoin_welcome, routed_later) =
        readd_bob_then_commit_ahead_of_the_welcome(&mut alice, &mut bob, &group_id).await;

    let outcome = bob.ingest(routed_later).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::LocalState {
                state: LocalIngestState::Removed
            }
        ),
        "the realizing message still classifies Removed; got {outcome:?}"
    );
    assert!(
        bob_storage.get_group(&group_id).unwrap().removed,
        "the realization obligation is unchanged: the copy is marked removed"
    );

    drop(bob);
    let mut bob = build_client_on_storage(b"bob", bob_storage.clone());
    bob.hydrate_all_stored_groups().unwrap();
    bob.drain_events();

    bob.join_welcome(rejoin_welcome).await.unwrap();
    bob.drain_events();
    converge_buffered_commit(&mut bob, &group_id);

    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap(),
        "the realizing arm owes the same retention as the record gate: this \
         commit has no second delivery either"
    );
}

/// A whole raced interval replays, commits and chat alike.
///
/// The realistic shape is not one commit: the group keeps committing AND
/// talking while the re-add Welcome is in flight. Every one of those events
/// reaches the removed copy first, so the retained ring has to carry the chain
/// in order — each commit applying, each application message surfacing once the
/// epoch that seals it lands.
#[tokio::test]
async fn a_raced_interval_of_commits_and_chat_replays_in_full_after_the_rejoin() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-retain-interval").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();
    assert!(bob_storage.get_group(&group_id).unwrap().removed);

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let rejoin_welcome = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![bob_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution {
            mut welcomes,
            pending,
            ..
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };

    // Three commits and, after each, a message sealed under the epoch it
    // opens. All of it races ahead of the Welcome and reaches bob removed.
    const RACED_COMMITS: usize = 3;
    for round in 0..RACED_COMMITS {
        let commit = route_group_commit(
            commit_and_confirm(
                &mut alice,
                SendIntent::SelfUpdate {
                    group_id: group_id.clone(),
                },
            )
            .await,
            &group_id,
        );
        let outcome = bob.ingest(commit).await.unwrap();
        assert!(
            matches!(
                outcome,
                IngestOutcome::LocalState {
                    state: LocalIngestState::Removed
                }
            ),
            "round {round}: raced commit is refused on the record; got {outcome:?}"
        );
        let chat =
            post_eviction_app_message(&mut alice, &group_id, format!("raced-{round}").as_bytes())
                .await;
        let outcome = bob.ingest(chat).await.unwrap();
        assert!(
            matches!(
                outcome,
                IngestOutcome::LocalState {
                    state: LocalIngestState::Removed
                }
            ),
            "round {round}: raced chat is refused on the record; got {outcome:?}"
        );
    }

    // The Welcome lands. Nothing is redelivered.
    bob.join_welcome(rejoin_welcome).await.unwrap();
    bob.drain_events();

    let target = alice.epoch(&group_id).unwrap();
    let mut received = 0usize;
    for round in 1..=8u64 {
        bob.converge_stored_openmls_messages_at(&group_id, round * 1_000_000)
            .expect("a replayed ring must not fail a pass");
        received += bob
            .drain_events()
            .into_iter()
            .filter(|event| {
                matches!(
                    event,
                    cgka_traits::engine::GroupEvent::MessageReceived { group_id: id, .. }
                        if *id == group_id
                )
            })
            .count();
        if bob.epoch(&group_id).unwrap() == target && received == RACED_COMMITS {
            break;
        }
    }
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        target,
        "every raced commit in the ring must apply"
    );
    assert_eq!(
        received, RACED_COMMITS,
        "and every raced application message must surface behind them"
    );
}

/// Mirrors `message_processor::MAX_RETAINED_ROWS_PER_REMOVED_GROUP`, which is
/// crate-private. A change there is meant to be felt here.
const REMOVED_RING_BOUND: usize = 256;

/// Raw transport rows this group is holding for a later replay.
fn retained_raw_rows(storage: &SqliteAccountStorage, group_id: &GroupId) -> usize {
    storage
        .list_messages_in_states(
            group_id,
            &[MessageState::Retryable],
            cgka_traits::EpochId(0),
        )
        .unwrap()
        .into_iter()
        .filter(|record| {
            StoredMessagePayload::decode(&record.payload)
                .is_ok_and(|payload| payload.as_raw_transport().is_some())
        })
        .count()
}

/// Seed a content-derived `Retryable` row — the shape a retained standalone
/// proposal, or a future-epoch application message the copy cannot decrypt,
/// leaves behind. These survive a removal: only `PeelDeferred` rows are retired
/// when the copy becomes terminal.
fn seed_content_retryable_row(
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
    msg: &TransportMessage,
) {
    let epoch = storage.get_group(group_id).unwrap().epoch;
    storage
        .put_message(&MessageRecord {
            id: msg.id.clone(),
            group_id: group_id.clone(),
            epoch,
            state: MessageState::Retryable,
            payload: StoredMessagePayload::openmls_wire(msg.clone())
                .encode()
                .unwrap(),
            deferred_peel: None,
        })
        .unwrap();
}

/// The ring is a bound on RAW rows, and content rows do not spend its slots.
///
/// A removed copy can hold content-derived `Retryable` rows — retained
/// proposals, undecryptable future-epoch application messages — and the
/// eviction helper must not evict them: they are convergence inputs authored by
/// a seam that authenticated them. Counting them anyway would be the worst of
/// both: every one squeezes raw retention below the bound and makes the next
/// refusal evict a raced commit to make room for a row that is never evicted,
/// and a group whose oldest rows are all content rows would find no
/// candidate at all and grow raw rows without limit — #1840's objection exactly.
#[tokio::test]
async fn content_rows_neither_spend_nor_are_evicted_from_the_removed_ring() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-retain-content").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    // Seeded first, so they are the OLDEST rows in insert order — the position
    // from which a miscounted ring does its damage.
    const CONTENT_ROWS: usize = 3;
    let mut content = Vec::new();
    for index in 0..CONTENT_ROWS {
        let msg =
            post_eviction_app_message(&mut alice, &group_id, format!("content-{index}").as_bytes())
                .await;
        seed_content_retryable_row(&bob_storage, &group_id, &msg);
        content.push(msg);
    }

    let mut raw = Vec::new();
    for index in 0..REMOVED_RING_BOUND + 1 {
        let msg =
            post_eviction_app_message(&mut alice, &group_id, format!("raw-{index}").as_bytes())
                .await;
        bob.ingest(msg.clone()).await.unwrap();
        raw.push(msg);
    }

    assert_eq!(
        retained_raw_rows(&bob_storage, &group_id),
        REMOVED_RING_BOUND,
        "the bound is over raw rows, so content rows must not spend its slots"
    );
    assert!(
        matches!(
            bob_storage.get_message(&raw[0].id),
            Err(cgka_traits::storage::StorageError::NotFound)
        ),
        "the one row past the bound evicts the oldest RAW row; got {:?}",
        bob_storage.get_message(&raw[0].id).map(|row| row.state)
    );
    for msg in raw.iter().skip(1) {
        assert_eq!(
            bob_storage.get_message(&msg.id).unwrap().state,
            MessageState::Retryable,
            "no raw row past the oldest is evicted"
        );
    }
    for msg in &content {
        assert_eq!(
            bob_storage.get_message(&msg.id).unwrap().state,
            MessageState::Retryable,
            "a content-derived row is a convergence input, not the ring's to drop"
        );
    }
}

/// Retention is a newest-wins ring, not a licence to grow.
///
/// #1840's objection stands: a removed copy that kept every refused message
/// would grow the durable ledger without bound for a group this device left.
/// The ring answers it — past the bound the OLDEST row is released, which drops
/// the bytes WITHOUT a terminal deduplication verdict, so the host un-sees the
/// id and a later targeted re-fetch can still recover it.
#[tokio::test]
async fn the_removed_copys_retained_rows_are_a_newest_wins_ring() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-retain-ring").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();
    assert_eq!(
        retained_raw_rows(&bob_storage, &group_id),
        0,
        "precondition: the removed copy starts with an empty ring"
    );

    const OVERFLOW: usize = 4;
    let mut delivered = Vec::new();
    for index in 0..REMOVED_RING_BOUND + OVERFLOW {
        let msg =
            post_eviction_app_message(&mut alice, &group_id, format!("ring-{index}").as_bytes())
                .await;
        bob.ingest(msg.clone()).await.unwrap();
        delivered.push(msg);
    }

    assert_eq!(
        retained_raw_rows(&bob_storage, &group_id),
        REMOVED_RING_BOUND,
        "the ring holds the bound and no more"
    );
    for (index, msg) in delivered.iter().take(OVERFLOW).enumerate() {
        assert!(
            matches!(
                bob_storage.get_message(&msg.id),
                Err(cgka_traits::storage::StorageError::NotFound)
            ),
            "the oldest {OVERFLOW} rows are evicted; row {index} survived as {:?}",
            bob_storage.get_message(&msg.id).map(|row| row.state)
        );
    }
    for msg in delivered.iter().skip(OVERFLOW) {
        assert_eq!(
            bob_storage.get_message(&msg.id).unwrap().state,
            MessageState::Retryable,
            "everything newer than the evicted prefix is still retained"
        );
    }

    // Released, not failed: the host un-sees the id, so redelivery of that
    // exact event is processed rather than discarded as already-decided.
    let evicted = delivered[0].clone();
    let outcome = bob.ingest(evicted).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::LocalState {
                state: LocalIngestState::Removed
            }
        ),
        "an evicted id is un-seen, so redelivery reaches the gate again and is \
         refused-and-retained rather than discarded as a duplicate; got {outcome:?}"
    );
}

/// The re-join drains the ring in one pass — it does not inherit churn.
///
/// Most of a removal interval's traffic predates the re-add Welcome, and the
/// new copy holds no secret that opens it. Those rows must settle on the
/// join's own replay — terminal, or `PeelDeferred` under its bounded residence
/// budget — rather than sitting `Retryable` and being re-peeled by every later
/// publish-cycle replay. And a branch this copy never held must not halt the
/// group the Welcome just repaired.
#[tokio::test]
async fn the_rejoin_settles_the_whole_ring_without_halting_the_repaired_group() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-retain-drain").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    // Pre-Welcome traffic: commits from a branch this copy will never hold,
    // and chat sealed under epochs the replacement copy has no secret for.
    let mut refused = Vec::new();
    for round in 0..3u8 {
        let commit = route_group_commit(
            commit_and_confirm(
                &mut alice,
                SendIntent::SelfUpdate {
                    group_id: group_id.clone(),
                },
            )
            .await,
            &group_id,
        );
        bob.ingest(commit.clone()).await.unwrap();
        refused.push(commit);
        let chat =
            post_eviction_app_message(&mut alice, &group_id, format!("era-{round}").as_bytes())
                .await;
        bob.ingest(chat.clone()).await.unwrap();
        refused.push(chat);
    }
    for msg in &refused {
        assert_eq!(
            bob_storage.get_message(&msg.id).unwrap().state,
            MessageState::Retryable,
            "precondition: the removal interval is retained"
        );
    }

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let rejoin_welcome = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![bob_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution {
            mut welcomes,
            pending,
            ..
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };

    bob.join_welcome(rejoin_welcome).await.unwrap();
    let pass = bob
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();

    for msg in &refused {
        let state = bob_storage.get_message(&msg.id).map(|record| record.state);
        assert!(
            !matches!(state, Ok(MessageState::Retryable)),
            "a replayed row must leave the retry lifecycle on the join's own \
             pass, not be re-peeled forever; got {state:?}"
        );
    }
    let still_pending: Vec<_> = bob_storage
        .list_messages_in_states(
            &group_id,
            &[MessageState::Retryable, MessageState::ConvergenceDeferred],
            cgka_traits::EpochId(0),
        )
        .unwrap()
        .iter()
        .map(|record| (record.epoch, record.state))
        .collect();
    assert!(
        still_pending.is_empty(),
        "group-wide: the join's pass must leave no row of the removal interval \
         in a retry or parked state, raw or content-derived; got {still_pending:?}"
    );
    assert!(
        pass.errors.is_empty(),
        "no pass should be asked to reconstruct a branch this copy never held; \
         got {:?}",
        pass.errors
    );
    assert!(
        !bob_storage.get_group(&group_id).unwrap().unrecoverable,
        "a replayed removal interval must not halt the group the Welcome repaired"
    );
    let events = bob.drain_events();
    assert!(
        !events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupUnrecoverable { .. }
        )),
        "got {events:?}"
    );
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap(),
        "and the re-joined copy stays converged"
    );
}

/// Redelivery of a RETAINED id answers `Buffered`, and changes nothing.
///
/// A retained raw row is `Retryable`, and `recorded_message_outcome` maps that
/// to `Buffered` before ingest ever reads the group record — deliberately, so
/// the hot dedup seam does no per-group lookup. So the second copy of a refused
/// message never reaches the gate, and the outcome the host sees is `Buffered`
/// rather than `LocalState { Removed }`. The visible contract changed with
/// retention; what must not change is the durable state.
#[tokio::test]
async fn redelivery_of_a_retained_id_answers_buffered_and_moves_nothing() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-retain-redeliver").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    let routed_app = post_eviction_app_message(&mut alice, &group_id, b"retained-once").await;
    let first = bob.ingest(routed_app.clone()).await.unwrap();
    assert!(
        matches!(
            first,
            IngestOutcome::LocalState {
                state: LocalIngestState::Removed
            }
        ),
        "the first copy reaches the gate; got {first:?}"
    );
    let rows_after_first = bob_storage
        .list_messages(&group_id, cgka_traits::EpochId(0))
        .unwrap()
        .len();
    let raw_after_first = retained_raw_rows(&bob_storage, &group_id);
    let row_after_first = bob_storage.get_message(&routed_app.id).unwrap();

    let second = bob.ingest(routed_app.clone()).await.unwrap();
    assert!(
        matches!(second, IngestOutcome::Buffered { .. }),
        "the durable dedup seam answers a retained row before the gate is \
         reached; got {second:?}"
    );
    assert_eq!(
        bob_storage
            .list_messages(&group_id, cgka_traits::EpochId(0))
            .unwrap()
            .len(),
        rows_after_first,
        "no duplicate row"
    );
    assert_eq!(
        retained_raw_rows(&bob_storage, &group_id),
        raw_after_first,
        "the ring is unchanged, so a redelivery flood cannot churn it"
    );
    let row_after_second = bob_storage.get_message(&routed_app.id).unwrap();
    assert_eq!(
        (row_after_second.state, row_after_second.epoch),
        (row_after_first.state, row_after_first.epoch),
        "and the retained row is not re-stamped"
    );
}

/// A removal realized mid-replay must not relabel the rows behind it.
///
/// `replay_buffered_messages` retires a replayed row as `Processed` once
/// ingest has classified it. `Processed` is an OpenMLS graph input state and
/// is outside `unresolved_commit_state`, so a row stamped that way is scored
/// as canonical evidence and survives the re-join retirement — for a message
/// this device never applied. When the replay loop realizes our own removal
/// partway through, every row behind it is refused on the record and must keep
/// its retained state instead.
#[tokio::test]
async fn removal_realized_mid_replay_leaves_later_buffered_rows_retained() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-midreplay").await;
    // Settle the replayed removal commit inside the replay loop rather than a
    // wall-clock quiescence window later, so the loop itself crosses the
    // removal boundary the way a slower device does.
    bob.set_convergence_policy(cgka_engine::canonicalization::CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..cgka_engine::canonicalization::CanonicalizationPolicy::default()
    })
    .unwrap();

    // Bob holds a publication, so inbound traffic is retained for replay.
    let bob_pending = match bob
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected GroupEvolution, got {other:?}"),
    };

    let routed_app = post_eviction_app_message(&mut alice, &group_id, b"behind-the-removal").await;
    let removal_id = routed_commit.id.clone();
    let later_id = routed_app.id.clone();

    for msg in [routed_commit, routed_app] {
        let outcome = bob.ingest(msg).await.unwrap();
        assert!(
            matches!(outcome, IngestOutcome::Buffered { .. }),
            "a held publication retains inbound traffic; got {outcome:?}"
        );
    }

    // The publish fails, which replays both retained rows in order.
    bob.publish_failed(bob_pending).await.unwrap();
    assert!(
        bob_storage.get_group(&group_id).unwrap().removed,
        "precondition: the replayed removal commit realized the eviction"
    );

    // The removal commit itself was applied, so its raw wrapper leaves the
    // retry lifecycle; only the row refused behind it keeps its slot.
    let removal = bob_storage.get_message(&removal_id).unwrap();
    assert_eq!(
        removal.state,
        MessageState::Processed,
        "the applied removal commit's raw wrapper must be retired"
    );
    let later = bob_storage.get_message(&later_id).unwrap();
    assert_ne!(
        later.state,
        MessageState::Processed,
        "a row refused on the removed record was never applied and must not be \
         relabelled a canonicalization input"
    );
    assert_eq!(
        later.state,
        MessageState::Retryable,
        "the refused row keeps its retry slot so a re-join replay can process it"
    );
}

/// Realizing the removal retains the message that realized it.
///
/// The realizing arm is the FIRST post-removal message on a copy the marker
/// has not reached yet, and it is the one most likely to be a commit racing
/// ahead of a re-add Welcome — so it owes the record gate's retention, and owes
/// it more: the arm runs once per copy, so a message dropped here has no second
/// chance at all. Retained `Retryable`, not `Failed`:
/// `replay_buffered_messages` admits only `Created | Retryable | PeelDeferred`,
/// and `Failed` answers `Duplicate` on redelivery, so a `Failed` row would lose
/// the message to this device for good.
#[tokio::test]
async fn realizing_the_removal_retains_one_row_for_the_realizing_message() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-realize-no-row").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    // The silent-eviction shape: OpenMLS records the eviction, the durable
    // record does not. The next message reaches the realizing arm.
    let mut record = bob_storage.get_group(&group_id).unwrap();
    record.removed = false;
    record.members = vec![cgka_traits::group::Member {
        id: bob.self_id(),
        credential: bob.self_id().as_slice().to_vec(),
    }];
    bob_storage.put_group(&record).unwrap();

    let rows_before = bob_storage
        .list_messages(&group_id, cgka_traits::EpochId(0))
        .unwrap()
        .len();

    let routed_app = post_eviction_app_message(&mut alice, &group_id, b"realizing").await;
    let outcome = bob.ingest(routed_app.clone()).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::LocalState {
                state: LocalIngestState::Removed
            }
        ),
        "the realizing message still classifies Removed; got {outcome:?}"
    );
    assert!(
        bob_storage.get_group(&group_id).unwrap().removed,
        "the realization obligation is unchanged: the copy is marked removed"
    );
    assert_eq!(
        bob_storage
            .list_messages(&group_id, cgka_traits::EpochId(0))
            .unwrap()
            .len(),
        rows_before + 1,
        "the message that realized the removal is retained, exactly once"
    );
    assert_eq!(
        bob_storage.get_message(&routed_app.id).unwrap().state,
        MessageState::Retryable,
        "and in the state the re-join's replay admits"
    );
}

/// A commit from an epoch below this copy's own history stays out of
/// convergence even while a pass is open.
///
/// The admission gate reads an open pass as licence to admit any in-horizon
/// past-epoch commit, which is right for a rival of a branch this copy could
/// rewind onto. Below the epoch the copy was installed at there is no such
/// branch: retained anchors only ever cover the rewind horizon below the
/// current copy's own tip and never reach beneath its first join, so admitting
/// one hands the pass a candidate whose state it cannot reconstruct. The
/// ordinary past-epoch arm is the whole answer. No re-join here — the plain
/// first-join shape carries the same floor.
#[tokio::test]
async fn commit_below_this_copys_install_epoch_is_refused_while_a_pass_is_open() {
    let mut alice = build_client(b"below-install-alice");
    let mut bob = build_client(b"below-install-bob");
    let (mut carol, carol_storage) = build_with_storage(b"below-install-carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "below-install".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
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
    bob.join_welcome(welcomes.remove(0)).await.unwrap();

    // An in-horizon epoch that exists BEFORE carol is ever invited.
    let below_install = route_group_commit(
        commit_and_confirm(
            &mut alice,
            SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            },
        )
        .await,
        &group_id,
    );

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (carol_welcome, invite_pending) = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution {
            mut welcomes,
            pending,
            ..
        } => (welcomes.remove(0), pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(invite_pending).await.unwrap();
    carol.join_welcome(carol_welcome).await.unwrap();
    carol.drain_events();

    let install_epoch = carol.epoch(&group_id).unwrap();
    let record = carol_storage.get_group(&group_id).unwrap();
    assert_eq!(record.local_copy_install_epoch, install_epoch);
    assert_eq!(record.join_epoch, install_epoch);

    // Open a pass the ordinary way: one commit at carol's own tip, buffered
    // by ingest and deliberately left unconverged.
    let at_the_tip = route_group_commit(
        commit_and_confirm(
            &mut alice,
            SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            },
        )
        .await,
        &group_id,
    );
    assert!(
        matches!(
            carol.ingest(at_the_tip).await.unwrap(),
            IngestOutcome::Buffered { .. }
        ),
        "a commit at the tip opens the pass this test needs"
    );
    let open_pass = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("a pass is open");
    assert!(open_pass.is_active(), "got {:?}", open_pass.phase);

    let outcome = carol.ingest(below_install.clone()).await.unwrap();

    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: cgka_traits::ingest::StaleReason::AlreadyAtEpoch { .. }
            }
        ),
        "a commit from below the install epoch takes the ordinary past-epoch \
         arm, not convergence admission; got {outcome:?}"
    );
    assert!(
        !carol_storage.get_group(&group_id).unwrap().unrecoverable,
        "refusing a commit this copy never had state for must not halt the group"
    );
    let events = carol.drain_events();
    assert!(
        !events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupUnrecoverable { .. }
        )),
        "got {events:?}"
    );
    let live: Vec<_> = carol_storage
        .list_messages_in_states(
            &group_id,
            &[
                MessageState::Created,
                MessageState::Retryable,
                MessageState::PeelDeferred,
                MessageState::ConvergenceDeferred,
            ],
            cgka_traits::EpochId(0),
        )
        .unwrap()
        .into_iter()
        .filter(|record| record.id == content_id(&below_install))
        .map(|record| (record.epoch, record.state))
        .collect();
    assert!(
        live.is_empty(),
        "it must not be left a live canonicalization input steering later \
         passes; got {live:?}"
    );
    let pass_after = carol_storage
        .convergence_pass(&group_id)
        .unwrap()
        .expect("the open pass survives");
    assert_eq!(pass_after.generation, open_pass.generation);
    assert!(pass_after.is_active(), "got {:?}", pass_after.phase);
}

/// Stage one group evolution and confirm it published, returning its commit.
async fn commit_and_confirm(
    engine: &mut Engine<SqliteAccountStorage>,
    intent: SendIntent,
) -> TransportMessage {
    let (msg, pending) = match engine.send(intent).await.unwrap() {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    engine.confirm_published(pending).await.unwrap();
    msg
}

fn route_group_commit(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    }
}

/// A commit from below this local copy's install epoch is not a rival.
///
/// After a re-add, commits the group published during the eviction era are
/// still in flight. They fork from epochs this copy never held, so no rewind
/// target for them exists or ever could — the same fact that lets a
/// replacement Welcome retire the retained commits below its own epoch. The
/// convergence admission gate's missing-anchor alarm is for a gap in the
/// copy's OWN history, and the only thing that used to keep eviction-era
/// commits out of it was `join_epoch` — which a replacement Welcome
/// deliberately records as 0 so prior-interval application messages stay
/// decryptable. So ordinary relay redelivery after a re-add admitted them as
/// rivals of a branch this device can never reconstruct: the pass errors on
/// unavailable candidate state and parks one of them `ConvergenceDeferred`,
/// where it stays a live canonicalization input steering every later pass's
/// rewind target.
#[tokio::test]
async fn eviction_era_commits_redelivered_after_a_rejoin_are_not_rivals() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-era-redelivery").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();
    assert!(bob_storage.get_group(&group_id).unwrap().removed);

    // The group keeps committing while bob is gone. Both land inside the
    // rewind horizon of the epoch he is about to re-join at.
    let mut eviction_era = Vec::new();
    for _ in 0..2 {
        let (msg, pending) = match alice
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap()
        {
            SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
            other => panic!("expected GroupEvolution, got {other:?}"),
        };
        alice.confirm_published(pending).await.unwrap();
        eviction_era.push(TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        });
    }

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (rejoin_welcome, invite_pending) = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![bob_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution {
            mut welcomes,
            pending,
            ..
        } => (welcomes.remove(0), pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(invite_pending).await.unwrap();
    bob.join_welcome(rejoin_welcome).await.unwrap();
    bob.drain_events();

    // The relay finally redelivers the eviction-era commits.
    let mut outcomes = Vec::new();
    for msg in &eviction_era {
        outcomes.push(bob.ingest(msg.clone()).await.unwrap());
    }
    let pass = bob
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();

    assert!(
        !bob_storage.get_group(&group_id).unwrap().unrecoverable,
        "redelivered eviction-era traffic must not halt the group the Welcome repaired"
    );
    let events = bob.drain_events();
    assert!(
        !events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupUnrecoverable { .. }
        )),
        "got {events:?}"
    );
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap(),
        "bob stays converged with the group he was re-added to"
    );
    assert!(
        outcomes.iter().all(|outcome| matches!(
            outcome,
            IngestOutcome::Stale {
                reason: cgka_traits::ingest::StaleReason::AlreadyAtEpoch { .. }
            }
        )),
        "an eviction-era commit falls through to the ordinary past-epoch arm — \
         terminally stale, not a rival awaiting adjudication; got {outcomes:?}"
    );
    assert!(
        pass.errors.is_empty(),
        "no pass should be asked to reconstruct a branch this copy never held; \
         got {:?}",
        pass.errors
    );
    let live: Vec<_> = bob_storage
        .list_messages_in_states(
            &group_id,
            &[
                MessageState::Created,
                MessageState::Retryable,
                MessageState::PeelDeferred,
                MessageState::ConvergenceDeferred,
            ],
            cgka_traits::EpochId(0),
        )
        .unwrap()
        .iter()
        .map(|record| (record.epoch, record.state))
        .collect();
    assert!(
        live.is_empty(),
        "an eviction-era commit must not be left a live canonicalization input \
         steering later passes; got {live:?}"
    );
}

/// Seed a raw transport row exactly as a pre-#1840 build's realizing arm would
/// The pending-work snapshot treats the removed copy's raw ring rows as parked:
/// nothing on this device processes them until a re-add Welcome replays them.
/// A content-derived `Retryable` row on the same copy is different — it is a
/// convergence input the re-join's pass owns and removal never retires it — so
/// it keeps counting as durable work.
#[cfg(feature = "test-conformance-snapshot")]
#[tokio::test]
async fn only_the_removed_copys_raw_ring_rows_are_parked_in_pending_work() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-parked-rows").await;
    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();
    assert!(bob_storage.get_group(&group_id).unwrap().removed);

    for label in [b"raw-one".as_slice(), b"raw-two".as_slice()] {
        let msg = post_eviction_app_message(&mut alice, &group_id, label).await;
        bob.ingest(msg).await.unwrap();
    }
    assert_eq!(retained_raw_rows(&bob_storage, &group_id), 2);
    assert_eq!(
        bob.conformance_pending_work_snapshot(&group_id)
            .unwrap()
            .stored_retryable_messages,
        0,
        "the ring's raw rows are parked for the re-join, not pending work"
    );

    let content = post_eviction_app_message(&mut alice, &group_id, b"content-row").await;
    bob_storage
        .put_message(&MessageRecord {
            id: content.id.clone(),
            group_id: group_id.clone(),
            epoch: bob_storage.get_group(&group_id).unwrap().epoch,
            state: MessageState::Retryable,
            payload: StoredMessagePayload::openmls_wire(content.clone())
                .encode()
                .unwrap(),
            deferred_peel: None,
        })
        .unwrap();
    assert_eq!(
        bob.conformance_pending_work_snapshot(&group_id)
            .unwrap()
            .stored_retryable_messages,
        1,
        "a content-derived row on the removed copy is durable work the re-join's pass owns"
    );
}

/// have written it: `Failed`, stamped with the removed copy's own epoch.
fn seed_legacy_refused_row(
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
    msg: &TransportMessage,
) {
    let epoch = storage.get_group(group_id).unwrap().epoch;
    storage
        .put_message(&MessageRecord {
            id: msg.id.clone(),
            group_id: group_id.clone(),
            epoch,
            state: MessageState::Failed,
            payload: StoredMessagePayload::raw_transport(msg.clone())
                .encode()
                .unwrap(),
            deferred_peel: None,
        })
        .unwrap();
}

/// A re-add Welcome must re-open the rows the eviction era refused, so the
/// join's own replay processes them without waiting on the relay.
///
/// `Failed` on those rows is a verdict on the copy that is being discarded, not
/// on the message. It is in neither `replay_buffered_messages`' replayable set
/// nor `unresolved_commit_state`, so a commit that raced ahead of this Welcome
/// would otherwise be invisible to every later pass and the device would sit
/// behind the group it was just re-added to. No redelivery here: the join alone
/// must catch the copy up.
#[tokio::test]
async fn rejoin_reopens_refused_rows_and_catches_up_without_redelivery() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-rejoin-reopen").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();
    assert!(bob_storage.get_group(&group_id).unwrap().removed);

    let (rejoin_welcome, routed_later) =
        readd_bob_then_commit_ahead_of_the_welcome(&mut alice, &mut bob, &group_id).await;

    // The commit reaches bob while he is still removed. A pre-#1840 build
    // recorded it `Failed`; that row is what this device wakes up holding.
    let outcome = bob.ingest(routed_later.clone()).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::LocalState {
            state: LocalIngestState::Removed
        }
    ));
    seed_legacy_refused_row(&bob_storage, &group_id, &routed_later);

    // The Welcome lands. Nothing else is delivered.
    bob.join_welcome(rejoin_welcome).await.unwrap();
    bob.drain_events();
    converge_buffered_commit(&mut bob, &group_id);

    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap(),
        "the join's own replay must process the refused commit: a re-added \
         device cannot depend on the relay redelivering it"
    );
}

/// Re-add bob, then publish one more commit that races ahead of his Welcome.
/// Returns the Welcome and the raced-ahead commit routed for group ingestion.
async fn readd_bob_then_commit_ahead_of_the_welcome(
    alice: &mut Engine<SqliteAccountStorage>,
    bob: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
) -> (TransportMessage, TransportMessage) {
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (rejoin_welcome, invite_pending) = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![bob_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution {
            mut welcomes,
            pending,
            ..
        } => (welcomes.remove(0), pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(invite_pending).await.unwrap();

    let (later_commit, later_pending) = match alice
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(later_pending).await.unwrap();
    let routed_later = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..later_commit
    };
    (rejoin_welcome, routed_later)
}

/// The re-open is durable, and the device no longer depends on redelivery.
///
/// A device that was removed has usually been restarted since: the legacy
/// `Failed` rows are all it wakes up holding, and its in-memory caches are
/// empty. The join must still catch it up from storage alone — and the relay
/// redelivery that eventually follows must find the message already applied
/// rather than lost.
#[tokio::test]
async fn a_restarted_device_catches_up_from_the_reopened_rows_alone() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-rejoin-redeliver").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    let (rejoin_welcome, routed_later) =
        readd_bob_then_commit_ahead_of_the_welcome(&mut alice, &mut bob, &group_id).await;
    bob.ingest(routed_later.clone()).await.unwrap();
    seed_legacy_refused_row(&bob_storage, &group_id, &routed_later);

    // Restart before the Welcome: durable state is the only thing that can
    // carry the refused commit across.
    drop(bob);
    let mut bob = build_client_on_storage(b"bob", bob_storage.clone());
    bob.hydrate_all_stored_groups().unwrap();
    bob.drain_events();

    bob.join_welcome(rejoin_welcome).await.unwrap();
    bob.drain_events();
    converge_buffered_commit(&mut bob, &group_id);
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap(),
        "a restarted device must catch up from the re-opened rows alone"
    );

    // The relay eventually redelivers. It is a duplicate of a message this
    // device has now APPLIED — the outcome the dead `Failed` row used to fake
    // for a message it had never applied at all.
    let outcome = bob.ingest(routed_later).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Ignored {
                category: cgka_traits::ingest::InputRejectionCategory::Duplicate
            }
        ),
        "got {outcome:?}"
    );
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap(),
        "and it costs nothing: the device stays converged"
    );
}

/// A re-opened row that is genuinely dead must re-terminalize through ordinary
/// ingest, not sit `Retryable` forever.
///
/// The re-open deliberately makes no epoch judgement — a raw row's wire epoch
/// is unreadable without a peel, and its stamped `epoch` column is the
/// discarded copy's — so removed-era traffic the new copy can never apply is
/// re-opened alongside the commit that matters. The cost must be one pass, not
/// a permanently retained row.
#[tokio::test]
async fn a_genuinely_dead_reopened_row_terminalizes_again_after_the_join() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-rejoin-dead-row").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    // An application message from the eviction era: sealed under an epoch the
    // replacement copy never holds, so nothing can ever apply it.
    let dead_app = post_eviction_app_message(&mut alice, &group_id, b"dead-era").await;
    bob.ingest(dead_app.clone()).await.unwrap();
    seed_legacy_refused_row(&bob_storage, &group_id, &dead_app);

    // A row from BELOW the eviction era — the shape a `PeelDeferred` row
    // retired at removal leaves, stamped `EpochId(0)`. The re-open's epoch
    // bound must not reach it.
    let below_era = post_eviction_app_message(&mut alice, &group_id, b"below-era").await;
    bob_storage
        .put_message(&MessageRecord {
            id: below_era.id.clone(),
            group_id: group_id.clone(),
            epoch: cgka_traits::EpochId(0),
            state: MessageState::Failed,
            payload: StoredMessagePayload::raw_transport(below_era.clone())
                .encode()
                .unwrap(),
            deferred_peel: None,
        })
        .unwrap();

    let (rejoin_welcome, routed_later) =
        readd_bob_then_commit_ahead_of_the_welcome(&mut alice, &mut bob, &group_id).await;
    bob.ingest(routed_later.clone()).await.unwrap();
    seed_legacy_refused_row(&bob_storage, &group_id, &routed_later);

    bob.join_welcome(rejoin_welcome).await.unwrap();
    bob.drain_events();
    converge_buffered_commit(&mut bob, &group_id);

    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap(),
        "precondition: the re-open ran and the live commit among these rows applied"
    );
    let state = bob_storage.get_message(&dead_app.id).unwrap().state;
    assert!(
        !matches!(
            state,
            MessageState::Created | MessageState::Retryable | MessageState::PeelDeferred
        ),
        "a dead row must re-terminalize through ordinary ingest rather than \
         stay retained forever; got {state:?}"
    );
    assert_eq!(
        bob_storage.get_message(&below_era.id).unwrap().state,
        MessageState::Failed,
        "a row stamped below the discarded copy's epoch is outside the eviction \
         era the re-open exists for and must be left alone"
    );
}

/// The re-open is bounded to a copy that was actually evicted.
///
/// A replacement Welcome for a copy that was never removed has no eviction era
/// behind it, so its `Failed` rows are genuine verdicts on messages this device
/// really did refuse. Re-opening those would be pure churn: every one of them
/// would be peeled and re-classified on a join that repaired something else.
#[tokio::test]
async fn a_replacement_welcome_for_a_copy_that_was_not_removed_leaves_failed_rows_alone() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-rejoin-not-removed").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    let (rejoin_welcome, routed_later) =
        readd_bob_then_commit_ahead_of_the_welcome(&mut alice, &mut bob, &group_id).await;
    bob.ingest(routed_later.clone()).await.unwrap();
    seed_legacy_refused_row(&bob_storage, &group_id, &routed_later);

    // Same Welcome, same row — but the copy this join discards does not record
    // an eviction, so the join is repairing something other than a removal.
    let mut record = bob_storage.get_group(&group_id).unwrap();
    record.removed = false;
    bob_storage.put_group(&record).unwrap();

    bob.join_welcome(rejoin_welcome).await.unwrap();
    bob.drain_events();

    assert_eq!(
        bob_storage.get_message(&routed_later.id).unwrap().state,
        MessageState::Failed,
        "a replacement Welcome that is not repairing an eviction must leave \
         genuine Failed verdicts alone"
    );
}

/// A re-opened row holding an ETERNAL eviction-era commit is terminal, not a
/// rival.
///
/// The re-open makes no epoch judgement, so a legacy `Failed` row holding a
/// commit the group published while this device was removed is handed back to
/// ingest alongside the one that matters. Below the new copy's install epoch it
/// is not a rival of anything — the same rule that protects plain relay
/// redelivery — so it terminalizes rather than dragging a pass onto state this
/// copy never held.
#[tokio::test]
async fn a_reopened_eviction_era_commit_is_not_treated_as_a_rival() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-rejoin-era-row").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    // A commit the group published while bob was removed, recorded the way a
    // pre-#1840 build recorded every post-removal message.
    let (era_commit, era_pending) = match alice
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(era_pending).await.unwrap();
    let routed_era = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..era_commit
    };
    bob.ingest(routed_era.clone()).await.unwrap();
    seed_legacy_refused_row(&bob_storage, &group_id, &routed_era);

    let (rejoin_welcome, routed_later) =
        readd_bob_then_commit_ahead_of_the_welcome(&mut alice, &mut bob, &group_id).await;
    bob.ingest(routed_later.clone()).await.unwrap();
    seed_legacy_refused_row(&bob_storage, &group_id, &routed_later);

    bob.join_welcome(rejoin_welcome).await.unwrap();
    let events = bob.drain_events();
    let pass = bob
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();

    assert!(
        !bob_storage.get_group(&group_id).unwrap().unrecoverable,
        "a re-opened eviction-era commit must not halt the group the Welcome repaired"
    );
    assert!(
        !events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupUnrecoverable { .. }
        )),
        "got {events:?}"
    );
    assert!(
        pass.errors.is_empty(),
        "no pass should be asked to reconstruct a branch this copy never held; \
         got {:?}",
        pass.errors
    );
    // The RAW wrapper alone proves nothing: on the bug path
    // `buffer_openmls_message_into_convergence` retires it `Processed` and it
    // is the CONTENT row that parks `ConvergenceDeferred`. Assert over every
    // row the group holds instead.
    let live: Vec<_> = bob_storage
        .list_messages_in_states(
            &group_id,
            &[
                MessageState::Created,
                MessageState::Retryable,
                MessageState::PeelDeferred,
                MessageState::ConvergenceDeferred,
            ],
            cgka_traits::EpochId(0),
        )
        .unwrap()
        .iter()
        .map(|record| (record.epoch, record.state))
        .collect();
    assert!(
        live.is_empty(),
        "a re-opened eviction-era commit must not be left a live canonicalization \
         input steering later passes; got {live:?}"
    );
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap(),
        "and the commit that raced ahead of the Welcome still applies"
    );
}

/// Must match `cgka_engine::message_processor::MAX_DEFERRED_ROWS_PER_SWEEP`,
/// the bound the re-open reuses. It is `pub(crate)`, so an integration test
/// cannot name it.
const REOPEN_SWEEP_BOUND: usize = 64;

/// The re-open's bound counts ELIGIBLE rows, not rows inspected.
///
/// Raced-ahead commits apply as a chain: the copy cannot advance past the
/// oldest one it is missing. So if an ineligible `Failed` row — content-derived
/// or undecodable — that happens to sit newer in insert order consumes a slot
/// in the newest-first bound, the row it displaces is the OLDEST raced commit,
/// which is exactly the one the whole chain hangs off. The device then stalls
/// at the epoch the Welcome installed while holding every later commit.
#[tokio::test]
async fn the_reopen_bound_is_not_spent_on_rows_it_cannot_reopen() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-rejoin-bound").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    // The admin re-adds bob...
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let rejoin_welcome = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![bob_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution {
            mut welcomes,
            pending,
            ..
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };

    // ...and exactly the bound's worth of commits race ahead of the Welcome.
    // A pre-#1840 build recorded each one `Failed`, oldest first.
    for _ in 0..REOPEN_SWEEP_BOUND {
        let raced = match alice
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap()
        {
            SendResult::GroupEvolution { msg, pending, .. } => {
                alice.confirm_published(pending).await.unwrap();
                msg
            }
            other => panic!("expected GroupEvolution, got {other:?}"),
        };
        let routed = TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..raced
        };
        bob.ingest(routed.clone()).await.unwrap();
        seed_legacy_refused_row(&bob_storage, &group_id, &routed);
    }

    // One row the re-open can never act on, inserted LAST so it is the newest:
    // a content-derived `Failed` row, the shape the `UseAfterEviction` arm
    // leaves behind.
    let ineligible_id = MessageId::new(vec![0xE1; 32]);
    let ineligible_epoch = bob_storage.get_group(&group_id).unwrap().epoch;
    let ineligible_wire = post_eviction_app_message(&mut alice, &group_id, b"ineligible").await;
    bob_storage
        .put_message(&MessageRecord {
            id: ineligible_id.clone(),
            group_id: group_id.clone(),
            epoch: ineligible_epoch,
            state: MessageState::Failed,
            payload: StoredMessagePayload::openmls_wire(ineligible_wire)
                .encode()
                .unwrap(),
            deferred_peel: None,
        })
        .unwrap();

    bob.join_welcome(rejoin_welcome).await.unwrap();
    bob.drain_events();

    // The re-opened chain applies through convergence a rewind window at a
    // time, and a pass that only re-seeds is a normal beat — so drive a bounded
    // number of passes, stopping once bob reaches alice's epoch, rather than
    // stopping at the first pass that does not advance.
    let target = alice.epoch(&group_id).unwrap();
    for round in 1..=(REOPEN_SWEEP_BOUND as u64 + 4) {
        if bob.epoch(&group_id).unwrap() == target {
            break;
        }
        let _ = bob.converge_stored_openmls_messages_at(&group_id, round * 1_000_000);
    }

    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        alice.epoch(&group_id).unwrap(),
        "an ineligible row must not spend a slot the oldest raced commit needs: \
         without it the whole chain behind it cannot apply"
    );
    assert_eq!(
        bob_storage.get_message(&ineligible_id).unwrap().state,
        MessageState::Failed,
        "the re-open never acts on a content-derived row"
    );
}

/// Rows the bound cannot re-open are RELEASED, not left `Failed`.
///
/// The bound counts rows, not commits, and the removed copy refused both. One
/// raced-ahead commit behind a chatty interval sits outside the newest-`N`
/// window, and `Failed` is a dead end: `recorded_message_outcome` answers
/// `Duplicate` for it, nothing prunes `cgka_messages` on a schedule, and this
/// helper is the only reader of `Failed` rows in the engine — so relay
/// redelivery could never rescue that commit either. Left that way the legacy
/// repair is strictly WORSE than a current build, whose traceless refusal keeps
/// every raced-ahead message redeliverable. Releasing the remainder puts those
/// rows back on exactly that footing.
#[tokio::test]
async fn rows_beyond_the_reopen_bound_are_released_for_redelivery() {
    let (mut alice, mut bob, bob_storage, group_id, routed_commit) =
        setup_removed_member(b"evict-rejoin-release").await;

    bob.ingest(routed_commit).await.unwrap();
    converge_buffered_commit(&mut bob, &group_id);
    bob.drain_events();

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let rejoin_welcome = match alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![bob_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution {
            mut welcomes,
            pending,
            ..
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };

    // One commit races ahead of the Welcome — the row the whole catch-up hangs
    // off — and then the group keeps chatting. A pre-#1840 build recorded every
    // one of them `Failed`, oldest first, so the commit is the OLDEST row and
    // the bound's newest-first window lands entirely on the chatter.
    let raced_commit = route_group_commit(
        commit_and_confirm(
            &mut alice,
            SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            },
        )
        .await,
        &group_id,
    );
    bob.ingest(raced_commit.clone()).await.unwrap();
    seed_legacy_refused_row(&bob_storage, &group_id, &raced_commit);

    for index in 0..REOPEN_SWEEP_BOUND {
        let chatter =
            post_eviction_app_message(&mut alice, &group_id, format!("chatter-{index}").as_bytes())
                .await;
        bob.ingest(chatter.clone()).await.unwrap();
        seed_legacy_refused_row(&bob_storage, &group_id, &chatter);
    }

    // The Welcome lands. Nothing is redelivered yet.
    bob.join_welcome(rejoin_welcome).await.unwrap();
    bob.drain_events();

    assert!(
        matches!(
            bob_storage.get_message(&raced_commit.id),
            Err(cgka_traits::storage::StorageError::NotFound)
        ),
        "a row the bound could not re-open must be released, not left `Failed` \
         where no redelivery can ever reach it; got {:?}",
        bob_storage
            .get_message(&raced_commit.id)
            .map(|row| row.state)
    );

    // The relay redelivers that exact id, which is the whole point of releasing.
    let redelivered = bob.ingest(raced_commit.clone()).await.unwrap();
    assert!(
        !matches!(
            redelivered,
            IngestOutcome::Ignored {
                category: cgka_traits::ingest::InputRejectionCategory::Duplicate
            }
        ),
        "the released id must not answer `Duplicate`; got {redelivered:?}"
    );

    let target = alice.epoch(&group_id).unwrap();
    for round in 1..=8u64 {
        if bob.epoch(&group_id).unwrap() == target {
            break;
        }
        let _ = bob.converge_stored_openmls_messages_at(&group_id, round * 1_000_000);
    }
    assert_eq!(
        bob.epoch(&group_id).unwrap(),
        target,
        "the redelivered commit still applies, so the copy catches up"
    );

    let received = bob
        .drain_events()
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                cgka_traits::engine::GroupEvent::MessageReceived { group_id: id, .. }
                    if *id == group_id
            )
        })
        .count();
    assert_eq!(
        received, REOPEN_SWEEP_BOUND,
        "and the re-opened chatter behind it surfaces once the commit lands"
    );
}
