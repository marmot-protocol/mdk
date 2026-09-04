//! Fork detection and recovery.
//!
//! A concurrent-invite scenario deliberately produces divergent epoch-2
//! histories. The engine should:
//! - Admit the same-epoch rival into distributed convergence via the retained
//!   source-epoch anchor — one route for committers and observers alike
//! - Compare deterministic ordering keys (and valid branch depth) inside the
//!   settled pass
//! - Reorg onto the winning branch and park the loser reconsiderable
//!
//! The tail of this file covers the seam where none of that is possible: an
//! in-horizon rival whose fork-source anchor snapshot is gone. Ingest reaches
//! that state through OpenMLS's `WrongEpoch` framing check, upstream of every
//! signature and membership-tag check, so the rival's claimed source epoch is
//! unauthenticated. Ingest therefore retains and schedules but decides nothing
//! terminal; the durable halt comes from the convergence coordinator's own
//! `MissingRetainedAnchor` verdict.

use async_trait::async_trait;
use cgka_engine::canonicalization::{
    CanonicalizationError, CanonicalizationPolicy, CanonicalizationState, ConvergenceStatus,
};
use cgka_engine::convergence::V1_MAX_REWIND_COMMITS;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::openmls_projection::{
    OpenMlsProjectionError, apply_openmls_canonicalization_result,
    canonicalize_stored_openmls_messages,
};
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_engine::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{
    CgkaEngine, CommitOrderingKey, CommitOrderingPriority, CreateGroupRequest, GroupEvent,
    SendIntent, SendResult,
};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerStorage, ConvergencePassStorage, GroupStorage, MessageStorage,
    StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, MemberId, MessageId};
use openmls::group::MlsGroup;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider as _;
use std::collections::BTreeSet;
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

fn mutate_own_commit_stamp(
    storage: &SqliteAccountStorage,
    message_id: &MessageId,
    mutate: impl FnOnce(&mut cgka_traits::message::OwnCommitConvergenceStamp),
) {
    let mut record = storage.get_message(message_id).unwrap();
    let mut payload = StoredMessagePayload::decode(&record.payload).unwrap();
    match &mut payload {
        StoredMessagePayload::SignedOpenMlsWire {
            stamp: Some(stamp), ..
        }
        | StoredMessagePayload::OwnCommitWire { stamp, .. } => mutate(stamp),
        _ => panic!("expected a stamped own commit"),
    }
    record.payload = payload.encode().unwrap();
    storage.put_message(&record).unwrap();
}

fn own_commit_stamp(
    storage: &SqliteAccountStorage,
    message_id: &MessageId,
) -> cgka_traits::message::OwnCommitConvergenceStamp {
    let record = storage.get_message(message_id).unwrap();
    StoredMessagePayload::decode(&record.payload)
        .unwrap()
        .own_commit_stamp()
        .expect("expected a stamped own commit")
        .clone()
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

fn build_client(id: &[u8]) -> impl CgkaEngine {
    build_client_with_storage(id).0
}

fn build_client_with_storage(id: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    (engine, storage)
}

fn reopen_current_client(id: &[u8], storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    let mut engine = EngineBuilder::new(storage)
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .protocol_profile(ProtocolProfile::Current)
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    engine.hydrate_all_stored_groups().unwrap();
    engine
}

fn reopen_legacy_client(id: &[u8], storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    let mut engine = EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    engine.hydrate_all_stored_groups().unwrap();
    engine
}

fn raw_self_update_commit(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &cgka_traits::types::GroupId,
) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load member MLS group")
        .expect("member has group state");
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

    let commit_bundle = mls_group
        .commit_builder()
        .load_psks(provider.storage())
        .expect("load PSKs")
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .expect("build ordinary self-update commit")
        .stage_commit(&provider)
        .expect("stage ordinary self-update commit");
    let (commit_out, _welcome_opt, _group_info) = commit_bundle.into_contents();
    let commit_bytes = commit_out
        .tls_serialize_detached()
        .expect("serialize ordinary self-update commit");
    mls_group
        .clear_pending_commit(provider.storage())
        .expect("clear generated self-update pending commit");

    TransportMessage {
        id: hash_id(&commit_bytes),
        payload: commit_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("grinding-openmls-self-update".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

#[tokio::test]
async fn concurrent_invites_recover_to_deterministic_winner() {
    // Setup: alice + bob in group at epoch 1. Both at Stable{1}.
    let (mut alice, alice_storage) = build_client_with_storage(b"alice");
    let (mut bob, bob_storage) = build_client_with_storage(b"bob");
    let mut david = build_client(b"david");
    let mut eve = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "fork".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
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

    assert_eq!(alice.epoch(&group_id).unwrap().0, 1);
    assert_eq!(bob.epoch(&group_id).unwrap().0, 1);

    // Concurrent fork: alice and bob both invite someone at epoch 1, neither
    // having seen the other's commit yet.
    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();

    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    // Both now expose the projected epoch 2 while awaiting publish confirm.
    assert_eq!(alice.epoch(&group_id).unwrap().0, 2);
    assert_eq!(bob.epoch(&group_id).unwrap().0, 2);

    // Both confirm publish so they transition Pending → Stable.
    if let SendResult::GroupEvolution { pending, .. } = &alice_invite {
        alice.confirm_published(*pending).await.unwrap();
    }
    if let SendResult::GroupEvolution { pending, .. } = &bob_invite {
        bob.confirm_published(*pending).await.unwrap();
    }

    // Extract both wrapped commit messages so we can compute their authenticated
    // ordering keys up front. Both commits are privileged admin invites, so the
    // non-grindable committer identity chooses the winner before the digest
    // fallback; we orchestrate both recovery paths below.
    let alice_commit = match alice_invite {
        SendResult::GroupEvolution { msg, .. } => msg,
        _ => unreachable!(),
    };
    let bob_commit = match bob_invite {
        SendResult::GroupEvolution { msg, .. } => msg,
        _ => unreachable!(),
    };
    let alice_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(b"alice")),
        &alice_commit.payload,
    );
    let bob_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(b"bob")),
        &bob_commit.payload,
    );
    assert_ne!(alice_key, bob_key, "distinct commits must order distinctly");
    let bob_wins = bob_key < alice_key;

    let route = |msg: TransportMessage| TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    };

    // Loser ingests winner's commit. The rival enters distributed convergence
    // (the committer takes the same route as any observer); once the pass
    // settles, deterministic ordering rolls the loser onto the winner's branch.
    let (winning_invitee, losing_invitee) = if bob_wins {
        assert!(bob_key < alice_key);
        let outcome = alice.ingest(route(bob_commit.clone())).await.unwrap();
        assert!(
            matches!(outcome, IngestOutcome::Buffered { .. }),
            "the rival commit must enter convergence, got {outcome:?}"
        );
        let result = alice
            .converge_stored_openmls_messages_at(&group_id, u64::MAX)
            .expect("the fork settles on the loser");
        assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
        assert_eq!(alice.epoch(&group_id).unwrap().0, 2);
        ("eve", "david")
    } else {
        assert!(alice_key < bob_key);
        let outcome = bob.ingest(route(alice_commit.clone())).await.unwrap();
        assert!(
            matches!(outcome, IngestOutcome::Buffered { .. }),
            "the rival commit must enter convergence, got {outcome:?}"
        );
        let result = bob
            .converge_stored_openmls_messages_at(&group_id, u64::MAX)
            .expect("the fork settles on the loser");
        assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
        assert_eq!(bob.epoch(&group_id).unwrap().0, 2);
        ("david", "eve")
    };

    // Verify the loser's group state now reflects the winner's invitee.
    let loser_members = if bob_wins {
        alice.members(&group_id).unwrap()
    } else {
        bob.members(&group_id).unwrap()
    };
    assert!(
        loser_members
            .iter()
            .any(|m| m.id == MemberId::new(pad32(winning_invitee.as_bytes())))
    );
    assert!(
        !loser_members
            .iter()
            .any(|m| m.id == MemberId::new(pad32(losing_invitee.as_bytes())))
    );

    // Winner ingests loser's commit through the same convergence route. The
    // settled pass must keep the winner on its already-winning branch and park
    // the losing rival reconsiderable.
    let (winner_engine, winner_storage, losing_commit) = if bob_wins {
        (&mut bob, &bob_storage, alice_commit)
    } else {
        (&mut alice, &alice_storage, bob_commit)
    };
    let losing_content_id = {
        use sha2::{Digest, Sha256};
        MessageId::new(Sha256::digest(&losing_commit.payload).to_vec())
    };
    let outcome = winner_engine.ingest(route(losing_commit)).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "the losing rival must enter convergence on the winner too, got {outcome:?}"
    );
    let result = winner_engine
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the fork settles on the winner");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        winner_engine.epoch(&group_id).unwrap().0,
        2,
        "the winner must stay on its own branch"
    );
    let winner_members = winner_engine.members(&group_id).unwrap();
    assert!(
        winner_members
            .iter()
            .any(|m| m.id == MemberId::new(pad32(winning_invitee.as_bytes())))
    );
    assert!(
        !winner_members
            .iter()
            .any(|m| m.id == MemberId::new(pad32(losing_invitee.as_bytes())))
    );
    assert_eq!(
        winner_storage
            .get_message(&losing_content_id)
            .unwrap()
            .state,
        MessageState::ConvergenceDeferred,
        "the losing rival stays parked reconsiderable on the winner"
    );
}

#[tokio::test]
async fn strict_cutover_legacy_add_cannot_displace_valid_fork_incumbent() {
    use cgka_traits::ingest::IngestOutcome;
    use sha2::{Digest, Sha256};

    // Both commits below are privileged, so choose identities that make the
    // forbidden Add sort before the valid incumbent. This pins the exact
    // failure mode: without the materialization-time strict-cutover gate,
    // branch selection would prefer the forbidden Add on the ordering key and
    // roll the valid incumbent back.
    let first = b"strict-fork-first".as_slice();
    let second = b"strict-fork-second".as_slice();
    let (incumbent_id, candidate_id) = if pad32(first) > pad32(second) {
        (first, second)
    } else {
        (second, first)
    };

    let (mut incumbent, incumbent_storage) = build_client_with_storage(incumbent_id);
    let mut candidate = build_client(candidate_id);
    let mut invitee = build_client(b"strict-fork-invitee");

    let candidate_kp = candidate.fresh_key_package().await.unwrap();
    let (group_id, create) = incumbent
        .create_group(CreateGroupRequest {
            name: "strict fork incumbent".into(),
            description: String::new(),
            members: vec![candidate_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![candidate.self_id()],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            incumbent.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected legacy GroupCreated, got {other:?}"),
    };
    candidate.join_welcome(welcome).await.unwrap();

    // Candidate branches from epoch 1 with a legacy Add while legacy fixture
    // generation is still active on its copy.
    let invitee_kp = invitee.fresh_key_package().await.unwrap();
    let legacy_add = match candidate
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![invitee_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, .. } => msg,
        other => panic!("expected legacy Add GroupEvolution, got {other:?}"),
    };

    // Reopen the incumbent under the strict current profile, then publish a
    // valid privileged group-data commit from the same source epoch.
    drop(incumbent);
    let mut incumbent = reopen_current_client(incumbent_id, incumbent_storage.clone());
    let (incumbent_commit, incumbent_pending) = match incumbent
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("valid incumbent".into()),
            description: None,
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected incumbent GroupEvolution, got {other:?}"),
    };

    let candidate_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        candidate.self_id(),
        &legacy_add.payload,
    );
    let incumbent_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        incumbent.self_id(),
        &incumbent_commit.payload,
    );
    assert!(
        candidate_key < incumbent_key,
        "fixture must make the forbidden Add win ordering if it reaches selection"
    );

    incumbent
        .confirm_published(incumbent_pending)
        .await
        .unwrap();
    assert_eq!(incumbent.epoch(&group_id).unwrap(), EpochId(2));
    assert_eq!(
        incumbent_storage.get_group(&group_id).unwrap().name,
        "valid incumbent"
    );

    let content_id = MessageId::new(Sha256::digest(&legacy_add.payload).to_vec());
    let routed_add = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..legacy_add
    };
    // The rival candidate enters distributed convergence like any other
    // in-horizon fork commit; branch materialization enforces the strict
    // cutover (`reject_legacy_group_additions`) and must drop it there,
    // before selection can compare ordering keys.
    let outcome = incumbent.ingest(routed_add).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "the rival candidate must enter convergence, got {outcome:?}"
    );
    let result = incumbent
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the pass settles after rejecting the forbidden candidate");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);

    assert_eq!(
        incumbent.epoch(&group_id).unwrap(),
        EpochId(2),
        "forbidden candidate must not roll back the valid incumbent"
    );
    assert_eq!(
        incumbent_storage.get_group(&group_id).unwrap().name,
        "valid incumbent",
        "incumbent group projection must survive the rejected fork candidate"
    );
    assert_eq!(
        incumbent.members(&group_id).unwrap().len(),
        2,
        "the forbidden legacy Add invitee must not join"
    );
    assert_eq!(
        incumbent_storage.get_message(&content_id).unwrap().state,
        MessageState::EpochInvalidated,
        "the forbidden candidate must be retired terminally"
    );
}

#[tokio::test]
async fn convergence_privileged_remove_beats_grinding_ordinary_self_update() {
    // Alice's admin Remove(Bob) and Bob's ordinary self-update both branch from
    // epoch 1. The self-update is generated until its SHA-256 digest sorts
    // before the Remove, pinning the exploit shape that digest-only ordering
    // would have let Bob grind into the winning branch.
    let (mut alice, _alice_storage) = build_client_with_storage(b"alice-remove-admin");
    let (mut bob, bob_storage) = build_client_with_storage(b"bob-grinding-member");
    let bob_id = bob.self_id();

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "privileged-remove-vs-grinding-update".into(),
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
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcome).await.unwrap();
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(bob.epoch(&group_id).unwrap(), EpochId(1));

    let remove = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob_id.clone()],
        })
        .await
        .unwrap();
    let (remove_commit, remove_pending) = match remove {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected RemoveMembers GroupEvolution, got {other:?}"),
    };
    let remove_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        alice.self_id(),
        &remove_commit.payload,
    );

    let (self_update, self_update_key) = (0..4096)
        .map(|_| {
            let msg = raw_self_update_commit(&bob_storage, &bob_id, &group_id);
            let key = CommitOrderingKey::from_commit_bytes(
                EpochId(1),
                CommitOrderingPriority::Ordinary,
                bob_id.clone(),
                &msg.payload,
            );
            (msg, key)
        })
        .find(|(_, key)| key.commit_digest < remove_key.commit_digest)
        .expect("ordinary self-update grinding should find a digest that sorts before the remove");
    assert!(
        self_update_key.commit_digest < remove_key.commit_digest,
        "test must exercise the digest-grinding case that beat digest-only ordering"
    );
    assert!(
        remove_key < self_update_key,
        "privileged admin remove must sort before ordinary self-update despite the digest"
    );

    alice.confirm_published(remove_pending).await.unwrap();
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(2));

    // The routed self-update enters distributed convergence; the settled pass
    // must keep the privileged remove selected — a ground digest cannot beat
    // commit priority.
    let routed_self_update = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..self_update
    };
    let outcome = alice.ingest(routed_self_update).await.unwrap();
    use cgka_traits::ingest::IngestOutcome;
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "the rival self-update must enter convergence, got {outcome:?}"
    );
    let result = alice
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the fork settles on the remover");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        alice.epoch(&group_id).unwrap(),
        EpochId(2),
        "the privileged remove stays selected"
    );
    let members = alice.members(&group_id).unwrap();
    assert!(
        !members.iter().any(|member| member.id == bob_id),
        "Bob remains removed; the grinding self-update cannot resurrect him"
    );
}

/// A peer's same-epoch commit that arrives during our own `PendingPublish`
/// window is buffered `Retryable` before any peel. When our own commit confirms
/// and wins the fork through the convergence pass, the buffered rival must be
/// reclassified: the content row parks `ConvergenceDeferred` — reconsiderable,
/// not terminal, because the rival branch can still win a later pass by
/// growing deeper (see `incumbent_committer_defers_to_deeper_convergence_branch`)
/// — and the raw transport wrapper is retired `Processed`, not left
/// `Retryable` to be re-peeled on every later publish-cycle replay.
#[tokio::test]
async fn buffered_losing_fork_commit_raw_row_is_retired_after_confirm_replay() {
    use cgka_traits::ingest::IngestOutcome;
    use sha2::{Digest, Sha256};

    let (mut alice, alice_storage) = build_client_with_storage(b"alice-buffered-fork");
    let (mut bob, bob_storage) = build_client_with_storage(b"bob-buffered-fork");
    let bob_id = bob.self_id();

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "buffered-losing-fork".into(),
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
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcome).await.unwrap();
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(1));

    // Bob's ordinary self-update commit branches from epoch 1. A privileged
    // admin commit always sorts ahead of an ordinary one, so the incumbent wins
    // regardless of digest — no grinding needed to pin the winner.
    let self_update = raw_self_update_commit(&bob_storage, &bob_id, &group_id);
    let raw_id = self_update.id.clone();
    let content_id = MessageId::new(Sha256::digest(&self_update.payload).to_vec());

    // Alice stages a privileged admin Remove(Bob) → PendingPublish, the window
    // where inbound input is buffered `Retryable` before any peel.
    let remove_pending = match alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob_id.clone()],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected RemoveMembers GroupEvolution, got {other:?}"),
    };

    let buffered = alice.ingest(self_update).await.unwrap();
    assert!(
        matches!(buffered, IngestOutcome::Buffered { .. }),
        "peer commit during PendingPublish must buffer, got {buffered:?}"
    );
    assert_eq!(
        alice_storage.get_message(&raw_id).unwrap().state,
        MessageState::Retryable,
        "the buffered raw transport row is persisted Retryable pending replay"
    );

    // Confirm advances Alice to epoch 2 and replays the backlog. The replayed
    // rival routes into distributed convergence; the settled pass keeps the
    // incumbent (privileged > ordinary) and parks the loser reconsiderable.
    alice.confirm_published(remove_pending).await.unwrap();
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(2));
    let result = alice
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the replayed rival settles through convergence");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        alice.epoch(&group_id).unwrap(),
        EpochId(2),
        "the incumbent remove stays selected"
    );

    assert_eq!(
        alice_storage.get_message(&content_id).unwrap().state,
        MessageState::ConvergenceDeferred,
        "the losing fork commit's content row is parked reconsiderable \
         (distributed convergence may still select its branch if it grows \
         deeper), not terminally EpochInvalidated"
    );
    assert_eq!(
        alice_storage.get_message(&raw_id).unwrap().state,
        MessageState::Processed,
        "the raw transport wrapper must be retired terminal after replay — not \
         left Retryable to be re-peeled on every later publish cycle"
    );
}

/// Two peer rows buffered during our own `PendingPublish` window replay in a
/// single pass. The first is a privileged admin `RemoveMembers` that removes
/// our leaf; being privileged it deterministically wins the same-source-epoch
/// fork over our own ordinary `UpdateGroupData`, so the settled convergence
/// pass rolls us back and applies it — our local group state goes `Inactive`.
/// The second buffered row loses branch selection to it.
///
/// The invariant this guards (regression shape from ae616488, retargeted to
/// the unified route): replay must respect the verdicts committed during
/// re-ingest. The raw wrappers leave the retry lifecycle exactly once their
/// content rows are durable convergence input, and a losing rival's CONTENT
/// row must never be relabeled `Processed` — a `Processed` content row is a
/// canonicalization input (`openmls_projection` / `distributed_convergence`
/// select on it), so sweeping the loser back in could resurrect the removed
/// member.
#[tokio::test]
async fn buffered_losing_rival_content_row_is_never_swept_canonical_on_replay() {
    use cgka_traits::ingest::IngestOutcome;

    let (mut alice, alice_storage) = build_client_with_storage(b"alice-self-evict-replay");
    let (mut bob, bob_storage) = build_client_with_storage(b"bob-self-evict-replay");
    let alice_id = alice.self_id();
    let bob_id = bob.self_id();

    // Bob is a co-admin so he can remove Alice; Alice (creator) is implicitly an
    // admin, so removing her still leaves an admin (Bob) — MIP-03 §149.
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "self-evict-replay".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob_id.clone()],
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
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcome).await.unwrap();
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(1));

    let route = |msg: TransportMessage| TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    };

    // A second epoch-1 message from Bob, produced before he advances. On
    // replay it buffers into the same convergence pass as the remove and
    // loses branch selection to it.
    let second = route(raw_self_update_commit(&bob_storage, &bob_id, &group_id));
    let second_id = second.id.clone();
    let second_payload = second.payload.clone();

    // Bob (admin) removes Alice at epoch 1 → a privileged commit.
    let remove_alice = match bob
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![alice_id.clone()],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            bob.confirm_published(pending).await.unwrap();
            route(msg)
        }
        other => panic!("expected RemoveMembers GroupEvolution, got {other:?}"),
    };
    assert_ne!(remove_alice.id, second_id, "distinct buffered rows");

    // Alice stages her own ordinary commit → PendingPublish, the window where
    // inbound input buffers `Retryable` before any peel. Buffer the eviction
    // commit FIRST (lower insert_order → replayed first), then the second row.
    let staged = match alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("pending".into()),
            description: None,
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected UpdateGroupData GroupEvolution, got {other:?}"),
    };

    for msg in [remove_alice, second] {
        let id = msg.id.clone();
        assert!(
            matches!(
                alice.ingest(msg).await.unwrap(),
                IngestOutcome::Buffered { .. }
            ),
            "peer input during PendingPublish must buffer"
        );
        assert_eq!(
            alice_storage.get_message(&id).unwrap().state,
            MessageState::Retryable,
            "buffered raw rows are persisted Retryable pending replay"
        );
    }

    // Confirm advances Alice to epoch 2 (her ordinary update applied) and
    // replays the backlog into distributed convergence. The buffered remove is
    // a same-source-epoch fork the privileged committer wins, so the settled
    // pass rolls Alice back and applies it — evicting her leaf.
    alice.confirm_published(staged).await.unwrap();
    alice
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the replayed remove settles through convergence");

    // The buffered remove really did evict Alice on replay.
    assert!(
        !alice
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == alice_id),
        "the buffered remove must have evicted Alice on replay"
    );

    // The second buffered row was peeled and durably buffered as convergence
    // input during the same replay: its raw wrapper is retired (out of the
    // retry lifecycle, never re-peeled), while its CONTENT row carries the
    // verdict and must never be swept into canonical state — the losing
    // ordinary commit cannot resurrect Alice.
    assert_eq!(
        alice_storage.get_message(&second_id).unwrap().state,
        MessageState::Processed,
        "the second row's raw wrapper must be retired after buffering"
    );
    let second_content_id = {
        use sha2::Digest as _;
        MessageId::new(sha2::Sha256::digest(&second_payload).to_vec())
    };
    let second_content = alice_storage.get_message(&second_content_id).unwrap();
    assert_ne!(
        second_content.state,
        MessageState::Processed,
        "the losing ordinary commit must never become canonical input, got {:?}",
        second_content.state
    );
    assert!(
        !alice
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == alice_id),
        "Alice stays evicted after the backlog fully settles"
    );
}

#[tokio::test]
async fn stale_commit_outside_rewind_horizon_is_not_treated_as_recoverable_fork() {
    let mut labels: Vec<&'static [u8]> = vec![
        &b"fork-retention-00"[..],
        &b"fork-retention-01"[..],
        &b"fork-retention-02"[..],
        &b"fork-retention-03"[..],
        &b"fork-retention-04"[..],
        &b"fork-retention-05"[..],
    ];
    labels.sort_by_key(|label| pad32(label));
    let late_committer = labels[0];
    let local_committer = labels[labels.len() - 1];

    let (mut alice, _alice_storage) = build_client_with_storage(local_committer);
    let mut bob = build_client(late_committer);
    let mut dave = build_client(b"late-dave");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "retention-horizon".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
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

    // Bob produces a same-source-epoch commit from epoch 1, then Alice advances
    // past the pinned v1 rewind horizon without seeing it. Once Alice is beyond
    // epoch 1 + V1_MAX_REWIND_COMMITS, source epoch 1 is outside recovery and
    // must be classified as a stale commit, not a recoverable fork.
    let dave_kp = dave.fresh_key_package().await.unwrap();
    let late_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![dave_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let late_commit = match late_invite {
        SendResult::GroupEvolution { msg, pending, .. } => {
            bob.confirm_published(pending).await.unwrap();
            msg
        }
        other => panic!("expected Bob invite GroupEvolution, got {other:?}"),
    };

    let advance_epochs = V1_MAX_REWIND_COMMITS + 1;
    for i in 0..advance_epochs {
        let update = alice
            .send(SendIntent::UpdateGroupData {
                group_id: group_id.clone(),
                name: Some(format!("retention-horizon-{i}")),
                description: None,
            })
            .await
            .unwrap();
        let pending = match update {
            SendResult::GroupEvolution { pending, .. } => pending,
            other => panic!("expected Alice update GroupEvolution, got {other:?}"),
        };
        alice.confirm_published(pending).await.unwrap();
    }
    let terminal_epoch = EpochId(1 + advance_epochs);
    assert_eq!(alice.epoch(&group_id).unwrap(), terminal_epoch);

    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..late_commit
    };
    // Clear the setup traffic's events so the assertion below only sees what
    // the stale ingest itself produced.
    alice.drain_events();
    let outcome = alice.ingest(routed).await.unwrap();
    use cgka_traits::ingest::{IngestOutcome, StaleReason};
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadyAtEpoch {
                current,
                msg_epoch: EpochId(1),
            }
        } if current == terminal_epoch
    ));
    let events = alice.drain_events();
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, GroupEvent::EpochChanged { .. })),
        "late commits outside the rewind horizon must not change canonical state"
    );
    assert_eq!(alice.epoch(&group_id).unwrap(), terminal_epoch);
}

#[tokio::test]
async fn stale_commit_without_own_commit_is_classified_as_already_at_epoch_not_fork() {
    // Bob receives a commit targeting an epoch he didn't himself commit
    // from — this is the welcome-before-commit case, not a fork.
    // (Proven indirectly by the existing ingest.rs tests, duplicated here
    // explicitly for the fork-detection boundary.)
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
    let mut carol = build_client(b"carol");
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
    let bob_welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        _ => unreachable!(),
    };
    bob.join_welcome(bob_welcome).await.unwrap();

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (commit, carol_welcome, pending) = match invite {
        SendResult::GroupEvolution {
            msg,
            mut welcomes,
            pending,
        } => (msg, welcomes.remove(0), pending),
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    carol.join_welcome(carol_welcome).await.unwrap();

    // Carol (who joined via welcome at epoch 2, never committed herself)
    // ingests the commit. She's at epoch 2. Commit targets epoch 1.
    // She did NOT commit-from-1 → this is NOT a fork, it's AlreadyAtEpoch.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..commit
    };
    let outcome = carol.ingest(routed).await.unwrap();
    use cgka_traits::ingest::{IngestOutcome, StaleReason};
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadyAtEpoch { .. }
        }
    ));
}

#[tokio::test]
async fn failed_invite_staging_does_not_poison_fork_detection() {
    // Regression (historical shape): `do_send_invite` used to record
    // fork-detection bookkeeping BEFORE staging the commit; when staging
    // failed, the leftover phantom entry mis-routed a legitimate same-epoch
    // sibling commit into fail-closed fork recovery, sticking the group in
    // Recovering. Routing no longer consults committer-side bookkeeping at
    // all — the sibling is admitted into convergence by the retained
    // source-epoch anchor — and this test keeps pinning that a failed staging
    // attempt leaves later sibling classification untouched.
    let (mut alice, _alice_storage) = build_client_with_storage(b"phantom-alice");
    let mut bob = build_client(b"phantom-bob");
    let mut carol = build_client(b"phantom-carol");
    let (mut dave, dave_storage) = build_client_with_storage(b"phantom-dave");
    let dave_id = MemberId::new(pad32(b"phantom-dave"));

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let dave_kp = dave.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp, dave_kp],
            required_features: vec![],
            app_components: vec![],
            // Bob must be an admin so his sibling-epoch invite below passes
            // the MIP-03 committer guard.
            initial_admins: vec![MemberId::new(pad32(b"phantom-bob"))],
        })
        .await
        .unwrap();
    let (bob_welcome, dave_welcome) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            let dave_welcome = welcomes.remove(1);
            (welcomes.remove(0), dave_welcome)
        }
        _ => unreachable!(),
    };
    bob.join_welcome(bob_welcome).await.unwrap();
    dave.join_welcome(dave_welcome).await.unwrap();

    // Dave produces (but never publishes/applies) a sibling commit from the
    // current epoch — the legitimate same-epoch race Alice must classify
    // later.
    let dave_sibling_commit = raw_self_update_commit(&dave_storage, &dave_id, &group_id);

    // Alice's invite fails DURING staging: the duplicate-Bob KeyPackage is
    // signed with Bob's existing leaf signature key, which OpenMLS rejects
    // inside `add_members` — after capability validation, before
    // `begin_pending`.
    let duplicate_bob_kp = bob.fresh_key_package().await.unwrap();
    let failed = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![duplicate_bob_kp],
            initial_admins: vec![],
        })
        .await;
    assert!(
        failed.is_err(),
        "duplicate-member invite must fail during staging"
    );

    // Bob commits from the same epoch (invites Carol). Alice advances by
    // settling Bob's commit through convergence — a peer-driven advance, so
    // she has no fork-recovery incumbent of her own for the source epoch.
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (bob_commit, pending) = match invite {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        _ => unreachable!(),
    };
    bob.confirm_published(pending).await.unwrap();
    let routed_bob_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..bob_commit
    };
    alice
        .buffer_openmls_convergence_message_at(&group_id, routed_bob_commit, 1_000)
        .expect("bob commit buffered");
    alice
        .converge_stored_openmls_messages_at(&group_id, 3_000)
        .expect("bob commit settles");
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(2));

    // Dave's sibling commit for the now-past epoch arrives. Alice never
    // published a commit from that epoch, so ingest must classify it (stale
    // losing branch, or a reorg onto the winning branch) — NOT take the
    // fork-recovery path, which with the phantom entry and no tracked
    // snapshot failed closed with ForkedEpoch and left the group stuck in
    // Recovering.
    alice
        .ingest(dave_sibling_commit)
        .await
        .expect("sibling commit after failed staging must not fail closed");

    // The group is still operational: a fresh (valid) invite from Alice is
    // accepted — staged immediately or queued behind unresolved convergence
    // input. In Recovering it would error instead (`begin_pending` rejects
    // non-Stable states).
    let mut erin = build_client(b"phantom-erin");
    let erin_kp = erin.fresh_key_package().await.unwrap();
    let recovery_probe = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![erin_kp],
            initial_admins: vec![],
        })
        .await
        .expect("group must remain usable after failed staging + sibling commit");
    assert!(matches!(
        recovery_probe,
        SendResult::GroupEvolution { .. } | SendResult::Queued { .. }
    ));
}

#[tokio::test]
async fn publish_failed_rollback_does_not_poison_fork_detection() {
    // Companion regression to `failed_invite_staging_does_not_poison_fork_
    // detection`, for the POST-staging failure: staging succeeds and then
    // the publish fails. Historically the rollback left phantom
    // fork-detection bookkeeping behind that mis-routed a legitimate late
    // same-epoch sibling into fail-closed fork recovery. Routing no longer
    // consults committer-side bookkeeping; this test keeps pinning that a
    // rolled-back publish leaves later sibling classification untouched.
    let (mut alice, _alice_storage) = build_client_with_storage(b"rollback-alice");
    let mut bob = build_client(b"rollback-bob");
    let mut carol = build_client(b"rollback-carol");
    let (mut dave, dave_storage) = build_client_with_storage(b"rollback-dave");
    let dave_id = MemberId::new(pad32(b"rollback-dave"));

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let dave_kp = dave.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp, dave_kp],
            required_features: vec![],
            app_components: vec![],
            // Bob must be an admin so his sibling-epoch invite below passes
            // the MIP-03 committer guard.
            initial_admins: vec![MemberId::new(pad32(b"rollback-bob"))],
        })
        .await
        .unwrap();
    let (bob_welcome, dave_welcome) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            let dave_welcome = welcomes.remove(1);
            (welcomes.remove(0), dave_welcome)
        }
        _ => unreachable!(),
    };
    bob.join_welcome(bob_welcome).await.unwrap();
    dave.join_welcome(dave_welcome).await.unwrap();

    // Dave produces (but never publishes/applies) a sibling commit from the
    // current epoch — the legitimate same-epoch race Alice must classify
    // later.
    let dave_sibling_commit = raw_self_update_commit(&dave_storage, &dave_id, &group_id);

    // Alice's invite stages successfully — and then the publish fails.
    let mut frank = build_client(b"rollback-frank");
    let frank_kp = frank.fresh_key_package().await.unwrap();
    let staged = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match staged {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.publish_failed(pending).await.unwrap();

    // Bob commits from the same epoch (invites Carol). Alice advances by
    // settling Bob's commit through convergence — a peer-driven advance, so
    // she has no fork-recovery incumbent of her own for the source epoch.
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (bob_commit, pending) = match invite {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        _ => unreachable!(),
    };
    bob.confirm_published(pending).await.unwrap();
    let routed_bob_commit = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..bob_commit
    };
    alice
        .buffer_openmls_convergence_message_at(&group_id, routed_bob_commit, 1_000)
        .expect("bob commit buffered");
    alice
        .converge_stored_openmls_messages_at(&group_id, 3_000)
        .expect("bob commit settles");
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(2));

    // Dave's sibling commit for the now-past epoch arrives. Alice's rolled-
    // back commit reached no one, so ingest must classify it — NOT take the
    // fork-recovery path and fail closed with ForkedEpoch.
    alice
        .ingest(dave_sibling_commit)
        .await
        .expect("sibling commit after rolled-back publish must not fail closed");

    // The group is still operational: a fresh (valid) invite from Alice is
    // accepted — staged immediately or queued behind unresolved convergence
    // input. In Recovering it would error instead (`begin_pending` rejects
    // non-Stable states).
    let mut erin = build_client(b"rollback-erin");
    let erin_kp = erin.fresh_key_package().await.unwrap();
    let recovery_probe = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![erin_kp],
            initial_admins: vec![],
        })
        .await
        .expect("group must remain usable after rolled-back publish + sibling commit");
    assert!(matches!(
        recovery_probe,
        SendResult::GroupEvolution { .. } | SendResult::Queued { .. }
    ));
}

#[tokio::test]
async fn incumbent_committer_defers_to_deeper_convergence_branch() {
    // Formerly `pairwise_incumbent_defers_to_deeper_convergence_branch`
    // (#1285's regression at the deleted pairwise seam). Unified route: the
    // committer that advanced from epoch N adjudicates a same-epoch rival
    // through the same distributed-convergence pass as every observer. At
    // equal depth the ordering key keeps the committer's own branch and the
    // losing rival root must stay reconsiderable — not terminally
    // invalidated — because a deeper valid branch outranks the ordering key
    // in a later pass. If the loser were invalidated terminally, the
    // committer could never follow the fleet onto the rival branch once that
    // branch grows — a permanent lineage split in which each side keeps
    // decrypting only its own history.
    //
    // This test drives the exact sequence: the committer must first keep its
    // own branch (incumbent wins on the ordering key), then CONVERGE onto the
    // rival branch after a follow-on commit makes it the deeper valid branch.
    use cgka_traits::ingest::IngestOutcome;

    // Fix which identity wins the equal-depth race up front (privileged admin
    // commits at the same epoch order by committer identity).
    let first = b"seam-first".as_slice();
    let second = b"seam-second".as_slice();
    let (winner_id, loser_id) = if pad32(first) < pad32(second) {
        (first, second)
    } else {
        (second, first)
    };

    // Concrete Engine type: the test drives the convergence pass to
    // completion explicitly (`converge_stored_openmls_messages_at`), which is
    // not part of the CgkaEngine trait surface.
    let (mut winner, winner_storage) = build_client_with_storage(winner_id); // equal-depth incumbent-keeper
    let mut loser = build_client(loser_id); //  rival whose branch grows deeper
    let mut david = build_client(b"seam-david");
    let mut eve = build_client(b"seam-eve");
    let mut frank = build_client(b"seam-frank");

    let loser_kp = loser.fresh_key_package().await.unwrap();
    let (group_id, create) = winner
        .create_group(CreateGroupRequest {
            name: "cross-seam".into(),
            description: String::new(),
            members: vec![loser_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![loser.self_id()],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            winner.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        _ => unreachable!(),
    };
    loser.join_welcome(welcome).await.unwrap();
    assert_eq!(winner.epoch(&group_id).unwrap().0, 1);
    assert_eq!(loser.epoch(&group_id).unwrap().0, 1);

    let route = |msg: TransportMessage| TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    };

    // Rival commits from epoch 1: the winner invites david, the loser invites
    // eve. Neither sees the other's commit yet.
    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let winner_invite = winner
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let loser_invite = loser
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (winner_commit, loser_root) = match (&winner_invite, &loser_invite) {
        (
            SendResult::GroupEvolution {
                msg: w,
                pending: wp,
                ..
            },
            SendResult::GroupEvolution {
                msg: l,
                pending: lp,
                ..
            },
        ) => {
            let (w, l, wp, lp) = (w.clone(), l.clone(), *wp, *lp);
            winner.confirm_published(wp).await.unwrap();
            loser.confirm_published(lp).await.unwrap();
            (w, l)
        }
        _ => unreachable!(),
    };
    let winner_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(winner_id)),
        &winner_commit.payload,
    );
    let loser_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(loser_id)),
        &loser_root.payload,
    );
    assert!(
        winner_key < loser_key,
        "identity choice must make the incumbent win the equal-depth race"
    );

    // Pass 1 on the winner: the rival root LOSES the equal-depth ordering
    // comparison inside the convergence pass. The winner keeps its own
    // branch, and — the fix under test — the loser's root must stay
    // reconsiderable, not terminally invalidated.
    let outcome = winner.ingest(route(loser_root.clone())).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "the rival root must enter convergence, got {outcome:?}"
    );
    let result = winner
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the equal-depth fork settles on the winner");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(winner.epoch(&group_id).unwrap().0, 2);
    // The parked loser-root row IS the fix: `ConvergenceDeferred` (so branch
    // materialization re-admits it) and keyed by its SOURCE epoch (the apply
    // stage derives its retained-anchor rewind target from `record.epoch`; a
    // current-epoch key would skip the rewind and fail replay).
    let loser_root_content_id = {
        use sha2::{Digest, Sha256};
        MessageId::new(Sha256::digest(&loser_root.payload).to_vec())
    };
    let parked = winner_storage.get_message(&loser_root_content_id).unwrap();
    assert_eq!(
        parked.state,
        MessageState::ConvergenceDeferred,
        "the losing rival root must be parked reconsiderable, not terminally invalidated"
    );
    assert_eq!(
        parked.epoch,
        EpochId(1),
        "the parked loser-root must be keyed by its source epoch, not the winner's current epoch"
    );

    // The loser's branch grows deeper: a follow-on invite from ITS epoch 2.
    let frank_kp = frank.fresh_key_package().await.unwrap();
    let loser_follow_on = match loser
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            loser.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    assert_eq!(loser.epoch(&group_id).unwrap().0, 3);

    // Pass 2 on the winner: the follow-on commit routes into distributed
    // convergence, which must now select the rival branch (valid depth 2 from
    // the fork point vs the winner's own depth 1) and rewind the winner onto
    // it — the same branch every convergence-only node picks. Before the fix
    // the rival root was `EpochInvalidated` and could never be materialized,
    // so the winner stayed on its own lineage forever.
    let follow_on_outcome = winner.ingest(route(loser_follow_on)).await.unwrap();
    assert!(
        matches!(follow_on_outcome, IngestOutcome::Buffered { .. }),
        "the rival follow-on must enter the convergence pass, got {follow_on_outcome:?}"
    );
    // Drive the pass past its quiescence window (production wnd gets here via
    // the passage of time); the deeper rival branch must now be selected.
    let result = winner
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("cross-seam reorg onto the deeper rival branch");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);

    assert_eq!(
        winner.epoch(&group_id).unwrap().0,
        3,
        "winner must converge onto the deeper rival branch"
    );
    let winner_members: Vec<_> = winner
        .members(&group_id)
        .unwrap()
        .iter()
        .map(|m| m.id.clone())
        .collect();
    assert!(
        winner_members.contains(&MemberId::new(pad32(b"seam-eve"))),
        "rival branch's first invitee must be present after convergence"
    );
    assert!(
        winner_members.contains(&MemberId::new(pad32(b"seam-frank"))),
        "rival branch's second invitee must be present after convergence"
    );
    assert!(
        !winner_members.contains(&MemberId::new(pad32(b"seam-david"))),
        "the abandoned own branch's invitee must be gone"
    );
    let loser_members: Vec<_> = loser
        .members(&group_id)
        .unwrap()
        .iter()
        .map(|m| m.id.clone())
        .collect();
    assert_eq!(
        {
            let mut w = winner_members.clone();
            w.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
            w
        },
        {
            let mut l = loser_members.clone();
            l.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
            l
        },
        "both nodes must end on the identical branch"
    );
}

#[tokio::test]
async fn rival_win_leaves_displaced_own_commit_reconsiderable() {
    // Formerly `pairwise_candidate_win_leaves_old_incumbent_reconsiderable`.
    // The mirror of `incumbent_committer_defers_to_deeper_convergence_branch`,
    // for the RIVAL-wins outcome of the equal-depth race: node X's own
    // confirmed commit A loses to an inbound rival B and the convergence pass
    // reorgs X onto B. The displaced own commit A must be parked
    // `ConvergenceDeferred` at its SOURCE epoch — not terminally
    // `EpochInvalidated` — because a peer that applied A and never saw B can
    // keep extending the A-branch. Once that branch is deeper, distributed
    // convergence selects it fleet-wide, and X can only follow if A's stored
    // row (with its own-commit ordering stamp) is still convergence input.
    use cgka_traits::ingest::IngestOutcome;

    // Privileged same-epoch commits order by committer identity: the rival's
    // identity must sort BEFORE X's so the inbound candidate B wins.
    let first = b"cwin-first".as_slice();
    let second = b"cwin-second".as_slice();
    let (rival_id, x_id) = if pad32(first) < pad32(second) {
        (first, second)
    } else {
        (second, first)
    };

    // Concrete Engine type: the test drives the convergence pass to
    // completion explicitly (`converge_stored_openmls_messages_at`), which is
    // not part of the CgkaEngine trait surface.
    let (mut x, x_storage) = build_client_with_storage(x_id); // rolls back onto B, must later reorg onto A
    let mut rival = build_client(rival_id); //                   authors the equal-depth-winning B
    let (mut y, _y_storage) = build_client_with_storage(b"cwin-y"); // applied A, never sees B
    let mut david = build_client(b"cwin-david");
    let mut eve = build_client(b"cwin-eve");
    let mut frank = build_client(b"cwin-frank");

    let rival_kp = rival.fresh_key_package().await.unwrap();
    let y_kp = y.fresh_key_package().await.unwrap();
    let (group_id, create) = x
        .create_group(CreateGroupRequest {
            name: "candidate-win-reconsider".into(),
            description: String::new(),
            members: vec![rival_kp, y_kp],
            required_features: vec![],
            app_components: vec![],
            // Both peers need admin so their commits below pass the MIP-03
            // committer guard (rival's rival root, Y's follow-on invite).
            initial_admins: vec![rival.self_id(), y.self_id()],
        })
        .await
        .unwrap();
    let (rival_welcome, y_welcome) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            x.confirm_published(pending).await.unwrap();
            let y_welcome = welcomes.remove(1);
            (welcomes.remove(0), y_welcome)
        }
        _ => unreachable!(),
    };
    rival.join_welcome(rival_welcome).await.unwrap();
    y.join_welcome(y_welcome).await.unwrap();
    assert_eq!(x.epoch(&group_id).unwrap().0, 1);
    assert_eq!(y.epoch(&group_id).unwrap().0, 1);

    let route = |msg: TransportMessage| TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    };

    // (1) X commits from epoch 1 (commit A: invite david) and confirms — A is
    // X's confirmed own commit. (2)'s rival B (invite eve) branches from
    // the same epoch without seeing A.
    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let commit_a = match x
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            x.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    let commit_b = match rival
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            rival.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    let a_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(x_id)),
        &commit_a.payload,
    );
    let b_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(rival_id)),
        &commit_b.payload,
    );
    assert!(
        b_key < a_key,
        "identity choice must make the inbound rival win the equal-depth race"
    );

    // (2) B arrives at X and WINS the equal-depth ordering comparison inside
    // the convergence pass: X reorgs off A onto B.
    let outcome = x.ingest(route(commit_b)).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "the rival must enter convergence, got {outcome:?}"
    );
    let result = x
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the equal-depth fork settles on X");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(x.epoch(&group_id).unwrap().0, 2);
    assert!(
        x.members(&group_id)
            .unwrap()
            .iter()
            .any(|m| m.id == MemberId::new(pad32(b"cwin-eve"))),
        "X must land on the rival branch (B's invitee present)"
    );

    // The fix under test: the displaced incumbent A is parked reconsiderable
    // at its SOURCE epoch, with its stored payload (own-commit convergence
    // stamp) intact — not terminally `EpochInvalidated`, which would exclude
    // it from every later convergence pass and freeze X off the A-branch.
    let parked = x_storage.get_message(&commit_a.id).unwrap();
    assert_eq!(
        parked.state,
        MessageState::ConvergenceDeferred,
        "the displaced own commit must be parked reconsiderable, not terminally invalidated"
    );
    assert_eq!(
        parked.epoch,
        EpochId(1),
        "the parked incumbent must be keyed by its source epoch for the convergence rewind target"
    );

    // (3) Y applied A (and never sees B), then extends the A-branch with a
    // follow-on invite from ITS epoch 2 — the A-branch is now depth 2. Y never
    // committed from epoch 1, so A routes through Y's convergence pass; drive
    // it past quiescence to settle A onto Y.
    y.ingest(route(commit_a.clone())).await.unwrap();
    y.converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("A settles on Y through convergence");
    assert_eq!(y.epoch(&group_id).unwrap().0, 2);
    let frank_kp = frank.fresh_key_package().await.unwrap();
    let follow_on = match y
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            y.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    assert_eq!(y.epoch(&group_id).unwrap().0, 3);

    // (4) X ingests the follow-on: source epoch 2 >= X's current epoch, so it
    // routes into distributed convergence, which must select the DEEPER
    // A-branch (depth 2 from the fork point vs B's depth 1) and reorg X onto
    // it — the same branch every convergence-only node picks. Before the fix
    // A's root was `EpochInvalidated` and could never be materialized, so X
    // stayed on the B lineage forever.
    let follow_on_outcome = x.ingest(route(follow_on)).await.unwrap();
    assert!(
        matches!(follow_on_outcome, IngestOutcome::Buffered { .. }),
        "the A-branch follow-on must enter the convergence pass, got {follow_on_outcome:?}"
    );
    // Drive the pass past its quiescence window (production gets here via the
    // passage of time); the deeper A-branch must now be selected.
    let result = x
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("reorg back onto the deeper A-branch");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);

    assert_eq!(
        x.epoch(&group_id).unwrap().0,
        3,
        "X must converge onto the deeper A-branch"
    );
    let x_members: Vec<_> = x
        .members(&group_id)
        .unwrap()
        .iter()
        .map(|m| m.id.clone())
        .collect();
    assert!(
        x_members.contains(&MemberId::new(pad32(b"cwin-david"))),
        "A-branch's first invitee must be present after convergence"
    );
    assert!(
        x_members.contains(&MemberId::new(pad32(b"cwin-frank"))),
        "A-branch's second invitee must be present after convergence"
    );
    assert!(
        !x_members.contains(&MemberId::new(pad32(b"cwin-eve"))),
        "the abandoned B-branch's invitee must be gone"
    );
    let y_members: Vec<_> = y
        .members(&group_id)
        .unwrap()
        .iter()
        .map(|m| m.id.clone())
        .collect();
    assert_eq!(
        {
            let mut a = x_members.clone();
            a.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
            a
        },
        {
            let mut b = y_members.clone();
            b.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
            b
        },
        "X and Y must end on the identical branch"
    );
}

#[tokio::test]
async fn own_commit_checkpoint_survives_rival_anchor_overwrite_and_restart() {
    // X confirms A, loses the equal-depth convergence race to B, and advances
    // B far enough to replace every epoch-named anchor that previously
    // described A.  After a restart, A grows deeper. X must cross its own
    // path-bearing commit without asking OpenMLS to process the wire echo:
    // the immutable commit-addressed checkpoint restores A's exact post-merge
    // state and replay continues.
    use cgka_traits::ingest::IngestOutcome;

    let first = b"cwrf-first".as_slice();
    let second = b"cwrf-second".as_slice();
    let (rival_id, x_id) = if pad32(first) < pad32(second) {
        (first, second)
    } else {
        (second, first)
    };

    let (mut x, x_storage) = build_client_with_storage(x_id);
    let mut rival = build_client(rival_id);
    let (mut y, _y_storage) = build_client_with_storage(b"cwrf-y");
    let mut david = build_client(b"cwrf-david");
    let mut eve = build_client(b"cwrf-eve");
    let mut frank = build_client(b"cwrf-frank");
    let mut grace = build_client(b"cwrf-grace");
    let mut heidi = build_client(b"cwrf-heidi");

    let rival_kp = rival.fresh_key_package().await.unwrap();
    let y_kp = y.fresh_key_package().await.unwrap();
    let (group_id, create) = x
        .create_group(CreateGroupRequest {
            name: "candidate-win-rival-follow-on".into(),
            description: String::new(),
            members: vec![rival_kp, y_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![rival.self_id(), y.self_id()],
        })
        .await
        .unwrap();
    let (rival_welcome, y_welcome) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            x.confirm_published(pending).await.unwrap();
            let y_welcome = welcomes.remove(1);
            (welcomes.remove(0), y_welcome)
        }
        _ => unreachable!(),
    };
    rival.join_welcome(rival_welcome).await.unwrap();
    y.join_welcome(y_welcome).await.unwrap();

    let route = |msg: TransportMessage| TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    };

    // (1) X's own commit A and the rival's competing B, both from epoch 1.
    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let commit_a = match x
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            x.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    let commit_b = match rival
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            rival.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    let a_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(x_id)),
        &commit_a.payload,
    );
    let b_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(rival_id)),
        &commit_b.payload,
    );
    assert!(
        b_key < a_key,
        "the inbound rival must win the equal-depth race"
    );

    // (2) B wins the equal-depth convergence race at X; A is parked
    // reconsiderable at its source epoch.
    let outcome = x.ingest(route(commit_b)).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "the rival must enter convergence, got {outcome:?}"
    );
    x.converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("rival win must reorg X onto B");
    x.drain_events();
    assert_eq!(x.epoch(&group_id).unwrap().0, 2);
    let parked = x_storage.get_message(&commit_a.id).unwrap();
    assert_eq!(parked.state, MessageState::ConvergenceDeferred);
    assert_eq!(parked.epoch, EpochId(1));

    // (2b) THE EXTRA COMMIT. The rival extends its own winning branch and X
    // applies it normally. X's merge of this commit re-captures
    // `openmls-retained-anchor-2` at the pre-merge epoch — clobbering the
    // capture that held A's post-merge state. Nothing about the anchor's NAME
    // changes, and no own-stamped row records the overwrite.
    let heidi_kp = heidi.fresh_key_package().await.unwrap();
    let rival_follow_on = match rival
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![heidi_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            rival.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    x.ingest(route(rival_follow_on)).await.unwrap();
    x.drain_events();
    // The parked A row keeps a convergence pass live, so the rival's follow-on
    // routes through convergence rather than the linear pending replay. Drive
    // the pass: it selects the rival branch (depth 2 vs A's 1) and applies the
    // follow-on — and THAT apply is what re-captures `openmls-retained-anchor-2`
    // with the rival branch's state, over A's.
    x.converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the rival follow-on settles on X's current branch");
    assert_eq!(
        x.epoch(&group_id).unwrap().0,
        3,
        "X must apply the rival's follow-on on the branch it rolled onto"
    );
    assert_eq!(
        x_storage
            .list_group_state_checkpoints(&group_id)
            .unwrap()
            .len(),
        1,
        "the own-commit checkpoint must not alias the rival's epoch anchor"
    );

    // Prove checkpoint identity and the own-commit stamp survive hydration.
    drop(x);
    let mut x = reopen_legacy_client(x_id, x_storage.clone());

    // (3) Y settles A and grows the A-branch two commits deeper, so distributed
    // convergence unambiguously prefers it (depth 3 vs the rival branch's 2)
    // and X is asked to reorg onto a branch rooted at its own parked commit A.
    y.ingest(route(commit_a.clone())).await.unwrap();
    y.converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("A settles on Y through convergence");
    assert_eq!(y.epoch(&group_id).unwrap().0, 2);
    let frank_kp = frank.fresh_key_package().await.unwrap();
    let follow_on = match y
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            y.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    let grace_kp = grace.fresh_key_package().await.unwrap();
    let follow_on_2 = match y
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![grace_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            y.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    assert_eq!(y.epoch(&group_id).unwrap().0, 4);

    // (4) X ingests the deeper A-branch. Convergence selects it, restores A's
    // commit-addressed checkpoint, then replays both peer-authored descendants.
    let outcome = x.ingest(route(follow_on)).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "the A-branch follow-on must enter the convergence pass, got {outcome:?}"
    );
    let outcome_2 = x.ingest(route(follow_on_2)).await.unwrap();
    assert!(
        matches!(outcome_2, IngestOutcome::Buffered { .. }),
        "the second A-branch follow-on must enter the convergence pass, got {outcome_2:?}"
    );

    // Select with the valid checkpoint, then corrupt only the stamped
    // authenticator before apply. The restore must fail closed and the apply
    // snapshot must return canonical state to the rival branch.
    let policy = CanonicalizationPolicy::default();
    let selection = canonicalize_stored_openmls_messages(
        &x_storage,
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 3,
            retained_anchor_epoch: 0,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        Vec::new(),
        policy.clone(),
        u64::MAX,
    )
    .expect("the deeper A branch should select with an intact checkpoint");
    let before_failed_apply = x_storage.get_group(&group_id).unwrap();
    let original_own_record = x_storage.get_message(&commit_a.id).unwrap();
    mutate_own_commit_stamp(&x_storage, &commit_a.id, |stamp| {
        stamp.resulting_epoch_authenticator = Some("mismatched-authenticator".into());
    });
    let error = apply_openmls_canonicalization_result(
        &x_storage,
        &group_id,
        &selection,
        policy.convergence.max_rewind_commits,
    )
    .expect_err("a mismatched checkpoint authenticator must abort apply");
    assert!(matches!(
        error,
        OpenMlsProjectionError::CheckpointStateMismatch
    ));
    assert_eq!(
        x_storage.get_group(&group_id).unwrap(),
        before_failed_apply,
        "failed checkpoint verification must roll back canonical state"
    );
    assert_eq!(
        x_storage.get_message(&commit_a.id).unwrap().state,
        MessageState::ConvergenceDeferred,
        "failed apply must leave the parked root reconsiderable"
    );
    x_storage.put_message(&original_own_record).unwrap();

    let convergence = x
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the deeper A branch must be realizable after restart");

    let mut x_members: Vec<_> = x
        .members(&group_id)
        .unwrap()
        .iter()
        .map(|m| m.id.clone())
        .collect();
    let mut y_members: Vec<_> = y
        .members(&group_id)
        .unwrap()
        .iter()
        .map(|m| m.id.clone())
        .collect();
    x_members.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    y_members.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    assert_eq!(
        x_members,
        y_members,
        "X and Y must converge after restart; X epoch {:?}, result {convergence:?}",
        x.epoch(&group_id)
    );
    assert!(x_members.contains(&MemberId::new(pad32(b"cwrf-david"))));
    assert!(x_members.contains(&MemberId::new(pad32(b"cwrf-frank"))));
    assert!(x_members.contains(&MemberId::new(pad32(b"cwrf-grace"))));
    assert!(!x_members.contains(&MemberId::new(pad32(b"cwrf-eve"))));
    assert!(!x_members.contains(&MemberId::new(pad32(b"cwrf-heidi"))));
    assert_eq!(
        x.epoch(&group_id).unwrap().0,
        4,
        "X must reach the selected A-branch tip"
    );
    let realized = x_storage.get_message(&commit_a.id).unwrap();
    assert_eq!(
        realized.state,
        MessageState::Processed,
        "the restored own commit must become canonical"
    );

    // Model an upgrade from a pre-checkpoint database: the durable own stamp
    // remains, but migration 42 starts with no historical checkpoint rows and
    // the optional fields deserialize as absent. This must report missing
    // required retained state, which the convergence coordinator turns into a
    // durable Unrecoverable halt, rather than repeatedly selecting the branch.
    let stamp = own_commit_stamp(&x_storage, &commit_a.id);
    x_storage
        .release_group_state_checkpoint(
            &group_id,
            stamp
                .checkpoint_id
                .as_deref()
                .expect("new own commit has checkpoint id"),
        )
        .unwrap();
    mutate_own_commit_stamp(&x_storage, &commit_a.id, |stamp| {
        stamp.checkpoint_id = None;
        stamp.resulting_epoch_authenticator = None;
    });
    x_storage
        .update_message_state(&commit_a.id, MessageState::ConvergenceDeferred)
        .unwrap();
    let fresh_trigger = x_storage
        .list_messages(&group_id, EpochId(3))
        .unwrap()
        .into_iter()
        .find(|record| record.epoch == EpochId(3) && record.state == MessageState::Processed)
        .expect("the selected branch has an epoch-3 descendant");
    x_storage
        .update_message_state(&fresh_trigger.id, MessageState::Created)
        .unwrap();
    x_storage.delete_convergence_pass(&group_id).unwrap();
    let legacy_result = x
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("legacy missing-checkpoint state should produce a terminal result");
    assert_eq!(
        legacy_result.errors,
        vec![CanonicalizationError::MissingOwnCommitCheckpoint]
    );
    assert_eq!(legacy_result.convergence_status, ConvergenceStatus::Blocked);
    assert!(
        x_storage.get_group(&group_id).unwrap().unrecoverable,
        "missing a required legacy own-commit checkpoint must durably halt the group"
    );
    assert!(
        x.drain_events().iter().any(|event| matches!(
            event,
            GroupEvent::GroupUnrecoverable { group_id: halted } if halted == &group_id
        )),
        "the upgrade-path halt must be surfaced to the host"
    );
}

// --- One route for every member, restarted or live --------------------------
//
// A same-epoch rival commit is adjudicated by distributed convergence whether
// the device is the committer that advanced past the rival's source epoch, an
// observer, or a committer that restarted in between. The durable
// source-epoch anchor (`openmls-retained-anchor-{epoch}`) is what admits the
// rival into the pass; when it is missing inside the rewind horizon the
// device halts loudly instead of silently keeping its own branch. These two
// tests pin the restart shape of both outcomes.

/// Which branch of a two-way epoch-1 fork a device ended up on.
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use sha2::{Digest as _, Sha256};

#[derive(Debug, PartialEq, Eq)]
enum Branch {
    Own,
    Sibling,
}

struct RouterFlipFixture {
    group_id: cgka_traits::types::GroupId,
    local_storage: SqliteAccountStorage,
    local_seed: Vec<u8>,
    competing: TransportMessage,
    /// Wrap-time transport id of the device's own confirmed commit — the id
    /// its stored row is keyed by, and therefore the id any rollback /
    /// invalidation event attributing that commit must carry.
    own_commit_id: MessageId,
    own_invitee: MemberId,
    sibling_invitee: MemberId,
    /// True when deterministic commit ordering makes the inbound sibling commit
    /// the winner, so a correct device must end on [`Branch::Sibling`].
    sibling_wins: bool,
}

/// Two admins concurrently invite from epoch 1 and both confirm publish. The
/// device under test is the joiner. Seeds are assigned so the creator's identity
/// always loses the `CommitOrderingKey` committer comparison to nobody — i.e.
/// sorts FIRST — which makes the inbound sibling commit the ordering winner for
/// every `tag`, so control and restart runs are directly comparable.
async fn router_flip_fixture(tag: &str) -> (RouterFlipFixture, Engine<SqliteAccountStorage>) {
    router_flip_fixture_arranged(tag, true).await
}

/// [`router_flip_fixture`], additionally returning the creator engine — the
/// sibling author, live on the branch the device under test cannot adjudicate.
/// Repair-path tests need it to keep driving the group from that side.
async fn router_flip_fixture_with_creator(
    tag: &str,
) -> (
    RouterFlipFixture,
    Engine<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
) {
    router_flip_fixture_arranged_with_creator(tag, true).await
}

/// [`router_flip_fixture`] with the ordering winner chosen up front:
/// `sibling_wins` picks whether the creator's inbound sibling commit or the
/// joiner's own confirmed commit wins the privileged same-epoch committer
/// comparison (identities are seed-derived, so the arrangement is exact).
async fn router_flip_fixture_arranged(
    tag: &str,
    sibling_wins: bool,
) -> (RouterFlipFixture, Engine<SqliteAccountStorage>) {
    let (fixture, joiner, _creator) =
        router_flip_fixture_arranged_with_creator(tag, sibling_wins).await;
    (fixture, joiner)
}

/// The general form: ordering winner chosen up front AND the creator engine
/// returned for repair-path tests that keep driving the group from the
/// sibling author's side.
async fn router_flip_fixture_arranged_with_creator(
    tag: &str,
    sibling_wins: bool,
) -> (
    RouterFlipFixture,
    Engine<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
) {
    let a = format!("rf-a-{tag}").into_bytes();
    let b = format!("rf-b-{tag}").into_bytes();
    let (creator_seed, joiner_seed) = if (pad32(&a) < pad32(&b)) == sibling_wins {
        (a, b)
    } else {
        (b, a)
    };
    let own_seed = format!("rf-own-invitee-{tag}").into_bytes();
    let sibling_seed = format!("rf-sibling-invitee-{tag}").into_bytes();

    let (mut creator, _creator_storage) = build_client_with_storage(&creator_seed);
    let (mut joiner, joiner_storage) = build_client_with_storage(&joiner_seed);
    let mut own_invitee = build_client(&own_seed);
    let mut sibling_invitee = build_client(&sibling_seed);

    let joiner_kp = joiner.fresh_key_package().await.unwrap();
    let (group_id, create) = creator
        .create_group(CreateGroupRequest {
            name: "router flip".into(),
            description: String::new(),
            members: vec![joiner_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![joiner.self_id()],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            creator.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    let welcome_id = welcome.id.clone();
    joiner.join_welcome(welcome).await.unwrap();
    // Play the host for the join notification: take it and acknowledge it.
    // An unacknowledged application event stays durably pending and is
    // re-delivered on every session open, so skipping the ack would hand each
    // `reopen_legacy_client` below a `GroupJoined` from this arrangement.
    joiner.drain_events();
    joiner_storage
        .delete_pending_application_events(&[welcome_id])
        .unwrap();

    let own_kp = own_invitee.fresh_key_package().await.unwrap();
    let sibling_kp = sibling_invitee.fresh_key_package().await.unwrap();
    let (own_commit, own_pending) = match joiner
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![own_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let (sibling_commit, sibling_pending) = match creator
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![sibling_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    joiner.confirm_published(own_pending).await.unwrap();
    creator.confirm_published(sibling_pending).await.unwrap();
    assert_eq!(joiner.epoch(&group_id).unwrap(), EpochId(2));

    let own_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        joiner.self_id(),
        &own_commit.payload,
    );
    let sibling_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        creator.self_id(),
        &sibling_commit.payload,
    );

    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..sibling_commit
    };
    let fixture = RouterFlipFixture {
        group_id,
        local_storage: joiner_storage,
        local_seed: joiner_seed,
        competing: routed,
        own_commit_id: own_commit.id,
        own_invitee: MemberId::new(pad32(&own_seed)),
        sibling_invitee: MemberId::new(pad32(&sibling_seed)),
        sibling_wins: sibling_key < own_key,
    };
    (fixture, joiner, creator)
}

fn settled_branch(engine: &Engine<SqliteAccountStorage>, f: &RouterFlipFixture) -> Branch {
    let members = engine.members(&f.group_id).unwrap();
    let has_sibling = members.iter().any(|m| m.id == f.sibling_invitee);
    let has_own = members.iter().any(|m| m.id == f.own_invitee);
    assert_ne!(
        has_sibling, has_own,
        "exactly one of the two forked invitees must be present"
    );
    if has_sibling {
        Branch::Sibling
    } else {
        Branch::Own
    }
}

/// Drive convergence like a runtime scheduler until the competing commit leaves
/// `Created`, letting the real P4 quiescence window elapse.
async fn drive_convergence(
    engine: &mut Engine<SqliteAccountStorage>,
    f: &RouterFlipFixture,
    competing_id: &MessageId,
) {
    for _ in 0..40 {
        engine
            .converge_stored_openmls_messages(&f.group_id)
            .expect("convergence pass runs");
        let state = f.local_storage.get_message(competing_id).unwrap().state;
        if state != MessageState::Created {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("competing commit never left MessageState::Created");
}

#[tokio::test]
async fn restarted_committer_routes_same_epoch_sibling_into_convergence() {
    // Formerly `restarted_committer_routes_same_epoch_sibling_into_convergence_not_fork_recovery`;
    // since the route unification this is the SAME route every live committer
    // takes — the test remains as the restart-shape pin.
    let (f, local) = router_flip_fixture("converge").await;
    assert!(
        f.sibling_wins,
        "fixture must make the inbound sibling commit the ordering winner"
    );
    let competing_id = MessageId::new(Sha256::digest(&f.competing.payload).to_vec());

    // The confirm path retained an anchor at the commit's SOURCE epoch, which
    // is what admits the sibling into convergence.
    assert!(
        f.local_storage
            .list_group_snapshots(&f.group_id)
            .unwrap()
            .contains(&"openmls-retained-anchor-1".to_string()),
        "confirm_published must retain a source-epoch anchor"
    );

    drop(local);
    let mut local = reopen_legacy_client(&f.local_seed, f.local_storage.clone());

    let outcome = local.ingest(f.competing.clone()).await.unwrap();
    assert!(
        !matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::AlreadyAtEpoch { .. }
            }
        ),
        "a restarted committer must not classify the sibling stale, got {outcome:?}"
    );

    drive_convergence(&mut local, &f, &competing_id).await;
    assert_eq!(
        settled_branch(&local, &f),
        Branch::Sibling,
        "convergence must still land the restarted committer on the winning branch"
    );
    assert_eq!(
        f.local_storage.get_message(&competing_id).unwrap().state,
        MessageState::Processed
    );
}

#[tokio::test]
async fn restarted_committer_without_source_anchor_halts_through_convergence() {
    // Control on the same deterministic fixture: no restart. The live
    // committer resolves the rival through the convergence pass like every
    // other member.
    let (control, mut control_local) = router_flip_fixture("control").await;
    assert!(control.sibling_wins);
    control_local
        .ingest(control.competing.clone())
        .await
        .unwrap();
    control_local
        .converge_stored_openmls_messages_at(&control.group_id, u64::MAX)
        .expect("the control fork settles through convergence");
    assert_eq!(
        settled_branch(&control_local, &control),
        Branch::Sibling,
        "the convergence pass rolls the committer onto the winning branch"
    );

    // Same fixture shape, but the device restarts AND the source-epoch anchor
    // is absent (pre-mechanism database, storage loss). The rival is then
    // unadjudicable: `has_retained_anchor_snapshot` refuses convergence
    // admission and no other resolution route exists.
    // Within the rewind horizon that absence is abnormal: the device stopped
    // at this epoch, so it anchored it, and pruning runs only beyond the
    // horizon. A fork epoch the device merely *traversed* is a different
    // shape, adjudicated from the anchor below it
    // (`convergence_rewinds_to_greatest_anchor_at_or_below_traversed_fork_epoch`).
    // With nothing at or below the fork, a durable, observable halt is the
    // honest outcome: silently keeping our own (possibly losing) branch would
    // be permanent divergence invisible to both the app and forensics.
    //
    // Ingest does not write that halt. It cannot honestly: it reaches this
    // decision through OpenMLS's `WrongEpoch` framing check, upstream of every
    // signature and membership-tag check, so the rival's claimed epoch is
    // unauthenticated (see `unauthenticated_past_epoch_rival_never_halts_the_
    // group_at_ingest`). What ingest owes is retention and a scheduled pass;
    // the halt belongs to the convergence coordinator, which owns the
    // `MissingRetainedAnchor` verdict. This pins the whole route end to end, so
    // the original silent-drop defect stays closed.
    let f = anchor_less_forked_device("silent").await;
    let competing_id = MessageId::new(Sha256::digest(&f.competing.payload).to_vec());
    let (mut local, _audit_dir, audit_path) =
        restarted_device_with_recorder(&f, "restarted-committer");
    let _ = local.drain_pending_convergence_groups();

    let outcome = local.ingest(f.competing.clone()).await.unwrap();

    // The rival's arrival is loud: retained for adjudication, never a silent
    // Stale, and never a terminal verdict derived from its own claim.
    assert_eq!(
        outcome,
        IngestOutcome::Buffered {
            group_id: f.group_id.clone(),
            epoch: EpochId(2),
        },
        "the unadjudicated rival must be retained, not silently classified stale"
    );
    assert_eq!(
        f.local_storage.get_message(&competing_id).unwrap().state,
        MessageState::Created,
        "the rival stays in the pass-opening state convergence needs"
    );
    assert!(
        !f.local_storage
            .get_group(&f.group_id)
            .unwrap()
            .unrecoverable,
        "ingest must not derive a terminal state from an unauthenticated claim"
    );

    // Retention only pays off if something opens the pass, and applications
    // open passes off `drain_pending_convergence_groups`.
    let scheduled = local.drain_pending_convergence_groups();
    assert!(
        scheduled.contains(&f.group_id),
        "ingest must hand the group holding the retained rival to the drain; got {scheduled:?}"
    );
    for group_id in &scheduled {
        let _ = local.converge_stored_openmls_messages_at(group_id, 0);
        let _ = local.converge_stored_openmls_messages_at(group_id, 60_000);
    }

    assert!(
        f.local_storage
            .get_group(&f.group_id)
            .unwrap()
            .unrecoverable,
        "missing in-horizon fork-recovery material must durably halt the group"
    );
    assert!(
        local.drain_events().iter().any(|event| matches!(
            event,
            GroupEvent::GroupUnrecoverable { group_id } if group_id == &f.group_id
        )),
        "the halt must reach the app so it can surface repair"
    );

    // Canonical state is untouched: the device keeps its own branch at its own
    // epoch until a verified repair path adjudicates the fork.
    assert_eq!(
        settled_branch(&local, &f),
        Branch::Own,
        "the halt must not adjudicate the fork without recovery material"
    );
    assert_eq!(local.epoch(&f.group_id).unwrap(), EpochId(2));

    // Drop the engine so the JsonlRecorder flushes on Drop, then pin the
    // forensic trail of the halt.
    drop(local);
    let events: Vec<marmot_forensics::AuditEvent> = std::fs::read_to_string(&audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        events.iter().any(|event| matches!(
            &event.kind,
            marmot_forensics::AuditEventKind::EpochStateChanged { new_state, reason, .. }
                if new_state == "unrecoverable" && reason == "missing_retained_anchor"
        )),
        "the durable halt must leave an audit row naming the missing material"
    );
    assert!(
        events.iter().any(|event| matches!(
            &event.kind,
            marmot_forensics::AuditEventKind::Rejection { reason, .. }
                if reason == "fork_rival_missing_retained_anchor"
        )),
        "the ingest seam must record why it could not adjudicate the rival"
    );
}

/// The `restarted_committer_without_source_anchor_halts_through_convergence`
/// precondition, without the engine: the epoch-1 fork fixture with its
/// source-epoch anchor released. The caller reopens the device (which is what
/// clears `committed_from`) once it has finished reading storage directly.
async fn anchor_less_forked_device(tag: &str) -> RouterFlipFixture {
    let (f, local) = router_flip_fixture(tag).await;
    assert!(f.sibling_wins);
    drop(local);
    f.local_storage
        .release_group_snapshot(&f.group_id, "openmls-retained-anchor-1")
        .expect("release the source-epoch anchor");
    f
}

/// Reopen the device with a forensic recorder installed. Returns the engine and
/// the audit path the recorder flushes to on drop.
fn restarted_device_with_recorder(
    f: &RouterFlipFixture,
    tag: &str,
) -> (
    Engine<SqliteAccountStorage>,
    tempfile::TempDir,
    std::path::PathBuf,
) {
    let audit_dir = tempfile::TempDir::new().unwrap();
    let audit_path = audit_dir.path().join("audit.jsonl");
    let recorder = marmot_forensics::JsonlRecorder::open(&audit_path, tag.to_string()).unwrap();
    let mut engine = EngineBuilder::new(f.local_storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(&f.local_seed))
        .account_identity_proof_signer(proof_signer(&f.local_seed))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .recorder(Box::new(recorder))
        .build()
        .unwrap();
    engine.hydrate_stable_groups_from_storage().unwrap();
    (engine, audit_dir, audit_path)
}

/// The MLS epoch a set of raw commit bytes claims, read the way ingest reads it.
fn claimed_mls_epoch(mls_bytes: &[u8]) -> EpochId {
    use openmls::framing::{MlsMessageBodyIn, MlsMessageIn, ProtocolMessage};
    use tls_codec::Deserialize as _;
    let msg_in =
        MlsMessageIn::tls_deserialize_exact(mls_bytes).expect("forged bytes still TLS-parse");
    let proto: ProtocolMessage = match msg_in.extract() {
        MlsMessageBodyIn::PublicMessage(p) => p.into(),
        MlsMessageBodyIn::PrivateMessage(p) => p.into(),
        other => panic!("expected a framed MLS message, got {other:?}"),
    };
    EpochId(proto.epoch().as_u64())
}

/// Wrap forged MLS bytes as an inbound transport message for `group_id`. The id
/// is content-derived so a forgery never dedups against the genuine rival.
fn forged_rival_envelope(
    mls_bytes: Vec<u8>,
    group_id: &cgka_traits::types::GroupId,
) -> TransportMessage {
    TransportMessage {
        id: MessageId::new(Sha256::digest(&mls_bytes).to_vec()),
        payload: mls_bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("forged-past-epoch-rival".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

/// Assert the anchor-less device's INGEST seam derives no durable terminal
/// state from `forged`, whose claimed past epoch is the only attacker-controlled
/// fact behind the halt this seam used to write.
///
/// Scoped to the ingest seam on purpose. The convergence coordinator's own
/// `MissingRetainedAnchor` halt reads a `source_epoch` that
/// `openmls_projection::project_mls_message` re-derives from the same
/// unauthenticated wire bytes for every retained commit row, so it still halts
/// this group on a later pass. That is a distinct, already-merged seam; this
/// test does not claim to cover it and must not be widened to, or it would
/// assert behavior no change at this seam can deliver.
async fn assert_forged_rival_never_halts_at_ingest(
    case: &str,
    f: &RouterFlipFixture,
    mut local: Engine<SqliteAccountStorage>,
    audit_path: &std::path::Path,
    forged: TransportMessage,
) {
    // Hydration may schedule groups of its own; drain first so the assertion
    // below observes only what ingest scheduled.
    let _ = local.drain_pending_convergence_groups();
    let outcome = local.ingest(forged).await;
    assert!(
        outcome.is_ok(),
        "{case}: an unauthenticated rival must not abort the transport drain, got {outcome:?}"
    );

    assert!(
        !f.local_storage
            .get_group(&f.group_id)
            .unwrap()
            .unrecoverable,
        "{case}: unauthenticated bytes must never write the durable terminal marker"
    );
    assert!(
        local.drain_events().iter().all(|event| !matches!(
            event,
            GroupEvent::GroupUnrecoverable { group_id } if group_id == &f.group_id
        )),
        "{case}: unauthenticated bytes must never announce a terminal group state"
    );
    // The group must stay usable: a fire-and-forget forgery cannot cost the
    // device its ability to ingest, which is what the durable halt takes away.
    assert_eq!(local.epoch(&f.group_id).unwrap(), EpochId(2));
    assert_eq!(settled_branch(&local, f), Branch::Own);

    // The rival is retained rather than dropped, so the seam still owes the
    // group a pass; applications open one off `drain_pending_convergence_groups`.
    let scheduled = local.drain_pending_convergence_groups();
    assert!(
        scheduled.contains(&f.group_id),
        "{case}: a retained, unapplied rival must schedule its group; got {scheduled:?}"
    );

    // Drop the engine so the JsonlRecorder flushes on Drop, then pin the
    // forensic trail.
    drop(local);
    let events: Vec<marmot_forensics::AuditEvent> = std::fs::read_to_string(audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        events.iter().all(|event| !matches!(
            &event.kind,
            marmot_forensics::AuditEventKind::EpochStateChanged { new_state, .. }
                if new_state == "unrecoverable"
        )),
        "{case}: unauthenticated bytes must never record a terminal state change"
    );
}

/// A rival commit reaches the missing-anchor fail-closed halt through OpenMLS's
/// `WrongEpoch` framing check, which runs BEFORE membership-tag and signature
/// verification (`validate_framing` is the first statement of `decrypt_message`).
/// Nothing cryptographic has therefore run when the halt fires, and nothing
/// could: the membership MAC needs the claimed epoch's membership key and the
/// signature covers that epoch's group context — both live in the anchor
/// snapshot that is missing by precondition.
///
/// So the claimed epoch is raw attacker input, and any member (or a removed
/// member whose epoch snapshot is still retained) can fire one parseable
/// datagram to durably freeze the group on every device whose anchor for that
/// in-horizon epoch is absent. Freezing on unauthenticated input is the bug:
/// a genuine anchor gap is a LOCAL fact and does not need the rival's word for
/// it. This pins that the rival's word alone never buys a terminal state at
/// this seam — see `assert_forged_rival_never_halts_at_ingest` for why the
/// scope stops there.
#[tokio::test]
async fn unauthenticated_past_epoch_rival_never_halts_the_group_at_ingest() {
    // Case A — signature-invalid, epoch untouched. Flipping the last byte lands
    // inside the trailing `FramedContentAuthData` / membership-tag region: the
    // message still TLS-parses and still claims in-horizon epoch 1, but it is
    // no longer authentic under any key.
    let f = anchor_less_forked_device("forged-authtag").await;
    let (local, _audit_dir, audit_path) = restarted_device_with_recorder(&f, "forged-authtag");
    let mut forged_bytes = f.competing.payload.clone();
    let last = forged_bytes.len() - 1;
    forged_bytes[last] ^= 0x01;
    assert_ne!(forged_bytes, f.competing.payload);
    assert_eq!(
        claimed_mls_epoch(&forged_bytes),
        EpochId(1),
        "the forgery must keep claiming the in-horizon source epoch"
    );
    let forged = forged_rival_envelope(forged_bytes, &f.group_id);
    assert_forged_rival_never_halts_at_ingest(
        "case A (auth-tag flip)",
        &f,
        local,
        &audit_path,
        forged,
    )
    .await;

    // Case B — epoch surgery. A commit genuinely authored at the current epoch 2
    // has its epoch field rewritten to the in-horizon past epoch 1. This is the
    // pure form of the defect: every other byte is a member's real commit, and
    // the single field that decides whether the group freezes is the one nothing
    // authenticates.
    let f = anchor_less_forked_device("forged-epoch").await;
    let local_id = MemberId::new(pad32(&f.local_seed));
    let mut forged_bytes = raw_self_update_commit(&f.local_storage, &local_id, &f.group_id).payload;
    // `MlsMessageOut` is version(u16) ++ wire_format(u16) ++ body; a
    // `PublicMessage` body opens with `FramedContent`, whose `group_id` VLBytes
    // (1-byte length for the 16-byte OpenMLS group id) precedes the fixed-width
    // `u64` epoch. Assert the field before rewriting it so a layout change fails
    // loudly here instead of silently testing nothing.
    const EPOCH_OFFSET: usize = 2 + 2 + 1 + 16;
    assert_eq!(
        &forged_bytes[EPOCH_OFFSET..EPOCH_OFFSET + 8],
        &2u64.to_be_bytes(),
        "expected the epoch field at the computed FramedContent offset"
    );
    forged_bytes[EPOCH_OFFSET..EPOCH_OFFSET + 8].copy_from_slice(&1u64.to_be_bytes());
    assert_eq!(
        claimed_mls_epoch(&forged_bytes),
        EpochId(1),
        "the rewritten commit must claim the in-horizon past epoch"
    );
    let (local, _audit_dir, audit_path) = restarted_device_with_recorder(&f, "forged-epoch");
    let forged = forged_rival_envelope(forged_bytes, &f.group_id);
    assert_forged_rival_never_halts_at_ingest(
        "case B (epoch surgery)",
        &f,
        local,
        &audit_path,
        forged,
    )
    .await;
}

/// A verified repair must STICK. `repair_to_stable`'s only production caller is
/// the authenticated-Welcome join path (mdk#971, `join_welcome_repair`), and
/// exiting the halt is worthless if the very next convergence drain walks the
/// group straight back into it.
///
/// The residue that makes this sharp is the rival ingest retained. Ingest
/// deliberately keeps it in the pass-opening `Created` state and writes no
/// terminal verdict — its claimed epoch is unauthenticated at that seam (see
/// `unauthenticated_past_epoch_rival_never_halts_the_group_at_ingest`), and the
/// pass it schedules is what lets the convergence coordinator own the
/// `MissingRetainedAnchor` halt (see
/// `restarted_committer_without_source_anchor_halts_through_convergence`). The
/// convergence seeder then re-derives that rival's source epoch from its own
/// wire bytes — an epoch this device holds no anchor for — so without a repair
/// that disposes of it, the repaired group re-halts at the repaired tip.
///
/// An authenticated Welcome is exactly the seam that can dispose of it
/// honestly: it re-anchors the device at a join epoch derived from
/// authenticated material, and everything below that epoch is material this
/// device is not a party to and can never adjudicate.
#[tokio::test]
async fn verified_welcome_repair_survives_the_next_convergence_drain() {
    let (f, local, mut creator) = router_flip_fixture_with_creator("repair-sticks").await;
    assert!(f.sibling_wins);
    let competing_id = MessageId::new(Sha256::digest(&f.competing.payload).to_vec());
    drop(local);
    f.local_storage
        .release_group_snapshot(&f.group_id, "openmls-retained-anchor-1")
        .expect("release the source-epoch anchor");
    let mut local = reopen_legacy_client(&f.local_seed, f.local_storage.clone());

    // (1) The halt, exactly as pinned by
    // `restarted_committer_without_source_anchor_halts_through_convergence`.
    let outcome = local.ingest(f.competing.clone()).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Buffered { .. }));
    let scheduled = local.drain_pending_convergence_groups();
    assert!(
        scheduled.contains(&f.group_id),
        "ingest must hand the group holding the retained rival to the drain; got {scheduled:?}"
    );
    for group_id in &scheduled {
        let _ = local.converge_stored_openmls_messages_at(group_id, 0);
        let _ = local.converge_stored_openmls_messages_at(group_id, 60_000);
    }
    assert!(
        f.local_storage
            .get_group(&f.group_id)
            .unwrap()
            .unrecoverable
    );
    assert_eq!(
        f.local_storage.get_message(&competing_id).unwrap().state,
        MessageState::Created,
        "ingest and the coordinator both leave the rival pass-opening, awaiting a verdict"
    );
    local.drain_events();

    // A halted group refuses new work — the wedge is real before the repair.
    assert!(
        local
            .send(SendIntent::SelfUpdate {
                group_id: f.group_id.clone(),
            })
            .await
            .is_err(),
        "an unrecoverable group must refuse sends"
    );

    // (2) The verified repair: the sibling author removes the wedged device
    // from the fleet's branch and re-invites it with a fresh key package.
    let device_id = MemberId::new(pad32(&f.local_seed));
    match creator
        .send(SendIntent::RemoveMembers {
            group_id: f.group_id.clone(),
            members: vec![device_id],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => {
            creator.confirm_published(pending).await.unwrap();
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    }
    let fresh_kp = local.fresh_key_package().await.unwrap();
    let welcome = match creator
        .send(SendIntent::Invite {
            group_id: f.group_id.clone(),
            key_packages: vec![fresh_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution {
            pending,
            mut welcomes,
            ..
        } => {
            creator.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let joined = local.join_welcome(welcome).await.unwrap();
    assert_eq!(joined, f.group_id, "the Welcome repairs the SAME group");
    assert!(
        !f.local_storage
            .get_group(&f.group_id)
            .unwrap()
            .unrecoverable,
        "an authenticated Welcome is a verified repair path out of the halt"
    );
    assert_eq!(
        local.epoch(&f.group_id).unwrap(),
        EpochId(4),
        "the repaired device joins the fleet's branch at the re-invite epoch"
    );
    assert_eq!(
        settled_branch(&local, &f),
        Branch::Sibling,
        "the repair lands the device on the branch it could not adjudicate"
    );

    // (3) The property under test: the repair STICKS. The rival ingest retained
    // is below the authenticated join epoch, so the repair disposed of it as
    // input; the next drain has nothing left to re-derive the halt from.
    let result = local
        .converge_stored_openmls_messages_at(&f.group_id, u64::MAX)
        .expect("the repaired group's convergence drain must run");
    assert!(
        !result
            .errors
            .iter()
            .any(|error| matches!(error, CanonicalizationError::MissingRetainedAnchor)),
        "the repair must evict the input that re-derives the halt: {:?}",
        result.errors
    );
    assert_ne!(
        result.convergence_status,
        ConvergenceStatus::Blocked,
        "a repaired group must not re-block on residue the repair superseded"
    );
    assert!(
        !f.local_storage
            .get_group(&f.group_id)
            .unwrap()
            .unrecoverable,
        "the drain must not re-halt the group the repair just cleared"
    );
    assert_eq!(
        local.epoch(&f.group_id).unwrap(),
        EpochId(4),
        "the drain must not move the repaired tip"
    );
    assert_ne!(
        f.local_storage.get_message(&competing_id).unwrap().state,
        MessageState::Created,
        "the below-join rival must leave the pass-opening set"
    );

    // Usability is the point of the repair, and it must outlive the drain.
    let probe = local
        .send(SendIntent::SelfUpdate {
            group_id: f.group_id.clone(),
        })
        .await
        .expect("the repaired group must still accept new work after a drain");
    assert!(matches!(
        probe,
        SendResult::GroupEvolution { .. } | SendResult::Queued { .. }
    ));
}

#[tokio::test]
async fn committers_losing_rival_is_reconsidered_onto_the_fleets_deeper_branch() {
    // Formerly `pairwise_loser_is_reconsidered_onto_the_fleets_deeper_branch`
    // — the go/no-go evidence for deleting the pairwise fast-path (option C
    // Slice B → C). With the routes unified, both the committer A and the
    // observer O adjudicate the same fork through distributed convergence;
    // the test remains as the eventual-agreement pin:
    //
    // - A commits `UpdateGroupData` from epoch 1, confirms, and STAYS LIVE.
    //   Seeds are arranged so A's own commit wins the ordering key and the
    //   rival root B is parked, not applied.
    // - O never commits: it resolves the identical fork through distributed
    //   convergence. At depth 1 vs 1 the ordering key makes O select A's
    //   branch first — so O must itself REORG when depth later disagrees.
    // - The rival's branch then grows two follow-on commits deeper. Under the
    //   convergence rule valid depth outranks the ordering key, so the fleet
    //   (O, and the rival committer trivially) settles the rival branch.
    //
    // The verdict this test pins: A's convergence pass re-admits the PARKED
    // loser as branch input and reorgs A onto the fleet's deeper branch —
    // committer and observer agree eventually on members, epoch, and group
    // name.

    // Privileged same-epoch commits order by committer identity: A's identity
    // must sort BEFORE the rival's so A's own commit wins the equal-depth race.
    let first = b"n5-first".as_slice();
    let second = b"n5-second".as_slice();
    let (a_id, rival_id) = if pad32(first) < pad32(second) {
        (first, second)
    } else {
        (second, first)
    };

    // Concrete Engine types: the test drives convergence passes to completion
    // explicitly (`converge_stored_openmls_messages_at`), which is not part of
    // the CgkaEngine trait surface.
    let (mut a, a_storage) = build_client_with_storage(a_id); // live committer
    let mut rival = build_client(rival_id); //                   authors the parked loser root
    let (mut observer, observer_storage) = build_client_with_storage(b"n5-observer");
    let mut eve = build_client(b"n5-eve");
    let mut frank = build_client(b"n5-frank");

    let rival_kp = rival.fresh_key_package().await.unwrap();
    let observer_kp = observer.fresh_key_package().await.unwrap();
    let (group_id, create) = a
        .create_group(CreateGroupRequest {
            name: "route-agreement".into(),
            description: String::new(),
            members: vec![rival_kp, observer_kp],
            required_features: vec![],
            app_components: vec![],
            // The rival needs admin for its UpdateGroupData root and follow-on
            // invites; the observer stays a plain member so its only
            // resolution route is distributed convergence.
            initial_admins: vec![rival.self_id()],
        })
        .await
        .unwrap();
    let (rival_welcome, observer_welcome) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            a.confirm_published(pending).await.unwrap();
            let observer_welcome = welcomes.remove(1);
            (welcomes.remove(0), observer_welcome)
        }
        _ => unreachable!(),
    };
    rival.join_welcome(rival_welcome).await.unwrap();
    observer.join_welcome(observer_welcome).await.unwrap();
    assert_eq!(a.epoch(&group_id).unwrap().0, 1);
    assert_eq!(observer.epoch(&group_id).unwrap().0, 1);

    let route = |msg: TransportMessage| TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    };

    // Rival `UpdateGroupData` commits from epoch 1: the branch-sensitive group
    // name makes the finally selected branch observable on every device.
    let a_root = match a
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("a-branch".into()),
            description: None,
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            a.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    let rival_root = match rival
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("rival-branch".into()),
            description: None,
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            rival.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    let a_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(a_id)),
        &a_root.payload,
    );
    let rival_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(rival_id)),
        &rival_root.payload,
    );
    assert!(
        a_key < rival_key,
        "seed arrangement must make A's own commit the equal-depth winner"
    );

    // Pass on A: the rival root LOSES the equal-depth ordering comparison
    // inside A's convergence pass. A keeps its own branch (no rollback) and
    // parks the loser reconsiderable at its source epoch.
    let outcome = a.ingest(route(rival_root.clone())).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "the rival root must enter A's convergence pass, got {outcome:?}"
    );
    let result = a
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the equal-depth fork settles on A");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(a.epoch(&group_id).unwrap().0, 2);
    assert_eq!(
        a_storage.get_group(&group_id).unwrap().name,
        "a-branch",
        "A must keep its own equal-depth winning branch"
    );
    let rival_root_content_id = MessageId::new(Sha256::digest(&rival_root.payload).to_vec());
    let parked = a_storage.get_message(&rival_root_content_id).unwrap();
    assert_eq!(parked.state, MessageState::ConvergenceDeferred);
    assert_eq!(parked.epoch, EpochId(1));

    // The observer consumes the same depth-1 fork through convergence. Both
    // roots are equally deep, so the ordering key decides: the observer first
    // settles A's branch — agreeing with A's own settled pass.
    observer.ingest(route(a_root.clone())).await.unwrap();
    observer.ingest(route(rival_root.clone())).await.unwrap();
    observer
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the depth-1 fork settles on the observer");
    assert_eq!(observer.epoch(&group_id).unwrap().0, 2);
    assert_eq!(
        observer_storage.get_group(&group_id).unwrap().name,
        "a-branch",
        "at equal depth the ordering key must hand the observer A's branch"
    );

    // The rival's branch grows TWO follow-on commits deeper (it never saw A's
    // commit). Depth now outranks the ordering key fleet-wide.
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let follow_on_1 = match rival
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            rival.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    let frank_kp = frank.fresh_key_package().await.unwrap();
    let follow_on_2 = match rival
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            rival.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    assert_eq!(rival.epoch(&group_id).unwrap().0, 4);

    // The observer control: its next pass must REORG off A's branch onto the
    // deeper rival branch — this is the fleet outcome A has to match.
    observer.ingest(route(follow_on_1.clone())).await.unwrap();
    observer.ingest(route(follow_on_2.clone())).await.unwrap();
    observer
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the deeper rival branch settles on the observer");
    assert_eq!(
        observer.epoch(&group_id).unwrap().0,
        4,
        "the observer must reorg onto the deeper rival branch"
    );
    assert_eq!(
        observer_storage.get_group(&group_id).unwrap().name,
        "rival-branch"
    );

    // THE QUESTION UNDER TEST. A — whose settled pass kept its own branch
    // and parked the rival root — ingests the follow-ons and runs its next
    // convergence pass. The parked loser must be re-admitted as branch input
    // and A must follow the fleet.
    let outcome_1 = a.ingest(route(follow_on_1)).await.unwrap();
    assert!(
        matches!(outcome_1, IngestOutcome::Buffered { .. }),
        "the first rival follow-on must enter the convergence pass, got {outcome_1:?}"
    );
    let outcome_2 = a.ingest(route(follow_on_2)).await.unwrap();
    assert!(
        matches!(outcome_2, IngestOutcome::Buffered { .. }),
        "the second rival follow-on must enter the convergence pass, got {outcome_2:?}"
    );
    let result = a
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("A's pass reconsiders the parked loser");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);

    // VERDICT: eventual agreement between committer and observer — members,
    // epoch, and group name.
    let sorted_members = |members: Vec<cgka_traits::group::Member>| {
        let mut ids: Vec<_> = members.into_iter().map(|m| m.id).collect();
        ids.sort_by(|x, y| x.as_slice().cmp(y.as_slice()));
        ids
    };
    let a_members = sorted_members(a.members(&group_id).unwrap());
    let observer_members = sorted_members(observer.members(&group_id).unwrap());
    let rival_members = sorted_members(rival.members(&group_id).unwrap());
    assert_eq!(
        a_members, observer_members,
        "the committer and the convergence-resolved observer must agree"
    );
    assert_eq!(
        observer_members, rival_members,
        "the observer must match the rival branch author"
    );
    assert!(a_members.contains(&MemberId::new(pad32(b"n5-eve"))));
    assert!(a_members.contains(&MemberId::new(pad32(b"n5-frank"))));
    assert_eq!(
        a.epoch(&group_id).unwrap().0,
        4,
        "A must reach the fleet's tip"
    );
    assert_eq!(
        a_storage.get_group(&group_id).unwrap().name,
        "rival-branch",
        "A must surface the selected branch's group data"
    );
    let realized_root = a_storage.get_message(&rival_root_content_id).unwrap();
    assert_eq!(
        realized_root.state,
        MessageState::Processed,
        "the parked loser must become canonical, not stay parked"
    );
}

/// Pins both halves of the rollback-announcement seam (defects (a) + (e)).
///
/// `emit_rolled_back_commits` announces the `CommitRolledBack` +
/// `GroupStateInvalidated` withdrawal pair for every commit a pass parks
/// `ConvergenceDeferred` / `NonSelectedEligibleBranch`. That state is
/// *reconsiderable*, so the same commit can be parked by pass after pass and
/// can later be RE-ADOPTED onto the selected branch. Neither used to be handled:
///
/// - (a) every pass that re-parked the same commit re-announced the identical
///   withdrawal pair, so announcement history was not evidence of anything.
/// - (e) the withdrawal was never taken back. Since #1608 made storage-side
///   invalidation terminal, the re-adopted commit's kind-1210 rows stayed
///   tombstoned forever.
///
/// Both are fixed, and this test is what holds them fixed: the scenario walks
/// one commit through park → re-park → re-adoption on a single device, and
/// asserts one withdrawal across the two parkings plus a revalidation on the
/// re-adoption.
#[tokio::test]
async fn reparked_and_readopted_commit_announces_once_and_is_revalidated() {
    // A's identity must sort before the rival's so A's own commit wins the
    // equal-depth ordering race in every pass below.
    let first = b"wd-first".as_slice();
    let second = b"wd-second".as_slice();
    let (a_id, rival_id) = if pad32(first) < pad32(second) {
        (first, second)
    } else {
        (second, first)
    };
    let (mut a, a_storage) = build_client_with_storage(a_id);
    let mut rival = build_client(rival_id);
    let mut eve = build_client(b"wd-eve");
    let mut frank = build_client(b"wd-frank");

    let rival_kp = rival.fresh_key_package().await.unwrap();
    let (group_id, create) = a
        .create_group(CreateGroupRequest {
            name: "withdrawal-lifecycle".into(),
            description: String::new(),
            members: vec![rival_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![rival.self_id()],
        })
        .await
        .unwrap();
    let rival_welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            a.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        _ => unreachable!(),
    };
    rival.join_welcome(rival_welcome).await.unwrap();
    assert_eq!(a.epoch(&group_id).unwrap().0, 1);

    let route = |msg: TransportMessage| TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    };
    let rename = |name: &str| SendIntent::UpdateGroupData {
        group_id: group_id.clone(),
        name: Some(name.to_owned()),
        description: None,
    };

    // Rival branch root, authored from epoch 1 and never delivered to A until
    // after A has committed its own epoch-1 rival.
    let rival_root = match rival.send(rename("rival-branch")).await.unwrap() {
        SendResult::GroupEvolution { msg, pending, .. } => {
            rival.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    let rival_root_id = MessageId::new(Sha256::digest(&rival_root.payload).to_vec());

    let a_root = match a.send(rename("a-branch")).await.unwrap() {
        SendResult::GroupEvolution { pending, msg, .. } => {
            a.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    let a_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(a_id)),
        &a_root.payload,
    );
    let rival_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(rival_id)),
        &rival_root.payload,
    );
    assert!(a_key < rival_key, "A must win the equal-depth ordering key");

    // --- Pass 1: A parks the rival root and announces its withdrawal. -------
    a.ingest(route(rival_root.clone())).await.unwrap();
    a.converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the equal-depth fork settles on A");
    assert_eq!(
        a_storage.get_message(&rival_root_id).unwrap().state,
        MessageState::ConvergenceDeferred
    );
    let pass_1 = a.drain_events();
    assert_eq!(
        withdrawals_naming(&pass_1, &rival_root_id),
        1,
        "pass 1 must announce the parked rival's withdrawal exactly once: {pass_1:?}"
    );

    // A deepens its own branch to depth 2 so the next pass re-parks the rival
    // root (equal depth, A still wins the ordering key) instead of adopting it.
    match a.send(rename("a-branch-2")).await.unwrap() {
        SendResult::GroupEvolution { pending, .. } => a.confirm_published(pending).await.unwrap(),
        _ => unreachable!(),
    };
    assert_eq!(a.epoch(&group_id).unwrap().0, 3);

    // The rival branch grows two follow-ons; A learns them one at a time.
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let follow_on_1 = match rival
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            rival.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };
    let frank_kp = frank.fresh_key_package().await.unwrap();
    let follow_on_2 = match rival
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            rival.confirm_published(pending).await.unwrap();
            msg
        }
        _ => unreachable!(),
    };

    // --- Pass 2: the rival root is RE-parked. No second announcement. ------
    a.ingest(route(follow_on_1)).await.unwrap();
    a.converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the equal-depth fork settles again on A");
    assert_eq!(
        a_storage.get_message(&rival_root_id).unwrap().state,
        MessageState::ConvergenceDeferred,
        "pass 2 must re-park the rival root, not adopt it"
    );
    let pass_2 = a.drain_events();
    assert_eq!(
        withdrawals_naming(&pass_2, &rival_root_id),
        0,
        "(a) a re-parked commit must not re-announce a withdrawal: {pass_2:?}"
    );

    // --- Pass 3: the rival branch outgrows A's; the parked root is adopted. -
    a.ingest(route(follow_on_2)).await.unwrap();
    a.converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("A reorgs onto the deeper rival branch");
    assert_eq!(
        a_storage.get_message(&rival_root_id).unwrap().state,
        MessageState::Processed,
        "the parked root must become canonical"
    );
    assert_eq!(
        a_storage.get_group(&group_id).unwrap().name,
        "rival-branch",
        "A must surface the adopted branch's group data"
    );
    let pass_3 = a.drain_events();
    assert_eq!(
        pass_3
            .iter()
            .filter(|event| matches!(
                event,
                GroupEvent::GroupStateRevalidated { revalidated_commit_id, .. }
                    if revalidated_commit_id == &rival_root_id
            ))
            .count(),
        1,
        "(e) re-adopting a withdrawn commit must take its withdrawal back: {pass_3:?}"
    );
    assert_eq!(
        withdrawals_naming(&pass_3, &rival_root_id),
        0,
        "an adopted commit must never be named by a withdrawal: {pass_3:?}"
    );
}

/// Number of `GroupStateInvalidated` withdrawals in `events` naming `commit_id`.
fn withdrawals_naming(events: &[GroupEvent], commit_id: &MessageId) -> usize {
    events
        .iter()
        .filter(|event| {
            matches!(
                event,
                GroupEvent::GroupStateInvalidated { invalidated_commit_id, .. }
                    if invalidated_commit_id == commit_id
            )
        })
        .count()
}

// --- U4 event fidelity: what a convergence apply tells the app --------------
//
// `emit_rolled_back_commits` / `emit_superseded_processed_commits`
// (distributed_convergence.rs) are the only paths that withdraw state
// notifications on the stored-convergence seam. #1285 touched this region
// (own commits now materialize from commit-addressed checkpoints, so a kept
// own commit lands in `accepted_commits` instead of having no disposition).
// These two tests pin the EXACT GroupEvent set a settling pass emits when it
// (i) keeps the device's own commit and (ii) replaces it — the event contract
// the pairwise-route deletion (Slice C) had to preserve.

#[tokio::test]
async fn convergence_pass_that_keeps_the_own_commit_emits_no_own_withdrawal() {
    // Keep-own arm. A restarted committer routes the losing sibling through
    // stored convergence; the pass keeps the device's own (ordering-winning)
    // branch. The pre-#1285 hazard was a spurious withdrawal of the KEPT own
    // commit: with no checkpoint the own commit could not be materialized
    // into the accepted set, so the superseded-processed sweep saw a
    // `Processed` commit row with no disposition and invalidated it — telling
    // the app to tombstone rows for a commit the device still stands on.
    // #1285's checkpoint materialization closes that: this test pins the
    // clean behavior.
    let (f, local) = router_flip_fixture_arranged("u4-keep", false).await;
    assert!(
        !f.sibling_wins,
        "fixture must make the device's own commit the ordering winner"
    );
    let competing_id = MessageId::new(Sha256::digest(&f.competing.payload).to_vec());
    drop(local);
    let mut local = reopen_legacy_client(&f.local_seed, f.local_storage.clone());

    let outcome = local.ingest(f.competing.clone()).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "the losing sibling must enter the convergence pass, got {outcome:?}"
    );
    assert!(
        local.drain_events().is_empty(),
        "buffering the rival must not be application-visible"
    );
    // The withdrawal below names a commit this device never applied. Pinning the
    // pre-pass state makes that deliberate: `emit_rolled_back_commits` reads the
    // pre-apply state only to suppress a repeat announcement, never to require
    // prior local application, so narrowing it to `Processed` would silence the
    // pair a non-adopting peer records as its share of the fleet's agreement
    // about which commit lost.
    assert_eq!(
        f.local_storage.get_message(&competing_id).unwrap().state,
        MessageState::Created,
        "the rival must reach the settling pass never having been applied"
    );

    drive_convergence(&mut local, &f, &competing_id).await;
    assert_eq!(settled_branch(&local, &f), Branch::Own);
    assert_eq!(local.epoch(&f.group_id).unwrap(), EpochId(2));

    // The exact application-visible output of the settling pass: the losing
    // sibling's withdrawal pair, and nothing else — no epoch change, no
    // membership diff (the canonical state did not move), and above all no
    // event naming the KEPT own commit.
    let events = local.drain_events();
    assert!(
        events.iter().all(|event| match event {
            GroupEvent::CommitRolledBack {
                invalidated_commit_id,
                ..
            }
            | GroupEvent::GroupStateInvalidated {
                invalidated_commit_id,
                ..
            } => invalidated_commit_id != &f.own_commit_id,
            _ => true,
        }),
        "a kept own commit must never be withdrawn: {events:?}"
    );
    assert_eq!(
        events.len(),
        2,
        "the settling pass must emit exactly the sibling's withdrawal pair: {events:?}"
    );
    assert!(
        matches!(
            &events[0],
            GroupEvent::CommitRolledBack { group_id, invalidated_commit_id }
                if group_id == &f.group_id && invalidated_commit_id == &competing_id
        ),
        "first event must roll back the losing sibling: {events:?}"
    );
    assert!(
        matches!(
            &events[1],
            GroupEvent::GroupStateInvalidated { group_id, epoch, invalidated_commit_id, reason }
                if group_id == &f.group_id
                    && *epoch == EpochId(1)
                    && invalidated_commit_id == &competing_id
                    && *reason == cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection
        ),
        "second event must withdraw the sibling's state notifications at its source epoch: {events:?}"
    );

    // Dispositions: the kept own commit stays canonical; the losing sibling is
    // parked reconsiderable at its source epoch (N4 — not terminally
    // invalidated), so a later deeper rival branch can still be materialized.
    assert_eq!(
        f.local_storage.get_message(&f.own_commit_id).unwrap().state,
        MessageState::Processed,
        "the kept own commit must stay canonical"
    );
    let sibling = f.local_storage.get_message(&competing_id).unwrap();
    assert_eq!(sibling.state, MessageState::ConvergenceDeferred);
    assert_eq!(sibling.epoch, EpochId(1));
}

#[tokio::test]
async fn convergence_pass_that_replaces_the_own_commit_withdraws_it_exactly_once() {
    // Replace-own arm. Same restarted-committer route, but the inbound sibling
    // wins the ordering: the pass reorgs the device off its own published-and-
    // confirmed commit. Spec (convergence.md "Applying the selected branch"):
    // superseding a previously applied commit — including the device's own —
    // MUST withdraw the state notifications attributed to it, exactly once.
    let (f, local) = router_flip_fixture_arranged("u4-replace", true).await;
    assert!(
        f.sibling_wins,
        "fixture must make the inbound sibling commit the ordering winner"
    );
    let competing_id = MessageId::new(Sha256::digest(&f.competing.payload).to_vec());
    drop(local);
    let mut local = reopen_legacy_client(&f.local_seed, f.local_storage.clone());

    let outcome = local.ingest(f.competing.clone()).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "the winning sibling must enter the convergence pass, got {outcome:?}"
    );
    assert!(
        local.drain_events().is_empty(),
        "buffering the rival must not be application-visible"
    );

    drive_convergence(&mut local, &f, &competing_id).await;
    assert_eq!(settled_branch(&local, &f), Branch::Sibling);
    assert_eq!(local.epoch(&f.group_id).unwrap(), EpochId(2));

    // The exact application-visible output of the settling pass: the reorg's
    // membership diff (the sibling's invitee replaces the own invitee — both
    // unattributed, stamped with the winning commit as origin), then the own
    // commit's withdrawal pair. Same-numbered epochs on both branches, so no
    // EpochChanged.
    let events = local.drain_events();
    let state_changes: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::GroupStateChanged {
                group_id,
                epoch,
                actor,
                change,
                ..
            } if group_id == &f.group_id => Some((epoch, actor, change)),
            _ => None,
        })
        .collect();
    assert_eq!(
        state_changes.len(),
        2,
        "the reorg must announce exactly the two membership deltas: {events:?}"
    );
    assert!(
        state_changes.iter().any(|(epoch, actor, change)| {
            **epoch == EpochId(2)
                && actor.is_none()
                && matches!(
                    change,
                    cgka_traits::engine::GroupStateChange::MemberAdded { member }
                        if member == &f.sibling_invitee
                )
        }),
        "the winning branch's invitee must be announced: {events:?}"
    );
    assert!(
        state_changes.iter().any(|(epoch, actor, change)| {
            **epoch == EpochId(2)
                && actor.is_none()
                && matches!(
                    change,
                    cgka_traits::engine::GroupStateChange::MemberRemoved { member }
                        if member == &f.own_invitee
                )
        }),
        "the abandoned own branch's invitee must be withdrawn from membership: {events:?}"
    );
    let withdrawals: Vec<_> = events
        .iter()
        .filter(|event| {
            matches!(
                event,
                GroupEvent::CommitRolledBack { .. } | GroupEvent::GroupStateInvalidated { .. }
            )
        })
        .collect();
    assert_eq!(
        withdrawals.len(),
        2,
        "the superseded own commit must be withdrawn exactly once: {events:?}"
    );
    assert!(
        matches!(
            withdrawals[0],
            GroupEvent::CommitRolledBack { group_id, invalidated_commit_id }
                if group_id == &f.group_id && invalidated_commit_id == &f.own_commit_id
        ),
        "the rollback must name the own commit by its stored id: {events:?}"
    );
    assert!(
        matches!(
            withdrawals[1],
            GroupEvent::GroupStateInvalidated { group_id, epoch, invalidated_commit_id, reason }
                if group_id == &f.group_id
                    && *epoch == EpochId(1)
                    && invalidated_commit_id == &f.own_commit_id
                    && *reason == cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection
        ),
        "the withdrawal must name the own commit at its source epoch: {events:?}"
    );
    assert_eq!(
        events.len(),
        4,
        "the settling pass must emit exactly the membership diff plus the own-commit withdrawal pair: {events:?}"
    );

    // Dispositions: the winning sibling becomes canonical; the displaced own
    // commit is parked reconsiderable at its source epoch (a peer that
    // applied the own commit and never saw the sibling can still deepen that
    // branch, and this device must be able to follow).
    assert_eq!(
        f.local_storage.get_message(&competing_id).unwrap().state,
        MessageState::Processed
    );
    let own = f.local_storage.get_message(&f.own_commit_id).unwrap();
    assert_eq!(
        own.state,
        MessageState::ConvergenceDeferred,
        "the displaced own commit must stay reconsiderable"
    );
    assert_eq!(own.epoch, EpochId(1));
}
