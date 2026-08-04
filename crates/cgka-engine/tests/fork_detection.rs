//! Fork detection and recovery.
//!
//! A concurrent-invite scenario deliberately produces divergent epoch-2
//! histories. The engine should:
//! - Recognize the fork via `committed_from_epochs` + inbound WrongEpoch
//! - Compare deterministic transport ordering keys
//! - Roll back to the pre-commit snapshot if the inbound commit wins
//! - Apply the winning commit and return to Stable

use async_trait::async_trait;
use cgka_engine::canonicalization::{CanonicalizationPolicy, ConvergenceStatus};
use cgka_engine::convergence::ConvergencePolicy;
use cgka_engine::feature_registry::FeatureRegistry;
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
use cgka_traits::message::MessageState;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerStorage, GroupStorage, MessageStorage, StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::group::MlsGroup;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider as _;
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
    engine.hydrate_stable_groups_from_storage().unwrap();
    engine
}

/// Restart under the SAME legacy-compatibility profile `build_client` used.
/// The restart-routing tests below must isolate the fork-routing rebuild:
/// reopening under `ProtocolProfile::Current` would additionally arm the
/// strict-cutover probe gate, which rejects the rival Add commit outright
/// (see `strict_cutover_legacy_add_cannot_displace_valid_fork_incumbent`)
/// instead of letting it race the incumbent.
fn reopen_legacy_client(id: &[u8], storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    let mut engine = EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    engine.hydrate_stable_groups_from_storage().unwrap();
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
    let mut alice = build_client(b"alice");
    let mut bob = build_client(b"bob");
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

    // Loser ingests winner's commit → fork recovery rolls them back.
    let (winning_invitee, losing_invitee) = if bob_wins {
        alice.ingest(route(bob_commit.clone())).await.unwrap();
        let events = alice.drain_events();
        let (source_epoch, recovered_epoch, winner, invalidated) =
            extract_fork_recovered(&events, &group_id)
                .expect("alice should emit ForkRecovered after rolling back to Bob's commit");
        assert_eq!(source_epoch.0, 1);
        assert_eq!(recovered_epoch.0, 2);
        assert_eq!(winner, &bob_key);
        assert_eq!(invalidated, &alice_key);
        assert!(winner < invalidated);
        assert_eq!(alice.epoch(&group_id).unwrap().0, 2);
        ("eve", "david")
    } else {
        bob.ingest(route(alice_commit.clone())).await.unwrap();
        let events = bob.drain_events();
        let (source_epoch, recovered_epoch, winner, invalidated) =
            extract_fork_recovered(&events, &group_id)
                .expect("bob should emit ForkRecovered after rolling back to Alice's commit");
        assert_eq!(source_epoch.0, 1);
        assert_eq!(recovered_epoch.0, 2);
        assert_eq!(winner, &alice_key);
        assert_eq!(invalidated, &bob_key);
        assert!(winner < invalidated);
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

    // Winner ingests loser's commit. Should be classified as stale, not roll
    // the winner back off their already-winning branch.
    let outcome = if bob_wins {
        bob.ingest(route(alice_commit)).await.unwrap()
    } else {
        alice.ingest(route(bob_commit)).await.unwrap()
    };
    use cgka_traits::ingest::{IngestOutcome, StaleReason};
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadyAtEpoch { .. }
        }
    ));
}

#[tokio::test]
async fn strict_cutover_legacy_add_cannot_displace_valid_fork_incumbent() {
    use cgka_traits::ingest::{IngestOutcome, StaleReason};
    use sha2::{Digest, Sha256};

    // Both commits below are privileged, so choose identities that make the
    // forbidden Add sort before the valid incumbent. This pins the exact
    // failure mode: without the probe-time strict-cutover gate, fork recovery
    // rolls back the incumbent before normal ingest rejects the Add.
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
    let outcome = incumbent.ingest(routed_add).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::InvalidAgainstCanonicalState
            }
        ),
        "probe-time strict cutover must reject the candidate before selection, got {outcome:?}"
    );

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
        MessageState::Failed,
        "the forbidden candidate must be retired terminally"
    );
    assert!(
        incumbent
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::ForkRecovered { .. })),
        "a candidate rejected by the probe must never emit ForkRecovered"
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

    let outcome = alice.ingest(self_update).await.unwrap();
    use cgka_traits::ingest::{IngestOutcome, StaleReason};
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadyAtEpoch {
                current: EpochId(2),
                msg_epoch: EpochId(1),
            }
        }
    ));
    let events = alice.drain_events();
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, GroupEvent::ForkRecovered { .. })),
        "ordinary self-update must not win fork recovery over privileged remove"
    );
    let members = alice.members(&group_id).unwrap();
    assert!(
        !members.iter().any(|member| member.id == bob_id),
        "Bob remains removed; the grinding self-update cannot resurrect him"
    );
}

/// A peer's same-epoch commit that arrives during our own `PendingPublish`
/// window is buffered `Retryable` before any peel. When our own commit confirms
/// and wins the fork, replay must reclassify the buffered commit: the content
/// row parks `ConvergenceDeferred` — reconsiderable, not terminal, because
/// nodes that did not commit from that epoch resolve the same conflict through
/// distributed convergence, where the rival branch can still win by growing
/// deeper (see `pairwise_incumbent_defers_to_deeper_convergence_branch`) — and
/// the raw transport wrapper is retired `Processed`, not left `Retryable` to be
/// re-peeled on every later publish-cycle replay.
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

    // Confirm advances Alice to epoch 2 and replays the backlog. The buffered
    // commit loses the fork to the incumbent (privileged > ordinary).
    alice.confirm_published(remove_pending).await.unwrap();
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(2));

    assert_eq!(
        alice_storage.get_message(&content_id).unwrap().state,
        MessageState::ConvergenceDeferred,
        "the pairwise-losing fork commit's content row is parked reconsiderable \
         (cross-seam: distributed convergence may still select its branch if it \
         grows deeper), not terminally EpochInvalidated"
    );
    assert_eq!(
        alice_storage.get_message(&raw_id).unwrap().state,
        MessageState::Processed,
        "the raw transport wrapper must be retired terminal after replay — not \
         left Retryable to be re-peeled on every later publish cycle"
    );
    assert!(
        alice
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::ForkRecovered { .. })),
        "the incumbent won the fork; no rollback / ForkRecovered is emitted"
    );
}

/// Two peer rows buffered during our own `PendingPublish` window replay in a
/// single pass. The first is a privileged admin `RemoveMembers` that removes
/// our leaf; being privileged it deterministically wins the same-source-epoch
/// fork over our own ordinary `UpdateGroupData`, so on confirm-replay fork
/// recovery rolls us back and applies it inline — our local group state goes
/// `Inactive`. The second buffered row is then re-ingested against that
/// inactive state, so `ingest_group_message` classifies it `SelfEvicted` and
/// persists its raw row `Failed` (authenticated evidence we were removed).
///
/// Replay retires the backlog, and that retirement must only touch rows STILL
/// awaiting retry after re-ingest. The unconditional retirement write introduced
/// in ae616488 violates this in two ways in exactly this scenario: it errors
/// (`Storage(NotFound)`) on the winning remove's raw row, which fork-recovery
/// rollback already swept away, and — the invariant this guards — it would
/// relabel the `SelfEvicted` row `Processed`, clobbering the `Failed` verdict
/// ingest committed. A `Processed` raw row is a canonicalization input
/// (`openmls_projection` / `distributed_convergence` select on it), so a row we
/// were evicted on must stay `Failed`, never be swept back into convergence.
#[tokio::test]
async fn buffered_self_evicted_row_stays_failed_not_swept_processed_on_replay() {
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

    // A second epoch-1 message from Bob, produced before he advances. On replay
    // this is the row that classifies `SelfEvicted` once Alice's leaf is gone —
    // its content is never peeled (the `!is_active` gate fires first).
    let second = route(raw_self_update_commit(&bob_storage, &bob_id, &group_id));
    let second_id = second.id.clone();

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
    // replays the backlog. The buffered remove is a same-source-epoch fork the
    // privileged committer wins, so fork recovery rolls Alice back and applies
    // it inline — evicting her leaf — before the second row is replayed.
    alice.confirm_published(staged).await.unwrap();

    // The buffered remove really did evict Alice on replay.
    assert!(
        !alice
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == alice_id),
        "the buffered remove must have evicted Alice on replay"
    );

    // Regression: the `SelfEvicted` row's raw wrapper must keep the `Failed`
    // state ingest committed — never clobbered to `Processed`.
    assert_eq!(
        alice_storage.get_message(&second_id).unwrap().state,
        MessageState::Failed,
        "a row we were evicted on must stay Failed after replay, not be swept \
         into canonicalization as Processed"
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

    let policy = CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    };
    alice
        .set_group_convergence_policy(&group_id, policy)
        .unwrap();

    // Bob produces a same-source-epoch commit from epoch 1, then Alice advances
    // two epochs without seeing it. Once Alice is at epoch 3 and the policy
    // keeps only one rewind commit, source epoch 1 is outside the recovery
    // horizon and must be classified as a stale commit, not a recoverable fork.
    let dave_kp = dave.fresh_key_package().await.unwrap();
    let late_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![dave_kp],
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

    for i in 0..2 {
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
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(3));

    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..late_commit
    };
    let outcome = alice.ingest(routed).await.unwrap();
    use cgka_traits::ingest::{IngestOutcome, StaleReason};
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadyAtEpoch {
                current: EpochId(3),
                msg_epoch: EpochId(1),
            }
        }
    ));
    let events = alice.drain_events();
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, GroupEvent::ForkRecovered { .. })),
        "late commits outside the rewind horizon must not trigger fork recovery"
    );
}

fn extract_fork_recovered<'a>(
    events: &'a [GroupEvent],
    group_id: &cgka_traits::types::GroupId,
) -> Option<(
    EpochId,
    EpochId,
    &'a CommitOrderingKey,
    &'a CommitOrderingKey,
)> {
    events.iter().find_map(|event| match event {
        GroupEvent::ForkRecovered {
            group_id: event_group,
            source_epoch,
            recovered_epoch,
            winner,
            invalidated,
            ..
        } if event_group == group_id => {
            Some((*source_epoch, *recovered_epoch, winner, invalidated))
        }
        _ => None,
    })
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
    // Regression: `do_send_invite` used to record `committed_from` BEFORE
    // staging the commit. When staging failed, the cleanup guard cleared the
    // OpenMLS pending commit but nothing pruned the phantom "we committed
    // from this epoch" entry. Once Alice later advanced past that epoch via a
    // PEER's commit (settled through convergence — so no fork-recovery
    // incumbent of her own exists), a legitimate same-epoch sibling commit
    // was mis-routed: the phantom blocked convergence entry, the WrongEpoch
    // fork branch found no recovery snapshot, and ingest failed closed with
    // ForkedEpoch, sticking the group in Recovering. `committed_from` is now
    // recorded only inside `begin_pending`, atomically with the transition.
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
    // detection`, for the POST-staging failure: staging succeeds, so
    // `begin_pending` records `committed_from`, and then the publish fails.
    // `rollback_publish` used to clear the staged commit and drop its
    // recovery snapshot but leave the provisional `committed_from` entry
    // behind. Once Alice later advanced past that epoch via a peer's commit,
    // a legitimate late same-epoch sibling hit the phantom entry, found no
    // recovery snapshot, and failed closed with ForkedEpoch. Rollback now
    // removes the provisional entry it recorded.
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

    // Alice's invite stages successfully — `begin_pending` records the
    // provisional `committed_from` entry — and then the publish fails.
    let mut frank = build_client(b"rollback-frank");
    let frank_kp = frank.fresh_key_package().await.unwrap();
    let staged = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
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
        })
        .await
        .expect("group must remain usable after rolled-back publish + sibling commit");
    assert!(matches!(
        recovery_probe,
        SendResult::GroupEvolution { .. } | SendResult::Queued { .. }
    ));
}

#[tokio::test]
async fn pairwise_incumbent_defers_to_deeper_convergence_branch() {
    // Cross-seam divergence, as observed in multi-VM soak runs: a node that
    // committed from epoch N resolves a same-epoch rival PAIRWISE
    // (ForkRecoveryManager — ordering key only, depth-blind), while every
    // node that did NOT commit from N resolves the same conflict through
    // distributed convergence, where a deeper valid branch outranks the
    // ordering key. If the pairwise loser is invalidated terminally, the
    // pairwise node can never follow the fleet onto the rival branch once
    // that branch grows — a permanent lineage split in which each side keeps
    // decrypting only its own history.
    //
    // This test drives the exact sequence: the pairwise winner must first
    // reject the rival root (incumbent wins on the ordering key), then
    // CONVERGE onto the rival branch after a follow-on commit makes it the
    // deeper valid branch.
    use cgka_traits::ingest::{IngestOutcome, StaleReason};

    // Fix which identity wins the pairwise race up front (privileged admin
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
    let (mut winner, winner_storage) = build_client_with_storage(winner_id); // pairwise incumbent-keeper
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
        })
        .await
        .unwrap();
    let loser_invite = loser
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
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
        "identity choice must make the incumbent win the pairwise race"
    );

    // Seam 1 on the winner: the rival root LOSES the pairwise race. The
    // winner keeps its own branch (no ForkRecovered), and — the fix under
    // test — the loser's root must stay reconsiderable, not terminally
    // invalidated.
    let outcome = winner.ingest(route(loser_root.clone())).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadyAtEpoch { .. }
        }
    ));
    let events = winner.drain_events();
    assert!(
        extract_fork_recovered(&events, &group_id).is_none(),
        "incumbent-wins must not roll the winner back"
    );
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
        "the pairwise loser-root must be parked reconsiderable, not terminally invalidated"
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

    // Seam 2 on the winner: the follow-on commit routes into distributed
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
        "the abandoned pairwise branch's invitee must be gone"
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

/// Shared fixture for the restart-routing tests: `local` creates the group
/// with `rival` as a second admin, then both invite someone from epoch 1
/// without seeing each other's commit — a same-epoch privileged fork. Both
/// confirm their own publish. Returns local's storage (for the restart), the
/// two competing epoch-1 commits, and the group id.
async fn forked_privileged_invites(
    local_id: &[u8],
    rival_id: &[u8],
    local_invitee_id: &[u8],
    rival_invitee_id: &[u8],
) -> (
    cgka_traits::types::GroupId,
    SqliteAccountStorage,
    TransportMessage,
    TransportMessage,
) {
    let (mut local, local_storage) = build_client_with_storage(local_id);
    let mut rival = build_client(rival_id);
    let mut local_invitee = build_client(local_invitee_id);
    let mut rival_invitee = build_client(rival_invitee_id);

    let rival_kp = rival.fresh_key_package().await.unwrap();
    let (group_id, create) = local
        .create_group(CreateGroupRequest {
            name: "restart-routing".into(),
            description: String::new(),
            members: vec![rival_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![rival.self_id()],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            local.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        _ => unreachable!(),
    };
    rival.join_welcome(welcome).await.unwrap();
    assert_eq!(local.epoch(&group_id).unwrap().0, 1);
    assert_eq!(rival.epoch(&group_id).unwrap().0, 1);

    let local_invitee_kp = local_invitee.fresh_key_package().await.unwrap();
    let rival_invitee_kp = rival_invitee.fresh_key_package().await.unwrap();
    let local_invite = local
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![local_invitee_kp],
        })
        .await
        .unwrap();
    let rival_invite = rival
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![rival_invitee_kp],
        })
        .await
        .unwrap();
    let (local_commit, rival_root) = match (local_invite, rival_invite) {
        (
            SendResult::GroupEvolution {
                msg: l,
                pending: lp,
                ..
            },
            SendResult::GroupEvolution {
                msg: r,
                pending: rp,
                ..
            },
        ) => {
            local.confirm_published(lp).await.unwrap();
            rival.confirm_published(rp).await.unwrap();
            (l, r)
        }
        _ => unreachable!(),
    };
    assert_eq!(local.epoch(&group_id).unwrap().0, 2);
    (group_id, local_storage, local_commit, rival_root)
}

#[tokio::test]
async fn restarted_incumbent_keeper_still_resolves_pairwise_and_parks_loser_root() {
    // The fork-routing state (`committed_from` + the fork-recovery incumbent)
    // used to live only in memory: a RESTARTED member that had committed from
    // epoch 1 no longer knew it, so the same-epoch rival detoured through
    // distributed convergence instead of losing the pairwise race. After the
    // hydrate-time rebuild, the restarted path must be byte-for-byte the
    // no-restart path of `pairwise_incumbent_defers_to_deeper_convergence_branch`:
    // Stale/AlreadyAtEpoch, no ForkRecovered, and the loser root parked
    // `ConvergenceDeferred` at its source epoch.
    use cgka_traits::ingest::{IngestOutcome, StaleReason};

    // The local (restarted) member must WIN the pairwise race: privileged
    // same-epoch commits order by committer identity, lower wins.
    let first = b"restart-park-first".as_slice();
    let second = b"restart-park-second".as_slice();
    let (local_id, rival_id) = if pad32(first) < pad32(second) {
        (first, second)
    } else {
        (second, first)
    };
    let (group_id, local_storage, local_commit, rival_root) = forked_privileged_invites(
        local_id,
        rival_id,
        b"restart-park-david",
        b"restart-park-eve",
    )
    .await;

    let local_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(local_id)),
        &local_commit.payload,
    );
    let rival_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(rival_id)),
        &rival_root.payload,
    );
    assert!(
        local_key < rival_key,
        "identity choice must make the restarted incumbent win the pairwise race"
    );

    // RESTART: routing state must be rebuilt from durable evidence, not lost.
    let mut local = reopen_legacy_client(local_id, local_storage.clone());
    assert_eq!(local.epoch(&group_id).unwrap().0, 2);
    let _ = local.drain_events();

    let outcome = local
        .ingest(TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..rival_root.clone()
        })
        .await
        .unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::AlreadyAtEpoch { .. }
            }
        ),
        "restart must not reroute the pairwise loser into convergence, got {outcome:?}"
    );
    let events = local.drain_events();
    assert!(
        extract_fork_recovered(&events, &group_id).is_none(),
        "incumbent-wins must not roll the restarted winner back"
    );
    assert_eq!(local.epoch(&group_id).unwrap().0, 2);

    // Same parked disposition as the no-restart path: `ConvergenceDeferred`
    // (reconsiderable by branch materialization), keyed by its SOURCE epoch.
    let rival_root_content_id = {
        use sha2::{Digest, Sha256};
        MessageId::new(Sha256::digest(&rival_root.payload).to_vec())
    };
    let parked = local_storage.get_message(&rival_root_content_id).unwrap();
    assert_eq!(
        parked.state,
        MessageState::ConvergenceDeferred,
        "the pairwise loser-root must be parked reconsiderable after a restart too"
    );
    assert_eq!(
        parked.epoch,
        EpochId(1),
        "the parked loser-root must be keyed by its source epoch"
    );
}

#[tokio::test]
async fn restarted_incumbent_rolls_back_to_winning_rival_via_rebuilt_snapshot() {
    // Mirror image of the test above: the inbound rival WINS the pairwise
    // race. The restarted member must roll back onto the rival commit through
    // the durable fork snapshot referenced by the REBUILT incumbent record —
    // emitting ForkRecovered exactly as the never-restarted path does.
    let first = b"restart-roll-first".as_slice();
    let second = b"restart-roll-second".as_slice();
    // Local must LOSE: give it the higher (worse) committer identity.
    let (local_id, rival_id) = if pad32(first) < pad32(second) {
        (second, first)
    } else {
        (first, second)
    };
    let (group_id, local_storage, local_commit, rival_root) = forked_privileged_invites(
        local_id,
        rival_id,
        b"restart-roll-david",
        b"restart-roll-eve",
    )
    .await;

    let local_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(local_id)),
        &local_commit.payload,
    );
    let rival_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        MemberId::new(pad32(rival_id)),
        &rival_root.payload,
    );
    assert!(
        rival_key < local_key,
        "identity choice must make the inbound rival win the pairwise race"
    );

    // RESTART: both the incumbent's ordering key (from the stamped own-commit
    // row) and its pre-commit snapshot binding must survive the reopen.
    let mut local = reopen_legacy_client(local_id, local_storage.clone());
    assert_eq!(local.epoch(&group_id).unwrap().0, 2);
    let _ = local.drain_events();

    local
        .ingest(TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..rival_root.clone()
        })
        .await
        .unwrap();
    let events = local.drain_events();
    let (source_epoch, recovered_epoch, winner, invalidated) =
        extract_fork_recovered(&events, &group_id)
            .expect("restarted loser must emit ForkRecovered after rolling back to the rival");
    assert_eq!(source_epoch.0, 1);
    assert_eq!(recovered_epoch.0, 2);
    assert_eq!(winner, &rival_key);
    assert_eq!(invalidated, &local_key);
    assert_eq!(local.epoch(&group_id).unwrap().0, 2);

    // The group state now reflects the rival branch: its invitee joined, the
    // abandoned local branch's invitee did not.
    let members: Vec<_> = local
        .members(&group_id)
        .unwrap()
        .iter()
        .map(|m| m.id.clone())
        .collect();
    assert!(
        members.contains(&MemberId::new(pad32(b"restart-roll-eve"))),
        "rival branch's invitee must be present after the rebuilt rollback"
    );
    assert!(
        !members.contains(&MemberId::new(pad32(b"restart-roll-david"))),
        "the abandoned local branch's invitee must be gone"
    );
    // The invalidated own commit is retired on its durable row, exactly as in
    // the never-restarted path. Resolve the row through the event: the
    // rebuilt incumbent record carries the storage-layer identity. The
    // displaced incumbent is parked `ConvergenceDeferred` at its source
    // epoch, not retired terminally, so a peer that keeps extending its
    // branch can still bring this node back onto it (see
    // `pairwise_candidate_win_leaves_old_incumbent_reconsiderable`). A
    // missing row is tolerated only for pre-parking recovery states.
    let invalidated_commit_id = events
        .iter()
        .find_map(|event| match event {
            GroupEvent::ForkRecovered {
                group_id: event_group,
                invalidated_commit_id,
                ..
            } if event_group == &group_id => Some(invalidated_commit_id.clone()),
            _ => None,
        })
        .expect("ForkRecovered carries the invalidated commit's storage id");
    match local_storage.get_message(&invalidated_commit_id) {
        Ok(record) => {
            assert_eq!(
                record.state,
                MessageState::ConvergenceDeferred,
                "the displaced incumbent must stay reconsiderable after a restart-path rollback"
            );
            assert_eq!(
                record.epoch,
                EpochId(1),
                "the parked incumbent must be keyed by its source epoch"
            );
        }
        Err(cgka_traits::storage::StorageError::NotFound) => {}
        Err(other) => panic!("unexpected storage error: {other:?}"),
    }
}

#[tokio::test]
async fn pairwise_candidate_win_leaves_old_incumbent_reconsiderable() {
    // The mirror of `pairwise_incumbent_defers_to_deeper_convergence_branch`,
    // for the CANDIDATE-wins outcome of the pairwise race: node X's own
    // confirmed commit A loses to an inbound rival B and X rolls back onto B
    // (ForkRecovered). The displaced incumbent A must be parked
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
    let mut rival = build_client(rival_id); //                   authors the pairwise-winning B
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
    // X's fork-recovery incumbent. (2)'s rival B (invite eve) branches from
    // the same epoch without seeing A.
    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let commit_a = match x
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
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
        "identity choice must make the inbound candidate win the pairwise race"
    );

    // (2) B arrives at X and WINS: X rolls back off A onto B (ForkRecovered).
    x.ingest(route(commit_b)).await.unwrap();
    let events = x.drain_events();
    let (source_epoch, recovered_epoch, winner, invalidated) =
        extract_fork_recovered(&events, &group_id)
            .expect("candidate win must roll X back and emit ForkRecovered");
    assert_eq!(source_epoch.0, 1);
    assert_eq!(recovered_epoch.0, 2);
    assert_eq!(winner, &b_key);
    assert_eq!(invalidated, &a_key);
    assert_eq!(x.epoch(&group_id).unwrap().0, 2);

    // The fix under test: the displaced incumbent A is parked reconsiderable
    // at its SOURCE epoch, with its stored payload (own-commit convergence
    // stamp) intact — not terminally `EpochInvalidated`, which would exclude
    // it from every later convergence pass and freeze X off the A-branch.
    let parked = x_storage.get_message(&commit_a.id).unwrap();
    assert_eq!(
        parked.state,
        MessageState::ConvergenceDeferred,
        "the pairwise-losing incumbent must be parked reconsiderable, not terminally invalidated"
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
async fn pairwise_candidate_win_with_rival_follow_on_fails_closed_not_wrong_lineage() {
    // Variant of `pairwise_candidate_win_leaves_old_incumbent_reconsiderable`
    // with ONE extra commit on the winning (rival) branch between the
    // displacement and the A-branch follow-on. That single commit is what
    // breaks the retained-anchor fast path, because retained anchors are
    // name-keyed by resulting epoch (`openmls-retained-anchor-<N>`) and every
    // capture at that epoch REPLACES the previous one — including the captures
    // `ingest` takes around each inbound merge. Applying the rival's follow-on
    // therefore overwrites the anchor that held X's parked own commit A's
    // post-merge state, with no own-stamped row left behind to notice it.
    //
    // What this test pins down is the SAFE outcome. The apply rewinds to the
    // anchor, recomputes the content-bound tree marker, finds it does not match
    // the marker A stamped at confirm time, and aborts — the rewind is rolled
    // back and X keeps its existing (rival-branch) state. The unsafe outcome
    // this guards against is the one the positive check replaced: silently
    // adopting whatever the clobbered anchor happens to hold, i.e. installing a
    // lineage that never existed on any node.
    //
    // NOTE — this is the clobbered-anchor LIVENESS limitation, not a
    // silent-corruption path. Once the anchor is gone, the parked own commit
    // cannot be realized at all: the anchor rewind is its only route, since MLS
    // `process_message` refuses this device's own commits, so normal replay
    // cannot materialize it either. X therefore fails closed and stays on its
    // own branch, diverged from the fleet, until the rewind horizon retires the
    // parked row and it reorgs onto whatever remains selectable. Correctness is
    // preserved; liveness inside that window is not. Restoring it needs
    // content-keyed retained anchors, which is shared with the convergence
    // engine and out of scope for this fix.
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
        "the inbound candidate must win the pairwise race"
    );

    // (2) B wins at X; A is parked reconsiderable at its source epoch.
    x.ingest(route(commit_b)).await.unwrap();
    let events = x.drain_events();
    extract_fork_recovered(&events, &group_id).expect("candidate win must roll X back onto B");
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

    // (4) X ingests the deeper A-branch. Convergence selects it, the apply
    // reaches the retained-anchor fast path for the parked own commit A, and
    // the post-rewind marker check refuses it.
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
    let converge = x.converge_stored_openmls_messages_at(&group_id, u64::MAX);

    // Whatever convergence reports, the invariant is the same: X must NOT be
    // holding a state assembled from the clobbered anchor.
    let x_members: Vec<_> = x
        .members(&group_id)
        .unwrap()
        .iter()
        .map(|m| m.id.clone())
        .collect();
    assert!(
        !x_members.contains(&MemberId::new(pad32(b"cwrf-david"))),
        "X must not silently install the A-branch it cannot prove it rewound to; \
         members were {x_members:?}, convergence returned {converge:?}"
    );
    assert!(
        x_members.contains(&MemberId::new(pad32(b"cwrf-eve")))
            && x_members.contains(&MemberId::new(pad32(b"cwrf-heidi"))),
        "X must keep the intact branch it was already on; members were {x_members:?}"
    );
    assert_eq!(
        x.epoch(&group_id).unwrap().0,
        3,
        "the refused rewind must leave X's live epoch untouched"
    );
    // The parked own commit is still reconsiderable: nothing terminalized it,
    // so once the horizon retires it (or a future engine key anchors by
    // content) X is free to reorg.
    let still_parked = x_storage.get_message(&commit_a.id).unwrap();
    assert_eq!(
        still_parked.state,
        MessageState::ConvergenceDeferred,
        "failing closed must not terminalize the parked own commit"
    );
}

#[tokio::test]
async fn hydrate_advances_snapshot_allocator_past_skipped_fork_snapshots() {
    // The hydrate-time rebuild only advanced the snapshot-name allocator for
    // snapshots it actually REBUILT (via `record_applied`). A snapshot the
    // scan parsed and then skipped — an orphan of a crash between snapshot
    // creation and the apply, a below-horizon leftover, or one whose replay
    // probe failed — left the allocator behind the highest counter on disk,
    // so the first post-restart `fork-<epoch>-<counter>-…` name could collide
    // with (and clobber) a snapshot that is still there.
    let local_id = b"alloc-local".as_slice();
    let (group_id, local_storage, _local_commit, _rival_root) =
        forked_privileged_invites(local_id, b"alloc-rival", b"alloc-david", b"alloc-eve").await;

    // An orphan fork snapshot at the CURRENT epoch: nothing in storage is an
    // applied commit row for source epoch 2, so the hydrate scan parses this
    // name and then skips it. Its counter is far above every counter the
    // engine has minted so far.
    let orphan_counter = 9_000_u64;
    let orphan = format!("fork-2-{orphan_counter}-0123456789abcdef");
    local_storage
        .create_group_snapshot(&group_id, &orphan)
        .unwrap();

    // RESTART: the scan must observe the orphan's counter even though it
    // rebuilds nothing from it.
    let mut local = reopen_legacy_client(local_id, local_storage.clone());
    let before: Vec<u64> = fork_snapshot_counters(&local_storage, &group_id);
    assert!(before.contains(&orphan_counter));

    // Any new commit mints the next fork snapshot name from the allocator.
    let mut frank = build_client(b"alloc-frank");
    let frank_kp = frank.fresh_key_package().await.unwrap();
    local
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
        })
        .await
        .unwrap();

    let after = fork_snapshot_counters(&local_storage, &group_id);
    let minted: Vec<u64> = after
        .iter()
        .copied()
        .filter(|counter| !before.contains(counter))
        .collect();
    assert!(
        !minted.is_empty(),
        "the new commit must mint a fresh fork snapshot"
    );
    assert!(
        minted.iter().all(|counter| *counter > orphan_counter),
        "post-restart names must be allocated above every counter on disk, \
         including skipped ones; minted {minted:?} vs orphan {orphan_counter}"
    );
    assert!(
        after.contains(&orphan_counter),
        "the skipped orphan snapshot must not have been clobbered"
    );
}

fn fork_snapshot_counters(storage: &SqliteAccountStorage, group_id: &GroupId) -> Vec<u64> {
    storage
        .list_group_snapshots(group_id)
        .unwrap()
        .iter()
        .filter_map(|name| {
            name.strip_prefix("fork-")?
                .split('-')
                .nth(1)?
                .parse::<u64>()
                .ok()
        })
        .collect()
}
