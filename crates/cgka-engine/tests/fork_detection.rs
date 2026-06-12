//! Fork detection and recovery.
//!
//! A concurrent-invite scenario deliberately produces divergent epoch-2
//! histories. The engine should:
//! - Recognize the fork via `committed_from_epochs` + inbound WrongEpoch
//! - Compare deterministic transport ordering keys
//! - Roll back to the pre-commit snapshot if the inbound commit wins
//! - Apply the winning commit and return to Stable

use async_trait::async_trait;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_engine::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{
    CgkaEngine, CommitOrderingKey, CommitOrderingPriority, CreateGroupRequest, GroupEvent,
    SendIntent, SendResult,
};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{AccountDeviceSignerStorage, StorageProvider};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, MemberId, MessageId};
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
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    (engine, storage)
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
