//! Fork detection and recovery.
//!
//! A concurrent-invite scenario deliberately produces divergent epoch-2
//! histories. The engine should:
//! - Recognize the fork via `committed_from_epochs` + inbound WrongEpoch
//! - Compare deterministic transport ordering keys
//! - Roll back to the pre-commit snapshot if the inbound commit wins
//! - Apply the winning commit and return to Stable

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{
    CgkaEngine, CommitOrderingKey, CreateGroupRequest, GroupEvent, SendIntent, SendResult,
};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, MemberId, MessageId};
use storage_memory::MemoryStorage;

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
    EngineBuilder::new(MemoryStorage::new())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
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

    // Extract both wrapped commit messages so we can compute their content
    // digests up front. With content-derived ordering, the winner is fixed by
    // SHA-256(mls_bytes); we orchestrate the test so the LOSER ingests the
    // WINNER's commit (the "candidate wins" path that fires fork recovery)
    // and the WINNER ingests the LOSER's commit (the "incumbent wins" path
    // that returns Stale).
    let alice_commit = match alice_invite {
        SendResult::GroupEvolution { msg, .. } => msg,
        _ => unreachable!(),
    };
    let bob_commit = match bob_invite {
        SendResult::GroupEvolution { msg, .. } => msg,
        _ => unreachable!(),
    };
    let alice_key = CommitOrderingKey::from_commit_bytes(EpochId(1), &alice_commit.payload);
    let bob_key = CommitOrderingKey::from_commit_bytes(EpochId(1), &bob_commit.payload);
    assert_ne!(alice_key, bob_key, "distinct commits must hash distinctly");
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
