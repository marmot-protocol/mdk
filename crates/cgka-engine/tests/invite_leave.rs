//! Invite and MIP-03 SelfRemove round trips.

use async_trait::async_trait;
use cgka_engine::canonicalization::ConvergenceStatus;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::EngineError;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use storage_sqlite::SqliteAccountStorage;

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

fn build_client(id: &[u8]) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
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
        alice_events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::MemberRemoved { member, .. }
                if member == &bob.self_id()
        )),
        "alice should emit MemberRemoved after confirm; got {alice_events:?}"
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
    //   alice ingests bob's proposal → stages an auto-commit (lowest-index
    //                                   remaining, not the target, alice is
    //                                   admin so no §150 depletion concern)
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

    // Alice ingests bob's proposal — alice is the lowest-index non-target
    // remaining member AND alice is admin, so auto-commit fires.
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
        !alice_events.iter().any(|e| matches!(
            e,
            cgka_traits::engine::GroupEvent::MemberRemoved { member, .. }
                if member == &bob.self_id()
        )),
        "alice must not emit MemberRemoved until auto-commit publish is confirmed; got {alice_events:?}"
    );

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
        alice_events.iter().any(|e| matches!(
            e,
            cgka_traits::engine::GroupEvent::MemberRemoved { member, .. }
                if member == &bob.self_id()
        )),
        "alice should emit MemberRemoved for bob after confirm; got {alice_events:?}"
    );

    // Bob ingests alice's commit — bob's epoch advances; he sees himself
    // removed.
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
        bob_events.iter().any(|e| matches!(
            e,
            cgka_traits::engine::GroupEvent::MemberRemoved { member, .. }
                if member == &bob.self_id()
        )),
        "bob should emit MemberRemoved for himself; got {bob_events:?}"
    );
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
        !events.iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::MemberRemoved { member, .. }
                if member == &bob.self_id()
        )),
        "failed auto-publish must not emit MemberRemoved; got {events:?}"
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

    // Alice ingests the proposal — classifies as Processed (OpenMLS buffers
    // + auto-committer fires).
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
