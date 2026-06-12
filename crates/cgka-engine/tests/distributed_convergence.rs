//! Engine integration for stored-message distributed convergence.

use async_trait::async_trait;
use cgka_engine::canonicalization::{
    CanonicalizationError, CanonicalizationPolicy, ConvergenceStatus, DroppedMessageReason,
    InvalidatedAppMessageReason, MessageKind,
};
use cgka_engine::convergence::{ConvergencePolicy, ConvergencePolicyError};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::openmls_projection::{OpenMlsProjectionError, project_mls_message};
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{
    AppMessageInvalidationReason, CgkaEngine, CreateGroupRequest, GroupEvent, SendIntent,
    SendResult,
};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage};
use cgka_traits::message::MessageState;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    GroupStorage, MessageStorage, OutboundIntentStorage, QueuedOutboundIntent,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};
use storage_sqlite::SqliteAccountStorage;

mod support;
use support::proof_signer;

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

struct MockPeeler;

fn commit_tiebreak_winner_index(first: &MemberId, second: &MemberId) -> usize {
    if first.as_slice() < second.as_slice() {
        0
    } else {
        1
    }
}

fn committer_wins(challenger: &MemberId, incumbent: &MemberId) -> bool {
    challenger.as_slice() < incumbent.as_slice()
}

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

fn build_client(id: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = build_client_with_storage(id, storage.clone());
    (engine, storage)
}

fn build_client_with_storage(
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

#[tokio::test]
async fn engine_converges_stored_openmls_messages_to_selected_branch() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

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
    let (alice_commit, alice_pending) = evolution(alice_invite);
    let (bob_commit, bob_pending) = evolution(bob_invite);
    let commit_messages = [
        route(alice_commit.clone(), &group_id),
        route(bob_commit.clone(), &group_id),
    ];

    // Give the app witness to the branch that would otherwise lose the
    // same-epoch authenticated committer tie-break, proving witnesses still
    // override the final tie-breaker.
    let app_branch_index = 1 - commit_tiebreak_winner_index(&alice.self_id(), &bob.self_id());
    let quiet_branch_index = 1 - app_branch_index;

    let app_msg = if app_branch_index == 0 {
        alice.confirm_published(alice_pending).await.unwrap();
        send_app(&mut alice, &group_id, b"engine witness from alice".to_vec()).await
    } else {
        bob.confirm_published(bob_pending).await.unwrap();
        send_app(&mut bob, &group_id, b"engine witness from bob".to_vec()).await
    };

    carol
        .buffer_openmls_convergence_message(&group_id, commit_messages[0].clone(), 1_000)
        .expect("first commit buffered");
    carol
        .buffer_openmls_convergence_message(&group_id, commit_messages[1].clone(), 1_000)
        .expect("second commit buffered");
    carol
        .buffer_openmls_convergence_message(&group_id, app_msg.clone(), 1_000)
        .expect("app witness buffered");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("stored OpenMLS messages converge");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_eq!(
        carol_storage
            .get_group(&group_id)
            .expect("group stored")
            .epoch,
        EpochId(2)
    );
    assert_eq!(
        result.accepted_commits,
        vec![content_hex(&commit_messages[app_branch_index])]
    );
    assert_message_state(
        &carol_storage,
        &commit_messages[app_branch_index],
        MessageState::Processed,
    );
    assert_message_state(
        &carol_storage,
        &commit_messages[quiet_branch_index],
        MessageState::EpochInvalidated,
    );
    assert_message_state(&carol_storage, &app_msg, MessageState::Processed);

    let members = carol.members(&group_id).unwrap();
    let selected_invitee = if app_branch_index == 0 {
        MemberId::new(pad32(b"david"))
    } else {
        MemberId::new(pad32(b"eve"))
    };
    let losing_invitee = if app_branch_index == 0 {
        MemberId::new(pad32(b"eve"))
    } else {
        MemberId::new(pad32(b"david"))
    };
    assert!(members.iter().any(|member| member.id == selected_invitee));
    assert!(!members.iter().any(|member| member.id == losing_invitee));

    let repeated = carol
        .converge_stored_openmls_messages(&group_id, 3_000)
        .expect("repeated convergence after applying is a no-op");
    assert!(repeated.accepted_commits.is_empty());
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
}

#[tokio::test]
async fn engine_does_not_apply_stored_branch_before_stability_gate() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-syncing".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, commit.clone(), 1_000)
        .expect("commit buffered");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_500)
        .expect("stored OpenMLS messages canonicalize while syncing");

    assert_eq!(result.convergence_status, ConvergenceStatus::Syncing);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(
        carol_storage
            .get_group(&group_id)
            .expect("group stored")
            .epoch,
        EpochId(1)
    );
    assert_message_state(&carol_storage, &commit, MessageState::Created);
}

#[tokio::test]
async fn engine_ingest_buffers_commit_for_convergence_before_quiescence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-ingest-convergence-buffer".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);

    let outcome = carol.ingest(commit.clone()).await.unwrap();

    assert!(matches!(
        outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_message_state(&carol_storage, &commit, MessageState::Created);

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("stored commit applies after quiescence");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
}

#[tokio::test]
async fn engine_materializes_multi_commit_path_from_stored_commits() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-chain".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_eve, pending_eve) = evolution(invite_eve);
    alice.confirm_published(pending_eve).await.unwrap();
    let app_msg = send_app(
        &mut alice,
        &group_id,
        b"multi commit canonical payload".to_vec(),
    )
    .await;

    let commit_eve = route(commit_eve, &group_id);
    let commit_david = route(commit_david, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, commit_eve.clone(), 1_000)
        .expect("child commit buffered first");
    carol
        .buffer_openmls_convergence_message(&group_id, commit_david.clone(), 1_000)
        .expect("parent commit buffered second");
    carol
        .buffer_openmls_convergence_message(&group_id, app_msg.clone(), 1_000)
        .expect("app message buffered after child and parent");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("stored parent and child commits converge as one path");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
    assert_eq!(
        result.accepted_commits,
        vec![content_hex(&commit_david), content_hex(&commit_eve)]
    );
    assert_eq!(result.accepted_app_messages, vec![content_hex(&app_msg)]);
    assert_message_state(&carol_storage, &commit_david, MessageState::Processed);
    assert_message_state(&carol_storage, &commit_eve, MessageState::Processed);
    assert_message_state(&carol_storage, &app_msg, MessageState::Processed);
    let members = carol.members(&group_id).unwrap();
    assert!(members.iter().any(|member| member.id == david.self_id()));
    assert!(members.iter().any(|member| member.id == eve.self_id()));
    let events = carol.drain_events();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                GroupEvent::MessageReceived { group_id: event_group, payload, .. }
                    if *event_group == group_id
                        && app_content(payload) == b"multi commit canonical payload"
            )
        }),
        "expected multi-commit canonical app payload event, got {events:?}"
    );
}

#[tokio::test]
async fn engine_keeps_child_commit_pending_until_parent_arrives() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-missing-parent".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (_commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_eve, _pending_eve) = evolution(invite_eve);
    let commit_eve = route(commit_eve, &group_id);

    carol
        .buffer_openmls_convergence_message(&group_id, commit_eve.clone(), 1_000)
        .expect("child commit buffered without parent");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("missing parent is a pending graph input, not a hard error");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert!(result.accepted_commits.is_empty());
    assert!(result.dropped_messages.is_empty());
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_message_state(&carol_storage, &commit_eve, MessageState::Created);
}

#[tokio::test]
async fn engine_replays_late_same_epoch_commit_from_retained_anchor() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-retained-anchor".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
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
    let (alice_commit, _alice_pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, alice_commit.clone(), 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("alice branch applies and retains epoch 1 anchor");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    let bob_commit = route(bob_commit, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, bob_commit.clone(), 2_000)
        .expect("late bob commit buffered");

    let bob_wins = committer_wins(&bob.self_id(), &alice.self_id());

    let result = carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
        .expect("late same-epoch commit replays from retained anchor");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_ne!(
        carol_storage
            .get_message(&content_id(&bob_commit))
            .unwrap()
            .state,
        MessageState::Created,
        "late commit should be resolved once the retained anchor is available"
    );
    if bob_wins {
        assert_eq!(result.accepted_commits, vec![content_hex(&bob_commit)]);
        assert_message_state(&carol_storage, &bob_commit, MessageState::Processed);
    } else {
        assert_eq!(result.accepted_commits, vec![content_hex(&alice_commit)]);
        assert_message_state(&carol_storage, &bob_commit, MessageState::EpochInvalidated);
    }
    let members = carol.members(&group_id).unwrap();
    assert_eq!(
        members.iter().any(|member| member.id == eve.self_id()),
        bob_wins
    );
    assert_eq!(
        members.iter().any(|member| member.id == david.self_id()),
        !bob_wins
    );
}

#[tokio::test]
async fn engine_metrics_count_post_settle_reorg_from_late_same_epoch_commit() {
    // End-to-end check that the diagnostic reorg telemetry
    // (`docs/marmot-architecture/relay-delivery-telemetry.md` §"Validation:
    // post-settle reorg rate") is wired to the convergence apply site: the
    // first settle is never a reorg, and a late same-epoch commit that flips
    // the selected branch below the applied tip is counted as one.
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-reorg-metrics".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.set_convergence_policy(CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    });

    // Carol settles on Alice's commit (epoch 1 -> 2) and retains the epoch-1
    // anchor. This is the first settle for the group: not a reorg.
    let david_kp = david.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (alice_commit, _alice_pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, alice_commit.clone(), 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 3_000)
        .expect("alice branch applies and retains epoch 1 anchor");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));

    let after_first_settle = carol.engine_metrics();
    assert_eq!(after_first_settle.settles, 1, "first settle counts");
    assert_eq!(
        after_first_settle.post_settle_reorgs, 0,
        "a first settle is never a reorg"
    );
    assert_eq!(after_first_settle.observed_reorg_rate(), Some(0.0));

    // A competing same-epoch commit arrives after the settle. Convergence
    // rolls back to the retained anchor and re-selects; whether it reorgs
    // depends on the content-derived branch tiebreak.
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    let bob_commit = route(bob_commit, &group_id);

    let bob_wins = committer_wins(&bob.self_id(), &alice.self_id());

    carol
        .buffer_openmls_convergence_message(&group_id, bob_commit.clone(), 3_100)
        .expect("late bob commit buffered");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 4_500)
        .expect("late same-epoch commit replays from retained anchor");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);

    let after_late_commit = carol.engine_metrics();
    assert_eq!(
        after_late_commit.settles, 2,
        "the second applied settle is counted"
    );
    if bob_wins {
        // The selection flipped to a different branch that forks below the
        // previously-applied tip (epoch 2): a post-settle reorg.
        assert_eq!(after_late_commit.post_settle_reorgs, 1);
        assert_eq!(after_late_commit.observed_reorg_rate(), Some(0.5));
        // Rewind depth = previous_applied_tip (2) - new_fork_epoch (1) = 1.
        assert_eq!(after_late_commit.reorg_rewind_depth.sample_count(), 1);
        let depth_one = after_late_commit
            .reorg_rewind_depth
            .buckets
            .iter()
            .find(|bucket| bucket.upper_bound == 1)
            .expect("depth-1 bucket");
        assert_eq!(depth_one.count, 1);
        // Lateness = reorg time (4_500) - superseded settle time (3_000) =
        // 1_500ms.
        assert_eq!(after_late_commit.reorg_lateness_ms.sample_count(), 1);
        let lateness = after_late_commit
            .reorg_lateness_ms
            .buckets
            .iter()
            .find(|bucket| bucket.upper_bound == 1_500)
            .expect("1500ms bucket");
        assert_eq!(lateness.count, 1);
    } else {
        // Alice's branch wins again: re-selecting the same branch is a settle
        // but not a reorg.
        assert_eq!(after_late_commit.post_settle_reorgs, 0);
        assert_eq!(after_late_commit.observed_reorg_rate(), Some(0.0));
        assert_eq!(after_late_commit.reorg_rewind_depth.sample_count(), 0);
        assert_eq!(after_late_commit.reorg_lateness_ms.sample_count(), 0);
    }
}

#[tokio::test]
async fn rebuilt_engine_replays_late_same_epoch_commit_from_retained_anchor() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");
    let policy = CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    };

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-retained-anchor-restart".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_group_convergence_policy(&group_id, policy.clone())
        .expect("group convergence policy persisted");

    let david_kp = david.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (alice_commit, _alice_pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, alice_commit.clone(), 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("alice branch applies and retains epoch 1 anchor");
    assert_eq!(
        carol_storage.get_group(&group_id).unwrap().epoch,
        EpochId(2)
    );
    drop(carol);

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    let bob_commit = route(bob_commit, &group_id);
    let bob_wins = committer_wins(&bob.self_id(), &alice.self_id());

    let mut carol = build_client_with_storage(b"carol", carol_storage.clone());
    carol
        .buffer_openmls_convergence_message(&group_id, bob_commit.clone(), 2_000)
        .expect("late bob commit buffered after restart");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
        .expect("rebuilt engine replays late same-epoch commit from retained anchor");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_ne!(
        carol_storage
            .get_message(&content_id(&bob_commit))
            .unwrap()
            .state,
        MessageState::Created,
        "late commit should be resolved after engine rebuild"
    );
    if bob_wins {
        assert_message_state(&carol_storage, &bob_commit, MessageState::Processed);
    } else {
        assert_message_state(&carol_storage, &bob_commit, MessageState::EpochInvalidated);
    }
    let members = carol.members(&group_id).unwrap();
    assert_eq!(
        members.iter().any(|member| member.id == eve.self_id()),
        bob_wins
    );
    assert_eq!(
        members.iter().any(|member| member.id == david.self_id()),
        !bob_wins
    );
}

#[tokio::test]
async fn engine_reports_missing_retained_anchor_without_mutating_late_commit() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-missing-anchor".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
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
    let (alice_commit, _alice_pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, alice_commit, 1_000)
        .expect("alice commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("alice branch applies and retains epoch 1 anchor");
    carol_storage
        .release_group_snapshot(&group_id, "openmls-retained-anchor-1")
        .expect("test removes retained anchor");

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (bob_commit, _bob_pending) = evolution(bob_invite);
    let bob_commit = route(bob_commit, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, bob_commit.clone(), 2_000)
        .expect("late bob commit buffered");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
        .expect("missing retained anchor is reported as a local result");

    assert_eq!(
        result.errors,
        vec![CanonicalizationError::MissingRetainedAnchor]
    );
    assert_eq!(result.convergence_status, ConvergenceStatus::Blocked);
    // retained-history.md:30-31 — canonical state is left unchanged...
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &bob_commit, MessageState::Created);
    assert!(
        !carol
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == eve.self_id())
    );
    // ...and the group moves to Unrecoverable, which the engine surfaces via a
    // GroupUnrecoverable event.
    assert!(
        carol.drain_events().iter().any(|e| matches!(
            e,
            GroupEvent::GroupUnrecoverable { group_id: g } if g == &group_id
        )),
        "engine must emit GroupUnrecoverable on MissingRetainedAnchor"
    );

    // group-state.md:50-51,65 — while Unrecoverable, the client MUST stop
    // applying group-state changes. A second convergence pass still reports
    // MissingRetainedAnchor and applies nothing.
    let second = carol
        .converge_stored_openmls_messages(&group_id, 4_000_000)
        .expect("convergence on an unrecoverable group is a no-op result");
    assert_eq!(
        second.errors,
        vec![CanonicalizationError::MissingRetainedAnchor]
    );
    assert_eq!(second.convergence_status, ConvergenceStatus::Blocked);
    assert!(second.selected_tip.is_none());
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &bob_commit, MessageState::Created);

    // Inbound ingest is halted too: a fresh inbound group message is retained
    // (buffered), not applied, until a verified repair path.
    let outcome = carol
        .ingest(bob_commit.clone())
        .await
        .expect("ingest does not error on an unrecoverable group");
    assert!(
        matches!(
            outcome,
            IngestOutcome::Buffered { .. } | IngestOutcome::Stale { .. }
        ),
        "inbound must not be applied while Unrecoverable; got {outcome:?}"
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
}

#[tokio::test]
async fn engine_prunes_retained_anchor_snapshots_to_rewind_horizon() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-retained-anchor-prune".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.set_convergence_policy(CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    });

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();
    let commit_david = route(commit_david, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, commit_david, 1_000)
        .expect("david commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("david branch applies");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_eve, _pending_eve) = evolution(invite_eve);
    let commit_eve = route(commit_eve, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, commit_eve, 2_000)
        .expect("eve commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
        .expect("eve branch applies");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));

    let snapshots = carol_storage
        .list_group_snapshots(&group_id)
        .expect("snapshots list");
    assert!(
        !snapshots.contains(&"openmls-retained-anchor-1".to_string()),
        "epoch 1 anchor should be pruned once max rewind is 1 at epoch 3: {snapshots:?}"
    );
    assert!(snapshots.contains(&"openmls-retained-anchor-2".to_string()));
    assert!(snapshots.contains(&"openmls-retained-anchor-3".to_string()));
}

#[tokio::test]
async fn engine_invalidates_commit_older_than_retained_anchor() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");
    let (mut frank, _frank_storage) = build_client(b"frank");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-old-commit-invalidated".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.set_convergence_policy(CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    });

    let frank_kp = frank.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
        })
        .await
        .unwrap();
    let (stale_bob_commit, _bob_pending) = evolution(bob_invite);
    let stale_bob_commit = route(stale_bob_commit, &group_id);

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();
    let commit_david = route(commit_david, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, commit_david, 1_000)
        .expect("david commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("david branch applies");

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_eve, _pending_eve) = evolution(invite_eve);
    let commit_eve = route(commit_eve, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, commit_eve, 2_000)
        .expect("eve commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
        .expect("eve branch applies");
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));

    carol
        .buffer_openmls_convergence_message(&group_id, stale_bob_commit.clone(), 4_000)
        .expect("stale bob commit buffered");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 5_000_000)
        .expect("stale commit is resolved without historical replay");

    assert!(result.dropped_messages.iter().any(|dropped| {
        dropped.message_id == content_hex(&stale_bob_commit)
            && dropped.kind == MessageKind::Commit
            && dropped.reason == DroppedMessageReason::BeyondAnchor
    }));
    assert_message_state(
        &carol_storage,
        &stale_bob_commit,
        MessageState::EpochInvalidated,
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
    assert!(
        !carol
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == frank.self_id())
    );
}

#[tokio::test]
async fn rebuilt_engine_invalidates_commit_older_than_retained_anchor() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");
    let (mut frank, _frank_storage) = build_client(b"frank");
    let policy = CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    };

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-old-commit-invalidated-restart".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol
        .set_group_convergence_policy(&group_id, policy.clone())
        .expect("group convergence policy persisted");

    let frank_kp = frank.fresh_key_package().await.unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![frank_kp],
        })
        .await
        .unwrap();
    let (stale_bob_commit, _bob_pending) = evolution(bob_invite);
    let stale_bob_commit = route(stale_bob_commit, &group_id);

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit_david, pending_david) = evolution(invite_david);
    alice.confirm_published(pending_david).await.unwrap();
    let commit_david = route(commit_david, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, commit_david, 1_000)
        .expect("david commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("david branch applies");

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();
    let (commit_eve, _pending_eve) = evolution(invite_eve);
    let commit_eve = route(commit_eve, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, commit_eve, 2_000)
        .expect("eve commit buffered");
    carol
        .converge_stored_openmls_messages(&group_id, 3_000_000)
        .expect("eve branch applies");
    assert_eq!(
        carol_storage.get_group(&group_id).unwrap().epoch,
        EpochId(3)
    );
    drop(carol);

    let mut carol = build_client_with_storage(b"carol", carol_storage.clone());
    carol
        .buffer_openmls_convergence_message(&group_id, stale_bob_commit.clone(), 4_000)
        .expect("stale bob commit buffered after restart");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 5_000_000)
        .expect("rebuilt engine resolves stale commit without historical replay");

    assert!(result.dropped_messages.iter().any(|dropped| {
        dropped.message_id == content_hex(&stale_bob_commit)
            && dropped.kind == MessageKind::Commit
            && dropped.reason == DroppedMessageReason::BeyondAnchor
    }));
    assert_message_state(
        &carol_storage,
        &stale_bob_commit,
        MessageState::EpochInvalidated,
    );
    assert_eq!(
        carol_storage.get_group(&group_id).unwrap().epoch,
        EpochId(3)
    );
    assert!(
        !carol
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == frank.self_id())
    );
}

#[tokio::test]
async fn engine_ingest_buffers_future_epoch_app_message_as_convergence_witness() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-ingest-app-witness".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, pending) = evolution(invite);
    alice.confirm_published(pending).await.unwrap();
    let app_msg = send_app(&mut alice, &group_id, b"future epoch witness".to_vec()).await;

    let outcome = carol.ingest(app_msg.clone()).await.unwrap();

    assert!(matches!(
        outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_message_state(&carol_storage, &app_msg, MessageState::Created);

    carol
        .ingest(route(commit, &group_id))
        .await
        .expect("commit is buffered by ingest");
    let result = carol
        .converge_stored_openmls_messages(&group_id, 2_000)
        .expect("future app witness applies after selected commit");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(result.accepted_app_messages, vec![content_hex(&app_msg)]);
    assert_message_state(&carol_storage, &app_msg, MessageState::Processed);

    let events = carol.drain_events();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                GroupEvent::MessageReceived { group_id: event_group, payload, .. }
                    if *event_group == group_id && app_content(payload) == b"future epoch witness"
            )
        }),
        "expected accepted app message event after canonical convergence, got {events:?}"
    );
}

#[tokio::test]
async fn engine_emits_only_canonical_branch_app_messages_after_convergence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-canonical-app-output".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

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
    let (alice_commit, alice_pending) = evolution(alice_invite);
    let (bob_commit, bob_pending) = evolution(bob_invite);
    let commit_messages = [
        route(alice_commit.clone(), &group_id),
        route(bob_commit.clone(), &group_id),
    ];

    alice.confirm_published(alice_pending).await.unwrap();
    bob.confirm_published(bob_pending).await.unwrap();
    let alice_app = send_app(&mut alice, &group_id, b"alice branch payload".to_vec()).await;
    let bob_app = send_app(&mut bob, &group_id, b"bob branch payload".to_vec()).await;
    let app_messages = [alice_app, bob_app];

    let selected_index = commit_tiebreak_winner_index(&alice.self_id(), &bob.self_id());
    let losing_index = 1 - selected_index;

    for message in commit_messages.iter().chain(app_messages.iter()) {
        carol
            .buffer_openmls_convergence_message(&group_id, message.clone(), 1_000)
            .expect("message buffered");
    }

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("stored OpenMLS messages converge");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        result.accepted_app_messages,
        vec![content_hex(&app_messages[selected_index])]
    );
    assert!(result.invalidated_app_messages.iter().any(|invalidated| {
        invalidated.message_id == content_hex(&app_messages[losing_index])
            && invalidated.reason == InvalidatedAppMessageReason::LosingBranch
    }));
    assert_message_state(
        &carol_storage,
        &app_messages[selected_index],
        MessageState::Processed,
    );
    assert_message_state(
        &carol_storage,
        &app_messages[losing_index],
        MessageState::EpochInvalidated,
    );

    let events = carol.drain_events();
    let received_payloads: Vec<Vec<u8>> = events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { payload, .. } => Some(app_content(payload)),
            _ => None,
        })
        .collect();
    assert_eq!(
        received_payloads,
        vec![if selected_index == 0 {
            b"alice branch payload".to_vec()
        } else {
            b"bob branch payload".to_vec()
        }]
    );
    assert!(events.iter().any(|event| {
        matches!(
            event,
            GroupEvent::AppMessageInvalidated {
                group_id: event_group,
                message_id,
                epoch,
                reason: AppMessageInvalidationReason::LosingBranch,
                decrypted_payload_ref: Some(_),
            } if *event_group == group_id
                && *message_id == content_id(&app_messages[losing_index])
                && *epoch == EpochId(2)
        )
    }));
}

#[tokio::test]
async fn rebuilt_engine_emits_canonical_app_message_after_convergence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-restart-app-output".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, pending) = evolution(invite);
    alice.confirm_published(pending).await.unwrap();
    let app_msg = send_app(&mut alice, &group_id, b"restart canonical payload".to_vec()).await;

    carol
        .ingest(app_msg.clone())
        .await
        .expect("future app message is stored");
    carol
        .ingest(route(commit, &group_id))
        .await
        .expect("commit is stored");

    let mut restarted = EngineBuilder::new(carol_storage.clone())
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();

    let result = restarted
        .converge_stored_openmls_messages(&group_id, 2_000)
        .expect("rebuilt engine converges stored OpenMLS messages");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(restarted.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &app_msg, MessageState::Processed);
    let events = restarted.drain_events();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                GroupEvent::MessageReceived { group_id: event_group, payload, .. }
                    if *event_group == group_id
                        && app_content(payload) == b"restart canonical payload"
            )
        }),
        "expected rebuilt engine to emit canonical app payload, got {events:?}"
    );
}

#[tokio::test]
async fn rebuilt_engine_emits_losing_branch_app_invalidation_after_convergence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-restart-app-invalidation".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

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
    let (alice_commit, alice_pending) = evolution(alice_invite);
    let (bob_commit, bob_pending) = evolution(bob_invite);
    let commit_messages = [
        route(alice_commit.clone(), &group_id),
        route(bob_commit.clone(), &group_id),
    ];

    alice.confirm_published(alice_pending).await.unwrap();
    bob.confirm_published(bob_pending).await.unwrap();
    let app_messages = [
        send_app(&mut alice, &group_id, b"restart alice branch".to_vec()).await,
        send_app(&mut bob, &group_id, b"restart bob branch".to_vec()).await,
    ];

    let selected_index = commit_tiebreak_winner_index(&alice.self_id(), &bob.self_id());
    let losing_index = 1 - selected_index;

    for message in commit_messages.iter().chain(app_messages.iter()) {
        carol
            .buffer_openmls_convergence_message(&group_id, message.clone(), 1_000)
            .expect("message buffered");
    }

    let mut restarted = EngineBuilder::new(carol_storage.clone())
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();

    let result = restarted
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("rebuilt engine converges stored OpenMLS messages");

    assert_eq!(
        result.accepted_app_messages,
        vec![content_hex(&app_messages[selected_index])]
    );
    assert_message_state(
        &carol_storage,
        &app_messages[losing_index],
        MessageState::EpochInvalidated,
    );
    let losing_content_id = content_id(&app_messages[losing_index]);
    let events = restarted.drain_events();
    assert!(events.iter().any(|event| {
        matches!(
            event,
            GroupEvent::AppMessageInvalidated {
                group_id: event_group,
                message_id,
                reason: AppMessageInvalidationReason::LosingBranch,
                ..
            } if *event_group == group_id && *message_id == losing_content_id
        )
    }));
    let received_payloads: Vec<Vec<u8>> = events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { payload, .. } => Some(app_content(payload)),
            _ => None,
        })
        .collect();
    assert_eq!(
        received_payloads,
        vec![if selected_index == 0 {
            b"restart alice branch".to_vec()
        } else {
            b"restart bob branch".to_vec()
        }]
    );
}

#[tokio::test]
async fn engine_ingest_retains_proposal_until_canonical_commit_consumes_it() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-ingest-proposal-convergence".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let proposal = proposal(
        bob.send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap(),
    );
    let proposal = route(proposal, &group_id);

    let carol_outcome = carol.ingest(proposal.clone()).await.unwrap();

    assert!(matches!(
        carol_outcome,
        cgka_traits::ingest::IngestOutcome::Processed
    ));
    assert_message_state(&carol_storage, &proposal, MessageState::Created);

    let alice_outcome = alice.ingest(proposal.clone()).await.unwrap();
    assert!(matches!(
        alice_outcome,
        cgka_traits::ingest::IngestOutcome::Processed
    ));
    let auto_commit = alice
        .drain_auto_publish()
        .into_iter()
        .next()
        .expect("alice auto-commits bob's self-remove");
    alice.confirm_published(auto_commit.pending).await.unwrap();

    let commit = route(auto_commit.msg, &group_id);
    let commit_outcome = carol.ingest(commit.clone()).await.unwrap();
    assert!(matches!(
        commit_outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("proposal-consuming commit converges");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(result.accepted_proposals, vec![content_hex(&proposal)]);
    assert_message_state(&carol_storage, &proposal, MessageState::Processed);
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert!(
        !carol
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == bob.self_id())
    );
}

#[tokio::test]
async fn engine_duplicate_convergence_input_does_not_reset_quiescence() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-convergence-duplicate".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);

    carol
        .buffer_openmls_convergence_message(&group_id, commit.clone(), 1_000)
        .expect("commit buffered");
    carol
        .buffer_openmls_convergence_message(&group_id, commit.clone(), 1_900)
        .expect("duplicate commit ignored");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 2_000)
        .expect("duplicate should not pin syncing");

    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
}

#[tokio::test]
async fn engine_queues_app_send_until_convergence_is_settled() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-queued-send".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    assert!(matches!(
        carol.ingest(commit.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let queued = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"queued until stable"),
        })
        .await
        .unwrap();

    assert!(matches!(queued, SendResult::Queued { .. }));
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_message_state(&carol_storage, &commit, MessageState::Created);
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    let early = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 500)
        .await
        .unwrap();
    assert!(early.is_empty());
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    let drained = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();

    assert_eq!(drained.len(), 1);
    let sent_app = match &drained[0] {
        SendResult::ApplicationMessage { msg } => route(msg.clone(), &group_id),
        other => panic!("expected ApplicationMessage, got {other:?}"),
    };
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
    assert_eq!(
        project_mls_message(&sent_app.payload)
            .expect("queued app projects")
            .source_epoch,
        Some(2)
    );
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn engine_queues_group_evolution_until_convergence_is_settled() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-queued-commit".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![carol.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (alice_commit, _pending) = evolution(alice_invite);
    let alice_commit = route(alice_commit, &group_id);
    assert!(matches!(
        carol.ingest(alice_commit.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let queued = carol
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
        })
        .await
        .unwrap();

    assert!(matches!(queued, SendResult::Queued { .. }));
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    let drained = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();

    assert_eq!(drained.len(), 1);
    let queued_commit = match &drained[0] {
        SendResult::GroupEvolution { msg, welcomes, .. } => {
            assert_eq!(welcomes.len(), 1);
            route(msg.clone(), &group_id)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    assert_message_state(&carol_storage, &alice_commit, MessageState::Processed);
    assert_eq!(
        project_mls_message(&queued_commit.payload)
            .expect("queued commit projects")
            .source_epoch,
        Some(2)
    );
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn trait_advance_convergence_drains_queued_outbound_intent() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "trait-advance-convergence".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    assert!(matches!(
        carol.ingest(commit.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let queued = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"queued through trait lifecycle"),
        })
        .await
        .unwrap();
    assert!(matches!(queued, SendResult::Queued { .. }));

    let policy = CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    };
    carol.set_convergence_policy(policy);

    let mut engine: Box<dyn CgkaEngine> = Box::new(carol);
    let drained = engine.advance_convergence(&group_id).await.unwrap();

    assert_eq!(drained.len(), 1);
    let sent_app = match &drained[0] {
        SendResult::ApplicationMessage { msg } => route(msg.clone(), &group_id),
        other => panic!("expected ApplicationMessage, got {other:?}"),
    };
    assert_eq!(engine.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
    assert_eq!(
        project_mls_message(&sent_app.payload)
            .expect("trait-drained app projects")
            .source_epoch,
        Some(2)
    );
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn advance_convergence_retains_queued_intent_when_regeneration_fails() {
    let (mut alice, alice_storage) = build_client(b"alice");

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "failed-regeneration".into(),
            description: "".into(),
            members: vec![],
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

    let intent_id = MessageId::new(b"invalid-update".to_vec());
    alice_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: intent_id.clone(),
            group_id: group_id.clone(),
            intent: SendIntent::UpdateGroupData {
                group_id: group_id.clone(),
                name: None,
                description: None,
            },
            created_at_ms: 0,
        })
        .unwrap();

    let err = alice.advance_convergence(&group_id).await.err().unwrap();
    assert!(
        matches!(err, cgka_traits::EngineError::Other(ref msg) if msg.contains("no fields")),
        "expected validation error from queued intent regeneration, got {err:?}"
    );
    let queued = alice_storage
        .list_queued_outbound_intents(&group_id)
        .unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].id, intent_id);
}

#[tokio::test]
async fn queued_group_evolution_pauses_later_queued_intents_until_publish_resolves() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, _carol_storage) = build_client(b"carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "queued-evolution-pause".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let carol_kp = carol.fresh_key_package().await.unwrap();
    alice_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: MessageId::new(b"invite-carol".to_vec()),
            group_id: group_id.clone(),
            intent: SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![carol_kp],
            },
            created_at_ms: 0,
        })
        .unwrap();
    alice_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: MessageId::new(b"later-app".to_vec()),
            group_id: group_id.clone(),
            intent: SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&alice, b"after invite publish resolves"),
            },
            created_at_ms: 1,
        })
        .unwrap();

    let drained = alice.advance_convergence(&group_id).await.unwrap();
    assert_eq!(drained.len(), 1);
    let pending_invite = match &drained[0] {
        SendResult::GroupEvolution { pending, .. } => *pending,
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    assert_eq!(
        alice_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    let paused = alice.advance_convergence(&group_id).await.unwrap();
    assert!(
        paused.is_empty(),
        "pending publish should pause queued lifecycle, got {paused:?}"
    );
    assert_eq!(
        alice_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    alice.publish_failed(pending_invite).await.unwrap();
    let drained_after_failure = alice.advance_convergence(&group_id).await.unwrap();
    assert_eq!(drained_after_failure.len(), 1);
    assert!(
        matches!(
            drained_after_failure[0],
            SendResult::ApplicationMessage { .. }
        ),
        "expected later app intent after publish failure, got {drained_after_failure:?}"
    );
    assert!(
        alice_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn queued_outbound_intent_survives_engine_rebuild() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut david, _david_storage) = build_client(b"david");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "engine-queued-restart".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
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
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
        })
        .await
        .unwrap();
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    assert!(matches!(
        carol.ingest(commit.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let queued = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&carol, b"queued across restart"),
        })
        .await
        .unwrap();
    assert!(matches!(queued, SendResult::Queued { .. }));
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    let mut restarted = EngineBuilder::new(carol_storage.clone())
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    let drained = restarted
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();

    assert_eq!(drained.len(), 1);
    let sent_app = match &drained[0] {
        SendResult::ApplicationMessage { msg } => route(msg.clone(), &group_id),
        other => panic!("expected ApplicationMessage, got {other:?}"),
    };
    assert_eq!(restarted.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
    assert_eq!(
        project_mls_message(&sent_app.payload)
            .expect("restarted queued app projects")
            .source_epoch,
        Some(2)
    );
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );
}

fn evolution(result: SendResult) -> (TransportMessage, cgka_traits::engine_state::PendingStateRef) {
    match result {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    }
}

fn proposal(result: SendResult) -> TransportMessage {
    match result {
        SendResult::Proposal { msg } => msg,
        other => panic!("expected Proposal, got {other:?}"),
    }
}

fn welcome_for(welcomes: &[TransportMessage], name: &[u8]) -> TransportMessage {
    let recipient = MemberId::new(pad32(name));
    welcomes
        .iter()
        .find(|message| {
            matches!(
                &message.envelope,
                TransportEnvelope::Welcome { recipient: actual } if *actual == recipient
            )
        })
        .expect("welcome exists")
        .clone()
}

async fn send_app(
    engine: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    payload: Vec<u8>,
) -> TransportMessage {
    let result = engine
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(engine, payload),
        })
        .await
        .expect("send app");
    match result {
        SendResult::ApplicationMessage { msg } => route(msg, group_id),
        other => panic!("expected app message, got {other:?}"),
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

fn app_content(payload: &[u8]) -> Vec<u8> {
    MarmotAppEvent::decode(payload)
        .expect("test app event decodes")
        .content
        .into_bytes()
}

fn route(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    match msg.envelope {
        TransportEnvelope::Welcome { .. } => msg,
        TransportEnvelope::GroupMessage { .. } => TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        },
    }
}

/// Content-derived dedup id of a group message (#238). Inbound / buffered
/// group messages are stored and reported under SHA-256 of the recovered MLS
/// bytes, not the outer transport id. Under the pass-through `MockPeeler` the
/// recovered MLS bytes are exactly `msg.payload`.
fn content_id(msg: &TransportMessage) -> MessageId {
    MessageId::new(Sha256::digest(&msg.payload).to_vec())
}

/// Hex form of [`content_id`], for comparing against canonicalization-result
/// message ids.
fn content_hex(msg: &TransportMessage) -> String {
    hex::encode(content_id(msg).as_slice())
}

fn assert_message_state(
    storage: &SqliteAccountStorage,
    msg: &TransportMessage,
    expected: MessageState,
) {
    let record = storage
        .get_message(&content_id(msg))
        .expect("message remains stored");
    assert_eq!(record.state, expected);
}

// --- #113: witness-override policy bound -----------------------------------

#[test]
fn convergence_policy_default_satisfies_witness_override_bound() {
    assert!(ConvergencePolicy::default().validate().is_ok());
}

#[test]
fn convergence_policy_allows_witness_override_equal_to_rewind_horizon() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 5,
        max_witness_override_depth: 5,
        ..ConvergencePolicy::default()
    };
    assert!(policy.validate().is_ok());
}

#[test]
fn convergence_policy_rejects_witness_override_exceeding_rewind_horizon() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 5,
        max_witness_override_depth: 1000,
        ..ConvergencePolicy::default()
    };
    assert_eq!(
        policy.validate(),
        Err(ConvergencePolicyError::WitnessOverrideExceedsRewind {
            max_witness_override_depth: 1000,
            max_rewind_commits: 5,
        })
    );
}

#[test]
fn set_group_convergence_policy_rejects_witness_override_exceeding_rewind() {
    let (mut alice, _storage) = build_client(b"alice");
    let group_id = GroupId::new(vec![0u8; 32]);
    let bad_policy = CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 5,
            max_witness_override_depth: 1000,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    };

    let err = alice
        .set_group_convergence_policy(&group_id, bad_policy)
        .expect_err("policy violating the witness-override bound must be rejected");
    assert!(
        matches!(err, OpenMlsProjectionError::InvalidPolicy(_)),
        "expected InvalidPolicy, got {err:?}"
    );
}
