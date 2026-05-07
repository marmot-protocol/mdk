//! Engine integration for stored-message distributed convergence.

use async_trait::async_trait;
use cgka_engine::canonicalization::{CanonicalizationPolicy, SyncState};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::openmls_projection::project_mls_message;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::message::MessageState;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    GroupStorage, MessageStorage, OutboundIntentStorage, QueuedOutboundIntent,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use storage_memory::MemoryStorage;

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
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

fn build_client(id: &[u8]) -> (Engine<MemoryStorage>, MemoryStorage) {
    let storage = MemoryStorage::new();
    let engine = EngineBuilder::new(storage.clone())
        .identity(pad32(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    (engine, storage)
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
    let commit_messages = vec![
        route(alice_commit.clone(), &group_id),
        route(bob_commit.clone(), &group_id),
    ];

    let first_digest = project_mls_message(&commit_messages[0].payload)
        .expect("first commit projects")
        .message_digest;
    let second_digest = project_mls_message(&commit_messages[1].payload)
        .expect("second commit projects")
        .message_digest;
    let app_branch_index = if first_digest > second_digest { 0 } else { 1 };
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

    assert_eq!(result.sync_state, SyncState::Stable);
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
        vec![hex::encode(commit_messages[app_branch_index].id.as_slice())]
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
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    carol
        .buffer_openmls_convergence_message(&group_id, commit.clone(), 1_000)
        .expect("commit buffered");

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_500)
        .expect("stored OpenMLS messages canonicalize while syncing");

    assert_eq!(result.sync_state, SyncState::Syncing);
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

    assert_eq!(result.sync_state, SyncState::Stable);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
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

    assert_eq!(result.sync_state, SyncState::Stable);
    assert_eq!(
        result.accepted_app_messages,
        vec![hex::encode(app_msg.id.as_slice())]
    );
    assert_message_state(&carol_storage, &app_msg, MessageState::Processed);
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

    let commit = route(auto_commit, &group_id);
    let commit_outcome = carol.ingest(commit.clone()).await.unwrap();
    assert!(matches!(
        commit_outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let result = carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
        .expect("proposal-consuming commit converges");

    assert_eq!(result.sync_state, SyncState::Stable);
    assert_eq!(
        result.accepted_proposals,
        vec![hex::encode(proposal.id.as_slice())]
    );
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

    assert_eq!(result.sync_state, SyncState::Stable);
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(2));
    assert_message_state(&carol_storage, &commit, MessageState::Processed);
}

#[tokio::test]
async fn engine_queues_app_send_until_convergence_is_stable() {
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
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    assert!(matches!(
        carol.ingest(commit.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let queued = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: b"queued until stable".to_vec(),
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
async fn engine_queues_group_evolution_until_convergence_is_stable() {
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
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    assert!(matches!(
        carol.ingest(commit.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let queued = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: b"queued through trait lifecycle".to_vec(),
        })
        .await
        .unwrap();
    assert!(matches!(queued, SendResult::Queued { .. }));

    let policy = CanonicalizationPolicy {
        stable_quiescence_ms: 0,
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
            initial_admins: vec![],
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
                payload: b"after invite publish resolves".to_vec(),
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
    let (commit, _pending) = evolution(invite);
    let commit = route(commit, &group_id);
    assert!(matches!(
        carol.ingest(commit.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let queued = carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: b"queued across restart".to_vec(),
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
    engine: &mut Engine<MemoryStorage>,
    group_id: &GroupId,
    payload: Vec<u8>,
) -> TransportMessage {
    let result = engine
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
        })
        .await
        .expect("send app");
    match result {
        SendResult::ApplicationMessage { msg } => route(msg, group_id),
        other => panic!("expected app message, got {other:?}"),
    }
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

fn assert_message_state(storage: &MemoryStorage, msg: &TransportMessage, expected: MessageState) {
    let record = storage
        .get_message(&msg.id)
        .expect("message remains stored");
    assert_eq!(record.state, expected);
}
