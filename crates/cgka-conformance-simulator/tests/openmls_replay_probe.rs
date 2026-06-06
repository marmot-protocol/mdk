use std::collections::BTreeSet;

use cgka_conformance_simulator::canonicalization::{
    CanonicalizationError, CanonicalizationInput, CanonicalizationPolicy, CanonicalizationResult,
    CanonicalizationState, ConvergenceStatus, DroppedMessage, DroppedMessageReason,
    InvalidatedAppMessage, InvalidatedAppMessageReason, MessageKind,
    canonicalize_with_materialized_candidates,
};
use cgka_conformance_simulator::convergence::ConvergencePolicy;
use cgka_conformance_simulator::openmls_projection::{
    OpenMlsCandidatePath, OpenMlsCanonicalizationBatch, OpenMlsContentKind,
    OpenMlsReplayObservation, apply_openmls_canonicalization_result, canonicalize_openmls_batch,
    canonicalize_stored_openmls_messages, materialize_openmls_candidate_paths,
    persist_openmls_canonicalization_dispositions, project_mls_message, replay_openmls_messages,
};
use cgka_conformance_simulator::{ClientBuilder, HarnessClient, TransportBus};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_traits::capabilities::{
    Capability, CapabilityRequirement, Feature, GroupCapabilities, RequirementLevel,
};
use cgka_traits::group::{Group, Member};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::{GroupStorage, MessageStorage, StorageProvider};
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::group::MlsGroup;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
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

fn one_rewind_policy() -> CanonicalizationPolicy {
    CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            witness_quorum_senders_per_epoch: 2,
            witness_quorum_epochs: 1,
            max_witness_override_depth: 1,
        },
        app_message_past_epoch_limit: 5,
        settlement_quiescence_ms: 1_000,
    }
}

async fn openmls_projection_message(
    client: &HarnessClient,
    msg: &TransportMessage,
) -> TransportMessage {
    client
        .openmls_projection_message(msg)
        .await
        .expect("transport message peels to MLS projection bytes")
}

async fn openmls_projection_messages(
    client: &HarnessClient,
    messages: Vec<TransportMessage>,
) -> Vec<TransportMessage> {
    let mut out = Vec::new();
    for message in messages {
        if let Ok(message) = client.openmls_projection_message(&message).await {
            out.push(message);
        }
    }
    out
}

async fn queued_commit_messages(
    client: &HarnessClient,
    bus: &TransportBus,
) -> Vec<TransportMessage> {
    openmls_projection_messages(client, bus.queued_messages())
        .await
        .into_iter()
        .filter(|msg| {
            project_mls_message(&msg.payload)
                .is_ok_and(|projection| projection.kind == OpenMlsContentKind::Commit)
        })
        .collect()
}

#[tokio::test]
async fn openmls_probe_replays_consumed_proposal_without_mutating_live_state() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group("openmls-probe", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let proposal_msg = bob.leave_capture().await;
    let proposal_msg = openmls_projection_message(&carol, &proposal_msg).await;
    assert_projected_kind(&proposal_msg, OpenMlsContentKind::Proposal, 1);

    bus.deliver_all();
    let alice_outcomes = alice.tick().await;
    assert!(
        alice_outcomes.iter().all(Result::is_ok),
        "alice should process bob's proposal and auto-commit: {alice_outcomes:?}"
    );

    let commit_msg = queued_commit_messages(&carol, &bus)
        .await
        .into_iter()
        .next()
        .expect("alice auto-published a commit");
    assert_projected_kind(&commit_msg, OpenMlsContentKind::Commit, 1);

    let observations = replay_openmls_messages(
        carol.storage(),
        &group_id,
        &[proposal_msg, commit_msg.clone()],
    )
    .expect("probe replay succeeds");
    let proposal_ref = observations
        .iter()
        .find_map(|observation| match observation {
            OpenMlsReplayObservation::ProposalStored { proposal_ref, .. } => {
                Some(proposal_ref.clone())
            }
            _ => None,
        })
        .expect("proposal stored during probe replay");
    let consumed_refs = observations
        .iter()
        .find_map(|observation| match observation {
            OpenMlsReplayObservation::CommitStaged {
                consumed_proposal_refs,
                ..
            } => Some(consumed_proposal_refs.clone()),
            _ => None,
        })
        .expect("commit staged during probe replay");
    assert_eq!(consumed_refs, vec![proposal_ref]);
    assert_eq!(carol.epoch().0, 1, "probe replay rolls back live storage");

    bus.deliver_all();
    let carol_outcomes = carol.tick().await;
    assert!(
        carol_outcomes.iter().all(Result::is_ok),
        "carol should still process the real proposal and commit after probe: {carol_outcomes:?}"
    );
    assert_eq!(carol.epoch().0, 2);
}

#[tokio::test]
async fn openmls_materializes_competing_commit_paths_from_same_anchor() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins(
            "openmls-branches",
            vec![bob_kp, carol_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let _alice_pending = alice.invite(vec![david_kp]).await;
    let _bob_pending = bob.invite(vec![eve_kp]).await;

    let commit_messages = queued_commit_messages(&carol, &bus).await;
    assert_eq!(
        commit_messages.len(),
        2,
        "expected two competing commit candidates"
    );

    let candidates = materialize_openmls_candidate_paths(
        carol.storage(),
        &group_id,
        &[
            OpenMlsCandidatePath {
                branch_id: "alice-adds-david".into(),
                messages: vec![commit_messages[0].clone()],
            },
            OpenMlsCandidatePath {
                branch_id: "bob-adds-eve".into(),
                messages: vec![commit_messages[1].clone()],
            },
        ],
    )
    .expect("candidate paths materialize");

    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().all(|candidate| candidate.fork_epoch == 1));
    assert!(candidates.iter().all(|candidate| candidate.tip_epoch == 2));
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.commit_message_ids.len() == 1)
    );
    assert_ne!(candidates[0].tip_digest, candidates[1].tip_digest);
    let canonicalized = canonicalize_with_materialized_candidates(
        CanonicalizationInput {
            state: CanonicalizationState {
                current_tip_epoch: 1,
                retained_anchor_epoch: 1,
                last_convergence_relevant_input_ms: 0,
                seen_message_ids: BTreeSet::new(),
            },
            pending_messages: vec![],
            outbound_intents: vec![],
            candidate_branches: vec![],
            policy: CanonicalizationPolicy {
                convergence: ConvergencePolicy {
                    max_rewind_commits: 5,
                    witness_quorum_senders_per_epoch: 2,
                    witness_quorum_epochs: 1,
                    max_witness_override_depth: 1,
                },
                app_message_past_epoch_limit: 5,
                settlement_quiescence_ms: 1_000,
            },
            now_ms: 2_000,
        },
        candidates
            .iter()
            .map(|candidate| candidate.canonical_materialized_candidate())
            .collect(),
    );
    let lower_digest_candidate = candidates
        .iter()
        .min_by_key(|candidate| candidate.tip_digest)
        .expect("candidate set is not empty");
    assert_eq!(
        canonicalized.selected_branch_id.as_deref(),
        Some(lower_digest_candidate.branch_id.as_str())
    );
    assert_eq!(
        canonicalized.accepted_commits,
        lower_digest_candidate.commit_message_ids
    );
    let losing_commit_id = candidates
        .iter()
        .find(|candidate| candidate.branch_id != lower_digest_candidate.branch_id)
        .and_then(|candidate| candidate.commit_message_ids.first())
        .expect("losing commit exists");
    assert!(canonicalized.dropped_messages.iter().any(|dropped| {
        dropped.message_id == *losing_commit_id
            && dropped.kind == MessageKind::Commit
            && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
    }));
    assert_eq!(
        carol.epoch().0,
        1,
        "candidate materialization must leave the retained anchor untouched"
    );
}

#[tokio::test]
async fn openmls_canonicalization_maps_consumed_proposal_refs_to_pending_proposals() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group("openmls-canonical-proposal", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let proposal_msg = bob.leave_capture().await;
    let proposal_msg = openmls_projection_message(&carol, &proposal_msg).await;
    bus.deliver_all();
    let alice_outcomes = alice.tick().await;
    assert!(
        alice_outcomes.iter().all(Result::is_ok),
        "alice should process bob's proposal and auto-commit: {alice_outcomes:?}"
    );
    let commit_msg = queued_commit_messages(&carol, &bus)
        .await
        .into_iter()
        .next()
        .expect("alice auto-published a commit");

    let result = canonicalize_openmls_batch(
        carol.storage(),
        &group_id,
        OpenMlsCanonicalizationBatch {
            state: CanonicalizationState {
                current_tip_epoch: 1,
                retained_anchor_epoch: 1,
                last_convergence_relevant_input_ms: 0,
                seen_message_ids: BTreeSet::new(),
            },
            candidate_paths: vec![OpenMlsCandidatePath {
                branch_id: "bob-leaves".into(),
                messages: vec![commit_msg.clone()],
            }],
            pending_messages: vec![proposal_msg.clone()],
            outbound_intents: vec![],
            policy: CanonicalizationPolicy {
                convergence: ConvergencePolicy {
                    max_rewind_commits: 5,
                    witness_quorum_senders_per_epoch: 2,
                    witness_quorum_epochs: 1,
                    max_witness_override_depth: 1,
                },
                app_message_past_epoch_limit: 5,
                settlement_quiescence_ms: 1_000,
            },
            now_ms: 2_000,
        },
    )
    .expect("OpenMLS canonicalization adapter succeeds");

    let proposal_id = hex::encode(proposal_msg.id.as_slice());
    let commit_id = hex::encode(commit_msg.id.as_slice());
    assert_eq!(result.selected_branch_id.as_deref(), Some("bob-leaves"));
    assert_eq!(result.accepted_commits, vec![commit_id]);
    assert_eq!(result.accepted_proposals, vec![proposal_id]);
    assert!(result.dropped_messages.is_empty());
    assert_eq!(
        carol.epoch().0,
        1,
        "canonicalization probes must leave the retained anchor untouched"
    );
}

#[tokio::test]
async fn openmls_canonicalization_uses_app_messages_as_branch_witnesses() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins(
            "openmls-canonical-app",
            vec![bob_kp, carol_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let alice_pending = alice.invite(vec![david_kp]).await;
    let bob_pending = bob.invite(vec![eve_kp]).await;

    let commit_messages = queued_commit_messages(&carol, &bus).await;
    assert_eq!(commit_messages.len(), 2);

    let first_digest = project_mls_message(&commit_messages[0].payload)
        .expect("first commit projects")
        .message_digest;
    let second_digest = project_mls_message(&commit_messages[1].payload)
        .expect("second commit projects")
        .message_digest;
    let app_branch_index = if first_digest > second_digest { 0 } else { 1 };
    let quiet_branch_index = 1 - app_branch_index;

    let app_msg = if app_branch_index == 0 {
        alice.confirm(alice_pending).await;
        let msg = alice
            .send_app_capture(b"witness from higher digest branch".to_vec())
            .await;
        openmls_projection_message(&alice, &msg).await
    } else {
        bob.confirm(bob_pending).await;
        let msg = bob
            .send_app_capture(b"witness from higher digest branch".to_vec())
            .await;
        openmls_projection_message(&bob, &msg).await
    };

    let result = canonicalize_openmls_batch(
        carol.storage(),
        &group_id,
        OpenMlsCanonicalizationBatch {
            state: CanonicalizationState {
                current_tip_epoch: 1,
                retained_anchor_epoch: 1,
                last_convergence_relevant_input_ms: 0,
                seen_message_ids: BTreeSet::new(),
            },
            candidate_paths: vec![
                OpenMlsCandidatePath {
                    branch_id: "app-branch".into(),
                    messages: vec![commit_messages[app_branch_index].clone()],
                },
                OpenMlsCandidatePath {
                    branch_id: "quiet-branch".into(),
                    messages: vec![commit_messages[quiet_branch_index].clone()],
                },
            ],
            pending_messages: vec![app_msg.clone()],
            outbound_intents: vec![],
            policy: CanonicalizationPolicy {
                convergence: ConvergencePolicy {
                    max_rewind_commits: 5,
                    witness_quorum_senders_per_epoch: 2,
                    witness_quorum_epochs: 1,
                    max_witness_override_depth: 1,
                },
                app_message_past_epoch_limit: 5,
                settlement_quiescence_ms: 1_000,
            },
            now_ms: 2_000,
        },
    )
    .expect("OpenMLS canonicalization adapter succeeds");

    assert_eq!(result.selected_branch_id.as_deref(), Some("app-branch"));
    assert_eq!(
        result.accepted_app_messages,
        vec![hex::encode(app_msg.id.as_slice())]
    );
    assert!(
        result.invalidated_app_messages.is_empty(),
        "app branch witness should be accepted, not invalidated"
    );
    assert_eq!(
        carol.epoch().0,
        1,
        "canonicalization probes must leave the retained anchor untouched"
    );
}

#[tokio::test]
async fn stored_openmls_messages_reconstruct_canonicalization_batch() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins(
            "stored-openmls-canonical",
            vec![bob_kp, carol_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let alice_pending = alice.invite(vec![david_kp]).await;
    let bob_pending = bob.invite(vec![eve_kp]).await;

    let commit_messages = queued_commit_messages(&carol, &bus).await;
    assert_eq!(commit_messages.len(), 2);

    let first_digest = project_mls_message(&commit_messages[0].payload)
        .expect("first commit projects")
        .message_digest;
    let second_digest = project_mls_message(&commit_messages[1].payload)
        .expect("second commit projects")
        .message_digest;
    let app_branch_index = if first_digest > second_digest { 0 } else { 1 };

    let app_msg = if app_branch_index == 0 {
        alice.confirm(alice_pending).await;
        let msg = alice
            .send_app_capture(b"stored witness from higher digest branch".to_vec())
            .await;
        openmls_projection_message(&alice, &msg).await
    } else {
        bob.confirm(bob_pending).await;
        let msg = bob
            .send_app_capture(b"stored witness from higher digest branch".to_vec())
            .await;
        openmls_projection_message(&bob, &msg).await
    };

    store_created_message(carol.storage(), &group_id, &commit_messages[0]);
    store_created_message(carol.storage(), &group_id, &commit_messages[1]);
    store_created_message(carol.storage(), &group_id, &app_msg);

    let result = canonicalize_stored_openmls_messages(
        carol.storage(),
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 1,
            retained_anchor_epoch: 1,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        vec![],
        CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 5,
                witness_quorum_senders_per_epoch: 2,
                witness_quorum_epochs: 1,
                max_witness_override_depth: 1,
            },
            app_message_past_epoch_limit: 5,
            settlement_quiescence_ms: 1_000,
        },
        2_000,
    )
    .expect("stored OpenMLS canonicalization succeeds");

    let app_commit_id = hex::encode(commit_messages[app_branch_index].id.as_slice());
    assert_eq!(result.accepted_commits, vec![app_commit_id]);
    assert_eq!(
        result.accepted_app_messages,
        vec![hex::encode(app_msg.id.as_slice())]
    );
    assert_eq!(
        carol.epoch().0,
        1,
        "stored canonicalization must not mutate the retained anchor"
    );
}

#[tokio::test]
async fn stored_openmls_canonicalization_persists_message_dispositions() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins(
            "stored-openmls-dispositions",
            vec![bob_kp, carol_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let alice_pending = alice.invite(vec![david_kp]).await;
    let bob_pending = bob.invite(vec![eve_kp]).await;

    let commit_messages = queued_commit_messages(&carol, &bus).await;
    assert_eq!(commit_messages.len(), 2);

    let first_digest = project_mls_message(&commit_messages[0].payload)
        .expect("first commit projects")
        .message_digest;
    let second_digest = project_mls_message(&commit_messages[1].payload)
        .expect("second commit projects")
        .message_digest;
    let app_branch_index = if first_digest > second_digest { 0 } else { 1 };
    let quiet_branch_index = 1 - app_branch_index;

    let app_msg = if app_branch_index == 0 {
        alice.confirm(alice_pending).await;
        let msg = alice
            .send_app_capture(b"persisted witness from higher digest branch".to_vec())
            .await;
        openmls_projection_message(&alice, &msg).await
    } else {
        bob.confirm(bob_pending).await;
        let msg = bob
            .send_app_capture(b"persisted witness from higher digest branch".to_vec())
            .await;
        openmls_projection_message(&bob, &msg).await
    };

    store_created_message(carol.storage(), &group_id, &commit_messages[0]);
    store_created_message(carol.storage(), &group_id, &commit_messages[1]);
    store_created_message(carol.storage(), &group_id, &app_msg);

    let result = canonicalize_stored_openmls_messages(
        carol.storage(),
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 1,
            retained_anchor_epoch: 1,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        vec![],
        CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 5,
                witness_quorum_senders_per_epoch: 2,
                witness_quorum_epochs: 1,
                max_witness_override_depth: 1,
            },
            app_message_past_epoch_limit: 5,
            settlement_quiescence_ms: 1_000,
        },
        2_000,
    )
    .expect("stored OpenMLS canonicalization succeeds");

    persist_openmls_canonicalization_dispositions(carol.storage(), &result)
        .expect("canonicalization dispositions persist");

    assert_message_state(
        carol.storage(),
        &commit_messages[app_branch_index],
        MessageState::Processed,
    );
    assert_message_state(
        carol.storage(),
        &commit_messages[quiet_branch_index],
        MessageState::EpochInvalidated,
    );
    assert_message_state(carol.storage(), &app_msg, MessageState::Processed);
}

#[tokio::test]
async fn stored_openmls_canonicalization_applies_selected_branch_to_retained_group() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins(
            "stored-openmls-apply",
            vec![bob_kp, carol_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let alice_pending = alice.invite(vec![david_kp]).await;
    let bob_pending = bob.invite(vec![eve_kp]).await;

    let commit_messages = queued_commit_messages(&carol, &bus).await;
    assert_eq!(commit_messages.len(), 2);

    let first_digest = project_mls_message(&commit_messages[0].payload)
        .expect("first commit projects")
        .message_digest;
    let second_digest = project_mls_message(&commit_messages[1].payload)
        .expect("second commit projects")
        .message_digest;
    let app_branch_index = if first_digest > second_digest { 0 } else { 1 };
    let quiet_branch_index = 1 - app_branch_index;

    let app_msg = if app_branch_index == 0 {
        alice.confirm(alice_pending).await;
        let msg = alice
            .send_app_capture(b"applied witness from higher digest branch".to_vec())
            .await;
        openmls_projection_message(&alice, &msg).await
    } else {
        bob.confirm(bob_pending).await;
        let msg = bob
            .send_app_capture(b"applied witness from higher digest branch".to_vec())
            .await;
        openmls_projection_message(&bob, &msg).await
    };

    store_created_message(carol.storage(), &group_id, &commit_messages[0]);
    store_created_message(carol.storage(), &group_id, &commit_messages[1]);
    store_created_message(carol.storage(), &group_id, &app_msg);

    let result = canonicalize_stored_openmls_messages(
        carol.storage(),
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 1,
            retained_anchor_epoch: 1,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        vec![],
        CanonicalizationPolicy {
            convergence: ConvergencePolicy {
                max_rewind_commits: 5,
                witness_quorum_senders_per_epoch: 2,
                witness_quorum_epochs: 1,
                max_witness_override_depth: 1,
            },
            app_message_past_epoch_limit: 5,
            settlement_quiescence_ms: 1_000,
        },
        2_000,
    )
    .expect("stored OpenMLS canonicalization succeeds");

    let observations = apply_openmls_canonicalization_result(
        carol.storage(),
        &group_id,
        &result,
        CanonicalizationPolicy::default()
            .convergence
            .max_rewind_commits,
    )
    .expect("selected OpenMLS branch applies");

    assert_eq!(stored_openmls_epoch(carol.storage(), &group_id), 2);
    assert_eq!(
        carol
            .storage()
            .get_group(&group_id)
            .expect("group stored")
            .epoch,
        EpochId(2)
    );
    assert!(observations.iter().any(|observation| {
        matches!(
            observation,
            OpenMlsReplayObservation::CommitStaged { message_id, .. }
                if *message_id == hex::encode(commit_messages[app_branch_index].id.as_slice())
        )
    }));
    assert!(observations.iter().any(|observation| {
        matches!(
            observation,
            OpenMlsReplayObservation::ApplicationProcessed { message_id, .. }
                if *message_id == hex::encode(app_msg.id.as_slice())
        )
    }));
    assert_message_state(
        carol.storage(),
        &commit_messages[app_branch_index],
        MessageState::Processed,
    );
    assert_message_state(
        carol.storage(),
        &commit_messages[quiet_branch_index],
        MessageState::EpochInvalidated,
    );
    assert_message_state(carol.storage(), &app_msg, MessageState::Processed);
}

#[tokio::test]
async fn retained_anchor_late_commit_within_horizon_is_resolved() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins(
            "retained-anchor-late-within",
            vec![bob_kp, carol_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let _alice_pending = alice.invite(vec![david_kp]).await;
    let _bob_pending = bob.invite(vec![eve_kp]).await;
    let commit_messages = queued_commit_messages(&carol, &bus).await;
    assert_eq!(commit_messages.len(), 2);
    let online_commit = commit_messages[0].clone();
    let late_commit = commit_messages[1].clone();
    let policy = one_rewind_policy();

    store_created_message(carol.storage(), &group_id, &online_commit);
    let first_result = canonicalize_stored_openmls_messages(
        carol.storage(),
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 1,
            retained_anchor_epoch: 1,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        vec![],
        policy.clone(),
        2_000,
    )
    .expect("online branch canonicalizes");
    apply_openmls_canonicalization_result(
        carol.storage(),
        &group_id,
        &first_result,
        policy.convergence.max_rewind_commits,
    )
    .expect("online branch applies and retains epoch 1");
    assert_eq!(stored_openmls_epoch(carol.storage(), &group_id), 2);

    store_created_message(carol.storage(), &group_id, &late_commit);
    let late_result = canonicalize_stored_openmls_messages(
        carol.storage(),
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 2,
            retained_anchor_epoch: 1,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        vec![],
        policy.clone(),
        3_000,
    )
    .expect("late branch canonicalizes from retained anchor");

    assert!(late_result.errors.is_empty());
    assert_ne!(
        late_result.selected_branch_id, None,
        "late same-epoch input should produce a selectable branch"
    );
    apply_openmls_canonicalization_result(
        carol.storage(),
        &group_id,
        &late_result,
        policy.convergence.max_rewind_commits,
    )
    .expect("selected retained-anchor branch applies");

    assert_eq!(stored_openmls_epoch(carol.storage(), &group_id), 2);
    assert_ne!(
        carol.storage().get_message(&late_commit.id).unwrap().state,
        MessageState::Created,
        "late commit should be resolved within the retained horizon"
    );
}

#[tokio::test]
async fn retained_anchor_missing_anchor_reports_error_without_mutation() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins(
            "retained-anchor-missing",
            vec![bob_kp, carol_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let _alice_pending = alice.invite(vec![david_kp]).await;
    let _bob_pending = bob.invite(vec![eve_kp]).await;
    let commit_messages = queued_commit_messages(&carol, &bus).await;
    assert_eq!(commit_messages.len(), 2);
    let online_commit = commit_messages[0].clone();
    let late_commit = commit_messages[1].clone();
    let policy = one_rewind_policy();

    store_created_message(carol.storage(), &group_id, &online_commit);
    let first_result = canonicalize_stored_openmls_messages(
        carol.storage(),
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 1,
            retained_anchor_epoch: 1,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        vec![],
        policy.clone(),
        2_000,
    )
    .expect("online branch canonicalizes");
    apply_openmls_canonicalization_result(
        carol.storage(),
        &group_id,
        &first_result,
        policy.convergence.max_rewind_commits,
    )
    .expect("online branch applies and retains epoch 1");
    carol
        .storage()
        .release_group_snapshot(&group_id, "openmls-retained-anchor-1")
        .expect("test removes retained anchor");

    store_created_message(carol.storage(), &group_id, &late_commit);
    let late_result = canonicalize_stored_openmls_messages(
        carol.storage(),
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 2,
            retained_anchor_epoch: 1,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        vec![],
        policy,
        3_000,
    )
    .expect("missing retained anchor is reported in result");

    assert_eq!(
        late_result.errors,
        vec![CanonicalizationError::MissingRetainedAnchor]
    );
    assert_eq!(
        late_result.convergence_status,
        ConvergenceStatus::Blocked,
        "missing retained anchor after quiescence blocks convergence instead of settling"
    );
    assert_eq!(stored_openmls_epoch(carol.storage(), &group_id), 2);
    assert_message_state(carol.storage(), &late_commit, MessageState::Created);
}

#[tokio::test]
async fn retained_anchor_commit_beyond_anchor_is_invalidated() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut frank = ClientBuilder::new(pad32(b"frank"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins(
            "retained-anchor-beyond",
            vec![bob_kp, carol_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;
    let policy = one_rewind_policy();

    let frank_kp = frank.fresh_key_package().await;
    let _bob_pending = bob.invite(vec![frank_kp]).await;
    let stale_commit = queued_commit_messages(&carol, &bus)
        .await
        .into_iter()
        .next()
        .expect("bob emitted stale commit");

    let david_kp = david.fresh_key_package().await;
    let alice_pending = alice.invite(vec![david_kp]).await;
    let commit_david = queued_commit_messages(&carol, &bus)
        .await
        .into_iter()
        .find(|msg| msg.id != stale_commit.id)
        .expect("alice emitted david commit");
    store_created_message(carol.storage(), &group_id, &commit_david);
    let david_result = canonicalize_stored_openmls_messages(
        carol.storage(),
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 1,
            retained_anchor_epoch: 1,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        vec![],
        policy.clone(),
        2_000,
    )
    .expect("david branch canonicalizes");
    apply_openmls_canonicalization_result(
        carol.storage(),
        &group_id,
        &david_result,
        policy.convergence.max_rewind_commits,
    )
    .expect("david branch applies");
    alice.confirm(alice_pending).await;

    let eve_kp = eve.fresh_key_package().await;
    let _eve_pending = alice.invite(vec![eve_kp]).await;
    let commit_eve = queued_commit_messages(&carol, &bus)
        .await
        .into_iter()
        .find(|msg| msg.id != stale_commit.id && msg.id != commit_david.id)
        .expect("alice emitted eve commit");
    store_created_message(carol.storage(), &group_id, &commit_eve);
    let eve_result = canonicalize_stored_openmls_messages(
        carol.storage(),
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 2,
            retained_anchor_epoch: 1,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        vec![],
        policy.clone(),
        3_000,
    )
    .expect("eve branch canonicalizes");
    apply_openmls_canonicalization_result(
        carol.storage(),
        &group_id,
        &eve_result,
        policy.convergence.max_rewind_commits,
    )
    .expect("eve branch applies and prunes epoch 1");
    assert_eq!(stored_openmls_epoch(carol.storage(), &group_id), 3);

    store_created_message(carol.storage(), &group_id, &stale_commit);
    let stale_result = canonicalize_stored_openmls_messages(
        carol.storage(),
        &group_id,
        CanonicalizationState {
            current_tip_epoch: 3,
            retained_anchor_epoch: 2,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        vec![],
        policy,
        4_000,
    )
    .expect("stale branch canonicalizes as a disposition-only drop");

    assert!(stale_result.dropped_messages.iter().any(|dropped| {
        dropped.message_id == hex::encode(stale_commit.id.as_slice())
            && dropped.kind == MessageKind::Commit
            && dropped.reason == DroppedMessageReason::BeyondAnchor
    }));
    persist_openmls_canonicalization_dispositions(carol.storage(), &stale_result)
        .expect("stale disposition persists");
    assert_message_state(
        carol.storage(),
        &stale_commit,
        MessageState::EpochInvalidated,
    );
    assert_eq!(stored_openmls_epoch(carol.storage(), &group_id), 3);
}

#[tokio::test]
async fn openmls_canonicalization_apply_rolls_back_when_selected_path_fails() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins(
            "stored-openmls-apply-rollback",
            vec![bob_kp, carol_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let _alice_pending = alice.invite(vec![david_kp]).await;
    let _bob_pending = bob.invite(vec![eve_kp]).await;

    let commit_messages = queued_commit_messages(&carol, &bus).await;
    assert_eq!(commit_messages.len(), 2);

    store_created_message(carol.storage(), &group_id, &commit_messages[0]);
    store_created_message(carol.storage(), &group_id, &commit_messages[1]);

    let bad_result = CanonicalizationResult {
        previous_tip: 1,
        selected_tip: Some(3),
        selected_fork_epoch: Some(1),
        selected_branch_id: Some("bad-selected-path".into()),
        convergence_status: ConvergenceStatus::Settled,
        accepted_commits: commit_messages
            .iter()
            .map(|message| hex::encode(message.id.as_slice()))
            .collect(),
        accepted_proposals: vec![],
        accepted_app_messages: vec![],
        invalidated_app_messages: vec![],
        dropped_messages: vec![],
        already_seen: vec![],
        queued_outbound_intents: vec![],
        publishable_outbound_messages: vec![],
        errors: vec![],
    };

    let err = apply_openmls_canonicalization_result(
        carol.storage(),
        &group_id,
        &bad_result,
        CanonicalizationPolicy::default()
            .convergence
            .max_rewind_commits,
    )
    .expect_err("conflicting same-epoch commits cannot both apply");

    assert!(
        err.to_string().contains("process_message"),
        "unexpected error: {err}"
    );
    assert_eq!(stored_openmls_epoch(carol.storage(), &group_id), 1);
    assert_message_state(carol.storage(), &commit_messages[0], MessageState::Created);
    assert_message_state(carol.storage(), &commit_messages[1], MessageState::Created);
}

#[test]
fn openmls_disposition_persistence_maps_all_canonicalization_states() {
    let storage = storage_sqlite::SqliteAccountStorage::in_memory().unwrap();
    let group_id = GroupId::new(b"disposition-group".to_vec());
    let accepted_commit_id = MessageId::new(vec![1]);
    let accepted_app_id = MessageId::new(vec![2]);
    let losing_commit_id = MessageId::new(vec![3]);
    let losing_app_id = MessageId::new(vec![4]);
    let malformed_proposal_id = MessageId::new(vec![5]);

    for id in [
        &accepted_commit_id,
        &accepted_app_id,
        &losing_commit_id,
        &losing_app_id,
        &malformed_proposal_id,
    ] {
        store_dummy_created_message(&storage, &group_id, id);
    }

    let result = CanonicalizationResult {
        previous_tip: 1,
        selected_tip: Some(2),
        selected_fork_epoch: Some(1),
        selected_branch_id: Some("accepted-branch".into()),
        convergence_status: ConvergenceStatus::Settled,
        accepted_commits: vec![hex::encode(accepted_commit_id.as_slice())],
        accepted_proposals: vec![],
        accepted_app_messages: vec![hex::encode(accepted_app_id.as_slice())],
        invalidated_app_messages: vec![InvalidatedAppMessage {
            message_id: hex::encode(losing_app_id.as_slice()),
            epoch: 2,
            reason: InvalidatedAppMessageReason::LosingBranch,
            decrypted_payload_ref: Some("stored-payload".into()),
        }],
        dropped_messages: vec![
            DroppedMessage {
                message_id: hex::encode(losing_commit_id.as_slice()),
                kind: MessageKind::Commit,
                reason: DroppedMessageReason::InvalidAgainstCandidateState,
            },
            DroppedMessage {
                message_id: hex::encode(malformed_proposal_id.as_slice()),
                kind: MessageKind::Proposal,
                reason: DroppedMessageReason::Malformed,
            },
        ],
        already_seen: vec![],
        queued_outbound_intents: vec![],
        publishable_outbound_messages: vec![],
        errors: vec![],
    };

    persist_openmls_canonicalization_dispositions(&storage, &result)
        .expect("canonicalization dispositions persist");

    assert_message_id_state(&storage, &accepted_commit_id, MessageState::Processed);
    assert_message_id_state(&storage, &accepted_app_id, MessageState::Processed);
    assert_message_id_state(&storage, &losing_commit_id, MessageState::EpochInvalidated);
    assert_message_id_state(&storage, &losing_app_id, MessageState::EpochInvalidated);
    assert_message_id_state(&storage, &malformed_proposal_id, MessageState::Failed);
}

fn assert_projected_kind(msg: &TransportMessage, expected_kind: OpenMlsContentKind, source: u64) {
    let projection = project_mls_message(&msg.payload).expect("MLS message projects");
    assert_eq!(projection.kind, expected_kind);
    assert_eq!(projection.source_epoch, Some(source));
}

fn assert_message_state(
    storage: &storage_sqlite::SqliteAccountStorage,
    msg: &TransportMessage,
    expected: MessageState,
) {
    assert_message_id_state(storage, &msg.id, expected);
}

fn assert_message_id_state(
    storage: &storage_sqlite::SqliteAccountStorage,
    id: &MessageId,
    expected: MessageState,
) {
    let record = storage.get_message(id).expect("message remains stored");
    assert_eq!(record.state, expected);
}

fn stored_openmls_epoch(storage: &storage_sqlite::SqliteAccountStorage, group_id: &GroupId) -> u64 {
    let crypto = RustCrypto::default();
    let provider = EngineOpenMlsProvider::<storage_sqlite::SqliteAccountStorage>::new(
        &crypto,
        storage.mls_storage(),
    );
    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    let group = MlsGroup::load(provider.storage(), &mls_group_id)
        .expect("MLS group loads")
        .expect("MLS group exists");
    group.epoch().as_u64()
}

fn store_dummy_created_message(
    storage: &storage_sqlite::SqliteAccountStorage,
    group_id: &GroupId,
    id: &MessageId,
) {
    storage
        .put_group(&dummy_group(group_id.clone()))
        .expect("group stored");
    storage
        .put_message(&MessageRecord {
            id: id.clone(),
            group_id: group_id.clone(),
            epoch: EpochId(1),
            state: MessageState::Created,
            payload: Vec::new(),
        })
        .expect("message stored");
}

fn dummy_group(group_id: GroupId) -> Group {
    Group {
        id: group_id,
        name: "probe".to_owned(),
        description: String::new(),
        epoch: EpochId(1),
        members: vec![Member {
            id: MemberId::new(vec![1]),
            credential: vec![1],
        }],
        required_capabilities: GroupCapabilities::default(),
    }
}

fn store_created_message(
    storage: &storage_sqlite::SqliteAccountStorage,
    group_id: &GroupId,
    msg: &TransportMessage,
) {
    let projection = project_mls_message(&msg.payload).expect("message projects");
    let epoch = projection
        .source_epoch
        .expect("group message has source epoch");
    storage
        .put_message(&MessageRecord {
            id: msg.id.clone(),
            group_id: group_id.clone(),
            epoch: EpochId(epoch),
            state: MessageState::Created,
            payload: serde_json::to_vec(msg).expect("transport serializes"),
        })
        .expect("message stored");
}
