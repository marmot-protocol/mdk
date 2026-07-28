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
use cgka_engine::{DEFAULT_CIPHERSUITE, openmls_projection::OpenMlsProjectionError};
use cgka_traits::app_components::{GROUP_PROFILE_COMPONENT_ID, encode_component_vectors};
use cgka_traits::capabilities::{
    Capability, CapabilityRequirement, Feature, GroupCapabilities, RequirementLevel,
};
use cgka_traits::engine::CgkaEngine;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group::{Group, Member};
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, ProposalRejectionCategory};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerStorage, GroupStorage, MessageStorage, StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls::group::MlsGroup;
use openmls::messages::proposals::AppDataUpdateOperation;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use tls_codec::Serialize;

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

fn base_test_policy() -> CanonicalizationPolicy {
    CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 5,
            witness_quorum_senders_per_epoch: 2,
            witness_quorum_epochs: 1,
            max_witness_override_depth: 1,
        },
        app_message_past_epoch_limit: 5,
        settlement_quiescence_ms: 1_000,
        max_convergence_pass_ms: 5_000,
    }
}

fn one_rewind_policy() -> CanonicalizationPolicy {
    CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..base_test_policy().convergence
        },
        ..base_test_policy()
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

fn raw_group_profile_update_proposal(
    client: &HarnessClient,
    group_id: &GroupId,
) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider = EngineOpenMlsProvider::<storage_sqlite::SqliteAccountStorage>::new(
        &crypto,
        client.storage().mls_storage(),
    );
    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut group = MlsGroup::load(provider.storage(), &mls_group_id)
        .expect("load MLS group")
        .expect("MLS group exists");
    let binding = client
        .storage()
        .account_device_signer(&client.member_id())
        .expect("load signer binding")
        .expect("signer binding exists");
    let signer = SignatureKeyPair::read(
        client.storage().mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .expect("load MLS signer");
    let (proposal, _) = group
        .propose_app_data_update(
            &provider,
            &signer,
            GROUP_PROFILE_COMPONENT_ID,
            AppDataUpdateOperation::Update(
                encode_component_vectors(&[b"renamed", b"description"]).into(),
            ),
        )
        .expect("build valid group-profile proposal");
    let payload = proposal
        .tls_serialize_detached()
        .expect("serialize proposal");
    TransportMessage {
        id: MessageId::new(Sha256::digest(&payload).to_vec()),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("openmls-proposal-vector".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

fn stored_pending_proposal_count(client: &HarnessClient, group_id: &GroupId) -> usize {
    let crypto = RustCrypto::default();
    let provider = EngineOpenMlsProvider::<storage_sqlite::SqliteAccountStorage>::new(
        &crypto,
        client.storage().mls_storage(),
    );
    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    MlsGroup::load(provider.storage(), &mls_group_id)
        .expect("load MLS group")
        .expect("MLS group exists")
        .pending_proposals()
        .count()
}

#[tokio::test]
async fn proposal_authorization_vector_rejects_direct_and_nostr_wrapped_input() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .protocol_profile(ProtocolProfile::Current)
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .protocol_profile(ProtocolProfile::Current)
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins_maybe_pending(
            "proposal-authorization-vector",
            vec![bob_kp],
            vec![],
            vec![],
        )
        .await;
    assert!(
        pending.is_none(),
        "current-profile founding creation is immediately stable"
    );
    bus.deliver_all();
    let join_outcomes = bob.tick().await;
    assert!(
        join_outcomes.iter().all(Result::is_ok),
        "bob joins current-profile group: {join_outcomes:?}"
    );

    // Bob is a member but not an admin. The proposal is MLS-valid and its
    // component payload is well-formed, so authorization is the only reason it
    // must be rejected.
    let stable_epoch = alice.epoch();
    let direct = raw_group_profile_update_proposal(&bob, &group_id);
    let direct_rejection =
        replay_openmls_messages(alice.storage(), &group_id, std::slice::from_ref(&direct))
            .expect_err("direct OpenMLS replay rejects unauthorized proposal");
    assert!(matches!(
        direct_rejection,
        OpenMlsProjectionError::RejectedProposal {
            category: ProposalRejectionCategory::AuthorizationFailed,
            ..
        }
    ));
    assert_eq!(
        alice.epoch(),
        stable_epoch,
        "direct replay rolls back without changing the live group"
    );
    assert_eq!(
        stored_pending_proposal_count(&alice, &group_id),
        0,
        "direct replay cannot leave the rejected proposal pending"
    );

    // Exercise the production-shaped Nostr kind-445 seam with the same inner
    // MLS proposal. It must terminate as Failed before pending storage or
    // auto-commit scheduling.
    let snapshot = {
        let context = alice
            .engine_mut()
            .group_context(&group_id)
            .expect("load group context");
        GroupContextSnapshot::from_context(
            context.as_ref(),
            &[transport_nostr_peeler::DEFAULT_EXPORTER_LABEL],
        )
    };
    let wrapped = transport_nostr_peeler::NostrMlsPeeler::default()
        .wrap_group_message(
            &EncryptedPayload {
                ciphertext: direct.payload,
                aad: vec![],
            },
            &snapshot,
        )
        .await
        .expect("wrap proposal as Nostr group event");
    bus.inject(alice.bus_id, wrapped.clone());
    let outcomes = alice.tick_ingest_only().await;
    assert!(
        matches!(
            outcomes.as_slice(),
            [Ok(IngestOutcome::Rejected {
                category: ProposalRejectionCategory::AuthorizationFailed
            })]
        ),
        "wrapped unauthorized proposal is terminal: {outcomes:?}"
    );
    assert!(
        alice
            .storage()
            .list_messages(&group_id, EpochId(0))
            .expect("list durable group messages")
            .iter()
            .any(|record| record.state == MessageState::Failed),
        "wrapped rejection leaves a terminal failed content record"
    );
    assert!(
        alice.engine_mut().drain_auto_publish().is_empty(),
        "rejected proposal cannot schedule an auto-commit"
    );
    assert_eq!(
        stored_pending_proposal_count(&alice, &group_id),
        0,
        "wrapped ingest cannot leave the rejected proposal pending"
    );
    assert_eq!(alice.epoch(), stable_epoch);
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

    let carol_proposal_outcomes = carol.tick().await;
    assert!(
        carol_proposal_outcomes.iter().all(Result::is_ok),
        "carol should still process the real proposal after probe: {carol_proposal_outcomes:?}"
    );

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
            policy: base_test_policy(),
            now_ms: 2_000,
        },
        candidates
            .iter()
            .map(|candidate| candidate.canonical_materialized_candidate())
            .collect(),
    );
    let selected_candidate = candidates
        .iter()
        .min_by_key(|candidate| {
            (
                candidate.tip_priority,
                candidate.tip_committer.clone(),
                candidate.tip_digest,
            )
        })
        .expect("candidate set is not empty");
    assert_eq!(
        canonicalized.selected_branch_id.as_deref(),
        Some(selected_candidate.branch_id.as_str())
    );
    assert_eq!(
        canonicalized.accepted_commits,
        selected_candidate.commit_message_ids
    );
    let losing_commit_id = candidates
        .iter()
        .find(|candidate| candidate.branch_id != selected_candidate.branch_id)
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
            already_delivered_app_ids: BTreeSet::new(),
            outbound_intents: vec![],
            policy: base_test_policy(),
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
            already_delivered_app_ids: BTreeSet::new(),
            outbound_intents: vec![],
            policy: base_test_policy(),
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
async fn multi_device_account_witness_deduplication_uses_real_openmls_leaves() {
    let bus = TransportBus::ordered();
    let shared_account_seed = pad32(b"shared-account");
    let mut device_a = ClientBuilder::new(shared_account_seed.clone())
        .registry(selfremove_registry())
        .protocol_profile(ProtocolProfile::Current)
        .attach(&bus);
    let mut device_b = ClientBuilder::new(shared_account_seed)
        .registry(selfremove_registry())
        .protocol_profile(ProtocolProfile::Current)
        .attach(&bus);
    let mut other_account = ClientBuilder::new(pad32(b"other-account"))
        .registry(selfremove_registry())
        .protocol_profile(ProtocolProfile::Current)
        .attach(&bus);
    let mut competitor = ClientBuilder::new(pad32(b"competitor"))
        .registry(selfremove_registry())
        .protocol_profile(ProtocolProfile::Current)
        .attach(&bus);
    let mut observer = ClientBuilder::new(pad32(b"observer"))
        .registry(selfremove_registry())
        .protocol_profile(ProtocolProfile::Current)
        .attach(&bus);
    let mut app_invitee = ClientBuilder::new(pad32(b"app-invitee"))
        .registry(selfremove_registry())
        .protocol_profile(ProtocolProfile::Current)
        .attach(&bus);
    let mut quiet_invitee = ClientBuilder::new(pad32(b"quiet-invitee"))
        .registry(selfremove_registry())
        .protocol_profile(ProtocolProfile::Current)
        .attach(&bus);

    assert_eq!(
        device_a.member_id(),
        device_b.member_id(),
        "the two devices intentionally share one Marmot account credential"
    );
    let device_b_kp = device_b.fresh_key_package().await;
    let other_account_kp = other_account.fresh_key_package().await;
    let competitor_kp = competitor.fresh_key_package().await;
    let observer_kp = observer.fresh_key_package().await;
    let (group_id, pending) = device_a
        .create_group_with_admins_maybe_pending(
            "multi-device-account-witness-dedupe",
            vec![device_b_kp, other_account_kp, competitor_kp, observer_kp],
            vec![],
            vec![competitor.member_id()],
        )
        .await;
    assert!(
        pending.is_none(),
        "current-profile founding creation is immediately stable"
    );
    bus.deliver_all();
    for client in [
        &mut device_b,
        &mut other_account,
        &mut competitor,
        &mut observer,
    ] {
        let outcomes = client.tick().await;
        assert!(
            outcomes.iter().all(Result::is_ok),
            "client joins the shared base group: {outcomes:?}"
        );
    }

    let base_epoch = observer.epoch().0;
    let observer_members = observer.members();
    let shared_account_leaves: Vec<_> = observer_members
        .iter()
        .filter(|member| member.id == device_a.member_id())
        .collect();
    assert_eq!(
        shared_account_leaves.len(),
        2,
        "the base group must contain two MLS leaves for the shared account"
    );
    assert_ne!(
        shared_account_leaves[0].credential, shared_account_leaves[1].credential,
        "the shared-account leaves retain distinct MLS signature keys"
    );

    let shared_history = device_b
        .send_app_capture(b"shared history before the fork".to_vec())
        .await;
    let shared_history = openmls_projection_message(&device_b, &shared_history).await;
    assert_eq!(
        project_mls_message(&shared_history.payload)
            .expect("shared-history app projects")
            .source_epoch,
        Some(base_epoch),
        "the control message is at the fork epoch and must not witness either branch"
    );

    let app_invitee_kp = app_invitee.fresh_key_package().await;
    let quiet_invitee_kp = quiet_invitee.fresh_key_package().await;
    let app_pending = device_a.invite(vec![app_invitee_kp]).await;
    let _quiet_pending = competitor.invite(vec![quiet_invitee_kp]).await;
    let commit_messages = queued_commit_messages(&observer, &bus).await;
    assert_eq!(
        commit_messages.len(),
        2,
        "the setup creates two branch tips"
    );

    let wrapped_app_commit = bus
        .queued_messages()
        .into_iter()
        .find(|message| message.id == commit_messages[0].id)
        .expect("wrapped app-branch commit remains queued");
    device_a.confirm(app_pending).await;
    for client in [&mut device_b, &mut other_account] {
        bus.inject(client.bus_id, wrapped_app_commit.clone());
        let outcomes = client.tick().await;
        assert!(
            outcomes.iter().all(Result::is_ok),
            "peer advances onto the app branch: {outcomes:?}"
        );
        assert_eq!(client.epoch().0, base_epoch + 1);
    }

    let device_b_app = device_b
        .send_app_capture(b"shared account device B".to_vec())
        .await;
    let device_b_app = openmls_projection_message(&device_b, &device_b_app).await;
    let device_a_app = device_a
        .send_app_capture(b"shared account device A".to_vec())
        .await;
    let device_a_app = openmls_projection_message(&device_a, &device_a_app).await;
    let other_account_app = other_account
        .send_app_capture(b"different account witness".to_vec())
        .await;
    let other_account_app = openmls_projection_message(&other_account, &other_account_app).await;

    let canonicalize = |pending_messages: Vec<TransportMessage>| {
        canonicalize_openmls_batch(
            observer.storage(),
            &group_id,
            OpenMlsCanonicalizationBatch {
                state: CanonicalizationState {
                    current_tip_epoch: base_epoch,
                    retained_anchor_epoch: base_epoch,
                    last_convergence_relevant_input_ms: 0,
                    seen_message_ids: BTreeSet::new(),
                },
                candidate_paths: vec![
                    OpenMlsCandidatePath {
                        branch_id: "same-account-branch".into(),
                        messages: vec![commit_messages[0].clone()],
                    },
                    OpenMlsCandidatePath {
                        branch_id: "quiet-branch".into(),
                        messages: vec![commit_messages[1].clone()],
                    },
                ],
                pending_messages,
                already_delivered_app_ids: BTreeSet::new(),
                outbound_intents: vec![],
                policy: base_test_policy(),
                now_ms: 2_000,
            },
        )
        .expect("real OpenMLS canonicalization succeeds")
    };

    let device_b_first = canonicalize(vec![
        shared_history.clone(),
        device_b_app.clone(),
        device_a_app.clone(),
    ]);
    let device_a_first = canonicalize(vec![
        device_a_app.clone(),
        shared_history.clone(),
        device_b_app.clone(),
    ]);
    for result in [&device_b_first, &device_a_first] {
        let trace = result
            .selection_trace
            .as_ref()
            .expect("selection trace is recorded");
        let candidate = trace
            .candidates
            .iter()
            .find(|candidate| candidate.branch_id == "same-account-branch")
            .expect("app branch is traced");
        assert_eq!(candidate.app_witnesses.len(), 2);
        assert_eq!(
            candidate.score.app_witness_score, 1,
            "two real leaves of one account count once"
        );
        assert!(
            !candidate.score.witness_quorum_met,
            "one distinct account cannot satisfy a two-account quorum"
        );
        assert_eq!(
            result.selected_branch_id.as_deref(),
            Some("same-account-branch")
        );
        assert_eq!(
            trace
                .rule_trace
                .iter()
                .find(|rule| rule.decisive)
                .map(|rule| rule.rule_name),
            Some("app_witness_score")
        );
    }
    assert_eq!(
        device_b_first.selection_trace, device_a_first.selection_trace,
        "delivery order and which same-account device arrives first do not change selection"
    );

    let with_other_account = canonicalize(vec![
        shared_history,
        device_b_app,
        other_account_app,
        device_a_app,
    ]);
    let trace = with_other_account
        .selection_trace
        .as_ref()
        .expect("selection trace is recorded");
    let candidate = trace
        .candidates
        .iter()
        .find(|candidate| candidate.branch_id == "same-account-branch")
        .expect("app branch is traced");
    assert_eq!(
        candidate.app_witnesses.len(),
        3,
        "the fork-epoch shared-history message is excluded from branch witnesses"
    );
    assert_eq!(
        candidate.score.app_witness_score, 2,
        "a genuinely different account increases the witness score"
    );
    assert!(
        candidate.score.witness_quorum_met,
        "two distinct accounts satisfy the configured quorum"
    );
    assert_eq!(
        with_other_account.selected_branch_id.as_deref(),
        Some("same-account-branch")
    );
    assert_eq!(
        trace
            .rule_trace
            .iter()
            .find(|rule| rule.decisive)
            .map(|rule| rule.rule_name),
        Some("effective_commit_depth"),
        "quorum boost is the first decisive selector field"
    );
    assert_eq!(
        observer.epoch().0,
        base_epoch,
        "projection probes leave the retained observer state untouched"
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
        base_test_policy(),
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
        base_test_policy(),
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
        base_test_policy(),
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
        candidate_count: 2,
        eligible_count: 2,
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
        selection_trace: None,
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
        candidate_count: 2,
        eligible_count: 1,
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
                rejection_category: None,
            },
            DroppedMessage {
                message_id: hex::encode(malformed_proposal_id.as_slice()),
                kind: MessageKind::Proposal,
                reason: DroppedMessageReason::Malformed,
                rejection_category: None,
            },
        ],
        already_seen: vec![],
        queued_outbound_intents: vec![],
        publishable_outbound_messages: vec![],
        errors: vec![],
        selection_trace: None,
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
        protocol_profile: cgka_traits::group::ProtocolProfile::Legacy,
        removed: false,
        unrecoverable: false,
        disbanded: None,
        join_epoch: EpochId(0),
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
