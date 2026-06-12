use std::collections::BTreeSet;

use cgka_conformance_simulator::canonicalization::{
    AlreadySeen, CanonicalizationInput, CanonicalizationPolicy, CanonicalizationState,
    ConvergenceStatus, DroppedMessage, DroppedMessageReason, InvalidatedAppMessage,
    InvalidatedAppMessageReason, MaterializedCandidate, MessageKind, OutboundIntent, PeeledMessage,
    PeeledMessageKind, canonicalize, canonicalize_with_materialized_candidates,
};
use cgka_conformance_simulator::convergence::{BranchCandidate, ConvergencePolicy};
use cgka_traits::engine::CommitOrderingPriority;

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn branch(id: &str, fork_epoch: u64, tip_epoch: u64, digest_byte: u8) -> BranchCandidate {
    BranchCandidate {
        id: id.into(),
        fork_epoch,
        tip_epoch,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"alice".to_vec(),
        tip_digest: digest(digest_byte),
        app_witnesses: vec![],
    }
}

fn policy() -> CanonicalizationPolicy {
    CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 5,
            witness_quorum_senders_per_epoch: 2,
            witness_quorum_epochs: 1,
            max_witness_override_depth: 1,
        },
        app_message_past_epoch_limit: 5,
        settlement_quiescence_ms: 1_000,
    }
}

fn state(current_tip_epoch: u64, retained_anchor_epoch: u64) -> CanonicalizationState {
    CanonicalizationState {
        current_tip_epoch,
        retained_anchor_epoch,
        last_convergence_relevant_input_ms: 0,
        seen_message_ids: BTreeSet::new(),
    }
}

fn input(
    pending_messages: Vec<PeeledMessage>,
    candidate_branches: Vec<BranchCandidate>,
) -> CanonicalizationInput {
    CanonicalizationInput {
        state: state(3, 1),
        pending_messages,
        outbound_intents: vec![],
        candidate_branches,
        policy: policy(),
        now_ms: 2_000,
    }
}

fn commit(id: &str, branch_id: &str, fork_epoch: u64) -> PeeledMessage {
    commit_edge(id, branch_id, None, fork_epoch, fork_epoch + 1, 0x00)
}

fn commit_edge(
    id: &str,
    branch_id: &str,
    parent_branch_id: Option<&str>,
    fork_epoch: u64,
    resulting_epoch: u64,
    tip_digest: u8,
) -> PeeledMessage {
    commit_edge_with_proposals(
        id,
        branch_id,
        parent_branch_id,
        fork_epoch,
        resulting_epoch,
        tip_digest,
        &[],
    )
}

fn commit_edge_with_proposals(
    id: &str,
    branch_id: &str,
    parent_branch_id: Option<&str>,
    fork_epoch: u64,
    resulting_epoch: u64,
    tip_digest: u8,
    consumed_proposal_ids: &[&str],
) -> PeeledMessage {
    PeeledMessage {
        message_id: id.into(),
        group_id: "group".into(),
        sender: b"alice".to_vec(),
        source_epoch: fork_epoch,
        kind: PeeledMessageKind::Commit {
            branch_id: branch_id.into(),
            parent_branch_id: parent_branch_id.map(str::to_owned),
            fork_epoch,
            resulting_epoch,
            tip_priority: CommitOrderingPriority::Ordinary,
            tip_digest: digest(tip_digest),
            consumed_proposal_ids: consumed_proposal_ids
                .iter()
                .map(|proposal_id| (*proposal_id).to_owned())
                .collect(),
        },
    }
}

struct ChildCommitEdge<'a> {
    branch_id: &'a str,
    parent_branch_id: &'a str,
    fork_epoch: u64,
    source_epoch: u64,
    resulting_epoch: u64,
    tip_digest: u8,
}

fn child_commit_edge(
    id: &str,
    branch_id: &str,
    parent_branch_id: &str,
    fork_epoch: u64,
    source_epoch: u64,
    resulting_epoch: u64,
    tip_digest: u8,
) -> PeeledMessage {
    child_commit_edge_with_proposals(
        id,
        ChildCommitEdge {
            branch_id,
            parent_branch_id,
            fork_epoch,
            source_epoch,
            resulting_epoch,
            tip_digest,
        },
        &[],
    )
}

fn child_commit_edge_with_proposals(
    id: &str,
    edge: ChildCommitEdge<'_>,
    consumed_proposal_ids: &[&str],
) -> PeeledMessage {
    PeeledMessage {
        message_id: id.into(),
        group_id: "group".into(),
        sender: b"alice".to_vec(),
        source_epoch: edge.source_epoch,
        kind: PeeledMessageKind::Commit {
            branch_id: edge.branch_id.into(),
            parent_branch_id: Some(edge.parent_branch_id.into()),
            fork_epoch: edge.fork_epoch,
            resulting_epoch: edge.resulting_epoch,
            tip_priority: CommitOrderingPriority::Ordinary,
            tip_digest: digest(edge.tip_digest),
            consumed_proposal_ids: consumed_proposal_ids
                .iter()
                .map(|proposal_id| (*proposal_id).to_owned())
                .collect(),
        },
    }
}

fn proposal(id: &str, branch_id: &str) -> PeeledMessage {
    PeeledMessage {
        message_id: id.into(),
        group_id: "group".into(),
        sender: b"alice".to_vec(),
        source_epoch: 2,
        kind: PeeledMessageKind::Proposal {
            branch_id: branch_id.into(),
        },
    }
}

fn app_message(
    id: &str,
    sender: &str,
    epoch: u64,
    decrypts_on_branches: &[&str],
    payload_ref: Option<&str>,
) -> PeeledMessage {
    PeeledMessage {
        message_id: id.into(),
        group_id: "group".into(),
        sender: sender.as_bytes().to_vec(),
        source_epoch: epoch,
        kind: PeeledMessageKind::AppMessage {
            epoch,
            decrypts_on_branches: decrypts_on_branches
                .iter()
                .map(|branch| (*branch).to_owned())
                .collect(),
            decrypted_payload_ref: payload_ref.map(str::to_owned),
        },
    }
}

#[test]
fn same_pending_set_in_different_orders_yields_same_result() {
    let branches = vec![branch("live", 1, 3, 0xff), branch("quiet", 1, 3, 0x00)];
    let app_a = app_message("app-a", "alice", 2, &["live"], Some("payload-a"));
    let app_b = app_message("app-b", "bob", 2, &["live"], Some("payload-b"));

    let forward = canonicalize(input(vec![app_a.clone(), app_b.clone()], branches.clone()));
    let reversed = canonicalize(input(vec![app_b, app_a], branches));

    assert_eq!(forward, reversed);
    assert_eq!(forward.selected_branch_id.as_deref(), Some("live"));
    assert_eq!(
        forward.accepted_app_messages,
        vec!["app-a".to_string(), "app-b".to_string()]
    );
}

#[test]
fn commit_edges_materialize_candidate_branches_before_selection() {
    let result = canonicalize(input(
        vec![
            child_commit_edge("live-2", "live-tip", "live-mid", 1, 2, 3, 0xff),
            commit_edge("withheld-1", "withheld-tip", None, 1, 2, 0x00),
            commit_edge("live-1", "live-mid", None, 1, 2, 0xff),
        ],
        vec![],
    ));

    assert_eq!(result.selected_branch_id.as_deref(), Some("live-tip"));
    assert_eq!(result.selected_tip, Some(3));
    assert_eq!(
        result.accepted_commits,
        vec!["live-1".to_string(), "live-2".to_string()]
    );
    assert_eq!(
        result.dropped_messages,
        vec![DroppedMessage {
            message_id: "withheld-1".into(),
            kind: MessageKind::Commit,
            reason: DroppedMessageReason::InvalidAgainstCandidateState,
        }]
    );
}

#[test]
fn commit_with_missing_parent_remains_pending() {
    let result = canonicalize(input(
        vec![child_commit_edge(
            "orphan", "child", "missing", 1, 2, 3, 0x00,
        )],
        vec![branch("live", 1, 3, 0x00)],
    ));

    assert_eq!(result.selected_branch_id.as_deref(), Some("live"));
    assert!(result.accepted_commits.is_empty());
    assert!(result.dropped_messages.is_empty());
}

#[test]
fn duplicate_commit_proposal_and_app_message_return_already_seen() {
    let result = canonicalize(input(
        vec![
            commit("commit-1", "live", 1),
            commit("commit-1", "live", 1),
            proposal("proposal-1", "live"),
            proposal("proposal-1", "live"),
            app_message("app-1", "alice", 2, &["live"], Some("payload-1")),
            app_message("app-1", "alice", 2, &["live"], Some("payload-1")),
        ],
        vec![branch("live", 1, 3, 0x00)],
    ));

    assert_eq!(
        result.already_seen,
        vec![
            AlreadySeen {
                message_id: "app-1".into(),
                kind: MessageKind::AppMessage,
            },
            AlreadySeen {
                message_id: "commit-1".into(),
                kind: MessageKind::Commit,
            },
            AlreadySeen {
                message_id: "proposal-1".into(),
                kind: MessageKind::Proposal,
            },
        ]
    );
}

#[test]
fn losing_branch_app_message_is_invalidated_with_payload_ref() {
    let result = canonicalize(input(
        vec![app_message(
            "losing-app",
            "mallory",
            2,
            &["losing"],
            Some("stored-payload"),
        )],
        vec![branch("live", 1, 3, 0x00), branch("losing", 1, 2, 0xff)],
    ));

    assert_eq!(result.selected_branch_id.as_deref(), Some("live"));
    assert_eq!(
        result.invalidated_app_messages,
        vec![InvalidatedAppMessage {
            message_id: "losing-app".into(),
            epoch: 2,
            reason: InvalidatedAppMessageReason::LosingBranch,
            decrypted_payload_ref: Some("stored-payload".into()),
        }]
    );
}

#[test]
fn proposals_are_accepted_only_when_consumed_by_canonical_commits() {
    let result = canonicalize(input(
        vec![
            proposal("accepted-proposal", "live-parent"),
            proposal("pending-proposal", "live-parent"),
            proposal("losing-proposal", "losing-parent"),
            child_commit_edge_with_proposals(
                "live-commit",
                ChildCommitEdge {
                    branch_id: "live-tip",
                    parent_branch_id: "live-parent",
                    fork_epoch: 1,
                    source_epoch: 3,
                    resulting_epoch: 4,
                    tip_digest: 0x00,
                },
                &["accepted-proposal"],
            ),
            child_commit_edge_with_proposals(
                "losing-commit",
                ChildCommitEdge {
                    branch_id: "losing-tip",
                    parent_branch_id: "losing-parent",
                    fork_epoch: 1,
                    source_epoch: 3,
                    resulting_epoch: 4,
                    tip_digest: 0xff,
                },
                &["losing-proposal"],
            ),
        ],
        vec![
            branch("live-parent", 1, 3, 0x00),
            branch("losing-parent", 1, 3, 0xff),
        ],
    ));

    assert_eq!(result.accepted_proposals, vec!["accepted-proposal"]);
    assert_eq!(
        result.dropped_messages,
        vec![
            DroppedMessage {
                message_id: "losing-commit".into(),
                kind: MessageKind::Commit,
                reason: DroppedMessageReason::InvalidAgainstCandidateState,
            },
            DroppedMessage {
                message_id: "losing-proposal".into(),
                kind: MessageKind::Proposal,
                reason: DroppedMessageReason::InvalidAgainstCandidateState,
            },
        ]
    );
    assert!(
        !result
            .accepted_proposals
            .contains(&"pending-proposal".into())
    );
}

#[test]
fn materialized_candidates_drive_commit_and_proposal_dispositions() {
    let result = canonicalize_with_materialized_candidates(
        input(
            vec![
                proposal("accepted-proposal", "live"),
                proposal("losing-proposal", "losing"),
            ],
            vec![],
        ),
        vec![
            MaterializedCandidate {
                branch: branch("live", 1, 4, 0x00),
                commit_message_ids: vec!["live-commit".into()],
                consumed_proposal_ids: vec!["accepted-proposal".into()],
            },
            MaterializedCandidate {
                branch: branch("losing", 1, 4, 0xff),
                commit_message_ids: vec!["losing-commit".into()],
                consumed_proposal_ids: vec!["losing-proposal".into()],
            },
        ],
    );

    assert_eq!(result.selected_branch_id.as_deref(), Some("live"));
    assert_eq!(result.accepted_commits, vec!["live-commit"]);
    assert_eq!(result.accepted_proposals, vec!["accepted-proposal"]);
    assert_eq!(
        result.dropped_messages,
        vec![
            DroppedMessage {
                message_id: "losing-commit".into(),
                kind: MessageKind::Commit,
                reason: DroppedMessageReason::InvalidAgainstCandidateState,
            },
            DroppedMessage {
                message_id: "losing-proposal".into(),
                kind: MessageKind::Proposal,
                reason: DroppedMessageReason::InvalidAgainstCandidateState,
            },
        ]
    );
}

#[test]
fn materialized_candidate_preserves_commit_application_order() {
    let result = canonicalize_with_materialized_candidates(
        input(vec![], vec![]),
        vec![MaterializedCandidate {
            branch: branch("live", 1, 4, 0x00),
            commit_message_ids: vec!["z-first-commit".into(), "a-second-commit".into()],
            consumed_proposal_ids: vec![],
        }],
    );

    assert_eq!(
        result.accepted_commits,
        vec!["z-first-commit".to_string(), "a-second-commit".to_string()]
    );
}

#[test]
fn app_message_beyond_mls_past_epoch_limit_is_invalidated() {
    let mut input = input(
        vec![app_message("expired-app", "alice", 2, &["live"], None)],
        vec![branch("live", 1, 8, 0x00)],
    );
    input.state.current_tip_epoch = 8;
    input.policy.app_message_past_epoch_limit = 5;

    let result = canonicalize(input);

    assert_eq!(
        result.invalidated_app_messages,
        vec![InvalidatedAppMessage {
            message_id: "expired-app".into(),
            epoch: 2,
            reason: InvalidatedAppMessageReason::BeyondAppRetention,
            decrypted_payload_ref: None,
        }]
    );
}

#[test]
fn commit_beyond_rollback_horizon_is_discarded() {
    let mut input = input(
        vec![commit("stale-commit", "stale", 4)],
        vec![branch("live", 8, 10, 0x00), branch("stale", 4, 7, 0xff)],
    );
    input.state.current_tip_epoch = 10;
    input.policy.convergence.max_rewind_commits = 5;

    let result = canonicalize(input);

    assert_eq!(
        result.dropped_messages,
        vec![DroppedMessage {
            message_id: "stale-commit".into(),
            kind: MessageKind::Commit,
            reason: DroppedMessageReason::BeyondRollbackHorizon,
        }]
    );
}

#[test]
fn outbound_intents_are_queued_while_syncing() {
    let mut input = input(vec![], vec![branch("live", 1, 3, 0x00)]);
    input.state.last_convergence_relevant_input_ms = 1_500;
    input.now_ms = 2_000;
    input.outbound_intents = vec![OutboundIntent::SendAppMessage {
        payload: "hello".into(),
    }];

    let result = canonicalize(input);

    assert_eq!(result.convergence_status, ConvergenceStatus::Syncing);
    assert_eq!(
        result.queued_outbound_intents,
        vec![OutboundIntent::SendAppMessage {
            payload: "hello".into(),
        }]
    );
    assert!(result.publishable_outbound_messages.is_empty());
}

#[test]
fn quiescence_with_no_input_is_settled() {
    let mut input = input(vec![], vec![branch("live", 1, 3, 0x00)]);
    input.state.last_convergence_relevant_input_ms = 0;
    input.now_ms = 5_000; // window definitely closed

    let result = canonicalize(input);

    assert_eq!(
        result.convergence_status,
        ConvergenceStatus::Settled,
        "quiesced + nothing pending = Settled"
    );
}

#[test]
fn quiescence_with_orphan_commit_in_input_is_resolving() {
    // Construct a commit whose parent branch isn't materialized AND
    // doesn't fork from a tracked candidate. The canonicalizer cannot
    // give it a disposition this pass — the spec calls this state
    // "Resolving" (window closed but pass left work pending),
    // distinct from Settled (fixed point reached).
    let orphan = commit_edge(
        "orphan-1",
        "orphan-branch",
        Some("missing-parent"),
        5,
        6,
        0x99,
    );
    let mut inp = input(vec![orphan], vec![]);
    inp.state.last_convergence_relevant_input_ms = 0;
    inp.now_ms = 5_000; // window closed

    let result = canonicalize(inp);

    assert_eq!(
        result.convergence_status,
        ConvergenceStatus::Resolving,
        "orphan commit with no parent leaves work pending -> Resolving"
    );
    // The orphan didn't get a disposition.
    assert!(result.accepted_commits.is_empty());
    assert!(result.dropped_messages.is_empty());
    assert!(result.invalidated_app_messages.is_empty());
}
