use std::collections::{BTreeMap, BTreeSet};

use cgka_conformance_simulator::canonicalization::{
    CanonicalizationInput, CanonicalizationPolicy, CanonicalizationState, DeferredMessageReason,
    DroppedMessageReason, PeeledMessage, PeeledMessageKind, canonicalize,
};
use cgka_conformance_simulator::convergence::{
    AppWitness, BranchCandidate, ConvergencePolicy, select_canonical_branch,
};
use cgka_conformance_simulator::policy_cases::parse_policy_cases;
use cgka_conformance_simulator::reference_convergence::{
    ReferenceAppMessage, ReferenceCandidate, ReferenceCommit, ReferenceDisposition, ReferenceInput,
    ReferencePolicy, ReferencePriority, ReferenceProposal, ReferenceWitness, WitnessMode, evaluate,
    select,
};
use cgka_traits::engine::CommitOrderingPriority;
use proptest::prelude::*;
use proptest::test_runner::{RngAlgorithm, RngSeed};

const POLICY_CASES_JSON: &str = include_str!("../../../formal/tamarin/policy_cases.json");

fn ref_priority(value: CommitOrderingPriority) -> ReferencePriority {
    match value {
        CommitOrderingPriority::Privileged => ReferencePriority::Privileged,
        CommitOrderingPriority::Ordinary => ReferencePriority::Ordinary,
    }
}

fn reference_candidate(value: &BranchCandidate) -> ReferenceCandidate {
    ReferenceCandidate {
        id: value.id.clone(),
        fork_epoch: value.fork_epoch,
        tip_epoch: value.tip_epoch,
        tip_priority: ref_priority(value.tip_priority),
        tip_committer: value.tip_committer.clone(),
        tip_digest: value.tip_digest,
        app_witnesses: value
            .app_witnesses
            .iter()
            .map(|witness| ReferenceWitness {
                epoch: witness.epoch,
                sender: witness.sender.clone(),
            })
            .collect(),
    }
}

fn reference_policy(value: &ConvergencePolicy) -> ReferencePolicy {
    ReferencePolicy {
        max_rewind_commits: value.max_rewind_commits,
        witness_quorum_senders_per_epoch: value.witness_quorum_senders_per_epoch,
        witness_quorum_epochs: value.witness_quorum_epochs,
        max_witness_override_depth: value.max_witness_override_depth,
        app_message_past_epoch_limit: 5,
    }
}

#[test]
fn independent_source_has_no_production_model_import() {
    let source = include_str!("../src/reference_convergence.rs");
    for forbidden in [
        "cgka_engine",
        "canonicalization",
        "crate::convergence",
        "crate::{convergence",
    ] {
        assert!(
            !source.contains(forbidden),
            "reference model must stay independent of {forbidden}"
        );
    }
}

#[test]
fn independent_reference_matches_production_selector_policy_corpus() {
    for case in parse_policy_cases(POLICY_CASES_JSON) {
        let policy = ConvergencePolicy::from(&case.policy);
        let production: Vec<BranchCandidate> = case
            .branches
            .iter()
            .map(|branch| branch.to_candidate())
            .collect();
        let reference: Vec<ReferenceCandidate> =
            production.iter().map(reference_candidate).collect();
        let reference_refs: Vec<&ReferenceCandidate> = reference.iter().collect();

        let production_winner =
            select_canonical_branch(case.current_tip_epoch, &production, &policy).unwrap();
        let reference_winner = select(
            case.current_tip_epoch,
            &reference_refs,
            &reference_policy(&policy),
        )
        .unwrap();
        assert_eq!(reference_winner.id, production_winner.id, "{}", case.name);
        assert_eq!(reference_winner.id, case.expected.branch, "{}", case.name);
    }
}

fn candidate(id: &str, fork_epoch: u64, tip_epoch: u64, digest: u8) -> BranchCandidate {
    BranchCandidate {
        id: id.into(),
        fork_epoch,
        tip_epoch,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"alice".to_vec(),
        tip_digest: [digest; 32],
        app_witnesses: Vec::new(),
    }
}

fn commit(
    id: &str,
    branch_id: &str,
    parent: Option<&str>,
    source_epoch: u64,
    resulting_epoch: u64,
    proposals: &[&str],
) -> PeeledMessage {
    PeeledMessage {
        message_id: id.into(),
        group_id: "group".into(),
        sender: b"alice".to_vec(),
        source_epoch,
        kind: PeeledMessageKind::Commit {
            branch_id: branch_id.into(),
            parent_branch_id: parent.map(str::to_owned),
            fork_epoch: 1,
            resulting_epoch,
            tip_priority: CommitOrderingPriority::Ordinary,
            tip_digest: [resulting_epoch as u8; 32],
            consumed_proposal_ids: proposals.iter().map(|id| (*id).to_owned()).collect(),
        },
    }
}

fn proposal(id: &str, branch_id: &str, source_epoch: u64) -> PeeledMessage {
    PeeledMessage {
        message_id: id.into(),
        group_id: "group".into(),
        sender: b"alice".to_vec(),
        source_epoch,
        kind: PeeledMessageKind::Proposal {
            branch_id: branch_id.into(),
        },
    }
}

fn canonical_input(messages: Vec<PeeledMessage>) -> CanonicalizationInput {
    CanonicalizationInput {
        state: CanonicalizationState {
            current_tip_epoch: 3,
            retained_anchor_epoch: 1,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: std::sync::Arc::new(BTreeSet::new()),
        },
        pending_messages: messages,
        outbound_intents: Vec::new(),
        candidate_branches: vec![candidate("parent", 1, 3, 0)],
        policy: CanonicalizationPolicy::default(),
        now_ms: 5_000,
    }
}

#[test]
fn dependency_closure_multi_proposal_and_expiry_match_production_canonicalizer() {
    let messages = vec![
        proposal("proposal-a", "parent", 3),
        proposal("proposal-b", "parent", 3),
        proposal("expired", "parent", 2),
        commit(
            "commit-4",
            "tip",
            Some("parent"),
            3,
            4,
            &["proposal-a", "proposal-b"],
        ),
    ];
    let production = canonicalize(canonical_input(messages));

    let reference = evaluate(&ReferenceInput {
        current_tip_epoch: 3,
        retained_anchor_epoch: 1,
        candidates: vec![reference_candidate(&candidate("parent", 1, 3, 0))],
        commits: vec![ReferenceCommit {
            message_id: "commit-4".into(),
            branch_id: "tip".into(),
            parent_branch_id: Some("parent".into()),
            sender: b"alice".to_vec(),
            source_epoch: 3,
            fork_epoch: 1,
            resulting_epoch: 4,
            tip_priority: ReferencePriority::Ordinary,
            tip_digest: [4; 32],
            consumed_proposal_ids: vec!["proposal-a".into(), "proposal-b".into()],
            authenticated: true,
            authorized: true,
        }],
        proposals: vec![
            ReferenceProposal {
                message_id: "proposal-a".into(),
                branch_id: "parent".into(),
                source_epoch: 3,
                authenticated: true,
                authorized: true,
            },
            ReferenceProposal {
                message_id: "proposal-b".into(),
                branch_id: "parent".into(),
                source_epoch: 3,
                authenticated: true,
                authorized: true,
            },
            ReferenceProposal {
                message_id: "expired".into(),
                branch_id: "parent".into(),
                source_epoch: 2,
                authenticated: true,
                authorized: true,
            },
        ],
        app_messages: Vec::new(),
        policy: ReferencePolicy::default(),
        witness_mode: WitnessMode::Enabled,
    });

    assert_eq!(reference.selected_branch_id, production.selected_branch_id);
    assert_eq!(reference.accepted_commit_path, production.accepted_commits);
    assert_eq!(
        production.accepted_proposals,
        vec!["proposal-a", "proposal-b"]
    );
    assert_eq!(
        reference.dispositions["proposal-a"],
        ReferenceDisposition::Accepted
    );
    assert_eq!(
        reference.dispositions["proposal-b"],
        ReferenceDisposition::Accepted
    );
    assert_eq!(
        reference.dispositions["expired"],
        ReferenceDisposition::DroppedExpiredProposal
    );
    assert!(production.dropped_messages.iter().any(|entry| {
        entry.message_id == "expired"
            && entry.reason == DroppedMessageReason::InvalidAgainstCandidateState
    }));
}

#[test]
fn missing_parent_disposition_matches_production_canonicalizer() {
    let orphan = commit("orphan", "tip", Some("absent"), 3, 4, &[]);
    let production = canonicalize(canonical_input(vec![orphan]));
    let reference = evaluate(&ReferenceInput {
        current_tip_epoch: 3,
        retained_anchor_epoch: 1,
        candidates: vec![reference_candidate(&candidate("parent", 1, 3, 0))],
        commits: vec![ReferenceCommit {
            message_id: "orphan".into(),
            branch_id: "tip".into(),
            parent_branch_id: Some("absent".into()),
            sender: b"alice".to_vec(),
            source_epoch: 3,
            fork_epoch: 1,
            resulting_epoch: 4,
            tip_priority: ReferencePriority::Ordinary,
            tip_digest: [4; 32],
            consumed_proposal_ids: Vec::new(),
            authenticated: true,
            authorized: true,
        }],
        proposals: Vec::new(),
        app_messages: Vec::new(),
        policy: ReferencePolicy::default(),
        witness_mode: WitnessMode::Enabled,
    });
    assert_eq!(
        reference.dispositions["orphan"],
        ReferenceDisposition::DeferredMissingParent
    );
    assert!(production.deferred_messages.iter().any(|entry| {
        entry.message_id == "orphan"
            && entry.reason == DeferredMessageReason::MissingCandidateParent
    }));
}

#[test]
fn invalid_commit_shape_is_not_misclassified_as_a_missing_parent() {
    let reference = evaluate(&ReferenceInput {
        current_tip_epoch: 3,
        retained_anchor_epoch: 1,
        candidates: vec![reference_candidate(&candidate("parent", 1, 3, 0))],
        commits: vec![
            ReferenceCommit {
                message_id: "non-advancing".into(),
                branch_id: "non-advancing-tip".into(),
                parent_branch_id: Some("parent".into()),
                sender: b"alice".to_vec(),
                source_epoch: 3,
                fork_epoch: 1,
                resulting_epoch: 3,
                tip_priority: ReferencePriority::Ordinary,
                tip_digest: [3; 32],
                consumed_proposal_ids: Vec::new(),
                authenticated: true,
                authorized: true,
            },
            ReferenceCommit {
                message_id: "duplicate-branch".into(),
                branch_id: "parent".into(),
                parent_branch_id: Some("parent".into()),
                sender: b"alice".to_vec(),
                source_epoch: 3,
                fork_epoch: 1,
                resulting_epoch: 4,
                tip_priority: ReferencePriority::Ordinary,
                tip_digest: [4; 32],
                consumed_proposal_ids: Vec::new(),
                authenticated: true,
                authorized: true,
            },
        ],
        proposals: Vec::new(),
        app_messages: Vec::new(),
        policy: ReferencePolicy::default(),
        witness_mode: WitnessMode::Enabled,
    });

    assert_eq!(
        reference.dispositions["non-advancing"],
        ReferenceDisposition::DroppedInvalidCommit
    );
    assert_eq!(
        reference.dispositions["duplicate-branch"],
        ReferenceDisposition::DroppedInvalidCommit
    );
}

fn arb_witnesses() -> impl Strategy<Value = Vec<AppWitness>> {
    prop::collection::vec((0u64..6, 0u8..4), 0..8).prop_map(|items| {
        items
            .into_iter()
            .map(|(epoch, sender)| AppWitness {
                epoch,
                sender: vec![sender],
            })
            .collect()
    })
}

proptest! {
    // This differential property stays beside the bounded reference corpus so
    // model/production conversion helpers have one owner. Unlike general
    // simulator invariants, it does not drive the engine harness.
    #![proptest_config(ProptestConfig {
        cases: 256,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(0x4d34_5245_464d_4f44),
        ..ProptestConfig::default()
    })]

    #[test]
    fn small_shrinkable_selector_inputs_match_independent_model(
        current_tip in 0u64..9,
        fork_a in 0u64..6,
        fork_b in 0u64..6,
        depth_a in 1u64..5,
        depth_b in 1u64..5,
        privileged_a in any::<bool>(),
        privileged_b in any::<bool>(),
        committer_a in 0u8..4,
        committer_b in 0u8..4,
        witnesses_a in arb_witnesses(),
        witnesses_b in arb_witnesses(),
        max_rewind in 0u64..7,
        quorum_senders in 1usize..4,
        quorum_epochs in 1usize..3,
        boost in 0u64..3,
    ) {
        let policy = ConvergencePolicy {
            max_rewind_commits: max_rewind.max(boost),
            witness_quorum_senders_per_epoch: quorum_senders,
            witness_quorum_epochs: quorum_epochs,
            max_witness_override_depth: boost,
        };
        let candidates = vec![
            BranchCandidate {
                id: "a".into(), fork_epoch: fork_a, tip_epoch: fork_a + depth_a,
                tip_priority: if privileged_a { CommitOrderingPriority::Privileged } else { CommitOrderingPriority::Ordinary },
                tip_committer: vec![committer_a], tip_digest: [0; 32], app_witnesses: witnesses_a,
            },
            BranchCandidate {
                id: "b".into(), fork_epoch: fork_b, tip_epoch: fork_b + depth_b,
                tip_priority: if privileged_b { CommitOrderingPriority::Privileged } else { CommitOrderingPriority::Ordinary },
                tip_committer: vec![committer_b], tip_digest: [1; 32], app_witnesses: witnesses_b,
            },
        ];
        let reference: Vec<ReferenceCandidate> = candidates.iter().map(reference_candidate).collect();
        let reference_refs: Vec<&ReferenceCandidate> = reference.iter().collect();
        let production = select_canonical_branch(current_tip, &candidates, &policy).map(|c| c.id.as_str());
        let model = select(current_tip, &reference_refs, &reference_policy(&policy)).map(|c| c.id.as_str());
        prop_assert!(
            model == production,
            "selector drift at current_tip={}, policy={:?}, candidates={:?}",
            current_tip,
            policy,
            candidates
        );
    }
}

#[test]
fn witness_mode_is_a_first_class_input_not_a_policy_rewrite() {
    let apps = vec![
        ReferenceAppMessage {
            message_id: "a".into(),
            sender: b"alice".to_vec(),
            epoch: 2,
            decrypts_on_branches: vec!["online".into()],
            authenticated: true,
            authorized: true,
        },
        ReferenceAppMessage {
            message_id: "b".into(),
            sender: b"bob".to_vec(),
            epoch: 2,
            decrypts_on_branches: vec!["online".into()],
            authenticated: true,
            authorized: true,
        },
    ];
    let base = ReferenceInput {
        current_tip_epoch: 3,
        retained_anchor_epoch: 1,
        candidates: vec![
            reference_candidate(&candidate("online", 1, 2, 0xff)),
            reference_candidate(&candidate("withheld", 1, 3, 0x00)),
        ],
        commits: Vec::new(),
        proposals: Vec::new(),
        app_messages: apps,
        policy: ReferencePolicy::default(),
        witness_mode: WitnessMode::Enabled,
    };
    let enabled = evaluate(&base);
    let disabled = evaluate(&ReferenceInput {
        witness_mode: WitnessMode::Disabled,
        ..base
    });
    assert_eq!(enabled.selected_branch_id.as_deref(), Some("online"));
    assert_eq!(disabled.selected_branch_id.as_deref(), Some("withheld"));
}

#[test]
fn result_dispositions_are_keyed_for_direct_ledger_comparison() {
    let result = evaluate(&ReferenceInput {
        current_tip_epoch: 0,
        retained_anchor_epoch: 0,
        candidates: Vec::new(),
        commits: Vec::new(),
        proposals: Vec::new(),
        app_messages: Vec::new(),
        policy: ReferencePolicy::default(),
        witness_mode: WitnessMode::Enabled,
    });
    let expected = BTreeMap::<String, ReferenceDisposition>::new();
    assert_eq!(result.dispositions, expected);
}
