#![cfg(feature = "test-policy-overrides")]

use cgka_conformance_simulator::canonicalization::{
    CanonicalizationInput, CanonicalizationPolicy, CanonicalizationState,
};
use cgka_conformance_simulator::convergence::BranchCandidate;
use cgka_conformance_simulator::{PolicySweepConstantV1, sweep_canonicalization_policy};
use cgka_traits::engine::CommitOrderingPriority;
use std::collections::BTreeSet;

fn fixed_input() -> CanonicalizationInput {
    CanonicalizationInput {
        state: CanonicalizationState {
            current_tip_epoch: 10,
            retained_anchor_epoch: 5,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: BTreeSet::new(),
        },
        pending_messages: vec![],
        outbound_intents: vec![],
        candidate_branches: vec![BranchCandidate {
            id: "depth-boundary".into(),
            fork_epoch: 5,
            tip_epoch: 11,
            tip_priority: CommitOrderingPriority::Ordinary,
            tip_committer: b"alice".to_vec(),
            tip_digest: [7; 32],
            app_witnesses: vec![],
        }],
        policy: CanonicalizationPolicy::default(),
        now_ms: 10_000,
    }
}

#[test]
fn sweep_preserves_inputs_and_exposes_the_rewind_boundary() {
    let input = fixed_input();
    let curve =
        sweep_canonicalization_policy(&input, PolicySweepConstantV1::MaxRewindCommits, [4, 5, 6]);

    assert_eq!(curve.retained_input_count, input.pending_messages.len());
    assert_eq!(curve.current_tip_epoch, input.state.current_tip_epoch);
    assert_eq!(
        curve.retained_anchor_epoch,
        input.state.retained_anchor_epoch
    );
    assert_eq!(curve.points[0].eligible_count, 0);
    assert_eq!(curve.points[1].eligible_count, 1);
    assert_eq!(curve.points[2].eligible_count, 1);
    assert!(!curve.production_auto_tuning_permitted);
}

#[test]
fn invalid_witness_override_is_a_named_boundary_failure() {
    let curve = sweep_canonicalization_policy(
        &fixed_input(),
        PolicySweepConstantV1::MaxWitnessOverrideDepth,
        [1, 6],
    );
    assert!(curve.points[0].boundary_failure.is_none());
    assert!(
        curve.points[1]
            .boundary_failure
            .as_deref()
            .is_some_and(|failure| failure.contains("must not exceed"))
    );
}
