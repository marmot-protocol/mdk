use std::collections::BTreeSet;

use cgka_conformance_simulator::mutation_adequacy::{
    SemanticMutation, run_all_mutation_sentinels, run_mutation_sentinel,
};

#[test]
fn every_targeted_semantic_mutation_is_killed() {
    let results = run_all_mutation_sentinels();
    assert_eq!(results.len(), SemanticMutation::ALL.len());
    for result in results {
        assert!(
            result.killed(),
            "mutation {} survived with observation {:?}",
            result.mutation.id(),
            result.baseline_observation
        );
    }
}

#[test]
fn lifecycle_and_output_mutants_start_from_shared_baseline_observations() {
    let expected = [
        (
            SemanticMutation::SchedulerDeadlineRearm,
            "phase:Collecting:frozen:None",
        ),
        (
            SemanticMutation::OutputInvalidation,
            "InvalidatedLosingBranch",
        ),
        (
            SemanticMutation::PublicationAcknowledgement,
            "resolution:Some(Accepted)",
        ),
        (
            SemanticMutation::RetainedHistoryExpirationBoundary,
            "Accepted",
        ),
    ];
    for (mutation, baseline) in expected {
        assert_eq!(
            run_mutation_sentinel(mutation).baseline_observation,
            baseline,
            "{mutation:?}"
        );
    }
}

#[test]
fn mutation_matrix_has_exactly_one_row_per_executable_mutant() {
    let matrix = include_str!("../MUTATION_MATRIX.md");
    let ids: BTreeSet<&str> = SemanticMutation::ALL
        .iter()
        .map(|mutation| mutation.id())
        .collect();
    for id in &ids {
        assert_eq!(
            matrix.matches(&format!("`{id}`")).count(),
            1,
            "matrix must contain exactly one row for {id}"
        );
    }
    assert_eq!(matrix.matches("| `").count(), ids.len());
}
