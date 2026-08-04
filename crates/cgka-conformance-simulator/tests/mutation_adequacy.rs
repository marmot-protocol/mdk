use std::collections::BTreeSet;

use cgka_conformance_simulator::mutation_adequacy::{
    SemanticMutation, run_all_mutation_sentinels, run_mutation_sentinel,
};

#[tokio::test]
async fn every_targeted_semantic_mutation_is_killed() {
    let results = run_all_mutation_sentinels().await;
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

#[tokio::test]
async fn lifecycle_and_output_mutants_start_from_shared_baseline_observations() {
    let expected = [
        (
            SemanticMutation::SchedulerDeadlineRearm,
            "phase:Collecting:frozen:None",
        ),
        (
            SemanticMutation::OutputInvalidation,
            "InvalidatedLosingBranch",
        ),
        (SemanticMutation::PublicationAcknowledgement, "pending:2->0"),
        (
            SemanticMutation::RetainedHistoryExpirationBoundary,
            "Accepted",
        ),
    ];
    for (mutation, baseline) in expected {
        assert_eq!(
            run_mutation_sentinel(mutation).await.baseline_observation,
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
    let row_ids = matrix
        .lines()
        .filter_map(|line| {
            line.strip_prefix("| `")
                .and_then(|rest| rest.split_once("` |"))
                .map(|(id, _)| id)
        })
        .collect::<Vec<_>>();
    for id in &ids {
        assert_eq!(
            row_ids.iter().filter(|row_id| *row_id == id).count(),
            1,
            "matrix must contain exactly one row for {id}"
        );
    }
    assert_eq!(row_ids.len(), ids.len());
}
