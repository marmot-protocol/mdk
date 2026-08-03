use std::collections::BTreeSet;

use cgka_conformance_simulator::mutation_adequacy::{SemanticMutation, run_all_mutation_sentinels};

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
