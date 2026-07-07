//! End-to-end convergence accept path: a recovered committer-decided
//! convergence synthesizes a vector whose scenario the simulator reproduces —
//! the observer's settled decision is `tip_committer`-decided with no witness
//! quorum. `accept_convergence` returning `Ok` *is* that proof (it
//! run-and-compares internally).

use incident_replay::{accept_convergence, parse, recover_convergence};

const COMMITTER_DECIDED_CONVERGENCE: &str = r#"{
  "events": [
    {
      "kind": {
        "type": "convergence_decision",
        "current_tip_epoch": 30,
        "selected_branch_id": "win",
        "candidates": [
          { "branch_id": "win", "score": { "witness_quorum_met": false } },
          { "branch_id": "lose", "score": { "witness_quorum_met": false } }
        ],
        "rule_trace": [
          { "rule_name": "effective_commit_depth", "decisive": false },
          { "rule_name": "tip_committer", "decisive": true }
        ],
        "selected_tip_epoch": 31,
        "losing_branch_ids": ["lose"]
      }
    }
  ]
}"#;

/// Witness-decided: `effective_commit_depth` decisive with the winner meeting an
/// app-witness quorum — the case that matches real convergence traffic.
const WITNESS_DECIDED_CONVERGENCE: &str = r#"{
  "events": [
    {
      "kind": {
        "type": "convergence_decision",
        "current_tip_epoch": 30,
        "selected_branch_id": "win",
        "candidates": [
          { "branch_id": "win", "score": { "witness_quorum_met": true } },
          { "branch_id": "lose", "score": { "witness_quorum_met": false } }
        ],
        "rule_trace": [
          { "rule_name": "effective_commit_depth", "decisive": true },
          { "rule_name": "tip_committer", "decisive": false }
        ],
        "selected_tip_epoch": 31,
        "losing_branch_ids": ["lose"]
      }
    }
  ]
}"#;

#[test]
fn committer_decided_convergence_accepts_with_a_reproducible_vector() {
    let conv = recover_convergence(&parse(COMMITTER_DECIDED_CONVERGENCE).expect("parses"))
        .expect("recovers");
    let vector = accept_convergence(&conv, "test-committer-convergence/v1")
        .expect("run-and-compare reproduces the convergence decision");

    assert_eq!(vector.scenario_name, "test-committer-convergence/v1");
    // observer + two committers + two invitees.
    assert_eq!(vector.scenario.clients.len(), 5);
    // A single ConvergenceDecision expectation.
    assert_eq!(vector.expected_outcomes.len(), 1);
}

#[test]
fn witness_decided_convergence_accepts_with_a_reproducible_vector() {
    let conv = recover_convergence(&parse(WITNESS_DECIDED_CONVERGENCE).expect("parses"))
        .expect("recovers");
    let vector = accept_convergence(&conv, "test-witness-convergence/v1")
        .expect("run-and-compare reproduces the witnessed convergence decision");

    assert_eq!(vector.scenario_name, "test-witness-convergence/v1");
    assert_eq!(vector.scenario.clients.len(), 5);
    assert_eq!(vector.expected_outcomes.len(), 1);
}
