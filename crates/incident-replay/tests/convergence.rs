//! Extraction gate for the convergence path: `recover_convergence` turns a
//! contested `convergence_decision` into the facts needed to synthesize a
//! vector, and fail-closes on anything it cannot faithfully reproduce.

use incident_replay::{
    ConvergenceDecisionKind, ConvergenceRecoveryError, parse, recover_convergence,
};

/// A committer-decided contested convergence: two branches, `tip_committer`
/// decisive, and the winner met no witness quorum.
const COMMITTER_DECIDED: &str = r#"{
  "events": [
    {
      "kind": {
        "type": "convergence_decision",
        "selected_branch_id": "win",
        "candidates": [
          { "branch_id": "win", "score": { "witness_quorum_met": false } },
          { "branch_id": "lose", "score": { "witness_quorum_met": false } }
        ],
        "rule_trace": [
          { "rule_name": "effective_commit_depth", "decisive": false },
          { "rule_name": "witness_quorum_met", "decisive": false },
          { "rule_name": "tip_committer", "decisive": true }
        ],
        "losing_branch_ids": ["lose"]
      }
    }
  ]
}"#;

fn recover(json: &str) -> Result<incident_replay::RecoveredConvergence, ConvergenceRecoveryError> {
    recover_convergence(&parse(json).expect("parses"))
}

#[test]
fn recovers_a_committer_decided_two_branch_convergence() {
    let recovered = recover(COMMITTER_DECIDED).expect("recovers");
    assert_eq!(recovered.decisive_rule, "tip_committer");
    assert_eq!(recovered.kind, ConvergenceDecisionKind::CommitterDecided);
}

/// A witness-decided contested convergence: `effective_commit_depth` decisive
/// (the witnessed branch's quorum boost) and the winner met the quorum.
const WITNESS_DECIDED: &str = r#"{
  "events": [
    {
      "kind": {
        "type": "convergence_decision",
        "selected_branch_id": "win",
        "candidates": [
          { "branch_id": "win", "score": { "witness_quorum_met": true } },
          { "branch_id": "lose", "score": { "witness_quorum_met": false } }
        ],
        "rule_trace": [
          { "rule_name": "effective_commit_depth", "decisive": true },
          { "rule_name": "tip_committer", "decisive": false }
        ],
        "losing_branch_ids": ["lose"]
      }
    }
  ]
}"#;

#[test]
fn recovers_a_witness_decided_two_branch_convergence() {
    let recovered = recover(WITNESS_DECIDED).expect("recovers");
    assert_eq!(recovered.decisive_rule, "effective_commit_depth");
    assert_eq!(recovered.kind, ConvergenceDecisionKind::WitnessDecided);
}

#[test]
fn an_effective_depth_win_without_a_quorum_is_quarantined() {
    // `effective_commit_depth` decided it, but the winner met no quorum — it won
    // by raw commit depth (a differing-depth branch), which the equal-depth
    // witness vector cannot reproduce. The rule *is* supported, so the reason is a
    // quorum error — not `UnsupportedDecisiveRule` (which would be self-contradictory).
    let json = WITNESS_DECIDED.replace(
        r#"{ "branch_id": "win", "score": { "witness_quorum_met": true } }"#,
        r#"{ "branch_id": "win", "score": { "witness_quorum_met": false } }"#,
    );
    assert_eq!(
        recover(&json),
        Err(ConvergenceRecoveryError::WitnessQuorumUnconfirmed)
    );
}

#[test]
fn a_committer_tiebreak_that_met_a_quorum_is_quarantined() {
    // `tip_committer` decided it, yet the winner met a quorum — the no-witness
    // committer vector would assert quorum-false, so this is not reproducible.
    let json = COMMITTER_DECIDED.replace(
        r#"{ "branch_id": "win", "score": { "witness_quorum_met": false } }"#,
        r#"{ "branch_id": "win", "score": { "witness_quorum_met": true } }"#,
    );
    assert_eq!(
        recover(&json),
        Err(ConvergenceRecoveryError::WitnessQuorumUnsupported)
    );
}

#[test]
fn an_unconfirmed_witness_quorum_is_quarantined() {
    // The winner carries no score, so a witness quorum cannot be ruled out.
    let json = COMMITTER_DECIDED.replace(
        r#"{ "branch_id": "win", "score": { "witness_quorum_met": false } }"#,
        r#"{ "branch_id": "win" }"#,
    );
    assert_eq!(
        recover(&json),
        Err(ConvergenceRecoveryError::WitnessQuorumUnsupported)
    );
}

#[test]
fn a_non_committer_decisive_rule_is_quarantined() {
    let json = COMMITTER_DECIDED.replace(
        r#"{ "rule_name": "tip_committer", "decisive": true }"#,
        r#"{ "rule_name": "app_witness_score", "decisive": true }"#,
    );
    assert_eq!(
        recover(&json),
        Err(ConvergenceRecoveryError::UnsupportedDecisiveRule(
            "app_witness_score".to_owned()
        ))
    );
}

#[test]
fn more_than_two_candidates_is_quarantined() {
    let json = COMMITTER_DECIDED.replace(
        r#"{ "branch_id": "lose", "score": { "witness_quorum_met": false } }"#,
        r#"{ "branch_id": "lose", "score": { "witness_quorum_met": false } },
          { "branch_id": "third", "score": { "witness_quorum_met": false } }"#,
    );
    assert_eq!(
        recover(&json),
        Err(ConvergenceRecoveryError::AmbiguousCandidates(3))
    );
}

#[test]
fn a_decision_without_a_decisive_rule_is_quarantined() {
    let json = r#"{
      "events": [
        {
          "kind": {
            "type": "convergence_decision",
            "selected_branch_id": "win",
            "candidates": [{ "branch_id": "win" }, { "branch_id": "lose" }],
            "losing_branch_ids": ["lose"]
          }
        }
      ]
    }"#;
    assert_eq!(recover(json), Err(ConvergenceRecoveryError::NoDecisiveRule));
}

#[test]
fn an_export_without_a_contested_convergence_is_quarantined() {
    let json = r#"{ "events": [ { "kind": { "type": "epoch_confirmed", "epoch": 3 } } ] }"#;
    assert_eq!(
        recover(json),
        Err(ConvergenceRecoveryError::NoConvergenceDecision)
    );
}
