//! Classification behaviour, exercised through the public parse + classify API
//! against synthetic, non-sensitive fixtures.

use incident_replay::{QuarantineReason, Verdict, classify, parse};

fn load(name: &str) -> incident_replay::AgentStateExport {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let json =
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read fixture {path}: {err}"));
    parse(&json).unwrap_or_else(|err| panic!("parse fixture {name}: {err}"))
}

#[test]
fn healthy_export_classifies_as_healthy() {
    assert_eq!(classify(&load("healthy.json")), Verdict::Healthy);
}

#[test]
fn fork_resolution_without_contested_convergence_is_fork_recovery() {
    assert_eq!(classify(&load("fork-recovery.json")), Verdict::ForkRecovery);
}

#[test]
fn routine_single_branch_convergence_is_healthy() {
    // exp-07 shape: real traffic emits many convergence_decisions that select the
    // sole branch with no loser. Those are not incidents.
    assert_eq!(
        classify(&load("healthy-routine-convergence.json")),
        Verdict::Healthy
    );
}

#[test]
fn contested_convergence_dominates_fork_recovery() {
    // exp-03 shape: a real incident carries both a fork_resolution and a
    // contested convergence_decision; the convergence selection wins the route.
    assert_eq!(
        classify(&load("convergence-selected.json")),
        Verdict::ConvergenceSelected
    );
}

#[test]
fn fork_resolution_with_missing_snapshot_quarantines() {
    // The winning branch's pre-commit snapshot was unavailable, so the fork
    // cannot be replayed — quarantine rather than emit a wrong vector.
    assert_eq!(
        classify(&load("quarantine-missing-snapshot.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::MissingSnapshot
        }
    );
}

#[test]
fn contested_convergence_outranks_a_missing_snapshot_fork() {
    // A reproducible convergence selection routes to Phase 4 even alongside an
    // unrecoverable fork: the missing-snapshot quarantine only applies when the
    // fork-recovery path is the one being taken.
    assert_eq!(
        classify(&load("convergence-with-missing-snapshot-fork.json")),
        Verdict::ConvergenceSelected
    );
}

#[test]
fn truncated_projection_quarantines_even_when_contested() {
    // A capped derived_projections section means the export is incomplete;
    // reproduction could miss witnesses, so truncation quarantines regardless of
    // any incident signal in the (uncapped) event log.
    assert_eq!(
        classify(&load("quarantine-truncated.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::TruncatedProjections
        }
    );
}
