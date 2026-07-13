//! Classification behaviour, exercised through the public parse + classify API
//! against synthetic, non-sensitive fixtures.

use incident_replay::{BehindEngine, BehindMode, QuarantineReason, Verdict, classify, parse};

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
    // Real traffic emits many convergence_decisions that select the sole branch
    // with no loser. Those are not incidents.
    assert_eq!(
        classify(&load("healthy-routine-convergence.json")),
        Verdict::Healthy
    );
}

#[test]
fn contested_convergence_dominates_fork_recovery() {
    // A real incident carries both a fork_resolution and a contested
    // convergence_decision; the convergence selection wins the route.
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
fn partial_audit_coverage_alone_stays_healthy() {
    // The group_context reports 3 members while only 2 engines contributed
    // events. Audit is opt-in, so real groups routinely have more members than
    // exporting engines (a real six-member group exported from only two
    // engines); coverage alone is not an incident, and gating on it would
    // quarantine those groups forever.
    assert_eq!(
        classify(&load("healthy-partial-audit-coverage.json")),
        Verdict::Healthy
    );
}

#[test]
fn an_engine_the_group_advanced_past_quarantines_as_went_dark() {
    // engine-a's audit stream ends at epoch 4 — with one stray event *within*
    // the catch-up grace of the group reaching epoch 6 — so its lag reads as
    // going dark, not as an engine demonstrably running without its commits.
    // This shape is also exactly what a member offline through two quick commits
    // looks like on a single pull; it quarantines fail-closed by design,
    // and cross-pull persistence — not this one verdict — is the operator's
    // discriminator between a genuine split and catch-up still in flight.
    assert_eq!(
        classify(&load("quarantine-went-dark-engine.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::EpochDivergence {
                group_epoch: 6,
                engines: vec![BehindEngine {
                    engine_id: "engine-a".into(),
                    epoch: 4,
                    mode: BehindMode::WentDark,
                }],
            }
        }
    );
}

#[test]
fn an_active_engine_two_epochs_behind_quarantines_as_active_while_behind() {
    // engine-b keeps recording events well past the catch-up grace after
    // engine-a evidenced epoch 6, yet never advances beyond 4: commits are not
    // reaching it while its other traffic flows.
    assert_eq!(
        classify(&load("quarantine-epoch-divergence.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::EpochDivergence {
                group_epoch: 6,
                engines: vec![BehindEngine {
                    engine_id: "engine-b".into(),
                    epoch: 4,
                    mode: BehindMode::ActiveWhileBehind,
                }],
            }
        }
    );
}

#[test]
fn one_epoch_of_lag_is_routine_propagation_not_divergence() {
    assert_eq!(
        classify(&load("healthy-lagging-engine.json")),
        Verdict::Healthy
    );
}

#[test]
fn a_behind_engine_without_timestamps_leaves_the_gate_unarmed() {
    // engine-b sits two epochs back, but its own events carry no wall clock, so
    // there is no moment to time its lag from. The gate refuses to arm on
    // untimed evidence rather than guess when the engine went quiet — legacy and
    // partially-instrumented exports classify as before.
    assert_eq!(
        classify(&load("healthy-untimed-behind-engine.json")),
        Verdict::Healthy
    );
}

#[test]
fn an_untimed_group_advance_leaves_the_gate_unarmed() {
    // engine-b's lag is plainly visible — its high-water epoch trails the group
    // by two — but the only evidence of the group moving past it carries no wall
    // clock, so there is no moment to order the lag against. It is the missing
    // order evidence, not the lag, that keeps the gate unarmed rather than
    // guessing when the group left the engine behind.
    assert_eq!(
        classify(&load("healthy-untimed-group-advance.json")),
        Verdict::Healthy
    );
}

#[test]
fn a_reproducible_incident_outranks_the_liveness_gate() {
    // A fork resolution is a replayable incident; an engine left behind
    // elsewhere in the export must not preempt it (recovery fail-closes
    // downstream if the data it needs turns out to be missing).
    assert_eq!(
        classify(&load("fork-recovery-with-behind-engine.json")),
        Verdict::ForkRecovery
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
