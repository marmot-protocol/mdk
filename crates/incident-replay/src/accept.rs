//! Run-and-compare: turn a recovered fork into an accepted vector, or quarantine.

use cgka_conformance_simulator::{VectorFixture, run_scenario_spec};

use crate::convergence::RecoveredConvergence;
use crate::fork::{ForkCommitKind, RecoveredFork};
use crate::synth::{WINNER_BRANCH, synthesize, synthesize_convergence};

/// Why an accept attempt produced no vector (fail-closed).
#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    #[error("the simulator could not be driven: {0}")]
    Run(String),
    #[error("run-and-compare did not reproduce the recorded outcome after {tries} attempt(s)")]
    NotReproduced { tries: usize },
}

/// The winner is decided by committer bytes, so exactly one of these two
/// orderings puts the designated winner's key below the loser's.
const LABEL_ORDERINGS: [(&str, &str); 2] = [("alice", "bob"), ("bob", "alice")];

/// Synthesize and verify a vector for a recovered fork, dispatching on the
/// commit kind (the two shapes verify differently).
pub fn accept(fork: &RecoveredFork, name: &str) -> Result<VectorFixture, AcceptError> {
    match fork.commit {
        ForkCommitKind::GroupData => accept_group_data_fork(fork, name),
        ForkCommitKind::Membership => accept_membership_fork(fork, name),
    }
}

/// Group-data fork: bounded label search. For each ordering, run the synthesized
/// scenario and accept iff the full `RecoverySummary` expectations hold **and**
/// the designated winner's branch (its group name) is the one that survived. The
/// summary is the gate; branch survival only selects the correct ordering.
fn accept_group_data_fork(fork: &RecoveredFork, name: &str) -> Result<VectorFixture, AcceptError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|err| AcceptError::Run(err.to_string()))?;

    for (winner, loser) in LABEL_ORDERINGS {
        let vector = synthesize(fork, name, winner, loser);
        let trace = runtime
            .block_on(run_scenario_spec(&vector.scenario))
            .map_err(|err| AcceptError::Run(err.to_string()))?;

        let summary_matches = vector.compare_observed_trace(&trace).is_empty();
        let winner_branch_survived = trace
            .observations
            .iter()
            .any(|observation| observation.group_name == WINNER_BRANCH);
        if summary_matches && winner_branch_survived {
            return Ok(vector);
        }
    }
    Err(AcceptError::NotReproduced {
        tries: LABEL_ORDERINGS.len(),
    })
}

/// Membership fork: a single run-and-compare. The recovery is winner-agnostic —
/// `member_count == 3` after recovery proves exactly one branch's invite
/// survived — so there is no group-name to search label orderings for (unlike
/// the group-data fork). Accept iff the synthesized scenario reproduces the
/// recovery summary and the surviving-member count.
fn accept_membership_fork(fork: &RecoveredFork, name: &str) -> Result<VectorFixture, AcceptError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|err| AcceptError::Run(err.to_string()))?;

    let (winner, loser) = LABEL_ORDERINGS[0];
    let vector = synthesize(fork, name, winner, loser);
    let trace = runtime
        .block_on(run_scenario_spec(&vector.scenario))
        .map_err(|err| AcceptError::Run(err.to_string()))?;

    if vector.compare_observed_trace(&trace).is_empty() {
        Ok(vector)
    } else {
        Err(AcceptError::NotReproduced { tries: 1 })
    }
}

/// Synthesize and verify a vector for a recovered convergence decision.
///
/// A single run-and-compare: the committer-decided decision is winner-agnostic
/// (`tip_committer` is decisive whichever committer key wins), so unlike the fork
/// path there is no label search. Accept iff the synthesized scenario reproduces
/// the recorded convergence decision (decisive rule + no witness quorum).
pub fn accept_convergence(
    conv: &RecoveredConvergence,
    name: &str,
) -> Result<VectorFixture, AcceptError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|err| AcceptError::Run(err.to_string()))?;

    let vector = synthesize_convergence(conv, name);
    let trace = runtime
        .block_on(run_scenario_spec(&vector.scenario))
        .map_err(|err| AcceptError::Run(err.to_string()))?;

    if vector.compare_observed_trace(&trace).is_empty() {
        Ok(vector)
    } else {
        Err(AcceptError::NotReproduced { tries: 1 })
    }
}
