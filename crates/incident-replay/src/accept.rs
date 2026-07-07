//! Run-and-compare: turn a recovered fork into an accepted vector, or quarantine.

use cgka_conformance_simulator::{VectorFixture, run_scenario_spec};

use crate::fork::RecoveredFork;
use crate::synth::{WINNER_BRANCH, synthesize};

/// Why an accept attempt produced no vector (fail-closed).
#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    #[error("the simulator could not be driven: {0}")]
    Run(String),
    #[error("run-and-compare did not reproduce the recorded winner in {tries} label orderings")]
    NotReproduced { tries: usize },
}

/// The winner is decided by committer bytes, so exactly one of these two
/// orderings puts the designated winner's key below the loser's.
const LABEL_ORDERINGS: [(&str, &str); 2] = [("alice", "bob"), ("bob", "alice")];

/// Synthesize and verify a vector for a recovered fork.
///
/// Bounded label search: for each ordering, run the synthesized scenario and
/// accept iff the full `RecoverySummary` (and convergence) expectations hold
/// **and** the designated winner's branch is the one that survived. The summary
/// is the gate; branch survival only selects the correct ordering.
pub fn accept(fork: &RecoveredFork, name: &str) -> Result<VectorFixture, AcceptError> {
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
