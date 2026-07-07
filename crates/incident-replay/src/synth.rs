//! Synthesize a conformance vector from a recovered fork.
//!
//! The shape is the validated exp-06 blueprint: the two committers raise
//! competing metadata commits at the same epoch and the engine fork-recovers on
//! delivery — no `SetPartition` fault is needed, because the commits are
//! concurrent (neither is delivered before the other is staged). Epochs are
//! normalized to the simulator's range (real `N → N+1` becomes `1 → 2`) by
//! outcome-equivalence, and the committer identities are synthetic labels the
//! caller assigns so the designated winner's branch wins.

use cgka_conformance_simulator::{ScenarioSpec, ScenarioStep, TraceExpectation, VectorFixture};

use crate::fork::{ForkCommitKind, RecoveredFork};

/// The group name the winning branch commits; its survival after convergence is
/// how the accept path confirms the designated winner won.
pub const WINNER_BRANCH: &str = "winner-branch";
/// The group name the losing branch commits.
pub const LOSER_BRANCH: &str = "loser-branch";

fn commit_step(kind: ForkCommitKind, client: &str, name: &str, pending: &str) -> ScenarioStep {
    match kind {
        ForkCommitKind::GroupData => ScenarioStep::UpdateGroupData {
            client: client.to_owned(),
            name: name.to_owned(),
            pending: pending.to_owned(),
        },
    }
}

/// Build the concurrent-fork vector. `winner`/`loser` are the synthetic client
/// labels; the caller (the accept path) tries both orderings so the label whose
/// committer key wins the `CommitOrderingKey` tiebreak is the one on the winning
/// branch.
pub fn synthesize(fork: &RecoveredFork, name: &str, winner: &str, loser: &str) -> VectorFixture {
    let steps = vec![
        ScenarioStep::CreateGroup {
            creator: winner.to_owned(),
            name: "replay".to_owned(),
            invitees: vec![loser.to_owned()],
            required_features: Vec::new(),
            initial_admins: None,
            pending: "create".to_owned(),
        },
        ScenarioStep::ConfirmPending {
            client: winner.to_owned(),
            pending: "create".to_owned(),
        },
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: vec![loser.to_owned()],
        },
        ScenarioStep::ClearEvents {
            clients: vec![winner.to_owned(), loser.to_owned()],
        },
        // Competing commits from the same epoch — the fork.
        commit_step(fork.commit, winner, WINNER_BRANCH, "w"),
        commit_step(fork.commit, loser, LOSER_BRANCH, "l"),
        ScenarioStep::ConfirmPending {
            client: winner.to_owned(),
            pending: "w".to_owned(),
        },
        ScenarioStep::ConfirmPending {
            client: loser.to_owned(),
            pending: "l".to_owned(),
        },
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: vec![winner.to_owned(), loser.to_owned()],
        },
        ScenarioStep::Observe {
            clients: vec![winner.to_owned(), loser.to_owned()],
        },
    ];

    VectorFixture {
        scenario_name: name.to_owned(),
        vector_version: "1".to_owned(),
        conformance_version: env!("CARGO_PKG_VERSION").to_owned(),
        seed: None,
        scenario: ScenarioSpec {
            name: name.to_owned(),
            spec_version: "1".to_owned(),
            clients: vec![winner.to_owned(), loser.to_owned()],
            steps,
        },
        expected_trace: None,
        expected_outcomes: vec![
            // Rule 4: assert the full recovery summary, not just the winner.
            TraceExpectation::RecoverySummary {
                count: 1,
                source_epoch: Some(1),
                recovered_epoch: Some(2),
                winner_differs_from_invalidated: true,
            },
            // Both committers settle on the one surviving branch.
            TraceExpectation::ClientsConverged {
                clients: vec![winner.to_owned(), loser.to_owned()],
                epoch: Some(2),
                member_count: Some(2),
            },
        ],
    }
}
