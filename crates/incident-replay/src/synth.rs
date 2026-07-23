//! Synthesize a conformance vector from a recovered fork.
//!
//! The shape follows the blueprint validated by replaying a real two-committer
//! fork incident: the two committers raise competing metadata commits at the
//! same epoch and the engine fork-recovers on delivery — no `SetPartition`
//! fault is needed, because the commits are concurrent (neither is delivered
//! before the other is staged). Epochs are
//! normalized to the simulator's range (real `N → N+1` becomes `1 → 2`) by
//! outcome-equivalence, and the committer identities are synthetic labels the
//! caller assigns so the designated winner's branch wins.

use cgka_conformance_simulator::{ScenarioSpec, ScenarioStep, TraceExpectation, VectorFixture};

use crate::convergence::{ConvergenceDecisionKind, RecoveredConvergence};
use crate::fork::{ForkCommitKind, RecoveredFork};

/// The group name the winning branch commits; its survival after convergence is
/// how the accept path confirms the designated winner won.
pub const WINNER_BRANCH: &str = "winner-branch";
/// The group name the losing branch commits.
pub const LOSER_BRANCH: &str = "loser-branch";

/// The two new members each competing branch invites in a membership fork. An
/// invite race is the proven reproduction (the `convergence-chaos/v1`
/// invite-fork arm): after recovery, `member_count == 3` is the winner-agnostic
/// proof that exactly one branch's invite survived (both would be 4, neither 2).
const FORK_INVITEE_A: &str = "david";
const FORK_INVITEE_B: &str = "eve";

/// Build the concurrent-fork vector for a recovered fork, dispatching on the
/// commit kind: a group-metadata fork races two `UpdateGroupData` commits and is
/// winner-branch-checked by the accept path's label search; a membership fork
/// races two competing invites and is winner-agnostic (see [`ForkCommitKind`]).
pub fn synthesize(fork: &RecoveredFork, name: &str, winner: &str, loser: &str) -> VectorFixture {
    match fork.commit {
        ForkCommitKind::GroupData => synthesize_group_data_fork(name, winner, loser),
        ForkCommitKind::Membership => synthesize_membership_fork(name, winner, loser),
    }
}

/// Build the group-metadata concurrent-fork vector. `winner`/`loser` are the
/// synthetic client labels; the caller (the accept path) tries both orderings so
/// the label whose committer key wins the `CommitOrderingKey` tiebreak is the one
/// on the winning branch.
fn synthesize_group_data_fork(name: &str, winner: &str, loser: &str) -> VectorFixture {
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
        // Competing group-data commits from the same epoch — the fork.
        ScenarioStep::UpdateGroupData {
            client: winner.to_owned(),
            name: WINNER_BRANCH.to_owned(),
            pending: "w".to_owned(),
        },
        ScenarioStep::UpdateGroupData {
            client: loser.to_owned(),
            name: LOSER_BRANCH.to_owned(),
            pending: "l".to_owned(),
        },
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
            TraceExpectation::PendingResolution {
                step_index: 1,
                client: winner.to_owned(),
                pending: "create".to_owned(),
                resolution: "confirmed".to_owned(),
            },
            TraceExpectation::PendingResolution {
                step_index: 7,
                client: winner.to_owned(),
                pending: "w".to_owned(),
                resolution: "confirmed".to_owned(),
            },
            TraceExpectation::PendingResolution {
                step_index: 8,
                client: loser.to_owned(),
                pending: "l".to_owned(),
                resolution: "confirmed".to_owned(),
            },
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

/// Build the membership concurrent-fork vector: two committers race competing
/// invites from the same epoch and the engine fork-recovers on delivery. The two
/// invitees are held out of the race with a partition so only the committers'
/// competing commits reach each other (the proven `convergence-chaos/v1`
/// invite-fork shape). The assertion is winner-agnostic: `member_count == 3`
/// after recovery proves exactly one branch's invite survived, so unlike the
/// group-data fork no branch-name survival check (and no label search) is needed.
fn synthesize_membership_fork(name: &str, winner: &str, loser: &str) -> VectorFixture {
    let clients = vec![
        winner.to_owned(),
        loser.to_owned(),
        FORK_INVITEE_A.to_owned(),
        FORK_INVITEE_B.to_owned(),
    ];
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
            clients: clients.clone(),
        },
        // Hold the invitees out so only the two committers' competing commits
        // race each other. (The runner auto-promotes `loser` to admin when it
        // sends the competing invite.)
        ScenarioStep::SetPartition {
            allow: vec![winner.to_owned(), loser.to_owned()],
        },
        // Competing membership commits from the same epoch — the fork.
        ScenarioStep::InviteMembers {
            inviter: winner.to_owned(),
            invitees: vec![FORK_INVITEE_A.to_owned()],
            pending: "w".to_owned(),
        },
        ScenarioStep::InviteMembers {
            inviter: loser.to_owned(),
            invitees: vec![FORK_INVITEE_B.to_owned()],
            pending: "l".to_owned(),
        },
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
            clients,
            steps,
        },
        expected_trace: None,
        expected_outcomes: vec![
            TraceExpectation::PendingResolution {
                step_index: 1,
                client: winner.to_owned(),
                pending: "create".to_owned(),
                resolution: "confirmed".to_owned(),
            },
            TraceExpectation::PendingResolution {
                step_index: 8,
                client: winner.to_owned(),
                pending: "w".to_owned(),
                resolution: "confirmed".to_owned(),
            },
            TraceExpectation::PendingResolution {
                step_index: 9,
                client: loser.to_owned(),
                pending: "l".to_owned(),
                resolution: "confirmed".to_owned(),
            },
            // Rule 4: assert the full recovery summary, not just the winner.
            TraceExpectation::RecoverySummary {
                count: 1,
                source_epoch: Some(1),
                recovered_epoch: Some(2),
                winner_differs_from_invalidated: true,
            },
            // member_count 3 == exactly one branch's invite survived (both would
            // be 4, neither 2): the winner-agnostic survival proof.
            TraceExpectation::ClientsConverged {
                clients: vec![winner.to_owned(), loser.to_owned()],
                epoch: Some(2),
                member_count: Some(3),
            },
        ],
    }
}

/// The observer that runs the convergence selector over the competing branches.
const OBSERVER: &str = "carol";
/// The two admins that raise competing commits from the same epoch.
const COMMITTER_A: &str = "alice";
const COMMITTER_B: &str = "bob";
/// The new members each competing branch adds (an invite race is the proven way
/// to create two competing stored branches the observer must converge).
const INVITEE_A: &str = "david";
const INVITEE_B: &str = "eve";

/// Build the convergence vector for a recovered decision.
///
/// Both shapes start from the validated `convergence-committer-selected/v1`
/// blueprint: two admins raise competing invite commits from the same epoch and a
/// passive observer runs the convergence selector over both stored branches. The
/// selector's outcome is content-independent for the reproduced rules, so the
/// invite race reproduces the recorded convergence regardless of what the real
/// branches committed (outcome-equivalence). The assertion is winner-agnostic —
/// the recorded decisive rule and witness-quorum status, not which branch won —
/// so no label search is needed.
pub fn synthesize_convergence(conv: &RecoveredConvergence, name: &str) -> VectorFixture {
    match conv.kind {
        ConvergenceDecisionKind::CommitterDecided => synthesize_committer_decided(conv, name),
        ConvergenceDecisionKind::WitnessDecided => synthesize_witness_decided(conv, name),
    }
}

/// The setup both shapes share: a two-admin group with a passive observer, then
/// two competing same-epoch invite commits (confirmed, not yet delivered).
fn convergence_preamble() -> Vec<ScenarioStep> {
    vec![
        ScenarioStep::CreateGroup {
            creator: COMMITTER_A.to_owned(),
            name: "replay".to_owned(),
            invitees: vec![COMMITTER_B.to_owned(), OBSERVER.to_owned()],
            required_features: Vec::new(),
            // Both committers must be admins to raise competing commits.
            initial_admins: Some(vec![COMMITTER_B.to_owned()]),
            pending: "create".to_owned(),
        },
        ScenarioStep::ConfirmPending {
            client: COMMITTER_A.to_owned(),
            pending: "create".to_owned(),
        },
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: vec![COMMITTER_B.to_owned(), OBSERVER.to_owned()],
        },
        ScenarioStep::ClearEvents {
            clients: vec![
                COMMITTER_A.to_owned(),
                COMMITTER_B.to_owned(),
                OBSERVER.to_owned(),
            ],
        },
        // Competing commits from the same epoch — the contested branches.
        ScenarioStep::InviteMembers {
            inviter: COMMITTER_A.to_owned(),
            invitees: vec![INVITEE_A.to_owned()],
            pending: "invite-a".to_owned(),
        },
        ScenarioStep::InviteMembers {
            inviter: COMMITTER_B.to_owned(),
            invitees: vec![INVITEE_B.to_owned()],
            pending: "invite-b".to_owned(),
        },
        ScenarioStep::ConfirmPending {
            client: COMMITTER_A.to_owned(),
            pending: "invite-a".to_owned(),
        },
        ScenarioStep::ConfirmPending {
            client: COMMITTER_B.to_owned(),
            pending: "invite-b".to_owned(),
        },
    ]
}

/// Wrap `steps` and the winner-agnostic convergence assertion into a fixture.
fn convergence_fixture(
    name: &str,
    steps: Vec<ScenarioStep>,
    expected: TraceExpectation,
) -> VectorFixture {
    VectorFixture {
        scenario_name: name.to_owned(),
        vector_version: "1".to_owned(),
        conformance_version: env!("CARGO_PKG_VERSION").to_owned(),
        seed: None,
        scenario: ScenarioSpec {
            name: name.to_owned(),
            spec_version: "1".to_owned(),
            clients: [COMMITTER_A, COMMITTER_B, OBSERVER, INVITEE_A, INVITEE_B]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            steps,
        },
        expected_trace: None,
        expected_outcomes: vec![
            TraceExpectation::PendingResolution {
                step_index: 1,
                client: COMMITTER_A.to_owned(),
                pending: "create".to_owned(),
                resolution: "confirmed".to_owned(),
            },
            TraceExpectation::PendingResolution {
                step_index: 7,
                client: COMMITTER_A.to_owned(),
                pending: "invite-a".to_owned(),
                resolution: "confirmed".to_owned(),
            },
            TraceExpectation::PendingResolution {
                step_index: 8,
                client: COMMITTER_B.to_owned(),
                pending: "invite-b".to_owned(),
                resolution: "confirmed".to_owned(),
            },
            expected,
        ],
    }
}

/// Committer-decided: both branches reach the observer at once and the
/// `tip_committer` tiebreak picks the winner (no witnesses).
fn synthesize_committer_decided(conv: &RecoveredConvergence, name: &str) -> VectorFixture {
    let mut steps = convergence_preamble();
    steps.extend([
        ScenarioStep::DeliverAll,
        // Convergence runs on Tick, not DeliverAll.
        ScenarioStep::Tick {
            clients: vec![OBSERVER.to_owned()],
        },
        ScenarioStep::Observe {
            clients: vec![OBSERVER.to_owned()],
        },
    ]);
    convergence_fixture(
        name,
        steps,
        TraceExpectation::ConvergenceDecision {
            client: Some(OBSERVER.to_owned()),
            selected_branch_id: None,
            selected_tip_epoch: Some(2),
            decisive_rule: Some(conv.decisive_rule.clone()),
            witness_quorum_met: Some(false),
            min_app_witness_score: None,
        },
    )
}

/// Witness-decided: the observer delivers two distinct senders' app messages on
/// one branch *before* the competing commit arrives, so on the reorg the
/// app-witness quorum overrides the committer tiebreak. Holding the competing
/// commit (`DelayQueued`/`ReleaseDelayed`) is what stages the "delivered, then
/// contested" ordering; the second observer `Tick` after release is the reorg.
fn synthesize_witness_decided(conv: &RecoveredConvergence, name: &str) -> VectorFixture {
    let mut steps = convergence_preamble();
    steps.extend([
        // Hold the competing branch-B commit (queue index 3: welcome-a, commit-a,
        // welcome-b, commit-b) so only branch A reaches the observer first.
        ScenarioStep::DelayQueued {
            index: 3,
            delayed: "held-b".to_owned(),
        },
        ScenarioStep::DeliverAll,
        // The invitee joins branch A so it can be the second witness sender.
        ScenarioStep::Tick {
            clients: vec![INVITEE_A.to_owned()],
        },
        ScenarioStep::SendAppMessage {
            sender: COMMITTER_A.to_owned(),
            payload: "witness-a-1".to_owned(),
        },
        ScenarioStep::SendAppMessage {
            sender: INVITEE_A.to_owned(),
            payload: "witness-a-2".to_owned(),
        },
        ScenarioStep::DeliverAll,
        // The observer delivers (applies) both branch-A app messages.
        ScenarioStep::Tick {
            clients: vec![OBSERVER.to_owned()],
        },
        // The competing branch-B commit now arrives, forcing a reorg.
        ScenarioStep::ReleaseDelayed {
            delayed: "held-b".to_owned(),
        },
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: vec![OBSERVER.to_owned()],
        },
        ScenarioStep::Observe {
            clients: vec![OBSERVER.to_owned()],
        },
    ]);
    convergence_fixture(
        name,
        steps,
        TraceExpectation::ConvergenceDecision {
            client: Some(OBSERVER.to_owned()),
            selected_branch_id: None,
            selected_tip_epoch: Some(2),
            decisive_rule: Some(conv.decisive_rule.clone()),
            witness_quorum_met: Some(true),
            min_app_witness_score: Some(2),
        },
    )
}
