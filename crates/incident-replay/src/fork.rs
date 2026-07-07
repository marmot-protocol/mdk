//! Recover the fork from a `ForkRecovery`-classified export (rules 2 & 3).
//!
//! This is the extraction gate: it turns the forensic record of a same-epoch
//! commit race into the minimal facts needed to synthesize a vector, and
//! fail-closes (quarantines) on anything it cannot faithfully reproduce.

use std::collections::BTreeSet;

use crate::export::{AgentStateExport, EventKind, ForkWinner};

/// The kind of commit both branches raced with. Only group-metadata forks are
/// synthesizable today; membership/admin forks are deferred (they need a
/// distinct scenario shape) and quarantine as unmapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkCommitKind {
    /// A group-metadata commit (topic/name/avatar/retention) → `UpdateGroupData`.
    GroupData,
}

/// The minimal, reproducible facts of a recovered fork.
///
/// The winning committer is recovered as a *gate* (rule 3) but is not stored:
/// the synthesized vector uses synthetic labels and asserts the winner-agnostic
/// `RecoverySummary`, so the identity of the real committer never leaves this
/// step. What downstream needs is the source epoch (normalized to the sim's
/// range) and the commit kind to race.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredFork {
    pub source_epoch: u64,
    pub commit: ForkCommitKind,
}

/// Why a fork-recovery export cannot be turned into a vector. Every variant is a
/// fail-closed quarantine: better no vector than a wrong one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForkRecoveryError {
    #[error("no fork_resolution event")]
    NoForkResolution,
    #[error("fork_resolution has no source_epoch")]
    MissingSourceEpoch,
    #[error("the winning branch's pre-commit snapshot was missing")]
    MissingSnapshot,
    #[error("expected exactly two committers at the contested tip, found {0}")]
    AmbiguousCommitters(usize),
    #[error(
        "could not recover the winner: the invalidated commit has no attributable publisher among the committers"
    )]
    UnrecoverableWinner,
    #[error("unmapped commit kind `{0}` at the contested tip")]
    UnmappedCommitKind(String),
}

fn commit_kind(change_kind: &str) -> Result<ForkCommitKind, ForkRecoveryError> {
    match change_kind {
        "topic_changed" | "group_renamed" | "avatar_changed" | "retention_changed" => {
            Ok(ForkCommitKind::GroupData)
        }
        other => Err(ForkRecoveryError::UnmappedCommitKind(other.to_string())),
    }
}

/// Recover the fork, or return the fail-closed reason it can't be reproduced.
pub fn recover_fork(export: &AgentStateExport) -> Result<RecoveredFork, ForkRecoveryError> {
    let (winner_role, source_epoch, invalidated) = export
        .events
        .iter()
        .find_map(|event| match &event.kind {
            EventKind::ForkResolution {
                winner,
                source_epoch,
                invalidated_msg_id,
            } => Some((*winner, *source_epoch, invalidated_msg_id.as_deref())),
            _ => None,
        })
        .ok_or(ForkRecoveryError::NoForkResolution)?;

    if winner_role == ForkWinner::MissingSnapshot {
        return Err(ForkRecoveryError::MissingSnapshot);
    }
    let source_epoch = source_epoch.ok_or(ForkRecoveryError::MissingSourceEpoch)?;
    let contested_tip = source_epoch + 1; // rule 2: the racers land at source_epoch + 1.

    // The competing commits are the group-state changes at the contested tip.
    let tip: Vec<(&str, &str)> = export
        .events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::GroupStateChanged {
                epoch: Some(epoch),
                change_kind: Some(change_kind),
                actor_member_ref: Some(actor),
            } if *epoch == contested_tip => Some((actor.as_str(), change_kind.as_str())),
            _ => None,
        })
        .collect();

    let committers: BTreeSet<&str> = tip.iter().map(|(actor, _)| *actor).collect();
    if committers.len() != 2 {
        return Err(ForkRecoveryError::AmbiguousCommitters(committers.len()));
    }

    // Every competing commit must map to one synthesizable kind.
    let mut commit = None;
    for (_, change_kind) in &tip {
        commit = Some(commit_kind(change_kind)?);
    }
    let commit = commit.expect("two committers implies at least one tip change");

    // Rule 3 tier-b: the account that published the invalidated commit is the
    // loser; the winner is the other committer. If the invalidated commit can't
    // be attributed to one of the two committers, the winner is unrecoverable.
    let loser = invalidated
        .and_then(|inv| {
            export
                .events
                .iter()
                .find(|e| e.published_msg_id() == Some(inv))
        })
        .and_then(|event| event.account_ref.as_deref());
    if !loser.is_some_and(|loser| committers.contains(loser)) {
        return Err(ForkRecoveryError::UnrecoverableWinner);
    }

    Ok(RecoveredFork {
        source_epoch,
        commit,
    })
}
