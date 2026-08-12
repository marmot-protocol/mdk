//! Recover the fork from a `ForkRecovery`-classified export (rules 2 & 3).
//!
//! This is the extraction gate: it turns the forensic record of a same-epoch
//! commit race into the minimal facts needed to synthesize a vector, and
//! fail-closes (quarantines) on anything it cannot faithfully reproduce.

use std::collections::BTreeSet;

use crate::export::{AgentStateExport, EventKind, ForkWinner};

/// The kind of commit both branches raced with. Two shapes are synthesizable:
/// group-metadata forks (`UpdateGroupData`) and membership/admin forks (a
/// competing-invite race). The fork-recovery mechanism is content-independent —
/// what matters is that two committers raced a commit at the same epoch and one
/// branch was invalidated — so a membership-changing commit race reproduces the
/// same `RecoverySummary` (outcome-equivalence, as the convergence path does).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkCommitKind {
    /// A group-metadata commit (topic/name/avatar/retention) → `UpdateGroupData`.
    GroupData,
    /// A membership/admin commit (member add/remove, admin grant/revoke) →
    /// reproduced by a competing-invite race, where `member_count == 3` after
    /// recovery is the winner-agnostic proof that exactly one branch survived.
    Membership,
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
    #[error("fork_resolution source_epoch cannot advance to a contested tip")]
    SourceEpochOverflow,
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
    #[error(
        "the contested tip mixes a group-metadata commit with a membership commit, which has no \
         single vector shape"
    )]
    MixedCommitKinds,
}

fn commit_kind(change_kind: &str) -> Result<ForkCommitKind, ForkRecoveryError> {
    match change_kind {
        "topic_changed" | "group_renamed" | "avatar_changed" | "retention_changed" => {
            Ok(ForkCommitKind::GroupData)
        }
        "member_added" | "member_removed" | "admin_added" | "admin_removed" => {
            Ok(ForkCommitKind::Membership)
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
    let contested_tip = source_epoch
        .checked_add(1)
        .ok_or(ForkRecoveryError::SourceEpochOverflow)?; // rule 2: racers land at source + 1.

    // The competing commits are the group-state changes at the contested tip.
    let tip: Vec<(&str, &str, Option<&str>)> = export
        .events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::GroupStateChanged {
                epoch: Some(epoch),
                change_kind: Some(change_kind),
                actor_member_ref: Some(actor),
                origin_commit_id,
            } if *epoch == contested_tip => Some((
                actor.as_str(),
                change_kind.as_str(),
                origin_commit_id.as_deref(),
            )),
            _ => None,
        })
        .collect();

    let committers: BTreeSet<&str> = tip.iter().map(|(actor, _, _)| *actor).collect();
    if committers.len() != 2 {
        return Err(ForkRecoveryError::AmbiguousCommitters(committers.len()));
    }

    // Every competing commit must map to one synthesizable kind. A single fork
    // is one shape: a tip that mixes a group-metadata commit with a membership
    // commit has no single vector to race, so it fail-closes. (The membership
    // variants all collapse to one `Membership` kind, so the real add-vs-promote
    // race — `member_added` on one branch, `admin_added` on the other — is not
    // mixed.)
    let mut kinds: Vec<ForkCommitKind> = Vec::new();
    for (_, change_kind, _) in &tip {
        let kind = commit_kind(change_kind)?;
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    let commit = match kinds.as_slice() {
        [only] => *only,
        [] => unreachable!("two committers implies at least one tip change"),
        _ => return Err(ForkRecoveryError::MixedCommitKinds),
    };

    // Rule 3 tier-b winner attribution is only needed for the group-data fork,
    // whose accept path label-searches for the ordering that makes the designated
    // winner's branch survive. The membership fork is winner-agnostic
    // (`member_count == 3` is the survival proof, so accept is a single run with
    // no label search).
    if commit == ForkCommitKind::GroupData {
        // The group-state row originated by the invalidated commit identifies
        // the loser in the same member-ref namespace as the committer set.
        let loser = invalidated.and_then(|invalidated| {
            tip.iter().find_map(|(actor, _, origin_commit_id)| {
                (*origin_commit_id == Some(invalidated)).then_some(*actor)
            })
        });
        if !loser.is_some_and(|loser| committers.contains(loser)) {
            return Err(ForkRecoveryError::UnrecoverableWinner);
        }
    }

    Ok(RecoveredFork {
        source_epoch,
        commit,
    })
}
