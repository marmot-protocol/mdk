//! Recover the convergence decision from a `ConvergenceSelected`-classified
//! export (Phase 4).
//!
//! This is the extraction gate for the observer-side convergence path: it turns
//! the forensic record of a contested branch selection into the minimal facts
//! needed to synthesize a vector, and fail-closes (quarantines) on anything it
//! cannot faithfully reproduce.
//!
//! Two reproducible shapes are recovered: the **committer-decided** case (the
//! selector reached the authenticated-committer tiebreak with no app-witness
//! quorum) and the **witness-decided** case (two equal-depth branches where an
//! app-witness quorum's boost broke the tie) — the case that matches real
//! convergence traffic. Anything else fail-closes rather than synthesize a
//! vector that would silently assert the wrong outcome: a committer tiebreak that
//! itself met a quorum, a witness winner whose branches were *not* at equal depth
//! (so it won on raw commit depth, not the quorum boost), indistinguishable
//! candidate branches, or a priority/digest rule.

use crate::export::{AgentStateExport, ConvergenceCandidate, ConvergenceRule, EventKind};

/// The authenticated-committer tiebreak, reached only when every witness and
/// priority rule tied — the committer-decided shape.
const TIP_COMMITTER_RULE: &str = "tip_committer";
/// The rule an app-witness quorum wins by: the witnessed branch's quorum boost
/// gives it greater effective depth — the witness-decided shape.
const EFFECTIVE_COMMIT_DEPTH_RULE: &str = "effective_commit_depth";

/// Which selector rule decided the convergence, and thus which vector shape
/// reproduces it. Both are winner-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvergenceDecisionKind {
    /// The authenticated-committer tiebreak decided it, with no witness quorum.
    CommitterDecided,
    /// An app-witness quorum decided it: the witnessed branch's greater
    /// effective depth won over the competing branch.
    WitnessDecided,
}

/// The minimal, reproducible facts of a recovered convergence decision.
///
/// Like [`crate::fork::RecoveredFork`], the winning branch identity is never
/// stored: the synthesized vector uses synthetic labels and asserts the
/// winner-agnostic decision (the decisive rule and the witness-quorum status),
/// which the selector reproduces regardless of which label's committer key wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredConvergence {
    /// The selector rule the engine marked decisive.
    pub decisive_rule: String,
    /// The reproducible shape this decision maps to.
    pub kind: ConvergenceDecisionKind,
}

/// Why a convergence export cannot be turned into a vector. Every variant is a
/// fail-closed quarantine: better no vector than one that asserts the wrong
/// convergence outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConvergenceRecoveryError {
    #[error("no contested convergence_decision event")]
    NoConvergenceDecision,
    #[error("expected exactly two contested branches, found {0}")]
    AmbiguousCandidates(usize),
    #[error("the two candidates do not have distinct, non-empty branch ids")]
    IndistinctCandidates,
    #[error("the convergence_decision recorded no decisive selector rule")]
    NoDecisiveRule,
    #[error(
        "unsupported decisive selector rule `{0}` (v1 reproduces `tip_committer` and \
         `effective_commit_depth` only)"
    )]
    UnsupportedDecisiveRule(String),
    #[error("the selected branch is not among the recorded candidates")]
    MissingSelectedBranch,
    #[error(
        "the committer-tiebreak winner met (or may have met) an app-witness quorum, which the \
         no-witness committer vector cannot reproduce"
    )]
    WitnessQuorumUnsupported,
    #[error(
        "the effective-depth winner did not meet (or did not confirm) an app-witness quorum, so it \
         won by commit depth, which the witness-decided vector cannot reproduce"
    )]
    WitnessQuorumUnconfirmed,
    #[error(
        "the effective-depth winner's quorum boost is not provably decisive: the two branches are \
         not recorded at equal valid commit depth, so a deeper branch could have won on raw depth, \
         which the equal-depth witness-decided vector cannot reproduce"
    )]
    WitnessBoostNotDecisive,
}

/// Recover the convergence decision, or return the fail-closed reason it can't
/// be reproduced.
pub fn recover_convergence(
    export: &AgentStateExport,
) -> Result<RecoveredConvergence, ConvergenceRecoveryError> {
    // The settled decision is the last contested pass (mirrors the simulator's
    // `settled_decision`: the last pass that actually evaluated a candidate set).
    let (selected_branch_id, candidates, rule_trace) = export
        .events
        .iter()
        .rev()
        .find_map(|event| match &event.kind {
            EventKind::ConvergenceDecision {
                selected_branch_id,
                candidates,
                rule_trace,
                losing_branch_ids,
            } if !losing_branch_ids.is_empty() || candidates.len() >= 2 => {
                Some((selected_branch_id.as_deref(), candidates, rule_trace))
            }
            _ => None,
        })
        .ok_or(ConvergenceRecoveryError::NoConvergenceDecision)?;

    // v1 synthesizes a two-branch race; more branches need a distinct shape.
    if candidates.len() != 2 {
        return Err(ConvergenceRecoveryError::AmbiguousCandidates(
            candidates.len(),
        ));
    }

    // A faithful two-branch race needs two distinguishable branches. A missing
    // (empty) or duplicated branch id means the export did not actually record two
    // distinct branches — `selected_branch_id` could not pick a unique winner and
    // the loser would be ambiguous — so fail closed rather than reproduce a
    // fictional race.
    if candidates[0].branch_id.is_empty()
        || candidates[1].branch_id.is_empty()
        || candidates[0].branch_id == candidates[1].branch_id
    {
        return Err(ConvergenceRecoveryError::IndistinctCandidates);
    }

    let decisive = decisive_rule(rule_trace).ok_or(ConvergenceRecoveryError::NoDecisiveRule)?;
    let (winner, loser) = winner_and_loser(selected_branch_id, candidates)
        .ok_or(ConvergenceRecoveryError::MissingSelectedBranch)?;
    let quorum_met = winner
        .score
        .as_ref()
        .and_then(|score| score.witness_quorum_met);

    // The decisive rule plus the winner's quorum status selects the reproducible
    // shape; every other combination fail-closes with the reason that fits it:
    // - `tip_committer` is committer-decided only with *no* quorum; a committer
    //   tiebreak that met (or might have met) a quorum can't be reproduced by the
    //   no-witness committer vector.
    // - `effective_commit_depth` is witness-decided only with a *met* quorum whose
    //   boost was decisive. It won by `effective = valid_commit_depth + boost`, so a
    //   winner that is simply deeper wins on raw depth whether or not it has a
    //   quorum; only when both branches sit at equal valid depth did the quorum
    //   boost break the tie — the shape the equal-depth witness vector reproduces.
    //   No met quorum ⇒ `WitnessQuorumUnconfirmed`; a met quorum on unequal (or
    //   unrecorded) depths ⇒ `WitnessBoostNotDecisive`. The rule is supported in
    //   both, so neither is an `UnsupportedDecisiveRule`.
    // - any other rule (priority, digest) has no v1 vector shape.
    let kind = match (decisive, quorum_met) {
        (TIP_COMMITTER_RULE, Some(false)) => ConvergenceDecisionKind::CommitterDecided,
        (EFFECTIVE_COMMIT_DEPTH_RULE, Some(true)) => {
            confirm_witness_boost_decisive(winner, loser)?;
            ConvergenceDecisionKind::WitnessDecided
        }
        (TIP_COMMITTER_RULE, _) => return Err(ConvergenceRecoveryError::WitnessQuorumUnsupported),
        (EFFECTIVE_COMMIT_DEPTH_RULE, _) => {
            return Err(ConvergenceRecoveryError::WitnessQuorumUnconfirmed);
        }
        (other, _) => {
            return Err(ConvergenceRecoveryError::UnsupportedDecisiveRule(
                other.to_owned(),
            ));
        }
    };

    Ok(RecoveredConvergence {
        decisive_rule: decisive.to_owned(),
        kind,
    })
}

/// The `rule_name` of the rule the selector marked decisive, if any.
fn decisive_rule(rule_trace: &[ConvergenceRule]) -> Option<&str> {
    rule_trace
        .iter()
        .find(|rule| rule.decisive == Some(true))
        .map(|rule| rule.rule_name.as_str())
}

/// The (winner, loser) pair for a two-candidate decision, matched by
/// `selected_branch_id`. Returns `None` if the selected id matches no candidate.
/// The caller guarantees exactly two candidates with distinct branch ids, so the
/// loser is the candidate the selected id does not name.
fn winner_and_loser<'a>(
    selected_branch_id: Option<&str>,
    candidates: &'a [ConvergenceCandidate],
) -> Option<(&'a ConvergenceCandidate, &'a ConvergenceCandidate)> {
    let selected = selected_branch_id?;
    let winner = candidates
        .iter()
        .find(|candidate| candidate.branch_id == selected)?;
    let loser = candidates
        .iter()
        .find(|candidate| candidate.branch_id != selected)?;
    Some((winner, loser))
}

/// Confirm the app-witness quorum boost — not raw commit depth — won the
/// `effective_commit_depth` comparison. The selector ranks on `effective =
/// valid_commit_depth + boost`, so the witness-decided vector (which races two
/// equal-depth branches) only reproduces a win where both branches sit at the
/// same valid commit depth and the winner's quorum boost broke the tie. A deeper
/// winner, or an export that did not record both depths, fail-closes.
fn confirm_witness_boost_decisive(
    winner: &ConvergenceCandidate,
    loser: &ConvergenceCandidate,
) -> Result<(), ConvergenceRecoveryError> {
    let depth = |candidate: &ConvergenceCandidate| {
        candidate
            .score
            .as_ref()
            .and_then(|score| score.valid_commit_depth)
    };
    match (depth(winner), depth(loser)) {
        (Some(winner_depth), Some(loser_depth)) if winner_depth == loser_depth => Ok(()),
        _ => Err(ConvergenceRecoveryError::WitnessBoostNotDecisive),
    }
}
