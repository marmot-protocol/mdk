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
//! quorum) and the **witness-decided** case (an app-witness quorum won by greater
//! effective depth) — the case that matches real convergence traffic. Anything
//! else (a committer tiebreak that itself met a quorum, or a priority/digest/
//! differing-depth rule) fail-closes rather than synthesize a vector that would
//! silently assert the wrong outcome.

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

    let decisive = decisive_rule(rule_trace).ok_or(ConvergenceRecoveryError::NoDecisiveRule)?;
    let winner = winning_candidate(selected_branch_id, candidates)
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
    // - `effective_commit_depth` is witness-decided only with a *met* quorum (which
    //   implies an app-witness score at the quorum threshold); without one the
    //   winner won by raw commit depth (a differing-depth branch), which the
    //   equal-depth witness vector can't reproduce. The rule is supported here — the
    //   quorum status is what is not — so this is a quorum error, not an
    //   `UnsupportedDecisiveRule`.
    // - any other rule (priority, digest, valid-depth) has no v1 vector shape.
    let kind = match (decisive, quorum_met) {
        (TIP_COMMITTER_RULE, Some(false)) => ConvergenceDecisionKind::CommitterDecided,
        (EFFECTIVE_COMMIT_DEPTH_RULE, Some(true)) => ConvergenceDecisionKind::WitnessDecided,
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

/// The candidate the decision selected, matched by `selected_branch_id`.
fn winning_candidate<'a>(
    selected_branch_id: Option<&str>,
    candidates: &'a [ConvergenceCandidate],
) -> Option<&'a ConvergenceCandidate> {
    let selected = selected_branch_id?;
    candidates
        .iter()
        .find(|candidate| candidate.branch_id == selected)
}
