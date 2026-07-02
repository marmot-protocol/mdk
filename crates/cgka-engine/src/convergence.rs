//! Candidate-state graph rules for distributed convergence.
//!
//! This module does not drive OpenMLS. It captures the deterministic branch
//! selection policy that the engine canonicalizer uses after materializing
//! competing MLS states.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use cgka_traits::engine::CommitOrderingPriority;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergencePolicy {
    pub max_rewind_commits: u64,
    pub witness_quorum_senders_per_epoch: usize,
    pub witness_quorum_epochs: usize,
    pub max_witness_override_depth: u64,
}

impl Default for ConvergencePolicy {
    fn default() -> Self {
        Self {
            max_rewind_commits: 5,
            witness_quorum_senders_per_epoch: 2,
            witness_quorum_epochs: 1,
            max_witness_override_depth: 1,
        }
    }
}

/// Validation errors for a [`ConvergencePolicy`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConvergencePolicyError {
    /// `max_witness_override_depth` exceeds `max_rewind_commits`. The witness-quorum
    /// boost is capped by group policy; if it could exceed the rollback horizon, app
    /// payload traffic could push a branch past an arbitrarily longer valid commit
    /// branch — the invariant at `spec/protocol-core/convergence.md` lines 119-120.
    #[error(
        "max_witness_override_depth ({max_witness_override_depth}) must not exceed \
         max_rewind_commits ({max_rewind_commits})"
    )]
    WitnessOverrideExceedsRewind {
        max_witness_override_depth: u64,
        max_rewind_commits: u64,
    },
}

impl ConvergencePolicy {
    /// Enforce the witness-override invariant as a hard policy bound: a witness-quorum
    /// boost must never be able to push a branch past the rollback horizon. This is
    /// checked when a stored policy is decoded and when a group policy is set, so an
    /// out-of-bound policy can never drive branch selection.
    pub fn validate(&self) -> Result<(), ConvergencePolicyError> {
        if self.max_witness_override_depth > self.max_rewind_commits {
            return Err(ConvergencePolicyError::WitnessOverrideExceedsRewind {
                max_witness_override_depth: self.max_witness_override_depth,
                max_rewind_commits: self.max_rewind_commits,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchCandidate {
    pub id: String,
    pub fork_epoch: u64,
    pub tip_epoch: u64,
    pub tip_priority: CommitOrderingPriority,
    pub tip_committer: Vec<u8>,
    pub tip_digest: [u8; 32],
    pub app_witnesses: Vec<AppWitness>,
}

impl BranchCandidate {
    pub fn score(&self, policy: &ConvergencePolicy) -> BranchScore {
        BranchScore {
            valid_commit_depth: self.tip_epoch.saturating_sub(self.fork_epoch),
            effective_commit_depth: self
                .tip_epoch
                .saturating_sub(self.fork_epoch)
                .saturating_add(witness_depth_boost(self, policy)),
            witness_quorum_met: witness_quorum_met(&self.app_witnesses, policy),
            app_witness_score: app_witness_score(&self.app_witnesses, policy),
            tip_priority: self.tip_priority,
            tip_committer: self.tip_committer.clone(),
            tip_digest: self.tip_digest,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppWitness {
    pub epoch: u64,
    pub sender: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchScore {
    pub valid_commit_depth: u64,
    pub effective_commit_depth: u64,
    pub witness_quorum_met: bool,
    pub app_witness_score: usize,
    pub tip_priority: CommitOrderingPriority,
    pub tip_committer: Vec<u8>,
    pub tip_digest: [u8; 32],
}

pub fn is_branch_eligible(
    current_tip_epoch: u64,
    branch: &BranchCandidate,
    policy: &ConvergencePolicy,
) -> bool {
    current_tip_epoch.saturating_sub(branch.fork_epoch) <= policy.max_rewind_commits
}

pub fn select_canonical_branch<'a>(
    current_tip_epoch: u64,
    candidates: &'a [BranchCandidate],
    policy: &ConvergencePolicy,
) -> Option<&'a BranchCandidate> {
    candidates
        .iter()
        .filter(|candidate| is_branch_eligible(current_tip_epoch, candidate, policy))
        .max_by(|a, b| compare_scores(&a.score(policy), &b.score(policy)))
}

fn compare_scores(a: &BranchScore, b: &BranchScore) -> Ordering {
    a.effective_commit_depth
        .cmp(&b.effective_commit_depth)
        .then_with(|| a.witness_quorum_met.cmp(&b.witness_quorum_met))
        .then_with(|| a.valid_commit_depth.cmp(&b.valid_commit_depth))
        .then_with(|| a.app_witness_score.cmp(&b.app_witness_score))
        .then_with(|| b.tip_priority.cmp(&a.tip_priority))
        .then_with(|| b.tip_committer.cmp(&a.tip_committer))
        .then_with(|| b.tip_digest.cmp(&a.tip_digest))
}

/// Stable string for a tip's commit-ordering priority, for audit traces.
pub fn tip_priority_str(priority: CommitOrderingPriority) -> &'static str {
    match priority {
        CommitOrderingPriority::Ordinary => "ordinary",
        CommitOrderingPriority::Privileged => "privileged",
    }
}

/// Per-candidate evaluation captured during selection, for forensic audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateEvaluation {
    pub branch_id: String,
    pub fork_epoch: u64,
    pub tip_epoch: u64,
    pub tip_priority: CommitOrderingPriority,
    pub tip_committer: Vec<u8>,
    pub tip_digest: [u8; 32],
    pub app_witnesses: Vec<AppWitness>,
    pub eligible: bool,
    pub rejection_reasons: Vec<String>,
    pub score: BranchScore,
}

/// One selector-rule comparison between the winner and the runner-up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleEvaluation {
    pub rule_name: &'static str,
    pub winner_branch_id: String,
    pub other_branch_id: String,
    pub winner_value: String,
    pub other_value: String,
    pub decisive: bool,
}

/// The full audit trace of a branch-selection decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchSelectionTrace {
    pub selected_branch_id: Option<String>,
    pub candidates: Vec<CandidateEvaluation>,
    pub rule_trace: Vec<RuleEvaluation>,
    pub losing_branch_ids: Vec<String>,
}

/// Select the canonical branch and capture an audit trace: per-candidate scores
/// and eligibility, the ordered rule-by-rule comparison between the winner and
/// the runner-up (marking the decisive rule), and the losing branches. The
/// selection itself is identical to [`select_canonical_branch`].
pub fn select_canonical_branch_traced(
    current_tip_epoch: u64,
    candidates: &[BranchCandidate],
    policy: &ConvergencePolicy,
) -> BranchSelectionTrace {
    // Order the trace by branch id so it is a pure function of the candidate
    // *set*: distributed convergence must be input-order independent, and the
    // trace is part of `CanonicalizationResult` equality. Branch ids are unique.
    let mut ordered: Vec<&BranchCandidate> = candidates.iter().collect();
    ordered.sort_by(|a, b| a.id.cmp(&b.id));

    let evaluations: Vec<CandidateEvaluation> = ordered
        .iter()
        .map(|candidate| {
            let eligible = is_branch_eligible(current_tip_epoch, candidate, policy);
            let mut rejection_reasons = Vec::new();
            if !eligible {
                rejection_reasons.push("beyond_rewind_horizon".to_string());
            }
            // Canonicalize witness order by (epoch, sender) so the trace stays a
            // pure function of the candidate set, independent of message arrival
            // order. The score already aggregates witnesses order-independently.
            let mut app_witnesses = candidate.app_witnesses.clone();
            app_witnesses
                .sort_by(|a, b| a.epoch.cmp(&b.epoch).then_with(|| a.sender.cmp(&b.sender)));
            CandidateEvaluation {
                branch_id: candidate.id.clone(),
                fork_epoch: candidate.fork_epoch,
                tip_epoch: candidate.tip_epoch,
                tip_priority: candidate.tip_priority,
                tip_committer: candidate.tip_committer.clone(),
                tip_digest: candidate.tip_digest,
                app_witnesses,
                eligible,
                rejection_reasons,
                score: candidate.score(policy),
            }
        })
        .collect();

    let selected = select_canonical_branch(current_tip_epoch, candidates, policy);
    let selected_branch_id = selected.map(|branch| branch.id.clone());

    let mut rule_trace = Vec::new();
    if let Some(winner) = selected {
        // Runner-up = the best eligible candidate other than the winner, drawn
        // from the branch-id-ordered set so it is deterministic. The decisive
        // rule is the first one where the winner's score differs.
        let runner_up = ordered
            .iter()
            .copied()
            .filter(|candidate| is_branch_eligible(current_tip_epoch, candidate, policy))
            .filter(|candidate| candidate.id != winner.id)
            .max_by(|a, b| compare_scores(&a.score(policy), &b.score(policy)));
        if let Some(other) = runner_up {
            rule_trace = build_rule_trace(
                &winner.score(policy),
                &other.score(policy),
                &winner.id,
                &other.id,
            );
        }
    }

    let losing_branch_ids = evaluations
        .iter()
        .filter(|evaluation| Some(&evaluation.branch_id) != selected_branch_id.as_ref())
        .map(|evaluation| evaluation.branch_id.clone())
        .collect();

    BranchSelectionTrace {
        selected_branch_id,
        candidates: evaluations,
        rule_trace,
        losing_branch_ids,
    }
}

/// Walk the `compare_scores` rules in order between the winner and runner-up,
/// recording each rule's values and marking the first differentiator decisive.
/// The orderings mirror `compare_scores` exactly (the last three rules favour
/// the lexicographically smaller value, hence `other.cmp(winner)`).
fn build_rule_trace(
    winner: &BranchScore,
    other: &BranchScore,
    winner_id: &str,
    other_id: &str,
) -> Vec<RuleEvaluation> {
    let entries: [(&'static str, Ordering, String, String); 7] = [
        (
            "effective_commit_depth",
            winner
                .effective_commit_depth
                .cmp(&other.effective_commit_depth),
            winner.effective_commit_depth.to_string(),
            other.effective_commit_depth.to_string(),
        ),
        (
            "witness_quorum_met",
            winner.witness_quorum_met.cmp(&other.witness_quorum_met),
            winner.witness_quorum_met.to_string(),
            other.witness_quorum_met.to_string(),
        ),
        (
            "valid_commit_depth",
            winner.valid_commit_depth.cmp(&other.valid_commit_depth),
            winner.valid_commit_depth.to_string(),
            other.valid_commit_depth.to_string(),
        ),
        (
            "app_witness_score",
            winner.app_witness_score.cmp(&other.app_witness_score),
            winner.app_witness_score.to_string(),
            other.app_witness_score.to_string(),
        ),
        (
            "tip_priority",
            other.tip_priority.cmp(&winner.tip_priority),
            tip_priority_str(winner.tip_priority).to_string(),
            tip_priority_str(other.tip_priority).to_string(),
        ),
        (
            "tip_committer",
            other.tip_committer.cmp(&winner.tip_committer),
            hex::encode(&winner.tip_committer),
            hex::encode(&other.tip_committer),
        ),
        (
            "tip_digest",
            other.tip_digest.cmp(&winner.tip_digest),
            hex::encode(winner.tip_digest),
            hex::encode(other.tip_digest),
        ),
    ];
    let mut decided = false;
    entries
        .into_iter()
        .map(|(rule_name, ordering, winner_value, other_value)| {
            let decisive = !decided && ordering != Ordering::Equal;
            if decisive {
                decided = true;
            }
            RuleEvaluation {
                rule_name,
                winner_branch_id: winner_id.to_string(),
                other_branch_id: other_id.to_string(),
                winner_value,
                other_value,
                decisive,
            }
        })
        .collect()
}

fn witness_depth_boost(branch: &BranchCandidate, policy: &ConvergencePolicy) -> u64 {
    if witness_quorum_met(&branch.app_witnesses, policy) {
        policy.max_witness_override_depth
    } else {
        0
    }
}

fn witness_quorum_met(witnesses: &[AppWitness], policy: &ConvergencePolicy) -> bool {
    if policy.witness_quorum_senders_per_epoch == 0 || policy.witness_quorum_epochs == 0 {
        return false;
    }
    witnesses_by_epoch(witnesses)
        .values()
        .filter(|senders| senders.len() >= policy.witness_quorum_senders_per_epoch)
        .count()
        >= policy.witness_quorum_epochs
}

fn app_witness_score(witnesses: &[AppWitness], policy: &ConvergencePolicy) -> usize {
    witnesses_by_epoch(witnesses)
        .values()
        .map(|senders| senders.len().min(policy.witness_quorum_senders_per_epoch))
        .sum()
}

fn witnesses_by_epoch(witnesses: &[AppWitness]) -> BTreeMap<u64, BTreeSet<Vec<u8>>> {
    let mut by_epoch: BTreeMap<u64, BTreeSet<Vec<u8>>> = BTreeMap::new();
    for witness in witnesses {
        by_epoch
            .entry(witness.epoch)
            .or_default()
            .insert(witness.sender.clone());
    }
    by_epoch
}
