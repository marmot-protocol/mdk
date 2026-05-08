//! Candidate-state graph rules for distributed convergence.
//!
//! This module does not drive OpenMLS. It captures the deterministic branch
//! selection policy that the engine canonicalizer uses after materializing
//! competing MLS states.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchCandidate {
    pub id: String,
    pub fork_epoch: u64,
    pub tip_epoch: u64,
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
        .then_with(|| b.tip_digest.cmp(&a.tip_digest))
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
