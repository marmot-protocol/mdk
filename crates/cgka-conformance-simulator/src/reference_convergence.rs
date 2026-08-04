//! Independent, symbolic convergence oracle.
//!
//! This module intentionally does not import the production engine crate. It restates the
//! observable convergence contract using small serializable values so bounded
//! differential tests can detect drift in the production selector and
//! canonicalizer. Authentication and authorization are explicit inputs here;
//! production comparison begins after those checks at the peeled-message
//! boundary.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferencePolicy {
    pub max_rewind_commits: u64,
    pub witness_quorum_senders_per_epoch: usize,
    pub witness_quorum_epochs: usize,
    pub max_witness_override_depth: u64,
    pub app_message_past_epoch_limit: u64,
}

impl Default for ReferencePolicy {
    fn default() -> Self {
        Self {
            max_rewind_commits: 5,
            witness_quorum_senders_per_epoch: 2,
            witness_quorum_epochs: 1,
            max_witness_override_depth: 1,
            app_message_past_epoch_limit: 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessMode {
    #[default]
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferencePriority {
    Privileged,
    Ordinary,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceWitness {
    pub epoch: u64,
    pub sender: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceCandidate {
    pub id: String,
    pub fork_epoch: u64,
    pub tip_epoch: u64,
    pub tip_priority: ReferencePriority,
    pub tip_committer: Vec<u8>,
    pub tip_digest: [u8; 32],
    #[serde(default)]
    pub app_witnesses: Vec<ReferenceWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceCommit {
    pub message_id: String,
    pub branch_id: String,
    pub parent_branch_id: Option<String>,
    pub sender: Vec<u8>,
    pub source_epoch: u64,
    pub fork_epoch: u64,
    pub resulting_epoch: u64,
    pub tip_priority: ReferencePriority,
    pub tip_digest: [u8; 32],
    #[serde(default)]
    pub consumed_proposal_ids: Vec<String>,
    pub authenticated: bool,
    pub authorized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceProposal {
    pub message_id: String,
    pub branch_id: String,
    pub source_epoch: u64,
    pub authenticated: bool,
    pub authorized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceAppMessage {
    pub message_id: String,
    pub sender: Vec<u8>,
    pub epoch: u64,
    #[serde(default)]
    pub decrypts_on_branches: Vec<String>,
    pub authenticated: bool,
    pub authorized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceInput {
    pub current_tip_epoch: u64,
    pub retained_anchor_epoch: u64,
    #[serde(default)]
    pub candidates: Vec<ReferenceCandidate>,
    #[serde(default)]
    pub commits: Vec<ReferenceCommit>,
    #[serde(default)]
    pub proposals: Vec<ReferenceProposal>,
    #[serde(default)]
    pub app_messages: Vec<ReferenceAppMessage>,
    pub policy: ReferencePolicy,
    #[serde(default)]
    pub witness_mode: WitnessMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceScore {
    pub effective_commit_depth: u64,
    pub witness_quorum_met: bool,
    pub app_witness_score: usize,
    pub tip_priority: ReferencePriority,
    pub tip_committer: Vec<u8>,
    pub tip_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceDisposition {
    Accepted,
    DeferredMissingParent,
    DeferredLosingEligibleBranch,
    DeferredAwaitingCommit,
    DeferredFutureEpoch,
    DroppedUnauthenticated,
    DroppedUnauthorized,
    DroppedBeyondAnchor,
    DroppedBeyondRollbackHorizon,
    DroppedInvalidCommit,
    DroppedExpiredProposal,
    InvalidatedBeyondAppRetention,
    InvalidatedLosingBranch,
    InvalidatedUndecryptable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceResult {
    pub selected_branch_id: Option<String>,
    pub selected_tip_epoch: Option<u64>,
    pub scores: BTreeMap<String, ReferenceScore>,
    pub dispositions: BTreeMap<String, ReferenceDisposition>,
    pub accepted_commit_path: Vec<String>,
    pub materialized_branch_ids: BTreeSet<String>,
}

/// Production decision seam through which an authenticated dependency-closed
/// input set first becomes visible. Route choice may affect transient work but
/// must not change the canonical result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "route", rename_all = "snake_case")]
pub enum ReferenceDecisionRoute {
    OrdinaryIngest,
    PairwiseForkRecovery { provisional_winner: String },
    StoredConvergence,
    RetainedHistoryReplay,
    CrashRestartRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceRouteResult {
    pub route: ReferenceDecisionRoute,
    pub canonical: ReferenceResult,
    /// Authenticated losing branches that remain eligible for a later pass.
    pub reconsiderable_branch_ids: BTreeSet<String>,
}

/// Evaluate the same durable input set through a named production route.
///
/// Pairwise recovery is modeled as a provisional decision only: its displaced
/// branch remains materializable until the shared canonical evaluator assigns
/// a terminal disposition. This is the rule #1236 showed must be identical at
/// every seam.
pub fn evaluate_via_route(
    input: &ReferenceInput,
    route: ReferenceDecisionRoute,
) -> ReferenceRouteResult {
    let canonical = evaluate(input);
    let reconsiderable_branch_ids = canonical
        .materialized_branch_ids
        .iter()
        .filter(|branch| Some(*branch) != canonical.selected_branch_id.as_ref())
        .cloned()
        .collect();
    ReferenceRouteResult {
        route,
        canonical,
        reconsiderable_branch_ids,
    }
}

#[derive(Clone)]
struct MaterializedBranch {
    candidate: ReferenceCandidate,
    commit_path: Vec<String>,
    branch_path: BTreeSet<String>,
    consumed_proposals: BTreeSet<String>,
}

/// Evaluate one finite symbolic input without calling production code.
pub fn evaluate(input: &ReferenceInput) -> ReferenceResult {
    let mut dispositions = BTreeMap::new();
    let mut graph: BTreeMap<String, MaterializedBranch> = input
        .candidates
        .iter()
        .cloned()
        .map(|candidate| {
            let id = candidate.id.clone();
            (
                id.clone(),
                MaterializedBranch {
                    candidate,
                    commit_path: Vec::new(),
                    branch_path: BTreeSet::from([id]),
                    consumed_proposals: BTreeSet::new(),
                },
            )
        })
        .collect();

    let mut commits: Vec<&ReferenceCommit> = input.commits.iter().collect();
    commits.sort_by(|a, b| {
        a.source_epoch
            .cmp(&b.source_epoch)
            .then_with(|| a.message_id.cmp(&b.message_id))
    });
    let mut materialized = BTreeSet::new();
    loop {
        let mut progressed = false;
        for commit in &commits {
            if materialized.contains(&commit.message_id) {
                continue;
            }
            if let Some(disposition) = rejected_commit(input, commit) {
                dispositions.insert(commit.message_id.clone(), disposition);
                materialized.insert(commit.message_id.clone());
                continue;
            }
            if commit.resulting_epoch <= commit.source_epoch
                || graph.contains_key(&commit.branch_id)
            {
                dispositions.insert(
                    commit.message_id.clone(),
                    ReferenceDisposition::DroppedInvalidCommit,
                );
                materialized.insert(commit.message_id.clone());
                continue;
            }
            let parent = match &commit.parent_branch_id {
                Some(parent_id) => graph
                    .get(parent_id)
                    .cloned()
                    .filter(|parent| parent.candidate.tip_epoch == commit.source_epoch),
                None if commit.source_epoch == commit.fork_epoch => Some(root_parent(commit)),
                _ => None,
            };
            let Some(mut parent) = parent else { continue };
            parent.commit_path.push(commit.message_id.clone());
            parent.branch_path.insert(commit.branch_id.clone());
            parent
                .consumed_proposals
                .extend(commit.consumed_proposal_ids.iter().cloned());
            graph.insert(
                commit.branch_id.clone(),
                MaterializedBranch {
                    candidate: ReferenceCandidate {
                        id: commit.branch_id.clone(),
                        fork_epoch: parent.candidate.fork_epoch,
                        tip_epoch: commit.resulting_epoch,
                        tip_priority: commit.tip_priority,
                        tip_committer: commit.sender.clone(),
                        tip_digest: commit.tip_digest,
                        app_witnesses: Vec::new(),
                    },
                    commit_path: parent.commit_path,
                    branch_path: parent.branch_path,
                    consumed_proposals: parent.consumed_proposals,
                },
            );
            materialized.insert(commit.message_id.clone());
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    for commit in &commits {
        if !dispositions.contains_key(&commit.message_id)
            && !materialized.contains(&commit.message_id)
        {
            dispositions.insert(
                commit.message_id.clone(),
                ReferenceDisposition::DeferredMissingParent,
            );
        }
    }

    if input.witness_mode == WitnessMode::Enabled {
        attach_witnesses(input, &mut graph);
    }
    let candidates: Vec<&ReferenceCandidate> = graph.values().map(|b| &b.candidate).collect();
    let scores = candidates
        .iter()
        .map(|candidate| (candidate.id.clone(), score(candidate, &input.policy)))
        .collect();
    let selected = select(input.current_tip_epoch, &candidates, &input.policy);
    let selected_id = selected.map(|candidate| candidate.id.clone());
    let selected_tip_epoch = selected.map(|candidate| candidate.tip_epoch);
    let selected_branch = selected_id.as_ref().and_then(|id| graph.get(id));
    let selected_commit_set: BTreeSet<&str> = selected_branch
        .map(|branch| branch.commit_path.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let selected_branch_path = selected_branch
        .map(|b| b.branch_path.clone())
        .unwrap_or_default();
    let selected_consumed = selected_branch
        .map(|b| b.consumed_proposals.clone())
        .unwrap_or_default();
    let all_consumed: BTreeSet<String> = graph
        .values()
        .flat_map(|branch| branch.consumed_proposals.iter().cloned())
        .collect();

    for commit in &input.commits {
        if dispositions.contains_key(&commit.message_id) {
            continue;
        }
        dispositions.insert(
            commit.message_id.clone(),
            if selected_commit_set.contains(commit.message_id.as_str()) {
                ReferenceDisposition::Accepted
            } else {
                ReferenceDisposition::DeferredLosingEligibleBranch
            },
        );
    }
    for proposal in &input.proposals {
        dispositions.insert(
            proposal.message_id.clone(),
            proposal_disposition(
                input,
                proposal,
                &graph,
                selected_id.as_ref(),
                selected_tip_epoch,
                &selected_branch_path,
                &selected_consumed,
                &all_consumed,
            ),
        );
    }
    for message in &input.app_messages {
        dispositions.insert(
            message.message_id.clone(),
            app_disposition(input, message, selected_id.as_ref(), selected_tip_epoch),
        );
    }

    ReferenceResult {
        selected_branch_id: selected_id,
        selected_tip_epoch,
        scores,
        dispositions,
        accepted_commit_path: selected_branch
            .map(|b| b.commit_path.clone())
            .unwrap_or_default(),
        materialized_branch_ids: graph.keys().cloned().collect(),
    }
}

fn rejected_commit(
    input: &ReferenceInput,
    commit: &ReferenceCommit,
) -> Option<ReferenceDisposition> {
    if !commit.authenticated {
        Some(ReferenceDisposition::DroppedUnauthenticated)
    } else if !commit.authorized {
        Some(ReferenceDisposition::DroppedUnauthorized)
    } else if commit.fork_epoch < input.retained_anchor_epoch {
        Some(ReferenceDisposition::DroppedBeyondAnchor)
    } else if input.current_tip_epoch.saturating_sub(commit.fork_epoch)
        > input.policy.max_rewind_commits
    {
        Some(ReferenceDisposition::DroppedBeyondRollbackHorizon)
    } else {
        None
    }
}

fn root_parent(commit: &ReferenceCommit) -> MaterializedBranch {
    MaterializedBranch {
        candidate: ReferenceCandidate {
            id: String::new(),
            fork_epoch: commit.fork_epoch,
            tip_epoch: commit.fork_epoch,
            tip_priority: commit.tip_priority,
            tip_committer: Vec::new(),
            tip_digest: [0; 32],
            app_witnesses: Vec::new(),
        },
        commit_path: Vec::new(),
        branch_path: BTreeSet::new(),
        consumed_proposals: BTreeSet::new(),
    }
}

fn attach_witnesses(input: &ReferenceInput, graph: &mut BTreeMap<String, MaterializedBranch>) {
    for message in &input.app_messages {
        if !(message.authenticated && message.authorized) {
            continue;
        }
        for branch_id in &message.decrypts_on_branches {
            let Some(branch) = graph.get_mut(branch_id) else {
                continue;
            };
            if message.epoch <= branch.candidate.fork_epoch
                || expired(
                    branch.candidate.tip_epoch,
                    message.epoch,
                    input.policy.app_message_past_epoch_limit,
                )
            {
                continue;
            }
            branch.candidate.app_witnesses.push(ReferenceWitness {
                epoch: message.epoch,
                sender: message.sender.clone(),
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn proposal_disposition(
    input: &ReferenceInput,
    proposal: &ReferenceProposal,
    graph: &BTreeMap<String, MaterializedBranch>,
    selected_id: Option<&String>,
    selected_tip: Option<u64>,
    selected_path: &BTreeSet<String>,
    selected_consumed: &BTreeSet<String>,
    all_consumed: &BTreeSet<String>,
) -> ReferenceDisposition {
    if !proposal.authenticated {
        return ReferenceDisposition::DroppedUnauthenticated;
    }
    if !proposal.authorized {
        return ReferenceDisposition::DroppedUnauthorized;
    }
    if proposal.source_epoch < input.retained_anchor_epoch {
        return ReferenceDisposition::DroppedBeyondAnchor;
    }
    if selected_consumed.contains(&proposal.message_id) {
        return ReferenceDisposition::Accepted;
    }
    if all_consumed.contains(&proposal.message_id)
        && graph.contains_key(&proposal.branch_id)
        && !selected_path.contains(&proposal.branch_id)
        && selected_id.is_some()
    {
        let branch = &graph[&proposal.branch_id].candidate;
        if branch.fork_epoch < input.retained_anchor_epoch {
            return ReferenceDisposition::DroppedBeyondAnchor;
        }
        if !eligible(input.current_tip_epoch, branch, &input.policy) {
            return ReferenceDisposition::DroppedBeyondRollbackHorizon;
        }
        return ReferenceDisposition::DeferredLosingEligibleBranch;
    }
    if selected_tip.unwrap_or(input.current_tip_epoch) > proposal.source_epoch {
        ReferenceDisposition::DroppedExpiredProposal
    } else {
        ReferenceDisposition::DeferredAwaitingCommit
    }
}

fn app_disposition(
    input: &ReferenceInput,
    message: &ReferenceAppMessage,
    selected_id: Option<&String>,
    selected_tip: Option<u64>,
) -> ReferenceDisposition {
    if !message.authenticated {
        return ReferenceDisposition::DroppedUnauthenticated;
    }
    if !message.authorized {
        return ReferenceDisposition::DroppedUnauthorized;
    }
    if message.epoch < input.retained_anchor_epoch {
        return ReferenceDisposition::DroppedBeyondAnchor;
    }
    if expired(
        input.current_tip_epoch,
        message.epoch,
        input.policy.app_message_past_epoch_limit,
    ) {
        return ReferenceDisposition::InvalidatedBeyondAppRetention;
    }
    if selected_id.is_some_and(|id| message.decrypts_on_branches.contains(id)) {
        return ReferenceDisposition::Accepted;
    }
    if message.decrypts_on_branches.is_empty()
        && message.epoch > selected_tip.unwrap_or(input.current_tip_epoch)
    {
        ReferenceDisposition::DeferredFutureEpoch
    } else if message.decrypts_on_branches.is_empty() {
        ReferenceDisposition::InvalidatedUndecryptable
    } else {
        ReferenceDisposition::InvalidatedLosingBranch
    }
}

pub fn score(candidate: &ReferenceCandidate, policy: &ReferencePolicy) -> ReferenceScore {
    let quorum = witness_quorum(&candidate.app_witnesses, policy);
    ReferenceScore {
        effective_commit_depth: candidate
            .tip_epoch
            .saturating_sub(candidate.fork_epoch)
            .saturating_add(if quorum {
                policy.max_witness_override_depth
            } else {
                0
            }),
        witness_quorum_met: quorum,
        app_witness_score: witness_score(&candidate.app_witnesses, policy),
        tip_priority: candidate.tip_priority,
        tip_committer: candidate.tip_committer.clone(),
        tip_digest: candidate.tip_digest,
    }
}

pub fn select<'a>(
    current_tip_epoch: u64,
    candidates: &'a [&ReferenceCandidate],
    policy: &ReferencePolicy,
) -> Option<&'a ReferenceCandidate> {
    candidates
        .iter()
        .copied()
        .filter(|candidate| eligible(current_tip_epoch, candidate, policy))
        .max_by(|a, b| compare(&score(a, policy), &score(b, policy)))
}

fn eligible(current_tip: u64, candidate: &ReferenceCandidate, policy: &ReferencePolicy) -> bool {
    current_tip.saturating_sub(candidate.fork_epoch) <= policy.max_rewind_commits
}

pub(crate) fn compare(a: &ReferenceScore, b: &ReferenceScore) -> Ordering {
    a.effective_commit_depth
        .cmp(&b.effective_commit_depth)
        .then_with(|| a.witness_quorum_met.cmp(&b.witness_quorum_met))
        .then_with(|| a.app_witness_score.cmp(&b.app_witness_score))
        .then_with(|| b.tip_priority.cmp(&a.tip_priority))
        .then_with(|| b.tip_committer.cmp(&a.tip_committer))
        .then_with(|| b.tip_digest.cmp(&a.tip_digest))
}

fn witness_quorum(witnesses: &[ReferenceWitness], policy: &ReferencePolicy) -> bool {
    if policy.witness_quorum_senders_per_epoch == 0 || policy.witness_quorum_epochs == 0 {
        return false;
    }
    senders_by_epoch(witnesses)
        .values()
        .filter(|senders| senders.len() >= policy.witness_quorum_senders_per_epoch)
        .count()
        >= policy.witness_quorum_epochs
}

fn witness_score(witnesses: &[ReferenceWitness], policy: &ReferencePolicy) -> usize {
    senders_by_epoch(witnesses)
        .values()
        .map(|senders| senders.len().min(policy.witness_quorum_senders_per_epoch))
        .sum()
}

fn senders_by_epoch(witnesses: &[ReferenceWitness]) -> BTreeMap<u64, BTreeSet<&[u8]>> {
    let mut result = BTreeMap::<u64, BTreeSet<&[u8]>>::new();
    for witness in witnesses {
        result
            .entry(witness.epoch)
            .or_default()
            .insert(&witness.sender);
    }
    result
}

fn expired(reference_tip: u64, message_epoch: u64, limit: u64) -> bool {
    reference_tip.saturating_sub(message_epoch) > limit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, fork: u64, tip: u64, digest: u8) -> ReferenceCandidate {
        ReferenceCandidate {
            id: id.into(),
            fork_epoch: fork,
            tip_epoch: tip,
            tip_priority: ReferencePriority::Ordinary,
            tip_committer: b"alice".to_vec(),
            tip_digest: [digest; 32],
            app_witnesses: Vec::new(),
        }
    }

    #[test]
    fn authentication_and_authorization_are_explicit_model_inputs() {
        let input = ReferenceInput {
            current_tip_epoch: 1,
            retained_anchor_epoch: 0,
            candidates: vec![candidate("live", 0, 1, 0)],
            commits: Vec::new(),
            proposals: vec![ReferenceProposal {
                message_id: "forged".into(),
                branch_id: "live".into(),
                source_epoch: 1,
                authenticated: false,
                authorized: false,
            }],
            app_messages: vec![ReferenceAppMessage {
                message_id: "former-member".into(),
                sender: b"mallory".to_vec(),
                epoch: 1,
                decrypts_on_branches: vec!["live".into()],
                authenticated: true,
                authorized: false,
            }],
            policy: ReferencePolicy::default(),
            witness_mode: WitnessMode::Enabled,
        };
        let result = evaluate(&input);
        assert_eq!(
            result.dispositions["forged"],
            ReferenceDisposition::DroppedUnauthenticated
        );
        assert_eq!(
            result.dispositions["former-member"],
            ReferenceDisposition::DroppedUnauthorized
        );
    }

    #[test]
    fn witness_free_variant_exposes_marginal_selection_effect() {
        let mut online = candidate("online", 1, 2, 0xff);
        online.app_witnesses = vec![
            ReferenceWitness {
                epoch: 2,
                sender: b"a".to_vec(),
            },
            ReferenceWitness {
                epoch: 2,
                sender: b"b".to_vec(),
            },
        ];
        let withheld = candidate("withheld", 1, 3, 0x00);
        assert_eq!(
            select(3, &[&online, &withheld], &ReferencePolicy::default())
                .unwrap()
                .id,
            "online"
        );
        online.app_witnesses.clear();
        assert_eq!(
            select(3, &[&online, &withheld], &ReferencePolicy::default())
                .unwrap()
                .id,
            "withheld"
        );
    }
}
