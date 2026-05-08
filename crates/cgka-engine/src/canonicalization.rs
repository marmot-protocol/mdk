//! Executable model for the CGKA canonicalization contract.
//!
//! This module stays above OpenMLS. It models the post-peeling contract with
//! symbolic candidate branches and messages, while OpenMLS-specific adapters
//! materialize the candidate states from stored protocol bytes.

use std::collections::{BTreeMap, BTreeSet};

use crate::convergence::{AppWitness, BranchCandidate, ConvergencePolicy, select_canonical_branch};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalizationPolicy {
    pub convergence: ConvergencePolicy,
    pub app_message_past_epoch_limit: u64,
    pub stable_quiescence_ms: u64,
}

impl Default for CanonicalizationPolicy {
    fn default() -> Self {
        Self {
            convergence: ConvergencePolicy::default(),
            app_message_past_epoch_limit: 5,
            stable_quiescence_ms: 1_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalizationState {
    pub current_tip_epoch: u64,
    pub retained_anchor_epoch: u64,
    pub sync_state: SyncState,
    pub last_convergence_relevant_input_ms: u64,
    pub seen_message_ids: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SyncState {
    Syncing,
    Canonicalizing,
    Stable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalizationInput {
    pub state: CanonicalizationState,
    pub pending_messages: Vec<PeeledMessage>,
    pub outbound_intents: Vec<OutboundIntent>,
    pub candidate_branches: Vec<BranchCandidate>,
    pub policy: CanonicalizationPolicy,
    pub now_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedCandidate {
    pub branch: BranchCandidate,
    pub commit_message_ids: Vec<String>,
    pub consumed_proposal_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeeledMessage {
    pub message_id: String,
    pub group_id: String,
    pub sender: Vec<u8>,
    pub source_epoch: u64,
    pub kind: PeeledMessageKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeeledMessageKind {
    Commit {
        branch_id: String,
        parent_branch_id: Option<String>,
        fork_epoch: u64,
        resulting_epoch: u64,
        tip_digest: [u8; 32],
        consumed_proposal_ids: Vec<String>,
    },
    Proposal {
        branch_id: String,
    },
    AppMessage {
        epoch: u64,
        decrypts_on_branches: Vec<String>,
        decrypted_payload_ref: Option<String>,
    },
}

impl PeeledMessage {
    fn kind_name(&self) -> MessageKind {
        match self.kind {
            PeeledMessageKind::Commit { .. } => MessageKind::Commit,
            PeeledMessageKind::Proposal { .. } => MessageKind::Proposal,
            PeeledMessageKind::AppMessage { .. } => MessageKind::AppMessage,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OutboundIntent {
    SendAppMessage { payload: String },
    CreateCommit { change: String },
    PublishProposal { proposal: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageKind {
    Commit,
    Proposal,
    AppMessage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalizationResult {
    pub previous_tip: u64,
    pub selected_tip: Option<u64>,
    pub selected_branch_id: Option<String>,
    pub sync_state: SyncState,
    pub accepted_commits: Vec<String>,
    pub accepted_proposals: Vec<String>,
    pub accepted_app_messages: Vec<String>,
    pub invalidated_app_messages: Vec<InvalidatedAppMessage>,
    pub dropped_messages: Vec<DroppedMessage>,
    pub already_seen: Vec<AlreadySeen>,
    pub queued_outbound_intents: Vec<OutboundIntent>,
    pub publishable_outbound_messages: Vec<OutboundIntent>,
    pub errors: Vec<CanonicalizationError>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InvalidatedAppMessage {
    pub message_id: String,
    pub epoch: u64,
    pub reason: InvalidatedAppMessageReason,
    pub decrypted_payload_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InvalidatedAppMessageReason {
    LosingBranch,
    BeyondAnchor,
    BeyondAppRetention,
    UndecryptableInCanonicalState,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DroppedMessage {
    pub message_id: String,
    pub kind: MessageKind,
    pub reason: DroppedMessageReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DroppedMessageReason {
    BeyondRollbackHorizon,
    BeyondAnchor,
    BeyondAppRetention,
    InvalidAgainstCandidateState,
    UnsupportedPolicy,
    Malformed,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AlreadySeen {
    pub message_id: String,
    pub kind: MessageKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CanonicalizationError {
    UnsupportedPolicy,
    MissingRetainedAnchor,
    CandidateStateUnavailable,
    MlsValidationFailed,
    OutboundIntentStale,
    StorageUnavailable,
}

pub fn canonicalize(input: CanonicalizationInput) -> CanonicalizationResult {
    canonicalize_internal(input, &[])
}

pub fn canonicalize_with_materialized_candidates(
    input: CanonicalizationInput,
    materialized_candidates: Vec<MaterializedCandidate>,
) -> CanonicalizationResult {
    canonicalize_internal(input, &materialized_candidates)
}

fn canonicalize_internal(
    input: CanonicalizationInput,
    materialized_candidates: &[MaterializedCandidate],
) -> CanonicalizationResult {
    let mut already_seen = Vec::new();
    let mut observed_ids = input.state.seen_message_ids.clone();
    let mut unique_messages = Vec::new();

    for message in input.pending_messages.iter() {
        if !observed_ids.insert(message.message_id.clone()) {
            already_seen.push(AlreadySeen {
                message_id: message.message_id.clone(),
                kind: message.kind_name(),
            });
            continue;
        }
        unique_messages.push(message);
    }

    let mut materialized_graph =
        materialize_candidate_graph(&input, &unique_messages, materialized_candidates);
    attach_app_witnesses(
        &mut materialized_graph,
        &unique_messages,
        &input.state,
        &input.policy,
    );
    let selected_branch = select_canonical_branch(
        input.state.current_tip_epoch,
        &materialized_graph.candidates,
        &input.policy.convergence,
    );
    let selected_branch_id = selected_branch.map(|branch| branch.id.clone());
    let selected_tip = selected_branch.map(|branch| branch.tip_epoch);

    let mut result = CanonicalizationResult {
        previous_tip: input.state.current_tip_epoch,
        selected_tip,
        selected_branch_id: selected_branch_id.clone(),
        sync_state: sync_state_for(&input),
        accepted_commits: Vec::new(),
        accepted_proposals: Vec::new(),
        accepted_app_messages: Vec::new(),
        invalidated_app_messages: Vec::new(),
        dropped_messages: Vec::new(),
        already_seen,
        queued_outbound_intents: Vec::new(),
        publishable_outbound_messages: Vec::new(),
        errors: Vec::new(),
    };

    if selected_branch_id.is_none() {
        result
            .errors
            .push(CanonicalizationError::CandidateStateUnavailable);
    }

    let selected_commit_ids = selected_branch_id
        .as_deref()
        .and_then(|branch_id| materialized_graph.commit_path_by_branch.get(branch_id))
        .cloned()
        .unwrap_or_default();
    let selected_commit_id_set: BTreeSet<String> = selected_commit_ids.iter().cloned().collect();
    let selected_branch_path = selected_branch_id
        .as_deref()
        .and_then(|branch_id| materialized_graph.branch_path_by_branch.get(branch_id))
        .cloned()
        .unwrap_or_default();
    let selected_consumed_proposal_ids = selected_branch_id
        .as_deref()
        .and_then(|branch_id| {
            materialized_graph
                .consumed_proposal_ids_by_branch
                .get(branch_id)
        })
        .cloned()
        .unwrap_or_default();
    result.accepted_commits = selected_commit_ids;

    for message in unique_messages {
        match &message.kind {
            PeeledMessageKind::Commit {
                branch_id,
                parent_branch_id: _,
                fork_epoch,
                resulting_epoch: _,
                tip_digest: _,
                consumed_proposal_ids: _,
            } => handle_commit(
                &mut result,
                &input,
                message,
                branch_id,
                *fork_epoch,
                &selected_commit_id_set,
                &materialized_graph.branch_ids,
            ),
            PeeledMessageKind::Proposal { branch_id } => handle_proposal(
                &mut result,
                &input,
                message,
                branch_id,
                &selected_consumed_proposal_ids,
                &selected_branch_path,
                &materialized_graph.branch_ids,
            ),
            PeeledMessageKind::AppMessage {
                epoch,
                decrypts_on_branches,
                decrypted_payload_ref,
            } => handle_app_message(
                &mut result,
                &input,
                message,
                *epoch,
                decrypts_on_branches,
                decrypted_payload_ref.clone(),
            ),
        }
    }
    drop_losing_materialized_candidate_commits(
        &mut result,
        &materialized_graph.materialized_commit_ids_by_branch,
    );

    if result.sync_state == SyncState::Stable {
        result.publishable_outbound_messages = input.outbound_intents;
    } else {
        result.queued_outbound_intents = input.outbound_intents;
    }

    result.sort();
    result
}

#[derive(Clone, Debug)]
struct MaterializedGraph {
    candidates: Vec<BranchCandidate>,
    commit_path_by_branch: BTreeMap<String, Vec<String>>,
    branch_path_by_branch: BTreeMap<String, BTreeSet<String>>,
    consumed_proposal_ids_by_branch: BTreeMap<String, BTreeSet<String>>,
    materialized_commit_ids_by_branch: BTreeMap<String, BTreeSet<String>>,
    branch_ids: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct ResolvedParent {
    fork_epoch: u64,
    commit_path: Vec<String>,
    branch_path: BTreeSet<String>,
    consumed_proposal_ids: BTreeSet<String>,
}

fn materialize_candidate_graph(
    input: &CanonicalizationInput,
    unique_messages: &[&PeeledMessage],
    materialized_candidates: &[MaterializedCandidate],
) -> MaterializedGraph {
    let mut candidates: BTreeMap<String, BranchCandidate> = input
        .candidate_branches
        .iter()
        .cloned()
        .map(|candidate| (candidate.id.clone(), candidate))
        .collect();
    let mut commit_path_by_branch: BTreeMap<String, Vec<String>> = input
        .candidate_branches
        .iter()
        .map(|candidate| (candidate.id.clone(), Vec::new()))
        .collect();
    let mut branch_path_by_branch: BTreeMap<String, BTreeSet<String>> = input
        .candidate_branches
        .iter()
        .map(|candidate| (candidate.id.clone(), BTreeSet::from([candidate.id.clone()])))
        .collect();
    let mut consumed_proposal_ids_by_branch: BTreeMap<String, BTreeSet<String>> = input
        .candidate_branches
        .iter()
        .map(|candidate| (candidate.id.clone(), BTreeSet::new()))
        .collect();
    let mut materialized_commit_ids_by_branch = BTreeMap::new();

    for materialized in materialized_candidates {
        let branch_id = materialized.branch.id.clone();
        candidates.insert(branch_id.clone(), materialized.branch.clone());
        commit_path_by_branch.insert(branch_id.clone(), materialized.commit_message_ids.clone());
        branch_path_by_branch.insert(branch_id.clone(), BTreeSet::from([branch_id.clone()]));
        consumed_proposal_ids_by_branch.insert(
            branch_id.clone(),
            materialized.consumed_proposal_ids.iter().cloned().collect(),
        );
        materialized_commit_ids_by_branch.insert(
            branch_id,
            materialized.commit_message_ids.iter().cloned().collect(),
        );
    }

    let mut materialized_commit_ids = BTreeSet::new();

    let mut commit_messages: Vec<&PeeledMessage> = unique_messages
        .iter()
        .copied()
        .filter(|message| matches!(message.kind, PeeledMessageKind::Commit { .. }))
        .collect();
    commit_messages.sort_by(|a, b| {
        a.source_epoch
            .cmp(&b.source_epoch)
            .then_with(|| a.message_id.cmp(&b.message_id))
    });

    loop {
        let mut progressed = false;

        for message in &commit_messages {
            let PeeledMessageKind::Commit {
                branch_id,
                parent_branch_id,
                fork_epoch,
                resulting_epoch,
                tip_digest,
                consumed_proposal_ids,
            } = &message.kind
            else {
                continue;
            };

            if materialized_commit_ids.contains(&message.message_id)
                || candidates.contains_key(branch_id)
                || *fork_epoch < input.state.retained_anchor_epoch
                || input.state.current_tip_epoch.saturating_sub(*fork_epoch)
                    > input.policy.convergence.max_rewind_commits
                || *resulting_epoch <= message.source_epoch
            {
                continue;
            }

            let Some(mut resolved_parent) = resolve_parent(
                parent_branch_id.as_deref(),
                *fork_epoch,
                &candidates,
                &commit_path_by_branch,
                &branch_path_by_branch,
                &consumed_proposal_ids_by_branch,
            ) else {
                continue;
            };

            if !source_epoch_matches_parent(
                parent_branch_id.as_deref(),
                message.source_epoch,
                *fork_epoch,
                &candidates,
            ) {
                continue;
            }

            resolved_parent.commit_path.push(message.message_id.clone());
            resolved_parent.branch_path.insert(branch_id.clone());
            resolved_parent
                .consumed_proposal_ids
                .extend(consumed_proposal_ids.iter().cloned());
            candidates.insert(
                branch_id.clone(),
                BranchCandidate {
                    id: branch_id.clone(),
                    fork_epoch: resolved_parent.fork_epoch,
                    tip_epoch: *resulting_epoch,
                    tip_digest: *tip_digest,
                    app_witnesses: vec![],
                },
            );
            commit_path_by_branch.insert(branch_id.clone(), resolved_parent.commit_path);
            branch_path_by_branch.insert(branch_id.clone(), resolved_parent.branch_path);
            consumed_proposal_ids_by_branch
                .insert(branch_id.clone(), resolved_parent.consumed_proposal_ids);
            materialized_commit_ids.insert(message.message_id.clone());
            progressed = true;
        }

        if !progressed {
            break;
        }
    }

    let branch_ids = candidates.keys().cloned().collect();
    MaterializedGraph {
        candidates: candidates.into_values().collect(),
        commit_path_by_branch,
        branch_path_by_branch,
        consumed_proposal_ids_by_branch,
        materialized_commit_ids_by_branch,
        branch_ids,
    }
}

fn resolve_parent(
    parent_branch_id: Option<&str>,
    fork_epoch: u64,
    candidates: &BTreeMap<String, BranchCandidate>,
    commit_path_by_branch: &BTreeMap<String, Vec<String>>,
    branch_path_by_branch: &BTreeMap<String, BTreeSet<String>>,
    consumed_proposal_ids_by_branch: &BTreeMap<String, BTreeSet<String>>,
) -> Option<ResolvedParent> {
    if let Some(parent_id) = parent_branch_id {
        let parent = candidates.get(parent_id)?;
        let commit_path = commit_path_by_branch
            .get(parent_id)
            .cloned()
            .unwrap_or_default();
        let branch_path = branch_path_by_branch
            .get(parent_id)
            .cloned()
            .unwrap_or_default();
        let consumed_proposal_ids = consumed_proposal_ids_by_branch
            .get(parent_id)
            .cloned()
            .unwrap_or_default();
        Some(ResolvedParent {
            fork_epoch: parent.fork_epoch,
            commit_path,
            branch_path,
            consumed_proposal_ids,
        })
    } else {
        Some(ResolvedParent {
            fork_epoch,
            commit_path: Vec::new(),
            branch_path: BTreeSet::new(),
            consumed_proposal_ids: BTreeSet::new(),
        })
    }
}

fn source_epoch_matches_parent(
    parent_branch_id: Option<&str>,
    source_epoch: u64,
    fork_epoch: u64,
    candidates: &BTreeMap<String, BranchCandidate>,
) -> bool {
    if let Some(parent_id) = parent_branch_id {
        candidates
            .get(parent_id)
            .is_some_and(|parent| parent.tip_epoch == source_epoch)
    } else {
        source_epoch == fork_epoch
    }
}

fn attach_app_witnesses(
    graph: &mut MaterializedGraph,
    unique_messages: &[&PeeledMessage],
    state: &CanonicalizationState,
    policy: &CanonicalizationPolicy,
) {
    for message in unique_messages {
        let PeeledMessageKind::AppMessage {
            epoch,
            decrypts_on_branches,
            ..
        } = &message.kind
        else {
            continue;
        };
        if app_message_expired(state, policy, *epoch) {
            continue;
        }
        for branch_id in decrypts_on_branches {
            if let Some(candidate) = graph
                .candidates
                .iter_mut()
                .find(|candidate| candidate.id == *branch_id)
            {
                candidate.app_witnesses.push(AppWitness {
                    epoch: *epoch,
                    sender: message.sender.clone(),
                });
            }
        }
    }
}

fn handle_commit(
    result: &mut CanonicalizationResult,
    input: &CanonicalizationInput,
    message: &PeeledMessage,
    branch_id: &str,
    fork_epoch: u64,
    selected_commit_ids: &BTreeSet<String>,
    materialized_branch_ids: &BTreeSet<String>,
) {
    if fork_epoch < input.state.retained_anchor_epoch {
        result
            .dropped_messages
            .push(dropped(message, DroppedMessageReason::BeyondAnchor));
    } else if input.state.current_tip_epoch.saturating_sub(fork_epoch)
        > input.policy.convergence.max_rewind_commits
    {
        result.dropped_messages.push(dropped(
            message,
            DroppedMessageReason::BeyondRollbackHorizon,
        ));
    } else if !selected_commit_ids.contains(&message.message_id) {
        if Some(branch_id) == result.selected_branch_id.as_deref() {
            result.accepted_commits.push(message.message_id.clone());
        } else if materialized_branch_ids.contains(branch_id) && result.selected_branch_id.is_some()
        {
            result.dropped_messages.push(dropped(
                message,
                DroppedMessageReason::InvalidAgainstCandidateState,
            ));
        }
    }
}

fn handle_proposal(
    result: &mut CanonicalizationResult,
    input: &CanonicalizationInput,
    message: &PeeledMessage,
    branch_id: &str,
    selected_consumed_proposal_ids: &BTreeSet<String>,
    selected_branch_path: &BTreeSet<String>,
    materialized_branch_ids: &BTreeSet<String>,
) {
    if message.source_epoch < input.state.retained_anchor_epoch {
        result
            .dropped_messages
            .push(dropped(message, DroppedMessageReason::BeyondAnchor));
    } else if selected_consumed_proposal_ids.contains(&message.message_id) {
        result.accepted_proposals.push(message.message_id.clone());
    } else if materialized_branch_ids.contains(branch_id)
        && !selected_branch_path.contains(branch_id)
        && result.selected_branch_id.is_some()
    {
        result.dropped_messages.push(dropped(
            message,
            DroppedMessageReason::InvalidAgainstCandidateState,
        ));
    }
}

fn handle_app_message(
    result: &mut CanonicalizationResult,
    input: &CanonicalizationInput,
    message: &PeeledMessage,
    epoch: u64,
    decrypts_on_branches: &[String],
    decrypted_payload_ref: Option<String>,
) {
    if epoch < input.state.retained_anchor_epoch {
        result.invalidated_app_messages.push(invalidated_app(
            message,
            epoch,
            InvalidatedAppMessageReason::BeyondAnchor,
            decrypted_payload_ref,
        ));
    } else if app_message_expired(&input.state, &input.policy, epoch) {
        result.invalidated_app_messages.push(invalidated_app(
            message,
            epoch,
            InvalidatedAppMessageReason::BeyondAppRetention,
            decrypted_payload_ref,
        ));
    } else if result
        .selected_branch_id
        .as_ref()
        .is_some_and(|selected| decrypts_on_branches.contains(selected))
    {
        result
            .accepted_app_messages
            .push(message.message_id.clone());
    } else if decrypts_on_branches.is_empty() {
        result.invalidated_app_messages.push(invalidated_app(
            message,
            epoch,
            InvalidatedAppMessageReason::UndecryptableInCanonicalState,
            decrypted_payload_ref,
        ));
    } else {
        result.invalidated_app_messages.push(invalidated_app(
            message,
            epoch,
            InvalidatedAppMessageReason::LosingBranch,
            decrypted_payload_ref,
        ));
    }
}

fn drop_losing_materialized_candidate_commits(
    result: &mut CanonicalizationResult,
    materialized_commit_ids_by_branch: &BTreeMap<String, BTreeSet<String>>,
) {
    let Some(selected_branch_id) = result.selected_branch_id.as_deref() else {
        return;
    };
    for (branch_id, commit_ids) in materialized_commit_ids_by_branch {
        if branch_id == selected_branch_id {
            continue;
        }
        for message_id in commit_ids {
            if result
                .dropped_messages
                .iter()
                .any(|dropped| dropped.message_id == *message_id)
            {
                continue;
            }
            result.dropped_messages.push(DroppedMessage {
                message_id: message_id.clone(),
                kind: MessageKind::Commit,
                reason: DroppedMessageReason::InvalidAgainstCandidateState,
            });
        }
    }
}

fn sync_state_for(input: &CanonicalizationInput) -> SyncState {
    let elapsed = input
        .now_ms
        .saturating_sub(input.state.last_convergence_relevant_input_ms);
    if elapsed >= input.policy.stable_quiescence_ms {
        SyncState::Stable
    } else {
        SyncState::Syncing
    }
}

fn app_message_expired(
    state: &CanonicalizationState,
    policy: &CanonicalizationPolicy,
    epoch: u64,
) -> bool {
    state.current_tip_epoch.saturating_sub(epoch) > policy.app_message_past_epoch_limit
}

fn dropped(message: &PeeledMessage, reason: DroppedMessageReason) -> DroppedMessage {
    DroppedMessage {
        message_id: message.message_id.clone(),
        kind: message.kind_name(),
        reason,
    }
}

fn invalidated_app(
    message: &PeeledMessage,
    epoch: u64,
    reason: InvalidatedAppMessageReason,
    decrypted_payload_ref: Option<String>,
) -> InvalidatedAppMessage {
    InvalidatedAppMessage {
        message_id: message.message_id.clone(),
        epoch,
        reason,
        decrypted_payload_ref,
    }
}

impl CanonicalizationResult {
    fn sort(&mut self) {
        self.accepted_proposals.sort();
        self.accepted_app_messages.sort();
        self.invalidated_app_messages.sort();
        self.dropped_messages.sort();
        self.already_seen.sort();
        self.queued_outbound_intents.sort();
        self.publishable_outbound_messages.sort();
        self.errors.sort();
    }
}
