//! Executable model for the CGKA canonicalization contract.
//!
//! This module stays above OpenMLS. It models the post-peeling contract with
//! symbolic candidate branches and messages, while OpenMLS-specific adapters
//! materialize the candidate states from stored protocol bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::convergence::{
    AppWitness, BranchCandidate, BranchSelectionTrace, ConvergencePolicy, ConvergencePolicyError,
    is_branch_eligible, select_canonical_branch, select_canonical_branch_traced,
};
use cgka_traits::engine::CommitOrderingPriority;
use serde::{Deserialize, Serialize};

/// Adopted v1 app-message past-epoch delivery/decrypt window.
///
/// Must stay equal to [`crate::wire_format::DEFAULT_MAX_PAST_EPOCHS`] — the MLS
/// past-epoch window — so witness and delivery horizons cannot diverge.
pub const V1_APP_MESSAGE_PAST_EPOCH_LIMIT: u64 = 5;
/// Adopted v1 settlement quiescence window, in milliseconds.
pub const V1_SETTLEMENT_QUIESCENCE_MS: u64 = 1_000;
/// Adopted v1 absolute convergence-pass cap, in milliseconds.
pub const V1_MAX_CONVERGENCE_PASS_MS: u64 = 5_000;

const fn v1_max_convergence_pass_ms() -> u64 {
    V1_MAX_CONVERGENCE_PASS_MS
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalizationPolicy {
    pub convergence: ConvergencePolicy,
    pub app_message_past_epoch_limit: u64,
    pub settlement_quiescence_ms: u64,
    /// Immutable upper bound from pass admission to the frozen selection set.
    ///
    /// The serde default is only for records written before this field existed;
    /// policy validation still requires exact equality with the adopted v1
    /// policy.
    #[serde(default = "v1_max_convergence_pass_ms")]
    pub max_convergence_pass_ms: u64,
}

impl Default for CanonicalizationPolicy {
    fn default() -> Self {
        Self {
            convergence: ConvergencePolicy::default(),
            app_message_past_epoch_limit: V1_APP_MESSAGE_PAST_EPOCH_LIMIT,
            settlement_quiescence_ms: V1_SETTLEMENT_QUIESCENCE_MS,
            max_convergence_pass_ms: V1_MAX_CONVERGENCE_PASS_MS,
        }
    }
}

/// Validation errors for a [`CanonicalizationPolicy`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalizationPolicyError {
    #[error(transparent)]
    Convergence(#[from] ConvergencePolicyError),
    /// Policy differs from the adopted v1 baseline. Until a negotiation mechanism
    /// exists behind a required capability, every client MUST use exactly those
    /// pinned constants — not a local preference or per-group override.
    #[error("convergence policy must equal the pinned v1 baseline")]
    NotPinnedV1,
    /// App-message window disagrees with the engine's MLS `max_past_epochs`.
    #[error(
        "app_message_past_epoch_limit ({app_message_past_epoch_limit}) must equal \
         engine max_past_epochs ({max_past_epochs})"
    )]
    AppWindowMismatch {
        app_message_past_epoch_limit: u64,
        max_past_epochs: u64,
    },
}

impl CanonicalizationPolicy {
    /// Validate the nested convergence policy bounds. See
    /// [`ConvergencePolicy::validate`](crate::convergence::ConvergencePolicy::validate).
    pub fn validate(&self) -> Result<(), ConvergencePolicyError> {
        self.convergence.validate()
    }

    /// Exact equality with the adopted convergence-policy v1 constants.
    pub fn is_pinned_v1(&self) -> bool {
        self == &Self::default()
    }

    /// Fail closed unless this policy is exactly the adopted v1 baseline.
    pub fn ensure_pinned_v1(&self) -> Result<(), CanonicalizationPolicyError> {
        self.validate()?;
        if !self.is_pinned_v1() {
            return Err(CanonicalizationPolicyError::NotPinnedV1);
        }
        Ok(())
    }

    /// Keep the app-message delivery window aligned with MLS past-epoch decryptability.
    pub fn ensure_app_window_matches(
        &self,
        max_past_epochs: usize,
    ) -> Result<(), CanonicalizationPolicyError> {
        if self.app_message_past_epoch_limit != max_past_epochs as u64 {
            return Err(CanonicalizationPolicyError::AppWindowMismatch {
                app_message_past_epoch_limit: self.app_message_past_epoch_limit,
                max_past_epochs: max_past_epochs as u64,
            });
        }
        Ok(())
    }

    /// Same acceptance contract as engine setters and session open (mdk#970).
    ///
    /// Always enforces the witness-override bound and app-window alignment.
    /// Normal builds also require the pinned v1 baseline. Only test harnesses
    /// built with the explicit `test-policy-overrides` feature may override it.
    pub fn ensure_acceptable(
        &self,
        max_past_epochs: usize,
    ) -> Result<(), CanonicalizationPolicyError> {
        self.validate()?;
        self.ensure_app_window_matches(max_past_epochs)?;
        #[cfg(not(feature = "test-policy-overrides"))]
        if !self.is_pinned_v1() {
            return Err(CanonicalizationPolicyError::NotPinnedV1);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalizationState {
    pub current_tip_epoch: u64,
    pub retained_anchor_epoch: u64,
    pub last_convergence_relevant_input_ms: u64,
    // Shared, not owned: the engine's dedup snapshot holds up to 100k ids and
    // a convergence drain builds this state up to 16 times per drain.
    pub seen_message_ids: Arc<BTreeSet<String>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConvergenceStatus {
    Syncing,
    Resolving,
    Settled,
    Blocked,
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
        tip_priority: CommitOrderingPriority,
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
        /// This message was already applied/delivered on a prior convergence
        /// pass (its stored record is `Processed`). It is re-admitted so it can
        /// still witness its branch during scoring — a same-epoch fork resolved
        /// *after* the message was delivered must not lose the message's witness
        /// weight (that would make branch selection depend on local arrival
        /// order, violating the convergence contract's order-independence). It is
        /// never re-delivered: [`handle_app_message`] resolves it as already-seen.
        already_delivered: bool,
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
    /// Fork epoch of the selected branch (the epoch it diverges from common
    /// history). `None` when no branch was selected. Diagnostic only — used by
    /// engine reorg telemetry to classify a settle as a forward advance or a
    /// post-settle reorg; never an input to convergence or branch selection.
    pub selected_fork_epoch: Option<u64>,
    pub selected_branch_id: Option<String>,
    pub candidate_count: usize,
    pub eligible_count: usize,
    pub convergence_status: ConvergenceStatus,
    pub accepted_commits: Vec<String>,
    pub accepted_proposals: Vec<String>,
    pub accepted_app_messages: Vec<String>,
    /// Inputs with a current protocol `deferred` disposition. They remain
    /// retained and eligible for reconsideration in a later pass.
    pub deferred_messages: Vec<DeferredMessage>,
    pub invalidated_app_messages: Vec<InvalidatedAppMessage>,
    pub dropped_messages: Vec<DroppedMessage>,
    pub already_seen: Vec<AlreadySeen>,
    pub queued_outbound_intents: Vec<OutboundIntent>,
    pub publishable_outbound_messages: Vec<OutboundIntent>,
    pub errors: Vec<CanonicalizationError>,
    /// OpenMLS candidate replay probes consumed by this stored pass. Pure
    /// symbolic canonicalization reports zero.
    #[cfg(feature = "test-conformance-snapshot")]
    pub replay_probe_count: u64,
    /// Forensic audit trace of the branch-selection decision (per-candidate
    /// scores, the rule-by-rule comparison, and the losing branches). `None`
    /// when no selection was attempted (early-return result builders).
    pub selection_trace: Option<BranchSelectionTrace>,
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
    pub rejection_category: Option<cgka_traits::ingest::ProposalRejectionCategory>,
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeferredMessage {
    pub message_id: String,
    pub kind: MessageKind,
    pub reason: DeferredMessageReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeferredMessageReason {
    MissingCandidateParent,
    NonSelectedEligibleBranch,
    AwaitingCanonicalCommit,
    FutureEpoch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CanonicalizationError {
    UnsupportedPolicy,
    MissingRetainedAnchor,
    MissingOwnCommitCheckpoint,
    CandidateStateUnavailable,
    MlsValidationFailed,
    OutboundIntentStale,
    StorageUnavailable,
}

pub fn canonicalize(input: CanonicalizationInput) -> CanonicalizationResult {
    canonicalize_internal(input, &[], true)
}

pub fn canonicalize_with_materialized_candidates(
    input: CanonicalizationInput,
    materialized_candidates: Vec<MaterializedCandidate>,
) -> CanonicalizationResult {
    canonicalize_internal(input, &materialized_candidates, true)
}

/// Canonicalize with an explicit application-witness admission switch.
///
/// This is an engine-internal test seam used by the conformance simulator to
/// compare the complete stored-message engine path with and without the
/// speculative app-witness ranking term. Production callers always use
/// [`canonicalize_with_materialized_candidates`].
#[cfg(feature = "test-policy-overrides")]
pub(crate) fn canonicalize_with_materialized_candidates_for_test(
    input: CanonicalizationInput,
    materialized_candidates: Vec<MaterializedCandidate>,
    admit_app_witnesses: bool,
) -> CanonicalizationResult {
    canonicalize_internal(input, &materialized_candidates, admit_app_witnesses)
}

fn canonicalize_internal(
    input: CanonicalizationInput,
    materialized_candidates: &[MaterializedCandidate],
    admit_app_witnesses: bool,
) -> CanonicalizationResult {
    let mut already_seen = Vec::new();
    // Dedup against the (large, shared) base set by lookup; only ids first
    // observed in this batch need an owned set.
    let base_seen_ids = &input.state.seen_message_ids;
    let mut batch_observed_ids = BTreeSet::new();
    let mut unique_messages = Vec::new();

    for message in input.pending_messages.iter() {
        // An already-delivered app is intentionally in `seen_message_ids`, but it
        // must still reach materialization + `attach_app_witnesses` to witness its
        // branch. Exempt it from the seen-dedup here; `handle_app_message` resolves
        // it as already-seen so it is counted (not `Resolving`) yet never
        // re-delivered.
        let readmitted_witness = matches!(
            message.kind,
            PeeledMessageKind::AppMessage {
                already_delivered: true,
                ..
            }
        );
        if !readmitted_witness
            && (base_seen_ids.contains(&message.message_id)
                || !batch_observed_ids.insert(message.message_id.clone()))
        {
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
    if admit_app_witnesses {
        attach_app_witnesses(&mut materialized_graph, &unique_messages, &input.policy);
    }
    let selected_branch = select_canonical_branch(
        input.state.current_tip_epoch,
        &materialized_graph.candidates,
        &input.policy.convergence,
    );
    let selection_trace = Some(select_canonical_branch_traced(
        input.state.current_tip_epoch,
        &materialized_graph.candidates,
        &input.policy.convergence,
    ));
    let candidate_count = materialized_graph.candidates.len();
    let eligible_count = materialized_graph
        .candidates
        .iter()
        .filter(|candidate| {
            is_branch_eligible(
                input.state.current_tip_epoch,
                candidate,
                &input.policy.convergence,
            )
        })
        .count();
    let selected_branch_id = selected_branch.map(|branch| branch.id.clone());
    let selected_tip = selected_branch.map(|branch| branch.tip_epoch);
    let selected_fork_epoch = selected_branch.map(|branch| branch.fork_epoch);

    let mut result = CanonicalizationResult {
        previous_tip: input.state.current_tip_epoch,
        selected_tip,
        selected_fork_epoch,
        selected_branch_id: selected_branch_id.clone(),
        candidate_count,
        eligible_count,
        // Provisional; recomputed after dispositions are known so a completed
        // frozen batch can distinguish a fixed point from an actual blocking
        // error. Missing dependencies receive explicit deferred dispositions.
        convergence_status: ConvergenceStatus::Syncing,
        accepted_commits: Vec::new(),
        accepted_proposals: Vec::new(),
        accepted_app_messages: Vec::new(),
        deferred_messages: Vec::new(),
        invalidated_app_messages: Vec::new(),
        dropped_messages: Vec::new(),
        already_seen,
        queued_outbound_intents: Vec::new(),
        publishable_outbound_messages: Vec::new(),
        errors: Vec::new(),
        #[cfg(feature = "test-conformance-snapshot")]
        replay_probe_count: 0,
        selection_trace,
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
    let all_consumed_proposal_ids = materialized_graph
        .consumed_proposal_ids_by_branch
        .values()
        .flat_map(|ids| ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let proposal_disposition_context = ProposalDispositionContext {
        selected_consumed_proposal_ids: &selected_consumed_proposal_ids,
        all_consumed_proposal_ids: &all_consumed_proposal_ids,
        selected_branch_path: &selected_branch_path,
        materialized_branch_ids: &materialized_graph.branch_ids,
        candidate_branches: &materialized_graph.candidates,
    };
    result.accepted_commits = selected_commit_ids;

    for message in unique_messages {
        match &message.kind {
            PeeledMessageKind::Commit {
                branch_id,
                parent_branch_id: _,
                fork_epoch,
                resulting_epoch: _,
                tip_priority: _,
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
                &proposal_disposition_context,
            ),
            PeeledMessageKind::AppMessage {
                epoch,
                decrypts_on_branches,
                decrypted_payload_ref,
                already_delivered,
            } => handle_app_message(
                &mut result,
                &input,
                message,
                *epoch,
                decrypts_on_branches,
                decrypted_payload_ref.clone(),
                *already_delivered,
            ),
        }
    }
    classify_losing_materialized_candidate_commits(
        &mut result,
        &input,
        &materialized_graph.candidates,
        &materialized_graph.materialized_commit_ids_by_branch,
    );

    // Compute the convergence status now that dispositions are known. Spec
    // (cgka-engine-canonicalization-contract.md §Lifecycle):
    //
    // - Syncing: convergence-relevant input window has not yet quiesced.
    // - Resolving: the frozen batch is actively being resolved. This
    //   synchronous executable model returns only after resolution, so
    //   missing dependencies receive an explicit deferred disposition
    //   rather than pinning the completed pass in Resolving.
    // - Blocked: window quiesced and convergence cannot advance without
    //   a repair path or missing retained material.
    // - Settled: window quiesced AND every input message received a
    //   disposition AND no blocking error remains.
    result.convergence_status =
        convergence_status_for_result(&input, &input.pending_messages, &result);

    if result.convergence_status == ConvergenceStatus::Settled {
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
                tip_priority,
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
                    tip_priority: *tip_priority,
                    tip_committer: message.sender.clone(),
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
        for branch_id in decrypts_on_branches {
            if let Some(candidate) = graph
                .candidates
                .iter_mut()
                .find(|candidate| candidate.id == *branch_id)
            {
                // Shared-history traffic is not evidence that a branch was
                // actually used. Only messages from branch epochs strictly
                // after the divergence point can witness this candidate
                // (convergence-v1, #964).
                if *epoch <= candidate.fork_epoch {
                    continue;
                }
                // Witness counting evaluates the retained app-payload window with
                // the CANDIDATE's tip_epoch as the reference tip, not the global
                // canonical tip (retained-history.md "App-payload retention" and
                // convergence.md "App-payload witnesses"). Active convergence
                // retains the ability to authenticate the frozen input at its
                // source epoch; it does not make an expired witness eligible.
                if app_message_expired(candidate.tip_epoch, policy, *epoch) {
                    continue;
                }
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
            result.deferred_messages.push(deferred(
                message,
                DeferredMessageReason::NonSelectedEligibleBranch,
            ));
        } else {
            result.deferred_messages.push(deferred(
                message,
                DeferredMessageReason::MissingCandidateParent,
            ));
        }
    }
}

struct ProposalDispositionContext<'a> {
    selected_consumed_proposal_ids: &'a BTreeSet<String>,
    all_consumed_proposal_ids: &'a BTreeSet<String>,
    selected_branch_path: &'a BTreeSet<String>,
    materialized_branch_ids: &'a BTreeSet<String>,
    candidate_branches: &'a [BranchCandidate],
}

fn handle_proposal(
    result: &mut CanonicalizationResult,
    input: &CanonicalizationInput,
    message: &PeeledMessage,
    branch_id: &str,
    context: &ProposalDispositionContext<'_>,
) {
    if message.source_epoch < input.state.retained_anchor_epoch {
        result
            .dropped_messages
            .push(dropped(message, DroppedMessageReason::BeyondAnchor));
    } else if context
        .selected_consumed_proposal_ids
        .contains(&message.message_id)
    {
        result.accepted_proposals.push(message.message_id.clone());
    } else if context
        .all_consumed_proposal_ids
        .contains(&message.message_id)
        && context.materialized_branch_ids.contains(branch_id)
        && !context.selected_branch_path.contains(branch_id)
        && result.selected_branch_id.is_some()
    {
        let ineligibility_reason = context
            .candidate_branches
            .iter()
            .find(|candidate| candidate.id == branch_id)
            .and_then(|candidate| branch_ineligibility_reason(input, candidate));
        if let Some(reason) = ineligibility_reason {
            result.dropped_messages.push(dropped(message, reason));
        } else {
            result.deferred_messages.push(deferred(
                message,
                DeferredMessageReason::NonSelectedEligibleBranch,
            ));
        }
    } else if result.selected_tip.unwrap_or(input.state.current_tip_epoch) > message.source_epoch {
        // An unconsumed proposal cannot cross an epoch boundary. Once the
        // canonical tip advances past its source epoch it is terminal and must
        // not be prepended to every later candidate replay (#963).
        result.dropped_messages.push(dropped(
            message,
            DroppedMessageReason::InvalidAgainstCandidateState,
        ));
    } else {
        result.deferred_messages.push(deferred(
            message,
            DeferredMessageReason::AwaitingCanonicalCommit,
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
    already_delivered: bool,
) {
    // A message applied on a prior pass is re-admitted so it can witness its
    // branch again (see `attach_app_witnesses`). It must never be re-delivered,
    // but a later reorg still has to withdraw it when its branch loses (#965).
    if already_delivered {
        let selected_still_decrypts = result
            .selected_branch_id
            .as_ref()
            .is_some_and(|selected| decrypts_on_branches.contains(selected));
        if result.selected_branch_id.is_some()
            && !selected_still_decrypts
            && !decrypts_on_branches.is_empty()
        {
            result.invalidated_app_messages.push(invalidated_app(
                message,
                epoch,
                InvalidatedAppMessageReason::LosingBranch,
                decrypted_payload_ref,
            ));
        } else {
            result.already_seen.push(AlreadySeen {
                message_id: message.message_id.clone(),
                kind: message.kind_name(),
            });
        }
        return;
    }
    if epoch < input.state.retained_anchor_epoch {
        result.invalidated_app_messages.push(invalidated_app(
            message,
            epoch,
            InvalidatedAppMessageReason::BeyondAnchor,
            decrypted_payload_ref,
        ));
    } else if app_message_expired(input.state.current_tip_epoch, &input.policy, epoch) {
        // Delivery decisions use the canonical tip as the reference tip
        // (retained-history.md). Witness counting uses the candidate tip instead;
        // see attach_app_witnesses.
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
    } else if decrypts_on_branches.is_empty()
        && epoch > result.selected_tip.unwrap_or(input.state.current_tip_epoch)
    {
        result
            .deferred_messages
            .push(deferred(message, DeferredMessageReason::FutureEpoch));
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

fn classify_losing_materialized_candidate_commits(
    result: &mut CanonicalizationResult,
    input: &CanonicalizationInput,
    candidates: &[BranchCandidate],
    materialized_commit_ids_by_branch: &BTreeMap<String, BTreeSet<String>>,
) {
    let Some(selected_branch_id) = result.selected_branch_id.as_deref() else {
        return;
    };
    for (branch_id, commit_ids) in materialized_commit_ids_by_branch {
        if branch_id == selected_branch_id {
            continue;
        }
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.id == *branch_id);
        for message_id in commit_ids {
            if result.accepted_commits.contains(message_id)
                || result
                    .deferred_messages
                    .iter()
                    .any(|deferred| deferred.message_id == *message_id)
                || result
                    .dropped_messages
                    .iter()
                    .any(|dropped| dropped.message_id == *message_id)
            {
                continue;
            }
            let ineligibility_reason =
                candidate.and_then(|candidate| branch_ineligibility_reason(input, candidate));
            if candidate.is_some() && ineligibility_reason.is_none() {
                result.deferred_messages.push(DeferredMessage {
                    message_id: message_id.clone(),
                    kind: MessageKind::Commit,
                    reason: DeferredMessageReason::NonSelectedEligibleBranch,
                });
            } else {
                result.dropped_messages.push(DroppedMessage {
                    message_id: message_id.clone(),
                    kind: MessageKind::Commit,
                    reason: ineligibility_reason
                        .unwrap_or(DroppedMessageReason::BeyondRollbackHorizon),
                    rejection_category: None,
                });
            }
        }
    }
}

fn branch_ineligibility_reason(
    input: &CanonicalizationInput,
    candidate: &BranchCandidate,
) -> Option<DroppedMessageReason> {
    if candidate.fork_epoch < input.state.retained_anchor_epoch {
        Some(DroppedMessageReason::BeyondAnchor)
    } else if !is_branch_eligible(
        input.state.current_tip_epoch,
        candidate,
        &input.policy.convergence,
    ) {
        Some(DroppedMessageReason::BeyondRollbackHorizon)
    } else {
        None
    }
}

fn convergence_status_for_result(
    input: &CanonicalizationInput,
    input_messages: &[PeeledMessage],
    result: &CanonicalizationResult,
) -> ConvergenceStatus {
    let elapsed = input
        .now_ms
        .saturating_sub(input.state.last_convergence_relevant_input_ms);
    if elapsed < input.policy.settlement_quiescence_ms {
        return ConvergenceStatus::Syncing;
    }

    let resolved: BTreeSet<&str> = result
        .accepted_commits
        .iter()
        .map(String::as_str)
        .chain(result.accepted_proposals.iter().map(String::as_str))
        .chain(result.accepted_app_messages.iter().map(String::as_str))
        .chain(
            result
                .deferred_messages
                .iter()
                .map(|d| d.message_id.as_str()),
        )
        .chain(
            result
                .dropped_messages
                .iter()
                .map(|d| d.message_id.as_str()),
        )
        .chain(
            result
                .invalidated_app_messages
                .iter()
                .map(|i| i.message_id.as_str()),
        )
        .chain(result.already_seen.iter().map(|s| s.message_id.as_str()))
        .collect();

    let unresolved_input = input_messages
        .iter()
        .any(|message| !resolved.contains(message.message_id.as_str()));

    if unresolved_input {
        ConvergenceStatus::Resolving
    } else if has_blocking_convergence_error(result) {
        ConvergenceStatus::Blocked
    } else {
        ConvergenceStatus::Settled
    }
}

fn has_blocking_convergence_error(result: &CanonicalizationResult) -> bool {
    result.errors.iter().any(|error| {
        matches!(
            error,
            CanonicalizationError::MissingRetainedAnchor
                | CanonicalizationError::MissingOwnCommitCheckpoint
        )
    })
}

fn app_message_expired(
    reference_tip_epoch: u64,
    policy: &CanonicalizationPolicy,
    epoch: u64,
) -> bool {
    reference_tip_epoch.saturating_sub(epoch) > policy.app_message_past_epoch_limit
}

fn dropped(message: &PeeledMessage, reason: DroppedMessageReason) -> DroppedMessage {
    DroppedMessage {
        message_id: message.message_id.clone(),
        kind: message.kind_name(),
        reason,
        rejection_category: None,
    }
}

fn deferred(message: &PeeledMessage, reason: DeferredMessageReason) -> DeferredMessage {
    DeferredMessage {
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
        self.deferred_messages.sort();
        self.invalidated_app_messages.sort();
        self.dropped_messages.sort();
        self.already_seen.sort();
        self.queued_outbound_intents.sort();
        self.publishable_outbound_messages.sort();
        self.errors.sort();
    }
}

#[cfg(test)]
mod witness_window_tests {
    use super::*;

    #[test]
    fn v1_default_policy_constants_are_pinned() {
        use crate::convergence::{
            V1_MAX_REWIND_COMMITS, V1_MAX_WITNESS_OVERRIDE_DEPTH, V1_WITNESS_QUORUM_EPOCHS,
            V1_WITNESS_QUORUM_SENDERS_PER_EPOCH,
        };
        assert_eq!(
            CanonicalizationPolicy::default(),
            CanonicalizationPolicy {
                convergence: ConvergencePolicy {
                    max_rewind_commits: V1_MAX_REWIND_COMMITS,
                    witness_quorum_senders_per_epoch: V1_WITNESS_QUORUM_SENDERS_PER_EPOCH,
                    witness_quorum_epochs: V1_WITNESS_QUORUM_EPOCHS,
                    max_witness_override_depth: V1_MAX_WITNESS_OVERRIDE_DEPTH,
                },
                app_message_past_epoch_limit: V1_APP_MESSAGE_PAST_EPOCH_LIMIT,
                settlement_quiescence_ms: V1_SETTLEMENT_QUIESCENCE_MS,
                max_convergence_pass_ms: V1_MAX_CONVERGENCE_PASS_MS,
            }
        );
        assert!(CanonicalizationPolicy::default().ensure_pinned_v1().is_ok());
        assert_eq!(
            CanonicalizationPolicy {
                settlement_quiescence_ms: 0,
                ..CanonicalizationPolicy::default()
            }
            .ensure_pinned_v1(),
            Err(CanonicalizationPolicyError::NotPinnedV1)
        );
    }

    #[test]
    fn app_message_window_must_match_engine_max_past_epochs() {
        let policy = CanonicalizationPolicy::default();
        assert!(
            policy
                .ensure_app_window_matches(V1_APP_MESSAGE_PAST_EPOCH_LIMIT as usize)
                .is_ok()
        );
        assert_eq!(
            policy.ensure_app_window_matches(1),
            Err(CanonicalizationPolicyError::AppWindowMismatch {
                app_message_past_epoch_limit: V1_APP_MESSAGE_PAST_EPOCH_LIMIT,
                max_past_epochs: 1,
            })
        );
    }

    #[test]
    fn ensure_acceptable_requires_app_window_alignment() {
        let policy = CanonicalizationPolicy {
            app_message_past_epoch_limit: 1,
            ..CanonicalizationPolicy::default()
        };
        assert_eq!(
            policy.ensure_acceptable(V1_APP_MESSAGE_PAST_EPOCH_LIMIT as usize),
            Err(CanonicalizationPolicyError::AppWindowMismatch {
                app_message_past_epoch_limit: 1,
                max_past_epochs: V1_APP_MESSAGE_PAST_EPOCH_LIMIT,
            })
        );
        assert!(
            CanonicalizationPolicy::default()
                .ensure_acceptable(V1_APP_MESSAGE_PAST_EPOCH_LIMIT as usize)
                .is_ok()
        );
    }

    #[test]
    fn app_message_expired_is_relative_to_the_passed_reference_tip() {
        // app_message_expired must gate on the reference tip it is GIVEN, so the
        // witness path can pass the candidate's tip_epoch (not the global canonical
        // tip). limit = app_message_past_epoch_limit (pinned 5 by default).
        let policy = CanonicalizationPolicy::default();
        let limit = policy.app_message_past_epoch_limit;
        let epoch = 10;
        // Within the window for a near reference tip.
        assert!(!app_message_expired(epoch + limit, &policy, epoch));
        // Just outside the window for a farther reference tip.
        assert!(app_message_expired(epoch + limit + 1, &policy, epoch));
        // A nearer (candidate) reference tip can keep a message in-window even when
        // a farther (global) tip would expire it — the exact distinction this fix
        // restores for witness counting.
        let global_tip = epoch + limit + 5;
        let candidate_tip = epoch + 1;
        assert!(app_message_expired(global_tip, &policy, epoch));
        assert!(!app_message_expired(candidate_tip, &policy, epoch));
    }
}
