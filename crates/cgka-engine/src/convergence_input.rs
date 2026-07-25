//! Role-aware classification for retained convergence inputs.
//!
//! Commits form candidate branches, proposals can satisfy commit dependencies,
//! and application messages can provide bounded witness evidence. Keeping
//! those roles explicit prevents an unresolved payload disposition from being
//! mistaken for ambiguous canonical group state.

use std::collections::{BTreeMap, BTreeSet};

use cgka_traits::message::MessageState;

use crate::openmls_projection::OpenMlsContentKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConvergenceInputRole {
    CommitEdge,
    ProposalDependency,
    AppWitnessCandidate,
}

impl ConvergenceInputRole {
    pub(crate) fn for_content_kind(kind: OpenMlsContentKind) -> Option<Self> {
        match kind {
            OpenMlsContentKind::Commit => Some(Self::CommitEdge),
            OpenMlsContentKind::Proposal => Some(Self::ProposalDependency),
            OpenMlsContentKind::Application => Some(Self::AppWitnessCandidate),
            OpenMlsContentKind::Welcome | OpenMlsContentKind::Other => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClassifiedConvergenceInput {
    pub(crate) role: ConvergenceInputRole,
    pub(crate) source_epoch: u64,
    pub(crate) state: MessageState,
    pub(crate) digest: [u8; 32],
}

impl ClassifiedConvergenceInput {
    pub(crate) fn from_projection(
        kind: OpenMlsContentKind,
        source_epoch: u64,
        state: MessageState,
        digest: [u8; 32],
    ) -> Option<Self> {
        Some(Self {
            role: ConvergenceInputRole::for_content_kind(kind)?,
            source_epoch,
            state,
            digest,
        })
    }

    fn can_start_pass(self) -> bool {
        matches!(
            self.state,
            MessageState::Sent | MessageState::Created | MessageState::Retryable
        )
    }

    fn can_gate_outbound(self) -> bool {
        matches!(self.state, MessageState::Created | MessageState::Retryable)
    }
}

#[derive(Default)]
pub(crate) struct ConvergenceInputContext {
    commit_edges_by_source_epoch: BTreeMap<u64, BTreeSet<[u8; 32]>>,
}

impl ConvergenceInputContext {
    pub(crate) fn from_inputs(
        inputs: impl IntoIterator<Item = ClassifiedConvergenceInput>,
    ) -> Self {
        let mut context = Self::default();
        for input in inputs {
            if input.role == ConvergenceInputRole::CommitEdge {
                context
                    .commit_edges_by_source_epoch
                    .entry(input.source_epoch)
                    .or_default()
                    .insert(input.digest);
            }
        }
        context
    }

    fn has_commit_at(&self, source_epoch: u64) -> bool {
        self.commit_edges_by_source_epoch
            .get(&source_epoch)
            .is_some_and(|edges| !edges.is_empty())
    }

    fn has_competing_commit_before(&self, source_epoch: u64) -> bool {
        self.commit_edges_by_source_epoch
            .range(..source_epoch)
            .any(|(_, edges)| edges.len() > 1)
    }

    /// Whether admitting this input can change deterministic resolution of the
    /// current batch.
    ///
    /// An application message is only potentially selection-relevant when the
    /// frozen inputs contain competing commit edges from an earlier epoch.  A
    /// proposal is only potentially relevant when a commit at the same source
    /// epoch may depend on it. Authentication and actual dependency/witness
    /// contribution are still proven by OpenMLS during frozen resolution.
    pub(crate) fn is_potentially_selection_relevant(
        &self,
        input: ClassifiedConvergenceInput,
    ) -> bool {
        match input.role {
            ConvergenceInputRole::CommitEdge => true,
            ConvergenceInputRole::ProposalDependency => self.has_commit_at(input.source_epoch),
            ConvergenceInputRole::AppWitnessCandidate => {
                self.has_competing_commit_before(input.source_epoch)
            }
        }
    }

    pub(crate) fn opens_pass(&self, input: ClassifiedConvergenceInput) -> bool {
        input.can_start_pass()
            && match input.role {
                ConvergenceInputRole::CommitEdge => true,
                ConvergenceInputRole::ProposalDependency => false,
                ConvergenceInputRole::AppWitnessCandidate => {
                    self.has_competing_commit_before(input.source_epoch)
                }
            }
    }

    pub(crate) fn gates_outbound(&self, input: ClassifiedConvergenceInput) -> bool {
        input.can_gate_outbound()
            && match input.role {
                ConvergenceInputRole::CommitEdge => true,
                ConvergenceInputRole::ProposalDependency => false,
                ConvergenceInputRole::AppWitnessCandidate => {
                    self.has_competing_commit_before(input.source_epoch)
                }
            }
    }

    /// Whether a member of an already-active pass keeps outbound work gated.
    ///
    /// Pass membership, not the mutable message disposition, is authoritative
    /// here. A crash can leave a frozen/resolving pass after an accepted commit
    /// record has already moved to `Processed`; outbound work must still wait
    /// until the durable pass reaches `Completed`.
    pub(crate) fn active_pass_member_gates_outbound(
        &self,
        input: ClassifiedConvergenceInput,
    ) -> bool {
        match input.role {
            ConvergenceInputRole::CommitEdge => true,
            ConvergenceInputRole::ProposalDependency => false,
            ConvergenceInputRole::AppWitnessCandidate => {
                self.has_competing_commit_before(input.source_epoch)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(
        role: ConvergenceInputRole,
        source_epoch: u64,
        state: MessageState,
        digest_byte: u8,
    ) -> ClassifiedConvergenceInput {
        ClassifiedConvergenceInput {
            role,
            source_epoch,
            state,
            digest: [digest_byte; 32],
        }
    }

    #[test]
    fn future_app_without_a_candidate_branch_is_delivery_only_for_scheduling() {
        let app = input(
            ConvergenceInputRole::AppWitnessCandidate,
            2,
            MessageState::Created,
            1,
        );
        let context = ConvergenceInputContext::from_inputs([app]);

        assert!(!context.opens_pass(app));
        assert!(!context.gates_outbound(app));
        assert!(!context.is_potentially_selection_relevant(app));
    }

    #[test]
    fn app_after_competing_edges_is_a_selection_relevant_witness_candidate() {
        let first = input(
            ConvergenceInputRole::CommitEdge,
            1,
            MessageState::Created,
            1,
        );
        let second = input(
            ConvergenceInputRole::CommitEdge,
            1,
            MessageState::Created,
            2,
        );
        let app = input(
            ConvergenceInputRole::AppWitnessCandidate,
            2,
            MessageState::Created,
            3,
        );
        let context = ConvergenceInputContext::from_inputs([first, second, app]);

        assert!(context.opens_pass(app));
        assert!(context.gates_outbound(app));
        assert!(context.is_potentially_selection_relevant(app));
        assert!(context.active_pass_member_gates_outbound(app));
    }

    #[test]
    fn proposal_only_becomes_potentially_relevant_beside_same_epoch_commit() {
        let commit = input(
            ConvergenceInputRole::CommitEdge,
            4,
            MessageState::Created,
            1,
        );
        let proposal = input(
            ConvergenceInputRole::ProposalDependency,
            4,
            MessageState::Created,
            2,
        );
        let context = ConvergenceInputContext::from_inputs([commit, proposal]);

        assert!(context.is_potentially_selection_relevant(proposal));
        assert!(!context.opens_pass(proposal));
        assert!(!context.gates_outbound(proposal));
    }

    #[test]
    fn processed_commit_still_gates_while_its_durable_pass_is_active() {
        let commit = input(
            ConvergenceInputRole::CommitEdge,
            7,
            MessageState::Processed,
            1,
        );
        let context = ConvergenceInputContext::from_inputs([commit]);

        assert!(!context.gates_outbound(commit));
        assert!(context.active_pass_member_gates_outbound(commit));
    }
}
