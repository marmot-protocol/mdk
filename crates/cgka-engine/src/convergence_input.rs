//! Role-aware classification for retained convergence inputs.
//!
//! Commits form candidate branches, proposals can satisfy commit dependencies,
//! and application messages can provide bounded witness evidence. Keeping
//! those roles explicit prevents an unresolved payload disposition from being
//! mistaken for ambiguous canonical group state.

use std::collections::{BTreeMap, BTreeSet};

use cgka_traits::convergence_pass::{ConvergencePassMember, ConvergencePassMemberRole};
use cgka_traits::message::MessageState;

use crate::openmls_projection::OpenMlsContentKind;

pub(crate) fn role_for_content_kind(kind: OpenMlsContentKind) -> Option<ConvergencePassMemberRole> {
    match kind {
        OpenMlsContentKind::Commit => Some(ConvergencePassMemberRole::CommitEdge),
        OpenMlsContentKind::Proposal => Some(ConvergencePassMemberRole::ProposalDependency),
        OpenMlsContentKind::Application => Some(ConvergencePassMemberRole::AppWitnessCandidate),
        OpenMlsContentKind::Welcome | OpenMlsContentKind::Other => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClassifiedConvergenceInput {
    pub(crate) role: ConvergencePassMemberRole,
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
            role: role_for_content_kind(kind)?,
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
        OUTBOUND_GATING_STATES.contains(&self.state)
    }
}

/// The stored message states in which a retained input can gate outbound
/// sends. `Engine::has_unresolved_convergence_inputs` passes this list to an
/// indexed storage existence probe before paying a full list-and-decode scan;
/// defining [`ClassifiedConvergenceInput::can_gate_outbound`] in terms of the
/// same constant keeps the fast path and the classifier in lockstep.
pub(crate) const OUTBOUND_GATING_STATES: [MessageState; 2] =
    [MessageState::Created, MessageState::Retryable];

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
            if input.role == ConvergencePassMemberRole::CommitEdge {
                context
                    .commit_edges_by_source_epoch
                    .entry(input.source_epoch)
                    .or_default()
                    .insert(input.digest);
            }
        }
        context
    }

    pub(crate) fn from_pass_members<'a>(
        members: impl IntoIterator<Item = &'a ConvergencePassMember>,
    ) -> Self {
        let mut context = Self::default();
        for member in members {
            if member.role == ConvergencePassMemberRole::CommitEdge {
                context
                    .commit_edges_by_source_epoch
                    .entry(member.source_epoch)
                    .or_default()
                    .insert(member.payload_digest);
            }
        }
        context
    }

    #[cfg(test)]
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
    ///
    /// Test-only since pass admission moved to [`scan_selection_relevance`]:
    /// this stays as the map-based oracle the parity test compares against.
    #[cfg(test)]
    pub(crate) fn is_potentially_selection_relevant(
        &self,
        input: ClassifiedConvergenceInput,
    ) -> bool {
        match input.role {
            ConvergencePassMemberRole::CommitEdge => true,
            ConvergencePassMemberRole::ProposalDependency => self.has_commit_at(input.source_epoch),
            ConvergencePassMemberRole::AppWitnessCandidate => {
                self.has_competing_commit_before(input.source_epoch)
            }
        }
    }

    pub(crate) fn opens_pass(&self, input: ClassifiedConvergenceInput) -> bool {
        input.can_start_pass()
            && match input.role {
                ConvergencePassMemberRole::CommitEdge => true,
                ConvergencePassMemberRole::ProposalDependency => false,
                ConvergencePassMemberRole::AppWitnessCandidate => {
                    self.has_competing_commit_before(input.source_epoch)
                }
            }
    }

    pub(crate) fn gates_outbound(&self, input: ClassifiedConvergenceInput) -> bool {
        input.can_gate_outbound()
            && match input.role {
                ConvergencePassMemberRole::CommitEdge => true,
                ConvergencePassMemberRole::ProposalDependency => false,
                ConvergencePassMemberRole::AppWitnessCandidate => {
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
    pub(crate) fn active_pass_member_gates_outbound(&self, member: &ConvergencePassMember) -> bool {
        match member.role {
            ConvergencePassMemberRole::CommitEdge => true,
            ConvergencePassMemberRole::ProposalDependency => false,
            ConvergencePassMemberRole::AppWitnessCandidate => {
                self.has_competing_commit_before(member.source_epoch)
            }
        }
    }
}

/// One input's [`ConvergenceInputContext::is_potentially_selection_relevant`]
/// verdict in a single member scan, without materializing the commit-edge
/// map. Pass admission answers exactly one input per call, so building the
/// full context there is wasted work; equivalence with the context-based
/// verdict is pinned by `scan_relevance_matches_context_relevance`.
pub(crate) fn scan_selection_relevance(
    members: &[ConvergencePassMember],
    input: ClassifiedConvergenceInput,
) -> bool {
    use std::collections::hash_map::Entry;

    match input.role {
        ConvergencePassMemberRole::CommitEdge => true,
        ConvergencePassMemberRole::ProposalDependency => members.iter().any(|member| {
            member.role == ConvergencePassMemberRole::CommitEdge
                && member.source_epoch == input.source_epoch
        }),
        ConvergencePassMemberRole::AppWitnessCandidate => {
            // Competing commit edges strictly before the witness epoch: two
            // distinct digests sharing one source epoch. Short-circuits on
            // the first competing pair.
            let mut first_digest_by_epoch = std::collections::HashMap::new();
            for member in members {
                if member.role != ConvergencePassMemberRole::CommitEdge
                    || member.source_epoch >= input.source_epoch
                {
                    continue;
                }
                match first_digest_by_epoch.entry(member.source_epoch) {
                    Entry::Vacant(entry) => {
                        entry.insert(member.payload_digest);
                    }
                    Entry::Occupied(entry) => {
                        if *entry.get() != member.payload_digest {
                            return true;
                        }
                    }
                }
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::types::MessageId;

    fn member(
        role: ConvergencePassMemberRole,
        source_epoch: u64,
        digest_byte: u8,
    ) -> ConvergencePassMember {
        ConvergencePassMember {
            message_id: MessageId::new(vec![digest_byte; 32]),
            payload_digest: [digest_byte; 32],
            role,
            source_epoch,
        }
    }

    #[test]
    fn scan_relevance_matches_context_relevance() {
        use ConvergencePassMemberRole::*;

        // Competing commits at epoch 1, a lone commit at epoch 3, a proposal
        // and an app scattered around them.
        let member_sets: Vec<Vec<ConvergencePassMember>> = vec![
            vec![],
            vec![member(CommitEdge, 1, 1)],
            vec![member(CommitEdge, 1, 1), member(CommitEdge, 1, 2)],
            vec![
                member(CommitEdge, 1, 1),
                member(CommitEdge, 1, 2),
                member(CommitEdge, 3, 3),
                member(ProposalDependency, 1, 4),
                member(AppWitnessCandidate, 2, 5),
            ],
            // Duplicate digest at one epoch is one edge, not a competition.
            vec![member(CommitEdge, 2, 6), member(CommitEdge, 2, 6)],
        ];

        for members in &member_sets {
            let context = ConvergenceInputContext::from_pass_members(members);
            for role in [CommitEdge, ProposalDependency, AppWitnessCandidate] {
                for source_epoch in 0..=4 {
                    let candidate = input(role, source_epoch, MessageState::Created, 9);
                    assert_eq!(
                        scan_selection_relevance(members, candidate),
                        context.is_potentially_selection_relevant(candidate),
                        "verdicts diverge for {role:?} at epoch {source_epoch} over {members:?}"
                    );
                }
            }
        }
    }

    fn input(
        role: ConvergencePassMemberRole,
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
    fn outbound_gating_states_stay_in_lockstep_with_the_classifier() {
        // The indexed send-gate fast path prunes on `OUTBOUND_GATING_STATES`
        // before the full scan runs `can_gate_outbound`; a state that gates in
        // the classifier but is missing from the constant would make the fast
        // path silently unblock sends.
        for state in [
            MessageState::Sent,
            MessageState::Created,
            MessageState::Processed,
            MessageState::Failed,
            MessageState::Retryable,
            MessageState::EpochInvalidated,
            MessageState::PeelDeferred,
            MessageState::ConvergenceDeferred,
        ] {
            let classified = input(ConvergencePassMemberRole::CommitEdge, 1, state, 1);
            assert_eq!(
                classified.can_gate_outbound(),
                OUTBOUND_GATING_STATES.contains(&state),
                "{state:?} disagrees between can_gate_outbound and OUTBOUND_GATING_STATES"
            );
        }
    }

    #[test]
    fn future_app_without_a_candidate_branch_is_delivery_only_for_scheduling() {
        let app = input(
            ConvergencePassMemberRole::AppWitnessCandidate,
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
            ConvergencePassMemberRole::CommitEdge,
            1,
            MessageState::Created,
            1,
        );
        let second = input(
            ConvergencePassMemberRole::CommitEdge,
            1,
            MessageState::Created,
            2,
        );
        let app = input(
            ConvergencePassMemberRole::AppWitnessCandidate,
            2,
            MessageState::Created,
            3,
        );
        let context = ConvergenceInputContext::from_inputs([first, second, app]);

        assert!(context.opens_pass(app));
        assert!(context.gates_outbound(app));
        assert!(context.is_potentially_selection_relevant(app));
        let member = ConvergencePassMember {
            message_id: cgka_traits::MessageId::new(vec![3]),
            payload_digest: app.digest,
            role: app.role,
            source_epoch: app.source_epoch,
        };
        assert!(context.active_pass_member_gates_outbound(&member));
    }

    #[test]
    fn proposal_only_becomes_potentially_relevant_beside_same_epoch_commit() {
        let commit = input(
            ConvergencePassMemberRole::CommitEdge,
            4,
            MessageState::Created,
            1,
        );
        let proposal = input(
            ConvergencePassMemberRole::ProposalDependency,
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
    fn no_input_opens_a_pass_without_a_commit_edge_to_gate_outbound_work() {
        // The reachability premise behind `discard_stale_convergence_pass`: an
        // open pass always holds at least one `CommitEdge` member, and a
        // `CommitEdge` member gates outbound work unconditionally (pinned by
        // `processed_commit_still_gates_while_its_durable_pass_is_active`).
        // Together those mean the tip cannot advance underneath an open pass, so
        // a pass whose base epoch disagrees with the tip is inherited scheduling
        // state rather than a live transition.
        for role in [
            ConvergencePassMemberRole::ProposalDependency,
            ConvergencePassMemberRole::AppWitnessCandidate,
        ] {
            for state in [
                MessageState::Sent,
                MessageState::Created,
                MessageState::Retryable,
                MessageState::ConvergenceDeferred,
            ] {
                let non_edge = input(role, 3, state, 1);
                let context = ConvergenceInputContext::from_inputs([non_edge]);

                assert!(
                    !context.opens_pass(non_edge),
                    "{role:?}/{state:?} opened a pass with no commit edge to gate outbound work"
                );
            }
        }
    }

    #[test]
    fn convergence_deferred_commit_is_context_but_not_a_fresh_trigger() {
        let deferred = input(
            ConvergencePassMemberRole::CommitEdge,
            3,
            MessageState::ConvergenceDeferred,
            1,
        );
        let fresh = input(
            ConvergencePassMemberRole::CommitEdge,
            3,
            MessageState::Created,
            2,
        );
        let context = ConvergenceInputContext::from_inputs([deferred, fresh]);

        assert!(!context.opens_pass(deferred));
        assert!(!context.gates_outbound(deferred));
        assert!(context.opens_pass(fresh));
        assert!(context.gates_outbound(fresh));
    }

    #[test]
    fn processed_commit_still_gates_while_its_durable_pass_is_active() {
        let commit = input(
            ConvergencePassMemberRole::CommitEdge,
            7,
            MessageState::Processed,
            1,
        );
        let context = ConvergenceInputContext::from_inputs([commit]);

        assert!(!context.gates_outbound(commit));
        let member = ConvergencePassMember {
            message_id: cgka_traits::MessageId::new(vec![1]),
            payload_digest: commit.digest,
            role: commit.role,
            source_epoch: commit.source_epoch,
        };
        assert!(context.active_pass_member_gates_outbound(&member));
    }
}
