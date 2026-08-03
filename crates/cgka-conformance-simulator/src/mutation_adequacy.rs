//! Deterministic semantic mutation sentinels for the convergence contract.
//!
//! Mutants live only in this simulator module. Each one changes exactly one
//! rule over a minimal input, then records whether the adopted behavior differs.
//! Production code is never compiled with a mutation feature.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::lifecycle_model::{LifecycleActionKind, LifecycleModel, LifecycleState, PassPhase};
use crate::reference_convergence::{
    ReferenceCandidate, ReferencePolicy, ReferencePriority, ReferenceScore, ReferenceWitness,
    score, select,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticMutation {
    SelectorComparisonOrder,
    WitnessSenderEpochDeduplication,
    AppWitnessAdmissionRemoval,
    CutoffBoundaryAdmission,
    FrozenMemberPersistence,
    SchedulerDeadlineRearm,
    OutputInvalidation,
    PublicationAcknowledgement,
    RetainedHistoryExpirationBoundary,
}

impl SemanticMutation {
    pub const ALL: [Self; 9] = [
        Self::SelectorComparisonOrder,
        Self::WitnessSenderEpochDeduplication,
        Self::AppWitnessAdmissionRemoval,
        Self::CutoffBoundaryAdmission,
        Self::FrozenMemberPersistence,
        Self::SchedulerDeadlineRearm,
        Self::OutputInvalidation,
        Self::PublicationAcknowledgement,
        Self::RetainedHistoryExpirationBoundary,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::SelectorComparisonOrder => "selector_comparison_order",
            Self::WitnessSenderEpochDeduplication => "witness_sender_epoch_deduplication",
            Self::AppWitnessAdmissionRemoval => "app_witness_admission_removal",
            Self::CutoffBoundaryAdmission => "cutoff_boundary_admission",
            Self::FrozenMemberPersistence => "frozen_member_persistence",
            Self::SchedulerDeadlineRearm => "scheduler_deadline_rearm",
            Self::OutputInvalidation => "output_invalidation",
            Self::PublicationAcknowledgement => "publication_acknowledgement",
            Self::RetainedHistoryExpirationBoundary => "retained_history_expiration_boundary",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationSentinelResult {
    pub mutation: SemanticMutation,
    pub baseline_observation: String,
    pub mutant_observation: String,
}

impl MutationSentinelResult {
    pub fn killed(&self) -> bool {
        self.baseline_observation != self.mutant_observation
    }
}

pub fn run_all_mutation_sentinels() -> Vec<MutationSentinelResult> {
    SemanticMutation::ALL
        .into_iter()
        .map(run_mutation_sentinel)
        .collect()
}

pub fn run_mutation_sentinel(mutation: SemanticMutation) -> MutationSentinelResult {
    let (baseline_observation, mutant_observation) = match mutation {
        SemanticMutation::SelectorComparisonOrder => selector_order_sentinel(),
        SemanticMutation::WitnessSenderEpochDeduplication => witness_dedup_sentinel(),
        SemanticMutation::AppWitnessAdmissionRemoval => witness_admission_sentinel(),
        SemanticMutation::CutoffBoundaryAdmission => cutoff_sentinel(),
        SemanticMutation::FrozenMemberPersistence => frozen_persistence_sentinel(),
        SemanticMutation::SchedulerDeadlineRearm => scheduler_rearm_sentinel(),
        SemanticMutation::OutputInvalidation => output_invalidation_sentinel(),
        SemanticMutation::PublicationAcknowledgement => publication_ack_sentinel(),
        SemanticMutation::RetainedHistoryExpirationBoundary => expiration_sentinel(),
    };
    MutationSentinelResult {
        mutation,
        baseline_observation,
        mutant_observation,
    }
}

fn candidate(id: &str, depth: u64, digest: u8) -> ReferenceCandidate {
    ReferenceCandidate {
        id: id.into(),
        fork_epoch: 1,
        tip_epoch: 1 + depth,
        tip_priority: ReferencePriority::Ordinary,
        tip_committer: b"alice".to_vec(),
        tip_digest: [digest; 32],
        app_witnesses: Vec::new(),
    }
}

fn selected(candidates: &[ReferenceCandidate], policy: &ReferencePolicy) -> String {
    let refs: Vec<&ReferenceCandidate> = candidates.iter().collect();
    select(6, &refs, policy)
        .map(|candidate| candidate.id.clone())
        .unwrap_or_else(|| "none".into())
}

fn selector_order_sentinel() -> (String, String) {
    let policy = ReferencePolicy {
        witness_quorum_senders_per_epoch: 2,
        witness_quorum_epochs: 1,
        max_witness_override_depth: 1,
        ..ReferencePolicy::default()
    };
    let mut witnessed = candidate("witnessed", 1, 0xff);
    witnessed.app_witnesses = vec![
        ReferenceWitness {
            epoch: 2,
            sender: b"alice".to_vec(),
        },
        ReferenceWitness {
            epoch: 2,
            sender: b"bob".to_vec(),
        },
    ];
    let deeper = candidate("deeper", 2, 0x00);
    let candidates = vec![witnessed, deeper];
    let baseline = selected(&candidates, &policy);
    let mutant = candidates
        .iter()
        .max_by(|a, b| {
            // Mutant: raw depth is incorrectly compared before effective depth.
            a.tip_epoch
                .saturating_sub(a.fork_epoch)
                .cmp(&b.tip_epoch.saturating_sub(b.fork_epoch))
                .then_with(|| compare_reference_scores(&score(a, &policy), &score(b, &policy)))
        })
        .unwrap()
        .id
        .clone();
    (baseline, mutant)
}

fn witness_dedup_sentinel() -> (String, String) {
    let policy = ReferencePolicy::default();
    let mut repeated = candidate("repeated", 1, 0xff);
    repeated.app_witnesses = vec![
        ReferenceWitness {
            epoch: 2,
            sender: b"alice".to_vec(),
        },
        ReferenceWitness {
            epoch: 2,
            sender: b"alice".to_vec(),
        },
    ];
    let deeper = candidate("deeper", 2, 0x00);
    let baseline = selected(&[repeated.clone(), deeper.clone()], &policy);
    let mutant_quorum = repeated.app_witnesses.len()
        >= policy.witness_quorum_senders_per_epoch * policy.witness_quorum_epochs;
    let mutant = if mutant_quorum {
        repeated.id
    } else {
        deeper.id
    };
    (baseline, mutant)
}

fn witness_admission_sentinel() -> (String, String) {
    let policy = ReferencePolicy::default();
    let mut witnessed = candidate("witnessed", 1, 0xff);
    witnessed.app_witnesses = vec![
        ReferenceWitness {
            epoch: 2,
            sender: b"alice".to_vec(),
        },
        ReferenceWitness {
            epoch: 2,
            sender: b"bob".to_vec(),
        },
    ];
    let deeper = candidate("deeper", 2, 0x00);
    let baseline = selected(&[witnessed.clone(), deeper.clone()], &policy);
    witnessed.app_witnesses.clear();
    let mutant = selected(&[witnessed, deeper], &policy);
    (baseline, mutant)
}

fn cutoff_sentinel() -> (String, String) {
    let policy = ReferencePolicy::default();
    let boundary = candidate("exact-boundary", 1, 0);
    let baseline = selected(std::slice::from_ref(&boundary), &policy);
    let mutant_eligible = 6u64.saturating_sub(boundary.fork_epoch) < policy.max_rewind_commits;
    let mutant = if mutant_eligible {
        boundary.id
    } else {
        "none".into()
    };
    (baseline, mutant)
}

fn frozen_persistence_sentinel() -> (String, String) {
    let model = LifecycleModel {
        fair_after_input_closure: false,
    };
    let mut state = LifecycleState {
        history_a: 2,
        history_b: 2,
        ..LifecycleState::default()
    };
    state = model
        .next_state(&state, LifecycleActionKind::FreezePass)
        .unwrap();
    state = model
        .next_state(&state, LifecycleActionKind::Crash)
        .unwrap();
    state = model
        .next_state(&state, LifecycleActionKind::Restart)
        .unwrap();
    let baseline = format!("{:?}:{:?}", state.phase, state.frozen_revision);
    let mutant = format!("{:?}:{:?}", PassPhase::Collecting, Option::<u8>::None);
    (baseline, mutant)
}

#[derive(Clone, Copy)]
struct SchedulerState {
    input_revision: u8,
    armed_revision: Option<u8>,
}

fn scheduler_rearm_sentinel() -> (String, String) {
    let settled = SchedulerState {
        input_revision: 1,
        armed_revision: None,
    };
    let new_input_revision = settled.input_revision + 1;
    let baseline = SchedulerState {
        input_revision: new_input_revision,
        armed_revision: Some(new_input_revision),
    };
    let mutant = SchedulerState {
        input_revision: new_input_revision,
        // Mutant: a settled pass suppresses re-arm for genuinely new input.
        armed_revision: settled.armed_revision,
    };
    (
        format!("armed:{:?}", baseline.armed_revision),
        format!("armed:{:?}", mutant.armed_revision),
    )
}

fn output_invalidation_sentinel() -> (String, String) {
    let projected = vec![("losing", "payload"), ("winner", "payload-2")];
    let baseline: Vec<_> = projected
        .iter()
        .filter(|(branch, _)| *branch == "winner")
        .copied()
        .collect();
    let mutant = projected;
    (format!("{baseline:?}"), format!("{mutant:?}"))
}

fn publication_ack_sentinel() -> (String, String) {
    let pending = vec!["outbound-1"];
    let baseline: Vec<&str> = pending
        .iter()
        .copied()
        .filter(|id| *id != "outbound-1")
        .collect();
    let mutant = pending;
    (format!("{baseline:?}"), format!("{mutant:?}"))
}

fn expiration_sentinel() -> (String, String) {
    let reference_tip = 6u64;
    let message_epoch = 1u64;
    let limit = 5u64;
    let baseline_expired = reference_tip.saturating_sub(message_epoch) > limit;
    let mutant_expired = reference_tip.saturating_sub(message_epoch) >= limit;
    (
        format!("expired:{baseline_expired}"),
        format!("expired:{mutant_expired}"),
    )
}

fn compare_reference_scores(a: &ReferenceScore, b: &ReferenceScore) -> Ordering {
    a.effective_commit_depth
        .cmp(&b.effective_commit_depth)
        .then_with(|| a.witness_quorum_met.cmp(&b.witness_quorum_met))
        .then_with(|| a.app_witness_score.cmp(&b.app_witness_score))
        .then_with(|| b.tip_priority.cmp(&a.tip_priority))
        .then_with(|| b.tip_committer.cmp(&a.tip_committer))
        .then_with(|| b.tip_digest.cmp(&a.tip_digest))
}
