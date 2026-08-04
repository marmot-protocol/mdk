//! Deterministic semantic mutation sentinels for the convergence contract.
//!
//! Mutants live only in this simulator module. Each one changes exactly one
//! rule over a minimal input, then records whether the adopted behavior differs.
//! Production code is never compiled with a mutation feature.

use serde::{Deserialize, Serialize};

use crate::lifecycle_model::{
    DecisionRouteKind, LifecycleActionKind, LifecycleModel, LifecycleMutation, LifecycleState,
    PassPhase, RouteBranch, RouteLifecycleState,
};
use crate::reference_convergence::{
    ReferenceAppMessage, ReferenceCandidate, ReferenceDisposition, ReferenceInput, ReferencePolicy,
    ReferencePriority, ReferenceWitness, WitnessMode, compare, evaluate, score, select,
};
use crate::{
    ConvergenceSubject, ReferenceModelSubject, SubjectCreateGroup, SubjectOutboundOutcome,
};

macro_rules! semantic_mutations {
    ($( $variant:ident => $id:literal ),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum SemanticMutation {
            $( $variant, )+
        }

        impl SemanticMutation {
            /// Complete catalog generated from the same declaration as the enum.
            pub const ALL: &'static [Self] = &[
                $( Self::$variant, )+
            ];

            pub const fn id(self) -> &'static str {
                match self {
                    $( Self::$variant => $id, )+
                }
            }
        }
    };
}

semantic_mutations! {
    SelectorComparisonOrder => "selector_comparison_order",
    WitnessSenderEpochDeduplication => "witness_sender_epoch_deduplication",
    AppWitnessAdmissionRemoval => "app_witness_admission_removal",
    CutoffBoundaryAdmission => "cutoff_boundary_admission",
    FrozenMemberPersistence => "frozen_member_persistence",
    SchedulerDeadlineRearm => "scheduler_deadline_rearm",
    OutputInvalidation => "output_invalidation",
    PublicationAcknowledgement => "publication_acknowledgement",
    RetainedHistoryExpirationBoundary => "retained_history_expiration_boundary",
    PairwiseLosingBranchTerminalization => "pairwise_losing_branch_terminalization",
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

pub async fn run_all_mutation_sentinels() -> Vec<MutationSentinelResult> {
    let mut results = Vec::with_capacity(SemanticMutation::ALL.len());
    for mutation in SemanticMutation::ALL.iter().copied() {
        results.push(run_mutation_sentinel(mutation).await);
    }
    results
}

pub async fn run_mutation_sentinel(mutation: SemanticMutation) -> MutationSentinelResult {
    let (baseline_observation, mutant_observation) = match mutation {
        SemanticMutation::SelectorComparisonOrder => selector_order_sentinel(),
        SemanticMutation::WitnessSenderEpochDeduplication => witness_dedup_sentinel(),
        SemanticMutation::AppWitnessAdmissionRemoval => witness_admission_sentinel(),
        SemanticMutation::CutoffBoundaryAdmission => cutoff_sentinel(),
        SemanticMutation::FrozenMemberPersistence => frozen_persistence_sentinel(),
        SemanticMutation::SchedulerDeadlineRearm => scheduler_rearm_sentinel(),
        SemanticMutation::OutputInvalidation => output_invalidation_sentinel(),
        SemanticMutation::PublicationAcknowledgement => publication_ack_sentinel().await,
        SemanticMutation::RetainedHistoryExpirationBoundary => expiration_sentinel(),
        SemanticMutation::PairwiseLosingBranchTerminalization => {
            pairwise_loser_terminalization_sentinel()
        }
    };
    MutationSentinelResult {
        mutation,
        baseline_observation,
        mutant_observation,
    }
}

fn pairwise_loser_terminalization_sentinel() -> (String, String) {
    let routed = RouteLifecycleState::new(vec![
        RouteBranch {
            id: 1,
            effective_depth: 1,
            ordering_key: 0,
        },
        RouteBranch {
            id: 2,
            effective_depth: 2,
            ordering_key: 1,
        },
    ])
    .observe_route(DecisionRouteKind::PairwiseForkRecovery, Some(1));
    let baseline = routed.clone().settle().canonical_winner;
    let mutant = routed
        .settle_with_terminal_pairwise_loser()
        .canonical_winner;
    (format!("winner:{baseline:?}"), format!("winner:{mutant:?}"))
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
                .then_with(|| compare(&score(a, &policy), &score(b, &policy)))
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
    let state = LifecycleState {
        history_a: 2,
        history_b: 2,
        input_open: false,
        crash_budget: 1,
        ..LifecycleState::default()
    };
    let frozen = model
        .next_state(&state, LifecycleActionKind::FreezePass)
        .unwrap();
    let baseline_crashed = model
        .next_state(&frozen, LifecycleActionKind::Crash)
        .unwrap();
    let baseline = model
        .next_state(&baseline_crashed, LifecycleActionKind::Restart)
        .unwrap();
    let mutant_crashed = model
        .next_state_with_mutation(
            &frozen,
            LifecycleActionKind::Crash,
            LifecycleMutation::LoseDurableFrozenRevisionOnCrash,
        )
        .unwrap();
    let mutant = model
        .next_state(&mutant_crashed, LifecycleActionKind::Restart)
        .unwrap();
    (
        format!(
            "phase:{:?}:durable:{:?}:staged:{:?}",
            baseline.phase, baseline.frozen_revision, baseline.staged_revision
        ),
        format!(
            "phase:{:?}:durable:{:?}:staged:{:?}",
            mutant.phase, mutant.frozen_revision, mutant.staged_revision
        ),
    )
}

fn scheduler_rearm_sentinel() -> (String, String) {
    let model = LifecycleModel {
        fair_after_input_closure: false,
    };
    let settled = LifecycleState {
        history_a: 2,
        history_b: 2,
        input_open: true,
        phase: PassPhase::Settled,
        frozen_revision: Some(2),
        staged_revision: Some(2),
        admin_pending: false,
        admin_applied: true,
        ..LifecycleState::default()
    };
    let baseline = model
        .next_state(&settled, LifecycleActionKind::SelfUpdate)
        .expect("new convergence input reopens collection");
    let mutant = model
        .next_state_with_mutation(
            &settled,
            LifecycleActionKind::SelfUpdate,
            LifecycleMutation::SuppressRearmAfterSettlement,
        )
        .expect("mutated transition consumes new input without re-arming");
    (
        format!(
            "phase:{:?}:frozen:{:?}",
            baseline.phase, baseline.frozen_revision
        ),
        format!(
            "phase:{:?}:frozen:{:?}",
            mutant.phase, mutant.frozen_revision
        ),
    )
}

fn output_invalidation_sentinel() -> (String, String) {
    let input = ReferenceInput {
        current_tip_epoch: 3,
        retained_anchor_epoch: 1,
        candidates: vec![candidate("winner", 2, 0), candidate("losing", 1, 1)],
        commits: Vec::new(),
        proposals: Vec::new(),
        app_messages: vec![ReferenceAppMessage {
            message_id: "losing-output".into(),
            sender: b"alice".to_vec(),
            epoch: 2,
            decrypts_on_branches: vec!["losing".into()],
            authenticated: true,
            authorized: true,
        }],
        policy: ReferencePolicy::default(),
        witness_mode: WitnessMode::Disabled,
    };
    let baseline = evaluate(&input).dispositions["losing-output"];
    let mutant = ReferenceDisposition::Accepted;
    (format!("{baseline:?}"), format!("{mutant:?}"))
}

async fn publication_ack_observation(acknowledge: bool) -> String {
    let clients = vec!["alice".to_owned(), "bob".to_owned()];
    let invitees = vec!["bob".to_owned()];
    let initial_admins = vec!["alice".to_owned()];
    let mut subject = ReferenceModelSubject::new(&clients).expect("reference subject");
    subject
        .create_group(SubjectCreateGroup {
            action_id: "mutation-step-0:create_group",
            creator: "alice",
            name: "publication-ack-mutation",
            invitees: &invitees,
            required_features: &[],
            initial_admins: &initial_admins,
            pending: "create",
        })
        .await
        .expect("reference group creation emits publication work");
    let before = subject
        .structural_progress()
        .expect("pending-work observation before acknowledgement")
        .outbound_awaiting_acknowledgement;
    let outbound = subject
        .poll_outbound("alice")
        .expect("reference outbound publication work");
    assert_eq!(before, outbound.len());
    if acknowledge {
        for artifact in outbound {
            subject
                .acknowledge_outbound(
                    "alice",
                    &artifact.outbound_id,
                    SubjectOutboundOutcome::Accepted,
                )
                .await
                .expect("accepted acknowledgement clears reference publication work");
        }
    }
    let after = subject
        .structural_progress()
        .expect("pending-work observation after acknowledgement")
        .outbound_awaiting_acknowledgement;
    format!("pending:{before}->{after}")
}

async fn publication_ack_sentinel() -> (String, String) {
    (
        publication_ack_observation(true).await,
        publication_ack_observation(false).await,
    )
}

fn expiration_sentinel() -> (String, String) {
    let input = ReferenceInput {
        current_tip_epoch: 6,
        retained_anchor_epoch: 1,
        candidates: vec![ReferenceCandidate {
            id: "winner".into(),
            fork_epoch: 1,
            tip_epoch: 6,
            tip_priority: ReferencePriority::Ordinary,
            tip_committer: b"alice".to_vec(),
            tip_digest: [0; 32],
            app_witnesses: Vec::new(),
        }],
        commits: Vec::new(),
        proposals: Vec::new(),
        app_messages: vec![ReferenceAppMessage {
            message_id: "boundary-message".into(),
            sender: b"alice".to_vec(),
            epoch: 1,
            decrypts_on_branches: vec!["winner".into()],
            authenticated: true,
            authorized: true,
        }],
        policy: ReferencePolicy::default(),
        witness_mode: WitnessMode::Disabled,
    };
    let baseline = evaluate(&input).dispositions["boundary-message"];
    let mutant = ReferenceDisposition::InvalidatedBeyondAppRetention;
    (format!("{baseline:?}"), format!("{mutant:?}"))
}
