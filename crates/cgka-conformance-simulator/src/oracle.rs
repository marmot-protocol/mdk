//! Scenario oracle and coverage evidence.
//!
//! The simulator has two jobs: run scenario inputs and explain what behavior
//! those inputs actually checked. This module keeps that second job explicit.

use crate::{ScenarioReport, ScenarioSpec, ScenarioStep, ScenarioTrace, TraceExpectation};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStimulus {
    CreateGroup,
    InviteMembers,
    GroupDataUpdate,
    PublishConfirm,
    PublishFail,
    AppMessage,
    Leave,
    QueueDrop,
    QueueDuplicate,
    QueueDelay,
    QueueReorder,
    Partition,
    Restart,
    LargeGroup,
    MessageStorm,
    CommitStorm,
    MixedMessageCommitStorm,
    CandidateGraph,
    CanonicalizationBatch,
    QuiescenceGate,
    CapabilityMatrix,
    DeliveryProfile,
    StorageRestart,
    Replay,
    PublishLifecycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleBehavior {
    PendingConfirmed,
    PendingRolledBack,
    ClientState,
    ClientConvergence,
    DeliveredPayload,
    MemberAdded,
    MemberRemoved,
    EpochChanged,
    ForkRecovered,
    AppInvalidated,
    LargeGroupObserved,
    SelectorDeterminism,
    CanonicalDisposition,
    IdempotentReplay,
    QuiescenceState,
    CapabilityNegotiation,
    RestartEquivalence,
    PublishLifecycleChecked,
    ReplayDeduplication,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorEvidenceSummary {
    pub observed_clients: usize,
    pub max_member_count: usize,
    pub pending_confirmed: usize,
    pub pending_rolled_back: usize,
    pub delivered_payloads: usize,
    pub member_additions: usize,
    pub member_removals: usize,
    pub epoch_changes: usize,
    pub app_invalidations: usize,
    pub recoveries: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleCoverageWarning {
    pub stimulus: ScenarioStimulus,
    pub expected_any_of: Vec<OracleBehavior>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioOracleReport {
    pub stimuli: Vec<ScenarioStimulus>,
    pub oracle_behaviors: Vec<OracleBehavior>,
    pub observed_behaviors: Vec<OracleBehavior>,
    pub missing_observed_behaviors: Vec<OracleBehavior>,
    pub evidence: BehaviorEvidenceSummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weak_oracle_warnings: Vec<OracleCoverageWarning>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageMatrixEntry {
    pub scenario_name: String,
    pub source: String,
    pub stimuli: Vec<ScenarioStimulus>,
    pub oracle_behaviors: Vec<OracleBehavior>,
    pub observed_behaviors: Vec<OracleBehavior>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weak_oracle_warnings: Vec<OracleCoverageWarning>,
}

pub fn build_scenario_oracle_report(
    spec: &ScenarioSpec,
    expected_trace: Option<&ScenarioTrace>,
    expected_outcomes: &[TraceExpectation],
    observed_trace: &ScenarioTrace,
) -> ScenarioOracleReport {
    let stimuli = scenario_stimuli(spec);
    let oracle_behaviors = expected_behaviors(expected_trace, expected_outcomes);
    let observed_behaviors = trace_behaviors(observed_trace);
    let evidence = behavior_evidence(observed_trace);

    let observed_set = observed_behaviors.iter().copied().collect::<BTreeSet<_>>();
    let missing_observed_behaviors = oracle_behaviors
        .iter()
        .copied()
        .filter(|behavior| !observed_set.contains(behavior))
        .collect();
    let weak_oracle_warnings = weak_oracle_warnings(&stimuli, &oracle_behaviors);

    ScenarioOracleReport {
        stimuli,
        oracle_behaviors,
        observed_behaviors,
        missing_observed_behaviors,
        evidence,
        weak_oracle_warnings,
    }
}

pub fn coverage_matrix_entry(
    source: impl Into<String>,
    report: &ScenarioReport,
) -> CoverageMatrixEntry {
    CoverageMatrixEntry {
        scenario_name: report.metadata.scenario_name.clone(),
        source: source.into(),
        stimuli: report.oracle.stimuli.clone(),
        oracle_behaviors: report.oracle.oracle_behaviors.clone(),
        observed_behaviors: report.oracle.observed_behaviors.clone(),
        weak_oracle_warnings: report.oracle.weak_oracle_warnings.clone(),
    }
}

pub fn property_test_coverage_entries() -> Vec<CoverageMatrixEntry> {
    vec![
        property_entry(
            "prop_candidate_graph_selection_is_order_invariant",
            vec![ScenarioStimulus::CandidateGraph],
            vec![OracleBehavior::SelectorDeterminism],
        ),
        property_entry(
            "prop_canonicalization_dispositions_are_order_invariant",
            vec![
                ScenarioStimulus::CanonicalizationBatch,
                ScenarioStimulus::QueueDuplicate,
                ScenarioStimulus::QueueReorder,
            ],
            vec![OracleBehavior::CanonicalDisposition],
        ),
        property_entry(
            "prop_canonicalization_replay_is_already_seen",
            vec![ScenarioStimulus::Replay],
            vec![OracleBehavior::IdempotentReplay],
        ),
        property_entry(
            "prop_quiescence_gate_controls_stability",
            vec![ScenarioStimulus::QuiescenceGate],
            vec![OracleBehavior::QuiescenceState],
        ),
        property_entry(
            "prop_capability_negotiation_matches_matrix",
            vec![ScenarioStimulus::CapabilityMatrix],
            vec![OracleBehavior::CapabilityNegotiation],
        ),
        property_entry(
            "prop_convergence_under_send_leave_sequence",
            vec![ScenarioStimulus::AppMessage, ScenarioStimulus::Leave],
            vec![OracleBehavior::ClientConvergence],
        ),
        property_entry(
            "prop_convergence_under_varied_delivery",
            vec![
                ScenarioStimulus::AppMessage,
                ScenarioStimulus::Leave,
                ScenarioStimulus::DeliveryProfile,
            ],
            vec![OracleBehavior::ClientConvergence],
        ),
        property_entry(
            "prop_stored_convergence_restart_equivalence",
            vec![
                ScenarioStimulus::CanonicalizationBatch,
                ScenarioStimulus::StorageRestart,
            ],
            vec![OracleBehavior::RestartEquivalence],
        ),
        property_entry(
            "prop_group_data_update_publish_lifecycle",
            vec![
                ScenarioStimulus::GroupDataUpdate,
                ScenarioStimulus::PublishLifecycle,
            ],
            vec![OracleBehavior::PublishLifecycleChecked],
        ),
        property_entry(
            "prop_true_same_id_replay",
            vec![ScenarioStimulus::Replay],
            vec![OracleBehavior::ReplayDeduplication],
        ),
        property_entry(
            "prop_upgrade_confirm_or_fail_round_trip",
            vec![ScenarioStimulus::PublishLifecycle],
            vec![OracleBehavior::PublishLifecycleChecked],
        ),
    ]
}

fn property_entry(
    name: &str,
    stimuli: Vec<ScenarioStimulus>,
    oracle_behaviors: Vec<OracleBehavior>,
) -> CoverageMatrixEntry {
    CoverageMatrixEntry {
        scenario_name: name.into(),
        source: "property_test".into(),
        stimuli,
        oracle_behaviors: oracle_behaviors.clone(),
        observed_behaviors: oracle_behaviors,
        weak_oracle_warnings: vec![],
    }
}

pub fn scenario_stimuli(spec: &ScenarioSpec) -> Vec<ScenarioStimulus> {
    let mut stimuli = BTreeSet::new();
    let mut sends = 0usize;
    let mut commits = 0usize;

    if spec.clients.len() >= 20 {
        stimuli.insert(ScenarioStimulus::LargeGroup);
    }

    for step in &spec.steps {
        match step {
            ScenarioStep::CreateGroup { .. } => {
                stimuli.insert(ScenarioStimulus::CreateGroup);
            }
            ScenarioStep::InviteMembers { .. } => {
                stimuli.insert(ScenarioStimulus::InviteMembers);
            }
            ScenarioStep::UpdateGroupData { .. } => {
                stimuli.insert(ScenarioStimulus::GroupDataUpdate);
                commits += 1;
            }
            ScenarioStep::ConfirmPending { .. } => {
                stimuli.insert(ScenarioStimulus::PublishConfirm);
            }
            ScenarioStep::FailPending { .. } => {
                stimuli.insert(ScenarioStimulus::PublishFail);
            }
            ScenarioStep::SendAppMessage { .. } => {
                stimuli.insert(ScenarioStimulus::AppMessage);
                sends += 1;
            }
            ScenarioStep::Leave { .. } => {
                stimuli.insert(ScenarioStimulus::Leave);
            }
            ScenarioStep::DropQueued { .. } => {
                stimuli.insert(ScenarioStimulus::QueueDrop);
            }
            ScenarioStep::DuplicateQueued { .. } => {
                stimuli.insert(ScenarioStimulus::QueueDuplicate);
            }
            ScenarioStep::DelayQueued { .. } | ScenarioStep::ReleaseDelayed { .. } => {
                stimuli.insert(ScenarioStimulus::QueueDelay);
            }
            ScenarioStep::ReorderQueued { .. } => {
                stimuli.insert(ScenarioStimulus::QueueReorder);
            }
            ScenarioStep::SetPartition { .. } | ScenarioStep::ClearPartition => {
                stimuli.insert(ScenarioStimulus::Partition);
            }
            ScenarioStep::RestartClient { .. } => {
                stimuli.insert(ScenarioStimulus::Restart);
            }
            ScenarioStep::DeliverAll
            | ScenarioStep::Tick { .. }
            | ScenarioStep::Observe { .. }
            | ScenarioStep::ClearEvents { .. } => {}
        }
    }

    if sends >= 20 {
        stimuli.insert(ScenarioStimulus::MessageStorm);
    }
    if commits >= 4 {
        stimuli.insert(ScenarioStimulus::CommitStorm);
    }
    if sends >= 20 && commits >= 4 {
        stimuli.insert(ScenarioStimulus::MixedMessageCommitStorm);
    }

    stimuli.into_iter().collect()
}

pub fn expected_behaviors(
    expected_trace: Option<&ScenarioTrace>,
    expected_outcomes: &[TraceExpectation],
) -> Vec<OracleBehavior> {
    let mut behaviors = BTreeSet::new();
    if let Some(trace) = expected_trace {
        behaviors.extend(trace_behaviors(trace));
    }
    for expectation in expected_outcomes {
        behaviors.extend(expectation_behaviors(expectation));
    }
    behaviors.into_iter().collect()
}

pub fn trace_behaviors(trace: &ScenarioTrace) -> Vec<OracleBehavior> {
    let mut behaviors = BTreeSet::new();
    if !trace.observations.is_empty() {
        behaviors.insert(OracleBehavior::ClientState);
    }

    let evidence = behavior_evidence(trace);
    if evidence.pending_confirmed > 0 {
        behaviors.insert(OracleBehavior::PendingConfirmed);
    }
    if evidence.pending_rolled_back > 0 {
        behaviors.insert(OracleBehavior::PendingRolledBack);
    }
    if evidence.delivered_payloads > 0 {
        behaviors.insert(OracleBehavior::DeliveredPayload);
    }
    if evidence.member_additions > 0 {
        behaviors.insert(OracleBehavior::MemberAdded);
    }
    if evidence.member_removals > 0 {
        behaviors.insert(OracleBehavior::MemberRemoved);
    }
    if evidence.epoch_changes > 0 {
        behaviors.insert(OracleBehavior::EpochChanged);
    }
    if evidence.app_invalidations > 0 {
        behaviors.insert(OracleBehavior::AppInvalidated);
    }
    if evidence.recoveries > 0 {
        behaviors.insert(OracleBehavior::ForkRecovered);
    }
    if evidence.max_member_count >= 20 {
        behaviors.insert(OracleBehavior::LargeGroupObserved);
    }
    if trace.observations.len() >= 2 {
        let first_epoch = trace.observations[0].epoch;
        let first_member_count = trace.observations[0].member_count;
        if trace.observations.iter().all(|observation| {
            observation.epoch == first_epoch && observation.member_count == first_member_count
        }) {
            behaviors.insert(OracleBehavior::ClientConvergence);
        }
    }
    behaviors.into_iter().collect()
}

pub fn behavior_evidence(trace: &ScenarioTrace) -> BehaviorEvidenceSummary {
    let mut evidence = BehaviorEvidenceSummary {
        observed_clients: trace.observations.len(),
        ..BehaviorEvidenceSummary::default()
    };
    for pending in &trace.pending_resolutions {
        match pending.resolution.as_str() {
            "confirmed" => evidence.pending_confirmed += 1,
            "rolled_back" => evidence.pending_rolled_back += 1,
            _ => {}
        }
    }
    for observation in &trace.observations {
        evidence.max_member_count = evidence.max_member_count.max(observation.member_count);
        evidence.delivered_payloads += observation.received_payloads.len();
        evidence.member_additions += observation.added_members.len();
        evidence.member_removals += observation.removed_members.len();
        evidence.epoch_changes += observation.epoch_changes.len();
        evidence.app_invalidations += observation.app_invalidations.len();
        evidence.recoveries += observation.recoveries.len();
    }
    evidence
}

fn expectation_behaviors(expectation: &TraceExpectation) -> BTreeSet<OracleBehavior> {
    let mut behaviors = BTreeSet::new();
    match expectation {
        TraceExpectation::PendingResolution { resolution, .. } => {
            match resolution.as_str() {
                "confirmed" => {
                    behaviors.insert(OracleBehavior::PendingConfirmed);
                }
                "rolled_back" => {
                    behaviors.insert(OracleBehavior::PendingRolledBack);
                }
                _ => {}
            };
        }
        TraceExpectation::ClientState {
            member_count,
            received_payloads,
            added_members,
            removed_members,
            ..
        } => {
            behaviors.insert(OracleBehavior::ClientState);
            if *member_count >= 20 {
                behaviors.insert(OracleBehavior::LargeGroupObserved);
            }
            if received_payloads
                .as_ref()
                .is_some_and(|payloads| !payloads.is_empty())
            {
                behaviors.insert(OracleBehavior::DeliveredPayload);
            }
            if added_members
                .as_ref()
                .is_some_and(|members| !members.is_empty())
            {
                behaviors.insert(OracleBehavior::MemberAdded);
            }
            if removed_members
                .as_ref()
                .is_some_and(|members| !members.is_empty())
            {
                behaviors.insert(OracleBehavior::MemberRemoved);
            }
        }
        TraceExpectation::ClientsConverged { member_count, .. } => {
            behaviors.insert(OracleBehavior::ClientConvergence);
            if member_count.is_some_and(|count| count >= 20) {
                behaviors.insert(OracleBehavior::LargeGroupObserved);
            }
        }
        TraceExpectation::ClientEpochChanges { .. } => {
            behaviors.insert(OracleBehavior::EpochChanged);
        }
        TraceExpectation::ClientRecoveries { .. } | TraceExpectation::RecoverySummary { .. } => {
            behaviors.insert(OracleBehavior::ForkRecovered);
        }
    }
    behaviors
}

fn weak_oracle_warnings(
    stimuli: &[ScenarioStimulus],
    oracle_behaviors: &[OracleBehavior],
) -> Vec<OracleCoverageWarning> {
    let oracle_behaviors = oracle_behaviors.iter().copied().collect::<BTreeSet<_>>();
    stimuli
        .iter()
        .filter_map(|stimulus| {
            let expected_any_of = recommended_behaviors(*stimulus);
            if expected_any_of.is_empty()
                || expected_any_of
                    .iter()
                    .any(|behavior| oracle_behaviors.contains(behavior))
            {
                return None;
            }
            Some(OracleCoverageWarning {
                stimulus: *stimulus,
                expected_any_of,
                message: format!(
                    "scenario includes {stimulus:?} but no expectation checks the matching behavior"
                ),
            })
        })
        .collect()
}

fn recommended_behaviors(stimulus: ScenarioStimulus) -> Vec<OracleBehavior> {
    match stimulus {
        ScenarioStimulus::CreateGroup => {
            vec![
                OracleBehavior::PendingConfirmed,
                OracleBehavior::ClientState,
            ]
        }
        ScenarioStimulus::InviteMembers => vec![
            OracleBehavior::PendingConfirmed,
            OracleBehavior::MemberAdded,
            OracleBehavior::ClientConvergence,
            OracleBehavior::ClientState,
        ],
        ScenarioStimulus::GroupDataUpdate => vec![
            OracleBehavior::PendingConfirmed,
            OracleBehavior::PendingRolledBack,
            OracleBehavior::ForkRecovered,
            OracleBehavior::EpochChanged,
            OracleBehavior::ClientConvergence,
        ],
        ScenarioStimulus::PublishConfirm => vec![OracleBehavior::PendingConfirmed],
        ScenarioStimulus::PublishFail => vec![OracleBehavior::PendingRolledBack],
        ScenarioStimulus::AppMessage => {
            vec![
                OracleBehavior::DeliveredPayload,
                OracleBehavior::AppInvalidated,
            ]
        }
        ScenarioStimulus::Leave => vec![
            OracleBehavior::MemberRemoved,
            OracleBehavior::ClientConvergence,
            OracleBehavior::ClientState,
        ],
        ScenarioStimulus::QueueDrop
        | ScenarioStimulus::QueueDuplicate
        | ScenarioStimulus::QueueDelay
        | ScenarioStimulus::QueueReorder
        | ScenarioStimulus::Partition
        | ScenarioStimulus::Restart => vec![
            OracleBehavior::ClientConvergence,
            OracleBehavior::ClientState,
            OracleBehavior::DeliveredPayload,
            OracleBehavior::AppInvalidated,
            OracleBehavior::ForkRecovered,
        ],
        ScenarioStimulus::LargeGroup => vec![
            OracleBehavior::LargeGroupObserved,
            OracleBehavior::ClientConvergence,
            OracleBehavior::ClientState,
        ],
        ScenarioStimulus::MessageStorm => vec![OracleBehavior::DeliveredPayload],
        ScenarioStimulus::CommitStorm => vec![
            OracleBehavior::ForkRecovered,
            OracleBehavior::ClientConvergence,
            OracleBehavior::EpochChanged,
        ],
        ScenarioStimulus::MixedMessageCommitStorm => vec![
            OracleBehavior::DeliveredPayload,
            OracleBehavior::ForkRecovered,
            OracleBehavior::ClientConvergence,
        ],
        ScenarioStimulus::CandidateGraph => vec![OracleBehavior::SelectorDeterminism],
        ScenarioStimulus::CanonicalizationBatch => vec![OracleBehavior::CanonicalDisposition],
        ScenarioStimulus::QuiescenceGate => vec![OracleBehavior::QuiescenceState],
        ScenarioStimulus::CapabilityMatrix => vec![OracleBehavior::CapabilityNegotiation],
        ScenarioStimulus::DeliveryProfile => vec![OracleBehavior::ClientConvergence],
        ScenarioStimulus::StorageRestart => vec![OracleBehavior::RestartEquivalence],
        ScenarioStimulus::Replay => vec![
            OracleBehavior::IdempotentReplay,
            OracleBehavior::ReplayDeduplication,
        ],
        ScenarioStimulus::PublishLifecycle => vec![OracleBehavior::PublishLifecycleChecked],
    }
}
