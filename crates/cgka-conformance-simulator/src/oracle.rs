//! Scenario oracle and coverage evidence.
//!
//! The simulator has two jobs: run scenario inputs and explain what behavior
//! those inputs actually checked. This module keeps that second job explicit.

use crate::{
    QuiescenceObservation, ScenarioAssertionObservationV2, ScenarioReport, ScenarioSpec,
    ScenarioStep, ScenarioTrace, TraceExpectation, compare_trace_expectations,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStimulus {
    CreateGroup,
    InviteMembers,
    RemoveMembers,
    SelfUpdate,
    GroupDataUpdate,
    AdminPolicyUpdate,
    PublishConfirm,
    PublishFail,
    AppMessage,
    BidirectionalDecryptabilityProbe,
    Leave,
    QueueDrop,
    QueueDuplicate,
    QueueDelay,
    QueueReorder,
    Partition,
    Restart,
    OfflineReconnect,
    ProcessCrash,
    StorageFault,
    RetainedRelaySync,
    RelayHistoryControl,
    RelayHistoryReconciliation,
    VirtualTimeAdvance,
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
    ExpectedError,
    AdminPolicyObserved,
    ClientState,
    ClientConvergence,
    ExactStateEquivalence,
    ExactStateNonEquivalence,
    ScenarioInputDisposition,
    NoPendingWorkObserved,
    BidirectionalDecryptabilityObserved,
    DeliveredPayload,
    MemberAdded,
    MemberRemoved,
    EpochChanged,
    ConvergenceDecisionObserved,
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
    pub expected_errors: usize,
    pub admin_policy_observations: usize,
    pub delivered_payloads: usize,
    pub member_additions: usize,
    pub member_removals: usize,
    pub epoch_changes: usize,
    pub app_invalidations: usize,
    pub convergence_decisions: usize,
    pub scenario_input_entries: usize,
    pub scenario_inputs_deduplicated: usize,
    pub no_pending_work_observations: usize,
    pub decryptability_probe_edges: usize,
    pub decryptability_probe_edges_delivered: usize,
    pub bidirectional_decryptability_observations: usize,
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
    assertion_observations: &[ScenarioAssertionObservationV2],
    quiescence_observations: &[QuiescenceObservation],
) -> ScenarioOracleReport {
    let stimuli = scenario_stimuli(spec);
    let mut oracle_behaviors = expected_behaviors(expected_trace, expected_outcomes);
    for behavior in assertion_behaviors(spec) {
        if !oracle_behaviors.contains(&behavior) {
            oracle_behaviors.push(behavior);
        }
    }
    if spec
        .steps
        .iter()
        .any(|step| matches!(step, ScenarioStep::AwaitQuiescence { .. }))
        && !oracle_behaviors.contains(&OracleBehavior::QuiescenceState)
    {
        oracle_behaviors.push(OracleBehavior::QuiescenceState);
    }
    oracle_behaviors.sort();
    let mut observed_behaviors = trace_behaviors(observed_trace);
    for behavior in observed_assertion_behaviors(assertion_observations) {
        if !observed_behaviors.contains(&behavior) {
            observed_behaviors.push(behavior);
        }
    }
    observed_behaviors.sort();
    if expected_outcomes.iter().any(|expectation| {
        matches!(expectation, TraceExpectation::ClientsNotEquivalent { .. })
            && compare_trace_expectations(None, std::slice::from_ref(expectation), observed_trace)
                .is_empty()
    }) && !observed_behaviors.contains(&OracleBehavior::ExactStateNonEquivalence)
    {
        observed_behaviors.push(OracleBehavior::ExactStateNonEquivalence);
        observed_behaviors.sort();
    }
    // The global heuristics in `trace_behaviors` compare every observation in
    // the trace, so they cannot see subset agreement when a scenario also
    // observes intentionally divergent branch devices or earlier mid-schedule
    // states. A passing equivalence/convergence expectation is direct observed
    // evidence for exactly that subset; both expectations fail on missing
    // observations, so they cannot pass vacuously.
    if expected_outcomes.iter().any(|expectation| {
        matches!(
            expectation,
            TraceExpectation::ClientsExactlyEquivalent { .. }
        ) && compare_trace_expectations(None, std::slice::from_ref(expectation), observed_trace)
            .is_empty()
    }) {
        for behavior in [
            OracleBehavior::ExactStateEquivalence,
            OracleBehavior::ClientConvergence,
        ] {
            if !observed_behaviors.contains(&behavior) {
                observed_behaviors.push(behavior);
            }
        }
        observed_behaviors.sort();
    }
    if expected_outcomes.iter().any(|expectation| {
        matches!(expectation, TraceExpectation::ClientsConverged { .. })
            && compare_trace_expectations(None, std::slice::from_ref(expectation), observed_trace)
                .is_empty()
    }) && !observed_behaviors.contains(&OracleBehavior::ClientConvergence)
    {
        observed_behaviors.push(OracleBehavior::ClientConvergence);
        observed_behaviors.sort();
    }
    if quiescence_observations
        .iter()
        .any(|observation| observation.status.is_quiescent())
        && !observed_behaviors.contains(&OracleBehavior::QuiescenceState)
    {
        observed_behaviors.push(OracleBehavior::QuiescenceState);
        observed_behaviors.sort();
    }
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
            "prop_quiescence_gate_controls_settlement",
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
        let mut step = step;
        while let ScenarioStep::InGroup { action, .. } = step {
            step = action.as_ref();
        }
        match step {
            ScenarioStep::InGroup { .. } => unreachable!("all group wrappers were unwrapped"),
            ScenarioStep::CreateGroup { .. } => {
                stimuli.insert(ScenarioStimulus::CreateGroup);
            }
            ScenarioStep::InviteMembers { .. } => {
                stimuli.insert(ScenarioStimulus::InviteMembers);
            }
            ScenarioStep::RemoveMembers { .. } => {
                stimuli.insert(ScenarioStimulus::RemoveMembers);
                commits += 1;
            }
            ScenarioStep::SelfUpdate { .. } => {
                stimuli.insert(ScenarioStimulus::SelfUpdate);
                commits += 1;
            }
            ScenarioStep::UpdateGroupData { .. } | ScenarioStep::UpdateGroupProfile { .. } => {
                stimuli.insert(ScenarioStimulus::GroupDataUpdate);
                commits += 1;
            }
            ScenarioStep::UpdateAdminPolicy { .. } => {
                stimuli.insert(ScenarioStimulus::AdminPolicyUpdate);
                commits += 1;
            }
            ScenarioStep::ExpectUpdateAdminPolicyError { .. } => {
                stimuli.insert(ScenarioStimulus::AdminPolicyUpdate);
            }
            ScenarioStep::AcknowledgeOutbound { outcome, .. } => {
                stimuli.insert(match outcome {
                    crate::SubjectOutboundOutcome::Accepted => ScenarioStimulus::PublishConfirm,
                    crate::SubjectOutboundOutcome::ReachedNoEndpoint => {
                        ScenarioStimulus::PublishFail
                    }
                });
            }
            ScenarioStep::SendAppMessage { .. } => {
                stimuli.insert(ScenarioStimulus::AppMessage);
                sends += 1;
            }
            ScenarioStep::ProbeBidirectionalDecryptability { clients } => {
                stimuli.insert(ScenarioStimulus::AppMessage);
                stimuli.insert(ScenarioStimulus::BidirectionalDecryptabilityProbe);
                sends += clients.len();
            }
            ScenarioStep::Leave { .. } => {
                stimuli.insert(ScenarioStimulus::Leave);
            }
            ScenarioStep::OmitMessage { .. } => {
                stimuli.insert(ScenarioStimulus::QueueDrop);
            }
            ScenarioStep::DuplicateMessage { .. } => {
                stimuli.insert(ScenarioStimulus::QueueDuplicate);
            }
            ScenarioStep::WithholdMessage { .. } | ScenarioStep::ReleaseWithheld { .. } => {
                stimuli.insert(ScenarioStimulus::QueueDelay);
            }
            ScenarioStep::ReorderMessages { .. } => {
                stimuli.insert(ScenarioStimulus::QueueReorder);
            }
            ScenarioStep::SetPartition { .. } | ScenarioStep::ClearPartition => {
                stimuli.insert(ScenarioStimulus::Partition);
            }
            ScenarioStep::RestartClient { .. } => {
                stimuli.insert(ScenarioStimulus::Restart);
            }
            ScenarioStep::SetClientOffline { .. } | ScenarioStep::ReconnectClient { .. } => {
                stimuli.insert(ScenarioStimulus::OfflineReconnect);
            }
            ScenarioStep::SyncRelayHistory { .. } => {
                stimuli.insert(ScenarioStimulus::RetainedRelaySync);
            }
            ScenarioStep::ConfigureRelay { .. } | ScenarioStep::SetRelayEventVisibility { .. } => {
                stimuli.insert(ScenarioStimulus::RelayHistoryControl);
            }
            ScenarioStep::ReconcileRelayHistories { .. } => {
                stimuli.insert(ScenarioStimulus::RelayHistoryReconciliation);
            }
            ScenarioStep::CrashProcess { .. } | ScenarioStep::RestartProcess { .. } => {
                stimuli.insert(ScenarioStimulus::ProcessCrash);
            }
            ScenarioStep::InjectStorageFault { .. } | ScenarioStep::ClearStorageFault { .. } => {
                stimuli.insert(ScenarioStimulus::StorageFault);
            }
            ScenarioStep::AdvanceTime { .. } => {
                stimuli.insert(ScenarioStimulus::VirtualTimeAdvance);
            }
            ScenarioStep::AwaitQuiescence { .. } => {
                stimuli.insert(ScenarioStimulus::QuiescenceGate);
                stimuli.insert(ScenarioStimulus::VirtualTimeAdvance);
            }
            ScenarioStep::DeliverAll
            | ScenarioStep::Tick { .. }
            | ScenarioStep::ExpectTickError { .. }
            | ScenarioStep::Observe { .. }
            | ScenarioStep::ObserveExact { .. }
            | ScenarioStep::ObserveAdminPolicy { .. }
            | ScenarioStep::ClearEvents { .. }
            | ScenarioStep::Barrier { .. }
            | ScenarioStep::Assert { .. } => {}
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

/// Executable scenario assertions are oracle evidence. A positive payload-count
/// check covers `AppMessage` without inventing a cross-sender `received_payloads`
/// order, which MLS does not define. Declared asserts contribute expected
/// coverage; only passing assertion observations count as observed evidence.
fn assertion_behaviors(spec: &ScenarioSpec) -> BTreeSet<OracleBehavior> {
    let mut behaviors = BTreeSet::new();
    for step in &spec.steps {
        let mut step = step;
        while let ScenarioStep::InGroup { action, .. } = step {
            step = action.as_ref();
        }
        let ScenarioStep::Assert { assertion } = step else {
            continue;
        };
        if payload_count_covers_delivery(assertion) {
            behaviors.insert(OracleBehavior::DeliveredPayload);
        }
    }
    behaviors
}

fn observed_assertion_behaviors(
    observations: &[ScenarioAssertionObservationV2],
) -> BTreeSet<OracleBehavior> {
    let mut behaviors = BTreeSet::new();
    for observation in observations {
        if observation.passed && payload_count_covers_delivery(&observation.assertion) {
            behaviors.insert(OracleBehavior::DeliveredPayload);
        }
    }
    behaviors
}

fn payload_count_covers_delivery(assertion: &crate::ScenarioAssertionV2) -> bool {
    let predicate = match assertion {
        crate::ScenarioAssertionV2::Exactly { predicate }
        | crate::ScenarioAssertionV2::Eventually { predicate, .. }
        | crate::ScenarioAssertionV2::Within { predicate, .. } => predicate,
        crate::ScenarioAssertionV2::Never { .. } | crate::ScenarioAssertionV2::Resource { .. } => {
            return false;
        }
    };
    matches!(
        predicate,
        crate::ScenarioPredicateV2::PayloadCount { count, .. } if *count > 0
    )
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
    if evidence.expected_errors > 0 {
        behaviors.insert(OracleBehavior::ExpectedError);
    }
    if evidence.admin_policy_observations > 0 {
        behaviors.insert(OracleBehavior::AdminPolicyObserved);
    }
    if evidence.delivered_payloads > 0 || evidence.decryptability_probe_edges_delivered > 0 {
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
    if evidence.convergence_decisions > 0 {
        behaviors.insert(OracleBehavior::ConvergenceDecisionObserved);
    }
    if evidence.scenario_input_entries > 0 {
        behaviors.insert(OracleBehavior::ScenarioInputDisposition);
    }
    if evidence.scenario_inputs_deduplicated > 0 {
        behaviors.insert(OracleBehavior::ReplayDeduplication);
    }
    if evidence.no_pending_work_observations > 0 {
        behaviors.insert(OracleBehavior::NoPendingWorkObserved);
    }
    if evidence.bidirectional_decryptability_observations > 0 {
        behaviors.insert(OracleBehavior::BidirectionalDecryptabilityObserved);
    }
    if evidence.max_member_count >= 20 {
        behaviors.insert(OracleBehavior::LargeGroupObserved);
    }
    if trace.observations.len() >= 2 {
        let first_epoch = trace.observations[0].epoch;
        let first_member_count = trace.observations[0].member_count;
        let first_group_name = &trace.observations[0].group_name;
        let first_group_description = &trace.observations[0].group_description;
        if trace.observations.iter().all(|observation| {
            observation.epoch == first_epoch
                && observation.member_count == first_member_count
                && &observation.group_name == first_group_name
                && &observation.group_description == first_group_description
        }) {
            behaviors.insert(OracleBehavior::ClientConvergence);
        }
        let exact_states = trace
            .observations
            .iter()
            .filter_map(|observation| observation.canonical_state.as_ref())
            .collect::<Vec<_>>();
        if exact_states.len() >= 2
            && exact_states
                .iter()
                .all(|snapshot| *snapshot == exact_states[0])
        {
            behaviors.insert(OracleBehavior::ExactStateEquivalence);
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
    evidence.expected_errors += trace.errors.len();
    evidence.admin_policy_observations += trace.admin_policies.len();
    for observation in &trace.decryptability_probes {
        evidence.decryptability_probe_edges += observation.probes.len();
        evidence.decryptability_probe_edges_delivered += observation
            .probes
            .iter()
            .filter(|probe| probe.succeeded())
            .count();
        if observation.succeeded() {
            evidence.bidirectional_decryptability_observations += 1;
        }
    }
    for observation in &trace.observations {
        evidence.max_member_count = evidence.max_member_count.max(observation.member_count);
        evidence.delivered_payloads += observation.received_payloads.len();
        evidence.member_additions += observation.added_members.len();
        evidence.member_removals += observation.removed_members.len();
        evidence.epoch_changes += observation.epoch_changes.len();
        evidence.app_invalidations += observation.app_invalidations.len();
        evidence.convergence_decisions += observation.convergence_decisions.len();
        evidence.scenario_input_entries += observation.scenario_input_ledger.len();
        evidence.scenario_inputs_deduplicated += observation
            .scenario_input_ledger
            .iter()
            .map(|entry| entry.deduplicated)
            .sum::<usize>();
        if observation
            .pending_work
            .as_ref()
            .is_some_and(|pending| pending.is_empty())
        {
            evidence.no_pending_work_observations += 1;
        }
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
        TraceExpectation::ExpectedError { .. } => {
            behaviors.insert(OracleBehavior::ExpectedError);
        }
        TraceExpectation::AdminPolicy { .. } => {
            behaviors.insert(OracleBehavior::AdminPolicyObserved);
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
        TraceExpectation::ApplicationPayloadMultiset { payloads, .. } => {
            behaviors.insert(OracleBehavior::ClientState);
            if !payloads.is_empty() {
                behaviors.insert(OracleBehavior::DeliveredPayload);
            }
        }
        TraceExpectation::GroupProfile { .. } => {
            behaviors.insert(OracleBehavior::ClientState);
        }
        TraceExpectation::ClientsConverged { member_count, .. } => {
            behaviors.insert(OracleBehavior::ClientConvergence);
            if member_count.is_some_and(|count| count >= 20) {
                behaviors.insert(OracleBehavior::LargeGroupObserved);
            }
        }
        TraceExpectation::ClientsExactlyEquivalent { .. } => {
            behaviors.insert(OracleBehavior::ClientConvergence);
            behaviors.insert(OracleBehavior::ExactStateEquivalence);
        }
        TraceExpectation::ClientsNotEquivalent { .. } => {
            behaviors.insert(OracleBehavior::ExactStateNonEquivalence);
        }
        TraceExpectation::ScenarioInputLedger { entries, .. } => {
            behaviors.insert(OracleBehavior::ScenarioInputDisposition);
            if entries.iter().any(|entry| entry.delivered > 0) {
                behaviors.insert(OracleBehavior::DeliveredPayload);
            }
            if entries.iter().any(|entry| entry.deduplicated > 0) {
                behaviors.insert(OracleBehavior::ReplayDeduplication);
            }
            if entries.iter().any(|entry| !entry.invalidated.is_empty()) {
                behaviors.insert(OracleBehavior::AppInvalidated);
            }
        }
        TraceExpectation::NoPendingWork { .. }
        | TraceExpectation::NoPendingWorkExceptRetainedJoinCommit { .. } => {
            behaviors.insert(OracleBehavior::NoPendingWorkObserved);
        }
        TraceExpectation::ClientsBidirectionallyDecryptable { .. } => {
            behaviors.insert(OracleBehavior::BidirectionalDecryptabilityObserved);
            // A successful active probe is itself application-message delivery
            // evidence in every requested direction. Do not require a second,
            // unrelated payload expectation merely because the probe sends app
            // messages internally.
            behaviors.insert(OracleBehavior::DeliveredPayload);
        }
        TraceExpectation::ClientEpochChanges { .. } => {
            behaviors.insert(OracleBehavior::EpochChanged);
        }
        TraceExpectation::ConvergenceDecision { .. } => {
            behaviors.insert(OracleBehavior::ConvergenceDecisionObserved);
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
        ScenarioStimulus::RemoveMembers => vec![
            OracleBehavior::PendingConfirmed,
            OracleBehavior::MemberRemoved,
            OracleBehavior::ClientConvergence,
            OracleBehavior::ClientState,
        ],
        ScenarioStimulus::SelfUpdate => vec![
            OracleBehavior::PendingConfirmed,
            OracleBehavior::EpochChanged,
            OracleBehavior::ClientConvergence,
        ],
        ScenarioStimulus::GroupDataUpdate => vec![
            OracleBehavior::PendingConfirmed,
            OracleBehavior::PendingRolledBack,
            OracleBehavior::EpochChanged,
            OracleBehavior::ClientConvergence,
        ],
        ScenarioStimulus::AdminPolicyUpdate => vec![
            OracleBehavior::PendingConfirmed,
            OracleBehavior::ExpectedError,
            OracleBehavior::AdminPolicyObserved,
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
        ScenarioStimulus::BidirectionalDecryptabilityProbe => {
            vec![OracleBehavior::BidirectionalDecryptabilityObserved]
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
        | ScenarioStimulus::Restart
        | ScenarioStimulus::OfflineReconnect
        | ScenarioStimulus::ProcessCrash
        | ScenarioStimulus::StorageFault
        | ScenarioStimulus::RetainedRelaySync
        | ScenarioStimulus::RelayHistoryControl
        | ScenarioStimulus::RelayHistoryReconciliation => vec![
            OracleBehavior::ClientConvergence,
            OracleBehavior::ClientState,
            OracleBehavior::DeliveredPayload,
            OracleBehavior::AppInvalidated,
        ],
        ScenarioStimulus::LargeGroup => vec![
            OracleBehavior::LargeGroupObserved,
            OracleBehavior::ClientConvergence,
            OracleBehavior::ClientState,
        ],
        ScenarioStimulus::MessageStorm => vec![OracleBehavior::DeliveredPayload],
        ScenarioStimulus::CommitStorm => vec![
            OracleBehavior::ClientConvergence,
            OracleBehavior::EpochChanged,
        ],
        ScenarioStimulus::MixedMessageCommitStorm => vec![
            OracleBehavior::DeliveredPayload,
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
        // Advancing the controlled clock must be paired with evidence that the
        // resulting timed work was observed. A fixed-point quiescence result is
        // the strongest form; an exact no-pending observation is the appropriate
        // equivalent for explicitly stepped scenarios. Coverage is set-based and
        // does not prove that the no-pending expectation follows the advance;
        // generated families rely on `add_strict_reliability_oracle` appending it.
        ScenarioStimulus::VirtualTimeAdvance => vec![
            OracleBehavior::QuiescenceState,
            OracleBehavior::NoPendingWorkObserved,
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientEventCounts, ClientObservation, ConformanceCanonicalStateSnapshot};

    fn observation(
        client: &str,
        epoch: u64,
        member_count: usize,
        group_name: &str,
    ) -> ClientObservation {
        ClientObservation {
            client: client.into(),
            epoch,
            member_count,
            group_name: group_name.into(),
            group_description: String::new(),
            canonical_state: None,
            scenario_input_ledger: Vec::new(),
            pending_work: None,
            event_counts: ClientEventCounts::default(),
            received_payloads: Vec::new(),
            added_members: Vec::new(),
            removed_members: Vec::new(),
            epoch_changes: Vec::new(),
            app_invalidations: Vec::new(),
            convergence_decisions: Vec::new(),
        }
    }

    fn trace(observations: Vec<ClientObservation>) -> ScenarioTrace {
        ScenarioTrace {
            name: "oracle-convergence".into(),
            pending_resolutions: Vec::new(),
            errors: Vec::new(),
            admin_policies: Vec::new(),
            decryptability_probes: Vec::new(),
            observations,
        }
    }

    #[test]
    fn trace_behaviors_rejects_group_data_branch_fork_as_client_convergence() {
        let observed = trace(vec![
            observation("alice", 2, 21, "alice branch"),
            observation("bob", 2, 21, "bob branch"),
        ]);

        let behaviors = trace_behaviors(&observed);

        assert!(
            !behaviors.contains(&OracleBehavior::ClientConvergence),
            "same epoch/member_count with different group names is a branch fork, not convergence: {behaviors:#?}"
        );
    }

    #[test]
    fn trace_behaviors_accepts_shared_group_name_as_client_convergence() {
        let observed = trace(vec![
            observation("alice", 2, 21, "winner branch"),
            observation("bob", 2, 21, "winner branch"),
        ]);

        let behaviors = trace_behaviors(&observed);

        assert!(
            behaviors.contains(&OracleBehavior::ClientConvergence),
            "same epoch/member_count/group_name should count as convergence: {behaviors:#?}"
        );
    }

    #[test]
    fn trace_behaviors_finds_exact_equivalence_after_legacy_observations() {
        let mut alice_exact = observation("alice", 2, 2, "winner");
        alice_exact.canonical_state = Some(ConformanceCanonicalStateSnapshot::Live(Box::default()));
        let mut bob_exact = observation("bob", 2, 2, "winner");
        bob_exact.canonical_state = alice_exact.canonical_state.clone();
        let observed = trace(vec![
            observation("alice", 2, 2, "winner"),
            observation("bob", 2, 2, "winner"),
            alice_exact,
            bob_exact,
        ]);

        assert!(
            trace_behaviors(&observed).contains(&OracleBehavior::ExactStateEquivalence),
            "legacy observations must not hide a later equivalent exact sample"
        );
    }

    #[test]
    fn strict_oracle_records_satisfied_exact_non_equivalence() {
        let mut david = observation("david", 2, 3, "winner");
        david.canonical_state = Some(ConformanceCanonicalStateSnapshot::Live(Box::default()));
        let mut eve = observation("eve", 2, 3, "loser");
        let mut eve_state =
            Box::<cgka_engine::conformance_snapshot::ConformanceGroupSnapshot>::default();
        eve_state.epoch = 9;
        eve.canonical_state = Some(ConformanceCanonicalStateSnapshot::Live(eve_state));
        let expectation = TraceExpectation::ClientsNotEquivalent {
            clients: vec!["david".into(), "eve".into()],
            reason: "named branch split".into(),
        };
        let spec = ScenarioSpec {
            name: "oracle/non-equivalence".into(),
            spec_version: "2".into(),
            clients: vec!["david".into(), "eve".into()],
            topology: Default::default(),
            steps: Vec::new(),
        };

        let report = build_scenario_oracle_report(
            &spec,
            None,
            std::slice::from_ref(&expectation),
            &trace(vec![david, eve]),
            &[],
            &[],
        );

        assert!(
            report
                .observed_behaviors
                .contains(&OracleBehavior::ExactStateNonEquivalence)
        );
        assert!(report.missing_observed_behaviors.is_empty());
    }

    #[test]
    fn strict_oracle_records_subset_exact_equivalence_beside_divergent_branch_devices() {
        // alice and bob share one exact snapshot; david stays on a divergent
        // branch. The global all-observations heuristic cannot see the
        // alice/bob agreement, so the passing subset expectation must carry
        // the observed-equivalence evidence.
        let mut alice = observation("alice", 2, 3, "winner");
        alice.canonical_state = Some(ConformanceCanonicalStateSnapshot::Live(Box::default()));
        let mut bob = observation("bob", 2, 3, "winner");
        bob.canonical_state = alice.canonical_state.clone();
        let mut david = observation("david", 2, 3, "loser");
        let mut david_state =
            Box::<cgka_engine::conformance_snapshot::ConformanceGroupSnapshot>::default();
        david_state.epoch = 9;
        david.canonical_state = Some(ConformanceCanonicalStateSnapshot::Live(david_state));
        let expectation = TraceExpectation::ClientsExactlyEquivalent {
            clients: vec!["alice".into(), "bob".into()],
        };
        let spec = ScenarioSpec {
            name: "oracle/subset-equivalence".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into(), "david".into()],
            topology: Default::default(),
            steps: Vec::new(),
        };

        let report = build_scenario_oracle_report(
            &spec,
            None,
            std::slice::from_ref(&expectation),
            &trace(vec![alice, bob, david]),
            &[],
            &[],
        );

        assert!(
            report
                .observed_behaviors
                .contains(&OracleBehavior::ExactStateEquivalence)
        );
        assert!(
            report
                .observed_behaviors
                .contains(&OracleBehavior::ClientConvergence)
        );
        assert!(report.missing_observed_behaviors.is_empty());
    }

    #[test]
    fn bidirectional_probe_expectation_is_application_delivery_evidence() {
        let behaviors = expected_behaviors(
            None,
            &[TraceExpectation::ClientsBidirectionallyDecryptable {
                clients: vec!["alice".into(), "bob".into()],
            }],
        );

        assert!(behaviors.contains(&OracleBehavior::BidirectionalDecryptabilityObserved));
        assert!(behaviors.contains(&OracleBehavior::DeliveredPayload));
    }

    fn payload_count_assertion(
        client: &str,
        payload: &str,
        count: usize,
    ) -> crate::ScenarioAssertionV2 {
        crate::ScenarioAssertionV2::Exactly {
            predicate: crate::ScenarioPredicateV2::PayloadCount {
                client: client.into(),
                payload: payload.into(),
                count,
            },
        }
    }

    fn payload_count_observation(
        assertion: crate::ScenarioAssertionV2,
        passed: bool,
    ) -> crate::ScenarioAssertionObservationV2 {
        crate::ScenarioAssertionObservationV2 {
            step_index: 1,
            assertion,
            passed,
            samples: 1,
            elapsed_virtual_ms: 0,
            final_actual: serde_json::json!(if passed { 1 } else { 0 }),
        }
    }

    fn passing_payload_count_observations(
        spec: &ScenarioSpec,
    ) -> Vec<crate::ScenarioAssertionObservationV2> {
        spec.steps
            .iter()
            .enumerate()
            .filter_map(|(step_index, step)| {
                let mut step = step;
                while let ScenarioStep::InGroup { action, .. } = step {
                    step = action.as_ref();
                }
                let ScenarioStep::Assert { assertion } = step else {
                    return None;
                };
                payload_count_covers_delivery(assertion).then(|| {
                    crate::ScenarioAssertionObservationV2 {
                        step_index,
                        assertion: assertion.clone(),
                        passed: true,
                        samples: 1,
                        elapsed_virtual_ms: 0,
                        final_actual: serde_json::json!(1),
                    }
                })
            })
            .collect()
    }

    #[test]
    fn positive_payload_count_assert_covers_app_message() {
        let assertion = payload_count_assertion("carol", "eve-witness", 1);
        let spec = ScenarioSpec {
            name: "payload-count-covers-app".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into(), "carol".into()],
            steps: vec![
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "eve-witness".into(),
                },
                ScenarioStep::Assert {
                    assertion: assertion.clone(),
                },
            ],
        };
        let undeclared_execution =
            build_scenario_oracle_report(&spec, None, &[], &trace(Vec::new()), &[], &[]);
        assert!(
            undeclared_execution
                .oracle_behaviors
                .contains(&OracleBehavior::DeliveredPayload),
            "{undeclared_execution:#?}"
        );
        assert!(
            undeclared_execution.weak_oracle_warnings.is_empty(),
            "{:#?}",
            undeclared_execution.weak_oracle_warnings
        );
        assert!(
            undeclared_execution
                .missing_observed_behaviors
                .contains(&OracleBehavior::DeliveredPayload),
            "a declared assert without a passing observation must remain missing: {undeclared_execution:#?}"
        );

        let failed = build_scenario_oracle_report(
            &spec,
            None,
            &[],
            &trace(Vec::new()),
            &[payload_count_observation(assertion.clone(), false)],
            &[],
        );
        assert!(
            failed
                .missing_observed_behaviors
                .contains(&OracleBehavior::DeliveredPayload),
            "a failed payload-count assert is not observed delivery: {failed:#?}"
        );

        let report = build_scenario_oracle_report(
            &spec,
            None,
            &[],
            &trace(Vec::new()),
            &[payload_count_observation(assertion, true)],
            &[],
        );
        assert!(
            report
                .observed_behaviors
                .contains(&OracleBehavior::DeliveredPayload),
            "{report:#?}"
        );
        assert!(report.missing_observed_behaviors.is_empty(), "{report:#?}");
        assert!(
            report.weak_oracle_warnings.is_empty(),
            "{:#?}",
            report.weak_oracle_warnings
        );
    }

    #[test]
    fn zero_payload_count_assert_does_not_cover_app_message() {
        let spec = ScenarioSpec {
            name: "payload-absent-does-not-cover-app".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into(), "carol".into()],
            steps: vec![
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "david-witness".into(),
                },
                ScenarioStep::Assert {
                    assertion: payload_count_assertion("carol", "david-witness", 0),
                },
            ],
        };
        let report = build_scenario_oracle_report(&spec, None, &[], &trace(Vec::new()), &[], &[]);
        assert!(
            !report
                .oracle_behaviors
                .contains(&OracleBehavior::DeliveredPayload),
            "{report:#?}"
        );
        assert!(
            report
                .weak_oracle_warnings
                .iter()
                .any(|warning| warning.stimulus == ScenarioStimulus::AppMessage),
            "{:#?}",
            report.weak_oracle_warnings
        );
    }

    #[test]
    fn app_witness_value_family_covers_app_message_under_strict_oracle() {
        let generated = crate::generate_adversarial_reliability_case(7, 9);
        assert!(
            generated.scenario.name.contains("app-witness-value"),
            "{}",
            generated.scenario.name
        );
        let passing = passing_payload_count_observations(&generated.scenario);
        assert!(
            !passing.is_empty(),
            "app-witness-value must declare positive payload-count asserts"
        );
        let report = build_scenario_oracle_report(
            &generated.scenario,
            None,
            &generated.expected_outcomes,
            &trace(Vec::new()),
            &passing,
            &[],
        );
        assert!(
            report
                .weak_oracle_warnings
                .iter()
                .all(|warning| warning.stimulus != ScenarioStimulus::AppMessage),
            "{:#?}",
            report.weak_oracle_warnings
        );
        assert!(
            report
                .observed_behaviors
                .contains(&OracleBehavior::DeliveredPayload),
            "{report:#?}"
        );
        assert!(
            !report
                .missing_observed_behaviors
                .contains(&OracleBehavior::DeliveredPayload),
            "{report:#?}"
        );
    }

    #[test]
    fn virtual_time_accepts_fixed_point_or_exact_no_pending_evidence() {
        assert!(
            weak_oracle_warnings(
                &[ScenarioStimulus::VirtualTimeAdvance],
                &[OracleBehavior::QuiescenceState],
            )
            .is_empty()
        );
        assert!(
            weak_oracle_warnings(
                &[ScenarioStimulus::VirtualTimeAdvance],
                &[OracleBehavior::NoPendingWorkObserved],
            )
            .is_empty()
        );
        assert_eq!(
            weak_oracle_warnings(&[ScenarioStimulus::VirtualTimeAdvance], &[])
                .first()
                .map(|warning| warning.expected_any_of.as_slice()),
            Some(
                [
                    OracleBehavior::QuiescenceState,
                    OracleBehavior::NoPendingWorkObserved,
                ]
                .as_slice()
            )
        );
    }
}
