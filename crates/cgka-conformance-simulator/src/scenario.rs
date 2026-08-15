//! Serializable scripted scenarios for the harness.
//!
//! `ScenarioSpec` is the v2 input-side companion to `ScenarioTrace`: external
//! implementations can drive the same logical client operations, then compare
//! their observed trace to exact or semantic fixture expectations.

use crate::{
    BidirectionalDecryptabilityObservation, ClientObservation, ConvergenceFaultSubject,
    ConvergenceSubject, EngineHarnessSubject, ExpectationFailure, HarnessStorageMode,
    PendingResolutionObservation, QuiescenceObservation, QuiescencePolicy,
    ScenarioAdminPolicyObservation, ScenarioErrorObservation, ScenarioOracleReport, ScenarioTrace,
    SubjectCreateGroup, SubjectDescriptor, SubjectError, SubjectFailureCategory,
    SubjectInviteMembers, SubjectOutboundArtifact, SubjectOutboundKind, SubjectOutboundOutcome,
    SubjectRemoveMembers, SubjectSelfUpdate, SubjectSendApplication, SubjectUpdateAdminPolicy,
    SubjectUpdateGroupData, TraceExpectation, VectorFixture, build_scenario_oracle_report,
    compare_trace_expectations, compile_scenario, drive_subject_to_quiescence,
    preflight_compiled_scenario,
};
use cgka_traits::group::ProtocolProfile;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioSpec {
    pub name: String,
    pub spec_version: String,
    pub clients: Vec<String>,
    #[serde(default, skip_serializing_if = "crate::ScenarioTopologyV2::is_empty")]
    pub topology: crate::ScenarioTopologyV2,
    pub steps: Vec<ScenarioStep>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioOutboundSelection {
    #[default]
    All,
    StateConfirmation,
    Welcome,
    GroupMessage,
    RegeneratedQueuedIntent,
}

impl ScenarioOutboundSelection {
    fn matches(self, artifact: &SubjectOutboundArtifact) -> bool {
        match self {
            Self::All => true,
            Self::StateConfirmation => artifact.state_confirmation_required,
            Self::Welcome => artifact.kind == SubjectOutboundKind::Welcome,
            Self::GroupMessage => artifact.kind == SubjectOutboundKind::GroupMessage,
            Self::RegeneratedQueuedIntent => artifact.regenerated_queued_intent,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScenarioStep {
    /// Execute one ordinary group-scoped action against a stable scenario
    /// group label. The compiler lowers this wrapper before adapter execution.
    InGroup {
        group: String,
        action: Box<ScenarioStep>,
    },
    CreateGroup {
        creator: String,
        name: String,
        invitees: Vec<String>,
        #[serde(default)]
        required_features: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_admins: Option<Vec<String>>,
        pending: String,
    },
    InviteMembers {
        inviter: String,
        invitees: Vec<String>,
        pending: String,
    },
    RemoveMembers {
        remover: String,
        members: Vec<String>,
        pending: String,
    },
    SelfUpdate {
        client: String,
        pending: String,
    },
    UpdateGroupData {
        client: String,
        name: String,
        pending: String,
    },
    /// Update one or both fields of the canonical Marmot group profile.
    ///
    /// This action is available in Scenario IR v3. The v2
    /// `update_group_data` action remains the stable name-only contract.
    UpdateGroupProfile {
        client: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        pending: String,
    },
    UpdateAdminPolicy {
        client: String,
        admins: Vec<String>,
        pending: String,
    },
    ExpectUpdateAdminPolicyError {
        client: String,
        admins: Vec<String>,
        error: String,
    },
    AcknowledgeOutbound {
        client: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        publication: Option<String>,
        #[serde(default)]
        selection: ScenarioOutboundSelection,
        outcome: SubjectOutboundOutcome,
    },
    SendAppMessage {
        sender: String,
        payload: String,
    },
    Leave {
        client: String,
    },
    DeliverAll,
    Tick {
        clients: Vec<String>,
    },
    /// Advance both convergence-clock domains without waking a participant.
    /// Use `Tick` to select which participant runtimes observe elapsed time.
    AdvanceTime {
        delta_ms: u64,
    },
    /// Drive the complete subject to a bounded structural fixed point using
    /// virtual time. A non-quiescent terminal result is retained in the report
    /// and fails the scenario invariant.
    AwaitQuiescence {
        #[serde(default)]
        policy: QuiescencePolicy,
    },
    Observe {
        clients: Vec<String>,
    },
    /// Capture the exact canonical state and scenario-input ledger used by
    /// reliability expectations.
    ObserveExact {
        clients: Vec<String>,
    },
    /// Actively prove the application-message path in every direction between
    /// the named clients.
    ProbeBidirectionalDecryptability {
        clients: Vec<String>,
    },
    ObserveAdminPolicy {
        clients: Vec<String>,
    },
    ClearEvents {
        clients: Vec<String>,
    },
    OmitMessage {
        selector: crate::ScenarioMessageSelectorV2,
    },
    DuplicateMessage {
        selector: crate::ScenarioMessageSelectorV2,
    },
    WithholdMessage {
        selector: crate::ScenarioMessageSelectorV2,
        label: String,
    },
    ReleaseWithheld {
        label: String,
    },
    ReorderMessages {
        order: Vec<crate::ScenarioMessageSelectorV2>,
    },
    SetPartition {
        allow: Vec<String>,
    },
    ClearPartition,
    RestartClient {
        client: String,
    },
    SetClientOffline {
        client: String,
    },
    ReconnectClient {
        client: String,
    },
    SyncRelayHistory {
        clients: Vec<String>,
        sync: crate::ScenarioRelaySyncModeV2,
    },
    ConfigureRelay {
        relay: String,
        order: crate::ScenarioRelayOrderV2,
        /// Total copies returned for each matching retained event.
        duplicate_copies: usize,
    },
    SetRelayEventVisibility {
        relay: String,
        selector: crate::ScenarioMessageSelectorV2,
        clients: Vec<String>,
        visible: bool,
    },
    ReconcileRelayHistories {
        relays: Vec<String>,
    },
    CrashProcess {
        process: String,
    },
    RestartProcess {
        process: String,
    },
    InjectStorageFault {
        fault: crate::ScenarioStorageFaultV2,
    },
    ClearStorageFault {
        target: String,
    },
    /// Compiler-recorded synchronization point. It is a no-op for subjects.
    Barrier {
        name: String,
    },
    Assert {
        assertion: crate::ScenarioAssertionV2,
    },
}

impl ScenarioStep {
    pub const KINDS: &'static [&'static str] = &[
        "in_group",
        "create_group",
        "invite_members",
        "remove_members",
        "self_update",
        "update_group_data",
        "update_group_profile",
        "update_admin_policy",
        "expect_update_admin_policy_error",
        "acknowledge_outbound",
        "send_app_message",
        "leave",
        "deliver_all",
        "tick",
        "advance_time",
        "await_quiescence",
        "observe",
        "observe_exact",
        "probe_bidirectional_decryptability",
        "observe_admin_policy",
        "clear_events",
        "omit_message",
        "duplicate_message",
        "withhold_message",
        "release_withheld",
        "reorder_messages",
        "set_partition",
        "clear_partition",
        "restart_client",
        "set_client_offline",
        "reconnect_client",
        "sync_relay_history",
        "configure_relay",
        "set_relay_event_visibility",
        "reconcile_relay_histories",
        "crash_process",
        "restart_process",
        "inject_storage_fault",
        "clear_storage_fault",
        "barrier",
        "assert",
    ];

    pub fn accept_publication(client: impl Into<String>, publication: impl Into<String>) -> Self {
        Self::AcknowledgeOutbound {
            client: client.into(),
            publication: Some(publication.into()),
            selection: ScenarioOutboundSelection::All,
            outcome: SubjectOutboundOutcome::Accepted,
        }
    }

    pub fn fail_publication(client: impl Into<String>, publication: impl Into<String>) -> Self {
        Self::AcknowledgeOutbound {
            client: client.into(),
            publication: Some(publication.into()),
            selection: ScenarioOutboundSelection::All,
            outcome: SubjectOutboundOutcome::ReachedNoEndpoint,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            ScenarioStep::InGroup { action, .. } => action.kind(),
            ScenarioStep::CreateGroup { .. } => "create_group",
            ScenarioStep::InviteMembers { .. } => "invite_members",
            ScenarioStep::RemoveMembers { .. } => "remove_members",
            ScenarioStep::SelfUpdate { .. } => "self_update",
            ScenarioStep::UpdateGroupData { .. } => "update_group_data",
            ScenarioStep::UpdateGroupProfile { .. } => "update_group_profile",
            ScenarioStep::UpdateAdminPolicy { .. } => "update_admin_policy",
            ScenarioStep::ExpectUpdateAdminPolicyError { .. } => "expect_update_admin_policy_error",
            ScenarioStep::AcknowledgeOutbound { .. } => "acknowledge_outbound",
            ScenarioStep::SendAppMessage { .. } => "send_app_message",
            ScenarioStep::Leave { .. } => "leave",
            ScenarioStep::DeliverAll => "deliver_all",
            ScenarioStep::Tick { .. } => "tick",
            ScenarioStep::AdvanceTime { .. } => "advance_time",
            ScenarioStep::AwaitQuiescence { .. } => "await_quiescence",
            ScenarioStep::Observe { .. } => "observe",
            ScenarioStep::ObserveExact { .. } => "observe_exact",
            ScenarioStep::ProbeBidirectionalDecryptability { .. } => {
                "probe_bidirectional_decryptability"
            }
            ScenarioStep::ObserveAdminPolicy { .. } => "observe_admin_policy",
            ScenarioStep::ClearEvents { .. } => "clear_events",
            ScenarioStep::OmitMessage { .. } => "omit_message",
            ScenarioStep::DuplicateMessage { .. } => "duplicate_message",
            ScenarioStep::WithholdMessage { .. } => "withhold_message",
            ScenarioStep::ReleaseWithheld { .. } => "release_withheld",
            ScenarioStep::ReorderMessages { .. } => "reorder_messages",
            ScenarioStep::SetPartition { .. } => "set_partition",
            ScenarioStep::ClearPartition => "clear_partition",
            ScenarioStep::RestartClient { .. } => "restart_client",
            ScenarioStep::SetClientOffline { .. } => "set_client_offline",
            ScenarioStep::ReconnectClient { .. } => "reconnect_client",
            ScenarioStep::SyncRelayHistory { .. } => "sync_relay_history",
            ScenarioStep::ConfigureRelay { .. } => "configure_relay",
            ScenarioStep::SetRelayEventVisibility { .. } => "set_relay_event_visibility",
            ScenarioStep::ReconcileRelayHistories { .. } => "reconcile_relay_histories",
            ScenarioStep::CrashProcess { .. } => "crash_process",
            ScenarioStep::RestartProcess { .. } => "restart_process",
            ScenarioStep::InjectStorageFault { .. } => "inject_storage_fault",
            ScenarioStep::ClearStorageFault { .. } => "clear_storage_fault",
            ScenarioStep::Barrier { .. } => "barrier",
            ScenarioStep::Assert { .. } => "assert",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub metadata: ScenarioReportMetadata,
    pub scenario: ScenarioSpec,
    /// Validated explicit topology, including deterministic projection for
    /// legacy client-only vectors.
    #[serde(default, skip_serializing_if = "crate::ScenarioTopologyV2::is_empty")]
    pub resolved_topology: crate::ScenarioTopologyV2,
    /// Authoritative compiler output executed by the selected adapter. Its
    /// declared time excludes clock movement inside assertions/quiescence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expanded_schedule: Vec<crate::ScenarioActionScheduleV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_observations: Vec<crate::ScenarioAssertionObservationV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_sync_observations: Vec<crate::RelaySyncObservationV2>,
    pub expected_trace: Option<ScenarioTrace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_outcomes: Vec<TraceExpectation>,
    pub observed_trace: Option<ScenarioTrace>,
    pub oracle: ScenarioOracleReport,
    pub step_log: Vec<ScenarioStepLogEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_resolution_observations: Vec<PendingResolutionObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quiescence_observations: Vec<QuiescenceObservation>,
    pub epoch_change_observations: Vec<EpochChangeReportObservation>,
    pub app_invalidation_observations: Vec<AppInvalidationReportObservation>,
    #[serde(default)]
    pub expectation_failures: Vec<ExpectationFailure>,
    pub invariant_failures: Vec<InvariantFailure>,
    #[serde(default)]
    pub campaign_measurements: crate::CampaignMeasurementsV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochChangeReportObservation {
    pub client: String,
    pub from: u64,
    pub to: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInvalidationReportObservation {
    pub client: String,
    pub epoch: u64,
    pub reason: String,
    pub payload_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioReportMetadata {
    pub scenario_name: String,
    pub spec_version: String,
    pub step_count: usize,
    pub storage_backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectDescriptor>,
    pub generated: Option<GeneratedScenarioMetadata>,
    pub fixture: Option<VectorFixtureMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_provenance: Option<crate::ScenarioInputProvenanceV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorFixtureMetadata {
    pub scenario_name: String,
    pub vector_version: String,
    pub conformance_version: String,
    pub seed: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedScenarioMetadata {
    pub family_name: String,
    pub generator_version: String,
    pub seed: u64,
    pub case_index: u64,
    pub minimized_case: Option<ScenarioSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioStepLogEntry {
    pub step_index: usize,
    pub step_type: String,
    pub status: ScenarioStepStatus,
    #[serde(default)]
    pub wall_us: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ScenarioStepStatus {
    Completed,
    Failed {
        #[serde(default = "default_step_failure_kind")]
        kind: String,
        #[serde(default)]
        category: SubjectFailureCategory,
        message: String,
    },
}

fn default_step_failure_kind() -> String {
    "scenario_step_failed".into()
}

impl ScenarioStepStatus {
    pub fn is_completed(&self) -> bool {
        matches!(self, ScenarioStepStatus::Completed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantFailure {
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioRunError {
    pub step_index: Option<usize>,
    pub kind: String,
    pub category: SubjectFailureCategory,
    pub message: String,
}

impl fmt::Display for ScenarioRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.step_index {
            Some(step_index) => write!(f, "scenario step {step_index}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for ScenarioRunError {}

pub async fn run_scenario_spec(spec: &ScenarioSpec) -> Result<ScenarioTrace, ScenarioRunError> {
    let report = run_scenario_report(spec, None).await?;
    ensure_execution_succeeded(&report)?;
    Ok(report
        .observed_trace
        .expect("successful report always includes an observed trace"))
}

/// Run ScenarioSpec v2 through an explicitly supplied convergence subject.
pub async fn run_scenario_spec_with_subject(
    spec: &ScenarioSpec,
    subject: &mut dyn ConvergenceSubject,
) -> Result<ScenarioTrace, ScenarioRunError> {
    let report = run_scenario_report_with_subject(spec, None, Vec::new(), subject).await?;
    ensure_execution_succeeded(&report)?;
    Ok(report
        .observed_trace
        .expect("successful report always includes an observed trace"))
}

pub async fn run_scenario_report(
    spec: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
) -> Result<ScenarioReport, ScenarioRunError> {
    run_scenario_report_with_storage_mode(spec, expected_trace, HarnessStorageMode::from_env())
        .await
}

pub async fn run_scenario_report_with_storage_mode(
    spec: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    storage_mode: HarnessStorageMode,
) -> Result<ScenarioReport, ScenarioRunError> {
    let mut subject = EngineHarnessSubject::new_with_topology(
        &spec.clients,
        &spec.topology,
        ProtocolProfile::Legacy,
        storage_mode,
    )
    .map_err(subject_setup_error)?;
    run_scenario_report_inner(spec, expected_trace, vec![], None, &mut subject).await
}

pub async fn run_scenario_report_with_outcomes(
    spec: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    expected_outcomes: Vec<TraceExpectation>,
) -> Result<ScenarioReport, ScenarioRunError> {
    run_scenario_report_with_outcomes_and_storage_mode(
        spec,
        expected_trace,
        expected_outcomes,
        HarnessStorageMode::from_env(),
    )
    .await
}

pub async fn run_scenario_report_with_outcomes_and_storage_mode(
    spec: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    expected_outcomes: Vec<TraceExpectation>,
    storage_mode: HarnessStorageMode,
) -> Result<ScenarioReport, ScenarioRunError> {
    let mut subject = EngineHarnessSubject::new_with_topology(
        &spec.clients,
        &spec.topology,
        ProtocolProfile::Legacy,
        storage_mode,
    )
    .map_err(subject_setup_error)?;
    run_scenario_report_inner(spec, expected_trace, expected_outcomes, None, &mut subject).await
}

/// Run the in-process engine subject and retain a bounded exact-transport tail.
/// When explicitly requested, also capture the final planned recipient tick;
/// callers must treat that checkpoint as sensitive even with synthetic keys.
pub async fn run_scenario_report_with_outcomes_and_capture(
    spec: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    expected_outcomes: Vec<TraceExpectation>,
    storage_mode: HarnessStorageMode,
    capture_sensitive_replay: bool,
) -> Result<(ScenarioReport, crate::ScenarioFailureCaptureV1), ScenarioRunError> {
    let mut subject = EngineHarnessSubject::new_with_topology(
        &spec.clients,
        &spec.topology,
        ProtocolProfile::Legacy,
        storage_mode,
    )
    .map_err(subject_setup_error)?;
    if capture_sensitive_replay && let Some(recipient_tick) = final_planned_recipient_tick(spec) {
        subject.capture_failure_replay_at_tick(recipient_tick);
    }
    let report =
        run_scenario_report_inner(spec, expected_trace, expected_outcomes, None, &mut subject)
            .await?;
    Ok((
        report,
        crate::ScenarioFailureCaptureV1 {
            transport: subject.captured_transport_window(),
            byte_replay: subject.byte_replay_capture(),
        },
    ))
}

/// Build a complete report using an explicitly supplied adapter.
///
/// Capability validation runs before the subject receives any action.
pub async fn run_scenario_report_with_subject(
    spec: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    expected_outcomes: Vec<TraceExpectation>,
    subject: &mut dyn ConvergenceSubject,
) -> Result<ScenarioReport, ScenarioRunError> {
    run_scenario_report_inner(spec, expected_trace, expected_outcomes, None, subject).await
}

pub async fn run_vector_fixture_report(
    fixture: &VectorFixture,
) -> Result<ScenarioReport, ScenarioRunError> {
    run_vector_fixture_report_with_storage_mode(fixture, HarnessStorageMode::from_env()).await
}

pub async fn run_vector_fixture_report_with_storage_mode(
    fixture: &VectorFixture,
    storage_mode: HarnessStorageMode,
) -> Result<ScenarioReport, ScenarioRunError> {
    let protocol_profile = fixture_protocol_profile(fixture)?;
    let mut subject = EngineHarnessSubject::new_with_topology(
        &fixture.scenario.clients,
        &fixture.scenario.topology,
        protocol_profile,
        storage_mode,
    )
    .map_err(subject_setup_error)?;
    run_scenario_report_inner(
        &fixture.scenario,
        fixture.expected_trace.clone(),
        fixture.expected_outcomes.clone(),
        Some(VectorFixtureMetadata {
            scenario_name: fixture.scenario_name.clone(),
            vector_version: fixture.vector_version.clone(),
            conformance_version: fixture.conformance_version.clone(),
            seed: fixture.seed,
        }),
        &mut subject,
    )
    .await
}

/// Vector runner variant used by the report CLI when it must emit exact wire
/// evidence and, by explicit opt-in, a final recipient-tick checkpoint.
pub async fn run_vector_fixture_report_with_capture(
    fixture: &VectorFixture,
    storage_mode: HarnessStorageMode,
    capture_sensitive_replay: bool,
) -> Result<(ScenarioReport, crate::ScenarioFailureCaptureV1), ScenarioRunError> {
    let protocol_profile = fixture_protocol_profile(fixture)?;
    let mut subject = EngineHarnessSubject::new_with_topology(
        &fixture.scenario.clients,
        &fixture.scenario.topology,
        protocol_profile,
        storage_mode,
    )
    .map_err(subject_setup_error)?;
    if capture_sensitive_replay
        && let Some(recipient_tick) = final_planned_recipient_tick(&fixture.scenario)
    {
        subject.capture_failure_replay_at_tick(recipient_tick);
    }
    let report = run_scenario_report_inner(
        &fixture.scenario,
        fixture.expected_trace.clone(),
        fixture.expected_outcomes.clone(),
        Some(VectorFixtureMetadata {
            scenario_name: fixture.scenario_name.clone(),
            vector_version: fixture.vector_version.clone(),
            conformance_version: fixture.conformance_version.clone(),
            seed: fixture.seed,
        }),
        &mut subject,
    )
    .await?;
    Ok((
        report,
        crate::ScenarioFailureCaptureV1 {
            transport: subject.captured_transport_window(),
            byte_replay: subject.byte_replay_capture(),
        },
    ))
}

fn final_planned_recipient_tick(spec: &ScenarioSpec) -> Option<usize> {
    spec.steps
        .iter()
        .filter_map(|step| match step {
            ScenarioStep::Tick { clients } => Some(clients.len()),
            _ => None,
        })
        .sum::<usize>()
        .checked_sub(1)
}

fn fixture_protocol_profile(fixture: &VectorFixture) -> Result<ProtocolProfile, ScenarioRunError> {
    Ok(
        match fixture
            .application_profile
            .as_ref()
            .map(|profile| profile.name.as_str())
        {
            None | Some("legacy") => ProtocolProfile::Legacy,
            Some("current") => ProtocolProfile::Current,
            Some(name) => {
                return Err(ScenarioRunError {
                    step_index: None,
                    kind: "unsupported_application_profile".into(),
                    category: SubjectFailureCategory::Environment,
                    message: format!("unsupported application profile {name}"),
                });
            }
        },
    )
}

#[derive(Default)]
struct ScenarioStepOutputs {
    pending_resolutions: Vec<PendingResolutionObservation>,
    observations: Vec<ClientObservation>,
    decryptability_probes: Vec<BidirectionalDecryptabilityObservation>,
    admin_policy_observations: Vec<ScenarioAdminPolicyObservation>,
    error_observations: Vec<ScenarioErrorObservation>,
    quiescence_observations: Vec<QuiescenceObservation>,
    assertion_observations: Vec<crate::ScenarioAssertionObservationV2>,
}

async fn execute_scenario_step(
    spec: &ScenarioSpec,
    step_index: usize,
    action_id: &str,
    step: &ScenarioStep,
    subject: &mut dyn ConvergenceSubject,
    outputs: &mut ScenarioStepOutputs,
) -> Result<(), ScenarioRunError> {
    let ScenarioStepOutputs {
        pending_resolutions,
        observations,
        decryptability_probes,
        admin_policy_observations,
        error_observations,
        quiescence_observations,
        assertion_observations,
    } = outputs;
    match step {
        ScenarioStep::InGroup { .. } => {
            unreachable!("in_group is lowered by the Scenario IR compiler")
        }
        ScenarioStep::CreateGroup {
            creator,
            name,
            invitees,
            required_features,
            initial_admins,
            pending,
        } => {
            let initial_admin_labels = initial_admins
                .clone()
                .unwrap_or_else(|| scenario_initial_admins(spec, step_index, invitees));
            subject
                .create_group(SubjectCreateGroup {
                    action_id,
                    creator,
                    name,
                    invitees,
                    required_features,
                    initial_admins: &initial_admin_labels,
                    pending,
                })
                .await
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::InviteMembers {
            inviter,
            invitees,
            pending,
        } => {
            subject
                .invite_members(SubjectInviteMembers {
                    action_id,
                    inviter,
                    invitees,
                    pending,
                })
                .await
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::RemoveMembers {
            remover,
            members,
            pending,
        } => {
            subject
                .remove_members(SubjectRemoveMembers {
                    action_id,
                    remover,
                    members,
                    pending,
                })
                .await
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::SelfUpdate { client, pending } => {
            subject
                .self_update(SubjectSelfUpdate {
                    action_id,
                    client,
                    pending,
                })
                .await
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::UpdateGroupData {
            client,
            name,
            pending,
        } => {
            subject
                .update_group_data(SubjectUpdateGroupData {
                    action_id,
                    client,
                    name: Some(name),
                    description: None,
                    pending,
                })
                .await
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::UpdateGroupProfile {
            client,
            name,
            description,
            pending,
        } => {
            subject
                .update_group_data(SubjectUpdateGroupData {
                    action_id,
                    client,
                    name: name.as_deref(),
                    description: description.as_deref(),
                    pending,
                })
                .await
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::UpdateAdminPolicy {
            client,
            admins,
            pending,
        } => {
            subject
                .update_admin_policy(SubjectUpdateAdminPolicy {
                    action_id: Some(action_id),
                    client,
                    admins,
                    pending: Some(pending),
                })
                .await
                .map_err(|error| {
                    let mut failure = subject_step_error(step_index, error);
                    failure.message = format!(
                        "update_admin_policy unexpectedly failed: {}",
                        failure.message
                    );
                    failure
                })?;
        }
        ScenarioStep::ExpectUpdateAdminPolicyError {
            client,
            admins,
            error,
        } => {
            let client_label = client.clone();
            match subject
                .update_admin_policy(SubjectUpdateAdminPolicy {
                    action_id: None,
                    client,
                    admins,
                    pending: None,
                })
                .await
            {
                Ok(_) => {
                    return Err(err(
                        step_index,
                        format!("update_admin_policy unexpectedly succeeded; expected {error}"),
                    ));
                }
                Err(actual) => {
                    if &actual.code != error {
                        return Err(err(
                            step_index,
                            format!(
                                "update_admin_policy failed with {}; expected {error}",
                                actual.code
                            ),
                        ));
                    }
                    error_observations.push(ScenarioErrorObservation {
                        step_index,
                        client: client_label,
                        operation: "update_admin_policy".into(),
                        error: actual.code,
                    });
                }
            }
        }
        ScenarioStep::AcknowledgeOutbound {
            client,
            publication,
            selection,
            outcome,
        } => {
            let client_label = client.clone();
            let already_accepted = if let Some(publication) = publication {
                subject.scenario_publication_already_accepted(client, publication)
            } else {
                false
            };
            if already_accepted {
                if *outcome != SubjectOutboundOutcome::Accepted {
                    return Err(subject_step_error(
                        step_index,
                        SubjectError::classified(
                            SubjectFailureCategory::ExpectedRefusal,
                            "publication_rollback_rejected",
                            format!(
                                "publication {publication:?} for client {client} was already accepted and cannot be rolled back"
                            ),
                        ),
                    ));
                }
            } else {
                let artifacts = subject
                    .poll_outbound(client)
                    .map_err(|error| subject_step_error(step_index, error))?
                    .into_iter()
                    .filter(|artifact| {
                        publication.as_ref().is_none_or(|publication| {
                            artifact.publication.as_ref() == Some(publication)
                        }) && selection.matches(artifact)
                    })
                    .collect::<Vec<_>>();
                if artifacts.is_empty() && publication.is_some() {
                    return Err(subject_step_error(
                        step_index,
                        SubjectError::classified(
                            SubjectFailureCategory::ExpectedRefusal,
                            "publication_not_found",
                            format!(
                                "no unresolved outbound artifacts matched client {client}, publication {publication:?}, selection {selection:?}"
                            ),
                        ),
                    ));
                }
                for artifact in artifacts {
                    subject
                        .acknowledge_outbound(client, &artifact.outbound_id, *outcome)
                        .await
                        .map_err(|error| subject_step_error(step_index, error))?;
                }
            }
            if let Some(publication) = publication {
                pending_resolutions.push(PendingResolutionObservation {
                    step_index,
                    client: client_label,
                    pending: publication.clone(),
                    resolution: match outcome {
                        SubjectOutboundOutcome::Accepted => "confirmed",
                        SubjectOutboundOutcome::ReachedNoEndpoint => "rolled_back",
                    }
                    .into(),
                });
            }
        }
        ScenarioStep::SendAppMessage { sender, payload } => {
            subject
                .send_application(SubjectSendApplication {
                    action_id,
                    sender,
                    payload,
                })
                .await
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::Leave { client } => {
            subject
                .leave(action_id, client)
                .await
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::DeliverAll => subject
            .deliver_all()
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::Tick { clients: labels } => {
            subject
                .tick(labels)
                .await
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::AdvanceTime { delta_ms } => {
            subject
                .advance_time(*delta_ms)
                .await
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::AwaitQuiescence { policy } => {
            quiescence_observations.push(
                drive_subject_to_quiescence(subject, &spec.clients, policy, step_index)
                    .await
                    .map_err(|error| subject_step_error(step_index, error))?,
            );
        }
        ScenarioStep::Observe { clients: labels } => {
            observations.extend(
                subject
                    .observe(labels)
                    .map_err(|error| subject_step_error(step_index, error))?,
            );
        }
        ScenarioStep::ObserveExact { clients: labels } => {
            observations.extend(
                subject
                    .observe_exact(labels)
                    .map_err(|error| subject_step_error(step_index, error))?,
            );
        }
        ScenarioStep::ProbeBidirectionalDecryptability { clients: labels } => {
            decryptability_probes.push(
                subject
                    .probe_bidirectional_decryptability(labels, step_index)
                    .await
                    .map_err(|error| subject_step_error(step_index, error))?,
            );
        }
        ScenarioStep::ObserveAdminPolicy { clients: labels } => {
            admin_policy_observations.extend(
                subject
                    .observe_admin_policy(labels)
                    .map_err(|error| subject_step_error(step_index, error))?,
            );
        }
        ScenarioStep::ClearEvents { clients: labels } => {
            subject
                .clear_events(labels)
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::OmitMessage { selector } => {
            subject_faults(subject, step_index)?
                .omit_message(selector)
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::DuplicateMessage { selector } => {
            subject_faults(subject, step_index)?
                .duplicate_message(selector)
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::WithholdMessage { selector, label } => {
            subject_faults(subject, step_index)?
                .withhold_message(selector, label)
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::ReleaseWithheld { label } => {
            subject_faults(subject, step_index)?
                .release_withheld(label)
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::ReorderMessages { order } => {
            subject_faults(subject, step_index)?
                .reorder_messages(order)
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::SetPartition { allow } => {
            subject_faults(subject, step_index)?
                .set_partition(allow)
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::ClearPartition => subject_faults(subject, step_index)?
            .clear_partition()
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::RestartClient { client } => {
            subject
                .restart(client)
                .map_err(|error| subject_step_error(step_index, error))?;
        }
        ScenarioStep::SetClientOffline { client } => subject
            .set_client_online(client, false)
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::ReconnectClient { client } => subject
            .set_client_online(client, true)
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::SyncRelayHistory { clients, sync } => subject
            .sync_relay_history(clients, sync)
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::ConfigureRelay {
            relay,
            order,
            duplicate_copies,
        } => subject
            .configure_relay(relay, *order, *duplicate_copies)
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::SetRelayEventVisibility {
            relay,
            selector,
            clients,
            visible,
        } => subject
            .set_relay_event_visibility(relay, selector, clients, *visible)
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::ReconcileRelayHistories { relays } => subject
            .reconcile_relay_histories(relays)
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::CrashProcess { process } => subject
            .crash_process(process)
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::RestartProcess { process } => subject
            .restart_process(process)
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::InjectStorageFault { fault } => subject
            .inject_storage_fault(fault)
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::ClearStorageFault { target } => subject
            .clear_storage_fault(target)
            .map_err(|error| subject_step_error(step_index, error))?,
        ScenarioStep::Barrier { .. } => {}
        ScenarioStep::Assert { assertion } => {
            let observation = execute_assertion(assertion, subject, &spec.clients, step_index)
                .await
                .map_err(|error| subject_step_error(step_index, error))?;
            let passed = observation.passed;
            let final_actual = observation.final_actual.clone();
            assertion_observations.push(observation);
            if !passed {
                return Err(err(
                    step_index,
                    format!("scenario assertion failed; final actual {final_actual}"),
                ));
            }
        }
    }
    Ok::<(), ScenarioRunError>(())
}

async fn execute_assertion(
    assertion: &crate::ScenarioAssertionV2,
    subject: &mut dyn ConvergenceSubject,
    clients: &[String],
    step_index: usize,
) -> Result<crate::ScenarioAssertionObservationV2, SubjectError> {
    use crate::ScenarioAssertionV2;

    let mut samples = 0_usize;
    let mut elapsed_virtual_ms = 0_u64;
    let mut final_actual = serde_json::Value::Null;
    let passed = match assertion {
        ScenarioAssertionV2::Exactly { predicate } => {
            let observation = subject.evaluate_predicate(predicate)?;
            samples = 1;
            final_actual = observation.actual;
            observation.matched
        }
        ScenarioAssertionV2::Eventually {
            predicate,
            max_iterations,
        } => {
            let mut matched = false;
            for iteration in 0..=*max_iterations {
                let observation = subject.evaluate_predicate(predicate)?;
                samples += 1;
                final_actual = observation.actual;
                if observation.matched {
                    matched = true;
                    break;
                }
                if iteration < *max_iterations {
                    subject.tick(clients).await?;
                }
            }
            matched
        }
        ScenarioAssertionV2::Within {
            predicate,
            timeout_ms,
            poll_interval_ms,
        } => {
            let mut matched = false;
            loop {
                let observation = subject.evaluate_predicate(predicate)?;
                samples += 1;
                final_actual = observation.actual;
                if observation.matched {
                    matched = true;
                    break;
                }
                if elapsed_virtual_ms == *timeout_ms {
                    break;
                }
                let delta = (*timeout_ms - elapsed_virtual_ms).min(*poll_interval_ms);
                subject.advance_time(delta).await?;
                elapsed_virtual_ms += delta;
                subject.tick(clients).await?;
            }
            matched
        }
        ScenarioAssertionV2::Never {
            predicate,
            duration_ms,
            poll_interval_ms,
        } => {
            let mut never_matched = true;
            loop {
                let observation = subject.evaluate_predicate(predicate)?;
                samples += 1;
                final_actual = observation.actual;
                if observation.matched {
                    never_matched = false;
                    break;
                }
                if elapsed_virtual_ms == *duration_ms {
                    break;
                }
                let delta = (*duration_ms - elapsed_virtual_ms).min(*poll_interval_ms);
                subject.advance_time(delta).await?;
                elapsed_virtual_ms += delta;
                subject.tick(clients).await?;
            }
            never_matched
        }
        ScenarioAssertionV2::Resource {
            metric,
            comparison,
            value,
        } => {
            let snapshot = subject.structural_progress()?;
            let actual = crate::resource_value(&snapshot, *metric);
            samples = 1;
            final_actual = serde_json::json!({
                "metric": metric,
                "value": actual,
                "structural_token": snapshot.structural_token,
            });
            comparison.matches(actual, *value)
        }
    };
    Ok(crate::ScenarioAssertionObservationV2 {
        step_index,
        assertion: assertion.clone(),
        passed,
        samples,
        elapsed_virtual_ms,
        final_actual,
    })
}

async fn run_scenario_report_inner(
    spec: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    expected_outcomes: Vec<TraceExpectation>,
    fixture: Option<VectorFixtureMetadata>,
    subject: &mut dyn ConvergenceSubject,
) -> Result<ScenarioReport, ScenarioRunError> {
    let scenario_started = std::time::Instant::now();
    let descriptor = subject.descriptor();
    let compiled = compile_scenario(spec)?;
    preflight_compiled_scenario(&compiled, &descriptor)?;
    let mut outputs = ScenarioStepOutputs::default();
    let mut step_log = Vec::new();
    let mut sampled_max_queue_depth = 0_usize;

    for action in &compiled.actions {
        let step_started = std::time::Instant::now();
        let step_index = action.schedule.source_step_index;
        let step = &action.step;
        let step_result = if let Some(group) = action.scenario_group.as_deref() {
            subject
                .select_scenario_group(group, matches!(step, ScenarioStep::CreateGroup { .. }))
                .map_err(|error| subject_step_error(step_index, error))
        } else {
            Ok(())
        };
        let step_result = match step_result {
            Ok(()) => {
                execute_scenario_step(
                    spec,
                    step_index,
                    &action.schedule.action_id,
                    step,
                    subject,
                    &mut outputs,
                )
                .await
            }
            Err(error) => Err(error),
        };
        if descriptor.supports(crate::SubjectCapability::StructuralProgress)
            && let Ok(progress) = subject.structural_progress()
        {
            sampled_max_queue_depth = sampled_max_queue_depth.max(
                progress
                    .transport_queued_messages
                    .saturating_add(progress.transport_delayed_messages)
                    .saturating_add(progress.transport_mailbox_messages),
            );
        }
        if let Err(error) = step_result {
            step_log.push(ScenarioStepLogEntry {
                step_index,
                step_type: step.kind().into(),
                status: ScenarioStepStatus::Failed {
                    kind: error.kind,
                    category: error.category,
                    message: error.message,
                },
                wall_us: elapsed_us(step_started.elapsed()),
            });
            break;
        }
        step_log.push(ScenarioStepLogEntry {
            step_index,
            step_type: step.kind().into(),
            status: ScenarioStepStatus::Completed,
            wall_us: elapsed_us(step_started.elapsed()),
        });
    }

    let ScenarioStepOutputs {
        pending_resolutions,
        observations,
        decryptability_probes,
        admin_policy_observations,
        error_observations,
        quiescence_observations,
        assertion_observations,
    } = outputs;
    let relay_sync_observations = subject.relay_sync_observations();

    let observed_trace = ScenarioTrace {
        name: spec.name.clone(),
        pending_resolutions,
        errors: error_observations,
        admin_policies: admin_policy_observations,
        decryptability_probes,
        observations,
    };
    let pending_resolution_observations = observed_trace.pending_resolutions.clone();
    let epoch_change_observations = observed_trace
        .observations
        .iter()
        .flat_map(|observation| {
            observation
                .epoch_changes
                .iter()
                .map(|epoch_change| EpochChangeReportObservation {
                    client: observation.client.clone(),
                    from: epoch_change.from,
                    to: epoch_change.to,
                })
        })
        .collect();
    let app_invalidation_observations = observed_trace
        .observations
        .iter()
        .flat_map(|observation| {
            observation.app_invalidations.iter().map(|invalidation| {
                AppInvalidationReportObservation {
                    client: observation.client.clone(),
                    epoch: invalidation.epoch,
                    reason: invalidation.reason.clone(),
                    payload_ref: invalidation.payload_ref.clone(),
                }
            })
        })
        .collect();
    let mut expectation_failures =
        compare_trace_expectations(expected_trace.as_ref(), &expected_outcomes, &observed_trace);
    for observation in &quiescence_observations {
        if !observation.status.is_quiescent() {
            expectation_failures.push(ExpectationFailure {
                kind: "quiescence_not_reached".into(),
                message: format!(
                    "await_quiescence step {} ended as {:?}",
                    observation.step_index, observation.status
                ),
                expected: serde_json::json!({"status": "quiescent"}),
                actual: serde_json::to_value(observation)
                    .expect("quiescence observation serializes"),
            });
        }
    }
    let invariant_failures = invariant_failures(&expectation_failures);
    let oracle = build_scenario_oracle_report(
        spec,
        expected_trace.as_ref(),
        &expected_outcomes,
        &observed_trace,
        &assertion_observations,
        &quiescence_observations,
    );

    let database_bytes = subject.database_bytes();
    let replay_probe_count = subject.replay_probe_count();
    let engine_metrics = subject.engine_metrics();
    let mut report = ScenarioReport {
        metadata: ScenarioReportMetadata {
            scenario_name: spec.name.clone(),
            spec_version: spec.spec_version.clone(),
            step_count: compiled.actions.len(),
            storage_backend: descriptor.storage_backend.clone(),
            subject: Some(descriptor),
            generated: None,
            fixture,
            input_provenance: None,
        },
        scenario: spec.clone(),
        resolved_topology: compiled.topology.clone(),
        expanded_schedule: compiled.expanded_schedule(),
        assertion_observations,
        relay_sync_observations,
        expected_trace,
        expected_outcomes,
        observed_trace: Some(observed_trace),
        oracle,
        step_log,
        pending_resolution_observations,
        quiescence_observations,
        epoch_change_observations,
        app_invalidation_observations,
        expectation_failures,
        invariant_failures,
        campaign_measurements: crate::CampaignMeasurementsV1::default(),
    };
    report.campaign_measurements = crate::CampaignMeasurementsV1::from_report(
        &report,
        elapsed_us(scenario_started.elapsed()),
        database_bytes,
        sampled_max_queue_depth,
        replay_probe_count,
        engine_metrics.as_ref(),
    );
    Ok(report)
}

fn elapsed_us(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Validate adapter support before the first scenario action is executed.
pub fn validate_scenario_for_subject(
    spec: &ScenarioSpec,
    descriptor: &SubjectDescriptor,
) -> Result<(), ScenarioRunError> {
    let compiled = compile_scenario(spec)?;
    preflight_compiled_scenario(&compiled, descriptor)
}

fn scenario_initial_admins(
    spec: &ScenarioSpec,
    create_step_index: usize,
    invitees: &[String],
) -> Vec<String> {
    invitees
        .iter()
        .filter(|invitee| {
            spec.steps
                .iter()
                .skip(create_step_index + 1)
                .any(|step| admin_gated_actor(step).is_some_and(|actor| actor == invitee.as_str()))
        })
        .cloned()
        .collect()
}

fn admin_gated_actor(step: &ScenarioStep) -> Option<&str> {
    match step {
        ScenarioStep::InviteMembers { inviter, .. } => Some(inviter),
        ScenarioStep::UpdateGroupData { client, .. }
        | ScenarioStep::UpdateGroupProfile { client, .. } => Some(client),
        ScenarioStep::UpdateAdminPolicy { client, .. } => Some(client),
        _ => None,
    }
}

fn subject_faults(
    subject: &mut dyn ConvergenceSubject,
    step_index: usize,
) -> Result<&mut dyn ConvergenceFaultSubject, ScenarioRunError> {
    subject.fault_injection().ok_or_else(|| {
        err(
            step_index,
            "subject declared a white-box fault capability without a fault interface".into(),
        )
    })
}

fn err(step_index: usize, message: String) -> ScenarioRunError {
    ScenarioRunError {
        step_index: Some(step_index),
        kind: "scenario_error".into(),
        category: SubjectFailureCategory::Environment,
        message,
    }
}

pub(crate) fn subject_setup_error(error: SubjectError) -> ScenarioRunError {
    let message = error.to_string();
    ScenarioRunError {
        step_index: None,
        kind: error.code,
        category: error.category,
        message,
    }
}

fn subject_step_error(step_index: usize, error: SubjectError) -> ScenarioRunError {
    ScenarioRunError {
        step_index: Some(step_index),
        kind: error.code,
        category: error.category,
        message: error.message,
    }
}

fn invariant_failures(expectation_failures: &[ExpectationFailure]) -> Vec<InvariantFailure> {
    expectation_failures
        .iter()
        .map(|failure| InvariantFailure {
            kind: failure.kind.clone(),
            message: failure.message.clone(),
        })
        .collect()
}

fn ensure_execution_succeeded(report: &ScenarioReport) -> Result<(), ScenarioRunError> {
    if let Some(step) = report
        .step_log
        .iter()
        .find(|step| !step.status.is_completed())
    {
        let ScenarioStepStatus::Failed {
            kind,
            category,
            message,
        } = &step.status
        else {
            unreachable!("non-completed step must be failed")
        };
        return Err(ScenarioRunError {
            step_index: Some(step.step_index),
            kind: kind.clone(),
            category: *category,
            message: message.clone(),
        });
    }
    let Some(observation) = report
        .quiescence_observations
        .iter()
        .find(|observation| !observation.status.is_quiescent())
    else {
        return Ok(());
    };
    let artifact = serde_json::to_string(observation).unwrap_or_else(|_| "unserializable".into());
    Err(ScenarioRunError {
        step_index: Some(observation.step_index),
        kind: "quiescence_not_reached".into(),
        category: SubjectFailureCategory::Protocol,
        message: format!("quiescence was not reached: {artifact}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::required_capabilities;
    use crate::{SubjectCapability, SubjectSendApplication};
    use async_trait::async_trait;
    use std::collections::BTreeSet;

    struct RecordingSubject {
        descriptor: SubjectDescriptor,
        send_called: bool,
        time_advances: Vec<u64>,
    }

    #[async_trait]
    impl ConvergenceSubject for RecordingSubject {
        fn descriptor(&self) -> SubjectDescriptor {
            self.descriptor.clone()
        }

        async fn send_application(
            &mut self,
            _action: SubjectSendApplication<'_>,
        ) -> Result<(), SubjectError> {
            self.send_called = true;
            Ok(())
        }

        async fn advance_time(&mut self, delta_ms: u64) -> Result<(), SubjectError> {
            self.time_advances.push(delta_ms);
            Ok(())
        }
    }

    #[test]
    fn fallback_initial_admins_include_future_admin_policy_actors() {
        let spec = ScenarioSpec {
            name: "admin policy fallback".to_owned(),
            spec_version: "2".to_owned(),
            topology: Default::default(),
            clients: vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()],
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".to_owned(),
                    name: "agent".to_owned(),
                    invitees: vec!["bob".to_owned(), "carol".to_owned()],
                    required_features: Vec::new(),
                    initial_admins: None,
                    pending: "create".to_owned(),
                },
                ScenarioStep::UpdateAdminPolicy {
                    client: "bob".to_owned(),
                    admins: vec!["alice".to_owned(), "bob".to_owned()],
                    pending: "admins".to_owned(),
                },
            ],
        };

        assert_eq!(
            scenario_initial_admins(&spec, 0, &["bob".to_owned(), "carol".to_owned()]),
            vec!["bob".to_owned()]
        );
    }

    #[tokio::test]
    async fn unsupported_capability_is_rejected_before_subject_action() {
        let spec = ScenarioSpec {
            name: "unsupported-subject-capability/v1".to_owned(),
            spec_version: "2".to_owned(),
            topology: Default::default(),
            clients: vec!["alice".to_owned()],
            steps: vec![
                ScenarioStep::SendAppMessage {
                    sender: "alice".to_owned(),
                    payload: "hello".to_owned(),
                },
                ScenarioStep::RestartClient {
                    client: "alice".to_owned(),
                },
            ],
        };
        let mut subject = RecordingSubject {
            descriptor: SubjectDescriptor {
                adapter: "recording-subject".to_owned(),
                adapter_version: "1".to_owned(),
                storage_backend: "none".to_owned(),
                capabilities: BTreeSet::from([SubjectCapability::ApplicationMessaging]),
            },
            send_called: false,
            time_advances: Vec::new(),
        };

        let error = run_scenario_spec_with_subject(&spec, &mut subject)
            .await
            .expect_err("unsupported scenario must fail preflight");

        assert_eq!(error.step_index, Some(1));
        assert!(error.message.contains("crash_reopen"));
        assert!(!subject.send_called);
    }

    #[tokio::test]
    async fn virtual_time_is_capability_gated_serializable_and_dispatched() {
        let spec = ScenarioSpec {
            name: "subject-virtual-time/v1".to_owned(),
            spec_version: "2".to_owned(),
            topology: Default::default(),
            clients: vec!["alice".to_owned(), "bob".to_owned()],
            steps: vec![ScenarioStep::AdvanceTime { delta_ms: 750 }],
        };
        let encoded = serde_json::to_value(&spec).expect("virtual time scenario serializes");
        assert_eq!(encoded["steps"][0]["type"], "advance_time");
        assert_eq!(encoded["steps"][0]["delta_ms"], 750);
        let decoded: ScenarioSpec =
            serde_json::from_value(encoded).expect("virtual time scenario deserializes");
        assert_eq!(decoded, spec);
        let mut subject = RecordingSubject {
            descriptor: SubjectDescriptor {
                adapter: "recording-subject".to_owned(),
                adapter_version: "1".to_owned(),
                storage_backend: "none".to_owned(),
                capabilities: BTreeSet::new(),
            },
            send_called: false,
            time_advances: Vec::new(),
        };

        let error = run_scenario_spec_with_subject(&spec, &mut subject)
            .await
            .expect_err("virtual time must fail preflight when unsupported");
        assert_eq!(error.step_index, Some(0));
        assert!(error.message.contains("virtual_time"));
        assert!(subject.time_advances.is_empty());

        subject
            .descriptor
            .capabilities
            .insert(SubjectCapability::VirtualTime);
        run_scenario_spec_with_subject(&spec, &mut subject)
            .await
            .expect("supported virtual time step succeeds");
        assert_eq!(subject.time_advances, vec![750]);
    }

    #[test]
    fn await_quiescence_is_serializable_and_requires_composed_capabilities() {
        let step = ScenarioStep::AwaitQuiescence {
            policy: QuiescencePolicy::default(),
        };
        let encoded = serde_json::to_value(&step).expect("quiescence step serializes");
        assert_eq!(encoded["type"], "await_quiescence");
        assert_eq!(encoded["policy"]["max_iterations"], 256);
        assert_eq!(
            serde_json::from_value::<ScenarioStep>(encoded).expect("quiescence step deserializes"),
            step
        );
        assert_eq!(
            required_capabilities(&step),
            vec![
                SubjectCapability::StructuralProgress,
                SubjectCapability::VirtualTime,
                SubjectCapability::TransportDelivery,
                SubjectCapability::OutboundPublication,
            ]
        );

        let manual = ScenarioStep::AwaitQuiescence {
            policy: QuiescencePolicy {
                outbound: crate::QuiescenceOutboundPolicy::Manual,
                ..QuiescencePolicy::default()
            },
        };
        assert!(!required_capabilities(&manual).contains(&SubjectCapability::OutboundPublication));
    }

    #[tokio::test]
    async fn await_quiescence_drives_a_real_subject_and_records_the_terminal_artifact() {
        let spec = ScenarioSpec {
            name: "await-quiescence-smoke/v1".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into(), "bob".into()],
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "quiescence".into(),
                    invitees: vec!["bob".into()],
                    required_features: Vec::new(),
                    initial_admins: None,
                    pending: "create".into(),
                },
                ScenarioStep::AwaitQuiescence {
                    policy: QuiescencePolicy::default(),
                },
                ScenarioStep::ObserveExact {
                    clients: vec!["alice".into(), "bob".into()],
                },
            ],
        };

        let report = run_scenario_report(&spec, None)
            .await
            .expect("real subject scenario runs");
        assert_eq!(report.quiescence_observations.len(), 1);
        assert_eq!(
            report.quiescence_observations[0].status,
            crate::QuiescenceStatus::Quiescent
        );
        assert!(
            report.quiescence_observations[0]
                .final_progress
                .is_quiescent()
        );
        assert!(report.expectation_failures.is_empty());
        assert!(
            report
                .oracle
                .observed_behaviors
                .contains(&crate::OracleBehavior::QuiescenceState)
        );
    }

    #[tokio::test]
    async fn blocked_quiescence_is_a_report_artifact_and_a_spec_run_error() {
        let spec = ScenarioSpec {
            name: "await-quiescence-blocked/v1".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into(), "bob".into()],
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "quiescence".into(),
                    invitees: vec!["bob".into()],
                    required_features: Vec::new(),
                    initial_admins: None,
                    pending: "create".into(),
                },
                ScenarioStep::AwaitQuiescence {
                    policy: QuiescencePolicy::default(),
                },
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "withheld".into(),
                },
                ScenarioStep::AcknowledgeOutbound {
                    client: "alice".into(),
                    publication: None,
                    selection: ScenarioOutboundSelection::All,
                    outcome: SubjectOutboundOutcome::Accepted,
                },
                ScenarioStep::WithholdMessage {
                    selector: crate::ScenarioMessageSelectorV2 {
                        sender: Some("alice".into()),
                        class: Some(crate::ScenarioTransportClass::Application),
                        ..Default::default()
                    },
                    label: "withheld".into(),
                },
                ScenarioStep::AwaitQuiescence {
                    policy: QuiescencePolicy::default(),
                },
            ],
        };

        let report = run_scenario_report(&spec, None)
            .await
            .expect("blocked quiescence still produces a report");
        assert!(matches!(
            report.quiescence_observations[1].status,
            crate::QuiescenceStatus::Blocked { .. }
        ));
        assert_eq!(
            report.expectation_failures[0].kind,
            "quiescence_not_reached"
        );

        let error = run_scenario_spec(&spec)
            .await
            .expect_err("a blocked await step cannot silently succeed");
        assert_eq!(error.step_index, Some(5));
        assert!(error.message.contains("transport_delayed"));
        assert!(error.message.contains("\"status\":\"blocked\""));
    }

    #[tokio::test]
    async fn subject_step_failure_is_a_report_artifact_and_a_spec_run_error() {
        let spec = ScenarioSpec {
            name: "step-failure-artifact/v1".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into()],
            steps: vec![ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: Some("missing-publication".into()),
                selection: ScenarioOutboundSelection::All,
                outcome: SubjectOutboundOutcome::Accepted,
            }],
        };

        let report = run_scenario_report(&spec, None)
            .await
            .expect("execution failures remain reportable");
        assert!(matches!(
            &report.step_log[0].status,
            ScenarioStepStatus::Failed { message, .. } if message.contains("no unresolved outbound")
        ));
        assert!(report.observed_trace.is_some());

        let error = run_scenario_spec(&spec)
            .await
            .expect_err("trace-only execution still reports the failed step");
        assert_eq!(error.step_index, Some(0));
        assert!(error.message.contains("no unresolved outbound"));
    }

    #[test]
    fn legacy_failed_step_status_defaults_its_failure_kind() {
        let status: ScenarioStepStatus = serde_json::from_value(serde_json::json!({
            "status": "failed",
            "message": "legacy report"
        }))
        .expect("legacy failed status remains readable");

        assert_eq!(
            status,
            ScenarioStepStatus::Failed {
                kind: "scenario_step_failed".into(),
                category: SubjectFailureCategory::Environment,
                message: "legacy report".into(),
            }
        );
    }

    #[tokio::test]
    async fn fixed_point_is_invariant_to_same_horizon_batch_partitioning() {
        fn scenario(split_delivery: bool) -> ScenarioSpec {
            let clients = vec!["alice".into(), "bob".into(), "carol".into()];
            let mut steps = vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "batch-partition".into(),
                    invitees: vec!["bob".into(), "carol".into()],
                    required_features: Vec::new(),
                    initial_admins: Some(vec!["bob".into()]),
                    pending: "create".into(),
                },
                ScenarioStep::AwaitQuiescence {
                    policy: QuiescencePolicy::default(),
                },
                ScenarioStep::UpdateGroupData {
                    client: "alice".into(),
                    name: "alice branch".into(),
                    pending: "alice-update".into(),
                },
                ScenarioStep::UpdateGroupData {
                    client: "bob".into(),
                    name: "bob branch".into(),
                    pending: "bob-update".into(),
                },
                ScenarioStep::accept_publication("alice", "alice-update"),
                ScenarioStep::accept_publication("bob", "bob-update"),
            ];
            if split_delivery {
                steps.extend([
                    ScenarioStep::WithholdMessage {
                        selector: crate::ScenarioMessageSelectorV2 {
                            sender: Some("bob".into()),
                            class: Some(crate::ScenarioTransportClass::Commit),
                            ..Default::default()
                        },
                        label: "second-branch".into(),
                    },
                    ScenarioStep::DeliverAll,
                    ScenarioStep::Tick {
                        clients: clients.clone(),
                    },
                    ScenarioStep::AdvanceTime { delta_ms: 1_000 },
                    ScenarioStep::Tick {
                        clients: clients.clone(),
                    },
                    ScenarioStep::ReleaseWithheld {
                        label: "second-branch".into(),
                    },
                ]);
            }
            steps.extend([
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: clients.clone(),
                },
                ScenarioStep::AwaitQuiescence {
                    policy: QuiescencePolicy::default(),
                },
                ScenarioStep::ObserveExact {
                    clients: clients.clone(),
                },
            ]);
            ScenarioSpec {
                name: if split_delivery {
                    "same-horizon-split/v1".into()
                } else {
                    "same-horizon-batch/v1".into()
                },
                spec_version: "2".into(),
                topology: Default::default(),
                clients,
                steps,
            }
        }

        let batch = run_scenario_report(&scenario(false), None)
            .await
            .expect("batch scenario runs");
        let split = run_scenario_report(&scenario(true), None)
            .await
            .expect("split scenario runs");
        assert!(batch.expectation_failures.is_empty(), "{batch:#?}");
        assert!(split.expectation_failures.is_empty(), "{split:#?}");

        let states = |report: &ScenarioReport| {
            report
                .observed_trace
                .as_ref()
                .expect("trace exists")
                .observations
                .iter()
                .map(|observation| {
                    observation
                        .canonical_state
                        .clone()
                        .expect("exact state exists")
                })
                .collect::<Vec<_>>()
        };
        let batch_states = states(&batch);
        let split_states = states(&split);
        let retention_assumption_violations = |report: &ScenarioReport| {
            report
                .observed_trace
                .as_ref()
                .expect("trace exists")
                .observations
                .iter()
                .flat_map(|observation| {
                    observation
                        .scenario_input_ledger
                        .iter()
                        .filter(|entry| {
                            entry.expired > 0
                                || entry.resource_refused > 0
                                || entry.rejected > 0
                                || entry.ingest_errors > 0
                        })
                        .map(|entry| {
                            format!(
                                "{}:{}:{:?}",
                                observation.client, entry.scenario_id, entry.disposition
                            )
                        })
                })
                .collect::<Vec<_>>()
        };
        assert!(
            retention_assumption_violations(&batch).is_empty(),
            "batch retention/anchor assumption violations: {:?}",
            retention_assumption_violations(&batch)
        );
        assert!(
            retention_assumption_violations(&split).is_empty(),
            "split retention/anchor assumption violations: {:?}",
            retention_assumption_violations(&split)
        );
        assert!(batch_states.iter().all(|state| state == &batch_states[0]));
        assert!(split_states.iter().all(|state| state == &split_states[0]));
        let semantic_result = |state: &crate::ConformanceCanonicalStateSnapshot| match state {
            crate::ConformanceCanonicalStateSnapshot::Live(snapshot) => (
                snapshot.epoch,
                snapshot.group_name.clone(),
                snapshot.group_description.clone(),
                snapshot.sorted_member_identities_hex.clone(),
                snapshot.admin_identities_hex.clone(),
                snapshot.protocol_lifecycle,
                snapshot.protocol_profile,
            ),
            crate::ConformanceCanonicalStateSnapshot::Disbanded(_) => {
                panic!("metamorphic branch race unexpectedly disbanded")
            }
        };
        assert_eq!(
            semantic_result(&batch_states[0]),
            semantic_result(&split_states[0])
        );
    }

    #[test]
    fn semantic_fault_steps_require_adapter_neutral_capability() {
        let capabilities = required_capabilities(&ScenarioStep::OmitMessage {
            selector: crate::ScenarioMessageSelectorV2 {
                sender: Some("alice".into()),
                ..Default::default()
            },
        });

        assert_eq!(
            capabilities,
            vec![SubjectCapability::SemanticTransportFaults]
        );
        assert!(!capabilities[0].is_white_box());
    }

    #[test]
    fn scenario_spec_v1_is_rejected_after_clean_v2_cutover() {
        let spec = ScenarioSpec {
            name: "removed-v1".to_owned(),
            spec_version: "1".to_owned(),
            topology: Default::default(),
            clients: vec!["alice".to_owned()],
            steps: Vec::new(),
        };
        let descriptor = SubjectDescriptor {
            adapter: "recording-subject".to_owned(),
            adapter_version: "1".to_owned(),
            storage_backend: "none".to_owned(),
            capabilities: BTreeSet::new(),
        };

        let error = validate_scenario_for_subject(&spec, &descriptor)
            .expect_err("ScenarioSpec v1 must not retain a runtime compatibility path");

        assert_eq!(error.step_index, None);
        assert!(error.message.contains("unsupported ScenarioSpec version 1"));
    }

    #[test]
    fn sensitive_replay_targets_only_the_final_planned_recipient_tick() {
        let spec = ScenarioSpec {
            name: "replay-target".to_owned(),
            spec_version: "2".to_owned(),
            topology: Default::default(),
            clients: vec!["alice".to_owned(), "bob".to_owned()],
            steps: vec![
                ScenarioStep::Tick {
                    clients: vec!["alice".to_owned()],
                },
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["alice".to_owned(), "bob".to_owned()],
                },
            ],
        };

        assert_eq!(final_planned_recipient_tick(&spec), Some(2));
    }

    #[tokio::test]
    async fn default_and_explicit_engine_subjects_share_outbound_lifecycle() {
        let spec = ScenarioSpec {
            name: "subject-boundary-smoke/v2".to_owned(),
            spec_version: "2".to_owned(),
            topology: Default::default(),
            clients: vec!["alice".to_owned(), "bob".to_owned()],
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".to_owned(),
                    name: "subject-boundary".to_owned(),
                    invitees: vec!["bob".to_owned()],
                    required_features: Vec::new(),
                    initial_admins: None,
                    pending: "create".to_owned(),
                },
                ScenarioStep::accept_publication("alice".to_owned(), "create".to_owned()),
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["bob".to_owned()],
                },
                ScenarioStep::Observe {
                    clients: vec!["alice".to_owned(), "bob".to_owned()],
                },
            ],
        };

        let default_trace = run_scenario_spec(&spec)
            .await
            .expect("default engine runner succeeds");
        let mut subject = EngineHarnessSubject::new(
            &spec.clients,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        let explicit_trace = run_scenario_spec_with_subject(&spec, &mut subject)
            .await
            .expect("explicit engine subject succeeds");

        assert_eq!(explicit_trace, default_trace);
    }
}
