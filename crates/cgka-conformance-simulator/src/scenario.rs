//! Serializable scripted scenarios for the harness.
//!
//! `ScenarioSpec` is the v1 input-side companion to `ScenarioTrace`: external
//! implementations can drive the same logical client operations, then compare
//! their observed trace to exact or semantic fixture expectations.

use crate::{
    ConvergenceFaultSubject, ConvergenceSubject, EngineHarnessSubject, ExpectationFailure,
    HarnessStorageMode, PendingResolutionObservation, ScenarioErrorObservation,
    ScenarioOracleReport, ScenarioTrace, SubjectCreateGroup, SubjectDescriptor, SubjectError,
    SubjectInviteMembers, SubjectSendApplication, SubjectUpdateAdminPolicy, SubjectUpdateGroupData,
    TraceExpectation, VectorFixture, build_scenario_oracle_report, compare_trace_expectations,
    required_capability,
};
use cgka_traits::group::ProtocolProfile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioSpec {
    pub name: String,
    pub spec_version: String,
    pub clients: Vec<String>,
    pub steps: Vec<ScenarioStep>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScenarioStep {
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
    UpdateGroupData {
        client: String,
        name: String,
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
    ConfirmPending {
        client: String,
        pending: String,
    },
    FailPending {
        client: String,
        pending: String,
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
    DropQueued {
        index: usize,
    },
    DuplicateQueued {
        index: usize,
    },
    DelayQueued {
        index: usize,
        delayed: String,
    },
    ReleaseDelayed {
        delayed: String,
    },
    ReorderQueued {
        order: Vec<usize>,
    },
    SetPartition {
        allow: Vec<String>,
    },
    ClearPartition,
    RestartClient {
        client: String,
    },
}

impl ScenarioStep {
    pub fn kind(&self) -> &'static str {
        match self {
            ScenarioStep::CreateGroup { .. } => "create_group",
            ScenarioStep::InviteMembers { .. } => "invite_members",
            ScenarioStep::UpdateGroupData { .. } => "update_group_data",
            ScenarioStep::UpdateAdminPolicy { .. } => "update_admin_policy",
            ScenarioStep::ExpectUpdateAdminPolicyError { .. } => "expect_update_admin_policy_error",
            ScenarioStep::ConfirmPending { .. } => "confirm_pending",
            ScenarioStep::FailPending { .. } => "fail_pending",
            ScenarioStep::SendAppMessage { .. } => "send_app_message",
            ScenarioStep::Leave { .. } => "leave",
            ScenarioStep::DeliverAll => "deliver_all",
            ScenarioStep::Tick { .. } => "tick",
            ScenarioStep::AdvanceTime { .. } => "advance_time",
            ScenarioStep::Observe { .. } => "observe",
            ScenarioStep::ObserveExact { .. } => "observe_exact",
            ScenarioStep::ProbeBidirectionalDecryptability { .. } => {
                "probe_bidirectional_decryptability"
            }
            ScenarioStep::ObserveAdminPolicy { .. } => "observe_admin_policy",
            ScenarioStep::ClearEvents { .. } => "clear_events",
            ScenarioStep::DropQueued { .. } => "drop_queued",
            ScenarioStep::DuplicateQueued { .. } => "duplicate_queued",
            ScenarioStep::DelayQueued { .. } => "delay_queued",
            ScenarioStep::ReleaseDelayed { .. } => "release_delayed",
            ScenarioStep::ReorderQueued { .. } => "reorder_queued",
            ScenarioStep::SetPartition { .. } => "set_partition",
            ScenarioStep::ClearPartition => "clear_partition",
            ScenarioStep::RestartClient { .. } => "restart_client",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub metadata: ScenarioReportMetadata,
    pub scenario: ScenarioSpec,
    pub expected_trace: Option<ScenarioTrace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_outcomes: Vec<TraceExpectation>,
    pub observed_trace: Option<ScenarioTrace>,
    pub oracle: ScenarioOracleReport,
    pub step_log: Vec<ScenarioStepLogEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_resolution_observations: Vec<PendingResolutionObservation>,
    pub recovery_observations: Vec<crate::ForkRecoveryObservation>,
    pub epoch_change_observations: Vec<EpochChangeReportObservation>,
    pub app_invalidation_observations: Vec<AppInvalidationReportObservation>,
    #[serde(default)]
    pub expectation_failures: Vec<ExpectationFailure>,
    pub invariant_failures: Vec<InvariantFailure>,
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ScenarioStepStatus {
    Completed,
    Failed { message: String },
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
    Ok(report
        .observed_trace
        .expect("successful report always includes an observed trace"))
}

/// Run ScenarioSpec v1 through an explicitly supplied convergence subject.
pub async fn run_scenario_spec_with_subject(
    spec: &ScenarioSpec,
    subject: &mut dyn ConvergenceSubject,
) -> Result<ScenarioTrace, ScenarioRunError> {
    let report = run_scenario_report_with_subject(spec, None, Vec::new(), subject).await?;
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
    let mut subject =
        EngineHarnessSubject::new(&spec.clients, ProtocolProfile::Legacy, storage_mode)
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
    let mut subject =
        EngineHarnessSubject::new(&spec.clients, ProtocolProfile::Legacy, storage_mode)
            .map_err(subject_setup_error)?;
    run_scenario_report_inner(spec, expected_trace, expected_outcomes, None, &mut subject).await
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
    let protocol_profile = match fixture
        .application_profile
        .as_ref()
        .map(|profile| profile.name.as_str())
    {
        None | Some("legacy") => ProtocolProfile::Legacy,
        Some("current") => ProtocolProfile::Current,
        Some(name) => {
            return Err(ScenarioRunError {
                step_index: None,
                message: format!("unsupported application profile {name}"),
            });
        }
    };
    let mut subject =
        EngineHarnessSubject::new(&fixture.scenario.clients, protocol_profile, storage_mode)
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

async fn run_scenario_report_inner(
    spec: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    expected_outcomes: Vec<TraceExpectation>,
    fixture: Option<VectorFixtureMetadata>,
    subject: &mut dyn ConvergenceSubject,
) -> Result<ScenarioReport, ScenarioRunError> {
    let descriptor = subject.descriptor();
    validate_scenario_for_subject(spec, &descriptor)?;
    let mut pending_resolutions = Vec::new();
    let mut observations = Vec::new();
    let mut decryptability_probes = Vec::new();
    let mut admin_policy_observations = Vec::new();
    let mut error_observations = Vec::new();
    let mut step_log = Vec::new();

    for (step_index, step) in spec.steps.iter().enumerate() {
        let action_id = scenario_input_id(step_index, step);
        match step {
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
                        action_id: &action_id,
                        inviter,
                        invitees,
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
                        action_id: &action_id,
                        client,
                        name,
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
                        action_id: Some(&action_id),
                        client,
                        admins,
                        pending: Some(pending),
                    })
                    .await
                    .map_err(|error| {
                        err(
                            step_index,
                            format!("update_admin_policy unexpectedly failed: {error}"),
                        )
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
            ScenarioStep::ConfirmPending { client, pending } => {
                let client_label = client.clone();
                subject
                    .confirm_pending(client, pending)
                    .await
                    .map_err(|error| subject_step_error(step_index, error))?;
                pending_resolutions.push(PendingResolutionObservation {
                    step_index,
                    client: client_label,
                    pending: pending.clone(),
                    resolution: "confirmed".into(),
                });
            }
            ScenarioStep::FailPending { client, pending } => {
                let client_label = client.clone();
                subject
                    .fail_pending(client, pending)
                    .await
                    .map_err(|error| subject_step_error(step_index, error))?;
                pending_resolutions.push(PendingResolutionObservation {
                    step_index,
                    client: client_label,
                    pending: pending.clone(),
                    resolution: "rolled_back".into(),
                });
            }
            ScenarioStep::SendAppMessage { sender, payload } => {
                subject
                    .send_application(SubjectSendApplication {
                        action_id: &action_id,
                        sender,
                        payload,
                    })
                    .await
                    .map_err(|error| subject_step_error(step_index, error))?;
            }
            ScenarioStep::Leave { client } => {
                subject
                    .leave(&action_id, client)
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
            ScenarioStep::DropQueued { index } => {
                subject_faults(subject, step_index)?
                    .drop_queued(*index)
                    .map_err(|error| subject_step_error(step_index, error))?;
            }
            ScenarioStep::DuplicateQueued { index } => {
                subject_faults(subject, step_index)?
                    .duplicate_queued(*index)
                    .map_err(|error| subject_step_error(step_index, error))?;
            }
            ScenarioStep::DelayQueued { index, delayed } => {
                subject_faults(subject, step_index)?
                    .delay_queued(*index, delayed)
                    .map_err(|error| subject_step_error(step_index, error))?;
            }
            ScenarioStep::ReleaseDelayed { delayed } => {
                subject_faults(subject, step_index)?
                    .release_delayed(delayed)
                    .map_err(|error| subject_step_error(step_index, error))?;
            }
            ScenarioStep::ReorderQueued { order } => {
                subject_faults(subject, step_index)?
                    .reorder_queued(order)
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
        }
        step_log.push(ScenarioStepLogEntry {
            step_index,
            step_type: step.kind().into(),
            status: ScenarioStepStatus::Completed,
        });
    }

    let observed_trace = ScenarioTrace {
        name: spec.name.clone(),
        pending_resolutions,
        errors: error_observations,
        admin_policies: admin_policy_observations,
        decryptability_probes,
        observations,
    };
    let pending_resolution_observations = observed_trace.pending_resolutions.clone();
    let recovery_observations = observed_trace
        .observations
        .iter()
        .flat_map(|observation| observation.recoveries.clone())
        .collect();
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
    let expectation_failures =
        compare_trace_expectations(expected_trace.as_ref(), &expected_outcomes, &observed_trace);
    let invariant_failures = invariant_failures(&expectation_failures);
    let oracle = build_scenario_oracle_report(
        spec,
        expected_trace.as_ref(),
        &expected_outcomes,
        &observed_trace,
    );

    Ok(ScenarioReport {
        metadata: ScenarioReportMetadata {
            scenario_name: spec.name.clone(),
            spec_version: spec.spec_version.clone(),
            step_count: spec.steps.len(),
            storage_backend: descriptor.storage_backend.clone(),
            subject: Some(descriptor),
            generated: None,
            fixture,
        },
        scenario: spec.clone(),
        expected_trace,
        expected_outcomes,
        observed_trace: Some(observed_trace),
        oracle,
        step_log,
        pending_resolution_observations,
        recovery_observations,
        epoch_change_observations,
        app_invalidation_observations,
        expectation_failures,
        invariant_failures,
    })
}

fn scenario_input_id(step_index: usize, step: &ScenarioStep) -> String {
    format!("step-{step_index}:{}", step.kind())
}

/// Validate adapter support before the first scenario action is executed.
pub fn validate_scenario_for_subject(
    spec: &ScenarioSpec,
    descriptor: &SubjectDescriptor,
) -> Result<(), ScenarioRunError> {
    if spec.spec_version != "1" {
        return Err(ScenarioRunError {
            step_index: None,
            message: format!("unsupported ScenarioSpec version {}", spec.spec_version),
        });
    }
    let mut clients = BTreeSet::new();
    for label in &spec.clients {
        if !clients.insert(label) {
            return Err(ScenarioRunError {
                step_index: None,
                message: format!("duplicate client label {label}"),
            });
        }
    }
    for (step_index, step) in spec.steps.iter().enumerate() {
        let capability = required_capability(step);
        if !descriptor.supports(capability) {
            return Err(err(
                step_index,
                format!(
                    "subject {} does not support capability {} required by {}",
                    descriptor.adapter,
                    capability,
                    step.kind()
                ),
            ));
        }
    }
    Ok(())
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
        ScenarioStep::UpdateGroupData { client, .. } => Some(client),
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
        message,
    }
}

fn subject_setup_error(error: SubjectError) -> ScenarioRunError {
    ScenarioRunError {
        step_index: None,
        message: error.to_string(),
    }
}

fn subject_step_error(step_index: usize, error: SubjectError) -> ScenarioRunError {
    err(step_index, error.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SubjectCapability, SubjectSendApplication};
    use async_trait::async_trait;

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
            spec_version: "1".to_owned(),
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
            spec_version: "1".to_owned(),
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
            spec_version: "1".to_owned(),
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
    fn queue_fault_steps_require_explicit_white_box_capability() {
        let capability = required_capability(&ScenarioStep::DropQueued { index: 0 });

        assert_eq!(capability, SubjectCapability::WhiteBoxTransportQueueFaults);
        assert!(capability.is_white_box());
    }

    #[tokio::test]
    async fn explicit_engine_subject_preserves_default_runner_trace() {
        let spec = ScenarioSpec {
            name: "subject-boundary-smoke/v1".to_owned(),
            spec_version: "1".to_owned(),
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
                ScenarioStep::ConfirmPending {
                    client: "alice".to_owned(),
                    pending: "create".to_owned(),
                },
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
