//! Serializable scripted scenarios for the harness.
//!
//! `ScenarioSpec` is the v1 input-side companion to `ScenarioTrace`: external
//! implementations can drive the same logical client operations, then compare
//! their observed trace to exact or semantic fixture expectations.

use crate::{
    ClientBuilder, ExpectationFailure, HarnessClient, PendingResolutionObservation,
    ScenarioAdminPolicyObservation, ScenarioErrorObservation, ScenarioOracleReport, ScenarioTrace,
    TraceExpectation, TransportBus, VectorFixture, build_scenario_oracle_report,
    compare_trace_expectations, observe_client,
};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::EngineError;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::KeyPackage;
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::types::MemberId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
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
    Observe {
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
            ScenarioStep::Observe { .. } => "observe",
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

pub async fn run_scenario_report(
    spec: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
) -> Result<ScenarioReport, ScenarioRunError> {
    run_scenario_report_inner(spec, expected_trace, vec![], None).await
}

pub async fn run_scenario_report_with_outcomes(
    spec: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    expected_outcomes: Vec<TraceExpectation>,
) -> Result<ScenarioReport, ScenarioRunError> {
    run_scenario_report_inner(spec, expected_trace, expected_outcomes, None).await
}

pub async fn run_vector_fixture_report(
    fixture: &VectorFixture,
) -> Result<ScenarioReport, ScenarioRunError> {
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
    )
    .await
}

async fn run_scenario_report_inner(
    spec: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    expected_outcomes: Vec<TraceExpectation>,
    fixture: Option<VectorFixtureMetadata>,
) -> Result<ScenarioReport, ScenarioRunError> {
    if spec.spec_version != "1" {
        return Err(ScenarioRunError {
            step_index: None,
            message: format!("unsupported ScenarioSpec version {}", spec.spec_version),
        });
    }
    let bus = TransportBus::ordered();
    let mut clients = BTreeMap::new();
    for label in &spec.clients {
        if clients.contains_key(label) {
            return Err(ScenarioRunError {
                step_index: None,
                message: format!("duplicate client label {label}"),
            });
        }
        let client = ClientBuilder::new(pad32(label.as_bytes()))
            .registry(scenario_registry())
            .attach(&bus);
        clients.insert(label.clone(), client);
    }

    let mut pending_refs = HashMap::new();
    let mut pending_resolutions = Vec::new();
    let mut observations = Vec::new();
    let mut admin_policy_observations = Vec::new();
    let mut error_observations = Vec::new();
    let mut step_log = Vec::new();

    for (step_index, step) in spec.steps.iter().enumerate() {
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
                let initial_admins = member_ids(&clients, &initial_admin_labels, step_index)?;
                let key_packages = fresh_key_packages(&mut clients, invitees, step_index).await?;
                let required_features =
                    required_features_from_names(required_features, step_index)?;
                let creator = client_mut(&mut clients, creator, step_index)?;
                let (_group_id, pending_ref) = creator
                    .create_group_with_admins(name, key_packages, required_features, initial_admins)
                    .await;
                insert_pending(&mut pending_refs, pending, pending_ref, step_index)?;
            }
            ScenarioStep::InviteMembers {
                inviter,
                invitees,
                pending,
            } => {
                let key_packages = fresh_key_packages(&mut clients, invitees, step_index).await?;
                let inviter = client_mut(&mut clients, inviter, step_index)?;
                let pending_ref = inviter.invite(key_packages).await;
                insert_pending(&mut pending_refs, pending, pending_ref, step_index)?;
            }
            ScenarioStep::UpdateGroupData {
                client,
                name,
                pending,
            } => {
                let client = client_mut(&mut clients, client, step_index)?;
                let pending_ref = client.update_group_data(name.clone()).await;
                insert_pending(&mut pending_refs, pending, pending_ref, step_index)?;
            }
            ScenarioStep::UpdateAdminPolicy {
                client,
                admins,
                pending,
            } => {
                let admin_ids = member_ids(&clients, admins, step_index)?;
                let client = client_mut(&mut clients, client, step_index)?;
                let pending_ref = client.update_admin_policy(admin_ids).await.map_err(|e| {
                    err(
                        step_index,
                        format!("update_admin_policy unexpectedly failed: {e}"),
                    )
                })?;
                insert_pending(&mut pending_refs, pending, pending_ref, step_index)?;
            }
            ScenarioStep::ExpectUpdateAdminPolicyError {
                client,
                admins,
                error,
            } => {
                let admin_ids = member_ids(&clients, admins, step_index)?;
                let client_label = client.clone();
                let client = client_mut(&mut clients, client, step_index)?;
                match client.update_admin_policy(admin_ids).await {
                    Ok(_) => {
                        return Err(err(
                            step_index,
                            format!("update_admin_policy unexpectedly succeeded; expected {error}"),
                        ));
                    }
                    Err(actual) => {
                        let actual = observe_engine_error(&actual);
                        if &actual != error {
                            return Err(err(
                                step_index,
                                format!(
                                    "update_admin_policy failed with {actual}; expected {error}"
                                ),
                            ));
                        }
                        error_observations.push(ScenarioErrorObservation {
                            step_index,
                            client: client_label,
                            operation: "update_admin_policy".into(),
                            error: actual,
                        });
                    }
                }
            }
            ScenarioStep::ConfirmPending { client, pending } => {
                let pending_ref = take_pending(&mut pending_refs, pending, step_index)?;
                let client_label = client.clone();
                let client = client_mut(&mut clients, client, step_index)?;
                client.confirm(pending_ref).await;
                pending_resolutions.push(PendingResolutionObservation {
                    step_index,
                    client: client_label,
                    pending: pending.clone(),
                    resolution: "confirmed".into(),
                });
            }
            ScenarioStep::FailPending { client, pending } => {
                let pending_ref = take_pending(&mut pending_refs, pending, step_index)?;
                let client_label = client.clone();
                let client = client_mut(&mut clients, client, step_index)?;
                client.fail(pending_ref).await;
                pending_resolutions.push(PendingResolutionObservation {
                    step_index,
                    client: client_label,
                    pending: pending.clone(),
                    resolution: "rolled_back".into(),
                });
            }
            ScenarioStep::SendAppMessage { sender, payload } => {
                let sender = client_mut(&mut clients, sender, step_index)?;
                sender.send_app(payload.clone().into_bytes()).await;
            }
            ScenarioStep::Leave { client } => {
                let client = client_mut(&mut clients, client, step_index)?;
                client.leave().await;
            }
            ScenarioStep::DeliverAll => bus.deliver_all(),
            ScenarioStep::Tick { clients: labels } => {
                for label in labels {
                    let client = client_mut(&mut clients, label, step_index)?;
                    client.tick().await;
                }
            }
            ScenarioStep::Observe { clients: labels } => {
                for label in labels {
                    let client = client_mut(&mut clients, label, step_index)?;
                    observations.push(observe_client(label.clone(), client));
                }
            }
            ScenarioStep::ObserveAdminPolicy { clients: labels } => {
                for label in labels {
                    let client = client_ref(&clients, label, step_index)?;
                    admin_policy_observations.push(ScenarioAdminPolicyObservation {
                        client: label.clone(),
                        admins: client.admin_labels(),
                    });
                }
            }
            ScenarioStep::ClearEvents { clients: labels } => {
                for label in labels {
                    let client = client_mut(&mut clients, label, step_index)?;
                    client.drain_events();
                }
            }
            ScenarioStep::DropQueued { index } => {
                if !bus.drop_queued(*index) {
                    return Err(err(
                        step_index,
                        format!("queued message index {index} does not exist"),
                    ));
                }
            }
            ScenarioStep::DuplicateQueued { index } => {
                if !bus.duplicate_queued(*index) {
                    return Err(err(
                        step_index,
                        format!("queued message index {index} does not exist"),
                    ));
                }
            }
            ScenarioStep::DelayQueued { index, delayed } => {
                if !bus.delay_queued(*index, delayed.clone()) {
                    return Err(err(
                        step_index,
                        format!("queued message index {index} does not exist"),
                    ));
                }
            }
            ScenarioStep::ReleaseDelayed { delayed } => {
                if !bus.release_delayed(delayed) {
                    return Err(err(
                        step_index,
                        format!("delayed queue label {delayed} does not exist"),
                    ));
                }
            }
            ScenarioStep::ReorderQueued { order } => {
                if !bus.reorder_queued(order) {
                    return Err(err(
                        step_index,
                        format!("invalid queue reorder permutation {order:?}"),
                    ));
                }
            }
            ScenarioStep::SetPartition { allow } => {
                let mut allowed = Vec::with_capacity(allow.len());
                for label in allow {
                    allowed.push(client_ref(&clients, label, step_index)?.bus_id);
                }
                bus.set_partition(Some(allowed));
            }
            ScenarioStep::ClearPartition => bus.set_partition(None),
            ScenarioStep::RestartClient { client } => {
                let client = client_mut(&mut clients, client, step_index)?;
                client.restart();
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

async fn fresh_key_packages(
    clients: &mut BTreeMap<String, HarnessClient>,
    labels: &[String],
    step_index: usize,
) -> Result<Vec<KeyPackage>, ScenarioRunError> {
    let mut key_packages = Vec::with_capacity(labels.len());
    for label in labels {
        let client = client_mut(clients, label, step_index)?;
        key_packages.push(client.fresh_key_package().await);
    }
    Ok(key_packages)
}

fn member_ids(
    clients: &BTreeMap<String, HarnessClient>,
    labels: &[String],
    step_index: usize,
) -> Result<Vec<MemberId>, ScenarioRunError> {
    labels
        .iter()
        .map(|label| client_ref(clients, label, step_index).map(HarnessClient::member_id))
        .collect()
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

fn insert_pending(
    pending_refs: &mut HashMap<String, PendingStateRef>,
    label: &str,
    pending_ref: PendingStateRef,
    step_index: usize,
) -> Result<(), ScenarioRunError> {
    if pending_refs
        .insert(label.to_string(), pending_ref)
        .is_some()
    {
        return Err(err(step_index, format!("duplicate pending label {label}")));
    }
    Ok(())
}

fn take_pending(
    pending_refs: &mut HashMap<String, PendingStateRef>,
    label: &str,
    step_index: usize,
) -> Result<PendingStateRef, ScenarioRunError> {
    pending_refs
        .remove(label)
        .ok_or_else(|| err(step_index, format!("unknown pending label {label}")))
}

fn client_ref<'a>(
    clients: &'a BTreeMap<String, HarnessClient>,
    label: &str,
    step_index: usize,
) -> Result<&'a HarnessClient, ScenarioRunError> {
    clients
        .get(label)
        .ok_or_else(|| err(step_index, format!("unknown client {label}")))
}

fn client_mut<'a>(
    clients: &'a mut BTreeMap<String, HarnessClient>,
    label: &str,
    step_index: usize,
) -> Result<&'a mut HarnessClient, ScenarioRunError> {
    clients
        .get_mut(label)
        .ok_or_else(|| err(step_index, format!("unknown client {label}")))
}

fn required_features_from_names(
    names: &[String],
    step_index: usize,
) -> Result<Vec<Feature>, ScenarioRunError> {
    names
        .iter()
        .map(|name| match name.as_str() {
            "self-remove" => Ok(Feature("self-remove")),
            _ => Err(err(step_index, format!("unknown required feature {name}"))),
        })
        .collect()
}

fn scenario_registry() -> FeatureRegistry {
    let mut registry = FeatureRegistry::new();
    registry.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    registry
}

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

fn err(step_index: usize, message: String) -> ScenarioRunError {
    ScenarioRunError {
        step_index: Some(step_index),
        message,
    }
}

fn observe_engine_error(error: &EngineError) -> String {
    match error {
        EngineError::NotGroupAdmin { .. } => "not_group_admin",
        EngineError::AdminCannotSelfRemove { .. } | EngineError::AdminDepletion { .. } => {
            "admin_policy"
        }
        EngineError::Serialize(_) => "invalid_admin_policy",
        EngineError::InvalidTransition(_) => "invalid_transition",
        EngineError::UnknownGroup(_) => "unknown_group",
        EngineError::UnknownMember { .. } => "unknown_member",
        EngineError::NotAMember { .. } => "not_a_member",
        EngineError::Other(_) => "other",
        EngineError::Backend(_) => "backend",
        EngineError::Storage(_) => "storage",
        EngineError::Peeler(_) => "peeler",
        EngineError::ForkedEpoch { .. } => "forked_epoch",
        EngineError::MissingRequiredCapabilities { .. } => "missing_required_capabilities",
        EngineError::InvalidCredentialIdentity(_) => "invalid_credential_identity",
        EngineError::InvalidAccountIdentityProof(_) => "invalid_account_identity_proof",
        EngineError::UnsupportedCiphersuite { .. } => "unsupported_ciphersuite",
        EngineError::InvalidAppMessagePayload(_) => "invalid_app_message_payload",
        EngineError::UnknownPending => "unknown_pending",
    }
    .into()
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
}
