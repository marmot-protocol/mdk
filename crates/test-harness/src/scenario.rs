//! Serializable scripted scenarios for the harness.
//!
//! `ScenarioSpec` is the v1 input-side companion to `ScenarioTrace`: external
//! implementations can drive the same logical client operations, then compare
//! their observed trace to the fixture's expected trace.

use crate::{ClientBuilder, HarnessClient, ScenarioTrace, TransportBus, observe_client};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::KeyPackage;
use cgka_traits::engine_state::PendingStateRef;
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
        pending: String,
    },
    InviteMembers {
        inviter: String,
        invitees: Vec<String>,
        pending: String,
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
}

impl ScenarioStep {
    pub fn kind(&self) -> &'static str {
        match self {
            ScenarioStep::CreateGroup { .. } => "create_group",
            ScenarioStep::InviteMembers { .. } => "invite_members",
            ScenarioStep::ConfirmPending { .. } => "confirm_pending",
            ScenarioStep::FailPending { .. } => "fail_pending",
            ScenarioStep::SendAppMessage { .. } => "send_app_message",
            ScenarioStep::Leave { .. } => "leave",
            ScenarioStep::DeliverAll => "deliver_all",
            ScenarioStep::Tick { .. } => "tick",
            ScenarioStep::Observe { .. } => "observe",
            ScenarioStep::DropQueued { .. } => "drop_queued",
            ScenarioStep::DuplicateQueued { .. } => "duplicate_queued",
            ScenarioStep::DelayQueued { .. } => "delay_queued",
            ScenarioStep::ReleaseDelayed { .. } => "release_delayed",
            ScenarioStep::ReorderQueued { .. } => "reorder_queued",
            ScenarioStep::SetPartition { .. } => "set_partition",
            ScenarioStep::ClearPartition => "clear_partition",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub metadata: ScenarioReportMetadata,
    pub expected_trace: Option<ScenarioTrace>,
    pub observed_trace: Option<ScenarioTrace>,
    pub step_log: Vec<ScenarioStepLogEntry>,
    pub recovery_observations: Vec<crate::ForkRecoveryObservation>,
    pub invariant_failures: Vec<InvariantFailure>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioReportMetadata {
    pub scenario_name: String,
    pub spec_version: String,
    pub step_count: usize,
    pub generated: Option<GeneratedScenarioMetadata>,
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
    let mut observations = Vec::new();
    let mut step_log = Vec::new();

    for (step_index, step) in spec.steps.iter().enumerate() {
        match step {
            ScenarioStep::CreateGroup {
                creator,
                name,
                invitees,
                required_features,
                pending,
            } => {
                let key_packages = fresh_key_packages(&mut clients, invitees, step_index).await?;
                let required_features =
                    required_features_from_names(required_features, step_index)?;
                let creator = client_mut(&mut clients, creator, step_index)?;
                let (_group_id, pending_ref) = creator
                    .create_group(name, key_packages, required_features)
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
            ScenarioStep::ConfirmPending { client, pending } => {
                let pending_ref = take_pending(&mut pending_refs, pending, step_index)?;
                let client = client_mut(&mut clients, client, step_index)?;
                client.confirm(pending_ref).await;
            }
            ScenarioStep::FailPending { client, pending } => {
                let pending_ref = take_pending(&mut pending_refs, pending, step_index)?;
                let client = client_mut(&mut clients, client, step_index)?;
                client.fail(pending_ref).await;
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
        }
        step_log.push(ScenarioStepLogEntry {
            step_index,
            step_type: step.kind().into(),
            status: ScenarioStepStatus::Completed,
        });
    }

    let observed_trace = ScenarioTrace {
        name: spec.name.clone(),
        observations,
    };
    let recovery_observations = observed_trace
        .observations
        .iter()
        .flat_map(|observation| observation.recoveries.clone())
        .collect();
    let invariant_failures = invariant_failures(expected_trace.as_ref(), &observed_trace);

    Ok(ScenarioReport {
        metadata: ScenarioReportMetadata {
            scenario_name: spec.name.clone(),
            spec_version: spec.spec_version.clone(),
            step_count: spec.steps.len(),
            generated: None,
        },
        expected_trace,
        observed_trace: Some(observed_trace),
        step_log,
        recovery_observations,
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

fn invariant_failures(
    expected_trace: Option<&ScenarioTrace>,
    observed_trace: &ScenarioTrace,
) -> Vec<InvariantFailure> {
    let Some(expected_trace) = expected_trace else {
        return vec![];
    };
    if expected_trace == observed_trace {
        return vec![];
    }
    vec![InvariantFailure {
        kind: "trace_mismatch".into(),
        message: format!(
            "expected trace for {} did not match observed trace",
            observed_trace.name
        ),
    }]
}
