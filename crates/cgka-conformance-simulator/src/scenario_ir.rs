//! Canonical compilation contract for adapter-neutral scenario input.
//!
//! Scenario documents are serialized as [`ScenarioSpec`](crate::ScenarioSpec)
//! v2. Adapters never interpret that document directly: compilation validates
//! stable identities and produces one deterministic action schedule which is
//! then preflighted against the selected adapter before any action executes.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    ScenarioRunError, ScenarioSpec, ScenarioStep, SubjectCapability, SubjectDescriptor,
    SubjectFailureCategory, required_capabilities,
};

pub const SCENARIO_IR_VERSION: &str = "2";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioActionScheduleV2 {
    pub action_id: String,
    pub source_step_index: usize,
    pub action_type: String,
    /// Virtual monotonic time immediately before the action executes.
    pub virtual_time_ms: u64,
    pub required_capabilities: BTreeSet<SubjectCapability>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledScenarioActionV2 {
    pub schedule: ScenarioActionScheduleV2,
    pub step: ScenarioStep,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledScenarioV2 {
    pub name: String,
    pub spec_version: String,
    pub clients: Vec<String>,
    pub topology: crate::ScenarioTopologyV2,
    pub actions: Vec<CompiledScenarioActionV2>,
}

impl CompiledScenarioV2 {
    pub fn expanded_schedule(&self) -> Vec<ScenarioActionScheduleV2> {
        self.actions
            .iter()
            .map(|action| action.schedule.clone())
            .collect()
    }
}

pub fn stable_action_id(source_step_index: usize, step: &ScenarioStep) -> String {
    format!("step-{source_step_index}:{}", step.kind())
}

/// Compile canonical JSON input into the only schedule adapters may execute.
pub fn compile_scenario(spec: &ScenarioSpec) -> Result<CompiledScenarioV2, ScenarioRunError> {
    if spec.spec_version != SCENARIO_IR_VERSION {
        return Err(ScenarioRunError {
            step_index: None,
            kind: "unsupported_scenario_version".into(),
            category: SubjectFailureCategory::Environment,
            message: format!("unsupported ScenarioSpec version {}", spec.spec_version),
        });
    }
    if spec.name.trim().is_empty() {
        return Err(compile_error(
            None,
            "scenario name must not be empty".into(),
        ));
    }

    let mut clients = BTreeSet::new();
    for label in &spec.clients {
        if label.trim().is_empty() {
            return Err(compile_error(None, "client label must not be empty".into()));
        }
        if !clients.insert(label) {
            return Err(ScenarioRunError {
                step_index: None,
                kind: "duplicate_client".into(),
                category: SubjectFailureCategory::Environment,
                message: format!("duplicate client label {label}"),
            });
        }
    }

    let mut virtual_time_ms = 0_u64;
    let topology = spec.topology.resolve_for_clients(&spec.clients)?;
    let mut action_ids = BTreeSet::new();
    let mut actions = Vec::with_capacity(spec.steps.len());
    for (source_step_index, step) in spec.steps.iter().enumerate() {
        validate_step(source_step_index, step, &clients, &topology)?;
        let action_id = stable_action_id(source_step_index, step);
        if !action_ids.insert(action_id.clone()) {
            return Err(compile_error(
                Some(source_step_index),
                format!("duplicate compiled action id {action_id}"),
            ));
        }
        let required_capabilities = required_capabilities(step).into_iter().collect();
        actions.push(CompiledScenarioActionV2 {
            schedule: ScenarioActionScheduleV2 {
                action_id,
                source_step_index,
                action_type: step.kind().into(),
                virtual_time_ms,
                required_capabilities,
            },
            step: step.clone(),
        });
        if let ScenarioStep::AdvanceTime { delta_ms } = step {
            virtual_time_ms = virtual_time_ms.checked_add(*delta_ms).ok_or_else(|| {
                compile_error(
                    Some(source_step_index),
                    "scenario virtual time overflows u64".into(),
                )
            })?;
        }
    }

    Ok(CompiledScenarioV2 {
        name: spec.name.clone(),
        spec_version: spec.spec_version.clone(),
        clients: spec.clients.clone(),
        topology,
        actions,
    })
}

fn validate_step(
    step_index: usize,
    step: &ScenarioStep,
    clients: &BTreeSet<&String>,
    topology: &crate::ScenarioTopologyV2,
) -> Result<(), ScenarioRunError> {
    let selectors = match step {
        ScenarioStep::OmitMessage { selector }
        | ScenarioStep::DuplicateMessage { selector }
        | ScenarioStep::WithholdMessage { selector, .. } => std::slice::from_ref(selector),
        ScenarioStep::ReorderMessages { order } => order.as_slice(),
        _ => &[],
    };
    if matches!(step, ScenarioStep::ReorderMessages { order } if order.is_empty()) {
        return Err(compile_error(
            Some(step_index),
            "semantic reorder requires at least one selector".into(),
        ));
    }
    if selectors.iter().any(|selector| !selector.is_semantic()) {
        return Err(compile_error(
            Some(step_index),
            "message selector must constrain action_id, publication, sender, or class".into(),
        ));
    }
    if matches!(step, ScenarioStep::WithholdMessage { label, .. } | ScenarioStep::ReleaseWithheld { label } if label.trim().is_empty())
    {
        return Err(compile_error(
            Some(step_index),
            "withheld message label must not be empty".into(),
        ));
    }
    if let ScenarioStep::SetClientOffline { client } | ScenarioStep::ReconnectClient { client } =
        step
        && !clients.contains(client)
    {
        return Err(compile_error(
            Some(step_index),
            format!("connectivity action references unknown client {client}"),
        ));
    }
    if let ScenarioStep::CrashProcess { process } | ScenarioStep::RestartProcess { process } = step
        && !topology.processes.iter().any(|item| item.id == *process)
    {
        return Err(compile_error(
            Some(step_index),
            format!("process lifecycle action references unknown process {process}"),
        ));
    }
    if let ScenarioStep::InjectStorageFault { fault } = step {
        if fault.operations == 0 {
            return Err(compile_error(
                Some(step_index),
                "storage fault operations must be non-zero".into(),
            ));
        }
        validate_storage_target(step_index, &fault.target, topology)?;
    }
    if let ScenarioStep::ClearStorageFault { target } = step {
        validate_storage_target(step_index, target, topology)?;
    }
    if let ScenarioStep::Assert { assertion } = step {
        match assertion {
            crate::ScenarioAssertionV2::Exactly { predicate } => {
                validate_predicate(step_index, predicate, clients)?;
            }
            crate::ScenarioAssertionV2::Eventually {
                predicate,
                max_iterations,
            } => {
                validate_predicate(step_index, predicate, clients)?;
                if *max_iterations == 0 {
                    return Err(compile_error(
                        Some(step_index),
                        "eventually max_iterations must be non-zero".into(),
                    ));
                }
            }
            crate::ScenarioAssertionV2::Within {
                predicate,
                poll_interval_ms,
                ..
            }
            | crate::ScenarioAssertionV2::Never {
                predicate,
                poll_interval_ms,
                ..
            } => {
                validate_predicate(step_index, predicate, clients)?;
                if *poll_interval_ms == 0 {
                    return Err(compile_error(
                        Some(step_index),
                        "temporal assertion poll_interval_ms must be non-zero".into(),
                    ));
                }
            }
            crate::ScenarioAssertionV2::Resource { .. } => {}
        }
    }
    Ok(())
}

fn validate_predicate(
    step_index: usize,
    predicate: &crate::ScenarioPredicateV2,
    clients: &BTreeSet<&String>,
) -> Result<(), ScenarioRunError> {
    let labels = match predicate {
        crate::ScenarioPredicateV2::ClientState { client, .. }
        | crate::ScenarioPredicateV2::PayloadCount { client, .. } => std::slice::from_ref(client),
        crate::ScenarioPredicateV2::ClientsExactlyEquivalent { clients }
        | crate::ScenarioPredicateV2::NoPendingWork { clients } => clients.as_slice(),
    };
    if labels.is_empty() {
        return Err(compile_error(
            Some(step_index),
            "assertion predicate requires at least one client".into(),
        ));
    }
    for client in labels {
        if !clients.contains(client) {
            return Err(compile_error(
                Some(step_index),
                format!("assertion predicate references unknown client {client}"),
            ));
        }
    }
    Ok(())
}

fn validate_storage_target(
    step_index: usize,
    target: &str,
    topology: &crate::ScenarioTopologyV2,
) -> Result<(), ScenarioRunError> {
    if !topology.devices.iter().any(|item| item.id == target)
        && !topology.processes.iter().any(|item| item.id == target)
    {
        return Err(compile_error(
            Some(step_index),
            format!("storage fault references unknown device or process {target}"),
        ));
    }
    Ok(())
}

/// Reject unsupported behavior before an adapter receives its first action.
pub fn preflight_compiled_scenario(
    compiled: &CompiledScenarioV2,
    descriptor: &SubjectDescriptor,
) -> Result<(), ScenarioRunError> {
    for action in &compiled.actions {
        for capability in &action.schedule.required_capabilities {
            if !descriptor.supports(*capability) {
                return Err(ScenarioRunError {
                    step_index: Some(action.schedule.source_step_index),
                    kind: "unsupported_subject_capability".into(),
                    category: SubjectFailureCategory::Environment,
                    message: format!(
                        "subject {} does not support capability {} required by {}",
                        descriptor.adapter, capability, action.schedule.action_type
                    ),
                });
            }
        }
    }
    Ok(())
}

fn compile_error(step_index: Option<usize>, message: String) -> ScenarioRunError {
    ScenarioRunError {
        step_index,
        kind: "scenario_compile_error".into(),
        category: SubjectFailureCategory::Environment,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compilation_assigns_stable_ids_and_virtual_time_before_actions() {
        let spec = ScenarioSpec {
            name: "compile/v2".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into()],
            steps: vec![
                ScenarioStep::AdvanceTime { delta_ms: 25 },
                ScenarioStep::Tick {
                    clients: vec!["alice".into()],
                },
                ScenarioStep::AdvanceTime { delta_ms: 75 },
            ],
        };

        let compiled = compile_scenario(&spec).expect("scenario compiles");
        assert_eq!(
            compiled.actions[0].schedule.action_id,
            "step-0:advance_time"
        );
        assert_eq!(compiled.actions[0].schedule.virtual_time_ms, 0);
        assert_eq!(compiled.actions[1].schedule.action_id, "step-1:tick");
        assert_eq!(compiled.actions[1].schedule.virtual_time_ms, 25);
        assert_eq!(compiled.actions[2].schedule.virtual_time_ms, 25);
    }

    #[test]
    fn preflight_rejects_unsupported_action_before_execution() {
        let spec = ScenarioSpec {
            name: "preflight/v2".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into()],
            steps: vec![ScenarioStep::RestartClient {
                client: "alice".into(),
            }],
        };
        let compiled = compile_scenario(&spec).expect("scenario compiles");
        let descriptor = SubjectDescriptor {
            adapter: "reference".into(),
            adapter_version: "1".into(),
            storage_backend: "none".into(),
            capabilities: BTreeSet::new(),
        };

        let error = preflight_compiled_scenario(&compiled, &descriptor)
            .expect_err("unsupported restart is rejected");
        assert_eq!(error.step_index, Some(0));
        assert_eq!(error.kind, "unsupported_subject_capability");
    }
}
