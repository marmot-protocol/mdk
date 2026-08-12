//! Canonical compilation contract for adapter-neutral scenario input.
//!
//! Scenario documents are serialized as versioned [`ScenarioSpec`](crate::ScenarioSpec)
//! values. Adapters never interpret that document directly: compilation validates
//! stable identities and produces one deterministic action schedule which is
//! then preflighted against the selected adapter before any action executes.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    ScenarioRunError, ScenarioSpec, ScenarioStep, SubjectCapability, SubjectDescriptor,
    SubjectFailureCategory, required_capabilities,
};

/// Stable canonical version for the original Scenario IR action set.
pub const SCENARIO_IR_V2_VERSION: &str = "2";
/// Canonical version that adds full group-profile updates.
pub const SCENARIO_IR_V3_VERSION: &str = "3";
/// Newest Scenario IR version emitted when newly authored actions require it.
pub const SCENARIO_IR_LATEST_VERSION: &str = SCENARIO_IR_V3_VERSION;
/// Action kinds introduced after Scenario IR v2.
pub const SCENARIO_IR_V3_ONLY_STEP_KINDS: &[&str] = &["update_group_profile"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioActionScheduleV2 {
    pub action_id: String,
    pub source_step_index: usize,
    pub action_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scenario_group: Option<String>,
    /// Sum of explicit `advance_time` deltas preceding this action.
    ///
    /// Assertions and quiescence may advance an adapter's observed clock while
    /// executing, so this compiler schedule is intentionally not that clock.
    pub declared_virtual_time_ms: u64,
    pub required_capabilities: BTreeSet<SubjectCapability>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledScenarioActionV2 {
    pub schedule: ScenarioActionScheduleV2,
    pub step: ScenarioStep,
    pub scenario_group: Option<String>,
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
    match step {
        ScenarioStep::InGroup { group, action } => {
            format!("step-{source_step_index}:{}@{group}", action.kind())
        }
        _ => format!("step-{source_step_index}:{}", step.kind()),
    }
}

/// Compile canonical JSON input into the only schedule adapters may execute.
pub fn compile_scenario(spec: &ScenarioSpec) -> Result<CompiledScenarioV2, ScenarioRunError> {
    if !matches!(
        spec.spec_version.as_str(),
        SCENARIO_IR_V2_VERSION | SCENARIO_IR_V3_VERSION
    ) {
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
    let uses_explicit_group_targets = spec
        .steps
        .iter()
        .any(|step| matches!(step, ScenarioStep::InGroup { .. }));
    let mut actions = Vec::with_capacity(spec.steps.len());
    for (source_step_index, step) in spec.steps.iter().enumerate() {
        if uses_explicit_group_targets
            && !matches!(step, ScenarioStep::InGroup { .. })
            && is_group_scoped(step)
        {
            return Err(compile_error(
                Some(source_step_index),
                format!(
                    "{} must use in_group when the scenario targets multiple groups",
                    step.kind()
                ),
            ));
        }
        let (scenario_group, executable_step) =
            lower_group_action(source_step_index, step, &topology)?;
        validate_step_version(source_step_index, &spec.spec_version, executable_step)?;
        validate_step(source_step_index, executable_step, &clients, &topology)?;
        let action_id = stable_action_id(source_step_index, step);
        let required_capabilities = required_capabilities(step)
            .into_iter()
            .collect::<BTreeSet<_>>();
        actions.push(CompiledScenarioActionV2 {
            schedule: ScenarioActionScheduleV2 {
                action_id,
                source_step_index,
                action_type: executable_step.kind().into(),
                scenario_group: scenario_group.clone(),
                declared_virtual_time_ms: virtual_time_ms,
                required_capabilities,
            },
            step: executable_step.clone(),
            scenario_group,
        });
        if let ScenarioStep::AdvanceTime { delta_ms } = executable_step {
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

fn lower_group_action<'a>(
    step_index: usize,
    step: &'a ScenarioStep,
    topology: &crate::ScenarioTopologyV2,
) -> Result<(Option<String>, &'a ScenarioStep), ScenarioRunError> {
    let ScenarioStep::InGroup { group, action } = step else {
        return Ok((None, step));
    };
    if group.trim().is_empty() {
        return Err(compile_error(
            Some(step_index),
            "scenario group label must not be empty".into(),
        ));
    }
    if matches!(action.as_ref(), ScenarioStep::InGroup { .. }) {
        return Err(compile_error(
            Some(step_index),
            "nested in_group actions are not allowed".into(),
        ));
    }
    if !is_group_scoped(action) {
        return Err(compile_error(
            Some(step_index),
            format!("{} is not a group-scoped action", action.kind()),
        ));
    }
    if !topology.groups.is_empty() && !topology.groups.iter().any(|item| item.id == *group) {
        return Err(compile_error(
            Some(step_index),
            format!("in_group references unknown scenario group {group}"),
        ));
    }
    Ok((Some(group.clone()), action))
}

fn is_group_scoped(step: &ScenarioStep) -> bool {
    matches!(
        step,
        ScenarioStep::CreateGroup { .. }
            | ScenarioStep::InviteMembers { .. }
            | ScenarioStep::RemoveMembers { .. }
            | ScenarioStep::SelfUpdate { .. }
            | ScenarioStep::UpdateGroupData { .. }
            | ScenarioStep::UpdateGroupProfile { .. }
            | ScenarioStep::UpdateAdminPolicy { .. }
            | ScenarioStep::ExpectUpdateAdminPolicyError { .. }
            | ScenarioStep::SendAppMessage { .. }
            | ScenarioStep::Leave { .. }
            | ScenarioStep::ProbeBidirectionalDecryptability { .. }
            | ScenarioStep::ObserveAdminPolicy { .. }
            | ScenarioStep::Observe { .. }
            | ScenarioStep::ObserveExact { .. }
            | ScenarioStep::ClearEvents { .. }
    )
}

fn validate_step_version(
    step_index: usize,
    spec_version: &str,
    step: &ScenarioStep,
) -> Result<(), ScenarioRunError> {
    if spec_version == SCENARIO_IR_V2_VERSION && step_requires_v3(step) {
        return Err(compile_error(
            Some(step_index),
            format!("{} requires ScenarioSpec version 3", step.kind()),
        ));
    }
    Ok(())
}

pub(crate) fn minimum_ir_version(steps: &[ScenarioStep]) -> &'static str {
    if steps.iter().any(step_requires_v3) {
        SCENARIO_IR_V3_VERSION
    } else {
        SCENARIO_IR_V2_VERSION
    }
}

fn step_requires_v3(step: &ScenarioStep) -> bool {
    let executable = match step {
        ScenarioStep::InGroup { action, .. } => action.as_ref(),
        step => step,
    };
    SCENARIO_IR_V3_ONLY_STEP_KINDS.contains(&executable.kind())
}

fn validate_step(
    step_index: usize,
    step: &ScenarioStep,
    clients: &BTreeSet<&String>,
    topology: &crate::ScenarioTopologyV2,
) -> Result<(), ScenarioRunError> {
    match step {
        ScenarioStep::InGroup { .. } => unreachable!("group wrapper is lowered before validation"),
        ScenarioStep::OmitMessage { selector } | ScenarioStep::DuplicateMessage { selector } => {
            validate_semantic_selector(step_index, selector)?;
        }
        ScenarioStep::WithholdMessage { selector, label } => {
            validate_semantic_selector(step_index, selector)?;
            validate_withheld_label(step_index, label)?;
        }
        ScenarioStep::ReleaseWithheld { label } => {
            validate_withheld_label(step_index, label)?;
        }
        ScenarioStep::ReorderMessages { order } => {
            if order.is_empty() {
                return Err(compile_error(
                    Some(step_index),
                    "semantic reorder requires at least one selector".into(),
                ));
            }
            for selector in order {
                validate_semantic_selector(step_index, selector)?;
            }
        }
        ScenarioStep::CreateGroup {
            creator,
            invitees,
            initial_admins,
            ..
        } => {
            validate_client(step_index, creator, clients, "group creation")?;
            validate_clients(step_index, invitees, clients, "group creation invitees")?;
            if let Some(initial_admins) = initial_admins {
                validate_clients(
                    step_index,
                    initial_admins,
                    clients,
                    "group creation administrators",
                )?;
                for admin in initial_admins {
                    if admin != creator && !invitees.contains(admin) {
                        return Err(compile_error(
                            Some(step_index),
                            format!(
                                "group creation administrator {admin} is neither the creator nor an invitee"
                            ),
                        ));
                    }
                }
            }
        }
        ScenarioStep::InviteMembers {
            inviter, invitees, ..
        } => {
            validate_client(step_index, inviter, clients, "member invitation")?;
            validate_clients(step_index, invitees, clients, "member invitation")?;
        }
        ScenarioStep::RemoveMembers {
            remover, members, ..
        } => {
            validate_client(step_index, remover, clients, "member removal")?;
            validate_clients(step_index, members, clients, "member removal")?;
        }
        ScenarioStep::UpdateGroupProfile {
            client,
            name,
            description,
            ..
        } => {
            validate_client(step_index, client, clients, step.kind())?;
            if name.is_none() && description.is_none() {
                return Err(compile_error(
                    Some(step_index),
                    "group profile update must change a name or description".into(),
                ));
            }
        }
        ScenarioStep::SelfUpdate { client, .. }
        | ScenarioStep::UpdateGroupData { client, .. }
        | ScenarioStep::Leave { client }
        | ScenarioStep::RestartClient { client }
        | ScenarioStep::SetClientOffline { client }
        | ScenarioStep::ReconnectClient { client } => {
            validate_client(step_index, client, clients, step.kind())?;
        }
        ScenarioStep::UpdateAdminPolicy { client, admins, .. }
        | ScenarioStep::ExpectUpdateAdminPolicyError { client, admins, .. } => {
            validate_client(step_index, client, clients, step.kind())?;
            validate_clients(step_index, admins, clients, step.kind())?;
        }
        ScenarioStep::AcknowledgeOutbound { client, .. } => {
            validate_client(step_index, client, clients, "outbound acknowledgement")?;
        }
        ScenarioStep::SendAppMessage { sender, .. } => {
            validate_client(step_index, sender, clients, "application send")?;
        }
        ScenarioStep::Tick { clients: labels }
        | ScenarioStep::Observe { clients: labels }
        | ScenarioStep::ObserveExact { clients: labels }
        | ScenarioStep::ProbeBidirectionalDecryptability { clients: labels }
        | ScenarioStep::ObserveAdminPolicy { clients: labels }
        | ScenarioStep::ClearEvents { clients: labels } => {
            validate_clients(step_index, labels, clients, step.kind())?;
        }
        ScenarioStep::SyncRelayHistory {
            clients: sync_clients,
            ..
        } => {
            validate_nonempty_clients(step_index, sync_clients, clients, "relay sync")?;
        }
        ScenarioStep::ConfigureRelay {
            relay,
            duplicate_copies,
            ..
        } => {
            validate_relay(step_index, relay, topology)?;
            if *duplicate_copies == 0 {
                return Err(compile_error(
                    Some(step_index),
                    "relay duplicate_copies must be non-zero".into(),
                ));
            }
        }
        ScenarioStep::SetRelayEventVisibility {
            relay,
            selector,
            clients: visibility_clients,
            ..
        } => {
            validate_relay(step_index, relay, topology)?;
            if !selector.is_semantic() {
                return Err(compile_error(
                    Some(step_index),
                    "relay visibility selector must be semantic".into(),
                ));
            }
            validate_nonempty_clients(step_index, visibility_clients, clients, "relay visibility")?;
        }
        ScenarioStep::ReconcileRelayHistories { relays } => {
            if relays.len() < 2 {
                return Err(compile_error(
                    Some(step_index),
                    "relay reconciliation requires at least two relays".into(),
                ));
            }
            let mut seen = BTreeSet::new();
            for relay in relays {
                if !seen.insert(relay.as_str()) {
                    return Err(compile_error(
                        Some(step_index),
                        format!("relay reconciliation repeats relay {relay}"),
                    ));
                }
            }
            for relay in relays {
                validate_relay(step_index, relay, topology)?;
            }
        }
        ScenarioStep::CrashProcess { process } | ScenarioStep::RestartProcess { process } => {
            if !topology.processes.iter().any(|item| item.id == *process) {
                return Err(compile_error(
                    Some(step_index),
                    format!("process lifecycle action references unknown process {process}"),
                ));
            }
        }
        ScenarioStep::InjectStorageFault { fault } => {
            if fault.operations == 0 {
                return Err(compile_error(
                    Some(step_index),
                    "storage fault operations must be non-zero".into(),
                ));
            }
            validate_storage_target(step_index, &fault.target, topology)?;
        }
        ScenarioStep::ClearStorageFault { target } => {
            validate_storage_target(step_index, target, topology)?;
        }
        ScenarioStep::Assert { assertion } => {
            validate_assertion(step_index, assertion, clients)?;
        }
        ScenarioStep::SetPartition { allow } => {
            validate_clients(step_index, allow, clients, "partition")?;
        }
        ScenarioStep::DeliverAll
        | ScenarioStep::AdvanceTime { .. }
        | ScenarioStep::AwaitQuiescence { .. }
        | ScenarioStep::ClearPartition
        | ScenarioStep::Barrier { .. } => {}
    }
    Ok(())
}

fn validate_semantic_selector(
    step_index: usize,
    selector: &crate::ScenarioMessageSelectorV2,
) -> Result<(), ScenarioRunError> {
    if selector.is_semantic() {
        Ok(())
    } else {
        Err(compile_error(
            Some(step_index),
            "message selector must constrain action_id, publication, sender, or class".into(),
        ))
    }
}

fn validate_withheld_label(step_index: usize, label: &str) -> Result<(), ScenarioRunError> {
    if label.trim().is_empty() {
        Err(compile_error(
            Some(step_index),
            "withheld message label must not be empty".into(),
        ))
    } else {
        Ok(())
    }
}

fn validate_nonempty_clients(
    step_index: usize,
    labels: &[String],
    clients: &BTreeSet<&String>,
    operation: &str,
) -> Result<(), ScenarioRunError> {
    if labels.is_empty() {
        return Err(compile_error(
            Some(step_index),
            format!("{operation} requires at least one client"),
        ));
    }
    validate_clients(step_index, labels, clients, operation)
}

fn validate_clients(
    step_index: usize,
    labels: &[String],
    clients: &BTreeSet<&String>,
    operation: &str,
) -> Result<(), ScenarioRunError> {
    for client in labels {
        validate_client(step_index, client, clients, operation)?;
    }
    Ok(())
}

fn validate_client(
    step_index: usize,
    client: &String,
    clients: &BTreeSet<&String>,
    operation: &str,
) -> Result<(), ScenarioRunError> {
    if clients.contains(client) {
        Ok(())
    } else {
        Err(compile_error(
            Some(step_index),
            format!("{operation} references unknown client {client}"),
        ))
    }
}

fn validate_assertion(
    step_index: usize,
    assertion: &crate::ScenarioAssertionV2,
    clients: &BTreeSet<&String>,
) -> Result<(), ScenarioRunError> {
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
    Ok(())
}

fn validate_relay(
    step_index: usize,
    relay: &str,
    topology: &crate::ScenarioTopologyV2,
) -> Result<(), ScenarioRunError> {
    if topology
        .relays
        .iter()
        .any(|candidate| candidate.id == relay)
    {
        Ok(())
    } else {
        Err(compile_error(
            Some(step_index),
            format!("relay action references unknown relay {relay}"),
        ))
    }
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

    fn assert_step_compile_error(step: ScenarioStep, expected_message: &str) {
        let spec = ScenarioSpec {
            name: "compile/rejection".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into()],
            steps: vec![step],
        };
        let error = compile_scenario(&spec).expect_err("step must be rejected");
        assert_eq!(error.kind, "scenario_compile_error");
        assert_eq!(error.step_index, Some(0));
        assert!(
            error.message.contains(expected_message),
            "unexpected compile error: {error:?}"
        );
    }

    #[test]
    fn compilation_assigns_stable_ids_and_declared_time_before_actions() {
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
        assert_eq!(compiled.actions[0].schedule.declared_virtual_time_ms, 0);
        assert_eq!(compiled.actions[1].schedule.action_id, "step-1:tick");
        assert_eq!(compiled.actions[1].schedule.declared_virtual_time_ms, 25);
        assert_eq!(compiled.actions[2].schedule.declared_virtual_time_ms, 25);
    }

    #[test]
    fn step_validation_rejects_invalid_cross_references_and_selectors() {
        assert_step_compile_error(
            ScenarioStep::OmitMessage {
                selector: Default::default(),
            },
            "message selector must constrain",
        );
        assert_step_compile_error(
            ScenarioStep::ConfigureRelay {
                relay: "relay:missing".into(),
                order: Default::default(),
                duplicate_copies: 1,
            },
            "unknown relay",
        );
        assert_step_compile_error(
            ScenarioStep::CrashProcess {
                process: "process:missing".into(),
            },
            "unknown process",
        );
        assert_step_compile_error(
            ScenarioStep::ClearStorageFault {
                target: "device:missing".into(),
            },
            "unknown device or process",
        );
        assert_step_compile_error(
            ScenarioStep::Assert {
                assertion: crate::ScenarioAssertionV2::Exactly {
                    predicate: crate::ScenarioPredicateV2::ClientState {
                        client: "bob".into(),
                        epoch: None,
                        member_count: None,
                    },
                },
            },
            "unknown client bob",
        );
    }

    #[test]
    fn every_client_bearing_step_rejects_unknown_labels_before_execution() {
        let unknown = "bob".to_owned();
        let steps = vec![
            ScenarioStep::CreateGroup {
                creator: unknown.clone(),
                name: "group".into(),
                invitees: vec![],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "group".into(),
                invitees: vec![unknown.clone()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "group".into(),
                invitees: vec![],
                required_features: vec![],
                initial_admins: Some(vec![unknown.clone()]),
                pending: "create".into(),
            },
            ScenarioStep::InviteMembers {
                inviter: unknown.clone(),
                invitees: vec![],
                pending: "invite".into(),
            },
            ScenarioStep::InviteMembers {
                inviter: "alice".into(),
                invitees: vec![unknown.clone()],
                pending: "invite".into(),
            },
            ScenarioStep::RemoveMembers {
                remover: unknown.clone(),
                members: vec![],
                pending: "remove".into(),
            },
            ScenarioStep::RemoveMembers {
                remover: "alice".into(),
                members: vec![unknown.clone()],
                pending: "remove".into(),
            },
            ScenarioStep::SelfUpdate {
                client: unknown.clone(),
                pending: "self".into(),
            },
            ScenarioStep::UpdateGroupData {
                client: unknown.clone(),
                name: "next".into(),
                pending: "data".into(),
            },
            ScenarioStep::UpdateAdminPolicy {
                client: unknown.clone(),
                admins: vec![],
                pending: "admins".into(),
            },
            ScenarioStep::UpdateAdminPolicy {
                client: "alice".into(),
                admins: vec![unknown.clone()],
                pending: "admins".into(),
            },
            ScenarioStep::ExpectUpdateAdminPolicyError {
                client: unknown.clone(),
                admins: vec![],
                error: "not_authorized".into(),
            },
            ScenarioStep::AcknowledgeOutbound {
                client: unknown.clone(),
                publication: None,
                selection: Default::default(),
                outcome: crate::SubjectOutboundOutcome::Accepted,
            },
            ScenarioStep::SendAppMessage {
                sender: unknown.clone(),
                payload: "payload".into(),
            },
            ScenarioStep::Leave {
                client: unknown.clone(),
            },
            ScenarioStep::Tick {
                clients: vec![unknown.clone()],
            },
            ScenarioStep::Observe {
                clients: vec![unknown.clone()],
            },
            ScenarioStep::ObserveExact {
                clients: vec![unknown.clone()],
            },
            ScenarioStep::ProbeBidirectionalDecryptability {
                clients: vec![unknown.clone()],
            },
            ScenarioStep::ObserveAdminPolicy {
                clients: vec![unknown.clone()],
            },
            ScenarioStep::ClearEvents {
                clients: vec![unknown.clone()],
            },
            ScenarioStep::SetPartition {
                allow: vec![unknown.clone()],
            },
            ScenarioStep::RestartClient {
                client: unknown.clone(),
            },
            ScenarioStep::SetClientOffline {
                client: unknown.clone(),
            },
            ScenarioStep::ReconnectClient { client: unknown },
        ];

        for step in steps {
            assert_step_compile_error(step, "unknown client bob");
        }
    }

    #[test]
    fn group_creation_rejects_declared_nonmember_initial_admin() {
        let spec = ScenarioSpec {
            name: "compile/nonmember-initial-admin".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into(), "bob".into(), "mallory".into()],
            steps: vec![ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "group".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: Some(vec!["mallory".into()]),
                pending: "create".into(),
            }],
        };

        let error = compile_scenario(&spec).expect_err("nonmember admin must be rejected");
        assert_eq!(error.kind, "scenario_compile_error");
        assert_eq!(error.step_index, Some(0));
        assert!(error.message.contains("neither the creator nor an invitee"));
    }

    #[test]
    fn relay_reconciliation_rejects_duplicate_ids_before_lookup() {
        assert_step_compile_error(
            ScenarioStep::ReconcileRelayHistories {
                relays: vec!["relay:same".into(), "relay:same".into()],
            },
            "repeats relay relay:same",
        );
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
