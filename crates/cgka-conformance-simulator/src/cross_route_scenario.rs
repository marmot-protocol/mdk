//! Canonical four-party route-assurance scenario shared by capable adapters.
//!
//! The engine-capable form owns exact MLS state, durable dispositions, and
//! active decryptability. The public form is intentionally limited to the
//! protocol/application projection exposed by app, process, and distributed
//! adapters. Keeping both forms here prevents those execution routes from
//! silently drifting onto different canonical inputs or terminal oracles.

use std::collections::{BTreeMap, BTreeSet};

use crate::process_orchestrator::{ProcessActionStatusV1, ProcessScenarioReportV1};
use crate::retained_relay::ScenarioRelaySyncModeV2;
use crate::scenario::{ScenarioSpec, ScenarioStep};
use crate::scenario_faults::ScenarioMessageSelectorV2;
use crate::scenario_input::canonical_scenario_ir_sha256;
use crate::scenario_ir::compile_scenario;
use crate::subject::SubjectOutboundOutcome;
use crate::topology::{
    ScenarioAccountV2, ScenarioDeviceV2, ScenarioProcessV2, ScenarioRelayV2, ScenarioTopologyV2,
};

fn in_group(action: ScenarioStep) -> ScenarioStep {
    ScenarioStep::InGroup {
        group: "main".into(),
        action: Box::new(action),
    }
}

fn single_relay_topology(clients: &[String]) -> ScenarioTopologyV2 {
    ScenarioTopologyV2 {
        accounts: clients
            .iter()
            .map(|client| ScenarioAccountV2 {
                id: format!("account:{client}"),
                roles: vec!["member".into()],
            })
            .collect(),
        devices: clients
            .iter()
            .map(|client| ScenarioDeviceV2 {
                id: format!("device:{client}"),
                account: format!("account:{client}"),
                process: format!("process:{client}"),
                client: client.clone(),
            })
            .collect(),
        processes: clients
            .iter()
            .map(|client| ScenarioProcessV2 {
                id: format!("process:{client}"),
                binary_version: "current-test-node".into(),
                policy_version: "marmot-convergence-v1".into(),
                relays: vec!["relay:shared".into()],
            })
            .collect(),
        groups: Vec::new(),
        relays: vec![ScenarioRelayV2 {
            id: "relay:shared".into(),
            implementation_version: "retained-memory/v1".into(),
            policy_version: "retain-all-v1".into(),
        }],
    }
}

/// The exact engine-capable form of `cross-route-app-runtime-recovery/v1`.
pub fn cross_route_app_runtime_recovery_exact_scenario() -> ScenarioSpec {
    build_cross_route_app_runtime_recovery_scenario(true)
}

/// The public-projection form of `cross-route-app-runtime-recovery/v1` used by
/// app-runtime, process, container, and VM adapters.
pub fn cross_route_app_runtime_recovery_public_scenario() -> ScenarioSpec {
    build_cross_route_app_runtime_recovery_scenario(false)
}

fn build_cross_route_app_runtime_recovery_scenario(strict_engine_tail: bool) -> ScenarioSpec {
    let clients = vec![
        "zeta".into(),
        "alpha".into(),
        "yankee".into(),
        "observer".into(),
    ];
    let mut steps = vec![
        in_group(ScenarioStep::CreateGroup {
            creator: "zeta".into(),
            name: "cross-route".into(),
            invitees: vec!["alpha".into(), "yankee".into(), "observer".into()],
            required_features: Vec::new(),
            initial_admins: Some(vec!["zeta".into()]),
            pending: "create".into(),
        }),
        ScenarioStep::AcknowledgeOutbound {
            client: "zeta".into(),
            publication: Some("create".into()),
            selection: Default::default(),
            outcome: SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["alpha".into(), "yankee".into(), "observer".into()],
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: vec!["alpha".into(), "yankee".into(), "observer".into()],
        },
        in_group(ScenarioStep::UpdateAdminPolicy {
            client: "zeta".into(),
            admins: vec!["zeta".into(), "alpha".into()],
            pending: "promote-alpha".into(),
        }),
        ScenarioStep::AcknowledgeOutbound {
            client: "zeta".into(),
            publication: Some("promote-alpha".into()),
            selection: Default::default(),
            outcome: SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
        in_group(ScenarioStep::UpdateAdminPolicy {
            client: "zeta".into(),
            admins: vec!["zeta".into(), "alpha".into(), "yankee".into()],
            pending: "promote-yankee".into(),
        }),
        ScenarioStep::AcknowledgeOutbound {
            client: "zeta".into(),
            publication: Some("promote-yankee".into()),
            selection: Default::default(),
            outcome: SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
        in_group(ScenarioStep::ClearEvents {
            clients: clients.clone(),
        }),
        in_group(ScenarioStep::Observe {
            clients: clients.clone(),
        }),
        ScenarioStep::SetClientOffline {
            client: "alpha".into(),
        },
        ScenarioStep::SetClientOffline {
            client: "observer".into(),
        },
        in_group(ScenarioStep::UpdateGroupData {
            client: "zeta".into(),
            name: "zeta-root".into(),
            pending: "zeta-root".into(),
        }),
        ScenarioStep::AcknowledgeOutbound {
            client: "zeta".into(),
            publication: Some("zeta-root".into()),
            selection: Default::default(),
            outcome: SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["yankee".into()],
            sync: ScenarioRelaySyncModeV2::Incremental,
        },
        ScenarioStep::Tick {
            clients: vec!["yankee".into()],
        },
        in_group(ScenarioStep::SendAppMessage {
            sender: "yankee".into(),
            payload: "zeta-branch-witness".into(),
        }),
        ScenarioStep::SetClientOffline {
            client: "zeta".into(),
        },
        ScenarioStep::SetClientOffline {
            client: "yankee".into(),
        },
        ScenarioStep::SetRelayEventVisibility {
            relay: "relay:shared".into(),
            selector: ScenarioMessageSelectorV2 {
                action_id: Some("step-16:update_group_data@main".into()),
                ..Default::default()
            },
            clients: vec!["alpha".into(), "observer".into()],
            visible: false,
        },
        ScenarioStep::ReconnectClient {
            client: "alpha".into(),
        },
        in_group(ScenarioStep::UpdateGroupData {
            client: "alpha".into(),
            name: "alpha-root".into(),
            pending: "alpha-root".into(),
        }),
        ScenarioStep::AcknowledgeOutbound {
            client: "alpha".into(),
            publication: Some("alpha-root".into()),
            selection: Default::default(),
            outcome: SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::ReconnectClient {
            client: "zeta".into(),
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["zeta".into()],
            sync: ScenarioRelaySyncModeV2::Incremental,
        },
        ScenarioStep::Tick {
            clients: vec!["zeta".into()],
        },
        ScenarioStep::SetClientOffline {
            client: "alpha".into(),
        },
        ScenarioStep::SetClientOffline {
            client: "zeta".into(),
        },
        ScenarioStep::SetRelayEventVisibility {
            relay: "relay:shared".into(),
            selector: ScenarioMessageSelectorV2 {
                action_id: Some("step-25:update_group_data@main".into()),
                ..Default::default()
            },
            clients: vec!["yankee".into(), "observer".into()],
            visible: false,
        },
        in_group(ScenarioStep::Observe {
            clients: clients.clone(),
        }),
        ScenarioStep::ReconnectClient {
            client: "yankee".into(),
        },
        in_group(ScenarioStep::UpdateGroupData {
            client: "yankee".into(),
            name: "zeta-branch-depth-two".into(),
            pending: "zeta-child".into(),
        }),
        ScenarioStep::AcknowledgeOutbound {
            client: "yankee".into(),
            publication: Some("zeta-child".into()),
            selection: Default::default(),
            outcome: SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::RestartClient {
            client: "zeta".into(),
        },
        ScenarioStep::ReconnectClient {
            client: "zeta".into(),
        },
        ScenarioStep::SetRelayEventVisibility {
            relay: "relay:shared".into(),
            selector: ScenarioMessageSelectorV2 {
                action_id: Some("step-16:update_group_data@main".into()),
                ..Default::default()
            },
            clients: vec!["alpha".into(), "observer".into()],
            visible: true,
        },
        ScenarioStep::SetRelayEventVisibility {
            relay: "relay:shared".into(),
            selector: ScenarioMessageSelectorV2 {
                action_id: Some("step-25:update_group_data@main".into()),
                ..Default::default()
            },
            clients: vec!["yankee".into(), "observer".into()],
            visible: true,
        },
        ScenarioStep::ReconnectClient {
            client: "alpha".into(),
        },
        ScenarioStep::ReconnectClient {
            client: "observer".into(),
        },
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
    ];
    if strict_engine_tail {
        steps.push(ScenarioStep::AwaitQuiescence {
            policy: crate::QuiescencePolicy {
                max_iterations: 200,
                ..Default::default()
            },
        });
    }
    for client in &clients {
        steps.push(in_group(ScenarioStep::SendAppMessage {
            sender: client.clone(),
            payload: format!("probe-from-{client}"),
        }));
    }
    steps.extend([
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
    ]);
    if strict_engine_tail {
        steps.push(ScenarioStep::AwaitQuiescence {
            policy: crate::QuiescencePolicy {
                max_iterations: 200,
                ..Default::default()
            },
        });
    }
    steps.push(in_group(ScenarioStep::Observe {
        clients: clients.clone(),
    }));
    if !strict_engine_tail {
        // Two identical terminal observations form the public stable-checkpoint
        // contract used by the process and distributed adapters.
        steps.push(in_group(ScenarioStep::Observe {
            clients: clients.clone(),
        }));
    }
    if strict_engine_tail {
        steps.extend([
            in_group(ScenarioStep::ProbeBidirectionalDecryptability {
                clients: clients.clone(),
            }),
            in_group(ScenarioStep::ObserveExact {
                clients: clients.clone(),
            }),
        ]);
    }
    ScenarioSpec {
        name: "cross-route-app-runtime-recovery/v1".into(),
        spec_version: "2".into(),
        topology: single_relay_topology(&clients),
        clients,
        steps,
    }
}

/// Validate the strict public-projection contract shared by isolated-process,
/// container, and VM executions of the four-party route scenario.
pub fn validate_cross_route_public_process_report(
    spec: &ScenarioSpec,
    report: &ProcessScenarioReportV1,
) -> Result<(), String> {
    if !report.completed || !report.failure_capsules.is_empty() {
        return Err(format!(
            "process execution did not complete cleanly; last action={:?}, lifecycle tail={:?}, failure capsules={:?}",
            report.actions.last(),
            report.lifecycle.iter().rev().take(6).collect::<Vec<_>>(),
            report.failure_capsules,
        ));
    }
    let schedule = compile_scenario(spec).map_err(|error| error.to_string())?;
    if report.canonical_schedule != schedule.expanded_schedule()
        || report.actions.len() != report.canonical_schedule.len()
        || report
            .actions
            .iter()
            .any(|action| action.status == ProcessActionStatusV1::Failed)
    {
        return Err(format!(
            "process execution did not preserve the canonical schedule: {report:#?}"
        ));
    }
    let expected_digest = canonical_scenario_ir_sha256(spec).map_err(|error| error.to_string())?;
    if report.executed_scenario_ir_sha256.as_deref() != Some(expected_digest.as_str()) {
        return Err(format!(
            "process execution reported the wrong Scenario IR digest: {report:#?}"
        ));
    }
    if spec.clients.is_empty() || report.observations.len() != spec.clients.len() * 4 {
        return Err(format!(
            "expected four complete process checkpoints: {report:#?}"
        ));
    }
    let checkpoints = report
        .observations
        .chunks_exact(spec.clients.len())
        .map(|observations| {
            observations
                .iter()
                .map(|observation| (observation.participant.as_str(), observation))
                .collect::<BTreeMap<_, _>>()
        })
        .collect::<Vec<_>>();
    let expected_participants = spec
        .clients
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if checkpoints.iter().any(|checkpoint| {
        checkpoint.keys().copied().collect::<BTreeSet<_>>() != expected_participants
    }) {
        return Err(format!(
            "process checkpoints did not report exactly one observation per participant: {report:#?}"
        ));
    }
    let baseline = &checkpoints[0];
    let routed = &checkpoints[1];
    let first_settled = &checkpoints[2];
    let settled = &checkpoints[3];
    if routed["zeta"].protocol.epoch != 4
        || routed["alpha"].protocol.epoch != 4
        || routed["yankee"].protocol.epoch != 4
        || routed["observer"].protocol.epoch != 3
    {
        return Err(format!(
            "process route did not reach the controlled intermediate split: {routed:#?}"
        ));
    }

    let expected_payloads = BTreeSet::from([
        "probe-from-alpha".to_owned(),
        "probe-from-observer".to_owned(),
        "probe-from-yankee".to_owned(),
        "probe-from-zeta".to_owned(),
        "zeta-branch-witness".to_owned(),
    ]);
    let mut public_commitments = BTreeSet::new();
    for client in &spec.clients {
        let observation = settled[client.as_str()];
        let prior = first_settled[client.as_str()];
        if prior.protocol != observation.protocol
            || prior.application != observation.application
            || prior.progress.projection_checkpoint_sha256
                != observation.progress.projection_checkpoint_sha256
            || prior.progress.relay_inbound_events_seen
                != observation.progress.relay_inbound_events_seen
            || prior.progress.relay_inbound_events_delivered
                != observation.progress.relay_inbound_events_delivered
            || prior.progress.relay_publish_attempts != observation.progress.relay_publish_attempts
            || prior.progress.relay_publish_failures != observation.progress.relay_publish_failures
            || prior.progress.relay_directory_inflight_fetches != 0
            || observation.progress.relay_directory_inflight_fetches != 0
            || prior.progress.relay_directory_completed_fetches
                != observation.progress.relay_directory_completed_fetches
            || prior.progress.retry_timer_armed
            || observation.progress.retry_timer_armed
            || observation.progress.stable_checkpoint_observations
                < prior.progress.stable_checkpoint_observations
            || observation.progress.stable_checkpoint_observations < 2
        {
            return Err(format!(
                "{client} did not preserve a stable final process checkpoint: {first_settled:#?} {settled:#?}"
            ));
        }
        if observation.protocol.epoch != 5
            || observation.protocol.member_count != 4
            || observation.protocol.member_identities != ["alpha", "observer", "yankee", "zeta"]
            || observation.protocol.admin_identities != ["alpha", "yankee", "zeta"]
            || observation.protocol.group_name != "zeta-branch-depth-two"
            || !observation.protocol.group_description.is_empty()
        {
            return Err(format!(
                "{client} did not reach the selected public protocol state: {settled:#?}"
            ));
        }
        public_commitments.insert(observation.protocol.state_commitment_sha256.as_str());
        let payloads = observation
            .application
            .visible_plaintexts
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if payloads != expected_payloads
            || observation.application.visible_plaintexts.len() != payloads.len()
            || observation.application.pending_confirmation
        {
            return Err(format!(
                "{client} did not reach the complete duplicate-free application projection: {settled:#?}"
            ));
        }
        let invalidated = observation.application.invalidated_message_ids.len();
        let left_losing_branch = observation.protocol.group_name != "alpha-root"
            && observation.protocol.epoch > baseline[client.as_str()].protocol.epoch;
        if invalidated > 1
            || (invalidated != 0 && !left_losing_branch)
            || (client == "alpha" && invalidated != usize::from(left_losing_branch))
            || ((client == "yankee" || client == "zeta") && invalidated != 0)
        {
            return Err(format!(
                "{client} violated the losing-branch withdrawal rule: {settled:#?}"
            ));
        }
        let visible_ids = observation
            .application
            .visible_message_ids
            .iter()
            .collect::<BTreeSet<_>>();
        if observation
            .application
            .invalidated_message_ids
            .iter()
            .any(|id| visible_ids.contains(id))
        {
            return Err(format!(
                "{client} projected an invalidated row as visible: {settled:#?}"
            ));
        }
    }
    if public_commitments.len() != 1 {
        return Err(format!(
            "process participants disagree on their public state commitment: {settled:#?}"
        ));
    }
    let zeta_launches = report
        .lifecycle
        .iter()
        .filter(|event| event.participant == "zeta" && event.event == "launched")
        .count();
    if zeta_launches < 2 {
        return Err(format!(
            "zeta did not reopen through the process lifecycle: {:#?}",
            report.lifecycle
        ));
    }
    Ok(())
}
