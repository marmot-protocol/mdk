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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrossRouteRestartBoundaryV1 {
    PublicationAccepted(&'static str),
    BranchWitnessSent,
    AlphaRootIngestedByZeta,
    FirstFullHistoryRepairCompleted,
}

/// One reviewed restart point in the current-build four-party cross-route
/// campaign. The id and target are durable campaign vocabulary; the private
/// boundary matcher keeps action indices out of that contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrossRouteRestartPermutationV1 {
    pub id: &'static str,
    pub client: &'static str,
    boundary: CrossRouteRestartBoundaryV1,
}

/// Versioned, bounded restart catalog for `cross-route-app-runtime-recovery`.
///
/// The first eight cases reopen the participant that durably authored or
/// consumed the named transition. The final four reopen every participant
/// after the first complete retained-history repair, before terminal probes.
pub const CROSS_ROUTE_RESTART_PERMUTATIONS_V1: [CrossRouteRestartPermutationV1; 12] = [
    CrossRouteRestartPermutationV1 {
        id: "after-create-accepted",
        client: "zeta",
        boundary: CrossRouteRestartBoundaryV1::PublicationAccepted("create"),
    },
    CrossRouteRestartPermutationV1 {
        id: "after-promote-alpha-accepted",
        client: "zeta",
        boundary: CrossRouteRestartBoundaryV1::PublicationAccepted("promote-alpha"),
    },
    CrossRouteRestartPermutationV1 {
        id: "after-promote-yankee-accepted",
        client: "zeta",
        boundary: CrossRouteRestartBoundaryV1::PublicationAccepted("promote-yankee"),
    },
    CrossRouteRestartPermutationV1 {
        id: "after-zeta-root-accepted",
        client: "zeta",
        boundary: CrossRouteRestartBoundaryV1::PublicationAccepted("zeta-root"),
    },
    CrossRouteRestartPermutationV1 {
        id: "after-branch-witness-sent",
        client: "yankee",
        boundary: CrossRouteRestartBoundaryV1::BranchWitnessSent,
    },
    CrossRouteRestartPermutationV1 {
        id: "after-alpha-root-accepted",
        client: "alpha",
        boundary: CrossRouteRestartBoundaryV1::PublicationAccepted("alpha-root"),
    },
    CrossRouteRestartPermutationV1 {
        id: "after-alpha-root-ingested-by-zeta",
        client: "zeta",
        boundary: CrossRouteRestartBoundaryV1::AlphaRootIngestedByZeta,
    },
    CrossRouteRestartPermutationV1 {
        id: "after-zeta-child-accepted",
        client: "yankee",
        boundary: CrossRouteRestartBoundaryV1::PublicationAccepted("zeta-child"),
    },
    CrossRouteRestartPermutationV1 {
        id: "after-repair-zeta",
        client: "zeta",
        boundary: CrossRouteRestartBoundaryV1::FirstFullHistoryRepairCompleted,
    },
    CrossRouteRestartPermutationV1 {
        id: "after-repair-alpha",
        client: "alpha",
        boundary: CrossRouteRestartBoundaryV1::FirstFullHistoryRepairCompleted,
    },
    CrossRouteRestartPermutationV1 {
        id: "after-repair-yankee",
        client: "yankee",
        boundary: CrossRouteRestartBoundaryV1::FirstFullHistoryRepairCompleted,
    },
    CrossRouteRestartPermutationV1 {
        id: "after-repair-observer",
        client: "observer",
        boundary: CrossRouteRestartBoundaryV1::FirstFullHistoryRepairCompleted,
    },
];

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
    build_cross_route_app_runtime_recovery_scenario(true, None)
}

/// The public-projection form of `cross-route-app-runtime-recovery/v1` used by
/// app-runtime, process, container, and VM adapters.
pub fn cross_route_app_runtime_recovery_public_scenario() -> ScenarioSpec {
    build_cross_route_app_runtime_recovery_scenario(false, None)
}

/// Exact retained-engine form with one additional restart selected from the
/// reviewed v1 catalog. Seeds rotate the catalog while case indices enumerate
/// it, so twelve consecutive cases always cover every boundary.
pub fn cross_route_restart_permutation_exact_scenario(seed: u64, case_index: u64) -> ScenarioSpec {
    let permutation = restart_permutation(seed, case_index);
    build_cross_route_app_runtime_recovery_scenario(true, Some(permutation))
}

/// Public app/process/container/VM form of one reviewed restart permutation.
pub fn cross_route_restart_permutation_public_scenario(seed: u64, case_index: u64) -> ScenarioSpec {
    let permutation = restart_permutation(seed, case_index);
    build_cross_route_app_runtime_recovery_scenario(false, Some(permutation))
}

fn restart_permutation(seed: u64, case_index: u64) -> CrossRouteRestartPermutationV1 {
    let offset = usize::try_from(seed % CROSS_ROUTE_RESTART_PERMUTATIONS_V1.len() as u64)
        .expect("catalog length fits usize");
    let index = usize::try_from(case_index % CROSS_ROUTE_RESTART_PERMUTATIONS_V1.len() as u64)
        .expect("bounded case index fits usize");
    CROSS_ROUTE_RESTART_PERMUTATIONS_V1
        [(offset + index) % CROSS_ROUTE_RESTART_PERMUTATIONS_V1.len()]
}

fn build_cross_route_app_runtime_recovery_scenario(
    strict_engine_tail: bool,
    restart_permutation: Option<CrossRouteRestartPermutationV1>,
) -> ScenarioSpec {
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
                publication: Some("zeta-root".into()),
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
                publication: Some("alpha-root".into()),
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
                publication: Some("zeta-root".into()),
                ..Default::default()
            },
            clients: vec!["alpha".into(), "observer".into()],
            visible: true,
        },
        ScenarioStep::SetRelayEventVisibility {
            relay: "relay:shared".into(),
            selector: ScenarioMessageSelectorV2 {
                publication: Some("alpha-root".into()),
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
    if let Some(permutation) = restart_permutation {
        insert_restart_permutation(&mut steps, permutation, &clients);
    }
    bind_relay_visibility_action_ids(&mut steps);
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
        if restart_permutation.is_some() {
            steps.push(in_group(ScenarioStep::ObserveAdminPolicy {
                clients: clients.clone(),
            }));
        }
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
    let name = restart_permutation.map_or_else(
        || "cross-route-app-runtime-recovery/v1".into(),
        |permutation| {
            let family = if strict_engine_tail {
                "cross-route-exact-restart-permutations/v1"
            } else {
                "cross-route-restart-permutations/v1"
            };
            format!("{family}/{}-{}", permutation.id, permutation.client)
        },
    );
    ScenarioSpec {
        name,
        spec_version: "2".into(),
        topology: single_relay_topology(&clients),
        clients,
        steps,
    }
}

fn insert_restart_permutation(
    steps: &mut Vec<ScenarioStep>,
    permutation: CrossRouteRestartPermutationV1,
    clients: &[String],
) {
    let boundary_index = match permutation.boundary {
        CrossRouteRestartBoundaryV1::PublicationAccepted(publication) => {
            steps.iter().position(|step| {
                matches!(
                    step,
                    ScenarioStep::AcknowledgeOutbound {
                        publication: Some(observed),
                        outcome: SubjectOutboundOutcome::Accepted,
                        ..
                    } if observed == publication
                )
            })
        }
        CrossRouteRestartBoundaryV1::BranchWitnessSent => steps.iter().position(|step| {
            matches!(
                step,
                ScenarioStep::InGroup { action, .. }
                    if matches!(
                        action.as_ref(),
                        ScenarioStep::SendAppMessage { payload, .. }
                            if payload == "zeta-branch-witness"
                    )
            )
        }),
        CrossRouteRestartBoundaryV1::AlphaRootIngestedByZeta => steps
            .windows(3)
            .position(|window| {
                matches!(
                    window,
                    [
                        ScenarioStep::ReconnectClient { client },
                        ScenarioStep::SyncRelayHistory {
                            clients,
                            sync: ScenarioRelaySyncModeV2::Incremental,
                        },
                        ScenarioStep::Tick {
                            clients: tick_clients,
                        },
                    ] if client == "zeta"
                        && clients == &["zeta".to_owned()]
                        && tick_clients == clients
                )
            })
            .map(|window_start| window_start + 2),
        CrossRouteRestartBoundaryV1::FirstFullHistoryRepairCompleted => steps
            .windows(3)
            .position(|window| {
                matches!(
                    window,
                    [
                        ScenarioStep::ReconnectClient { client },
                        ScenarioStep::SyncRelayHistory {
                            clients: sync_clients,
                            sync: ScenarioRelaySyncModeV2::FullHistory,
                        },
                        ScenarioStep::Tick {
                            clients: tick_clients,
                        },
                    ] if client == "observer"
                        && sync_clients == clients
                        && tick_clients == clients
                )
            })
            .map(|window_start| window_start + 2),
    }
    .unwrap_or_else(|| panic!("missing cross-route restart boundary {}", permutation.id));
    steps.insert(
        boundary_index + 1,
        ScenarioStep::RestartClient {
            client: permutation.client.into(),
        },
    );
}

fn bind_relay_visibility_action_ids(steps: &mut [ScenarioStep]) {
    let publication_actions = steps
        .iter()
        .enumerate()
        .filter_map(|(step_index, step)| match step {
            ScenarioStep::InGroup { action, .. } => match action.as_ref() {
                ScenarioStep::UpdateGroupData { pending, .. } => {
                    Some((pending.clone(), crate::stable_action_id(step_index, step)))
                }
                _ => None,
            },
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    for step in steps {
        let ScenarioStep::SetRelayEventVisibility { selector, .. } = step else {
            continue;
        };
        let Some(publication) = selector.publication.take() else {
            continue;
        };
        selector.action_id = Some(
            publication_actions
                .get(&publication)
                .unwrap_or_else(|| panic!("missing relay publication action {publication}"))
                .clone(),
        );
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
    let checkpoint_actions = schedule
        .actions
        .iter()
        .filter(|action| {
            matches!(
                &action.step,
                ScenarioStep::Observe { .. }
                    | ScenarioStep::ObserveExact { .. }
                    | ScenarioStep::ObserveAdminPolicy { .. }
            )
        })
        .collect::<Vec<_>>();
    let expected_checkpoint_count = checkpoint_actions.len();
    if spec.clients.is_empty()
        || expected_checkpoint_count < 4
        || report.observations.len() != spec.clients.len() * expected_checkpoint_count
    {
        return Err(format!(
            "expected {expected_checkpoint_count} complete process checkpoints from the canonical schedule: {report:#?}"
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
    let terminal_observe_indices = checkpoint_actions
        .iter()
        .enumerate()
        .filter_map(|(index, action)| {
            matches!(&action.step, ScenarioStep::Observe { .. }).then_some(index)
        })
        .rev()
        .take(2)
        .collect::<Vec<_>>();
    let [settled_index, first_settled_index] = terminal_observe_indices.as_slice() else {
        return Err(format!(
            "canonical schedule lacks two terminal public observations: {report:#?}"
        ));
    };
    let first_settled = &checkpoints[*first_settled_index];
    let settled = &checkpoints[*settled_index];
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
    for action in &schedule.actions {
        let ScenarioStep::RestartClient { client } = &action.step else {
            continue;
        };
        if !report.lifecycle.iter().any(|event| {
            event.action_id == action.schedule.action_id
                && event.participant == *client
                && event.event == "restarted"
        }) {
            return Err(format!(
                "{client} did not durably reopen at {}: {:#?}",
                action.schedule.action_id, report.lifecycle
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_catalog_is_complete_unique_and_compilable() {
        let ids = CROSS_ROUTE_RESTART_PERMUTATIONS_V1
            .iter()
            .map(|permutation| permutation.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), CROSS_ROUTE_RESTART_PERMUTATIONS_V1.len());

        let baseline = cross_route_app_runtime_recovery_public_scenario();
        let baseline_restarts = baseline
            .steps
            .iter()
            .filter(|step| matches!(step, ScenarioStep::RestartClient { .. }))
            .count();
        assert_eq!(baseline_restarts, 1);
        assert!(baseline.steps.iter().all(|step| !matches!(
            step,
            ScenarioStep::InGroup { action, .. }
                if matches!(action.as_ref(), ScenarioStep::ObserveAdminPolicy { .. })
        )));

        let variants = (0..CROSS_ROUTE_RESTART_PERMUTATIONS_V1.len() as u64)
            .map(|case_index| cross_route_restart_permutation_public_scenario(0, case_index))
            .collect::<Vec<_>>();
        assert_eq!(
            variants
                .iter()
                .map(|scenario| scenario.name.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            CROSS_ROUTE_RESTART_PERMUTATIONS_V1.len()
        );
        let expected_restart_loci = [
            ("after-create-accepted", ("zeta", 2)),
            ("after-promote-alpha-accepted", ("zeta", 6)),
            ("after-promote-yankee-accepted", ("zeta", 10)),
            ("after-zeta-root-accepted", ("zeta", 18)),
            ("after-branch-witness-sent", ("yankee", 21)),
            ("after-alpha-root-accepted", ("alpha", 27)),
            ("after-alpha-root-ingested-by-zeta", ("zeta", 30)),
            ("after-zeta-child-accepted", ("yankee", 37)),
            ("after-repair-zeta", ("zeta", 45)),
            ("after-repair-alpha", ("alpha", 45)),
            ("after-repair-yankee", ("yankee", 45)),
            ("after-repair-observer", ("observer", 45)),
        ]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
        for scenario in variants {
            compile_scenario(&scenario).expect("restart permutation compiles");
            assert_eq!(
                scenario
                    .steps
                    .iter()
                    .filter(|step| matches!(step, ScenarioStep::RestartClient { .. }))
                    .count(),
                baseline_restarts + 1,
                "{} must add exactly one reviewed restart",
                scenario.name
            );
            assert_eq!(
                scenario
                    .steps
                    .iter()
                    .filter(|step| matches!(
                        step,
                        ScenarioStep::InGroup { action, .. }
                            if matches!(action.as_ref(), ScenarioStep::ObserveAdminPolicy { .. })
                    ))
                    .count(),
                1,
                "{} must carry the catalog-only portable admin observation",
                scenario.name
            );
            let permutation_id = scenario
                .name
                .rsplit_once('/')
                .expect("catalog scenario has a family prefix")
                .1
                .rsplit_once('-')
                .expect("catalog scenario names its restart client")
                .0;
            let (expected_client, expected_index) = expected_restart_loci
                .get(permutation_id)
                .unwrap_or_else(|| panic!("missing pinned locus for {permutation_id}"));
            assert!(
                matches!(
                    &scenario.steps[*expected_index],
                    ScenarioStep::RestartClient { client } if client == expected_client
                ),
                "{} moved from pinned restart step {}",
                scenario.name,
                expected_index
            );
        }
    }

    #[test]
    fn exact_and_public_restart_artifacts_have_distinct_names() {
        let public = cross_route_restart_permutation_public_scenario(0, 0);
        let exact = cross_route_restart_permutation_exact_scenario(0, 0);
        assert!(
            public
                .name
                .starts_with("cross-route-restart-permutations/v1/")
        );
        assert!(
            exact
                .name
                .starts_with("cross-route-exact-restart-permutations/v1/")
        );
        assert_ne!(public.name, exact.name);
    }

    #[test]
    fn relay_visibility_action_ids_follow_inserted_restart_indices() {
        for scenario in std::iter::once(cross_route_app_runtime_recovery_public_scenario()).chain(
            (0..CROSS_ROUTE_RESTART_PERMUTATIONS_V1.len() as u64)
                .map(|case_index| cross_route_restart_permutation_public_scenario(0, case_index)),
        ) {
            let publication_actions = scenario
                .steps
                .iter()
                .enumerate()
                .filter_map(|(step_index, step)| match step {
                    ScenarioStep::InGroup { action, .. } => match action.as_ref() {
                        ScenarioStep::UpdateGroupData { pending, .. }
                            if pending == "zeta-root" || pending == "alpha-root" =>
                        {
                            Some(crate::stable_action_id(step_index, step))
                        }
                        _ => None,
                    },
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            let selectors = scenario.steps.iter().filter_map(|step| match step {
                ScenarioStep::SetRelayEventVisibility { selector, .. } => Some(selector),
                _ => None,
            });
            for selector in selectors {
                assert!(
                    selector
                        .action_id
                        .as_ref()
                        .is_some_and(|action_id| publication_actions.contains(action_id)),
                    "{} has a stale visibility selector: {selector:?}",
                    scenario.name
                );
                assert!(selector.publication.is_none(), "{}", scenario.name);
            }
        }
    }

    #[test]
    fn seed_rotates_but_does_not_change_the_restart_catalog() {
        let names = |seed| {
            (0..CROSS_ROUTE_RESTART_PERMUTATIONS_V1.len() as u64)
                .map(|case_index| {
                    cross_route_restart_permutation_public_scenario(seed, case_index).name
                })
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(names(0), names(7));
    }
}
