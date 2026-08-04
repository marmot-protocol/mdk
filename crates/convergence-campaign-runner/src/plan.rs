use std::collections::BTreeMap;
use std::path::PathBuf;

use cgka_conformance_simulator::process_orchestrator::{
    ProcessNodeLaunchV1, process_participant_token,
};
use serde::{Deserialize, Serialize};

use crate::RunnerError;
use crate::manifest::{
    ContainerBackendV1, DistributedBackendV1, DistributedCampaignManifestV1, DistributedFaultV1,
    FaultPeerV1,
};

pub const DISTRIBUTED_EXECUTION_PLAN_VERSION: &str = "1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedExecutionPlanV1 {
    pub schema_version: String,
    pub campaign_id: String,
    pub backend: String,
    pub setup: Vec<PlannedCommandV1>,
    pub fault_commands: BTreeMap<String, Vec<PlannedCommandV1>>,
    pub cleanup: Vec<PlannedCommandV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_driver: Option<PlannedCommandV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedCommandV1 {
    pub purpose: String,
    pub program: String,
    pub args: Vec<String>,
    #[serde(default = "default_success_codes")]
    pub success_exit_codes: Vec<i32>,
}

fn default_success_codes() -> Vec<i32> {
    vec![0]
}

impl PlannedCommandV1 {
    fn exact(purpose: impl Into<String>, program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            purpose: purpose.into(),
            program: program.into(),
            args,
            success_exit_codes: vec![0],
        }
    }

    fn idempotent(
        purpose: impl Into<String>,
        program: impl Into<String>,
        args: Vec<String>,
    ) -> Self {
        Self {
            purpose: purpose.into(),
            program: program.into(),
            args,
            success_exit_codes: vec![0, 1, 2],
        }
    }
}

pub fn build_execution_plan(
    manifest: &DistributedCampaignManifestV1,
) -> Result<DistributedExecutionPlanV1, RunnerError> {
    manifest.validate()?;
    match &manifest.backend {
        DistributedBackendV1::Container(container) => container_plan(manifest, container),
        DistributedBackendV1::VirtualMachine(vm) => {
            let args = vm
                .driver_args
                .iter()
                .map(|argument| {
                    argument
                        .replace(
                            "{manifest}",
                            manifest
                                .output_dir
                                .join("normalized-manifest.json")
                                .to_str()
                                .unwrap_or("<non-utf8>"),
                        )
                        .replace(
                            "{scenario}",
                            manifest.scenario.path.to_str().unwrap_or("<non-utf8>"),
                        )
                        .replace(
                            "{output_dir}",
                            manifest.output_dir.to_str().unwrap_or("<non-utf8>"),
                        )
                        .replace(
                            "{participant_count}",
                            &manifest.participants.len().to_string(),
                        )
                })
                .collect();
            Ok(DistributedExecutionPlanV1 {
                schema_version: DISTRIBUTED_EXECUTION_PLAN_VERSION.into(),
                campaign_id: manifest.campaign_id.clone(),
                backend: "virtual_machine".into(),
                setup: Vec::new(),
                fault_commands: BTreeMap::new(),
                cleanup: Vec::new(),
                vm_driver: Some(PlannedCommandV1::exact(
                    "run_external_vm_campaign",
                    vm.driver.to_string_lossy(),
                    args,
                )),
            })
        }
    }
}

fn container_plan(
    manifest: &DistributedCampaignManifestV1,
    container: &ContainerBackendV1,
) -> Result<DistributedExecutionPlanV1, RunnerError> {
    let runtime = container.runtime.executable();
    let network = format!("{}-network", container.namespace);
    let relay = format!("{}-relay", container.namespace);
    let label = format!("io.marmot.convergence={}", manifest.campaign_id);
    let setup = vec![
        PlannedCommandV1::exact(
            "create_isolated_network",
            runtime,
            vec![
                "network".into(),
                "create".into(),
                "--label".into(),
                label.clone(),
                network.clone(),
            ],
        ),
        PlannedCommandV1::exact(
            "start_retained_relay",
            runtime,
            [
                vec![
                    "run".into(),
                    "--detach".into(),
                    "--rm".into(),
                    "--name".into(),
                    relay.clone(),
                    "--network".into(),
                    network.clone(),
                    "--label".into(),
                    label,
                    container.relay_image.clone(),
                ],
                container.relay_command.clone(),
            ]
            .concat(),
        ),
    ];

    let mut fault_commands = BTreeMap::<String, Vec<PlannedCommandV1>>::new();
    for fault in &manifest.faults {
        fault_commands
            .entry(fault.at_barrier.clone())
            .or_default()
            .extend(container_fault_commands(runtime, &relay, &fault.action));
    }
    let cleanup = vec![
        PlannedCommandV1::idempotent(
            "remove_retained_relay",
            runtime,
            vec!["rm".into(), "--force".into(), relay],
        ),
        PlannedCommandV1::idempotent(
            "remove_isolated_network",
            runtime,
            vec!["network".into(), "rm".into(), network],
        ),
    ];
    Ok(DistributedExecutionPlanV1 {
        schema_version: DISTRIBUTED_EXECUTION_PLAN_VERSION.into(),
        campaign_id: manifest.campaign_id.clone(),
        backend: "container".into(),
        setup,
        fault_commands,
        cleanup,
        vm_driver: None,
    })
}

pub fn container_node_launch(
    manifest: &DistributedCampaignManifestV1,
) -> Result<ProcessNodeLaunchV1, RunnerError> {
    manifest.validate()?;
    let DistributedBackendV1::Container(container) = &manifest.backend else {
        return Err(RunnerError::validation(
            "container_backend_required",
            "container node launch is unavailable for VM manifests",
        ));
    };
    let runtime = container.runtime.executable();
    let network = format!("{}-network", container.namespace);
    let relay = format!("{}-relay", container.namespace);
    let mut args_by_participant = BTreeMap::new();
    for participant in &manifest.participants {
        let image = participant
            .container_image
            .as_ref()
            .unwrap_or(&container.default_participant_image);
        let args = [
            vec![
                "run".into(),
                "--rm".into(),
                "--interactive".into(),
                "--init".into(),
                "--name".into(),
                "{run_token}-{participant}".into(),
                "--network".into(),
                network.clone(),
                "--cap-add".into(),
                "NET_ADMIN".into(),
                "--mount".into(),
                "type=bind,src={host_run_root},dst={child_run_root}".into(),
                image.clone(),
            ],
            [
                container.node_command.clone(),
                vec!["--relay-proxy".into(), format!("{relay}:8080")],
            ]
            .concat(),
        ]
        .concat();
        args_by_participant.insert(participant.id.clone(), args);
    }
    Ok(ProcessNodeLaunchV1 {
        program: PathBuf::from(runtime),
        args: Vec::new(),
        args_by_participant,
        child_run_root: Some(PathBuf::from("/campaign")),
    })
}

fn container_fault_commands(
    runtime: &str,
    relay: &str,
    fault: &DistributedFaultV1,
) -> Vec<PlannedCommandV1> {
    match fault {
        DistributedFaultV1::NetworkPartition { participant, peer } => vec![exec(
            runtime,
            participant_container(participant),
            "partition_network",
            vec![
                "iptables".into(),
                "-I".into(),
                "OUTPUT".into(),
                "-d".into(),
                peer_container(peer, relay),
                "-j".into(),
                "REJECT".into(),
            ],
        )],
        DistributedFaultV1::NetworkHeal { participant, peer } => {
            vec![PlannedCommandV1::idempotent(
                "heal_network_partition",
                runtime,
                [
                    vec!["exec".into(), participant_container(participant)],
                    vec![
                        "iptables".into(),
                        "-D".into(),
                        "OUTPUT".into(),
                        "-d".into(),
                        peer_container(peer, relay),
                        "-j".into(),
                        "REJECT".into(),
                    ],
                ]
                .concat(),
            )]
        }
        DistributedFaultV1::NetworkShape {
            participant,
            latency_ms,
            jitter_ms,
            loss_basis_points,
            bandwidth_kbit,
        } => vec![exec(
            runtime,
            participant_container(participant),
            "shape_network",
            vec![
                "tc".into(),
                "qdisc".into(),
                "replace".into(),
                "dev".into(),
                "eth0".into(),
                "root".into(),
                "netem".into(),
                "delay".into(),
                format!("{latency_ms}ms"),
                format!("{jitter_ms}ms"),
                "loss".into(),
                format_basis_points(*loss_basis_points),
                "rate".into(),
                format!("{bandwidth_kbit}kbit"),
            ],
        )],
        DistributedFaultV1::NetworkReset { participant } => vec![PlannedCommandV1::idempotent(
            "reset_network_shape",
            runtime,
            vec![
                "exec".into(),
                participant_container(participant),
                "tc".into(),
                "qdisc".into(),
                "del".into(),
                "dev".into(),
                "eth0".into(),
                "root".into(),
            ],
        )],
        DistributedFaultV1::RestartRelay => vec![PlannedCommandV1::exact(
            "restart_relay_host",
            runtime,
            vec!["restart".into(), relay.into()],
        )],
        DistributedFaultV1::CrashParticipantHost { participant } => {
            vec![PlannedCommandV1::idempotent(
                "crash_participant_host",
                runtime,
                vec!["kill".into(), participant_container(participant)],
            )]
        }
        DistributedFaultV1::FillDisk { participant, bytes } => vec![exec(
            runtime,
            participant_container(participant),
            "fill_participant_disk",
            vec![
                "fallocate".into(),
                "-l".into(),
                bytes.to_string(),
                participant_pressure_path(participant),
            ],
        )],
        DistributedFaultV1::ReleaseDisk { participant } => vec![PlannedCommandV1::idempotent(
            "release_participant_disk",
            runtime,
            vec![
                "exec".into(),
                participant_container(participant),
                "rm".into(),
                "-f".into(),
                participant_pressure_path(participant),
            ],
        )],
        DistributedFaultV1::DatabaseContention {
            participant,
            workers,
            bytes_per_worker,
            duration_ms,
        } => vec![PlannedCommandV1::exact(
            "start_database_contention",
            runtime,
            vec![
                "exec".into(),
                "--detach".into(),
                participant_container(participant),
                "stress-ng".into(),
                "--hdd".into(),
                workers.to_string(),
                "--hdd-bytes".into(),
                bytes_per_worker.to_string(),
                "--temp-path".into(),
                participant_state_path(participant),
                "--timeout".into(),
                format!("{duration_ms}ms"),
            ],
        )],
        DistributedFaultV1::StopDatabaseContention { participant } => {
            vec![PlannedCommandV1::idempotent(
                "stop_database_contention",
                runtime,
                vec![
                    "exec".into(),
                    participant_container(participant),
                    "pkill".into(),
                    "-x".into(),
                    "stress-ng".into(),
                ],
            )]
        }
        DistributedFaultV1::SlowBlockDevice { .. } => Vec::new(),
    }
}

fn exec(runtime: &str, container: String, purpose: &str, command: Vec<String>) -> PlannedCommandV1 {
    PlannedCommandV1::exact(
        purpose,
        runtime,
        [vec!["exec".into(), container], command].concat(),
    )
}

fn participant_container(participant: &str) -> String {
    format!("{{run_token}}-{}", process_participant_token(participant))
}

fn participant_state_path(participant: &str) -> String {
    format!(
        "/campaign/participants/{}",
        process_participant_token(participant)
    )
}

fn participant_pressure_path(participant: &str) -> String {
    format!("{}/.disk-pressure", participant_state_path(participant))
}

fn peer_container(peer: &FaultPeerV1, relay: &str) -> String {
    match peer {
        FaultPeerV1::Relay => relay.into(),
        FaultPeerV1::Participant(participant) => participant_container(participant),
    }
}

fn format_basis_points(value: u16) -> String {
    format!("{}.{:02}%", value / 100, value % 100)
}
