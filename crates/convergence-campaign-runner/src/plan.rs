use std::collections::BTreeMap;
use std::path::PathBuf;

use cgka_conformance_simulator::process_orchestrator::{
    ProcessNodeLaunchV1, process_participant_token,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fault_rollbacks: BTreeMap<String, Vec<PlannedCommandV1>>,
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
            let normalized_manifest = manifest.output_dir.join("normalized-manifest.json");
            let normalized_manifest = utf8_path(&normalized_manifest, "normalized_manifest")?;
            let scenario = utf8_path(&manifest.scenario.path, "scenario")?;
            let output_dir = utf8_path(&manifest.output_dir, "output_dir")?;
            let driver = utf8_path(&vm.driver, "vm_driver")?;
            let args = vm
                .driver_args
                .iter()
                .map(|argument| {
                    argument
                        .replace("{manifest}", normalized_manifest)
                        .replace("{scenario}", scenario)
                        .replace("{output_dir}", output_dir)
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
                fault_rollbacks: BTreeMap::new(),
                cleanup: Vec::new(),
                vm_driver: Some(PlannedCommandV1::exact(
                    "run_external_vm_campaign",
                    driver,
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
    let mut fault_rollbacks = BTreeMap::<String, Vec<PlannedCommandV1>>::new();
    for fault in &manifest.faults {
        fault_commands
            .entry(fault.at_barrier.clone())
            .or_default()
            .extend(container_fault_commands(
                runtime,
                &relay,
                &container.default_participant_image,
                &fault.action,
            ));
        let rollback = container_fault_rollback_commands(
            runtime,
            &relay,
            &container.default_participant_image,
            &fault.action,
        );
        if !rollback.is_empty() {
            fault_rollbacks
                .entry(fault.at_barrier.clone())
                .or_default()
                .extend(rollback);
        }
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
        fault_rollbacks,
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
    fault_injector_image: &str,
    fault: &DistributedFaultV1,
) -> Vec<PlannedCommandV1> {
    match fault {
        DistributedFaultV1::NetworkPartition { participant, peer } => {
            let container = participant_container(participant);
            let peer = peer_container(peer, relay);
            network_partition_commands(runtime, fault_injector_image, container, participant, peer)
        }
        DistributedFaultV1::NetworkHeal { participant, peer } => {
            let container = participant_container(participant);
            let peer = peer_container(peer, relay);
            network_heal_commands(runtime, fault_injector_image, container, participant, peer)
        }
        DistributedFaultV1::NetworkShape {
            participant,
            latency_ms,
            jitter_ms,
            loss_basis_points,
            bandwidth_kbit,
        } => vec![network_exec(
            runtime,
            fault_injector_image,
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
        DistributedFaultV1::NetworkReset { participant } => {
            vec![network_exec_accepting(
                runtime,
                fault_injector_image,
                participant_container(participant),
                "reset_network_shape",
                vec![
                    "tc".into(),
                    "qdisc".into(),
                    "del".into(),
                    "dev".into(),
                    "eth0".into(),
                    "root".into(),
                ],
                vec![0, 2],
            )]
        }
        DistributedFaultV1::RestartRelay => vec![PlannedCommandV1::exact(
            "restart_relay_host",
            runtime,
            vec!["restart".into(), relay.into()],
        )],
        // The process orchestrator must own the crash/relaunch so its JSONL
        // stdio handles are replaced with the new container process. The
        // runner lowers this manifest fault into CrashProcess + RestartProcess.
        DistributedFaultV1::CrashParticipantHost { .. } => Vec::new(),
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
            "rm",
            vec![
                "-f".into(),
                format!(
                    "{{host_run_root}}/participants/{}/.disk-pressure",
                    process_participant_token(participant)
                ),
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

fn container_fault_rollback_commands(
    runtime: &str,
    relay: &str,
    fault_injector_image: &str,
    fault: &DistributedFaultV1,
) -> Vec<PlannedCommandV1> {
    match fault {
        DistributedFaultV1::NetworkPartition { participant, peer } => network_heal_commands(
            runtime,
            fault_injector_image,
            participant_container(participant),
            participant,
            peer_container(peer, relay),
        ),
        DistributedFaultV1::NetworkHeal { participant, peer } => network_partition_commands(
            runtime,
            fault_injector_image,
            participant_container(participant),
            participant,
            peer_container(peer, relay),
        ),
        _ => Vec::new(),
    }
}

fn network_partition_commands(
    runtime: &str,
    image: &str,
    container: String,
    participant: &str,
    peer: String,
) -> Vec<PlannedCommandV1> {
    let chain = partition_chain(participant, &peer);
    let peer_set = partition_set(participant, &peer);
    let inbound_rule = vec![
        "-m".into(),
        "set".into(),
        "--match-set".into(),
        peer_set.clone(),
        "src".into(),
        "-j".into(),
        "REJECT".into(),
    ];
    let outbound_rule = vec![
        "-m".into(),
        "set".into(),
        "--match-set".into(),
        peer_set.clone(),
        "dst".into(),
        "-j".into(),
        "REJECT".into(),
    ];
    vec![
        network_exec(
            runtime,
            image,
            container.clone(),
            "create_network_partition_peer_set",
            vec![
                "ipset".into(),
                "create".into(),
                peer_set.clone(),
                "hash:ip".into(),
                "-exist".into(),
            ],
        ),
        network_exec(
            runtime,
            image,
            container.clone(),
            "reset_network_partition_peer_set",
            vec!["ipset".into(), "flush".into(), peer_set.clone()],
        ),
        network_exec(
            runtime,
            image,
            container.clone(),
            "record_network_partition_peer_address",
            vec![
                "ipset".into(),
                "add".into(),
                peer_set.clone(),
                peer,
                "-exist".into(),
            ],
        ),
        network_exec_accepting(
            runtime,
            image,
            container.clone(),
            "create_network_partition_chain",
            vec!["iptables".into(), "-N".into(), chain.clone()],
            vec![0, 1],
        ),
        network_exec(
            runtime,
            image,
            container.clone(),
            "reset_network_partition_chain",
            vec!["iptables".into(), "-F".into(), chain.clone()],
        ),
        network_exec(
            runtime,
            image,
            container.clone(),
            "partition_network_inbound",
            [
                vec!["iptables".into(), "-A".into(), chain.clone()],
                inbound_rule.clone(),
            ]
            .concat(),
        ),
        network_exec(
            runtime,
            image,
            container.clone(),
            "partition_network_outbound",
            [
                vec!["iptables".into(), "-A".into(), chain.clone()],
                outbound_rule.clone(),
            ]
            .concat(),
        ),
        network_exec_accepting(
            runtime,
            image,
            container.clone(),
            "remove_stale_inbound_partition_jump",
            vec![
                "iptables".into(),
                "-D".into(),
                "INPUT".into(),
                "-j".into(),
                chain.clone(),
            ],
            vec![0, 1],
        ),
        network_exec_accepting(
            runtime,
            image,
            container.clone(),
            "remove_stale_outbound_partition_jump",
            vec![
                "iptables".into(),
                "-D".into(),
                "OUTPUT".into(),
                "-j".into(),
                chain.clone(),
            ],
            vec![0, 1],
        ),
        network_exec(
            runtime,
            image,
            container.clone(),
            "activate_inbound_partition",
            vec![
                "iptables".into(),
                "-I".into(),
                "INPUT".into(),
                "-j".into(),
                chain.clone(),
            ],
        ),
        network_exec(
            runtime,
            image,
            container.clone(),
            "activate_outbound_partition",
            vec![
                "iptables".into(),
                "-I".into(),
                "OUTPUT".into(),
                "-j".into(),
                chain.clone(),
            ],
        ),
        network_exec(
            runtime,
            image,
            container.clone(),
            "verify_network_partition_inbound_rule",
            [
                vec!["iptables".into(), "-C".into(), chain.clone()],
                inbound_rule,
            ]
            .concat(),
        ),
        network_exec(
            runtime,
            image,
            container.clone(),
            "verify_network_partition_outbound_rule",
            [
                vec!["iptables".into(), "-C".into(), chain.clone()],
                outbound_rule,
            ]
            .concat(),
        ),
        network_exec(
            runtime,
            image,
            container.clone(),
            "verify_inbound_partition_active",
            vec![
                "iptables".into(),
                "-C".into(),
                "INPUT".into(),
                "-j".into(),
                chain.clone(),
            ],
        ),
        network_exec(
            runtime,
            image,
            container,
            "verify_outbound_partition_active",
            vec![
                "iptables".into(),
                "-C".into(),
                "OUTPUT".into(),
                "-j".into(),
                chain,
            ],
        ),
    ]
}

fn network_heal_commands(
    runtime: &str,
    image: &str,
    container: String,
    participant: &str,
    peer: String,
) -> Vec<PlannedCommandV1> {
    let chain = partition_chain(participant, &peer);
    let peer_set = partition_set(participant, &peer);
    vec![
        network_exec_accepting(
            runtime,
            image,
            container.clone(),
            "heal_inbound_network_partition",
            vec![
                "iptables".into(),
                "-D".into(),
                "INPUT".into(),
                "-j".into(),
                chain.clone(),
            ],
            vec![0, 1],
        ),
        network_exec_accepting(
            runtime,
            image,
            container.clone(),
            "heal_outbound_network_partition",
            vec![
                "iptables".into(),
                "-D".into(),
                "OUTPUT".into(),
                "-j".into(),
                chain.clone(),
            ],
            vec![0, 1],
        ),
        network_exec_accepting(
            runtime,
            image,
            container.clone(),
            "verify_inbound_partition_healed",
            vec![
                "iptables".into(),
                "-C".into(),
                "INPUT".into(),
                "-j".into(),
                chain.clone(),
            ],
            vec![1],
        ),
        network_exec_accepting(
            runtime,
            image,
            container.clone(),
            "verify_outbound_partition_healed",
            vec![
                "iptables".into(),
                "-C".into(),
                "OUTPUT".into(),
                "-j".into(),
                chain.clone(),
            ],
            vec![1],
        ),
        network_exec_accepting(
            runtime,
            image,
            container.clone(),
            "flush_network_partition_chain",
            vec!["iptables".into(), "-F".into(), chain.clone()],
            vec![0, 1],
        ),
        network_exec_accepting(
            runtime,
            image,
            container.clone(),
            "remove_network_partition_chain",
            vec!["iptables".into(), "-X".into(), chain.clone()],
            vec![0, 1],
        ),
        network_exec_accepting(
            runtime,
            image,
            container.clone(),
            "verify_network_partition_chain_removed",
            vec!["iptables".into(), "-L".into(), chain],
            vec![1],
        ),
        network_exec_accepting(
            runtime,
            image,
            container.clone(),
            "remove_network_partition_peer_set",
            vec!["ipset".into(), "destroy".into(), peer_set.clone()],
            vec![0, 1],
        ),
        network_exec_accepting(
            runtime,
            image,
            container,
            "verify_network_partition_peer_set_removed",
            vec!["ipset".into(), "list".into(), peer_set],
            vec![1],
        ),
    ]
}

fn exec(runtime: &str, container: String, purpose: &str, command: Vec<String>) -> PlannedCommandV1 {
    PlannedCommandV1::exact(
        purpose,
        runtime,
        [vec!["exec".into(), container], command].concat(),
    )
}

/// Run a network mutation from a short-lived, capability-scoped container
/// sharing the participant's network namespace. Participant processes remain
/// unprivileged; only this dedicated injector receives `NET_ADMIN`.
fn network_exec(
    runtime: &str,
    image: &str,
    participant_container: String,
    purpose: impl Into<String>,
    command: Vec<String>,
) -> PlannedCommandV1 {
    PlannedCommandV1::exact(
        purpose,
        runtime,
        [
            vec![
                "run".into(),
                "--rm".into(),
                "--network".into(),
                format!("container:{participant_container}"),
                "--cap-drop".into(),
                "ALL".into(),
                "--cap-add".into(),
                "NET_ADMIN".into(),
                image.into(),
            ],
            command,
        ]
        .concat(),
    )
}

fn network_exec_accepting(
    runtime: &str,
    image: &str,
    participant_container: String,
    purpose: impl Into<String>,
    command: Vec<String>,
    success_exit_codes: Vec<i32>,
) -> PlannedCommandV1 {
    let mut planned = network_exec(runtime, image, participant_container, purpose, command);
    planned.success_exit_codes = success_exit_codes;
    planned
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

fn partition_chain(participant: &str, peer: &str) -> String {
    let digest = Sha256::digest(format!("{participant}\0{peer}"));
    format!("MARMOT_{}", hex::encode(&digest[..8]).to_ascii_uppercase())
}

fn partition_set(participant: &str, peer: &str) -> String {
    let digest = Sha256::digest(format!("{participant}\0{peer}"));
    format!("MSET_{}", hex::encode(&digest[..8]).to_ascii_uppercase())
}

fn utf8_path<'a>(path: &'a std::path::Path, field: &str) -> Result<&'a str, RunnerError> {
    path.to_str().ok_or_else(|| {
        RunnerError::validation(
            "non_utf8_path",
            format!("{field} must be representable as UTF-8 argv"),
        )
    })
}

fn format_basis_points(value: u16) -> String {
    format!("{}.{:02}%", value / 100, value % 100)
}
