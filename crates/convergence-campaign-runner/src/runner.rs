use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use cgka_conformance_simulator::process_orchestrator::{
    ProcessBarrierHook, ProcessOrchestrator, ProcessOrchestratorError, ProcessScenarioReportV1,
    process_participant_token,
};
use cgka_conformance_simulator::{ScenarioSpec, compile_scenario};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::time::timeout;

use crate::manifest::{DistributedBackendV1, DistributedCampaignManifestV1};
use crate::plan::{DistributedExecutionPlanV1, PlannedCommandV1, build_execution_plan};
use crate::{RunnerError, container_node_launch, verify_manifest_inputs};

pub const DISTRIBUTED_RUN_RECEIPT_VERSION: &str = "1";
const INFRASTRUCTURE_COMMAND_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedRunReceiptV1 {
    pub schema_version: String,
    pub campaign_id: String,
    pub backend: String,
    pub command_receipts: Vec<CommandReceiptV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_report: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cleanup_failures: Vec<String>,
    pub completed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandReceiptV1 {
    pub purpose: String,
    pub exit_code: Option<i32>,
    pub accepted: bool,
}

pub async fn run_manifest(
    manifest: &DistributedCampaignManifestV1,
) -> Result<DistributedRunReceiptV1, RunnerError> {
    let scenario_bytes = verify_manifest_inputs(manifest)?;
    let plan = build_execution_plan(manifest)?;
    let scenario: ScenarioSpec = serde_json::from_slice(&scenario_bytes)
        .map_err(|error| RunnerError::environment("scenario_parse", error))?;
    validate_scenario_binding(manifest, &scenario)?;
    fs_private::create_dir_all_private(&manifest.output_dir)
        .map_err(|error| RunnerError::environment("output_directory", error))?;
    fs_private::write_private(
        &manifest.output_dir.join("normalized-manifest.json"),
        &serde_json::to_vec_pretty(manifest)
            .map_err(|error| RunnerError::environment("manifest_serialize", error))?,
    )
    .map_err(|error| RunnerError::environment("manifest_write", error))?;
    match &manifest.backend {
        DistributedBackendV1::Container(_) => run_container(manifest, &plan, &scenario).await,
        DistributedBackendV1::VirtualMachine(_) => run_vm(manifest, &plan).await,
    }
}

fn validate_scenario_binding(
    manifest: &DistributedCampaignManifestV1,
    scenario: &ScenarioSpec,
) -> Result<(), RunnerError> {
    let manifest_clients = manifest
        .participants
        .iter()
        .map(|participant| participant.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let scenario_clients = scenario
        .clients
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if manifest_clients != scenario_clients {
        return Err(RunnerError::validation(
            "scenario_participant_mismatch",
            "manifest participants must exactly match canonical scenario clients",
        ));
    }
    let compiled = compile_scenario(scenario)
        .map_err(|error| RunnerError::environment("scenario_compile", error))?;
    let barriers = compiled
        .actions
        .iter()
        .filter_map(|action| match &action.step {
            cgka_conformance_simulator::ScenarioStep::Barrier { name } => Some(name.as_str()),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    for fault in &manifest.faults {
        if !barriers.contains(fault.at_barrier.as_str()) {
            return Err(RunnerError::validation(
                "unknown_fault_barrier",
                "every scheduled fault must bind to a canonical scenario barrier",
            ));
        }
    }
    if matches!(manifest.backend, DistributedBackendV1::Container(_))
        && compiled.topology.relays.len() > 1
    {
        return Err(RunnerError::validation(
            "multiple_container_relays_unsupported",
            "container campaigns currently require zero or one declared relay",
        ));
    }
    validate_partition_restart_order(manifest, &compiled)?;
    Ok(())
}

fn validate_partition_restart_order(
    manifest: &DistributedCampaignManifestV1,
    compiled: &cgka_conformance_simulator::CompiledScenarioV2,
) -> Result<(), RunnerError> {
    let barrier_order = compiled
        .actions
        .iter()
        .enumerate()
        .filter_map(|(index, action)| match &action.step {
            cgka_conformance_simulator::ScenarioStep::Barrier { name } => {
                Some((name.as_str(), index))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut faults = manifest.faults.iter().collect::<Vec<_>>();
    faults.sort_by_key(|fault| barrier_order.get(fault.at_barrier.as_str()).copied());
    let mut active = std::collections::BTreeSet::<(String, String)>::new();
    for fault in faults {
        match &fault.action {
            crate::DistributedFaultV1::NetworkPartition { participant, peer } => {
                active.insert((participant.clone(), fault_peer_key(peer)));
            }
            crate::DistributedFaultV1::NetworkHeal { participant, peer } => {
                active.remove(&(participant.clone(), fault_peer_key(peer)));
            }
            crate::DistributedFaultV1::CrashParticipantHost { participant }
                if active.iter().any(|(subject, peer)| {
                    subject == participant || peer == &format!("participant:{participant}")
                }) =>
            {
                return Err(RunnerError::validation(
                    "partition_peer_restart_unsupported",
                    "heal participant partitions before recreating either endpoint",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn fault_peer_key(peer: &crate::FaultPeerV1) -> String {
    match peer {
        crate::FaultPeerV1::Relay => "relay".into(),
        crate::FaultPeerV1::Participant(participant) => format!("participant:{participant}"),
    }
}

async fn run_container(
    manifest: &DistributedCampaignManifestV1,
    plan: &DistributedExecutionPlanV1,
    scenario: &ScenarioSpec,
) -> Result<DistributedRunReceiptV1, RunnerError> {
    let mut receipts = Vec::new();
    let mut cleanup_failures = Vec::new();
    for command in &plan.setup {
        match execute(command, CommandContext::default()).await {
            Ok(receipt) => receipts.push(receipt),
            Err(failure) => {
                if let Some(receipt) = failure.receipt {
                    receipts.push(receipt);
                }
                cleanup(plan, None, &mut receipts, &mut cleanup_failures).await;
                let receipt = DistributedRunReceiptV1 {
                    schema_version: DISTRIBUTED_RUN_RECEIPT_VERSION.into(),
                    campaign_id: manifest.campaign_id.clone(),
                    backend: "container".into(),
                    command_receipts: receipts,
                    process_report: None,
                    cleanup_failures,
                    completed: false,
                };
                write_receipt(manifest, &receipt)?;
                return Err(failure.error);
            }
        }
    }

    let result = run_container_scenario(manifest, plan, scenario, &mut receipts).await;
    let run_token = match &result {
        Ok(result) => Some(result.run_token.as_str()),
        Err(failure) => failure.run_token.as_deref(),
    };
    if let Some(run_token) = run_token {
        cleanup_participants(manifest, run_token, &mut receipts, &mut cleanup_failures).await;
    }
    cleanup(plan, run_token, &mut receipts, &mut cleanup_failures).await;

    let process_report = if let Ok(result) = &result {
        let path = manifest.output_dir.join("process-report.json");
        match serde_json::to_vec_pretty(&result.report) {
            Ok(bytes) => match fs_private::write_private(&path, &bytes) {
                Ok(()) => Some(path),
                Err(_) => {
                    cleanup_failures.push("report_write".into());
                    None
                }
            },
            Err(_) => {
                cleanup_failures.push("report_serialize".into());
                None
            }
        }
    } else {
        None
    };
    let completed = result
        .as_ref()
        .map(|result| result.report.completed)
        .unwrap_or(false)
        && cleanup_failures.is_empty();
    let receipt = DistributedRunReceiptV1 {
        schema_version: DISTRIBUTED_RUN_RECEIPT_VERSION.into(),
        campaign_id: manifest.campaign_id.clone(),
        backend: "container".into(),
        command_receipts: receipts,
        process_report,
        cleanup_failures,
        completed,
    };
    write_receipt(manifest, &receipt)?;
    result.map_err(|error| error.error)?;
    Ok(receipt)
}

struct ContainerScenarioResult {
    report: ProcessScenarioReportV1,
    run_token: String,
}

struct ContainerScenarioFailure {
    error: RunnerError,
    run_token: Option<String>,
}

async fn run_container_scenario(
    manifest: &DistributedCampaignManifestV1,
    plan: &DistributedExecutionPlanV1,
    scenario: &ScenarioSpec,
    receipts: &mut Vec<CommandReceiptV1>,
) -> Result<ContainerScenarioResult, ContainerScenarioFailure> {
    let node_launch =
        container_node_launch(manifest).map_err(|error| ContainerScenarioFailure {
            error,
            run_token: None,
        })?;
    let scenario = lower_container_host_faults(manifest, scenario).map_err(|error| {
        ContainerScenarioFailure {
            error,
            run_token: None,
        }
    })?;
    let compiled = compile_scenario(&scenario).map_err(|error| ContainerScenarioFailure {
        error: RunnerError::environment("scenario_compile", error),
        run_token: None,
    })?;
    let relay_labels = if compiled.topology.relays.is_empty() {
        vec!["relay:shared".to_owned()]
    } else {
        compiled
            .topology
            .relays
            .iter()
            .map(|relay| relay.id.clone())
            .collect()
    };
    let relay_urls = relay_labels
        .into_iter()
        .map(|label| (label, "ws://127.0.0.1:18080".into()))
        .collect::<BTreeMap<_, _>>();
    let mut orchestrator = ProcessOrchestrator::launch_with(
        node_launch,
        Some(relay_urls),
        &scenario,
        &manifest.output_dir,
    )
    .await
    .map_err(|error| ContainerScenarioFailure {
        error: RunnerError::environment("container_node_launch", error),
        run_token: None,
    })?;
    let run_token = orchestrator.run_token().to_owned();
    let host_run_root = orchestrator.run_root().to_path_buf();
    let mut hook = ContainerFaultHook {
        commands: plan.fault_commands.clone(),
        run_token: run_token.clone(),
        host_run_root,
        receipts,
    };
    let report = orchestrator
        .run_with_barrier_hook(&mut hook)
        .await
        .map_err(|error| ContainerScenarioFailure {
            error: RunnerError::environment("container_scenario", error),
            run_token: Some(run_token.clone()),
        });
    orchestrator.shutdown().await;
    report.map(|report| ContainerScenarioResult { report, run_token })
}

fn lower_container_host_faults(
    manifest: &DistributedCampaignManifestV1,
    scenario: &ScenarioSpec,
) -> Result<ScenarioSpec, RunnerError> {
    let process_by_participant = scenario
        .topology
        .devices
        .iter()
        .map(|device| (device.client.as_str(), device.process.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut crashes = BTreeMap::<&str, Vec<&str>>::new();
    for fault in &manifest.faults {
        if let crate::DistributedFaultV1::CrashParticipantHost { participant } = &fault.action {
            let process = process_by_participant
                .get(participant.as_str())
                .copied()
                .ok_or_else(|| {
                    RunnerError::validation(
                        "crash_process_mapping",
                        "crashed participant has no topology process",
                    )
                })?;
            crashes
                .entry(fault.at_barrier.as_str())
                .or_default()
                .push(process);
        }
    }
    let mut lowered = scenario.clone();
    lowered.steps = Vec::with_capacity(scenario.steps.len() + crashes.len() * 2);
    for step in &scenario.steps {
        lowered.steps.push(step.clone());
        if let cgka_conformance_simulator::ScenarioStep::Barrier { name } = step
            && let Some(processes) = crashes.get(name.as_str())
        {
            for process in processes {
                lowered
                    .steps
                    .push(cgka_conformance_simulator::ScenarioStep::CrashProcess {
                        process: (*process).into(),
                    });
                lowered
                    .steps
                    .push(cgka_conformance_simulator::ScenarioStep::RestartProcess {
                        process: (*process).into(),
                    });
            }
        }
    }
    Ok(lowered)
}

struct ContainerFaultHook<'a> {
    commands: BTreeMap<String, Vec<PlannedCommandV1>>,
    run_token: String,
    host_run_root: PathBuf,
    receipts: &'a mut Vec<CommandReceiptV1>,
}

#[async_trait::async_trait]
impl ProcessBarrierHook for ContainerFaultHook<'_> {
    async fn before_barrier(&mut self, name: &str) -> Result<(), ProcessOrchestratorError> {
        let commands = self.commands.remove(name).unwrap_or_default();
        for command in commands {
            match execute(
                &command,
                CommandContext {
                    run_token: Some(&self.run_token),
                    host_run_root: Some(&self.host_run_root),
                },
            )
            .await
            {
                Ok(receipt) => self.receipts.push(receipt),
                Err(failure) => {
                    if let Some(receipt) = failure.receipt {
                        self.receipts.push(receipt);
                    }
                    return Err(ProcessOrchestratorError::new(
                        "distributed_fault",
                        failure.error.to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

async fn run_vm(
    manifest: &DistributedCampaignManifestV1,
    plan: &DistributedExecutionPlanV1,
) -> Result<DistributedRunReceiptV1, RunnerError> {
    let command = plan.vm_driver.as_ref().ok_or_else(|| {
        RunnerError::validation("vm_plan", "VM plan is missing its external driver")
    })?;
    let executed = execute(command, CommandContext::default()).await;
    let (command_receipts, error) = match executed {
        Ok(receipt) => (vec![receipt], None),
        Err(failure) => (failure.receipt.into_iter().collect(), Some(failure.error)),
    };
    let receipt = DistributedRunReceiptV1 {
        schema_version: DISTRIBUTED_RUN_RECEIPT_VERSION.into(),
        campaign_id: manifest.campaign_id.clone(),
        backend: "virtual_machine".into(),
        command_receipts,
        process_report: None,
        cleanup_failures: Vec::new(),
        completed: error.is_none(),
    };
    write_receipt(manifest, &receipt)?;
    if let Some(error) = error {
        return Err(error);
    }
    Ok(receipt)
}

async fn cleanup_participants(
    manifest: &DistributedCampaignManifestV1,
    run_token: &str,
    receipts: &mut Vec<CommandReceiptV1>,
    failures: &mut Vec<String>,
) {
    let DistributedBackendV1::Container(container) = &manifest.backend else {
        return;
    };
    for participant in &manifest.participants {
        let command = PlannedCommandV1 {
            purpose: "remove_participant_container".into(),
            program: container.runtime.executable().into(),
            args: vec![
                "rm".into(),
                "--force".into(),
                format!("{run_token}-{}", process_participant_token(&participant.id)),
            ],
            success_exit_codes: vec![0, 1],
        };
        match execute(&command, CommandContext::default()).await {
            Ok(receipt) => receipts.push(receipt),
            Err(failure) => {
                if let Some(receipt) = failure.receipt {
                    receipts.push(receipt);
                }
                failures.push(failure.error.code);
            }
        }
    }
}

async fn cleanup(
    plan: &DistributedExecutionPlanV1,
    run_token: Option<&str>,
    receipts: &mut Vec<CommandReceiptV1>,
    failures: &mut Vec<String>,
) {
    for command in &plan.cleanup {
        match execute(
            command,
            CommandContext {
                run_token,
                host_run_root: None,
            },
        )
        .await
        {
            Ok(receipt) => receipts.push(receipt),
            Err(failure) => {
                if let Some(receipt) = failure.receipt {
                    receipts.push(receipt);
                }
                failures.push(failure.error.code);
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
struct CommandContext<'a> {
    run_token: Option<&'a str>,
    host_run_root: Option<&'a Path>,
}

struct CommandFailure {
    error: RunnerError,
    receipt: Option<CommandReceiptV1>,
}

async fn execute(
    command: &PlannedCommandV1,
    context: CommandContext<'_>,
) -> Result<CommandReceiptV1, CommandFailure> {
    let mut args = Vec::with_capacity(command.args.len());
    for argument in &command.args {
        let mut rendered = argument.clone();
        if rendered.contains("{run_token}") {
            let token = context.run_token.ok_or_else(|| CommandFailure {
                error: RunnerError::validation(
                    "missing_run_token",
                    format!("{} requires an unavailable run token", command.purpose),
                ),
                receipt: None,
            })?;
            rendered = rendered.replace("{run_token}", token);
        }
        if rendered.contains("{host_run_root}") {
            let root = context.host_run_root.ok_or_else(|| CommandFailure {
                error: RunnerError::validation(
                    "missing_host_run_root",
                    format!("{} requires an unavailable host run root", command.purpose),
                ),
                receipt: None,
            })?;
            let root = root.to_str().ok_or_else(|| CommandFailure {
                error: RunnerError::validation(
                    "non_utf8_host_run_root",
                    "host run root must be valid UTF-8",
                ),
                receipt: None,
            })?;
            rendered = rendered.replace("{host_run_root}", root);
        }
        args.push(rendered);
    }
    let mut child = Command::new(&command.program);
    child
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = timeout(INFRASTRUCTURE_COMMAND_TIMEOUT, child.status())
        .await
        .map_err(|_| CommandFailure {
            error: RunnerError::validation("command_timeout", &command.purpose),
            receipt: None,
        })?
        .map_err(|error| CommandFailure {
            error: RunnerError::environment("command_spawn", error),
            receipt: None,
        })?;
    let exit_code = status.code();
    let accepted = exit_code.is_some_and(|code| command.success_exit_codes.contains(&code));
    let receipt = CommandReceiptV1 {
        purpose: command.purpose.clone(),
        exit_code,
        accepted,
    };
    if !accepted {
        return Err(CommandFailure {
            error: RunnerError::validation(
                "command_failed",
                format!("{} exited outside its accepted status set", command.purpose),
            ),
            receipt: Some(receipt),
        });
    }
    Ok(receipt)
}

fn write_receipt(
    manifest: &DistributedCampaignManifestV1,
    receipt: &DistributedRunReceiptV1,
) -> Result<(), RunnerError> {
    let path = manifest.output_dir.join("distributed-run.json");
    fs_private::write_private(
        &path,
        &serde_json::to_vec_pretty(receipt)
            .map_err(|error| RunnerError::environment("receipt_serialize", error))?,
    )
    .map_err(|error| RunnerError::environment("receipt_write", error))
}

pub fn receipt_path(output_dir: &Path) -> PathBuf {
    output_dir.join("distributed-run.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ContainerBackendV1, DistributedFaultV1, DistributedParticipantV1, OciRuntimeV1,
        ScenarioArtifactV1, ScheduledFaultV1, VirtualMachineBackendV1,
    };
    use std::collections::BTreeSet;

    fn manifest(root: &Path, backend: DistributedBackendV1) -> DistributedCampaignManifestV1 {
        DistributedCampaignManifestV1 {
            schema_version: "1".into(),
            campaign_id: "receipt-test".into(),
            scenario: ScenarioArtifactV1 {
                path: root.join("scenario.json"),
                sha256: "00".repeat(32),
            },
            participants: ["alice", "bob"]
                .into_iter()
                .map(|id| DistributedParticipantV1 {
                    id: id.into(),
                    build_id: "test".into(),
                    container_image: None,
                })
                .collect(),
            backend,
            faults: Vec::new(),
            output_dir: root.join("output"),
        }
    }

    fn planned(purpose: &str, program: &str, args: Vec<String>) -> PlannedCommandV1 {
        PlannedCommandV1 {
            purpose: purpose.into(),
            program: program.into(),
            args,
            success_exit_codes: vec![0],
        }
    }

    #[tokio::test]
    async fn missing_run_token_fails_before_spawning_a_command() {
        let command = planned(
            "requires_token",
            "definitely-not-a-real-program",
            vec!["{run_token}".into()],
        );
        let failure = execute(&command, CommandContext::default())
            .await
            .unwrap_err();
        assert_eq!(failure.error.code, "missing_run_token");
        assert!(failure.receipt.is_none());
    }

    #[tokio::test]
    async fn failed_vm_command_writes_an_incomplete_receipt() {
        let root = tempfile::tempdir().unwrap();
        let manifest = manifest(
            root.path(),
            DistributedBackendV1::VirtualMachine(VirtualMachineBackendV1 {
                driver: "false".into(),
                driver_args: Vec::new(),
                capabilities: BTreeSet::new(),
            }),
        );
        fs_private::create_dir_all_private(&manifest.output_dir).unwrap();
        let plan = DistributedExecutionPlanV1 {
            schema_version: "1".into(),
            campaign_id: manifest.campaign_id.clone(),
            backend: "virtual_machine".into(),
            setup: Vec::new(),
            fault_commands: BTreeMap::new(),
            cleanup: Vec::new(),
            vm_driver: Some(planned("failing_vm_driver", "false", Vec::new())),
        };
        let error = run_vm(&manifest, &plan).await.unwrap_err();
        assert_eq!(error.code, "command_failed");
        let receipt: DistributedRunReceiptV1 =
            serde_json::from_slice(&std::fs::read(receipt_path(&manifest.output_dir)).unwrap())
                .unwrap();
        assert!(!receipt.completed);
        assert_eq!(receipt.command_receipts.len(), 1);
        assert!(!receipt.command_receipts[0].accepted);
    }

    #[tokio::test]
    async fn failed_container_setup_writes_an_incomplete_receipt() {
        let root = tempfile::tempdir().unwrap();
        let manifest = manifest(
            root.path(),
            DistributedBackendV1::Container(ContainerBackendV1 {
                runtime: OciRuntimeV1::Docker,
                namespace: "receipt-test".into(),
                default_participant_image: "unused".into(),
                relay_image: "unused".into(),
                relay_command: vec!["unused".into()],
                node_command: vec!["unused".into()],
            }),
        );
        fs_private::create_dir_all_private(&manifest.output_dir).unwrap();
        let plan = DistributedExecutionPlanV1 {
            schema_version: "1".into(),
            campaign_id: manifest.campaign_id.clone(),
            backend: "container".into(),
            setup: vec![planned("failing_setup", "false", Vec::new())],
            fault_commands: BTreeMap::new(),
            cleanup: Vec::new(),
            vm_driver: None,
        };
        let scenario = ScenarioSpec {
            name: "unused".into(),
            spec_version: "2".into(),
            clients: Vec::new(),
            topology: cgka_conformance_simulator::ScenarioTopologyV2::default(),
            steps: Vec::new(),
        };
        let error = run_container(&manifest, &plan, &scenario)
            .await
            .unwrap_err();
        assert_eq!(error.code, "command_failed");
        let receipt: DistributedRunReceiptV1 =
            serde_json::from_slice(&std::fs::read(receipt_path(&manifest.output_dir)).unwrap())
                .unwrap();
        assert!(!receipt.completed);
        assert_eq!(receipt.command_receipts.len(), 1);
        assert!(!receipt.command_receipts[0].accepted);
    }

    #[test]
    fn host_crash_fault_lowers_to_owned_process_crash_and_restart() {
        let root = tempfile::tempdir().unwrap();
        let mut manifest = manifest(
            root.path(),
            DistributedBackendV1::Container(ContainerBackendV1 {
                runtime: OciRuntimeV1::Docker,
                namespace: "crash-lowering".into(),
                default_participant_image: "unused".into(),
                relay_image: "unused".into(),
                relay_command: vec!["unused".into()],
                node_command: vec!["unused".into()],
            }),
        );
        manifest.faults = vec![ScheduledFaultV1 {
            at_barrier: "crash".into(),
            action: DistributedFaultV1::CrashParticipantHost {
                participant: "alice".into(),
            },
        }];
        let scenario = ScenarioSpec {
            name: "crash".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: cgka_conformance_simulator::ScenarioTopologyV2 {
                devices: vec![
                    cgka_conformance_simulator::ScenarioDeviceV2 {
                        id: "device:alice".into(),
                        account: "alice".into(),
                        process: "process:alice".into(),
                        client: "alice".into(),
                    },
                    cgka_conformance_simulator::ScenarioDeviceV2 {
                        id: "device:bob".into(),
                        account: "bob".into(),
                        process: "process:bob".into(),
                        client: "bob".into(),
                    },
                ],
                ..Default::default()
            },
            steps: vec![cgka_conformance_simulator::ScenarioStep::Barrier {
                name: "crash".into(),
            }],
        };
        let lowered = lower_container_host_faults(&manifest, &scenario).unwrap();
        assert!(matches!(
            &lowered.steps[1],
            cgka_conformance_simulator::ScenarioStep::CrashProcess { process }
                if process == "process:alice"
        ));
        assert!(matches!(
            &lowered.steps[2],
            cgka_conformance_simulator::ScenarioStep::RestartProcess { process }
                if process == "process:alice"
        ));
    }

    #[test]
    fn container_binding_rejects_multi_relay_topologies() {
        let root = tempfile::tempdir().unwrap();
        let mut scenario = cgka_conformance_simulator::generate_cross_route_regression_family()
            .into_iter()
            .next()
            .unwrap()
            .scenario;
        scenario
            .topology
            .relays
            .push(cgka_conformance_simulator::ScenarioRelayV2 {
                id: "relay:secondary".into(),
                implementation_version: "test".into(),
                policy_version: "test".into(),
            });
        let mut manifest = manifest(
            root.path(),
            DistributedBackendV1::Container(ContainerBackendV1 {
                runtime: OciRuntimeV1::Docker,
                namespace: "relay-validation".into(),
                default_participant_image: "unused".into(),
                relay_image: "unused".into(),
                relay_command: vec!["unused".into()],
                node_command: vec!["unused".into()],
            }),
        );
        manifest.participants = scenario
            .clients
            .iter()
            .map(|id| DistributedParticipantV1 {
                id: id.clone(),
                build_id: "test".into(),
                container_image: None,
            })
            .collect();
        let error = validate_scenario_binding(&manifest, &scenario).unwrap_err();
        assert_eq!(error.code, "multiple_container_relays_unsupported");
    }
}
