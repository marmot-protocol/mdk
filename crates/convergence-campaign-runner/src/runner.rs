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
use crate::{
    RunnerError, container_node_launch, record_distributed_failure, verify_manifest_inputs,
};

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
    let result = match &manifest.backend {
        DistributedBackendV1::Container(_) => run_container(manifest, &plan, &scenario).await,
        DistributedBackendV1::VirtualMachine(_) => run_vm(manifest, &plan).await,
    };
    if let Err(error) = &result
        && let Err(corpus_error) = record_distributed_failure(manifest, error)
    {
        return Err(RunnerError::validation(
            "failure_corpus_record",
            format!(
                "run failed with {}; failure evidence could not be recorded ({})",
                error.code, corpus_error.code
            ),
        ));
    }
    result
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
    Ok(())
}

async fn run_container(
    manifest: &DistributedCampaignManifestV1,
    plan: &DistributedExecutionPlanV1,
    scenario: &ScenarioSpec,
) -> Result<DistributedRunReceiptV1, RunnerError> {
    let mut receipts = Vec::new();
    let mut cleanup_failures = Vec::new();
    for command in &plan.setup {
        match execute(command, None).await {
            Ok(receipt) => receipts.push(receipt),
            Err(error) => {
                cleanup(plan, None, &mut receipts, &mut cleanup_failures).await;
                return Err(error);
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

    let completed = result
        .as_ref()
        .map(|result| result.report.completed)
        .unwrap_or(false)
        && cleanup_failures.is_empty();
    let process_report = if let Ok(result) = &result {
        let path = manifest.output_dir.join("process-report.json");
        fs_private::write_private(
            &path,
            &serde_json::to_vec_pretty(&result.report)
                .map_err(|error| RunnerError::environment("report_serialize", error))?,
        )
        .map_err(|error| RunnerError::environment("report_write", error))?;
        Some(path)
    } else {
        None
    };
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
    let compiled = compile_scenario(scenario).map_err(|error| ContainerScenarioFailure {
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
        scenario,
        &manifest.output_dir,
    )
    .await
    .map_err(|error| ContainerScenarioFailure {
        error: RunnerError::environment("container_node_launch", error),
        run_token: None,
    })?;
    let run_token = orchestrator.run_token().to_owned();
    let mut hook = ContainerFaultHook {
        commands: plan.fault_commands.clone(),
        run_token: run_token.clone(),
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

struct ContainerFaultHook<'a> {
    commands: BTreeMap<String, Vec<PlannedCommandV1>>,
    run_token: String,
    receipts: &'a mut Vec<CommandReceiptV1>,
}

#[async_trait::async_trait]
impl ProcessBarrierHook for ContainerFaultHook<'_> {
    async fn before_barrier(&mut self, name: &str) -> Result<(), ProcessOrchestratorError> {
        let commands = self.commands.remove(name).unwrap_or_default();
        for command in commands {
            let receipt = execute(&command, Some(&self.run_token))
                .await
                .map_err(|error| {
                    ProcessOrchestratorError::new("distributed_fault", error.to_string())
                })?;
            self.receipts.push(receipt);
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
    let command_receipts = vec![execute(command, None).await?];
    let receipt = DistributedRunReceiptV1 {
        schema_version: DISTRIBUTED_RUN_RECEIPT_VERSION.into(),
        campaign_id: manifest.campaign_id.clone(),
        backend: "virtual_machine".into(),
        command_receipts,
        process_report: None,
        cleanup_failures: Vec::new(),
        completed: true,
    };
    write_receipt(manifest, &receipt)?;
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
        match execute(&command, None).await {
            Ok(receipt) => receipts.push(receipt),
            Err(error) => failures.push(error.code),
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
        match execute(command, run_token).await {
            Ok(receipt) => receipts.push(receipt),
            Err(error) => failures.push(error.code),
        }
    }
}

async fn execute(
    command: &PlannedCommandV1,
    run_token: Option<&str>,
) -> Result<CommandReceiptV1, RunnerError> {
    let args = command
        .args
        .iter()
        .map(|argument| {
            argument.replace("{run_token}", run_token.unwrap_or("unavailable-run-token"))
        })
        .collect::<Vec<_>>();
    let mut child = Command::new(&command.program);
    child
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = timeout(INFRASTRUCTURE_COMMAND_TIMEOUT, child.status())
        .await
        .map_err(|_| RunnerError::validation("command_timeout", &command.purpose))?
        .map_err(|error| RunnerError::environment("command_spawn", error))?;
    let exit_code = status.code();
    let accepted = exit_code.is_some_and(|code| command.success_exit_codes.contains(&code));
    let receipt = CommandReceiptV1 {
        purpose: command.purpose.clone(),
        exit_code,
        accepted,
    };
    if !accepted {
        return Err(RunnerError::validation(
            "command_failed",
            format!("{} exited outside its accepted status set", command.purpose),
        ));
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
