//! Multi-process executor for canonical convergence Scenario IR.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use nostr_relay_builder::MockRelay;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

use crate::node_protocol::{
    NODE_OBSERVATION_SCHEMA_VERSION, NODE_PROTOCOL_VERSION, NodeCommandV1, NodeErrorV1,
    NodeFailureCapsuleV1, NodeObservationV1, NodeRequestV1, NodeResponseBodyV1, NodeResponseV1,
};
use crate::{
    CompiledScenarioV2, ScenarioActionScheduleV2, ScenarioRelaySyncModeV2, ScenarioSpec,
    ScenarioStep, SubjectCapability, SubjectDescriptor, SubjectFailureCategory, compile_scenario,
    preflight_compiled_scenario,
};

pub const PROCESS_SCENARIO_REPORT_SCHEMA_VERSION: &str = "1";
const NODE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(45);
const PROCESS_QUIESCENCE_POLL: Duration = Duration::from_millis(100);

/// Adapter-neutral command template for a participant node process. The
/// distributed runner uses this seam to launch the exact same JSONL node in a
/// container without teaching the simulator about Docker, Podman, or VMs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessNodeLaunchV1 {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Optional exact argv overrides keyed by canonical participant label.
    /// This permits mixed-build container campaigns without changing the node
    /// protocol or canonical Scenario IR.
    pub args_by_participant: BTreeMap<String, Vec<String>>,
    /// Root visible to the child. `None` means the host run root is visible at
    /// the same path, as it is for an ordinary local process.
    pub child_run_root: Option<PathBuf>,
}

impl ProcessNodeLaunchV1 {
    pub fn executable(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            args_by_participant: BTreeMap::new(),
            child_run_root: None,
        }
    }
}

#[async_trait::async_trait]
pub trait ProcessBarrierHook: Send {
    async fn before_barrier(&mut self, name: &str) -> Result<(), ProcessOrchestratorError>;
}

struct NoopProcessBarrierHook;

#[async_trait::async_trait]
impl ProcessBarrierHook for NoopProcessBarrierHook {
    async fn before_barrier(&mut self, _name: &str) -> Result<(), ProcessOrchestratorError> {
        Ok(())
    }
}

/// Values substituted in [`ProcessNodeLaunchV1::args`]:
/// `{participant}`, `{run_token}`, `{host_run_root}`, and `{child_run_root}`.
/// Substitution is argv-local; no shell is involved.
fn render_node_arg(
    template: &str,
    participant: &str,
    run_token: &str,
    host_run_root: &Path,
    child_run_root: &Path,
) -> Result<String, ProcessOrchestratorError> {
    let host_run_root = host_run_root.to_str().ok_or_else(|| {
        ProcessOrchestratorError::new(
            "non_utf8_run_root",
            "node command templates require UTF-8 run-root paths",
        )
    })?;
    let child_run_root = child_run_root.to_str().ok_or_else(|| {
        ProcessOrchestratorError::new(
            "non_utf8_child_root",
            "node command templates require UTF-8 child-root paths",
        )
    })?;
    let rendered = template
        .replace("{participant}", participant)
        .replace("{run_token}", run_token)
        .replace("{host_run_root}", host_run_root)
        .replace("{child_run_root}", child_run_root);
    if rendered.contains('{') || rendered.contains('}') {
        return Err(ProcessOrchestratorError::new(
            "unknown_node_command_placeholder",
            "node command contains an unknown template placeholder",
        ));
    }
    Ok(rendered)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessScenarioReportV1 {
    pub schema_version: String,
    pub scenario_name: String,
    pub canonical_schedule: Vec<ScenarioActionScheduleV2>,
    pub actions: Vec<ProcessActionResultV1>,
    pub observations: Vec<NodeObservationV1>,
    pub lifecycle: Vec<ProcessLifecycleEventV1>,
    pub failure_capsules: Vec<PathBuf>,
    pub completed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessActionResultV1 {
    pub action_id: String,
    pub action_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub participants: Vec<String>,
    pub status: ProcessActionStatusV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessActionStatusV1 {
    Completed,
    AlreadyPublished,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessLifecycleEventV1 {
    pub action_id: String,
    pub participant: String,
    pub event: String,
}

#[derive(Debug)]
pub struct ProcessOrchestratorError {
    pub code: String,
    pub message: String,
}

impl ProcessOrchestratorError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ProcessOrchestratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProcessOrchestratorError {}

pub struct ProcessOrchestrator {
    node_launch: ProcessNodeLaunchV1,
    run_root: tempfile::TempDir,
    artifact_directory: PathBuf,
    compiled: CompiledScenarioV2,
    _relays: BTreeMap<String, MockRelay>,
    relay_urls: BTreeMap<String, String>,
    nodes: BTreeMap<String, NodeProcess>,
    account_ids: BTreeMap<String, String>,
    processes: BTreeMap<String, String>,
    process_relays: BTreeMap<String, Vec<String>>,
    groups: BTreeMap<String, String>,
    lifecycle: Vec<ProcessLifecycleEventV1>,
}

struct NodeProcess {
    participant: String,
    root: PathBuf,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_request: u64,
    paused: bool,
}

impl ProcessOrchestrator {
    pub async fn launch(
        node_executable: impl AsRef<Path>,
        scenario: &ScenarioSpec,
        artifact_directory: impl AsRef<Path>,
    ) -> Result<Self, ProcessOrchestratorError> {
        Self::launch_with(
            ProcessNodeLaunchV1::executable(node_executable.as_ref()),
            None,
            scenario,
            artifact_directory,
        )
        .await
    }

    /// Launch participant nodes through a caller-supplied argv template and,
    /// optionally, use already-running retained relays. This is the boundary
    /// used by distributed container/VM orchestration; the canonical scenario
    /// executor and node protocol stay unchanged.
    pub async fn launch_with(
        node_launch: ProcessNodeLaunchV1,
        external_relay_urls: Option<BTreeMap<String, String>>,
        scenario: &ScenarioSpec,
        artifact_directory: impl AsRef<Path>,
    ) -> Result<Self, ProcessOrchestratorError> {
        let compiled = compile_scenario(scenario).map_err(|error| {
            ProcessOrchestratorError::new("scenario_compile", error.to_string())
        })?;
        preflight_process_compiled_scenario(&compiled, &process_subject_descriptor()).map_err(
            |error| {
                ProcessOrchestratorError::new("process_capability_preflight", error.to_string())
            },
        )?;
        let artifact_directory = artifact_directory.as_ref().to_path_buf();
        fs_private::create_dir_all_private(&artifact_directory).map_err(environment_error)?;
        let run_root = tempfile::Builder::new()
            .prefix("marmot-process-conformance-")
            .tempdir()
            .map_err(environment_error)?;
        fs_private::create_dir_all_private(run_root.path()).map_err(environment_error)?;

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
        let mut relays = BTreeMap::new();
        let relay_urls = if let Some(relay_urls) = external_relay_urls {
            let expected = relay_labels
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let actual = relay_urls
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if actual != expected {
                return Err(ProcessOrchestratorError::new(
                    "missing_external_relay",
                    "external relay map must exactly match the scenario topology",
                ));
            }
            relay_urls
        } else {
            let mut relay_urls = BTreeMap::new();
            for label in relay_labels {
                let relay = MockRelay::run().await.map_err(environment_error)?;
                relay_urls.insert(label.clone(), relay.url().await.to_string());
                relays.insert(label, relay);
            }
            relay_urls
        };

        let processes = compiled
            .topology
            .devices
            .iter()
            .map(|device| (device.client.clone(), device.process.clone()))
            .collect::<BTreeMap<_, _>>();
        if processes.values().collect::<BTreeSet<_>>().len() != processes.len() {
            return Err(ProcessOrchestratorError::new(
                "shared_process_unsupported",
                "Milestone 5 nodes require one account-device participant per process",
            ));
        }
        let process_relays = compiled
            .topology
            .processes
            .iter()
            .map(|process| (process.id.clone(), process.relays.clone()))
            .collect::<BTreeMap<_, _>>();
        let clients = compiled.clients.clone();

        let mut orchestrator = Self {
            node_launch,
            run_root,
            artifact_directory,
            compiled,
            _relays: relays,
            relay_urls,
            nodes: BTreeMap::new(),
            account_ids: BTreeMap::new(),
            processes,
            process_relays,
            groups: BTreeMap::new(),
            lifecycle: Vec::new(),
        };
        for client in &clients {
            orchestrator.launch_participant(client, "launch").await?;
        }
        orchestrator.configure_peers().await?;
        orchestrator
            .barrier_all("launch", "all_nodes_initialized")
            .await
            .map_err(process_action_error)?;
        Ok(orchestrator)
    }

    pub fn run_root(&self) -> &Path {
        self.run_root.path()
    }

    pub fn run_token(&self) -> Result<&str, ProcessOrchestratorError> {
        self.run_root
            .path()
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                ProcessOrchestratorError::new(
                    "invalid_run_root",
                    "process run root has no UTF-8 final component",
                )
            })
    }

    pub fn participant_roots(&self) -> BTreeMap<String, PathBuf> {
        self.nodes
            .iter()
            .map(|(label, node)| (label.clone(), node.root.clone()))
            .collect()
    }

    pub async fn run(&mut self) -> Result<ProcessScenarioReportV1, ProcessOrchestratorError> {
        let mut hook = NoopProcessBarrierHook;
        self.run_with_barrier_hook(&mut hook).await
    }

    pub async fn run_with_barrier_hook(
        &mut self,
        hook: &mut dyn ProcessBarrierHook,
    ) -> Result<ProcessScenarioReportV1, ProcessOrchestratorError> {
        let compiled = self.compiled.clone();
        let schedule = compiled.expanded_schedule();
        let mut report = ProcessScenarioReportV1 {
            schema_version: PROCESS_SCENARIO_REPORT_SCHEMA_VERSION.into(),
            scenario_name: compiled.name.clone(),
            canonical_schedule: schedule,
            actions: Vec::new(),
            observations: Vec::new(),
            lifecycle: Vec::new(),
            failure_capsules: Vec::new(),
            completed: false,
        };
        for action in &compiled.actions {
            let action_id = action.schedule.action_id.clone();
            match self.execute_action(action, &mut report, hook).await {
                Ok((participants, status)) => report.actions.push(ProcessActionResultV1 {
                    action_id,
                    action_type: action.schedule.action_type.clone(),
                    participants,
                    status,
                }),
                Err((participant, error)) => {
                    let capsule_path = self.write_failure_capsule(
                        participant.as_deref().unwrap_or("orchestrator"),
                        &action_id,
                        &error,
                    )?;
                    report.failure_capsules.push(capsule_path);
                    report.actions.push(ProcessActionResultV1 {
                        action_id,
                        action_type: action.schedule.action_type.clone(),
                        participants: participant.into_iter().collect(),
                        status: ProcessActionStatusV1::Failed,
                    });
                    report.lifecycle = self.lifecycle.clone();
                    return Ok(report);
                }
            }
        }
        report.lifecycle = self.lifecycle.clone();
        report.completed = true;
        Ok(report)
    }

    pub async fn shutdown(&mut self) {
        let labels = self.nodes.keys().cloned().collect::<Vec<_>>();
        for label in labels {
            if let Some(mut node) = self.nodes.remove(&label) {
                if node.paused {
                    let _ = resume_pid(node.child.id());
                }
                let _ = node.send(NodeCommandV1::Shutdown).await;
                let _ = timeout(Duration::from_secs(5), node.child.wait()).await;
                let _ = kill_process_group(&mut node.child).await;
            }
        }
    }

    async fn execute_action(
        &mut self,
        action: &crate::CompiledScenarioActionV2,
        report: &mut ProcessScenarioReportV1,
        hook: &mut dyn ProcessBarrierHook,
    ) -> Result<(Vec<String>, ProcessActionStatusV1), (Option<String>, NodeErrorV1)> {
        let action_id = action.schedule.action_id.as_str();
        let group = action
            .scenario_group
            .clone()
            .unwrap_or_else(|| "default".into());
        match &action.step {
            ScenarioStep::CreateGroup {
                creator,
                name,
                invitees,
                initial_admins,
                ..
            } => {
                let members = self.account_ids(invitees).map_err(orchestrator_failure)?;
                let default_admins;
                let admin_labels = match initial_admins {
                    Some(admins) => admins,
                    None => {
                        default_admins = vec![creator.clone()];
                        &default_admins
                    }
                };
                let admins = self
                    .account_ids(admin_labels)
                    .map_err(orchestrator_failure)?;
                let response = self
                    .send(
                        creator,
                        NodeCommandV1::CreateGroup {
                            action_id: action_id.into(),
                            group: group.clone(),
                            name: name.clone(),
                            member_accounts: members,
                            initial_admin_accounts: admins,
                        },
                    )
                    .await?;
                let group_id = match response {
                    NodeResponseBodyV1::Ack {
                        group_id_hex: Some(group_id),
                        ..
                    } => group_id,
                    body => return Err((Some(creator.clone()), unexpected_response(body))),
                };
                self.groups.insert(group.clone(), group_id.clone());
                let labels = self.running_labels();
                for client in &labels {
                    self.expect_ack(
                        client,
                        NodeCommandV1::SelectGroup {
                            group: group.clone(),
                            group_id_hex: group_id.clone(),
                        },
                    )
                    .await?;
                }
                Ok((vec![creator.clone()], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::InviteMembers {
                inviter, invitees, ..
            } => {
                self.select_group(inviter, &group).await?;
                let member_accounts = self.account_ids(invitees).map_err(orchestrator_failure)?;
                self.expect_ack(
                    inviter,
                    NodeCommandV1::InviteMembers {
                        action_id: action_id.into(),
                        member_accounts,
                    },
                )
                .await?;
                Ok((vec![inviter.clone()], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::RemoveMembers {
                remover, members, ..
            } => {
                self.select_group(remover, &group).await?;
                let member_accounts = self.account_ids(members).map_err(orchestrator_failure)?;
                self.expect_ack(
                    remover,
                    NodeCommandV1::RemoveMembers {
                        action_id: action_id.into(),
                        member_accounts,
                    },
                )
                .await?;
                Ok((vec![remover.clone()], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::SelfUpdate { client, .. } => {
                self.select_group(client, &group).await?;
                self.expect_ack(
                    client,
                    NodeCommandV1::SelfUpdate {
                        action_id: action_id.into(),
                    },
                )
                .await?;
                Ok((vec![client.clone()], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::UpdateGroupData { client, name, .. } => {
                self.select_group(client, &group).await?;
                self.expect_ack(
                    client,
                    NodeCommandV1::UpdateGroupData {
                        action_id: action_id.into(),
                        name: name.clone(),
                    },
                )
                .await?;
                Ok((vec![client.clone()], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::UpdateAdminPolicy { client, admins, .. } => {
                self.select_group(client, &group).await?;
                let admin_accounts = self.account_ids(admins).map_err(orchestrator_failure)?;
                self.expect_ack(
                    client,
                    NodeCommandV1::UpdateAdminPolicy {
                        action_id: action_id.into(),
                        admin_accounts,
                    },
                )
                .await?;
                Ok((vec![client.clone()], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::SendAppMessage { sender, payload } => {
                self.select_group(sender, &group).await?;
                self.expect_ack(
                    sender,
                    NodeCommandV1::SendApplication {
                        action_id: action_id.into(),
                        payload: payload.clone(),
                    },
                )
                .await?;
                Ok((vec![sender.clone()], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::Leave { client } => {
                self.select_group(client, &group).await?;
                self.expect_ack(
                    client,
                    NodeCommandV1::Leave {
                        action_id: action_id.into(),
                    },
                )
                .await?;
                Ok((vec![client.clone()], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::DeliverAll => {
                let labels = self.running_labels();
                self.catch_up(&labels, action_id, false).await?;
                Ok((labels, ProcessActionStatusV1::Completed))
            }
            ScenarioStep::Tick { clients } => {
                let labels = clients
                    .iter()
                    .filter(|client| self.nodes.get(*client).is_some_and(|node| !node.paused))
                    .cloned()
                    .collect::<Vec<_>>();
                self.catch_up(&labels, action_id, false).await?;
                Ok((labels, ProcessActionStatusV1::Completed))
            }
            ScenarioStep::SyncRelayHistory { clients, sync } => {
                let clients = clients
                    .iter()
                    .filter(|client| self.nodes.get(*client).is_some_and(|node| !node.paused))
                    .cloned()
                    .collect::<Vec<_>>();
                let full_history = matches!(
                    sync,
                    ScenarioRelaySyncModeV2::FullHistory
                        | ScenarioRelaySyncModeV2::SetReconciliation
                );
                self.catch_up(&clients, action_id, full_history).await?;
                Ok((clients, ProcessActionStatusV1::Completed))
            }
            ScenarioStep::Observe { clients } | ScenarioStep::ObserveExact { clients } => {
                let observations = self.observe(clients, action_id).await?;
                report.observations.extend(observations);
                Ok((clients.clone(), ProcessActionStatusV1::Completed))
            }
            ScenarioStep::ObserveAdminPolicy { clients } => {
                let observations = self.observe(clients, action_id).await?;
                report.observations.extend(observations);
                Ok((clients.clone(), ProcessActionStatusV1::Completed))
            }
            ScenarioStep::AwaitQuiescence { policy } => {
                let labels = self.running_labels();
                let observations = self
                    .await_quiescence(&labels, action_id, policy.max_iterations)
                    .await?;
                report.observations.extend(observations);
                Ok((labels, ProcessActionStatusV1::Completed))
            }
            ScenarioStep::AcknowledgeOutbound { client, .. } => Ok((
                vec![client.clone()],
                ProcessActionStatusV1::AlreadyPublished,
            )),
            ScenarioStep::Barrier { name } => {
                hook.before_barrier(name)
                    .await
                    .map_err(orchestrator_failure)?;
                let labels = self.running_labels();
                self.barrier_all(action_id, name).await?;
                Ok((labels, ProcessActionStatusV1::Completed))
            }
            ScenarioStep::RestartClient { client } => {
                self.restart_participant(client, action_id).await?;
                Ok((vec![client.clone()], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::SetClientOffline { client } => {
                self.pause_participant(client, action_id)?;
                Ok((vec![client.clone()], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::ReconnectClient { client } => {
                self.resume_participant(client, action_id)?;
                self.catch_up(std::slice::from_ref(client), action_id, false)
                    .await?;
                Ok((vec![client.clone()], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::CrashProcess { process } => {
                let client = self
                    .client_for_process(process)
                    .map_err(orchestrator_failure)?;
                self.crash_participant(&client, action_id).await?;
                Ok((vec![client], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::RestartProcess { process } => {
                let client = self
                    .client_for_process(process)
                    .map_err(orchestrator_failure)?;
                self.restart_participant(&client, action_id).await?;
                Ok((vec![client], ProcessActionStatusV1::Completed))
            }
            ScenarioStep::AdvanceTime { delta_ms } => {
                tokio::time::sleep(Duration::from_millis(*delta_ms)).await;
                Ok((Vec::new(), ProcessActionStatusV1::Completed))
            }
            ScenarioStep::ClearEvents { clients } => {
                for client in clients {
                    self.expect_ack(
                        client,
                        NodeCommandV1::ClearEvents {
                            action_id: action_id.into(),
                        },
                    )
                    .await?;
                }
                Ok((clients.clone(), ProcessActionStatusV1::Completed))
            }
            unsupported => Err((
                action_participant(unsupported),
                NodeErrorV1 {
                    code: "unsupported_process_action".into(),
                    category: SubjectFailureCategory::ExpectedRefusal,
                    retryable: false,
                    message: format!(
                        "process adapter does not support scenario action {}",
                        unsupported.kind()
                    ),
                },
            )),
        }
    }

    async fn launch_participant(
        &mut self,
        client: &str,
        action_id: &str,
    ) -> Result<(), ProcessOrchestratorError> {
        let client_token = process_participant_token(client);
        let run_token = self.run_token()?;
        let root = self
            .run_root
            .path()
            .join("participants")
            .join(&client_token);
        let child_run_root = self
            .node_launch
            .child_run_root
            .as_deref()
            .unwrap_or_else(|| self.run_root.path());
        let child_root = child_run_root.join("participants").join(&client_token);
        fs_private::create_dir_all_private(&root).map_err(environment_error)?;
        let stderr_dir = self.run_root.path().join("node-stderr");
        fs_private::create_dir_all_private(&stderr_dir).map_err(environment_error)?;
        let stderr =
            fs_private::open_private_append(&stderr_dir.join(format!("{client_token}.log")))
                .map_err(environment_error)?;
        let mut command = Command::new(&self.node_launch.program);
        let arguments = self
            .node_launch
            .args_by_participant
            .get(client)
            .unwrap_or(&self.node_launch.args);
        for argument in arguments {
            command.arg(render_node_arg(
                argument,
                &client_token,
                run_token,
                self.run_root.path(),
                child_run_root,
            )?);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.as_std_mut().process_group(0);
        }
        let mut child = command.spawn().map_err(environment_error)?;
        let stdin = child.stdin.take().ok_or_else(|| {
            ProcessOrchestratorError::new("node_stdio", "node stdin was not piped")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ProcessOrchestratorError::new("node_stdio", "node stdout was not piped")
        })?;
        let mut node = NodeProcess {
            participant: client.into(),
            root: root.clone(),
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_request: 0,
            paused: false,
        };
        let relay_urls = self.relay_urls_for_client(client)?;
        let response = node
            .send(NodeCommandV1::Initialize {
                participant: client.into(),
                root: child_root,
                relay_urls,
            })
            .await?;
        let account_id = match response {
            NodeResponseBodyV1::Initialized { account_id } => account_id,
            NodeResponseBodyV1::Error(error) => {
                return Err(ProcessOrchestratorError::new(error.code, error.message));
            }
            _ => {
                return Err(ProcessOrchestratorError::new(
                    "unexpected_node_response",
                    "node did not return initialized",
                ));
            }
        };
        if let Some(previous) = self.account_ids.get(client)
            && previous != &account_id
        {
            return Err(ProcessOrchestratorError::new(
                "identity_changed_after_restart",
                "participant account identity changed after restart",
            ));
        }
        self.account_ids.insert(client.into(), account_id);
        self.nodes.insert(client.into(), node);
        self.lifecycle.push(ProcessLifecycleEventV1 {
            action_id: action_id.into(),
            participant: client.into(),
            event: "launched".into(),
        });
        Ok(())
    }

    async fn configure_peers(&mut self) -> Result<(), ProcessOrchestratorError> {
        let labels = self.running_labels();
        for label in labels {
            let response = self
                .nodes
                .get_mut(&label)
                .expect("node label remains present")
                .send(NodeCommandV1::ConfigurePeers {
                    accounts_by_participant: self.account_ids.clone(),
                })
                .await?;
            if !matches!(response, NodeResponseBodyV1::Ack { .. }) {
                return Err(ProcessOrchestratorError::new(
                    "peer_configuration_failed",
                    "node rejected peer aliases",
                ));
            }
        }
        Ok(())
    }

    fn relay_urls_for_client(&self, client: &str) -> Result<Vec<String>, ProcessOrchestratorError> {
        let process = self.processes.get(client).ok_or_else(|| {
            ProcessOrchestratorError::new("topology", "participant has no process mapping")
        })?;
        let labels = self
            .process_relays
            .get(process)
            .cloned()
            .unwrap_or_default();
        if labels.is_empty() {
            return Ok(self.relay_urls.values().cloned().collect());
        }
        labels
            .into_iter()
            .map(|label| {
                self.relay_urls.get(&label).cloned().ok_or_else(|| {
                    ProcessOrchestratorError::new("topology", "process references unknown relay")
                })
            })
            .collect()
    }

    fn account_ids(&self, labels: &[String]) -> Result<Vec<String>, ProcessOrchestratorError> {
        labels
            .iter()
            .map(|label| {
                self.account_ids.get(label).cloned().ok_or_else(|| {
                    ProcessOrchestratorError::new("unknown_participant", "account alias is missing")
                })
            })
            .collect()
    }

    async fn select_group(
        &mut self,
        client: &str,
        group: &str,
    ) -> Result<(), (Option<String>, NodeErrorV1)> {
        let group_id = self.groups.get(group).cloned().ok_or_else(|| {
            orchestrator_failure(ProcessOrchestratorError::new(
                "unknown_group",
                "scenario group has not been created",
            ))
        })?;
        self.expect_ack(
            client,
            NodeCommandV1::SelectGroup {
                group: group.into(),
                group_id_hex: group_id,
            },
        )
        .await
    }

    async fn send(
        &mut self,
        client: &str,
        command: NodeCommandV1,
    ) -> Result<NodeResponseBodyV1, (Option<String>, NodeErrorV1)> {
        let node = self.nodes.get_mut(client).ok_or_else(|| {
            (
                Some(client.into()),
                NodeErrorV1 {
                    code: "participant_not_running".into(),
                    category: SubjectFailureCategory::Environment,
                    retryable: true,
                    message: "participant process is not running".into(),
                },
            )
        })?;
        if node.paused {
            return Err((
                Some(client.into()),
                NodeErrorV1 {
                    code: "participant_paused".into(),
                    category: SubjectFailureCategory::ExpectedRefusal,
                    retryable: true,
                    message: "participant process is paused".into(),
                },
            ));
        }
        match node.send(command).await {
            Ok(NodeResponseBodyV1::Error(error)) => Err((Some(client.into()), error)),
            Ok(body) => Ok(body),
            Err(error) => Err((
                Some(client.into()),
                NodeErrorV1 {
                    code: error.code,
                    category: SubjectFailureCategory::Environment,
                    retryable: true,
                    message: error.message,
                },
            )),
        }
    }

    async fn expect_ack(
        &mut self,
        client: &str,
        command: NodeCommandV1,
    ) -> Result<(), (Option<String>, NodeErrorV1)> {
        match self.send(client, command).await? {
            NodeResponseBodyV1::Ack { .. } => Ok(()),
            body => Err((Some(client.into()), unexpected_response(body))),
        }
    }

    async fn catch_up(
        &mut self,
        clients: &[String],
        action_id: &str,
        full_history: bool,
    ) -> Result<(), (Option<String>, NodeErrorV1)> {
        for client in clients {
            self.expect_ack(
                client,
                NodeCommandV1::CatchUp {
                    action_id: action_id.into(),
                    full_history,
                },
            )
            .await?;
        }
        Ok(())
    }

    async fn observe(
        &mut self,
        clients: &[String],
        action_id: &str,
    ) -> Result<Vec<NodeObservationV1>, (Option<String>, NodeErrorV1)> {
        let mut observations = Vec::with_capacity(clients.len());
        for client in clients {
            match self
                .send(
                    client,
                    NodeCommandV1::Observe {
                        action_id: action_id.into(),
                    },
                )
                .await?
            {
                NodeResponseBodyV1::Observation { observation, .. } => {
                    observations.push(*observation)
                }
                body => return Err((Some(client.clone()), unexpected_response(body))),
            }
        }
        Ok(observations)
    }

    async fn await_quiescence(
        &mut self,
        clients: &[String],
        action_id: &str,
        max_iterations: u32,
    ) -> Result<Vec<NodeObservationV1>, (Option<String>, NodeErrorV1)> {
        for _ in 0..max_iterations.max(1) {
            self.catch_up(clients, action_id, false).await?;
            let observations = self.observe(clients, action_id).await?;
            let commitments = observations
                .iter()
                .map(|observation| observation.protocol.state_commitment_sha256.as_str())
                .collect::<BTreeSet<_>>();
            if commitments.len() == 1
                && observations
                    .iter()
                    .all(|observation| observation.progress.observably_quiescent())
            {
                return Ok(observations);
            }
            tokio::time::sleep(PROCESS_QUIESCENCE_POLL).await;
        }
        Err((
            None,
            NodeErrorV1 {
                code: "process_quiescence_timeout".into(),
                category: SubjectFailureCategory::Resource,
                retryable: true,
                message: "process observations did not reach a shared stable checkpoint".into(),
            },
        ))
    }

    async fn barrier_all(
        &mut self,
        action_id: &str,
        barrier: &str,
    ) -> Result<(), (Option<String>, NodeErrorV1)> {
        let labels = self.running_labels();
        for label in labels {
            match self
                .send(
                    &label,
                    NodeCommandV1::Barrier {
                        action_id: action_id.into(),
                        barrier: barrier.into(),
                    },
                )
                .await?
            {
                NodeResponseBodyV1::BarrierReady {
                    barrier: observed, ..
                } if observed == barrier => {}
                body => return Err((Some(label), unexpected_response(body))),
            }
        }
        Ok(())
    }

    fn running_labels(&self) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|(_, node)| !node.paused)
            .map(|(label, _)| label.clone())
            .collect()
    }

    fn pause_participant(
        &mut self,
        client: &str,
        action_id: &str,
    ) -> Result<(), (Option<String>, NodeErrorV1)> {
        let node = self.nodes.get_mut(client).ok_or_else(|| {
            orchestrator_failure(ProcessOrchestratorError::new(
                "participant_not_running",
                "cannot pause a stopped participant",
            ))
        })?;
        pause_pid(node.child.id()).map_err(|error| {
            orchestrator_failure(ProcessOrchestratorError::new(
                "pause_failed",
                error.to_string(),
            ))
        })?;
        node.paused = true;
        self.lifecycle.push(ProcessLifecycleEventV1 {
            action_id: action_id.into(),
            participant: client.into(),
            event: "paused".into(),
        });
        Ok(())
    }

    fn resume_participant(
        &mut self,
        client: &str,
        action_id: &str,
    ) -> Result<(), (Option<String>, NodeErrorV1)> {
        let node = self.nodes.get_mut(client).ok_or_else(|| {
            orchestrator_failure(ProcessOrchestratorError::new(
                "participant_not_running",
                "cannot resume a stopped participant",
            ))
        })?;
        resume_pid(node.child.id()).map_err(|error| {
            orchestrator_failure(ProcessOrchestratorError::new(
                "resume_failed",
                error.to_string(),
            ))
        })?;
        node.paused = false;
        self.lifecycle.push(ProcessLifecycleEventV1 {
            action_id: action_id.into(),
            participant: client.into(),
            event: "resumed".into(),
        });
        Ok(())
    }

    async fn crash_participant(
        &mut self,
        client: &str,
        action_id: &str,
    ) -> Result<(), (Option<String>, NodeErrorV1)> {
        let mut node = self.nodes.remove(client).ok_or_else(|| {
            orchestrator_failure(ProcessOrchestratorError::new(
                "participant_not_running",
                "cannot crash a stopped participant",
            ))
        })?;
        if node.paused {
            let _ = resume_pid(node.child.id());
        }
        kill_process_group(&mut node.child).await.map_err(|error| {
            orchestrator_failure(ProcessOrchestratorError::new(
                "kill_failed",
                error.to_string(),
            ))
        })?;
        self.lifecycle.push(ProcessLifecycleEventV1 {
            action_id: action_id.into(),
            participant: client.into(),
            event: "killed".into(),
        });
        Ok(())
    }

    async fn restart_participant(
        &mut self,
        client: &str,
        action_id: &str,
    ) -> Result<(), (Option<String>, NodeErrorV1)> {
        if self.nodes.contains_key(client) {
            self.crash_participant(client, action_id).await?;
        }
        self.launch_participant(client, action_id)
            .await
            .map_err(orchestrator_failure)?;
        self.configure_peers().await.map_err(orchestrator_failure)?;
        let groups = self.groups.clone();
        for (group, group_id_hex) in groups {
            self.expect_ack(
                client,
                NodeCommandV1::SelectGroup {
                    group,
                    group_id_hex,
                },
            )
            .await?;
        }
        self.lifecycle.push(ProcessLifecycleEventV1 {
            action_id: action_id.into(),
            participant: client.into(),
            event: "restarted".into(),
        });
        Ok(())
    }

    fn client_for_process(&self, process: &str) -> Result<String, ProcessOrchestratorError> {
        self.processes
            .iter()
            .find_map(|(client, candidate)| (candidate == process).then(|| client.clone()))
            .ok_or_else(|| {
                ProcessOrchestratorError::new("unknown_process", "scenario process is unknown")
            })
    }

    fn write_failure_capsule(
        &self,
        participant: &str,
        action_id: &str,
        error: &NodeErrorV1,
    ) -> Result<PathBuf, ProcessOrchestratorError> {
        let directory = self.artifact_directory.join("failure-capsules");
        fs_private::create_dir_all_private(&directory).map_err(environment_error)?;
        let digest = hex::encode(sha2::Sha256::digest(action_id.as_bytes()));
        let path = directory.join(format!("{}.json", &digest[..16]));
        NodeFailureCapsuleV1::from_error(participant, action_id, error)
            .write_private(&path)
            .map_err(environment_error)?;
        Ok(path)
    }

    pub fn write_report_private(
        &self,
        report: &ProcessScenarioReportV1,
        path: &Path,
    ) -> Result<(), ProcessOrchestratorError> {
        fs_private::write_private(
            path,
            &serde_json::to_vec_pretty(report).map_err(environment_error)?,
        )
        .map_err(environment_error)
    }
}

impl NodeProcess {
    async fn send(
        &mut self,
        command: NodeCommandV1,
    ) -> Result<NodeResponseBodyV1, ProcessOrchestratorError> {
        self.next_request = self.next_request.saturating_add(1);
        let request_id = format!("{}:{}", self.participant, self.next_request);
        let request = NodeRequestV1::new(request_id.clone(), command);
        self.stdin
            .write_all(&serde_json::to_vec(&request).map_err(environment_error)?)
            .await
            .map_err(environment_error)?;
        self.stdin
            .write_all(b"\n")
            .await
            .map_err(environment_error)?;
        self.stdin.flush().await.map_err(environment_error)?;
        let mut line = String::new();
        timeout(NODE_RESPONSE_TIMEOUT, self.stdout.read_line(&mut line))
            .await
            .map_err(|_| ProcessOrchestratorError::new("node_timeout", "node response timed out"))?
            .map_err(environment_error)?;
        if line.is_empty() {
            return Err(ProcessOrchestratorError::new(
                "node_closed",
                "node closed stdout before responding",
            ));
        }
        let response = decode_node_response(&line, &request_id)?;
        Ok(response.body)
    }
}

fn decode_node_response(
    line: &str,
    request_id: &str,
) -> Result<NodeResponseV1, ProcessOrchestratorError> {
    let raw: serde_json::Value = serde_json::from_str(line).map_err(environment_error)?;
    let protocol = raw.get("protocol").and_then(serde_json::Value::as_str);
    let response_request_id = raw.get("request_id").and_then(serde_json::Value::as_str);
    if protocol != Some(NODE_PROTOCOL_VERSION) || response_request_id != Some(request_id) {
        return Err(ProcessOrchestratorError::new(
            "node_protocol_mismatch",
            "node response did not match the request",
        ));
    }
    if raw
        .pointer("/body/type")
        .and_then(serde_json::Value::as_str)
        == Some("observation")
        && raw
            .pointer("/body/observation/schema_version")
            .and_then(serde_json::Value::as_str)
            != Some(NODE_OBSERVATION_SCHEMA_VERSION)
    {
        return Err(ProcessOrchestratorError::new(
            "node_observation_schema_mismatch",
            "node observation schema is unsupported",
        ));
    }
    let response: NodeResponseV1 = serde_json::from_value(raw).map_err(environment_error)?;
    Ok(response)
}

fn process_subject_descriptor() -> SubjectDescriptor {
    SubjectDescriptor {
        adapter: "marmot_app_process".into(),
        adapter_version: "1".into(),
        storage_backend: "sqlcipher_per_process".into(),
        capabilities: BTreeSet::from([
            SubjectCapability::GroupMutation,
            SubjectCapability::ApplicationMessaging,
            SubjectCapability::TransportDelivery,
            SubjectCapability::EventObservation,
            SubjectCapability::AdminPolicyObservation,
            SubjectCapability::CrashReopen,
            SubjectCapability::OutboundPublication,
            SubjectCapability::StructuralProgress,
            SubjectCapability::ParticipantConnectivity,
            SubjectCapability::ProcessLifecycle,
            SubjectCapability::MultiGroup,
            SubjectCapability::RetainedRelayHistory,
        ]),
    }
}

/// Preflight the canonical schedule against the process executor's actual
/// capabilities. `AwaitQuiescence` is a semantic fixed-point gate here: the
/// orchestrator polls real participant progress with a bounded wall-clock
/// deadline, so it discharges that action without claiming arbitrary virtual
/// time support. Other time-dependent actions remain rejected.
fn preflight_process_compiled_scenario(
    compiled: &CompiledScenarioV2,
    descriptor: &SubjectDescriptor,
) -> Result<(), crate::ScenarioRunError> {
    let mut process_compiled = compiled.clone();
    for action in &mut process_compiled.actions {
        if matches!(action.step, ScenarioStep::AwaitQuiescence { .. }) {
            action
                .schedule
                .required_capabilities
                .remove(&SubjectCapability::VirtualTime);
        }
    }
    preflight_compiled_scenario(&process_compiled, descriptor)
}

fn unexpected_response(_body: NodeResponseBodyV1) -> NodeErrorV1 {
    NodeErrorV1 {
        code: "unexpected_node_response".into(),
        category: SubjectFailureCategory::Environment,
        retryable: false,
        message: "node returned an unexpected response variant".into(),
    }
}

fn orchestrator_failure(error: ProcessOrchestratorError) -> (Option<String>, NodeErrorV1) {
    (
        None,
        NodeErrorV1 {
            code: error.code,
            category: SubjectFailureCategory::Environment,
            retryable: false,
            message: error.message,
        },
    )
}

fn environment_error(error: impl fmt::Display) -> ProcessOrchestratorError {
    ProcessOrchestratorError::new("process_environment", error.to_string())
}

fn action_participant(step: &ScenarioStep) -> Option<String> {
    match step {
        ScenarioStep::ExpectUpdateAdminPolicyError { client, .. }
        | ScenarioStep::ClearStorageFault { target: client } => Some(client.clone()),
        ScenarioStep::InjectStorageFault { fault } => Some(fault.target.clone()),
        _ => None,
    }
}

fn process_action_error(error: (Option<String>, NodeErrorV1)) -> ProcessOrchestratorError {
    ProcessOrchestratorError::new(error.1.code, error.1.message)
}

pub fn process_participant_token(label: &str) -> String {
    let digest = hex::encode(sha2::Sha256::digest(label.as_bytes()));
    format!("participant-{}", &digest[..16])
}

#[cfg(unix)]
fn pause_pid(pid: Option<u32>) -> std::io::Result<()> {
    signal_pid(pid, libc::SIGSTOP)
}

#[cfg(not(unix))]
fn pause_pid(_pid: Option<u32>) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process pause is unavailable on this platform",
    ))
}

#[cfg(unix)]
fn resume_pid(pid: Option<u32>) -> std::io::Result<()> {
    signal_pid(pid, libc::SIGCONT)
}

#[cfg(not(unix))]
fn resume_pid(_pid: Option<u32>) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process resume is unavailable on this platform",
    ))
}

#[cfg(unix)]
fn signal_pid(pid: Option<u32>, signal: libc::c_int) -> std::io::Result<()> {
    let pid = pid.ok_or_else(|| std::io::Error::other("child has no pid"))?;
    let pid = i32::try_from(pid).map_err(std::io::Error::other)?;
    // SAFETY: the pid belongs to a live direct child owned by this orchestrator.
    if unsafe { libc::kill(pid, signal) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

async fn kill_process_group(child: &mut Child) -> std::io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let pid = child
            .id()
            .ok_or_else(|| std::io::Error::other("child has no pid"))?;
        let pid = i32::try_from(pid).map_err(std::io::Error::other)?;
        // SAFETY: the child was spawned as process-group leader; a negative pid
        // targets only that owned group.
        if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        let _ = child.wait().await?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        child.kill().await?;
        let _ = child.wait().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_report_round_trip_preserves_canonical_schedule() {
        let report = ProcessScenarioReportV1 {
            schema_version: PROCESS_SCENARIO_REPORT_SCHEMA_VERSION.into(),
            scenario_name: "round-trip".into(),
            canonical_schedule: Vec::new(),
            actions: Vec::new(),
            observations: Vec::new(),
            lifecycle: Vec::new(),
            failure_capsules: Vec::new(),
            completed: true,
        };
        assert_eq!(
            serde_json::from_slice::<ProcessScenarioReportV1>(
                &serde_json::to_vec(&report).unwrap()
            )
            .unwrap(),
            report
        );
    }

    #[test]
    fn node_command_template_is_argv_local_and_rejects_unknown_placeholders() {
        let host = Path::new("/tmp/host-run");
        let child = Path::new("/campaign");
        assert_eq!(
            render_node_arg(
                "name={run_token}-{participant}:{host_run_root}:{child_run_root}",
                "participant-abcd",
                "run-1234",
                host,
                child,
            )
            .unwrap(),
            "name=run-1234-participant-abcd:/tmp/host-run:/campaign"
        );
        let error = render_node_arg("{shell}", "p", "r", host, child).unwrap_err();
        assert_eq!(error.code, "unknown_node_command_placeholder");
    }
    #[test]
    fn observation_schema_is_rejected_before_typed_observation_decoding() {
        let line = format!(
            r#"{{"protocol":"{NODE_PROTOCOL_VERSION}","request_id":"request-1","participant":"alice","body":{{"type":"observation","action_id":"observe","observation":{{"schema_version":"0"}}}}}}"#
        );
        let error = decode_node_response(&line, "request-1").unwrap_err();
        assert_eq!(error.code, "node_observation_schema_mismatch");
    }

    #[test]
    fn process_preflight_supports_observed_quiescence_without_claiming_virtual_time() {
        let descriptor = process_subject_descriptor();
        assert!(!descriptor.supports(SubjectCapability::VirtualTime));

        let await_spec = ScenarioSpec {
            name: "process-observed-quiescence".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into()],
            topology: Default::default(),
            steps: vec![ScenarioStep::AwaitQuiescence {
                policy: Default::default(),
            }],
        };
        let compiled = compile_scenario(&await_spec).unwrap();
        preflight_process_compiled_scenario(&compiled, &descriptor).unwrap();

        let advance_spec = ScenarioSpec {
            name: "process-rejects-virtual-time".into(),
            steps: vec![ScenarioStep::AdvanceTime { delta_ms: 1 }],
            ..await_spec
        };
        let compiled = compile_scenario(&advance_spec).unwrap();
        let error = preflight_process_compiled_scenario(&compiled, &descriptor)
            .expect_err("arbitrary virtual-time actions remain unsupported");
        assert_eq!(error.kind, "unsupported_subject_capability");
        assert_eq!(error.step_index, Some(0));
    }
}
