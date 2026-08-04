//! Versioned JSONL control protocol for one application-runtime participant.
//!
//! The wire surface is intentionally application-level. It carries scenario
//! labels, public account keys required to address peers, group ids required
//! to resume a scenario, projection commitments, and aggregate relay/runtime
//! progress. It never exposes engine state, storage queries, MLS secrets, raw
//! transport objects, or private identity material.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use cgka_traits::{GroupId, TransportEndpoint};
use marmot_account::AccountHome;
use marmot_app::{
    AccountSetupRequest, AppError, AppMessageQuery, MarmotApp, MarmotAppConfig, MarmotAppRuntime,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::broadcast;

use crate::app_runtime::{opaque_public_identity, public_protocol_projection};
use crate::{
    AppRuntimeApplicationProjectionV1, AppRuntimeProtocolProjectionV1,
    ConformanceCanonicalStateSnapshot, SubjectFailureCategory,
};

pub const NODE_PROTOCOL_VERSION: &str = "marmot-convergence-node-v1";
pub const NODE_OBSERVATION_SCHEMA_VERSION: &str = "2";
pub const NODE_FAILURE_CAPSULE_SCHEMA_VERSION: &str = "1";
pub const MAX_NODE_JSONL_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRequestV1 {
    pub protocol: String,
    pub request_id: String,
    pub command: NodeCommandV1,
}

impl NodeRequestV1 {
    pub fn new(request_id: impl Into<String>, command: NodeCommandV1) -> Self {
        Self {
            protocol: NODE_PROTOCOL_VERSION.into(),
            request_id: request_id.into(),
            command,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeCommandV1 {
    Initialize {
        participant: String,
        root: PathBuf,
        relay_urls: Vec<String>,
    },
    ConfigurePeers {
        accounts_by_participant: BTreeMap<String, String>,
    },
    SelectGroup {
        group: String,
        group_id_hex: String,
    },
    CreateGroup {
        action_id: String,
        group: String,
        name: String,
        member_accounts: Vec<String>,
        initial_admin_accounts: Vec<String>,
    },
    InviteMembers {
        action_id: String,
        member_accounts: Vec<String>,
    },
    RemoveMembers {
        action_id: String,
        member_accounts: Vec<String>,
    },
    UpdateGroupData {
        action_id: String,
        name: String,
    },
    UpdateAdminPolicy {
        action_id: String,
        admin_accounts: Vec<String>,
    },
    SelfUpdate {
        action_id: String,
    },
    SendApplication {
        action_id: String,
        payload: String,
    },
    Leave {
        action_id: String,
    },
    CatchUp {
        action_id: String,
        full_history: bool,
    },
    Observe {
        action_id: String,
    },
    ClearEvents {
        action_id: String,
    },
    Barrier {
        action_id: String,
        barrier: String,
    },
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeResponseV1 {
    pub protocol: String,
    pub request_id: String,
    pub participant: Option<String>,
    pub body: NodeResponseBodyV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeResponseBodyV1 {
    Initialized {
        /// Ephemeral orchestration datum. Failure capsules must replace this
        /// with the scenario participant label.
        account_id: String,
    },
    Ack {
        action_id: String,
        published: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_id_hex: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        application_message_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        application_origin_branch_id: Option<String>,
        #[serde(default)]
        application_origin_branch_unknown: bool,
    },
    Observation {
        action_id: String,
        observation: Box<NodeObservationV1>,
    },
    BarrierReady {
        action_id: String,
        barrier: String,
    },
    Error(NodeErrorV1),
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeErrorV1 {
    pub code: String,
    pub category: SubjectFailureCategory,
    pub retryable: bool,
    /// Fixed or locally generated diagnostic text. Runtime error values are
    /// normalized before entering this field.
    pub message: String,
}

/// Shareable process-layer failure evidence. This intentionally contains no
/// account ids, group ids, relay URLs, payloads, database paths, or raw errors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeFailureCapsuleV1 {
    pub schema_version: String,
    pub participant: String,
    pub action_id: String,
    pub layer: String,
    pub code: String,
    pub category: SubjectFailureCategory,
    pub retryable: bool,
    pub replay: NodeReplayInstructionsV1,
    pub sensitive_data_included: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeReplayInstructionsV1 {
    pub protocol: String,
    pub canonical_scenario_required: bool,
    pub isolated_root_required: bool,
    pub steps: Vec<String>,
}

impl NodeFailureCapsuleV1 {
    pub fn from_error(participant: &str, action_id: &str, error: &NodeErrorV1) -> Self {
        Self {
            schema_version: NODE_FAILURE_CAPSULE_SCHEMA_VERSION.into(),
            participant: participant.into(),
            action_id: action_id.into(),
            layer: "app_process".into(),
            code: error.code.clone(),
            category: error.category,
            retryable: error.retryable,
            replay: NodeReplayInstructionsV1 {
                protocol: NODE_PROTOCOL_VERSION.into(),
                canonical_scenario_required: true,
                isolated_root_required: true,
                steps: vec![
                    "launch the convergence node with a fresh isolated root".into(),
                    "replay the saved canonical Scenario IR through the named action".into(),
                    "capture two stable public projection checkpoints".into(),
                ],
            },
            sensitive_data_included: false,
        }
    }

    pub fn write_private(&self, path: &std::path::Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        fs_private::write_private(path, &bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeObservationV1 {
    pub schema_version: String,
    pub participant: String,
    pub protocol: AppRuntimeProtocolProjectionV1,
    /// Feature-gated exact canonical state commitment. No exporter secret or
    /// engine storage enters the process protocol.
    pub canonical_state: ConformanceCanonicalStateSnapshot,
    pub application: AppRuntimeApplicationProjectionV1,
    pub progress: NodeProgressV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeProgressV1 {
    pub relay_inbound_events_seen: usize,
    pub relay_inbound_events_delivered: usize,
    pub relay_publish_attempts: usize,
    pub relay_publish_failures: usize,
    pub relay_directory_inflight_fetches: usize,
    pub relay_directory_completed_fetches: usize,
    pub retry_timer_armed: bool,
    pub projection_checkpoint_sha256: String,
    pub stable_checkpoint_observations: u32,
}

impl NodeProgressV1 {
    /// The node serves one command at a time, so quiescence is the combination
    /// of no observed relay/retry work and two identical public checkpoints.
    /// This projection deliberately makes no claim about an unexposed runtime
    /// outbox signal.
    pub fn observably_quiescent(&self) -> bool {
        self.relay_directory_inflight_fetches == 0
            && !self.retry_timer_armed
            && self.stable_checkpoint_observations >= 2
    }
}

pub struct NodeServer {
    state: Option<NodeRuntimeState>,
}

struct NodeRuntimeState {
    participant: String,
    app: MarmotApp,
    runtime: MarmotAppRuntime,
    account_id: String,
    accounts_by_participant: BTreeMap<String, String>,
    groups: BTreeMap<String, GroupId>,
    active_group: Option<String>,
    previous_checkpoint: Option<String>,
    stable_checkpoint_observations: u32,
    retry_timer_armed: bool,
    events: broadcast::Receiver<marmot_app::MarmotAppEvent>,
    runtime_events_observed: usize,
}

impl Default for NodeServer {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeServer {
    pub fn new() -> Self {
        Self { state: None }
    }

    pub async fn handle(&mut self, request: NodeRequestV1) -> NodeResponseV1 {
        let request_id = request.request_id.clone();
        if request.protocol != NODE_PROTOCOL_VERSION {
            return self.error_response(
                request_id,
                NodeErrorV1 {
                    code: "wrong_protocol".into(),
                    category: SubjectFailureCategory::Environment,
                    retryable: false,
                    message: "unsupported node protocol version".into(),
                },
            );
        }
        let body = match self.execute(request.command).await {
            Ok(body) => body,
            Err(error) => NodeResponseBodyV1::Error(error),
        };
        NodeResponseV1 {
            protocol: NODE_PROTOCOL_VERSION.into(),
            request_id,
            participant: self.state.as_ref().map(|state| state.participant.clone()),
            body,
        }
    }

    pub async fn shutdown(&mut self) {
        if let Some(state) = self.state.take() {
            state.runtime.shutdown().await;
        }
    }

    async fn execute(&mut self, command: NodeCommandV1) -> Result<NodeResponseBodyV1, NodeErrorV1> {
        match command {
            NodeCommandV1::Initialize {
                participant,
                root,
                relay_urls,
            } => self.initialize(participant, root, relay_urls).await,
            NodeCommandV1::Shutdown => {
                self.shutdown().await;
                Ok(NodeResponseBodyV1::Shutdown)
            }
            command => self.execute_initialized(command).await,
        }
    }

    async fn initialize(
        &mut self,
        participant: String,
        root: PathBuf,
        relay_urls: Vec<String>,
    ) -> Result<NodeResponseBodyV1, NodeErrorV1> {
        if self.state.is_some() {
            return Err(protocol_error(
                "already_initialized",
                "node is already initialized",
            ));
        }
        fs_private::create_dir_all_private(&root).map_err(environment_node_error)?;
        if relay_urls.is_empty() {
            return Err(protocol_error(
                "missing_relay",
                "node initialization requires at least one relay",
            ));
        }
        let home = AccountHome::open(&root);
        let app = MarmotApp::try_with_relays_and_account_home_and_config(
            &root,
            relay_urls.clone(),
            home,
            MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
        )
        .map_err(app_node_error)?;
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.start().await.map_err(app_node_error)?;
        let existing = runtime
            .accounts()
            .managed_accounts()
            .map_err(app_node_error)?
            .into_iter()
            .find(|account| account.local_signing && !account.signed_out);
        let account_id = if let Some(account) = existing {
            account.account_id_hex
        } else {
            let endpoints = relay_urls
                .iter()
                .cloned()
                .map(TransportEndpoint::from)
                .collect::<Vec<_>>();
            runtime
                .create_identity(AccountSetupRequest {
                    default_relays: endpoints.clone(),
                    bootstrap_relays: endpoints,
                    publish_missing_relay_lists: true,
                    publish_initial_key_package: true,
                    ..AccountSetupRequest::default()
                })
                .await
                .map_err(app_node_error)?
                .account
                .account_id_hex
        };
        let events = runtime.subscribe();
        self.state = Some(NodeRuntimeState {
            participant,
            app,
            runtime,
            account_id: account_id.clone(),
            accounts_by_participant: BTreeMap::new(),
            groups: BTreeMap::new(),
            active_group: None,
            previous_checkpoint: None,
            stable_checkpoint_observations: 0,
            retry_timer_armed: false,
            events,
            runtime_events_observed: 0,
        });
        Ok(NodeResponseBodyV1::Initialized { account_id })
    }

    async fn execute_initialized(
        &mut self,
        command: NodeCommandV1,
    ) -> Result<NodeResponseBodyV1, NodeErrorV1> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| protocol_error("not_initialized", "node is not initialized"))?;
        match command {
            NodeCommandV1::Initialize { .. } | NodeCommandV1::Shutdown => unreachable!(),
            NodeCommandV1::ConfigurePeers {
                accounts_by_participant,
            } => {
                if accounts_by_participant
                    .values()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != accounts_by_participant.len()
                {
                    return Err(protocol_error(
                        "duplicate_peer_account",
                        "peer account aliases must be one-to-one",
                    ));
                }
                state.accounts_by_participant = accounts_by_participant;
                Ok(ack("configure_peers", 0, None))
            }
            NodeCommandV1::SelectGroup {
                group,
                group_id_hex,
            } => {
                let group_id = parse_group_id(&group_id_hex)?;
                state.groups.insert(group.clone(), group_id);
                state.active_group = Some(group);
                Ok(ack("select_group", 0, None))
            }
            NodeCommandV1::CreateGroup {
                action_id,
                group,
                name,
                member_accounts,
                initial_admin_accounts,
            } => {
                let group_id = state
                    .runtime
                    .create_group(&state.account_id, &name, &member_accounts, None)
                    .await
                    .map_err(app_node_error)?;
                state.groups.insert(group.clone(), group_id.clone());
                state.active_group = Some(group);
                set_admins(state, &group_id, &initial_admin_accounts).await?;
                Ok(ack(action_id, 1, Some(hex::encode(group_id.as_slice()))))
            }
            NodeCommandV1::InviteMembers {
                action_id,
                member_accounts,
            } => {
                let group_id = active_group(state)?;
                let summary = state
                    .runtime
                    .invite_members(&state.account_id, &group_id, &member_accounts)
                    .await
                    .map_err(app_node_error)?;
                Ok(ack(action_id, summary.published, None))
            }
            NodeCommandV1::RemoveMembers {
                action_id,
                member_accounts,
            } => {
                let group_id = active_group(state)?;
                let summary = state
                    .runtime
                    .remove_members(&state.account_id, &group_id, &member_accounts)
                    .await
                    .map_err(app_node_error)?;
                Ok(ack(action_id, summary.published, None))
            }
            NodeCommandV1::UpdateGroupData { action_id, name } => {
                let group_id = active_group(state)?;
                let summary = state
                    .runtime
                    .update_group_profile(&state.account_id, &group_id, Some(name), None)
                    .await
                    .map_err(app_node_error)?;
                Ok(ack(action_id, summary.published, None))
            }
            NodeCommandV1::UpdateAdminPolicy {
                action_id,
                admin_accounts,
            } => {
                let group_id = active_group(state)?;
                set_admins(state, &group_id, &admin_accounts).await?;
                Ok(ack(action_id, 1, None))
            }
            NodeCommandV1::SelfUpdate { action_id } => {
                let group_id = active_group(state)?;
                state
                    .runtime
                    .schedule_manual_self_update(&state.account_id, &group_id)
                    .await
                    .map_err(app_node_error)?;
                Ok(ack(action_id, 0, None))
            }
            NodeCommandV1::SendApplication { action_id, payload } => {
                let group_id = active_group(state)?;
                let summary = state
                    .runtime
                    .send_message(&state.account_id, &group_id, payload.into_bytes())
                    .await
                    .map_err(app_node_error)?;
                let (origin_branch_id, application_origin_branch_unknown) = match state
                    .runtime
                    .conformance_canonical_state_snapshot(&state.account_id, &group_id)
                    .await
                {
                    Ok(ConformanceCanonicalStateSnapshot::Live(snapshot)) => {
                        (Some(snapshot.selected_branch_id), false)
                    }
                    Ok(ConformanceCanonicalStateSnapshot::Disbanded(_)) => (None, false),
                    Err(_) => (None, true),
                };
                Ok(NodeResponseBodyV1::Ack {
                    action_id,
                    published: summary.published,
                    group_id_hex: None,
                    application_message_id: summary.message_ids.first().cloned(),
                    application_origin_branch_id: origin_branch_id,
                    application_origin_branch_unknown,
                })
            }
            NodeCommandV1::Leave { action_id } => {
                let group_id = active_group(state)?;
                let summary = state
                    .runtime
                    .leave_group(&state.account_id, &group_id)
                    .await
                    .map_err(app_node_error)?;
                Ok(ack(action_id, summary.published, None))
            }
            NodeCommandV1::CatchUp {
                action_id,
                full_history,
            } => {
                let result = if full_history {
                    state.runtime.repair_full_history(&state.account_id).await
                } else {
                    state.runtime.catch_up_accounts().await
                };
                match result {
                    Ok(()) => {
                        state.retry_timer_armed = false;
                        if state.active_group.is_some() {
                            accept_active_invite(state).await?;
                        }
                        Ok(ack(action_id, 0, None))
                    }
                    Err(error) => {
                        state.retry_timer_armed = is_retryable_app_error(&error);
                        Err(app_node_error(error))
                    }
                }
            }
            NodeCommandV1::Observe { action_id } => {
                let observation = observe_node(state).await?;
                Ok(NodeResponseBodyV1::Observation {
                    action_id,
                    observation: Box::new(observation),
                })
            }
            NodeCommandV1::ClearEvents { action_id } => {
                while state.events.try_recv().is_ok() {}
                state.runtime_events_observed = 0;
                state.previous_checkpoint = None;
                state.stable_checkpoint_observations = 0;
                Ok(ack(action_id, 0, None))
            }
            NodeCommandV1::Barrier { action_id, barrier } => {
                Ok(NodeResponseBodyV1::BarrierReady { action_id, barrier })
            }
        }
    }

    fn error_response(&self, request_id: String, error: NodeErrorV1) -> NodeResponseV1 {
        NodeResponseV1 {
            protocol: NODE_PROTOCOL_VERSION.into(),
            request_id,
            participant: self.state.as_ref().map(|state| state.participant.clone()),
            body: NodeResponseBodyV1::Error(error),
        }
    }
}

pub async fn run_node_jsonl<R, W>(reader: R, mut writer: W) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = reader;
    let mut server = NodeServer::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = (&mut reader)
            .take((MAX_NODE_JSONL_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .await?;
        if read == 0 {
            break;
        }
        let response = if line.len() > MAX_NODE_JSONL_BYTES {
            if !line.ends_with(b"\n") {
                discard_through_newline(&mut reader).await?;
            }
            NodeResponseV1 {
                protocol: NODE_PROTOCOL_VERSION.into(),
                request_id: "oversized".into(),
                participant: None,
                body: NodeResponseBodyV1::Error(protocol_error(
                    "frame_too_large",
                    "node request exceeds the JSONL frame limit",
                )),
            }
        } else {
            match serde_json::from_slice::<NodeRequestV1>(&line) {
                Ok(request) => server.handle(request).await,
                Err(_) => NodeResponseV1 {
                    protocol: NODE_PROTOCOL_VERSION.into(),
                    request_id: "unparseable".into(),
                    participant: None,
                    body: NodeResponseBodyV1::Error(protocol_error(
                        "invalid_json",
                        "node request is not valid protocol JSON",
                    )),
                },
            }
        };
        let shutdown = matches!(response.body, NodeResponseBodyV1::Shutdown);
        writer.write_all(&serde_json::to_vec(&response)?).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        if shutdown {
            return Ok(());
        }
    }
    server.shutdown().await;
    Ok(())
}

async fn discard_through_newline<R>(reader: &mut R) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(());
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            reader.consume(newline + 1);
            return Ok(());
        }
        let consumed = available.len();
        reader.consume(consumed);
    }
}

pub async fn run_node_stdio() -> std::io::Result<()> {
    run_node_jsonl(BufReader::new(tokio::io::stdin()), tokio::io::stdout()).await
}

async fn accept_active_invite(state: &mut NodeRuntimeState) -> Result<(), NodeErrorV1> {
    let group_id = active_group(state)?;
    let group_id_hex = hex::encode(group_id.as_slice());
    if state
        .app
        .group(&state.account_id, &group_id_hex)
        .map_err(app_node_error)?
        .is_some_and(|group| group.pending_confirmation)
    {
        state
            .runtime
            .accept_group_invite(&state.account_id, &group_id)
            .await
            .map_err(app_node_error)?;
    }
    Ok(())
}

async fn observe_node(state: &mut NodeRuntimeState) -> Result<NodeObservationV1, NodeErrorV1> {
    while state.events.try_recv().is_ok() {
        state.runtime_events_observed = state.runtime_events_observed.saturating_add(1);
    }
    let group_id = active_group(state)?;
    let group_id_hex = hex::encode(group_id.as_slice());
    let group = state
        .app
        .group(&state.account_id, &group_id_hex)
        .map_err(app_node_error)?
        .ok_or_else(|| protocol_error("unknown_group", "group projection is unavailable"))?;
    let mls = state
        .runtime
        .group_mls_state(&state.account_id, &group_id)
        .await
        .map_err(app_node_error)?;
    let canonical_state = state
        .runtime
        .conformance_canonical_state_snapshot(&state.account_id, &group_id)
        .await
        .map_err(app_node_error)?;
    let reverse = state
        .accounts_by_participant
        .iter()
        .map(|(label, account)| (account.as_str(), label.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut members = state
        .runtime
        .group_members(&state.account_id, &group_id)
        .await
        .map_err(app_node_error)?
        .into_iter()
        .map(|member| {
            reverse
                .get(member.member_id_hex.as_str())
                .map(|label| (*label).to_owned())
                .unwrap_or_else(|| opaque_public_identity(&member.member_id_hex))
        })
        .collect::<Vec<_>>();
    members.sort();
    let mut admins = group
        .admin_policy
        .admins
        .iter()
        .map(|account| {
            reverse
                .get(account.as_str())
                .map(|label| (*label).to_owned())
                .unwrap_or_else(|| opaque_public_identity(account))
        })
        .collect::<Vec<_>>();
    admins.sort();
    let protocol = public_protocol_projection(
        mls.epoch,
        members,
        admins,
        group.profile.name.clone(),
        mls.member_count,
    );
    let messages = state
        .app
        .messages_with_query(
            &state.account_id,
            AppMessageQuery {
                group_id_hex: Some(group_id_hex),
                limit: None,
            },
        )
        .map_err(app_node_error)?;
    let mut visible = messages
        .iter()
        .filter(|message| !message.invalidated)
        .collect::<Vec<_>>();
    visible.sort_by(|left, right| left.message_id_hex.cmp(&right.message_id_hex));
    let mut invalidated_message_ids = messages
        .iter()
        .filter(|message| message.invalidated)
        .map(|message| message.message_id_hex.clone())
        .collect::<Vec<_>>();
    invalidated_message_ids.sort();
    let application = AppRuntimeApplicationProjectionV1 {
        visible_message_ids: visible
            .iter()
            .map(|message| message.message_id_hex.clone())
            .collect(),
        visible_plaintexts: visible
            .iter()
            .filter(|message| message.kind == cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT)
            .map(|message| message.plaintext.clone())
            .collect(),
        invalidated_message_ids,
        pending_confirmation: group.pending_confirmation,
        stored_member_count: group.member_count,
        runtime_events_observed: state.runtime_events_observed,
    };
    let checkpoint = projection_checkpoint(&protocol, &application);
    if state.previous_checkpoint.as_ref() == Some(&checkpoint) {
        state.stable_checkpoint_observations =
            state.stable_checkpoint_observations.saturating_add(1);
    } else {
        state.previous_checkpoint = Some(checkpoint.clone());
        state.stable_checkpoint_observations = 1;
    }
    let telemetry = state.app.relay_telemetry().await;
    Ok(NodeObservationV1 {
        schema_version: NODE_OBSERVATION_SCHEMA_VERSION.into(),
        participant: state.participant.clone(),
        protocol,
        canonical_state,
        application,
        progress: NodeProgressV1 {
            relay_inbound_events_seen: telemetry.metrics.inbound_events_seen,
            relay_inbound_events_delivered: telemetry.metrics.inbound_events_delivered,
            relay_publish_attempts: telemetry.metrics.publish_attempts,
            relay_publish_failures: telemetry.metrics.publish_failures,
            relay_directory_inflight_fetches: telemetry.health.directory_inflight_fetches,
            relay_directory_completed_fetches: telemetry.health.directory_completed_fetches,
            retry_timer_armed: state.retry_timer_armed,
            projection_checkpoint_sha256: checkpoint,
            stable_checkpoint_observations: state.stable_checkpoint_observations,
        },
    })
}

async fn set_admins(
    state: &NodeRuntimeState,
    group_id: &GroupId,
    targets: &[String],
) -> Result<(), NodeErrorV1> {
    let group = state
        .app
        .group(&state.account_id, &hex::encode(group_id.as_slice()))
        .map_err(app_node_error)?
        .ok_or_else(|| protocol_error("unknown_group", "group projection is unavailable"))?;
    let targets = targets.iter().cloned().collect::<BTreeSet<_>>();
    let members = state
        .runtime
        .group_members(&state.account_id, group_id)
        .await
        .map_err(app_node_error)?
        .into_iter()
        .map(|member| member.member_id_hex)
        .collect::<BTreeSet<_>>();
    if targets.is_empty() || !targets.is_subset(&members) {
        return Err(protocol_error(
            "invalid_admin_set",
            "the requested admin set must contain group members",
        ));
    }
    let current = group
        .admin_policy
        .admins
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut applied = Vec::new();
    for account in targets.difference(&current) {
        if let Err(error) = state
            .runtime
            .promote_admin(&state.account_id, group_id, account)
            .await
        {
            return Err(compensate_node_admin_changes(state, group_id, &applied, error).await);
        }
        applied.push(NodeAdminChange::Promoted(account.clone()));
    }
    for account in current
        .difference(&targets)
        .filter(|account| *account != &state.account_id)
    {
        if let Err(error) = state
            .runtime
            .demote_admin(&state.account_id, group_id, account)
            .await
        {
            return Err(compensate_node_admin_changes(state, group_id, &applied, error).await);
        }
        applied.push(NodeAdminChange::Demoted(account.clone()));
    }
    if current.contains(&state.account_id)
        && !targets.contains(&state.account_id)
        && let Err(error) = state
            .runtime
            .self_demote_admin(&state.account_id, group_id)
            .await
    {
        return Err(compensate_node_admin_changes(state, group_id, &applied, error).await);
    }
    Ok(())
}

enum NodeAdminChange {
    Promoted(String),
    Demoted(String),
}

async fn compensate_node_admin_changes(
    state: &NodeRuntimeState,
    group_id: &GroupId,
    applied: &[NodeAdminChange],
    original: AppError,
) -> NodeErrorV1 {
    for change in applied.iter().rev() {
        let result = match change {
            NodeAdminChange::Promoted(account) => {
                state
                    .runtime
                    .demote_admin(&state.account_id, group_id, account)
                    .await
            }
            NodeAdminChange::Demoted(account) => {
                state
                    .runtime
                    .promote_admin(&state.account_id, group_id, account)
                    .await
            }
        };
        if result.is_err() {
            return NodeErrorV1 {
                code: "admin_set_compensation_failed".into(),
                category: SubjectFailureCategory::Environment,
                retryable: false,
                message: "admin policy update failed and its applied changes could not be fully compensated".into(),
            };
        }
    }
    app_node_error(original)
}

fn active_group(state: &NodeRuntimeState) -> Result<GroupId, NodeErrorV1> {
    let label = state
        .active_group
        .as_ref()
        .ok_or_else(|| protocol_error("group_not_selected", "no scenario group is selected"))?;
    state
        .groups
        .get(label)
        .cloned()
        .ok_or_else(|| protocol_error("unknown_group", "selected scenario group is unknown"))
}

fn parse_group_id(value: &str) -> Result<GroupId, NodeErrorV1> {
    let bytes = hex::decode(value)
        .map_err(|_| protocol_error("invalid_group_id", "group id must be hexadecimal"))?;
    if bytes.is_empty() {
        return Err(protocol_error(
            "invalid_group_id",
            "group id must not be empty",
        ));
    }
    Ok(GroupId::new(bytes))
}

fn projection_checkpoint(
    protocol: &AppRuntimeProtocolProjectionV1,
    application: &AppRuntimeApplicationProjectionV1,
) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(&(protocol, application))
            .expect("public node observation is serializable"),
    ))
}

fn ack(
    action_id: impl Into<String>,
    published: usize,
    group_id_hex: Option<String>,
) -> NodeResponseBodyV1 {
    NodeResponseBodyV1::Ack {
        action_id: action_id.into(),
        published,
        group_id_hex,
        application_message_id: None,
        application_origin_branch_id: None,
        application_origin_branch_unknown: false,
    }
}

fn protocol_error(code: &str, message: &str) -> NodeErrorV1 {
    NodeErrorV1 {
        code: code.into(),
        category: SubjectFailureCategory::Protocol,
        retryable: false,
        message: message.into(),
    }
}

fn environment_node_error(error: impl std::fmt::Display) -> NodeErrorV1 {
    NodeErrorV1 {
        code: "node_environment".into(),
        category: SubjectFailureCategory::Environment,
        retryable: false,
        message: error.to_string(),
    }
}

fn app_node_error(error: impl IntoAppNodeError) -> NodeErrorV1 {
    error.into_node_error()
}

trait IntoAppNodeError {
    fn into_node_error(self) -> NodeErrorV1;
}

impl IntoAppNodeError for AppError {
    fn into_node_error(self) -> NodeErrorV1 {
        let retryable = is_retryable_app_error(&self);
        let code = match self {
            AppError::AccountSessionBusy => "account_session_busy",
            AppError::RuntimeBusy => "runtime_busy",
            AppError::RuntimeStopping => "runtime_stopping",
            AppError::TransportClosed => "transport_closed",
            AppError::AccountCatchUp(_) => "account_catch_up",
            AppError::Publish(_) => "publish_failed",
            AppError::UnknownGroup(_) => "unknown_group",
            _ => "app_runtime_operation_failed",
        };
        NodeErrorV1 {
            code: code.into(),
            category: if retryable {
                SubjectFailureCategory::Resource
            } else {
                SubjectFailureCategory::Environment
            },
            retryable,
            message: "application runtime operation failed".into(),
        }
    }
}

impl IntoAppNodeError for marmot_account::AccountHomeError {
    fn into_node_error(self) -> NodeErrorV1 {
        NodeErrorV1 {
            code: "account_home".into(),
            category: SubjectFailureCategory::Environment,
            retryable: false,
            message: "account home operation failed".into(),
        }
    }
}

fn is_retryable_app_error(error: &AppError) -> bool {
    matches!(
        error,
        AppError::AccountSessionBusy
            | AppError::RuntimeBusy
            | AppError::RuntimeStopping
            | AppError::TransportClosed
            | AppError::AccountCatchUp(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_round_trip_and_quiescence_contract_are_stable() {
        let request = NodeRequestV1::new(
            "request-1",
            NodeCommandV1::Barrier {
                action_id: "step-1:barrier".into(),
                barrier: "ready".into(),
            },
        );
        assert_eq!(
            serde_json::from_slice::<NodeRequestV1>(&serde_json::to_vec(&request).unwrap())
                .unwrap(),
            request
        );
        let mut progress = NodeProgressV1 {
            relay_inbound_events_seen: 1,
            relay_inbound_events_delivered: 1,
            relay_publish_attempts: 1,
            relay_publish_failures: 0,
            relay_directory_inflight_fetches: 0,
            relay_directory_completed_fetches: 1,
            retry_timer_armed: false,
            projection_checkpoint_sha256: "checkpoint".into(),
            stable_checkpoint_observations: 1,
        };
        assert!(!progress.observably_quiescent());
        progress.stable_checkpoint_observations = 2;
        assert!(progress.observably_quiescent());

        let marker = "participant-a";
        let capsule = NodeFailureCapsuleV1::from_error(
            marker,
            "step-4:observe",
            &protocol_error("projection_timeout", "fixed message"),
        );
        let encoded = serde_json::to_string(&capsule).unwrap();
        assert!(encoded.contains(marker));
        assert!(!capsule.sensitive_data_included);
        assert_eq!(capsule.layer, "app_process");
    }

    #[tokio::test]
    async fn wrong_protocol_fails_closed_without_initializing() {
        let mut server = NodeServer::new();
        let response = server
            .handle(NodeRequestV1 {
                protocol: "future".into(),
                request_id: "wrong".into(),
                command: NodeCommandV1::Shutdown,
            })
            .await;
        assert!(matches!(
            response.body,
            NodeResponseBodyV1::Error(NodeErrorV1 { code, .. }) if code == "wrong_protocol"
        ));
    }
}
