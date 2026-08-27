//! Black-box application-runtime adapter for convergence scenarios.
//!
//! This adapter deliberately uses only the public [`marmot_app::MarmotAppRuntime`]
//! command and projection surfaces. It never opens the account session, engine
//! storage, or conformance-only engine snapshots. Each participant owns a
//! distinct restrictive root and one SQLCipher database.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{GroupId, TransportEndpoint};
use marmot_app::{
    AccountSetupRequest, AppError, AppMessageQuery, MarmotApp, MarmotAppConfig, MarmotAppEvent,
    MarmotAppRuntime,
};
use nostr_relay_builder::LocalRelay;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::broadcast;

use crate::relay_control::{
    RELAY_ACTION_PUBLICATION_TIMEOUT, RelayActionEvents, RelayActionExpectation, RelayControl,
    RelayControlError,
};
use crate::{
    ClientEventCounts, ClientObservation, ConvergenceSubject, ScenarioAdminPolicyObservation,
    ScenarioInputLedgerEntry, SubjectCapability, SubjectCreateGroup, SubjectDescriptor,
    SubjectError, SubjectFailureCategory, SubjectInviteMembers, SubjectOutboundArtifact,
    SubjectOutboundOutcome, SubjectRemoveMembers, SubjectSelfUpdate, SubjectSendApplication,
    SubjectUpdateAdminPolicy, SubjectUpdateGroupData,
};

pub const APP_RUNTIME_OBSERVATION_SCHEMA_VERSION: &str = "1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRuntimeProtocolProjectionV1 {
    pub epoch: u64,
    pub member_identities: Vec<String>,
    pub admin_identities: Vec<String>,
    pub group_name: String,
    #[serde(default)]
    pub group_description: String,
    pub member_count: usize,
    /// SHA-256 over the canonical JSON encoding of the preceding public facts.
    /// This is an opaque comparison value, not an MLS secret or engine dump.
    pub state_commitment_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRuntimeApplicationProjectionV1 {
    pub visible_message_ids: Vec<String>,
    pub visible_plaintexts: Vec<String>,
    pub invalidated_message_ids: Vec<String>,
    pub pending_confirmation: bool,
    pub stored_member_count: Option<u64>,
    pub runtime_events_observed: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRuntimeLocalDiagnosticsV1 {
    pub online: bool,
    pub catch_up_attempts: u64,
    pub reopen_count: u64,
    pub retryable_failures: u64,
    pub terminal_failures: u64,
    pub database_exists: bool,
    pub database_encrypted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_kind: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRuntimeObservationV1 {
    pub schema_version: String,
    pub participant: String,
    pub protocol: AppRuntimeProtocolProjectionV1,
    pub application: AppRuntimeApplicationProjectionV1,
    pub local: AppRuntimeLocalDiagnosticsV1,
}

struct Participant {
    root: TempDir,
    app: MarmotApp,
    runtime: Option<MarmotAppRuntime>,
    events: Option<broadcast::Receiver<MarmotAppEvent>>,
    account_id: String,
    online: bool,
    catch_up_attempts: u64,
    reopen_count: u64,
    retryable_failures: u64,
    terminal_failures: u64,
    last_error_kind: Option<String>,
    runtime_events_observed: usize,
    cached_members: BTreeMap<String, Vec<String>>,
    cached_epochs: BTreeMap<String, u64>,
    offline_observation: Option<AppRuntimeObservationV1>,
}

impl Participant {
    fn root(&self) -> &Path {
        self.root.path()
    }

    fn runtime(&self) -> Result<&MarmotAppRuntime, SubjectError> {
        self.runtime.as_ref().ok_or_else(|| {
            SubjectError::classified(
                SubjectFailureCategory::ExpectedRefusal,
                "participant_offline",
                "participant runtime is offline",
            )
        })
    }
}

/// In-process application harness backed by one real local Nostr relay.
pub struct AppRuntimeHarness {
    _relay: LocalRelay,
    relay_control: RelayControl,
    relay_url: String,
    participants: BTreeMap<String, Participant>,
    scenario_groups: BTreeMap<String, GroupId>,
    active_scenario_group: Option<String>,
    accepted_publications: BTreeMap<String, BTreeSet<String>>,
    relay_action_events: RelayActionEvents,
    settlement_quiescence_ms: Option<u64>,
}

impl AppRuntimeHarness {
    pub async fn new(clients: &[String]) -> Result<Self, SubjectError> {
        Self::new_with_settlement_quiescence(clients, None).await
    }

    /// Build the retained-history regression harness with the protocol-pinned
    /// settlement window even when the workspace enables test-policy overrides.
    pub async fn new_with_pinned_settlement(clients: &[String]) -> Result<Self, SubjectError> {
        Self::new_with_settlement_quiescence(clients, Some(1_000)).await
    }

    async fn new_with_settlement_quiescence(
        clients: &[String],
        settlement_quiescence_ms: Option<u64>,
    ) -> Result<Self, SubjectError> {
        let relay_control = RelayControl::new();
        let relay = LocalRelay::new(relay_control.relay_builder());
        relay.run().await.map_err(environment_error)?;
        let relay_url = relay.url().await.to_string();
        let endpoint = TransportEndpoint::from(relay_url.clone());
        let mut participants = BTreeMap::new();
        for client in clients {
            let root = tempfile::Builder::new()
                .prefix("marmot-app-conformance-")
                .tempdir()
                .map_err(environment_error)?;
            fs_private::create_dir_all_private(root.path()).map_err(environment_error)?;
            let app = app_for_root(root.path(), &relay_url, settlement_quiescence_ms);
            let runtime = MarmotAppRuntime::new(app.clone());
            runtime.start().await.map_err(app_error)?;
            let setup = runtime
                .create_identity(AccountSetupRequest {
                    default_relays: vec![endpoint.clone()],
                    bootstrap_relays: vec![endpoint.clone()],
                    publish_missing_relay_lists: true,
                    publish_initial_key_package: true,
                    ..AccountSetupRequest::default()
                })
                .await
                .map_err(app_error)?;
            let events = runtime.subscribe();
            participants.insert(
                client.clone(),
                Participant {
                    root,
                    app,
                    runtime: Some(runtime),
                    events: Some(events),
                    account_id: setup.account.account_id_hex,
                    online: true,
                    catch_up_attempts: 0,
                    reopen_count: 0,
                    retryable_failures: 0,
                    terminal_failures: 0,
                    last_error_kind: None,
                    runtime_events_observed: 0,
                    cached_members: BTreeMap::new(),
                    cached_epochs: BTreeMap::new(),
                    offline_observation: None,
                },
            );
        }
        Ok(Self {
            _relay: relay,
            relay_control,
            relay_url,
            participants,
            scenario_groups: BTreeMap::new(),
            active_scenario_group: None,
            accepted_publications: BTreeMap::new(),
            relay_action_events: BTreeMap::new(),
            settlement_quiescence_ms,
        })
    }

    async fn relay_publication_cursor(&self) -> usize {
        self.relay_control.publication_cursor().await
    }

    async fn set_all_maintenance_paused(&self, paused: bool) -> Result<(), SubjectError> {
        let labels = self
            .participants
            .iter()
            .filter(|(_, participant)| participant.online && participant.runtime.is_some())
            .map(|(label, _)| label.clone())
            .collect::<Vec<_>>();
        let mut changed = Vec::new();
        let mut first_resume_error = None;
        for label in labels {
            let participant = self.participant(&label)?;
            let runtime = participant.runtime()?;
            let result = if paused {
                runtime.pause_maintenance(&participant.account_id).await
            } else {
                runtime.resume_maintenance(&participant.account_id).await
            };
            match result {
                Ok(()) => changed.push(label),
                Err(error) if paused => {
                    for changed_label in changed.iter().rev() {
                        let changed_participant = self.participant(changed_label)?;
                        let _ = changed_participant
                            .runtime()?
                            .resume_maintenance(&changed_participant.account_id)
                            .await;
                    }
                    return Err(app_error(error));
                }
                Err(error) => {
                    first_resume_error.get_or_insert_with(|| app_error(error));
                }
            }
        }
        first_resume_error.map_or(Ok(()), Err)
    }

    async fn record_relay_action_events(
        &mut self,
        action_id: &str,
        actor: &str,
        before: usize,
        include_welcomes: bool,
        expected_publications: usize,
        expected_event_ids: &[String],
    ) -> Result<(), SubjectError> {
        self.participant(actor)?;
        // Scenario commands execute serially. Where the public app API exposes
        // transport message ids, validate those exact relay events; chat sends
        // expose only application-event ids, so they retain the bounded count
        // fallback at this command boundary. Kind-445 outer authors are
        // intentionally ephemeral and cannot identify the actor.
        self.relay_control
            .wait_for_action_events(
                &mut self.relay_action_events,
                action_id,
                before,
                RelayActionExpectation {
                    include_welcomes,
                    expected_publications,
                    expected_event_ids,
                    timeout: RELAY_ACTION_PUBLICATION_TIMEOUT,
                },
            )
            .await
            .map_err(relay_control_error)
    }

    async fn set_shared_relay_event_presence(
        &mut self,
        relay: &str,
        selector: &crate::ScenarioMessageSelectorV2,
        clients: &[String],
        visible: bool,
    ) -> Result<(), SubjectError> {
        if relay != "relay:shared" {
            return Err(SubjectError::classified(
                SubjectFailureCategory::ExpectedRefusal,
                "unknown_relay",
                "the app-runtime adapter owns only relay:shared",
            ));
        }
        if clients
            .iter()
            .any(|client| !self.participants.contains_key(client))
        {
            return Err(SubjectError::classified(
                SubjectFailureCategory::ExpectedRefusal,
                "unknown_relay_removal_client",
                "every named relay-removal client must belong to the harness",
            ));
        }
        if !visible
            && self
                .participants
                .values()
                .any(|participant| participant.online)
        {
            return Err(SubjectError::classified(
                SubjectFailureCategory::ExpectedRefusal,
                "relay_removal_requires_all_participants_offline",
                "an event can be hidden from the shared relay only while every harness participant is offline",
            ));
        }
        self.relay_control
            .set_action_event_visibility(&self.relay_action_events, selector, visible)
            .await
            .map_err(relay_control_error)
    }

    pub fn participant_roots(&self) -> BTreeMap<String, PathBuf> {
        self.participants
            .iter()
            .map(|(label, participant)| (label.clone(), participant.root().to_path_buf()))
            .collect()
    }

    pub async fn catch_up(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        for label in clients {
            let participant = self.participant_mut(label)?;
            if !participant.online {
                continue;
            }
            participant.catch_up_attempts = participant.catch_up_attempts.saturating_add(1);
            let result = participant.runtime()?.catch_up_accounts().await;
            if let Err(error) = result {
                record_failure(participant, &error);
                return Err(app_error(error));
            }
        }
        self.refresh_cached_members(clients).await
    }

    pub async fn repair_full_history(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        for label in clients {
            let participant = self.participant_mut(label)?;
            if !participant.online {
                continue;
            }
            participant.catch_up_attempts = participant.catch_up_attempts.saturating_add(1);
            let account_id = participant.account_id.clone();
            if let Err(error) = participant
                .runtime()?
                .repair_full_history(&account_id)
                .await
            {
                record_failure(participant, &error);
                return Err(app_error(error));
            }
        }
        self.refresh_cached_members(clients).await
    }

    pub async fn set_online(&mut self, client: &str, online: bool) -> Result<(), SubjectError> {
        if online {
            self.reopen(client).await
        } else {
            if !self.participant(client)?.online {
                return Ok(());
            }
            let mut offline_observation = if self.active_scenario_group.is_some() {
                match self.layered_observation(client) {
                    Ok(observation) => Some(observation),
                    Err(error) if error.code == "unknown_group" => None,
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
            if let Some(observation) = offline_observation.as_mut() {
                observation.local.online = false;
            }
            let participant = self.participant_mut(client)?;
            if let Some(runtime) = participant.runtime.take() {
                runtime.shutdown_and_close().await.map_err(app_error)?;
            }
            participant.events = None;
            participant.online = false;
            participant.offline_observation = offline_observation;
            Ok(())
        }
    }

    pub async fn reopen(&mut self, client: &str) -> Result<(), SubjectError> {
        let relay_url = self.relay_url.clone();
        let settlement_quiescence_ms = self.settlement_quiescence_ms;
        let participant = self.participant_mut(client)?;
        if participant.online
            && let Some(runtime) = participant.runtime.take()
        {
            runtime.shutdown_and_close().await.map_err(app_error)?;
        }
        participant.app = app_for_root(participant.root(), &relay_url, settlement_quiescence_ms);
        let runtime = MarmotAppRuntime::new(participant.app.clone());
        runtime.start().await.map_err(app_error)?;
        participant.events = Some(runtime.subscribe());
        participant.runtime = Some(runtime);
        participant.online = true;
        participant.reopen_count = participant.reopen_count.saturating_add(1);
        participant.offline_observation = None;
        Ok(())
    }

    pub async fn observations(
        &mut self,
        clients: &[String],
    ) -> Result<Vec<AppRuntimeObservationV1>, SubjectError> {
        self.refresh_cached_members(clients).await?;
        clients
            .iter()
            .map(|client| self.layered_observation(client))
            .collect()
    }

    /// Drive public catch-up/timer work until all named participants expose
    /// one shared, stable protocol commitment and no pending projection.
    /// Quiescence is intentionally defined without engine-private counters.
    pub async fn await_observable_settlement(
        &mut self,
        clients: &[String],
        max_wait: Duration,
    ) -> Result<Vec<AppRuntimeObservationV1>, SubjectError> {
        let deadline = tokio::time::Instant::now() + max_wait;
        let mut previous_commitments: Option<Vec<String>> = None;
        loop {
            self.catch_up(clients).await?;
            let observations = self.observations(clients).await?;
            let commitments = observations
                .iter()
                .map(|observation| observation.protocol.state_commitment_sha256.clone())
                .collect::<Vec<_>>();
            let shared = commitments
                .first()
                .is_some_and(|first| commitments.iter().all(|item| item == first));
            let projections_settled = observations
                .iter()
                .all(|observation| !observation.application.pending_confirmation);
            if shared && projections_settled && previous_commitments.as_ref() == Some(&commitments)
            {
                return Ok(observations);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(SubjectError::classified(
                    SubjectFailureCategory::Resource,
                    "app_runtime_settlement_timeout",
                    "public app projections did not reach a stable shared commitment before the deadline",
                ));
            }
            previous_commitments = Some(commitments);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn shutdown(&mut self) {
        for participant in self.participants.values_mut() {
            if let Some(runtime) = participant.runtime.take() {
                runtime.shutdown().await;
            }
            participant.online = false;
        }
    }

    fn active_group(&self) -> Result<GroupId, SubjectError> {
        let label = self.active_scenario_group.as_ref().ok_or_else(|| {
            SubjectError::new("scenario_group_missing", "no scenario group is selected")
        })?;
        self.scenario_groups.get(label).cloned().ok_or_else(|| {
            SubjectError::new(
                "scenario_group_missing",
                format!("scenario group {label} has not been created"),
            )
        })
    }

    fn participant(&self, label: &str) -> Result<&Participant, SubjectError> {
        self.participants.get(label).ok_or_else(|| {
            SubjectError::new(
                "unknown_participant",
                format!("unknown participant {label}"),
            )
        })
    }

    fn participant_mut(&mut self, label: &str) -> Result<&mut Participant, SubjectError> {
        self.participants.get_mut(label).ok_or_else(|| {
            SubjectError::new(
                "unknown_participant",
                format!("unknown participant {label}"),
            )
        })
    }

    fn account_ids(&self, labels: &[String]) -> Result<Vec<String>, SubjectError> {
        labels
            .iter()
            .map(|label| Ok(self.participant(label)?.account_id.clone()))
            .collect()
    }

    fn record_accepted_publication(&mut self, client: &str, publication: &str) {
        self.accepted_publications
            .entry(client.to_owned())
            .or_default()
            .insert(publication.to_owned());
    }

    async fn refresh_cached_members(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        let Some(group_label) = self.active_scenario_group.clone() else {
            return Ok(());
        };
        let Some(group_id) = self.scenario_groups.get(&group_label).cloned() else {
            return Ok(());
        };
        for label in clients {
            let participant = self.participant_mut(label)?;
            if !participant.online {
                continue;
            }
            let members = participant
                .runtime()?
                .group_members(&participant.account_id, &group_id)
                .await
                .map_err(app_error)?;
            participant.cached_members.insert(
                group_label.clone(),
                members
                    .into_iter()
                    .map(|member| member.member_id_hex)
                    .collect(),
            );
            let state = participant
                .runtime()?
                .group_mls_state(&participant.account_id, &group_id)
                .await
                .map_err(app_error)?;
            participant
                .cached_epochs
                .insert(group_label.clone(), state.epoch);
            drain_runtime_events(participant);
        }
        Ok(())
    }

    async fn accept_pending_invites(&self, clients: &[String]) -> Result<(), SubjectError> {
        let Some(group_label) = self.active_scenario_group.as_ref() else {
            return Ok(());
        };
        let Some(group_id) = self.scenario_groups.get(group_label) else {
            return Ok(());
        };
        let group_id_hex = hex::encode(group_id.as_slice());
        for label in clients {
            let participant = self.participant(label)?;
            if !participant.online {
                continue;
            }
            if participant
                .app
                .group(&participant.account_id, &group_id_hex)
                .map_err(app_error)?
                .is_some_and(|group| group.pending_confirmation)
            {
                accept_group_invite_retrying_busy(
                    participant.runtime()?,
                    &participant.account_id,
                    group_id,
                )
                .await
                .map_err(app_error)?;
            }
        }
        Ok(())
    }

    fn layered_observation(
        &mut self,
        client: &str,
    ) -> Result<AppRuntimeObservationV1, SubjectError> {
        let participant = self.participant(client)?;
        if !participant.online {
            return participant.offline_observation.clone().ok_or_else(|| {
                SubjectError::new(
                    "offline_observation_unavailable",
                    "no public projection was captured before the participant went offline",
                )
            });
        }
        let group_label = self.active_scenario_group.clone().ok_or_else(|| {
            SubjectError::new("scenario_group_missing", "no scenario group is selected")
        })?;
        let group_id = self.active_group()?;
        let participant_by_account = self
            .participants
            .iter()
            .map(|(label, participant)| (participant.account_id.clone(), label.clone()))
            .collect::<BTreeMap<_, _>>();
        let participant = self.participant_mut(client)?;
        drain_runtime_events(participant);
        let group_id_hex = hex::encode(group_id.as_slice());
        let group = participant
            .app
            .group(&participant.account_id, &group_id_hex)
            .map_err(app_error)?
            .ok_or_else(|| SubjectError::new("unknown_group", "group projection is missing"))?;
        let members = participant
            .cached_members
            .get(&group_label)
            .cloned()
            .unwrap_or_default();
        let mut members = members
            .into_iter()
            .map(|account| {
                participant_by_account
                    .get(&account)
                    .cloned()
                    .unwrap_or_else(|| opaque_public_identity(&account))
            })
            .collect::<Vec<_>>();
        members.sort();
        let mut admins = group
            .admin_policy
            .admins
            .iter()
            .map(|account| {
                participant_by_account
                    .get(account)
                    .cloned()
                    .unwrap_or_else(|| opaque_public_identity(account))
            })
            .collect::<Vec<_>>();
        admins.sort();
        let epoch = participant
            .cached_epochs
            .get(&group_label)
            .copied()
            .unwrap_or(group.nostr_routing_last_epoch);
        let protocol = public_protocol_projection(
            epoch,
            members,
            admins,
            group.profile.name.clone(),
            group.profile.description.clone(),
            group.member_count.unwrap_or_default() as usize,
        );
        let messages = participant
            .app
            .messages_with_query(
                &participant.account_id,
                AppMessageQuery {
                    group_id_hex: Some(group_id_hex),
                    kinds: None,
                    limit: None,
                },
            )
            .map_err(app_error)?;
        let mut visible = messages
            .iter()
            .filter(|message| !message.invalidated)
            .collect::<Vec<_>>();
        visible.sort_by(|left, right| left.message_id_hex.cmp(&right.message_id_hex));
        let mut invalidated = messages
            .iter()
            .filter(|message| message.invalidated)
            .map(|message| message.message_id_hex.clone())
            .collect::<Vec<_>>();
        invalidated.sort();
        let status = participant
            .app
            .status(&participant.account_id)
            .map_err(app_error)?;
        let database_bytes = std::fs::metadata(&status.projections.account.path)
            .ok()
            .map(|metadata| metadata.len());
        Ok(AppRuntimeObservationV1 {
            schema_version: APP_RUNTIME_OBSERVATION_SCHEMA_VERSION.into(),
            participant: client.into(),
            protocol,
            application: AppRuntimeApplicationProjectionV1 {
                visible_message_ids: visible
                    .iter()
                    .map(|message| message.message_id_hex.clone())
                    .collect(),
                visible_plaintexts: visible
                    .iter()
                    .filter(|message| {
                        message.kind == cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT
                    })
                    .map(|message| message.plaintext.clone())
                    .collect(),
                invalidated_message_ids: invalidated,
                pending_confirmation: group.pending_confirmation,
                stored_member_count: group.member_count,
                runtime_events_observed: participant.runtime_events_observed,
            },
            local: AppRuntimeLocalDiagnosticsV1 {
                online: participant.online,
                catch_up_attempts: participant.catch_up_attempts,
                reopen_count: participant.reopen_count,
                retryable_failures: participant.retryable_failures,
                terminal_failures: participant.terminal_failures,
                database_exists: status.projections.account.exists,
                database_encrypted: status.projections.account.encrypted,
                database_bytes,
                last_error_kind: participant.last_error_kind.clone(),
            },
        })
    }

    fn legacy_observations(
        &mut self,
        clients: &[String],
    ) -> Result<Vec<ClientObservation>, SubjectError> {
        clients
            .iter()
            .map(|client| {
                let layered = self.layered_observation(client)?;
                Ok(ClientObservation {
                    client: client.clone(),
                    epoch: layered.protocol.epoch,
                    member_count: layered.protocol.member_count,
                    group_name: layered.protocol.group_name,
                    group_description: layered.protocol.group_description,
                    canonical_state: None,
                    scenario_input_ledger: Vec::<ScenarioInputLedgerEntry>::new(),
                    pending_work: None,
                    event_counts: ClientEventCounts {
                        message_received: layered.application.visible_plaintexts.len(),
                        ..ClientEventCounts::default()
                    },
                    received_payloads: layered.application.visible_plaintexts,
                    added_members: Vec::new(),
                    removed_members: Vec::new(),
                    epoch_changes: Vec::new(),
                    app_invalidations: Vec::new(),
                    convergence_decisions: Vec::new(),
                })
            })
            .collect()
    }
}

#[async_trait]
impl ConvergenceSubject for AppRuntimeHarness {
    fn descriptor(&self) -> SubjectDescriptor {
        SubjectDescriptor {
            adapter: "marmot_app_runtime".into(),
            adapter_version: "1".into(),
            storage_backend: "sqlcipher_per_participant".into(),
            capabilities: BTreeSet::from([
                SubjectCapability::GroupMutation,
                SubjectCapability::ApplicationMessaging,
                SubjectCapability::TransportDelivery,
                SubjectCapability::EventObservation,
                SubjectCapability::AdminPolicyObservation,
                SubjectCapability::CrashReopen,
                SubjectCapability::OutboundPublication,
                SubjectCapability::ParticipantConnectivity,
                SubjectCapability::MultiGroup,
                SubjectCapability::RetainedRelayHistory,
                SubjectCapability::RetainedRelayControl,
            ]),
        }
    }

    fn database_bytes(&self) -> Option<u64> {
        Some(
            self.participants
                .values()
                .flat_map(|participant| walk_file_bytes(participant.root()))
                .fold(0_u64, u64::saturating_add),
        )
    }

    fn select_scenario_group(
        &mut self,
        group: &str,
        allow_create: bool,
    ) -> Result<(), SubjectError> {
        if !allow_create && !self.scenario_groups.contains_key(group) {
            return Err(SubjectError::new(
                "unknown_scenario_group",
                format!("scenario group {group} has not been created"),
            ));
        }
        self.active_scenario_group = Some(group.to_owned());
        Ok(())
    }

    async fn create_group(&mut self, action: SubjectCreateGroup<'_>) -> Result<(), SubjectError> {
        if !action.required_features.is_empty() {
            return Err(SubjectError::classified(
                SubjectFailureCategory::ExpectedRefusal,
                "unsupported_required_feature",
                "app-runtime adapter does not synthesize feature-gated key packages",
            ));
        }
        self.set_all_maintenance_paused(true).await?;
        let result = async {
            let before = self.relay_publication_cursor().await;
            let invitees = self.account_ids(action.invitees)?;
            let participant = self.participant(action.creator)?;
            let group_id = participant
                .runtime()?
                .create_group(&participant.account_id, action.name, &invitees, None)
                .await
                .map_err(app_error)?;
            let group_label = self
                .active_scenario_group
                .clone()
                .unwrap_or_else(|| "default".into());
            self.scenario_groups.insert(group_label, group_id.clone());
            let message_ids = self
                .apply_admin_set(action.creator, &group_id, action.initial_admins)
                .await?;
            self.record_relay_action_events(
                action.action_id,
                action.creator,
                before,
                true,
                action.invitees.len() + message_ids.len(),
                &message_ids,
            )
            .await
        }
        .await;
        let resume = self.set_all_maintenance_paused(false).await;
        match (result, resume) {
            (Err(error), _) | (Ok(()), Err(error)) => return Err(error),
            (Ok(()), Ok(())) => {}
        }
        self.record_accepted_publication(action.creator, action.pending);
        Ok(())
    }

    async fn invite_members(
        &mut self,
        action: SubjectInviteMembers<'_>,
    ) -> Result<(), SubjectError> {
        let before = self.relay_publication_cursor().await;
        let group_id = self.active_group()?;
        let invitees = self.account_ids(action.invitees)?;
        let participant = self.participant(action.inviter)?;
        let summary = participant
            .runtime()?
            .invite_members(&participant.account_id, &group_id, &invitees)
            .await
            .map_err(app_error)?;
        self.record_relay_action_events(
            action.action_id,
            action.inviter,
            before,
            true,
            summary.published,
            &summary.message_ids,
        )
        .await?;
        self.record_accepted_publication(action.inviter, action.pending);
        Ok(())
    }

    async fn update_group_data(
        &mut self,
        action: SubjectUpdateGroupData<'_>,
    ) -> Result<(), SubjectError> {
        let before = self.relay_publication_cursor().await;
        let group_id = self.active_group()?;
        let participant = self.participant(action.client)?;
        let summary = participant
            .runtime()?
            .update_group_profile(
                &participant.account_id,
                &group_id,
                action.name.map(str::to_owned),
                action.description.map(str::to_owned),
            )
            .await
            .map_err(app_error)?;
        self.record_relay_action_events(
            action.action_id,
            action.client,
            before,
            false,
            summary.published,
            &summary.message_ids,
        )
        .await?;
        self.record_accepted_publication(action.client, action.pending);
        Ok(())
    }

    async fn remove_members(
        &mut self,
        action: SubjectRemoveMembers<'_>,
    ) -> Result<(), SubjectError> {
        let before = self.relay_publication_cursor().await;
        let group_id = self.active_group()?;
        let members = self.account_ids(action.members)?;
        let participant = self.participant(action.remover)?;
        let summary = participant
            .runtime()?
            .remove_members(&participant.account_id, &group_id, &members)
            .await
            .map_err(app_error)?;
        self.record_relay_action_events(
            action.action_id,
            action.remover,
            before,
            false,
            summary.published,
            &summary.message_ids,
        )
        .await?;
        self.record_accepted_publication(action.remover, action.pending);
        Ok(())
    }

    async fn self_update(&mut self, action: SubjectSelfUpdate<'_>) -> Result<(), SubjectError> {
        let group_id = self.active_group()?;
        let participant = self.participant(action.client)?;
        participant
            .runtime()?
            .schedule_manual_self_update(&participant.account_id, &group_id)
            .await
            .map_err(app_error)?;
        self.record_accepted_publication(action.client, action.pending);
        Ok(())
    }

    async fn update_admin_policy(
        &mut self,
        action: SubjectUpdateAdminPolicy<'_>,
    ) -> Result<(), SubjectError> {
        let before = self.relay_publication_cursor().await;
        let group_id = self.active_group()?;
        let message_ids = self
            .apply_admin_set(action.client, &group_id, action.admins)
            .await?;
        if let Some(action_id) = action.action_id {
            self.record_relay_action_events(
                action_id,
                action.client,
                before,
                false,
                message_ids.len(),
                &message_ids,
            )
            .await?;
        }
        if let Some(pending) = action.pending {
            self.record_accepted_publication(action.client, pending);
        }
        Ok(())
    }

    fn scenario_publication_already_accepted(&self, client: &str, publication: &str) -> bool {
        self.accepted_publications
            .get(client)
            .is_some_and(|publications| publications.contains(publication))
    }

    fn poll_outbound(
        &mut self,
        _client: &str,
    ) -> Result<Vec<SubjectOutboundArtifact>, SubjectError> {
        // App commands publish before returning, so this adapter never has an
        // unresolved transport-ready artifact for the scenario runner.
        Ok(Vec::new())
    }

    async fn acknowledge_outbound(
        &mut self,
        client: &str,
        publication: &str,
        outcome: SubjectOutboundOutcome,
    ) -> Result<(), SubjectError> {
        if !self.scenario_publication_already_accepted(client, publication) {
            return Err(SubjectError::classified(
                SubjectFailureCategory::ExpectedRefusal,
                "publication_not_found",
                "the app runtime has no accepted publication with that label",
            ));
        }
        if outcome != SubjectOutboundOutcome::Accepted {
            return Err(SubjectError::classified(
                SubjectFailureCategory::ExpectedRefusal,
                "publication_rollback_rejected",
                "an app-runtime publication already accepted by transport cannot be rolled back",
            ));
        }
        Ok(())
    }

    async fn send_application(
        &mut self,
        action: SubjectSendApplication<'_>,
    ) -> Result<(), SubjectError> {
        self.set_all_maintenance_paused(true).await?;
        let result = async {
            let before = self.relay_publication_cursor().await;
            let group_id = self.active_group()?;
            let participant = self.participant(action.sender)?;
            let summary = participant
                .runtime()?
                .send_message(
                    &participant.account_id,
                    &group_id,
                    action.payload.as_bytes().to_vec(),
                )
                .await
                .map_err(app_error)?;
            self.record_relay_action_events(
                action.action_id,
                action.sender,
                before,
                false,
                summary.published,
                &[],
            )
            .await
        }
        .await;
        let resume = self.set_all_maintenance_paused(false).await;
        match (result, resume) {
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn leave(&mut self, action_id: &str, client: &str) -> Result<(), SubjectError> {
        let before = self.relay_publication_cursor().await;
        let group_id = self.active_group()?;
        let participant = self.participant(client)?;
        let summary = participant
            .runtime()?
            .leave_group(&participant.account_id, &group_id)
            .await
            .map_err(app_error)?;
        self.record_relay_action_events(
            action_id,
            client,
            before,
            false,
            summary.published,
            &summary.message_ids,
        )
        .await?;
        Ok(())
    }

    fn deliver_all(&mut self) -> Result<(), SubjectError> {
        block_on_subject(self.catch_up(&self.participants.keys().cloned().collect::<Vec<_>>()))
    }

    async fn tick(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        self.catch_up(clients).await?;
        self.accept_pending_invites(clients).await?;
        self.refresh_cached_members(clients).await
    }

    fn observe(&mut self, clients: &[String]) -> Result<Vec<ClientObservation>, SubjectError> {
        self.legacy_observations(clients)
    }

    fn observe_admin_policy(
        &self,
        clients: &[String],
    ) -> Result<Vec<ScenarioAdminPolicyObservation>, SubjectError> {
        let group_id = self.active_group()?;
        let group_id_hex = hex::encode(group_id.as_slice());
        clients
            .iter()
            .map(|client| {
                let participant = self.participant(client)?;
                let group = participant
                    .app
                    .group(&participant.account_id, &group_id_hex)
                    .map_err(app_error)?
                    .ok_or_else(|| {
                        SubjectError::new("unknown_group", "group projection is missing")
                    })?;
                let reverse = self
                    .participants
                    .iter()
                    .map(|(label, participant)| (participant.account_id.as_str(), label.as_str()))
                    .collect::<BTreeMap<_, _>>();
                let mut admins = group
                    .admin_policy
                    .admins
                    .iter()
                    .filter_map(|account| {
                        reverse
                            .get(account.as_str())
                            .map(|label| (*label).to_owned())
                    })
                    .collect::<Vec<_>>();
                admins.sort();
                Ok(ScenarioAdminPolicyObservation {
                    client: client.clone(),
                    admins,
                })
            })
            .collect()
    }

    fn clear_events(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        for client in clients {
            let participant = self.participant_mut(client)?;
            drain_runtime_events(participant);
            participant.runtime_events_observed = 0;
        }
        Ok(())
    }

    fn restart(&mut self, client: &str) -> Result<(), SubjectError> {
        block_on_subject(self.reopen(client))
    }

    fn set_client_online(&mut self, client: &str, online: bool) -> Result<(), SubjectError> {
        block_on_subject(self.set_online(client, online))
    }

    fn sync_relay_history(
        &mut self,
        clients: &[String],
        mode: &crate::ScenarioRelaySyncModeV2,
    ) -> Result<(), SubjectError> {
        match mode {
            crate::ScenarioRelaySyncModeV2::FullHistory
            | crate::ScenarioRelaySyncModeV2::SetReconciliation => {
                block_on_subject(self.repair_full_history(clients))
            }
            crate::ScenarioRelaySyncModeV2::Incremental
            | crate::ScenarioRelaySyncModeV2::Since { .. } => {
                block_on_subject(self.catch_up(clients))
            }
        }
    }

    fn set_relay_event_visibility(
        &mut self,
        relay: &str,
        selector: &crate::ScenarioMessageSelectorV2,
        clients: &[String],
        visible: bool,
    ) -> Result<(), SubjectError> {
        block_on_subject(self.set_shared_relay_event_presence(relay, selector, clients, visible))
    }
}

impl AppRuntimeHarness {
    async fn apply_admin_set(
        &self,
        actor: &str,
        group_id: &GroupId,
        target_labels: &[String],
    ) -> Result<Vec<String>, SubjectError> {
        let actor_participant = self.participant(actor)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let group = actor_participant
            .app
            .group(&actor_participant.account_id, &group_id_hex)
            .map_err(app_error)?
            .ok_or_else(|| SubjectError::new("unknown_group", "group projection is missing"))?;
        let targets = self
            .account_ids(target_labels)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let members = actor_participant
            .runtime()?
            .group_members(&actor_participant.account_id, group_id)
            .await
            .map_err(app_error)?
            .into_iter()
            .map(|member| member.member_id_hex)
            .collect::<BTreeSet<_>>();
        if targets.is_empty() || !targets.is_subset(&members) {
            return Err(SubjectError::classified(
                SubjectFailureCategory::ExpectedRefusal,
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
        let mut message_ids = Vec::new();
        for account_id in targets.difference(&current) {
            let summary = match actor_participant
                .runtime()?
                .promote_admin(&actor_participant.account_id, group_id, account_id)
                .await
            {
                Ok(summary) => summary,
                Err(error) => {
                    return Err(compensate_admin_changes(
                        actor_participant,
                        group_id,
                        &applied,
                        error,
                    )
                    .await);
                }
            };
            message_ids.extend(summary.message_ids);
            applied.push(AdminChange::Promoted(account_id.clone()));
        }
        for account_id in current
            .difference(&targets)
            .filter(|account_id| *account_id != &actor_participant.account_id)
        {
            let summary = match actor_participant
                .runtime()?
                .demote_admin(&actor_participant.account_id, group_id, account_id)
                .await
            {
                Ok(summary) => summary,
                Err(error) => {
                    return Err(compensate_admin_changes(
                        actor_participant,
                        group_id,
                        &applied,
                        error,
                    )
                    .await);
                }
            };
            message_ids.extend(summary.message_ids);
            applied.push(AdminChange::Demoted(account_id.clone()));
        }
        if current.contains(&actor_participant.account_id)
            && !targets.contains(&actor_participant.account_id)
        {
            let summary = match actor_participant
                .runtime()?
                .self_demote_admin(&actor_participant.account_id, group_id)
                .await
            {
                Ok(summary) => summary,
                Err(error) => {
                    return Err(compensate_admin_changes(
                        actor_participant,
                        group_id,
                        &applied,
                        error,
                    )
                    .await);
                }
            };
            message_ids.extend(summary.message_ids);
        }
        Ok(message_ids)
    }
}

enum AdminChange {
    Promoted(String),
    Demoted(String),
}

async fn compensate_admin_changes(
    actor: &Participant,
    group_id: &GroupId,
    applied: &[AdminChange],
    original: AppError,
) -> SubjectError {
    let Ok(runtime) = actor.runtime() else {
        return SubjectError::classified(
            SubjectFailureCategory::Environment,
            "admin_set_compensation_failed",
            "admin policy update failed after the participant runtime became unavailable",
        );
    };
    for change in applied.iter().rev() {
        let result = match change {
            AdminChange::Promoted(account) => {
                runtime
                    .demote_admin(&actor.account_id, group_id, account)
                    .await
            }
            AdminChange::Demoted(account) => {
                runtime
                    .promote_admin(&actor.account_id, group_id, account)
                    .await
            }
        };
        if result.is_err() {
            return SubjectError::classified(
                SubjectFailureCategory::Environment,
                "admin_set_compensation_failed",
                "admin policy update failed and its applied changes could not be fully compensated",
            );
        }
    }
    app_error(original)
}

fn app_for_root(root: &Path, relay_url: &str, settlement_quiescence_ms: Option<u64>) -> MarmotApp {
    let mut config = MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true);
    if let Some(ms) = settlement_quiescence_ms {
        config = config.with_dev_settlement_quiescence_ms(ms);
    }
    MarmotApp::with_relay_and_config(root, relay_url.to_owned(), config)
}

pub(crate) fn public_protocol_projection(
    epoch: u64,
    member_identities: Vec<String>,
    admin_identities: Vec<String>,
    group_name: String,
    group_description: String,
    member_count: usize,
) -> AppRuntimeProtocolProjectionV1 {
    #[derive(Serialize)]
    struct Commitment<'a> {
        epoch: u64,
        member_identities: &'a [String],
        admin_identities: &'a [String],
        group_name: &'a str,
        group_description: &'a str,
        member_count: usize,
    }
    let encoded = serde_json::to_vec(&Commitment {
        epoch,
        member_identities: &member_identities,
        admin_identities: &admin_identities,
        group_name: &group_name,
        group_description: &group_description,
        member_count,
    })
    .expect("public convergence commitment is serializable");
    AppRuntimeProtocolProjectionV1 {
        epoch,
        member_identities,
        admin_identities,
        group_name,
        group_description,
        member_count,
        state_commitment_sha256: hex::encode(Sha256::digest(encoded)),
    }
}

pub(crate) fn opaque_public_identity(account: &str) -> String {
    format!(
        "unknown:{}",
        &hex::encode(Sha256::digest(account.as_bytes()))[..16]
    )
}

fn drain_runtime_events(participant: &mut Participant) {
    let Some(events) = participant.events.as_mut() else {
        return;
    };
    while events.try_recv().is_ok() {
        participant.runtime_events_observed = participant.runtime_events_observed.saturating_add(1);
    }
}

pub(crate) async fn accept_group_invite_retrying_busy(
    runtime: &MarmotAppRuntime,
    account_ref: &str,
    group_id: &GroupId,
) -> Result<(), AppError> {
    const BUSY_RETRY_ATTEMPTS: usize = 500;
    const BUSY_RETRY_DELAY: Duration = Duration::from_millis(10);
    const ACCEPT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

    let mut last_retryable = AppError::AccountWorkerBusy;
    for attempt in 0..BUSY_RETRY_ATTEMPTS {
        match tokio::time::timeout(
            ACCEPT_ATTEMPT_TIMEOUT,
            runtime.accept_group_invite(account_ref, group_id),
        )
        .await
        {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(error @ (AppError::AccountWorkerBusy | AppError::UnknownGroup(_)))) => {
                last_retryable = error;
                if attempt + 1 < BUSY_RETRY_ATTEMPTS {
                    tokio::time::sleep(BUSY_RETRY_DELAY).await;
                }
            }
            Ok(Err(error)) => return Err(error),
            // This accept may have reached the worker, so its completion is
            // unknown. Never collapse that ambiguity into definitely-not-
            // started AccountWorkerBusy.
            Err(_) => return Err(AppError::AccountWorkerResponseTimedOut),
        }
    }

    // The fixed attempt budget was exhausted entirely by confirmed
    // definitely-not-started responses.
    Err(last_retryable)
}

fn record_failure(participant: &mut Participant, error: &AppError) {
    let kind = match error {
        AppError::AccountSessionBusy => "account_session_busy",
        AppError::AccountWorkerBusy => "account_worker_busy",
        AppError::AccountWorkerResponseTimedOut => "account_worker_response_timed_out",
        AppError::DirectConversationIndexNotReady => "direct_conversation_index_not_ready",
        AppError::RuntimeBusy => "runtime_busy",
        AppError::RuntimeStopping => "runtime_stopping",
        AppError::TransportClosed => "transport_closed",
        AppError::AccountCatchUp(_) => "account_catch_up",
        AppError::Publish(_) => "publish",
        AppError::Storage(_) | AppError::Sqlite(_) | AppError::SqlcipherKeyDerivation(_) => {
            "storage"
        }
        _ => "app_runtime_operation",
    }
    .to_owned();
    participant.last_error_kind = Some(kind);
    if matches!(
        error,
        AppError::AccountSessionBusy
            | AppError::AccountWorkerBusy
            | AppError::RuntimeBusy
            | AppError::TransportClosed
            | AppError::DirectConversationIndexNotReady
    ) {
        participant.retryable_failures = participant.retryable_failures.saturating_add(1);
    } else {
        participant.terminal_failures = participant.terminal_failures.saturating_add(1);
    }
}

fn app_error(error: AppError) -> SubjectError {
    let category = match error {
        AppError::RuntimeBusy
        | AppError::AccountSessionBusy
        | AppError::AccountWorkerBusy
        | AppError::AccountWorkerResponseTimedOut
        | AppError::DirectConversationIndexNotReady
        | AppError::RuntimeStopping
        | AppError::TransportClosed
        | AppError::AccountCatchUp(_)
        | AppError::RelayDirectory(_)
        | AppError::Publish(_)
        | AppError::BlobStore(_)
        | AppError::AuditLogUpload(_)
        | AppError::ExternalSignerUnavailable(_)
        | AppError::BlockingTask(_) => SubjectFailureCategory::Resource,
        AppError::Json(_)
        | AppError::Hex(_)
        | AppError::InvalidChatPin(_)
        | AppError::InvalidGroupMembershipPage(_)
        | AppError::InvalidCachedIdentityPage(_)
        | AppError::InvalidMessageDraft(_)
        | AppError::InvalidPublicKey
        | AppError::UnexpectedPrivateKey
        | AppError::IdentityKeyMismatch
        | AppError::InvalidKeyPackageEvent(_)
        | AppError::InvalidDirectorySearch(_)
        | AppError::InvalidGroupProfile(_)
        | AppError::InvalidNostrRouting(_)
        | AppError::InvalidGroupAvatarUrl(_)
        | AppError::InvalidAgentTextStreamPolicy(_)
        | AppError::InvalidEncryptedMedia(_)
        | AppError::UnsafeMediaFetch(_)
        | AppError::InvalidAppMessagePayload(_)
        | AppError::InvalidPushToken(_)
        | AppError::InvalidPushServer(_)
        | AppError::InvalidPushGossip(_)
        | AppError::InvalidRelayTelemetrySettings(_)
        | AppError::InvalidAuditLogFile(_)
        | AppError::AgentStreamInvalidCandidate(_) => SubjectFailureCategory::Protocol,
        AppError::MissingKeyPackage(_)
        | AppError::UnknownGroup(_)
        | AppError::GroupDisbanding(_)
        | AppError::AgentStreamMissingStart
        | AppError::AgentStreamStartNotConfirmed
        | AppError::AgentStreamUnsupportedRoute
        | AppError::AgentStreamMissingCandidate
        | AppError::MissingDefaultRelays
        | AppError::MissingRelayLists(_)
        | AppError::FollowListUnavailable
        | AppError::ExternalSignerMismatch
        | AppError::ExternalSignerRejected
        | AppError::MissingDirectoryEntry(_)
        | AppError::NotificationsDisabled
        | AppError::AccountSetupRecoveryRequired
        | AppError::AccountSetupRetryRequired
        | AppError::AccountSetupResetNotApplicable
        | AppError::AccountSetupKeyPackageRecoveryAvailable
        | AppError::ReactionNotFound => SubjectFailureCategory::ExpectedRefusal,
        AppError::Account(_)
        | AppError::AccountHome(_)
        | AppError::Session(_)
        | AppError::Storage(_)
        | AppError::Transport(_)
        | AppError::Io(_)
        | AppError::Sqlite(_)
        | AppError::CreatedGroupProjectionUnavailable(_)
        | AppError::SqlcipherKeyDerivation(_) => SubjectFailureCategory::Environment,
    };
    SubjectError::classified(
        category,
        "app_runtime_operation_failed",
        "application runtime operation failed",
    )
}

fn environment_error(error: impl std::fmt::Display) -> SubjectError {
    SubjectError::new("app_runtime_environment", error.to_string())
}

fn relay_control_error(error: RelayControlError) -> SubjectError {
    let category = match error.code {
        "relay_publication_cursor_invalid"
        | "relay_action_publication_timeout"
        | "relay_action_publication_count_mismatch"
        | "relay_action_publication_identity_mismatch"
        | "relay_action_publication_identity_count_mismatch" => SubjectFailureCategory::Environment,
        _ => SubjectFailureCategory::ExpectedRefusal,
    };
    SubjectError::classified(category, error.code, error.message)
}

fn block_on_subject<F>(future: F) -> Result<(), SubjectError>
where
    F: std::future::Future<Output = Result<(), SubjectError>>,
{
    let handle = tokio::runtime::Handle::try_current().map_err(|_| {
        SubjectError::classified(
            SubjectFailureCategory::Environment,
            "tokio_runtime_missing",
            "app-runtime adapter requires an active Tokio runtime",
        )
    })?;
    if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        return Err(SubjectError::classified(
            SubjectFailureCategory::ExpectedRefusal,
            "tokio_runtime_flavor_unsupported",
            "blocking app-runtime adapter operations require a multi-thread Tokio runtime",
        ));
    }
    tokio::task::block_in_place(|| handle.block_on(future))
}

fn walk_file_bytes(root: &Path) -> Vec<u64> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(walk_file_bytes(&path));
        } else if let Ok(metadata) = entry.metadata() {
            files.push(metadata.len());
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_commitment_preserves_a_reported_zero_member_count() {
        let projection = public_protocol_projection(
            7,
            vec!["alice".into()],
            vec!["alice".into()],
            "group".into(),
            "description".into(),
            0,
        );
        assert_eq!(projection.member_count, 0);
    }

    #[test]
    fn app_errors_are_classified_without_serializing_inner_details() {
        let marker = "private-storage-path";
        let environment = app_error(AppError::SqlcipherKeyDerivation(marker.into()));
        assert_eq!(environment.category, SubjectFailureCategory::Environment);
        assert!(!environment.message.contains(marker));

        let protocol = app_error(AppError::InvalidGroupProfile(marker.into()));
        assert_eq!(protocol.category, SubjectFailureCategory::Protocol);
        assert!(!protocol.message.contains(marker));

        let resource = app_error(AppError::RuntimeBusy);
        assert_eq!(resource.category, SubjectFailureCategory::Resource);
    }

    #[test]
    fn relay_publication_correlation_failures_are_environment_errors() {
        for code in [
            "relay_publication_cursor_invalid",
            "relay_action_publication_timeout",
            "relay_action_publication_count_mismatch",
            "relay_action_publication_identity_mismatch",
            "relay_action_publication_identity_count_mismatch",
        ] {
            let error = relay_control_error(RelayControlError {
                code,
                message: "normalized relay-control failure",
            });
            assert_eq!(error.code, code);
            assert_eq!(error.category, SubjectFailureCategory::Environment);
        }

        let expected_refusal = relay_control_error(RelayControlError {
            code: "unsupported_relay_selector",
            message: "normalized relay-control refusal",
        });
        assert_eq!(
            expected_refusal.category,
            SubjectFailureCategory::ExpectedRefusal
        );
    }
}
