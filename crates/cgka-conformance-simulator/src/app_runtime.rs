//! Black-box application-runtime adapter for convergence scenarios.
//!
//! This adapter deliberately uses only the public [`marmot_app::MarmotAppRuntime`]
//! command and projection surfaces. Exact cryptographic observations cross a
//! feature-gated, read-only app command that returns commitments but never raw
//! secrets or storage. Each participant owns a distinct restrictive root and
//! one SQLCipher database.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{GroupId, TransportEndpoint};
use marmot_app::{
    AccountSetupRequest, AppError, AppMessageQuery, MarmotApp, MarmotAppConfig, MarmotAppEvent,
    MarmotAppRuntime, SendSummary,
};
use nostr_relay_builder::MockRelay;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::broadcast;

use crate::{
    BidirectionalDecryptabilityObservation, ClientEventCounts, ClientObservation,
    ConformanceCanonicalStateSnapshot, ConvergenceSubject, DecryptabilityProbeSendStatus,
    DirectionalDecryptabilityProbe, ForkRecoveryObservation, ScenarioAdminPolicyObservation,
    ScenarioInputDisposition, ScenarioInputKind, ScenarioInputLedgerEntry, SubjectCapability,
    SubjectCreateGroup, SubjectDescriptor, SubjectError, SubjectFailureCategory,
    SubjectInviteMembers, SubjectRemoveMembers, SubjectSelfUpdate, SubjectSendApplication,
    SubjectUpdateAdminPolicy, SubjectUpdateGroupData,
};

pub const APP_RUNTIME_OBSERVATION_SCHEMA_VERSION: &str = "2";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRuntimeProtocolProjectionV1 {
    pub epoch: u64,
    pub member_identities: Vec<String>,
    pub admin_identities: Vec<String>,
    pub group_name: String,
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
    /// Feature-gated exact canonical state. It contains cryptographic
    /// commitments and public protocol state, never exporter secrets.
    pub canonical_state: ConformanceCanonicalStateSnapshot,
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
    cached_exact: BTreeMap<String, ConformanceCanonicalStateSnapshot>,
}

#[derive(Clone, Debug)]
struct AppRuntimeInputRecord {
    action_id: String,
    sender: String,
    payload: String,
    logical_id: Option<String>,
    origin_branch_id: Option<String>,
    origin_branch_unknown: bool,
    published: usize,
    failed: bool,
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
    _relay: MockRelay,
    relay_url: String,
    participants: BTreeMap<String, Participant>,
    scenario_groups: BTreeMap<String, GroupId>,
    scenario_group_members: BTreeMap<String, BTreeSet<String>>,
    active_scenario_group: Option<String>,
    application_inputs: BTreeMap<String, AppRuntimeInputRecord>,
}

impl AppRuntimeHarness {
    pub async fn new(clients: &[String]) -> Result<Self, SubjectError> {
        let relay = MockRelay::run().await.map_err(environment_error)?;
        let relay_url = relay.url().await.to_string();
        let endpoint = TransportEndpoint::from(relay_url.clone());
        let mut participants = BTreeMap::new();
        for client in clients {
            let root = tempfile::Builder::new()
                .prefix("marmot-app-conformance-")
                .tempdir()
                .map_err(environment_error)?;
            fs_private::create_dir_all_private(root.path()).map_err(environment_error)?;
            let app = app_for_root(root.path(), &relay_url);
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
                    cached_exact: BTreeMap::new(),
                },
            );
        }
        Ok(Self {
            _relay: relay,
            relay_url,
            participants,
            scenario_groups: BTreeMap::new(),
            scenario_group_members: BTreeMap::new(),
            active_scenario_group: None,
            application_inputs: BTreeMap::new(),
        })
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
            let participant = self.participant_mut(client)?;
            if let Some(runtime) = participant.runtime.take() {
                runtime.shutdown().await;
            }
            participant.events = None;
            participant.online = false;
            participant.cached_exact.clear();
            Ok(())
        }
    }

    pub async fn reopen(&mut self, client: &str) -> Result<(), SubjectError> {
        let relay_url = self.relay_url.clone();
        let participant = self.participant_mut(client)?;
        if participant.online
            && let Some(runtime) = participant.runtime.take()
        {
            runtime.shutdown().await;
        }
        participant.app = app_for_root(participant.root(), &relay_url);
        let runtime = MarmotAppRuntime::new(participant.app.clone());
        runtime.start().await.map_err(app_error)?;
        participant.events = Some(runtime.subscribe());
        participant.runtime = Some(runtime);
        participant.online = true;
        participant.cached_exact.clear();
        participant.reopen_count = participant.reopen_count.saturating_add(1);
        Ok(())
    }

    fn active_group_members(&self) -> Vec<String> {
        let tracked = self
            .active_scenario_group
            .as_ref()
            .and_then(|group| self.scenario_group_members.get(group))
            .map(|members| members.iter().cloned().collect());
        tracked.unwrap_or_else(|| self.participants.keys().cloned().collect())
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
            let exact = participant
                .runtime()?
                .conformance_canonical_state_snapshot(&participant.account_id, &group_id)
                .await
                .map_err(app_error)?;
            participant.cached_exact.insert(group_label.clone(), exact);
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
                participant
                    .runtime()?
                    .accept_group_invite(&participant.account_id, group_id)
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
        let canonical_state = participant
            .cached_exact
            .get(&group_label)
            .cloned()
            .ok_or_else(|| {
                SubjectError::new(
                    "exact_state_unavailable",
                    "exact app-runtime state has not been refreshed",
                )
            })?;
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
            group.member_count.unwrap_or_default() as usize,
        );
        let messages = participant
            .app
            .messages_with_query(
                &participant.account_id,
                AppMessageQuery {
                    group_id_hex: Some(group_id_hex),
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
            canonical_state,
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
                let scenario_input_ledger = self.application_ledger_for(&layered);
                Ok(ClientObservation {
                    client: client.clone(),
                    epoch: layered.protocol.epoch,
                    member_count: layered.protocol.member_count,
                    group_name: layered.protocol.group_name,
                    canonical_state: Some(layered.canonical_state.clone()),
                    scenario_input_ledger,
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
                    recoveries: Vec::<ForkRecoveryObservation>::new(),
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
                SubjectCapability::ParticipantConnectivity,
                SubjectCapability::MultiGroup,
                SubjectCapability::RetainedRelayHistory,
                SubjectCapability::ExactConformanceObservation,
                SubjectCapability::ActiveDecryptabilityProbe,
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
        self.scenario_groups
            .insert(group_label.clone(), group_id.clone());
        self.scenario_group_members.insert(
            group_label,
            std::iter::once(action.creator.to_owned())
                .chain(action.invitees.iter().map(|invitee| (*invitee).to_owned()))
                .collect(),
        );
        self.apply_admin_set(action.creator, &group_id, action.initial_admins)
            .await?;
        Ok(())
    }

    async fn invite_members(
        &mut self,
        action: SubjectInviteMembers<'_>,
    ) -> Result<(), SubjectError> {
        let group_id = self.active_group()?;
        let invitees = self.account_ids(action.invitees)?;
        let participant = self.participant(action.inviter)?;
        participant
            .runtime()?
            .invite_members(&participant.account_id, &group_id, &invitees)
            .await
            .map_err(app_error)?;
        if let Some(group) = &self.active_scenario_group {
            self.scenario_group_members
                .entry(group.clone())
                .or_default()
                .extend(action.invitees.iter().map(|invitee| (*invitee).to_owned()));
        }
        Ok(())
    }

    async fn update_group_data(
        &mut self,
        action: SubjectUpdateGroupData<'_>,
    ) -> Result<(), SubjectError> {
        let group_id = self.active_group()?;
        let participant = self.participant(action.client)?;
        participant
            .runtime()?
            .update_group_profile(
                &participant.account_id,
                &group_id,
                Some(action.name.into()),
                None,
            )
            .await
            .map_err(app_error)?;
        Ok(())
    }

    async fn remove_members(
        &mut self,
        action: SubjectRemoveMembers<'_>,
    ) -> Result<(), SubjectError> {
        let group_id = self.active_group()?;
        let members = self.account_ids(action.members)?;
        let participant = self.participant(action.remover)?;
        participant
            .runtime()?
            .remove_members(&participant.account_id, &group_id, &members)
            .await
            .map_err(app_error)?;
        if let Some(group) = &self.active_scenario_group
            && let Some(current) = self.scenario_group_members.get_mut(group)
        {
            for member in action.members {
                current.remove(member);
            }
        }
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
        Ok(())
    }

    async fn update_admin_policy(
        &mut self,
        action: SubjectUpdateAdminPolicy<'_>,
    ) -> Result<(), SubjectError> {
        let group_id = self.active_group()?;
        self.apply_admin_set(action.client, &group_id, action.admins)
            .await
    }

    async fn send_application(
        &mut self,
        action: SubjectSendApplication<'_>,
    ) -> Result<(), SubjectError> {
        self.send_application_input(action.action_id, action.sender, action.payload)
            .await
            .map(|_| ())
    }

    async fn leave(&mut self, _action_id: &str, client: &str) -> Result<(), SubjectError> {
        let group_id = self.active_group()?;
        let participant = self.participant(client)?;
        participant
            .runtime()?
            .leave_group(&participant.account_id, &group_id)
            .await
            .map_err(app_error)?;
        if let Some(group) = &self.active_scenario_group
            && let Some(current) = self.scenario_group_members.get_mut(group)
        {
            current.remove(client);
        }
        Ok(())
    }

    fn deliver_all(&mut self) -> Result<(), SubjectError> {
        block_on_subject(self.catch_up(&self.active_group_members()))
    }

    async fn tick(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        self.catch_up(clients).await?;
        self.accept_pending_invites(clients).await?;
        self.refresh_cached_members(clients).await
    }

    async fn advance_time(&mut self, delta_ms: u64) -> Result<(), SubjectError> {
        tokio::time::sleep(Duration::from_millis(delta_ms)).await;
        Ok(())
    }

    fn observe(&mut self, clients: &[String]) -> Result<Vec<ClientObservation>, SubjectError> {
        self.legacy_observations(clients)
    }

    fn observe_exact(
        &mut self,
        clients: &[String],
    ) -> Result<Vec<ClientObservation>, SubjectError> {
        self.legacy_observations(clients)
    }

    async fn probe_bidirectional_decryptability(
        &mut self,
        clients: &[String],
        step_index: usize,
    ) -> Result<BidirectionalDecryptabilityObservation, SubjectError> {
        let unique = clients.iter().collect::<BTreeSet<_>>();
        if clients.len() < 2 || unique.len() != clients.len() {
            return Err(SubjectError::new(
                "invalid_probe_clients",
                "bidirectional decryptability probe requires at least two unique clients",
            ));
        }
        let mut sends = BTreeMap::new();
        for sender in clients {
            self.participant(sender)?;
            let action_id = format!("probe-{step_index}-{sender}");
            let payload = format!("cgka-decryptability-probe/v1/{step_index}/{sender}");
            let result = self
                .send_application_input(&action_id, sender, &payload)
                .await;
            let status = match result {
                Ok(summary) => (
                    DecryptabilityProbeSendStatus::Published,
                    summary.message_ids.first().cloned(),
                ),
                Err(error) => (
                    DecryptabilityProbeSendStatus::Failed { error: error.code },
                    None,
                ),
            };
            sends.insert(sender.clone(), (action_id, payload, status));
        }
        self.catch_up(&self.active_group_members()).await?;
        let observations = self.legacy_observations(clients)?;
        let by_client = observations
            .into_iter()
            .map(|observation| (observation.client.clone(), observation))
            .collect::<BTreeMap<_, _>>();
        let mut probes = Vec::with_capacity(clients.len() * (clients.len() - 1));
        for sender in clients {
            let (action_id, payload, (send_status, logical_id)) = &sends[sender];
            for recipient in clients {
                if sender == recipient {
                    continue;
                }
                let recipient_ledger = by_client[recipient]
                    .scenario_input_ledger
                    .iter()
                    .find(|entry| entry.scenario_id == *action_id)
                    .cloned();
                probes.push(DirectionalDecryptabilityProbe {
                    sender: sender.clone(),
                    recipient: recipient.clone(),
                    payload: payload.clone(),
                    logical_id: logical_id.clone(),
                    send_status: send_status.clone(),
                    recipient_ledger,
                });
            }
        }
        Ok(BidirectionalDecryptabilityObservation {
            step_index,
            clients: clients.to_vec(),
            probes,
        })
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
}

impl AppRuntimeHarness {
    async fn send_application_input(
        &mut self,
        action_id: &str,
        sender: &str,
        payload: &str,
    ) -> Result<SendSummary, SubjectError> {
        let group_id = self.active_group()?;
        let participant = self.participant(sender)?;
        let result = participant
            .runtime()?
            .send_message(
                &participant.account_id,
                &group_id,
                payload.as_bytes().to_vec(),
            )
            .await;
        match result {
            Ok(summary) => {
                let (origin_branch_id, origin_branch_unknown) = match participant
                    .runtime()?
                    .conformance_canonical_state_snapshot(&participant.account_id, &group_id)
                    .await
                {
                    Ok(snapshot) => (canonical_branch_id(snapshot), false),
                    Err(_) => (None, true),
                };
                self.application_inputs.insert(
                    action_id.to_owned(),
                    AppRuntimeInputRecord {
                        action_id: action_id.to_owned(),
                        sender: sender.to_owned(),
                        payload: payload.to_owned(),
                        logical_id: summary.message_ids.first().cloned(),
                        origin_branch_id,
                        origin_branch_unknown,
                        published: summary.published,
                        failed: false,
                    },
                );
                Ok(summary)
            }
            Err(error) => {
                self.application_inputs.insert(
                    action_id.to_owned(),
                    AppRuntimeInputRecord {
                        action_id: action_id.to_owned(),
                        sender: sender.to_owned(),
                        payload: payload.to_owned(),
                        logical_id: None,
                        origin_branch_id: None,
                        origin_branch_unknown: false,
                        published: 0,
                        failed: true,
                    },
                );
                Err(app_error(error))
            }
        }
    }

    fn application_ledger_for(
        &self,
        observation: &AppRuntimeObservationV1,
    ) -> Vec<ScenarioInputLedgerEntry> {
        let projection = &observation.application;
        let current_branch_id = canonical_branch_id(observation.canonical_state.clone());
        self.application_inputs
            .values()
            .map(|input| {
                let visible = input.logical_id.as_ref().is_some_and(|id| {
                    projection
                        .visible_message_ids
                        .iter()
                        .any(|value| value == id)
                });
                let invalidated = input.logical_id.as_ref().is_some_and(|id| {
                    projection
                        .invalidated_message_ids
                        .iter()
                        .any(|value| value == id)
                });
                let (disposition, pending, delivered, rejected, invalidations) = if input.failed {
                    (
                        ScenarioInputDisposition::Rejected,
                        false,
                        0,
                        1,
                        vec!["app_runtime_send_failed".into()],
                    )
                } else if input.origin_branch_unknown {
                    (ScenarioInputDisposition::Deferred, true, 0, 0, Vec::new())
                } else if invalidated
                    || input.origin_branch_id.is_some()
                        && input.origin_branch_id != current_branch_id
                {
                    (
                        ScenarioInputDisposition::Invalidated,
                        false,
                        0,
                        0,
                        vec!["fork_recovery".into()],
                    )
                } else if visible {
                    (ScenarioInputDisposition::Delivered, false, 1, 0, Vec::new())
                } else {
                    (ScenarioInputDisposition::Deferred, true, 0, 0, Vec::new())
                };
                ScenarioInputLedgerEntry {
                    scenario_id: input.action_id.clone(),
                    kind: ScenarioInputKind::Application,
                    sender: input.sender.clone(),
                    logical_id: input.logical_id.clone(),
                    payload: input.payload.clone(),
                    disposition,
                    send_attempts: 1,
                    send_accepted: usize::from(!input.failed),
                    send_queued: 0,
                    blocked_send_duration_us: 0,
                    published: input.published,
                    ingest_attempts: usize::from(visible || invalidated),
                    ingest_accepted: usize::from(visible),
                    transport_deferred: usize::from(!input.failed && !visible && !invalidated),
                    resource_refused: 0,
                    ignored: 0,
                    local_state: 0,
                    rejected,
                    ingest_errors: usize::from(input.origin_branch_unknown),
                    delivered,
                    deduplicated: 0,
                    expired: 0,
                    invalidated: invalidations,
                    pending,
                }
            })
            .collect()
    }

    async fn apply_admin_set(
        &self,
        actor: &str,
        group_id: &GroupId,
        target_labels: &[String],
    ) -> Result<(), SubjectError> {
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
        for account_id in targets.difference(&current) {
            if let Err(error) = actor_participant
                .runtime()?
                .promote_admin(&actor_participant.account_id, group_id, account_id)
                .await
            {
                return Err(
                    compensate_admin_changes(actor_participant, group_id, &applied, error).await,
                );
            }
            applied.push(AdminChange::Promoted(account_id.clone()));
        }
        for account_id in current
            .difference(&targets)
            .filter(|account_id| *account_id != &actor_participant.account_id)
        {
            if let Err(error) = actor_participant
                .runtime()?
                .demote_admin(&actor_participant.account_id, group_id, account_id)
                .await
            {
                return Err(
                    compensate_admin_changes(actor_participant, group_id, &applied, error).await,
                );
            }
            applied.push(AdminChange::Demoted(account_id.clone()));
        }
        if current.contains(&actor_participant.account_id)
            && !targets.contains(&actor_participant.account_id)
            && let Err(error) = actor_participant
                .runtime()?
                .self_demote_admin(&actor_participant.account_id, group_id)
                .await
        {
            return Err(
                compensate_admin_changes(actor_participant, group_id, &applied, error).await,
            );
        }
        Ok(())
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

fn canonical_branch_id(state: ConformanceCanonicalStateSnapshot) -> Option<String> {
    match state {
        ConformanceCanonicalStateSnapshot::Live(snapshot) => Some(snapshot.selected_branch_id),
        ConformanceCanonicalStateSnapshot::Disbanded(_) => None,
    }
}

fn app_for_root(root: &Path, relay_url: &str) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        root,
        relay_url.to_owned(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    )
}

pub(crate) fn public_protocol_projection(
    epoch: u64,
    member_identities: Vec<String>,
    admin_identities: Vec<String>,
    group_name: String,
    member_count: usize,
) -> AppRuntimeProtocolProjectionV1 {
    #[derive(Serialize)]
    struct Commitment<'a> {
        epoch: u64,
        member_identities: &'a [String],
        admin_identities: &'a [String],
        group_name: &'a str,
        member_count: usize,
    }
    let encoded = serde_json::to_vec(&Commitment {
        epoch,
        member_identities: &member_identities,
        admin_identities: &admin_identities,
        group_name: &group_name,
        member_count,
    })
    .expect("public convergence commitment is serializable");
    AppRuntimeProtocolProjectionV1 {
        epoch,
        member_identities,
        admin_identities,
        group_name,
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

fn record_failure(participant: &mut Participant, error: &AppError) {
    let kind = match error {
        AppError::AccountSessionBusy => "account_session_busy",
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
        AppError::AccountSessionBusy | AppError::RuntimeBusy | AppError::TransportClosed
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
        | AppError::ReactionNotFound => SubjectFailureCategory::ExpectedRefusal,
        AppError::Account(_)
        | AppError::AccountHome(_)
        | AppError::Session(_)
        | AppError::Storage(_)
        | AppError::Transport(_)
        | AppError::Io(_)
        | AppError::Sqlite(_)
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

    #[tokio::test]
    async fn offline_state_is_not_cached_and_untracked_delivery_targets_every_participant() {
        let clients = vec!["alice".to_owned(), "bob".to_owned()];
        let mut harness = AppRuntimeHarness::new(&clients).await.unwrap();
        assert_eq!(harness.active_group_members(), clients);
        assert!(
            !harness
                .descriptor()
                .capabilities
                .contains(&SubjectCapability::VirtualTime)
        );

        harness.application_inputs.insert(
            "step-1:send_application@main".into(),
            AppRuntimeInputRecord {
                action_id: "step-1:send_application@main".into(),
                sender: "alice".into(),
                payload: "payload".into(),
                logical_id: Some("message".into()),
                origin_branch_id: None,
                origin_branch_unknown: true,
                published: 1,
                failed: false,
            },
        );
        let ledger = harness.application_ledger_for(&AppRuntimeObservationV1 {
            schema_version: APP_RUNTIME_OBSERVATION_SCHEMA_VERSION.into(),
            participant: "alice".into(),
            protocol: AppRuntimeProtocolProjectionV1 {
                epoch: 1,
                member_identities: Vec::new(),
                admin_identities: Vec::new(),
                group_name: "group".into(),
                member_count: 1,
                state_commitment_sha256: "commitment".into(),
            },
            canonical_state: ConformanceCanonicalStateSnapshot::Live(Box::default()),
            application: AppRuntimeApplicationProjectionV1 {
                visible_message_ids: Vec::new(),
                visible_plaintexts: Vec::new(),
                invalidated_message_ids: Vec::new(),
                pending_confirmation: false,
                stored_member_count: Some(1),
                runtime_events_observed: 0,
            },
            local: AppRuntimeLocalDiagnosticsV1 {
                online: true,
                catch_up_attempts: 0,
                reopen_count: 0,
                retryable_failures: 0,
                terminal_failures: 0,
                database_exists: true,
                database_encrypted: true,
                database_bytes: None,
                last_error_kind: None,
            },
        });
        assert_eq!(ledger[0].disposition, ScenarioInputDisposition::Deferred);
        assert_eq!(ledger[0].ingest_errors, 1);

        harness
            .participants
            .get_mut("alice")
            .unwrap()
            .cached_exact
            .insert(
                "main".into(),
                ConformanceCanonicalStateSnapshot::Live(Box::default()),
            );
        harness.set_online("alice", false).await.unwrap();
        assert!(
            harness.participants["alice"].cached_exact.is_empty(),
            "offline observations must not reuse an earlier exact snapshot"
        );
        harness.set_online("bob", false).await.unwrap();
    }
}
