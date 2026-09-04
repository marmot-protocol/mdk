//! Deterministic retained multi-relay adapter over the real engine subject.
//!
//! Engine emissions are removed from the fast packet bus after capture and
//! persisted in relay-specific histories. Participant delivery is driven by
//! explicit history queries, so offline recovery comes from retained events
//! rather than healing a packet-loss partition.

use crate::{
    BidirectionalDecryptabilityObservation, ClientObservation, ConvergenceSubject,
    EngineHarnessSubject, HarnessStorageMode, ScenarioAdminPolicyObservation,
    ScenarioMessageSelectorV2, ScenarioPredicateObservationV2, ScenarioPredicateV2,
    ScenarioRelayV2, ScenarioTopologyV2, ScenarioTransportClass, SubjectCapability,
    SubjectCreateGroup, SubjectDescriptor, SubjectError, SubjectFailureCategory,
    SubjectInviteMembers, SubjectOutboundArtifact, SubjectOutboundKind, SubjectOutboundOutcome,
    SubjectProgressSnapshot, SubjectRemoveMembers, SubjectSelfUpdate, SubjectSendApplication,
    SubjectUpdateAdminPolicy, SubjectUpdateGroupData,
};
use async_trait::async_trait;
use cgka_traits::group::ProtocolProfile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

const DEFAULT_RELAY_ID: &str = "relay:retained-default";
const MAX_REDELIVERY_NO_PROGRESS_TURNS: usize = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioRelayOrderV2 {
    #[default]
    Natural,
    Reverse,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ScenarioRelaySyncModeV2 {
    #[default]
    Incremental,
    Since {
        timestamp: u64,
    },
    FullHistory,
    SetReconciliation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayHistoryCompletenessClaimV2 {
    NotAttempted,
    RelayEoseOnly,
    FullHistoryQueried,
    RelevantSetMismatch,
    RelevantSetEqualityVerified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaySyncObservationV2 {
    pub client: String,
    pub mode: ScenarioRelaySyncModeV2,
    pub queried_relays: Vec<String>,
    pub eose_relays: Vec<String>,
    pub events_returned: usize,
    pub unique_events_returned: usize,
    pub injected_objects: usize,
    pub quiet: bool,
    pub completeness: RelayHistoryCompletenessClaimV2,
}

#[derive(Clone, Debug)]
struct RetainedRelayEvent {
    sequence: u64,
    artifact: SubjectOutboundArtifact,
    action_id: Option<String>,
    class: ScenarioTransportClass,
    hidden_from: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct RetainedRelay {
    history: Vec<RetainedRelayEvent>,
    next_sequence: u64,
    order: ScenarioRelayOrderV2,
    duplicate_copies: usize,
}

impl Default for RetainedRelay {
    fn default() -> Self {
        Self {
            history: Vec::new(),
            next_sequence: 0,
            order: ScenarioRelayOrderV2::Natural,
            duplicate_copies: 1,
        }
    }
}

/// Production-engine adapter with deterministic retained relay histories.
pub struct RetainedRelaySubject {
    descriptor: SubjectDescriptor,
    engine: EngineHarnessSubject,
    clients: Vec<String>,
    client_relays: BTreeMap<String, Vec<String>>,
    online: BTreeSet<String>,
    relays: BTreeMap<String, RetainedRelay>,
    cursors: BTreeMap<(String, String), u64>,
    published_outbound: BTreeSet<String>,
    action_ids: BTreeMap<String, String>,
    semantic_classes: BTreeMap<String, ScenarioTransportClass>,
    sync_observations: Vec<RelaySyncObservationV2>,
    capacity_refused_redelivery: BTreeMap<String, usize>,
    redelivery_no_progress_turns: BTreeMap<String, usize>,
}

impl RetainedRelaySubject {
    pub fn new(
        clients: &[String],
        topology: &ScenarioTopologyV2,
        protocol_profile: ProtocolProfile,
        storage_mode: HarnessStorageMode,
    ) -> Result<Self, SubjectError> {
        Self::new_with_deferred_peel_limits(clients, topology, protocol_profile, storage_mode, None)
    }

    #[cfg(feature = "test-policy-overrides")]
    pub fn new_with_deferred_peel_limits_for_tests(
        clients: &[String],
        topology: &ScenarioTopologyV2,
        protocol_profile: ProtocolProfile,
        storage_mode: HarnessStorageMode,
        rows_per_group: usize,
        bytes_per_group: usize,
        bytes_per_account: usize,
    ) -> Result<Self, SubjectError> {
        Self::new_with_deferred_peel_limits(
            clients,
            topology,
            protocol_profile,
            storage_mode,
            Some((rows_per_group, bytes_per_group, bytes_per_account)),
        )
    }

    fn new_with_deferred_peel_limits(
        clients: &[String],
        topology: &ScenarioTopologyV2,
        protocol_profile: ProtocolProfile,
        storage_mode: HarnessStorageMode,
        deferred_peel_limits: Option<(usize, usize, usize)>,
    ) -> Result<Self, SubjectError> {
        let mut resolved = topology
            .resolve_for_clients(clients)
            .map_err(|error| SubjectError::new("scenario_topology_error", error.message))?;
        if resolved.relays.is_empty() {
            resolved.relays.push(ScenarioRelayV2 {
                id: DEFAULT_RELAY_ID.into(),
                implementation_version: "retained-memory/v1".into(),
                policy_version: "retain-all/v1".into(),
            });
            for process in &mut resolved.processes {
                process.relays = vec![DEFAULT_RELAY_ID.into()];
            }
        }

        let process_relays = resolved
            .processes
            .iter()
            .map(|process| (process.id.clone(), process.relays.clone()))
            .collect::<BTreeMap<_, _>>();
        let client_relays = resolved
            .devices
            .iter()
            .map(|device| {
                (
                    device.client.clone(),
                    process_relays
                        .get(&device.process)
                        .cloned()
                        .unwrap_or_default(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let relays = resolved
            .relays
            .iter()
            .map(|relay| (relay.id.clone(), RetainedRelay::default()))
            .collect::<BTreeMap<_, _>>();
        #[cfg(feature = "test-policy-overrides")]
        let engine = if let Some((rows, group_bytes, account_bytes)) = deferred_peel_limits {
            EngineHarnessSubject::new_with_deferred_peel_limits_for_tests(
                clients,
                topology,
                protocol_profile,
                storage_mode,
                rows,
                group_bytes,
                account_bytes,
            )?
        } else {
            EngineHarnessSubject::new_with_topology(
                clients,
                topology,
                protocol_profile,
                storage_mode,
            )?
        };
        #[cfg(not(feature = "test-policy-overrides"))]
        let engine = {
            let _ = deferred_peel_limits;
            EngineHarnessSubject::new_with_topology(
                clients,
                topology,
                protocol_profile,
                storage_mode,
            )?
        };
        let mut capabilities = engine.descriptor().capabilities;
        capabilities.retain(|capability| {
            !matches!(
                capability,
                SubjectCapability::WhiteBoxTransportPartition
                    | SubjectCapability::SemanticTransportFaults
            )
        });
        capabilities.extend([
            SubjectCapability::ParticipantConnectivity,
            SubjectCapability::RetainedRelayHistory,
            SubjectCapability::RetainedRelayControl,
        ]);
        Ok(Self {
            descriptor: SubjectDescriptor {
                adapter: "mdk-engine-retained-relays".into(),
                adapter_version: "1".into(),
                storage_backend: storage_mode.report_label().into(),
                capabilities,
            },
            engine,
            clients: clients.to_vec(),
            client_relays,
            online: clients.iter().cloned().collect(),
            relays,
            cursors: BTreeMap::new(),
            published_outbound: BTreeSet::new(),
            action_ids: BTreeMap::new(),
            semantic_classes: BTreeMap::new(),
            sync_observations: Vec::new(),
            capacity_refused_redelivery: BTreeMap::new(),
            redelivery_no_progress_turns: BTreeMap::new(),
        })
    }

    /// Bounded append-only transport evidence captured by the wrapped engine
    /// subject. Generated retained-history campaigns use this for the same
    /// failure-capsule diagnostics as packet-bus campaigns.
    pub fn captured_transport_window(&self) -> crate::CapturedTransportWindowV1 {
        self.engine.captured_transport_window()
    }

    fn unresolved_ids(&mut self, client: &str) -> Result<BTreeSet<String>, SubjectError> {
        Ok(self
            .engine
            .poll_outbound(client)?
            .into_iter()
            .map(|artifact| artifact.outbound_id)
            .collect())
    }

    fn tag_new_outbound(
        &mut self,
        client: &str,
        before: &BTreeSet<String>,
        action_id: &str,
        class: ScenarioTransportClass,
    ) -> Result<(), SubjectError> {
        for artifact in self.engine.poll_outbound(client)? {
            if !before.contains(&artifact.outbound_id) {
                self.action_ids
                    .insert(artifact.outbound_id.clone(), action_id.into());
                self.semantic_classes.insert(artifact.outbound_id, class);
            }
        }
        Ok(())
    }

    fn class_for(&self, artifact: &SubjectOutboundArtifact) -> ScenarioTransportClass {
        if artifact.kind == SubjectOutboundKind::Welcome {
            ScenarioTransportClass::Welcome
        } else {
            self.semantic_classes
                .get(&artifact.outbound_id)
                .copied()
                .unwrap_or(ScenarioTransportClass::GroupMessage)
        }
    }

    fn validate_publish_destination(
        &self,
        artifact: &SubjectOutboundArtifact,
    ) -> Result<(), SubjectError> {
        let relay_ids = self
            .client_relays
            .get(&artifact.client)
            .cloned()
            .unwrap_or_default();
        if relay_ids.is_empty() {
            return Err(SubjectError::new(
                "no_publish_relays",
                format!(
                    "client {} has no configured publish relays",
                    artifact.client
                ),
            ));
        }
        for relay_id in relay_ids {
            if !self.relays.contains_key(&relay_id) {
                return Err(SubjectError::new(
                    "unknown_relay",
                    format!("unknown relay {relay_id}"),
                ));
            }
        }
        Ok(())
    }

    fn publish_artifact(&mut self, artifact: SubjectOutboundArtifact) {
        if !self.published_outbound.insert(artifact.outbound_id.clone()) {
            return;
        }
        let relay_ids = self
            .client_relays
            .get(&artifact.client)
            .cloned()
            .expect("publish destination validated before acknowledgement");
        let action_id = self.action_ids.get(&artifact.outbound_id).cloned();
        let class = self.class_for(&artifact);
        for relay_id in relay_ids {
            let relay = self
                .relays
                .get_mut(&relay_id)
                .expect("publish relay validated before acknowledgement");
            let sequence = relay.next_sequence;
            relay.next_sequence = relay.next_sequence.saturating_add(1);
            relay.history.push(RetainedRelayEvent {
                sequence,
                artifact: artifact.clone(),
                action_id: action_id.clone(),
                class,
                hidden_from: BTreeSet::new(),
            });
        }
    }

    fn sync_one(
        &mut self,
        client: &str,
        mode: &ScenarioRelaySyncModeV2,
    ) -> Result<(), SubjectError> {
        if !self.online.contains(client) {
            return Err(SubjectError::new(
                "client_offline",
                format!("cannot query relay history for offline client {client}"),
            ));
        }
        let relay_ids = self.client_relays.get(client).cloned().unwrap_or_default();
        let sets_equal = relay_history_sets_equal(&relay_ids, &self.relays);
        let mut returned = Vec::new();
        for relay_id in &relay_ids {
            let relay = self.relays.get(relay_id).ok_or_else(|| {
                SubjectError::new("unknown_relay", format!("unknown relay {relay_id}"))
            })?;
            let cursor = self
                .cursors
                .get(&(client.to_owned(), relay_id.clone()))
                .copied();
            let mut events = relay
                .history
                .iter()
                .filter(|event| match mode {
                    ScenarioRelaySyncModeV2::Incremental => {
                        cursor.is_none_or(|cursor| event.sequence > cursor)
                    }
                    ScenarioRelaySyncModeV2::Since { timestamp } => {
                        event.artifact.message.timestamp.0 >= *timestamp
                    }
                    ScenarioRelaySyncModeV2::FullHistory
                    | ScenarioRelaySyncModeV2::SetReconciliation => true,
                })
                .cloned()
                .collect::<Vec<_>>();
            if relay.order == ScenarioRelayOrderV2::Reverse {
                events.reverse();
            }
            for event in events {
                if !event.hidden_from.contains(client) {
                    for _ in 0..relay.duplicate_copies {
                        returned.push(event.clone());
                    }
                }
            }
            // A timestamp-floor query is an independent backfill view. It must
            // not consume the incremental cursor for events below that floor.
            if !matches!(mode, ScenarioRelaySyncModeV2::Since { .. })
                && let Some(last_sequence) = relay.history.last().map(|event| event.sequence)
            {
                self.cursors
                    .insert((client.to_owned(), relay_id.clone()), last_sequence);
            }
        }

        let unique_events_returned = returned
            .iter()
            .map(|event| event.artifact.message.id.as_slice().to_vec())
            .collect::<HashSet<_>>()
            .len();
        let events_returned = returned.len();
        let mut injected_objects = 0_usize;
        for event in returned {
            if event.artifact.client == client {
                continue;
            }
            self.engine
                .inject_transport_for_client(client, event.artifact.message.clone())?;
            injected_objects = injected_objects.saturating_add(1);
        }
        let completeness = match mode {
            ScenarioRelaySyncModeV2::Incremental | ScenarioRelaySyncModeV2::Since { .. } => {
                RelayHistoryCompletenessClaimV2::RelayEoseOnly
            }
            ScenarioRelaySyncModeV2::FullHistory => {
                RelayHistoryCompletenessClaimV2::FullHistoryQueried
            }
            ScenarioRelaySyncModeV2::SetReconciliation if sets_equal => {
                RelayHistoryCompletenessClaimV2::RelevantSetEqualityVerified
            }
            ScenarioRelaySyncModeV2::SetReconciliation => {
                RelayHistoryCompletenessClaimV2::RelevantSetMismatch
            }
        };
        self.sync_observations.push(RelaySyncObservationV2 {
            client: client.into(),
            mode: mode.clone(),
            queried_relays: relay_ids.clone(),
            eose_relays: relay_ids,
            events_returned,
            unique_events_returned,
            injected_objects,
            quiet: events_returned == 0,
            completeness,
        });
        Ok(())
    }

    fn event_matches(event: &RetainedRelayEvent, selector: &ScenarioMessageSelectorV2) -> bool {
        selector
            .action_id
            .as_ref()
            .is_none_or(|action_id| event.action_id.as_ref() == Some(action_id))
            && selector
                .publication
                .as_ref()
                .is_none_or(|publication| event.artifact.publication.as_ref() == Some(publication))
            && selector
                .sender
                .as_ref()
                .is_none_or(|sender| event.artifact.client == *sender)
            && selector.class.is_none_or(|class| {
                class == event.class
                    || (class == ScenarioTransportClass::GroupMessage
                        && event.artifact.kind == SubjectOutboundKind::GroupMessage)
            })
    }
}

fn relay_history_sets_equal(
    relay_ids: &[String],
    relays: &BTreeMap<String, RetainedRelay>,
) -> bool {
    let mut sets = relay_ids.iter().filter_map(|relay_id| {
        relays.get(relay_id).map(|relay| {
            relay
                .history
                .iter()
                .map(|event| event.artifact.message.id.as_slice().to_vec())
                .collect::<HashSet<_>>()
        })
    });
    let Some(first) = sets.next() else {
        return false;
    };
    sets.all(|set| set == first)
}

fn redelivery_no_progress_turns(
    previous_turns: usize,
    attempted_objects: Option<usize>,
    refused_objects: Option<usize>,
    before_token: Option<&str>,
    after_token: Option<&str>,
) -> Result<usize, SubjectError> {
    let stalled = attempted_objects.is_some()
        && attempted_objects == refused_objects
        && before_token.is_some()
        && before_token == after_token;
    if !stalled {
        return Ok(0);
    }

    let turns = previous_turns.saturating_add(1);
    if turns >= MAX_REDELIVERY_NO_PROGRESS_TURNS {
        return Err(SubjectError::classified(
            SubjectFailureCategory::Resource,
            "retained_history_redelivery_no_progress",
            format!(
                "retained-history redelivery refused all {} object(s) for {turns} consecutive turns without engine progress",
                attempted_objects.unwrap_or_default()
            ),
        ));
    }
    Ok(turns)
}

#[async_trait]
impl ConvergenceSubject for RetainedRelaySubject {
    fn descriptor(&self) -> SubjectDescriptor {
        self.descriptor.clone()
    }

    fn database_bytes(&self) -> Option<u64> {
        self.engine.database_bytes()
    }

    fn replay_probe_count(&self) -> Option<u64> {
        self.engine.replay_probe_count()
    }

    fn engine_metrics(&self) -> Option<cgka_engine::engine_metrics::EngineMetricsSnapshot> {
        self.engine.engine_metrics()
    }

    fn select_scenario_group(
        &mut self,
        group: &str,
        allow_create: bool,
    ) -> Result<(), SubjectError> {
        self.engine.select_scenario_group(group, allow_create)
    }

    async fn create_group(&mut self, action: SubjectCreateGroup<'_>) -> Result<(), SubjectError> {
        let client = action.creator.to_owned();
        let action_id = action.action_id.to_owned();
        let before = self.unresolved_ids(&client)?;
        self.engine.create_group(action).await?;
        self.tag_new_outbound(&client, &before, &action_id, ScenarioTransportClass::Commit)
    }

    async fn invite_members(
        &mut self,
        action: SubjectInviteMembers<'_>,
    ) -> Result<(), SubjectError> {
        let client = action.inviter.to_owned();
        let action_id = action.action_id.to_owned();
        let before = self.unresolved_ids(&client)?;
        self.engine.invite_members(action).await?;
        self.tag_new_outbound(&client, &before, &action_id, ScenarioTransportClass::Commit)
    }

    async fn update_group_data(
        &mut self,
        action: SubjectUpdateGroupData<'_>,
    ) -> Result<(), SubjectError> {
        let client = action.client.to_owned();
        let action_id = action.action_id.to_owned();
        let before = self.unresolved_ids(&client)?;
        self.engine.update_group_data(action).await?;
        self.tag_new_outbound(&client, &before, &action_id, ScenarioTransportClass::Commit)
    }

    async fn remove_members(
        &mut self,
        action: SubjectRemoveMembers<'_>,
    ) -> Result<(), SubjectError> {
        let client = action.remover.to_owned();
        let action_id = action.action_id.to_owned();
        let before = self.unresolved_ids(&client)?;
        self.engine.remove_members(action).await?;
        self.tag_new_outbound(&client, &before, &action_id, ScenarioTransportClass::Commit)
    }

    async fn self_update(&mut self, action: SubjectSelfUpdate<'_>) -> Result<(), SubjectError> {
        let client = action.client.to_owned();
        let action_id = action.action_id.to_owned();
        let before = self.unresolved_ids(&client)?;
        self.engine.self_update(action).await?;
        self.tag_new_outbound(&client, &before, &action_id, ScenarioTransportClass::Commit)
    }

    async fn update_admin_policy(
        &mut self,
        action: SubjectUpdateAdminPolicy<'_>,
    ) -> Result<(), SubjectError> {
        let client = action.client.to_owned();
        let action_id = action.action_id.map(str::to_owned);
        let before = self.unresolved_ids(&client)?;
        self.engine.update_admin_policy(action).await?;
        if let Some(action_id) = action_id {
            self.tag_new_outbound(&client, &before, &action_id, ScenarioTransportClass::Commit)?;
        }
        Ok(())
    }

    async fn send_application(
        &mut self,
        action: SubjectSendApplication<'_>,
    ) -> Result<(), SubjectError> {
        let client = action.sender.to_owned();
        let action_id = action.action_id.to_owned();
        let before = self.unresolved_ids(&client)?;
        self.engine.send_application(action).await?;
        self.tag_new_outbound(
            &client,
            &before,
            &action_id,
            ScenarioTransportClass::Application,
        )
    }

    async fn leave(&mut self, action_id: &str, client: &str) -> Result<(), SubjectError> {
        let before = self.unresolved_ids(client)?;
        self.engine.leave(action_id, client).await?;
        self.tag_new_outbound(client, &before, action_id, ScenarioTransportClass::Proposal)
    }

    fn deliver_all(&mut self) -> Result<(), SubjectError> {
        let online = self.online.iter().cloned().collect::<Vec<_>>();
        for client in online {
            self.sync_one(&client, &ScenarioRelaySyncModeV2::Incremental)?;
        }
        Ok(())
    }

    async fn tick(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        for client in clients {
            if self.online.contains(client) {
                let retrying = self.capacity_refused_redelivery.get(client).copied();
                let before = retrying
                    .is_some()
                    .then(|| self.engine.structural_progress())
                    .transpose()?
                    .map(|snapshot| snapshot.structural_token);
                if retrying.is_some() {
                    self.sync_one(client, &ScenarioRelaySyncModeV2::FullHistory)?;
                }

                let refused = self
                    .engine
                    .tick_observing_capacity_refusals(std::slice::from_ref(client))
                    .await?
                    .get(client)
                    .copied();
                if let Some(refused) = refused {
                    self.capacity_refused_redelivery
                        .insert(client.clone(), refused);
                } else {
                    self.capacity_refused_redelivery.remove(client);
                }

                let after = retrying
                    .is_some()
                    .then(|| self.engine.structural_progress())
                    .transpose()?
                    .map(|snapshot| snapshot.structural_token);
                let no_progress_turns = redelivery_no_progress_turns(
                    self.redelivery_no_progress_turns
                        .get(client)
                        .copied()
                        .unwrap_or_default(),
                    retrying,
                    refused,
                    before.as_deref(),
                    after.as_deref(),
                )?;
                if no_progress_turns == 0 {
                    self.redelivery_no_progress_turns.remove(client);
                } else {
                    self.redelivery_no_progress_turns
                        .insert(client.clone(), no_progress_turns);
                }
            }
        }
        Ok(())
    }

    fn activate_virtual_time(&mut self) -> Result<(), SubjectError> {
        self.engine.activate_virtual_time()
    }

    async fn advance_time(&mut self, delta_ms: u64) -> Result<(), SubjectError> {
        self.engine.advance_time(delta_ms).await
    }

    fn poll_outbound(
        &mut self,
        client: &str,
    ) -> Result<Vec<SubjectOutboundArtifact>, SubjectError> {
        self.engine.poll_outbound(client)
    }

    async fn acknowledge_outbound(
        &mut self,
        client: &str,
        outbound_id: &str,
        outcome: SubjectOutboundOutcome,
    ) -> Result<(), SubjectError> {
        if outcome == SubjectOutboundOutcome::ReachedNoEndpoint
            && self.published_outbound.contains(outbound_id)
        {
            return Err(SubjectError::new(
                "outbound_already_exposed",
                format!("outbound artifact {outbound_id} is retained by a relay"),
            ));
        }
        let accepted_artifact = if outcome == SubjectOutboundOutcome::Accepted {
            let artifact = self
                .engine
                .poll_outbound(client)?
                .into_iter()
                .find(|artifact| artifact.outbound_id == outbound_id)
                .ok_or_else(|| {
                    SubjectError::new(
                        "unknown_outbound",
                        format!("unknown outbound artifact {outbound_id}"),
                    )
                })?;
            self.validate_publish_destination(&artifact)?;
            Some(artifact)
        } else {
            None
        };
        self.engine
            .acknowledge_outbound(client, outbound_id, outcome)
            .await?;
        if let Some(artifact) = accepted_artifact {
            self.publish_artifact(artifact.clone());
            self.engine.discard_packet_bus_artifact(artifact.message.id);
        }
        Ok(())
    }

    fn structural_progress(&mut self) -> Result<SubjectProgressSnapshot, SubjectError> {
        let mut snapshot = self.engine.structural_progress()?;
        let refused_objects = self
            .capacity_refused_redelivery
            .values()
            .copied()
            .sum::<usize>();
        let runnable_refused_objects = self
            .capacity_refused_redelivery
            .iter()
            .filter(|(client, _)| self.online.contains(*client))
            .map(|(_, count)| *count)
            .sum::<usize>();
        if refused_objects > 0 {
            snapshot.runnable_work = snapshot
                .runnable_work
                .saturating_add(runnable_refused_objects);
            snapshot.transport_delayed_messages = snapshot
                .transport_delayed_messages
                .saturating_add(refused_objects);
            snapshot.structural_token.clear();
            let encoded = serde_json::to_vec(&snapshot).map_err(|error| {
                SubjectError::new(
                    "progress_serialization_failed",
                    format!("serialize retained-relay progress: {error}"),
                )
            })?;
            snapshot.structural_token = hex::encode(Sha256::digest(encoded));
        }
        Ok(snapshot)
    }

    fn observe(&mut self, clients: &[String]) -> Result<Vec<ClientObservation>, SubjectError> {
        self.engine.observe(clients)
    }

    fn observe_exact(
        &mut self,
        clients: &[String],
    ) -> Result<Vec<ClientObservation>, SubjectError> {
        self.engine.observe_exact(clients)
    }

    async fn probe_bidirectional_decryptability(
        &mut self,
        clients: &[String],
        step_index: usize,
    ) -> Result<BidirectionalDecryptabilityObservation, SubjectError> {
        self.engine
            .probe_bidirectional_decryptability(clients, step_index)
            .await
    }

    fn observe_admin_policy(
        &self,
        clients: &[String],
    ) -> Result<Vec<ScenarioAdminPolicyObservation>, SubjectError> {
        self.engine.observe_admin_policy(clients)
    }

    fn evaluate_predicate(
        &mut self,
        predicate: &ScenarioPredicateV2,
    ) -> Result<ScenarioPredicateObservationV2, SubjectError> {
        self.engine.evaluate_predicate(predicate)
    }

    fn clear_events(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        self.engine.clear_events(clients)
    }

    fn restart(&mut self, client: &str) -> Result<(), SubjectError> {
        self.engine.restart(client)
    }

    fn set_client_online(&mut self, client: &str, online: bool) -> Result<(), SubjectError> {
        if !self.clients.iter().any(|candidate| candidate == client) {
            return Err(SubjectError::new(
                "unknown_client",
                format!("unknown client {client}"),
            ));
        }
        if online {
            self.online.insert(client.into());
        } else {
            self.online.remove(client);
        }
        Ok(())
    }

    fn sync_relay_history(
        &mut self,
        clients: &[String],
        mode: &ScenarioRelaySyncModeV2,
    ) -> Result<(), SubjectError> {
        for client in clients {
            self.sync_one(client, mode)?;
        }
        Ok(())
    }

    fn configure_relay(
        &mut self,
        relay: &str,
        order: ScenarioRelayOrderV2,
        duplicate_copies: usize,
    ) -> Result<(), SubjectError> {
        let relay = self
            .relays
            .get_mut(relay)
            .ok_or_else(|| SubjectError::new("unknown_relay", format!("unknown relay {relay}")))?;
        if duplicate_copies == 0 {
            return Err(SubjectError::new(
                "invalid_duplicate_copies",
                "relay duplicate copies must be non-zero",
            ));
        }
        relay.order = order;
        relay.duplicate_copies = duplicate_copies;
        Ok(())
    }

    fn set_relay_event_visibility(
        &mut self,
        relay: &str,
        selector: &ScenarioMessageSelectorV2,
        clients: &[String],
        visible: bool,
    ) -> Result<(), SubjectError> {
        let relay = self
            .relays
            .get_mut(relay)
            .ok_or_else(|| SubjectError::new("unknown_relay", format!("unknown relay {relay}")))?;
        let matching = relay
            .history
            .iter_mut()
            .filter(|event| Self::event_matches(event, selector))
            .nth(selector.occurrence)
            .ok_or_else(|| {
                SubjectError::new(
                    "relay_selector_no_match",
                    format!("no retained relay event matches {selector:?}"),
                )
            })?;
        for client in clients {
            if visible {
                matching.hidden_from.remove(client);
            } else {
                matching.hidden_from.insert(client.clone());
            }
        }
        Ok(())
    }

    fn reconcile_relay_histories(&mut self, relay_ids: &[String]) -> Result<(), SubjectError> {
        let mut union = BTreeMap::<String, RetainedRelayEvent>::new();
        for relay_id in relay_ids {
            let relay = self.relays.get(relay_id).ok_or_else(|| {
                SubjectError::new("unknown_relay", format!("unknown relay {relay_id}"))
            })?;
            for event in &relay.history {
                union
                    .entry(event.artifact.outbound_id.clone())
                    .or_insert_with(|| event.clone());
            }
        }
        for relay_id in relay_ids {
            let relay = self.relays.get_mut(relay_id).expect("validated relay");
            let existing = relay
                .history
                .iter()
                .map(|event| event.artifact.outbound_id.clone())
                .collect::<BTreeSet<_>>();
            for (outbound_id, event) in &union {
                if !existing.contains(outbound_id) {
                    let mut event = event.clone();
                    event.sequence = relay.next_sequence;
                    event.hidden_from.clear();
                    relay.next_sequence = relay.next_sequence.saturating_add(1);
                    relay.history.push(event);
                }
            }
        }
        Ok(())
    }

    fn relay_sync_observations(&self) -> Vec<RelaySyncObservationV2> {
        if !self.sync_observations.is_empty() {
            return self.sync_observations.clone();
        }
        self.clients
            .iter()
            .map(|client| RelaySyncObservationV2 {
                client: client.clone(),
                mode: ScenarioRelaySyncModeV2::Incremental,
                queried_relays: Vec::new(),
                eose_relays: Vec::new(),
                events_returned: 0,
                unique_events_returned: 0,
                injected_objects: 0,
                quiet: true,
                completeness: RelayHistoryCompletenessClaimV2::NotAttempted,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EngineHarnessSubject, ReferenceModelSubject, ScenarioAccountV2, ScenarioDeviceV2,
        ScenarioProcessV2, ScenarioSpec, ScenarioStep, TraceExpectation,
        run_scenario_report_with_subject,
    };

    #[test]
    fn unchanged_full_refusal_returns_typed_no_progress_failure() {
        let first =
            redelivery_no_progress_turns(0, Some(4), Some(4), Some("unchanged"), Some("unchanged"))
                .expect("first unchanged retry remains within the bound");
        let error = redelivery_no_progress_turns(
            first,
            Some(4),
            Some(4),
            Some("unchanged"),
            Some("unchanged"),
        )
        .expect_err("second unchanged retry reaches the no-progress bound");

        assert_eq!(error.category, SubjectFailureCategory::Resource);
        assert_eq!(error.code, "retained_history_redelivery_no_progress");
    }

    fn split_relay_topology() -> ScenarioTopologyV2 {
        ScenarioTopologyV2 {
            accounts: vec![
                ScenarioAccountV2 {
                    id: "account:alice".into(),
                    roles: vec!["admin".into()],
                },
                ScenarioAccountV2 {
                    id: "account:bob".into(),
                    roles: vec!["member".into()],
                },
            ],
            devices: vec![
                ScenarioDeviceV2 {
                    id: "device:alice".into(),
                    account: "account:alice".into(),
                    process: "process:alice".into(),
                    client: "alice".into(),
                },
                ScenarioDeviceV2 {
                    id: "device:bob".into(),
                    account: "account:bob".into(),
                    process: "process:bob".into(),
                    client: "bob".into(),
                },
            ],
            processes: vec![
                ScenarioProcessV2 {
                    id: "process:alice".into(),
                    binary_version: "test".into(),
                    policy_version: "v1".into(),
                    relays: vec!["relay:a".into()],
                },
                ScenarioProcessV2 {
                    id: "process:bob".into(),
                    binary_version: "test".into(),
                    policy_version: "v1".into(),
                    relays: vec!["relay:b".into()],
                },
            ],
            groups: Vec::new(),
            relays: vec![
                ScenarioRelayV2 {
                    id: "relay:a".into(),
                    implementation_version: "memory/v1".into(),
                    policy_version: "retain-all/v1".into(),
                },
                ScenarioRelayV2 {
                    id: "relay:b".into(),
                    implementation_version: "memory/v1".into(),
                    policy_version: "retain-all/v1".into(),
                },
            ],
        }
    }

    fn single_relay_topology() -> ScenarioTopologyV2 {
        let mut topology = split_relay_topology();
        topology.relays = vec![ScenarioRelayV2 {
            id: DEFAULT_RELAY_ID.into(),
            implementation_version: "memory/v1".into(),
            policy_version: "retain-all/v1".into(),
        }];
        for process in &mut topology.processes {
            process.relays = vec![DEFAULT_RELAY_ID.into()];
        }
        topology
    }

    #[tokio::test]
    async fn offline_client_recovers_from_retained_history() {
        let scenario = ScenarioSpec {
            name: "retained-relay/offline-recovery".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: single_relay_topology(),
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "retained".into(),
                    invitees: vec!["bob".into()],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                },
                ScenarioStep::accept_publication("alice", "create"),
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::SetClientOffline {
                    client: "bob".into(),
                },
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "while-offline".into(),
                },
                ScenarioStep::AcknowledgeOutbound {
                    client: "alice".into(),
                    publication: None,
                    selection: Default::default(),
                    outcome: SubjectOutboundOutcome::Accepted,
                },
                ScenarioStep::DeliverAll,
                ScenarioStep::ReconnectClient {
                    client: "bob".into(),
                },
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::FullHistory,
                },
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::Observe {
                    clients: vec!["bob".into()],
                },
            ],
        };
        let mut subject = RetainedRelaySubject::new(
            &scenario.clients,
            &scenario.topology,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        let report = run_scenario_report_with_subject(&scenario, None, vec![], &mut subject)
            .await
            .expect("retained relay scenario");
        let observation = &report.observed_trace.as_ref().unwrap().observations[0];
        assert_eq!(observation.received_payloads, vec!["while-offline"]);
        assert!(report.relay_sync_observations.iter().any(|observation| {
            observation.client == "bob"
                && observation.completeness == RelayHistoryCompletenessClaimV2::FullHistoryQueried
                && observation.injected_objects > 0
        }));
    }

    /// Regression for mdk#1650: after an offline member has consumed retained
    /// history, exact replay of the same transport wrappers must deduplicate
    /// before old peel contexts fall outside the rewind horizon. The restart
    /// between the incremental and full-history queries proves the outer-id
    /// decision is durable rather than only held by the hot-process cache.
    #[tokio::test]
    async fn exact_full_history_replay_after_restart_deduplicates_processed_wrappers() {
        let clients = vec!["alice".into(), "bob".into(), "carol".into(), "dave".into()];
        let mut steps = vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "round-0".into(),
                invitees: vec!["bob".into(), "carol".into(), "dave".into()],
                required_features: vec![],
                initial_admins: Some(vec!["alice".into()]),
                pending: "create".into(),
            },
            ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: None,
                selection: Default::default(),
                outcome: SubjectOutboundOutcome::Accepted,
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into(), "carol".into(), "dave".into()],
            },
            ScenarioStep::SetClientOffline {
                client: "bob".into(),
            },
        ];
        let expected_payloads = (1..=6)
            .map(|round| format!("offline-payload-{round}"))
            .collect::<Vec<_>>();
        for (round, payload) in expected_payloads.iter().enumerate() {
            let round = round + 1;
            let pending = format!("update-{round}");
            steps.extend([
                ScenarioStep::UpdateGroupData {
                    client: "alice".into(),
                    name: format!("round-{round}"),
                    pending: pending.clone(),
                },
                ScenarioStep::accept_publication("alice", &pending),
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["carol".into(), "dave".into()],
                },
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: payload.clone(),
                },
                ScenarioStep::AcknowledgeOutbound {
                    client: "alice".into(),
                    publication: None,
                    selection: Default::default(),
                    outcome: SubjectOutboundOutcome::Accepted,
                },
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["carol".into(), "dave".into()],
                },
            ]);
        }
        steps.extend([
            ScenarioStep::ReconnectClient {
                client: "bob".into(),
            },
            ScenarioStep::SyncRelayHistory {
                clients: vec!["bob".into()],
                sync: ScenarioRelaySyncModeV2::Incremental,
            },
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["bob".into()],
            },
            ScenarioStep::RestartClient {
                client: "bob".into(),
            },
            ScenarioStep::SyncRelayHistory {
                clients: vec!["bob".into()],
                sync: ScenarioRelaySyncModeV2::FullHistory,
            },
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::ObserveExact {
                clients: vec!["bob".into()],
            },
        ]);
        let scenario = ScenarioSpec {
            name: "retained-relay/exact-full-history-replay-after-restart".into(),
            spec_version: "2".into(),
            clients,
            topology: ScenarioTopologyV2::default(),
            steps,
        };
        let mut subject = RetainedRelaySubject::new(
            &scenario.clients,
            &scenario.topology,
            ProtocolProfile::Current,
            HarnessStorageMode::TempFileBackedSqlite,
        )
        .unwrap();

        let report = run_scenario_report_with_subject(
            &scenario,
            None,
            vec![
                TraceExpectation::ClientState {
                    client: "bob".into(),
                    epoch: 7,
                    member_count: 4,
                    received_payloads: Some(expected_payloads),
                    added_members: None,
                    removed_members: None,
                },
                TraceExpectation::GroupProfile {
                    client: "bob".into(),
                    name: "round-6".into(),
                    description: "".into(),
                },
                TraceExpectation::NoPendingWork {
                    clients: vec!["bob".into()],
                },
            ],
            &mut subject,
        )
        .await
        .expect("run exact full-history wrapper replay regression");

        let bob = report
            .observed_trace
            .as_ref()
            .and_then(|trace| {
                trace
                    .observations
                    .iter()
                    .rev()
                    .find(|observation| observation.client == "bob")
            })
            .expect("Bob has a final exact observation");
        let first_commit = bob
            .scenario_input_ledger
            .iter()
            .find(|entry| entry.scenario_id == "step-5:update_group_data")
            .expect("the first offline commit remains in Bob's input ledger");
        assert_eq!(
            first_commit.deduplicated, 1,
            "exact replay of the first processed wrapper must deduplicate"
        );
        assert_eq!(
            first_commit.transport_deferred, 0,
            "exact replay must not re-enter the deferred-peel lifecycle"
        );
        assert!(!first_commit.pending);

        assert!(
            report.expectation_failures.is_empty(),
            "unexpected failures: {:#?}",
            report.expectation_failures
        );
        assert!(
            report.invariant_failures.is_empty(),
            "unexpected invariant failures: {:#?}",
            report.invariant_failures
        );
    }

    #[tokio::test]
    async fn unequal_relay_histories_converge_after_set_equalization() {
        let scenario = ScenarioSpec {
            name: "retained-relay/history-equalization".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: split_relay_topology(),
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "before".into(),
                    invitees: vec!["bob".into()],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                },
                ScenarioStep::accept_publication("alice", "create"),
                ScenarioStep::ReconcileRelayHistories {
                    relays: vec!["relay:a".into(), "relay:b".into()],
                },
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::SetReconciliation,
                },
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::UpdateGroupData {
                    client: "alice".into(),
                    name: "after".into(),
                    pending: "rename".into(),
                },
                ScenarioStep::accept_publication("alice", "rename"),
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::Incremental,
                },
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::ObserveExact {
                    clients: vec!["alice".into(), "bob".into()],
                },
                ScenarioStep::ReconcileRelayHistories {
                    relays: vec!["relay:a".into(), "relay:b".into()],
                },
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::SetReconciliation,
                },
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::ObserveExact {
                    clients: vec!["alice".into(), "bob".into()],
                },
            ],
        };
        let mut subject = RetainedRelaySubject::new(
            &scenario.clients,
            &scenario.topology,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        let report = run_scenario_report_with_subject(&scenario, None, vec![], &mut subject)
            .await
            .expect("relay equalization scenario");
        let observations = &report.observed_trace.as_ref().unwrap().observations;
        assert_ne!(
            observations[0].canonical_state,
            observations[1].canonical_state
        );
        assert_eq!(
            observations[2].canonical_state,
            observations[3].canonical_state
        );
        assert!(report.relay_sync_observations.iter().any(|observation| {
            observation.quiet
                && observation.completeness == RelayHistoryCompletenessClaimV2::RelayEoseOnly
        }));
        assert!(report.relay_sync_observations.iter().any(|observation| {
            observation.completeness == RelayHistoryCompletenessClaimV2::RelevantSetEqualityVerified
        }));
    }

    #[tokio::test]
    async fn one_compiled_scenario_runs_unchanged_on_all_initial_adapters() {
        let scenario = ScenarioSpec {
            name: "scenario-ir/all-initial-adapters".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: single_relay_topology(),
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "common".into(),
                    invitees: vec!["bob".into()],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                },
                ScenarioStep::accept_publication("alice", "create"),
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "hello".into(),
                },
                ScenarioStep::AcknowledgeOutbound {
                    client: "alice".into(),
                    publication: None,
                    selection: Default::default(),
                    outcome: SubjectOutboundOutcome::Accepted,
                },
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::Observe {
                    clients: vec!["alice".into(), "bob".into()],
                },
            ],
        };
        let mut reference = ReferenceModelSubject::new(&scenario.clients).unwrap();
        let reference_report =
            run_scenario_report_with_subject(&scenario, None, vec![], &mut reference)
                .await
                .unwrap();
        let mut engine = EngineHarnessSubject::new(
            &scenario.clients,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        let engine_report = run_scenario_report_with_subject(&scenario, None, vec![], &mut engine)
            .await
            .unwrap();
        let mut retained = RetainedRelaySubject::new(
            &scenario.clients,
            &scenario.topology,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        let retained_report =
            run_scenario_report_with_subject(&scenario, None, vec![], &mut retained)
                .await
                .unwrap();
        let semantic = |report: &crate::ScenarioReport| {
            report
                .observed_trace
                .as_ref()
                .unwrap()
                .observations
                .iter()
                .map(|observation| {
                    (
                        observation.client.clone(),
                        observation.epoch,
                        observation.member_count,
                        observation.group_name.clone(),
                        observation.group_description.clone(),
                        observation.received_payloads.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(semantic(&reference_report), semantic(&engine_report));
        assert_eq!(semantic(&engine_report), semantic(&retained_report));
    }

    #[tokio::test]
    async fn implicit_topology_preserves_the_same_identities_on_retained_relays() {
        let scenario = ScenarioSpec {
            name: "retained-relay/implicit-identity-compat".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: Default::default(),
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "identity-compat".into(),
                    invitees: vec!["bob".into()],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                },
                ScenarioStep::accept_publication("alice", "create"),
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::ObserveExact {
                    clients: vec!["alice".into(), "bob".into()],
                },
            ],
        };
        let mut engine = EngineHarnessSubject::new(
            &scenario.clients,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        let engine_report = run_scenario_report_with_subject(&scenario, None, vec![], &mut engine)
            .await
            .unwrap();
        let mut retained = RetainedRelaySubject::new(
            &scenario.clients,
            &scenario.topology,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        let retained_report =
            run_scenario_report_with_subject(&scenario, None, vec![], &mut retained)
                .await
                .unwrap();

        let member_identities = |report: &crate::ScenarioReport| {
            report
                .observed_trace
                .as_ref()
                .unwrap()
                .observations
                .iter()
                .map(|observation| {
                    match observation.canonical_state.as_ref().unwrap() {
                    cgka_engine::conformance_snapshot::ConformanceCanonicalStateSnapshot::Live(
                        snapshot,
                    ) => snapshot.sorted_member_identities_hex.clone(),
                    cgka_engine::conformance_snapshot::ConformanceCanonicalStateSnapshot::Disbanded(
                        _,
                    ) => panic!("identity compatibility scenario remains live"),
                }
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            member_identities(&engine_report),
            member_identities(&retained_report)
        );
    }

    #[tokio::test]
    async fn create_group_stable_action_id_selects_engine_and_retained_artifacts() {
        let create_selector = ScenarioMessageSelectorV2 {
            action_id: Some("step-0:create_group".into()),
            class: Some(ScenarioTransportClass::Welcome),
            ..Default::default()
        };
        let engine_scenario = ScenarioSpec {
            name: "scenario-ir/create-action-id-engine".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: single_relay_topology(),
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "engine-create-id".into(),
                    invitees: vec!["bob".into()],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                },
                ScenarioStep::DuplicateMessage {
                    selector: create_selector.clone(),
                },
                ScenarioStep::accept_publication("alice", "create"),
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::Observe {
                    clients: vec!["bob".into()],
                },
            ],
        };
        let mut engine = EngineHarnessSubject::new(
            &engine_scenario.clients,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        let engine_report =
            run_scenario_report_with_subject(&engine_scenario, None, vec![], &mut engine)
                .await
                .unwrap();
        assert_eq!(
            engine_report.observed_trace.as_ref().unwrap().observations[0].member_count,
            2
        );

        let retained_scenario = ScenarioSpec {
            name: "scenario-ir/create-action-id-retained".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: single_relay_topology(),
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "retained-create-id".into(),
                    invitees: vec!["bob".into()],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                },
                ScenarioStep::accept_publication("alice", "create"),
                ScenarioStep::SetRelayEventVisibility {
                    relay: DEFAULT_RELAY_ID.into(),
                    selector: create_selector.clone(),
                    clients: vec!["bob".into()],
                    visible: false,
                },
                ScenarioStep::SetRelayEventVisibility {
                    relay: DEFAULT_RELAY_ID.into(),
                    selector: create_selector,
                    clients: vec!["bob".into()],
                    visible: true,
                },
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::FullHistory,
                },
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::Observe {
                    clients: vec!["bob".into()],
                },
            ],
        };
        let mut retained = RetainedRelaySubject::new(
            &retained_scenario.clients,
            &retained_scenario.topology,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        let retained_report =
            run_scenario_report_with_subject(&retained_scenario, None, vec![], &mut retained)
                .await
                .unwrap();
        assert_eq!(
            retained_report
                .observed_trace
                .as_ref()
                .unwrap()
                .observations[0]
                .member_count,
            2
        );
    }

    #[tokio::test]
    async fn artifact_free_founding_create_does_not_leak_its_action_id() {
        let scenario = ScenarioSpec {
            name: "scenario-ir/artifact-free-create-action-id".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: single_relay_topology(),
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "founding-create".into(),
                    invitees: vec![],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "artifact-free-create".into(),
                },
                ScenarioStep::InviteMembers {
                    inviter: "alice".into(),
                    invitees: vec!["bob".into()],
                    pending: "invite".into(),
                },
                ScenarioStep::accept_publication("alice", "invite"),
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::Observe {
                    clients: vec!["bob".into()],
                },
            ],
        };
        let mut engine = EngineHarnessSubject::new(
            &scenario.clients,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();

        let report = run_scenario_report_with_subject(&scenario, None, vec![], &mut engine)
            .await
            .unwrap();

        assert_eq!(
            report.observed_trace.as_ref().unwrap().observations[0].member_count,
            2
        );
    }

    #[tokio::test]
    async fn eose_does_not_heal_hidden_cursor_history_but_full_backfill_does() {
        let scenario = ScenarioSpec {
            name: "retained-relay/eose-versus-completeness".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: single_relay_topology(),
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "eose".into(),
                    invitees: vec!["bob".into()],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                },
                ScenarioStep::accept_publication("alice", "create"),
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "hidden".into(),
                },
                ScenarioStep::AcknowledgeOutbound {
                    client: "alice".into(),
                    publication: None,
                    selection: Default::default(),
                    outcome: SubjectOutboundOutcome::Accepted,
                },
                ScenarioStep::SetRelayEventVisibility {
                    relay: DEFAULT_RELAY_ID.into(),
                    selector: ScenarioMessageSelectorV2 {
                        sender: Some("alice".into()),
                        class: Some(ScenarioTransportClass::Application),
                        ..Default::default()
                    },
                    clients: vec!["bob".into()],
                    visible: false,
                },
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::Incremental,
                },
                ScenarioStep::SetRelayEventVisibility {
                    relay: DEFAULT_RELAY_ID.into(),
                    selector: ScenarioMessageSelectorV2 {
                        sender: Some("alice".into()),
                        class: Some(ScenarioTransportClass::Application),
                        ..Default::default()
                    },
                    clients: vec!["bob".into()],
                    visible: true,
                },
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::Incremental,
                },
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::Since {
                        timestamp: u64::MAX,
                    },
                },
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::FullHistory,
                },
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::Observe {
                    clients: vec!["bob".into()],
                },
            ],
        };
        let mut subject = RetainedRelaySubject::new(
            &scenario.clients,
            &scenario.topology,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        let report = run_scenario_report_with_subject(&scenario, None, vec![], &mut subject)
            .await
            .unwrap();
        assert_eq!(
            report.observed_trace.as_ref().unwrap().observations[0].received_payloads,
            vec!["hidden"]
        );
        let quiet_eose = report
            .relay_sync_observations
            .iter()
            .filter(|observation| {
                observation.quiet
                    && observation.completeness == RelayHistoryCompletenessClaimV2::RelayEoseOnly
            })
            .count();
        assert!(quiet_eose >= 3);
        assert!(report.relay_sync_observations.iter().any(|observation| {
            observation.completeness == RelayHistoryCompletenessClaimV2::FullHistoryQueried
                && observation.injected_objects > 0
        }));
    }

    #[tokio::test]
    async fn since_query_does_not_consume_the_incremental_cursor() {
        let scenario = ScenarioSpec {
            name: "retained-relay/since-preserves-incremental-cursor".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: single_relay_topology(),
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "since-cursor".into(),
                    invitees: vec!["bob".into()],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                },
                ScenarioStep::accept_publication("alice", "create"),
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "below-since-floor".into(),
                },
                ScenarioStep::AcknowledgeOutbound {
                    client: "alice".into(),
                    publication: None,
                    selection: Default::default(),
                    outcome: SubjectOutboundOutcome::Accepted,
                },
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::Since {
                        timestamp: u64::MAX,
                    },
                },
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::Incremental,
                },
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::Observe {
                    clients: vec!["bob".into()],
                },
            ],
        };
        let mut subject = RetainedRelaySubject::new(
            &scenario.clients,
            &scenario.topology,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();

        let report = run_scenario_report_with_subject(&scenario, None, vec![], &mut subject)
            .await
            .unwrap();

        assert_eq!(
            report.observed_trace.as_ref().unwrap().observations[0].received_payloads,
            vec!["below-since-floor"]
        );
        assert!(report.relay_sync_observations.iter().any(|observation| {
            matches!(observation.mode, ScenarioRelaySyncModeV2::Since { .. })
                && observation.events_returned == 0
        }));
        assert!(report.relay_sync_observations.iter().any(|observation| {
            observation.mode == ScenarioRelaySyncModeV2::Incremental
                && observation.injected_objects > 0
        }));
    }

    #[tokio::test]
    async fn relay_reverse_order_and_duplicates_are_explicit_and_deduplicated() {
        let scenario = ScenarioSpec {
            name: "retained-relay/order-duplicates".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: single_relay_topology(),
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "order".into(),
                    invitees: vec!["bob".into()],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                },
                ScenarioStep::accept_publication("alice", "create"),
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "first".into(),
                },
                ScenarioStep::AcknowledgeOutbound {
                    client: "alice".into(),
                    publication: None,
                    selection: Default::default(),
                    outcome: SubjectOutboundOutcome::Accepted,
                },
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "second".into(),
                },
                ScenarioStep::AcknowledgeOutbound {
                    client: "alice".into(),
                    publication: None,
                    selection: Default::default(),
                    outcome: SubjectOutboundOutcome::Accepted,
                },
                ScenarioStep::ConfigureRelay {
                    relay: DEFAULT_RELAY_ID.into(),
                    order: ScenarioRelayOrderV2::Reverse,
                    duplicate_copies: 2,
                },
                ScenarioStep::SyncRelayHistory {
                    clients: vec!["bob".into()],
                    sync: ScenarioRelaySyncModeV2::FullHistory,
                },
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::Observe {
                    clients: vec!["bob".into()],
                },
            ],
        };
        let mut subject = RetainedRelaySubject::new(
            &scenario.clients,
            &scenario.topology,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        let report = run_scenario_report_with_subject(&scenario, None, vec![], &mut subject)
            .await
            .unwrap();
        assert_eq!(
            report.observed_trace.as_ref().unwrap().observations[0].received_payloads,
            vec!["second", "first"]
        );
        assert!(report.relay_sync_observations.iter().any(|observation| {
            observation.events_returned > observation.unique_events_returned
        }));
    }

    #[tokio::test]
    async fn relay_history_contains_only_accepted_publications() {
        let clients = vec!["alice".into()];
        let topology = ScenarioTopologyV2::default();
        let mut subject = RetainedRelaySubject::new(
            &clients,
            &topology,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        subject
            .create_group(SubjectCreateGroup {
                action_id: "create-publication-lifecycle",
                creator: "alice",
                name: "publication-lifecycle",
                invitees: &[],
                required_features: &[],
                initial_admins: &[],
                pending: "create",
            })
            .await
            .unwrap();
        let create = subject.poll_outbound("alice").unwrap();
        for artifact in create {
            subject
                .acknowledge_outbound(
                    "alice",
                    &artifact.outbound_id,
                    SubjectOutboundOutcome::Accepted,
                )
                .await
                .unwrap();
        }
        let retained_before = subject
            .relays
            .values()
            .map(|relay| relay.history.len())
            .sum::<usize>();

        subject
            .send_application(SubjectSendApplication {
                action_id: "unaccepted-app",
                sender: "alice",
                payload: "not-published",
            })
            .await
            .unwrap();
        let app = subject.poll_outbound("alice").unwrap();
        assert_eq!(app.len(), 1);
        subject.deliver_all().unwrap();
        assert_eq!(
            subject
                .relays
                .values()
                .map(|relay| relay.history.len())
                .sum::<usize>(),
            retained_before,
            "querying relays must not publish unresolved artifacts"
        );
        subject
            .acknowledge_outbound(
                "alice",
                &app[0].outbound_id,
                SubjectOutboundOutcome::ReachedNoEndpoint,
            )
            .await
            .unwrap();
        assert_eq!(
            subject
                .relays
                .values()
                .map(|relay| relay.history.len())
                .sum::<usize>(),
            retained_before,
            "definite nonpublication must leave no retained event"
        );
    }
}
