//! Small independent state-machine subject for cross-adapter Scenario IR checks.
//!
//! This model deliberately does not call the production engine, selector, or
//! canonicalization implementation. It provides a semantic oracle for the
//! common group/publication/application lifecycle while declaring exact MLS
//! projection and adversarial transport capabilities unsupported.

use crate::{
    ClientEventCounts, ClientObservation, ClientStructuralProgress, ConvergenceSubject,
    EpochChangeObservation, ScenarioAdminPolicyObservation, ScenarioPredicateObservationV2,
    ScenarioPredicateV2, SubjectCapability, SubjectCreateGroup, SubjectDescriptor, SubjectError,
    SubjectOutboundArtifact, SubjectOutboundKind, SubjectOutboundOutcome, SubjectProgressSnapshot,
    SubjectRemoveMembers, SubjectSelfUpdate, SubjectSendApplication, SubjectUpdateAdminPolicy,
    SubjectUpdateGroupData,
};
use async_trait::async_trait;
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::types::{MemberId, MessageId};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::SubjectInviteMembers;

#[derive(Clone, Debug, Default)]
struct ReferenceClient {
    state: Option<ReferenceGroupState>,
    window: ReferenceEventWindow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReferenceGroupState {
    epoch: u64,
    name: String,
    members: BTreeSet<String>,
    admins: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
struct ReferenceEventWindow {
    received_payloads: Vec<String>,
    added_members: Vec<String>,
    removed_members: Vec<String>,
    epoch_changes: Vec<EpochChangeObservation>,
}

#[derive(Clone, Debug)]
enum ReferenceDeliveryEffect {
    State(ReferenceGroupState),
    Application(String),
}

#[derive(Clone, Debug)]
struct ReferenceDelivery {
    outbound_id: String,
    recipient: String,
    effect: ReferenceDeliveryEffect,
}

#[derive(Clone, Debug)]
struct ReferenceOutboundRecord {
    artifact: SubjectOutboundArtifact,
    resolution: Option<SubjectOutboundOutcome>,
    local_state: Option<ReferenceGroupState>,
}

/// An implementation-independent logical subject used to prove that canonical
/// Scenario IR is not coupled to the OpenMLS harness adapter.
pub struct ReferenceModelSubject {
    descriptor: SubjectDescriptor,
    clients: BTreeMap<String, ReferenceClient>,
    outbound: BTreeMap<u64, ReferenceOutboundRecord>,
    queued: Vec<ReferenceDelivery>,
    mailboxes: BTreeMap<String, Vec<ReferenceDeliveryEffect>>,
    next_outbound_sequence: u64,
    current_monotonic_ms: u64,
}

impl ReferenceModelSubject {
    pub fn new(clients: &[String]) -> Result<Self, SubjectError> {
        let mut participants = BTreeMap::new();
        for client in clients {
            if participants
                .insert(client.clone(), ReferenceClient::default())
                .is_some()
            {
                return Err(SubjectError::new(
                    "duplicate_client",
                    format!("duplicate client label {client}"),
                ));
            }
        }
        Ok(Self {
            descriptor: SubjectDescriptor {
                adapter: "independent-reference-model".into(),
                adapter_version: "1".into(),
                storage_backend: "symbolic-memory".into(),
                capabilities: BTreeSet::from([
                    SubjectCapability::GroupMutation,
                    SubjectCapability::ApplicationMessaging,
                    SubjectCapability::TransportDelivery,
                    SubjectCapability::EventObservation,
                    SubjectCapability::AdminPolicyObservation,
                    SubjectCapability::VirtualTime,
                    SubjectCapability::OutboundPublication,
                    SubjectCapability::StructuralProgress,
                    SubjectCapability::AssertionEvaluation,
                ]),
            },
            clients: participants,
            outbound: BTreeMap::new(),
            queued: Vec::new(),
            mailboxes: BTreeMap::new(),
            next_outbound_sequence: 0,
            current_monotonic_ms: 0,
        })
    }

    fn client(&self, label: &str) -> Result<&ReferenceClient, SubjectError> {
        self.clients
            .get(label)
            .ok_or_else(|| SubjectError::new("unknown_client", format!("unknown client {label}")))
    }

    fn client_mut(&mut self, label: &str) -> Result<&mut ReferenceClient, SubjectError> {
        self.clients
            .get_mut(label)
            .ok_or_else(|| SubjectError::new("unknown_client", format!("unknown client {label}")))
    }

    fn group_state(&self, label: &str) -> Result<ReferenceGroupState, SubjectError> {
        self.client(label)?.state.clone().ok_or_else(|| {
            SubjectError::new("group_not_found", format!("client {label} has no group"))
        })
    }

    fn validate_clients<'a>(
        &self,
        labels: impl IntoIterator<Item = &'a String>,
    ) -> Result<(), SubjectError> {
        for label in labels {
            self.client(label)?;
        }
        Ok(())
    }

    fn emit(
        &mut self,
        client: &str,
        publication: Option<&str>,
        kind: SubjectOutboundKind,
        recipient: Option<&str>,
        state_confirmation_required: bool,
        local_state: Option<ReferenceGroupState>,
    ) -> String {
        let sequence = self.next_outbound_sequence;
        self.next_outbound_sequence = self.next_outbound_sequence.saturating_add(1);
        let outbound_id = format!("reference-outbound/{sequence}");
        let message = TransportMessage {
            id: MessageId::new(sequence.to_be_bytes()),
            payload: sequence.to_be_bytes().to_vec(),
            timestamp: Timestamp(self.current_monotonic_ms / 1_000),
            causal_deps: Vec::new(),
            source: TransportSource("reference-model".into()),
            envelope: match recipient {
                Some(recipient) => TransportEnvelope::Welcome {
                    recipient: MemberId::new(Sha256::digest(recipient.as_bytes()).to_vec()),
                },
                None => TransportEnvelope::GroupMessage {
                    transport_group_id: b"reference-model-group".to_vec(),
                },
            },
        };
        self.outbound.insert(
            sequence,
            ReferenceOutboundRecord {
                artifact: SubjectOutboundArtifact {
                    outbound_id: outbound_id.clone(),
                    client: client.into(),
                    publication: publication.map(str::to_owned),
                    kind,
                    message,
                    state_confirmation_required,
                    regenerated_queued_intent: false,
                },
                resolution: None,
                local_state,
            },
        );
        outbound_id
    }

    fn stage_state_change(
        &mut self,
        actor: &str,
        pending: &str,
        state: ReferenceGroupState,
        welcomees: &[String],
    ) {
        let existing_recipients = self
            .clients
            .get(actor)
            .and_then(|client| client.state.as_ref())
            .map(|state| state.members.clone())
            .unwrap_or_default();
        let group_outbound = self.emit(
            actor,
            Some(pending),
            SubjectOutboundKind::GroupMessage,
            None,
            true,
            Some(state.clone()),
        );
        for recipient in existing_recipients.iter().filter(|member| *member != actor) {
            self.queued.push(ReferenceDelivery {
                outbound_id: group_outbound.clone(),
                recipient: recipient.clone(),
                effect: ReferenceDeliveryEffect::State(state.clone()),
            });
        }
        for recipient in welcomees {
            let welcome_outbound = self.emit(
                actor,
                Some(pending),
                SubjectOutboundKind::Welcome,
                Some(recipient),
                false,
                None,
            );
            self.queued.push(ReferenceDelivery {
                outbound_id: welcome_outbound,
                recipient: recipient.clone(),
                effect: ReferenceDeliveryEffect::State(state.clone()),
            });
        }
    }

    fn apply_state(client: &mut ReferenceClient, next: ReferenceGroupState) {
        let previous = client.state.replace(next.clone());
        if let Some(previous) = previous {
            if previous.epoch != next.epoch {
                client.window.epoch_changes.push(EpochChangeObservation {
                    from: previous.epoch,
                    to: next.epoch,
                });
            }
            client
                .window
                .added_members
                .extend(next.members.difference(&previous.members).cloned());
            client
                .window
                .removed_members
                .extend(previous.members.difference(&next.members).cloned());
        } else {
            client
                .window
                .added_members
                .extend(next.members.iter().cloned());
        }
    }

    fn observation(&mut self, label: &str) -> Result<ClientObservation, SubjectError> {
        let client = self.client_mut(label)?;
        let state = client.state.clone();
        let window = std::mem::take(&mut client.window);
        let event_counts = ClientEventCounts {
            message_received: window.received_payloads.len(),
            member_added: window.added_members.len(),
            member_removed: window.removed_members.len(),
            epoch_changed: window.epoch_changes.len(),
            ..Default::default()
        };
        Ok(ClientObservation {
            client: label.into(),
            epoch: state.as_ref().map_or(0, |state| state.epoch),
            member_count: state.as_ref().map_or(0, |state| state.members.len()),
            group_name: state
                .as_ref()
                .map_or_else(String::new, |state| state.name.clone()),
            canonical_state: None,
            scenario_input_ledger: Vec::new(),
            pending_work: None,
            event_counts,
            received_payloads: window.received_payloads,
            added_members: window.added_members,
            removed_members: window.removed_members,
            epoch_changes: window.epoch_changes,
            app_invalidations: Vec::new(),
            recoveries: Vec::new(),
            convergence_decisions: Vec::new(),
        })
    }

    fn predicate_observation(
        &mut self,
        predicate: &ScenarioPredicateV2,
    ) -> Result<ScenarioPredicateObservationV2, SubjectError> {
        let (matched, actual) = match predicate {
            ScenarioPredicateV2::ClientState {
                client,
                epoch,
                member_count,
            } => {
                let state = self.client(client)?.state.as_ref();
                let actual_epoch = state.map_or(0, |state| state.epoch);
                let actual_member_count = state.map_or(0, |state| state.members.len());
                (
                    epoch.is_none_or(|expected| expected == actual_epoch)
                        && member_count.is_none_or(|expected| expected == actual_member_count),
                    serde_json::json!({
                        "client": client,
                        "epoch": actual_epoch,
                        "member_count": actual_member_count,
                    }),
                )
            }
            ScenarioPredicateV2::PayloadCount {
                client,
                payload,
                count,
            } => {
                let actual_count = self
                    .client(client)?
                    .window
                    .received_payloads
                    .iter()
                    .filter(|candidate| *candidate == payload)
                    .count();
                (
                    actual_count == *count,
                    serde_json::json!({"count": actual_count}),
                )
            }
            ScenarioPredicateV2::ClientsExactlyEquivalent { .. }
            | ScenarioPredicateV2::NoPendingWork { .. } => {
                return Err(SubjectError::new(
                    "unsupported_capability",
                    "reference model does not expose the exact engine projection",
                ));
            }
        };
        Ok(ScenarioPredicateObservationV2 { matched, actual })
    }
}

#[async_trait]
impl ConvergenceSubject for ReferenceModelSubject {
    fn descriptor(&self) -> SubjectDescriptor {
        self.descriptor.clone()
    }

    async fn create_group(&mut self, action: SubjectCreateGroup<'_>) -> Result<(), SubjectError> {
        self.client(action.creator)?;
        self.validate_clients(action.invitees)?;
        self.validate_clients(action.initial_admins)?;
        if self.client(action.creator)?.state.is_some() {
            return Err(SubjectError::new(
                "group_already_exists",
                format!("client {} already has a group", action.creator),
            ));
        }
        let mut members = BTreeSet::from([action.creator.to_owned()]);
        members.extend(action.invitees.iter().cloned());
        let state = ReferenceGroupState {
            epoch: u64::from(!action.invitees.is_empty()),
            name: action.name.into(),
            members,
            admins: action.initial_admins.iter().cloned().collect(),
        };
        self.stage_state_change(action.creator, action.pending, state, action.invitees);
        Ok(())
    }

    async fn invite_members(
        &mut self,
        action: SubjectInviteMembers<'_>,
    ) -> Result<(), SubjectError> {
        self.validate_clients(action.invitees)?;
        let mut state = self.group_state(action.inviter)?;
        state.epoch = state.epoch.saturating_add(1);
        state.members.extend(action.invitees.iter().cloned());
        self.stage_state_change(action.inviter, action.pending, state, action.invitees);
        Ok(())
    }

    async fn update_group_data(
        &mut self,
        action: SubjectUpdateGroupData<'_>,
    ) -> Result<(), SubjectError> {
        let mut state = self.group_state(action.client)?;
        state.epoch = state.epoch.saturating_add(1);
        state.name = action.name.into();
        self.stage_state_change(action.client, action.pending, state, &[]);
        Ok(())
    }

    async fn remove_members(
        &mut self,
        action: SubjectRemoveMembers<'_>,
    ) -> Result<(), SubjectError> {
        self.validate_clients(action.members)?;
        let mut state = self.group_state(action.remover)?;
        state.epoch = state.epoch.saturating_add(1);
        for member in action.members {
            state.members.remove(member);
            state.admins.remove(member);
        }
        self.stage_state_change(action.remover, action.pending, state, &[]);
        Ok(())
    }

    async fn self_update(&mut self, action: SubjectSelfUpdate<'_>) -> Result<(), SubjectError> {
        let mut state = self.group_state(action.client)?;
        state.epoch = state.epoch.saturating_add(1);
        self.stage_state_change(action.client, action.pending, state, &[]);
        Ok(())
    }

    async fn update_admin_policy(
        &mut self,
        action: SubjectUpdateAdminPolicy<'_>,
    ) -> Result<(), SubjectError> {
        self.validate_clients(action.admins)?;
        let mut state = self.group_state(action.client)?;
        if !state.admins.contains(action.client) {
            return Err(SubjectError::new(
                "not_authorized",
                format!("client {} is not an administrator", action.client),
            ));
        }
        let pending = action.pending.ok_or_else(|| {
            SubjectError::new(
                "not_authorized",
                "reference model requires a successful policy update to name its publication",
            )
        })?;
        state.epoch = state.epoch.saturating_add(1);
        state.admins = action.admins.iter().cloned().collect();
        self.stage_state_change(action.client, pending, state, &[]);
        Ok(())
    }

    async fn send_application(
        &mut self,
        action: SubjectSendApplication<'_>,
    ) -> Result<(), SubjectError> {
        let state = self.group_state(action.sender)?;
        let outbound_id = self.emit(
            action.sender,
            None,
            SubjectOutboundKind::GroupMessage,
            None,
            false,
            None,
        );
        for recipient in state
            .members
            .iter()
            .filter(|member| *member != action.sender)
        {
            self.queued.push(ReferenceDelivery {
                outbound_id: outbound_id.clone(),
                recipient: recipient.clone(),
                effect: ReferenceDeliveryEffect::Application(action.payload.into()),
            });
        }
        Ok(())
    }

    async fn leave(&mut self, _action_id: &str, client: &str) -> Result<(), SubjectError> {
        let mut state = self.group_state(client)?;
        state.epoch = state.epoch.saturating_add(1);
        state.members.remove(client);
        state.admins.remove(client);
        let outbound_id = self.emit(
            client,
            None,
            SubjectOutboundKind::GroupMessage,
            None,
            false,
            None,
        );
        for recipient in &state.members {
            self.queued.push(ReferenceDelivery {
                outbound_id: outbound_id.clone(),
                recipient: recipient.clone(),
                effect: ReferenceDeliveryEffect::State(state.clone()),
            });
        }
        self.client_mut(client)?.state = None;
        Ok(())
    }

    fn deliver_all(&mut self) -> Result<(), SubjectError> {
        let resolutions = self
            .outbound
            .values()
            .map(|record| (record.artifact.outbound_id.clone(), record.resolution))
            .collect::<BTreeMap<_, _>>();
        let mut retained = Vec::new();
        for delivery in self.queued.drain(..) {
            match resolutions.get(&delivery.outbound_id) {
                Some(Some(SubjectOutboundOutcome::ReachedNoEndpoint)) => {}
                Some(None | Some(SubjectOutboundOutcome::Accepted)) => self
                    .mailboxes
                    .entry(delivery.recipient)
                    .or_default()
                    .push(delivery.effect),
                _ => retained.push(delivery),
            }
        }
        self.queued = retained;
        Ok(())
    }

    async fn tick(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        self.validate_clients(clients)?;
        for label in clients {
            let effects = self.mailboxes.remove(label).unwrap_or_default();
            let client = self.client_mut(label)?;
            for effect in effects {
                match effect {
                    ReferenceDeliveryEffect::State(state) => Self::apply_state(client, state),
                    ReferenceDeliveryEffect::Application(payload) => {
                        client.window.received_payloads.push(payload);
                    }
                }
            }
        }
        Ok(())
    }

    fn activate_virtual_time(&mut self) -> Result<(), SubjectError> {
        Ok(())
    }

    async fn advance_time(&mut self, delta_ms: u64) -> Result<(), SubjectError> {
        self.current_monotonic_ms = self.current_monotonic_ms.saturating_add(delta_ms);
        Ok(())
    }

    fn poll_outbound(
        &mut self,
        client: &str,
    ) -> Result<Vec<SubjectOutboundArtifact>, SubjectError> {
        self.client(client)?;
        Ok(self
            .outbound
            .values()
            .filter(|record| record.artifact.client == client && record.resolution.is_none())
            .map(|record| record.artifact.clone())
            .collect())
    }

    async fn acknowledge_outbound(
        &mut self,
        client: &str,
        outbound_id: &str,
        outcome: SubjectOutboundOutcome,
    ) -> Result<(), SubjectError> {
        self.client(client)?;
        let sequence = outbound_id
            .strip_prefix("reference-outbound/")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                SubjectError::new(
                    "unknown_outbound",
                    format!("unknown outbound artifact {outbound_id}"),
                )
            })?;
        let record = self.outbound.get(&sequence).cloned().ok_or_else(|| {
            SubjectError::new(
                "unknown_outbound",
                format!("unknown outbound artifact {outbound_id}"),
            )
        })?;
        if record.artifact.client != client {
            return Err(SubjectError::new(
                "outbound_client_mismatch",
                format!("outbound artifact {outbound_id} does not belong to {client}"),
            ));
        }
        if let Some(previous) = record.resolution {
            return if previous == outcome {
                Ok(())
            } else {
                Err(SubjectError::new(
                    "outbound_already_resolved",
                    format!("outbound artifact {outbound_id} was already resolved as {previous:?}"),
                ))
            };
        }

        if outcome == SubjectOutboundOutcome::Accepted
            && record.artifact.state_confirmation_required
            && let Some(state) = record.local_state
        {
            Self::apply_state(self.client_mut(client)?, state);
        }
        if outcome == SubjectOutboundOutcome::ReachedNoEndpoint {
            self.queued
                .retain(|delivery| delivery.outbound_id != outbound_id);
        }
        self.outbound
            .get_mut(&sequence)
            .expect("validated reference outbound remains present")
            .resolution = Some(outcome);
        Ok(())
    }

    fn structural_progress(&mut self) -> Result<SubjectProgressSnapshot, SubjectError> {
        let outbound_awaiting_acknowledgement = self
            .outbound
            .values()
            .filter(|record| record.resolution.is_none())
            .count();
        let mailbox_messages = self.mailboxes.values().map(Vec::len).sum::<usize>();
        let clients = self
            .clients
            .keys()
            .map(|client| ClientStructuralProgress {
                client: client.clone(),
                engine: None,
                scenario_inputs_pending: 0,
            })
            .collect::<Vec<_>>();
        let mut snapshot = SubjectProgressSnapshot {
            schema_version: "1".into(),
            structural_token: String::new(),
            current_monotonic_ms: self.current_monotonic_ms,
            runnable_engine_work: 0,
            runnable_work: self.queued.len().saturating_add(mailbox_messages),
            earliest_next_wake_monotonic_ms: None,
            deferred_retry_work: 0,
            outbound_awaiting_acknowledgement,
            transport_queued_messages: self.queued.len(),
            transport_delayed_messages: 0,
            transport_mailbox_messages: mailbox_messages,
            scenario_inputs_pending: 0,
            terminal_blockers: Vec::new(),
            clients,
        };
        let encoded = serde_json::to_vec(&snapshot).map_err(|error| {
            SubjectError::new(
                "progress_serialization_failed",
                format!("serialize structural progress: {error}"),
            )
        })?;
        snapshot.structural_token = hex::encode(Sha256::digest(encoded));
        Ok(snapshot)
    }

    fn observe(&mut self, clients: &[String]) -> Result<Vec<ClientObservation>, SubjectError> {
        clients
            .iter()
            .map(|client| self.observation(client))
            .collect()
    }

    fn observe_admin_policy(
        &self,
        clients: &[String],
    ) -> Result<Vec<ScenarioAdminPolicyObservation>, SubjectError> {
        clients
            .iter()
            .map(|client| {
                Ok(ScenarioAdminPolicyObservation {
                    client: client.clone(),
                    admins: self.group_state(client)?.admins.into_iter().collect(),
                })
            })
            .collect()
    }

    fn evaluate_predicate(
        &mut self,
        predicate: &ScenarioPredicateV2,
    ) -> Result<ScenarioPredicateObservationV2, SubjectError> {
        self.predicate_observation(predicate)
    }

    fn clear_events(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        self.validate_clients(clients)?;
        for client in clients {
            self.client_mut(client)?.window = ReferenceEventWindow::default();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EngineHarnessSubject, HarnessStorageMode, ScenarioAssertionV2, ScenarioSpec, ScenarioStep,
        run_scenario_report_with_subject,
    };
    use cgka_traits::group::ProtocolProfile;

    fn cross_adapter_scenario() -> ScenarioSpec {
        ScenarioSpec {
            name: "scenario-ir/reference-engine-common".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: Default::default(),
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
                ScenarioStep::DeliverAll,
                ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                ScenarioStep::Assert {
                    assertion: ScenarioAssertionV2::Exactly {
                        predicate: ScenarioPredicateV2::PayloadCount {
                            client: "bob".into(),
                            payload: "hello".into(),
                            count: 1,
                        },
                    },
                },
                ScenarioStep::Observe {
                    clients: vec!["alice".into(), "bob".into()],
                },
            ],
        }
    }

    #[tokio::test]
    async fn one_compiled_scenario_runs_unchanged_on_reference_and_engine_adapters() {
        let scenario = cross_adapter_scenario();
        let mut reference = ReferenceModelSubject::new(&scenario.clients).unwrap();
        let reference_report =
            run_scenario_report_with_subject(&scenario, None, vec![], &mut reference)
                .await
                .expect("reference scenario");
        let mut engine = EngineHarnessSubject::new(
            &scenario.clients,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .unwrap();
        let engine_report = run_scenario_report_with_subject(&scenario, None, vec![], &mut engine)
            .await
            .expect("engine scenario");

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
                        observation.received_payloads.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(semantic(&reference_report), semantic(&engine_report));
        assert_ne!(
            reference_report.metadata.subject, engine_report.metadata.subject,
            "the common trace must come from distinct adapters"
        );
    }

    #[tokio::test]
    async fn unsupported_exact_assertion_fails_before_reference_model_executes() {
        let scenario = ScenarioSpec {
            name: "scenario-ir/reference-preflight".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into(), "bob".into()],
            topology: Default::default(),
            steps: vec![
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "must-not-run".into(),
                },
                ScenarioStep::Assert {
                    assertion: ScenarioAssertionV2::Exactly {
                        predicate: ScenarioPredicateV2::ClientsExactlyEquivalent {
                            clients: vec!["alice".into(), "bob".into()],
                        },
                    },
                },
            ],
        };
        let mut reference = ReferenceModelSubject::new(&scenario.clients).unwrap();

        let error = run_scenario_report_with_subject(&scenario, None, vec![], &mut reference)
            .await
            .expect_err("exact projection must fail reference preflight");

        assert_eq!(error.step_index, Some(1));
        assert!(error.message.contains("exact_conformance_observation"));
        assert!(reference.poll_outbound("alice").unwrap().is_empty());
    }
}
