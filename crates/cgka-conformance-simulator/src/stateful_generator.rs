//! Stateful, legality-aware generation of product-shaped canonical scenarios.
//!
//! The generator owns only a small symbolic model. It emits ordinary
//! [`ScenarioSpec`] values and relies on the existing compiler, subjects,
//! reports, failure capsules, and reducer for execution and replay.

use std::collections::{BTreeMap, BTreeSet};

use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

use crate::{
    GeneratedScenarioCase, GeneratedSubjectKind, QuiescencePolicy, ScenarioAccountV2,
    ScenarioDeviceV2, ScenarioOutboundSelection, ScenarioProcessV2, ScenarioRelaySyncModeV2,
    ScenarioRelayV2, ScenarioSpec, ScenarioStep, ScenarioTopologyV2, SubjectOutboundOutcome,
    TraceExpectation,
};

pub const PUBLIC_APP_LARGE_GROUP_FAMILY: &str = "public-app-large-group/v1";

pub const STATEFUL_CHAT_JOURNEY_FAMILY: &str = "chat-journey/v1";
pub const STATEFUL_CHAT_JOURNEY_GENERATOR_VERSION: &str = "2";

pub const PUBLIC_APP_SEND_LEAVE_FAMILY: &str = "public-app-send-leave/v1";
pub const PUBLIC_APP_MEMBERSHIP_REENTRY_FAMILY: &str = "public-app-membership-reentry/v1";
pub const PUBLIC_APP_OFFLINE_RECOVERY_FAMILY: &str = "public-app-offline-recovery/v1";
pub const PUBLIC_APP_ADMIN_HANDOFF_FAMILY: &str = "public-app-admin-handoff/v1";
pub const PUBLIC_APP_JOURNEY_GENERATOR_VERSION: &str = "4";
pub const PUBLIC_APP_ADMIN_CHURN_FAMILY: &str = "public-app-admin-churn/v1";
pub const PUBLIC_APP_LATE_JOIN_FAMILY: &str = "public-app-late-join/v1";
pub const PUBLIC_APP_PRESSURE_GENERATOR_VERSION: &str = "1";
pub const PUBLIC_APP_RECOVERY_SCHEDULES_FAMILY: &str = "public-app-recovery-schedules/v1";
pub const PUBLIC_APP_STATEFUL_RECOVERY_FAMILY: &str = "public-app-stateful-recovery/v1";

pub const PUBLIC_APP_BACKLOG_RECOVERY_FAMILY: &str = "public-app-backlog-recovery/v1";

const CLIENTS: [&str; 4] = ["alice", "bob", "carol", "david"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JourneyProfile {
    Membership,
    OfflineRetainedHistory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JourneyActionKind {
    Invite,
    Remove,
    Send,
    UpdateProfile,
    UpdateAdminPolicy,
    SelfUpdate,
    SetOffline,
    Reconnect,
    Restart,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum JourneyAction {
    Invite { invitee: String },
    Remove { member: String },
    Send { sender: String },
    UpdateProfile { actor: String },
    UpdateAdminPolicy { target: String },
    SelfUpdate { client: String },
    SetOffline,
    Reconnect,
    Restart { client: String },
}

impl JourneyAction {
    fn kind(&self) -> JourneyActionKind {
        match self {
            Self::Invite { .. } => JourneyActionKind::Invite,
            Self::Remove { .. } => JourneyActionKind::Remove,
            Self::Send { .. } => JourneyActionKind::Send,
            Self::UpdateProfile { .. } => JourneyActionKind::UpdateProfile,
            Self::UpdateAdminPolicy { .. } => JourneyActionKind::UpdateAdminPolicy,
            Self::SelfUpdate { .. } => JourneyActionKind::SelfUpdate,
            Self::SetOffline => JourneyActionKind::SetOffline,
            Self::Reconnect => JourneyActionKind::Reconnect,
            Self::Restart { .. } => JourneyActionKind::Restart,
        }
    }
}

struct JourneyModel {
    clients: Vec<String>,
    offline_client: String,
    public_app: bool,
    batch_public_sends: bool,
    compact_public_payload_checks: bool,
    profile: JourneyProfile,
    case_index: u64,
    epoch: u64,
    members: BTreeSet<String>,
    admins: BTreeSet<String>,
    online: BTreeSet<String>,
    non_members: BTreeSet<String>,
    group_name: String,
    group_description: String,
    received_payloads: BTreeMap<String, Vec<String>>,
    self_updated_clients: BTreeSet<String>,
    publication_sequence: u64,
    payload_sequence: u64,
    profile_sequence: u64,
    steps: Vec<ScenarioStep>,
    expected: Vec<TraceExpectation>,
}

impl JourneyModel {
    fn new(case_index: u64, profile: JourneyProfile) -> Self {
        Self::with_clients(case_index, profile, client_labels(), "bob".into())
    }

    fn with_clients(
        case_index: u64,
        profile: JourneyProfile,
        clients: Vec<String>,
        offline_client: String,
    ) -> Self {
        let group_name = format!("chat-journey-{case_index}");
        let (members, non_members, founding_invitees) = match profile {
            JourneyProfile::Membership => (
                BTreeSet::from(["alice".into(), "bob".into()]),
                BTreeSet::from(["carol".into(), "david".into()]),
                vec!["bob".into()],
            ),
            JourneyProfile::OfflineRetainedHistory => (
                clients.iter().cloned().collect(),
                BTreeSet::new(),
                clients
                    .iter()
                    .filter(|client| client.as_str() != "alice")
                    .cloned()
                    .collect(),
            ),
        };
        let mut model = Self {
            clients: clients.clone(),
            offline_client,
            public_app: false,
            batch_public_sends: false,
            compact_public_payload_checks: false,
            profile,
            case_index,
            epoch: 1,
            members,
            admins: BTreeSet::from(["alice".into()]),
            online: clients.iter().cloned().collect(),
            non_members,
            group_name: group_name.clone(),
            group_description: String::new(),
            received_payloads: clients
                .iter()
                .cloned()
                .map(|client| (client, Vec::new()))
                .collect(),
            self_updated_clients: BTreeSet::new(),
            publication_sequence: 0,
            payload_sequence: 0,
            profile_sequence: case_index % 3,
            steps: vec![ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: group_name,
                invitees: founding_invitees,
                required_features: Vec::new(),
                initial_admins: Some(vec!["alice".into()]),
                pending: "create".into(),
            }],
            expected: Vec::new(),
        };
        model.confirm_publication("alice", "create");
        model.steps.push(ScenarioStep::DeliverAll);
        model.steps.push(ScenarioStep::Tick {
            clients: model.members.iter().cloned().collect(),
        });
        model.steps.push(ScenarioStep::ClearEvents {
            clients: clients.clone(),
        });
        model
    }

    fn legal_actions(&self) -> Vec<JourneyAction> {
        let mut actions = Vec::new();

        if self.profile == JourneyProfile::Membership && self.online.contains("alice") {
            actions.extend(
                self.non_members
                    .iter()
                    .cloned()
                    .map(|invitee| JourneyAction::Invite { invitee }),
            );
        }
        // Keep the two founders active and pending-free for the scoped
        // Membership terminal oracle, and retain a non-founder victim so the
        // forced Remove rotation always has at least one legal choice.
        actions.extend(
            self.members
                .iter()
                .filter(|member| {
                    member.as_str() != "alice"
                        && member.as_str() != self.offline_client
                        && !self.admins.contains(*member)
                })
                .cloned()
                .map(|member| JourneyAction::Remove { member }),
        );
        actions.extend(
            self.members
                .intersection(&self.online)
                .cloned()
                .map(|sender| JourneyAction::Send { sender }),
        );
        actions.extend(
            self.admins
                .intersection(&self.online)
                .cloned()
                .map(|actor| JourneyAction::UpdateProfile { actor }),
        );
        if self.online.contains("alice") {
            actions.extend(
                self.members
                    .iter()
                    .filter(|member| member.as_str() != "alice")
                    .cloned()
                    .map(|target| JourneyAction::UpdateAdminPolicy { target }),
            );
        }
        actions.extend(
            self.members
                .intersection(&self.online)
                .filter(|client| !self.self_updated_clients.contains(*client))
                .cloned()
                .map(|client| JourneyAction::SelfUpdate { client }),
        );
        if self.profile == JourneyProfile::OfflineRetainedHistory {
            if self.online.contains(&self.offline_client) {
                actions.push(JourneyAction::SetOffline);
            } else {
                actions.push(JourneyAction::Reconnect);
            }
        }
        actions.extend(
            self.members
                .intersection(&self.online)
                .cloned()
                .map(|client| JourneyAction::Restart { client }),
        );
        actions
    }

    fn choose_kind(&self, rng: &mut StdRng, kind: JourneyActionKind) -> JourneyAction {
        let choices = self
            .legal_actions()
            .into_iter()
            .filter(|action| action.kind() == kind)
            .collect::<Vec<_>>();
        assert!(
            !choices.is_empty(),
            "no legal {kind:?} action in generated case {}",
            self.case_index
        );
        choices[rng.gen_range(0..choices.len())].clone()
    }

    fn choose_non_restart(&self, rng: &mut StdRng) -> JourneyAction {
        let choices = self
            .legal_actions()
            .into_iter()
            .filter(|action| action.kind() != JourneyActionKind::Restart)
            .collect::<Vec<_>>();
        choices[rng.gen_range(0..choices.len())].clone()
    }

    fn apply(&mut self, action: JourneyAction) {
        match action {
            JourneyAction::Invite { invitee } => {
                debug_assert!(self.non_members.contains(&invitee));
                let pending = self.next_publication("invite");
                self.steps.push(ScenarioStep::InviteMembers {
                    inviter: "alice".into(),
                    invitees: vec![invitee.clone()],
                    pending: pending.clone(),
                });
                self.members.insert(invitee.clone());
                self.non_members.remove(&invitee);
                self.online.insert(invitee.clone());
                self.confirmed_mutation("alice", &pending);
            }
            JourneyAction::Remove { member } => {
                debug_assert!(self.members.contains(&member));
                debug_assert!(!self.admins.contains(&member));
                let pending = self.next_publication("remove");
                self.steps.push(ScenarioStep::RemoveMembers {
                    remover: "alice".into(),
                    members: vec![member.clone()],
                    pending: pending.clone(),
                });
                self.members.remove(&member);
                self.non_members.insert(member.clone());
                self.self_updated_clients.remove(&member);
                self.confirmed_mutation("alice", &pending);
            }
            JourneyAction::Send { sender } => {
                debug_assert!(self.members.contains(&sender));
                debug_assert!(self.online.contains(&sender));
                let payload = format!(
                    "journey-{}-message-{}-from-{sender}",
                    self.case_index, self.payload_sequence
                );
                self.payload_sequence = self.payload_sequence.saturating_add(1);
                self.steps.push(ScenarioStep::SendAppMessage {
                    sender: sender.clone(),
                    payload: payload.clone(),
                });
                self.steps.push(accept_all_outbound(&sender));
                for recipient in self
                    .members
                    .iter()
                    .filter(|client| self.public_app || **client != sender)
                {
                    self.received_payloads
                        .get_mut(recipient)
                        .expect("all clients have a delivery ledger")
                        .push(payload.clone());
                }
                if !self.batch_public_sends {
                    self.deliver_to_online();
                    if self.public_app {
                        self.public_delivered_payload_checkpoint(&payload);
                    }
                }
            }
            JourneyAction::UpdateProfile { actor } => {
                debug_assert!(self.admins.contains(&actor));
                debug_assert!(self.online.contains(&actor));
                let sequence = self.profile_sequence;
                self.profile_sequence = self.profile_sequence.saturating_add(1);
                let (name, description) = match sequence % 3 {
                    0 => (
                        Some(format!("chat-journey-{}-name-{sequence}", self.case_index)),
                        None,
                    ),
                    1 => (
                        None,
                        Some(format!(
                            "chat journey {} description {sequence}",
                            self.case_index
                        )),
                    ),
                    _ => (
                        Some(format!("chat-journey-{}-name-{sequence}", self.case_index)),
                        Some(format!(
                            "chat journey {} description {sequence}",
                            self.case_index
                        )),
                    ),
                };
                let pending = self.next_publication("profile");
                self.steps.push(ScenarioStep::UpdateGroupProfile {
                    client: actor.clone(),
                    name: name.clone(),
                    description: description.clone(),
                    pending: pending.clone(),
                });
                if let Some(name) = name {
                    self.group_name = name;
                }
                if let Some(description) = description {
                    self.group_description = description;
                }
                self.confirmed_mutation(&actor, &pending);
            }
            JourneyAction::UpdateAdminPolicy { target } => {
                debug_assert!(self.members.contains(&target));
                let mut admins = self.admins.clone();
                if !admins.remove(&target) {
                    admins.insert(target);
                }
                admins.insert("alice".into());
                let pending = self.next_publication("admins");
                self.steps.push(ScenarioStep::UpdateAdminPolicy {
                    client: "alice".into(),
                    admins: admins.iter().cloned().collect(),
                    pending: pending.clone(),
                });
                self.admins = admins;
                self.confirmed_mutation("alice", &pending);
            }
            JourneyAction::SelfUpdate { client } => {
                debug_assert!(self.members.contains(&client));
                debug_assert!(self.online.contains(&client));
                let pending = self.next_publication("self-update");
                self.steps.push(ScenarioStep::SelfUpdate {
                    client: client.clone(),
                    pending: pending.clone(),
                });
                self.self_updated_clients.insert(client.clone());
                self.confirmed_mutation(&client, &pending);
            }
            JourneyAction::SetOffline => {
                debug_assert!(self.online.contains(&self.offline_client));
                self.steps.push(ScenarioStep::SetClientOffline {
                    client: self.offline_client.clone(),
                });
                self.online.remove(&self.offline_client);
            }
            JourneyAction::Reconnect => self.reconnect_offline_client(),
            JourneyAction::Restart { client } => {
                debug_assert!(self.public_app || self.members.contains(&client));
                debug_assert!(self.online.contains(&client));
                self.steps.push(ScenarioStep::RestartClient {
                    client: client.clone(),
                });
                if !self.public_app {
                    self.received_payloads
                        .get_mut(&client)
                        .expect("all clients have a delivery ledger")
                        .clear();
                }
                self.deliver_to_online();
                if self.public_app {
                    self.public_state_checkpoint();
                    self.public_payload_checkpoint();
                }
            }
        }
    }

    fn next_publication(&mut self, kind: &str) -> String {
        let value = format!("{kind}-{}", self.publication_sequence);
        self.publication_sequence = self.publication_sequence.saturating_add(1);
        value
    }

    fn confirm_publication(&mut self, client: &str, pending: &str) {
        let step_index = self.steps.len();
        self.steps.push(ScenarioStep::AcknowledgeOutbound {
            client: client.into(),
            publication: Some(pending.into()),
            selection: ScenarioOutboundSelection::All,
            outcome: SubjectOutboundOutcome::Accepted,
        });
        self.expected.push(TraceExpectation::PendingResolution {
            step_index,
            client: client.into(),
            pending: pending.into(),
            resolution: "confirmed".into(),
        });
    }

    fn confirmed_mutation(&mut self, client: &str, pending: &str) {
        self.confirm_publication(client, pending);
        self.epoch = self.epoch.saturating_add(1);
        self.deliver_to_online();
        if self.public_app {
            self.public_state_checkpoint();
        }
    }

    fn deliver_to_online(&mut self) {
        self.steps.push(ScenarioStep::DeliverAll);
        self.steps.push(ScenarioStep::Tick {
            clients: self.online.iter().cloned().collect(),
        });
    }

    fn reconnect_offline_client(&mut self) {
        debug_assert!(!self.online.contains(&self.offline_client));
        self.steps.push(ScenarioStep::ReconnectClient {
            client: self.offline_client.clone(),
        });
        self.online.insert(self.offline_client.clone());
        self.steps.push(ScenarioStep::SyncRelayHistory {
            clients: vec![self.offline_client.clone()],
            sync: ScenarioRelaySyncModeV2::FullHistory,
        });
        self.steps.push(ScenarioStep::Tick {
            clients: vec![self.offline_client.clone()],
        });
        if self.public_app {
            self.public_state_checkpoint();
            self.public_payload_checkpoint();
        }
    }

    fn finish(mut self, seed: u64) -> GeneratedScenarioCase {
        if self.profile == JourneyProfile::OfflineRetainedHistory && !self.online.contains("bob") {
            self.reconnect_offline_client();
        }

        let active = self.members.iter().cloned().collect::<Vec<_>>();
        let pending_free_clients = match self.profile {
            JourneyProfile::Membership => vec!["alice".into(), "bob".into()],
            JourneyProfile::OfflineRetainedHistory => active.clone(),
        };
        for client in &active {
            self.steps.push(accept_all_outbound(client));
        }
        self.deliver_to_online();
        if self.profile == JourneyProfile::OfflineRetainedHistory {
            self.steps.push(ScenarioStep::AwaitQuiescence {
                policy: QuiescencePolicy::default(),
            });
        }
        self.steps.push(ScenarioStep::ObserveAdminPolicy {
            clients: active.clone(),
        });
        self.steps.push(ScenarioStep::ObserveExact {
            clients: active.clone(),
        });
        self.steps
            .push(ScenarioStep::ProbeBidirectionalDecryptability {
                clients: active.clone(),
            });

        for client in &active {
            self.expected.push(TraceExpectation::AdminPolicy {
                client: client.clone(),
                admins: self.admins.iter().cloned().collect(),
            });
            self.expected.push(TraceExpectation::ClientState {
                client: client.clone(),
                epoch: self.epoch,
                member_count: active.len(),
                received_payloads: Some(
                    self.received_payloads
                        .get(client)
                        .expect("all clients have a delivery ledger")
                        .clone(),
                ),
                added_members: None,
                removed_members: None,
            });
            self.expected.push(TraceExpectation::GroupProfile {
                client: client.clone(),
                name: self.group_name.clone(),
                description: self.group_description.clone(),
            });
        }
        self.expected.push(TraceExpectation::ClientsConverged {
            clients: active.clone(),
            epoch: Some(self.epoch),
            member_count: Some(active.len()),
        });
        self.expected
            .push(TraceExpectation::ClientsExactlyEquivalent {
                clients: active.clone(),
            });
        self.expected.push(TraceExpectation::NoPendingWork {
            clients: pending_free_clients,
        });
        self.expected
            .push(TraceExpectation::ClientsBidirectionallyDecryptable { clients: active });

        GeneratedScenarioCase {
            family_name: STATEFUL_CHAT_JOURNEY_FAMILY.into(),
            generator_version: STATEFUL_CHAT_JOURNEY_GENERATOR_VERSION.into(),
            seed,
            case_index: self.case_index,
            workload_profile: None,
            subject: match self.profile {
                JourneyProfile::Membership => GeneratedSubjectKind::Engine,
                JourneyProfile::OfflineRetainedHistory => GeneratedSubjectKind::RetainedRelay,
            },
            scenario: ScenarioSpec {
                name: format!("chat-journey/v1/case-{}", self.case_index),
                spec_version: "3".into(),
                clients: client_labels(),
                topology: match self.profile {
                    JourneyProfile::Membership => ScenarioTopologyV2::default(),
                    JourneyProfile::OfflineRetainedHistory => single_relay_topology(),
                },
                steps: self.steps,
            },
            expected_outcomes: self.expected,
        }
    }

    fn new_public(case_index: u64) -> Self {
        let mut model = Self::new(case_index, JourneyProfile::OfflineRetainedHistory);
        model.public_app = true;
        model.public_state_checkpoint();
        model
    }

    fn eventually(&mut self, predicate: crate::ScenarioPredicateV2) {
        self.steps.push(ScenarioStep::Assert {
            assertion: crate::ScenarioAssertionV2::Eventually {
                predicate,
                max_iterations: 30,
            },
        });
    }

    fn public_state_checkpoint(&mut self) {
        let clients = self
            .members
            .intersection(&self.online)
            .cloned()
            .collect::<Vec<_>>();
        // Preserve the old aggregate allowance of 30 rounds per online member,
        // but require every member to satisfy the state contract together.
        let max_iterations = 30 * clients.len();
        self.steps.push(ScenarioStep::Assert {
            assertion: crate::ScenarioAssertionV2::Eventually {
                predicate: crate::ScenarioPredicateV2::PublicGroupState {
                    clients,
                    members: self.members.iter().cloned().collect(),
                    admins: self.admins.iter().cloned().collect(),
                    name: self.group_name.clone(),
                    description: self.group_description.clone(),
                    minimum_epoch: self.epoch,
                },
                max_iterations,
            },
        });
    }

    fn public_delivered_payload_checkpoint(&mut self, payload: &str) {
        // Generated payloads are unique. Only current online members can have
        // received this send; full history checks belong at persistence boundaries.
        for client in self
            .members
            .intersection(&self.online)
            .cloned()
            .collect::<Vec<_>>()
        {
            self.eventually(crate::ScenarioPredicateV2::PayloadCount {
                client,
                payload: payload.to_owned(),
                count: 1,
            });
        }
    }

    fn public_payload_checkpoint(&mut self) {
        if self.compact_public_payload_checks {
            for client in self.online.iter().cloned().collect::<Vec<_>>() {
                self.eventually(crate::ScenarioPredicateV2::PublicPayloadMultiset {
                    payloads: self.received_payloads[&client].clone(),
                    client,
                });
            }
            return;
        }
        // Public history includes the sender's accepted message and survives
        // reopen. The engine event ledger deliberately has different semantics.
        for client in self.online.iter().cloned().collect::<Vec<_>>() {
            for payload in self.received_payloads[&client].clone() {
                self.eventually(crate::ScenarioPredicateV2::PayloadCount {
                    client: client.clone(),
                    payload,
                    count: 1,
                });
            }
        }
    }

    fn public_leave(&mut self, client: &str) {
        assert!(self.public_app && self.members.contains(client) && !self.admins.contains(client));
        self.steps.push(ScenarioStep::Leave {
            client: client.into(),
        });
        self.members.remove(client);
        self.non_members.insert(client.into());
        self.epoch += 1;
        self.deliver_to_online();
        // A leave publishes a request; the remaining members must apply
        // it before we count later traffic as outside the departed membership.
        self.public_state_checkpoint();
    }

    fn finish_public(mut self, family: &str, seed: u64) -> GeneratedScenarioCase {
        self.public_state_checkpoint();
        self.public_payload_checkpoint();
        let active = self.members.iter().cloned().collect::<Vec<_>>();
        self.steps.push(ScenarioStep::ObserveAdminPolicy {
            clients: active.clone(),
        });
        self.steps.push(ScenarioStep::Observe {
            clients: self.clients.clone(),
        });
        self.expected.push(TraceExpectation::ClientsConverged {
            clients: active.clone(),
            epoch: None,
            member_count: Some(active.len()),
        });
        for client in &active {
            self.expected.extend([
                TraceExpectation::GroupProfile {
                    client: client.clone(),
                    name: self.group_name.clone(),
                    description: self.group_description.clone(),
                },
                TraceExpectation::AdminPolicy {
                    client: client.clone(),
                    admins: self.admins.iter().cloned().collect(),
                },
            ]);
        }
        // Include departed clients: duplicate, missing and post-departure
        // messages all fail the exact public history contract.
        for (client, payloads) in self.received_payloads {
            self.expected
                .push(TraceExpectation::ApplicationPayloadMultiset { client, payloads });
        }
        GeneratedScenarioCase {
            family_name: family.into(),
            generator_version: PUBLIC_APP_JOURNEY_GENERATOR_VERSION.into(),
            seed,
            case_index: self.case_index,
            workload_profile: None,
            subject: GeneratedSubjectKind::AppRuntime,
            scenario: ScenarioSpec {
                name: format!("{family}/case-{}", self.case_index),
                spec_version: "3".into(),
                clients: self.clients.clone(),
                topology: single_relay_topology_for(&self.clients),
                steps: self.steps,
            },
            expected_outcomes: self.expected,
        }
    }
}

/// Public companions share the symbolic action model, but own an explicit
/// projection/persistence oracle. Seeds choose traffic and actors; the index
/// rotates required lifecycle interactions. Socket scheduling is not seeded.
pub fn generate_public_app_journey_case(
    family: &str,
    seed: u64,
    case_index: u64,
) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4150_505f_4a4f_5552 ^ case_index.rotate_left(23));
    let mut model = JourneyModel::new_public(case_index);
    let victim = CLIENTS[1 + rng.gen_range(0..3)].to_owned();
    model.apply(JourneyAction::Send {
        sender: victim.clone(),
    });
    match family {
        PUBLIC_APP_SEND_LEAVE_FAMILY => {
            if case_index.is_multiple_of(2) {
                model.apply(JourneyAction::Restart {
                    client: victim.clone(),
                });
            }
            model.public_leave(&victim);
            model.apply(JourneyAction::UpdateProfile {
                actor: "alice".into(),
            });
        }
        PUBLIC_APP_MEMBERSHIP_REENTRY_FAMILY => {
            for _ in 0..1 + case_index % 2 {
                model.apply(JourneyAction::Remove {
                    member: victim.clone(),
                });
                model.apply(JourneyAction::Send {
                    sender: "alice".into(),
                });
                if (case_index / 2).is_multiple_of(2) {
                    model.apply(JourneyAction::Restart {
                        client: victim.clone(),
                    });
                }
                model.apply(JourneyAction::Invite {
                    invitee: victim.clone(),
                });
                model.apply(JourneyAction::Send {
                    sender: victim.clone(),
                });
            }
            model.apply(JourneyAction::UpdateProfile {
                actor: "alice".into(),
            });
        }
        PUBLIC_APP_OFFLINE_RECOVERY_FAMILY => {
            for _ in 0..1 + case_index / 3 % 2 {
                model.apply(JourneyAction::SetOffline);
                for index in 0..[4, 8, 12][case_index as usize % 3] {
                    if index % 4 == 2 {
                        model.apply(JourneyAction::UpdateProfile {
                            actor: "alice".into(),
                        });
                    }
                    let action = model.choose_kind(&mut rng, JourneyActionKind::Send);
                    model.apply(action);
                }
                model.apply(JourneyAction::Reconnect);
                model.apply(JourneyAction::Send {
                    sender: "bob".into(),
                });
            }
        }
        PUBLIC_APP_ADMIN_HANDOFF_FAMILY => {
            for _ in 0..1 + case_index % 2 {
                model.apply(JourneyAction::UpdateAdminPolicy {
                    target: victim.clone(),
                });
                // The delegated member must exercise the permission, including
                // after reopen, before the founder revokes it.
                if (case_index / 2).is_multiple_of(2) {
                    model.apply(JourneyAction::Restart {
                        client: victim.clone(),
                    });
                }
                model.apply(JourneyAction::UpdateProfile {
                    actor: victim.clone(),
                });
                model.apply(JourneyAction::Send {
                    sender: victim.clone(),
                });
                model.apply(JourneyAction::UpdateAdminPolicy {
                    target: victim.clone(),
                });
                if !(case_index / 2).is_multiple_of(2) {
                    model.apply(JourneyAction::Restart {
                        client: victim.clone(),
                    });
                }
                let refusal_step = model.steps.len();
                let mut forbidden_admins = model.admins.clone();
                forbidden_admins.insert(victim.clone());
                model
                    .steps
                    .push(ScenarioStep::ExpectUpdateAdminPolicyError {
                        client: victim.clone(),
                        admins: forbidden_admins.into_iter().collect(),
                        error: "not_group_admin".into(),
                    });
                model.expected.push(TraceExpectation::ExpectedError {
                    step_index: refusal_step,
                    client: victim.clone(),
                    operation: "update_admin_policy".into(),
                    error: "not_group_admin".into(),
                });
                model.public_state_checkpoint();
                model.apply(JourneyAction::Send {
                    sender: victim.clone(),
                });
            }
            // Preserve the delegated profile in the terminal oracle. A later
            // founder edit would hide a missing delegated profile projection.
        }
        _ => panic!("unregistered public app journey family: {family}"),
    }
    // Every current member must actually send and receive after the transition,
    // and a recipient's complete history must survive an orderly reopen.
    for sender in model.members.iter().cloned().collect::<Vec<_>>() {
        model.apply(JourneyAction::Send { sender });
    }
    let restart = model.choose_kind(&mut rng, JourneyActionKind::Restart);
    model.apply(restart);
    model.apply(JourneyAction::Send {
        sender: "alice".into(),
    });
    model.finish_public(family, seed)
}

/// Public companions for the serialized admin-churn and latecomer motifs.
/// They deliberately own public history/state oracles rather than weakening
/// the exact/private assertions of their engine counterparts.
pub fn generate_public_app_pressure_case(
    family: &str,
    seed: u64,
    case_index: u64,
) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4150_505f_5052_4553 ^ case_index.rotate_left(23));
    let mut model = match family {
        PUBLIC_APP_ADMIN_CHURN_FAMILY => JourneyModel::new_public(case_index),
        PUBLIC_APP_LATE_JOIN_FAMILY => {
            let mut model = JourneyModel::new(case_index, JourneyProfile::Membership);
            model.public_app = true;
            model.public_state_checkpoint();
            model
        }
        _ => panic!("unregistered public pressure family: {family}"),
    };
    model.apply(JourneyAction::Send {
        sender: "alice".into(),
    });
    match family {
        PUBLIC_APP_ADMIN_CHURN_FAMILY => {
            let delegate = CLIENTS[1 + rng.gen_range(0..3)].to_owned();
            model.apply(JourneyAction::UpdateAdminPolicy { target: delegate });
            let rounds = [4, 8, 16][case_index as usize % 3];
            for round in 0..rounds {
                let kind = if round % 2 == 0 {
                    JourneyActionKind::UpdateProfile
                } else {
                    JourneyActionKind::UpdateAdminPolicy
                };
                let action = model.choose_kind(&mut rng, kind);
                model.apply(action);
                let send = model.choose_kind(&mut rng, JourneyActionKind::Send);
                model.apply(send);
                if round + 1 == rounds / 2 {
                    let restart = model.choose_kind(&mut rng, JourneyActionKind::Restart);
                    model.apply(restart);
                }
            }
        }
        PUBLIC_APP_LATE_JOIN_FAMILY => {
            // Cross the retained-context horizon in the largest arm before
            // asking a fresh Welcome to establish the current public state.
            let commits = [4, 12, 36][case_index as usize % 3];
            for index in 0..commits {
                model.apply(JourneyAction::UpdateProfile {
                    actor: "alice".into(),
                });
                if index % 4 == 3 {
                    let send = model.choose_kind(&mut rng, JourneyActionKind::Send);
                    model.apply(send);
                }
            }
            if (case_index / 3).is_multiple_of(2) {
                model.apply(JourneyAction::Restart {
                    client: "alice".into(),
                });
            }
            let joiners = if rng.gen_bool(0.5) {
                ["carol", "david"]
            } else {
                ["david", "carol"]
            };
            for invitee in joiners {
                model.apply(JourneyAction::Invite {
                    invitee: invitee.into(),
                });
                model.apply(JourneyAction::UpdateProfile {
                    actor: "alice".into(),
                });
                if !(case_index / 3).is_multiple_of(2) {
                    model.apply(JourneyAction::Restart {
                        client: invitee.into(),
                    });
                }
                model.apply(JourneyAction::Send {
                    sender: invitee.into(),
                });
            }
        }
        _ => unreachable!(),
    }
    for sender in model.members.iter().cloned().collect::<Vec<_>>() {
        model.apply(JourneyAction::Send { sender });
    }
    let restart = model.choose_kind(&mut rng, JourneyActionKind::Restart);
    model.apply(restart);
    model.apply(JourneyAction::Send {
        sender: "alice".into(),
    });
    let mut case = model.finish_public(family, seed);
    case.generator_version = PUBLIC_APP_PRESSURE_GENERATOR_VERSION.into();
    case
}

/// Intermediate retained-history pressure, with a reopen after the first
/// recovery request in half the cases. Socket scheduling may finish recovery
/// before that reopen; the input pins the boundary, not a partial row count.
pub fn generate_public_app_backlog_case(seed: u64, case_index: u64) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4241_434b_4c4f_4753 ^ case_index.rotate_left(23));
    let mut model = JourneyModel::new_public(case_index);
    model.apply(JourneyAction::Send {
        sender: "bob".into(),
    });
    model.apply(JourneyAction::SetOffline);
    // Public sends already publish to the live relay. Batch projection checks
    // at commit/recovery boundaries instead of doing a round trip per payload
    // per participant. The terminal oracle still requires every payload once.
    model.batch_public_sends = true;
    let messages = [64, 128, 256][case_index as usize % 3];
    for index in 0..messages {
        if index % 16 == 8 {
            let action = model.choose_kind(&mut rng, JourneyActionKind::UpdateProfile);
            model.apply(action);
        }
        if index % 32 == 16 {
            // Keep the offline recipient a non-admin throughout. Online
            // delegates exercise their authority in subsequent profile edits.
            model.apply(JourneyAction::UpdateAdminPolicy {
                target: "carol".into(),
            });
        }
        let action = model.choose_kind(&mut rng, JourneyActionKind::Send);
        model.apply(action);
    }
    model.batch_public_sends = false;
    if (case_index / 3).is_multiple_of(2) {
        model.apply(JourneyAction::Reconnect);
    } else {
        // Do not call reconnect_bob(): that helper waits for full recovery
        // before returning, which would erase this restart boundary.
        model.steps.extend([
            ScenarioStep::ReconnectClient {
                client: "bob".into(),
            },
            ScenarioStep::SyncRelayHistory {
                clients: vec!["bob".into()],
                sync: ScenarioRelaySyncModeV2::FullHistory,
            },
            ScenarioStep::RestartClient {
                client: "bob".into(),
            },
            ScenarioStep::SyncRelayHistory {
                clients: vec!["bob".into()],
                sync: ScenarioRelaySyncModeV2::FullHistory,
            },
        ]);
        model.online.insert("bob".into());
        model.deliver_to_online();
        model.public_state_checkpoint();
        model.public_payload_checkpoint();
    }
    for sender in CLIENTS {
        model.apply(JourneyAction::Send {
            sender: sender.into(),
        });
    }
    model.apply(JourneyAction::Restart {
        client: "bob".into(),
    });
    model.apply(JourneyAction::Send {
        sender: "bob".into(),
    });
    let mut case = model.finish_public(PUBLIC_APP_BACKLOG_RECOVERY_FAMILY, seed);
    case.generator_version = "2".into();
    case
}

/// Six explicit scale/formation arms: bulk and staged formation at 10, 20 and 50.
/// All participants own app runtimes and SQLCipher stores; no engine-only oracle.
pub fn generate_public_app_large_group_case(seed: u64, case_index: u64) -> GeneratedScenarioCase {
    let population = [10, 20, 50][(case_index / 2 % 3) as usize];
    let staged = case_index % 2 == 1;
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4c41_5247_4541_5050 ^ case_index.rotate_left(19));
    let clients = std::iter::once("alice".to_owned())
        .chain((1..population).map(|index| format!("member-{index:03}")))
        .collect::<Vec<_>>();
    let mut peers = clients[1..].to_vec();
    peers.shuffle(&mut rng);
    let cohort = peers[..population / 5].to_vec();
    let victim = peers[population / 5].clone();
    let admin = peers[population / 5 + 1].clone();
    let mut model = JourneyModel::with_clients(
        case_index,
        JourneyProfile::OfflineRetainedHistory,
        clients.clone(),
        cohort[0].clone(),
    );
    model.public_app = true;
    model.compact_public_payload_checks = true;
    model.batch_public_sends = true;
    if staged {
        let founders = peers[..3].to_vec();
        let ScenarioStep::CreateGroup { invitees, .. } = &mut model.steps[0] else {
            unreachable!()
        };
        *invitees = founders.clone();
        model.members = founders
            .into_iter()
            .chain(std::iter::once("alice".into()))
            .collect();
        model.non_members = clients
            .iter()
            .filter(|client| !model.members.contains(*client))
            .cloned()
            .collect();
        model.public_state_checkpoint();
        let joiners = peers[3..].to_vec();
        let batch_size = rng.gen_range(3..=5);
        for batch in joiners.chunks(batch_size) {
            let pending = model.next_publication("growth");
            model.steps.push(ScenarioStep::InviteMembers {
                inviter: "alice".into(),
                invitees: batch.to_vec(),
                pending: pending.clone(),
            });
            model.members.extend(batch.iter().cloned());
            for client in batch {
                model.non_members.remove(client);
            }
            model.confirmed_mutation("alice", &pending);
        }
    } else {
        model.public_state_checkpoint();
    }
    let mut senders = clients.clone();
    senders.shuffle(&mut rng);
    for sender in senders {
        model.apply(JourneyAction::Send { sender });
    }
    model.deliver_to_online();
    model.public_payload_checkpoint();
    for client in &cohort {
        model.steps.push(ScenarioStep::SetClientOffline {
            client: client.clone(),
        });
        model.online.remove(client);
    }
    model.apply(JourneyAction::UpdateAdminPolicy {
        target: admin.clone(),
    });
    model.apply(JourneyAction::UpdateProfile { actor: admin });
    model.apply(JourneyAction::Remove {
        member: victim.clone(),
    });
    for _ in 0..rng.gen_range(3..=8) {
        let action = model.choose_kind(&mut rng, JourneyActionKind::Send);
        model.apply(action);
    }
    // Acceptance can queue an application send. Establish delivery while the
    // victim is still excluded before assigning that history to the old epoch.
    model.deliver_to_online();
    model.public_payload_checkpoint();
    model.apply(JourneyAction::Invite {
        invitee: victim.clone(),
    });
    for client in &cohort {
        model.steps.push(ScenarioStep::ReconnectClient {
            client: client.clone(),
        });
        model.online.insert(client.clone());
    }
    model.steps.push(ScenarioStep::SyncRelayHistory {
        clients: cohort.clone(),
        sync: ScenarioRelaySyncModeV2::FullHistory,
    });
    model.deliver_to_online();
    model.public_state_checkpoint();
    model.public_payload_checkpoint();
    model.apply(JourneyAction::Restart {
        client: cohort[0].clone(),
    });
    model.apply(JourneyAction::Restart {
        client: victim.clone(),
    });
    for sender in ["alice".to_owned(), cohort[0].clone(), victim] {
        model.apply(JourneyAction::Send { sender });
    }
    model.deliver_to_online();
    let admin_count = model.admins.len();
    let applications = model.payload_sequence as usize;
    let commits = model.epoch.saturating_sub(1) as usize;
    let mut case = model.finish_public(PUBLIC_APP_LARGE_GROUP_FAMILY, seed);
    case.generator_version = "2".into();
    case.workload_profile = Some(crate::GeneratedWorkloadProfileV1 {
        name: format!("{population}-{}", if staged { "staged" } else { "bulk" }),
        version: "1".into(),
        size_tier: format!("members-{population}"),
        member_count: population,
        admin_regime: "founder-then-two".into(),
        initial_admin_count: 1,
        final_admin_count: admin_count,
        committer_mode: "sequential-2".into(),
        active_committer_count: 2,
        traffic_profile: "all-member-fanout-and-offline-cohort".into(),
        application_message_count: applications,
        workload_commit_count: commits,
        formation: if staged {
            "incremental-batches"
        } else {
            "bulk-create"
        }
        .into(),
        disruption: "offline-cohort-remove-readd-reopen".into(),
    });
    case
}

/// Generate deterministic, product-shaped canonical scenarios.
/// A bounded mixed recovery journey whose seed selects operation order, length,
/// population, offline member, bursts, outage durations and recovery boundaries.
/// The old finite families remain byte-for-byte replayable regression catalogs.
pub fn generate_public_app_stateful_recovery_case(
    seed: u64,
    case_index: u64,
) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5354_4154_4546_554c ^ case_index.rotate_left(23));
    let population = rng.gen_range(3..=6);
    let clients = ["alice", "bob", "carol", "david", "erin", "frank"][..population]
        .iter()
        .map(|label| (*label).to_owned())
        .collect::<Vec<_>>();
    let offline_client = clients[rng.gen_range(1..population)].clone();
    let mut model = JourneyModel::with_clients(
        case_index,
        JourneyProfile::OfflineRetainedHistory,
        clients,
        offline_client.clone(),
    );
    model.public_app = true;
    model.public_state_checkpoint();
    model.apply(JourneyAction::Send {
        sender: offline_client,
    });

    // Required motifs are shuffled, not merely their actors. Additional motifs
    // and a second outage interval change the schedule itself across seeds.
    let mut motifs = vec![0, 1, 2, 3, 4, 5, 6];
    for _ in 0..rng.gen_range(0..=3) {
        motifs.push(rng.gen_range(0..=6));
    }
    motifs.shuffle(&mut rng);
    model.apply(JourneyAction::SetOffline);
    for motif in motifs {
        match motif {
            0 => public_recovery_burst(&mut model, &mut rng, 4..=32),
            1 => {
                let action = model.choose_kind(&mut rng, JourneyActionKind::UpdateProfile);
                model.apply(action);
            }
            2 => {
                let target = public_online_peer(&model, &mut rng);
                model.apply(JourneyAction::UpdateAdminPolicy { target });
            }
            3 => {
                let target = public_online_peer(&model, &mut rng);
                if model.admins.contains(&target) {
                    model.apply(JourneyAction::UpdateAdminPolicy {
                        target: target.clone(),
                    });
                }
                model.apply(JourneyAction::Remove {
                    member: target.clone(),
                });
                public_recovery_burst(&mut model, &mut rng, 1..=4);
                if rng.gen_bool(0.5) {
                    model.apply(JourneyAction::Restart {
                        client: target.clone(),
                    });
                }
                model.apply(JourneyAction::Invite {
                    invitee: target.clone(),
                });
                model.apply(JourneyAction::Send { sender: target });
            }
            4 => {
                let restart = model.choose_kind(&mut rng, JourneyActionKind::Restart);
                model.apply(restart);
            }
            5 => {
                // No tick between the accepted burst and the socket cut.
                public_recovery_burst(&mut model, &mut rng, 2..=8);
                model.steps.push(ScenarioStep::InterruptRelay {
                    relay: "relay:default".into(),
                    outage_ms: rng.gen_range(50..=500),
                });
                model.deliver_to_online();
                model.public_state_checkpoint();
                model.public_payload_checkpoint();
            }
            6 => {
                let peer = public_online_peer(&model, &mut rng);
                if !model.admins.contains(&peer) {
                    model.apply(JourneyAction::UpdateAdminPolicy {
                        target: peer.clone(),
                    });
                }
                let mut authors = ["alice".to_owned(), peer];
                authors.shuffle(&mut rng);
                model.group_name = format!("mixed-{case_index}-name-{}", model.profile_sequence);
                model.group_description =
                    format!("mixed-{case_index}-description-{}", model.profile_sequence);
                model.profile_sequence += 1;
                model.steps.push(ScenarioStep::RaceGroupProfiles {
                    updates: vec![
                        crate::ScenarioProfileUpdate {
                            client: authors[0].clone(),
                            name: Some(model.group_name.clone()),
                            description: None,
                        },
                        crate::ScenarioProfileUpdate {
                            client: authors[1].clone(),
                            name: None,
                            description: Some(model.group_description.clone()),
                        },
                    ],
                });
                // At least one epoch must advance; concurrent resolution can
                // add more. Pin both disjoint edits, not an arbitrary winner.
                model.epoch += 1;
                model.deliver_to_online();
                model.public_state_checkpoint();
            }
            _ => unreachable!(),
        }
    }
    public_varied_recovery(&mut model, &mut rng);
    if rng.gen_bool(0.5) {
        model.apply(JourneyAction::SetOffline);
        public_recovery_burst(&mut model, &mut rng, 8..=48);
        let action = model.choose_kind(&mut rng, JourneyActionKind::UpdateProfile);
        model.apply(action);
        public_varied_recovery(&mut model, &mut rng);
    }
    let mut senders = model.members.iter().cloned().collect::<Vec<_>>();
    senders.shuffle(&mut rng);
    for sender in senders {
        model.apply(JourneyAction::Send { sender });
    }
    let restart = model.choose_kind(&mut rng, JourneyActionKind::Restart);
    model.apply(restart);
    model.apply(JourneyAction::Send {
        sender: "alice".into(),
    });
    let mut case = model.finish_public(PUBLIC_APP_STATEFUL_RECOVERY_FAMILY, seed);
    case.generator_version = "1".into();
    case
}

fn public_online_peer(model: &JourneyModel, rng: &mut StdRng) -> String {
    model
        .members
        .intersection(&model.online)
        .filter(|client| client.as_str() != "alice")
        .collect::<Vec<_>>()
        .choose(rng)
        .expect("an online peer remains")
        .to_string()
}

fn public_recovery_burst(
    model: &mut JourneyModel,
    rng: &mut StdRng,
    bounds: std::ops::RangeInclusive<usize>,
) {
    model.batch_public_sends = true;
    for _ in 0..rng.gen_range(bounds) {
        let action = model.choose_kind(rng, JourneyActionKind::Send);
        model.apply(action);
    }
    model.batch_public_sends = false;
}

fn public_varied_recovery(model: &mut JourneyModel, rng: &mut StdRng) {
    let client = model.offline_client.clone();
    match rng.gen_range(0..3) {
        0 => model.apply(JourneyAction::Reconnect),
        boundary => {
            model.steps.push(ScenarioStep::ReconnectClient {
                client: client.clone(),
            });
            model.online.insert(client.clone());
            if boundary == 1 {
                model.steps.push(ScenarioStep::SyncRelayHistory {
                    clients: vec![client.clone()],
                    sync: ScenarioRelaySyncModeV2::FullHistory,
                });
                model.steps.push(ScenarioStep::RestartClient {
                    client: client.clone(),
                });
            } else {
                // Issue traffic before the explicit history-repair/checkpoint.
                // This does not assert that background recovery is still partial.
                public_recovery_burst(model, rng, 2..=8);
            }
            model.steps.push(ScenarioStep::SyncRelayHistory {
                clients: vec![client],
                sync: ScenarioRelaySyncModeV2::FullHistory,
            });
            model.deliver_to_online();
            model.public_state_checkpoint();
            model.public_payload_checkpoint();
        }
    }
}

pub fn generate_stateful_chat_journey_family(
    seed: u64,
    cases: usize,
) -> Vec<GeneratedScenarioCase> {
    (0..cases)
        .map(|case_index| generate_stateful_chat_journey_case(seed, case_index as u64))
        .collect()
}

/// Generate one case without regenerating any prior case index.
pub fn generate_stateful_chat_journey_case(seed: u64, case_index: u64) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4348_4154_4a4f_5552 ^ case_index.rotate_left(23));
    let profile = if case_index.is_multiple_of(2) {
        JourneyProfile::Membership
    } else {
        JourneyProfile::OfflineRetainedHistory
    };
    let mut model = JourneyModel::new(case_index, profile);

    // Adjacent cases cover the two product-shaped backbones whose combination
    // would create a false no-pending guarantee for pre-admission history: a
    // later membership change, or offline traffic for a founding member.
    if profile == JourneyProfile::Membership {
        let action = model.choose_kind(&mut rng, JourneyActionKind::Invite);
        model.apply(action);
    }
    let action = model.choose_kind(&mut rng, JourneyActionKind::UpdateProfile);
    model.apply(action);
    if profile == JourneyProfile::OfflineRetainedHistory {
        let action = model.choose_kind(&mut rng, JourneyActionKind::SetOffline);
        model.apply(action);
    }
    let action = model.choose_kind(&mut rng, JourneyActionKind::Send);
    model.apply(action);

    // Rotate a guaranteed secondary lifecycle dimension across adjacent cases.
    let required_kind = match (case_index / 2) % 4 {
        0 => JourneyActionKind::UpdateAdminPolicy,
        1 => JourneyActionKind::SelfUpdate,
        2 => JourneyActionKind::Restart,
        _ => JourneyActionKind::Remove,
    };
    if required_kind != JourneyActionKind::Restart {
        let action = model.choose_kind(&mut rng, required_kind);
        let removed_member = match &action {
            JourneyAction::Remove { member } if profile == JourneyProfile::Membership => {
                Some(member.clone())
            }
            _ => None,
        };
        model.apply(action);
        // A membership-profile case in every eight-case rotation guarantees
        // the remove -> fresh re-invite interaction. Removed identities remain
        // legal invite candidates for later random actions as well.
        if let Some(invitee) = removed_member {
            model.apply(JourneyAction::Invite { invitee });
        }
    }

    let extra_actions = 4 + rng.gen_range(0..5);
    for _ in 0..extra_actions {
        let action = model.choose_non_restart(&mut rng);
        model.apply(action);
    }

    // Restart is a terminal checkpoint in this serialized product-journey
    // family. Mutation-after-reopen and crash races belong to the dedicated
    // convergence-chaos family.
    if required_kind == JourneyActionKind::Restart {
        let action = model.choose_kind(&mut rng, required_kind);
        model.apply(action);
    }

    model.finish(seed)
}

fn accept_all_outbound(client: &str) -> ScenarioStep {
    ScenarioStep::AcknowledgeOutbound {
        client: client.into(),
        publication: None,
        selection: ScenarioOutboundSelection::All,
        outcome: SubjectOutboundOutcome::Accepted,
    }
}

fn client_labels() -> Vec<String> {
    CLIENTS.into_iter().map(String::from).collect()
}

fn single_relay_topology() -> ScenarioTopologyV2 {
    single_relay_topology_for(&client_labels())
}

fn single_relay_topology_for(clients: &[String]) -> ScenarioTopologyV2 {
    let accounts = clients
        .iter()
        .map(|client| ScenarioAccountV2 {
            id: client.clone(),
            roles: vec!["member".into()],
        })
        .collect();
    let devices = clients
        .iter()
        .map(|client| ScenarioDeviceV2 {
            id: format!("device:{client}"),
            account: client.clone(),
            process: format!("process:{client}"),
            client: client.clone(),
        })
        .collect();
    let processes = clients
        .iter()
        .map(|client| ScenarioProcessV2 {
            id: format!("process:{client}"),
            binary_version: "mdk-current".into(),
            policy_version: "production-pinned/v1".into(),
            relays: vec!["relay:default".into()],
        })
        .collect();
    ScenarioTopologyV2 {
        accounts,
        devices,
        processes,
        groups: Vec::new(),
        relays: vec![ScenarioRelayV2 {
            id: "relay:default".into(),
            implementation_version: "memory/v1".into(),
            policy_version: "retain-all/v1".into(),
        }],
    }
}

/// New families leave all existing generator identities and prefixes unchanged.
pub fn generate_public_app_invite_profile_case(
    seed: u64,
    case_index: u64,
) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4956_5052 ^ case_index.rotate_left(23));
    let mut model = JourneyModel::new_public(case_index);
    // Rebuild formation before any actions execute: david is the late invitee.
    model.steps.clear();
    model.members.remove("david");
    model.non_members.insert("david".into());
    model.steps.push(ScenarioStep::CreateGroup {
        creator: "alice".into(),
        name: model.group_name.clone(),
        invitees: vec!["bob".into(), "carol".into()],
        required_features: vec![],
        initial_admins: Some(vec!["alice".into(), "bob".into(), "carol".into()]),
        pending: "create".into(),
    });
    model.steps.push(ScenarioStep::AcknowledgeOutbound {
        client: "alice".into(),
        publication: Some("create".into()),
        selection: ScenarioOutboundSelection::All,
        outcome: SubjectOutboundOutcome::Accepted,
    });
    model.admins = BTreeSet::from(["alice".into(), "bob".into(), "carol".into()]);
    model.public_state_checkpoint();
    let mut founders = ["alice".to_owned(), "bob".to_owned(), "carol".to_owned()];
    founders.shuffle(&mut rng);
    for _ in 0..rng.gen_range(1..=3) {
        model.apply(JourneyAction::Send {
            sender: founders[rng.gen_range(0..3)].clone(),
        });
    }
    // Vary which observer sees the race live and when it reopens. Actors stay
    // online; the invitee must receive the losing Welcome to exercise recovery.
    let observer_offline = rng.gen_bool(0.5);
    if observer_offline {
        model.steps.push(ScenarioStep::SetClientOffline {
            client: founders[2].clone(),
        });
        model.online.remove(&founders[2]);
    }
    if rng.gen_bool(0.5) {
        model.apply(JourneyAction::Restart {
            client: founders[0].clone(),
        });
    }
    model.group_name = format!("invite-profile-{case_index}");
    model.steps.push(ScenarioStep::RaceInviteProfile {
        actors: founders[..2].to_vec(),
        invitee: "david".into(),
        name: model.group_name.clone(),
        restart_at_offer: case_index.is_multiple_of(2),
    });
    model.members.insert("david".into());
    model.non_members.remove("david");
    model.epoch += 1;
    if rng.gen_bool(0.5) {
        model.steps.push(ScenarioStep::InterruptRelay {
            relay: "relay:default".into(),
            outage_ms: rng.gen_range(50..=200),
        });
    }
    if observer_offline {
        model.steps.push(ScenarioStep::ReconnectClient {
            client: founders[2].clone(),
        });
        model.online.insert(founders[2].clone());
    }
    model.deliver_to_online();
    model.public_state_checkpoint();
    for sender in ["david".to_owned(), founders[0].clone()] {
        model.apply(JourneyAction::Send { sender });
    }
    model.compact_public_payload_checks = true;
    let mut case = model.finish_public("public-app-invite-profile-recovery/v1", seed);
    case.generator_version = "2".into();
    case
}

/// Same app participants and encrypted databases across every activity cycle.
/// The long profile changes cycle count, never starts another fresh stack.
pub fn generate_public_app_activity_case(
    family: &str,
    seed: u64,
    case_index: u64,
) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4143_5449 ^ case_index.rotate_left(23));
    let pressure = family == "public-app-retained-traffic/v1";
    let cycles = if family == "public-app-longevity-extended/v1" {
        48
    } else {
        2 + (case_index % 2) as usize
    };
    let mut model = JourneyModel::new_public(case_index);
    model.compact_public_payload_checks = true;
    for cycle in 0..cycles {
        model.offline_client = CLIENTS[rng.gen_range(1..4)].into();
        model.apply(JourneyAction::SetOffline);
        let late = if pressure {
            let index = model.steps.len();
            model.apply(JourneyAction::Send {
                sender: "alice".into(),
            });
            let payload = model.received_payloads[&model.offline_client]
                .last()
                .unwrap()
                .clone();
            let selector = crate::ScenarioMessageSelectorV2 {
                action_id: Some(format!("step-{index}:send_app_message")),
                ..Default::default()
            };
            // Shared relay presence is global. Close every participant before
            // removing history, then reopen the caught-up peers on the same DBs.
            let live = model.online.iter().cloned().collect::<Vec<_>>();
            for client in &live {
                model.steps.push(ScenarioStep::SetClientOffline {
                    client: client.clone(),
                });
            }
            model.steps.push(ScenarioStep::SetRelayEventVisibility {
                relay: "relay:default".into(),
                selector: selector.clone(),
                clients: vec![model.offline_client.clone()],
                visible: false,
            });
            for client in live {
                model.steps.push(ScenarioStep::ReconnectClient { client });
            }
            // The returning device must first recover without this one event.
            model
                .received_payloads
                .get_mut(&model.offline_client)
                .unwrap()
                .retain(|p| p != &payload);
            Some((selector, payload))
        } else {
            None
        };
        let mut motifs = vec![0, 1, 2];
        motifs.shuffle(&mut rng);
        for motif in motifs {
            match motif {
                0 => public_recovery_burst(
                    &mut model,
                    &mut rng,
                    if pressure { 16..=24 } else { 2..=4 },
                ),
                1 => model.apply(JourneyAction::UpdateProfile {
                    actor: "alice".into(),
                }),
                2 => {
                    let victim = public_online_peer(&model, &mut rng);
                    model.apply(JourneyAction::Remove {
                        member: victim.clone(),
                    });
                    // Establish exclusion traffic before the fresh invitation.
                    model.apply(JourneyAction::Send {
                        sender: "alice".into(),
                    });
                    model.apply(JourneyAction::Invite { invitee: victim });
                }
                _ => unreachable!(),
            }
        }
        model.steps.push(ScenarioStep::InterruptRelay {
            relay: "relay:default".into(),
            outage_ms: rng.gen_range(50..=250),
        });
        // Reconnect without draining first; fresh sends enter while retained
        // history is eligible. This is interleaved traffic, not continuous load.
        let returning = model.offline_client.clone();
        model.steps.push(ScenarioStep::ReconnectClient {
            client: returning.clone(),
        });
        model.online.insert(returning.clone());
        public_recovery_burst(&mut model, &mut rng, 2..=4);
        model.steps.push(ScenarioStep::SyncRelayHistory {
            clients: vec![returning.clone()],
            sync: ScenarioRelaySyncModeV2::FullHistory,
        });
        model.deliver_to_online();
        model.public_state_checkpoint();
        model.public_payload_checkpoint();
        if let Some((selector, payload)) = late {
            model.eventually(crate::ScenarioPredicateV2::PayloadCount {
                client: returning.clone(),
                payload: payload.clone(),
                count: 0,
            });
            model.steps.push(ScenarioStep::SetRelayEventVisibility {
                relay: "relay:default".into(),
                selector,
                clients: vec![returning.clone()],
                visible: true,
            });
            model
                .received_payloads
                .get_mut(&returning)
                .unwrap()
                .push(payload);
            model.steps.push(ScenarioStep::SyncRelayHistory {
                clients: vec![returning.clone()],
                sync: ScenarioRelaySyncModeV2::FullHistory,
            });
            model.apply(JourneyAction::Send {
                sender: "alice".into(),
            });
            model.public_payload_checkpoint();
            // Re-request retained history after delivery to exercise deduplication.
            model.steps.push(ScenarioStep::SyncRelayHistory {
                clients: vec![returning.clone()],
                sync: ScenarioRelaySyncModeV2::FullHistory,
            });
            model.public_payload_checkpoint();
        }
        // Deliberate restarts only on alternating cycles; alice stays running.
        if cycle % 2 == 1 {
            model.apply(JourneyAction::Restart {
                client: returning.clone(),
            });
        }
        model.apply(JourneyAction::Send { sender: returning });
        model.apply(JourneyAction::Send {
            sender: "alice".into(),
        });
    }
    let mut case = model.finish_public(family, seed);
    case.generator_version = if pressure { "3" } else { "1" }.into();
    case
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;

    #[test]
    fn public_send_checks_only_new_payload_but_restart_checks_full_history() {
        let mut model = JourneyModel::new_public(0);
        for _ in 0..2 {
            model.apply(JourneyAction::Send {
                sender: "alice".into(),
            });
        }
        model.steps.clear();
        model.apply(JourneyAction::Send {
            sender: "alice".into(),
        });
        let payloads = model.received_payloads["alice"].clone();
        let assertions = model
            .steps
            .iter()
            .filter(|step| matches!(step, ScenarioStep::Assert { .. }))
            .collect::<Vec<_>>();
        assert_eq!(assertions.len(), model.members.len());
        for step in assertions {
            assert!(matches!(step, ScenarioStep::Assert {
                assertion: crate::ScenarioAssertionV2::Eventually {
                    predicate: crate::ScenarioPredicateV2::PayloadCount { payload, count: 1, .. }, ..
                }
            } if payload == &payloads[2]));
        }
        model.steps.clear();
        model.apply(JourneyAction::Restart {
            client: "bob".into(),
        });
        let checks = model
            .steps
            .iter()
            .filter(|step| {
                matches!(
                    step,
                    ScenarioStep::Assert {
                        assertion: crate::ScenarioAssertionV2::Eventually {
                            predicate: crate::ScenarioPredicateV2::PayloadCount { .. },
                            ..
                        }
                    }
                )
            })
            .count();
        assert_eq!(checks, model.members.len() * payloads.len());
    }
}
