//! Stateful, legality-aware generation of product-shaped canonical scenarios.
//!
//! The generator owns only a small symbolic model. It emits ordinary
//! [`ScenarioSpec`] values and relies on the existing compiler, subjects,
//! reports, failure capsules, and reducer for execution and replay.

use std::collections::{BTreeMap, BTreeSet};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::{
    GeneratedScenarioCase, GeneratedSubjectKind, QuiescencePolicy, ScenarioAccountV2,
    ScenarioDeviceV2, ScenarioOutboundSelection, ScenarioProcessV2, ScenarioRelaySyncModeV2,
    ScenarioRelayV2, ScenarioSpec, ScenarioStep, ScenarioTopologyV2, SubjectOutboundOutcome,
    TraceExpectation,
};

pub const STATEFUL_CHAT_JOURNEY_FAMILY: &str = "chat-journey/v1";
pub const STATEFUL_CHAT_JOURNEY_GENERATOR_VERSION: &str = "1";

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
    profile: JourneyProfile,
    case_index: u64,
    epoch: u64,
    members: BTreeSet<String>,
    admins: BTreeSet<String>,
    online: BTreeSet<String>,
    never_joined: BTreeSet<String>,
    group_name: String,
    group_description: String,
    received_payloads: BTreeMap<String, Vec<String>>,
    publication_sequence: u64,
    payload_sequence: u64,
    profile_sequence: u64,
    steps: Vec<ScenarioStep>,
    expected: Vec<TraceExpectation>,
}

impl JourneyModel {
    fn new(case_index: u64, profile: JourneyProfile) -> Self {
        let group_name = format!("chat-journey-{case_index}");
        let clients = client_labels();
        let (members, never_joined, founding_invitees) = match profile {
            JourneyProfile::Membership => (
                BTreeSet::from(["alice".into(), "bob".into()]),
                BTreeSet::from(["carol".into(), "david".into()]),
                vec!["bob".into()],
            ),
            JourneyProfile::OfflineRetainedHistory => (
                clients.iter().cloned().collect(),
                BTreeSet::new(),
                vec!["bob".into(), "carol".into(), "david".into()],
            ),
        };
        let mut model = Self {
            profile,
            case_index,
            epoch: 1,
            members,
            admins: BTreeSet::from(["alice".into()]),
            online: clients.iter().cloned().collect(),
            never_joined,
            group_name: group_name.clone(),
            group_description: String::new(),
            received_payloads: clients
                .iter()
                .cloned()
                .map(|client| (client, Vec::new()))
                .collect(),
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
                self.never_joined
                    .iter()
                    .cloned()
                    .map(|invitee| JourneyAction::Invite { invitee }),
            );
        }
        actions.extend(
            self.members
                .iter()
                .filter(|member| {
                    member.as_str() != "alice"
                        && member.as_str() != "bob"
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
                .cloned()
                .map(|client| JourneyAction::SelfUpdate { client }),
        );
        if self.profile == JourneyProfile::OfflineRetainedHistory {
            if self.online.contains("bob") {
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
        choices[rng.gen_range(0..choices.len())].clone()
    }

    fn choose_any(&self, rng: &mut StdRng) -> JourneyAction {
        let choices = self.legal_actions();
        choices[rng.gen_range(0..choices.len())].clone()
    }

    fn apply(&mut self, action: JourneyAction) {
        match action {
            JourneyAction::Invite { invitee } => {
                debug_assert!(self.never_joined.contains(&invitee));
                let pending = self.next_publication("invite");
                self.steps.push(ScenarioStep::InviteMembers {
                    inviter: "alice".into(),
                    invitees: vec![invitee.clone()],
                    pending: pending.clone(),
                });
                self.members.insert(invitee.clone());
                self.never_joined.remove(&invitee);
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
                for recipient in self.members.iter().filter(|client| **client != sender) {
                    self.received_payloads
                        .get_mut(recipient)
                        .expect("all clients have a delivery ledger")
                        .push(payload.clone());
                }
                self.deliver_to_online();
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
                self.confirmed_mutation(&client, &pending);
            }
            JourneyAction::SetOffline => {
                debug_assert!(self.online.contains("bob"));
                self.steps.push(ScenarioStep::SetClientOffline {
                    client: "bob".into(),
                });
                self.online.remove("bob");
            }
            JourneyAction::Reconnect => self.reconnect_bob(),
            JourneyAction::Restart { client } => {
                debug_assert!(self.members.contains(&client));
                debug_assert!(self.online.contains(&client));
                self.steps.push(ScenarioStep::RestartClient {
                    client: client.clone(),
                });
                self.received_payloads
                    .get_mut(&client)
                    .expect("all clients have a delivery ledger")
                    .clear();
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
    }

    fn deliver_to_online(&mut self) {
        self.steps.push(ScenarioStep::DeliverAll);
        self.steps.push(ScenarioStep::Tick {
            clients: self.online.iter().cloned().collect(),
        });
    }

    fn reconnect_bob(&mut self) {
        debug_assert!(!self.online.contains("bob"));
        self.steps.push(ScenarioStep::ReconnectClient {
            client: "bob".into(),
        });
        self.online.insert("bob".into());
        self.steps.push(ScenarioStep::SyncRelayHistory {
            clients: vec!["bob".into()],
            sync: ScenarioRelaySyncModeV2::FullHistory,
        });
        self.steps.push(ScenarioStep::Tick {
            clients: vec!["bob".into()],
        });
    }

    fn finish(mut self, seed: u64) -> GeneratedScenarioCase {
        if self.profile == JourneyProfile::OfflineRetainedHistory && !self.online.contains("bob") {
            self.reconnect_bob();
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
}

/// Generate deterministic, product-shaped canonical scenarios.
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
    let action = model.choose_kind(&mut rng, required_kind);
    model.apply(action);

    let extra_actions = 4 + rng.gen_range(0..5);
    for _ in 0..extra_actions {
        let action = model.choose_any(&mut rng);
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
    let accounts = CLIENTS
        .into_iter()
        .map(|client| ScenarioAccountV2 {
            id: client.into(),
            roles: vec!["member".into()],
        })
        .collect();
    let devices = CLIENTS
        .into_iter()
        .map(|client| ScenarioDeviceV2 {
            id: format!("device:{client}"),
            account: client.into(),
            process: format!("process:{client}"),
            client: client.into(),
        })
        .collect();
    let processes = CLIENTS
        .into_iter()
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
