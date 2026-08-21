//! Deterministic large-group workload profiles.
//!
//! The family keeps group size, administrator population, active committer
//! width, traffic balance, formation, and disruption explicit in replay
//! metadata. Cases are finite and use the ordinary Scenario IR executor.

use crate::{
    GeneratedScenarioCase, GeneratedSubjectKind, GeneratedWorkloadProfileV1, QuiescencePolicy,
    ScenarioMessageSelectorV2, ScenarioOutboundSelection, ScenarioSpec, ScenarioStep,
    ScenarioTransportClass, SubjectOutboundOutcome, TraceExpectation,
};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use std::collections::BTreeSet;

pub const LARGE_GROUP_PRESSURE_FAMILY: &str = "large-group-pressure/v1";
pub const LARGE_GROUP_PRESSURE_GENERATOR_VERSION: &str = "1";
pub const LARGE_GROUP_PRESSURE_PROFILE_VERSION: &str = "1";

const ARM_COUNT: u64 = 6;
const MAX_PROBE_CLIENTS: usize = 6;

#[derive(Clone, Copy)]
struct SizeProfile {
    name: &'static str,
    tier: &'static str,
    members: usize,
}

// Keep six-case size blocks ordered by execution cost because the campaign CLI
// selects a prefix. Names retain the anchor-versus-boundary distinction.
const SIZE_PROFILES: [SizeProfile; 9] = [
    SizeProfile {
        name: "mid-min-10",
        tier: "mid",
        members: 10,
    },
    SizeProfile {
        name: "mid-anchor-16",
        tier: "mid",
        members: 16,
    },
    SizeProfile {
        name: "mid-max-20",
        tier: "mid",
        members: 20,
    },
    SizeProfile {
        name: "medium-anchor-32",
        tier: "medium",
        members: 32,
    },
    SizeProfile {
        name: "medium-max-50",
        tier: "medium",
        members: 50,
    },
    SizeProfile {
        name: "large-anchor-64",
        tier: "large",
        members: 64,
    },
    SizeProfile {
        name: "large-max-100",
        tier: "large",
        members: 100,
    },
    SizeProfile {
        name: "xlarge-anchor-128",
        tier: "xlarge",
        members: 128,
    },
    SizeProfile {
        name: "xlarge-max-200",
        tier: "xlarge",
        members: 200,
    },
];

#[derive(Clone, Copy)]
enum WorkloadArm {
    BulkApplicationFanout,
    IncrementalGrowth,
    SparseAdminSequential,
    CompetingCommits,
    MixedInterleaved,
    AdminHandoffChurnRestart,
}

impl WorkloadArm {
    fn from_index(index: u64) -> Self {
        match index % ARM_COUNT {
            0 => Self::BulkApplicationFanout,
            1 => Self::IncrementalGrowth,
            2 => Self::SparseAdminSequential,
            3 => Self::CompetingCommits,
            4 => Self::MixedInterleaved,
            _ => Self::AdminHandoffChurnRestart,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::BulkApplicationFanout => "bulk-application-fanout",
            Self::IncrementalGrowth => "incremental-growth",
            Self::SparseAdminSequential => "sparse-admin-sequential",
            Self::CompetingCommits => "competing-commits",
            Self::MixedInterleaved => "mixed-interleaved",
            Self::AdminHandoffChurnRestart => "admin-handoff-churn-restart",
        }
    }

    fn traffic_profile(self) -> &'static str {
        match self {
            Self::BulkApplicationFanout => "application-heavy",
            Self::IncrementalGrowth => "growth-checkpoint",
            Self::SparseAdminSequential => "balanced-sequential",
            Self::CompetingCommits => "commit-heavy",
            Self::MixedInterleaved => "balanced-interleaved",
            Self::AdminHandoffChurnRestart => "membership-churn",
        }
    }

    fn formation(self) -> &'static str {
        match self {
            Self::IncrementalGrowth => "incremental-batches",
            _ => "bulk-create",
        }
    }

    fn disruption(self) -> &'static str {
        match self {
            Self::CompetingCommits => "commit-reorder-and-duplicate",
            Self::MixedInterleaved => "seeded-commit-reorder",
            Self::AdminHandoffChurnRestart => "restart-remove-and-readd",
            _ => "none",
        }
    }
}

#[derive(Clone, Copy)]
enum AdminRegime {
    FounderOnly,
    Few,
    Minority,
    Dense,
    All,
}

impl AdminRegime {
    fn from_index(index: usize) -> Self {
        match index % 5 {
            0 => Self::FounderOnly,
            1 => Self::Few,
            2 => Self::Minority,
            3 => Self::Dense,
            _ => Self::All,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::FounderOnly => "founder-only",
            Self::Few => "few-3",
            Self::Minority => "minority-10-percent",
            Self::Dense => "dense-50-percent",
            Self::All => "all-members",
        }
    }

    fn count(self, members: usize) -> usize {
        match self {
            Self::FounderOnly => 1,
            Self::Few => 3.min(members),
            Self::Minority => members.div_ceil(10).max(2).min(members),
            Self::Dense => members.div_ceil(2),
            Self::All => members,
        }
    }
}

struct BuiltCase {
    scenario: ScenarioSpec,
    expected: Vec<TraceExpectation>,
    final_admins: Vec<String>,
    active_committers: Vec<String>,
    authored_applications: Vec<(String, String)>,
    retained_joiners: BTreeSet<String>,
}

pub fn generate_large_group_pressure_family(seed: u64, cases: usize) -> Vec<GeneratedScenarioCase> {
    (0..cases)
        .map(|case_index| generate_large_group_pressure_case(seed, case_index as u64))
        .collect()
}

pub fn generate_large_group_pressure_case(seed: u64, case_index: u64) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4c41_5247_4547_5250 ^ case_index.rotate_left(31));
    let arm = WorkloadArm::from_index(case_index);
    let size_slot = usize::try_from(case_index / ARM_COUNT).expect("case index fits usize")
        % SIZE_PROFILES.len();
    let size = SIZE_PROFILES[size_slot];
    let arm_slot = usize::try_from(case_index % ARM_COUNT).expect("arm index fits usize");
    let admin_regime = admin_regime_for(size_slot, arm_slot);
    let requested_admin_count = admin_regime.count(size.members);
    let clients = large_clients(size.members);
    let initial_admins = choose_admins(&clients, requested_admin_count, &mut rng);

    let mut built = build_case(arm, case_index, clients, initial_admins.clone(), &mut rng);
    add_terminal_oracle(&mut built);

    let application_message_count = built.authored_applications.len();
    let workload_commit_count = built
        .scenario
        .steps
        .iter()
        .filter(|step| is_workload_commit(step))
        .count();
    let committer_mode = match built.active_committers.len() {
        0 | 1 => "sequential-1",
        2 => "rival-2",
        3..=8 => "rival-up-to-8",
        _ => "rival-up-to-16",
    };
    let profile_name = format!(
        "{}/{}/{}/{}",
        size.name,
        admin_regime.name(),
        arm.traffic_profile(),
        arm.name()
    );

    GeneratedScenarioCase {
        family_name: LARGE_GROUP_PRESSURE_FAMILY.into(),
        generator_version: LARGE_GROUP_PRESSURE_GENERATOR_VERSION.into(),
        seed,
        case_index,
        workload_profile: Some(GeneratedWorkloadProfileV1 {
            name: profile_name,
            version: LARGE_GROUP_PRESSURE_PROFILE_VERSION.into(),
            size_tier: size.tier.into(),
            member_count: size.members,
            admin_regime: admin_regime.name().into(),
            initial_admin_count: initial_admins.len(),
            final_admin_count: built.final_admins.len(),
            committer_mode: committer_mode.into(),
            active_committer_count: built.active_committers.len(),
            traffic_profile: arm.traffic_profile().into(),
            application_message_count,
            workload_commit_count,
            formation: arm.formation().into(),
            disruption: arm.disruption().into(),
        }),
        subject: GeneratedSubjectKind::Engine,
        scenario: built.scenario,
        expected_outcomes: built.expected,
    }
}

fn build_case(
    arm: WorkloadArm,
    case_index: u64,
    clients: Vec<String>,
    initial_admins: Vec<String>,
    rng: &mut StdRng,
) -> BuiltCase {
    let mut expected = Vec::new();
    let mut retained_joiners = BTreeSet::new();
    let mut final_admins = initial_admins.clone();
    let mut steps = match arm {
        WorkloadArm::IncrementalGrowth => incremental_setup(
            case_index,
            &clients,
            &initial_admins,
            &mut expected,
            &mut retained_joiners,
        ),
        _ => bulk_setup(case_index, &clients, &initial_admins, &mut expected),
    };
    steps.push(ScenarioStep::ClearEvents {
        clients: clients.clone(),
    });
    steps.push(ScenarioStep::AdvanceTime { delta_ms: 1 });

    let mut active_committers = vec!["alice".into()];
    let mut authored_applications = Vec::new();
    let final_profile_name = format!("large group settled {case_index}");

    match arm {
        WorkloadArm::BulkApplicationFanout => {
            sequential_profile_commit(
                &mut steps,
                &mut expected,
                "alice",
                format!("large group warmup {case_index}"),
                "warmup-profile",
            );
            send_application_batch(
                &mut steps,
                &clients,
                clients.len(),
                case_index,
                "app-heavy",
                rng,
                &mut authored_applications,
            );
            settle(&mut steps, &clients);
            sequential_profile_commit(
                &mut steps,
                &mut expected,
                "alice",
                final_profile_name.clone(),
                "final-profile",
            );
        }
        WorkloadArm::IncrementalGrowth => {
            send_application_batch(
                &mut steps,
                &clients,
                clients.len().div_ceil(4),
                case_index,
                "growth",
                rng,
                &mut authored_applications,
            );
            settle(&mut steps, &clients);
            sequential_profile_commit(
                &mut steps,
                &mut expected,
                "alice",
                final_profile_name.clone(),
                "final-profile",
            );
        }
        WorkloadArm::SparseAdminSequential => {
            let actor = initial_admins[0].clone();
            for round in 0..3 {
                sequential_profile_commit(
                    &mut steps,
                    &mut expected,
                    &actor,
                    format!("large group sequential {case_index} round {round}"),
                    &format!("sequential-profile-{round}"),
                );
                send_application_batch(
                    &mut steps,
                    &clients,
                    clients.len().div_ceil(12),
                    case_index,
                    &format!("sequential-{round}"),
                    rng,
                    &mut authored_applications,
                );
                settle(&mut steps, &clients);
            }
            sequential_profile_commit(
                &mut steps,
                &mut expected,
                &actor,
                final_profile_name.clone(),
                "final-profile",
            );
            if let Some(non_admin) = clients
                .iter()
                .find(|client| !initial_admins.contains(client))
            {
                steps.push(ScenarioStep::ExpectUpdateAdminPolicyError {
                    client: non_admin.clone(),
                    admins: initial_admins.clone(),
                    error: "not_group_admin".into(),
                });
            }
        }
        WorkloadArm::CompetingCommits => {
            active_committers = choose_committers(&initial_admins, 16, rng);
            competing_profile_wave(
                &mut steps,
                &mut expected,
                &active_committers,
                case_index,
                "commit-heavy",
                true,
                rng,
                &clients,
            );
            send_application_batch(
                &mut steps,
                &clients,
                clients.len().div_ceil(10),
                case_index,
                "commit-heavy",
                rng,
                &mut authored_applications,
            );
            settle(&mut steps, &clients);
            sequential_profile_commit(
                &mut steps,
                &mut expected,
                "alice",
                final_profile_name.clone(),
                "final-profile",
            );
        }
        WorkloadArm::MixedInterleaved => {
            active_committers = choose_committers(&initial_admins, 8, rng);
            let total = clients.len().div_ceil(2);
            let first = total.div_ceil(3);
            send_application_batch(
                &mut steps,
                &clients,
                first,
                case_index,
                "mixed-before",
                rng,
                &mut authored_applications,
            );
            settle(&mut steps, &clients);
            competing_profile_wave(
                &mut steps,
                &mut expected,
                &active_committers,
                case_index,
                "mixed-wave",
                false,
                rng,
                &clients,
            );
            send_application_batch(
                &mut steps,
                &clients,
                total - first,
                case_index,
                "mixed-after",
                rng,
                &mut authored_applications,
            );
            settle(&mut steps, &clients);
            sequential_profile_commit(
                &mut steps,
                &mut expected,
                "alice",
                final_profile_name.clone(),
                "final-profile",
            );
        }
        WorkloadArm::AdminHandoffChurnRestart => {
            let victim = clients.last().expect("large group has a victim").clone();
            let successor = clients
                .iter()
                .find(|client| client.as_str() != "alice" && **client != victim)
                .expect("large group has a successor")
                .clone();
            let desired_final_count = initial_admins.len().min(clients.len() - 2).max(1);
            final_admins = choose_final_handoff_admins(
                &clients,
                &successor,
                &victim,
                desired_final_count,
                rng,
            );
            let mut interim = final_admins.clone();
            interim.push("alice".into());
            interim.sort_by_key(|admin| {
                clients
                    .iter()
                    .position(|client| client == admin)
                    .unwrap_or(usize::MAX)
            });
            admin_policy_commit(
                &mut steps,
                &mut expected,
                "alice",
                interim,
                "handoff-stage",
                &clients,
            );
            admin_policy_commit(
                &mut steps,
                &mut expected,
                "alice",
                final_admins.clone(),
                "handoff-final",
                &clients,
            );
            active_committers = vec![successor.clone()];

            steps.push(ScenarioStep::RemoveMembers {
                remover: successor.clone(),
                members: vec![victim.clone()],
                pending: "remove-victim".into(),
            });
            push_confirmed(&mut steps, &mut expected, &successor, "remove-victim");
            steps.push(ScenarioStep::RestartClient {
                client: successor.clone(),
            });
            // The removed participant must ingest its own removal before the
            // fresh Welcome arrives. Otherwise it still holds a live pre-
            // removal OpenMLS state and cannot perform the clean rejoin path.
            settle(&mut steps, &clients);
            steps.push(ScenarioStep::InviteMembers {
                inviter: successor.clone(),
                invitees: vec![victim.clone()],
                pending: "readd-victim".into(),
            });
            push_confirmed(&mut steps, &mut expected, &successor, "readd-victim");
            steps.push(ScenarioStep::DeliverAll);
            steps.push(ScenarioStep::Tick {
                clients: clients.clone(),
            });
            retained_joiners.insert(victim.clone());
            sequential_profile_commit(
                &mut steps,
                &mut expected,
                &successor,
                final_profile_name.clone(),
                "final-profile",
            );
            send_application_batch(
                &mut steps,
                &clients,
                clients.len().div_ceil(4),
                case_index,
                "post-readd",
                rng,
                &mut authored_applications,
            );
            settle(&mut steps, &clients);
            steps.push(ScenarioStep::ExpectUpdateAdminPolicyError {
                client: "alice".into(),
                admins: final_admins.clone(),
                error: "not_group_admin".into(),
            });
        }
    }

    // A welcome-joined client currently retains its own join commit as a
    // named terminal harness wart. The strict fixed-point driver correctly
    // refuses to call that state quiescent, so late-join/rejoin arms settle by
    // explicit delivery/tick using the harness's legacy far-future tick and
    // assert the exact retained input below. Removing the explicit clock
    // activation is deliberate: otherwise those ticks would stop before the
    // convergence deadline while the strict driver remains unavailable.
    if !retained_joiners.is_empty() {
        steps.retain(|step| {
            !matches!(
                step,
                ScenarioStep::AwaitQuiescence { .. } | ScenarioStep::AdvanceTime { .. }
            )
        });
    }

    steps.push(ScenarioStep::ObserveAdminPolicy {
        clients: clients.clone(),
    });
    let probe_clients = choose_probe_clients(
        &clients,
        &final_admins,
        &active_committers,
        &retained_joiners,
        rng,
    );
    let probe_step_index = steps.len();
    steps.push(ScenarioStep::ProbeBidirectionalDecryptability {
        clients: probe_clients.clone(),
    });
    if retained_joiners.is_empty() {
        steps.push(ScenarioStep::AwaitQuiescence {
            policy: QuiescencePolicy::default(),
        });
    } else {
        steps.push(ScenarioStep::DeliverAll);
        steps.push(ScenarioStep::Tick {
            clients: clients.clone(),
        });
    }

    expected.push(TraceExpectation::ClientsConverged {
        clients: clients.clone(),
        epoch: None,
        member_count: Some(clients.len()),
    });
    expected.push(TraceExpectation::ClientsBidirectionallyDecryptable {
        clients: probe_clients.clone(),
    });
    for client in &clients {
        expected.push(TraceExpectation::AdminPolicy {
            client: client.clone(),
            admins: final_admins.clone(),
        });
        expected.push(TraceExpectation::GroupProfile {
            client: client.clone(),
            name: final_profile_name.clone(),
            description: String::new(),
        });
    }
    for client in &probe_clients {
        let payloads = authored_applications
            .iter()
            .filter(|(sender, _)| sender != client)
            .map(|(_, payload)| payload.clone())
            .chain(
                probe_clients
                    .iter()
                    .filter(|sender| *sender != client)
                    .map(|sender| {
                        format!("cgka-decryptability-probe/v1/{probe_step_index}/{sender}")
                    }),
            )
            .collect();
        expected.push(TraceExpectation::ApplicationPayloadMultiset {
            client: client.clone(),
            payloads,
        });
    }
    reindex_pending_expectations(&steps, &mut expected);

    BuiltCase {
        scenario: ScenarioSpec {
            name: format!(
                "{LARGE_GROUP_PRESSURE_FAMILY}/case-{case_index}/{}",
                arm.name()
            ),
            spec_version: "3".into(),
            topology: Default::default(),
            clients,
            steps,
        },
        expected,
        final_admins,
        active_committers,
        authored_applications,
        retained_joiners,
    }
}

fn bulk_setup(
    case_index: u64,
    clients: &[String],
    initial_admins: &[String],
    expected: &mut Vec<TraceExpectation>,
) -> Vec<ScenarioStep> {
    let mut steps = vec![ScenarioStep::CreateGroup {
        creator: "alice".into(),
        name: format!("large-group-{case_index}"),
        invitees: clients[1..].to_vec(),
        required_features: vec![],
        initial_admins: Some(initial_admins.to_vec()),
        pending: "create".into(),
    }];
    push_confirmed(&mut steps, expected, "alice", "create");
    steps.push(ScenarioStep::DeliverAll);
    steps.push(ScenarioStep::Tick {
        clients: clients[1..].to_vec(),
    });
    steps
}

fn incremental_setup(
    case_index: u64,
    clients: &[String],
    final_admins: &[String],
    expected: &mut Vec<TraceExpectation>,
    retained_joiners: &mut BTreeSet<String>,
) -> Vec<ScenarioStep> {
    let founding_count = 4.min(clients.len());
    let founding = &clients[..founding_count];
    let founding_admins = final_admins
        .iter()
        .filter(|admin| founding.contains(admin))
        .cloned()
        .collect::<Vec<_>>();
    let mut steps = vec![ScenarioStep::CreateGroup {
        creator: "alice".into(),
        name: format!("large-group-{case_index}"),
        invitees: founding[1..].to_vec(),
        required_features: vec![],
        initial_admins: Some(founding_admins),
        pending: "create".into(),
    }];
    push_confirmed(&mut steps, expected, "alice", "create");
    steps.push(ScenarioStep::DeliverAll);
    steps.push(ScenarioStep::Tick {
        clients: founding[1..].to_vec(),
    });

    let batch_size = match clients.len() {
        0..=20 => 4,
        21..=50 => 8,
        51..=100 => 16,
        _ => 32,
    };
    let mut joined = founding.to_vec();
    for (batch_index, batch) in clients[founding_count..].chunks(batch_size).enumerate() {
        let pending = format!("growth-batch-{batch_index}");
        steps.push(ScenarioStep::InviteMembers {
            inviter: "alice".into(),
            invitees: batch.to_vec(),
            pending: pending.clone(),
        });
        push_confirmed(&mut steps, expected, "alice", &pending);
        steps.push(ScenarioStep::DeliverAll);
        joined.extend_from_slice(batch);
        steps.push(ScenarioStep::Tick {
            clients: joined.clone(),
        });
        retained_joiners.extend(batch.iter().cloned());
    }
    admin_policy_commit(
        &mut steps,
        expected,
        "alice",
        final_admins.to_vec(),
        "growth-final-admins",
        clients,
    );
    steps
}

fn sequential_profile_commit(
    steps: &mut Vec<ScenarioStep>,
    expected: &mut Vec<TraceExpectation>,
    client: &str,
    name: String,
    pending: &str,
) {
    steps.push(ScenarioStep::UpdateGroupProfile {
        client: client.into(),
        name: Some(name),
        description: None,
        pending: pending.into(),
    });
    push_confirmed(steps, expected, client, pending);
    steps.push(ScenarioStep::AwaitQuiescence {
        policy: QuiescencePolicy::default(),
    });
}

fn admin_policy_commit(
    steps: &mut Vec<ScenarioStep>,
    expected: &mut Vec<TraceExpectation>,
    client: &str,
    admins: Vec<String>,
    pending: &str,
    settle_clients: &[String],
) {
    steps.push(ScenarioStep::UpdateAdminPolicy {
        client: client.into(),
        admins,
        pending: pending.into(),
    });
    push_confirmed(steps, expected, client, pending);
    settle(steps, settle_clients);
}

#[allow(clippy::too_many_arguments)]
fn competing_profile_wave(
    steps: &mut Vec<ScenarioStep>,
    expected: &mut Vec<TraceExpectation>,
    committers: &[String],
    case_index: u64,
    label: &str,
    duplicate: bool,
    rng: &mut StdRng,
    clients: &[String],
) {
    let mut publications = Vec::new();
    for committer in committers {
        let pending = format!("{label}-{committer}");
        steps.push(ScenarioStep::UpdateGroupData {
            client: committer.clone(),
            name: format!("{label} branch {committer} {case_index}"),
            pending: pending.clone(),
        });
        publications.push(pending);
    }
    for (committer, pending) in committers.iter().zip(&publications) {
        push_confirmed(steps, expected, committer, pending);
    }

    let mut selectors = publications
        .iter()
        .map(|publication| publication_selector(publication))
        .collect::<Vec<_>>();
    if duplicate && selectors.len() > 1 {
        let duplicate_index = rng.gen_range(0..selectors.len());
        steps.push(ScenarioStep::DuplicateMessage {
            selector: selectors[duplicate_index].clone(),
        });
        let mut copy = selectors[duplicate_index].clone();
        copy.occurrence = 1;
        selectors.insert(duplicate_index + 1, copy);
    }
    selectors.shuffle(rng);
    if selectors.len() > 1 {
        steps.push(ScenarioStep::ReorderMessages { order: selectors });
    }
    settle(steps, clients);
}

#[allow(clippy::too_many_arguments)]
fn send_application_batch(
    steps: &mut Vec<ScenarioStep>,
    clients: &[String],
    count: usize,
    case_index: u64,
    label: &str,
    rng: &mut StdRng,
    authored: &mut Vec<(String, String)>,
) {
    let mut senders = clients.to_vec();
    senders.shuffle(rng);
    for message_index in 0..count {
        let sender = senders[message_index % senders.len()].clone();
        let payload = format!("large-group:{case_index}:{label}:{message_index}:{sender}");
        steps.push(ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: payload.clone(),
        });
        authored.push((sender, payload));
    }
}

fn settle(steps: &mut Vec<ScenarioStep>, clients: &[String]) {
    steps.push(ScenarioStep::DeliverAll);
    steps.push(ScenarioStep::Tick {
        clients: clients.to_vec(),
    });
    steps.push(ScenarioStep::AwaitQuiescence {
        policy: QuiescencePolicy::default(),
    });
}

fn push_confirmed(
    steps: &mut Vec<ScenarioStep>,
    expected: &mut Vec<TraceExpectation>,
    client: &str,
    pending: &str,
) {
    expected.push(TraceExpectation::PendingResolution {
        step_index: steps.len(),
        client: client.into(),
        pending: pending.into(),
        resolution: "confirmed".into(),
    });
    steps.push(ScenarioStep::AcknowledgeOutbound {
        client: client.into(),
        publication: Some(pending.into()),
        selection: ScenarioOutboundSelection::All,
        outcome: SubjectOutboundOutcome::Accepted,
    });
}

fn reindex_pending_expectations(steps: &[ScenarioStep], expected: &mut [TraceExpectation]) {
    for expectation in expected {
        let TraceExpectation::PendingResolution {
            step_index,
            client,
            pending,
            ..
        } = expectation
        else {
            continue;
        };
        *step_index = steps
            .iter()
            .position(|step| {
                matches!(
                    step,
                    ScenarioStep::AcknowledgeOutbound {
                        client: step_client,
                        publication: Some(publication),
                        ..
                    } if step_client == client && publication == pending
                )
            })
            .expect("every pending-resolution expectation names an acknowledgement");
    }
}

fn add_terminal_oracle(built: &mut BuiltCase) {
    let clients = built.scenario.clients.clone();
    built.scenario.steps.push(ScenarioStep::DeliverAll);
    built.scenario.steps.push(ScenarioStep::Tick {
        clients: clients.clone(),
    });
    for client in &clients {
        built
            .scenario
            .steps
            .push(ScenarioStep::AcknowledgeOutbound {
                client: client.clone(),
                publication: None,
                selection: ScenarioOutboundSelection::All,
                outcome: SubjectOutboundOutcome::Accepted,
            });
    }
    built.scenario.steps.push(ScenarioStep::DeliverAll);
    built.scenario.steps.push(ScenarioStep::Tick {
        clients: clients.clone(),
    });
    built.scenario.steps.push(ScenarioStep::ObserveExact {
        clients: clients.clone(),
    });
    built
        .expected
        .push(TraceExpectation::ClientsExactlyEquivalent {
            clients: clients.clone(),
        });

    let pending_free = clients
        .iter()
        .filter(|client| !built.retained_joiners.contains(*client))
        .cloned()
        .collect::<Vec<_>>();
    if !pending_free.is_empty() {
        built.expected.push(TraceExpectation::NoPendingWork {
            clients: pending_free,
        });
    }
    for client in &built.retained_joiners {
        built
            .expected
            .push(TraceExpectation::NoPendingWorkExceptRetainedJoinCommit {
                client: client.clone(),
            });
    }
}

fn choose_admins(clients: &[String], count: usize, rng: &mut StdRng) -> Vec<String> {
    let mut candidates = clients[1..].to_vec();
    candidates.shuffle(rng);
    let chosen = candidates
        .into_iter()
        .take(count.saturating_sub(1))
        .collect::<BTreeSet<_>>();
    clients
        .iter()
        .filter(|client| client.as_str() == "alice" || chosen.contains(*client))
        .cloned()
        .collect()
}

fn admin_regime_for(size_slot: usize, arm_slot: usize) -> AdminRegime {
    let mut regime_indices = std::array::from_fn::<_, 6, _>(|offset| size_slot + offset);
    let founder_slot = regime_indices
        .iter()
        .position(|index| index % 5 == 0)
        .expect("six consecutive slots contain the founder-only regime");
    if matches!(founder_slot, 3 | 4) {
        regime_indices.swap(founder_slot, 5);
    }
    AdminRegime::from_index(regime_indices[arm_slot])
}

fn choose_committers(admins: &[String], maximum: usize, rng: &mut StdRng) -> Vec<String> {
    let mut committers = admins.to_vec();
    committers.shuffle(rng);
    committers.truncate(maximum.min(committers.len()));
    committers
}

fn choose_final_handoff_admins(
    clients: &[String],
    successor: &str,
    victim: &str,
    count: usize,
    rng: &mut StdRng,
) -> Vec<String> {
    let mut candidates = clients
        .iter()
        .filter(|client| client.as_str() != "alice" && client.as_str() != victim)
        .cloned()
        .collect::<Vec<_>>();
    candidates.shuffle(rng);
    let mut chosen = BTreeSet::from([successor.to_owned()]);
    chosen.extend(
        candidates
            .into_iter()
            .filter(|client| client != successor)
            .take(count - 1),
    );
    clients
        .iter()
        .filter(|client| chosen.contains(*client))
        .cloned()
        .collect()
}

fn choose_probe_clients(
    clients: &[String],
    admins: &[String],
    committers: &[String],
    retained_joiners: &BTreeSet<String>,
    rng: &mut StdRng,
) -> Vec<String> {
    let mut priority = vec!["alice".to_owned()];
    priority.extend(retained_joiners.iter().take(1).cloned());
    priority.push(clients.last().expect("large group is non-empty").clone());
    if let Some(non_admin) = clients.iter().find(|client| !admins.contains(client)) {
        priority.push(non_admin.clone());
    }
    priority.extend(committers.iter().take(2).cloned());
    priority.extend(admins.iter().take(2).cloned());

    let mut selected = BTreeSet::new();
    for client in priority {
        if selected.len() == MAX_PROBE_CLIENTS {
            break;
        }
        selected.insert(client);
    }

    let mut remainder = clients
        .iter()
        .filter(|client| !selected.contains(*client))
        .cloned()
        .collect::<Vec<_>>();
    remainder.shuffle(rng);
    selected.extend(
        remainder
            .into_iter()
            .take(MAX_PROBE_CLIENTS.saturating_sub(selected.len())),
    );
    clients
        .iter()
        .filter(|client| selected.contains(*client))
        .cloned()
        .collect()
}

fn publication_selector(publication: &str) -> ScenarioMessageSelectorV2 {
    ScenarioMessageSelectorV2 {
        publication: Some(publication.into()),
        class: Some(ScenarioTransportClass::Commit),
        ..Default::default()
    }
}

fn is_workload_commit(step: &ScenarioStep) -> bool {
    matches!(
        step,
        ScenarioStep::InviteMembers { .. }
            | ScenarioStep::RemoveMembers { .. }
            | ScenarioStep::SelfUpdate { .. }
            | ScenarioStep::UpdateGroupData { .. }
            | ScenarioStep::UpdateGroupProfile { .. }
            | ScenarioStep::UpdateAdminPolicy { .. }
    )
}

fn large_clients(count: usize) -> Vec<String> {
    let mut clients = Vec::with_capacity(count);
    clients.push("alice".into());
    for index in 1..count {
        clients.push(format!("member{index:03}"));
    }
    clients
}
