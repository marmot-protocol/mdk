//! Deterministic membership departure and re-entry scenarios.
//!
//! This family keeps most cases small so they can assert exact state, input
//! closure, and active decryptability cheaply. Two incident-shaped arms use a
//! wider group to make all or a seed-selected handful of unrelated incumbents
//! race to commit the same SelfRemove before the departed identity is invited
//! again. The catalog owns
//! interactions that broad membership and large-group workloads only reach
//! incidentally: repeated fresh-Welcome re-entry, self-update/removal races,
//! self-leave, and stale pre-removal Welcomes.

use crate::{
    GeneratedScenarioCase, GeneratedSubjectKind, ScenarioAssertionV2, ScenarioMessageSelectorV2,
    ScenarioOutboundSelection, ScenarioPredicateV2, ScenarioSpec, ScenarioStep,
    ScenarioTransportClass, SubjectOutboundOutcome, TraceExpectation,
};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

pub const MEMBERSHIP_REENTRY_FAMILY: &str = "membership-reentry/v1";
pub const MEMBERSHIP_REENTRY_GENERATOR_VERSION: &str = "1";

const ARM_COUNT: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReentryArm {
    SingleCycle,
    DoubleCycle,
    TripleCycleWithRestarts,
    SelfUpdateBetweenCycles,
    SelfUpdateRemovalRace,
    SelfLeaveThenReentry,
    SelfLeaveRemovalRace,
    StaleWelcomeThenFreshReentry,
    SelfLeaveMultiCommitterReentry,
    SelfLeavePartialMultiCommitterReentry,
}

impl ReentryArm {
    fn from_index(case_index: u64) -> Self {
        match case_index % ARM_COUNT {
            0 => Self::SingleCycle,
            1 => Self::DoubleCycle,
            2 => Self::TripleCycleWithRestarts,
            3 => Self::SelfUpdateBetweenCycles,
            4 => Self::SelfUpdateRemovalRace,
            5 => Self::SelfLeaveThenReentry,
            6 => Self::SelfLeaveRemovalRace,
            7 => Self::StaleWelcomeThenFreshReentry,
            8 => Self::SelfLeaveMultiCommitterReentry,
            _ => Self::SelfLeavePartialMultiCommitterReentry,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::SingleCycle => "single-cycle",
            Self::DoubleCycle => "double-cycle",
            Self::TripleCycleWithRestarts => "triple-cycle-with-restarts",
            Self::SelfUpdateBetweenCycles => "self-update-between-cycles",
            Self::SelfUpdateRemovalRace => "self-update-removal-race",
            Self::SelfLeaveThenReentry => "self-leave-then-reentry",
            Self::SelfLeaveRemovalRace => "self-leave-removal-race",
            Self::StaleWelcomeThenFreshReentry => "stale-welcome-then-fresh-reentry",
            Self::SelfLeaveMultiCommitterReentry => "self-leave-multi-committer-reentry",
            Self::SelfLeavePartialMultiCommitterReentry => {
                "self-leave-partial-multi-committer-reentry"
            }
        }
    }
}

pub fn generate_membership_reentry_family(seed: u64, cases: usize) -> Vec<GeneratedScenarioCase> {
    (0..cases)
        .map(|case_index| generate_membership_reentry_case(seed, case_index as u64))
        .collect()
}

pub fn generate_membership_reentry_case(seed: u64, case_index: u64) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4d45_4d42_4552_5348 ^ case_index.rotate_left(19));
    let arm = ReentryArm::from_index(case_index);
    let wide_incident_arm = matches!(
        arm,
        ReentryArm::SelfLeaveMultiCommitterReentry
            | ReentryArm::SelfLeavePartialMultiCommitterReentry
    );
    let clients = if wide_incident_arm {
        labels([
            "alice", "bob", "carol", "david", "erin", "frank", "grace", "heidi",
        ])
    } else {
        labels(["alice", "bob", "carol", "david"])
    };
    let victim = if wide_incident_arm {
        if rng.gen_bool(0.5) { "grace" } else { "heidi" }
    } else if rng.gen_bool(0.5) {
        "carol"
    } else {
        "david"
    };
    let mut delivery_order = clients.clone();
    delivery_order.shuffle(&mut rng);
    let mut steps = Vec::new();
    let mut expected = Vec::new();

    let mut epoch = if arm == ReentryArm::StaleWelcomeThenFreshReentry {
        setup_without_victim(
            &mut steps,
            &mut expected,
            case_index,
            &clients,
            victim,
            &delivery_order,
        );
        1
    } else {
        setup_full_group(
            &mut steps,
            &mut expected,
            case_index,
            &clients,
            &delivery_order,
        );
        1
    };

    match arm {
        ReentryArm::SingleCycle => {
            epoch = remove_and_readd(
                &mut steps,
                &mut expected,
                &clients,
                &delivery_order,
                victim,
                case_index,
                0,
                epoch,
                false,
            );
        }
        ReentryArm::DoubleCycle => {
            for cycle in 0..2 {
                epoch = remove_and_readd(
                    &mut steps,
                    &mut expected,
                    &clients,
                    &delivery_order,
                    victim,
                    case_index,
                    cycle,
                    epoch,
                    false,
                );
            }
        }
        ReentryArm::TripleCycleWithRestarts => {
            for cycle in 0..3 {
                epoch = remove_and_readd(
                    &mut steps,
                    &mut expected,
                    &clients,
                    &delivery_order,
                    victim,
                    case_index,
                    cycle,
                    epoch,
                    true,
                );
            }
        }
        ReentryArm::SelfUpdateBetweenCycles => {
            for cycle in 0..2 {
                epoch = self_update(
                    &mut steps,
                    &mut expected,
                    &clients,
                    &delivery_order,
                    victim,
                    cycle,
                    epoch,
                );
                epoch = remove_and_readd(
                    &mut steps,
                    &mut expected,
                    &clients,
                    &delivery_order,
                    victim,
                    case_index,
                    cycle,
                    epoch,
                    false,
                );
            }
        }
        ReentryArm::SelfUpdateRemovalRace => {
            let self_pending = "racing-self-update";
            steps.push(ScenarioStep::SelfUpdate {
                client: victim.into(),
                pending: self_pending.into(),
            });
            let remove_pending = "racing-remove";
            steps.push(ScenarioStep::RemoveMembers {
                remover: "alice".into(),
                members: vec![victim.into()],
                pending: remove_pending.into(),
            });
            confirm(&mut steps, &mut expected, victim, self_pending);
            confirm(&mut steps, &mut expected, "alice", remove_pending);
            settle_twice(&mut steps, &delivery_order);
            epoch += 1;
            assert_client_state(&mut steps, "alice", epoch, clients.len() - 1);
            epoch = readd_and_probe(
                &mut steps,
                &mut expected,
                &clients,
                &delivery_order,
                victim,
                case_index,
                0,
                epoch,
            );
        }
        ReentryArm::SelfLeaveThenReentry => {
            steps.push(ScenarioStep::Leave {
                client: victim.into(),
            });
            settle_self_leave(&mut steps, &delivery_order);
            epoch += 1;
            assert_client_state(&mut steps, "alice", epoch, clients.len() - 1);
            epoch = readd_and_probe(
                &mut steps,
                &mut expected,
                &clients,
                &delivery_order,
                victim,
                case_index,
                0,
                epoch,
            );
        }
        ReentryArm::SelfLeaveRemovalRace => {
            steps.push(ScenarioStep::Leave {
                client: victim.into(),
            });
            steps.push(ScenarioStep::RemoveMembers {
                remover: "alice".into(),
                members: vec![victim.into()],
                pending: "remove-against-self-leave".into(),
            });
            confirm(
                &mut steps,
                &mut expected,
                "alice",
                "remove-against-self-leave",
            );
            settle_twice(&mut steps, &delivery_order);
            epoch += 1;
            assert_client_state(&mut steps, "alice", epoch, clients.len() - 1);
            epoch = readd_and_probe(
                &mut steps,
                &mut expected,
                &clients,
                &delivery_order,
                victim,
                case_index,
                0,
                epoch,
            );
        }
        ReentryArm::StaleWelcomeThenFreshReentry => {
            steps.push(ScenarioStep::InviteMembers {
                inviter: "alice".into(),
                invitees: vec![victim.into()],
                pending: "stale-invite".into(),
            });
            confirm(&mut steps, &mut expected, "alice", "stale-invite");
            steps.push(ScenarioStep::WithholdMessage {
                selector: ScenarioMessageSelectorV2 {
                    publication: Some("stale-invite".into()),
                    class: Some(ScenarioTransportClass::Welcome),
                    ..Default::default()
                },
                label: "stale-original-welcome".into(),
            });
            settle(&mut steps, &delivery_order_without(&delivery_order, victim));
            epoch += 1;
            assert_client_state(&mut steps, "alice", epoch, clients.len());

            steps.push(ScenarioStep::RemoveMembers {
                remover: "alice".into(),
                members: vec![victim.into()],
                pending: "remove-before-welcome".into(),
            });
            confirm(&mut steps, &mut expected, "alice", "remove-before-welcome");
            steps.push(ScenarioStep::WithholdMessage {
                selector: ScenarioMessageSelectorV2 {
                    publication: Some("remove-before-welcome".into()),
                    class: Some(ScenarioTransportClass::GroupMessage),
                    ..Default::default()
                },
                label: "trusted-removal-after-stale-welcome".into(),
            });
            settle(&mut steps, &delivery_order_without(&delivery_order, victim));
            epoch += 1;
            assert_client_state(&mut steps, "alice", epoch, clients.len() - 1);

            steps.push(ScenarioStep::ReleaseWithheld {
                label: "stale-original-welcome".into(),
            });
            steps.push(ScenarioStep::Tick {
                clients: vec![victim.into()],
            });
            if rng.gen_bool(0.5) {
                steps.push(ScenarioStep::RestartClient {
                    client: victim.into(),
                });
            }
            // A newer Welcome cannot authenticate its own lineage. Release the
            // commit from the victim's currently trusted branch first; only
            // after that removal is applied is the fresh Welcome a re-entry.
            steps.push(ScenarioStep::ReleaseWithheld {
                label: "trusted-removal-after-stale-welcome".into(),
            });
            settle(&mut steps, &delivery_order);
            assert_client_state(&mut steps, "alice", epoch, clients.len() - 1);
            epoch = readd_and_probe(
                &mut steps,
                &mut expected,
                &clients,
                &delivery_order,
                victim,
                case_index,
                0,
                epoch,
            );
        }
        ReentryArm::SelfLeaveMultiCommitterReentry => {
            steps.push(ScenarioStep::Leave {
                client: victim.into(),
            });
            steps.push(ScenarioStep::DeliverAll);

            // Every remaining member observes the standalone SelfRemove before
            // any resulting commit is delivered. Each therefore stages and
            // publishes a legitimate sibling commit for the same next epoch,
            // matching the production incident's unrelated-incumbent fork.
            let incumbents = delivery_order_without(&delivery_order, victim);
            steps.push(ScenarioStep::Tick {
                clients: incumbents.clone(),
            });
            for incumbent in &incumbents {
                steps.push(accept_all_outbound(incumbent));
            }
            settle_twice(&mut steps, &delivery_order);
            epoch += 1;
            for incumbent in &incumbents {
                assert_client_state(&mut steps, incumbent, epoch, clients.len() - 1);
            }
            epoch = readd_and_probe(
                &mut steps,
                &mut expected,
                &clients,
                &delivery_order,
                victim,
                case_index,
                0,
                epoch,
            );
        }
        ReentryArm::SelfLeavePartialMultiCommitterReentry => {
            steps.push(ScenarioStep::Leave {
                client: victim.into(),
            });
            steps.push(ScenarioStep::DeliverAll);

            // Only a seed-selected handful of incumbents reach their delayed
            // auto-commit before the first sibling commit arrives. The rest
            // ingest one of those commits before their timer fires and follow
            // the winner directly. This preserves the production-shaped
            // partial-impact timing in which most members progress while a
            // few early committers must rewind and replay the shared proposal.
            let incumbents = delivery_order_without(&delivery_order, victim);
            let committer_count = rng.gen_range(2..=4).min(incumbents.len());
            let early_committers = incumbents[..committer_count].to_vec();
            steps.push(ScenarioStep::Tick {
                clients: early_committers.clone(),
            });
            for incumbent in &early_committers {
                steps.push(accept_all_outbound(incumbent));
            }
            settle_twice(&mut steps, &delivery_order);
            epoch += 1;
            for incumbent in &incumbents {
                assert_client_state(&mut steps, incumbent, epoch, clients.len() - 1);
            }
            epoch = readd_and_probe(
                &mut steps,
                &mut expected,
                &clients,
                &delivery_order,
                victim,
                case_index,
                0,
                epoch,
            );
        }
    }

    steps.push(ScenarioStep::ProbeBidirectionalDecryptability {
        clients: clients.clone(),
    });
    steps.push(ScenarioStep::ObserveExact {
        clients: clients.clone(),
    });
    expected.push(TraceExpectation::ClientsConverged {
        clients: clients.clone(),
        epoch: Some(epoch),
        member_count: Some(clients.len()),
    });
    expected.push(TraceExpectation::ClientsExactlyEquivalent {
        clients: clients.clone(),
    });
    expected.push(TraceExpectation::NoPendingWork {
        clients: clients
            .iter()
            .filter(|client| client.as_str() != victim)
            .cloned()
            .collect(),
    });
    expected.push(TraceExpectation::NoPendingWorkExceptRetainedJoinCommit {
        client: victim.into(),
    });
    expected.push(TraceExpectation::ClientsBidirectionallyDecryptable {
        clients: clients.clone(),
    });

    GeneratedScenarioCase {
        family_name: MEMBERSHIP_REENTRY_FAMILY.into(),
        generator_version: MEMBERSHIP_REENTRY_GENERATOR_VERSION.into(),
        seed,
        case_index,
        workload_profile: None,
        subject: GeneratedSubjectKind::Engine,
        scenario: ScenarioSpec {
            name: format!(
                "{MEMBERSHIP_REENTRY_FAMILY}/case-{case_index}/{}",
                arm.name()
            ),
            spec_version: "3".into(),
            clients,
            topology: Default::default(),
            steps,
        },
        expected_outcomes: expected,
    }
}

fn setup_full_group(
    steps: &mut Vec<ScenarioStep>,
    expected: &mut Vec<TraceExpectation>,
    case_index: u64,
    clients: &[String],
    delivery_order: &[String],
) {
    steps.push(ScenarioStep::CreateGroup {
        creator: "alice".into(),
        name: format!("membership-reentry-{case_index}"),
        invitees: clients[1..].to_vec(),
        required_features: vec![],
        initial_admins: Some(vec!["alice".into()]),
        pending: "create".into(),
    });
    confirm(steps, expected, "alice", "create");
    settle(steps, delivery_order);
    steps.push(ScenarioStep::ClearEvents {
        clients: clients.to_vec(),
    });
}

fn setup_without_victim(
    steps: &mut Vec<ScenarioStep>,
    expected: &mut Vec<TraceExpectation>,
    case_index: u64,
    clients: &[String],
    victim: &str,
    delivery_order: &[String],
) {
    let invitees = clients
        .iter()
        .filter(|client| client.as_str() != "alice" && client.as_str() != victim)
        .cloned()
        .collect();
    steps.push(ScenarioStep::CreateGroup {
        creator: "alice".into(),
        name: format!("membership-reentry-{case_index}"),
        invitees,
        required_features: vec![],
        initial_admins: Some(vec!["alice".into()]),
        pending: "create".into(),
    });
    confirm(steps, expected, "alice", "create");
    settle(steps, &delivery_order_without(delivery_order, victim));
    steps.push(ScenarioStep::ClearEvents {
        clients: clients.to_vec(),
    });
}

#[allow(clippy::too_many_arguments)]
fn remove_and_readd(
    steps: &mut Vec<ScenarioStep>,
    expected: &mut Vec<TraceExpectation>,
    clients: &[String],
    delivery_order: &[String],
    victim: &str,
    case_index: u64,
    cycle: usize,
    epoch: u64,
    restart_after_remove: bool,
) -> u64 {
    let pending = format!("remove-{cycle}");
    steps.push(ScenarioStep::RemoveMembers {
        remover: "alice".into(),
        members: vec![victim.into()],
        pending: pending.clone(),
    });
    confirm(steps, expected, "alice", &pending);
    settle(steps, delivery_order);
    let epoch = epoch + 1;
    assert_client_state(steps, "alice", epoch, clients.len() - 1);
    if restart_after_remove {
        steps.push(ScenarioStep::RestartClient {
            client: victim.into(),
        });
    }
    readd_and_probe(
        steps,
        expected,
        clients,
        delivery_order,
        victim,
        case_index,
        cycle,
        epoch,
    )
}

#[allow(clippy::too_many_arguments)]
fn readd_and_probe(
    steps: &mut Vec<ScenarioStep>,
    expected: &mut Vec<TraceExpectation>,
    clients: &[String],
    delivery_order: &[String],
    victim: &str,
    case_index: u64,
    cycle: usize,
    epoch: u64,
) -> u64 {
    let pending = format!("readd-{cycle}");
    steps.push(ScenarioStep::InviteMembers {
        inviter: "alice".into(),
        invitees: vec![victim.into()],
        pending: pending.clone(),
    });
    confirm(steps, expected, "alice", &pending);
    settle(steps, delivery_order);
    let epoch = epoch + 1;
    assert_client_state(steps, "alice", epoch, clients.len());
    assert_client_state(steps, victim, epoch, clients.len());

    let payload = format!("membership-reentry:{case_index}:{cycle}:{victim}");
    steps.push(ScenarioStep::SendAppMessage {
        sender: victim.into(),
        payload: payload.clone(),
    });
    steps.push(accept_all_outbound(victim));
    settle(steps, delivery_order);
    steps.push(ScenarioStep::Assert {
        assertion: ScenarioAssertionV2::Exactly {
            predicate: ScenarioPredicateV2::PayloadCount {
                client: "alice".into(),
                payload,
                count: 1,
            },
        },
    });
    epoch
}

fn self_update(
    steps: &mut Vec<ScenarioStep>,
    expected: &mut Vec<TraceExpectation>,
    clients: &[String],
    delivery_order: &[String],
    victim: &str,
    cycle: usize,
    epoch: u64,
) -> u64 {
    let pending = format!("self-update-{cycle}");
    steps.push(ScenarioStep::SelfUpdate {
        client: victim.into(),
        pending: pending.clone(),
    });
    confirm(steps, expected, victim, &pending);
    settle(steps, delivery_order);
    let epoch = epoch + 1;
    assert_client_state(steps, "alice", epoch, clients.len());
    epoch
}

fn settle_self_leave(steps: &mut Vec<ScenarioStep>, delivery_order: &[String]) {
    steps.push(ScenarioStep::DeliverAll);
    steps.push(ScenarioStep::Tick {
        clients: vec!["alice".into()],
    });
    steps.push(accept_all_outbound("alice"));
    settle(steps, delivery_order);
}

fn settle_twice(steps: &mut Vec<ScenarioStep>, delivery_order: &[String]) {
    settle(steps, delivery_order);
    settle(steps, delivery_order);
}

fn settle(steps: &mut Vec<ScenarioStep>, delivery_order: &[String]) {
    steps.push(ScenarioStep::DeliverAll);
    steps.push(ScenarioStep::Tick {
        clients: delivery_order.to_vec(),
    });
}

fn delivery_order_without(delivery_order: &[String], excluded: &str) -> Vec<String> {
    delivery_order
        .iter()
        .filter(|client| client.as_str() != excluded)
        .cloned()
        .collect()
}

fn confirm(
    steps: &mut Vec<ScenarioStep>,
    expected: &mut Vec<TraceExpectation>,
    client: &str,
    pending: &str,
) {
    let step_index = steps.len();
    steps.push(ScenarioStep::AcknowledgeOutbound {
        client: client.into(),
        publication: Some(pending.into()),
        selection: ScenarioOutboundSelection::All,
        outcome: SubjectOutboundOutcome::Accepted,
    });
    expected.push(TraceExpectation::PendingResolution {
        step_index,
        client: client.into(),
        pending: pending.into(),
        resolution: "confirmed".into(),
    });
}

fn accept_all_outbound(client: &str) -> ScenarioStep {
    ScenarioStep::AcknowledgeOutbound {
        client: client.into(),
        publication: None,
        selection: ScenarioOutboundSelection::All,
        outcome: SubjectOutboundOutcome::Accepted,
    }
}

fn assert_client_state(steps: &mut Vec<ScenarioStep>, client: &str, epoch: u64, members: usize) {
    steps.push(ScenarioStep::Assert {
        assertion: ScenarioAssertionV2::Exactly {
            predicate: ScenarioPredicateV2::ClientState {
                client: client.into(),
                epoch: Some(epoch),
                member_count: Some(members),
            },
        },
    });
}

fn labels<const N: usize>(values: [&str; N]) -> Vec<String> {
    values.into_iter().map(String::from).collect()
}
