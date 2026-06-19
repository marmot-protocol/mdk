//! Deterministic generated scenario families.
//!
//! Families produce ordinary [`ScenarioSpec`] values plus the metadata needed
//! to replay or promote a generated case into a fixed vector.

use crate::{
    GeneratedScenarioMetadata, ScenarioReport, ScenarioRunError, ScenarioSpec, ScenarioStep,
    ScenarioTrace, TraceExpectation, VectorFixture, run_scenario_report_with_outcomes,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedScenarioCase {
    pub family_name: String,
    pub generator_version: String,
    pub seed: u64,
    pub case_index: u64,
    pub scenario: ScenarioSpec,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_outcomes: Vec<TraceExpectation>,
}

impl GeneratedScenarioCase {
    pub fn to_vector_fixture(
        &self,
        conformance_version: impl Into<String>,
        expected_trace: Option<ScenarioTrace>,
    ) -> VectorFixture {
        VectorFixture {
            scenario_name: self.scenario.name.clone(),
            vector_version: "1".into(),
            conformance_version: conformance_version.into(),
            seed: Some(self.seed),
            scenario: self.scenario.clone(),
            expected_trace,
            expected_outcomes: self.expected_outcomes.clone(),
        }
    }
}

pub fn generate_send_leave_family(seed: u64, cases: usize) -> Vec<GeneratedScenarioCase> {
    let mut out = Vec::with_capacity(cases);
    for case_index in 0..cases {
        let mut rng = StdRng::seed_from_u64(seed ^ ((case_index as u64) << 32));
        out.push(GeneratedScenarioCase {
            family_name: "send-leave/v1".into(),
            generator_version: "1".into(),
            seed,
            case_index: case_index as u64,
            scenario: send_leave_case(&mut rng, case_index as u64),
            expected_outcomes: vec![],
        });
    }
    out
}

pub fn generate_convergence_e2e_delivery_family(
    seed: u64,
    cases: usize,
) -> Vec<GeneratedScenarioCase> {
    let mut out = Vec::with_capacity(cases);
    for case_index in 0..cases {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xC0A7_C0A7 ^ ((case_index as u64) << 32));
        out.push(GeneratedScenarioCase {
            family_name: "convergence-e2e-delivery/v1".into(),
            generator_version: "1".into(),
            seed,
            case_index: case_index as u64,
            scenario: convergence_e2e_delivery_case(&mut rng, case_index as u64),
            expected_outcomes: vec![],
        });
    }
    out
}

pub fn generate_convergence_chaos_family(seed: u64, cases: usize) -> Vec<GeneratedScenarioCase> {
    let mut out = Vec::with_capacity(cases);
    for case_index in 0..cases {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xC0A7_1CE5 ^ ((case_index as u64) << 32));
        let (scenario, expected_outcomes) = convergence_chaos_case(&mut rng, case_index as u64);
        out.push(GeneratedScenarioCase {
            family_name: "convergence-chaos/v1".into(),
            generator_version: "3".into(),
            seed,
            case_index: case_index as u64,
            scenario,
            expected_outcomes,
        });
    }
    out
}

pub async fn run_generated_case_report(
    case: &GeneratedScenarioCase,
    expected_trace: Option<ScenarioTrace>,
) -> Result<ScenarioReport, ScenarioRunError> {
    let mut report = run_scenario_report_with_outcomes(
        &case.scenario,
        expected_trace.clone(),
        case.expected_outcomes.clone(),
    )
    .await?;
    let minimized_case = if report.expectation_failures.is_empty() {
        None
    } else {
        minimize_failing_case(case, expected_trace.as_ref(), &report).await
    };
    report.metadata.generated = Some(GeneratedScenarioMetadata {
        family_name: case.family_name.clone(),
        generator_version: case.generator_version.clone(),
        seed: case.seed,
        case_index: case.case_index,
        minimized_case,
    });
    Ok(report)
}

async fn minimize_failing_case(
    case: &GeneratedScenarioCase,
    expected_trace: Option<&ScenarioTrace>,
    failing_report: &ScenarioReport,
) -> Option<ScenarioSpec> {
    let target_failures = failure_kinds(failing_report);
    if target_failures.is_empty() {
        return None;
    }

    let mut candidate = case.scenario.clone();
    let mut changed = false;
    let mut index = 0;
    while index < candidate.steps.len() {
        if !is_minimizer_removable(&candidate.steps[index]) {
            index += 1;
            continue;
        }

        let mut trial = candidate.clone();
        trial.steps.remove(index);
        if reproduces_failure(
            &trial,
            expected_trace.cloned(),
            case.expected_outcomes.clone(),
            &target_failures,
        )
        .await
        {
            candidate = trial;
            changed = true;
        } else {
            index += 1;
        }
    }

    changed.then_some(candidate)
}

async fn reproduces_failure(
    scenario: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    expected_outcomes: Vec<TraceExpectation>,
    target_failures: &BTreeSet<String>,
) -> bool {
    match run_scenario_report_with_outcomes(scenario, expected_trace, expected_outcomes).await {
        Ok(report) => target_failures.is_subset(&failure_kinds(&report)),
        Err(_) => false,
    }
}

fn failure_kinds(report: &ScenarioReport) -> BTreeSet<String> {
    report
        .expectation_failures
        .iter()
        .map(|failure| failure.kind.clone())
        .collect()
}

fn is_minimizer_removable(step: &ScenarioStep) -> bool {
    matches!(
        step,
        ScenarioStep::SendAppMessage { .. }
            | ScenarioStep::ClearEvents { .. }
            | ScenarioStep::DropQueued { .. }
            | ScenarioStep::DuplicateQueued { .. }
            | ScenarioStep::DelayQueued { .. }
            | ScenarioStep::ReleaseDelayed { .. }
            | ScenarioStep::ReorderQueued { .. }
            | ScenarioStep::SetPartition { .. }
            | ScenarioStep::ClearPartition
    )
}

fn convergence_chaos_case(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    match case_index % 11 {
        0 => convergence_chaos_invite_fork(case_index),
        1 => convergence_chaos_group_data_fork(case_index),
        2 => convergence_chaos_rollback_queue_faults(rng, case_index),
        3 => convergence_chaos_partition_leave(case_index),
        4 => convergence_chaos_delayed_past_epoch_app(case_index),
        5 => convergence_chaos_stable_queue_faults(case_index),
        6 => convergence_chaos_large_message_storm(rng, case_index),
        7 => convergence_chaos_large_partitioned_storm(rng, case_index),
        8 => convergence_chaos_large_commit_storm(rng, case_index),
        9 => convergence_chaos_large_mixed_message_commit_storm(rng, case_index),
        _ => convergence_chaos_restart_delivery_faults(case_index),
    }
}

fn convergence_chaos_invite_fork(case_index: u64) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients: labels(["alice", "bob", "david", "eve"]),
        steps: vec![
            create_group(
                "alice",
                format!("invite-fork-{case_index}"),
                ["bob"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob"]),
            clear(["alice", "bob", "david", "eve"]),
            ScenarioStep::SetPartition {
                allow: labels(["alice", "bob"]),
            },
            invite("alice", ["david"], "alice-invite"),
            invite("bob", ["eve"], "bob-invite"),
            confirmed_step("alice", "alice-invite"),
            confirmed_step("bob", "bob-invite"),
            ScenarioStep::DeliverAll,
            tick(["alice", "bob"]),
            observe(["alice", "bob"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        confirmed(8, "alice", "alice-invite"),
        confirmed(9, "bob", "bob-invite"),
        clients_converged(["alice", "bob"], Some(2), Some(3)),
        client_state("alice", 2, 3, vec![]),
        client_state("bob", 2, 3, vec![]),
        recovery_summary(1, Some(1), Some(2)),
    ];
    (scenario, expected)
}

fn convergence_chaos_group_data_fork(case_index: u64) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients: labels(["alice", "bob"]),
        steps: vec![
            create_group(
                "alice",
                format!("group-data-fork-{case_index}"),
                ["bob"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob"]),
            clear(["alice", "bob"]),
            ScenarioStep::UpdateGroupData {
                client: "alice".into(),
                name: format!("alice branch {case_index}"),
                pending: "alice-update".into(),
            },
            ScenarioStep::UpdateGroupData {
                client: "bob".into(),
                name: format!("bob branch {case_index}"),
                pending: "bob-update".into(),
            },
            confirmed_step("alice", "alice-update"),
            confirmed_step("bob", "bob-update"),
            ScenarioStep::DeliverAll,
            tick(["alice", "bob"]),
            observe(["alice", "bob"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        confirmed(7, "alice", "alice-update"),
        confirmed(8, "bob", "bob-update"),
        clients_converged(["alice", "bob"], Some(2), Some(2)),
        recovery_summary(1, Some(1), Some(2)),
    ];
    (scenario, expected)
}

fn convergence_chaos_rollback_queue_faults(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    // After alice's group-data update rolls back, alice's own commit stays on
    // the bus queue (FailPending only retracts the local pending state) and bob
    // sends several app messages behind it. Drive the delivery schedule of those
    // app messages from the seed so distinct seeds exercise distinct adversarial
    // orderings of the post-rollback queue, not just a different payload string.
    // FIFO delivery makes the observed payload order the permuted queue order,
    // so recompute the expectation from the same permutation. The rolled-back
    // commit is pinned at queue head so the duplicate/delay/release still pins
    // dedup of the redelivered commit across the rollback (the shape's reason
    // for existing) regardless of the seeded app order.
    let payloads = (0..6)
        .map(|index| format!("bob-after-rollback-{case_index}-{index}"))
        .collect::<Vec<_>>();
    let app_order = shuffled_order(rng, payloads.len());
    let expected_payloads = app_order
        .iter()
        .map(|index| payloads[*index].clone())
        .collect::<Vec<_>>();
    // Full-queue permutation: the rolled-back commit stays at index 0, the app
    // messages (queue indices 1..) are permuted per the seed.
    let order = std::iter::once(0)
        .chain(app_order.iter().map(|index| index + 1))
        .collect::<Vec<_>>();

    let mut steps = vec![
        create_group(
            "alice",
            format!("rollback-faults-{case_index}"),
            ["bob"],
            "create",
        ),
        confirmed_step("alice", "create"),
        ScenarioStep::DeliverAll,
        tick(["bob"]),
        clear(["alice", "bob"]),
        ScenarioStep::UpdateGroupData {
            client: "alice".into(),
            name: format!("rolled back {case_index}"),
            pending: "update".into(),
        },
        ScenarioStep::FailPending {
            client: "alice".into(),
            pending: "update".into(),
        },
    ];
    for payload in &payloads {
        steps.push(ScenarioStep::SendAppMessage {
            sender: "bob".into(),
            payload: payload.clone(),
        });
    }
    // Seed-driven delivery schedule for the post-rollback messages.
    steps.push(ScenarioStep::ReorderQueued { order });
    // Duplicate the first post-rollback app message, not the rolled-back commit
    // pinned at queue head. The original reaches alice in the first delivery
    // pass; the delayed copy is released and ticked separately, so this shape
    // exercises duplicate app-message handling under a rollback-tainted queue.
    steps.push(ScenarioStep::DuplicateQueued { index: 1 });
    steps.push(ScenarioStep::DelayQueued {
        index: 2,
        delayed: "duplicate-app".into(),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick(["alice"]));
    steps.push(ScenarioStep::ReleaseDelayed {
        delayed: "duplicate-app".into(),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick(["alice"]));
    steps.push(observe(["alice", "bob"]));

    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients: labels(["alice", "bob"]),
        steps,
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        rolled_back(6, "alice", "update"),
        clients_converged(["alice", "bob"], Some(1), Some(2)),
        client_state("alice", 1, 2, expected_payloads),
        client_state("bob", 1, 2, vec![]),
    ];
    (scenario, expected)
}

fn convergence_chaos_stable_queue_faults(case_index: u64) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let bob_payload = format!("bob-first-{case_index}");
    let carol_payload = format!("carol-second-{case_index}");
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients: labels(["alice", "bob", "carol"]),
        steps: vec![
            create_group(
                "alice",
                format!("stable-queue-faults-{case_index}"),
                ["bob", "carol"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob", "carol"]),
            clear(["alice", "bob", "carol"]),
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: bob_payload.clone(),
            },
            ScenarioStep::SendAppMessage {
                sender: "carol".into(),
                payload: carol_payload.clone(),
            },
            ScenarioStep::DuplicateQueued { index: 0 },
            ScenarioStep::DelayQueued {
                index: 1,
                delayed: "delayed-copy".into(),
            },
            ScenarioStep::ReorderQueued { order: vec![1, 0] },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            ScenarioStep::ReleaseDelayed {
                delayed: "delayed-copy".into(),
            },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            observe(["alice"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        client_state("alice", 1, 3, vec![carol_payload, bob_payload]),
    ];
    (scenario, expected)
}

fn convergence_chaos_partition_leave(case_index: u64) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let visible_payload = format!("bob-visible-{case_index}");
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients: labels(["alice", "bob"]),
        steps: vec![
            create_group(
                "alice",
                format!("partition-leave-{case_index}"),
                ["bob"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob"]),
            clear(["alice", "bob"]),
            ScenarioStep::SetPartition {
                allow: labels(["bob"]),
            },
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: format!("bob-hidden-{case_index}"),
            },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            ScenarioStep::ClearPartition,
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: visible_payload.clone(),
            },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            ScenarioStep::Leave {
                client: "bob".into(),
            },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            ScenarioStep::DeliverAll,
            tick(["bob"]),
            observe(["alice"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        TraceExpectation::ClientState {
            client: "alice".into(),
            epoch: 2,
            member_count: 1,
            received_payloads: Some(vec![visible_payload]),
            added_members: None,
            removed_members: Some(vec!["bob".into()]),
        },
    ];
    (scenario, expected)
}

fn convergence_chaos_delayed_past_epoch_app(
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let payload = format!("epoch-one-delayed-{case_index}");
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients: labels(["alice", "bob", "carol", "david"]),
        steps: vec![
            create_group(
                "alice",
                format!("delayed-past-epoch-{case_index}"),
                ["bob", "carol"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob", "carol"]),
            clear(["alice", "bob", "carol", "david"]),
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: payload.clone(),
            },
            ScenarioStep::DelayQueued {
                index: 0,
                delayed: "old-app".into(),
            },
            invite("alice", ["david"], "invite-david"),
            confirmed_step("alice", "invite-david"),
            ScenarioStep::DeliverAll,
            tick(["carol", "david"]),
            ScenarioStep::ReleaseDelayed {
                delayed: "old-app".into(),
            },
            ScenarioStep::DeliverAll,
            tick(["carol"]),
            observe(["carol"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        confirmed(8, "alice", "invite-david"),
        client_state("carol", 2, 4, vec![payload]),
    ];
    (scenario, expected)
}

fn convergence_chaos_large_message_storm(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = large_clients(21);
    let invitees = clients[1..].to_vec();
    let senders = clients[1..].to_vec();
    let payloads = senders
        .iter()
        .map(|sender| format!("{sender}:large-storm:{case_index}"))
        .collect::<Vec<_>>();
    // Drive the delivery schedule from the seed so distinct seeds exercise
    // distinct reorderings. FIFO delivery makes the observed payload order the
    // permuted queue order, so recompute the expectation from the same order.
    let order = shuffled_order(rng, senders.len());
    let expected_payloads = order
        .iter()
        .map(|index| payloads[*index].clone())
        .collect::<Vec<_>>();

    let mut steps = large_group_setup(
        format!("large-message-storm-{case_index}"),
        clients.clone(),
        invitees.clone(),
    );
    for (sender, payload) in senders.iter().zip(payloads.iter()) {
        steps.push(ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: payload.clone(),
        });
    }
    steps.push(ScenarioStep::ReorderQueued { order });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(vec!["alice".into()]));
    steps.push(observe_vec(vec!["alice".into()]));

    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients,
        steps,
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        client_state("alice", 1, 21, expected_payloads),
    ];
    (scenario, expected)
}

fn convergence_chaos_large_partitioned_storm(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = large_clients(25);
    let invitees = clients[1..].to_vec();
    let senders = clients[1..].to_vec();
    let payloads = senders
        .iter()
        .map(|sender| format!("{sender}:partitioned-storm:{case_index}"))
        .collect::<Vec<_>>();

    let mut steps = large_group_setup(
        format!("large-partitioned-storm-{case_index}"),
        clients.clone(),
        invitees.clone(),
    );
    steps.push(ScenarioStep::SetPartition {
        allow: vec!["alice".into()],
    });
    for (sender, payload) in senders.iter().zip(payloads.iter()) {
        steps.push(ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: payload.clone(),
        });
    }
    // Vary the seeded delivery schedule. Only alice is un-partitioned, so it
    // receives every payload; FIFO delivery makes the observed order the
    // permuted queue order, so recompute the expectation from the same order.
    let order = shuffled_order(rng, senders.len());
    let expected_payloads = order
        .iter()
        .map(|index| payloads[*index].clone())
        .collect::<Vec<_>>();
    steps.push(ScenarioStep::ReorderQueued { order });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(vec!["alice".into()]));
    steps.push(ScenarioStep::ClearPartition);
    steps.push(observe_vec(vec!["alice".into()]));

    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients,
        steps,
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        client_state("alice", 1, 25, expected_payloads),
    ];
    (scenario, expected)
}

fn convergence_chaos_large_commit_storm(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = large_clients(21);
    let invitees = clients[1..].to_vec();
    let committers = clients[..8].to_vec();
    let mut steps = large_group_setup(
        format!("large-commit-storm-{case_index}"),
        clients.clone(),
        invitees,
    );

    for committer in &committers {
        steps.push(ScenarioStep::UpdateGroupData {
            client: committer.clone(),
            name: format!("{committer} branch {case_index}"),
            pending: format!("{committer}-update"),
        });
    }
    for committer in &committers {
        steps.push(ScenarioStep::ConfirmPending {
            client: committer.clone(),
            pending: format!("{committer}-update"),
        });
    }
    // Vary which queued commit is duplicated and how the queue is reordered
    // from the seed. Convergence and per-committer confirmation are invariant
    // under delivery schedule, so the expectations stay fixed while distinct
    // seeds drive distinct adversarial commit-delivery orders.
    steps.push(ScenarioStep::DuplicateQueued {
        index: rng.gen_range(0..committers.len()),
    });
    steps.push(ScenarioStep::ReorderQueued {
        order: shuffled_order(rng, committers.len() + 1),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(committers.clone()));
    steps.push(observe_vec(committers.clone()));

    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients,
        steps,
    };
    let mut expected = vec![
        confirmed(1, "alice", "create"),
        clients_converged_vec(committers.clone(), Some(2), Some(21)),
    ];
    for (offset, committer) in committers.iter().enumerate() {
        expected.push(confirmed(
            13 + offset,
            committer,
            &format!("{committer}-update"),
        ));
    }
    (scenario, expected)
}

fn convergence_chaos_large_mixed_message_commit_storm(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = large_clients(21);
    let invitees = clients[1..].to_vec();
    let senders = clients[1..].to_vec();
    let committers = clients[..8].to_vec();
    let mut steps = large_group_setup(
        format!("large-mixed-message-commit-storm-{case_index}"),
        clients.clone(),
        invitees,
    );

    for sender in &senders {
        steps.push(ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: format!("{sender}:mixed-storm:{case_index}"),
        });
    }
    // Vary the message-phase schedule from the seed. These events are cleared
    // before the observed commit storm, so the schedule changes engine input
    // ordering without affecting the pinned expectations.
    steps.push(ScenarioStep::ReorderQueued {
        order: shuffled_order(rng, senders.len()),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients.clone()));
    steps.push(clear_vec(clients.clone()));

    for committer in &committers {
        steps.push(ScenarioStep::UpdateGroupData {
            client: committer.clone(),
            name: format!("{committer} mixed branch {case_index}"),
            pending: format!("{committer}-mixed-update"),
        });
    }
    for committer in &committers {
        steps.push(ScenarioStep::ConfirmPending {
            client: committer.clone(),
            pending: format!("{committer}-mixed-update"),
        });
    }
    // Vary the commit-storm duplicate target and reorder from the seed.
    // Convergence and per-committer confirmation are schedule-invariant.
    steps.push(ScenarioStep::DuplicateQueued {
        index: rng.gen_range(0..committers.len()),
    });
    steps.push(ScenarioStep::ReorderQueued {
        order: shuffled_order(rng, committers.len() + 1),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(committers.clone()));
    steps.push(observe_vec(committers.clone()));

    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients,
        steps,
    };
    let mut expected = vec![
        confirmed(1, "alice", "create"),
        clients_converged_vec(committers.clone(), Some(2), Some(21)),
    ];
    for (offset, committer) in committers.iter().enumerate() {
        expected.push(confirmed(
            37 + offset,
            committer,
            &format!("{committer}-mixed-update"),
        ));
    }
    (scenario, expected)
}

fn convergence_chaos_restart_delivery_faults(
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let payload = format!("bob:restart-delivery:{case_index}");
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients: labels(["alice", "bob", "carol"]),
        steps: vec![
            create_group(
                "alice",
                format!("restart-delivery-{case_index}"),
                ["bob", "carol"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob", "carol"]),
            clear(["alice", "bob", "carol"]),
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: payload.clone(),
            },
            ScenarioStep::DelayQueued {
                index: 0,
                delayed: "restart-delayed".into(),
            },
            ScenarioStep::RestartClient {
                client: "alice".into(),
            },
            ScenarioStep::ReleaseDelayed {
                delayed: "restart-delayed".into(),
            },
            ScenarioStep::DuplicateQueued { index: 0 },
            ScenarioStep::ReorderQueued { order: vec![1, 0] },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            observe(["alice"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        client_state("alice", 1, 3, vec![payload]),
    ];
    (scenario, expected)
}

fn labels<const N: usize>(items: [&str; N]) -> Vec<String> {
    items.into_iter().map(String::from).collect()
}

fn large_clients(count: usize) -> Vec<String> {
    let mut clients = Vec::with_capacity(count);
    clients.push("alice".into());
    for index in 1..count {
        clients.push(format!("member{index:02}"));
    }
    clients
}

fn large_group_setup(
    name: String,
    clients: Vec<String>,
    invitees: Vec<String>,
) -> Vec<ScenarioStep> {
    vec![
        create_group_vec("alice", name, invitees.clone(), "create"),
        confirmed_step("alice", "create"),
        ScenarioStep::DeliverAll,
        tick_vec(invitees),
        clear_vec(clients),
    ]
}

fn create_group<const N: usize>(
    creator: &str,
    name: String,
    invitees: [&str; N],
    pending: &str,
) -> ScenarioStep {
    ScenarioStep::CreateGroup {
        creator: creator.into(),
        name,
        invitees: labels(invitees),
        required_features: vec![],
        initial_admins: None,
        pending: pending.into(),
    }
}

fn create_group_vec(
    creator: &str,
    name: String,
    invitees: Vec<String>,
    pending: &str,
) -> ScenarioStep {
    ScenarioStep::CreateGroup {
        creator: creator.into(),
        name,
        invitees,
        required_features: vec![],
        initial_admins: None,
        pending: pending.into(),
    }
}

fn invite<const N: usize>(inviter: &str, invitees: [&str; N], pending: &str) -> ScenarioStep {
    ScenarioStep::InviteMembers {
        inviter: inviter.into(),
        invitees: labels(invitees),
        pending: pending.into(),
    }
}

fn confirmed_step(client: &str, pending: &str) -> ScenarioStep {
    ScenarioStep::ConfirmPending {
        client: client.into(),
        pending: pending.into(),
    }
}

fn tick<const N: usize>(clients: [&str; N]) -> ScenarioStep {
    ScenarioStep::Tick {
        clients: labels(clients),
    }
}

fn tick_vec(clients: Vec<String>) -> ScenarioStep {
    ScenarioStep::Tick { clients }
}

fn clear<const N: usize>(clients: [&str; N]) -> ScenarioStep {
    ScenarioStep::ClearEvents {
        clients: labels(clients),
    }
}

fn clear_vec(clients: Vec<String>) -> ScenarioStep {
    ScenarioStep::ClearEvents { clients }
}

fn observe<const N: usize>(clients: [&str; N]) -> ScenarioStep {
    ScenarioStep::Observe {
        clients: labels(clients),
    }
}

fn observe_vec(clients: Vec<String>) -> ScenarioStep {
    ScenarioStep::Observe { clients }
}

fn confirmed(step_index: usize, client: &str, pending: &str) -> TraceExpectation {
    TraceExpectation::PendingResolution {
        step_index,
        client: client.into(),
        pending: pending.into(),
        resolution: "confirmed".into(),
    }
}

fn rolled_back(step_index: usize, client: &str, pending: &str) -> TraceExpectation {
    TraceExpectation::PendingResolution {
        step_index,
        client: client.into(),
        pending: pending.into(),
        resolution: "rolled_back".into(),
    }
}

fn clients_converged<const N: usize>(
    clients: [&str; N],
    epoch: Option<u64>,
    member_count: Option<usize>,
) -> TraceExpectation {
    TraceExpectation::ClientsConverged {
        clients: labels(clients),
        epoch,
        member_count,
    }
}

fn clients_converged_vec(
    clients: Vec<String>,
    epoch: Option<u64>,
    member_count: Option<usize>,
) -> TraceExpectation {
    TraceExpectation::ClientsConverged {
        clients,
        epoch,
        member_count,
    }
}

fn client_state(
    client: &str,
    epoch: u64,
    member_count: usize,
    received_payloads: Vec<String>,
) -> TraceExpectation {
    TraceExpectation::ClientState {
        client: client.into(),
        epoch,
        member_count,
        received_payloads: Some(received_payloads),
        added_members: None,
        removed_members: None,
    }
}

fn recovery_summary(
    count: usize,
    source_epoch: Option<u64>,
    recovered_epoch: Option<u64>,
) -> TraceExpectation {
    TraceExpectation::RecoverySummary {
        count,
        source_epoch,
        recovered_epoch,
        winner_differs_from_invalidated: true,
    }
}

fn convergence_e2e_delivery_case(rng: &mut StdRng, case_index: u64) -> ScenarioSpec {
    let clients = vec![
        "alice".to_string(),
        "bob".to_string(),
        "carol".to_string(),
        "frank".to_string(),
        "david".to_string(),
        "eve".to_string(),
        "grace".to_string(),
    ];
    let mut steps = convergence_e2e_prefix_steps(case_index);
    let mut queue_len = 8usize;
    let split_delivery = match rng.gen_range(0..=6) {
        0 => false,
        1 => {
            steps.push(ScenarioStep::ReorderQueued {
                order: reversed_order(queue_len),
            });
            false
        }
        2 => {
            steps.push(ScenarioStep::DuplicateQueued {
                index: relevant_queue_index(rng, queue_len),
            });
            false
        }
        3 => {
            steps.push(ScenarioStep::DelayQueued {
                index: relevant_queue_index(rng, queue_len),
                delayed: "delayed-input".into(),
            });
            steps.push(ScenarioStep::ReleaseDelayed {
                delayed: "delayed-input".into(),
            });
            false
        }
        4 => {
            steps.push(ScenarioStep::DelayQueued {
                index: relevant_queue_index(rng, queue_len),
                delayed: "delayed-input".into(),
            });
            true
        }
        5 => {
            steps.push(ScenarioStep::ReorderQueued {
                order: rotated_order(queue_len, rng.gen_range(1..queue_len)),
            });
            false
        }
        _ => {
            steps.push(ScenarioStep::DuplicateQueued {
                index: relevant_queue_index(rng, queue_len),
            });
            queue_len += 1;
            steps.push(ScenarioStep::ReorderQueued {
                order: reversed_order(queue_len),
            });
            false
        }
    };

    if split_delivery {
        steps.push(ScenarioStep::DeliverAll);
        steps.push(ScenarioStep::ReleaseDelayed {
            delayed: "delayed-input".into(),
        });
        steps.push(ScenarioStep::DeliverAll);
    } else {
        steps.push(ScenarioStep::DeliverAll);
    }
    steps.push(ScenarioStep::Tick {
        clients: vec!["carol".into(), "frank".into()],
    });
    steps.push(ScenarioStep::Observe {
        clients: vec!["carol".into(), "frank".into()],
    });

    ScenarioSpec {
        name: format!("convergence-e2e-delivery/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients,
        steps,
    }
}

fn convergence_e2e_prefix_steps(case_index: u64) -> Vec<ScenarioStep> {
    vec![
        ScenarioStep::CreateGroup {
            creator: "alice".into(),
            name: format!("convergence-e2e-delivery-{case_index}"),
            invitees: vec!["bob".into(), "carol".into(), "frank".into()],
            required_features: vec![],
            initial_admins: None,
            pending: "create".into(),
        },
        ScenarioStep::ConfirmPending {
            client: "alice".into(),
            pending: "create".into(),
        },
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: vec!["bob".into(), "carol".into(), "frank".into()],
        },
        ScenarioStep::ClearEvents {
            clients: vec!["alice".into(), "bob".into(), "carol".into(), "frank".into()],
        },
        ScenarioStep::InviteMembers {
            inviter: "alice".into(),
            invitees: vec!["david".into()],
            pending: "alice-invite-david".into(),
        },
        ScenarioStep::ConfirmPending {
            client: "alice".into(),
            pending: "alice-invite-david".into(),
        },
        ScenarioStep::InviteMembers {
            inviter: "alice".into(),
            invitees: vec!["grace".into()],
            pending: "alice-invite-grace".into(),
        },
        ScenarioStep::ConfirmPending {
            client: "alice".into(),
            pending: "alice-invite-grace".into(),
        },
        ScenarioStep::InviteMembers {
            inviter: "bob".into(),
            invitees: vec!["eve".into()],
            pending: "bob-invite-eve".into(),
        },
        ScenarioStep::ConfirmPending {
            client: "bob".into(),
            pending: "bob-invite-eve".into(),
        },
        ScenarioStep::SendAppMessage {
            sender: "alice".into(),
            payload: "alice canonical payload".into(),
        },
        ScenarioStep::SendAppMessage {
            sender: "bob".into(),
            payload: "bob losing payload".into(),
        },
    ]
}

fn relevant_queue_index(rng: &mut StdRng, queue_len: usize) -> usize {
    const RELEVANT_BASE_INDICES: [usize; 5] = [1, 3, 5, 6, 7];
    let usable: Vec<usize> = RELEVANT_BASE_INDICES
        .into_iter()
        .filter(|index| *index < queue_len)
        .collect();
    usable[rng.gen_range(0..usable.len())]
}

fn reversed_order(len: usize) -> Vec<usize> {
    (0..len).rev().collect()
}

fn rotated_order(len: usize, left_by: usize) -> Vec<usize> {
    (0..len).map(|index| (index + left_by) % len).collect()
}

/// Seed-driven permutation of `0..len`. Distinct seeds produce distinct
/// delivery schedules, so the chaos family's queue-fault shapes vary real
/// behavior with the seed instead of re-running one fixed order. The result is
/// always a valid permutation, so `ScenarioStep::ReorderQueued` accepts it.
fn shuffled_order(rng: &mut StdRng, len: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..len).collect();
    // Fisher-Yates: deterministic for a fixed rng state.
    for i in (1..len).rev() {
        let j = rng.gen_range(0..=i);
        order.swap(i, j);
    }
    order
}

fn send_leave_case(rng: &mut StdRng, case_index: u64) -> ScenarioSpec {
    let clients = vec!["alice".to_string(), "bob".to_string(), "carol".to_string()];
    let mut steps = vec![
        ScenarioStep::CreateGroup {
            creator: "alice".into(),
            name: format!("send-leave-{case_index}"),
            invitees: vec!["bob".into(), "carol".into()],
            required_features: vec![],
            initial_admins: None,
            pending: "create".into(),
        },
        ScenarioStep::ConfirmPending {
            client: "alice".into(),
            pending: "create".into(),
        },
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: vec!["bob".into(), "carol".into()],
        },
    ];

    let send_count = 2 + rng.gen_range(0..=2);
    for send_index in 0..send_count {
        let sender = clients[rng.gen_range(0..clients.len())].clone();
        let marker: u16 = rng.r#gen();
        steps.push(ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: format!("case-{case_index}:send-{send_index}:{sender}:{marker}"),
        });
    }

    if send_count > 1 && rng.gen_bool(0.5) {
        steps.push(ScenarioStep::ReorderQueued {
            order: (0..send_count).rev().collect(),
        });
    }
    steps.push(ScenarioStep::DeliverAll);
    steps.push(ScenarioStep::Tick {
        clients: clients.clone(),
    });

    let leaver = if rng.gen_bool(0.5) {
        Some(if rng.gen_bool(0.5) { "bob" } else { "carol" })
    } else {
        None
    };

    let observe_clients = if let Some(leaver) = leaver {
        steps.push(ScenarioStep::Leave {
            client: leaver.into(),
        });
        steps.push(ScenarioStep::DeliverAll);
        steps.push(ScenarioStep::Tick {
            clients: vec!["alice".into()],
        });
        steps.push(ScenarioStep::DeliverAll);
        steps.push(ScenarioStep::Tick {
            clients: clients.clone(),
        });
        clients
            .iter()
            .filter(|client| client.as_str() != leaver)
            .cloned()
            .collect()
    } else {
        clients.clone()
    };

    steps.push(ScenarioStep::Observe {
        clients: observe_clients,
    });

    ScenarioSpec {
        name: format!("send-leave/v1/case-{case_index}"),
        spec_version: "1".into(),
        clients,
        steps,
    }
}
