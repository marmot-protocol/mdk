//! Deterministic generated scenario families.
//!
//! Families produce ordinary [`ScenarioSpec`] values plus the metadata needed
//! to replay or promote a generated case into a fixed vector.

use crate::{
    GeneratedScenarioMetadata, ScenarioReport, ScenarioRunError, ScenarioSpec, ScenarioStep,
    ScenarioTrace, run_scenario_report,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedScenarioCase {
    pub family_name: String,
    pub generator_version: String,
    pub seed: u64,
    pub case_index: u64,
    pub scenario: ScenarioSpec,
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
        });
    }
    out
}

pub async fn run_generated_case_report(
    case: &GeneratedScenarioCase,
    expected_trace: Option<ScenarioTrace>,
) -> Result<ScenarioReport, ScenarioRunError> {
    let mut report = run_scenario_report(&case.scenario, expected_trace).await?;
    report.metadata.generated = Some(GeneratedScenarioMetadata {
        family_name: case.family_name.clone(),
        generator_version: case.generator_version.clone(),
        seed: case.seed,
        case_index: case.case_index,
        minimized_case: None,
    });
    Ok(report)
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

fn send_leave_case(rng: &mut StdRng, case_index: u64) -> ScenarioSpec {
    let clients = vec!["alice".to_string(), "bob".to_string(), "carol".to_string()];
    let mut steps = vec![
        ScenarioStep::CreateGroup {
            creator: "alice".into(),
            name: format!("send-leave-{case_index}"),
            invitees: vec!["bob".into(), "carol".into()],
            required_features: vec![],
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
