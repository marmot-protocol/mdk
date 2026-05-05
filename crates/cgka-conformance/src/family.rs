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
