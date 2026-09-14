//! Compact reconstruction of the checkpoint's exact offline catch-up inputs.
//! Keep generator drift visible: hashes cover metadata, every action and every
//! expected outcome, not merely the seed or payload count.

use cgka_conformance_simulator::{
    GeneratedScenarioInputV1, ScenarioAssertionV2, ScenarioPredicateV2, ScenarioStep,
    TraceExpectation, generate_offline_catchup_pressure_case,
};

/// Serialize and verify the complete input against the normalized checkpoint
/// fixtures from commit 9282a643. Equality to both original parsed fixtures was
/// verified before removing them; the hashes include their expected outcomes.
pub fn bytes(message_count: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let expected = match message_count {
        368 => "bdcb4c56ed0582c8bf03c8cdf8a07bf9c6f6b0f50d517bf8f466b7b461a9b894",
        1024 => "46d5adef4fd084606fef9040ca8624af7296cb13af261114f015bf59f5592d07",
        _ => panic!("unsupported regression workload"),
    };
    let bytes = serde_json::to_vec(&input(message_count)).expect("serialize regression input");
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        expected,
        "regression input drifted; compare with checkpoint 9282a643 before changing its hash"
    );
    bytes
}

fn input(message_count: usize) -> GeneratedScenarioInputV1 {
    assert!(matches!(message_count, 368 | 1024));
    let mut case = generate_offline_catchup_pressure_case(17001, 19);
    // Current founding creation acknowledges all Welcomes; the original
    // generator's named pending-create publication targets Legacy semantics.
    if let ScenarioStep::AcknowledgeOutbound { publication, .. } = &mut case.scenario.steps[1] {
        *publication = None;
    } else {
        panic!("founding acknowledgement moved");
    }
    case.expected_outcomes.retain(|expectation| {
        !matches!(expectation, TraceExpectation::PendingResolution { pending, .. } if pending == "create")
    });
    if message_count == 368 {
        case.family_name = "offline-catchup-reverse-history/v1".into();
        case.generator_version = "fixed-regression/v1".into();
        case.workload_profile = None;
        case.scenario.name = "offline-catchup-reverse-history-368".into();
        let mut indices = vec![None; case.scenario.steps.len()];
        let mut steps = Vec::new();
        let mut payloads = Vec::new();
        let mut skip_ack = false;
        for (old_index, step) in case.scenario.steps.into_iter().enumerate() {
            if skip_ack {
                assert!(matches!(step, ScenarioStep::AcknowledgeOutbound { .. }));
                skip_ack = false;
                continue;
            }
            if let ScenarioStep::SendAppMessage { payload, .. } = &step {
                if payloads.len() == message_count {
                    skip_ack = true;
                    continue;
                }
                payloads.push(payload.clone());
            }
            indices[old_index] = Some(steps.len());
            steps.push(step);
        }
        for (index, step) in steps.iter_mut().enumerate() {
            match step {
                ScenarioStep::Assert {
                    assertion:
                        ScenarioAssertionV2::Eventually {
                            predicate: ScenarioPredicateV2::PayloadCount { payload, .. },
                            ..
                        },
                } => *payload = payloads.last().unwrap().clone(),
                ScenarioStep::ProbeBidirectionalDecryptability { clients } => {
                    payloads.extend(
                        clients
                            .iter()
                            .filter(|sender| *sender != "bob")
                            .map(|sender| format!("cgka-decryptability-probe/v1/{index}/{sender}")),
                    );
                }
                _ => {}
            }
        }
        for expectation in &mut case.expected_outcomes {
            match expectation {
                TraceExpectation::PendingResolution { step_index, .. } => {
                    *step_index = indices[*step_index].expect("confirmation step retained");
                }
                TraceExpectation::ApplicationPayloadMultiset {
                    payloads: expected, ..
                } => {
                    *expected = payloads.clone();
                }
                _ => {}
            }
        }
        case.scenario.steps = steps;
    }
    GeneratedScenarioInputV1::new(case)
}
