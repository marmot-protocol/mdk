use std::collections::{BTreeMap, BTreeSet};

use cgka_conformance_simulator::{
    MEMBERSHIP_REENTRY_FAMILY, MEMBERSHIP_REENTRY_GENERATOR_VERSION, ScenarioStep,
    TraceExpectation, compile_scenario, generate_family_case, generate_membership_reentry_case,
    generate_membership_reentry_family, run_generated_case_report,
};

const COMPLETE_CATALOG_CASES: usize = 10;
const MULTI_COMMITTER_INCIDENT_CASE: u64 = 8;
const PARTIAL_MULTI_COMMITTER_INCIDENT_CASE: u64 = 9;

#[test]
fn catalog_is_deterministic_prefix_stable_registered_and_varies_by_seed() {
    let seed = 0x5eed;
    let short = generate_membership_reentry_family(seed, COMPLETE_CATALOG_CASES);
    let long = generate_membership_reentry_family(seed, COMPLETE_CATALOG_CASES * 2);

    assert_eq!(
        short,
        generate_membership_reentry_family(seed, COMPLETE_CATALOG_CASES)
    );
    assert_eq!(short, long[..short.len()]);
    assert_ne!(
        short,
        generate_membership_reentry_family(seed + 1, COMPLETE_CATALOG_CASES)
    );
    for (case_index, case) in short.iter().enumerate() {
        assert_eq!(case.family_name, MEMBERSHIP_REENTRY_FAMILY);
        assert_eq!(case.generator_version, MEMBERSHIP_REENTRY_GENERATOR_VERSION);
        assert_eq!(
            case,
            &generate_family_case(MEMBERSHIP_REENTRY_FAMILY, seed, case_index as u64)
                .expect("membership-reentry family is registered")
        );
        compile_scenario(&case.scenario)
            .unwrap_or_else(|error| panic!("{}: {error}", case.scenario.name));
    }
}

#[test]
fn complete_catalog_guarantees_reentry_and_high_risk_interactions() {
    let cases = generate_membership_reentry_family(2026, COMPLETE_CATALOG_CASES);
    let expected_cycles = [1, 2, 3, 2, 1, 1, 1, 1, 1, 1];

    for (case, expected_cycle_count) in cases.iter().zip(expected_cycles) {
        let readds = case
            .scenario
            .steps
            .iter()
            .filter(|step| matches!(step, ScenarioStep::InviteMembers { pending, .. } if pending.starts_with("readd-")))
            .count();
        assert_eq!(
            readds, expected_cycle_count,
            "{} must retain its declared re-entry count",
            case.scenario.name
        );
        assert!(case.expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::ClientsExactlyEquivalent { .. }
        )));
        assert!(case.expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::ClientsBidirectionallyDecryptable { .. }
        )));
        if case.case_index == 7 {
            assert!(case.expected_outcomes.iter().any(|expectation| matches!(
                expectation,
                TraceExpectation::NoPendingWork { clients } if clients == &case.scenario.clients
            )));
        } else {
            assert!(case.expected_outcomes.iter().any(|expectation| matches!(
                expectation,
                TraceExpectation::NoPendingWorkExceptRetainedJoinCommit { .. }
            )));
        }
    }

    assert!(
        cases[2]
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::RestartClient { .. }))
    );
    assert!(cases[3..=4].iter().all(|case| {
        case.scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::SelfUpdate { .. }))
    }));
    assert!(cases[5..=6].iter().all(|case| {
        case.scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::Leave { .. }))
    }));
    assert!(cases[7].scenario.steps.iter().any(|step| matches!(
        step,
        ScenarioStep::WithholdMessage { label, .. } if label == "stale-original-welcome"
    )));
    let case_7_steps = &cases[7].scenario.steps;
    let step_index = |predicate: &dyn Fn(&ScenarioStep) -> bool| {
        case_7_steps
            .iter()
            .position(predicate)
            .expect("case 7 must contain the expected retry step")
    };
    let fresh_invite = step_index(
        &|step| matches!(step, ScenarioStep::InviteMembers { pending, .. } if pending == "readd-0"),
    );
    let refused_fresh_welcome = step_index(&|step| {
        matches!(
            step,
            ScenarioStep::ExpectTickError { error, .. } if error == "invalid_transition"
        )
    });
    let trusted_removal = step_index(&|step| {
        matches!(
            step,
            ScenarioStep::ReleaseWithheld { label }
                if label == "trusted-removal-after-stale-welcome"
        )
    });
    let welcome_retry = step_index(&|step| {
        matches!(
            step,
            ScenarioStep::ReleaseWithheld { label }
                if label == "fresh-reentry-welcome-retry"
        )
    });
    assert!(fresh_invite < refused_fresh_welcome);
    assert!(refused_fresh_welcome < trusted_removal);
    assert!(trusted_removal < welcome_retry);
    assert!(
        cases[7]
            .expected_outcomes
            .iter()
            .any(|expectation| matches!(
                expectation,
                TraceExpectation::ExpectedError {
                    operation,
                    error,
                    ..
                } if operation == "tick" && error == "invalid_transition"
            ))
    );
    assert_eq!(cases[8].scenario.clients.len(), 8);
    assert!(cases[8].scenario.steps.iter().any(|step| matches!(
        step,
        ScenarioStep::Tick { clients } if clients.len() == 7
    )));
    assert_eq!(
        cases[8]
            .scenario
            .steps
            .iter()
            .filter(|step| matches!(
                step,
                ScenarioStep::AcknowledgeOutbound {
                    publication: None,
                    ..
                }
            ))
            .count(),
        8,
        "seven competing SelfRemove committers plus the re-added member's probe message"
    );
    assert_eq!(cases[9].scenario.clients.len(), 8);
    let partial_committer_count = cases[9]
        .scenario
        .steps
        .iter()
        .find_map(|step| match step {
            ScenarioStep::Tick { clients } if (2..=4).contains(&clients.len()) => {
                Some(clients.len())
            }
            _ => None,
        })
        .expect("partial-impact arm ticks only a handful of early committers");
    assert_eq!(
        cases[9]
            .scenario
            .steps
            .iter()
            .filter(|step| matches!(
                step,
                ScenarioStep::AcknowledgeOutbound {
                    publication: None,
                    ..
                }
            ))
            .count(),
        partial_committer_count + 1,
        "only the early competing committers and re-added member's probe are auto-acknowledged"
    );

    let mut removals_by_case = BTreeMap::new();
    for case in &cases {
        let removed = case
            .scenario
            .steps
            .iter()
            .filter_map(|step| match step {
                ScenarioStep::RemoveMembers { members, .. } => Some(members.clone()),
                _ => None,
            })
            .flatten()
            .collect::<BTreeSet<_>>();
        let readded = case
            .scenario
            .steps
            .iter()
            .filter_map(|step| match step {
                ScenarioStep::InviteMembers {
                    invitees, pending, ..
                } if pending.starts_with("readd-") => Some(invitees.clone()),
                _ => None,
            })
            .flatten()
            .collect::<BTreeSet<_>>();
        if !removed.is_empty() {
            assert_eq!(
                removed, readded,
                "{} re-adds its victim",
                case.scenario.name
            );
        }
        removals_by_case.insert(case.case_index, removed);
    }
    assert_eq!(removals_by_case.len(), COMPLETE_CATALOG_CASES);
}

#[tokio::test(flavor = "multi_thread")]
async fn ordinary_catalog_passes_strict_runtime_oracles() {
    for case_index in 0..COMPLETE_CATALOG_CASES as u64 {
        let case = generate_membership_reentry_case(2026, case_index);
        let report = run_generated_case_report(&case, None)
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", case.scenario.name));
        assert!(
            report.expectation_failures.is_empty(),
            "{} expectation failures: {:#?}",
            case.scenario.name,
            report.expectation_failures
        );
        assert!(
            report.invariant_failures.is_empty(),
            "{} invariant failures: {:#?}",
            case.scenario.name,
            report.invariant_failures
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_committer_self_leave_reentry_passes_strict_runtime_oracles() {
    let case = generate_membership_reentry_case(2026, MULTI_COMMITTER_INCIDENT_CASE);
    let report = run_generated_case_report(&case, None)
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", case.scenario.name));
    assert!(
        report.expectation_failures.is_empty(),
        "{} expectation failures: {:#?}",
        case.scenario.name,
        report.expectation_failures
    );
    assert!(
        report.invariant_failures.is_empty(),
        "{} invariant failures: {:#?}",
        case.scenario.name,
        report.invariant_failures
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn partial_multi_committer_self_leave_reentry_passes_strict_runtime_oracles() {
    let case = generate_membership_reentry_case(2026, PARTIAL_MULTI_COMMITTER_INCIDENT_CASE);
    let report = run_generated_case_report(&case, None)
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", case.scenario.name));
    assert!(
        report.expectation_failures.is_empty(),
        "{} expectation failures: {:#?}",
        case.scenario.name,
        report.expectation_failures
    );
    assert!(
        report.invariant_failures.is_empty(),
        "{} invariant failures: {:#?}",
        case.scenario.name,
        report.invariant_failures
    );
}
