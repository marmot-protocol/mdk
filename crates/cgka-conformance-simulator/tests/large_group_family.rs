use std::collections::BTreeSet;

use cgka_conformance_simulator::{
    GeneratedScenarioInputV1, LARGE_GROUP_PRESSURE_FAMILY, LARGE_GROUP_PRESSURE_GENERATOR_VERSION,
    LARGE_GROUP_PRESSURE_PROFILE_VERSION, ScenarioStep, TraceExpectation, compile_scenario,
    generate_family_case, generate_large_group_pressure_case, generate_large_group_pressure_family,
    resolve_scenario_input_bytes, run_scenario_report_with_outcomes,
};

const COMPLETE_PROFILE_CASES: usize = 54;

#[test]
fn large_group_profiles_are_deterministic_prefix_stable_and_registered() {
    let seed = 0x5ca1e;
    let short = generate_large_group_pressure_family(seed, 6);
    let long = generate_large_group_pressure_family(seed, 12);

    assert_eq!(short, generate_large_group_pressure_family(seed, 6));
    assert_eq!(short, long[..short.len()]);
    assert_ne!(short, generate_large_group_pressure_family(seed + 1, 6));
    for (case_index, case) in short.iter().enumerate() {
        assert_eq!(
            case,
            &generate_family_case(LARGE_GROUP_PRESSURE_FAMILY, seed, case_index as u64)
                .expect("large-group family is registered")
        );
    }
}

#[test]
fn complete_catalog_covers_sizes_admin_regimes_traffic_and_disruptions() {
    let cases = generate_large_group_pressure_family(2026, COMPLETE_PROFILE_CASES);
    let expected_sizes = [16, 32, 64, 128, 10, 20, 50, 100, 200];

    for (size_slot, expected_size) in expected_sizes.into_iter().enumerate() {
        let block = &cases[(size_slot * 6)..((size_slot + 1) * 6)];
        assert!(
            block
                .iter()
                .all(|case| case.scenario.clients.len() == expected_size)
        );
        assert_eq!(
            block
                .iter()
                .map(|case| case
                    .workload_profile
                    .as_ref()
                    .expect("profile metadata")
                    .admin_regime
                    .as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            5,
            "each size block must cover all five admin regimes"
        );
    }

    let arms = &cases[..6];
    assert_eq!(
        arms[0]
            .scenario
            .steps
            .iter()
            .filter(|step| matches!(step, ScenarioStep::SendAppMessage { .. }))
            .count(),
        arms[0].scenario.clients.len(),
        "application-heavy arm authors one full member round"
    );
    assert!(arms[1].scenario.steps.iter().any(|step| matches!(
        step,
        ScenarioStep::InviteMembers { invitees, .. } if !invitees.is_empty()
    )));
    assert!(
        arms[2]
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::ExpectUpdateAdminPolicyError { .. }))
    );
    assert!(
        arms[3]
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::DuplicateMessage { .. }))
    );
    assert!(
        arms[4]
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::ReorderMessages { .. }))
    );
    assert!(
        arms[5]
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::RestartClient { .. }))
    );
    assert!(
        arms[5]
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::RemoveMembers { .. }))
    );

    for case in &cases {
        let profile = case
            .workload_profile
            .as_ref()
            .expect("versioned workload profile");
        assert_eq!(case.family_name, LARGE_GROUP_PRESSURE_FAMILY);
        assert_eq!(
            case.generator_version,
            LARGE_GROUP_PRESSURE_GENERATOR_VERSION
        );
        assert_eq!(profile.version, LARGE_GROUP_PRESSURE_PROFILE_VERSION);
        assert_eq!(profile.member_count, case.scenario.clients.len());
        assert_eq!(
            profile.application_message_count,
            case.scenario
                .steps
                .iter()
                .filter(|step| matches!(step, ScenarioStep::SendAppMessage { .. }))
                .count()
        );
        compile_scenario(&case.scenario)
            .unwrap_or_else(|error| panic!("{}: {error}", case.scenario.name));
    }
}

#[test]
fn every_case_carries_whole_group_and_sampled_delivery_oracles() {
    for case in generate_large_group_pressure_family(7, COMPLETE_PROFILE_CASES) {
        let all_clients = case
            .scenario
            .clients
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(case.expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::ClientsExactlyEquivalent { clients }
                if clients.iter().cloned().collect::<BTreeSet<_>>() == all_clients
        )));
        assert!(case.expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::ClientsBidirectionallyDecryptable { clients }
                if (2..=6).contains(&clients.len())
        )));
        assert!(case.expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::ApplicationPayloadMultiset { .. }
        )));

        let mut pending_scope = BTreeSet::new();
        for expectation in &case.expected_outcomes {
            match expectation {
                TraceExpectation::NoPendingWork { clients } => {
                    pending_scope.extend(clients.iter().cloned());
                }
                TraceExpectation::NoPendingWorkExceptRetainedJoinCommit { client } => {
                    pending_scope.insert(client.clone());
                }
                _ => {}
            }
        }
        assert_eq!(
            pending_scope, all_clients,
            "every client's terminal work is pinned"
        );
    }
}

#[test]
fn workload_profile_survives_generated_input_replay_provenance() {
    let case = generate_large_group_pressure_case(42, 18);
    let bytes = serde_json::to_vec(&GeneratedScenarioInputV1::new(case.clone())).unwrap();
    let resolved = resolve_scenario_input_bytes(&bytes).expect("generated input resolves");
    assert_eq!(resolved.generated_case.as_ref(), Some(&case));
    assert_eq!(
        resolved
            .provenance
            .generated
            .expect("generated provenance")
            .workload_profile,
        case.workload_profile
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mid_size_application_heavy_canary_passes_strict_oracles() {
    let case = generate_large_group_pressure_case(2026, 24);
    assert_eq!(case.scenario.clients.len(), 10);
    let report =
        run_scenario_report_with_outcomes(&case.scenario, None, case.expected_outcomes.clone())
            .await
            .expect("mid-size large-group canary executes");
    assert!(
        report.expectation_failures.is_empty(),
        "expectation failures: {:#?}",
        report.expectation_failures
    );
    assert!(
        report.invariant_failures.is_empty(),
        "invariant failures: {:#?}",
        report.invariant_failures
    );
}

#[ignore = "six real-engine arms; run explicitly or in a scheduled lane"]
#[tokio::test(flavor = "multi_thread")]
async fn mid_size_complete_arm_catalog_passes_strict_oracles() {
    for case_index in 24..30 {
        let case = generate_large_group_pressure_case(2026, case_index);
        let report =
            run_scenario_report_with_outcomes(&case.scenario, None, case.expected_outcomes.clone())
                .await
                .unwrap_or_else(|error| panic!("{}: {error}", case.scenario.name));
        assert!(
            report.expectation_failures.is_empty(),
            "{} failed steps: {:#?}; expectation failures: {:#?}",
            case.scenario.name,
            report
                .step_log
                .iter()
                .filter(|entry| !entry.status.is_completed())
                .collect::<Vec<_>>(),
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
