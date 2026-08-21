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
    let expected_sizes = [10, 16, 20, 32, 50, 64, 100, 128, 200];

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
        assert!(
            block[3]
                .workload_profile
                .as_ref()
                .expect("competing-commit profile")
                .active_committer_count
                >= 2,
            "the competing-commit arm must not degenerate to one committer"
        );
        assert!(
            block[3]
                .scenario
                .steps
                .iter()
                .any(|step| matches!(step, ScenarioStep::DuplicateMessage { .. }))
        );
        assert!(
            block[3]
                .scenario
                .steps
                .iter()
                .any(|step| matches!(step, ScenarioStep::ReorderMessages { .. }))
        );
        assert!(
            block[4]
                .workload_profile
                .as_ref()
                .expect("mixed-interleaved profile")
                .active_committer_count
                >= 2,
            "the mixed-interleaved arm must not degenerate to one committer"
        );
        assert!(
            block[4]
                .scenario
                .steps
                .iter()
                .any(|step| matches!(step, ScenarioStep::ReorderMessages { .. }))
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
        let probe_clients = case
            .expected_outcomes
            .iter()
            .find_map(|expectation| match expectation {
                TraceExpectation::ClientsBidirectionallyDecryptable { clients } => Some(clients),
                _ => None,
            })
            .expect("every case has a decryptability probe");
        assert!((2..=6).contains(&probe_clients.len()));
        assert!(
            probe_clients.contains(case.scenario.clients.last().expect("non-empty roster")),
            "{} must retain the roster tail in the probe cohort",
            case.scenario.name
        );
        assert!(case.expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::ApplicationPayloadMultiset { .. }
        )));

        let expected_retained = case
            .scenario
            .steps
            .iter()
            .filter_map(|step| match step {
                ScenarioStep::InviteMembers { invitees, .. } => Some(invitees.as_slice()),
                _ => None,
            })
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected_pending_free = all_clients
            .difference(&expected_retained)
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut actual_pending_free = BTreeSet::new();
        let mut actual_retained = BTreeSet::new();
        for expectation in &case.expected_outcomes {
            match expectation {
                TraceExpectation::NoPendingWork { clients } => {
                    actual_pending_free.extend(clients.iter().cloned());
                }
                TraceExpectation::NoPendingWorkExceptRetainedJoinCommit { client } => {
                    actual_retained.insert(client.clone());
                }
                _ => {}
            }
        }
        assert_eq!(
            actual_retained, expected_retained,
            "{} must pin every late join or re-add to the retained-join exception",
            case.scenario.name
        );
        assert_eq!(
            actual_pending_free, expected_pending_free,
            "{} must require strict no-pending-work for every other client",
            case.scenario.name
        );
        if !actual_retained.is_empty() {
            assert!(
                actual_retained
                    .iter()
                    .any(|client| probe_clients.contains(client)),
                "{} must retain a late-join representative in the probe cohort",
                case.scenario.name
            );
        }
        if case
            .workload_profile
            .as_ref()
            .is_some_and(|profile| profile.disruption == "restart-remove-and-readd")
        {
            assert!(
                actual_retained
                    .iter()
                    .all(|client| probe_clients.contains(client)),
                "{} must probe every re-added churn member",
                case.scenario.name
            );
        }
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
    let case = generate_large_group_pressure_case(2026, 0);
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

#[tokio::test(flavor = "multi_thread")]
async fn mid_size_incremental_join_canary_passes_strict_oracles() {
    let case = generate_large_group_pressure_case(2026, 1);
    assert_eq!(case.scenario.clients.len(), 10);
    assert!(case.expected_outcomes.iter().any(|expectation| matches!(
        expectation,
        TraceExpectation::NoPendingWorkExceptRetainedJoinCommit { .. }
    )));
    let report =
        run_scenario_report_with_outcomes(&case.scenario, None, case.expected_outcomes.clone())
            .await
            .expect("mid-size incremental-join canary executes");
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
    for case_index in 0..6 {
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
