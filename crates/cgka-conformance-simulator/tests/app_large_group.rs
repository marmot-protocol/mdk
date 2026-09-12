//! Full public app scale coverage; expensive executions remain explicit.
use cgka_conformance_simulator::{
    AppRuntimeHarness, ConvergenceSubject, GeneratedScenarioInputV1, PUBLIC_APP_LARGE_GROUP_FAMILY,
    ScenarioPredicateV2, ScenarioStep, TraceExpectation, compare_trace_expectations,
    compile_scenario, generate_family_case, preflight_compiled_scenario,
    run_scenario_report_with_subject,
};

#[tokio::test]
async fn large_app_catalog_is_replayable_and_checks_every_participant() {
    let mut subject = AppRuntimeHarness::new(&[]).await.unwrap();
    let descriptor = subject.descriptor();
    subject.shutdown().await;
    for seed in [7, 42, 100003] {
        for index in 0..6 {
            let case = generate_family_case(PUBLIC_APP_LARGE_GROUP_FAMILY, seed, index).unwrap();
            assert_eq!(
                case,
                generate_family_case(PUBLIC_APP_LARGE_GROUP_FAMILY, seed, index).unwrap()
            );
            let bytes = serde_json::to_vec(&case).unwrap();
            assert_eq!(case, serde_json::from_slice(&bytes).unwrap());
            let size = [10, 20, 50][index as usize / 2];
            assert_eq!(case.scenario.clients.len(), size);
            assert_eq!(case.generator_version, "2");
            assert_eq!(case.workload_profile.as_ref().unwrap().member_count, size);
            preflight_compiled_scenario(&compile_scenario(&case.scenario).unwrap(), &descriptor)
                .unwrap();
            let histories = case
                .expected_outcomes
                .iter()
                .filter_map(|e| match e {
                    TraceExpectation::ApplicationPayloadMultiset { client, payloads } => {
                        Some((client, payloads))
                    }
                    _ => None,
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(histories.len(), size);
            assert!(
                case.scenario
                    .clients
                    .iter()
                    .all(|client| histories.contains_key(client))
            );
            assert!(
                histories
                    .values()
                    .all(|payloads| payloads.len() >= size + 3)
            );
            assert_eq!(
                case.scenario
                    .steps
                    .iter()
                    .filter(|s| matches!(s, ScenarioStep::SetClientOffline { .. }))
                    .count(),
                size / 5
            );
            let ScenarioStep::CreateGroup { invitees, .. } = &case.scenario.steps[0] else {
                panic!("formation")
            };
            assert_eq!(invitees.len(), if index % 2 == 0 { size - 1 } else { 3 });
            assert!(
                case.scenario.steps.len() < 10 * size + 200,
                "assertions must not expand once per payload per member"
            );
        }
    }
    let short = (0..2)
        .map(|i| generate_family_case(PUBLIC_APP_LARGE_GROUP_FAMILY, 42, i).unwrap())
        .collect::<Vec<_>>();
    let long = (0..6)
        .map(|i| generate_family_case(PUBLIC_APP_LARGE_GROUP_FAMILY, 42, i).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(short, long[..2]);
    assert_ne!(
        long[0],
        generate_family_case(PUBLIC_APP_LARGE_GROUP_FAMILY, 7, 0).unwrap()
    );
}

#[test]
fn whole_history_assertion_requires_v3_and_known_client() {
    let mut case = generate_family_case(PUBLIC_APP_LARGE_GROUP_FAMILY, 42, 0).unwrap();
    case.scenario.steps = vec![ScenarioStep::Assert {
        assertion: cgka_conformance_simulator::ScenarioAssertionV2::Eventually {
            predicate: ScenarioPredicateV2::PublicPayloadMultiset {
                client: "alice".into(),
                payloads: vec![],
            },
            max_iterations: 2,
        },
    }];
    compile_scenario(&case.scenario).unwrap();
    case.scenario.spec_version = "2".into();
    assert!(compile_scenario(&case.scenario).is_err());
    case.scenario.spec_version = "3".into();
    let ScenarioStep::Assert {
        assertion:
            cgka_conformance_simulator::ScenarioAssertionV2::Eventually {
                predicate: ScenarioPredicateV2::PublicPayloadMultiset { client, .. },
                ..
            },
    } = &mut case.scenario.steps[0]
    else {
        unreachable!()
    };
    *client = "unknown".into();
    assert!(compile_scenario(&case.scenario).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "full app scale canary; release, MDK_LARGE_APP_CASE=0..5, unique MDK_APP_JOURNEY_ARTIFACTS"]
async fn large_group_app_canary() {
    let index = std::env::var("MDK_LARGE_APP_CASE")
        .unwrap_or_else(|_| "0".into())
        .parse::<u64>()
        .unwrap();
    assert!(index < 6);
    assert!(
        !AppRuntimeHarness::honors_maintenance_timing_override(),
        "use production policy"
    );
    let case = generate_family_case(PUBLIC_APP_LARGE_GROUP_FAMILY, 42, index).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let artifacts = std::env::var_os("MDK_APP_JOURNEY_ARTIFACTS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().into());
    fs_private::create_dir_all_private(&artifacts).unwrap();
    assert!(
        !artifacts.join("generated-input.json").exists(),
        "preserve prior evidence"
    );
    fs_private::write_private(
        &artifacts.join("generated-input.json"),
        &serde_json::to_vec_pretty(&GeneratedScenarioInputV1::new(case.clone())).unwrap(),
    )
    .unwrap();
    let mut subject = AppRuntimeHarness::new(&case.scenario.clients)
        .await
        .unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1800),
        run_scenario_report_with_subject(
            &case.scenario,
            None,
            case.expected_outcomes.clone(),
            &mut subject,
        ),
    )
    .await;
    if let Ok(Ok(report)) = &result {
        fs_private::write_private(
            &artifacts.join("report.json"),
            &serde_json::to_vec_pretty(report).unwrap(),
        )
        .unwrap();
    }
    // This public snapshot does not wait for the account worker that may have
    // caused the failure. Preserve its closed failure classifications before cleanup.
    fs_private::write_private(
        &artifacts.join("performance-before-cleanup.json"),
        &serde_json::to_vec_pretty(&subject.performance_snapshots()).unwrap(),
    )
    .unwrap();
    // Check the actual one-snapshot predicate as well as the final trace oracle.
    let expected = case
        .expected_outcomes
        .iter()
        .find_map(|e| match e {
            TraceExpectation::ApplicationPayloadMultiset { client, payloads }
                if client == "alice" =>
            {
                Some(payloads.clone())
            }
            _ => None,
        })
        .unwrap();
    let clean = matches!(&result, Ok(Ok(report)) if report.expectation_failures.is_empty() && report.invariant_failures.is_empty());
    eprintln!("large app workload finished; semantic checks passed: {clean}");
    let mut predicate_checks = Vec::new();
    if clean {
        for mutation in 0..3 {
            let mut payloads = expected.clone();
            if mutation == 1 {
                payloads.pop();
            }
            if mutation == 2 {
                payloads.push(payloads[0].clone());
            }
            predicate_checks.push(subject.evaluate_predicate(
                &ScenarioPredicateV2::PublicPayloadMultiset {
                    client: "alice".into(),
                    payloads,
                },
            ));
        }
    }
    eprintln!("large app cleanup started");
    let cleanup =
        tokio::time::timeout(std::time::Duration::from_secs(60), subject.shutdown()).await;
    drop(subject);
    eprintln!(
        "large app cleanup finished; within budget: {}",
        cleanup.is_ok()
    );
    let report = result.expect("large app deadline").unwrap();
    assert!(
        report.expectation_failures.is_empty(),
        "{:?}",
        report.expectation_failures
    );
    assert!(
        report.invariant_failures.is_empty(),
        "{:?}",
        report.invariant_failures
    );
    assert!(
        report.oracle.weak_oracle_warnings.is_empty(),
        "{:?}",
        report.oracle
    );
    assert!(
        report.oracle.missing_observed_behaviors.is_empty(),
        "{:?}",
        report.oracle
    );
    assert!(cleanup.is_ok(), "large app cleanup exceeded 60 seconds");
    assert!(predicate_checks[0].as_ref().unwrap().matched);
    assert!(!predicate_checks[1].as_ref().unwrap().matched);
    assert!(!predicate_checks[2].as_ref().unwrap().matched);
    let trace = report.observed_trace.unwrap();
    for client in &case.scenario.clients {
        for mutation in 0..4 {
            let mut changed = trace.clone();
            let observation = changed
                .observations
                .iter_mut()
                .find(|o| &o.client == client)
                .unwrap();
            match mutation {
                0 => {
                    observation.received_payloads.pop().unwrap();
                }
                1 => observation
                    .received_payloads
                    .push(observation.received_payloads[0].clone()),
                2 => observation.member_count += 1,
                _ => observation.group_name.push_str("wrong"),
            }
            assert!(
                !compare_trace_expectations(None, &case.expected_outcomes, &changed).is_empty()
            );
        }
    }
    eprintln!(
        "{} participants, {}: strict public state/history and oracle mutation checks passed",
        case.scenario.clients.len(),
        case.workload_profile.unwrap().formation
    );
}

#[test]
fn exclusion_delivery_is_observed_before_reinvitation() {
    for index in 0..6 {
        let case = generate_family_case(PUBLIC_APP_LARGE_GROUP_FAMILY, 42, index).unwrap();
        let steps = &case.scenario.steps;
        let removal = steps
            .iter()
            .position(|s| matches!(s, ScenarioStep::RemoveMembers { .. }))
            .unwrap();
        let reinvite = removal
            + 1
            + steps[removal + 1..]
                .iter()
                .position(|s| matches!(s, ScenarioStep::InviteMembers { .. }))
                .unwrap();
        let ScenarioStep::RemoveMembers { members, .. } = &steps[removal] else {
            unreachable!()
        };
        let gap = steps[removal + 1..reinvite]
            .iter()
            .filter_map(|s| match s {
                ScenarioStep::SendAppMessage { payload, .. } => Some(payload),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(gap.len() >= 3);
        let mut checked_recipients = 0;
        let mut checked_exclusion = false;
        for step in &steps[removal + 1..reinvite] {
            if let ScenarioStep::Assert {
                assertion:
                    cgka_conformance_simulator::ScenarioAssertionV2::Eventually {
                        predicate: ScenarioPredicateV2::PublicPayloadMultiset { client, payloads },
                        ..
                    },
            } = step
            {
                if client == &members[0] {
                    assert!(gap.iter().all(|p| !payloads.contains(p)));
                    checked_exclusion = true;
                } else if gap.iter().all(|p| payloads.contains(p)) {
                    checked_recipients += 1;
                }
            }
        }
        assert!(checked_exclusion);
        let size = case.scenario.clients.len();
        assert_eq!(checked_recipients, size - size / 5 - 1);
    }
}
