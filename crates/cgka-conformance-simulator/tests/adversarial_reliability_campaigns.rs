#[cfg(feature = "test-policy-overrides")]
use cgka_conformance_simulator::{
    ClientBuilder, EngineHarnessSubject, HarnessStorageMode, TransportBus,
    engine_harness_feature_registry, run_scenario_report_with_subject,
};
use cgka_conformance_simulator::{
    SubjectFailureCategory, compile_scenario, generate_adversarial_reliability_case,
    generate_adversarial_reliability_family, generate_adversarial_reliability_offline_regression,
    generate_adversarial_reliability_self_update_regression,
    generate_adversarial_reliability_sustained_regression, run_generated_case_report,
    run_generated_case_report_with_capture,
};
#[cfg(feature = "test-policy-overrides")]
use cgka_traits::group::ProtocolProfile;

#[test]
fn adversarial_reliability_catalog_covers_every_required_workload_shape() {
    let cases = generate_adversarial_reliability_family(7, 12);
    let names = cases
        .iter()
        .map(|case| case.family_name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(names.len(), 12);
    for case in &cases {
        compile_scenario(&case.scenario)
            .unwrap_or_else(|error| panic!("{}: {error}", case.family_name));
    }
}

#[test]
fn generator_versions_track_the_renamed_output_contract() {
    assert!(
        generate_adversarial_reliability_family(7, 12)
            .iter()
            .all(|case| case.generator_version == "2")
    );
    for case in [
        generate_adversarial_reliability_offline_regression(7),
        generate_adversarial_reliability_sustained_regression(7),
        generate_adversarial_reliability_self_update_regression(7),
    ] {
        assert_eq!(case.generator_version, "2-regression");
    }
}

async fn assert_generated_case(case_index: usize) -> cgka_conformance_simulator::ScenarioReport {
    assert_case(&generate_adversarial_reliability_case(7, case_index as u64)).await
}

async fn assert_case(
    case: &cgka_conformance_simulator::GeneratedScenarioCase,
) -> cgka_conformance_simulator::ScenarioReport {
    let report = run_generated_case_report(case, None)
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", case.family_name));
    let pending_inputs = report
        .observed_trace
        .as_ref()
        .into_iter()
        .flat_map(|trace| &trace.observations)
        .flat_map(|observation| &observation.scenario_input_ledger)
        .filter(|entry| entry.pending)
        .collect::<Vec<_>>();
    assert!(
        report.expectation_failures.is_empty(),
        "{} expectation failures: {:#?}; pending inputs: {pending_inputs:#?}",
        case.family_name,
        report.expectation_failures
    );
    assert!(
        report.invariant_failures.is_empty(),
        "{} invariant failures: {:#?}",
        case.family_name,
        report.invariant_failures
    );
    report
}

#[tokio::test]
async fn offline_retained_history_flood_runs_as_a_small_regression() {
    let report = assert_case(&generate_adversarial_reliability_offline_regression(7)).await;
    let measurements = &report.campaign_measurements;
    assert_eq!(measurements.schema_version, "1");
    assert!(measurements.total_wall_us > 0);
    assert_eq!(measurements.steps.len(), report.step_log.len());
    assert!(measurements.pass_count > 0);
    assert!(measurements.max_observed_queue_depth > 0);
    assert!(!measurements.input_dispositions.is_empty());
    assert!(
        measurements
            .replay_probe_count
            .is_some_and(|count| count > 0)
    );
    assert!(measurements.reorg_rewind_depth.is_some());
    assert!(measurements.reorg_lateness_ms.is_some());
    assert!(
        measurements
            .unavailable_process_fields
            .iter()
            .any(|field| field == "cpu_time_us")
    );
}

#[tokio::test]
async fn retained_relay_rejects_unavailable_sensitive_checkpoint_capture() {
    let case = generate_adversarial_reliability_offline_regression(7);
    let error = run_generated_case_report_with_capture(
        &case,
        None,
        cgka_conformance_simulator::HarnessStorageMode::InMemorySqlite,
        true,
    )
    .await
    .expect_err("retained relay cannot produce an engine checkpoint");
    assert_eq!(error.kind, "sensitive_replay_capture_unsupported");
}

#[ignore = "multi-round retained-history flood; run explicitly"]
#[tokio::test]
async fn offline_retained_history_flood_campaign() {
    let _ = assert_generated_case(0).await;
}

#[tokio::test]
async fn sustained_mixed_traffic_runs_as_a_small_regression() {
    let case = generate_adversarial_reliability_sustained_regression(7);
    let report = run_generated_case_report(&case, None)
        .await
        .expect("sustained regression runs");
    assert!(
        report.expectation_failures.is_empty(),
        "{:#?}",
        report.expectation_failures
    );
    assert!(
        report.invariant_failures.is_empty(),
        "{:#?}",
        report.invariant_failures
    );
}

#[ignore = "multi-round sustained campaign; run explicitly"]
#[tokio::test]
async fn sustained_mixed_traffic_campaign() {
    let _ = assert_generated_case(1).await;
}

#[tokio::test]
async fn self_update_admin_race_runs_as_a_small_regression() {
    let _ = assert_case(&generate_adversarial_reliability_self_update_regression(7)).await;
}

#[ignore = "sustained self-update adversary; run explicitly"]
#[tokio::test]
async fn self_update_admin_race_campaign() {
    let _ = assert_generated_case(2).await;
}

#[tokio::test]
async fn losing_branch_invite_has_a_named_unrecoverable_outcome() {
    let _ = assert_generated_case(3).await;
}

#[tokio::test]
async fn remaining_catalog_workloads_execute_under_the_strict_oracle() {
    for case_index in [4, 5, 6, 7, 8, 11] {
        let _ = assert_generated_case(case_index).await;
    }
}

#[tokio::test]
async fn branch_local_app_witnesses_converge_independent_of_transport_order() {
    let _ = assert_generated_case(9).await;
}

#[tokio::test]
async fn mixed_binary_versions_run_but_mixed_policies_are_rejected() {
    let case = generate_adversarial_reliability_case(7, 10);
    let _ = assert_case(&case).await;

    let mut incompatible = case.scenario.clone();
    incompatible.topology.processes[1].policy_version = "marmot-convergence-v2".into();
    let error = compile_scenario(&incompatible).expect_err("mixed policies fail preflight");
    assert_eq!(error.kind, "incompatible_convergence_policy");
    assert_eq!(error.category, SubjectFailureCategory::Environment);
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn full_engine_witness_ab_pair_can_select_different_canonical_branches() {
    let cases = generate_adversarial_reliability_family(7, 10);
    let case = &cases[9];
    let mut standard = EngineHarnessSubject::new_with_topology(
        &case.scenario.clients,
        &case.scenario.topology,
        ProtocolProfile::Legacy,
        HarnessStorageMode::InMemorySqlite,
    )
    .expect("standard subject");
    let standard_report = run_scenario_report_with_subject(
        &case.scenario,
        None,
        case.expected_outcomes.clone(),
        &mut standard,
    )
    .await
    .expect("standard witness run");

    let mut disabled = EngineHarnessSubject::new_without_app_witnesses_for_tests(
        &case.scenario.clients,
        &case.scenario.topology,
        ProtocolProfile::Legacy,
        HarnessStorageMode::InMemorySqlite,
    )
    .expect("witness-disabled subject");
    let disabled_report = run_scenario_report_with_subject(
        &case.scenario,
        None,
        case.expected_outcomes.clone(),
        &mut disabled,
    )
    .await
    .expect("witness-disabled run");

    for report in [&standard_report, &disabled_report] {
        let pending_inputs = report
            .observed_trace
            .as_ref()
            .into_iter()
            .flat_map(|trace| &trace.observations)
            .flat_map(|observation| &observation.scenario_input_ledger)
            .filter(|entry| entry.pending)
            .collect::<Vec<_>>();
        assert!(
            report.expectation_failures.is_empty(),
            "failures={:#?}; pending={pending_inputs:#?}",
            report.expectation_failures
        );
        assert!(
            report.invariant_failures.is_empty(),
            "{:#?}",
            report.invariant_failures
        );
    }
    let selected_state = |report: &cgka_conformance_simulator::ScenarioReport| {
        report
            .observed_trace
            .as_ref()
            .and_then(|trace| {
                trace
                    .observations
                    .iter()
                    .find(|item| item.client == "carol")
            })
            .and_then(|item| item.canonical_state.as_ref())
            .cloned()
            .expect("carol exact state")
    };
    assert_ne!(
        selected_state(&standard_report),
        selected_state(&disabled_report),
        "the paired fixture must make witness admission causally observable"
    );
    assert_eq!(
        standard_report.metadata.subject.as_ref().unwrap().adapter,
        "mdk-engine-harness"
    );
    assert_eq!(
        disabled_report.metadata.subject.as_ref().unwrap().adapter,
        "mdk-engine-harness-witness-disabled"
    );
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn replay_budget_exhaustion_fails_closed_then_repairs_with_same_durable_inputs() {
    let bus = TransportBus::ordered();
    let registry = engine_harness_feature_registry();
    let mut alice = ClientBuilder::new(b"resource-alice".to_vec())
        .registry(registry.clone())
        .attach(&bus);
    let mut bob = ClientBuilder::new(b"resource-bob".to_vec())
        .registry(registry.clone())
        .attach(&bus);
    let mut observer = ClientBuilder::new(b"resource-observer".to_vec())
        .registry(registry)
        // Two probes cover the competing-commit BFS, but not the application-
        // witness fallback materialization. The pass must share one ceiling.
        .replay_probe_budget_for_tests(Some(2))
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let observer_kp = observer.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins(
            "replay-budget-exhaustion",
            vec![bob_kp, observer_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    assert!(bob.tick().await.iter().all(Result::is_ok));
    assert!(observer.tick().await.iter().all(Result::is_ok));

    alice.send_app(b"retained-witness".to_vec()).await;
    bus.deliver_all();
    assert!(bob.tick().await.iter().all(Result::is_ok));
    assert!(observer.tick().await.iter().all(Result::is_ok));

    let alice_pending = alice.self_update().await;
    let bob_pending = bob.self_update().await;
    alice.confirm(alice_pending).await;
    bob.confirm(bob_pending).await;
    bus.deliver_all();
    let outcomes = observer.tick().await;
    assert!(
        outcomes.iter().any(|outcome| {
            outcome
                .as_ref()
                .err()
                .is_some_and(|error| error.to_string().contains("replay budget exceeded"))
        }),
        "the shared BFS-plus-fallback budget must surface a typed fail-closed error: {outcomes:?}"
    );
    assert!(
        observer.has_pending_convergence_inputs(),
        "a resource error must retain the frozen input set for retry"
    );

    observer.set_replay_probe_budget_for_tests(None);
    let repaired = observer
        .try_converge_stored_at(&group_id, 2_000_000)
        .expect("same durable inputs repair under the production budget");
    assert!(repaired.errors.is_empty(), "{:#?}", repaired.errors);
    assert_eq!(observer.epoch().0, 2);
}
