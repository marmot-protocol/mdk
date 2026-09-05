use cgka_conformance_simulator::{
    HarnessStorageMode, RetainedRelaySubject, ScenarioRelayOrderV2, ScenarioStep,
    ScenarioStepStatus, resolve_scenario_input_bytes, run_scenario_report_with_subject,
};
use cgka_traits::group::ProtocolProfile;

// Reduced from offline-catchup-pressure/v1, generator 1, seed 17001, case 19:
// retain all 16 commit rounds and the first 368 messages. Current founding
// creation acknowledges Welcomes without the Legacy pending-create filter.
// The fixture preserves full payload multiplicity, exact state, decryptability,
// and no-pending-work assertions. It contains synthetic scenario data only.
async fn check_history(order: ScenarioRelayOrderV2) {
    let mut input = resolve_scenario_input_bytes(include_bytes!(
        "../vectors/generated-inputs/offline-catchup-reverse-history-368.generated-input.json"
    ))
    .expect("saved regression input");
    for step in &mut input.scenario.steps {
        if let ScenarioStep::ConfigureRelay {
            order: selected, ..
        } = step
        {
            *selected = order;
        }
    }
    let mut subject = RetainedRelaySubject::new(
        &input.scenario.clients,
        &input.scenario.topology,
        ProtocolProfile::Current,
        HarnessStorageMode::TempFileBackedSqlite,
    )
    .expect("Current-profile file-backed subject");
    let report = run_scenario_report_with_subject(
        &input.scenario,
        None,
        input.expected_outcomes,
        &mut subject,
    )
    .await
    .expect("scenario executes");
    assert!(
        report
            .step_log
            .iter()
            .all(|step| matches!(step.status, ScenarioStepStatus::Completed))
    );
    assert!(report.oracle.weak_oracle_warnings.is_empty());
    assert!(report.oracle.missing_observed_behaviors.is_empty());
    assert!(
        report.invariant_failures.is_empty(),
        "{:?}",
        report.invariant_failures
    );
    assert!(
        report.expectation_failures.is_empty(),
        "{:?}",
        report.expectation_failures
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_reverse_history_delivers_every_retained_message() {
    check_history(ScenarioRelayOrderV2::Reverse).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_natural_history_control_delivers_every_retained_message() {
    check_history(ScenarioRelayOrderV2::Natural).await;
}
