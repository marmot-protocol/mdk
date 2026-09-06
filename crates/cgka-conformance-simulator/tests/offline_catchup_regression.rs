use cgka_conformance_simulator::{
    HarnessStorageMode, RetainedRelaySubject, ScenarioRelayOrderV2, ScenarioStep,
    ScenarioStepStatus, resolve_scenario_input_bytes, run_scenario_report_with_subject,
};
use cgka_traits::group::ProtocolProfile;

#[path = "support/offline_catchup.rs"]
mod offline_catchup;

#[test]
fn compact_inputs_match_checkpoint_hashes() {
    for count in [368, 1024] {
        resolve_scenario_input_bytes(&offline_catchup::bytes(count))
            .expect("pinned regression input");
    }
}

// Reduced from offline-catchup-pressure/v1, generator 1, seed 17001, case 19:
// retain all 16 commit rounds and the first 368 messages. Current founding
// creation acknowledges Welcomes without the Legacy pending-create filter.
// The fixture preserves full payload multiplicity, exact state, decryptability,
// and no-pending-work assertions. It contains synthetic scenario data only.
async fn check_history(order: ScenarioRelayOrderV2, overflow: bool) {
    let bytes = offline_catchup::bytes(if overflow { 1024 } else { 368 });
    let mut input = resolve_scenario_input_bytes(&bytes).expect("pinned regression input");
    for step in &mut input.scenario.steps {
        if let ScenarioStep::ConfigureRelay {
            order: selected, ..
        } = step
        {
            *selected = order;
        }
    }
    let artifacts = std::env::var_os("MDK_OFFLINE_REGRESSION_ARTIFACTS").map(|root| {
        let root = std::path::PathBuf::from(root);
        fs_private::create_dir_all_private(&root).unwrap();
        let path = tempfile::Builder::new()
            .prefix("offline-history-")
            .tempdir_in(root)
            .unwrap()
            .keep();
        let mut expanded: cgka_conformance_simulator::GeneratedScenarioInputV1 =
            serde_json::from_slice(&bytes).unwrap();
        expanded.case.scenario = input.scenario.clone();
        fs_private::write_private(
            &path.join("input.json"),
            &serde_json::to_vec_pretty(&expanded).unwrap(),
        )
        .unwrap();
        path
    });
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
    if let Some(path) = artifacts {
        fs_private::write_private(
            &path.join("report.json"),
            &serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        eprintln!("engine history evidence: {}", path.display());
    }
    assert!(
        report
            .step_log
            .iter()
            .all(|step| matches!(step.status, ScenarioStepStatus::Completed)),
        "incomplete steps: {:?}",
        report
            .step_log
            .iter()
            .filter(|step| !matches!(step.status, ScenarioStepStatus::Completed))
            .collect::<Vec<_>>()
    );
    assert!(report.oracle.weak_oracle_warnings.is_empty());
    assert!(
        report.oracle.missing_observed_behaviors.is_empty(),
        "{:?}",
        report.oracle.missing_observed_behaviors
    );
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
    check_history(ScenarioRelayOrderV2::Reverse, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_natural_history_control_delivers_every_retained_message() {
    check_history(ScenarioRelayOrderV2::Natural, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_reverse_overflow_history_delivers_every_retained_message() {
    check_history(ScenarioRelayOrderV2::Reverse, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_natural_overflow_history_control_delivers_every_retained_message() {
    check_history(ScenarioRelayOrderV2::Natural, true).await;
}
