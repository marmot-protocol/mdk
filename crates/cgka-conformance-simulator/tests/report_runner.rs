use std::fs;
use std::path::PathBuf;

use cgka_conformance_simulator::{
    OracleBehavior, ReportArgs, ReportCommand, ReportInput, ScenarioStimulus, parse_report_command,
    property_test_coverage_entries, run_report,
};

#[test]
fn parse_defaults_to_send_leave_family() {
    let command = parse_report_command(Vec::new()).expect("default args parse");
    assert_eq!(
        command,
        ReportCommand::Run(ReportArgs {
            input: ReportInput::GeneratedFamily {
                family: "send-leave/v1".into(),
                seed: 0,
                cases: 1,
            },
            out: PathBuf::from("target/cgka-conformance-simulator-reports"),
        })
    );
}

#[test]
fn parse_custom_report_args() {
    let command = parse_report_command([
        "--family".into(),
        "send-leave/v1".into(),
        "--seed".into(),
        "42".into(),
        "--cases".into(),
        "3".into(),
        "--out".into(),
        "target/custom".into(),
    ])
    .expect("custom args parse");

    assert_eq!(
        command,
        ReportCommand::Run(ReportArgs {
            input: ReportInput::GeneratedFamily {
                family: "send-leave/v1".into(),
                seed: 42,
                cases: 3,
            },
            out: PathBuf::from("target/custom"),
        })
    );
}

#[test]
fn parse_vector_fixture_report_args() {
    let command = parse_report_command([
        "--vectors".into(),
        "crates/cgka-conformance-simulator/vectors".into(),
        "--out".into(),
        "target/vector-reports".into(),
    ])
    .expect("vector args parse");

    assert_eq!(
        command,
        ReportCommand::Run(ReportArgs {
            input: ReportInput::VectorFixtures {
                paths: vec![PathBuf::from("crates/cgka-conformance-simulator/vectors")],
            },
            out: PathBuf::from("target/vector-reports"),
        })
    );
}

#[test]
fn parse_help_returns_help_command() {
    let command = parse_report_command(["--help".into()]).expect("help parses");
    assert_eq!(command, ReportCommand::Help);
}

#[test]
fn parse_rejects_unknown_argument() {
    let err = parse_report_command(["--wat".into()]).expect_err("unknown arg errors");
    assert!(err.to_string().contains("unknown argument --wat"));
}

#[test]
fn parse_rejects_missing_value() {
    let err = parse_report_command(["--seed".into()]).expect_err("missing value errors");
    assert!(err.to_string().contains("missing value for --seed"));
}

#[test]
fn property_test_coverage_matrix_names_each_property_family() {
    let matrix = property_test_coverage_entries();
    let names = matrix
        .iter()
        .map(|entry| entry.scenario_name.as_str())
        .collect::<Vec<_>>();

    for expected in [
        "prop_candidate_graph_selection_is_order_invariant",
        "prop_canonicalization_dispositions_are_order_invariant",
        "prop_canonicalization_replay_is_already_seen",
        "prop_quiescence_gate_controls_settlement",
        "prop_capability_negotiation_matches_matrix",
        "prop_convergence_under_send_leave_sequence",
        "prop_convergence_under_varied_delivery",
        "prop_stored_convergence_restart_equivalence",
        "prop_group_data_update_publish_lifecycle",
        "prop_true_same_id_replay",
        "prop_upgrade_confirm_or_fail_round_trip",
    ] {
        assert!(
            names.contains(&expected),
            "coverage matrix should include {expected}"
        );
    }

    assert!(matrix.iter().any(|entry| {
        entry.stimuli.contains(&ScenarioStimulus::StorageRestart)
            && entry
                .oracle_behaviors
                .contains(&OracleBehavior::RestartEquivalence)
    }));
}

#[tokio::test]
async fn report_runner_writes_send_leave_json_reports() {
    let out_dir = std::env::temp_dir().join(format!(
        "darkmatter-cgka-conformance-simulator-report-test-{}",
        std::process::id()
    ));
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).expect("remove stale output dir");
    }

    let summary = run_report(&ReportArgs {
        input: ReportInput::GeneratedFamily {
            family: "send-leave/v1".into(),
            seed: 42,
            cases: 2,
        },
        out: out_dir.clone(),
    })
    .await
    .expect("runner writes reports");
    assert_eq!(summary.total(), 2);
    assert_eq!(summary.failed(), 0);

    let case0 = out_dir.join("send-leave-v1-seed-42-case-0.json");
    let case1 = out_dir.join("send-leave-v1-seed-42-case-1.json");
    assert!(case0.exists(), "case 0 report should exist");
    assert!(case1.exists(), "case 1 report should exist");

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&case0).expect("read report"))
            .expect("report JSON parses");
    assert_eq!(
        report["metadata"]["generated"]["family_name"],
        "send-leave/v1"
    );
    assert_eq!(report["metadata"]["generated"]["seed"], 42);
    assert_eq!(report["metadata"]["generated"]["case_index"], 0);
    assert!(
        report["observed_trace"]["observations"]
            .as_array()
            .is_some_and(|observations| !observations.is_empty())
    );

    fs::remove_dir_all(out_dir).expect("clean output dir");
}

#[tokio::test]
async fn report_runner_writes_convergence_delivery_json_reports() {
    let out_dir = std::env::temp_dir().join(format!(
        "darkmatter-cgka-convergence-delivery-report-test-{}",
        std::process::id()
    ));
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).expect("remove stale output dir");
    }

    let summary = run_report(&ReportArgs {
        input: ReportInput::GeneratedFamily {
            family: "convergence-e2e-delivery/v1".into(),
            seed: 7,
            cases: 2,
        },
        out: out_dir.clone(),
    })
    .await
    .expect("runner writes convergence delivery reports");
    assert_eq!(summary.total(), 2);
    assert_eq!(summary.failed(), 0);

    let case0 = out_dir.join("convergence-e2e-delivery-v1-seed-7-case-0.json");
    let case1 = out_dir.join("convergence-e2e-delivery-v1-seed-7-case-1.json");
    assert!(case0.exists(), "case 0 report should exist");
    assert!(case1.exists(), "case 1 report should exist");

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&case0).expect("read report"))
            .expect("report JSON parses");
    assert_eq!(
        report["metadata"]["generated"]["family_name"],
        "convergence-e2e-delivery/v1"
    );
    assert_eq!(
        report["app_invalidation_observations"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    let epoch_change_count = report["epoch_change_observations"]
        .as_array()
        .map(Vec::len)
        .expect("epoch changes array");
    assert!(matches!(epoch_change_count, 2 | 4));

    fs::remove_dir_all(out_dir).expect("clean output dir");
}

#[tokio::test]
async fn report_runner_writes_convergence_chaos_reports_and_fixture_candidates() {
    let out_dir = std::env::temp_dir().join(format!(
        "darkmatter-cgka-convergence-chaos-report-test-{}",
        std::process::id()
    ));
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).expect("remove stale output dir");
    }

    let summary = run_report(&ReportArgs {
        input: ReportInput::GeneratedFamily {
            family: "convergence-chaos/v1".into(),
            seed: 13,
            cases: 2,
        },
        out: out_dir.clone(),
    })
    .await
    .expect("runner writes convergence chaos reports");
    assert_eq!(summary.total(), 2);
    assert_eq!(summary.failed(), 0);
    assert!(
        summary
            .scenarios
            .iter()
            .all(|scenario| scenario.expectation_count > 0),
        "chaos report summaries should count semantic expectations"
    );

    let report_path = out_dir.join("convergence-chaos-v1-seed-13-case-0.json");
    let fixture_path = out_dir.join("convergence-chaos-v1-seed-13-case-0-fixture.v1.json");
    assert!(report_path.exists(), "case 0 report should exist");
    assert!(
        fixture_path.exists(),
        "case 0 fixture candidate should exist"
    );

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report_path).expect("read report"))
            .expect("report JSON parses");
    assert_eq!(
        report["metadata"]["generated"]["family_name"],
        "convergence-chaos/v1"
    );
    assert_eq!(report["metadata"]["generated"]["seed"], 13);
    assert!(report["scenario"]["steps"].is_array());
    assert!(
        report["expected_outcomes"]
            .as_array()
            .is_some_and(|expectations| !expectations.is_empty())
    );
    assert!(
        report["oracle"]["stimuli"]
            .as_array()
            .is_some_and(|stimuli| !stimuli.is_empty()),
        "report should include scenario stimuli"
    );
    assert!(
        report["oracle"]["observed_behaviors"]
            .as_array()
            .is_some_and(|behaviors| !behaviors.is_empty()),
        "report should include observed behavior evidence"
    );

    let fixture: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&fixture_path).expect("read fixture candidate"))
            .expect("fixture candidate JSON parses");
    assert_eq!(fixture["scenario_name"], "convergence-chaos/v1/case-0");
    assert_eq!(fixture["vector_version"], "1");
    assert_eq!(fixture["seed"], 13);
    assert!(fixture["scenario"]["steps"].is_array());
    assert!(
        fixture["expected_outcomes"]
            .as_array()
            .is_some_and(|expectations| !expectations.is_empty())
    );
    assert!(
        summary.coverage_matrix.iter().any(|entry| {
            entry.stimuli.contains(&ScenarioStimulus::InviteMembers)
                && entry
                    .oracle_behaviors
                    .contains(&OracleBehavior::ForkRecovered)
        }),
        "coverage matrix should show which generated cases check fork recovery"
    );

    fs::remove_dir_all(out_dir).expect("clean output dir");
}

#[tokio::test]
async fn report_runner_writes_vector_fixture_reports_and_summary() {
    let out_dir = std::env::temp_dir().join(format!(
        "darkmatter-cgka-vector-report-test-{}",
        std::process::id()
    ));
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).expect("remove stale output dir");
    }

    let vectors_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors");
    let summary = run_report(&ReportArgs {
        input: ReportInput::VectorFixtures {
            paths: vec![vectors_dir],
        },
        out: out_dir.clone(),
    })
    .await
    .expect("runner writes vector reports");

    assert_eq!(summary.failed(), 0);
    assert!(summary.total() >= 3);
    let text = summary.to_human_text();
    assert!(text.contains("PASS"));
    assert!(text.contains("group-data-fork-recovery/v1"));

    let report_path = out_dir.join("group-data-fork-recovery-v1-report.json");
    assert!(
        report_path.exists(),
        "group-data fixture report should exist"
    );
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report_path).expect("read report"))
            .expect("report JSON parses");
    assert_eq!(
        report["metadata"]["fixture"]["scenario_name"],
        "group-data-fork-recovery/v1"
    );
    assert!(
        report["expected_outcomes"]
            .as_array()
            .is_some_and(|outcomes| !outcomes.is_empty())
    );
    assert_eq!(
        report["expectation_failures"].as_array().map(Vec::len),
        Some(0)
    );

    fs::remove_dir_all(out_dir).expect("clean output dir");
}
