use std::fs;
use std::path::PathBuf;

use cgka_conformance_simulator::{
    FailureCapsuleSensitivity, GeneratedScenarioCase, GeneratedScenarioInputV1,
    GeneratedScenarioMinimizationBudget, GeneratedScenarioMinimizationStatus, GeneratedSubjectKind,
    HarnessStorageMode, OracleBehavior, ReportArgs, ReportCommand, ReportInput, ScenarioReport,
    ScenarioSpec, ScenarioStep, ScenarioStimulus, TraceExpectation, parse_report_command,
    promote_failure_capsule_to_vector, property_test_coverage_entries, read_failure_capsule,
    replay_engine_bytes, run_report,
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
            strict_oracle: true,
            storage_mode: HarnessStorageMode::InMemorySqlite,
            capture_sensitive_replay: false,
            minimization_budget: Default::default(),
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
            strict_oracle: true,
            storage_mode: HarnessStorageMode::InMemorySqlite,
            capture_sensitive_replay: false,
            minimization_budget: Default::default(),
        })
    );
}

#[test]
fn explicit_storage_flag_overrides_environment_default() {
    let command =
        parse_report_command(["--storage".into(), "file".into()]).expect("storage mode args parse");
    let ReportCommand::Run(args) = command else {
        panic!("expected run command");
    };
    assert_eq!(args.storage_mode, HarnessStorageMode::TempFileBackedSqlite);
}

#[test]
fn generated_report_minimization_budgets_are_configurable() {
    let ReportCommand::Run(args) = parse_report_command([
        "--minimization-wall-time-secs".into(),
        "17".into(),
        "--minimization-max-trials".into(),
        "23".into(),
        "--minimization-trial-timeout-secs".into(),
        "3".into(),
    ])
    .expect("minimization budgets parse") else {
        panic!("expected run command");
    };
    assert_eq!(
        args.minimization_budget,
        GeneratedScenarioMinimizationBudget {
            wall_clock: std::time::Duration::from_secs(17),
            max_trials: 23,
            per_trial_timeout: std::time::Duration::from_secs(3),
        }
    );
}

#[test]
fn generated_report_rejects_zero_minimization_budgets() {
    for flag in [
        "--minimization-wall-time-secs",
        "--minimization-max-trials",
        "--minimization-trial-timeout-secs",
    ] {
        let error = parse_report_command([flag.into(), "0".into()])
            .expect_err("zero minimization budgets must fail");
        assert!(error.to_string().contains("must be greater than zero"));
    }
}

#[test]
fn sensitive_replay_capture_requires_an_explicit_flag() {
    let ReportCommand::Run(args) =
        parse_report_command(["--capture-sensitive-replay".into()]).expect("capture flag parses")
    else {
        panic!("expected run command");
    };
    assert!(args.capture_sensitive_replay);
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
            strict_oracle: true,
            storage_mode: HarnessStorageMode::InMemorySqlite,
            capture_sensitive_replay: false,
            minimization_budget: Default::default(),
        })
    );
}

#[test]
fn parse_generated_input_report_args() {
    let command = parse_report_command([
        "--generated-input".into(),
        "target/case-1-generated-input.json".into(),
        "--generated-input".into(),
        "target/case-3-generated-input.json".into(),
        "--adapter".into(),
        "app-runtime".into(),
        "--out".into(),
        "target/generated-input-reports".into(),
    ])
    .expect("generated input args parse");

    assert_eq!(
        command,
        ReportCommand::Run(ReportArgs {
            input: ReportInput::GeneratedInputs {
                paths: vec![
                    PathBuf::from("target/case-1-generated-input.json"),
                    PathBuf::from("target/case-3-generated-input.json"),
                ],
                adapter: Some(GeneratedSubjectKind::AppRuntime),
            },
            out: PathBuf::from("target/generated-input-reports"),
            strict_oracle: true,
            storage_mode: HarnessStorageMode::InMemorySqlite,
            capture_sensitive_replay: false,
            minimization_budget: Default::default(),
        })
    );
}

#[test]
fn parse_generated_input_rejects_other_scenario_sources() {
    for conflicting in ["--vectors", "--family", "--seed", "--cases"] {
        let value = match conflicting {
            "--vectors" => "crates/cgka-conformance-simulator/vectors",
            "--family" => "chat-journey/v1",
            "--seed" | "--cases" => "2",
            _ => unreachable!(),
        };
        let error = parse_report_command([
            "--generated-input".into(),
            "target/case-generated-input.json".into(),
            conflicting.into(),
            value.into(),
        ])
        .expect_err("generated input must be the only scenario source");
        assert!(error.to_string().contains("--generated-input"));
    }
}

#[test]
fn parse_adapter_accepts_only_the_documented_hyphenated_names() {
    for adapter in ["retained_relay", "app_runtime"] {
        let error = parse_report_command([
            "--generated-input".into(),
            "target/case-generated-input.json".into(),
            "--adapter".into(),
            adapter.into(),
        ])
        .expect_err("undocumented adapter alias must fail");
        assert!(
            error
                .to_string()
                .contains("unsupported generated-case adapter")
        );
    }
}

#[tokio::test]
async fn adapter_override_uses_distinct_artifacts_without_minting_a_fixture() {
    let root = tempfile::tempdir().unwrap();
    let input_path = root.path().join("case.json");
    let out = root.path().join("reports");
    let input = GeneratedScenarioInputV1::new(GeneratedScenarioCase {
        family_name: "selectable-report/v1".into(),
        generator_version: "1".into(),
        seed: 5,
        case_index: 2,
        workload_profile: None,
        subject: GeneratedSubjectKind::Engine,
        scenario: ScenarioSpec {
            name: "selectable-report/v1/case-2".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into()],
            topology: Default::default(),
            steps: vec![ScenarioStep::DeliverAll],
        },
        expected_outcomes: Vec::new(),
    });
    fs_private::write_private(&input_path, &serde_json::to_vec_pretty(&input).unwrap()).unwrap();

    for adapter in [None, Some(GeneratedSubjectKind::AppRuntime)] {
        run_report(&ReportArgs {
            input: ReportInput::GeneratedInputs {
                paths: vec![input_path.clone()],
                adapter,
            },
            out: out.clone(),
            strict_oracle: false,
            storage_mode: HarnessStorageMode::InMemorySqlite,
            capture_sensitive_replay: false,
            minimization_budget: Default::default(),
        })
        .await
        .unwrap();
    }

    let base = "selectable-report-v1-seed-5-case-2";
    assert!(out.join(format!("{base}.json")).exists());
    assert!(out.join(format!("{base}-fixture.v1.json")).exists());
    assert!(out.join(format!("{base}-app-runtime.json")).exists());
    assert!(
        !out.join(format!("{base}-app-runtime-fixture.v1.json"))
            .exists()
    );
}

#[test]
fn parse_strict_oracle_report_args() {
    let command = parse_report_command([
        "--family".into(),
        "send-leave/v1".into(),
        "--strict-oracle".into(),
    ])
    .expect("strict oracle args parse");

    assert_eq!(
        command,
        ReportCommand::Run(ReportArgs {
            input: ReportInput::GeneratedFamily {
                family: "send-leave/v1".into(),
                seed: 0,
                cases: 1,
            },
            out: PathBuf::from("target/cgka-conformance-simulator-reports"),
            strict_oracle: true,
            storage_mode: HarnessStorageMode::InMemorySqlite,
            capture_sensitive_replay: false,
            minimization_budget: Default::default(),
        })
    );
}

#[test]
fn parse_allow_weak_oracle_report_args() {
    let command = parse_report_command([
        "--family".into(),
        "send-leave/v1".into(),
        "--allow-weak-oracle".into(),
    ])
    .expect("weak oracle opt-out args parse");

    let ReportCommand::Run(args) = command else {
        panic!("expected run command");
    };
    assert!(!args.strict_oracle);
}

#[test]
fn parse_help_returns_help_command() {
    let command = parse_report_command(["--help".into()]).expect("help parses");
    assert_eq!(command, ReportCommand::Help);
}

#[test]
fn parse_replay_capsule_command() {
    let command = parse_report_command([
        "--replay-capsule".into(),
        "target/failure-capsule.v1.json".into(),
    ])
    .expect("replay capsule args parse");
    assert_eq!(
        command,
        ReportCommand::ReplayCapsule(PathBuf::from("target/failure-capsule.v1.json"))
    );
}

#[test]
fn parse_replay_capsule_rejects_scenario_inputs() {
    let error = parse_report_command([
        "--replay-capsule".into(),
        "target/failure-capsule.v1.json".into(),
        "--family".into(),
        "send-leave/v1".into(),
    ])
    .expect_err("replay capsule must not combine with family inputs");
    assert!(error.to_string().contains("--replay-capsule"));
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
        "mdk-cgka-conformance-simulator-report-test-{}",
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
        strict_oracle: false,
        storage_mode: HarnessStorageMode::InMemorySqlite,
        capture_sensitive_replay: false,
        minimization_budget: Default::default(),
    })
    .await
    .expect("runner writes reports");
    assert_eq!(summary.total(), 2);
    assert_eq!(summary.failed(), 0);
    assert!(
        summary
            .scenarios
            .iter()
            .all(|scenario| scenario.failures.is_empty()),
        "consumed self-remove proposals must not leave failed send/leave reports: {:?}",
        summary.scenarios
    );

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
    assert_eq!(report["metadata"]["storage_backend"], "in-memory-sqlite");
    assert_eq!(
        report["metadata"]["subject"]["adapter"],
        "mdk-engine-harness"
    );
    assert!(
        report["metadata"]["subject"]["capabilities"]
            .as_array()
            .is_some_and(|capabilities| capabilities
                .iter()
                .any(|capability| capability == "application_messaging"))
    );
    assert!(
        report["observed_trace"]["observations"]
            .as_array()
            .is_some_and(|observations| !observations.is_empty())
    );

    fs::remove_dir_all(out_dir).expect("clean output dir");
}

#[tokio::test]
async fn minimization_budget_exhaustion_preserves_the_original_failure_artifacts() {
    let root = tempfile::tempdir().expect("temporary report root");
    let input_path = root.path().join("generated-input.json");
    let out = root.path().join("reports");
    let case = GeneratedScenarioCase {
        family_name: "minimization-budget/v1".into(),
        generator_version: "1".into(),
        seed: 17,
        case_index: 0,
        workload_profile: None,
        subject: GeneratedSubjectKind::Engine,
        scenario: ScenarioSpec {
            name: "minimization-budget/v1/case-0".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into()],
            steps: vec![
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "budgeted".into(),
                    invitees: Vec::new(),
                    required_features: Vec::new(),
                    initial_admins: None,
                    pending: "create".into(),
                },
                ScenarioStep::SetPartition {
                    allow: vec!["alice".into()],
                },
                ScenarioStep::ClearPartition,
                ScenarioStep::Observe {
                    clients: vec!["alice".into()],
                },
            ],
        },
        expected_outcomes: vec![TraceExpectation::ClientState {
            client: "alice".into(),
            epoch: 1,
            member_count: 99,
            received_payloads: None,
            added_members: None,
            removed_members: None,
        }],
    };
    fs_private::write_private(
        &input_path,
        &serde_json::to_vec_pretty(&GeneratedScenarioInputV1::new(case))
            .expect("generated input serializes"),
    )
    .expect("generated input writes");

    let summary = run_report(&ReportArgs {
        input: ReportInput::GeneratedInputs {
            paths: vec![input_path],
            adapter: None,
        },
        out: out.clone(),
        strict_oracle: true,
        storage_mode: HarnessStorageMode::InMemorySqlite,
        capture_sensitive_replay: false,
        minimization_budget: GeneratedScenarioMinimizationBudget {
            wall_clock: std::time::Duration::from_secs(1),
            max_trials: 1,
            per_trial_timeout: std::time::Duration::from_secs(1),
        },
    })
    .await
    .expect("budget exhaustion remains a reportable failure");

    assert_eq!(summary.failed(), 1);
    let stem = "minimization-budget-v1-seed-17-case-0";
    let report_path = out.join(format!("{stem}.json"));
    let fixture_path = out.join(format!("{stem}-fixture.v1.json"));
    let capsule_path = out.join(format!("{stem}-failure-capsule.v1.json"));
    assert!(
        fixture_path.is_file(),
        "the original fixture remains durable"
    );
    let report: ScenarioReport = serde_json::from_slice(
        &fs::read(&report_path).expect("the original report remains durable"),
    )
    .expect("the report remains parseable");
    let generated = report
        .metadata
        .generated
        .as_ref()
        .expect("generated metadata exists");
    assert_eq!(
        generated.minimization.status,
        GeneratedScenarioMinimizationStatus::BudgetExhausted
    );
    assert_eq!(generated.minimization.trials, 1);
    assert!(generated.minimized_case.is_none());
    assert!(
        report
            .expectation_failures
            .iter()
            .any(|failure| failure.kind == "client_state_mismatch"),
        "unexpected original failures: {:?}; steps: {:?}",
        report.expectation_failures,
        report.step_log
    );

    let capsule = read_failure_capsule(&capsule_path).expect("portable capsule remains readable");
    assert_eq!(
        capsule.sensitivity,
        FailureCapsuleSensitivity::SyntheticShareable
    );
    assert!(
        capsule
            .report
            .expectation_failures
            .iter()
            .any(|failure| failure.kind == "client_state_mismatch")
    );
    assert_eq!(
        capsule
            .report
            .metadata
            .generated
            .as_ref()
            .expect("capsule generated metadata")
            .minimization
            .status,
        GeneratedScenarioMinimizationStatus::BudgetExhausted
    );
}

#[tokio::test]
async fn report_runner_strict_oracle_counts_weak_warnings_as_failures() {
    let out_dir = std::env::temp_dir().join(format!(
        "mdk-cgka-strict-oracle-report-test-{}",
        std::process::id()
    ));
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).expect("remove stale output dir");
    }

    // Every built-in family now carries strict oracle coverage, so the
    // weak-oracle failure path is pinned through a generated input whose
    // expectations were deliberately stripped.
    let mut case = cgka_conformance_simulator::generate_convergence_e2e_delivery_family(42, 1)
        .pop()
        .expect("family generates one case");
    case.expected_outcomes.clear();
    fs::create_dir_all(&out_dir).expect("create output dir");
    let input_path = out_dir.join("stripped-weak-oracle-input.json");
    fs::write(
        &input_path,
        serde_json::to_string(&GeneratedScenarioInputV1::new(case)).expect("serialize input"),
    )
    .expect("write stripped generated input");

    let summary = run_report(&ReportArgs {
        input: ReportInput::GeneratedInputs {
            paths: vec![input_path],
            adapter: None,
        },
        out: out_dir.clone(),
        strict_oracle: true,
        storage_mode: HarnessStorageMode::InMemorySqlite,
        capture_sensitive_replay: false,
        minimization_budget: Default::default(),
    })
    .await
    .expect("strict runner writes reports");

    assert_eq!(summary.total(), 1);
    assert_eq!(summary.failed(), 1);
    assert!(
        summary.scenarios[0]
            .failures
            .iter()
            .any(|failure| failure.kind == "weak_oracle_warning")
    );
    let capsule_path = summary.scenarios[0]
        .failure_capsule
        .as_ref()
        .expect("strict failure emits a capsule");
    assert!(capsule_path.exists());
    let capsule: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(capsule_path).expect("read capsule"))
            .expect("capsule JSON parses");
    assert_eq!(capsule["schema_version"], "1");
    assert_eq!(capsule["failure"]["classification"], "oracle_violation");
    assert!(capsule.get("captured_transport_artifacts").is_none());
    assert!(capsule.get("byte_replay").is_none());
    assert!(summary.scenarios[0].replay_capsule.is_none());

    fs::remove_dir_all(out_dir).expect("clean output dir");
}

#[tokio::test]
async fn report_runner_writes_convergence_delivery_json_reports() {
    let out_dir = std::env::temp_dir().join(format!(
        "mdk-cgka-convergence-delivery-report-test-{}",
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
        strict_oracle: false,
        storage_mode: HarnessStorageMode::InMemorySqlite,
        capture_sensitive_replay: false,
        minimization_budget: Default::default(),
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
        report["expectation_failures"].as_array().map(Vec::len),
        Some(0)
    );
    // The settle tail makes late-branch flips (and therefore invalidation and
    // per-client epoch-change counts) delivery-schedule dependent; the exact
    // convergence claims live in the family's generated expectations.
    let epoch_change_count = report["epoch_change_observations"]
        .as_array()
        .map(Vec::len)
        .expect("epoch changes array");
    assert!(epoch_change_count >= 2);

    fs::remove_dir_all(out_dir).expect("clean output dir");
}

#[tokio::test]
async fn report_runner_writes_convergence_chaos_reports_and_fixture_candidates() {
    let out_dir = std::env::temp_dir().join(format!(
        "mdk-cgka-convergence-chaos-report-test-{}",
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
        strict_oracle: false,
        storage_mode: HarnessStorageMode::InMemorySqlite,
        capture_sensitive_replay: false,
        minimization_budget: Default::default(),
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
                    .contains(&OracleBehavior::ClientConvergence)
        }),
        "coverage matrix should show which generated cases check fork convergence"
    );

    fs::remove_dir_all(out_dir).expect("clean output dir");
}

#[tokio::test]
async fn report_runner_writes_vector_fixture_reports_and_summary() {
    let out_dir = std::env::temp_dir().join(format!(
        "mdk-cgka-vector-report-test-{}",
        std::process::id()
    ));
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).expect("remove stale output dir");
    }

    // The canonical-scenarios gate executes every committed vector. This test
    // only needs one semantic fixture to prove the report writer and summary
    // path, rather than executing the complete vector directory a second time.
    let vector =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors/group-data-fork-recovery.v1.json");
    let summary = run_report(&ReportArgs {
        input: ReportInput::VectorFixtures {
            paths: vec![vector],
        },
        out: out_dir.clone(),
        strict_oracle: false,
        storage_mode: HarnessStorageMode::InMemorySqlite,
        capture_sensitive_replay: false,
        minimization_budget: Default::default(),
    })
    .await
    .expect("runner writes vector reports");

    assert_eq!(summary.failed(), 0);
    assert_eq!(summary.total(), 1);
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

#[tokio::test]
async fn failed_campaign_capsule_contains_a_replayable_tick_witness() {
    let temp = tempfile::tempdir().expect("campaign temp directory");
    let fixture_path = temp.path().join("failing-message-exchange.v1.json");
    let out_dir = temp.path().join("reports");
    let mut fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../vectors/three-client-message-exchange.v1.json"
    ))
    .expect("fixture parses");
    fixture["scenario_name"] = "campaign-byte-replay/v1".into();
    fixture["scenario"]["name"] = "campaign-byte-replay/v1".into();
    fixture["expected_trace"]["name"] = "campaign-byte-replay/v1".into();
    fixture["expected_trace"]["observations"][0]["member_count"] = 99.into();
    fs::write(
        &fixture_path,
        serde_json::to_vec_pretty(&fixture).expect("fixture serializes"),
    )
    .expect("fixture writes");

    let summary = run_report(&ReportArgs {
        input: ReportInput::VectorFixtures {
            paths: vec![fixture_path],
        },
        out: out_dir,
        strict_oracle: false,
        storage_mode: HarnessStorageMode::InMemorySqlite,
        capture_sensitive_replay: true,
        minimization_budget: Default::default(),
    })
    .await
    .expect("failing campaign reports");
    assert_eq!(summary.failed(), 1);
    let capsule_path = summary.scenarios[0]
        .failure_capsule
        .as_ref()
        .expect("failure capsule path");
    let capsule = read_failure_capsule(capsule_path).expect("campaign capsule reads");
    assert_eq!(
        capsule.sensitivity,
        FailureCapsuleSensitivity::SyntheticShareable
    );
    assert!(capsule.byte_replay.is_none());
    promote_failure_capsule_to_vector(&capsule, "test")
        .expect("the logical campaign capsule remains portable");

    let replay_capsule_path = summary.scenarios[0]
        .replay_capsule
        .as_ref()
        .expect("explicit replay capture writes a separate sibling");
    assert!(
        replay_capsule_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains("sensitive-replay-capsule"))
    );
    let replay_capsule =
        read_failure_capsule(replay_capsule_path).expect("sensitive replay capsule reads");
    assert_eq!(
        replay_capsule.sensitivity,
        FailureCapsuleSensitivity::SensitiveLocal
    );
    let replay = replay_capsule
        .byte_replay
        .as_ref()
        .expect("campaign exports its last real recipient tick");
    replay_engine_bytes(replay)
        .await
        .expect("campaign-produced tick witness replays exactly");

    let cli = std::process::Command::new(env!("CARGO_BIN_EXE_cgka-conformance-simulator-report"))
        .args([
            "--replay-capsule",
            &replay_capsule_path.display().to_string(),
        ])
        .output()
        .expect("replay CLI runs");
    assert!(
        cli.status.success(),
        "replay CLI failed: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
}

#[tokio::test]
async fn refused_application_send_fails_step_without_aborting_the_run() {
    // A scripted send_app_message from a client in `Leaving` is refused by
    // the engine (InvalidTransition). The report run must record a
    // structured invalid_transition step failure with a failure capsule,
    // keep executing sibling vectors, and report the run as failed.
    let base = std::env::temp_dir().join(format!(
        "mdk-cgka-refused-send-report-test-{}",
        std::process::id()
    ));
    if base.exists() {
        fs::remove_dir_all(&base).expect("remove stale test dir");
    }
    let vectors_dir = base.join("vectors");
    fs_private::create_dir_all_private(&vectors_dir).expect("create private vectors dir");
    let out_dir = base.join("out");

    let refused = serde_json::json!({
        "scenario_name": "refused-send-after-leave/v1",
        "vector_version": "1",
        "conformance_version": "0.0.0-test",
        "seed": null,
        "scenario": {
            "name": "refused-send-after-leave/v1",
            "spec_version": "2",
            "clients": ["alice", "bob", "carol"],
            "steps": [
                {"type": "create_group", "creator": "alice", "name": "refused-send",
                 "invitees": ["bob", "carol"], "required_features": [], "pending": "create"},
                {"type": "acknowledge_outbound", "client": "alice",
                 "publication": "create", "outcome": "accepted"},
                {"type": "deliver_all"},
                {"type": "tick", "clients": ["bob", "carol"]},
                {"type": "leave", "client": "carol"},
                {"type": "send_app_message", "sender": "carol", "payload": "carol:refused"},
                {"type": "observe", "clients": ["alice"]}
            ]
        },
        "expected_outcomes": [
            {"type": "client_state", "client": "alice", "epoch": 1,
             "member_count": 3, "received_payloads": []}
        ]
    });
    let sibling = serde_json::json!({
        "scenario_name": "zz-sibling-after-refusal/v1",
        "vector_version": "1",
        "conformance_version": "0.0.0-test",
        "seed": null,
        "scenario": {
            "name": "zz-sibling-after-refusal/v1",
            "spec_version": "2",
            "clients": ["alice", "bob"],
            "steps": [
                {"type": "create_group", "creator": "alice", "name": "sibling",
                 "invitees": ["bob"], "required_features": [], "pending": "create"},
                {"type": "acknowledge_outbound", "client": "alice",
                 "publication": "create", "outcome": "accepted"},
                {"type": "deliver_all"},
                {"type": "tick", "clients": ["bob"]},
                {"type": "observe", "clients": ["alice", "bob"]}
            ]
        },
        "expected_outcomes": [
            {"type": "client_state", "client": "alice", "epoch": 1,
             "member_count": 2, "received_payloads": []},
            {"type": "client_state", "client": "bob", "epoch": 1,
             "member_count": 2, "received_payloads": []}
        ]
    });
    fs_private::write_private(
        &vectors_dir.join("a-refused-send.v1.json"),
        &serde_json::to_vec_pretty(&refused).expect("encode refused fixture"),
    )
    .expect("write refused fixture");
    fs_private::write_private(
        &vectors_dir.join("zz-sibling.v1.json"),
        &serde_json::to_vec_pretty(&sibling).expect("encode sibling fixture"),
    )
    .expect("write sibling fixture");

    let summary = run_report(&ReportArgs {
        input: ReportInput::VectorFixtures {
            paths: vec![vectors_dir],
        },
        out: out_dir.clone(),
        strict_oracle: false,
        storage_mode: HarnessStorageMode::InMemorySqlite,
        capture_sensitive_replay: false,
        minimization_budget: Default::default(),
    })
    .await
    .expect("runner completes despite the refused send");

    // The refused send fails its scenario; the run reports it and continues.
    assert_eq!(summary.total(), 2, "both vectors execute");
    assert_eq!(summary.failed(), 1);
    assert_eq!(summary.passed(), 1, "sibling vector still runs and passes");
    assert!(summary.to_human_text().contains("1 passed, 1 failed"));

    let refused_summary = summary
        .scenarios
        .iter()
        .find(|scenario| scenario.scenario_name == "refused-send-after-leave/v1")
        .expect("refused scenario summarized");
    assert!(
        refused_summary.failures.iter().any(|failure| {
            failure.kind.contains("invalid_transition")
                || failure.message.contains("invalid_transition")
        }),
        "failures must name invalid_transition: {:?}",
        refused_summary.failures
    );
    let capsule = refused_summary
        .failure_capsule
        .as_ref()
        .expect("refused scenario writes a failure capsule");
    assert!(capsule.exists(), "failure capsule file exists");

    let report: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&refused_summary.output).expect("read refused report"),
    )
    .expect("refused report parses");
    let failed_step = report["step_log"]
        .as_array()
        .expect("step log")
        .iter()
        .find(|step| step["status"]["status"] == "failed")
        .expect("one step fails");
    assert_eq!(failed_step["step_type"], "send_app_message");
    assert_eq!(failed_step["status"]["kind"], "invalid_transition");

    let sibling_summary = summary
        .scenarios
        .iter()
        .find(|scenario| scenario.scenario_name == "zz-sibling-after-refusal/v1")
        .expect("sibling scenario summarized");
    assert_eq!(sibling_summary.failure_count, 0);

    fs::remove_dir_all(&base).expect("clean up test dir");
}
