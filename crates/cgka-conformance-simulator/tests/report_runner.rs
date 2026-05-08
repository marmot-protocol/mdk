use std::fs;
use std::path::PathBuf;

use cgka_conformance_simulator::{ReportArgs, ReportCommand, parse_report_command, run_report};

#[test]
fn parse_defaults_to_send_leave_family() {
    let command = parse_report_command(Vec::new()).expect("default args parse");
    assert_eq!(
        command,
        ReportCommand::Run(ReportArgs {
            family: "send-leave/v1".into(),
            seed: 0,
            cases: 1,
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
            family: "send-leave/v1".into(),
            seed: 42,
            cases: 3,
            out: PathBuf::from("target/custom"),
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

#[tokio::test]
async fn report_runner_writes_send_leave_json_reports() {
    let out_dir = std::env::temp_dir().join(format!(
        "darkmatter-cgka-conformance-simulator-report-test-{}",
        std::process::id()
    ));
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).expect("remove stale output dir");
    }

    run_report(&ReportArgs {
        family: "send-leave/v1".into(),
        seed: 42,
        cases: 2,
        out: out_dir.clone(),
    })
    .await
    .expect("runner writes reports");

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

    run_report(&ReportArgs {
        family: "convergence-e2e-delivery/v1".into(),
        seed: 7,
        cases: 2,
        out: out_dir.clone(),
    })
    .await
    .expect("runner writes convergence delivery reports");

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
        Some(2)
    );
    assert_eq!(
        report["epoch_change_observations"].as_array().map(Vec::len),
        Some(2)
    );

    fs::remove_dir_all(out_dir).expect("clean output dir");
}
