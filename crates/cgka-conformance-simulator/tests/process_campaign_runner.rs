use cgka_conformance_simulator::{
    GeneratedScenarioInputV1, ScenarioReport, ScenarioStepStatus,
    generate_convergence_e2e_delivery_case, resolve_scenario_input_bytes,
};
use std::path::Path;
use std::process::Command;

fn campaign_binary() -> &'static str {
    env!("CARGO_BIN_EXE_cgka-conformance-campaign")
}

#[test]
fn isolated_campaign_preserves_input_provenance_and_refuses_overwrite() {
    let temp = tempfile::tempdir().expect("temporary campaign root");
    let out = temp.path().join("campaign");
    let status = Command::new(campaign_binary())
        .args([
            "--family",
            "send-leave/v1",
            "--seed",
            "42",
            "--cases",
            "1",
            "--case-timeout-secs",
            "60",
            "--out",
        ])
        .arg(&out)
        .args(["--storage", "memory"])
        .status()
        .expect("campaign starts");
    assert!(status.success(), "campaign must pass");

    let stem = "send-leave-v1-seed-42-case-0";
    let input_path = out.join(format!("{stem}-generated-input.json"));
    let report_path = out.join(format!("{stem}.json"));
    let fixture_path = out.join(format!("{stem}-fixture.v1.json"));
    let summary_path = out.join("process-campaign.v1.json");
    for path in [&input_path, &report_path, &fixture_path, &summary_path] {
        assert!(path.is_file(), "missing {}", path.display());
    }

    let input_bytes = std::fs::read(&input_path).expect("saved input reads");
    let resolved = resolve_scenario_input_bytes(&input_bytes).expect("saved input resolves");
    let report: ScenarioReport =
        serde_json::from_slice(&std::fs::read(&report_path).expect("scenario report reads"))
            .expect("scenario report parses");
    assert_eq!(
        report
            .metadata
            .input_provenance
            .as_ref()
            .map(|value| value.source_sha256.as_str()),
        Some(resolved.provenance.source_sha256.as_str())
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&summary_path).expect("campaign summary reads"))
            .expect("campaign summary parses");
    assert_eq!(summary["family"], "send-leave/v1");
    assert_eq!(summary["storage"], "memory");
    assert_eq!(summary["case_timeout_ms"], 60_000);
    assert_eq!(summary["minimization_wall_time_ms"], 30_000);
    assert_eq!(summary["minimization_max_trials"], 256);
    assert_eq!(summary["minimization_trial_timeout_ms"], 5_000);
    assert_eq!(summary["cases"][0]["minimization_status"], "skipped");
    assert!(summary["cases"][0].get("timeout_phase").is_none());
    assert_eq!(
        summary["cases"][0]["artifact_integrity_errors"],
        serde_json::json!([])
    );
    assert_eq!(
        summary["cases"][0]["fixture_candidate"],
        fixture_path.to_string_lossy().as_ref()
    );

    let second = Command::new(campaign_binary())
        .args([
            "--family",
            "send-leave/v1",
            "--seed",
            "42",
            "--cases",
            "1",
            "--out",
        ])
        .arg(&out)
        .status()
        .expect("second campaign starts");
    assert!(
        !second.success(),
        "existing evidence must not be overwritten"
    );
    assert_eq!(
        std::fs::read(&input_path).expect("saved input remains"),
        input_bytes
    );
}

#[test]
fn strict_worker_failure_writes_a_portable_capsule() {
    let temp = tempfile::tempdir().expect("temporary campaign root");
    let out = temp.path().join("failure");
    fs_private::create_dir_all_private(&out).expect("private output directory");
    let mut case = generate_convergence_e2e_delivery_case(42, 0);
    case.expected_outcomes.clear();
    let input_path = out.join("stripped-generated-input.json");
    fs_private::write_private(
        &input_path,
        &serde_json::to_vec_pretty(&GeneratedScenarioInputV1::new(case))
            .expect("generated input serializes"),
    )
    .expect("generated input writes");

    let status = Command::new(campaign_binary())
        .arg("--worker")
        .arg("--input")
        .arg(&input_path)
        .arg("--out")
        .arg(&out)
        .args(["--storage", "memory"])
        .status()
        .expect("worker starts");
    assert_eq!(status.code(), Some(1));

    let stem = "convergence-e2e-delivery-v1-seed-42-case-0";
    assert!(out.join(format!("{stem}.json")).is_file());
    assert!(
        out.join(format!("{stem}-failure-capsule.v1.json"))
            .is_file()
    );
}

#[test]
#[ignore = "64-member Welcome-refusal boundary; prefer the campaign-bin fixture tests::large_group_pressure_8001_30_reports_create_refusal"]
fn large_group_pressure_8001_30_report_and_campaign_worker_exit_failed_scenario() {
    let temp = tempfile::tempdir().expect("temporary campaign root");
    let case = cgka_conformance_simulator::generate_large_group_pressure_case(8001, 30);
    let input = GeneratedScenarioInputV1::new(case);
    let campaign_out = temp.path().join("campaign");
    let report_out = temp.path().join("report");
    fs_private::create_dir_all_private(&campaign_out).expect("campaign out");
    fs_private::create_dir_all_private(&report_out).expect("report out");
    let input_path =
        campaign_out.join("large-group-pressure-v1-seed-8001-case-30-generated-input.json");
    fs_private::write_private(
        &input_path,
        &serde_json::to_vec_pretty(&input).expect("generated input serializes"),
    )
    .expect("generated input writes");

    let report_status = Command::new(env!("CARGO_BIN_EXE_cgka-conformance-simulator-report"))
        .arg("--generated-input")
        .arg(&input_path)
        .arg("--out")
        .arg(&report_out)
        .args(["--storage", "file"])
        .env("RUST_MIN_STACK", "4194304")
        .status()
        .expect("report binary starts");
    assert_eq!(report_status.code(), Some(1));

    let campaign_status = Command::new(campaign_binary())
        .arg("--worker")
        .arg("--input")
        .arg(&input_path)
        .arg("--out")
        .arg(&campaign_out)
        .args(["--storage", "file"])
        .env("RUST_MIN_STACK", "4194304")
        .status()
        .expect("campaign worker starts");
    assert_eq!(campaign_status.code(), Some(1));

    let stem = "large-group-pressure-v1-seed-8001-case-30";
    assert_create_refusal_artifacts(&report_out, stem);
    assert_create_refusal_artifacts(&campaign_out, stem);
}

fn assert_create_refusal_artifacts(out: &Path, stem: &str) {
    let report_path = out.join(format!("{stem}.json"));
    let fixture_path = out.join(format!("{stem}-fixture.v1.json"));
    let capsule_path = out.join(format!("{stem}-failure-capsule.v1.json"));
    let report: ScenarioReport =
        serde_json::from_slice(&std::fs::read(&report_path).expect("create-refusal report reads"))
            .expect("create-refusal report parses");
    assert!(
        fixture_path.is_file(),
        "missing fixture {}",
        fixture_path.display()
    );
    let capsule = cgka_conformance_simulator::read_failure_capsule(&capsule_path)
        .expect("create-refusal capsule reads");
    assert_eq!(
        capsule.sensitivity,
        cgka_conformance_simulator::FailureCapsuleSensitivity::SyntheticShareable
    );
    assert!(capsule.byte_replay.is_none());
    let first = report
        .step_log
        .first()
        .expect("failed create leaves a step log");
    assert_eq!(first.step_type, "create_group");
    match &first.status {
        ScenarioStepStatus::Failed { kind, .. } => {
            assert_eq!(kind, "peeler");
        }
        other => panic!("first step must fail with peeler, got {other:?}"),
    }
}
