use std::collections::BTreeMap;

use convergence_campaign_runner::{
    CampaignLaneConfigV1, CampaignLaneObservationV1, CampaignLaneStepObservationV1, CampaignLaneV1,
    ConvergenceEvidenceBundleV1, EvidenceArtifactV1, TestedBoundaryV1,
};
use sha2::{Digest, Sha256};

const LANES: &[CampaignLaneV1] = &[
    CampaignLaneV1::PullRequest,
    CampaignLaneV1::Nightly,
    CampaignLaneV1::WeeklyManual,
    CampaignLaneV1::ReleaseHardening,
];

#[test]
fn tracked_lane_manifests_are_the_reviewed_builtin_policy() {
    for lane in LANES {
        let config = CampaignLaneConfigV1::builtin(*lane);
        config.validate().unwrap();
        assert_eq!(config.lane, *lane);
    }
}

#[test]
fn every_lane_has_all_resource_retention_and_flake_budgets() {
    for lane in LANES {
        let config = CampaignLaneConfigV1::builtin(*lane);
        assert!(config.contents.minimum_executed_cases > 0);
        assert!(config.budgets.max_wall_clock_seconds > 0);
        assert!(config.budgets.max_cpu_seconds > 0);
        assert!(config.budgets.max_peak_rss_bytes > 0);
        assert!(config.budgets.max_disk_bytes > 0);
        assert!(config.budgets.max_artifact_bytes > 0);
        assert!(config.budgets.artifact_retention_days > 0);
        assert!(config.budgets.max_flake_rate_basis_points <= 10_000);
    }
}

#[test]
fn workflow_artifact_retention_matches_lane_policy() {
    let ci = include_str!("../../../.github/workflows/ci.yml");
    let nightly = include_str!("../../../.github/workflows/simulator-nightly.yml");
    let hardening = include_str!("../../../.github/workflows/convergence-hardening.yml");

    assert_artifact_retention(
        ci,
        "name: cgka-conformance-simulator-reports",
        &CampaignLaneConfigV1::builtin(CampaignLaneV1::PullRequest)
            .budgets
            .artifact_retention_days
            .to_string(),
    );
    assert_artifact_retention(
        nightly,
        "name: cgka-conformance-simulator-nightly-reports",
        &CampaignLaneConfigV1::builtin(CampaignLaneV1::Nightly)
            .budgets
            .artifact_retention_days
            .to_string(),
    );

    let weekly = CampaignLaneConfigV1::builtin(CampaignLaneV1::WeeklyManual)
        .budgets
        .artifact_retention_days;
    let release = CampaignLaneConfigV1::builtin(CampaignLaneV1::ReleaseHardening)
        .budgets
        .artifact_retention_days;
    assert_artifact_retention(
        hardening,
        "name: convergence-hardening-${{ github.run_id }}",
        &format!("${{{{ inputs.lane == 'release_hardening' && {release} || {weekly} }}}}"),
    );
}

#[test]
fn scheduled_workflows_collect_and_enforce_lane_observations() {
    let nightly = include_str!("../../../.github/workflows/simulator-nightly.yml");
    let hardening = include_str!("../../../.github/workflows/convergence-hardening.yml");

    for (workflow, lane, evidence_dir) in [
        (nightly, "nightly", "target/cgka-nightly-lane-evidence"),
        (
            hardening,
            "weekly_manual",
            "target/cgka-hardening-lane-evidence",
        ),
        (
            hardening,
            "release_hardening",
            "target/cgka-hardening-lane-evidence",
        ),
    ] {
        assert!(workflow.contains("observe-step"));
        assert!(workflow.contains("collect-observation"));
        assert!(workflow.contains(&format!("check-budget {lane}")));
        assert!(workflow.contains("observed-usage.v1.json"));
        assert!(workflow.contains("budget-evaluation.v1.json"));
        assert!(workflow.contains(evidence_dir));
    }
}

fn assert_artifact_retention(workflow: &str, artifact_name: &str, expected: &str) {
    let artifact_step = workflow
        .split_once(artifact_name)
        .unwrap_or_else(|| panic!("workflow is missing artifact {artifact_name}"))
        .1
        .split("\n\n")
        .next()
        .expect("artifact upload step has content");
    assert!(
        artifact_step.contains(&format!("retention-days: {expected}")),
        "artifact {artifact_name} retention does not match lane policy {expected}"
    );
}

#[test]
fn budget_evaluation_rejects_empty_and_inconsistent_observations() {
    let config = CampaignLaneConfigV1::builtin(CampaignLaneV1::WeeklyManual);
    let empty = config.evaluate(CampaignLaneObservationV1::default());
    assert!(!empty.passed);
    assert!(
        empty
            .violations
            .iter()
            .any(|violation| violation == "executed_cases:0")
    );

    let inconsistent = config.evaluate(CampaignLaneObservationV1 {
        executed_cases: config.contents.minimum_executed_cases,
        flaky_cases: config.contents.minimum_executed_cases + 1,
        ..CampaignLaneObservationV1::default()
    });
    assert!(!inconsistent.passed);
    assert!(
        inconsistent
            .violations
            .iter()
            .any(|violation| violation.starts_with("flaky_cases:"))
    );
}

#[test]
fn zero_flake_budget_rejects_any_nonzero_flake_rate() {
    let config = CampaignLaneConfigV1::builtin(CampaignLaneV1::PullRequest);
    let evaluation = config.evaluate(CampaignLaneObservationV1 {
        executed_cases: 10_001,
        flaky_cases: 1,
        ..CampaignLaneObservationV1::default()
    });
    assert_eq!(evaluation.flake_rate_basis_points, 1);
    assert!(!evaluation.passed);
    assert!(
        evaluation
            .violations
            .iter()
            .any(|violation| violation == "flake_rate_basis_points:1>0")
    );
}

#[test]
fn budget_evaluation_reports_every_exceeded_dimension() {
    let config = CampaignLaneConfigV1::builtin(CampaignLaneV1::PullRequest);
    let evaluation = config.evaluate(CampaignLaneObservationV1 {
        wall_clock_seconds: config.budgets.max_wall_clock_seconds + 1,
        cpu_seconds: config.budgets.max_cpu_seconds + 1,
        peak_rss_bytes: config.budgets.max_peak_rss_bytes + 1,
        disk_bytes: config.budgets.max_disk_bytes + 1,
        artifact_bytes: config.budgets.max_artifact_bytes + 1,
        executed_cases: 1,
        flaky_cases: 1,
        flake_retries: 1,
    });
    assert!(!evaluation.passed);
    assert_eq!(evaluation.violations.len(), 7);
}

#[test]
fn observer_and_collector_cli_write_private_machine_checkable_evidence() {
    let root = tempfile::tempdir().unwrap();
    let steps = root.path().join("steps");
    let observed_step = steps.join("observer-smoke.json");
    let observer = std::process::Command::new(env!("CARGO_BIN_EXE_cgka-distributed-campaign"))
        .args(["observe-step", "--name", "observer-smoke", "--output"])
        .arg(&observed_step)
        .args([
            "--",
            env!("CARGO_BIN_EXE_cgka-distributed-campaign"),
            "lane",
            "nightly",
        ])
        .output()
        .unwrap();
    assert!(
        observer.status.success(),
        "observer failed: {}",
        String::from_utf8_lossy(&observer.stderr)
    );
    let observed: CampaignLaneStepObservationV1 =
        serde_json::from_slice(&std::fs::read(&observed_step).unwrap()).unwrap();
    assert!(observed.succeeded());
    assert!(observed.user_cpu_us.is_some());
    assert!(observed.system_cpu_us.is_some());
    assert!(observed.peak_rss_bytes.is_some());

    let artifact = root.path().join("artifacts");
    let disk = root.path().join("disk");
    std::fs::create_dir(&artifact).unwrap();
    std::fs::create_dir(&disk).unwrap();
    std::fs::write(artifact.join("report.json"), b"report").unwrap();
    std::fs::write(disk.join("work.bin"), b"working-data").unwrap();

    let config = CampaignLaneConfigV1::builtin(CampaignLaneV1::Nightly);
    let mut completed = observed;
    completed.name = "completed-cases".into();
    completed.executed_cases = config.contents.minimum_executed_cases;
    completed
        .write_private(&steps.join("completed.json"))
        .unwrap();
    std::fs::remove_file(observed_step).unwrap();

    let usage = root.path().join("observed-usage.v1.json");
    let collected = std::process::Command::new(env!("CARGO_BIN_EXE_cgka-distributed-campaign"))
        .args(["collect-observation", "--step-dir"])
        .arg(&steps)
        .arg("--artifact-root")
        .arg(&artifact)
        .arg("--disk-root")
        .arg(&disk)
        .arg("--output")
        .arg(&usage)
        .output()
        .unwrap();
    assert!(
        collected.status.success(),
        "collector failed: {}",
        String::from_utf8_lossy(&collected.stderr)
    );
    let observation: CampaignLaneObservationV1 =
        serde_json::from_slice(&std::fs::read(&usage).unwrap()).unwrap();
    assert_eq!(
        observation.executed_cases,
        config.contents.minimum_executed_cases
    );
    assert_eq!(observation.artifact_bytes, 6);
    assert_eq!(observation.disk_bytes, 12);

    let evaluation = root.path().join("budget-evaluation.v1.json");
    let checked = std::process::Command::new(env!("CARGO_BIN_EXE_cgka-distributed-campaign"))
        .args(["check-budget", "nightly"])
        .arg(&usage)
        .arg("--output")
        .arg(&evaluation)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "budget check failed: {}",
        String::from_utf8_lossy(&checked.stderr)
    );

    #[cfg(unix)]
    for path in [steps.join("completed.json"), usage, evaluation] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn observer_persists_failure_status_before_returning_failure() {
    let root = tempfile::tempdir().unwrap();
    let observation = root.path().join("failed-step.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cgka-distributed-campaign"))
        .args(["observe-step", "--name", "expected-failure", "--output"])
        .arg(&observation)
        .args([
            "--",
            env!("CARGO_BIN_EXE_cgka-distributed-campaign"),
            "check-evidence",
            "missing-evidence.json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let observed: CampaignLaneStepObservationV1 =
        serde_json::from_slice(&std::fs::read(observation).unwrap()).unwrap();
    assert!(!observed.succeeded());
    assert!(observed.exit_code.is_some() || observed.signal.is_some());

    let artifacts = root.path().join("artifacts");
    let disk = root.path().join("disk");
    std::fs::create_dir(&artifacts).unwrap();
    std::fs::create_dir(&disk).unwrap();
    let aggregate = root.path().join("failed-observed-usage.v1.json");
    let collected = std::process::Command::new(env!("CARGO_BIN_EXE_cgka-distributed-campaign"))
        .args(["collect-observation", "--step-dir"])
        .arg(root.path())
        .arg("--artifact-root")
        .arg(&artifacts)
        .arg("--disk-root")
        .arg(&disk)
        .arg("--output")
        .arg(&aggregate)
        .output()
        .unwrap();
    assert!(!collected.status.success());
    let aggregate: CampaignLaneObservationV1 =
        serde_json::from_slice(&std::fs::read(aggregate).unwrap()).unwrap();
    assert_eq!(aggregate.executed_cases, 0);
}

#[test]
fn release_evidence_requires_scoped_coverage_and_a_passing_budget() {
    let config = CampaignLaneConfigV1::builtin(CampaignLaneV1::ReleaseHardening);
    let temp = tempfile::tempdir().unwrap();
    let artifact_bytes = b"process report";
    std::fs::create_dir(temp.path().join("reports")).unwrap();
    std::fs::write(temp.path().join("reports/process.json"), artifact_bytes).unwrap();
    let mut bundle = ConvergenceEvidenceBundleV1 {
        schema_version: "1".into(),
        lane: CampaignLaneV1::ReleaseHardening,
        source_revision: "0123456789abcdef".into(),
        assurance_claim: "The declared routes agree within the recorded boundaries.".into(),
        covered_decision_routes: vec!["ordinary_ingest".into()],
        models: vec!["independent_selector".into()],
        adapters: vec!["engine".into(), "distributed".into()],
        mutation_results: BTreeMap::from([("inconsistent_decision_seam".into(), true)]),
        tested_boundaries: vec![TestedBoundaryV1 {
            dimension: "participants".into(),
            minimum: "2".into(),
            maximum: "64".into(),
        }],
        unresolved_counterexamples: Vec::new(),
        residual_assumptions: vec!["eventual input-set equality".into()],
        untested_surfaces: vec!["unbounded executions".into()],
        budget: config.evaluate(CampaignLaneObservationV1 {
            executed_cases: config.contents.minimum_executed_cases,
            ..CampaignLaneObservationV1::default()
        }),
        artifacts: vec![EvidenceArtifactV1 {
            kind: "process_report".into(),
            path: "reports/process.json".into(),
            sha256: hex::encode(Sha256::digest(artifact_bytes)),
        }],
    };
    bundle.validate().unwrap();
    bundle.validate_artifacts(temp.path()).unwrap();
    bundle
        .write_private(&temp.path().join("evidence.json"))
        .unwrap();
    let cli = std::process::Command::new(env!("CARGO_BIN_EXE_cgka-distributed-campaign"))
        .current_dir(temp.path())
        .args(["check-evidence", "evidence.json"])
        .output()
        .unwrap();
    assert!(
        cli.status.success(),
        "bare bundle filename failed: {}",
        String::from_utf8_lossy(&cli.stderr)
    );

    let mut forged_budget = bundle.clone();
    forged_budget.budget.observation.wall_clock_seconds = config.budgets.max_wall_clock_seconds + 1;
    forged_budget.budget.passed = true;
    forged_budget.budget.violations.clear();
    assert_eq!(
        forged_budget.validate().unwrap_err().code,
        "evidence_budget"
    );

    let mut missing_artifacts = bundle.clone();
    missing_artifacts.artifacts.clear();
    assert_eq!(
        missing_artifacts.validate().unwrap_err().code,
        "incomplete_evidence_bundle"
    );

    bundle.artifacts[0].sha256 = "0".repeat(64);
    assert_eq!(
        bundle.validate_artifacts(temp.path()).unwrap_err().code,
        "evidence_artifact_digest_mismatch"
    );
    bundle.artifacts[0].sha256 = hex::encode(Sha256::digest(artifact_bytes));
    let mut traversal = bundle.clone();
    traversal.artifacts[0].path = "../process.json".into();
    assert_eq!(
        traversal.validate_artifacts(temp.path()).unwrap_err().code,
        "evidence_artifact_path"
    );
    bundle.untested_surfaces.clear();
    assert_eq!(
        bundle.validate().unwrap_err().code,
        "incomplete_evidence_bundle"
    );
}
