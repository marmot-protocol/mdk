use std::collections::BTreeMap;

use convergence_campaign_runner::{
    CampaignLaneConfigV1, CampaignLaneObservationV1, CampaignLaneV1, ConvergenceEvidenceBundleV1,
    EvidenceArtifactV1, TestedBoundaryV1,
};

const TRACKED_LANES: &[(CampaignLaneV1, &str)] = &[
    (
        CampaignLaneV1::PullRequest,
        include_str!("../lanes/pull-request.v1.json"),
    ),
    (
        CampaignLaneV1::Nightly,
        include_str!("../lanes/nightly.v1.json"),
    ),
    (
        CampaignLaneV1::WeeklyManual,
        include_str!("../lanes/weekly-manual.v1.json"),
    ),
    (
        CampaignLaneV1::ReleaseHardening,
        include_str!("../lanes/release-hardening.v1.json"),
    ),
];

#[test]
fn tracked_lane_manifests_equal_the_reviewed_builtin_policy() {
    for (lane, json) in TRACKED_LANES {
        let tracked: CampaignLaneConfigV1 = serde_json::from_str(json).unwrap();
        tracked.validate().unwrap();
        assert_eq!(tracked, CampaignLaneConfigV1::builtin(*lane));
    }
}

#[test]
fn every_lane_has_all_resource_retention_and_flake_budgets() {
    for (lane, _) in TRACKED_LANES {
        let config = CampaignLaneConfigV1::builtin(*lane);
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
fn release_evidence_requires_scoped_coverage_and_a_passing_budget() {
    let config = CampaignLaneConfigV1::builtin(CampaignLaneV1::ReleaseHardening);
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
        budget: config.evaluate(CampaignLaneObservationV1::default()),
        artifacts: vec![EvidenceArtifactV1 {
            kind: "process_report".into(),
            path: "reports/process.json".into(),
            sha256: "0".repeat(64),
        }],
    };
    bundle.validate().unwrap();
    bundle.untested_surfaces.clear();
    assert_eq!(
        bundle.validate().unwrap_err().code,
        "incomplete_evidence_bundle"
    );
}
