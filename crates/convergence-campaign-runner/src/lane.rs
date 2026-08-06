use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::RunnerError;

pub const CAMPAIGN_LANE_SCHEMA_VERSION: &str = "1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignLaneV1 {
    PullRequest,
    Nightly,
    WeeklyManual,
    ReleaseHardening,
}

impl CampaignLaneV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PullRequest => "pull_request",
            Self::Nightly => "nightly",
            Self::WeeklyManual => "weekly_manual",
            Self::ReleaseHardening => "release_hardening",
        }
    }
}

impl fmt::Display for CampaignLaneV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CampaignLaneV1 {
    type Err = RunnerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pull_request" | "pr" => Ok(Self::PullRequest),
            "nightly" => Ok(Self::Nightly),
            "weekly_manual" | "weekly" => Ok(Self::WeeklyManual),
            "release_hardening" | "release" => Ok(Self::ReleaseHardening),
            _ => Err(RunnerError::validation(
                "campaign_lane",
                "lane must be pull_request, nightly, weekly_manual, or release_hardening",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignLaneConfigV1 {
    pub schema_version: String,
    pub lane: CampaignLaneV1,
    pub contents: CampaignLaneContentsV1,
    pub budgets: CampaignLaneBudgetsV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignLaneContentsV1 {
    pub strict_formal_gate: bool,
    pub fixed_vectors: bool,
    /// Liveness floor proving that the lane executed some work. This is not a
    /// substitute for capability-specific coverage recorded in evidence.
    pub minimum_executed_cases: u64,
    pub file_backed_storage: bool,
    pub crash_matrix: bool,
    pub retained_relays: bool,
    pub mutation_scope: MutationScopeV1,
    pub process_campaigns: bool,
    pub container_campaigns: bool,
    pub resource_sweeps: bool,
    pub constant_sweeps: bool,
    pub mixed_version: bool,
    pub incident_corpus: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationScopeV1 {
    Sentinel,
    Targeted,
    FullTargeted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignLaneBudgetsV1 {
    pub max_wall_clock_seconds: u64,
    pub max_cpu_seconds: u64,
    pub max_peak_rss_bytes: u64,
    pub max_disk_bytes: u64,
    pub max_artifact_bytes: u64,
    pub artifact_retention_days: u16,
    pub max_flake_retries: u8,
    pub max_flake_rate_basis_points: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignLaneObservationV1 {
    pub wall_clock_seconds: u64,
    pub cpu_seconds: u64,
    pub peak_rss_bytes: u64,
    pub disk_bytes: u64,
    pub artifact_bytes: u64,
    pub executed_cases: u64,
    pub flaky_cases: u64,
    pub flake_retries: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignBudgetEvaluationV1 {
    pub lane: CampaignLaneV1,
    pub observation: CampaignLaneObservationV1,
    pub flake_rate_basis_points: u64,
    pub violations: Vec<String>,
    pub passed: bool,
}

impl CampaignLaneConfigV1 {
    pub fn builtin(lane: CampaignLaneV1) -> Self {
        let json = match lane {
            CampaignLaneV1::PullRequest => include_str!("../lanes/pull-request.v1.json"),
            CampaignLaneV1::Nightly => include_str!("../lanes/nightly.v1.json"),
            CampaignLaneV1::WeeklyManual => include_str!("../lanes/weekly-manual.v1.json"),
            CampaignLaneV1::ReleaseHardening => {
                include_str!("../lanes/release-hardening.v1.json")
            }
        };
        let config: Self =
            serde_json::from_str(json).expect("tracked campaign lane manifest must be valid JSON");
        assert_eq!(config.lane, lane, "tracked campaign lane manifest mismatch");
        config
            .validate()
            .expect("tracked campaign lane manifest must satisfy policy invariants");
        config
    }

    pub fn validate(&self) -> Result<(), RunnerError> {
        if self.schema_version != CAMPAIGN_LANE_SCHEMA_VERSION {
            return Err(RunnerError::validation(
                "campaign_lane_version",
                "unsupported campaign lane schema version",
            ));
        }
        if self.contents.minimum_executed_cases == 0 {
            return Err(RunnerError::validation(
                "campaign_lane_cases",
                "campaign lane must require at least one executed case",
            ));
        }
        let budgets = &self.budgets;
        if budgets.max_wall_clock_seconds == 0
            || budgets.max_cpu_seconds == 0
            || budgets.max_peak_rss_bytes == 0
            || budgets.max_disk_bytes == 0
            || budgets.max_artifact_bytes == 0
            || budgets.artifact_retention_days == 0
            || budgets.max_flake_rate_basis_points > 10_000
        {
            return Err(RunnerError::validation(
                "campaign_lane_budget",
                "campaign lane budgets must be nonzero and the flake rate must not exceed 10000 basis points",
            ));
        }
        Ok(())
    }

    pub fn evaluate(&self, observation: CampaignLaneObservationV1) -> CampaignBudgetEvaluationV1 {
        let mut violations = Vec::new();
        let budget = &self.budgets;
        check_limit(
            &mut violations,
            "wall_clock_seconds",
            observation.wall_clock_seconds,
            budget.max_wall_clock_seconds,
        );
        check_limit(
            &mut violations,
            "cpu_seconds",
            observation.cpu_seconds,
            budget.max_cpu_seconds,
        );
        check_limit(
            &mut violations,
            "peak_rss_bytes",
            observation.peak_rss_bytes,
            budget.max_peak_rss_bytes,
        );
        check_limit(
            &mut violations,
            "disk_bytes",
            observation.disk_bytes,
            budget.max_disk_bytes,
        );
        check_limit(
            &mut violations,
            "artifact_bytes",
            observation.artifact_bytes,
            budget.max_artifact_bytes,
        );
        check_limit(
            &mut violations,
            "flake_retries",
            observation.flake_retries,
            u64::from(budget.max_flake_retries),
        );
        if observation.executed_cases == 0 {
            violations.push("executed_cases:0".into());
        } else if observation.executed_cases < self.contents.minimum_executed_cases {
            violations.push(format!(
                "executed_cases:{}<{}",
                observation.executed_cases, self.contents.minimum_executed_cases
            ));
        }
        if observation.flaky_cases > observation.executed_cases {
            violations.push(format!(
                "flaky_cases:{}>{}",
                observation.flaky_cases, observation.executed_cases
            ));
        }
        let flake_rate_basis_points = observation
            .flaky_cases
            .saturating_mul(10_000)
            .div_ceil(observation.executed_cases.max(1));
        check_limit(
            &mut violations,
            "flake_rate_basis_points",
            flake_rate_basis_points,
            u64::from(budget.max_flake_rate_basis_points),
        );
        CampaignBudgetEvaluationV1 {
            lane: self.lane,
            observation,
            flake_rate_basis_points,
            passed: violations.is_empty(),
            violations,
        }
    }
}

fn check_limit(violations: &mut Vec<String>, name: &str, observed: u64, limit: u64) {
    if observed > limit {
        violations.push(format!("{name}:{observed}>{limit}"));
    }
}
