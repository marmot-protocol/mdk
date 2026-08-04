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
    pub engine_reference_relay_cases: u32,
    pub generated_seed_cases: u32,
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
        const GIB: u64 = 1024 * 1024 * 1024;
        let (contents, budgets) = match lane {
            CampaignLaneV1::PullRequest => (
                CampaignLaneContentsV1 {
                    strict_formal_gate: true,
                    fixed_vectors: true,
                    engine_reference_relay_cases: 32,
                    generated_seed_cases: 0,
                    file_backed_storage: true,
                    crash_matrix: false,
                    retained_relays: true,
                    mutation_scope: MutationScopeV1::Sentinel,
                    process_campaigns: false,
                    container_campaigns: false,
                    resource_sweeps: false,
                    constant_sweeps: false,
                    mixed_version: false,
                    incident_corpus: false,
                },
                CampaignLaneBudgetsV1 {
                    max_wall_clock_seconds: 3_600,
                    max_cpu_seconds: 7_200,
                    max_peak_rss_bytes: 6 * GIB,
                    max_disk_bytes: 12 * GIB,
                    max_artifact_bytes: GIB,
                    artifact_retention_days: 14,
                    max_flake_retries: 0,
                    max_flake_rate_basis_points: 0,
                },
            ),
            CampaignLaneV1::Nightly => (
                CampaignLaneContentsV1 {
                    strict_formal_gate: true,
                    fixed_vectors: true,
                    engine_reference_relay_cases: 256,
                    generated_seed_cases: 256,
                    file_backed_storage: true,
                    crash_matrix: true,
                    retained_relays: true,
                    mutation_scope: MutationScopeV1::Targeted,
                    process_campaigns: true,
                    container_campaigns: true,
                    resource_sweeps: false,
                    constant_sweeps: false,
                    mixed_version: false,
                    incident_corpus: true,
                },
                CampaignLaneBudgetsV1 {
                    max_wall_clock_seconds: 7_200,
                    max_cpu_seconds: 14_400,
                    max_peak_rss_bytes: 8 * GIB,
                    max_disk_bytes: 20 * GIB,
                    max_artifact_bytes: 5 * GIB,
                    artifact_retention_days: 30,
                    max_flake_retries: 1,
                    max_flake_rate_basis_points: 50,
                },
            ),
            CampaignLaneV1::WeeklyManual => (
                CampaignLaneContentsV1 {
                    strict_formal_gate: true,
                    fixed_vectors: true,
                    engine_reference_relay_cases: 1_024,
                    generated_seed_cases: 4_096,
                    file_backed_storage: true,
                    crash_matrix: true,
                    retained_relays: true,
                    mutation_scope: MutationScopeV1::FullTargeted,
                    process_campaigns: true,
                    container_campaigns: true,
                    resource_sweeps: true,
                    constant_sweeps: true,
                    mixed_version: true,
                    incident_corpus: true,
                },
                CampaignLaneBudgetsV1 {
                    max_wall_clock_seconds: 21_600,
                    max_cpu_seconds: 43_200,
                    max_peak_rss_bytes: 12 * GIB,
                    max_disk_bytes: 40 * GIB,
                    max_artifact_bytes: 10 * GIB,
                    artifact_retention_days: 60,
                    max_flake_retries: 2,
                    max_flake_rate_basis_points: 25,
                },
            ),
            CampaignLaneV1::ReleaseHardening => (
                CampaignLaneContentsV1 {
                    strict_formal_gate: true,
                    fixed_vectors: true,
                    engine_reference_relay_cases: 2_048,
                    generated_seed_cases: 8_192,
                    file_backed_storage: true,
                    crash_matrix: true,
                    retained_relays: true,
                    mutation_scope: MutationScopeV1::FullTargeted,
                    process_campaigns: true,
                    container_campaigns: true,
                    resource_sweeps: true,
                    constant_sweeps: true,
                    mixed_version: true,
                    incident_corpus: true,
                },
                CampaignLaneBudgetsV1 {
                    max_wall_clock_seconds: 28_800,
                    max_cpu_seconds: 57_600,
                    max_peak_rss_bytes: 12 * GIB,
                    max_disk_bytes: 50 * GIB,
                    max_artifact_bytes: 15 * GIB,
                    artifact_retention_days: 180,
                    max_flake_retries: 1,
                    max_flake_rate_basis_points: 10,
                },
            ),
        };
        Self {
            schema_version: CAMPAIGN_LANE_SCHEMA_VERSION.into(),
            lane,
            contents,
            budgets,
        }
    }

    pub fn validate(&self) -> Result<(), RunnerError> {
        if self.schema_version != CAMPAIGN_LANE_SCHEMA_VERSION {
            return Err(RunnerError::validation(
                "campaign_lane_version",
                "unsupported campaign lane schema version",
            ));
        }
        let expected = Self::builtin(self.lane);
        if self != &expected {
            return Err(RunnerError::validation(
                "campaign_lane_drift",
                "tracked lane configuration differs from the reviewed built-in policy",
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
        let flake_rate_basis_points = observation
            .flaky_cases
            .saturating_mul(10_000)
            .checked_div(observation.executed_cases)
            .unwrap_or(0);
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
