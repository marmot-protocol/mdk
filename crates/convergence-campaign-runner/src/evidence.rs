use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{CampaignBudgetEvaluationV1, CampaignLaneV1, RunnerError};

pub const CONVERGENCE_EVIDENCE_BUNDLE_VERSION: &str = "1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceEvidenceBundleV1 {
    pub schema_version: String,
    pub lane: CampaignLaneV1,
    pub source_revision: String,
    pub assurance_claim: String,
    pub covered_decision_routes: Vec<String>,
    pub models: Vec<String>,
    pub adapters: Vec<String>,
    pub mutation_results: BTreeMap<String, bool>,
    pub tested_boundaries: Vec<TestedBoundaryV1>,
    #[serde(default)]
    pub unresolved_counterexamples: Vec<String>,
    pub residual_assumptions: Vec<String>,
    pub untested_surfaces: Vec<String>,
    pub budget: CampaignBudgetEvaluationV1,
    #[serde(default)]
    pub artifacts: Vec<EvidenceArtifactV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestedBoundaryV1 {
    pub dimension: String,
    pub minimum: String,
    pub maximum: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifactV1 {
    pub kind: String,
    pub path: PathBuf,
    pub sha256: String,
}

impl ConvergenceEvidenceBundleV1 {
    pub fn validate(&self) -> Result<(), RunnerError> {
        if self.schema_version != CONVERGENCE_EVIDENCE_BUNDLE_VERSION {
            return Err(RunnerError::validation(
                "evidence_bundle_version",
                "unsupported convergence evidence bundle version",
            ));
        }
        if self.source_revision.is_empty() || self.assurance_claim.is_empty() {
            return Err(RunnerError::validation(
                "evidence_identity",
                "evidence requires a source revision and scoped assurance claim",
            ));
        }
        for (name, empty) in [
            (
                "covered_decision_routes",
                self.covered_decision_routes.is_empty(),
            ),
            ("models", self.models.is_empty()),
            ("adapters", self.adapters.is_empty()),
            ("mutation_results", self.mutation_results.is_empty()),
            ("tested_boundaries", self.tested_boundaries.is_empty()),
            ("residual_assumptions", self.residual_assumptions.is_empty()),
            ("untested_surfaces", self.untested_surfaces.is_empty()),
        ] {
            if empty {
                return Err(RunnerError::validation(
                    "incomplete_evidence_bundle",
                    format!("evidence bundle is missing {name}"),
                ));
            }
        }
        if self.budget.lane != self.lane || !self.budget.passed {
            return Err(RunnerError::validation(
                "evidence_budget",
                "evidence lane must match a passing budget evaluation",
            ));
        }
        for artifact in &self.artifacts {
            if artifact.sha256.len() != 64
                || !artifact
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(RunnerError::validation(
                    "evidence_artifact_digest",
                    "artifact digests must be lowercase SHA-256 values",
                ));
            }
        }
        Ok(())
    }

    pub fn write_private(&self, path: &Path) -> Result<(), RunnerError> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| RunnerError::environment("evidence_serialize", error))?;
        fs_private::write_private(path, &bytes)
            .map_err(|error| RunnerError::environment("evidence_write", error))
    }
}
