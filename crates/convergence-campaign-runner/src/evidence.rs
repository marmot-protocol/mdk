use std::collections::BTreeMap;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CampaignBudgetEvaluationV1, CampaignLaneConfigV1, CampaignLaneV1, RunnerError};

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

/// Directory against which an evidence bundle's relative artifact paths are
/// resolved. A bare filename lives in the current directory even though
/// `Path::parent` represents that parent as an empty path.
pub fn evidence_bundle_base_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
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
            ("artifacts", self.artifacts.is_empty()),
        ] {
            if empty {
                return Err(RunnerError::validation(
                    "incomplete_evidence_bundle",
                    format!("evidence bundle is missing {name}"),
                ));
            }
        }
        let expected_budget =
            CampaignLaneConfigV1::builtin(self.lane).evaluate(self.budget.observation.clone());
        if !expected_budget.passed || self.budget != expected_budget {
            return Err(RunnerError::validation(
                "evidence_budget",
                "evidence budget must match a recomputed passing lane evaluation",
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

    /// Validate artifact paths and bind every declared digest to the bytes
    /// present beside an ingested evidence bundle.
    pub fn validate_artifacts(&self, base_dir: &Path) -> Result<(), RunnerError> {
        self.validate()?;
        let canonical_base = std::fs::canonicalize(base_dir)
            .map_err(|error| RunnerError::environment("evidence_artifact_base", error))?;
        for artifact in &self.artifacts {
            if artifact.path.as_os_str().is_empty()
                || artifact.path.is_absolute()
                || artifact.path.components().any(|component| {
                    matches!(
                        component,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                })
            {
                return Err(RunnerError::validation(
                    "evidence_artifact_path",
                    "artifact paths must be nonempty relative paths without parent traversal",
                ));
            }
            let canonical_path = std::fs::canonicalize(canonical_base.join(&artifact.path))
                .map_err(|error| RunnerError::environment("evidence_artifact_read", error))?;
            if !canonical_path.starts_with(&canonical_base) {
                return Err(RunnerError::validation(
                    "evidence_artifact_path",
                    "artifact paths must remain within the evidence bundle directory",
                ));
            }
            let file = std::fs::File::open(canonical_path)
                .map_err(|error| RunnerError::environment("evidence_artifact_read", error))?;
            let mut reader = BufReader::new(file);
            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = reader
                    .read(&mut buffer)
                    .map_err(|error| RunnerError::environment("evidence_artifact_read", error))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            let actual = hex::encode(hasher.finalize());
            if actual != artifact.sha256 {
                return Err(RunnerError::validation(
                    "evidence_artifact_digest_mismatch",
                    "artifact bytes do not match the declared SHA-256 digest",
                ));
            }
        }
        Ok(())
    }

    /// Write an owner-only bundle after verifying that every declared artifact
    /// already exists beside the destination and matches its digest.
    pub fn write_private(&self, path: &Path) -> Result<(), RunnerError> {
        self.validate_artifacts(evidence_bundle_base_dir(path))?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| RunnerError::environment("evidence_serialize", error))?;
        fs_private::write_private(path, &bytes)
            .map_err(|error| RunnerError::environment("evidence_write", error))
    }
}

#[cfg(test)]
mod tests {
    use super::evidence_bundle_base_dir;
    use std::path::Path;

    #[test]
    fn bare_bundle_filename_resolves_artifacts_from_current_directory() {
        assert_eq!(
            evidence_bundle_base_dir(Path::new("evidence.json")),
            Path::new(".")
        );
        assert_eq!(
            evidence_bundle_base_dir(Path::new("reports/evidence.json")),
            Path::new("reports")
        );
    }
}
