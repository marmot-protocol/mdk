//! Distributed convergence campaigns above the in-process/process simulator.

use std::fmt;
use std::path::Path;

use sha2::Digest;

pub mod evidence;
pub mod failure_corpus;
pub mod lane;
pub mod lane_observation;
pub mod manifest;
pub mod plan;
mod relay_file_control;
pub mod runner;

pub use evidence::*;
pub use failure_corpus::*;
pub use lane::*;
pub use lane_observation::*;
pub use manifest::*;
pub use plan::*;
pub use relay_file_control::*;
pub use runner::*;

/// Runner-owned DNS alias attached only to the campaign relay container.
pub const ISOLATED_RELAY_NETWORK_ALIAS: &str = "marmot-campaign-relay";
pub const ISOLATED_RELAY_PORT: u16 = 8080;

#[derive(Debug)]
pub struct RunnerError {
    pub code: String,
    pub message: String,
}

impl RunnerError {
    pub(crate) fn validation(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub(crate) fn environment(code: impl Into<String>, error: impl fmt::Display) -> Self {
        Self {
            code: code.into(),
            message: error.to_string(),
        }
    }
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RunnerError {}

pub fn load_manifest(path: &Path) -> Result<DistributedCampaignManifestV1, RunnerError> {
    let bytes =
        std::fs::read(path).map_err(|error| RunnerError::environment("manifest_read", error))?;
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    let manifest = match extension.as_deref() {
        Some("yaml" | "yml") => serde_yaml_ng::from_slice(&bytes)
            .map_err(|error| RunnerError::environment("manifest_parse", error))?,
        _ => serde_json::from_slice(&bytes)
            .map_err(|error| RunnerError::environment("manifest_parse", error))?,
    };
    Ok(manifest)
}

pub fn verify_manifest_inputs(
    manifest: &DistributedCampaignManifestV1,
) -> Result<Vec<u8>, RunnerError> {
    manifest.validate()?;
    let scenario = std::fs::read(&manifest.scenario.path)
        .map_err(|error| RunnerError::environment("scenario_read", error))?;
    let actual = hex::encode(sha2::Sha256::digest(&scenario));
    if !actual.eq_ignore_ascii_case(&manifest.scenario.sha256) {
        return Err(RunnerError::validation(
            "scenario_digest_mismatch",
            "scenario bytes do not match the manifest digest",
        ));
    }
    Ok(scenario)
}
