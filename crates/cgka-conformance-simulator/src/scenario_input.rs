//! Shared resolution of canonical Scenario IR and saved generated inputs.
//!
//! Wider adapters consume this boundary so a saved generated case keeps one
//! scenario meaning. The source-byte digest identifies the selected artifact;
//! the canonical-IR digest identifies the exact [`ScenarioSpec`] every adapter
//! must execute after resolving the envelope.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{GeneratedScenarioInputV1, GeneratedSubjectKind, ScenarioSpec, TraceExpectation};

pub const SCENARIO_INPUT_PROVENANCE_SCHEMA_VERSION: &str = "1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioInputFormatV1 {
    CanonicalScenarioIr,
    GeneratedScenarioInputV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedScenarioProvenanceV1 {
    pub family_name: String,
    pub generator_version: String,
    pub seed: u64,
    pub case_index: u64,
    pub recorded_subject: GeneratedSubjectKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioInputProvenanceV1 {
    pub schema_version: String,
    pub format: ScenarioInputFormatV1,
    /// SHA-256 of the selected file bytes, including an envelope when present.
    pub source_sha256: String,
    /// SHA-256 of the deterministic compact JSON encoding of the embedded IR.
    pub canonical_ir_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<GeneratedScenarioProvenanceV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedScenarioInputV1 {
    pub scenario: ScenarioSpec,
    pub expected_outcomes: Vec<TraceExpectation>,
    pub provenance: ScenarioInputProvenanceV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioInputError {
    pub code: &'static str,
    pub message: String,
}

impl ScenarioInputError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ScenarioInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ScenarioInputError {}

pub fn resolve_scenario_input_bytes(
    bytes: &[u8],
) -> Result<ResolvedScenarioInputV1, ScenarioInputError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| ScenarioInputError::new("scenario_input_parse", error.to_string()))?;
    let source_sha256 = hex::encode(Sha256::digest(bytes));

    if value.get("schema_version").is_some() && value.get("case").is_some() {
        let input: GeneratedScenarioInputV1 = serde_json::from_value(value).map_err(|error| {
            ScenarioInputError::new("generated_scenario_input_parse", error.to_string())
        })?;
        input.validate().map_err(|message| {
            ScenarioInputError::new("generated_scenario_input_version", message)
        })?;
        let case = input.case;
        let canonical_ir_sha256 = canonical_scenario_ir_sha256(&case.scenario)?;
        return Ok(ResolvedScenarioInputV1 {
            scenario: case.scenario,
            expected_outcomes: case.expected_outcomes,
            provenance: ScenarioInputProvenanceV1 {
                schema_version: SCENARIO_INPUT_PROVENANCE_SCHEMA_VERSION.into(),
                format: ScenarioInputFormatV1::GeneratedScenarioInputV1,
                source_sha256,
                canonical_ir_sha256,
                generated: Some(GeneratedScenarioProvenanceV1 {
                    family_name: case.family_name,
                    generator_version: case.generator_version,
                    seed: case.seed,
                    case_index: case.case_index,
                    recorded_subject: case.subject,
                }),
            },
        });
    }

    let scenario: ScenarioSpec = serde_json::from_value(value).map_err(|error| {
        ScenarioInputError::new("canonical_scenario_ir_parse", error.to_string())
    })?;
    let canonical_ir_sha256 = canonical_scenario_ir_sha256(&scenario)?;
    Ok(ResolvedScenarioInputV1 {
        scenario,
        expected_outcomes: Vec::new(),
        provenance: ScenarioInputProvenanceV1 {
            schema_version: SCENARIO_INPUT_PROVENANCE_SCHEMA_VERSION.into(),
            format: ScenarioInputFormatV1::CanonicalScenarioIr,
            source_sha256,
            canonical_ir_sha256,
            generated: None,
        },
    })
}

pub fn canonical_scenario_ir_sha256(scenario: &ScenarioSpec) -> Result<String, ScenarioInputError> {
    let bytes = serde_json::to_vec(scenario).map_err(|error| {
        ScenarioInputError::new("canonical_scenario_ir_encode", error.to_string())
    })?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GeneratedScenarioCase, ScenarioStep};

    fn scenario() -> ScenarioSpec {
        ScenarioSpec {
            name: "selectable-input".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into()],
            topology: Default::default(),
            steps: vec![ScenarioStep::DeliverAll],
        }
    }

    #[test]
    fn raw_and_generated_inputs_resolve_to_the_same_canonical_ir_digest() {
        let scenario = scenario();
        let raw = serde_json::to_vec(&scenario).unwrap();
        let generated = serde_json::to_vec(&GeneratedScenarioInputV1::new(GeneratedScenarioCase {
            family_name: "selectable/v1".into(),
            generator_version: "3".into(),
            seed: 42,
            case_index: 7,
            subject: GeneratedSubjectKind::RetainedRelay,
            scenario: scenario.clone(),
            expected_outcomes: Vec::new(),
        }))
        .unwrap();

        let raw = resolve_scenario_input_bytes(&raw).unwrap();
        let generated = resolve_scenario_input_bytes(&generated).unwrap();
        assert_eq!(raw.scenario, scenario);
        assert_eq!(generated.scenario, scenario);
        assert_eq!(
            raw.provenance.canonical_ir_sha256,
            generated.provenance.canonical_ir_sha256
        );
        assert_ne!(
            raw.provenance.source_sha256,
            generated.provenance.source_sha256
        );
        assert_eq!(
            generated.provenance.generated.unwrap().recorded_subject,
            GeneratedSubjectKind::RetainedRelay
        );
    }

    #[test]
    fn a_generated_envelope_with_an_unknown_version_does_not_fall_back_to_raw_ir() {
        let bytes = serde_json::to_vec(&GeneratedScenarioInputV1 {
            schema_version: "99".into(),
            case: GeneratedScenarioCase {
                family_name: "selectable/v1".into(),
                generator_version: "3".into(),
                seed: 42,
                case_index: 7,
                subject: GeneratedSubjectKind::Engine,
                scenario: scenario(),
                expected_outcomes: Vec::new(),
            },
        })
        .unwrap();
        assert_eq!(
            resolve_scenario_input_bytes(&bytes).unwrap_err().code,
            "generated_scenario_input_version"
        );
    }
}
