//! Versioned incident scenario artifacts and exact normalized-history import.
//!
//! Existing Goggles audit exports usually support an outcome-equivalent
//! archetype, not exact action replay. An exact import is accepted only when a
//! producer supplies a complete normalized Scenario IR history and maps every
//! scenario step back to source audit-event indices. Raw MLS bytes and state
//! checkpoints stay outside this shareable artifact.

use cgka_conformance_simulator::{
    ScenarioSpec, TraceExpectation, VectorFixture, compile_scenario, run_scenario_spec,
};
use serde::{Deserialize, Serialize};

use crate::export::AgentStateExport;
use crate::export::EventKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSourceFormatV1 {
    AgentStateDocument,
    GogglesGroupExportStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentReplayFidelityV1 {
    ExactNormalizedHistory,
    OutcomeEquivalentArchetype,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidenceV1 {
    ExactNormalizedAvailableEvidence,
    DerivedOutcomeEquivalent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnavailableEvidenceV1 {
    pub field: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedActionEvidenceV1 {
    pub step_index: usize,
    pub source_event_indices: Vec<usize>,
}

/// Optional normalized history supplied alongside a forensic export. `complete`
/// means complete for the declared Scenario IR actions, not that unavailable
/// transport bytes or MLS secrets suddenly exist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedScenarioHistoryV1 {
    pub schema_version: String,
    pub complete: bool,
    pub scenario: ScenarioSpec,
    #[serde(default)]
    pub expected_outcomes: Vec<TraceExpectation>,
    #[serde(default)]
    pub action_evidence: Vec<NormalizedActionEvidenceV1>,
    /// Source rows that establish the fork/convergence incident this history
    /// claims to reproduce.
    #[serde(default)]
    pub incident_event_indices: Vec<usize>,
    #[serde(default)]
    pub unavailable_fields: Vec<UnavailableEvidenceV1>,
    /// Shareable exact-history import never embeds a database/OpenMLS
    /// checkpoint. Sensitive state belongs in a local failure capsule.
    #[serde(default)]
    pub sensitive_state_included: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentScenarioArtifactV1 {
    pub schema_version: String,
    pub source_format: IncidentSourceFormatV1,
    pub replay_fidelity: IncidentReplayFidelityV1,
    pub evidence_confidence: EvidenceConfidenceV1,
    pub source_event_count: usize,
    pub incident_event_indices: Vec<usize>,
    pub action_evidence: Vec<NormalizedActionEvidenceV1>,
    pub unavailable_fields: Vec<UnavailableEvidenceV1>,
    pub byte_replay_available: bool,
    pub vector: VectorFixture,
}

#[derive(Debug, thiserror::Error)]
pub enum ExactHistoryImportError {
    #[error("normalized scenario history uses unsupported schema `{0}`")]
    UnsupportedSchema(String),
    #[error("normalized scenario history is marked incomplete")]
    Incomplete,
    #[error("normalized scenario history includes sensitive state")]
    SensitiveStateIncluded,
    #[error("normalized scenario history has no semantic expected outcomes")]
    MissingExpectedOutcomes,
    #[error("normalized scenario history has no Scenario IR actions")]
    EmptyScenario,
    #[error("normalized scenario history does not identify a contested incident source event")]
    MissingIncidentEvidence,
    #[error("normalized scenario history does not map every Scenario IR step exactly once")]
    IncompleteActionEvidence,
    #[error("normalized scenario history references source event {index}, but only {count} exist")]
    SourceEventOutOfRange { index: usize, count: usize },
    #[error("normalized Scenario IR failed validation: {0}")]
    InvalidScenario(String),
    #[error("the simulator could not run exact normalized history: {0}")]
    Run(String),
    #[error("exact normalized history did not reproduce its recorded outcomes")]
    NotReproduced,
}

/// Import exact normalized Scenario IR when the export carries sufficient
/// evidence. `Ok(None)` is the ordinary legacy-export case and should fall
/// back to archetype synthesis with explicit unavailable fields.
pub fn import_exact_history(
    export: &AgentStateExport,
    source_format: IncidentSourceFormatV1,
) -> Result<Option<IncidentScenarioArtifactV1>, ExactHistoryImportError> {
    let Some(history) = export.normalized_scenario_history.as_ref() else {
        return Ok(None);
    };
    if history.schema_version != "1" {
        return Err(ExactHistoryImportError::UnsupportedSchema(
            history.schema_version.clone(),
        ));
    }
    if !history.complete {
        return Err(ExactHistoryImportError::Incomplete);
    }
    if history.sensitive_state_included {
        return Err(ExactHistoryImportError::SensitiveStateIncluded);
    }
    if history.expected_outcomes.is_empty() {
        return Err(ExactHistoryImportError::MissingExpectedOutcomes);
    }
    if history.scenario.steps.is_empty() {
        return Err(ExactHistoryImportError::EmptyScenario);
    }
    validate_action_evidence(history, export)?;
    compile_scenario(&history.scenario)
        .map_err(|error| ExactHistoryImportError::InvalidScenario(error.to_string()))?;

    let unavailable_fields = with_byte_replay_unavailable(history.unavailable_fields.clone());
    Ok(Some(IncidentScenarioArtifactV1 {
        schema_version: "1".into(),
        source_format,
        replay_fidelity: IncidentReplayFidelityV1::ExactNormalizedHistory,
        evidence_confidence: EvidenceConfidenceV1::ExactNormalizedAvailableEvidence,
        source_event_count: export.events.len(),
        incident_event_indices: history.incident_event_indices.clone(),
        action_evidence: history.action_evidence.clone(),
        unavailable_fields,
        byte_replay_available: false,
        vector: VectorFixture {
            scenario_name: history.scenario.name.clone(),
            vector_version: "1".into(),
            conformance_version: env!("CARGO_PKG_VERSION").into(),
            seed: None,
            application_profile: None,
            scenario: history.scenario.clone(),
            expected_trace: None,
            expected_outcomes: history.expected_outcomes.clone(),
        },
    }))
}

pub fn archetype_artifact(
    export: &AgentStateExport,
    source_format: IncidentSourceFormatV1,
    vector: VectorFixture,
) -> IncidentScenarioArtifactV1 {
    IncidentScenarioArtifactV1 {
        schema_version: "1".into(),
        source_format,
        replay_fidelity: IncidentReplayFidelityV1::OutcomeEquivalentArchetype,
        evidence_confidence: EvidenceConfidenceV1::DerivedOutcomeEquivalent,
        source_event_count: export.events.len(),
        incident_event_indices: incident_event_indices(export),
        action_evidence: Vec::new(),
        unavailable_fields: vec![
            unavailable(
                "exact_scenario_action_history",
                "the forensic export does not map audit observations to a complete Scenario IR action sequence",
            ),
            unavailable(
                "exact_transport_delivery_order",
                "audit observations do not prove the complete relay delivery schedule seen by every participant",
            ),
            unavailable(
                "raw_mls_transport_bytes",
                "the normalized forensic export intentionally carries no replayable MLS ciphertext",
            ),
            unavailable(
                "mls_state_checkpoint",
                "byte replay requires a separately captured sensitive local engine checkpoint",
            ),
        ],
        byte_replay_available: false,
        vector,
    }
}

pub fn accept_exact_history(
    artifact: IncidentScenarioArtifactV1,
) -> Result<IncidentScenarioArtifactV1, ExactHistoryImportError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|error| ExactHistoryImportError::Run(error.to_string()))?;
    let trace = runtime
        .block_on(run_scenario_spec(&artifact.vector.scenario))
        .map_err(|error| ExactHistoryImportError::Run(error.to_string()))?;
    if artifact.vector.compare_observed_trace(&trace).is_empty() {
        Ok(artifact)
    } else {
        Err(ExactHistoryImportError::NotReproduced)
    }
}

fn validate_action_evidence(
    history: &NormalizedScenarioHistoryV1,
    export: &AgentStateExport,
) -> Result<(), ExactHistoryImportError> {
    let source_event_count = export.events.len();
    let mut mapped = history
        .action_evidence
        .iter()
        .map(|evidence| evidence.step_index)
        .collect::<Vec<_>>();
    mapped.sort_unstable();
    if mapped != (0..history.scenario.steps.len()).collect::<Vec<_>>()
        || history
            .action_evidence
            .iter()
            .any(|evidence| evidence.source_event_indices.is_empty())
    {
        return Err(ExactHistoryImportError::IncompleteActionEvidence);
    }
    if let Some(index) = history
        .action_evidence
        .iter()
        .flat_map(|evidence| &evidence.source_event_indices)
        .copied()
        .find(|index| *index >= source_event_count)
    {
        return Err(ExactHistoryImportError::SourceEventOutOfRange {
            index,
            count: source_event_count,
        });
    }
    if history.incident_event_indices.is_empty()
        || history.incident_event_indices.iter().any(|index| {
            export
                .events
                .get(*index)
                .is_none_or(|event| !is_incident_event(&event.kind))
        })
    {
        return Err(ExactHistoryImportError::MissingIncidentEvidence);
    }
    Ok(())
}

fn incident_event_indices(export: &AgentStateExport) -> Vec<usize> {
    export
        .events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| is_incident_event(&event.kind).then_some(index))
        .collect()
}

fn is_incident_event(kind: &EventKind) -> bool {
    kind.is_fork_resolution() || kind.is_contested_convergence()
}

fn with_byte_replay_unavailable(
    mut unavailable_fields: Vec<UnavailableEvidenceV1>,
) -> Vec<UnavailableEvidenceV1> {
    for evidence in [
        unavailable(
            "raw_mls_transport_bytes",
            "exact normalized action replay is semantic; the shareable artifact contains no MLS ciphertext",
        ),
        unavailable(
            "mls_state_checkpoint",
            "byte replay requires a separately captured sensitive local engine checkpoint",
        ),
    ] {
        if !unavailable_fields
            .iter()
            .any(|existing| existing.field == evidence.field)
        {
            unavailable_fields.push(evidence);
        }
    }
    unavailable_fields
}

fn unavailable(field: &str, reason: &str) -> UnavailableEvidenceV1 {
    UnavailableEvidenceV1 {
        field: field.into(),
        reason: reason.into(),
    }
}
