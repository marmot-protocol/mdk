use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use cgka_conformance_simulator::{
    FailureCapsuleV1, FailureIdentityV1, ScenarioSpec, SubjectFailureCategory,
    TerminalOutcomeClassification, node_protocol::NodeFailureCapsuleV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{DistributedCampaignManifestV1, RunnerError};

pub const FAILURE_CORPUS_SCHEMA_VERSION: &str = "1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClassificationV1 {
    ProductDefect,
    ProtocolAmbiguity,
    EnvironmentFailure,
    ExpectedResourceRefusal,
}

impl FromStr for FailureClassificationV1 {
    type Err = RunnerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "product_defect" => Ok(Self::ProductDefect),
            "protocol_ambiguity" => Ok(Self::ProtocolAmbiguity),
            "environment_failure" => Ok(Self::EnvironmentFailure),
            "expected_resource_refusal" => Ok(Self::ExpectedResourceRefusal),
            _ => Err(RunnerError::validation(
                "failure_classification",
                "classification must be product_defect, protocol_ambiguity, environment_failure, or expected_resource_refusal",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignAdapterV1 {
    Engine,
    AppRuntime,
    Process,
    Container,
    VirtualMachine,
}

impl FromStr for CampaignAdapterV1 {
    type Err = RunnerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "engine" => Ok(Self::Engine),
            "app_runtime" => Ok(Self::AppRuntime),
            "process" => Ok(Self::Process),
            "container" => Ok(Self::Container),
            "virtual_machine" | "vm" => Ok(Self::VirtualMachine),
            _ => Err(RunnerError::validation(
                "campaign_adapter",
                "adapter must be engine, app_runtime, process, container, or virtual_machine",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterReductionCandidateV1 {
    pub source_adapter: CampaignAdapterV1,
    pub target_adapter: CampaignAdapterV1,
    pub failure_identity: FailureIdentityV1,
    pub scenario: ScenarioSpec,
    pub reducer: String,
}

pub fn build_adapter_reduction_candidate(
    source_adapter: CampaignAdapterV1,
    layer_specific: bool,
    scenario: ScenarioSpec,
    failure_identity: FailureIdentityV1,
) -> Option<AdapterReductionCandidateV1> {
    if layer_specific {
        return None;
    }
    let target_adapter = match source_adapter {
        CampaignAdapterV1::VirtualMachine => CampaignAdapterV1::Container,
        CampaignAdapterV1::Container => CampaignAdapterV1::Process,
        CampaignAdapterV1::Process => CampaignAdapterV1::AppRuntime,
        CampaignAdapterV1::AppRuntime => CampaignAdapterV1::Engine,
        CampaignAdapterV1::Engine => return None,
    };
    Some(AdapterReductionCandidateV1 {
        source_adapter,
        target_adapter,
        failure_identity,
        scenario,
        reducer: "scenario_ir_dependency_units_v1".into(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureCorpusObservationV1 {
    pub fingerprint: String,
    pub classification: FailureClassificationV1,
    pub adapter: CampaignAdapterV1,
    pub build_matrix: BTreeMap<String, String>,
    #[serde(default)]
    pub seeds: BTreeSet<u64>,
    #[serde(default)]
    pub capsule_paths: BTreeSet<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduction_candidate: Option<AdapterReductionCandidateV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureCorpusEntryV1 {
    pub fingerprint: String,
    pub classification: FailureClassificationV1,
    pub adapters: BTreeSet<CampaignAdapterV1>,
    pub build_matrices: Vec<BTreeMap<String, String>>,
    pub first_seen_sequence: u64,
    pub last_seen_sequence: u64,
    pub recurrence_count: u64,
    #[serde(default)]
    pub seeds: BTreeSet<u64>,
    #[serde(default)]
    pub capsule_paths: BTreeSet<PathBuf>,
    #[serde(default)]
    pub promoted_vectors: BTreeSet<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_diagnosis_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduction_candidate: Option<AdapterReductionCandidateV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureCorpusV1 {
    pub schema_version: String,
    pub next_sequence: u64,
    pub entries: BTreeMap<String, FailureCorpusEntryV1>,
}

impl Default for FailureCorpusV1 {
    fn default() -> Self {
        Self {
            schema_version: FAILURE_CORPUS_SCHEMA_VERSION.into(),
            next_sequence: 1,
            entries: BTreeMap::new(),
        }
    }
}

impl FailureCorpusV1 {
    pub fn record(&mut self, observation: FailureCorpusObservationV1) -> Result<(), RunnerError> {
        validate_fingerprint(&observation.fingerprint)?;
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let entry = self
            .entries
            .entry(observation.fingerprint.clone())
            .or_insert_with(|| FailureCorpusEntryV1 {
                fingerprint: observation.fingerprint.clone(),
                classification: observation.classification,
                adapters: BTreeSet::new(),
                build_matrices: Vec::new(),
                first_seen_sequence: sequence,
                last_seen_sequence: sequence,
                recurrence_count: 0,
                seeds: BTreeSet::new(),
                capsule_paths: BTreeSet::new(),
                promoted_vectors: BTreeSet::new(),
                minimum_diagnosis_seconds: None,
                reduction_candidate: observation.reduction_candidate.clone(),
            });
        entry.last_seen_sequence = sequence;
        entry.recurrence_count = entry.recurrence_count.saturating_add(1);
        entry.adapters.insert(observation.adapter);
        if !entry.build_matrices.contains(&observation.build_matrix) {
            entry.build_matrices.push(observation.build_matrix);
        }
        entry.seeds.extend(observation.seeds);
        entry.capsule_paths.extend(observation.capsule_paths);
        if entry.reduction_candidate.is_none() {
            entry.reduction_candidate = observation.reduction_candidate;
        }
        Ok(())
    }

    pub fn reclassify(
        &mut self,
        fingerprint: &str,
        classification: FailureClassificationV1,
    ) -> Result<(), RunnerError> {
        self.entry_mut(fingerprint)?.classification = classification;
        Ok(())
    }

    pub fn mark_diagnosed(
        &mut self,
        fingerprint: &str,
        elapsed_seconds: u64,
        promoted_vector: Option<PathBuf>,
    ) -> Result<(), RunnerError> {
        let entry = self.entry_mut(fingerprint)?;
        entry.minimum_diagnosis_seconds = Some(
            entry
                .minimum_diagnosis_seconds
                .map_or(elapsed_seconds, |current| current.min(elapsed_seconds)),
        );
        if let Some(vector) = promoted_vector {
            entry.promoted_vectors.insert(vector);
        }
        Ok(())
    }

    fn entry_mut(&mut self, fingerprint: &str) -> Result<&mut FailureCorpusEntryV1, RunnerError> {
        self.entries.get_mut(fingerprint).ok_or_else(|| {
            RunnerError::validation(
                "unknown_failure_fingerprint",
                "failure is not in the corpus",
            )
        })
    }
}

pub fn read_failure_corpus(path: &Path) -> Result<FailureCorpusV1, RunnerError> {
    if !path.exists() {
        return Ok(FailureCorpusV1::default());
    }
    let corpus: FailureCorpusV1 = serde_json::from_slice(
        &std::fs::read(path)
            .map_err(|error| RunnerError::environment("failure_corpus_read", error))?,
    )
    .map_err(|error| RunnerError::environment("failure_corpus_parse", error))?;
    if corpus.schema_version != FAILURE_CORPUS_SCHEMA_VERSION {
        return Err(RunnerError::validation(
            "failure_corpus_version",
            "unsupported failure corpus schema version",
        ));
    }
    Ok(corpus)
}

pub fn write_failure_corpus(path: &Path, corpus: &FailureCorpusV1) -> Result<(), RunnerError> {
    if let Some(parent) = path.parent() {
        fs_private::create_dir_all_private(parent)
            .map_err(|error| RunnerError::environment("failure_corpus_directory", error))?;
    }
    let bytes = serde_json::to_vec_pretty(corpus)
        .map_err(|error| RunnerError::environment("failure_corpus_serialize", error))?;
    fs_private::write_private(path, &bytes)
        .map_err(|error| RunnerError::environment("failure_corpus_write", error))
}

pub fn observation_from_capsule(
    capsule: &FailureCapsuleV1,
    capsule_path: PathBuf,
    adapter: CampaignAdapterV1,
    build_matrix: BTreeMap<String, String>,
) -> FailureCorpusObservationV1 {
    let classification = match capsule.failure.classification {
        TerminalOutcomeClassification::EnvironmentFailure => {
            FailureClassificationV1::EnvironmentFailure
        }
        _ => FailureClassificationV1::ProductDefect,
    };
    let scenario = capsule
        .minimized_reproducer
        .clone()
        .unwrap_or_else(|| capsule.report.scenario.clone());
    let mut observation = observation_from_scenario_failure(
        capsule.failure.digest.clone(),
        classification,
        adapter,
        build_matrix,
        scenario,
        capsule.failure.semantic_identity(),
        false,
    );
    observation.seeds = capsule.seeds.values().copied().collect();
    observation.capsule_paths.insert(capsule_path);
    observation
}

pub fn observation_from_node_capsule(
    capsule: &NodeFailureCapsuleV1,
    capsule_path: PathBuf,
    scenario: ScenarioSpec,
    scenario_digest: &str,
    build_matrix: BTreeMap<String, String>,
) -> FailureCorpusObservationV1 {
    let classification = if capsule.category == SubjectFailureCategory::Environment {
        FailureClassificationV1::EnvironmentFailure
    } else {
        FailureClassificationV1::ProductDefect
    };
    let fingerprint = hex::encode(Sha256::digest(
        format!(
            "{scenario_digest}:{}:{}:{}",
            capsule.participant, capsule.action_id, capsule.code
        )
        .as_bytes(),
    ));
    let terminal = if classification == FailureClassificationV1::EnvironmentFailure {
        TerminalOutcomeClassification::EnvironmentFailure
    } else {
        TerminalOutcomeClassification::OracleViolation
    };
    let mut observation = observation_from_scenario_failure(
        fingerprint,
        classification,
        CampaignAdapterV1::Process,
        build_matrix,
        scenario,
        FailureIdentityV1 {
            classification: terminal,
            failing_action_type: capsule
                .action_id
                .split_once(':')
                .map_or(capsule.action_id.clone(), |(_, kind)| kind.into()),
            failure_kind: capsule.code.clone(),
        },
        classification == FailureClassificationV1::EnvironmentFailure,
    );
    observation.capsule_paths.insert(capsule_path);
    observation
}

#[allow(clippy::too_many_arguments)]
pub fn observation_from_scenario_failure(
    fingerprint: String,
    classification: FailureClassificationV1,
    adapter: CampaignAdapterV1,
    build_matrix: BTreeMap<String, String>,
    scenario: ScenarioSpec,
    failure_identity: FailureIdentityV1,
    layer_specific: bool,
) -> FailureCorpusObservationV1 {
    FailureCorpusObservationV1 {
        fingerprint,
        classification,
        adapter,
        build_matrix,
        seeds: BTreeSet::new(),
        capsule_paths: BTreeSet::new(),
        reduction_candidate: build_adapter_reduction_candidate(
            adapter,
            layer_specific,
            scenario,
            failure_identity,
        ),
    }
}

pub fn record_distributed_failure(
    manifest: &DistributedCampaignManifestV1,
    error: &RunnerError,
) -> Result<PathBuf, RunnerError> {
    let path = manifest.output_dir.join("failure-corpus.v1.json");
    let mut corpus = read_failure_corpus(&path)?;
    let adapter = match &manifest.backend {
        crate::DistributedBackendV1::Container(_) => CampaignAdapterV1::Container,
        crate::DistributedBackendV1::VirtualMachine(_) => CampaignAdapterV1::VirtualMachine,
    };
    let classification = classify_runner_error(error);
    let fingerprint = hex::encode(Sha256::digest(
        format!("{}:{}:{adapter:?}", manifest.scenario.sha256, error.code).as_bytes(),
    ));
    let build_matrix = manifest
        .participants
        .iter()
        .map(|participant| (participant.id.clone(), participant.build_id.clone()))
        .collect();
    let scenario: ScenarioSpec = serde_json::from_slice(
        &std::fs::read(&manifest.scenario.path)
            .map_err(|read_error| RunnerError::environment("failure_scenario_read", read_error))?,
    )
    .map_err(|parse_error| RunnerError::environment("failure_scenario_parse", parse_error))?;
    let terminal = match classification {
        FailureClassificationV1::EnvironmentFailure => {
            TerminalOutcomeClassification::EnvironmentFailure
        }
        FailureClassificationV1::ExpectedResourceRefusal => {
            TerminalOutcomeClassification::ResourceFailure
        }
        FailureClassificationV1::ProductDefect | FailureClassificationV1::ProtocolAmbiguity => {
            TerminalOutcomeClassification::OracleViolation
        }
    };
    corpus.record(observation_from_scenario_failure(
        fingerprint,
        classification,
        adapter,
        build_matrix,
        scenario,
        FailureIdentityV1 {
            classification: terminal,
            failing_action_type: "distributed_run".into(),
            failure_kind: error.code.clone(),
        },
        classification == FailureClassificationV1::EnvironmentFailure,
    ))?;
    write_failure_corpus(&path, &corpus)?;
    Ok(path)
}

fn classify_runner_error(error: &RunnerError) -> FailureClassificationV1 {
    if error.code == "expected_resource_refusal" {
        FailureClassificationV1::ExpectedResourceRefusal
    } else if error.code == "protocol_ambiguity" {
        FailureClassificationV1::ProtocolAmbiguity
    } else if error.code.contains("spawn")
        || error.code.contains("timeout")
        || error.code.starts_with("output_")
        || error.code.starts_with("command_")
        || error.code.starts_with("vm_")
    {
        FailureClassificationV1::EnvironmentFailure
    } else {
        FailureClassificationV1::ProductDefect
    }
}

fn validate_fingerprint(fingerprint: &str) -> Result<(), RunnerError> {
    if fingerprint.len() == 64
        && fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(RunnerError::validation(
            "failure_fingerprint",
            "failure fingerprint must be a lowercase SHA-256 value",
        ))
    }
}
