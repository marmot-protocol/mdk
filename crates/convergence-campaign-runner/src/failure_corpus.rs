use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cgka_conformance_simulator::{
    FailureCapsuleV1, FailureIdentityV1, ScenarioSpec, SubjectFailureCategory,
    TerminalOutcomeClassification, node_protocol::NodeFailureCapsuleV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{DistributedCampaignManifestV1, RunnerError};

pub const FAILURE_CORPUS_SCHEMA_VERSION: &str = "1";
const FAILURE_CORPUS_LOCK_ATTEMPTS: usize = 500;
const FAILURE_CORPUS_LOCK_RETRY: Duration = Duration::from_millis(10);
static PRIVATE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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
    pub promoted_vectors: BTreeSet<PromotedVectorV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_diagnosis_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduction_candidate: Option<AdapterReductionCandidateV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PromotedVectorV1 {
    pub path: PathBuf,
    pub sha256: String,
    pub source_capsule: PathBuf,
    pub source_capsule_sha256: String,
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
        let entry = self.entry_mut(fingerprint)?;
        entry.classification = classification;
        if classification == FailureClassificationV1::EnvironmentFailure {
            entry.reduction_candidate = None;
        }
        Ok(())
    }

    pub fn mark_diagnosed(
        &mut self,
        fingerprint: &str,
        elapsed_seconds: u64,
    ) -> Result<(), RunnerError> {
        let entry = self.entry_mut(fingerprint)?;
        entry.minimum_diagnosis_seconds = Some(
            entry
                .minimum_diagnosis_seconds
                .map_or(elapsed_seconds, |current| current.min(elapsed_seconds)),
        );
        Ok(())
    }

    fn record_promotion(
        &mut self,
        fingerprint: &str,
        promotion: PromotedVectorV1,
    ) -> Result<(), RunnerError> {
        validate_digest(&promotion.sha256, "promoted_vector_digest")?;
        validate_digest(
            &promotion.source_capsule_sha256,
            "promoted_vector_source_digest",
        )?;
        self.entry_mut(fingerprint)?
            .promoted_vectors
            .insert(promotion);
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
    with_failure_corpus_lock(path, || write_failure_corpus_unlocked(path, corpus))
}

pub fn update_failure_corpus<T>(
    path: &Path,
    update: impl FnOnce(&mut FailureCorpusV1) -> Result<T, RunnerError>,
) -> Result<T, RunnerError> {
    with_failure_corpus_lock(path, || {
        let mut corpus = read_failure_corpus(path)?;
        let result = update(&mut corpus)?;
        write_failure_corpus_unlocked(path, &corpus)?;
        Ok(result)
    })
}

fn write_failure_corpus_unlocked(path: &Path, corpus: &FailureCorpusV1) -> Result<(), RunnerError> {
    let bytes = serde_json::to_vec_pretty(corpus)
        .map_err(|error| RunnerError::environment("failure_corpus_serialize", error))?;
    write_private_atomic(path, &bytes, "failure_corpus")
}

fn with_failure_corpus_lock<T>(
    path: &Path,
    operation: impl FnOnce() -> Result<T, RunnerError>,
) -> Result<T, RunnerError> {
    let parent = artifact_parent(path);
    fs_private::create_dir_all_private(parent)
        .map_err(|error| RunnerError::environment("failure_corpus_directory", error))?;

    #[cfg(unix)]
    {
        let file_name = path.file_name().ok_or_else(|| {
            RunnerError::validation(
                "failure_corpus_path",
                "failure corpus path has no file name",
            )
        })?;
        let lock_path = parent.join(format!(".{}.lock", file_name.to_string_lossy()));
        let mut lease = None;
        for _ in 0..FAILURE_CORPUS_LOCK_ATTEMPTS {
            match fs_private::try_acquire_private_exclusive_file_lease(&lock_path) {
                Ok(acquired) => {
                    lease = Some(acquired);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(FAILURE_CORPUS_LOCK_RETRY);
                }
                Err(error) => {
                    return Err(RunnerError::environment("failure_corpus_lock", error));
                }
            }
        }
        let _lease = lease.ok_or_else(|| {
            RunnerError::validation(
                "failure_corpus_lock_timeout",
                "timed out waiting for the failure corpus transaction lock",
            )
        })?;
        operation()
    }

    #[cfg(not(unix))]
    {
        let _ = operation;
        Err(RunnerError::validation(
            "failure_corpus_interprocess_lock_unsupported",
            "failure corpus mutation requires Unix advisory file leases",
        ))
    }
}

fn write_private_atomic(path: &Path, bytes: &[u8], code: &str) -> Result<(), RunnerError> {
    let parent = artifact_parent(path);
    fs_private::create_dir_all_private(parent)
        .map_err(|error| RunnerError::environment(format!("{code}_directory"), error))?;
    let file_name = path.file_name().ok_or_else(|| {
        RunnerError::validation(format!("{code}_path"), "artifact path has no file name")
    })?;
    let temporary = loop {
        let sequence = PRIVATE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{}.tmp.{}.{}",
            file_name.to_string_lossy(),
            std::process::id(),
            sequence
        ));
        match fs_private::create_new_private(&candidate) {
            Ok(mut file) => {
                let write_result = file.write_all(bytes).and_then(|()| file.sync_all());
                if let Err(error) = write_result {
                    drop(file);
                    let _ = std::fs::remove_file(&candidate);
                    return Err(RunnerError::environment(format!("{code}_write"), error));
                }
                drop(file);
                break candidate;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(RunnerError::environment(format!("{code}_write"), error));
            }
        }
    };
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(RunnerError::environment(format!("{code}_replace"), error));
    }
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| RunnerError::environment(format!("{code}_directory_sync"), error))?;
    Ok(())
}

fn write_private_atomic_new(path: &Path, bytes: &[u8], code: &str) -> Result<(), RunnerError> {
    let parent = artifact_parent(path);
    fs_private::create_dir_all_private(parent)
        .map_err(|error| RunnerError::environment(format!("{code}_directory"), error))?;
    let file_name = path.file_name().ok_or_else(|| {
        RunnerError::validation(format!("{code}_path"), "artifact path has no file name")
    })?;
    let temporary = loop {
        let sequence = PRIVATE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{}.tmp.{}.{}",
            file_name.to_string_lossy(),
            std::process::id(),
            sequence
        ));
        match fs_private::create_new_private(&candidate) {
            Ok(mut file) => {
                let write_result = file.write_all(bytes).and_then(|()| file.sync_all());
                if let Err(error) = write_result {
                    drop(file);
                    let _ = std::fs::remove_file(&candidate);
                    return Err(RunnerError::environment(format!("{code}_write"), error));
                }
                drop(file);
                break candidate;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(RunnerError::environment(format!("{code}_write"), error));
            }
        }
    };
    if let Err(error) = std::fs::hard_link(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(RunnerError::validation(
                format!("{code}_exists"),
                "artifact output path already exists",
            ))
        } else {
            Err(RunnerError::environment(format!("{code}_publish"), error))
        };
    }
    if let Err(error) = std::fs::remove_file(&temporary) {
        let _ = std::fs::remove_file(path);
        return Err(RunnerError::environment(
            format!("{code}_temporary_cleanup"),
            error,
        ));
    }
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| RunnerError::environment(format!("{code}_directory_sync"), error))?;
    Ok(())
}

pub fn promote_capsule_into_corpus(
    corpus_path: &Path,
    fingerprint: &str,
    capsule_path: &Path,
    output_path: &Path,
    generator_version: &str,
) -> Result<PromotedVectorV1, RunnerError> {
    validate_fingerprint(fingerprint)?;
    if paths_refer_to_same_artifact(output_path, corpus_path)?
        || paths_refer_to_same_artifact(output_path, capsule_path)?
    {
        return Err(RunnerError::validation(
            "promotion_output_alias",
            "promoted vector output must differ from the corpus and source capsule",
        ));
    }
    let capsule_bytes = std::fs::read(capsule_path)
        .map_err(|error| RunnerError::environment("promotion_capsule_read", error))?;
    let capsule: FailureCapsuleV1 = serde_json::from_slice(&capsule_bytes)
        .map_err(|error| RunnerError::environment("promotion_capsule_parse", error))?;
    capsule
        .validate()
        .map_err(|error| RunnerError::validation("promotion_capsule_invalid", error.to_string()))?;
    if capsule.failure.digest != fingerprint {
        return Err(RunnerError::validation(
            "promotion_capsule_fingerprint_mismatch",
            "source capsule failure digest does not match the selected corpus fingerprint",
        ));
    }
    let vector =
        cgka_conformance_simulator::promote_failure_capsule_to_vector(&capsule, generator_version)
            .map_err(|error| {
                RunnerError::validation("promotion_capsule_ineligible", error.to_string())
            })?;
    let vector_bytes = serde_json::to_vec_pretty(&vector)
        .map_err(|error| RunnerError::environment("promoted_vector_serialize", error))?;
    let promotion = PromotedVectorV1 {
        path: output_path.to_owned(),
        sha256: hex::encode(Sha256::digest(&vector_bytes)),
        source_capsule: capsule_path.to_owned(),
        source_capsule_sha256: hex::encode(Sha256::digest(&capsule_bytes)),
    };
    update_failure_corpus(corpus_path, |corpus| {
        corpus.entry_mut(fingerprint)?;
        for existing in corpus
            .entries
            .values()
            .flat_map(|entry| &entry.promoted_vectors)
        {
            if paths_refer_to_same_artifact(&existing.path, output_path)? {
                return Err(RunnerError::validation(
                    "promoted_vector_path_recorded",
                    "promoted vector output path is already recorded in the corpus",
                ));
            }
        }
        write_private_atomic_new(output_path, &vector_bytes, "promoted_vector")?;
        corpus.record_promotion(fingerprint, promotion.clone())
    })?;
    Ok(promotion)
}

fn paths_refer_to_same_artifact(first: &Path, second: &Path) -> Result<bool, RunnerError> {
    fn resolved(path: &Path) -> std::io::Result<PathBuf> {
        match path.canonicalize() {
            Ok(path) => Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let absolute = if path.is_absolute() {
                    path.to_owned()
                } else {
                    std::env::current_dir()?.join(path)
                };
                let mut cursor = absolute.as_path();
                let mut missing = Vec::new();
                while !cursor.exists() {
                    let component = cursor.file_name().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "artifact path has no existing ancestor",
                        )
                    })?;
                    missing.push(component.to_owned());
                    cursor = cursor.parent().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "artifact path has no parent",
                        )
                    })?;
                }
                let mut resolved = cursor.canonicalize()?;
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                Ok(resolved)
            }
            Err(error) => Err(error),
        }
    }

    resolved(first)
        .and_then(|first| resolved(second).map(|second| first == second))
        .map_err(|error| RunnerError::environment("promotion_path_resolution", error))
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
    // Corpus indexing deliberately prefers the reducer's semantic-identity
    // candidate. This is diagnostic/reduction provenance, not an assertion
    // that the candidate preserves the capsule's full state fingerprint.
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
        classification == FailureClassificationV1::EnvironmentFailure,
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
    let fingerprint = fingerprint_parts(&[
        "node_failure_v1",
        scenario_digest,
        &capsule.participant,
        &capsule.action_id,
        &capsule.code,
    ]);
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
    scenario: &ScenarioSpec,
) -> Result<PathBuf, RunnerError> {
    let path = manifest.output_dir.join("failure-corpus.v1.json");
    let adapter = match &manifest.backend {
        crate::DistributedBackendV1::Container(_) => CampaignAdapterV1::Container,
        crate::DistributedBackendV1::VirtualMachine(_) => CampaignAdapterV1::VirtualMachine,
    };
    let classification = classify_runner_error(error);
    let build_matrix = manifest
        .participants
        .iter()
        .map(|participant| (participant.id.clone(), participant.build_id.clone()))
        .collect();
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
    let failure_identity = FailureIdentityV1 {
        classification: terminal,
        failing_action_type: "distributed_run".into(),
        failure_kind: error.code.clone(),
    };
    let fingerprint = semantic_failure_fingerprint(&manifest.scenario.sha256, &failure_identity);
    let observation = observation_from_scenario_failure(
        fingerprint,
        classification,
        adapter,
        build_matrix,
        scenario.clone(),
        failure_identity,
        classification == FailureClassificationV1::EnvironmentFailure,
    );
    update_failure_corpus(&path, |corpus| corpus.record(observation))?;
    Ok(path)
}

fn classify_runner_error(error: &RunnerError) -> FailureClassificationV1 {
    match error.code.as_str() {
        "expected_resource_refusal" => FailureClassificationV1::ExpectedResourceRefusal,
        "protocol_ambiguity" => FailureClassificationV1::ProtocolAmbiguity,
        // Only errors that unambiguously mean the host could not start the
        // requested program are environmental. Timeouts and non-zero exits can
        // be the product livelock or defect the campaign exists to find.
        "command_spawn" => FailureClassificationV1::EnvironmentFailure,
        _ => FailureClassificationV1::ProductDefect,
    }
}

fn artifact_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn fingerprint_parts(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn semantic_failure_fingerprint(
    scenario_digest: &str,
    failure_identity: &FailureIdentityV1,
) -> String {
    #[derive(Serialize)]
    struct FingerprintMaterial<'a> {
        version: &'static str,
        scenario_digest: &'a str,
        failure_identity: &'a FailureIdentityV1,
    }

    let material = serde_json::to_vec(&FingerprintMaterial {
        version: "semantic_failure_v1",
        scenario_digest,
        failure_identity,
    })
    .expect("serializing semantic failure identity cannot fail");
    hex::encode(Sha256::digest(material))
}

fn validate_digest(digest: &str, code: &str) -> Result<(), RunnerError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(RunnerError::validation(
            code,
            "digest must be a lowercase SHA-256 value",
        ))
    }
}

fn validate_fingerprint(fingerprint: &str) -> Result<(), RunnerError> {
    validate_digest(fingerprint, "failure_fingerprint")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unambiguous_launch_failures_are_environmental() {
        let error = |code: &str| RunnerError {
            code: code.into(),
            message: "omitted".into(),
        };
        assert_eq!(
            classify_runner_error(&error("command_spawn")),
            FailureClassificationV1::EnvironmentFailure
        );
        assert_eq!(
            classify_runner_error(&error("command_timeout")),
            FailureClassificationV1::ProductDefect
        );
        assert_eq!(
            classify_runner_error(&error("command_failed")),
            FailureClassificationV1::ProductDefect
        );
        assert_eq!(
            classify_runner_error(&error("unknown_timeout")),
            FailureClassificationV1::ProductDefect
        );
    }

    #[test]
    fn promotion_provenance_requires_real_digests() {
        let fingerprint = "d".repeat(64);
        let mut corpus = FailureCorpusV1::default();
        corpus
            .record(FailureCorpusObservationV1 {
                fingerprint: fingerprint.clone(),
                classification: FailureClassificationV1::ProductDefect,
                adapter: CampaignAdapterV1::Engine,
                build_matrix: BTreeMap::new(),
                seeds: BTreeSet::new(),
                capsule_paths: BTreeSet::new(),
                reduction_candidate: None,
            })
            .unwrap();
        let error = corpus
            .record_promotion(
                &fingerprint,
                PromotedVectorV1 {
                    path: "vector.json".into(),
                    sha256: "not-a-digest".into(),
                    source_capsule: "capsule.json".into(),
                    source_capsule_sha256: "e".repeat(64),
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "promoted_vector_digest");
        assert!(corpus.entries[&fingerprint].promoted_vectors.is_empty());
    }
}
