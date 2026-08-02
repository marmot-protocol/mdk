//! Versioned, replayable failure artifacts for convergence reliability runs.
//!
//! A capsule keeps logical scenario/report evidence separate from the opaque
//! cryptographic checkpoint required for byte-exact MLS replay. Checkpoints are
//! always sensitive local evidence and must be written with owner-only modes.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use cgka_engine::ManualConvergenceClock;
use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::GroupId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ClientBuilder, ConformanceConstantSnapshot, HarnessStorageMode, QuiescencePolicy,
    QuiescenceStatus, ScenarioReport, ScenarioSpec, ScenarioStep, ScenarioStepStatus,
    SubjectDescriptor, TransportBus, conformance_constant_snapshot,
};

pub const FAILURE_CAPSULE_SCHEMA_VERSION: &str = "1";
pub const FAILURE_FINGERPRINT_VERSION: &str = "1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCapsuleSensitivity {
    SyntheticShareable,
    SensitiveLocal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcomeClassification {
    Converged,
    ExpectedRefusal,
    RetryableBlock,
    TerminalProtocolFailure,
    ResourceFailure,
    EnvironmentFailure,
    Timeout,
    OracleViolation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureFingerprintV1 {
    pub version: String,
    pub digest: String,
    pub classification: TerminalOutcomeClassification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_failing_action_id: Option<String>,
    pub failure_kind: String,
    pub normalized_state_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpandedScenarioActionV1 {
    pub action_id: String,
    pub step_index: usize,
    pub action_type: String,
    /// Virtual monotonic time immediately before this action executes.
    pub virtual_time_ms: u64,
    /// `None` means execution stopped before this planned action.
    pub status: Option<ScenarioStepStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedTransportArtifactV1 {
    pub sequence: u64,
    pub sender: String,
    pub message: TransportMessage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsulePolicySnapshotV1 {
    pub canonicalization: CanonicalizationPolicy,
    /// Exact policies selected by each `await_quiescence` action.
    pub quiescence_by_action: BTreeMap<String, QuiescencePolicy>,
    pub engine_constants: ConformanceConstantSnapshot,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceObservationV1 {
    pub counters: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineByteReplayV1 {
    pub client_label: String,
    /// Exact seed passed to `ClientBuilder`; this is not a secret for synthetic
    /// runs but is still carried only by a sensitive capsule with the checkpoint.
    pub identity_seed: Vec<u8>,
    pub protocol_profile: ProtocolProfile,
    pub group_id: Vec<u8>,
    /// Opaque serialized SQLite/OpenMLS group checkpoint. Contains key material.
    pub sensitive_checkpoint: Vec<u8>,
    pub captured_deliveries: Vec<TransportMessage>,
    pub checkpoint_monotonic_ms: u64,
    pub checkpoint_wall_ms: u64,
    /// Whether the original harness tick used the injected clock rather than
    /// the legacy far-future settlement shortcut.
    pub virtual_time_tick_enabled: bool,
    pub failure_kind: String,
    pub failing_action_id: String,
    pub expected_fingerprint: FailureFingerprintV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineByteReplayObservationV1 {
    pub client_label: String,
    pub epoch: u64,
    pub normalized_state_digest: String,
    pub fingerprint: FailureFingerprintV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureCapsuleV1 {
    pub schema_version: String,
    pub sensitivity: FailureCapsuleSensitivity,
    pub original_scenario: ScenarioSpec,
    pub canonical_scenario: ScenarioSpec,
    /// Stable named seeds/indices needed to reconstruct generated schedules.
    pub seeds: BTreeMap<String, u64>,
    pub expanded_schedule: Vec<ExpandedScenarioActionV1>,
    pub adapter: Option<SubjectDescriptor>,
    pub binary_version: String,
    pub policy: CapsulePolicySnapshotV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub captured_transport_artifacts: Vec<CapturedTransportArtifactV1>,
    pub report: ScenarioReport,
    pub resources: ResourceObservationV1,
    pub failure: FailureFingerprintV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_replay: Option<EngineByteReplayV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimized_reproducer: Option<ScenarioSpec>,
}

#[derive(Debug)]
pub enum FailureCapsuleError {
    NoFailure,
    SensitiveNotPortable,
    MissingPortableExpectation,
    InvalidVersion(String),
    ReplayFingerprintMismatch { expected: String, actual: String },
    Io(std::io::Error),
    Json(serde_json::Error),
    Replay(String),
}

impl fmt::Display for FailureCapsuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFailure => f.write_str("cannot create a failure capsule from a passing report"),
            Self::SensitiveNotPortable => {
                f.write_str("sensitive failure capsules cannot be promoted to portable vectors")
            }
            Self::MissingPortableExpectation => f.write_str(
                "failure capsule has no intended exact or semantic expectation to preserve",
            ),
            Self::InvalidVersion(version) => {
                write!(f, "unsupported failure capsule version {version}")
            }
            Self::ReplayFingerprintMismatch { expected, actual } => write!(
                f,
                "byte replay fingerprint mismatch: expected {expected}, got {actual}"
            ),
            Self::Io(error) => write!(f, "failure capsule I/O: {error}"),
            Self::Json(error) => write!(f, "failure capsule JSON: {error}"),
            Self::Replay(error) => write!(f, "failure capsule replay: {error}"),
        }
    }
}

impl Error for FailureCapsuleError {}

impl From<std::io::Error> for FailureCapsuleError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for FailureCapsuleError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl FailureCapsuleV1 {
    pub fn from_report(
        report: ScenarioReport,
        sensitivity: FailureCapsuleSensitivity,
        captured_transport_artifacts: Vec<CapturedTransportArtifactV1>,
        byte_replay: Option<EngineByteReplayV1>,
    ) -> Result<Self, FailureCapsuleError> {
        let failure = fingerprint_report_failure(&report)?;
        let mut virtual_time_ms = 0_u64;
        let expanded_schedule = report
            .scenario
            .steps
            .iter()
            .enumerate()
            .map(|(step_index, step)| {
                let action = ExpandedScenarioActionV1 {
                    action_id: format!("step-{step_index}:{}", step.kind()),
                    step_index,
                    action_type: step.kind().into(),
                    virtual_time_ms,
                    status: report
                        .step_log
                        .iter()
                        .find(|entry| entry.step_index == step_index)
                        .map(|entry| entry.status.clone()),
                };
                if let ScenarioStep::AdvanceTime { delta_ms } = step {
                    virtual_time_ms = virtual_time_ms.saturating_add(*delta_ms);
                }
                action
            })
            .collect();
        let quiescence_by_action = report
            .scenario
            .steps
            .iter()
            .enumerate()
            .filter_map(|(step_index, step)| match step {
                ScenarioStep::AwaitQuiescence { policy } => {
                    Some((format!("step-{step_index}:{}", step.kind()), policy.clone()))
                }
                _ => None,
            })
            .collect();
        let minimized_reproducer = report
            .metadata
            .generated
            .as_ref()
            .and_then(|generated| generated.minimized_case.clone());
        let seeds = report
            .metadata
            .generated
            .as_ref()
            .map(|generated| {
                BTreeMap::from([
                    ("generator_seed".into(), generated.seed),
                    ("case_index".into(), generated.case_index),
                ])
            })
            .unwrap_or_default();
        Ok(Self {
            schema_version: FAILURE_CAPSULE_SCHEMA_VERSION.into(),
            sensitivity,
            original_scenario: report.scenario.clone(),
            canonical_scenario: report.scenario.clone(),
            seeds,
            expanded_schedule,
            adapter: report.metadata.subject.clone(),
            binary_version: env!("CARGO_PKG_VERSION").into(),
            policy: CapsulePolicySnapshotV1 {
                canonicalization: CanonicalizationPolicy::default(),
                quiescence_by_action,
                engine_constants: conformance_constant_snapshot(),
            },
            resources: resource_observations(&report, &captured_transport_artifacts),
            captured_transport_artifacts,
            report,
            failure,
            byte_replay,
            minimized_reproducer,
        })
    }

    pub fn validate(&self) -> Result<(), FailureCapsuleError> {
        if self.schema_version != FAILURE_CAPSULE_SCHEMA_VERSION {
            return Err(FailureCapsuleError::InvalidVersion(
                self.schema_version.clone(),
            ));
        }
        if self.byte_replay.is_some()
            && self.sensitivity != FailureCapsuleSensitivity::SensitiveLocal
        {
            return Err(FailureCapsuleError::Replay(
                "byte replay checkpoints require sensitive_local classification".into(),
            ));
        }
        let report_fingerprint = fingerprint_report_failure(&self.report)?;
        if report_fingerprint != self.failure {
            return Err(FailureCapsuleError::Replay(
                "failure fingerprint does not match the captured report".into(),
            ));
        }
        if let Some(replay) = &self.byte_replay {
            let expected = build_fingerprint(
                replay.expected_fingerprint.classification,
                Some(replay.failing_action_id.clone()),
                replay.failure_kind.clone(),
                replay.expected_fingerprint.normalized_state_digest.clone(),
            );
            if expected != replay.expected_fingerprint {
                return Err(FailureCapsuleError::Replay(
                    "engine byte-replay fingerprint is internally inconsistent".into(),
                ));
            }
        }
        Ok(())
    }
}

pub fn write_failure_capsule(
    path: &Path,
    capsule: &FailureCapsuleV1,
) -> Result<(), FailureCapsuleError> {
    capsule.validate()?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        #[cfg(unix)]
        let _parent_guard = fs_private::prepare_directory_path(
            parent,
            fs_private::PRIVATE_DIR_MODE,
            fs_private::ExistingDirectoryMode::Preserve,
        )?;
        #[cfg(not(unix))]
        fs_private::create_dir_all_private(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(capsule)?;
    fs_private::write_private(path, &bytes)?;
    Ok(())
}

pub fn read_failure_capsule(path: &Path) -> Result<FailureCapsuleV1, FailureCapsuleError> {
    let capsule: FailureCapsuleV1 = serde_json::from_slice(&std::fs::read(path)?)?;
    capsule.validate()?;
    Ok(capsule)
}

/// Convert a reviewed synthetic failure into a portable regression-vector
/// candidate. Sensitive incident capsules are intentionally ineligible.
pub fn promote_failure_capsule_to_vector(
    capsule: &FailureCapsuleV1,
    conformance_version: impl Into<String>,
) -> Result<crate::VectorFixture, FailureCapsuleError> {
    capsule.validate()?;
    if capsule.sensitivity != FailureCapsuleSensitivity::SyntheticShareable {
        return Err(FailureCapsuleError::SensitiveNotPortable);
    }
    let scenario = capsule
        .minimized_reproducer
        .clone()
        .unwrap_or_else(|| capsule.canonical_scenario.clone());
    if capsule.report.expected_trace.is_none() && capsule.report.expected_outcomes.is_empty() {
        return Err(FailureCapsuleError::MissingPortableExpectation);
    }
    let mut expected_trace = capsule.report.expected_trace.clone();
    if let Some(expected_trace) = &mut expected_trace {
        expected_trace.name = scenario.name.clone();
    }
    Ok(crate::VectorFixture {
        scenario_name: scenario.name.clone(),
        vector_version: "1".into(),
        conformance_version: conformance_version.into(),
        seed: capsule
            .report
            .metadata
            .generated
            .as_ref()
            .map(|generated| generated.seed),
        application_profile: None,
        scenario,
        expected_trace,
        expected_outcomes: capsule.report.expected_outcomes.clone(),
    })
}

pub fn fingerprint_report_failure(
    report: &ScenarioReport,
) -> Result<FailureFingerprintV1, FailureCapsuleError> {
    let failed_step_evidence = report
        .step_log
        .iter()
        .filter_map(|step| match &step.status {
            ScenarioStepStatus::Completed => None,
            ScenarioStepStatus::Failed { kind, message } => Some((
                step.step_index,
                step.step_type.as_str(),
                kind.as_str(),
                message.as_str(),
            )),
        })
        .collect::<Vec<_>>();
    let normalized_state_digest = digest_json(&(
        &report.observed_trace,
        &report.quiescence_observations,
        &report.pending_resolution_observations,
        &report.epoch_change_observations,
        &report.app_invalidation_observations,
        failed_step_evidence,
    ))?;

    let failed_step = report.step_log.iter().find_map(|step| match &step.status {
        ScenarioStepStatus::Failed { kind, .. } => Some((
            TerminalOutcomeClassification::EnvironmentFailure,
            format!("step-{}:{}", step.step_index, step.step_type),
            format!("scenario_step_failed:{kind}"),
        )),
        ScenarioStepStatus::Completed => None,
    });
    let quiescence =
        report
            .quiescence_observations
            .iter()
            .find_map(|observation| match &observation.status {
                QuiescenceStatus::Quiescent => None,
                QuiescenceStatus::Blocked { .. } => Some((
                    if observation.final_progress.terminal_blockers.is_empty() {
                        TerminalOutcomeClassification::RetryableBlock
                    } else {
                        TerminalOutcomeClassification::TerminalProtocolFailure
                    },
                    format!("step-{}:await_quiescence", observation.step_index),
                    "quiescence_blocked".to_string(),
                )),
                QuiescenceStatus::TimedOut { .. } => Some((
                    TerminalOutcomeClassification::Timeout,
                    format!("step-{}:await_quiescence", observation.step_index),
                    "quiescence_timeout".to_string(),
                )),
            });
    let oracle = report
        .expectation_failures
        .first()
        .map(|failure| {
            (
                TerminalOutcomeClassification::OracleViolation,
                "oracle".to_string(),
                failure.kind.clone(),
            )
        })
        .or_else(|| {
            report.invariant_failures.first().map(|failure| {
                (
                    TerminalOutcomeClassification::OracleViolation,
                    "oracle".to_string(),
                    failure.kind.clone(),
                )
            })
        })
        .or_else(|| {
            report
                .oracle
                .missing_observed_behaviors
                .first()
                .map(|behavior| {
                    (
                        TerminalOutcomeClassification::OracleViolation,
                        "oracle".to_string(),
                        format!("missing_observed_behavior:{behavior:?}"),
                    )
                })
        })
        .or_else(|| {
            report.oracle.weak_oracle_warnings.first().map(|warning| {
                (
                    TerminalOutcomeClassification::OracleViolation,
                    "oracle".to_string(),
                    format!("weak_oracle_warning:{:?}", warning.stimulus),
                )
            })
        });
    let (classification, action_id, failure_kind) = failed_step
        .or(quiescence)
        .or(oracle)
        .ok_or(FailureCapsuleError::NoFailure)?;
    Ok(build_fingerprint(
        classification,
        Some(action_id),
        failure_kind,
        normalized_state_digest,
    ))
}

pub async fn replay_engine_bytes(
    replay: &EngineByteReplayV1,
) -> Result<EngineByteReplayObservationV1, FailureCapsuleError> {
    let bus = TransportBus::ordered();
    let clock =
        ManualConvergenceClock::new(replay.checkpoint_monotonic_ms, replay.checkpoint_wall_ms);
    let mut client = ClientBuilder::new(replay.identity_seed.clone())
        .registry(crate::subject::scenario_registry())
        .protocol_profile(replay.protocol_profile)
        .storage_mode(HarnessStorageMode::InMemorySqlite)
        .convergence_clock(Arc::new(clock))
        .attach(&bus);
    let group_id = GroupId::new(replay.group_id.clone());
    client
        .restore_conformance_replay_checkpoint(&group_id, &replay.sensitive_checkpoint)
        .map_err(|error| FailureCapsuleError::Replay(error.to_string()))?;
    if replay.virtual_time_tick_enabled {
        client.enable_virtual_time_tick();
    }
    for message in &replay.captured_deliveries {
        client.inject_captured_transport(message.clone());
    }
    let outcomes = client.tick().await;
    if let Some(error) = outcomes.into_iter().find_map(Result::err) {
        return Err(FailureCapsuleError::Replay(error.to_string()));
    }
    let canonical_state = client.canonical_state_snapshot();
    let normalized_state_digest = digest_json(&canonical_state)?;
    let fingerprint = build_fingerprint(
        replay.expected_fingerprint.classification,
        Some(replay.failing_action_id.clone()),
        replay.failure_kind.clone(),
        normalized_state_digest.clone(),
    );
    if fingerprint.digest != replay.expected_fingerprint.digest {
        return Err(FailureCapsuleError::ReplayFingerprintMismatch {
            expected: replay.expected_fingerprint.digest.clone(),
            actual: fingerprint.digest,
        });
    }
    Ok(EngineByteReplayObservationV1 {
        client_label: replay.client_label.clone(),
        epoch: client.epoch().0,
        normalized_state_digest,
        fingerprint,
    })
}

pub fn build_fingerprint(
    classification: TerminalOutcomeClassification,
    first_failing_action_id: Option<String>,
    failure_kind: String,
    normalized_state_digest: String,
) -> FailureFingerprintV1 {
    let material = serde_json::to_vec(&(
        FAILURE_FINGERPRINT_VERSION,
        classification,
        &first_failing_action_id,
        &failure_kind,
        &normalized_state_digest,
    ))
    .expect("failure fingerprint material serializes");
    FailureFingerprintV1 {
        version: FAILURE_FINGERPRINT_VERSION.into(),
        digest: hex::encode(Sha256::digest(material)),
        classification,
        first_failing_action_id,
        failure_kind,
        normalized_state_digest,
    }
}

pub fn digest_json(value: &impl Serialize) -> Result<String, FailureCapsuleError> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn resource_observations(
    report: &ScenarioReport,
    captured_transport_artifacts: &[CapturedTransportArtifactV1],
) -> ResourceObservationV1 {
    let mut counters = BTreeMap::new();
    counters.insert(
        "planned_scenario_steps".into(),
        report.scenario.steps.len() as u64,
    );
    counters.insert(
        "executed_scenario_steps".into(),
        report.step_log.len() as u64,
    );
    counters.insert(
        "observed_clients".into(),
        report
            .observed_trace
            .as_ref()
            .map_or(0, |trace| trace.observations.len()) as u64,
    );
    counters.insert(
        "expectation_failures".into(),
        report.expectation_failures.len() as u64,
    );
    counters.insert(
        "invariant_failures".into(),
        report.invariant_failures.len() as u64,
    );
    counters.insert(
        "quiescence_iterations".into(),
        report
            .quiescence_observations
            .iter()
            .map(|observation| observation.iterations as u64)
            .sum(),
    );
    counters.insert(
        "captured_transport_objects".into(),
        captured_transport_artifacts.len() as u64,
    );
    counters.insert(
        "captured_transport_json_bytes".into(),
        captured_transport_artifacts
            .iter()
            .map(|artifact| {
                serde_json::to_vec(&artifact.message).map_or(0, |bytes| bytes.len() as u64)
            })
            .sum(),
    );
    ResourceObservationV1 { counters }
}
