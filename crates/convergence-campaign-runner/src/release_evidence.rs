use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use cgka_conformance_simulator::process_orchestrator::ProcessScenarioReportV1;
use cgka_conformance_simulator::{
    canonical_scenario_ir_sha256, cross_route_app_runtime_recovery_public_scenario,
    resolve_scenario_input_bytes, validate_cross_route_public_process_report,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CampaignBudgetEvaluationV1, CampaignLaneConfigV1, CampaignLaneObservationV1,
    CampaignLaneStepObservationV1, CampaignLaneV1, ContainerBackendV1, ConvergenceEvidenceBundleV1,
    DistributedBackendV1, DistributedCampaignManifestV1, DistributedParticipantV1,
    DistributedRunReceiptV1, EvidenceArtifactV1, OciRuntimeV1, RunnerError, ScenarioArtifactV1,
    TestedBoundaryV1, load_manifest, verify_manifest_inputs,
};

/// Version of the human-reviewed claim document consumed by release evidence assembly.
pub const CONVERGENCE_EVIDENCE_CLAIM_VERSION: &str = "1";

const RELEASE_CAMPAIGN_ID: &str = "cross-route-mixed-build-v1";
const RELEASE_SCENARIO_FILE: &str = "canonical-scenario.json";
const RELEASE_MANIFEST_FILE: &str = "distributed-manifest.v1.json";
const RELEASE_OUTPUT_DIR: &str = "campaign-output";
const REQUIRED_RELEASE_STEPS: &[&str] = &[
    "distributed-image-build",
    "baseline-image-build",
    "release-hardening-core",
];

/// Reviewable assurance language and declared coverage, separate from runtime evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceEvidenceClaimV1 {
    pub schema_version: String,
    pub lane: CampaignLaneV1,
    pub campaign_id: String,
    pub scenario_name: String,
    pub canonical_ir_sha256: String,
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
}

/// Privacy-safe result of validating raw scenario and process evidence before bundling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEvidenceVerificationV1 {
    pub schema_version: String,
    pub campaign_id: String,
    pub scenario_name: String,
    pub canonical_ir_sha256: String,
    pub source_revision: String,
    pub participant_build_ids: Vec<String>,
    pub participant_image_ids: Vec<String>,
    pub selected_scenario_bytes_sha256: String,
    pub process_report_sha256: String,
    pub public_process_oracle_passed: bool,
}

impl ConvergenceEvidenceClaimV1 {
    /// Validate that the claim is scoped, complete, and pinned to one canonical scenario.
    pub fn validate(&self) -> Result<(), RunnerError> {
        if self.schema_version != CONVERGENCE_EVIDENCE_CLAIM_VERSION {
            return Err(RunnerError::validation(
                "evidence_claim_version",
                "unsupported convergence evidence claim version",
            ));
        }
        if self.lane != CampaignLaneV1::ReleaseHardening {
            return Err(RunnerError::validation(
                "evidence_claim_lane",
                "release evidence claims must select the release_hardening lane",
            ));
        }
        for (name, empty) in [
            ("campaign_id", self.campaign_id.is_empty()),
            ("scenario_name", self.scenario_name.is_empty()),
            ("assurance_claim", self.assurance_claim.is_empty()),
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
                    "incomplete_evidence_claim",
                    format!("evidence claim is missing {name}"),
                ));
            }
        }
        validate_lower_hex_digest("claim canonical IR", &self.canonical_ir_sha256)
    }
}

/// Materialize the shared four-party route scenario and a mixed-image container manifest.
///
/// Both source revisions must be exact lowercase Git object ids and both images must be
/// distinct local content-addressed image ids (`sha256:<64 lowercase hex>`).
pub fn materialize_release_campaign(
    output_root: &Path,
    current_revision: &str,
    current_image: &str,
    baseline_revision: &str,
    baseline_image: &str,
) -> Result<PathBuf, RunnerError> {
    validate_source_revision(current_revision)?;
    validate_source_revision(baseline_revision)?;
    validate_local_image_id(current_image)?;
    validate_local_image_id(baseline_image)?;
    if current_revision == baseline_revision {
        return Err(RunnerError::validation(
            "release_build_revisions",
            "release hardening requires two distinct source revisions",
        ));
    }
    if current_image == baseline_image {
        return Err(RunnerError::validation(
            "release_build_images",
            "release hardening requires two distinct content-addressed images",
        ));
    }
    if output_root.exists() {
        return Err(RunnerError::validation(
            "release_input_exists",
            "release campaign input directory must not already exist",
        ));
    }

    fs_private::create_dir_all_private(output_root)
        .map_err(|error| RunnerError::environment("release_input_directory", error))?;
    let scenario = cross_route_app_runtime_recovery_public_scenario();
    let scenario_bytes = serde_json::to_vec_pretty(&scenario)
        .map_err(|error| RunnerError::environment("release_scenario_serialize", error))?;
    let scenario_path = output_root.join(RELEASE_SCENARIO_FILE);
    fs_private::write_private(&scenario_path, &scenario_bytes)
        .map_err(|error| RunnerError::environment("release_scenario_write", error))?;
    let canonical_ir_sha256 = canonical_scenario_ir_sha256(&scenario)
        .map_err(|error| RunnerError::validation("release_scenario_digest", error.to_string()))?;

    let participants = scenario
        .clients
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let (build_id, image) = if index % 2 == 0 {
                (current_revision, current_image)
            } else {
                (baseline_revision, baseline_image)
            };
            DistributedParticipantV1 {
                id: id.clone(),
                build_id: build_id.into(),
                container_image: Some(image.into()),
            }
        })
        .collect();
    let manifest = DistributedCampaignManifestV1 {
        schema_version: "1".into(),
        campaign_id: RELEASE_CAMPAIGN_ID.into(),
        scenario: ScenarioArtifactV1 {
            path: scenario_path,
            sha256: hex::encode(Sha256::digest(&scenario_bytes)),
            canonical_ir_sha256: Some(canonical_ir_sha256),
        },
        participants,
        backend: DistributedBackendV1::Container(ContainerBackendV1 {
            runtime: OciRuntimeV1::Docker,
            namespace: "marmot-release-cross-route".into(),
            allow_mutable_image_references: false,
            allow_cleartext_isolated_relay: true,
            enable_retained_relay_control: true,
            default_participant_image: current_image.into(),
            relay_image: current_image.into(),
            relay_command: vec![
                "cgka-conformance-relay".into(),
                "--bind".into(),
                "0.0.0.0:8080".into(),
            ],
            node_command: vec!["cgka-conformance-node".into()],
        }),
        faults: Vec::new(),
        output_dir: output_root.join(RELEASE_OUTPUT_DIR),
    };
    manifest.validate_mixed_builds()?;
    let manifest_path = output_root.join(RELEASE_MANIFEST_FILE);
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| RunnerError::environment("release_manifest_serialize", error))?;
    fs_private::write_private(&manifest_path, &manifest_bytes)
        .map_err(|error| RunnerError::environment("release_manifest_write", error))?;
    Ok(manifest_path)
}

/// Validate one completed mixed-build release run and assemble a byte-pinned bundle.
pub fn assemble_release_evidence(
    claim_path: &Path,
    source_revision: &str,
    manifest_path: &Path,
    observation_path: &Path,
    budget_path: &Path,
    step_dir: &Path,
    output_path: &Path,
) -> Result<ConvergenceEvidenceBundleV1, RunnerError> {
    validate_source_revision(source_revision)?;
    if output_path.exists() {
        return Err(RunnerError::validation(
            "evidence_output_exists",
            "release evidence output must not already exist",
        ));
    }

    let claim: ConvergenceEvidenceClaimV1 = read_json(claim_path, "evidence_claim")?;
    claim.validate()?;
    let manifest = load_manifest(manifest_path)?;
    manifest.validate_mixed_builds()?;
    if manifest.campaign_id != claim.campaign_id {
        return Err(RunnerError::validation(
            "evidence_campaign_identity",
            "claim and distributed manifest campaign ids differ",
        ));
    }
    let build_ids = manifest
        .participants
        .iter()
        .map(|participant| participant.build_id.as_str())
        .collect::<BTreeSet<_>>();
    if !build_ids.contains(source_revision) {
        return Err(RunnerError::validation(
            "evidence_source_revision",
            "source revision is not one of the executed participant builds",
        ));
    }

    let scenario_bytes = verify_manifest_inputs(&manifest)?;
    let selected = resolve_scenario_input_bytes(&scenario_bytes)
        .map_err(|error| RunnerError::validation("evidence_scenario", error.to_string()))?;
    if selected.scenario != cross_route_app_runtime_recovery_public_scenario()
        || selected.scenario.name != claim.scenario_name
        || selected.provenance.canonical_ir_sha256 != claim.canonical_ir_sha256
    {
        return Err(RunnerError::validation(
            "evidence_scenario_identity",
            "release evidence claim does not match the selected canonical cross-route scenario",
        ));
    }

    let normalized_path = manifest.output_dir.join("normalized-manifest.json");
    let normalized: DistributedCampaignManifestV1 =
        read_json(&normalized_path, "evidence_normalized_manifest")?;
    let mut expected_normalized = manifest.clone();
    expected_normalized.scenario.canonical_ir_sha256 =
        Some(selected.provenance.canonical_ir_sha256.clone());
    if normalized != expected_normalized {
        return Err(RunnerError::validation(
            "evidence_normalized_manifest",
            "executed normalized manifest differs from the selected release manifest",
        ));
    }

    let receipt_path = manifest.output_dir.join("distributed-run.json");
    let receipt: DistributedRunReceiptV1 = read_json(&receipt_path, "evidence_run_receipt")?;
    let process_report_path = manifest.output_dir.join("process-report.json");
    if !receipt.completed
        || receipt.campaign_id != manifest.campaign_id
        || receipt.backend != "container"
        || !receipt.cleanup_failures.is_empty()
        || receipt.command_receipts.is_empty()
        || receipt
            .command_receipts
            .iter()
            .any(|command| !command.accepted)
        || receipt.process_report.as_deref() != Some(process_report_path.as_path())
    {
        return Err(RunnerError::validation(
            "evidence_run_receipt",
            "distributed run receipt is incomplete or inconsistent",
        ));
    }
    let process_report: ProcessScenarioReportV1 =
        read_json(&process_report_path, "evidence_process_report")?;
    validate_cross_route_public_process_report(&selected.scenario, &process_report)
        .map_err(|error| RunnerError::validation("evidence_public_oracle", error))?;
    let DistributedBackendV1::Container(container) = &manifest.backend else {
        return Err(RunnerError::validation(
            "evidence_backend",
            "release evidence assembly requires a container campaign",
        ));
    };
    let participant_image_ids = manifest
        .participants
        .iter()
        .map(|participant| {
            participant
                .container_image
                .as_deref()
                .unwrap_or(&container.default_participant_image)
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let verification = ReleaseEvidenceVerificationV1 {
        schema_version: "1".into(),
        campaign_id: manifest.campaign_id.clone(),
        scenario_name: selected.scenario.name.clone(),
        canonical_ir_sha256: selected.provenance.canonical_ir_sha256.clone(),
        source_revision: source_revision.into(),
        participant_build_ids: build_ids.into_iter().map(str::to_owned).collect(),
        participant_image_ids: participant_image_ids.into_iter().collect(),
        selected_scenario_bytes_sha256: digest_regular_file(&manifest.scenario.path)?,
        process_report_sha256: digest_regular_file(&process_report_path)?,
        public_process_oracle_passed: true,
    };

    let observation: CampaignLaneObservationV1 =
        read_json(observation_path, "evidence_observation")?;
    let budget: CampaignBudgetEvaluationV1 = read_json(budget_path, "evidence_budget")?;
    let expected_budget = CampaignLaneConfigV1::builtin(CampaignLaneV1::ReleaseHardening)
        .evaluate(observation.clone());
    if !expected_budget.passed || budget != expected_budget {
        return Err(RunnerError::validation(
            "evidence_budget",
            "release budget evidence must equal a recomputed passing evaluation",
        ));
    }
    let step_records = read_release_step_records(step_dir)?;

    let bundle_dir = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs_private::create_dir_all_private(bundle_dir)
        .map_err(|error| RunnerError::environment("evidence_bundle_directory", error))?;
    let artifact_dir = bundle_dir.join("artifacts");
    if artifact_dir.exists() {
        return Err(RunnerError::validation(
            "evidence_artifact_directory_exists",
            "release evidence artifact directory must not already exist",
        ));
    }
    fs_private::create_dir_all_private(&artifact_dir)
        .map_err(|error| RunnerError::environment("evidence_artifact_directory", error))?;

    let mut sources = vec![
        ("reviewed_claim".to_owned(), claim_path.to_path_buf()),
        ("selected_manifest".to_owned(), manifest_path.to_path_buf()),
        ("normalized_manifest".to_owned(), normalized_path),
        ("distributed_run".to_owned(), receipt_path),
        (
            "lane_observation".to_owned(),
            observation_path.to_path_buf(),
        ),
        ("budget_evaluation".to_owned(), budget_path.to_path_buf()),
    ];
    sources.extend(step_records.into_iter().map(|(name, path)| {
        (
            format!("step_observation_{}", sanitize_artifact_kind(&name)),
            path,
        )
    }));
    let mut artifacts = Vec::with_capacity(sources.len() + 1);
    artifacts.push(write_json_artifact_private(
        &artifact_dir,
        bundle_dir,
        "public_oracle_verification",
        &verification,
    )?);
    for (kind, source) in sources {
        artifacts.push(copy_artifact_private(
            &artifact_dir,
            bundle_dir,
            &kind,
            &source,
        )?);
    }

    let bundle = ConvergenceEvidenceBundleV1 {
        schema_version: "1".into(),
        lane: claim.lane,
        source_revision: source_revision.into(),
        assurance_claim: claim.assurance_claim,
        covered_decision_routes: claim.covered_decision_routes,
        models: claim.models,
        adapters: claim.adapters,
        mutation_results: claim.mutation_results,
        tested_boundaries: claim.tested_boundaries,
        unresolved_counterexamples: claim.unresolved_counterexamples,
        residual_assumptions: claim.residual_assumptions,
        untested_surfaces: claim.untested_surfaces,
        budget,
        artifacts,
    };
    bundle.write_private(output_path)?;
    Ok(bundle)
}

fn write_json_artifact_private<T: Serialize>(
    artifact_dir: &Path,
    bundle_dir: &Path,
    kind: &str,
    value: &T,
) -> Result<EvidenceArtifactV1, RunnerError> {
    validate_artifact_kind(kind)?;
    let destination = artifact_dir.join(format!("{kind}.json"));
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| RunnerError::environment("evidence_artifact_serialize", error))?;
    let mut output = fs_private::create_new_private(&destination)
        .map_err(|error| RunnerError::environment("evidence_artifact_write", error))?;
    output
        .write_all(&bytes)
        .and_then(|()| output.flush())
        .and_then(|()| output.sync_all())
        .map_err(|error| RunnerError::environment("evidence_artifact_write", error))?;
    evidence_artifact_from_destination(bundle_dir, kind, &destination)
}

fn read_release_step_records(step_dir: &Path) -> Result<Vec<(String, PathBuf)>, RunnerError> {
    let mut paths = std::fs::read_dir(step_dir)
        .map_err(|error| RunnerError::environment("evidence_step_directory", error))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| RunnerError::environment("evidence_step_directory", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    let mut records = Vec::new();
    let mut names = BTreeSet::new();
    for path in paths {
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let record: CampaignLaneStepObservationV1 = read_json(&path, "evidence_step")?;
        record.validate()?;
        if !record.succeeded() {
            return Err(RunnerError::validation(
                "evidence_step_failed",
                "release evidence cannot include a failed observed step",
            ));
        }
        if !names.insert(record.name.clone()) {
            return Err(RunnerError::validation(
                "evidence_step_duplicate",
                "release evidence contains duplicate step names",
            ));
        }
        records.push((record.name, path));
    }
    if REQUIRED_RELEASE_STEPS
        .iter()
        .any(|required| !names.contains(*required))
    {
        return Err(RunnerError::validation(
            "evidence_step_missing",
            "release evidence is missing a required observed step",
        ));
    }
    Ok(records)
}

fn copy_artifact_private(
    artifact_dir: &Path,
    bundle_dir: &Path,
    kind: &str,
    source: &Path,
) -> Result<EvidenceArtifactV1, RunnerError> {
    validate_artifact_kind(kind)?;
    let destination = artifact_dir.join(format!("{kind}.json"));
    let mut input = open_regular_no_follow(source, "evidence_artifact_read")?;
    let mut output = fs_private::create_new_private(&destination)
        .map_err(|error| RunnerError::environment("evidence_artifact_write", error))?;
    std::io::copy(&mut input, &mut output)
        .map_err(|error| RunnerError::environment("evidence_artifact_write", error))?;
    output
        .flush()
        .and_then(|()| output.sync_all())
        .map_err(|error| RunnerError::environment("evidence_artifact_write", error))?;
    evidence_artifact_from_destination(bundle_dir, kind, &destination)
}

fn evidence_artifact_from_destination(
    bundle_dir: &Path,
    kind: &str,
    destination: &Path,
) -> Result<EvidenceArtifactV1, RunnerError> {
    let sha256 = digest_regular_file(destination)?;
    let path = destination
        .strip_prefix(bundle_dir)
        .map_err(|_| {
            RunnerError::validation(
                "evidence_artifact_path",
                "assembled artifact escaped the evidence bundle directory",
            )
        })?
        .to_path_buf();
    Ok(EvidenceArtifactV1 {
        kind: kind.into(),
        path,
        sha256,
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, code: &str) -> Result<T, RunnerError> {
    let mut file = open_regular_no_follow(path, code)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| RunnerError::environment(code, error))?;
    serde_json::from_slice(&bytes).map_err(|error| RunnerError::environment(code, error))
}

fn digest_regular_file(path: &Path) -> Result<String, RunnerError> {
    let mut file = open_regular_no_follow(path, "evidence_artifact_digest")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| RunnerError::environment("evidence_artifact_digest", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn open_regular_no_follow(path: &Path, code: &str) -> Result<std::fs::File, RunnerError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|error| RunnerError::environment(code, error))?;
    if !file
        .metadata()
        .map_err(|error| RunnerError::environment(code, error))?
        .file_type()
        .is_file()
    {
        return Err(RunnerError::validation(
            code,
            "release evidence inputs must be regular files",
        ));
    }
    Ok(file)
}

fn validate_source_revision(value: &str) -> Result<(), RunnerError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RunnerError::validation(
            "release_source_revision",
            "release source revisions must be exact 40-character lowercase hexadecimal Git object ids",
        ));
    }
    Ok(())
}

fn validate_local_image_id(value: &str) -> Result<(), RunnerError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(RunnerError::validation(
            "release_image_id",
            "release materialization requires a local content-addressed sha256 image id",
        ));
    };
    validate_lower_hex_digest("release image", digest)
}

fn validate_lower_hex_digest(name: &str, value: &str) -> Result<(), RunnerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RunnerError::validation(
            "evidence_digest",
            format!("{name} digest must be 64 lowercase hexadecimal characters"),
        ));
    }
    Ok(())
}

fn sanitize_artifact_kind(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || byte == b'_' {
                char::from(byte.to_ascii_lowercase())
            } else {
                '_'
            }
        })
        .collect()
}

fn validate_artifact_kind(value: &str) -> Result<(), RunnerError> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(RunnerError::validation(
            "evidence_artifact_kind",
            "evidence artifact kinds must use 1-96 lowercase snake-case characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_conformance_simulator::mutation_adequacy::SemanticMutation;

    const CURRENT_REVISION: &str = "1111111111111111111111111111111111111111";
    const BASELINE_REVISION: &str = "2222222222222222222222222222222222222222";
    const CURRENT_IMAGE: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BASELINE_IMAGE: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn release_materialization_pins_two_revisions_images_and_the_shared_scenario() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("release-inputs");
        let manifest_path = materialize_release_campaign(
            &output,
            CURRENT_REVISION,
            CURRENT_IMAGE,
            BASELINE_REVISION,
            BASELINE_IMAGE,
        )
        .unwrap();
        let manifest = load_manifest(&manifest_path).unwrap();
        manifest.validate_mixed_builds().unwrap();
        assert_eq!(manifest.campaign_id, RELEASE_CAMPAIGN_ID);
        assert_eq!(
            manifest
                .participants
                .iter()
                .map(|participant| participant.build_id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([CURRENT_REVISION, BASELINE_REVISION])
        );
        assert_eq!(
            manifest
                .participants
                .iter()
                .filter_map(|participant| participant.container_image.as_deref())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([CURRENT_IMAGE, BASELINE_IMAGE])
        );
        let selected =
            resolve_scenario_input_bytes(&verify_manifest_inputs(&manifest).unwrap()).unwrap();
        assert_eq!(
            selected.scenario,
            cross_route_app_runtime_recovery_public_scenario()
        );
        assert_eq!(
            selected.provenance.canonical_ir_sha256,
            manifest.scenario.canonical_ir_sha256.unwrap()
        );

        #[cfg(unix)]
        for path in [manifest_path, manifest.scenario.path] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn release_materialization_rejects_non_distinct_or_mutable_inputs() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("release-inputs");
        assert_eq!(
            materialize_release_campaign(
                &output,
                CURRENT_REVISION,
                CURRENT_IMAGE,
                CURRENT_REVISION,
                BASELINE_IMAGE,
            )
            .unwrap_err()
            .code,
            "release_build_revisions"
        );
        assert_eq!(
            materialize_release_campaign(
                &output,
                CURRENT_REVISION,
                "marmot-conformance:latest",
                BASELINE_REVISION,
                BASELINE_IMAGE,
            )
            .unwrap_err()
            .code,
            "release_image_id"
        );
    }

    #[test]
    fn reviewed_release_claim_pins_the_scenario_and_complete_mutation_catalog() {
        let claim: ConvergenceEvidenceClaimV1 = serde_json::from_str(include_str!(
            "../release-claims/cross-route-mixed-build.v1.json"
        ))
        .unwrap();
        claim.validate().unwrap();
        let scenario = cross_route_app_runtime_recovery_public_scenario();
        assert_eq!(claim.campaign_id, RELEASE_CAMPAIGN_ID);
        assert_eq!(claim.scenario_name, scenario.name);
        assert_eq!(
            claim.canonical_ir_sha256,
            canonical_scenario_ir_sha256(&scenario).unwrap()
        );
        assert_eq!(
            claim
                .mutation_results
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            SemanticMutation::ALL
                .iter()
                .map(|mutation| mutation.id())
                .collect::<BTreeSet<_>>()
        );
        assert!(claim.mutation_results.values().all(|killed| *killed));
    }

    #[test]
    fn artifact_copy_is_private_digest_pinned_and_refuses_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let bundle = root.path().join("bundle");
        let artifacts = bundle.join("artifacts");
        fs_private::create_dir_all_private(&artifacts).unwrap();
        let source = root.path().join("source.json");
        fs_private::write_private(&source, b"{\"ok\":true}").unwrap();
        let artifact = copy_artifact_private(&artifacts, &bundle, "report", &source).unwrap();
        assert_eq!(artifact.path, Path::new("artifacts/report.json"));
        assert_eq!(
            artifact.sha256,
            hex::encode(Sha256::digest(b"{\"ok\":true}"))
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            let copied = bundle.join(&artifact.path);
            assert_eq!(
                std::fs::metadata(copied).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let link = root.path().join("source-link.json");
            symlink(&source, &link).unwrap();
            assert!(copy_artifact_private(&artifacts, &bundle, "linked", &link).is_err());
        }
    }

    #[test]
    fn release_step_evidence_requires_every_successful_named_boundary() {
        let root = tempfile::tempdir().unwrap();
        for name in REQUIRED_RELEASE_STEPS {
            successful_step(name)
                .write_private(&root.path().join(format!("{name}.json")))
                .unwrap();
        }
        assert_eq!(read_release_step_records(root.path()).unwrap().len(), 3);

        std::fs::remove_file(root.path().join("baseline-image-build.json")).unwrap();
        assert_eq!(
            read_release_step_records(root.path()).unwrap_err().code,
            "evidence_step_missing"
        );
        let mut failed = successful_step("baseline-image-build");
        failed.exit_code = Some(1);
        failed
            .write_private(&root.path().join("baseline-image-build.json"))
            .unwrap();
        assert_eq!(
            read_release_step_records(root.path()).unwrap_err().code,
            "evidence_step_failed"
        );
    }

    fn successful_step(name: &str) -> CampaignLaneStepObservationV1 {
        CampaignLaneStepObservationV1 {
            schema_version: "1".into(),
            name: name.into(),
            wall_clock_us: 1,
            user_cpu_us: Some(1),
            system_cpu_us: Some(1),
            peak_rss_bytes: Some(1),
            filesystem_block_write_lower_bound_bytes: Some(0),
            executed_cases: 0,
            flaky_cases: 0,
            flake_retries: 0,
            exit_code: Some(0),
            signal: None,
            unavailable_process_fields: Vec::new(),
        }
    }
}
