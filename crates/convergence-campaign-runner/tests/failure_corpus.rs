use std::collections::{BTreeMap, BTreeSet};

use cgka_conformance_simulator::{
    FailureIdentityV1, ScenarioSpec, ScenarioTopologyV2, TerminalOutcomeClassification,
};
use convergence_campaign_runner::{
    CampaignAdapterV1, ContainerBackendV1, DistributedBackendV1, DistributedCampaignManifestV1,
    DistributedParticipantV1, FailureClassificationV1, FailureCorpusObservationV1, FailureCorpusV1,
    OciRuntimeV1, RunnerError, ScenarioArtifactV1, build_adapter_reduction_candidate,
    read_failure_corpus, record_distributed_failure, write_failure_corpus,
};
use sha2::Digest;

fn observation(fingerprint: &str, adapter: CampaignAdapterV1) -> FailureCorpusObservationV1 {
    FailureCorpusObservationV1 {
        fingerprint: fingerprint.into(),
        classification: FailureClassificationV1::ProductDefect,
        adapter,
        build_matrix: BTreeMap::from([("alice".into(), "revision-a".into())]),
        seeds: BTreeSet::from([7]),
        capsule_paths: BTreeSet::from(["failure-7.json".into()]),
        reduction_candidate: None,
    }
}

#[test]
fn recurrence_classification_diagnosis_and_promotion_are_durable() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("failure-corpus.v1.json");
    let fingerprint = "a".repeat(64);
    let mut corpus = FailureCorpusV1::default();
    corpus
        .record(observation(&fingerprint, CampaignAdapterV1::Process))
        .unwrap();
    corpus
        .record(observation(&fingerprint, CampaignAdapterV1::Container))
        .unwrap();
    corpus
        .reclassify(&fingerprint, FailureClassificationV1::ProtocolAmbiguity)
        .unwrap();
    corpus
        .mark_diagnosed(&fingerprint, 900, Some("vectors/regression.v1.json".into()))
        .unwrap();
    corpus.mark_diagnosed(&fingerprint, 600, None).unwrap();
    write_failure_corpus(&path, &corpus).unwrap();

    let persisted = read_failure_corpus(&path).unwrap();
    let entry = &persisted.entries[&fingerprint];
    assert_eq!(entry.recurrence_count, 2);
    assert_eq!(entry.first_seen_sequence, 1);
    assert_eq!(entry.last_seen_sequence, 2);
    assert_eq!(entry.minimum_diagnosis_seconds, Some(600));
    assert_eq!(
        entry.classification,
        FailureClassificationV1::ProtocolAmbiguity
    );
    assert_eq!(entry.adapters.len(), 2);
    assert!(
        entry
            .promoted_vectors
            .contains(std::path::Path::new("vectors/regression.v1.json"))
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn non_layer_specific_failures_move_to_the_next_smaller_adapter() {
    let scenario = ScenarioSpec {
        name: "reduction/v1".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into(), "bob".into()],
        topology: ScenarioTopologyV2::default(),
        steps: Vec::new(),
    };
    let identity = FailureIdentityV1 {
        classification: TerminalOutcomeClassification::OracleViolation,
        failing_action_type: "observe_exact".into(),
        failure_kind: "state_mismatch".into(),
    };
    let candidate = build_adapter_reduction_candidate(
        CampaignAdapterV1::Container,
        false,
        scenario.clone(),
        identity.clone(),
    )
    .unwrap();
    assert_eq!(candidate.target_adapter, CampaignAdapterV1::Process);
    assert_eq!(candidate.scenario, scenario);
    assert_eq!(candidate.failure_identity, identity);
    assert!(
        build_adapter_reduction_candidate(
            CampaignAdapterV1::Container,
            true,
            candidate.scenario,
            candidate.failure_identity,
        )
        .is_none()
    );
}

#[test]
fn distributed_product_failures_are_saved_with_a_process_reduction_candidate() {
    let root = tempfile::tempdir().unwrap();
    let scenario = ScenarioSpec {
        name: "distributed-failure/v1".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into(), "bob".into()],
        topology: ScenarioTopologyV2::default(),
        steps: Vec::new(),
    };
    let scenario_path = root.path().join("scenario.json");
    let bytes = serde_json::to_vec(&scenario).unwrap();
    fs_private::write_private(&scenario_path, &bytes).unwrap();
    let manifest = DistributedCampaignManifestV1 {
        schema_version: "1".into(),
        campaign_id: "distributed-failure-v1".into(),
        scenario: ScenarioArtifactV1 {
            path: scenario_path,
            sha256: hex::encode(sha2::Sha256::digest(&bytes)),
        },
        participants: ["alice", "bob"]
            .into_iter()
            .map(|id| DistributedParticipantV1 {
                id: id.into(),
                build_id: "revision-a".into(),
                container_image: None,
            })
            .collect(),
        backend: DistributedBackendV1::Container(ContainerBackendV1 {
            runtime: OciRuntimeV1::Docker,
            namespace: "failure-test".into(),
            default_participant_image: "current".into(),
            relay_image: "current".into(),
            relay_command: vec!["relay".into()],
            node_command: vec!["node".into()],
        }),
        faults: Vec::new(),
        output_dir: root.path().join("output"),
    };
    let path = record_distributed_failure(
        &manifest,
        &RunnerError {
            code: "container_scenario".into(),
            message: "not persisted".into(),
        },
    )
    .unwrap();
    let corpus = read_failure_corpus(&path).unwrap();
    let entry = corpus.entries.values().next().unwrap();
    assert_eq!(entry.classification, FailureClassificationV1::ProductDefect);
    assert_eq!(
        entry.reduction_candidate.as_ref().unwrap().target_adapter,
        CampaignAdapterV1::Process
    );
    assert!(
        !std::fs::read_to_string(path)
            .unwrap()
            .contains("not persisted")
    );
}
