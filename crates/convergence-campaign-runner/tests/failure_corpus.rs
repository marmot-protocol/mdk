use std::collections::{BTreeMap, BTreeSet};

use cgka_conformance_simulator::{
    FailureCapsuleSensitivity, FailureCapsuleV1, FailureIdentityV1, ScenarioSpec,
    ScenarioStepLogEntry, ScenarioStepStatus, ScenarioTopologyV2, SubjectFailureCategory,
    TerminalOutcomeClassification, TraceExpectation, VectorMismatch,
    node_protocol::{NodeErrorV1, NodeFailureCapsuleV1},
    run_scenario_report, write_failure_capsule,
};
use convergence_campaign_runner::{
    CampaignAdapterV1, ContainerBackendV1, DistributedBackendV1, DistributedCampaignManifestV1,
    DistributedParticipantV1, FailureClassificationV1, FailureCorpusObservationV1, FailureCorpusV1,
    OciRuntimeV1, RunnerError, ScenarioArtifactV1, VirtualMachineBackendV1,
    build_adapter_reduction_candidate, observation_from_capsule, observation_from_node_capsule,
    promote_capsule_into_corpus, read_failure_corpus, record_distributed_failure,
    update_failure_corpus, write_failure_corpus,
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
fn recurrence_classification_and_diagnosis_are_durable() {
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
    corpus.mark_diagnosed(&fingerprint, 900).unwrap();
    corpus.mark_diagnosed(&fingerprint, 600).unwrap();
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
    assert!(entry.promoted_vectors.is_empty());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(root.path().join(".failure-corpus.v1.json.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
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
fn environmental_reclassification_clears_cross_adapter_reduction() {
    let fingerprint = "e".repeat(64);
    let scenario = ScenarioSpec {
        name: "reclassified-environment/v1".into(),
        spec_version: "2".into(),
        clients: Vec::new(),
        topology: ScenarioTopologyV2::default(),
        steps: Vec::new(),
    };
    let mut corpus = FailureCorpusV1::default();
    corpus
        .record(FailureCorpusObservationV1 {
            fingerprint: fingerprint.clone(),
            classification: FailureClassificationV1::ProductDefect,
            adapter: CampaignAdapterV1::Process,
            build_matrix: BTreeMap::new(),
            seeds: BTreeSet::new(),
            capsule_paths: BTreeSet::new(),
            reduction_candidate: build_adapter_reduction_candidate(
                CampaignAdapterV1::Process,
                false,
                scenario,
                FailureIdentityV1 {
                    classification: TerminalOutcomeClassification::OracleViolation,
                    failing_action_type: "tick".into(),
                    failure_kind: "timeout".into(),
                },
            ),
        })
        .unwrap();
    assert!(corpus.entries[&fingerprint].reduction_candidate.is_some());

    corpus
        .reclassify(&fingerprint, FailureClassificationV1::EnvironmentFailure)
        .unwrap();

    assert!(corpus.entries[&fingerprint].reduction_candidate.is_none());
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
            canonical_ir_sha256: None,
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
            allow_mutable_image_references: true,
            allow_cleartext_isolated_relay: true,
            enable_retained_relay_control: false,
            default_participant_image: "current".into(),
            relay_image: "current".into(),
            relay_command: vec!["relay".into()],
            node_command: vec!["node".into()],
        }),
        faults: Vec::new(),
        output_dir: root.path().join("output"),
    };
    let primary_error = RunnerError {
        code: "container_scenario".into(),
        message: "not persisted".into(),
    };
    let path = record_distributed_failure(&manifest, &primary_error, &scenario).unwrap();
    let vm_manifest = DistributedCampaignManifestV1 {
        backend: DistributedBackendV1::VirtualMachine(VirtualMachineBackendV1 {
            driver_contract_version: "1".into(),
            driver: "vm-driver".into(),
            driver_args: Vec::new(),
            cleanup_args: vec!["cleanup".into(), "{manifest}".into()],
            timeout_seconds: 30,
            cleanup_timeout_seconds: 10,
            capabilities: BTreeSet::new(),
        }),
        ..manifest.clone()
    };
    record_distributed_failure(&vm_manifest, &primary_error, &scenario).unwrap();
    record_distributed_failure(
        &vm_manifest,
        &RunnerError {
            code: "container_node_launch".into(),
            message: "also not persisted".into(),
        },
        &scenario,
    )
    .unwrap();
    let corpus = read_failure_corpus(&path).unwrap();
    assert_eq!(corpus.entries.len(), 2);
    let entry = corpus
        .entries
        .values()
        .find(|entry| entry.recurrence_count == 2)
        .unwrap();
    assert_eq!(entry.classification, FailureClassificationV1::ProductDefect);
    assert_eq!(
        entry.adapters,
        BTreeSet::from([
            CampaignAdapterV1::Container,
            CampaignAdapterV1::VirtualMachine,
        ])
    );
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

#[test]
fn concurrent_updates_do_not_lose_recurrences() {
    let root = tempfile::tempdir().unwrap();
    let path = std::sync::Arc::new(root.path().join("failure-corpus.v1.json"));
    let fingerprint = "b".repeat(64);
    let workers = 12;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(workers));
    let handles = (0..workers)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            let fingerprint = fingerprint.clone();
            std::thread::spawn(move || {
                barrier.wait();
                update_failure_corpus(&path, |corpus| {
                    corpus.record(observation(&fingerprint, CampaignAdapterV1::Process))
                })
                .unwrap();
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap();
    }

    let corpus = read_failure_corpus(&path).unwrap();
    let entry = &corpus.entries[&fingerprint];
    assert_eq!(entry.recurrence_count, workers as u64);
    assert_eq!(entry.first_seen_sequence, 1);
    assert_eq!(entry.last_seen_sequence, workers as u64);
    assert_eq!(corpus.next_sequence, workers as u64 + 1);
}

#[test]
fn abandoned_temporary_file_never_replaces_the_corpus() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("failure-corpus.v1.json");
    let fingerprint = "c".repeat(64);
    update_failure_corpus(&path, |corpus| {
        corpus.record(observation(&fingerprint, CampaignAdapterV1::Process))
    })
    .unwrap();
    fs_private::write_private(
        &root.path().join(".failure-corpus.v1.json.tmp.abandoned"),
        b"{not-json",
    )
    .unwrap();

    update_failure_corpus(&path, |corpus| {
        corpus.record(observation(&fingerprint, CampaignAdapterV1::Container))
    })
    .unwrap();

    let corpus = read_failure_corpus(&path).unwrap();
    assert_eq!(corpus.entries[&fingerprint].recurrence_count, 2);
}

#[tokio::test]
async fn successful_promotion_records_validated_capsule_and_vector_digests() {
    let root = tempfile::tempdir().unwrap();
    let corpus_path = root.path().join("failure-corpus.v1.json");
    let capsule_path = root.path().join("failure-capsule.v1.json");
    let vector_path = root.path().join("regression-vector.v1.json");
    let scenario = ScenarioSpec {
        name: "promotion-provenance/v1".into(),
        spec_version: "2".into(),
        clients: Vec::new(),
        topology: ScenarioTopologyV2::default(),
        steps: Vec::new(),
    };
    let mut report = run_scenario_report(&scenario, None).await.unwrap();
    report
        .expected_outcomes
        .push(TraceExpectation::NoPendingWork {
            clients: Vec::new(),
        });
    report.expectation_failures.push(VectorMismatch {
        kind: "promotion_sentinel".into(),
        message: "synthetic mismatch".into(),
        expected: serde_json::json!(true),
        actual: serde_json::json!(false),
    });
    let capsule = FailureCapsuleV1::from_report(
        report,
        FailureCapsuleSensitivity::SyntheticShareable,
        Vec::new(),
        None,
    )
    .unwrap();
    write_failure_capsule(&capsule_path, &capsule).unwrap();
    let fingerprint = capsule.failure.digest.clone();
    update_failure_corpus(&corpus_path, |corpus| {
        corpus.record(observation(&fingerprint, CampaignAdapterV1::Engine))
    })
    .unwrap();
    let unrelated_fingerprint = "f".repeat(64);
    update_failure_corpus(&corpus_path, |corpus| {
        corpus.record(observation(
            &unrelated_fingerprint,
            CampaignAdapterV1::Engine,
        ))
    })
    .unwrap();

    let alias_error = promote_capsule_into_corpus(
        &corpus_path,
        &fingerprint,
        &capsule_path,
        &corpus_path,
        "test",
    )
    .unwrap_err();
    assert_eq!(alias_error.code, "promotion_output_alias");
    assert!(read_failure_corpus(&corpus_path).is_ok());

    let mismatch_error = promote_capsule_into_corpus(
        &corpus_path,
        &unrelated_fingerprint,
        &capsule_path,
        &vector_path,
        "test",
    )
    .unwrap_err();
    assert_eq!(
        mismatch_error.code,
        "promotion_capsule_fingerprint_mismatch"
    );
    assert!(!vector_path.exists());

    let occupied_path = root.path().join("occupied-vector.v1.json");
    fs_private::write_private(&occupied_path, b"existing evidence").unwrap();
    let occupied_error = promote_capsule_into_corpus(
        &corpus_path,
        &fingerprint,
        &capsule_path,
        &occupied_path,
        "test",
    )
    .unwrap_err();
    assert_eq!(occupied_error.code, "promoted_vector_exists");
    assert_eq!(std::fs::read(&occupied_path).unwrap(), b"existing evidence");

    let promoted = promote_capsule_into_corpus(
        &corpus_path,
        &fingerprint,
        &capsule_path,
        &vector_path,
        "test",
    )
    .unwrap();

    assert_eq!(
        promoted.sha256,
        hex::encode(sha2::Sha256::digest(std::fs::read(&vector_path).unwrap()))
    );
    assert_eq!(
        promoted.source_capsule_sha256,
        hex::encode(sha2::Sha256::digest(std::fs::read(&capsule_path).unwrap()))
    );
    assert!(
        read_failure_corpus(&corpus_path).unwrap().entries[&fingerprint]
            .promoted_vectors
            .contains(&promoted)
    );

    let reused_path_error = promote_capsule_into_corpus(
        &corpus_path,
        &fingerprint,
        &capsule_path,
        &vector_path,
        "test",
    )
    .unwrap_err();
    assert_eq!(reused_path_error.code, "promoted_vector_path_recorded");
    assert_eq!(
        read_failure_corpus(&corpus_path).unwrap().entries[&fingerprint]
            .promoted_vectors
            .len(),
        1
    );
}

#[test]
fn node_capsule_fingerprints_are_unambiguous_for_delimiter_fields() {
    let error = NodeErrorV1 {
        code: "failure".into(),
        category: SubjectFailureCategory::Protocol,
        retryable: false,
        message: "normalized".into(),
    };
    let first = NodeFailureCapsuleV1::from_error("a:b", "c", &error);
    let second = NodeFailureCapsuleV1::from_error("a", "b:c", &error);
    let scenario = ScenarioSpec {
        name: "node-fingerprint/v1".into(),
        spec_version: "2".into(),
        clients: Vec::new(),
        topology: ScenarioTopologyV2::default(),
        steps: Vec::new(),
    };

    let first = observation_from_node_capsule(
        &first,
        "first.json".into(),
        scenario.clone(),
        &"a".repeat(64),
        BTreeMap::new(),
    );
    let second = observation_from_node_capsule(
        &second,
        "second.json".into(),
        scenario,
        &"a".repeat(64),
        BTreeMap::new(),
    );

    assert_ne!(first.fingerprint, second.fingerprint);
}

#[tokio::test]
async fn environment_capsules_do_not_emit_cross_adapter_reduction_candidates() {
    let scenario = ScenarioSpec {
        name: "environment-capsule/v1".into(),
        spec_version: "2".into(),
        clients: Vec::new(),
        topology: ScenarioTopologyV2::default(),
        steps: Vec::new(),
    };
    let mut report = run_scenario_report(&scenario, None).await.unwrap();
    report.step_log.push(ScenarioStepLogEntry {
        step_index: 0,
        step_type: "campaign_setup".into(),
        status: ScenarioStepStatus::Failed {
            kind: "environment_unavailable".into(),
            category: SubjectFailureCategory::Environment,
            message: "synthetic environment failure".into(),
        },
        wall_us: 0,
    });
    let capsule = FailureCapsuleV1::from_report(
        report,
        FailureCapsuleSensitivity::SyntheticShareable,
        Vec::new(),
        None,
    )
    .unwrap();

    let observation = observation_from_capsule(
        &capsule,
        "environment-capsule.v1.json".into(),
        CampaignAdapterV1::Process,
        BTreeMap::new(),
    );
    assert_eq!(
        observation.classification,
        FailureClassificationV1::EnvironmentFailure
    );
    assert!(observation.reduction_candidate.is_none());
}
