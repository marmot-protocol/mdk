use std::fs;

use cgka_conformance_simulator::TraceExpectation;
use cgka_conformance_simulator::VectorMismatch;
use cgka_conformance_simulator::{
    CapturedTransportArtifactV1, ClientBuilder, EngineByteReplayV1, FailureCapsuleError,
    FailureCapsuleSensitivity, FailureCapsuleV1, TerminalOutcomeClassification, TransportBus,
    build_fingerprint, digest_json, promote_failure_capsule_to_vector, read_failure_capsule,
    replay_engine_bytes, run_scenario_report, write_failure_capsule,
};
use cgka_conformance_simulator::{ScenarioSpec, ScenarioStep};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::{Capability, CapabilityRequirement, Feature, RequirementLevel};

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0_u8; 32];
    out[..name.len()].copy_from_slice(name);
    out
}

fn scenario_registry() -> FeatureRegistry {
    let mut registry = FeatureRegistry::new();
    registry.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    registry
}

#[tokio::test]
async fn exact_captured_commit_replays_from_sensitive_checkpoint() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(scenario_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(scenario_registry())
        .attach(&bus);
    let bob_key_package = bob.fresh_key_package().await;
    let (group_id, create) = alice
        .create_group("byte-replay", vec![bob_key_package], vec![])
        .await;
    alice.confirm(create).await;
    bus.deliver_all();
    assert!(bob.tick().await.into_iter().all(|outcome| outcome.is_ok()));

    let checkpoint = bob
        .export_conformance_replay_checkpoint(&group_id)
        .expect("export recipient checkpoint");
    let update = alice.update_group_data("captured branch").await;
    let captured_deliveries = bus.queued_messages();
    assert_eq!(captured_deliveries.len(), 1);
    alice.confirm(update).await;
    bus.deliver_all();
    assert!(bob.tick().await.into_iter().all(|outcome| outcome.is_ok()));

    let normalized_state_digest =
        digest_json(&bob.canonical_state_snapshot()).expect("digest canonical state");
    let expected_fingerprint = build_fingerprint(
        TerminalOutcomeClassification::OracleViolation,
        Some("step-6:tick".into()),
        "captured_commit_state".into(),
        normalized_state_digest,
    );
    let replay = EngineByteReplayV1 {
        client_label: "bob".into(),
        identity_seed: pad32(b"bob"),
        protocol_profile: ProtocolProfile::Legacy,
        group_id: group_id.as_slice().to_vec(),
        sensitive_checkpoint: checkpoint,
        captured_deliveries,
        checkpoint_monotonic_ms: 0,
        checkpoint_wall_ms: 0,
        virtual_time_tick_enabled: false,
        failure_kind: "captured_commit_state".into(),
        failing_action_id: "step-6:tick".into(),
        expected_fingerprint: expected_fingerprint.clone(),
    };

    let debug_bus = TransportBus::ordered();
    let mut debug_bob = ClientBuilder::new(pad32(b"bob"))
        .registry(scenario_registry())
        .attach(&debug_bus);
    debug_bob
        .restore_conformance_replay_checkpoint(&group_id, &replay.sensitive_checkpoint)
        .expect("restore debug checkpoint");
    for message in &replay.captured_deliveries {
        debug_bob.inject_captured_transport(message.clone());
    }
    assert!(
        debug_bob
            .tick()
            .await
            .into_iter()
            .all(|outcome| outcome.is_ok())
    );
    assert_eq!(
        debug_bob.canonical_state_snapshot(),
        bob.canonical_state_snapshot(),
        "checkpoint plus captured transport must recreate exact state"
    );

    let mut capsule_report = run_scenario_report(
        &ScenarioSpec {
            name: "captured-byte-replay/v1".into(),
            spec_version: "2".into(),
            clients: Vec::new(),
            steps: Vec::new(),
        },
        None,
    )
    .await
    .expect("capsule report");
    capsule_report.expectation_failures.push(VectorMismatch {
        kind: "captured_commit_state".into(),
        message: "captured byte-level sentinel".into(),
        expected: serde_json::json!({"epoch": 1}),
        actual: serde_json::json!({"epoch": 2}),
    });
    let capsule = FailureCapsuleV1::from_report(
        capsule_report,
        FailureCapsuleSensitivity::SensitiveLocal,
        vec![CapturedTransportArtifactV1 {
            sequence: 0,
            sender: "alice".into(),
            message: replay.captured_deliveries[0].clone(),
        }],
        Some(replay.clone()),
    )
    .expect("build byte replay capsule");
    let dir = tempfile::tempdir().expect("capsule directory");
    let capsule_path = dir.path().join("captured-byte-replay.v1.json");
    write_failure_capsule(&capsule_path, &capsule).expect("write byte replay capsule");
    let restored_capsule = read_failure_capsule(&capsule_path).expect("read byte replay capsule");
    let observation = replay_engine_bytes(
        restored_capsule
            .byte_replay
            .as_ref()
            .expect("capsule contains byte replay"),
    )
    .await
    .expect("exact bytes reproduce the state fingerprint");
    assert_eq!(observation.epoch, 2);
    assert_eq!(observation.fingerprint, expected_fingerprint);

    let mut missing_input = replay;
    missing_input.captured_deliveries.clear();
    let error = replay_engine_bytes(&missing_input)
        .await
        .expect_err("removing captured bytes must change the outcome");
    assert!(error.to_string().contains("fingerprint mismatch"));
}

#[tokio::test]
async fn capsule_round_trip_records_schedule_policy_and_resources() {
    let scenario = ScenarioSpec {
        name: "failure-capsule-contract/v1".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into(), "bob".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "capsule".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: Some("create".into()),
                selection: cgka_conformance_simulator::ScenarioOutboundSelection::All,
                outcome: cgka_conformance_simulator::SubjectOutboundOutcome::Accepted,
            },
            ScenarioStep::AdvanceTime { delta_ms: 250 },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::ObserveExact {
                clients: vec!["alice".into(), "bob".into()],
            },
        ],
    };
    let mut report = run_scenario_report(&scenario, None)
        .await
        .expect("scenario report");
    report
        .expected_outcomes
        .push(TraceExpectation::ClientState {
            client: "alice".into(),
            epoch: 999,
            member_count: 2,
            received_payloads: None,
            added_members: None,
            removed_members: None,
        });
    report.expectation_failures.push(VectorMismatch {
        kind: "sentinel_state_mismatch".into(),
        message: "intentional capsule sentinel".into(),
        expected: serde_json::json!({"epoch": 999}),
        actual: serde_json::json!({"epoch": 1}),
    });
    let capsule = FailureCapsuleV1::from_report(
        report,
        FailureCapsuleSensitivity::SyntheticShareable,
        Vec::new(),
        None,
    )
    .expect("build capsule");

    assert_eq!(capsule.schema_version, "1");
    assert_eq!(capsule.expanded_schedule[2].virtual_time_ms, 0);
    assert_eq!(capsule.expanded_schedule[3].virtual_time_ms, 250);
    assert_eq!(capsule.failure.failure_kind, "sentinel_state_mismatch");
    assert_eq!(capsule.resources.counters["planned_scenario_steps"], 6);
    assert_eq!(capsule.resources.counters["executed_scenario_steps"], 6);

    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/failure-capsule.v1.schema.json"))
            .expect("failure capsule schema parses");
    let encoded = serde_json::to_value(&capsule).expect("capsule serializes");
    for required in schema["required"].as_array().expect("required fields") {
        let required = required.as_str().expect("required field is a string");
        assert!(
            encoded.get(required).is_some(),
            "missing required {required}"
        );
    }
    let promoted = promote_failure_capsule_to_vector(&capsule, "test")
        .expect("synthetic capsule promotes to a vector candidate");
    assert_eq!(promoted.scenario, capsule.canonical_scenario);
    assert_eq!(promoted.expected_trace, capsule.report.expected_trace);
    assert_eq!(promoted.expected_outcomes, capsule.report.expected_outcomes);

    let mut expectationless = capsule.clone();
    expectationless.report.expected_trace = None;
    expectationless.report.expected_outcomes.clear();
    assert!(matches!(
        promote_failure_capsule_to_vector(&expectationless, "test"),
        Err(FailureCapsuleError::MissingPortableExpectation)
    ));

    let mut incorrectly_shareable = capsule.clone();
    incorrectly_shareable.byte_replay = Some(EngineByteReplayV1 {
        client_label: "alice".into(),
        identity_seed: pad32(b"alice"),
        protocol_profile: ProtocolProfile::Legacy,
        group_id: vec![1],
        sensitive_checkpoint: vec![1],
        captured_deliveries: Vec::new(),
        checkpoint_monotonic_ms: 0,
        checkpoint_wall_ms: 0,
        virtual_time_tick_enabled: false,
        failure_kind: incorrectly_shareable.failure.failure_kind.clone(),
        failing_action_id: "oracle".into(),
        expected_fingerprint: incorrectly_shareable.failure.clone(),
    });
    assert!(
        incorrectly_shareable.validate().is_err(),
        "a capsule containing key material must be sensitive_local"
    );

    let dir = tempfile::tempdir().expect("temporary capsule directory");
    let path = dir
        .path()
        .join("sensitive-capsules")
        .join("failure-capsule.v1.json");
    write_failure_capsule(&path, &capsule).expect("write private capsule");
    assert_eq!(read_failure_capsule(&path).expect("read capsule"), capsule);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    let mut unsupported = capsule;
    unsupported.schema_version = "2".into();
    assert!(unsupported.validate().is_err());
}
