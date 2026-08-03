use incident_replay::{
    EvidenceConfidenceV1, ForkCommitKind, IncidentArtifactSensitivityV1, IncidentReplayFidelityV1,
    IncidentReproductionStatusV1, IncidentSourceFormatV1, NormalizedActionEvidenceV1,
    NormalizedHistoryImportError, NormalizedScenarioHistoryV1, RecoveredFork,
    accept_attested_history, archetype_artifact, import_attested_history, parse, synthesize,
};
use std::collections::BTreeSet;

fn export_with_history() -> incident_replay::AgentStateExport {
    let fork = RecoveredFork {
        source_epoch: 30,
        commit: ForkCommitKind::Membership,
    };
    let vector = synthesize(
        &fork,
        "exact-normalized-membership-incident/v1",
        "alice",
        "bob",
    );
    let action_count = vector.scenario.steps.len();
    let mut events = vec![serde_json::json!({
        "kind": {
            "type": "fork_resolution",
            "source_epoch": 30,
            "winner": "candidate"
        }
    })];
    events.extend(
        (0..action_count)
            .map(|_| serde_json::json!({ "kind": { "type": "normalized_source_action" } }))
            .collect::<Vec<_>>(),
    );
    let mut export = parse(&serde_json::json!({ "events": events }).to_string()).expect("parses");
    export.normalized_scenario_history = Some(NormalizedScenarioHistoryV1 {
        schema_version: "1".into(),
        complete: true,
        scenario: vector.scenario,
        expected_outcomes: vector.expected_outcomes,
        action_evidence: (0..action_count)
            .map(|step_index| NormalizedActionEvidenceV1 {
                step_index,
                source_event_indices: vec![step_index + 1],
            })
            .collect(),
        incident_event_indices: vec![0],
        unavailable_fields: Vec::new(),
        sensitive_state_included: false,
    });
    export
}

#[test]
fn producer_attested_history_imports_and_reproduces() {
    let export = export_with_history();
    let artifact = import_attested_history(&export, IncidentSourceFormatV1::AgentStateDocument)
        .expect("valid normalized history imports")
        .expect("history is present");

    assert_eq!(
        artifact.replay_fidelity,
        IncidentReplayFidelityV1::ProducerAttestedNormalizedHistory
    );
    assert_eq!(
        artifact.evidence_confidence,
        EvidenceConfidenceV1::ProducerAttestedAvailableEvidence
    );
    assert_eq!(
        artifact.sensitivity,
        IncidentArtifactSensitivityV1::ConfidentialUnredactedScenario
    );
    assert_eq!(
        artifact.reproduction_status,
        IncidentReproductionStatusV1::Unverified
    );
    assert!(!artifact.byte_replay_available);
    assert!(artifact.unavailable_fields.iter().any(|field| {
        field.field == "mls_state_checkpoint" && field.reason.contains("sensitive")
    }));
    let artifact =
        accept_attested_history(artifact).expect("normalized history reproduces recorded outcomes");
    assert_eq!(
        artifact.reproduction_status,
        IncidentReproductionStatusV1::Reproduced
    );
}

#[test]
fn missing_action_mapping_fails_closed_instead_of_becoming_exact() {
    let mut export = export_with_history();
    export
        .normalized_scenario_history
        .as_mut()
        .unwrap()
        .action_evidence
        .pop();
    assert!(matches!(
        import_attested_history(&export, IncidentSourceFormatV1::AgentStateDocument),
        Err(NormalizedHistoryImportError::IncompleteActionEvidence)
    ));
}

#[test]
fn attested_history_preconditions_have_typed_fail_closed_errors() {
    let mut export = export_with_history();
    export
        .normalized_scenario_history
        .as_mut()
        .unwrap()
        .sensitive_state_included = true;
    assert!(matches!(
        import_attested_history(&export, IncidentSourceFormatV1::AgentStateDocument),
        Err(NormalizedHistoryImportError::SensitiveStateIncluded)
    ));

    let mut export = export_with_history();
    export
        .normalized_scenario_history
        .as_mut()
        .unwrap()
        .expected_outcomes
        .clear();
    assert!(matches!(
        import_attested_history(&export, IncidentSourceFormatV1::AgentStateDocument),
        Err(NormalizedHistoryImportError::MissingExpectedOutcomes)
    ));

    let mut export = export_with_history();
    export
        .normalized_scenario_history
        .as_mut()
        .unwrap()
        .incident_event_indices
        .clear();
    assert!(matches!(
        import_attested_history(&export, IncidentSourceFormatV1::AgentStateDocument),
        Err(NormalizedHistoryImportError::MissingIncidentEvidence)
    ));

    let mut export = export_with_history();
    let event_count = export.events.len();
    export
        .normalized_scenario_history
        .as_mut()
        .unwrap()
        .action_evidence[0]
        .source_event_indices = vec![event_count];
    assert!(matches!(
        import_attested_history(&export, IncidentSourceFormatV1::AgentStateDocument),
        Err(NormalizedHistoryImportError::SourceEventOutOfRange { .. })
    ));
}

#[test]
fn legacy_export_is_an_explicitly_inexact_archetype() {
    let mut export = export_with_history();
    export.normalized_scenario_history = None;
    assert!(
        import_attested_history(&export, IncidentSourceFormatV1::AgentStateDocument)
            .expect("absence is not malformed")
            .is_none()
    );

    let fork = RecoveredFork {
        source_epoch: 30,
        commit: ForkCommitKind::Membership,
    };
    let artifact = archetype_artifact(
        &export,
        IncidentSourceFormatV1::AgentStateDocument,
        synthesize(&fork, "archetype/v1", "alice", "bob"),
    )
    .expect("incident evidence permits archetype synthesis");
    assert_eq!(
        artifact.replay_fidelity,
        IncidentReplayFidelityV1::OutcomeEquivalentArchetype
    );
    assert_eq!(
        artifact.evidence_confidence,
        EvidenceConfidenceV1::DerivedOutcomeEquivalent
    );
    assert!(
        artifact
            .unavailable_fields
            .iter()
            .any(|field| { field.field == "exact_scenario_action_history" })
    );
}

#[test]
fn archetype_without_incident_evidence_fails_closed() {
    let export = parse(r#"{ "events": [] }"#).expect("parses");
    let fork = RecoveredFork {
        source_epoch: 30,
        commit: ForkCommitKind::Membership,
    };
    assert!(matches!(
        archetype_artifact(
            &export,
            IncidentSourceFormatV1::AgentStateDocument,
            synthesize(&fork, "archetype/v1", "alice", "bob"),
        ),
        Err(NormalizedHistoryImportError::MissingIncidentEvidence)
    ));
}

#[test]
fn committed_membership_fixture_drives_the_artifact_path() {
    let export = parse(include_str!("fixtures/replayable-membership-fork.json"))
        .expect("committed replay fixture parses");
    let fork = RecoveredFork {
        source_epoch: 30,
        commit: ForkCommitKind::Membership,
    };
    let artifact = archetype_artifact(
        &export,
        IncidentSourceFormatV1::AgentStateDocument,
        synthesize(&fork, "membership-fixture/v1", "alice", "bob"),
    )
    .expect("fixture carries contested incident evidence");
    assert_eq!(
        artifact.replay_fidelity,
        IncidentReplayFidelityV1::OutcomeEquivalentArchetype
    );
}

#[test]
fn artifact_schema_tracks_the_serialized_top_level_contract() {
    let export = export_with_history();
    let artifact = import_attested_history(&export, IncidentSourceFormatV1::AgentStateDocument)
        .expect("history imports")
        .expect("history exists");
    let artifact = accept_attested_history(artifact).expect("history reproduces");
    let serialized = serde_json::to_value(&artifact).expect("artifact serializes");
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schemas/incident-scenario-artifact.v1.schema.json"
    ))
    .expect("schema parses");

    let actual = serialized
        .as_object()
        .expect("artifact is an object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let declared = schema["properties"]
        .as_object()
        .expect("schema properties")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required = schema["required"]
        .as_array()
        .expect("schema required")
        .iter()
        .map(|value| value.as_str().expect("required name").to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        actual, declared,
        "schema properties drifted from serde output"
    );
    assert_eq!(actual, required, "all v1 artifact fields must be required");
    for field in [
        "source_format",
        "replay_fidelity",
        "evidence_confidence",
        "sensitivity",
        "reproduction_status",
    ] {
        let value = serialized[field].as_str().expect("serialized enum");
        assert!(
            schema["properties"][field]["enum"]
                .as_array()
                .expect("schema enum")
                .iter()
                .any(|candidate| candidate.as_str() == Some(value)),
            "schema enum for {field} does not contain {value}"
        );
    }
}
