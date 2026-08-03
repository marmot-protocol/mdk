use incident_replay::{
    EvidenceConfidenceV1, ExactHistoryImportError, ForkCommitKind, IncidentReplayFidelityV1,
    IncidentSourceFormatV1, NormalizedActionEvidenceV1, NormalizedScenarioHistoryV1, RecoveredFork,
    accept_exact_history, archetype_artifact, import_exact_history, parse, synthesize,
};

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
fn exact_normalized_history_imports_and_reproduces() {
    let export = export_with_history();
    let artifact = import_exact_history(&export, IncidentSourceFormatV1::AgentStateDocument)
        .expect("valid exact history imports")
        .expect("history is present");

    assert_eq!(
        artifact.replay_fidelity,
        IncidentReplayFidelityV1::ExactNormalizedHistory
    );
    assert_eq!(
        artifact.evidence_confidence,
        EvidenceConfidenceV1::ExactNormalizedAvailableEvidence
    );
    assert!(!artifact.byte_replay_available);
    assert!(artifact.unavailable_fields.iter().any(|field| {
        field.field == "mls_state_checkpoint" && field.reason.contains("sensitive")
    }));
    accept_exact_history(artifact).expect("normalized history reproduces recorded outcomes");
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
        import_exact_history(&export, IncidentSourceFormatV1::AgentStateDocument),
        Err(ExactHistoryImportError::IncompleteActionEvidence)
    ));
}

#[test]
fn exact_history_preconditions_have_typed_fail_closed_errors() {
    let mut export = export_with_history();
    export
        .normalized_scenario_history
        .as_mut()
        .unwrap()
        .sensitive_state_included = true;
    assert!(matches!(
        import_exact_history(&export, IncidentSourceFormatV1::AgentStateDocument),
        Err(ExactHistoryImportError::SensitiveStateIncluded)
    ));

    let mut export = export_with_history();
    export
        .normalized_scenario_history
        .as_mut()
        .unwrap()
        .expected_outcomes
        .clear();
    assert!(matches!(
        import_exact_history(&export, IncidentSourceFormatV1::AgentStateDocument),
        Err(ExactHistoryImportError::MissingExpectedOutcomes)
    ));

    let mut export = export_with_history();
    export
        .normalized_scenario_history
        .as_mut()
        .unwrap()
        .incident_event_indices
        .clear();
    assert!(matches!(
        import_exact_history(&export, IncidentSourceFormatV1::AgentStateDocument),
        Err(ExactHistoryImportError::MissingIncidentEvidence)
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
        import_exact_history(&export, IncidentSourceFormatV1::AgentStateDocument),
        Err(ExactHistoryImportError::SourceEventOutOfRange { .. })
    ));
}

#[test]
fn legacy_export_is_an_explicitly_inexact_archetype() {
    let mut export = export_with_history();
    export.normalized_scenario_history = None;
    assert!(
        import_exact_history(&export, IncidentSourceFormatV1::AgentStateDocument)
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
        Err(ExactHistoryImportError::MissingIncidentEvidence)
    ));
}
