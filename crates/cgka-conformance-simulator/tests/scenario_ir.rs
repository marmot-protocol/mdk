use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cgka_conformance_simulator::{
    ScenarioAssertionV2, ScenarioComparison, ScenarioMessageSelectorV2, ScenarioPredicateV2,
    ScenarioResourceMetric, ScenarioSpec, ScenarioStep, ScenarioTransportClass,
    SubjectOutboundOutcome, VectorFixture, compile_scenario, run_scenario_report,
};

#[test]
fn schema_declares_every_executable_step_kind() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/scenario-ir.v2.schema.json"))
            .expect("scenario IR schema parses");
    assert_eq!(schema["properties"]["spec_version"]["const"], "2");
    let schema_kinds = schema["$defs"]["step"]["oneOf"]
        .as_array()
        .expect("step variants")
        .iter()
        .map(|variant| {
            variant["properties"]["type"]["const"]
                .as_str()
                .expect("step kind")
        })
        .collect::<BTreeSet<_>>();
    let executable_kinds = ScenarioStep::KINDS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(schema_kinds, executable_kinds);
}

#[test]
fn authoring_schema_references_resolve_against_the_ir_schema_id() {
    let authoring: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/scenario-authoring.v1.schema.json"))
            .expect("authoring schema parses");
    let ir: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/scenario-ir.v2.schema.json"))
            .expect("scenario IR schema parses");
    let authoring_id = authoring["$id"].as_str().expect("authoring schema id");
    let ir_id = ir["$id"].as_str().expect("IR schema id");
    let base = authoring_id
        .rsplit_once('/')
        .map(|(base, _)| format!("{base}/"))
        .expect("schema id has a base");
    let mut refs = Vec::new();
    collect_external_refs(&authoring, &mut refs);
    assert!(!refs.is_empty());
    for reference in refs {
        let (resource, fragment) = reference.split_once('#').unwrap_or((reference, ""));
        assert_eq!(format!("{base}{resource}"), ir_id);
        if !fragment.is_empty() {
            assert!(
                ir.pointer(fragment).is_some(),
                "schema reference fragment does not resolve: {reference}"
            );
        }
    }
}

fn collect_external_refs<'a>(value: &'a serde_json::Value, refs: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(serde_json::Value::as_str)
                && !reference.starts_with('#')
            {
                refs.push(reference);
            }
            for child in object.values() {
                collect_external_refs(child, refs);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_external_refs(child, refs);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn self_update_and_remove_members_use_the_common_adapter_contract() {
    let scenario = ScenarioSpec {
        name: "scenario-ir/membership-operations".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into(), "bob".into()],
        topology: Default::default(),
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "membership".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: Some(vec!["alice".into()]),
                pending: "create".into(),
            },
            ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: Some("create".into()),
                selection: Default::default(),
                outcome: SubjectOutboundOutcome::Accepted,
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into(), "alice".into()],
            },
            ScenarioStep::SelfUpdate {
                client: "alice".into(),
                pending: "rotate".into(),
            },
            ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: Some("rotate".into()),
                selection: Default::default(),
                outcome: SubjectOutboundOutcome::Accepted,
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into(), "alice".into()],
            },
            ScenarioStep::RemoveMembers {
                remover: "alice".into(),
                members: vec!["bob".into()],
                pending: "remove".into(),
            },
            ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: Some("remove".into()),
                selection: Default::default(),
                outcome: SubjectOutboundOutcome::Accepted,
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into(), "alice".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["alice".into()],
            },
        ],
    };

    let report = run_scenario_report(&scenario, None)
        .await
        .expect("scenario report");
    assert!(
        report.step_log.iter().all(|step| matches!(
            step.status,
            cgka_conformance_simulator::ScenarioStepStatus::Completed
        )),
        "membership scenario failed: {:?}",
        report.step_log
    );
    assert_eq!(report.resolved_topology.devices.len(), 2);
}

#[tokio::test]
async fn semantic_transport_selectors_survive_queue_shape_changes() {
    let publication_selector = |class| ScenarioMessageSelectorV2 {
        publication: Some("create".into()),
        class: Some(class),
        ..Default::default()
    };
    let scenario = ScenarioSpec {
        name: "scenario-ir/semantic-selectors".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into(), "bob".into(), "carol".into()],
        topology: Default::default(),
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "selectors".into(),
                invitees: vec!["bob".into(), "carol".into()],
                required_features: vec![],
                initial_admins: Some(vec!["alice".into()]),
                pending: "create".into(),
            },
            ScenarioStep::WithholdMessage {
                selector: publication_selector(ScenarioTransportClass::Welcome),
                label: "held-welcome".into(),
            },
            ScenarioStep::DuplicateMessage {
                selector: ScenarioMessageSelectorV2 {
                    sender: Some("alice".into()),
                    class: Some(ScenarioTransportClass::Welcome),
                    ..Default::default()
                },
            },
            ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: Some("create".into()),
                selection: Default::default(),
                outcome: SubjectOutboundOutcome::Accepted,
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into(), "carol".into()],
            },
            ScenarioStep::ReleaseWithheld {
                label: "held-welcome".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["alice".into(), "bob".into(), "carol".into()],
            },
        ],
    };
    let report = run_scenario_report(&scenario, None)
        .await
        .expect("scenario report");
    assert!(
        report.step_log.iter().all(|step| matches!(
            step.status,
            cgka_conformance_simulator::ScenarioStepStatus::Completed
        )),
        "semantic selector scenario failed: {:?}",
        report.step_log
    );
    let observations = &report.observed_trace.expect("trace").observations;
    assert_eq!(observations.len(), 3);
    assert!(
        observations
            .iter()
            .all(|observation| observation.member_count == 3)
    );
}

#[tokio::test]
async fn temporal_and_resource_assertions_execute_and_record_samples() {
    let scenario = ScenarioSpec {
        name: "scenario-ir/assertions".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into(), "bob".into()],
        topology: Default::default(),
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "assertions".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: Some(vec!["alice".into()]),
                pending: "create".into(),
            },
            ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: Some("create".into()),
                selection: Default::default(),
                outcome: SubjectOutboundOutcome::Accepted,
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into(), "bob".into()],
            },
            ScenarioStep::Assert {
                assertion: ScenarioAssertionV2::Exactly {
                    predicate: ScenarioPredicateV2::ClientsExactlyEquivalent {
                        clients: vec!["alice".into(), "bob".into()],
                    },
                },
            },
            ScenarioStep::SendAppMessage {
                sender: "alice".into(),
                payload: "one".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Assert {
                assertion: ScenarioAssertionV2::Within {
                    predicate: ScenarioPredicateV2::PayloadCount {
                        client: "bob".into(),
                        payload: "one".into(),
                        count: 1,
                    },
                    timeout_ms: 10,
                    poll_interval_ms: 5,
                },
            },
            ScenarioStep::Assert {
                assertion: ScenarioAssertionV2::Never {
                    predicate: ScenarioPredicateV2::PayloadCount {
                        client: "bob".into(),
                        payload: "forbidden".into(),
                        count: 1,
                    },
                    duration_ms: 10,
                    poll_interval_ms: 5,
                },
            },
            ScenarioStep::Assert {
                assertion: ScenarioAssertionV2::Resource {
                    metric: ScenarioResourceMetric::TransportQueuedMessages,
                    comparison: ScenarioComparison::Equal,
                    value: 0,
                },
            },
        ],
    };

    let report = run_scenario_report(&scenario, None)
        .await
        .expect("scenario report");
    assert!(report.step_log.iter().all(|step| matches!(
        step.status,
        cgka_conformance_simulator::ScenarioStepStatus::Completed
    )));
    assert_eq!(report.assertion_observations.len(), 4);
    assert!(report.assertion_observations.iter().all(|item| item.passed));
    assert_eq!(report.assertion_observations[1].elapsed_virtual_ms, 5);
    assert_eq!(report.assertion_observations[2].samples, 3);
}

#[test]
fn every_repository_vector_compiles_to_stable_actions() {
    let vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors");
    let mut paths = Vec::new();
    collect_vector_paths(&vectors, &mut paths);
    assert!(!paths.is_empty());

    for path in paths {
        let fixture: VectorFixture = serde_json::from_slice(
            &fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
        )
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
        let first = compile_scenario(&fixture.scenario)
            .unwrap_or_else(|error| panic!("compile {}: {error}", path.display()));
        let second = compile_scenario(&fixture.scenario)
            .unwrap_or_else(|error| panic!("recompile {}: {error}", path.display()));
        assert_eq!(
            first,
            second,
            "compiled schedule drifted for {}",
            path.display()
        );
        assert_eq!(first.actions.len(), fixture.scenario.steps.len());
    }
}

#[tokio::test]
async fn report_records_the_exact_schedule_consumed_by_execution() {
    let scenario = ScenarioSpec {
        name: "compiled-report/v2".into(),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: vec!["alice".into()],
        steps: vec![
            ScenarioStep::AdvanceTime { delta_ms: 10 },
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
        ],
    };
    let compiled = compile_scenario(&scenario).expect("compile scenario");
    let report = run_scenario_report(&scenario, None)
        .await
        .expect("execute compiled scenario");

    assert_eq!(report.expanded_schedule, compiled.expanded_schedule());
    assert_eq!(report.step_log.len(), compiled.actions.len());
}

fn collect_vector_paths(directory: &Path, paths: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path.file_name().and_then(|name| name.to_str()) != Some("byte-fixtures") {
                collect_vector_paths(&path, paths);
            }
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.ends_with(".v1.json") && name != "manifest.v1.json" {
            paths.push(path);
        }
    }
}
