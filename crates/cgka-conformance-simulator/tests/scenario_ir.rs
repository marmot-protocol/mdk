use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cgka_conformance_simulator::{
    HarnessStorageMode, ScenarioAccountV2, ScenarioAssertionV2, ScenarioComparison,
    ScenarioDeviceV2, ScenarioMessageSelectorV2, ScenarioPredicateV2, ScenarioProcessV2,
    ScenarioResourceMetric, ScenarioSpec, ScenarioStep, ScenarioTopologyV2, ScenarioTransportClass,
    SubjectOutboundOutcome, VectorFixture, compile_scenario, run_scenario_report,
    run_vector_fixture_report_with_capture,
};

fn topology_for_accounts(entries: &[(&str, &str)]) -> ScenarioTopologyV2 {
    let mut accounts = entries
        .iter()
        .map(|(_, account)| *account)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|account| ScenarioAccountV2 {
            id: account.into(),
            roles: vec!["member".into()],
        })
        .collect::<Vec<_>>();
    accounts.sort_by(|a, b| a.id.cmp(&b.id));
    ScenarioTopologyV2 {
        accounts,
        devices: entries
            .iter()
            .map(|(client, account)| ScenarioDeviceV2 {
                id: format!("device:{client}"),
                account: (*account).into(),
                process: format!("process:{client}"),
                client: (*client).into(),
            })
            .collect(),
        processes: entries
            .iter()
            .map(|(client, _)| ScenarioProcessV2 {
                id: format!("process:{client}"),
                binary_version: "mdk-test".into(),
                policy_version: "marmot-convergence-v1".into(),
                relays: vec![],
            })
            .collect(),
        groups: vec![],
        relays: vec![],
    }
}

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

#[test]
fn nested_and_non_group_actions_fail_ir_preflight() {
    let base = ScenarioSpec {
        name: "scenario-ir/invalid-group-wrapper".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into()],
        topology: Default::default(),
        steps: vec![],
    };
    let mut nested = base.clone();
    nested.steps.push(ScenarioStep::InGroup {
        group: "red".into(),
        action: Box::new(ScenarioStep::InGroup {
            group: "blue".into(),
            action: Box::new(ScenarioStep::ClearEvents {
                clients: vec!["alice".into()],
            }),
        }),
    });
    assert!(
        compile_scenario(&nested)
            .expect_err("nested wrapper fails")
            .message
            .contains("nested")
    );

    let mut nongroup = base;
    nongroup.steps.push(ScenarioStep::InGroup {
        group: "red".into(),
        action: Box::new(ScenarioStep::DeliverAll),
    });
    assert!(
        compile_scenario(&nongroup)
            .expect_err("transport action is not group scoped")
            .message
            .contains("not a group-scoped action")
    );
}

#[tokio::test]
async fn typoed_group_label_fails_closed_at_execution() {
    let scenario = ScenarioSpec {
        name: "scenario-ir/unknown-group".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into()],
        topology: Default::default(),
        steps: vec![
            ScenarioStep::InGroup {
                group: "red".into(),
                action: Box::new(ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "red".into(),
                    invitees: vec![],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "red-create".into(),
                }),
            },
            ScenarioStep::InGroup {
                group: "reed".into(),
                action: Box::new(ScenarioStep::Observe {
                    clients: vec!["alice".into()],
                }),
            },
        ],
    };
    let report = run_scenario_report(&scenario, None)
        .await
        .expect("execution failures are reported structurally");
    assert!(report.step_log.iter().any(|step| matches!(
        &step.status,
        cgka_conformance_simulator::ScenarioStepStatus::Failed { kind, .. }
            if kind == "unknown_scenario_group"
    )));
}

#[tokio::test]
async fn wrapped_action_id_is_used_by_fault_selectors_and_the_runtime_ledger() {
    let in_group = |action| ScenarioStep::InGroup {
        group: "red".into(),
        action: Box::new(action),
    };
    let scenario = ScenarioSpec {
        name: "scenario-ir/wrapped-action-id".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into(), "bob".into()],
        topology: Default::default(),
        steps: vec![
            in_group(ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "red".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: Some(vec!["alice".into()]),
                pending: "create".into(),
            }),
            ScenarioStep::accept_publication("alice", "create"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            in_group(ScenarioStep::SendAppMessage {
                sender: "alice".into(),
                payload: "held".into(),
            }),
            ScenarioStep::WithholdMessage {
                selector: ScenarioMessageSelectorV2 {
                    action_id: Some("step-4:send_app_message@red".into()),
                    class: Some(ScenarioTransportClass::Application),
                    ..Default::default()
                },
                label: "held-red-app".into(),
            },
            ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: None,
                selection: Default::default(),
                outcome: SubjectOutboundOutcome::Accepted,
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            in_group(ScenarioStep::Observe {
                clients: vec!["bob".into()],
            }),
            ScenarioStep::ReleaseWithheld {
                label: "held-red-app".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            in_group(ScenarioStep::ObserveExact {
                clients: vec!["bob".into()],
            }),
        ],
    };

    let report = run_scenario_report(&scenario, None)
        .await
        .expect("wrapped action scenario runs");
    let observations = &report.observed_trace.as_ref().unwrap().observations;
    assert!(observations[0].received_payloads.is_empty());
    assert_eq!(observations[1].received_payloads, vec!["held"]);
    assert!(observations[1].scenario_input_ledger.iter().any(|entry| {
        entry.scenario_id == "step-4:send_app_message@red" && entry.delivered == 1
    }));
}

#[test]
fn grouped_scenarios_reject_unwrapped_group_scoped_actions() {
    let scenario = ScenarioSpec {
        name: "scenario-ir/ambiguous-unwrapped-group-action".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into()],
        topology: Default::default(),
        steps: vec![
            ScenarioStep::InGroup {
                group: "red".into(),
                action: Box::new(ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "red".into(),
                    invitees: vec![],
                    required_features: vec![],
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                }),
            },
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "ambiguous".into(),
                invitees: vec![],
                required_features: vec![],
                initial_admins: Some(vec!["alice".into()]),
                pending: "ambiguous".into(),
            },
        ],
    };

    let error = compile_scenario(&scenario).expect_err("ambiguous action must fail preflight");
    assert_eq!(error.step_index, Some(1));
    assert!(error.message.contains("must use in_group"));
}

#[tokio::test]
async fn grouped_observe_of_non_member_is_a_structured_failure() {
    let in_group = |action| ScenarioStep::InGroup {
        group: "red".into(),
        action: Box::new(action),
    };
    let scenario = ScenarioSpec {
        name: "scenario-ir/non-member-observe".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into(), "bob".into()],
        topology: Default::default(),
        steps: vec![
            in_group(ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "red".into(),
                invitees: vec![],
                required_features: vec![],
                initial_admins: Some(vec!["alice".into()]),
                pending: "create".into(),
            }),
            in_group(ScenarioStep::ObserveExact {
                clients: vec!["bob".into()],
            }),
        ],
    };

    let report = run_scenario_report(&scenario, None)
        .await
        .expect("subject failures are reported structurally");
    assert!(report.step_log.iter().any(|step| matches!(
        &step.status,
        cgka_conformance_simulator::ScenarioStepStatus::Failed { kind, .. }
            if kind == "client_not_in_scenario_group"
    )));
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

#[tokio::test]
async fn explicit_group_targets_keep_two_live_groups_independent() {
    fn in_group(group: &str, action: ScenarioStep) -> ScenarioStep {
        ScenarioStep::InGroup {
            group: group.into(),
            action: Box::new(action),
        }
    }
    fn create(group: &str) -> ScenarioStep {
        in_group(
            group,
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: group.into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: Some(vec!["alice".into()]),
                pending: format!("{group}-create"),
            },
        )
    }
    fn accept(publication: &str) -> ScenarioStep {
        ScenarioStep::AcknowledgeOutbound {
            client: "alice".into(),
            publication: Some(publication.into()),
            selection: Default::default(),
            outcome: SubjectOutboundOutcome::Accepted,
        }
    }

    let scenario = ScenarioSpec {
        name: "scenario-ir/two-independent-groups".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into(), "bob".into()],
        topology: Default::default(),
        steps: vec![
            create("red"),
            accept("red-create"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            create("blue"),
            accept("blue-create"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            in_group(
                "red",
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "red-only".into(),
                },
            ),
            ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: None,
                selection: Default::default(),
                outcome: SubjectOutboundOutcome::Accepted,
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            in_group(
                "red",
                ScenarioStep::Observe {
                    clients: vec!["bob".into()],
                },
            ),
            in_group(
                "blue",
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "blue-only".into(),
                },
            ),
            ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: None,
                selection: Default::default(),
                outcome: SubjectOutboundOutcome::Accepted,
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            in_group(
                "blue",
                ScenarioStep::Observe {
                    clients: vec!["bob".into()],
                },
            ),
        ],
    };

    let compiled = compile_scenario(&scenario).expect("compile multi-group scenario");
    assert_eq!(compiled.actions[0].scenario_group.as_deref(), Some("red"));
    assert_eq!(compiled.actions[4].scenario_group.as_deref(), Some("blue"));
    let report = run_scenario_report(&scenario, None)
        .await
        .expect("run multi-group scenario");
    let observations = &report.observed_trace.as_ref().unwrap().observations;
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].received_payloads, vec!["red-only"]);
    assert_eq!(observations[1].received_payloads, vec!["blue-only"]);
    assert_eq!(observations[0].epoch, 1);
    assert_eq!(observations[1].epoch, 1);
}

#[test]
fn incompatible_explicit_policy_versions_fail_before_action_zero() {
    let mut topology = topology_for_accounts(&[("alice", "account:alice"), ("bob", "account:bob")]);
    topology.processes[1].policy_version = "marmot-convergence-v2".into();
    let scenario = ScenarioSpec {
        name: "scenario-ir/incompatible-policies".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into(), "bob".into()],
        topology,
        steps: vec![],
    };

    let error = compile_scenario(&scenario).expect_err("mixed policies must not execute");
    assert_eq!(error.kind, "incompatible_convergence_policy");
    assert!(error.message.contains("incompatible convergence policies"));
    assert!(error.message.contains("marmot-convergence-v1"));
    assert!(error.message.contains("marmot-convergence-v2"));
}

#[tokio::test]
async fn topology_can_join_two_device_leaves_for_one_account() {
    let clients = vec!["alice-phone".into(), "alice-laptop".into(), "bob".into()];
    let scenario = ScenarioSpec {
        name: "scenario-ir/shared-account-devices".into(),
        spec_version: "2".into(),
        topology: topology_for_accounts(&[
            ("alice-phone", "account:alice"),
            ("alice-laptop", "account:alice"),
            ("bob", "account:bob"),
        ]),
        clients: clients.clone(),
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice-phone".into(),
                name: "multi-device".into(),
                invitees: vec!["alice-laptop".into(), "bob".into()],
                required_features: vec![],
                initial_admins: Some(vec!["alice-phone".into()]),
                pending: "create".into(),
            },
            ScenarioStep::accept_publication("alice-phone", "create"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice-laptop".into(), "bob".into()],
            },
            ScenarioStep::ObserveExact {
                clients: clients.clone(),
            },
        ],
    };

    let report = run_scenario_report(&scenario, None)
        .await
        .expect("shared-account device scenario");
    let observations = &report.observed_trace.as_ref().unwrap().observations;
    assert_eq!(observations.len(), 3);
    assert!(
        observations
            .iter()
            .all(|observation| observation.epoch == 1)
    );
    assert!(
        observations
            .iter()
            .all(|observation| observation.member_count == 3)
    );
    assert!(report.expectation_failures.is_empty());

    let fixture = VectorFixture {
        scenario_name: scenario.name.clone(),
        vector_version: "1".into(),
        conformance_version: env!("CARGO_PKG_VERSION").into(),
        seed: None,
        application_profile: None,
        scenario,
        expected_trace: None,
        expected_outcomes: vec![],
    };
    let (captured_report, _) =
        run_vector_fixture_report_with_capture(&fixture, HarnessStorageMode::InMemorySqlite, false)
            .await
            .expect("capture runner preserves explicit topology");
    let captured_state = captured_report
        .observed_trace
        .as_ref()
        .and_then(|trace| trace.observations.first())
        .and_then(|observation| observation.canonical_state.as_ref())
        .map(|state| serde_json::to_value(state).expect("canonical state serializes"))
        .expect("capture runner observes exact state");
    let identities = captured_state
        .pointer("/snapshot/sorted_member_identities_hex")
        .and_then(serde_json::Value::as_array)
        .expect("live snapshot carries sorted identities");
    assert_eq!(identities.len(), 3);
    assert!(
        identities.windows(2).any(|pair| pair[0] == pair[1]),
        "capture runner must preserve the shared account identity of both devices"
    );
}
