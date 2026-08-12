//! Long-lived multi-process convergence-orchestrator coverage.

use std::collections::{BTreeMap, BTreeSet};

use cgka_conformance_simulator::process_orchestrator::{ProcessNodeLaunchV1, ProcessOrchestrator};
use cgka_conformance_simulator::{
    AppRuntimeHarness, AppRuntimeObservationV1, GeneratedScenarioCase, GeneratedScenarioInputV1,
    GeneratedSubjectKind, HarnessStorageMode, RetainedRelaySubject, ScenarioAccountV2,
    ScenarioDeviceV2, ScenarioInputDisposition, ScenarioMessageSelectorV2, ScenarioProcessV2,
    ScenarioRelaySyncModeV2, ScenarioRelayV2, ScenarioSpec, ScenarioStep, ScenarioTopologyV2,
    TraceExpectation, compile_scenario, node_protocol::NodeObservationV1,
    resolve_scenario_input_bytes, run_scenario_report, run_scenario_report_with_subject,
};
use cgka_traits::group::ProtocolProfile;

fn in_group(group: &str, action: ScenarioStep) -> ScenarioStep {
    ScenarioStep::InGroup {
        group: group.into(),
        action: Box::new(action),
    }
}

fn process_scenario(name: &str, lifecycle: bool) -> ScenarioSpec {
    let clients = vec!["alice".to_owned(), "bob".to_owned()];
    let mut steps = vec![
        in_group(
            "main",
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "process group".into(),
                invitees: vec!["bob".into()],
                required_features: Vec::new(),
                initial_admins: Some(vec!["alice".into()]),
                pending: "create".into(),
            },
        ),
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
    ];
    if lifecycle {
        steps.push(ScenarioStep::SetClientOffline {
            client: "bob".into(),
        });
    }
    steps.extend([
        in_group(
            "main",
            ScenarioStep::UpdateGroupData {
                client: "alice".into(),
                name: "settled process group".into(),
                pending: "rename".into(),
            },
        ),
        in_group(
            "main",
            ScenarioStep::SendAppMessage {
                sender: "alice".into(),
                payload: "visible after settlement".into(),
            },
        ),
    ]);
    if lifecycle {
        steps.extend([
            ScenarioStep::CrashProcess {
                process: "process:alice".into(),
            },
            ScenarioStep::RestartProcess {
                process: "process:alice".into(),
            },
            ScenarioStep::ReconnectClient {
                client: "bob".into(),
            },
            ScenarioStep::CrashProcess {
                process: "process:bob".into(),
            },
            ScenarioStep::RestartProcess {
                process: "process:bob".into(),
            },
        ]);
    }
    steps.extend([
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: cgka_conformance_simulator::ScenarioRelaySyncModeV2::FullHistory,
        },
        in_group(
            "main",
            ScenarioStep::ClearEvents {
                clients: clients.clone(),
            },
        ),
        ScenarioStep::AwaitQuiescence {
            policy: cgka_conformance_simulator::QuiescencePolicy {
                max_iterations: 100,
                ..Default::default()
            },
        },
        in_group(
            "main",
            ScenarioStep::Observe {
                clients: clients.clone(),
            },
        ),
    ]);
    ScenarioSpec {
        name: name.into(),
        spec_version: "2".into(),
        clients,
        topology: controlled_relay_topology(),
        steps,
    }
}

fn controlled_relay_topology() -> ScenarioTopologyV2 {
    ScenarioTopologyV2 {
        accounts: ["alice", "bob"]
            .into_iter()
            .map(|client| ScenarioAccountV2 {
                id: format!("account:{client}"),
                roles: vec!["member".into()],
            })
            .collect(),
        devices: ["alice", "bob"]
            .into_iter()
            .map(|client| ScenarioDeviceV2 {
                id: format!("device:{client}"),
                account: format!("account:{client}"),
                process: format!("process:{client}"),
                client: client.into(),
            })
            .collect(),
        processes: ["alice", "bob"]
            .into_iter()
            .map(|client| ScenarioProcessV2 {
                id: format!("process:{client}"),
                binary_version: "current-test-node".into(),
                policy_version: "marmot-convergence-v1".into(),
                relays: vec!["relay:a".into(), "relay:b".into()],
            })
            .collect(),
        groups: Vec::new(),
        relays: ["relay:a", "relay:b"]
            .into_iter()
            .map(|id| ScenarioRelayV2 {
                id: id.into(),
                implementation_version: "mock-relay-v1".into(),
                policy_version: "retain-all-v1".into(),
            })
            .collect(),
    }
}

fn single_relay_topology(clients: &[String]) -> ScenarioTopologyV2 {
    ScenarioTopologyV2 {
        accounts: clients
            .iter()
            .map(|client| ScenarioAccountV2 {
                id: format!("account:{client}"),
                roles: vec!["member".into()],
            })
            .collect(),
        devices: clients
            .iter()
            .map(|client| ScenarioDeviceV2 {
                id: format!("device:{client}"),
                account: format!("account:{client}"),
                process: format!("process:{client}"),
                client: client.clone(),
            })
            .collect(),
        processes: clients
            .iter()
            .map(|client| ScenarioProcessV2 {
                id: format!("process:{client}"),
                binary_version: "current-test-node".into(),
                policy_version: "marmot-convergence-v1".into(),
                relays: vec!["relay:shared".into()],
            })
            .collect(),
        groups: Vec::new(),
        relays: vec![ScenarioRelayV2 {
            id: "relay:shared".into(),
            implementation_version: "retained-memory/v1".into(),
            policy_version: "retain-all-v1".into(),
        }],
    }
}

#[derive(Clone, Copy)]
enum CrossAdapterRecovery {
    Restart,
    OfflineFullHistory,
}

fn build_cross_adapter_scenario(recovery: CrossAdapterRecovery) -> ScenarioSpec {
    let include_offline_recovery = matches!(recovery, CrossAdapterRecovery::OfflineFullHistory);
    let clients = vec!["alice".into(), "bob".into(), "carol".into()];
    let mut steps = vec![
        in_group(
            "main",
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "initial".into(),
                invitees: vec!["bob".into(), "carol".into()],
                required_features: Vec::new(),
                initial_admins: Some(vec!["alice".into()]),
                pending: "create".into(),
            },
        ),
        ScenarioStep::AcknowledgeOutbound {
            client: "alice".into(),
            publication: Some("create".into()),
            selection: Default::default(),
            outcome: cgka_conformance_simulator::SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: vec!["bob".into(), "carol".into()],
        },
        in_group(
            "main",
            ScenarioStep::ClearEvents {
                clients: clients.clone(),
            },
        ),
    ];
    if include_offline_recovery {
        steps.push(ScenarioStep::SetClientOffline {
            client: "bob".into(),
        });
    }
    steps.extend([
        in_group(
            "main",
            ScenarioStep::UpdateGroupProfile {
                client: "alice".into(),
                name: Some("equivalent result".into()),
                description: Some("equivalent description".into()),
                pending: "rename".into(),
            },
        ),
        ScenarioStep::AcknowledgeOutbound {
            client: "alice".into(),
            publication: Some("rename".into()),
            selection: Default::default(),
            outcome: cgka_conformance_simulator::SubjectOutboundOutcome::Accepted,
        },
        in_group(
            "main",
            ScenarioStep::SendAppMessage {
                sender: "alice".into(),
                payload: "sent before restart".into(),
            },
        ),
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: vec!["alice".into(), "carol".into()],
        },
        ScenarioStep::RestartClient {
            client: "carol".into(),
        },
    ]);
    if include_offline_recovery {
        steps.extend([
            ScenarioStep::ReconnectClient {
                client: "bob".into(),
            },
            ScenarioStep::SyncRelayHistory {
                clients: clients.clone(),
                sync: cgka_conformance_simulator::ScenarioRelaySyncModeV2::FullHistory,
            },
        ]);
    }
    steps.extend([
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
        in_group(
            "main",
            ScenarioStep::SendAppMessage {
                sender: "alice".into(),
                payload: "sent after restart".into(),
            },
        ),
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
        in_group(
            "main",
            ScenarioStep::Observe {
                clients: clients.clone(),
            },
        ),
    ]);
    ScenarioSpec {
        name: if include_offline_recovery {
            "app-process-offline-restart-recovery".into()
        } else {
            "cross-adapter-restart-recovery".into()
        },
        spec_version: "3".into(),
        clients,
        topology: Default::default(),
        steps,
    }
}

fn cross_adapter_restart_scenario() -> ScenarioSpec {
    build_cross_adapter_scenario(CrossAdapterRecovery::Restart)
}

fn cross_adapter_offline_scenario() -> ScenarioSpec {
    build_cross_adapter_scenario(CrossAdapterRecovery::OfflineFullHistory)
}

fn cross_route_app_runtime_scenario(strict_engine_tail: bool) -> ScenarioSpec {
    let clients = vec![
        "zeta".into(),
        "alpha".into(),
        "yankee".into(),
        "observer".into(),
    ];
    let mut steps = vec![
        in_group(
            "main",
            ScenarioStep::CreateGroup {
                creator: "zeta".into(),
                name: "cross-route".into(),
                invitees: vec!["alpha".into(), "yankee".into(), "observer".into()],
                required_features: Vec::new(),
                initial_admins: Some(vec!["zeta".into()]),
                pending: "create".into(),
            },
        ),
        ScenarioStep::AcknowledgeOutbound {
            client: "zeta".into(),
            publication: Some("create".into()),
            selection: Default::default(),
            outcome: cgka_conformance_simulator::SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["alpha".into(), "yankee".into(), "observer".into()],
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: vec!["alpha".into(), "yankee".into(), "observer".into()],
        },
        in_group(
            "main",
            ScenarioStep::UpdateAdminPolicy {
                client: "zeta".into(),
                admins: vec!["zeta".into(), "alpha".into()],
                pending: "promote-alpha".into(),
            },
        ),
        ScenarioStep::AcknowledgeOutbound {
            client: "zeta".into(),
            publication: Some("promote-alpha".into()),
            selection: Default::default(),
            outcome: cgka_conformance_simulator::SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
        in_group(
            "main",
            ScenarioStep::UpdateAdminPolicy {
                client: "zeta".into(),
                admins: vec!["zeta".into(), "alpha".into(), "yankee".into()],
                pending: "promote-yankee".into(),
            },
        ),
        ScenarioStep::AcknowledgeOutbound {
            client: "zeta".into(),
            publication: Some("promote-yankee".into()),
            selection: Default::default(),
            outcome: cgka_conformance_simulator::SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
        in_group(
            "main",
            ScenarioStep::ClearEvents {
                clients: clients.clone(),
            },
        ),
        in_group(
            "main",
            ScenarioStep::Observe {
                clients: clients.clone(),
            },
        ),
        ScenarioStep::SetClientOffline {
            client: "alpha".into(),
        },
        ScenarioStep::SetClientOffline {
            client: "observer".into(),
        },
        in_group(
            "main",
            ScenarioStep::UpdateGroupData {
                client: "zeta".into(),
                name: "zeta-root".into(),
                pending: "zeta-root".into(),
            },
        ),
        ScenarioStep::AcknowledgeOutbound {
            client: "zeta".into(),
            publication: Some("zeta-root".into()),
            selection: Default::default(),
            outcome: cgka_conformance_simulator::SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["yankee".into()],
            sync: ScenarioRelaySyncModeV2::Incremental,
        },
        ScenarioStep::Tick {
            clients: vec!["yankee".into()],
        },
        in_group(
            "main",
            ScenarioStep::SendAppMessage {
                sender: "yankee".into(),
                payload: "zeta-branch-witness".into(),
            },
        ),
        ScenarioStep::SetClientOffline {
            client: "zeta".into(),
        },
        ScenarioStep::SetClientOffline {
            client: "yankee".into(),
        },
        ScenarioStep::SetRelayEventVisibility {
            relay: "relay:shared".into(),
            selector: ScenarioMessageSelectorV2 {
                action_id: Some("step-16:update_group_data@main".into()),
                ..Default::default()
            },
            clients: vec!["alpha".into(), "observer".into()],
            visible: false,
        },
        ScenarioStep::ReconnectClient {
            client: "alpha".into(),
        },
        in_group(
            "main",
            ScenarioStep::UpdateGroupData {
                client: "alpha".into(),
                name: "alpha-root".into(),
                pending: "alpha-root".into(),
            },
        ),
        ScenarioStep::AcknowledgeOutbound {
            client: "alpha".into(),
            publication: Some("alpha-root".into()),
            selection: Default::default(),
            outcome: cgka_conformance_simulator::SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::ReconnectClient {
            client: "zeta".into(),
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["zeta".into()],
            sync: ScenarioRelaySyncModeV2::Incremental,
        },
        ScenarioStep::Tick {
            clients: vec!["zeta".into()],
        },
        ScenarioStep::SetClientOffline {
            client: "alpha".into(),
        },
        ScenarioStep::SetClientOffline {
            client: "zeta".into(),
        },
        ScenarioStep::SetRelayEventVisibility {
            relay: "relay:shared".into(),
            selector: ScenarioMessageSelectorV2 {
                action_id: Some("step-25:update_group_data@main".into()),
                ..Default::default()
            },
            clients: vec!["yankee".into(), "observer".into()],
            visible: false,
        },
        in_group(
            "main",
            ScenarioStep::Observe {
                clients: clients.clone(),
            },
        ),
        ScenarioStep::ReconnectClient {
            client: "yankee".into(),
        },
        in_group(
            "main",
            ScenarioStep::UpdateGroupData {
                client: "yankee".into(),
                name: "zeta-branch-depth-two".into(),
                pending: "zeta-child".into(),
            },
        ),
        ScenarioStep::AcknowledgeOutbound {
            client: "yankee".into(),
            publication: Some("zeta-child".into()),
            selection: Default::default(),
            outcome: cgka_conformance_simulator::SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::RestartClient {
            client: "zeta".into(),
        },
        ScenarioStep::ReconnectClient {
            client: "zeta".into(),
        },
        ScenarioStep::SetRelayEventVisibility {
            relay: "relay:shared".into(),
            selector: ScenarioMessageSelectorV2 {
                action_id: Some("step-16:update_group_data@main".into()),
                ..Default::default()
            },
            clients: vec!["alpha".into(), "observer".into()],
            visible: true,
        },
        ScenarioStep::SetRelayEventVisibility {
            relay: "relay:shared".into(),
            selector: ScenarioMessageSelectorV2 {
                action_id: Some("step-25:update_group_data@main".into()),
                ..Default::default()
            },
            clients: vec!["yankee".into(), "observer".into()],
            visible: true,
        },
        ScenarioStep::ReconnectClient {
            client: "alpha".into(),
        },
        ScenarioStep::ReconnectClient {
            client: "observer".into(),
        },
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
    ];
    if strict_engine_tail {
        steps.push(ScenarioStep::AwaitQuiescence {
            policy: cgka_conformance_simulator::QuiescencePolicy {
                max_iterations: 200,
                ..Default::default()
            },
        });
    }
    for client in &clients {
        steps.push(in_group(
            "main",
            ScenarioStep::SendAppMessage {
                sender: client.clone(),
                payload: format!("probe-from-{client}"),
            },
        ));
    }
    steps.extend([
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
        ScenarioStep::SyncRelayHistory {
            clients: clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::Tick {
            clients: clients.clone(),
        },
    ]);
    if strict_engine_tail {
        steps.push(ScenarioStep::AwaitQuiescence {
            policy: cgka_conformance_simulator::QuiescencePolicy {
                max_iterations: 200,
                ..Default::default()
            },
        });
    }
    steps.push(in_group(
        "main",
        ScenarioStep::Observe {
            clients: clients.clone(),
        },
    ));
    if !strict_engine_tail {
        steps.push(in_group(
            "main",
            ScenarioStep::Observe {
                clients: clients.clone(),
            },
        ));
    }
    if strict_engine_tail {
        steps.extend([
            in_group(
                "main",
                ScenarioStep::ProbeBidirectionalDecryptability {
                    clients: clients.clone(),
                },
            ),
            in_group(
                "main",
                ScenarioStep::ObserveExact {
                    clients: clients.clone(),
                },
            ),
        ]);
    }
    let topology = single_relay_topology(&clients);
    ScenarioSpec {
        name: "cross-route-app-runtime-recovery/v1".into(),
        spec_version: "2".into(),
        clients,
        topology,
        steps,
    }
}

async fn run_app_runtime_adapter(
    spec: &ScenarioSpec,
) -> (
    cgka_conformance_simulator::ScenarioReport,
    BTreeMap<String, AppRuntimeObservationV1>,
) {
    let mut app = AppRuntimeHarness::new(&spec.clients).await.unwrap();
    let app_report = run_scenario_report_with_subject(spec, None, Vec::new(), &mut app)
        .await
        .unwrap();
    assert!(app_report.invariant_failures.is_empty(), "{app_report:#?}");
    assert_eq!(
        app_report.step_log.len(),
        compile_scenario(spec).unwrap().expanded_schedule().len(),
        "{app_report:#?}"
    );
    let app_observations = app
        .observations(&spec.clients)
        .await
        .unwrap()
        .into_iter()
        .map(|observation| (observation.participant.clone(), observation))
        .collect::<BTreeMap<_, _>>();
    app.shutdown().await;
    (app_report, app_observations)
}

async fn run_app_and_process_adapters(
    spec: &ScenarioSpec,
) -> (
    BTreeMap<String, AppRuntimeObservationV1>,
    BTreeMap<String, NodeObservationV1>,
) {
    let (_, app_observations) = run_app_runtime_adapter(spec).await;

    let process_artifacts = tempfile::tempdir().unwrap();
    let mut process = ProcessOrchestrator::launch(
        env!("CARGO_BIN_EXE_cgka-conformance-node"),
        spec,
        process_artifacts.path(),
    )
    .await
    .unwrap();
    let process_report = process.run().await.unwrap();
    assert!(process_report.completed, "{process_report:#?}");
    let process_observations = process_report
        .observations
        .iter()
        .rev()
        .take(spec.clients.len())
        .map(|observation| (observation.participant.clone(), observation.clone()))
        .collect::<BTreeMap<_, _>>();

    process.shutdown().await;
    (app_observations, process_observations)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn orchestrator_runs_canonical_schedule_with_isolated_process_roots() {
    let spec = process_scenario("app-process-canonical-schedule", false);
    let expected_schedule = compile_scenario(&spec).unwrap().expanded_schedule();
    let artifacts = tempfile::tempdir().unwrap();
    let mut orchestrator = ProcessOrchestrator::launch(
        env!("CARGO_BIN_EXE_cgka-conformance-node"),
        &spec,
        artifacts.path(),
    )
    .await
    .unwrap();
    let roots = orchestrator.participant_roots();
    assert_eq!(roots.values().collect::<BTreeSet<_>>().len(), 2);
    #[cfg(unix)]
    for root in roots.values() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    let report = orchestrator.run().await.unwrap();
    assert!(report.completed, "{report:#?}");
    assert_eq!(report.canonical_schedule, expected_schedule);
    assert_eq!(report.actions.len(), expected_schedule.len());
    let final_observations = &report.observations[report.observations.len() - 2..];
    assert_eq!(
        final_observations
            .iter()
            .map(|item| item.protocol.state_commitment_sha256.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        1,
        "{final_observations:#?}"
    );
    for observation in final_observations {
        assert_eq!(observation.protocol.member_identities, ["alice", "bob"]);
        assert_eq!(observation.protocol.group_name, "settled process group");
        assert_eq!(
            observation.application.visible_plaintexts,
            ["visible after settlement"]
        );
        assert!(observation.application.invalidated_message_ids.is_empty());
        assert!(observation.progress.observably_quiescent());
    }
    orchestrator.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_app_runtime_and_process_adapters_reach_equivalent_public_state() {
    let spec = cross_adapter_restart_scenario();
    let engine_report = run_scenario_report(&spec, None).await.unwrap();
    let engine = engine_report
        .observed_trace
        .as_ref()
        .unwrap()
        .observations
        .iter()
        .map(|observation| (observation.client.as_str(), observation))
        .collect::<BTreeMap<_, _>>();

    let (app_observations, process_observations) = run_app_and_process_adapters(&spec).await;

    for client in &spec.clients {
        let engine = engine[client.as_str()];
        let app = &app_observations[client];
        let process = &process_observations[client];

        assert_eq!(engine.epoch, app.protocol.epoch, "{client} app epoch");
        assert_eq!(
            engine.epoch, process.protocol.epoch,
            "{client} process epoch"
        );
        assert_eq!(
            engine.member_count, app.protocol.member_count,
            "{client} app roster"
        );
        assert_eq!(
            engine.member_count, process.protocol.member_count,
            "{client} process roster"
        );
        assert_eq!(
            engine.group_name, app.protocol.group_name,
            "{client} app name"
        );
        assert_eq!(
            engine.group_name, process.protocol.group_name,
            "{client} process name"
        );
        assert_eq!(
            engine.group_description, app.protocol.group_description,
            "{client} app description"
        );
        assert_eq!(
            engine.group_description, process.protocol.group_description,
            "{client} process description"
        );
        assert_eq!(engine.group_description, "equivalent description");
        let app_payloads = app
            .application
            .visible_plaintexts
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let process_payloads = process
            .application
            .visible_plaintexts
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            app_payloads, process_payloads,
            "{client} app/process projection"
        );
        assert_eq!(app.application.visible_plaintexts.len(), app_payloads.len());
        assert_eq!(
            process.application.visible_plaintexts.len(),
            process_payloads.len()
        );
        if client == "alice" {
            // The engine harness observes inbound delivery only, while the app
            // projection also includes the sender's locally authored rows.
            assert!(engine.received_payloads.is_empty());
        } else if client == "carol" {
            // Restart clears the engine harness's in-memory event window; the
            // app/process projection correctly retains already-projected rows.
            assert_eq!(engine.received_payloads, ["sent after restart"]);
        } else {
            let engine_payloads = engine
                .received_payloads
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            assert_eq!(
                engine_payloads, app_payloads,
                "{client} inbound application projection"
            );
            assert_eq!(engine.received_payloads.len(), engine_payloads.len());
        }
        assert_eq!(
            app.protocol.state_commitment_sha256, process.protocol.state_commitment_sha256,
            "{client} public commitment"
        );
        assert_eq!(app.protocol.member_identities, ["alice", "bob", "carol"]);
        assert_eq!(app.protocol.admin_identities, ["alice"]);
        assert!(app.application.invalidated_message_ids.is_empty());
        assert!(process.application.invalidated_message_ids.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_runtime_and_process_adapters_recover_the_same_offline_projection() {
    let spec = cross_adapter_offline_scenario();
    let (app_observations, process_observations) = run_app_and_process_adapters(&spec).await;

    let expected_payloads = BTreeSet::from(["sent after restart", "sent before restart"]);
    let bob = &app_observations["bob"];
    assert!(bob.local.online, "bob must be reconnected at the end");
    assert!(
        bob.local.reopen_count > 0,
        "bob's offline runtime must have reopened"
    );
    assert!(
        bob.local.catch_up_attempts > 0,
        "bob must have executed retained-history catch-up"
    );
    for client in &spec.clients {
        let app = &app_observations[client];
        let process = &process_observations[client];
        assert_eq!(
            app.protocol, process.protocol,
            "{client} protocol projection"
        );
        let app_payloads = app
            .application
            .visible_plaintexts
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let process_payloads = process
            .application
            .visible_plaintexts
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(app_payloads, expected_payloads, "{client} app message set");
        assert_eq!(
            process_payloads, expected_payloads,
            "{client} process message set"
        );
        assert_eq!(app.application.visible_plaintexts.len(), app_payloads.len());
        assert_eq!(
            process.application.visible_plaintexts.len(),
            process_payloads.len()
        );
        assert!(app.application.invalidated_message_ids.is_empty());
        assert!(process.application.invalidated_message_ids.is_empty());
        assert!(!app.application.pending_confirmation);
        assert!(!process.application.pending_confirmation);
        assert_eq!(
            app.application.stored_member_count,
            process.application.stored_member_count
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_party_cross_route_recovery_characterizes_corrected_app_runtime_outcomes() {
    let strict_spec = cross_route_app_runtime_scenario(true);
    let clients = strict_spec.clients.clone();
    let mut expectations = clients
        .iter()
        .map(|client| TraceExpectation::ClientState {
            client: client.clone(),
            epoch: 5,
            member_count: 4,
            received_payloads: None,
            added_members: None,
            removed_members: None,
        })
        .collect::<Vec<_>>();
    expectations.extend([
        TraceExpectation::GroupProfile {
            client: "zeta".into(),
            name: "zeta-branch-depth-two".into(),
            description: String::new(),
        },
        TraceExpectation::ClientsExactlyEquivalent {
            clients: clients.clone(),
        },
        TraceExpectation::ClientsBidirectionallyDecryptable {
            clients: clients.clone(),
        },
        TraceExpectation::NoPendingWork {
            clients: clients.clone(),
        },
    ]);
    let mut retained = RetainedRelaySubject::new(
        &clients,
        &strict_spec.topology,
        ProtocolProfile::Legacy,
        HarnessStorageMode::TempFileBackedSqlite,
    )
    .unwrap();
    let retained_report =
        run_scenario_report_with_subject(&strict_spec, None, expectations, &mut retained)
            .await
            .unwrap();
    assert!(
        retained_report.invariant_failures.is_empty(),
        "retained-engine invariants: {:#?}; steps: {:#?}",
        retained_report.invariant_failures,
        retained_report.step_log
    );
    assert!(
        retained_report.expectation_failures.is_empty(),
        "retained-engine expectations: {:#?}",
        retained_report.expectation_failures
    );
    let retained_trace = retained_report.observed_trace.unwrap();
    assert_eq!(retained_trace.observations.len(), clients.len() * 4);
    let retained_baseline = retained_trace.observations[..clients.len()]
        .iter()
        .map(|observation| (observation.client.as_str(), observation))
        .collect::<BTreeMap<_, _>>();
    let retained_observations = retained_trace
        .observations
        .iter()
        .rev()
        .take(clients.len())
        .map(|observation| (observation.client.clone(), observation))
        .collect::<BTreeMap<_, _>>();
    for observation in retained_observations.values() {
        for (scenario_id, disposition) in [
            (
                "step-16:update_group_data@main",
                ScenarioInputDisposition::Accepted,
            ),
            (
                "step-25:update_group_data@main",
                ScenarioInputDisposition::Invalidated,
            ),
            (
                "step-35:update_group_data@main",
                ScenarioInputDisposition::Accepted,
            ),
        ] {
            let entry = observation
                .scenario_input_ledger
                .iter()
                .find(|entry| entry.scenario_id == scenario_id)
                .unwrap_or_else(|| {
                    panic!(
                        "{} missing durable disposition for {scenario_id}",
                        observation.client
                    )
                });
            assert_eq!(
                entry.disposition, disposition,
                "{} disposition for {scenario_id}",
                observation.client
            );
        }
    }

    let public_spec = cross_route_app_runtime_scenario(false);
    let (app_report, app_observations) = run_app_runtime_adapter(&public_spec).await;
    let app_trace = app_report.observed_trace.unwrap().observations;
    assert_eq!(app_trace.len(), clients.len() * 4);
    let app_baseline = app_trace[..clients.len()]
        .iter()
        .map(|observation| (observation.client.as_str(), observation))
        .collect::<BTreeMap<_, _>>();
    let app_routed = app_trace[clients.len()..clients.len() * 2]
        .iter()
        .map(|observation| (observation.client.as_str(), observation))
        .collect::<BTreeMap<_, _>>();
    // Alpha and Observer have not ticked since the pre-split checkpoint, so
    // these two values pin cached schedule state. Zeta and Yankee's refreshed
    // epoch-4 observations are the independent evidence of the routed split.
    assert_eq!(app_routed["zeta"].epoch, 4);
    assert_eq!(app_routed["alpha"].epoch, 3);
    assert_eq!(app_routed["yankee"].epoch, 4);
    assert_eq!(app_routed["observer"].epoch, 3);
    let mut expected_payloads = clients
        .iter()
        .map(|client| format!("probe-from-{client}"))
        .collect::<BTreeSet<_>>();
    expected_payloads.insert("zeta-branch-witness".into());
    let mut protocol_equivalent = true;
    let mut protocol_equivalent_by_client = BTreeMap::new();
    let mut protocol_non_epoch_equivalent_by_client = BTreeMap::new();
    let mut app_payloads_by_client = BTreeMap::new();
    let mut invalidated_counts_by_client = BTreeMap::new();
    for client in &clients {
        let retained = retained_observations[client];
        let app = &app_observations[client];
        let retained_baseline = retained_baseline[client.as_str()];
        let app_baseline = app_baseline[client.as_str()];
        assert_eq!(
            app_baseline.epoch, retained_baseline.epoch,
            "{client} baseline epoch"
        );
        assert_eq!(
            retained.epoch - retained_baseline.epoch,
            2,
            "{client} retained route depth"
        );
        let non_epoch_equivalent = app.protocol.member_count == retained.member_count
            && app.protocol.member_identities == ["alpha", "observer", "yankee", "zeta"]
            && app.protocol.group_name == retained.group_name
            && app.protocol.group_description == retained.group_description;
        let client_protocol_equivalent =
            app.protocol.epoch == retained.epoch && non_epoch_equivalent;
        protocol_equivalent &= client_protocol_equivalent;
        protocol_equivalent_by_client.insert(client.clone(), client_protocol_equivalent);
        protocol_non_epoch_equivalent_by_client.insert(client.clone(), non_epoch_equivalent);
        assert_eq!(app.protocol.member_count, 4, "{client} roster size");
        assert_eq!(
            app.protocol.member_identities,
            ["alpha", "observer", "yankee", "zeta"],
            "{client} exact roster"
        );
        assert_eq!(app.protocol.admin_identities, ["alpha", "yankee", "zeta"]);
        let app_payloads = app
            .application
            .visible_plaintexts
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(
            app_payloads.is_subset(&expected_payloads),
            "{client} projected an unexpected application payload"
        );
        assert_eq!(app.application.visible_plaintexts.len(), app_payloads.len());
        app_payloads_by_client.insert(client.clone(), app_payloads);
        invalidated_counts_by_client.insert(
            client.clone(),
            app.application.invalidated_message_ids.len(),
        );
        assert!(!app.application.pending_confirmation);
    }

    // Applying Alpha's losing `alpha-root` commit synthesizes one kind-1210
    // rename row stamped with that commit's id; reorging onto the selected
    // branch rolls the commit back and `GroupStateInvalidated` withdraws that
    // row. The retained tombstone is therefore each participant's own evidence
    // that it once held the losing branch, so the rule below is per participant
    // and never compares ids across them — a reorged peer's row is unattributed
    // where Alpha's names itself, so the two are not even the same canonical id.
    //
    // Alpha published and confirmed the commit, so it always holds the row and
    // owes a withdrawal exactly when it ends off that branch. Zeta is the rival
    // same-epoch committer and defers only to a deeper branch; Yankee is already
    // two commits deep on the selected branch before `step-25` reaches it.
    // Neither ever synthesizes the row. Observer holds no branch of its own when
    // both commits arrive, so whether it adopts Alpha's before the selected
    // branch displaces it is a delivery-order detail: it may or may not carry
    // the withdrawal, but only after leaving the losing branch.
    for client in &clients {
        let app = &app_observations[client];
        let invalidated = invalidated_counts_by_client[client];
        let left_the_losing_branch = app.protocol.group_name != "alpha-root"
            && app.protocol.epoch > app_baseline[client.as_str()].epoch;
        assert!(
            invalidated <= 1,
            "{client} withdrew more than the losing commit's one row: {invalidated_counts_by_client:#?}"
        );
        assert!(
            invalidated == 0 || left_the_losing_branch,
            "{client} withdrew a losing-branch row without leaving that branch: {app:#?}"
        );
        if client == "alpha" {
            assert_eq!(
                invalidated,
                usize::from(left_the_losing_branch),
                "alpha owes its own confirmed alpha-root row a withdrawal exactly when it leaves that branch: {app:#?}"
            );
        }
        if client == "yankee" || client == "zeta" {
            assert_eq!(
                invalidated, 0,
                "{client} never adopted alpha's branch yet withdrew a row: {app:#?}"
            );
        }
        let visible = app
            .application
            .visible_message_ids
            .iter()
            .collect::<BTreeSet<_>>();
        assert!(
            app.application
                .invalidated_message_ids
                .iter()
                .all(|id| !visible.contains(id)),
            "{client} projected a withdrawn row as delivered: {app:#?}"
        );
    }

    let fully_equivalent = protocol_equivalent
        && app_payloads_by_client
            .values()
            .all(|payloads| payloads == &expected_payloads);

    let zeta_one_epoch_behind = clients.iter().all(|client| {
        if client == "zeta" {
            let app = &app_observations[client];
            let retained = retained_observations[client];
            app.protocol.epoch.checked_add(1) == Some(retained.epoch)
                && protocol_non_epoch_equivalent_by_client[client]
        } else {
            protocol_equivalent_by_client[client]
        }
    }) && app_payloads_by_client
        .values()
        .all(|payloads| payloads == &expected_payloads);

    let missing_at_zeta_after_agreement = |missing: &[&str]| {
        let mut expected_at_zeta = expected_payloads.clone();
        for payload in missing {
            assert!(expected_at_zeta.remove(*payload));
        }
        protocol_equivalent
            && clients.iter().all(|client| {
                let expected = if client == "zeta" {
                    &expected_at_zeta
                } else {
                    &expected_payloads
                };
                &app_payloads_by_client[client] == expected
            })
    };

    let payload_set = |payloads: &[&str]| {
        payloads
            .iter()
            .map(|payload| (*payload).to_owned())
            .collect::<BTreeSet<_>>()
    };
    let alpha_branch = |client: &str| {
        let app = &app_observations[client];
        app.protocol.epoch == app_baseline[client].epoch + 1
            && app.protocol.group_name == "alpha-root"
            && app.protocol.group_description.is_empty()
    };
    let legacy_split = alpha_branch("alpha")
        && app_observations["observer"].protocol.epoch == app_baseline["observer"].epoch
        && app_observations["observer"].protocol.group_name == "cross-route"
        && app_observations["observer"]
            .protocol
            .group_description
            .is_empty()
        && protocol_equivalent_by_client["yankee"]
        && protocol_equivalent_by_client["zeta"]
        && app_payloads_by_client["alpha"]
            == payload_set(&["probe-from-alpha", "probe-from-observer"])
        && app_payloads_by_client["observer"] == payload_set(&["probe-from-observer"])
        && app_payloads_by_client["yankee"]
            == payload_set(&[
                "probe-from-observer",
                "probe-from-yankee",
                "probe-from-zeta",
                "zeta-branch-witness",
            ])
        && app_payloads_by_client["zeta"] == app_payloads_by_client["yankee"];
    let corrected_split = alpha_branch("alpha")
        && alpha_branch("observer")
        && protocol_equivalent_by_client["yankee"]
        && protocol_equivalent_by_client["zeta"]
        && app_payloads_by_client["alpha"]
            == payload_set(&["probe-from-alpha", "probe-from-observer"])
        && app_payloads_by_client["observer"] == app_payloads_by_client["alpha"]
        && app_payloads_by_client["yankee"]
            == payload_set(&[
                "probe-from-yankee",
                "probe-from-zeta",
                "zeta-branch-witness",
            ])
        && app_payloads_by_client["zeta"] == app_payloads_by_client["yankee"];

    assert!(
        fully_equivalent
            || zeta_one_epoch_behind
            || missing_at_zeta_after_agreement(&["probe-from-alpha"])
            || missing_at_zeta_after_agreement(&["probe-from-alpha", "probe-from-observer",])
            || legacy_split
            || corrected_split,
        "app-runtime route result was not a characterized corrected-input outcome; protocol_match={protocol_equivalent_by_client:#?}; payloads={app_payloads_by_client:#?}; invalidated={invalidated_counts_by_client:#?}; observations={app_observations:#?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn process_adapter_executes_the_ir_embedded_in_a_saved_generated_input() {
    let spec = cross_adapter_restart_scenario();
    let input = GeneratedScenarioInputV1::new(GeneratedScenarioCase {
        family_name: "selectable-process/v1".into(),
        generator_version: "4".into(),
        seed: 17,
        case_index: 2,
        subject: GeneratedSubjectKind::Engine,
        scenario: spec.clone(),
        expected_outcomes: vec![TraceExpectation::GroupProfile {
            client: "alice".into(),
            name: "equivalent result".into(),
            description: "equivalent description".into(),
        }],
    });
    let resolved = resolve_scenario_input_bytes(&serde_json::to_vec(&input).unwrap()).unwrap();
    let artifacts = tempfile::tempdir().unwrap();
    let mut process = ProcessOrchestrator::launch_resolved(
        env!("CARGO_BIN_EXE_cgka-conformance-node"),
        &resolved,
        artifacts.path(),
    )
    .await
    .unwrap();

    let report = process.run().await.unwrap();
    assert!(report.completed, "{report:#?}");
    assert_eq!(report.expected_outcomes, input.case.expected_outcomes);
    assert_eq!(
        report.executed_scenario_ir_sha256.as_deref(),
        Some(resolved.provenance.canonical_ir_sha256.as_str())
    );
    let provenance = report.input_provenance.unwrap();
    assert_eq!(
        provenance.canonical_ir_sha256,
        resolved.provenance.canonical_ir_sha256
    );
    assert_eq!(
        provenance.generated.unwrap().family_name,
        "selectable-process/v1"
    );
    process.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn process_kill_pause_resume_and_restart_agree_with_uninterrupted_execution() {
    let uninterrupted_spec = process_scenario("uninterrupted-app-process", false);
    let uninterrupted_artifacts = tempfile::tempdir().unwrap();
    let mut uninterrupted = ProcessOrchestrator::launch(
        env!("CARGO_BIN_EXE_cgka-conformance-node"),
        &uninterrupted_spec,
        uninterrupted_artifacts.path(),
    )
    .await
    .unwrap();
    let uninterrupted_report = uninterrupted.run().await.unwrap();
    assert!(uninterrupted_report.completed, "{uninterrupted_report:#?}");
    let uninterrupted_final =
        &uninterrupted_report.observations[uninterrupted_report.observations.len() - 2..];
    uninterrupted.shutdown().await;

    let recovered_spec = process_scenario("recovered-app-process", true);
    let recovered_artifacts = tempfile::tempdir().unwrap();
    let mut recovered = ProcessOrchestrator::launch(
        env!("CARGO_BIN_EXE_cgka-conformance-node"),
        &recovered_spec,
        recovered_artifacts.path(),
    )
    .await
    .unwrap();
    let recovered_report = recovered.run().await.unwrap();
    assert!(recovered_report.completed, "{recovered_report:#?}");
    let recovered_final = &recovered_report.observations[recovered_report.observations.len() - 2..];

    let public_results =
        |observations: &[cgka_conformance_simulator::node_protocol::NodeObservationV1]| {
            observations
                .iter()
                .map(|item| {
                    (
                        item.participant.clone(),
                        item.protocol.clone(),
                        item.application.visible_plaintexts.clone(),
                        item.application.invalidated_message_ids.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
    assert_eq!(
        public_results(uninterrupted_final),
        public_results(recovered_final)
    );
    assert!(
        recovered_report
            .lifecycle
            .iter()
            .any(|event| event.event == "paused")
    );
    assert!(
        recovered_report
            .lifecycle
            .iter()
            .any(|event| event.event == "resumed")
    );
    assert!(
        recovered_report
            .lifecycle
            .iter()
            .any(|event| event.event == "killed")
    );
    assert!(
        recovered_report
            .lifecycle
            .iter()
            .any(|event| event.event == "restarted")
    );
    recovered.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn process_failures_write_replayable_privacy_safe_capsules() {
    let marker = "sensitive-production-log-marker";
    let mut spec = process_scenario("app-process-failure-capsule", false);
    spec.steps.push(in_group(
        "main",
        ScenarioStep::ExpectUpdateAdminPolicyError {
            client: "alice".into(),
            admins: vec!["alice".into()],
            error: marker.into(),
        },
    ));
    let artifacts = tempfile::tempdir().unwrap();
    let mut orchestrator = ProcessOrchestrator::launch(
        env!("CARGO_BIN_EXE_cgka-conformance-node"),
        &spec,
        artifacts.path(),
    )
    .await
    .unwrap();
    let report = orchestrator.run().await.unwrap();
    assert!(!report.completed);
    assert_eq!(report.failure_capsules.len(), 1);
    let capsule_path = &report.failure_capsules[0];
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(capsule_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let encoded = std::fs::read_to_string(capsule_path).unwrap();
    assert!(!encoded.contains(marker));
    let capsule: cgka_conformance_simulator::node_protocol::NodeFailureCapsuleV1 =
        serde_json::from_str(&encoded).unwrap();
    assert_eq!(capsule.participant, "alice");
    assert!(
        capsule
            .action_id
            .contains("expect_update_admin_policy_error")
    );
    assert_eq!(capsule.layer, "app_process");
    assert!(!capsule.replay.steps.is_empty());
    assert!(!capsule.sensitive_data_included);
    orchestrator.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unsupported_process_capabilities_fail_before_launch() {
    let mut spec = process_scenario("unsupported-process-capability", false);
    spec.steps.push(ScenarioStep::OmitMessage {
        selector: cgka_conformance_simulator::ScenarioMessageSelectorV2 {
            sender: Some("alice".into()),
            ..Default::default()
        },
    });
    let artifacts = tempfile::tempdir().unwrap();
    let error = match ProcessOrchestrator::launch(
        env!("CARGO_BIN_EXE_cgka-conformance-node"),
        &spec,
        artifacts.path(),
    )
    .await
    {
        Ok(mut orchestrator) => {
            orchestrator.shutdown().await;
            panic!("unsupported capability launched participant processes")
        }
        Err(error) => error,
    };
    assert_eq!(error.code, "process_capability_preflight");
    assert!(
        error
            .message
            .contains(&format!("scenario step {}", spec.steps.len() - 1)),
        "{}",
        error.message
    );
    assert!(error.message.contains("omit_message"), "{}", error.message);
}

#[tokio::test]
async fn external_relay_map_must_exactly_match_topology() {
    let spec = process_scenario("external-relay-map", false);
    let artifacts = tempfile::tempdir().unwrap();
    let error = match ProcessOrchestrator::launch_with(
        ProcessNodeLaunchV1::executable(env!("CARGO_BIN_EXE_cgka-conformance-node")),
        Some(BTreeMap::from([
            ("relay:a".into(), "ws://127.0.0.1:1".into()),
            ("relay:b".into(), "ws://127.0.0.1:2".into()),
            ("relay:unexpected".into(), "ws://127.0.0.1:3".into()),
        ])),
        &spec,
        artifacts.path(),
    )
    .await
    {
        Ok(mut orchestrator) => {
            orchestrator.shutdown().await;
            panic!("relay entries outside the topology launched participant processes")
        }
        Err(error) => error,
    };
    assert_eq!(error.code, "missing_external_relay");
}

#[test]
fn process_cli_writes_a_private_versioned_report() {
    let root = tempfile::tempdir().unwrap();
    let scenario_path = root.path().join("scenario.json");
    let report_path = root.path().join("report.json");
    fs_private::write_private(
        &scenario_path,
        &serde_json::to_vec_pretty(&cross_adapter_restart_scenario()).unwrap(),
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cgka-conformance-process"))
        .arg(&scenario_path)
        .arg(env!("CARGO_BIN_EXE_cgka-conformance-node"))
        .arg(&report_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&report_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let report: cgka_conformance_simulator::process_orchestrator::ProcessScenarioReportV1 =
        serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
    assert_eq!(report.schema_version, "1");
    assert!(report.completed, "{report:#?}");
}

#[test]
fn process_cli_failure_report_keeps_capsules_after_exit() {
    let root = tempfile::tempdir().unwrap();
    let scenario_path = root.path().join("scenario.json");
    let report_path = root.path().join("report.json");
    let mut spec = process_scenario("cli-failure-capsule", false);
    spec.steps.push(in_group(
        "main",
        ScenarioStep::ExpectUpdateAdminPolicyError {
            client: "alice".into(),
            admins: vec!["alice".into()],
            error: "controlled failure".into(),
        },
    ));
    fs_private::write_private(&scenario_path, &serde_json::to_vec_pretty(&spec).unwrap()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cgka-conformance-process"))
        .arg(&scenario_path)
        .arg(env!("CARGO_BIN_EXE_cgka-conformance-node"))
        .arg(&report_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: cgka_conformance_simulator::process_orchestrator::ProcessScenarioReportV1 =
        serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
    assert!(!report.completed);
    assert_eq!(report.failure_capsules.len(), 1);
    assert!(report.failure_capsules[0].is_file());
}
