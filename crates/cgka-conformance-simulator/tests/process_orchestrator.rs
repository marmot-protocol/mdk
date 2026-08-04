//! Long-lived multi-process convergence-orchestrator coverage.

use std::collections::BTreeSet;

use cgka_conformance_simulator::process_orchestrator::{
    PROCESS_SCENARIO_REPORT_SCHEMA_VERSION, ProcessOrchestrator,
};
use cgka_conformance_simulator::{
    AppRuntimeHarness, RouteCampaignAdapter, RouteRestartCheckpoint, ScenarioAccountV2,
    ScenarioDeviceV2, ScenarioProcessV2, ScenarioRelayV2, ScenarioSpec, ScenarioStep,
    ScenarioTopologyV2, compile_scenario, generate_cross_route_regression_family,
    run_scenario_report, run_scenario_report_with_subject, scenario_for_route_adapter,
};

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

fn cross_adapter_scenario() -> ScenarioSpec {
    ScenarioSpec {
        name: "cross-adapter-public-state".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into()],
        topology: Default::default(),
        steps: vec![
            in_group(
                "main",
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "initial".into(),
                    invitees: Vec::new(),
                    required_features: Vec::new(),
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                },
            ),
            in_group(
                "main",
                ScenarioStep::UpdateGroupData {
                    client: "alice".into(),
                    name: "equivalent result".into(),
                    pending: "rename".into(),
                },
            ),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            in_group(
                "main",
                ScenarioStep::Observe {
                    clients: vec!["alice".into()],
                },
            ),
        ],
    }
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
async fn separate_processes_recover_the_cross_route_deeper_branch() {
    let campaign = generate_cross_route_regression_family()
        .into_iter()
        .find(|campaign| campaign.restart_checkpoint == RouteRestartCheckpoint::None)
        .unwrap();
    let scenario = scenario_for_route_adapter(&campaign, RouteCampaignAdapter::Process);
    let artifacts = tempfile::tempdir().unwrap();
    let mut orchestrator = ProcessOrchestrator::launch(
        env!("CARGO_BIN_EXE_cgka-conformance-node"),
        &scenario,
        artifacts.path(),
    )
    .await
    .unwrap();

    let report = orchestrator.run().await.unwrap();
    assert!(report.completed, "{report:#?}");
    assert_eq!(report.decryptability_probes.len(), 1, "{report:#?}");
    assert!(report.decryptability_probes[0].succeeded(), "{report:#?}");
    assert!(
        report
            .application_dispositions
            .iter()
            .all(|disposition| !disposition.entry.pending),
        "{report:#?}"
    );
    let final_observations = &report.observations[report.observations.len() - 4..];
    assert_eq!(
        final_observations
            .iter()
            .map(|observation| observation.protocol.epoch)
            .collect::<BTreeSet<_>>()
            .len(),
        1,
        "{final_observations:#?}"
    );
    assert!(
        final_observations
            .iter()
            .all(|observation| observation.protocol.member_count == 6),
        "{final_observations:#?}"
    );
    assert_eq!(
        final_observations
            .iter()
            .map(|observation| observation.protocol.state_commitment_sha256.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        1,
        "{final_observations:#?}"
    );
    orchestrator.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_app_runtime_and_process_adapters_reach_equivalent_public_state() {
    let spec = cross_adapter_scenario();
    let engine_report = run_scenario_report(&spec, None).await.unwrap();
    let engine = engine_report
        .observed_trace
        .as_ref()
        .unwrap()
        .observations
        .last()
        .unwrap();

    let mut app = AppRuntimeHarness::new(&spec.clients).await.unwrap();
    let app_report = run_scenario_report_with_subject(&spec, None, Vec::new(), &mut app)
        .await
        .unwrap();
    assert!(app_report.invariant_failures.is_empty(), "{app_report:#?}");
    let app_observation = app.observations(&spec.clients).await.unwrap().remove(0);

    let process_artifacts = tempfile::tempdir().unwrap();
    let mut process = ProcessOrchestrator::launch(
        env!("CARGO_BIN_EXE_cgka-conformance-node"),
        &spec,
        process_artifacts.path(),
    )
    .await
    .unwrap();
    let process_report = process.run().await.unwrap();
    assert!(process_report.completed, "{process_report:#?}");
    let process_observation = process_report.observations.last().unwrap();

    assert_eq!(engine.epoch, app_observation.protocol.epoch);
    assert_eq!(engine.epoch, process_observation.protocol.epoch);
    assert_eq!(engine.member_count, app_observation.protocol.member_count);
    assert_eq!(
        engine.member_count,
        process_observation.protocol.member_count
    );
    assert_eq!(engine.group_name, app_observation.protocol.group_name);
    assert_eq!(engine.group_name, process_observation.protocol.group_name);
    assert_eq!(
        app_observation.protocol.state_commitment_sha256,
        process_observation.protocol.state_commitment_sha256
    );
    assert_eq!(app_observation.protocol.member_identities, ["alice"]);
    assert_eq!(app_observation.protocol.admin_identities, ["alice"]);

    process.shutdown().await;
    app.shutdown().await;
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
    spec.steps.push(in_group(
        "main",
        ScenarioStep::ProbeBidirectionalDecryptability {
            clients: vec!["alice".into(), "bob".into()],
        },
    ));
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
}

#[test]
fn process_cli_writes_a_private_versioned_report() {
    let root = tempfile::tempdir().unwrap();
    let scenario_path = root.path().join("scenario.json");
    let report_path = root.path().join("report.json");
    fs_private::write_private(
        &scenario_path,
        &serde_json::to_vec_pretty(&cross_adapter_scenario()).unwrap(),
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
    assert_eq!(
        report.schema_version,
        PROCESS_SCENARIO_REPORT_SCHEMA_VERSION
    );
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
