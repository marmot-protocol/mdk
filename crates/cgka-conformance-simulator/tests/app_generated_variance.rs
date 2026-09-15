//! Seed diversity is measured after removing labels, actors and payload text.
use std::collections::BTreeSet;

use cgka_conformance_simulator::{
    AppRuntimeHarness, ConvergenceSubject, GeneratedScenarioCase, ScenarioStep, compile_scenario,
    generate_family_case, preflight_compiled_scenario, validate_scenario_stimulus_evidence,
};

const FAMILIES: [&str; 2] = [
    "public-app-stateful-recovery/v1",
    "public-app-recovery-schedules/v1",
];

fn operation_order(case: &GeneratedScenarioCase) -> Vec<String> {
    compile_scenario(&case.scenario)
        .unwrap()
        .actions
        .into_iter()
        .filter(|a| {
            !matches!(
                a.step,
                ScenarioStep::Assert { .. }
                    | ScenarioStep::Observe { .. }
                    | ScenarioStep::ObserveAdminPolicy { .. }
                    | ScenarioStep::ClearEvents { .. }
                    | ScenarioStep::AcknowledgeOutbound { .. }
            )
        })
        .map(|a| a.step.kind().to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn seeded_app_schedules_change_operations_and_preflight_without_private_capabilities() {
    let mut subject = AppRuntimeHarness::new(&[]).await.unwrap();
    let descriptor = subject.descriptor();
    subject.shutdown().await.expect("app shutdown");
    for family in FAMILIES {
        let mut schedules = BTreeSet::new();
        let mut populations = BTreeSet::new();
        for seed in 0..128 {
            let case = generate_family_case(family, seed, 0).unwrap();
            assert_eq!(case, generate_family_case(family, seed, 0).unwrap());
            let serialized = serde_json::to_vec(&case).unwrap();
            assert_eq!(
                case,
                serde_json::from_slice::<GeneratedScenarioCase>(&serialized).unwrap()
            );
            let compiled = compile_scenario(&case.scenario).unwrap();
            preflight_compiled_scenario(&compiled, &descriptor).unwrap();
            schedules.insert(operation_order(&case));
            populations.insert(case.scenario.clients.len());
            if family == FAMILIES[0] {
                assert!(
                    compiled
                        .actions
                        .iter()
                        .any(|a| matches!(a.step, ScenarioStep::RaceGroupProfiles { .. }))
                );
                assert!(
                    compiled
                        .actions
                        .iter()
                        .any(|a| matches!(a.step, ScenarioStep::InterruptRelay { .. }))
                );
                assert!(
                    compiled
                        .actions
                        .iter()
                        .any(|a| matches!(a.step, ScenarioStep::RemoveMembers { .. }))
                );
                assert!(
                    compiled
                        .actions
                        .iter()
                        .any(|a| matches!(a.step, ScenarioStep::SetClientOffline { .. }))
                );
                assert!(validate_scenario_stimulus_evidence(&case.scenario, &[]).is_err());
            }
        }
        eprintln!(
            "{family}: {} distinct operation sequences across 128 seeds; populations={populations:?}",
            schedules.len()
        );
        assert!(
            schedules.len() >= 100,
            "seeds mostly repeat a fixed schedule for {family}"
        );
        if family == FAMILIES[0] {
            assert_eq!(populations, BTreeSet::from([3, 4, 5, 6]));
        }
        let short = (0..4)
            .map(|i| generate_family_case(family, 42, i).unwrap())
            .collect::<Vec<_>>();
        let long = (0..12)
            .map(|i| generate_family_case(family, 42, i).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(short, long[..4]);
    }
}

#[test]
fn runtime_stimuli_reject_invalid_callers_and_bounds_before_execution() {
    let case = generate_family_case(FAMILIES[0], 7, 0).unwrap();
    let edit = |client: &str| cgka_conformance_simulator::ScenarioProfileUpdate {
        client: client.into(),
        name: Some("profile".into()),
        description: None,
    };
    for invalid in [
        ScenarioStep::InterruptRelay {
            relay: "relay:default".into(),
            outage_ms: 0,
        },
        ScenarioStep::InterruptRelay {
            relay: "relay:default".into(),
            outage_ms: 30_001,
        },
        ScenarioStep::InterruptRelay {
            relay: "unknown".into(),
            outage_ms: 50,
        },
        ScenarioStep::RaceGroupProfiles {
            updates: Vec::new(),
        },
        ScenarioStep::RaceGroupProfiles {
            updates: vec![edit("alice"), edit("alice")],
        },
        ScenarioStep::RaceGroupProfiles {
            updates: vec![edit("alice"), edit("unknown")],
        },
    ] {
        let mut scenario = case.scenario.clone();
        scenario.steps.push(invalid);
        assert!(compile_scenario(&scenario).is_err());
    }
    let mut without_capabilities = cgka_conformance_simulator::SubjectDescriptor {
        adapter: "no-runtime-faults".into(),
        adapter_version: "1".into(),
        storage_backend: "none".into(),
        capabilities: BTreeSet::new(),
    };
    without_capabilities
        .capabilities
        .insert(cgka_conformance_simulator::SubjectCapability::GroupMutation);
    assert!(
        preflight_compiled_scenario(
            &compile_scenario(&case.scenario).unwrap(),
            &without_capabilities
        )
        .is_err()
    );
}

#[test]
fn runtime_stimulus_oracle_rejects_missing_faults_and_unaccepted_races() {
    use cgka_conformance_simulator::{
        ScenarioStimulusObservation as Evidence, app_runtime::ConcurrentMutationOutcome,
    };
    let case = generate_family_case(FAMILIES[0], 7, 0).unwrap();
    let observations = compile_scenario(&case.scenario)
        .unwrap()
        .actions
        .into_iter()
        .filter_map(|a| match a.step {
            ScenarioStep::InterruptRelay { outage_ms, .. } => Some(Evidence::RelayInterruption {
                action_id: a.schedule.action_id,
                requested_outage_ms: outage_ms,
                closed_connections: 2,
                rejected_connections: 0,
                runtimes_running: 3,
            }),
            ScenarioStep::RaceGroupProfiles { updates } => Some(Evidence::ConcurrentProfiles {
                action_id: a.schedule.action_id,
                callers_released: updates.len(),
                admitted_publications: 2,
                outcomes: updates
                    .into_iter()
                    .map(|u| ConcurrentMutationOutcome {
                        client: u.client,
                        accepted: true,
                        error_kind: None,
                    })
                    .collect(),
            }),
            _ => None,
        })
        .collect::<Vec<_>>();
    validate_scenario_stimulus_evidence(&case.scenario, &observations).unwrap();
    for index in 0..observations.len() {
        let mut missing = observations.clone();
        missing.remove(index);
        assert!(validate_scenario_stimulus_evidence(&case.scenario, &missing).is_err());
        let mut false_claim = observations.clone();
        match &mut false_claim[index] {
            Evidence::RelayInterruption {
                closed_connections, ..
            } => *closed_connections = 0,
            Evidence::ConcurrentProfiles { outcomes, .. } => outcomes[0].accepted = false,
        }
        assert!(validate_scenario_stimulus_evidence(&case.scenario, &false_claim).is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real participant processes, sockets and production settlement; run explicitly"]
async fn seeded_recovery_schedule_survives_real_process_kills() {
    use cgka_conformance_simulator::{
        GeneratedScenarioInputV1, process_orchestrator::ProcessOrchestrator,
        resolve_scenario_input_bytes, validate_cross_route_public_process_report,
    };
    let case = generate_family_case(FAMILIES[1], 7, 0).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let artifacts = std::env::var_os("MDK_APP_JOURNEY_ARTIFACTS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_owned());
    fs_private::create_dir_all_private(&artifacts).unwrap();
    let bytes = serde_json::to_vec_pretty(&GeneratedScenarioInputV1::new(case.clone())).unwrap();
    fs_private::write_private(&artifacts.join("generated-input.json"), &bytes).unwrap();
    let input = resolve_scenario_input_bytes(&bytes).unwrap();
    // Campaigns pin a production node copy before later compatibility builds.
    let node_binary = std::env::var_os("MDK_SCENARIO_NODE_BIN")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cgka-conformance-node").into());
    let mut process =
        ProcessOrchestrator::launch_resolved(node_binary, &input, artifacts.join("processes"))
            .await
            .unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(900), process.run()).await;
    if let Ok(Ok(report)) = &result {
        process
            .write_report_private(report, &artifacts.join("process-report.json"))
            .unwrap();
    }
    process.shutdown().await;
    let report = result.expect("process canary deadline").unwrap();
    validate_cross_route_public_process_report(&case.scenario, &report).unwrap();
    let restarts = case
        .scenario
        .steps
        .iter()
        .filter(|step| matches!(step, ScenarioStep::RestartClient { .. }))
        .count();
    assert!(restarts >= 3);
    let mut running = case
        .scenario
        .clients
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut expected_kills = 0;
    for step in &case.scenario.steps {
        match step {
            ScenarioStep::SetClientOffline { client } => {
                running.remove(client);
            }
            ScenarioStep::ReconnectClient { client } => {
                running.insert(client.clone());
            }
            ScenarioStep::RestartClient { client } => {
                expected_kills += usize::from(running.contains(client));
                running.insert(client.clone());
            }
            _ => {}
        }
    }
    assert!(expected_kills > 0);
    assert_eq!(
        report
            .lifecycle
            .iter()
            .filter(|event| event.event == "killed")
            .count(),
        expected_kills
    );
    // The strict process oracle must reject a run that merely claims reopens.
    let mut missing_kill = report;
    missing_kill
        .lifecycle
        .retain(|event| event.event != "killed");
    assert!(validate_cross_route_public_process_report(&case.scenario, &missing_kill).is_err());
}

#[test]
fn cross_route_generators_version_the_pre_witness_state_wait() {
    use cgka_conformance_simulator::{ScenarioAssertionV2, ScenarioPredicateV2};
    for family in [
        "cross-route-restart-permutations/v1",
        "public-app-recovery-schedules/v1",
    ] {
        for seed in [7, 42, 17001] {
            for case_index in 0..12 {
                let case = generate_family_case(family, seed, case_index).unwrap();
                assert_eq!(case.generator_version, "2");
                let compiled = compile_scenario(&case.scenario).unwrap();
                let witness = compiled.actions.iter().position(|action| matches!(
                    &action.step, ScenarioStep::SendAppMessage { payload, .. } if payload == "zeta-branch-witness"
                )).unwrap();
                assert!(matches!(&compiled.actions[witness - 1].step,
                    ScenarioStep::Assert { assertion: ScenarioAssertionV2::Eventually {
                        predicate: ScenarioPredicateV2::ClientState { client, epoch: Some(4), member_count: Some(4) },
                        max_iterations: 100,
                    }} if client == "yankee"
                ));
            }
        }
    }
}
