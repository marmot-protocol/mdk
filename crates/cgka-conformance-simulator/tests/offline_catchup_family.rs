use std::collections::BTreeSet;

use cgka_conformance_simulator::{
    GeneratedScenarioInputV1, GeneratedSubjectKind, HarnessStorageMode,
    OFFLINE_CATCHUP_PRESSURE_FAMILY, OFFLINE_CATCHUP_PRESSURE_GENERATOR_VERSION,
    OFFLINE_CATCHUP_PRESSURE_PROFILE_VERSION, ScenarioAssertionV2, ScenarioPredicateV2,
    ScenarioRelayOrderV2, ScenarioRelaySyncModeV2, ScenarioStep, TraceExpectation,
    compile_scenario, generate_family_case, generate_offline_catchup_pressure_case,
    generate_offline_catchup_pressure_family, resolve_scenario_input_bytes,
    run_generated_case_report_with_storage_mode,
};

const COMPLETE_PROFILE_CASES: usize = 24;

#[test]
fn offline_catchup_profiles_are_deterministic_prefix_stable_and_registered() {
    let seed = 0x000f_f11e;
    let short = generate_offline_catchup_pressure_family(seed, 6);
    let long = generate_offline_catchup_pressure_family(seed, 12);

    assert_eq!(short, generate_offline_catchup_pressure_family(seed, 6));
    assert_eq!(short, long[..short.len()]);
    assert_ne!(short, generate_offline_catchup_pressure_family(seed + 1, 6));
    for (case_index, case) in short.iter().enumerate() {
        assert_eq!(
            case,
            &generate_family_case(OFFLINE_CATCHUP_PRESSURE_FAMILY, seed, case_index as u64,)
                .expect("offline catch-up family is registered")
        );
    }
}

#[test]
fn complete_catalog_covers_volume_relay_and_recovery_boundaries() {
    let cases = generate_offline_catchup_pressure_family(2026, COMPLETE_PROFILE_CASES);
    let expected_volumes = [24, 96, 384, 1_024];

    for (volume_slot, expected_volume) in expected_volumes.into_iter().enumerate() {
        let block = &cases[(volume_slot * 6)..((volume_slot + 1) * 6)];
        for case in block {
            let profile = case.workload_profile.as_ref().expect("profile metadata");
            assert_eq!(case.subject, GeneratedSubjectKind::RetainedRelay);
            assert_eq!(profile.application_message_count, expected_volume);
            assert_eq!(profile.member_count, 4);
            assert_eq!(case.family_name, OFFLINE_CATCHUP_PRESSURE_FAMILY);
            assert_eq!(
                case.generator_version,
                OFFLINE_CATCHUP_PRESSURE_GENERATOR_VERSION
            );
            assert_eq!(profile.version, OFFLINE_CATCHUP_PRESSURE_PROFILE_VERSION);
            assert_eq!(
                case.scenario
                    .steps
                    .iter()
                    .filter(|step| matches!(step, ScenarioStep::SendAppMessage { .. }))
                    .count(),
                expected_volume
            );
            assert_eq!(
                case.scenario
                    .steps
                    .iter()
                    .filter(|step| matches!(step, ScenarioStep::UpdateGroupData { .. }))
                    .count(),
                profile.workload_commit_count
            );
            compile_scenario(&case.scenario)
                .unwrap_or_else(|error| panic!("{}: {error}", case.scenario.name));
        }

        assert!(
            !block[0]
                .scenario
                .steps
                .iter()
                .any(|step| matches!(step, ScenarioStep::ConfigureRelay { .. }))
        );
        assert!(block[1].scenario.steps.iter().any(|step| matches!(
            step,
            ScenarioStep::ConfigureRelay {
                order: ScenarioRelayOrderV2::Reverse,
                duplicate_copies: 1,
                ..
            }
        )));
        assert!(block[2].scenario.steps.iter().any(|step| matches!(
            step,
            ScenarioStep::ConfigureRelay {
                order: ScenarioRelayOrderV2::Reverse,
                duplicate_copies: 3,
                ..
            }
        )));
        assert!(block[3].scenario.steps.iter().any(|step| matches!(
            step,
            ScenarioStep::SyncRelayHistory {
                sync: ScenarioRelaySyncModeV2::Incremental,
                ..
            }
        )));
        assert!(block[3].scenario.steps.iter().any(|step| matches!(
            step,
            ScenarioStep::SyncRelayHistory {
                sync: ScenarioRelaySyncModeV2::FullHistory,
                ..
            }
        )));
        assert!(block[4].scenario.steps.iter().any(|step| matches!(
            step,
            ScenarioStep::RestartClient { client } if client == "bob"
        )));
        assert_eq!(
            block[5]
                .scenario
                .steps
                .iter()
                .filter(|step| matches!(step, ScenarioStep::UpdateGroupData { .. }))
                .count(),
            block[0]
                .scenario
                .steps
                .iter()
                .filter(|step| matches!(step, ScenarioStep::UpdateGroupData { .. }))
                .count()
                * 2
        );
    }
}

#[test]
fn every_case_keeps_bob_offline_until_the_terminal_catchup_and_has_strict_oracles() {
    for case in generate_offline_catchup_pressure_family(7, COMPLETE_PROFILE_CASES) {
        let offline_index = case
            .scenario
            .steps
            .iter()
            .position(|step| {
                matches!(
                    step,
                    ScenarioStep::SetClientOffline { client } if client == "bob"
                )
            })
            .expect("offline boundary");
        let reconnect_index = case
            .scenario
            .steps
            .iter()
            .position(|step| {
                matches!(
                    step,
                    ScenarioStep::ReconnectClient { client } if client == "bob"
                )
            })
            .expect("reconnect boundary");
        let last_workload_index = case
            .scenario
            .steps
            .iter()
            .rposition(|step| {
                matches!(
                    step,
                    ScenarioStep::SendAppMessage { .. } | ScenarioStep::UpdateGroupData { .. }
                )
            })
            .expect("workload action");
        assert!(offline_index < last_workload_index);
        assert!(last_workload_index < reconnect_index);
        assert!(reconnect_index * 4 > case.scenario.steps.len() * 3);

        assert!(
            case.scenario.steps[..reconnect_index]
                .iter()
                .any(|step| matches!(
                    step,
                    ScenarioStep::Assert {
                        assertion: ScenarioAssertionV2::Exactly {
                            predicate: ScenarioPredicateV2::PayloadCount {
                                client,
                                count: 0,
                                ..
                            }
                        }
                    } if client == "bob"
                ))
        );
        assert!(
            case.scenario.steps[reconnect_index..]
                .iter()
                .any(|step| matches!(
                    step,
                    ScenarioStep::Assert {
                        assertion: ScenarioAssertionV2::Eventually {
                            predicate: ScenarioPredicateV2::PayloadCount {
                                client,
                                count: 1,
                                ..
                            },
                            max_iterations: 128,
                        }
                    } if client == "bob"
                ))
        );

        let clients = case
            .scenario
            .clients
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(case.expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::ClientsExactlyEquivalent { clients: exact }
                if exact.iter().cloned().collect::<BTreeSet<_>>() == clients
        )));
        assert!(case.expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::NoPendingWork { clients: pending }
                if pending.iter().cloned().collect::<BTreeSet<_>>() == clients
        )));
        assert!(case.expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::ClientsBidirectionallyDecryptable { clients }
                if clients.contains(&"bob".to_string())
        )));
        let expected_payloads = case
            .workload_profile
            .as_ref()
            .expect("profile")
            .application_message_count
            + 2;
        assert!(case.expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::ApplicationPayloadMultiset { client, payloads }
                if client == "bob" && payloads.len() == expected_payloads
        )));
    }
}

#[test]
fn workload_profile_survives_generated_input_replay_provenance() {
    let case = generate_offline_catchup_pressure_case(42, 12);
    let bytes = serde_json::to_vec(&GeneratedScenarioInputV1::new(case.clone())).unwrap();
    let resolved = resolve_scenario_input_bytes(&bytes).expect("generated input resolves");
    assert_eq!(resolved.generated_case.as_ref(), Some(&case));
    assert_eq!(
        resolved
            .provenance
            .generated
            .expect("generated provenance")
            .workload_profile,
        case.workload_profile
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn smoke_natural_and_duplicate_history_cases_pass_file_backed_strict_oracles() {
    for case_index in [0, 2] {
        let case = generate_offline_catchup_pressure_case(2026, case_index);
        let report = run_generated_case_report_with_storage_mode(
            &case,
            None,
            HarnessStorageMode::TempFileBackedSqlite,
        )
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", case.scenario.name));
        assert!(
            report.expectation_failures.is_empty(),
            "{} expectation failures: {:#?}",
            case.scenario.name,
            report.expectation_failures
        );
        assert!(
            report.invariant_failures.is_empty(),
            "{} invariant failures: {:#?}",
            case.scenario.name,
            report.invariant_failures
        );
        assert!(report.relay_sync_observations.iter().any(|observation| {
            observation.client == "bob"
                && matches!(observation.mode, ScenarioRelaySyncModeV2::FullHistory)
                && observation.unique_events_returned
                    > case
                        .workload_profile
                        .as_ref()
                        .expect("profile")
                        .application_message_count
        }));
    }
}
