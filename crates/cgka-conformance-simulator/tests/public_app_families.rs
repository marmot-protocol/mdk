//! Seeded public companions. Socket canaries are explicit; pure generation and
//! capability checks stay in the ordinary test suite.

use cgka_conformance_simulator::{
    AppRuntimeHarness, ConvergenceSubject, GeneratedSubjectKind,
    PUBLIC_APP_MEMBERSHIP_REENTRY_FAMILY, PUBLIC_APP_OFFLINE_RECOVERY_FAMILY,
    PUBLIC_APP_SEND_LEAVE_FAMILY, ScenarioAssertionV2, ScenarioPredicateV2, ScenarioStep,
    ScenarioStepStatus, TraceExpectation, compare_trace_expectations, compile_scenario,
    generate_family_case, preflight_compiled_scenario, run_scenario_report_with_subject,
};

const FAMILIES: [&str; 3] = [
    PUBLIC_APP_SEND_LEAVE_FAMILY,
    PUBLIC_APP_MEMBERSHIP_REENTRY_FAMILY,
    PUBLIC_APP_OFFLINE_RECOVERY_FAMILY,
];

#[tokio::test(flavor = "multi_thread")]
async fn public_catalog_is_replayable_and_preflights_without_private_capabilities() {
    let mut subject = AppRuntimeHarness::new(&[]).await.unwrap();
    let descriptor = subject.descriptor();
    subject.shutdown().await;
    for family in FAMILIES {
        let generate = |seed, count| {
            (0..count)
                .map(|index| generate_family_case(family, seed, index).unwrap())
                .collect::<Vec<_>>()
        };
        let short = generate(7, 6);
        let long = generate(7, 12);
        assert_eq!(short, long[..6]);
        assert_eq!(short, generate(7, 6));
        // Compare actual workloads, not metadata containing the seed.
        assert_ne!(
            short.iter().map(|c| &c.scenario).collect::<Vec<_>>(),
            generate(42, 6)
                .iter()
                .map(|c| &c.scenario)
                .collect::<Vec<_>>()
        );
        for case in long {
            assert_eq!(case.subject, GeneratedSubjectKind::AppRuntime);
            assert_eq!(case.generator_version, "1");
            preflight_compiled_scenario(&compile_scenario(&case.scenario).unwrap(), &descriptor)
                .unwrap();
            for client in &case.scenario.clients {
                assert!(case.expected_outcomes.iter().any(|e| matches!(e,
                    TraceExpectation::ApplicationPayloadMultiset { client: label, payloads }
                    if label == client && !payloads.is_empty())));
            }
        }
    }
    for predicate in [
        ScenarioPredicateV2::ClientsExactlyEquivalent {
            clients: vec!["alice".into()],
        },
        ScenarioPredicateV2::NoPendingWork {
            clients: vec!["alice".into()],
        },
    ] {
        let mut case = generate_family_case(FAMILIES[0], 7, 0).unwrap();
        case.scenario.steps.push(ScenarioStep::Assert {
            assertion: ScenarioAssertionV2::Exactly { predicate },
        });
        assert!(
            preflight_compiled_scenario(&compile_scenario(&case.scenario).unwrap(), &descriptor)
                .is_err()
        );
    }
}

#[test]
fn public_catalog_guarantees_transitions_and_checkpoint_interactions() {
    for family in FAMILIES {
        for index in 0..6 {
            let case = generate_family_case(family, 7, index).unwrap();
            let steps = &case.scenario.steps;
            assert!(
                steps
                    .iter()
                    .any(|s| matches!(s, ScenarioStep::RestartClient { .. }))
            );
            let transitions = steps
                .iter()
                .enumerate()
                .filter(|(_, s)| {
                    matches!(
                        s,
                        ScenarioStep::Leave { .. }
                            | ScenarioStep::RemoveMembers { .. }
                            | ScenarioStep::InviteMembers { .. }
                            | ScenarioStep::ReconnectClient { .. }
                    )
                })
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            assert!(!transitions.is_empty());
            for start in transitions {
                let tail = &steps[start + 1..];
                let checkpoint = tail
                    .iter()
                    .position(|s| {
                        matches!(
                            s,
                            ScenarioStep::Assert {
                                assertion: ScenarioAssertionV2::Eventually {
                                    predicate: ScenarioPredicateV2::ClientState { .. },
                                    ..
                                }
                            }
                        )
                    })
                    .unwrap();
                let send = tail
                    .iter()
                    .position(|s| matches!(s, ScenarioStep::SendAppMessage { .. }))
                    .unwrap();
                assert!(
                    checkpoint < send,
                    "transition must settle before later traffic"
                );
            }
            let count = |kind| steps.iter().filter(|s| s.kind() == kind).count();
            match family {
                PUBLIC_APP_SEND_LEAVE_FAMILY => assert_eq!(count("leave"), 1),
                PUBLIC_APP_MEMBERSHIP_REENTRY_FAMILY => {
                    assert_eq!(count("remove_members"), 1 + index as usize % 2);
                    assert_eq!(count("invite_members"), count("remove_members"));
                }
                PUBLIC_APP_OFFLINE_RECOVERY_FAMILY => {
                    assert_eq!(count("set_client_offline"), 1 + index as usize / 3);
                    assert_eq!(count("reconnect_client"), count("set_client_offline"));
                    assert_eq!(
                        count("update_group_profile"),
                        (1 + index as usize % 3) * (1 + index as usize / 3)
                    );
                }
                _ => unreachable!(),
            }
        }
    }
}

async fn strict_canary(family: &str) {
    let case = generate_family_case(family, 7, 0).unwrap();
    let mut subject = AppRuntimeHarness::new_with_pinned_settlement(&case.scenario.clients)
        .await
        .unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(360),
        run_scenario_report_with_subject(
            &case.scenario,
            None,
            case.expected_outcomes.clone(),
            &mut subject,
        ),
    )
    .await;
    let wrong_epoch = subject.evaluate_predicate(&ScenarioPredicateV2::ClientState {
        client: "alice".into(),
        epoch: Some(u64::MAX),
        member_count: None,
    });
    let wrong_payload_count = subject.evaluate_predicate(&ScenarioPredicateV2::PayloadCount {
        client: "alice".into(),
        payload: "never-sent".into(),
        count: 1,
    });
    subject.shutdown().await;
    drop(subject); // Release all runtime/storage work before any assertion unwinds.
    let report = result
        .expect("public canary exceeded its wall-clock budget")
        .unwrap();
    assert!(!wrong_epoch.unwrap().matched);
    assert!(!wrong_payload_count.unwrap().matched);
    assert!(
        report
            .step_log
            .iter()
            .all(|s| matches!(s.status, ScenarioStepStatus::Completed)),
        "{:#?}",
        report.step_log
    );
    assert!(
        report.expectation_failures.is_empty(),
        "{:#?}",
        report.expectation_failures
    );
    assert!(
        report.invariant_failures.is_empty(),
        "{:#?}",
        report.invariant_failures
    );
    assert!(
        report.oracle.weak_oracle_warnings.is_empty(),
        "{:#?}",
        report.oracle
    );
    assert!(
        report.oracle.missing_observed_behaviors.is_empty(),
        "{:#?}",
        report.oracle
    );
    let trace = report.observed_trace.unwrap();
    // Prove the public oracle rejects loss, duplicates, wrong profile and a
    // wrong member count instead of merely declaring coverage.
    for mutation in 0..4 {
        let mut changed = trace.clone();
        let observation = changed
            .observations
            .iter_mut()
            .find(|o| o.client == "alice")
            .unwrap();
        match mutation {
            0 => {
                observation.received_payloads.pop().unwrap();
            }
            1 => observation
                .received_payloads
                .push(observation.received_payloads[0].clone()),
            2 => observation.member_count += 1,
            _ => observation.group_name.push_str("-wrong"),
        }
        assert!(!compare_trace_expectations(None, &case.expected_outcomes, &changed).is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real sockets and SQLCipher; run explicitly in release mode"]
async fn public_send_leave_strict_canary() {
    strict_canary(FAMILIES[0]).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real sockets and SQLCipher; run explicitly in release mode"]
async fn public_membership_reentry_strict_canary() {
    strict_canary(FAMILIES[1]).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real sockets and SQLCipher; run explicitly in release mode"]
async fn public_offline_recovery_strict_canary() {
    strict_canary(FAMILIES[2]).await;
}
