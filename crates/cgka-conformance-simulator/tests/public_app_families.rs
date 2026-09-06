//! Seeded public companions. Socket canaries are explicit; pure generation and
//! capability checks stay in the ordinary test suite.

use cgka_conformance_simulator::{
    AppRuntimeHarness, ConvergenceSubject, GeneratedSubjectKind, PUBLIC_APP_ADMIN_HANDOFF_FAMILY,
    PUBLIC_APP_MEMBERSHIP_REENTRY_FAMILY, PUBLIC_APP_OFFLINE_RECOVERY_FAMILY,
    PUBLIC_APP_SEND_LEAVE_FAMILY, ScenarioAssertionV2, ScenarioPredicateV2, ScenarioStep,
    ScenarioStepStatus, SubjectCapability, TraceExpectation, compare_trace_expectations,
    compile_scenario, generate_family_case, preflight_compiled_scenario,
    run_scenario_report_with_subject,
};

const FAMILIES: [&str; 4] = [
    PUBLIC_APP_SEND_LEAVE_FAMILY,
    PUBLIC_APP_MEMBERSHIP_REENTRY_FAMILY,
    PUBLIC_APP_OFFLINE_RECOVERY_FAMILY,
    PUBLIC_APP_ADMIN_HANDOFF_FAMILY,
];

#[tokio::test(flavor = "multi_thread")]
async fn public_catalog_is_replayable_and_preflights_without_private_capabilities() {
    let mut subject = AppRuntimeHarness::new(&[]).await.unwrap();
    let descriptor = subject.descriptor();
    subject.shutdown().await;
    let mut without_public_state = descriptor.clone();
    without_public_state
        .capabilities
        .remove(&SubjectCapability::PublicGroupStateObservation);
    let public_case = generate_family_case(FAMILIES[0], 7, 0).unwrap();
    assert!(
        preflight_compiled_scenario(
            &compile_scenario(&public_case.scenario).unwrap(),
            &without_public_state
        )
        .is_err()
    );
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
            assert_eq!(case.generator_version, "3");
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
fn public_group_checkpoints_reject_invalid_rosters_before_execution() {
    for mutation in 0..5 {
        let mut case = generate_family_case(PUBLIC_APP_ADMIN_HANDOFF_FAMILY, 7, 0).unwrap();
        let predicate = case
            .scenario
            .steps
            .iter_mut()
            .find_map(|step| match step {
                ScenarioStep::Assert {
                    assertion: ScenarioAssertionV2::Eventually { predicate, .. },
                } if matches!(predicate, ScenarioPredicateV2::PublicGroupState { .. }) => {
                    Some(predicate)
                }
                _ => None,
            })
            .unwrap();
        let ScenarioPredicateV2::PublicGroupState {
            clients,
            members,
            admins,
            ..
        } = predicate
        else {
            unreachable!()
        };
        match mutation {
            0 => clients.clear(),
            1 => members.push("unknown-client".into()),
            2 => members.push(members[0].clone()),
            3 => {
                members.retain(|member| member != "bob");
            }
            _ => {
                clients.retain(|client| client != "alice");
                members.retain(|member| member != "alice");
                assert_eq!(admins, &["alice"]);
            }
        }
        assert!(
            compile_scenario(&case.scenario).is_err(),
            "invalid public checkpoint {mutation} compiled"
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
                            | ScenarioStep::UpdateAdminPolicy { .. }
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
                                    predicate: ScenarioPredicateV2::PublicGroupState { .. },
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
                PUBLIC_APP_ADMIN_HANDOFF_FAMILY => {
                    assert_eq!(count("update_admin_policy"), 2 * (1 + index as usize % 2));
                    assert_eq!(count("update_group_profile"), 1 + index as usize % 2);
                    let mut delegated = None;
                    let mut did_edit = false;
                    for step in steps {
                        match step {
                            ScenarioStep::UpdateAdminPolicy { admins, .. } if admins.len() == 2 => {
                                delegated = admins.iter().find(|client| *client != "alice");
                                did_edit = false;
                            }
                            ScenarioStep::UpdateGroupProfile { client, .. } => {
                                assert_eq!(Some(client), delegated);
                                did_edit = true;
                            }
                            ScenarioStep::UpdateAdminPolicy { admins, .. } => {
                                assert_eq!(admins, &["alice"]);
                                assert!(
                                    did_edit,
                                    "delegated permission must be exercised before revocation"
                                );
                                delegated = None;
                            }
                            _ => {}
                        }
                    }
                    assert!(delegated.is_none());
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
    let mut wrong_admins = trace.clone();
    wrong_admins
        .admin_policies
        .last_mut()
        .unwrap()
        .admins
        .push("unexpected-admin".into());
    assert!(!compare_trace_expectations(None, &case.expected_outcomes, &wrong_admins).is_empty());
    // Prove the public oracle rejects loss, duplicates, wrong profile and a
    // wrong member count instead of merely declaring coverage.
    for mutation in 0..5 {
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
            3 => observation.group_name.push_str("-wrong"),
            _ => observation.epoch += 1,
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real sockets and SQLCipher; run explicitly in release mode"]
async fn public_admin_handoff_strict_canary() {
    strict_canary(PUBLIC_APP_ADMIN_HANDOFF_FAMILY).await;
}
