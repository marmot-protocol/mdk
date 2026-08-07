use std::collections::BTreeSet;

use cgka_conformance_simulator::{
    GeneratedScenarioInputV1, GeneratedSubjectKind, HarnessStorageMode, ReportArgs, ReportInput,
    STATEFUL_CHAT_JOURNEY_FAMILY, ScenarioStep, TraceExpectation, compile_scenario,
    generate_stateful_chat_journey_family, run_report,
};

#[test]
fn generated_journeys_are_deterministic_legal_canonical_ir() {
    let cases = generate_stateful_chat_journey_family(0x5eed, 8);
    assert_eq!(cases, generate_stateful_chat_journey_family(0x5eed, 8));

    let mut corpus_kinds = BTreeSet::new();
    for (case_index, case) in cases.iter().enumerate() {
        assert_eq!(case.scenario.spec_version, "3");
        compile_scenario(&case.scenario).expect("generated canonical IR compiles");
        assert_legal_journey(&case.scenario.steps);

        let kinds = case
            .scenario
            .steps
            .iter()
            .map(ScenarioStep::kind)
            .collect::<BTreeSet<_>>();
        corpus_kinds.extend(kinds.iter().copied());
        assert!(kinds.contains("update_group_profile"));
        assert!(kinds.contains("send_app_message"));
        assert!(kinds.contains("observe_exact"));
        assert!(kinds.contains("probe_bidirectional_decryptability"));
        assert!(
            case.expected_outcomes
                .iter()
                .any(|expectation| matches!(expectation, TraceExpectation::GroupProfile { .. }))
        );

        if case_index % 2 == 0 {
            assert_eq!(case.subject, GeneratedSubjectKind::Engine);
            assert!(kinds.contains("invite_members"));
            assert!(!kinds.contains("set_client_offline"));
        } else {
            assert_eq!(case.subject, GeneratedSubjectKind::RetainedRelay);
            assert!(kinds.contains("set_client_offline"));
            assert!(kinds.contains("reconnect_client"));
            assert!(kinds.contains("sync_relay_history"));
            assert!(kinds.contains("await_quiescence"));
        }
    }

    for required in [
        "invite_members",
        "remove_members",
        "send_app_message",
        "update_group_profile",
        "update_admin_policy",
        "self_update",
        "set_client_offline",
        "reconnect_client",
        "restart_client",
    ] {
        assert!(
            corpus_kinds.contains(required),
            "generated corpus never exercised {required}"
        );
    }
}

#[tokio::test]
async fn report_runner_executes_and_preserves_both_journey_profiles() {
    let target = std::fs::canonicalize(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
    )
    .expect("workspace target exists while tests run");
    let output = tempfile::Builder::new()
        .prefix("stateful-journey-")
        .tempdir_in(&target)
        .expect("private report output under target");
    let summary = run_report(&ReportArgs {
        input: ReportInput::GeneratedFamily {
            family: STATEFUL_CHAT_JOURNEY_FAMILY.into(),
            seed: 42,
            cases: 8,
        },
        out: output.path().to_path_buf(),
        strict_oracle: true,
        storage_mode: HarnessStorageMode::InMemorySqlite,
        capture_sensitive_replay: false,
    })
    .await
    .expect("representative journeys execute");

    assert_eq!(summary.total(), 8);
    assert_eq!(summary.failed(), 0, "{summary:#?}");
    let mut retained_input = None;
    for case_index in 0..8 {
        let input = output.path().join(format!(
            "chat-journey-v1-seed-42-case-{case_index}-generated-input.json"
        ));
        assert!(input.is_file(), "generated input must exist before replay");
        let saved: GeneratedScenarioInputV1 =
            serde_json::from_str(&std::fs::read_to_string(&input).expect("read generated input"))
                .expect("parse generated input");
        saved.validate().expect("supported generated input version");
        assert_eq!(saved.case.case_index, case_index);
        if case_index == 1 {
            assert_eq!(saved.case.subject, GeneratedSubjectKind::RetainedRelay);
            retained_input = Some(input.clone());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for artifact in [
                input,
                output
                    .path()
                    .join(format!("chat-journey-v1-seed-42-case-{case_index}.json")),
                output.path().join(format!(
                    "chat-journey-v1-seed-42-case-{case_index}-fixture.v1.json"
                )),
            ] {
                assert_eq!(
                    std::fs::metadata(artifact)
                        .expect("generated artifact metadata")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
    }

    let replay_output = tempfile::Builder::new()
        .prefix("stateful-journey-replay-")
        .tempdir_in(&target)
        .expect("private replay output under target");
    let replay = run_report(&ReportArgs {
        input: ReportInput::GeneratedInputs {
            paths: vec![retained_input.expect("retained input was saved")],
        },
        out: replay_output.path().to_path_buf(),
        strict_oracle: true,
        storage_mode: HarnessStorageMode::InMemorySqlite,
        capture_sensitive_replay: false,
    })
    .await
    .expect("saved retained-relay input replays");
    assert_eq!(replay.total(), 1);
    assert_eq!(replay.failed(), 0, "{replay:#?}");
}

fn assert_legal_journey(steps: &[ScenarioStep]) {
    let mut members = BTreeSet::new();
    let mut admins = BTreeSet::new();
    let mut online = BTreeSet::from([
        "alice".to_string(),
        "bob".to_string(),
        "carol".to_string(),
        "david".to_string(),
    ]);

    for step in steps {
        match step {
            ScenarioStep::CreateGroup {
                creator,
                invitees,
                initial_admins,
                ..
            } => {
                assert!(members.is_empty(), "group may be created only once");
                members.insert(creator.clone());
                members.extend(invitees.iter().cloned());
                admins.extend(
                    initial_admins
                        .clone()
                        .unwrap_or_else(|| vec![creator.clone()]),
                );
            }
            ScenarioStep::InviteMembers {
                inviter, invitees, ..
            } => {
                assert!(members.contains(inviter));
                assert!(admins.contains(inviter));
                assert!(online.contains(inviter));
                for invitee in invitees {
                    assert!(!members.contains(invitee));
                    members.insert(invitee.clone());
                }
            }
            ScenarioStep::RemoveMembers {
                remover,
                members: removed,
                ..
            } => {
                assert!(members.contains(remover));
                assert!(admins.contains(remover));
                assert!(online.contains(remover));
                for member in removed {
                    assert!(members.remove(member));
                    admins.remove(member);
                    online.remove(member);
                }
            }
            ScenarioStep::SelfUpdate { client, .. }
            | ScenarioStep::UpdateGroupProfile { client, .. } => {
                assert!(members.contains(client));
                assert!(online.contains(client));
                if matches!(step, ScenarioStep::UpdateGroupProfile { .. }) {
                    assert!(admins.contains(client));
                }
            }
            ScenarioStep::UpdateAdminPolicy {
                client,
                admins: updated,
                ..
            } => {
                assert!(members.contains(client));
                assert!(admins.contains(client));
                assert!(online.contains(client));
                assert!(!updated.is_empty());
                assert!(updated.iter().all(|admin| members.contains(admin)));
                admins = updated.iter().cloned().collect();
            }
            ScenarioStep::SendAppMessage { sender, .. } => {
                assert!(members.contains(sender));
                assert!(online.contains(sender));
            }
            ScenarioStep::SetClientOffline { client } => {
                assert!(online.remove(client));
            }
            ScenarioStep::ReconnectClient { client } => {
                assert!(online.insert(client.clone()));
            }
            ScenarioStep::RestartClient { client } => {
                assert!(members.contains(client));
                assert!(online.contains(client));
            }
            _ => {}
        }
    }
}
