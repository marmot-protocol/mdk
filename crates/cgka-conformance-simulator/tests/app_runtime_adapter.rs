//! Long-lived black-box coverage for the application-runtime adapter.

use std::collections::BTreeSet;
use std::time::Duration;

use cgka_conformance_simulator::{
    AppRuntimeHarness, ConvergenceSubject, GeneratedScenarioCase, GeneratedSubjectKind,
    HarnessStorageMode, ScenarioMessageSelectorV2, ScenarioOutboundSelection, ScenarioSpec,
    ScenarioStep, ScenarioStepStatus, SubjectFailureCategory, SubjectOutboundOutcome,
    TraceExpectation, run_generated_case_report_with_capture_on_subject,
    run_scenario_report_with_subject,
};

fn in_group(group: &str, action: ScenarioStep) -> ScenarioStep {
    ScenarioStep::InGroup {
        group: group.into(),
        action: Box::new(action),
    }
}

fn two_client_scenario() -> ScenarioSpec {
    let clients = vec!["alice".to_owned(), "bob".to_owned()];
    ScenarioSpec {
        name: "app-runtime-black-box".into(),
        spec_version: "2".into(),
        clients: clients.clone(),
        topology: Default::default(),
        steps: vec![
            in_group(
                "main",
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "reliable group".into(),
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
            in_group(
                "main",
                ScenarioStep::SendAppMessage {
                    sender: "alice".into(),
                    payload: "hello from the app adapter".into(),
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
        ],
    }
}

fn publication_acknowledgement_scenario(
    name: &str,
    publication: Option<&str>,
    outcome: SubjectOutboundOutcome,
) -> ScenarioSpec {
    ScenarioSpec {
        name: name.into(),
        spec_version: "2".into(),
        clients: vec!["alice".into()],
        topology: Default::default(),
        steps: vec![
            in_group(
                "main",
                ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "publication contract".into(),
                    invitees: Vec::new(),
                    required_features: Vec::new(),
                    initial_admins: Some(vec!["alice".into()]),
                    pending: "create".into(),
                },
            ),
            ScenarioStep::AcknowledgeOutbound {
                client: "alice".into(),
                publication: publication.map(str::to_owned),
                selection: ScenarioOutboundSelection::All,
                outcome,
            },
        ],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_runtime_subject_uses_distinct_private_encrypted_roots_and_public_projections() {
    let spec = two_client_scenario();
    let mut subject = AppRuntimeHarness::new(&spec.clients).await.unwrap();
    let layout = subject.process_layout();
    assert_eq!(layout["execution"], "participant_processes");
    let mut pids = layout["participants"]
        .as_object()
        .unwrap()
        .values()
        .map(|p| p.as_u64().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(pids.len(), spec.clients.len());
    assert!(pids.insert(layout["relay_pid"].as_u64().unwrap()));
    assert!(!pids.contains(&(std::process::id() as u64)));
    let roots = subject.participant_roots();
    assert_eq!(
        roots.values().collect::<BTreeSet<_>>().len(),
        spec.clients.len()
    );
    #[cfg(unix)]
    for root in roots.values() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    let report = run_scenario_report_with_subject(&spec, None, Vec::new(), &mut subject)
        .await
        .unwrap();
    assert_eq!(report.metadata.execution_layout.as_ref(), Some(&layout));
    assert!(report.invariant_failures.is_empty(), "{report:#?}");
    assert!(report.expectation_failures.is_empty(), "{report:#?}");

    let observations = subject.observations(&spec.clients).await.unwrap();
    assert_eq!(observations.len(), 2);
    let first_commitment = &observations[0].protocol.state_commitment_sha256;
    for observation in &observations {
        assert_eq!(
            &observation.protocol.state_commitment_sha256,
            first_commitment
        );
        assert_eq!(observation.protocol.member_count, 2);
        assert_eq!(observation.protocol.group_name, "reliable group");
        assert!(
            observation
                .application
                .visible_plaintexts
                .iter()
                .any(|payload| { payload == "hello from the app adapter" })
        );
        assert!(observation.application.invalidated_message_ids.is_empty());
        assert!(observation.local.database_exists);
        assert!(observation.local.database_encrypted);
        assert!(
            observation
                .local
                .database_bytes
                .is_some_and(|bytes| bytes > 0)
        );
    }
    subject.shutdown().await.expect("app shutdown");
    #[cfg(unix)]
    for pid in pids {
        assert!(
            !std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success(),
            "child {pid} survived shutdown"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_runtime_adapter_is_selectable_for_a_saved_generated_case() {
    let case = GeneratedScenarioCase {
        family_name: "selectable-app-runtime/v1".into(),
        generator_version: "2".into(),
        seed: 23,
        case_index: 5,
        workload_profile: None,
        subject: GeneratedSubjectKind::Engine,
        scenario: two_client_scenario(),
        expected_outcomes: vec![TraceExpectation::ClientsConverged {
            clients: vec!["alice".into(), "bob".into()],
            epoch: Some(1),
            member_count: Some(2),
        }],
    };

    let (report, _) = run_generated_case_report_with_capture_on_subject(
        &case,
        GeneratedSubjectKind::AppRuntime,
        None,
        HarnessStorageMode::InMemorySqlite,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        report.metadata.subject.as_ref().unwrap().adapter,
        "marmot_app_runtime"
    );
    assert!(report.expectation_failures.is_empty(), "{report:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_runtime_publication_acknowledgements_fail_closed_without_mid_run_capability_errors() {
    for (name, publication, outcome, expected_failure) in [
        (
            "accepted-publication-cannot-roll-back",
            Some("create"),
            SubjectOutboundOutcome::ReachedNoEndpoint,
            Some("publication_rollback_rejected"),
        ),
        (
            "unknown-publication-is-refused",
            Some("missing"),
            SubjectOutboundOutcome::Accepted,
            Some("publication_not_found"),
        ),
        (
            "unlabelled-publication-drain-is-idempotent",
            None,
            SubjectOutboundOutcome::Accepted,
            None,
        ),
    ] {
        let spec = publication_acknowledgement_scenario(name, publication, outcome);
        let mut subject = AppRuntimeHarness::new(&spec.clients).await.unwrap();
        let report = run_scenario_report_with_subject(&spec, None, Vec::new(), &mut subject)
            .await
            .unwrap();
        match expected_failure {
            Some(expected_kind) => assert!(matches!(
                &report.step_log[1].status,
                ScenarioStepStatus::Failed { kind, category, .. }
                    if kind == expected_kind
                        && *category == SubjectFailureCategory::ExpectedRefusal
            )),
            None => assert!(report.step_log[1].status.is_completed()),
        }
        subject.shutdown().await.expect("app shutdown");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn observations_keep_pending_invites_until_an_explicit_tick() {
    let clients = vec!["alice".to_owned(), "bob".to_owned()];
    let mut subject = AppRuntimeHarness::new(&clients).await.unwrap();
    subject.select_scenario_group("main", true).unwrap();
    subject
        .create_group(cgka_conformance_simulator::SubjectCreateGroup {
            action_id: "create",
            creator: "alice",
            name: "pending invite",
            invitees: &["bob".into()],
            required_features: &[],
            initial_admins: &["alice".into()],
            pending: "create",
        })
        .await
        .unwrap();

    subject.catch_up(&clients).await.unwrap();
    let pending = subject.observations(&clients).await.unwrap();
    assert!(
        pending
            .iter()
            .find(|item| item.participant == "bob")
            .unwrap()
            .application
            .pending_confirmation
    );

    subject.tick(&["bob".into()]).await.unwrap();
    let accepted = subject.observations(&clients).await.unwrap();
    assert!(
        !accepted
            .iter()
            .find(|item| item.participant == "bob")
            .unwrap()
            .application
            .pending_confirmation
    );
    subject.shutdown().await.expect("app shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_relay_control_resolves_immediate_app_publication_action_ids() {
    let clients = vec!["alice".to_owned(), "bob".to_owned()];
    let mut subject = AppRuntimeHarness::new(&clients).await.unwrap();
    subject.select_scenario_group("main", true).unwrap();
    subject
        .create_group(cgka_conformance_simulator::SubjectCreateGroup {
            action_id: "create",
            creator: "alice",
            name: "relay action ids",
            invitees: &["bob".into()],
            required_features: &[],
            initial_admins: &["alice".into()],
            pending: "create",
        })
        .await
        .unwrap();
    subject.tick(&clients).await.unwrap();
    subject
        .update_group_data(cgka_conformance_simulator::SubjectUpdateGroupData {
            action_id: "rename",
            client: "alice",
            name: Some("renamed"),
            description: None,
            pending: "rename",
        })
        .await
        .unwrap();
    subject
        .send_application(cgka_conformance_simulator::SubjectSendApplication {
            action_id: "send",
            sender: "alice",
            payload: "action-addressed application",
        })
        .await
        .unwrap();

    subject.set_online("alice", false).await.unwrap();
    subject.set_online("bob", false).await.unwrap();
    for action_id in ["create", "rename", "send"] {
        let selector = ScenarioMessageSelectorV2 {
            action_id: Some(action_id.into()),
            ..ScenarioMessageSelectorV2::default()
        };
        subject
            .set_relay_event_visibility("relay:shared", &selector, &clients, false)
            .unwrap_or_else(|error| panic!("{action_id}: {error}"));
        subject
            .set_relay_event_visibility("relay:shared", &selector, &clients, true)
            .unwrap();
    }
    subject.shutdown().await.expect("app shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_relay_control_restores_hidden_history_for_offline_repair() {
    let clients = vec!["alice".to_owned(), "bob".to_owned()];
    let mut subject = AppRuntimeHarness::new(&clients).await.unwrap();
    subject.select_scenario_group("main", true).unwrap();
    subject
        .create_group(cgka_conformance_simulator::SubjectCreateGroup {
            action_id: "create",
            creator: "alice",
            name: "reversible relay history",
            invitees: &["bob".into()],
            required_features: &[],
            initial_admins: &["alice".into()],
            pending: "create",
        })
        .await
        .unwrap();
    subject.tick(&clients).await.unwrap();

    subject.set_online("bob", false).await.unwrap();
    subject
        .send_application(cgka_conformance_simulator::SubjectSendApplication {
            action_id: "offline-send",
            sender: "alice",
            payload: "restored relay history",
        })
        .await
        .unwrap();
    subject.set_online("alice", false).await.unwrap();

    let selector = ScenarioMessageSelectorV2 {
        action_id: Some("offline-send".into()),
        ..ScenarioMessageSelectorV2::default()
    };
    subject
        .set_relay_event_visibility("relay:shared", &selector, &clients, false)
        .unwrap();
    subject.set_online("bob", true).await.unwrap();
    subject.repair_full_history(&["bob".into()]).await.unwrap();
    let hidden = subject.observations(&["bob".into()]).await.unwrap();
    assert_eq!(hidden[0].local.history_repairs_without_coverage, 1);
    assert!(hidden[0].application.visible_plaintexts.is_empty());

    subject
        .set_relay_event_visibility("relay:shared", &selector, &clients, true)
        .unwrap();
    subject.repair_full_history(&["bob".into()]).await.unwrap();
    let restored = subject.observations(&["bob".into()]).await.unwrap();
    assert_eq!(restored[0].local.history_repairs_without_coverage, 2);
    assert_eq!(
        restored[0].application.visible_plaintexts,
        ["restored relay history"]
    );
    subject.shutdown().await.expect("app shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_wide_removal_refuses_an_omitted_online_participant() {
    let clients = vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()];
    let mut subject = AppRuntimeHarness::new(&clients).await.unwrap();
    subject.select_scenario_group("main", true).unwrap();
    subject
        .create_group(cgka_conformance_simulator::SubjectCreateGroup {
            action_id: "create",
            creator: "alice",
            name: "relay-wide removal",
            invitees: &["bob".into()],
            required_features: &[],
            initial_admins: &["alice".into()],
            pending: "create",
        })
        .await
        .unwrap();
    subject.tick(&["alice".into(), "bob".into()]).await.unwrap();
    subject
        .send_application(cgka_conformance_simulator::SubjectSendApplication {
            action_id: "send",
            sender: "alice",
            payload: "relay-wide event",
        })
        .await
        .unwrap();
    subject.set_online("alice", false).await.unwrap();
    subject.set_online("bob", false).await.unwrap();

    let selector = ScenarioMessageSelectorV2 {
        action_id: Some("send".into()),
        ..ScenarioMessageSelectorV2::default()
    };
    let named_subset = vec!["alice".into(), "bob".into()];
    let error = subject
        .set_relay_event_visibility("relay:shared", &selector, &named_subset, false)
        .unwrap_err();
    assert_eq!(
        error.code,
        "relay_removal_requires_all_participants_offline"
    );

    subject.set_online("carol", false).await.unwrap();
    subject
        .set_relay_event_visibility("relay:shared", &selector, &named_subset, false)
        .unwrap();
    subject
        .set_relay_event_visibility("relay:shared", &selector, &named_subset, true)
        .unwrap();
    subject.shutdown().await.expect("app shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cold_reopen_recovers_quiet_offline_history_without_a_live_trigger() {
    let clients = vec!["alice".to_owned(), "bob".to_owned()];
    let mut subject = AppRuntimeHarness::new_with_pinned_settlement(&clients)
        .await
        .unwrap();
    subject.select_scenario_group("main", true).unwrap();
    subject
        .create_group(cgka_conformance_simulator::SubjectCreateGroup {
            action_id: "create",
            creator: "alice",
            name: "before offline",
            invitees: &["bob".into()],
            required_features: &[],
            initial_admins: &["alice".into()],
            pending: "create",
        })
        .await
        .unwrap();
    subject.tick(&clients).await.unwrap();

    let original_pid = subject.process_layout()["participants"]["bob"].clone();
    let original_root = subject.participant_roots()["bob"].clone();
    let original_identity = subject.account_identity("bob").unwrap().to_owned();
    subject.set_online("bob", false).await.unwrap();
    subject
        .update_group_data(cgka_conformance_simulator::SubjectUpdateGroupData {
            action_id: "rename-1",
            client: "alice",
            name: Some("offline epoch one"),
            description: None,
            pending: "rename-1",
        })
        .await
        .unwrap();
    subject
        .send_application(cgka_conformance_simulator::SubjectSendApplication {
            action_id: "offline-message",
            sender: "alice",
            payload: "retained while bob was offline",
        })
        .await
        .unwrap();
    subject
        .update_group_data(cgka_conformance_simulator::SubjectUpdateGroupData {
            action_id: "rename-2",
            client: "alice",
            name: Some("after quiet history"),
            description: Some("after quiet description"),
            pending: "rename-2",
        })
        .await
        .unwrap();

    // No new event is published after Bob reconnects. Incremental catch-up has
    // no live trigger capable of proving or repairing the retained-history gap.
    subject.set_online("bob", true).await.unwrap();
    assert_ne!(
        subject.process_layout()["participants"]["bob"],
        original_pid
    );
    assert_eq!(subject.participant_roots()["bob"], original_root);
    assert_eq!(subject.account_identity("bob").unwrap(), original_identity);
    subject.catch_up(&["bob".into()]).await.unwrap();
    let incremental = subject.observations(&clients).await.unwrap();
    let incremental_alice = incremental
        .iter()
        .find(|item| item.participant == "alice")
        .unwrap();
    let incremental_bob = incremental
        .iter()
        .find(|item| item.participant == "bob")
        .unwrap();
    assert_ne!(
        incremental_bob.protocol.state_commitment_sha256,
        incremental_alice.protocol.state_commitment_sha256,
        "ordinary catch-up unexpectedly repaired the quiet retained-history gap"
    );

    subject.repair_full_history(&["bob".into()]).await.unwrap();
    let observations = match subject
        .await_observable_settlement(&clients, Duration::from_secs(15))
        .await
    {
        Ok(observations) => observations,
        Err(error) => panic!(
            "{error}; observations={:#?}",
            subject.observations(&clients).await.unwrap()
        ),
    };
    let alice = observations
        .iter()
        .find(|item| item.participant == "alice")
        .unwrap();
    let bob = observations
        .iter()
        .find(|item| item.participant == "bob")
        .unwrap();
    assert_eq!(
        bob.protocol.state_commitment_sha256, alice.protocol.state_commitment_sha256,
        "alice={alice:#?}\nbob={bob:#?}"
    );
    assert_eq!(bob.protocol.group_name, "after quiet history");
    assert_eq!(bob.protocol.group_description, "after quiet description");
    assert!(
        bob.application
            .visible_plaintexts
            .iter()
            .any(|payload| { payload == "retained while bob was offline" })
    );
    assert_eq!(bob.local.reopen_count, 1);
    subject.shutdown().await.expect("app shutdown");
}

#[tokio::test]
async fn blocking_subject_operations_refuse_current_thread_runtimes_without_panicking() {
    let clients = vec!["alice".to_owned()];
    let mut subject = AppRuntimeHarness::new(&clients).await.unwrap();
    let error = subject.deliver_all().unwrap_err();
    assert_eq!(error.code, "tokio_runtime_flavor_unsupported");
    subject.shutdown().await.expect("app shutdown");
}

#[tokio::test]
async fn dropping_app_harness_reaps_children_even_without_explicit_shutdown() {
    let subject = AppRuntimeHarness::new(&["alice".into(), "bob".into()])
        .await
        .unwrap();
    let layout = subject.process_layout();
    let roots = subject.participant_roots();
    let pids = layout["participants"]
        .as_object()
        .unwrap()
        .values()
        .chain(std::iter::once(&layout["relay_pid"]))
        .map(|p| p.as_u64().unwrap())
        .collect::<Vec<_>>();
    drop(subject);
    for root in roots.values() {
        assert!(!root.exists());
    }
    #[cfg(unix)]
    for pid in pids {
        assert!(
            !std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success(),
            "child {pid} survived drop"
        );
    }
}

/// A case deadline kills the coordinator without running its Drop implementation.
/// Keep the child's stdin open to prove cleanup comes from owner death, not EOF.
#[cfg(unix)]
#[test]
fn relay_child_exits_when_its_coordinator_is_killed() {
    for shell in ["/bin/sh", "/bin/dash"] {
        if std::path::Path::new(shell).exists() {
            assert_relay_child_exits_when_its_coordinator_is_killed(shell);
        }
    }
}

#[cfg(unix)]
fn assert_relay_child_exits_when_its_coordinator_is_killed(shell: &str) {
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};
    let script = r#"export MDK_APP_PROCESS_PARENT_PID=$$
# Preserve the pipe before dash applies /dev/null to an asynchronous command.
exec 3<&0
"$1" --app-harness relay <&3 3<&- &
printf '%s\n' "$!"
wait
"#;
    let mut owner = Command::new(shell)
        .args([
            "-c",
            script,
            "app-owner",
            env!("CARGO_BIN_EXE_cgka-conformance-node"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut writer = owner.stdin.take().unwrap();
    let mut reader = std::io::BufReader::new(owner.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let pid: u32 = line.trim().parse().unwrap();
    writer.write_all(b"{\"protocol\":\"marmot-app-harness-process/v1\",\"id\":0,\"method\":\"hello\",\"args\":{}}\n").unwrap();
    writer.flush().unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    let hello: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        hello["result"]["Ok"]["protocol"],
        "marmot-app-harness-process/v1"
    );
    owner.kill().unwrap();
    owner.wait().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let status = Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        let state = String::from_utf8_lossy(&status.stdout);
        // An orphan zombie has exited; its system reaper owns the wait status.
        if state.trim().is_empty() || state.trim().starts_with('Z') {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            panic!("relay child survived coordinator death");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    drop(writer);
}
