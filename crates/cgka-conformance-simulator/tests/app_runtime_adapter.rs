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
    subject.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_runtime_adapter_is_selectable_for_a_saved_generated_case() {
    let case = GeneratedScenarioCase {
        family_name: "selectable-app-runtime/v1".into(),
        generator_version: "2".into(),
        seed: 23,
        case_index: 5,
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
        subject.shutdown().await;
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
    subject.shutdown().await;
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
    subject.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cold_reopen_recovers_quiet_offline_history_without_a_live_trigger() {
    let clients = vec!["alice".to_owned(), "bob".to_owned()];
    let mut subject = AppRuntimeHarness::new(&clients).await.unwrap();
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
    subject.shutdown().await;
}

#[tokio::test]
async fn blocking_subject_operations_refuse_current_thread_runtimes_without_panicking() {
    let clients = vec!["alice".to_owned()];
    let mut subject = AppRuntimeHarness::new(&clients).await.unwrap();
    let error = subject.deliver_all().unwrap_err();
    assert_eq!(error.code, "tokio_runtime_flavor_unsupported");
    subject.shutdown().await;
}
