//! Long-lived black-box coverage for the application-runtime adapter.

use std::collections::BTreeSet;
use std::time::Duration;

use cgka_conformance_simulator::{
    AppRuntimeHarness, ConvergenceSubject, ScenarioSpec, ScenarioStep,
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
        name: "milestone5-app-runtime-black-box".into(),
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
    subject.catch_up(&clients).await.unwrap();

    subject.set_online("bob", false).await.unwrap();
    subject
        .update_group_data(cgka_conformance_simulator::SubjectUpdateGroupData {
            action_id: "rename-1",
            client: "alice",
            name: "offline epoch one",
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
            name: "after quiet history",
            pending: "rename-2",
        })
        .await
        .unwrap();

    // No new event is published after Bob reconnects. Startup EOSE/history
    // completion and the runtime's selected backfill policy must close the gap.
    subject.set_online("bob", true).await.unwrap();
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
    assert!(
        bob.application
            .visible_plaintexts
            .iter()
            .any(|payload| { payload == "retained while bob was offline" })
    );
    assert_eq!(bob.local.reopen_count, 1);
    subject.shutdown().await;
}
