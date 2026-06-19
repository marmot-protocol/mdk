//! Canonical scripted scenarios driven through the harness bus.
//!
//! These tests cover named multi-client histories that are too important to
//! leave only to generated scenarios. The proptest layer generalizes the same
//! behavior into seeded random send/leave sequences.

use cgka_conformance_simulator::{
    ClientBuilder, EpochChangeObservation, GeneratedScenarioCase, HarnessClient,
    PendingResolutionObservation, ScenarioSpec, ScenarioStep, ScenarioTrace, TraceExpectation,
    TransportBus, VectorFixture, generate_convergence_chaos_family,
    generate_convergence_e2e_delivery_family, generate_send_leave_family, observe_client,
    run_generated_case_report, run_scenario_report, run_scenario_report_with_outcomes,
    run_scenario_spec, run_vector_fixture_report,
};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::openmls_projection::{OpenMlsContentKind, project_mls_message};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::GroupEvent;
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use cgka_traits::message::MessageState;
use cgka_traits::storage::MessageStorage;
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::EpochId;

fn pad32(name: &[u8]) -> Vec<u8> {
    // MIP-01 admin pubkeys MUST be 32 bytes. Test identities get
    // zero-padded to 32 so engine-layer admin tracking works without
    // breaking ergonomic test names.
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

fn selfremove_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r
}

async fn openmls_projection_messages(
    client: &HarnessClient,
    messages: Vec<TransportMessage>,
) -> Vec<TransportMessage> {
    let mut out = Vec::new();
    for message in messages {
        if let Ok(message) = client.openmls_projection_message(&message).await {
            out.push(message);
        }
    }
    out
}

#[tokio::test]
async fn three_client_happy_path_via_harness() {
    // Alice creates a group with Bob and Carol. Each sends one app message,
    // then all three converge on epoch 1 and see all three messages.
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;

    let (_gid, pending) = alice
        .create_group("smoke", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;

    // Deliver welcomes; bob & carol absorb and join.
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    assert_eq!(alice.epoch().0, 1);
    assert_eq!(bob.epoch().0, 1);
    assert_eq!(carol.epoch().0, 1);
    assert_eq!(alice.members().len(), 3);
    assert_eq!(bob.members().len(), 3);
    assert_eq!(carol.members().len(), 3);

    // Each sends one app message.
    alice.send_app(b"hi from alice".to_vec()).await;
    bob.send_app(b"hi from bob".to_vec()).await;
    carol.send_app(b"hi from carol".to_vec()).await;

    bus.deliver_all();
    let _ = (alice.tick().await, bob.tick().await, carol.tick().await);

    // Each has received 2 application messages (everyone else's).
    fn count_app_msgs(c: &mut cgka_conformance_simulator::HarnessClient) -> usize {
        c.drain_events()
            .into_iter()
            .filter(|e| matches!(e, GroupEvent::MessageReceived { .. }))
            .count()
    }
    assert_eq!(count_app_msgs(&mut alice), 2);
    assert_eq!(count_app_msgs(&mut bob), 2);
    assert_eq!(count_app_msgs(&mut carol), 2);

    // Convergence: same epoch, same member set across all clients.
    assert_eq!(alice.epoch(), bob.epoch());
    assert_eq!(alice.epoch(), carol.epoch());
}

#[tokio::test]
async fn delayed_past_epoch_app_message_peels_from_retained_anchor() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (_group_id, pending) = alice
        .create_group("delayed-past-epoch-app", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let delayed = bob.send_app_capture(b"epoch-one-delayed".to_vec()).await;
    assert!(bus.delay_queued(0, "old-app"));

    let david_kp = david.fresh_key_package().await;
    let invite = alice.invite(vec![david_kp]).await;
    alice.confirm(invite).await;
    bus.deliver_all();
    carol.tick().await;
    assert_eq!(carol.epoch().0, 2);

    assert!(bus.release_delayed("old-app"));
    bus.deliver_all();
    let outcomes = carol.tick().await;

    assert!(
        outcomes.iter().all(|outcome| {
            !matches!(
                outcome,
                Ok(IngestOutcome::Stale {
                    reason: StaleReason::PeelFailed
                })
            )
        }),
        "past-epoch app should peel from the retained epoch context: {outcomes:?}"
    );
    // The delayed past-epoch app message is stored under its content-derived
    // dedup id (#238), not the outer transport id `delayed.id`, so assert on the
    // terminal storage state without keying on the transport id: it must have
    // reached `Processed`, and nothing may be left stuck in `PeelDeferred`.
    let _ = &delayed;
    let carol_records = carol
        .storage()
        .list_messages(&carol.group_id(), EpochId(0))
        .expect("carol lists stored messages");
    assert!(
        carol_records
            .iter()
            .any(|record| record.state == MessageState::Processed),
        "delayed past-epoch app should be Processed in storage: {carol_records:?}"
    );
    assert!(
        carol_records
            .iter()
            .all(|record| record.state != MessageState::PeelDeferred),
        "no message should remain stuck in PeelDeferred: {carol_records:?}"
    );
    let events = carol.drain_events();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                GroupEvent::MessageReceived { payload, .. }
                    if cgka_conformance_simulator::client::decode_harness_app_payload(payload)
                        == b"epoch-one-delayed"
            )
        }),
        "expected delayed payload after retained-anchor peel, got {events:?}"
    );
}

#[tokio::test]
async fn three_client_message_exchange_vector_is_stable() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (_gid, pending) = alice
        .create_group("vector-smoke", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;
    for client in [&mut alice, &mut bob, &mut carol] {
        client.drain_events();
    }

    alice.send_app(b"alice:hello".to_vec()).await;
    bob.send_app(b"bob:hello".to_vec()).await;
    carol.send_app(b"carol:hello".to_vec()).await;
    bus.deliver_all();
    alice.tick().await;
    bob.tick().await;
    carol.tick().await;

    let trace = ScenarioTrace {
        name: "three-client-message-exchange/v1".into(),
        pending_resolutions: vec![PendingResolutionObservation {
            step_index: 1,
            client: "alice".into(),
            pending: "create".into(),
            resolution: "confirmed".into(),
        }],
        errors: vec![],
        admin_policies: vec![],
        observations: vec![
            observe_client("alice", &mut alice),
            observe_client("bob", &mut bob),
            observe_client("carol", &mut carol),
        ],
    };

    assert_eq!(
        trace,
        ScenarioTrace {
            name: "three-client-message-exchange/v1".into(),
            pending_resolutions: vec![PendingResolutionObservation {
                step_index: 1,
                client: "alice".into(),
                pending: "create".into(),
                resolution: "confirmed".into(),
            }],
            errors: vec![],
            admin_policies: vec![],
            observations: vec![
                cgka_conformance_simulator::ClientObservation {
                    client: "alice".into(),
                    epoch: 1,
                    member_count: 3,
                    group_name: "vector-smoke".into(),
                    event_counts: cgka_conformance_simulator::ClientEventCounts {
                        message_received: 2,
                        ..Default::default()
                    },
                    received_payloads: vec!["bob:hello".into(), "carol:hello".into()],
                    added_members: vec![],
                    removed_members: vec![],
                    epoch_changes: vec![],
                    app_invalidations: vec![],
                    recoveries: vec![],
                },
                cgka_conformance_simulator::ClientObservation {
                    client: "bob".into(),
                    epoch: 1,
                    member_count: 3,
                    group_name: "vector-smoke".into(),
                    event_counts: cgka_conformance_simulator::ClientEventCounts {
                        message_received: 2,
                        ..Default::default()
                    },
                    received_payloads: vec!["alice:hello".into(), "carol:hello".into()],
                    added_members: vec![],
                    removed_members: vec![],
                    epoch_changes: vec![],
                    app_invalidations: vec![],
                    recoveries: vec![],
                },
                cgka_conformance_simulator::ClientObservation {
                    client: "carol".into(),
                    epoch: 1,
                    member_count: 3,
                    group_name: "vector-smoke".into(),
                    event_counts: cgka_conformance_simulator::ClientEventCounts {
                        message_received: 2,
                        ..Default::default()
                    },
                    received_payloads: vec!["alice:hello".into(), "bob:hello".into()],
                    added_members: vec![],
                    removed_members: vec![],
                    epoch_changes: vec![],
                    app_invalidations: vec![],
                    recoveries: vec![],
                },
            ],
        }
    );
}

#[tokio::test]
async fn scenario_spec_runs_three_client_message_exchange() {
    let spec = ScenarioSpec {
        name: "three-client-message-exchange/v1".into(),
        spec_version: "1".into(),
        clients: vec!["alice".into(), "bob".into(), "carol".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "vector-smoke".into(),
                invitees: vec!["bob".into(), "carol".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "create".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into(), "carol".into()],
            },
            ScenarioStep::SendAppMessage {
                sender: "alice".into(),
                payload: "alice:hello".into(),
            },
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: "bob:hello".into(),
            },
            ScenarioStep::SendAppMessage {
                sender: "carol".into(),
                payload: "carol:hello".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into(), "bob".into(), "carol".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["alice".into(), "bob".into(), "carol".into()],
            },
        ],
    };

    let trace = run_scenario_spec(&spec).await.expect("scenario runs");

    assert_eq!(trace, three_client_message_exchange_trace().await);
}

#[tokio::test]
async fn scenario_spec_supports_publish_fail() {
    let spec = ScenarioSpec {
        name: "publish-fail/v1".into(),
        spec_version: "1".into(),
        clients: vec!["alice".into(), "bob".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "publish-fail".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::FailPending {
                client: "alice".into(),
                pending: "create".into(),
            },
            ScenarioStep::Observe {
                clients: vec!["alice".into()],
            },
        ],
    };

    let trace = run_scenario_spec(&spec).await.expect("scenario runs");

    assert_eq!(trace.observations[0].client, "alice");
    assert_eq!(trace.observations[0].epoch, 0);
    assert_eq!(trace.observations[0].member_count, 1);
    assert_eq!(
        trace.pending_resolutions,
        vec![PendingResolutionObservation {
            step_index: 1,
            client: "alice".into(),
            pending: "create".into(),
            resolution: "rolled_back".into(),
        }]
    );
}

#[tokio::test]
async fn scenario_spec_supports_leave_and_clear_partition() {
    let spec = ScenarioSpec {
        name: "leave-and-clear-partition/v1".into(),
        spec_version: "1".into(),
        clients: vec!["alice".into(), "bob".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "partition".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "create".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::SetPartition {
                allow: vec!["bob".into()],
            },
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: "bob:hidden".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            ScenarioStep::ClearPartition,
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: "bob:visible".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            ScenarioStep::Leave {
                client: "bob".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["alice".into()],
            },
        ],
    };

    let trace = run_scenario_spec(&spec).await.expect("scenario runs");
    let alice = &trace.observations[0];

    assert_eq!(alice.client, "alice");
    assert_eq!(alice.member_count, 1);
    assert_eq!(alice.received_payloads, vec!["bob:visible"]);
}

#[tokio::test]
async fn scenario_spec_can_drop_queued_message() {
    let spec = ScenarioSpec {
        name: "drop-queued/v1".into(),
        spec_version: "1".into(),
        clients: vec!["alice".into(), "bob".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "drop".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "create".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: "bob:dropped".into(),
            },
            ScenarioStep::DropQueued { index: 0 },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["alice".into()],
            },
        ],
    };

    let trace = run_scenario_spec(&spec).await.expect("scenario runs");

    assert_eq!(
        trace.observations[0].received_payloads,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn scenario_spec_can_duplicate_delay_and_reorder_queued_messages() {
    let spec = ScenarioSpec {
        name: "queue-faults/v1".into(),
        spec_version: "1".into(),
        clients: vec!["alice".into(), "bob".into(), "carol".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "faults".into(),
                invitees: vec!["bob".into(), "carol".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "create".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into(), "carol".into()],
            },
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: "bob:first".into(),
            },
            ScenarioStep::SendAppMessage {
                sender: "carol".into(),
                payload: "carol:second".into(),
            },
            ScenarioStep::DuplicateQueued { index: 0 },
            ScenarioStep::DelayQueued {
                index: 1,
                delayed: "delayed-copy".into(),
            },
            ScenarioStep::ReorderQueued { order: vec![1, 0] },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            ScenarioStep::ReleaseDelayed {
                delayed: "delayed-copy".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["alice".into()],
            },
        ],
    };

    let trace = run_scenario_spec(&spec).await.expect("scenario runs");

    assert_eq!(
        trace.observations[0].received_payloads,
        vec!["carol:second", "bob:first"]
    );
}

#[tokio::test]
async fn send_leave_family_records_seed_and_runs_generated_cases() {
    let cases = generate_send_leave_family(42, 3);

    assert_eq!(cases, generate_send_leave_family(42, 3));
    assert_eq!(cases.len(), 3);
    for (case_index, case) in cases.iter().enumerate() {
        assert_eq!(case.family_name, "send-leave/v1");
        assert_eq!(case.generator_version, "1");
        assert_eq!(case.seed, 42);
        assert_eq!(case.case_index, case_index as u64);

        let trace = run_scenario_spec(&case.scenario)
            .await
            .expect("generated scenario runs");
        assert_eq!(trace.name, case.scenario.name);
        assert!(!trace.observations.is_empty());
    }

    let json = serde_json::to_value(&cases[0]).expect("case serializes");
    assert_eq!(json["seed"], 42);
    assert_eq!(json["generator_version"], "1");
}

#[tokio::test]
async fn convergence_e2e_delivery_family_runs_generated_variants() {
    let cases = generate_convergence_e2e_delivery_family(99, 12);

    assert_eq!(cases, generate_convergence_e2e_delivery_family(99, 12));
    assert_eq!(cases.len(), 12);
    assert!(
        cases.iter().any(|case| case
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::DuplicateQueued { .. }))),
        "generated cases should include duplicate-delivery variants"
    );
    assert!(
        cases.iter().any(|case| case
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::DelayQueued { .. }))),
        "generated cases should include delayed-delivery variants"
    );
    assert!(
        cases.iter().any(|case| case
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::ReorderQueued { .. }))),
        "generated cases should include reordered-delivery variants"
    );

    for (case_index, case) in cases.iter().enumerate() {
        assert_eq!(case.family_name, "convergence-e2e-delivery/v1");
        assert_eq!(case.generator_version, "1");
        assert_eq!(case.seed, 99);
        assert_eq!(case.case_index, case_index as u64);

        let report = run_generated_case_report(case, None)
            .await
            .expect("generated convergence variant reports");
        assert!(report.invariant_failures.is_empty());
        assert_real_peeler_convergence_trace(report.observed_trace.as_ref().expect("trace"));
        assert!(matches!(report.epoch_change_observations.len(), 2 | 4));
        assert!(report.app_invalidation_observations.is_empty());
    }
}

#[tokio::test]
async fn convergence_chaos_family_generates_specs_with_semantic_expectations() {
    let cases = generate_convergence_chaos_family(123, 24);

    assert_eq!(cases, generate_convergence_chaos_family(123, 24));
    assert_eq!(cases.len(), 24);
    assert!(
        cases.iter().all(|case| !case.expected_outcomes.is_empty()),
        "chaos cases should carry semantic expectations"
    );
    assert!(
        cases.iter().any(|case| case
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::SetPartition { .. }))),
        "chaos cases should include partition windows"
    );
    assert!(
        cases.iter().any(|case| case
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::InviteMembers { .. }))),
        "chaos cases should include invite races"
    );
    assert!(
        cases.iter().any(|case| case
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::UpdateGroupData { .. }))),
        "chaos cases should include group-data races"
    );
    assert!(
        cases.iter().any(|case| case
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::FailPending { .. }))),
        "chaos cases should include publish rollback"
    );
    assert!(
        cases
            .iter()
            .any(|case| case.scenario.steps.iter().any(|step| matches!(
                step,
                ScenarioStep::DuplicateQueued { .. }
                    | ScenarioStep::DelayQueued { .. }
                    | ScenarioStep::ReorderQueued { .. }
            ))),
        "chaos cases should include queue schedule faults"
    );
    assert!(
        cases.iter().any(|case| case.scenario.clients.len() >= 21),
        "chaos cases should include 20+ client groups"
    );
    assert!(
        cases.iter().any(|case| {
            case.scenario
                .steps
                .iter()
                .filter(|step| matches!(step, ScenarioStep::SendAppMessage { .. }))
                .count()
                >= 20
        }),
        "chaos cases should include large message storms"
    );
    assert!(
        cases.iter().any(|case| {
            case.scenario
                .steps
                .iter()
                .filter(|step| matches!(step, ScenarioStep::UpdateGroupData { .. }))
                .count()
                >= 4
        }),
        "chaos cases should include multi-committer storms"
    );
    assert!(
        cases.iter().any(|case| {
            let sends = case
                .scenario
                .steps
                .iter()
                .filter(|step| matches!(step, ScenarioStep::SendAppMessage { .. }))
                .count();
            let commits = case
                .scenario
                .steps
                .iter()
                .filter(|step| matches!(step, ScenarioStep::UpdateGroupData { .. }))
                .count();
            case.scenario.clients.len() >= 21 && sends >= 20 && commits >= 4
        }),
        "chaos cases should include 20+ client mixed message and commit storms"
    );
    assert!(
        cases.iter().any(|case| case
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::RestartClient { .. }))),
        "chaos cases should include restart/reopen between delivery and observation"
    );

    for (case_index, case) in cases.iter().enumerate() {
        assert_eq!(case.family_name, "convergence-chaos/v1");
        assert_eq!(case.generator_version, "3");
        assert_eq!(case.seed, 123);
        assert_eq!(case.case_index, case_index as u64);

        let report = run_generated_case_report(case, None)
            .await
            .expect("generated convergence chaos report runs");
        assert_eq!(report.expected_outcomes, case.expected_outcomes);
        assert!(
            report.expectation_failures.is_empty(),
            "case {} failed expectations: {:?}",
            case.case_index,
            report.expectation_failures
        );
        assert!(report.invariant_failures.is_empty());
        assert_eq!(report.scenario, case.scenario);
    }
}

#[tokio::test]
async fn convergence_chaos_family_seed_changes_scenarios() {
    // Regression for darkmatter#166: distinct seeds must produce distinct
    // chaos scenarios. Before the fix, every shape except the rollback case was
    // a pure function of case_index, so seeded batches silently re-ran the same
    // fixed scenarios and coverage did not grow with seeds.
    let seed_a = generate_convergence_chaos_family(1, 11);
    let seed_b = generate_convergence_chaos_family(2, 11);
    assert_eq!(seed_a.len(), 11);
    assert_eq!(seed_b.len(), 11);

    // The two queue-fault/storm shapes that consume the rng must differ between
    // seeds (rollback delivery schedule, message storm, partitioned storm,
    // commit storm, mixed storm). Check the seed-driven shapes specifically.
    let seed_driven_arms = [2usize, 6, 7, 8, 9];
    for arm in seed_driven_arms {
        assert_ne!(
            seed_a[arm].scenario, seed_b[arm].scenario,
            "chaos arm {arm} should differ across seeds",
        );
    }

    // Arm 2 (rollback queue faults) must vary a real behavioral dimension, not
    // just the app payload string: the seed-driven delivery schedule (the
    // ReorderQueued permutation) must differ across seeds. This is the
    // regression guard for darkmatter#166's blocking review finding — before
    // the fix, arm 2's only rng use was a random u16 appended to a payload, so
    // normalizing the payload made both seeds' scenarios identical.
    let reorder_order = |case: &GeneratedScenarioCase| -> Vec<usize> {
        case.scenario
            .steps
            .iter()
            .find_map(|step| match step {
                ScenarioStep::ReorderQueued { order } => Some(order.clone()),
                _ => None,
            })
            .expect("rollback arm should carry a seed-driven ReorderQueued step")
    };
    assert_ne!(
        reorder_order(&seed_a[2]),
        reorder_order(&seed_b[2]),
        "arm 2 rollback delivery schedule must vary with the seed, not just the payload string",
    );

    // Every seed-driven scenario must still satisfy its pinned expectations,
    // so the divergence reflects real behavior variation, not breakage.
    for case in seed_a.iter().chain(seed_b.iter()) {
        let report = run_generated_case_report(case, None)
            .await
            .expect("seeded chaos case reports");
        assert!(
            report.expectation_failures.is_empty(),
            "case {} (seed {}) failed expectations: {:?}",
            case.case_index,
            case.seed,
            report.expectation_failures
        );
        assert!(report.invariant_failures.is_empty());
    }
}

#[tokio::test]
async fn convergence_chaos_rollback_fault_duplicates_post_rollback_app_message() {
    // Regression for darkmatter#163: the rollback arm must duplicate and delay
    // a Bob app message that Alice actually ticks, not the rolled-back commit
    // pinned at queue index 0 and addressed to Bob.
    let cases = generate_convergence_chaos_family(123, 3);
    let case = &cases[2];

    let duplicate_index = case
        .scenario
        .steps
        .iter()
        .find_map(|step| match step {
            ScenarioStep::DuplicateQueued { index } => Some(*index),
            _ => None,
        })
        .expect("rollback arm should duplicate a queued message");
    assert_eq!(
        duplicate_index, 1,
        "queue index 0 is Alice's rolled-back commit to Bob; duplicate the first post-rollback app message instead",
    );

    let delayed_copy = case
        .scenario
        .steps
        .iter()
        .find_map(|step| match step {
            ScenarioStep::DelayQueued { index, delayed } => Some((*index, delayed.as_str())),
            _ => None,
        })
        .expect("rollback arm should delay the duplicate copy");
    assert_eq!(delayed_copy, (2, "duplicate-app"));

    let report = run_generated_case_report(case, None)
        .await
        .expect("rollback duplicate-app case reports");
    assert!(
        report.expectation_failures.is_empty(),
        "rollback duplicate-app expectations failed: {:?}",
        report.expectation_failures
    );
    assert!(report.invariant_failures.is_empty());

    let trace = report.observed_trace.as_ref().expect("trace");
    let alice = trace
        .observations
        .iter()
        .find(|observation| observation.client == "alice")
        .expect("alice observation");
    assert_eq!(
        alice.received_payloads.len(),
        6,
        "Alice should receive the six unique post-rollback app payloads; the released duplicate must not emit a seventh",
    );
}

#[tokio::test]
async fn failing_generated_case_records_a_minimized_reproducer() {
    let scenario = ScenarioSpec {
        name: "convergence-chaos/minimizer-smoke/v1".into(),
        spec_version: "1".into(),
        clients: vec!["alice".into(), "bob".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "minimizer".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "create".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::ClearEvents {
                clients: vec!["alice".into(), "bob".into()],
            },
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: "irrelevant noise".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["alice".into()],
            },
        ],
    };
    let case = GeneratedScenarioCase {
        family_name: "convergence-chaos/v1".into(),
        generator_version: "1".into(),
        seed: 99,
        case_index: 0,
        expected_outcomes: vec![TraceExpectation::ClientState {
            client: "alice".into(),
            epoch: 1,
            member_count: 99,
            received_payloads: None,
            added_members: None,
            removed_members: None,
        }],
        scenario,
    };

    let report = run_generated_case_report(&case, None)
        .await
        .expect("failing generated case still reports");

    assert_eq!(report.expectation_failures.len(), 1);
    let minimized = report
        .metadata
        .generated
        .as_ref()
        .and_then(|generated| generated.minimized_case.as_ref())
        .expect("failing generated case should record a minimized case");
    assert!(
        minimized.steps.len() < case.scenario.steps.len(),
        "minimized case should remove irrelevant delivery noise"
    );
    let minimized_report =
        run_scenario_report_with_outcomes(minimized, None, case.expected_outcomes.clone())
            .await
            .expect("minimized report runs");
    assert!(
        minimized_report
            .expectation_failures
            .iter()
            .any(|failure| failure.kind == "client_state_mismatch"),
        "minimized case should reproduce the failure"
    );
}

#[tokio::test]
async fn scenario_report_records_trace_log_recoveries_and_failures() {
    let spec = deliberate_fork_recovery_spec();

    let report = run_scenario_report(&spec, None)
        .await
        .expect("scenario reports");

    assert_eq!(report.metadata.scenario_name, "deliberate-fork-recovery/v1");
    assert_eq!(report.metadata.step_count, spec.steps.len());
    assert_eq!(report.step_log.len(), spec.steps.len());
    assert!(
        report
            .step_log
            .iter()
            .all(|entry| entry.status.is_completed())
    );
    assert_eq!(report.recovery_observations.len(), 1);
    let recovery = &report.recovery_observations[0];
    assert_eq!(recovery.source_epoch, 1);
    assert_eq!(recovery.recovered_epoch, 2);
    assert_ne!(recovery.winner, recovery.invalidated);
    assert!(recovery.winner < recovery.invalidated);
    assert!(report.invariant_failures.is_empty());

    let json = serde_json::to_value(&report).expect("report serializes");
    assert_eq!(
        json["metadata"]["scenario_name"],
        "deliberate-fork-recovery/v1"
    );
    assert!(
        json["step_log"]
            .as_array()
            .is_some_and(|steps| !steps.is_empty())
    );
}

#[tokio::test]
async fn group_data_fork_recovery_fixture_uses_semantic_outcomes() {
    let spec = group_data_fork_recovery_spec();
    let trace = run_scenario_spec(&spec)
        .await
        .expect("group-data fork scenario runs");

    for label in ["alice", "bob"] {
        let observation = trace
            .observations
            .iter()
            .find(|observation| observation.client == label)
            .expect("client observation");
        assert_eq!(observation.epoch, 2);
        assert_eq!(observation.member_count, 2);
    }
    let recoveries = trace
        .observations
        .iter()
        .flat_map(|observation| observation.recoveries.iter())
        .collect::<Vec<_>>();
    assert_eq!(recoveries.len(), 1);
    assert_ne!(
        recoveries[0].winner, recoveries[0].invalidated,
        "semantic recovery fixture should not depend on exact commit digest bytes"
    );
}

#[tokio::test]
async fn vector_fixture_report_records_semantic_expectation_failures() {
    let fixture = VectorFixture {
        scenario_name: "group-data-fork-recovery/v1".into(),
        vector_version: "1".into(),
        conformance_version: env!("CARGO_PKG_VERSION").into(),
        seed: None,
        scenario: group_data_fork_recovery_spec(),
        expected_trace: None,
        expected_outcomes: vec![TraceExpectation::ClientState {
            client: "bob".into(),
            epoch: 99,
            member_count: 2,
            received_payloads: Some(vec![]),
            added_members: None,
            removed_members: None,
        }],
    };

    let report = run_vector_fixture_report(&fixture)
        .await
        .expect("fixture report runs");

    assert_eq!(report.expected_outcomes, fixture.expected_outcomes);
    assert_eq!(report.expectation_failures.len(), 1);
    assert_eq!(report.expectation_failures[0].kind, "client_state_mismatch");
    assert_eq!(report.invariant_failures[0].kind, "client_state_mismatch");

    let json = serde_json::to_value(&report).expect("report serializes");
    assert_eq!(
        json["metadata"]["fixture"]["scenario_name"],
        "group-data-fork-recovery/v1"
    );
    assert_eq!(
        json["expectation_failures"][0]["kind"],
        "client_state_mismatch"
    );
    assert!(json["expectation_failures"][0]["expected"].is_object());
    assert!(json["expectation_failures"][0]["actual"].is_object());
}

fn group_data_fork_recovery_spec() -> ScenarioSpec {
    ScenarioSpec {
        name: "group-data-fork-recovery/v1".into(),
        spec_version: "1".into(),
        clients: vec!["alice".into(), "bob".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "fork".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "create".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::ClearEvents {
                clients: vec!["alice".into(), "bob".into()],
            },
            ScenarioStep::UpdateGroupData {
                client: "alice".into(),
                name: "alice branch".into(),
                pending: "alice-update".into(),
            },
            ScenarioStep::UpdateGroupData {
                client: "bob".into(),
                name: "bob branch".into(),
                pending: "bob-update".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "alice-update".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "bob".into(),
                pending: "bob-update".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into(), "bob".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["alice".into(), "bob".into()],
            },
        ],
    }
}

fn deliberate_fork_recovery_spec() -> ScenarioSpec {
    ScenarioSpec {
        name: "deliberate-fork-recovery/v1".into(),
        spec_version: "1".into(),
        clients: vec!["alice".into(), "bob".into(), "david".into(), "eve".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "fork".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "create".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::SetPartition {
                allow: vec!["alice".into(), "bob".into()],
            },
            ScenarioStep::InviteMembers {
                inviter: "alice".into(),
                invitees: vec!["david".into()],
                pending: "alice-invite".into(),
            },
            ScenarioStep::InviteMembers {
                inviter: "bob".into(),
                invitees: vec!["eve".into()],
                pending: "bob-invite".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "alice-invite".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "bob".into(),
                pending: "bob-invite".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into(), "bob".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["alice".into(), "bob".into()],
            },
        ],
    }
}

#[tokio::test]
async fn scenario_report_records_mismatch_as_invariant_failure() {
    let spec = ScenarioSpec {
        name: "report-mismatch/v1".into(),
        spec_version: "1".into(),
        clients: vec!["alice".into(), "bob".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "report-mismatch".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "create".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["alice".into()],
            },
        ],
    };
    let expected = ScenarioTrace {
        name: spec.name.clone(),
        pending_resolutions: vec![],
        errors: vec![],
        admin_policies: vec![],
        observations: vec![],
    };

    let report = run_scenario_report(&spec, Some(expected))
        .await
        .expect("scenario reports");

    assert_eq!(report.invariant_failures.len(), 1);
    assert_eq!(report.invariant_failures[0].kind, "trace_mismatch");
}

#[tokio::test]
async fn generated_case_report_records_generator_metadata() {
    let case = generate_send_leave_family(7, 1).remove(0);

    let report = run_generated_case_report(&case, None)
        .await
        .expect("generated case reports");
    let generated = report
        .metadata
        .generated
        .as_ref()
        .expect("generated metadata");

    assert_eq!(generated.family_name, "send-leave/v1");
    assert_eq!(generated.generator_version, "1");
    assert_eq!(generated.seed, 7);
    assert_eq!(generated.case_index, 0);
    assert!(generated.minimized_case.is_none());
}

async fn three_client_message_exchange_trace() -> ScenarioTrace {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (_gid, pending) = alice
        .create_group("vector-smoke", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;
    for client in [&mut alice, &mut bob, &mut carol] {
        client.drain_events();
    }

    alice.send_app(b"alice:hello".to_vec()).await;
    bob.send_app(b"bob:hello".to_vec()).await;
    carol.send_app(b"carol:hello".to_vec()).await;
    bus.deliver_all();
    alice.tick().await;
    bob.tick().await;
    carol.tick().await;

    ScenarioTrace {
        name: "three-client-message-exchange/v1".into(),
        pending_resolutions: vec![PendingResolutionObservation {
            step_index: 1,
            client: "alice".into(),
            pending: "create".into(),
            resolution: "confirmed".into(),
        }],
        errors: vec![],
        admin_policies: vec![],
        observations: vec![
            observe_client("alice", &mut alice),
            observe_client("bob", &mut bob),
            observe_client("carol", &mut carol),
        ],
    }
}

#[tokio::test]
async fn add_then_self_remove_via_harness() {
    // Alice creates with Bob and Carol; Bob, a non-admin, leaves; Alice,
    // an admin, auto-commits the SelfRemove proposal.
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (_gid, pending) = alice
        .create_group("leave-test", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    // Bob (non-admin) leaves.
    bob.leave().await;
    bus.deliver_all();
    alice.tick().await; // ingests proposal + auto-commits

    // Alice's auto-commit goes onto the bus.
    bus.deliver_all();
    let bob_outcomes = bob.tick().await; // ingests alice's commit
    let carol_outcomes = carol.tick().await;

    assert_eq!(alice.epoch().0, 2);
    assert_eq!(alice.members().len(), 2);
    assert_eq!(bob.epoch().0, 2, "bob outcomes: {bob_outcomes:?}");
    assert!(
        carol_outcomes.iter().all(Result::is_ok),
        "carol outcomes: {carol_outcomes:?}"
    );
    let _ = carol;
}

#[tokio::test]
async fn deliberate_fork_via_harness() {
    // Alice and Bob each invite concurrently at the same epoch. The bus
    // partition keeps each side from seeing the other's commit until both
    // have committed locally. When the partition lifts, fork recovery rolls
    // both clients onto the same deterministic winner.
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let (group_id, pending) = alice
        .create_group_with_admins("fork", vec![bob_kp], vec![], vec![bob.member_id()])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;

    // Partition: drop everything queued so far (already delivered above)
    // and prevent David's & Eve's mailboxes from seeing the concurrent
    // commits — keeps the test focused on alice + bob's view.
    let alice_id = alice.bus_id;
    let bob_id = bob.bus_id;
    bus.set_partition(Some(vec![alice_id, bob_id]));

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;

    let alice_pending = alice.invite(vec![david_kp]).await;
    let bob_pending = bob.invite(vec![eve_kp]).await;
    // Both confirm so they're in Stable{2} (not PendingPublish — otherwise
    // can_ingest=false and inbound would short-circuit before fork detection).
    alice.confirm(alice_pending).await;
    bob.confirm(bob_pending).await;

    // Now deliver the cross-traffic. The lower transport ordering key wins;
    // the peer on the losing branch rolls back and applies that same winner.
    bus.deliver_all();
    let alice_outcomes = alice.tick().await;
    let bob_outcomes = bob.tick().await;

    let alice_forked = alice_outcomes
        .iter()
        .any(|o| matches!(o, Err(cgka_traits::EngineError::ForkedEpoch { .. })));
    let bob_forked = bob_outcomes
        .iter()
        .any(|o| matches!(o, Err(cgka_traits::EngineError::ForkedEpoch { .. })));
    assert!(
        !alice_forked,
        "alice should recover; got {alice_outcomes:?}"
    );
    assert!(!bob_forked, "bob should recover; got {bob_outcomes:?}");
    assert_eq!(alice.epoch().0, 2);
    assert_eq!(bob.epoch().0, 2);

    let alice_members = alice.members();
    let bob_members = bob.members();
    assert_eq!(
        alice_members, bob_members,
        "alice outcomes: {alice_outcomes:?}; bob outcomes: {bob_outcomes:?}"
    );
    let trace = ScenarioTrace {
        name: "deliberate-fork-recovery/v1".into(),
        pending_resolutions: vec![],
        errors: vec![],
        admin_policies: vec![],
        observations: vec![
            observe_client("alice", &mut alice),
            observe_client("bob", &mut bob),
        ],
    };
    let recoveries: Vec<_> = trace
        .observations
        .iter()
        .flat_map(|o| o.recoveries.iter())
        .collect();
    assert_eq!(
        recoveries.len(),
        1,
        "exactly one peer should roll back to the deterministic winner: {trace:#?}"
    );
    assert_eq!(recoveries[0].source_epoch, 1);
    assert_eq!(recoveries[0].recovered_epoch, 2);
    assert_ne!(recoveries[0].winner, recoveries[0].invalidated);
    assert!(recoveries[0].winner < recoveries[0].invalidated);
    let has_david = alice_members.iter().any(|m| m.id == david.member_id());
    let has_eve = alice_members.iter().any(|m| m.id == eve.member_id());
    assert_ne!(has_david, has_eve);
    let _ = group_id;
}

#[tokio::test]
async fn convergence_e2e_from_peeler_ingest_to_group_events() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut frank = ClientBuilder::new(pad32(b"frank"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut david = ClientBuilder::new(pad32(b"david"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let frank_kp = frank.fresh_key_package().await;
    let (_group_id, pending) = alice
        .create_group_with_admins(
            "convergence-e2e",
            vec![bob_kp, carol_kp, frank_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;
    frank.tick().await;
    for client in [&mut alice, &mut bob, &mut carol, &mut frank] {
        client.drain_events();
    }

    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let alice_pending = alice.invite(vec![david_kp]).await;
    let bob_pending = bob.invite(vec![eve_kp]).await;
    alice.confirm(alice_pending).await;
    bob.confirm(bob_pending).await;
    let alice_app = alice
        .send_app_capture(b"alice branch payload".to_vec())
        .await;
    let bob_app = bob.send_app_capture(b"bob branch payload".to_vec()).await;

    let queued_messages = openmls_projection_messages(&carol, bus.queued_messages()).await;
    let commit_messages: Vec<_> = queued_messages
        .iter()
        .filter(|message| {
            project_mls_message(&message.payload)
                .is_ok_and(|projection| projection.kind == OpenMlsContentKind::Commit)
        })
        .collect();
    assert_eq!(
        commit_messages.len(),
        2,
        "expected exactly the two competing invite commits in the bus queue"
    );
    // Both competing commits are privileged admin invites, so the authenticated
    // committer identity selects the branch before the digest fallback.
    let selected_index = if alice.member_id().as_slice() < bob.member_id().as_slice() {
        0
    } else {
        1
    };
    let expected_member = if selected_index == 0 {
        david.member_id()
    } else {
        eve.member_id()
    };
    let losing_member = if selected_index == 0 {
        eve.member_id()
    } else {
        david.member_id()
    };
    let (expected_payload, losing_payload) = if selected_index == 0 {
        (
            b"alice branch payload".to_vec(),
            b"bob branch payload".to_vec(),
        )
    } else {
        (
            b"bob branch payload".to_vec(),
            b"alice branch payload".to_vec(),
        )
    };
    let _ = (alice_app, bob_app);

    bus.deliver_all();
    let carol_outcomes = carol.tick().await;
    let frank_outcomes = frank.tick().await;
    assert_tick_reached_convergence("carol", &carol_outcomes);
    assert_tick_reached_convergence("frank", &frank_outcomes);

    assert_canonical_application_event(
        "carol",
        carol.drain_events(),
        &expected_payload,
        &losing_payload,
    );
    assert_canonical_application_event(
        "frank",
        frank.drain_events(),
        &expected_payload,
        &losing_payload,
    );
    assert_eq!(carol.epoch(), EpochId(2));
    assert_eq!(frank.epoch(), EpochId(2));
    for (name, members) in [("carol", carol.members()), ("frank", frank.members())] {
        assert!(
            members.iter().any(|member| member.id == expected_member),
            "{name} should contain the selected branch invitee"
        );
        assert!(
            !members.iter().any(|member| member.id == losing_member),
            "{name} should not contain the losing branch invitee"
        );
    }
}

#[tokio::test]
async fn scenario_report_records_convergence_e2e_group_events() {
    let spec = convergence_e2e_group_events_spec();

    let report = run_scenario_report(&spec, None)
        .await
        .expect("scenario reports");

    assert!(report.invariant_failures.is_empty());
    assert_real_peeler_convergence_trace(report.observed_trace.as_ref().expect("trace"));
    assert!(matches!(report.epoch_change_observations.len(), 2 | 4));
    assert!(report.app_invalidation_observations.is_empty());
    assert!(
        report
            .step_log
            .iter()
            .any(|entry| entry.step_type == "clear_events")
    );
}

#[tokio::test]
async fn canonical_vector_fixtures_match_generated_traces() {
    // Exact traces remain useful when the observable output is naturally
    // stable. Fork-recovery fixtures use semantic expectations because commit
    // digest bytes come from randomized MLS envelopes.
    let vectors = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");
    let mut fixtures = std::fs::read_dir(vectors)
        .expect("vectors dir exists")
        .map(|entry| entry.expect("vector entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".v1.json") && name != "manifest.v1.json")
        })
        .collect::<Vec<_>>();
    fixtures.sort();

    for path in fixtures {
        let fixture_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture file name");
        let fixture: VectorFixture =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture contents"))
                .unwrap_or_else(|e| panic!("{fixture_name} parses: {e}"));
        let observed_trace = run_scenario_spec(&fixture.scenario)
            .await
            .expect("fixture scenario runs");
        assert_vector_fixture_matches(fixture_name, &fixture, observed_trace);
    }
}

fn convergence_e2e_group_events_spec() -> ScenarioSpec {
    ScenarioSpec {
        name: "convergence-e2e-group-events/v1".into(),
        spec_version: "1".into(),
        clients: vec![
            "alice".into(),
            "bob".into(),
            "carol".into(),
            "frank".into(),
            "david".into(),
            "eve".into(),
            "grace".into(),
        ],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "convergence-e2e".into(),
                invitees: vec!["bob".into(), "carol".into(), "frank".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "create".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into(), "carol".into(), "frank".into()],
            },
            ScenarioStep::ClearEvents {
                clients: vec!["alice".into(), "bob".into(), "carol".into(), "frank".into()],
            },
            ScenarioStep::InviteMembers {
                inviter: "alice".into(),
                invitees: vec!["david".into()],
                pending: "alice-invite-david".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "alice-invite-david".into(),
            },
            ScenarioStep::InviteMembers {
                inviter: "alice".into(),
                invitees: vec!["grace".into()],
                pending: "alice-invite-grace".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "alice".into(),
                pending: "alice-invite-grace".into(),
            },
            ScenarioStep::InviteMembers {
                inviter: "bob".into(),
                invitees: vec!["eve".into()],
                pending: "bob-invite-eve".into(),
            },
            ScenarioStep::ConfirmPending {
                client: "bob".into(),
                pending: "bob-invite-eve".into(),
            },
            ScenarioStep::SendAppMessage {
                sender: "alice".into(),
                payload: "alice canonical payload".into(),
            },
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: "bob losing payload".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["carol".into(), "frank".into()],
            },
            ScenarioStep::Observe {
                clients: vec!["carol".into(), "frank".into()],
            },
        ],
    }
}

fn assert_tick_reached_convergence(
    client: &str,
    outcomes: &[Result<cgka_traits::ingest::IngestOutcome, cgka_traits::EngineError>],
) {
    assert!(
        outcomes.iter().all(Result::is_ok),
        "{client} should not hit ingest errors: {outcomes:?}"
    );
    assert!(
        outcomes.iter().any(|outcome| {
            matches!(
                outcome,
                Ok(cgka_traits::ingest::IngestOutcome::Buffered { .. })
            )
        }),
        "{client} should have buffered convergence input from peeler ingest: {outcomes:?}"
    );
}

fn assert_canonical_application_event(
    client: &str,
    events: Vec<GroupEvent>,
    expected_payload: &[u8],
    losing_payload: &[u8],
) {
    let received_payloads: Vec<Vec<u8>> = events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { payload, .. } => {
                Some(cgka_conformance_simulator::client::decode_harness_app_payload(payload))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        received_payloads,
        vec![expected_payload.to_vec()],
        "{client} should receive exactly the selected branch payload: {events:?}"
    );
    assert!(
        !received_payloads
            .iter()
            .any(|payload| payload == losing_payload),
        "{client} should not receive losing branch payload: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, GroupEvent::AppMessageInvalidated { .. })),
        "{client} invalidations: {events:?}"
    );
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                GroupEvent::EpochChanged {
                    from: EpochId(1),
                    to: EpochId(2),
                    ..
                }
            )
        }),
        "{client} should observe the canonical epoch transition: {events:?}"
    );
}

fn assert_real_peeler_convergence_trace(trace: &ScenarioTrace) {
    for observation in &trace.observations {
        match observation.received_payloads.as_slice() {
            [payload] if payload == "alice canonical payload" => {
                assert_eq!(observation.epoch, 3);
                assert_eq!(observation.member_count, 6);
                assert_eq!(observation.added_members, vec!["david", "grace"]);
                assert_eq!(
                    observation.epoch_changes,
                    vec![
                        EpochChangeObservation { from: 1, to: 2 },
                        EpochChangeObservation { from: 2, to: 3 },
                    ]
                );
            }
            [payload] if payload == "bob losing payload" => {
                assert_eq!(observation.epoch, 2);
                assert_eq!(observation.member_count, 5);
                assert_eq!(observation.added_members, vec!["eve"]);
                assert_eq!(
                    observation.epoch_changes,
                    vec![EpochChangeObservation { from: 1, to: 2 }]
                );
            }
            _ => panic!("unexpected convergence trace observation: {observation:?}"),
        }
        assert!(observation.removed_members.is_empty());
        assert!(observation.app_invalidations.is_empty());
        assert!(observation.recoveries.is_empty());
    }
}

fn assert_vector_fixture_matches(
    fixture_name: &str,
    fixture: &VectorFixture,
    observed_trace: ScenarioTrace,
) {
    assert_eq!(
        fixture.conformance_version,
        env!("CARGO_PKG_VERSION"),
        "fixture {fixture_name} has stale conformance_version"
    );
    assert_eq!(
        fixture.scenario_name, fixture.scenario.name,
        "fixture {fixture_name} metadata scenario_name must match scenario.name"
    );
    if let Some(expected_trace) = &fixture.expected_trace {
        assert_eq!(
            fixture.scenario_name, expected_trace.name,
            "fixture {fixture_name} metadata scenario_name must match expected_trace.name"
        );
    }
    assert!(
        fixture.expected_trace.is_some() || !fixture.expected_outcomes.is_empty(),
        "fixture {fixture_name} must define an exact expected_trace or semantic expected_outcomes"
    );
    let mismatches = fixture.compare_observed_trace(&observed_trace);
    assert!(
        mismatches.is_empty(),
        "fixture {fixture_name} mismatch\nseed: {:?}\nmismatches:\n{:#?}\nobserved trace:\n{}",
        fixture.seed,
        mismatches,
        serde_json::to_string_pretty(&observed_trace).expect("observed trace JSON"),
    );
}

#[tokio::test]
async fn welcome_before_commit_rejects_commit_echo_cleanly_via_harness() {
    // With the real Nostr outer group envelope, a newly invited member joins
    // via the NIP-59 welcome and cannot decrypt the pre-join group wrapper
    // around the invite commit. The important behavior is fail-closed stale
    // handling, not a hard ingest error.
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let (_gid, pending) = alice.create_group("wbc", vec![bob_kp], vec![]).await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;

    let carol_kp = carol.fresh_key_package().await;
    let invite_pending = alice.invite(vec![carol_kp]).await;
    alice.confirm(invite_pending).await;

    // Both arrive in the same delivery. Carol processes the welcome, then
    // treats the group-message echo as a stale peel failure because the
    // outer wrapper was encrypted for the pre-join epoch.
    bus.deliver_all();
    let outcomes = carol.tick().await;
    let saw_welcome = outcomes
        .iter()
        .any(|o| matches!(o, Ok(cgka_traits::ingest::IngestOutcome::Processed)));
    let saw_peel_failed = outcomes.iter().any(|o| {
        matches!(
            o,
            Ok(cgka_traits::ingest::IngestOutcome::Stale {
                reason: cgka_traits::ingest::StaleReason::PeelFailed,
            })
        )
    });
    assert!(
        saw_welcome,
        "expected welcome to be processed: {outcomes:?}"
    );
    assert!(saw_peel_failed, "expected stale peel failure: {outcomes:?}");
}
