//! Canonical scripted scenarios driven through the harness bus.
//!
//! These tests cover named multi-client histories that are too important to
//! leave only to generated scenarios. The proptest layer generalizes the same
//! behavior into seeded random send/leave sequences.

use cgka_conformance::{
    AppInvalidationObservation, ClientBuilder, EpochChangeObservation, ScenarioSpec, ScenarioStep,
    ScenarioTrace, TransportBus, VectorFixture, generate_convergence_e2e_delivery_family,
    generate_send_leave_family, observe_client, run_generated_case_report, run_scenario_report,
    run_scenario_spec,
};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::openmls_projection::{OpenMlsContentKind, project_mls_message};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{AppMessageInvalidationReason, GroupEvent};
use cgka_traits::types::{EpochId, MemberId, MessageId};
use sha2::{Digest, Sha256};

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
    fn count_app_msgs(c: &mut cgka_conformance::HarnessClient) -> usize {
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
            observations: vec![
                cgka_conformance::ClientObservation {
                    client: "alice".into(),
                    epoch: 1,
                    member_count: 3,
                    received_payloads: vec!["bob:hello".into(), "carol:hello".into()],
                    added_members: vec![],
                    removed_members: vec![],
                    epoch_changes: vec![],
                    app_invalidations: vec![],
                    recoveries: vec![],
                },
                cgka_conformance::ClientObservation {
                    client: "bob".into(),
                    epoch: 1,
                    member_count: 3,
                    received_payloads: vec!["alice:hello".into(), "carol:hello".into()],
                    added_members: vec![],
                    removed_members: vec![],
                    epoch_changes: vec![],
                    app_invalidations: vec![],
                    recoveries: vec![],
                },
                cgka_conformance::ClientObservation {
                    client: "carol".into(),
                    epoch: 1,
                    member_count: 3,
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

        let expected = convergence_e2e_group_events_trace_named(&case.scenario.name);
        let report = run_generated_case_report(case, Some(expected.clone()))
            .await
            .expect("generated convergence variant reports");
        assert_eq!(report.observed_trace, Some(expected));
        assert!(report.invariant_failures.is_empty());
        assert_eq!(report.epoch_change_observations.len(), 2);
        assert_eq!(report.app_invalidation_observations.len(), 2);
        assert!(
            report
                .app_invalidation_observations
                .iter()
                .all(|observation| observation.reason == "losing_branch"
                    && observation.payload_ref == Some(payload_ref("bob losing payload")))
        );
    }
}

#[tokio::test]
async fn scenario_report_records_trace_log_recoveries_and_failures() {
    // Drives a fork-recovery scenario inline (rather than from a JSON
    // fixture) because fork-recovery traces are not currently byte-equal
    // across runs — see the comment in
    // `canonical_vector_fixtures_match_generated_traces`. The properties
    // verified here are about the report *machinery*, not specific trace
    // bytes: step_log length, exactly-one recovery, invariant_failures
    // empty, JSON serializability.
    let spec = ScenarioSpec {
        name: "deliberate-fork-recovery/v1".into(),
        spec_version: "1".into(),
        clients: vec!["alice".into(), "bob".into(), "david".into(), "eve".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "fork".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
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
    };

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
    assert!(
        (
            recovery.winner.source_epoch,
            recovery.winner.commit_digest.as_str(),
        ) < (
            recovery.invalidated.source_epoch,
            recovery.invalidated.commit_digest.as_str(),
        )
    );
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
    bob.tick().await; // ingests alice's commit
    carol.tick().await;

    assert_eq!(alice.epoch().0, 2);
    assert_eq!(alice.members().len(), 2);
    assert_eq!(bob.epoch().0, 2);
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
    let (group_id, pending) = alice.create_group("fork", vec![bob_kp], vec![]).await;
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
    assert_eq!(alice_members, bob_members);
    let trace = ScenarioTrace {
        name: "deliberate-fork-recovery/v1".into(),
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
    assert!(
        (
            recoveries[0].winner.source_epoch,
            recoveries[0].winner.commit_digest.as_str()
        ) < (
            recoveries[0].invalidated.source_epoch,
            recoveries[0].invalidated.commit_digest.as_str()
        )
    );
    let has_david = alice_members
        .iter()
        .any(|m| m.id == MemberId::new(pad32(b"david")));
    let has_eve = alice_members
        .iter()
        .any(|m| m.id == MemberId::new(pad32(b"eve")));
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
        .create_group("convergence-e2e", vec![bob_kp, carol_kp, frank_kp], vec![])
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

    let queued_messages = bus.queued_messages();
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
    let alice_commit_digest = project_mls_message(&commit_messages[0].payload)
        .expect("alice commit projects")
        .message_digest;
    let bob_commit_digest = project_mls_message(&commit_messages[1].payload)
        .expect("bob commit projects")
        .message_digest;
    let selected_index = if alice_commit_digest < bob_commit_digest {
        0
    } else {
        1
    };
    let expected_payload = if selected_index == 0 {
        b"alice branch payload".to_vec()
    } else {
        b"bob branch payload".to_vec()
    };
    let losing_payload = if selected_index == 0 {
        b"bob branch payload".to_vec()
    } else {
        b"alice branch payload".to_vec()
    };
    let expected_member = if selected_index == 0 {
        MemberId::new(pad32(b"david"))
    } else {
        MemberId::new(pad32(b"eve"))
    };
    let losing_member = if selected_index == 0 {
        MemberId::new(pad32(b"eve"))
    } else {
        MemberId::new(pad32(b"david"))
    };
    let losing_app_id = if selected_index == 0 {
        bob_app.id.clone()
    } else {
        alice_app.id.clone()
    };

    bus.deliver_all();
    let carol_outcomes = carol.tick().await;
    let frank_outcomes = frank.tick().await;
    assert_tick_reached_convergence("carol", &carol_outcomes);
    assert_tick_reached_convergence("frank", &frank_outcomes);

    assert_canonical_application_events(
        "carol",
        carol.drain_events(),
        expected_payload.clone(),
        losing_payload.clone(),
        losing_app_id.clone(),
    );
    assert_canonical_application_events(
        "frank",
        frank.drain_events(),
        expected_payload,
        losing_payload,
        losing_app_id,
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
    let expected = convergence_e2e_group_events_trace();

    let report = run_scenario_report(&spec, Some(expected.clone()))
        .await
        .expect("scenario reports");

    assert_eq!(report.observed_trace, Some(expected));
    assert!(report.invariant_failures.is_empty());
    assert_eq!(report.epoch_change_observations.len(), 2);
    assert_eq!(report.app_invalidation_observations.len(), 2);
    assert!(
        report
            .step_log
            .iter()
            .any(|entry| entry.step_type == "clear_events")
    );
    assert!(
        report
            .app_invalidation_observations
            .iter()
            .all(|observation| observation.reason == "losing_branch"
                && observation.payload_ref == Some(payload_ref("bob losing payload")))
    );
}

#[tokio::test]
async fn canonical_vector_fixtures_match_generated_traces() {
    // Fork-recovery vectors are deliberately absent: under content-derived
    // ordering (`CommitOrderingKey { source_epoch, commit_digest }`), the
    // SHA-256 of an OpenMLS commit varies run-to-run because commits include
    // fresh HPKE path randomness. Both the digest values and the side that
    // ends up rolling back are non-stable, so byte-equal trace comparison
    // does not work for fork-recovery scenarios. See
    // `docs/marmot-architecture/distributed-convergence.md` (Track A) for
    // the path forward.
    let fixtures = [
        (
            "three-client-message-exchange.v1.json",
            include_str!("../vectors/three-client-message-exchange.v1.json"),
        ),
        (
            "convergence-e2e-group-events.v1.json",
            include_str!("../vectors/convergence-e2e-group-events.v1.json"),
        ),
    ];

    for (fixture_name, contents) in fixtures {
        let fixture: VectorFixture = serde_json::from_str(contents).expect("fixture JSON parses");
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

fn convergence_e2e_group_events_trace() -> ScenarioTrace {
    convergence_e2e_group_events_trace_named("convergence-e2e-group-events/v1")
}

fn convergence_e2e_group_events_trace_named(name: &str) -> ScenarioTrace {
    let observation = |client: &str| cgka_conformance::ClientObservation {
        client: client.into(),
        epoch: 3,
        member_count: 6,
        received_payloads: vec!["alice canonical payload".into()],
        added_members: vec!["david".into(), "grace".into()],
        removed_members: vec![],
        epoch_changes: vec![EpochChangeObservation { from: 1, to: 3 }],
        app_invalidations: vec![AppInvalidationObservation {
            epoch: 2,
            reason: "losing_branch".into(),
            payload_ref: Some(payload_ref("bob losing payload")),
        }],
        recoveries: vec![],
    };
    ScenarioTrace {
        name: name.into(),
        observations: vec![observation("carol"), observation("frank")],
    }
}

fn payload_ref(payload: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(payload.as_bytes())))
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

fn assert_canonical_application_events(
    client: &str,
    events: Vec<GroupEvent>,
    expected_payload: Vec<u8>,
    losing_payload: Vec<u8>,
    losing_app_id: MessageId,
) {
    let received_payloads: Vec<Vec<u8>> = events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        received_payloads,
        vec![expected_payload],
        "{client} should receive exactly the canonical branch application payload"
    );
    assert!(
        !received_payloads.contains(&losing_payload),
        "{client} must not receive the losing branch payload as a normal app message"
    );
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                GroupEvent::AppMessageInvalidated {
                    message_id,
                    epoch: EpochId(2),
                    reason: AppMessageInvalidationReason::LosingBranch,
                    decrypted_payload_ref: Some(_),
                    ..
                } if *message_id == losing_app_id
            )
        }),
        "{client} should receive an invalidation event for the losing branch app message: {events:?}"
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
        fixture.scenario_name, fixture.expected_trace.name,
        "fixture {fixture_name} metadata scenario_name must match expected_trace.name"
    );
    assert_eq!(
        fixture.scenario_name, fixture.scenario.name,
        "fixture {fixture_name} metadata scenario_name must match scenario.name"
    );
    assert_eq!(
        fixture.expected_trace,
        observed_trace,
        "fixture {fixture_name} mismatch\nseed: {:?}\nexpected trace:\n{}\nobserved trace:\n{}",
        fixture.seed,
        serde_json::to_string_pretty(&fixture.expected_trace).expect("expected trace JSON"),
        serde_json::to_string_pretty(&observed_trace).expect("observed trace JSON"),
    );
}

#[tokio::test]
async fn welcome_before_commit_via_harness() {
    // An invite commit arriving at a member who already joined via welcome at
    // the new epoch must classify as AlreadyAtEpoch, not error.
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

    // Carol absorbs the welcome FIRST (before the commit reaches her bus
    // mailbox to ingest). Both arrive in the same delivery — but carol
    // joins via welcome and then the commit arrives in her mailbox in the
    // same tick. We force welcome-first by ticking twice on different
    // mailbox subsets — for the harness's current shape, just delivering
    // both works because the welcome arm is taken before the commit arm
    // in `tick`'s mailbox iteration order. The engine's
    // welcome_before_commit case (commit arriving second, after we're at
    // the new epoch) plays out: outcome must be Stale{AlreadyAtEpoch}.
    bus.deliver_all();
    let outcomes = carol.tick().await;
    let saw_already = outcomes.iter().any(|o| {
        matches!(
            o,
            Ok(cgka_traits::ingest::IngestOutcome::Stale {
                reason: cgka_traits::ingest::StaleReason::AlreadyAtEpoch { .. }
            })
        )
    });
    assert!(
        saw_already,
        "expected AlreadyAtEpoch in outcomes: {outcomes:?}"
    );
}
