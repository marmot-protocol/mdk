//! Canonical scripted scenarios driven through the harness bus.
//!
//! Each scenario corresponds to a Phase 6 task in the production refactor
//! plan. These are the tests the proptest layer (Phase 6.8-6.9) generalizes
//! into seeded random sequences.

use cgka_conformance::{
    ClientBuilder, ScenarioSpec, ScenarioStep, ScenarioTrace, TransportBus, VectorFixture,
    generate_send_leave_family, observe_client, run_generated_case_report, run_scenario_report,
    run_scenario_spec,
};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::GroupEvent;
use cgka_traits::types::MemberId;

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
    // Task 6.4 — the canonical smoke test.
    // Alice creates a group with Bob and Carol. Each sends one app message.
    // All three converge on epoch 1 and see all three messages.
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
                    removed_members: vec![],
                    recoveries: vec![],
                },
                cgka_conformance::ClientObservation {
                    client: "bob".into(),
                    epoch: 1,
                    member_count: 3,
                    received_payloads: vec!["alice:hello".into(), "carol:hello".into()],
                    removed_members: vec![],
                    recoveries: vec![],
                },
                cgka_conformance::ClientObservation {
                    client: "carol".into(),
                    epoch: 1,
                    member_count: 3,
                    received_payloads: vec!["alice:hello".into(), "bob:hello".into()],
                    removed_members: vec![],
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
async fn scenario_report_records_trace_log_recoveries_and_failures() {
    let fixture: VectorFixture =
        serde_json::from_str(include_str!("../vectors/deliberate-fork-recovery.v1.json"))
            .expect("fixture JSON parses");

    let report = run_scenario_report(&fixture.scenario, Some(fixture.expected_trace.clone()))
        .await
        .expect("scenario reports");

    assert_eq!(report.metadata.scenario_name, "deliberate-fork-recovery/v1");
    assert_eq!(report.metadata.step_count, fixture.scenario.steps.len());
    assert_eq!(report.expected_trace, Some(fixture.expected_trace.clone()));
    assert_eq!(report.observed_trace, Some(fixture.expected_trace));
    assert_eq!(report.step_log.len(), fixture.scenario.steps.len());
    assert!(
        report
            .step_log
            .iter()
            .all(|entry| entry.status.is_completed())
    );
    assert_eq!(report.recovery_observations.len(), 1);
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
    // Task 6.6 echo (post-§149) — alice creates with bob+carol; bob (non-
    // admin) leaves; alice (admin) auto-commits.
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
    // Task 6.7 — alice and bob each invite concurrently at the same epoch.
    // The bus partition keeps each side from seeing the other's commit
    // until both have committed locally. When the partition lifts and they
    // ingest each other's commit, fork recovery rolls both clients onto the
    // same deterministic winner.
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
            recoveries[0].winner.timestamp,
            recoveries[0].winner.message_id.as_str()
        ) < (
            recoveries[0].invalidated.timestamp,
            recoveries[0].invalidated.message_id.as_str()
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
async fn canonical_vector_fixtures_match_generated_traces() {
    let fixtures = [
        (
            "three-client-message-exchange.v1.json",
            include_str!("../vectors/three-client-message-exchange.v1.json"),
        ),
        (
            "deliberate-fork-recovery.v1.json",
            include_str!("../vectors/deliberate-fork-recovery.v1.json"),
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
    // Task 6.5 echo — invite commit arriving at a member who already
    // joined via welcome at the new epoch must classify as AlreadyAtEpoch,
    // not error.
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
