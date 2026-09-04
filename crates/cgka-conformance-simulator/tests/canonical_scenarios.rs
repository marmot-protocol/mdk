//! Canonical scripted scenarios driven through the harness bus.
//!
//! These tests cover named multi-client histories that are too important to
//! leave only to generated scenarios. The proptest layer generalizes the same
//! behavior into seeded random send/leave sequences.

use cgka_conformance_simulator::{
    ClientBuilder, ConformanceCanonicalStateSnapshot, EpochChangeObservation,
    GeneratedScenarioCase, GeneratedScenarioInputV1, GeneratedSubjectKind, HarnessClient,
    HarnessStorageMode, PendingResolutionObservation, RelayHistoryCompletenessClaimV2,
    ScenarioInputDisposition, ScenarioInputKind, ScenarioInputLedgerEntry,
    ScenarioMessageSelectorV2, ScenarioReport, ScenarioSpec, ScenarioStep, ScenarioTrace,
    ScenarioTransportClass, SubjectOutboundOutcome, TraceExpectation, TransportBus, VectorFixture,
    compare_trace_expectations, compile_scenario, generate_admin_churn_family,
    generate_bounded_convergence_pressure_family, generate_convergence_chaos_family,
    generate_convergence_e2e_delivery_family, generate_send_leave_family, observe_client,
    observe_client_exact, run_generated_case_report, run_generated_case_report_with_storage_mode,
    run_scenario_report, run_scenario_report_with_outcomes,
    run_scenario_report_with_outcomes_and_storage_mode, run_scenario_spec,
    run_vector_fixture_report, run_vector_fixture_report_with_storage_mode,
};
use cgka_engine::ManualConvergenceClock;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::openmls_projection::{OpenMlsContentKind, project_mls_message};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{AppMessageInvalidationReason, GroupEvent};
use cgka_traits::group::ProtocolProfile;
use cgka_traits::ingest::IngestOutcome;
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

fn application_selector(sender: &str) -> ScenarioMessageSelectorV2 {
    ScenarioMessageSelectorV2 {
        sender: Some(sender.into()),
        class: Some(ScenarioTransportClass::Application),
        ..Default::default()
    }
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
async fn exact_oracle_matches_full_canonical_state_after_join() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice")).attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob")).attach(&bus);
    let bob_key_package = bob.fresh_key_package().await;

    let (_group_id, pending) = alice
        .create_group("exact-state", vec![bob_key_package], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;

    let alice_snapshot = alice.canonical_group_snapshot();
    let bob_snapshot = bob.canonical_group_snapshot();
    assert_eq!(alice_snapshot, bob_snapshot);
    assert_eq!(alice_snapshot.leaves.len(), 2);
    assert_eq!(alice_snapshot.sorted_member_identities_hex.len(), 2);
    assert_eq!(alice_snapshot.exporter_commitment_sha256.len(), 64);
    assert_eq!(alice_snapshot.group_context_sha256.len(), 64);

    let trace = ScenarioTrace {
        name: "exact-state-after-join/v1".into(),
        pending_resolutions: vec![],
        errors: vec![],
        admin_policies: vec![],
        decryptability_probes: vec![],
        observations: vec![
            observe_client_exact("alice", &mut alice),
            observe_client_exact("bob", &mut bob),
        ],
    };
    let failures = compare_trace_expectations(
        None,
        &[
            TraceExpectation::ClientsExactlyEquivalent {
                clients: vec!["alice".into(), "bob".into()],
            },
            TraceExpectation::NoPendingWork {
                clients: vec!["alice".into(), "bob".into()],
            },
        ],
        &trace,
    );
    assert!(failures.is_empty(), "unexpected failures: {failures:#?}");
}

#[tokio::test]
async fn exact_oracle_projects_terminal_disband_tombstone_across_restart() {
    let bus = TransportBus::ordered();
    let clock = ManualConvergenceClock::new(0, 10_000);
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .protocol_profile(ProtocolProfile::Current)
        .convergence_clock(std::sync::Arc::new(clock.clone()))
        .attach(&bus);
    let (_group_id, pending) = alice
        .create_group_with_admins_maybe_pending("terminal", vec![], vec![], vec![])
        .await;
    assert!(
        pending.is_none(),
        "current founding group is immediately live"
    );
    alice.drain_events();

    alice.request_disband().await.expect("request disband");
    alice
        .advance_convergence()
        .await
        .expect("prepare disband commit");
    let pending = alice.pending_publication_refs();
    assert_eq!(pending.len(), 1, "disband prepares one publication");
    alice.confirm(pending[0]).await;
    alice
        .advance_convergence()
        .await
        .expect("open disband collecting pass");
    clock.advance_ms(1_000);
    alice
        .advance_convergence()
        .await
        .expect("settle disband convergence at quiescence");
    assert!(
        matches!(
            alice.canonical_state_snapshot(),
            ConformanceCanonicalStateSnapshot::Disbanded(_)
        ),
        "disband must reach terminal state at the pinned quiescence boundary"
    );
    bus.deliver_all();

    let before_restart = alice.canonical_state_snapshot();
    let ConformanceCanonicalStateSnapshot::Disbanded(tombstone) = &before_restart else {
        panic!("expected terminal tombstone, got {before_restart:#?}");
    };
    assert_eq!(tombstone.epoch, 1);
    assert_eq!(tombstone.former_member_identities_hex.len(), 1);
    assert_eq!(tombstone.commit_digest_hex.len(), 64);

    let trace = ScenarioTrace {
        name: "exact-disband-tombstone".into(),
        pending_resolutions: vec![],
        errors: vec![],
        admin_policies: vec![],
        decryptability_probes: vec![],
        observations: vec![observe_client_exact("alice", &mut alice)],
    };
    let failures = compare_trace_expectations(
        None,
        &[
            TraceExpectation::ClientsExactlyEquivalent {
                clients: vec!["alice".into()],
            },
            TraceExpectation::NoPendingWork {
                clients: vec!["alice".into()],
            },
        ],
        &trace,
    );
    assert!(failures.is_empty(), "unexpected failures: {failures:#?}");

    alice.restart();
    assert_eq!(alice.canonical_state_snapshot(), before_restart);
}

/// A convergence pass that is open when the device crashes must survive the
/// reopen, keep pinning the tip while a backlog piles up behind it, and then
/// walk the device all the way to the group tip.
///
/// This is the scenario-level companion to the engine's
/// `stale_pass_base_epoch_reopens_at_the_current_tip_instead_of_halting` family
/// (mdk#1182, over the durable passes mdk#1110 added). The field incident was a
/// durable pass whose `base_epoch` disagreed with the live tip, which durably
/// halted the group.
/// Those engine tests install the disagreement on the durable record directly,
/// because the engine keeps a single tip authority and an active pass gates every
/// path that could move it. This scenario pins that precondition from the public
/// boundary instead: carol holds an open pass at epoch 1 across a crash/reopen and
/// a three-commit backlog burst without her tip ever drifting off the base, so the
/// disagreement the incident needed never arises, and she still reaches exact
/// equivalence with alice.
///
/// The timing is load-bearing evidence that the *same* durable pass survived the
/// crash rather than a fresh one reopening afterwards. The pass opens at virtual
/// time 0 with a 1000ms quiescence deadline; the restart happens at 700ms, the
/// backlog arrives while the reopened engine holds the pass, and the settle tick
/// at exactly 1000ms clears the original deadline. A pass reopened after the
/// restart would carry a later deadline and leave carol behind at epoch 1, which
/// the pinned epoch walk rejects.
///
/// The subject adapter's `structural_wake_rebases_across_restart_without_granting_fresh_time`
/// already covers the deadline-rebase half of this on a lone client with an empty
/// group. This scenario is the version that matters for the incident: the deadline has
/// to survive a *backlog* landing on the reopened engine, which is the pressure
/// that could plausibly re-derive it.
///
/// Deliberately does not use `ScenarioStep::AwaitQuiescence`. That step drives
/// virtual time to a fixed point, which settles the recovered pass whenever it
/// happens to come due and so erases the exact-deadline evidence — with it
/// appended, shortening the settle tick to 900ms still passes. The manual
/// `AdvanceTime`/`Tick` walk is what makes the timing falsifiable.
#[tokio::test]
async fn open_convergence_pass_survives_restart_and_walks_the_backlog_to_the_tip() {
    let update = |name: &str, pending: &str| ScenarioStep::UpdateGroupData {
        client: "alice".into(),
        name: name.into(),
        pending: pending.into(),
    };
    let confirm = |pending: &str| ScenarioStep::accept_publication("alice", pending);
    let tick_carol = || ScenarioStep::Tick {
        clients: vec!["carol".into()],
    };
    let both = || vec!["alice".to_owned(), "carol".to_owned()];

    let spec = ScenarioSpec {
        name: "open-pass-restart-catchup/v1".into(),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: both(),
        steps: vec![
            // 0-4: alice and carol settle at epoch 1.
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "open-pass-restart-catchup".into(),
                invitees: vec!["carol".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            confirm("create"),
            ScenarioStep::DeliverAll,
            tick_carol(),
            ScenarioStep::ClearEvents { clients: both() },
            // 5: take the scenario onto virtual time so a pass can stay open
            // between ticks instead of settling through the far-future shortcut.
            ScenarioStep::AdvanceTime { delta_ms: 0 },
            // 6-9: one inbound commit edge opens carol's pass at base epoch 1.
            update("backlog-2", "u2"),
            confirm("u2"),
            ScenarioStep::DeliverAll,
            tick_carol(),
            // 10-12: crash and reopen 300ms short of the pass cutoff.
            ScenarioStep::AdvanceTime { delta_ms: 700 },
            tick_carol(),
            ScenarioStep::RestartClient {
                client: "carol".into(),
            },
            // 13-20: three more commits land on the reopened engine while the
            // recovered pass still holds the boundary.
            update("backlog-3", "u3"),
            confirm("u3"),
            update("backlog-4", "u4"),
            confirm("u4"),
            update("backlog-5", "u5"),
            confirm("u5"),
            ScenarioStep::DeliverAll,
            tick_carol(),
            // 21: alice is four epochs ahead; carol is still pinned to her base.
            ScenarioStep::Observe { clients: both() },
            // 22-29: the recovered pass settles on its original deadline, then
            // one generation per quiescence window walks carol to the tip.
            ScenarioStep::AdvanceTime { delta_ms: 300 },
            tick_carol(),
            ScenarioStep::AdvanceTime { delta_ms: 1_000 },
            tick_carol(),
            ScenarioStep::AdvanceTime { delta_ms: 1_000 },
            tick_carol(),
            ScenarioStep::AdvanceTime { delta_ms: 1_000 },
            tick_carol(),
            // 30-32: drain both runtimes and compare exact canonical state.
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick { clients: both() },
            ScenarioStep::ObserveExact { clients: both() },
        ],
    };

    let epoch_walk = |from: u64| EpochChangeObservation { from, to: from + 1 };
    let report = run_scenario_report_with_outcomes_and_storage_mode(
        &spec,
        None,
        vec![
            TraceExpectation::PendingResolution {
                step_index: 1,
                client: "alice".into(),
                pending: "create".into(),
                resolution: "confirmed".into(),
            },
            TraceExpectation::PendingResolution {
                step_index: 7,
                client: "alice".into(),
                pending: "u2".into(),
                resolution: "confirmed".into(),
            },
            TraceExpectation::PendingResolution {
                step_index: 18,
                client: "alice".into(),
                pending: "u5".into(),
                resolution: "confirmed".into(),
            },
            // Step 21, mid-history: the backlog burst never moved carol's tip
            // off the open pass's base epoch, across the crash and reopen.
            TraceExpectation::ClientState {
                client: "carol".into(),
                epoch: 1,
                member_count: 2,
                received_payloads: None,
                added_members: None,
                removed_members: None,
            },
            TraceExpectation::ClientState {
                client: "alice".into(),
                epoch: 5,
                member_count: 2,
                received_payloads: None,
                added_members: None,
                removed_members: None,
            },
            // Step 32: carol catches up one generation per pass, with no skipped
            // epoch and no halt.
            TraceExpectation::ClientEpochChanges {
                client: "carol".into(),
                changes: vec![epoch_walk(1), epoch_walk(2), epoch_walk(3), epoch_walk(4)],
            },
            TraceExpectation::ClientsExactlyEquivalent { clients: both() },
            TraceExpectation::NoPendingWork { clients: both() },
        ],
        // A real close-and-reopen of the encrypted database, not just a rebuilt
        // engine over a live handle.
        HarnessStorageMode::TempFileBackedSqlite,
    )
    .await
    .expect("run open-pass restart catch-up scenario");

    assert!(
        report.expectation_failures.is_empty(),
        "unexpected failures: {:#?}",
        report.expectation_failures
    );
    assert!(
        report.invariant_failures.is_empty(),
        "unexpected invariant failures: {:#?}",
        report.invariant_failures
    );
}

#[tokio::test]
async fn bidirectional_decryptability_probe_passes_for_settled_members() {
    let spec = ScenarioSpec {
        name: "bidirectional-decryptability/settled".into(),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: vec!["alice".into(), "bob".into(), "carol".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "decryptability".into(),
                invitees: vec!["bob".into(), "carol".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::accept_publication("alice", "create"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into(), "carol".into()],
            },
            ScenarioStep::ProbeBidirectionalDecryptability {
                clients: vec!["alice".into(), "bob".into(), "carol".into()],
            },
            ScenarioStep::ObserveExact {
                clients: vec!["alice".into(), "bob".into(), "carol".into()],
            },
        ],
    };
    let report = run_scenario_report_with_outcomes(
        &spec,
        None,
        vec![
            TraceExpectation::ClientsExactlyEquivalent {
                clients: vec!["alice".into(), "bob".into(), "carol".into()],
            },
            TraceExpectation::ClientsBidirectionallyDecryptable {
                clients: vec!["alice".into(), "bob".into(), "carol".into()],
            },
            TraceExpectation::NoPendingWork {
                clients: vec!["alice".into(), "bob".into(), "carol".into()],
            },
        ],
    )
    .await
    .expect("run settled decryptability probe");

    assert!(
        report.expectation_failures.is_empty(),
        "unexpected failures: {:#?}",
        report.expectation_failures
    );
    let probe = &report
        .observed_trace
        .as_ref()
        .expect("trace")
        .decryptability_probes[0];
    assert!(probe.succeeded());
    assert_eq!(probe.probes.len(), 6);
}

#[tokio::test]
async fn bidirectional_decryptability_probe_exposes_asymmetric_epoch_reachability() {
    let spec = ScenarioSpec {
        name: "bidirectional-decryptability/asymmetric-epoch".into(),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: vec!["alice".into(), "bob".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "decryptability".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::accept_publication("alice", "create"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::UpdateGroupData {
                client: "alice".into(),
                name: "advanced-without-bob".into(),
                pending: "advance".into(),
            },
            ScenarioStep::accept_publication("alice", "advance"),
            ScenarioStep::OmitMessage {
                selector: ScenarioMessageSelectorV2 {
                    publication: Some("advance".into()),
                    class: Some(ScenarioTransportClass::Commit),
                    ..Default::default()
                },
            },
            ScenarioStep::ProbeBidirectionalDecryptability {
                clients: vec!["alice".into(), "bob".into()],
            },
        ],
    };
    let report = run_scenario_report_with_outcomes(
        &spec,
        None,
        vec![TraceExpectation::ClientsBidirectionallyDecryptable {
            clients: vec!["alice".into(), "bob".into()],
        }],
    )
    .await
    .expect("run asymmetric decryptability probe");

    assert_eq!(report.expectation_failures.len(), 1);
    assert_eq!(
        report.expectation_failures[0].kind,
        "bidirectional_decryptability_failed"
    );
    let probe = &report
        .observed_trace
        .as_ref()
        .expect("trace")
        .decryptability_probes[0];
    let alice_to_bob = probe
        .probes
        .iter()
        .find(|edge| edge.sender == "alice" && edge.recipient == "bob")
        .expect("alice to bob edge");
    assert!(!alice_to_bob.succeeded());
    assert_eq!(
        alice_to_bob
            .recipient_ledger
            .as_ref()
            .expect("deferred ledger")
            .transport_deferred,
        1
    );
    assert!(
        probe
            .probes
            .iter()
            .find(|edge| edge.sender == "bob" && edge.recipient == "alice")
            .expect("bob to alice edge")
            .succeeded()
    );
}

#[tokio::test]
async fn bidirectional_decryptability_probe_rejects_a_named_nonmember() {
    let spec = ScenarioSpec {
        name: "bidirectional-decryptability/nonmember".into(),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: vec!["alice".into(), "bob".into(), "carol".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "decryptability".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::accept_publication("alice", "create"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::ProbeBidirectionalDecryptability {
                clients: vec!["alice".into(), "bob".into(), "carol".into()],
            },
        ],
    };
    let report = run_scenario_report_with_outcomes(
        &spec,
        None,
        vec![TraceExpectation::ClientsBidirectionallyDecryptable {
            clients: vec!["alice".into(), "bob".into(), "carol".into()],
        }],
    )
    .await
    .expect("run nonmember decryptability probe");

    assert_eq!(report.expectation_failures.len(), 1);
    let probe = &report
        .observed_trace
        .as_ref()
        .expect("trace")
        .decryptability_probes[0];
    assert!(!probe.succeeded());
    assert!(probe.probes.iter().any(|edge| {
        edge.sender == "carol"
            && matches!(
                edge.send_status,
                cgka_conformance_simulator::DecryptabilityProbeSendStatus::Failed { .. }
            )
    }));
}

#[tokio::test]
async fn no_pending_work_rejects_delayed_transport_then_accepts_drained_delivery() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice")).attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob")).attach(&bus);
    let bob_key_package = bob.fresh_key_package().await;

    let (_group_id, pending) = alice
        .create_group("pending-delayed", vec![bob_key_package], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    alice.drain_events();
    bob.drain_events();

    bob.send_app(b"held".to_vec()).await;
    assert!(bus.delay_queued(0, "held-message"));
    let held_trace = ScenarioTrace {
        name: "pending-delayed/held".into(),
        pending_resolutions: vec![],
        errors: vec![],
        admin_policies: vec![],
        decryptability_probes: vec![],
        observations: vec![observe_client_exact("alice", &mut alice)],
    };
    let failures = compare_trace_expectations(
        None,
        &[TraceExpectation::NoPendingWork {
            clients: vec!["alice".into()],
        }],
        &held_trace,
    );
    assert_eq!(failures.len(), 1, "expected delayed blocker: {failures:#?}");
    assert_eq!(failures[0].kind, "pending_work_remaining");
    assert!(
        failures[0].message.contains("bus_delayed"),
        "delayed subsystem should be named: {failures:#?}"
    );

    assert!(bus.release_delayed("held-message"));
    bus.deliver_all();
    alice.tick().await;
    let drained_trace = ScenarioTrace {
        name: "pending-delayed/drained".into(),
        pending_resolutions: vec![],
        errors: vec![],
        admin_policies: vec![],
        decryptability_probes: vec![],
        observations: vec![observe_client_exact("alice", &mut alice)],
    };
    let failures = compare_trace_expectations(
        None,
        &[TraceExpectation::NoPendingWork {
            clients: vec!["alice".into()],
        }],
        &drained_trace,
    );
    assert!(
        failures.is_empty(),
        "unexpected pending work: {failures:#?}"
    );
}

#[tokio::test]
async fn no_pending_work_rejects_bus_queue_and_unread_mailbox() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice")).attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob")).attach(&bus);
    let bob_key_package = bob.fresh_key_package().await;

    let (_group_id, pending) = alice
        .create_group("pending-bus", vec![bob_key_package], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    alice.drain_events();
    bob.drain_events();

    bob.send_app(b"queued".to_vec()).await;
    let queued_for_alice = observe_client_exact("alice", &mut alice);
    assert_eq!(
        queued_for_alice
            .pending_work
            .as_ref()
            .expect("exact pending snapshot")
            .bus_queued_messages,
        1
    );
    let sender_does_not_own_queued_delivery = observe_client_exact("bob", &mut bob);
    assert_eq!(
        sender_does_not_own_queued_delivery
            .pending_work
            .as_ref()
            .expect("exact pending snapshot")
            .bus_queued_messages,
        0
    );

    bus.deliver_all();
    let unread_for_alice = observe_client_exact("alice", &mut alice);
    assert_eq!(
        unread_for_alice
            .pending_work
            .as_ref()
            .expect("exact pending snapshot")
            .bus_mailbox_messages,
        1
    );
    let sender_mailbox_remains_empty = observe_client_exact("bob", &mut bob);
    assert_eq!(
        sender_mailbox_remains_empty
            .pending_work
            .as_ref()
            .expect("exact pending snapshot")
            .bus_mailbox_messages,
        0
    );

    alice.tick().await;
    let drained = observe_client_exact("alice", &mut alice);
    assert!(
        drained
            .pending_work
            .as_ref()
            .expect("exact pending snapshot")
            .is_empty(),
        "all transport and engine work should be drained: {drained:#?}"
    );
}

#[tokio::test]
async fn no_pending_work_does_not_claim_delivery_of_dropped_application_input() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice")).attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob")).attach(&bus);
    let bob_key_package = bob.fresh_key_package().await;

    let (_group_id, pending) = alice
        .create_group("dropped-is-not-pending", vec![bob_key_package], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    alice.drain_events();
    bob.drain_events();

    alice.send_app(b"intentionally-dropped".to_vec()).await;
    assert!(bus.drop_queued(0), "drop the application transport object");

    let alice_observation = observe_client_exact("alice", &mut alice);
    let bob_observation = observe_client_exact("bob", &mut bob);
    let sender_entry = alice_observation
        .scenario_input_ledger
        .iter()
        .find(|entry| entry.payload == "intentionally-dropped")
        .expect("sender records the published application input");
    assert_eq!(
        sender_entry.disposition,
        ScenarioInputDisposition::Accepted,
        "sender acceptance is not an end-to-end delivery claim"
    );
    assert!(
        bob_observation.scenario_input_ledger.is_empty(),
        "a recipient cannot classify an object the scenario removed before delivery"
    );

    let trace = ScenarioTrace {
        name: "dropped-is-not-pending".into(),
        pending_resolutions: vec![],
        errors: vec![],
        admin_policies: vec![],
        decryptability_probes: vec![],
        observations: vec![alice_observation, bob_observation],
    };
    let no_pending_failures = compare_trace_expectations(
        None,
        &[TraceExpectation::NoPendingWork {
            clients: vec!["alice".into(), "bob".into()],
        }],
        &trace,
    );
    assert!(
        no_pending_failures.is_empty(),
        "NoPendingWork is local execution quiescence, not transport completeness: \
         {no_pending_failures:#?}"
    );

    let delivery_failures = compare_trace_expectations(
        None,
        &[TraceExpectation::ClientState {
            client: "bob".into(),
            epoch: 1,
            member_count: 2,
            received_payloads: Some(vec!["intentionally-dropped".into()]),
            added_members: None,
            removed_members: None,
        }],
        &trace,
    );
    assert_eq!(
        delivery_failures.len(),
        1,
        "delivery must be asserted independently from local quiescence"
    );
}

#[tokio::test]
async fn no_pending_work_rejects_unconfirmed_publish() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice")).attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob")).attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol")).attach(&bus);
    let bob_key_package = bob.fresh_key_package().await;

    let (_group_id, pending) = alice
        .create_group("pending-publish", vec![bob_key_package], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    alice.drain_events();
    bob.drain_events();

    let pending_invite = alice.invite(vec![carol.fresh_key_package().await]).await;
    let observation = observe_client_exact("alice", &mut alice);
    assert_eq!(
        observation
            .pending_work
            .as_ref()
            .expect("exact pending snapshot")
            .engine
            .non_stable_epoch_state,
        1
    );
    let trace = ScenarioTrace {
        name: "pending-publish/unconfirmed".into(),
        pending_resolutions: vec![],
        errors: vec![],
        admin_policies: vec![],
        decryptability_probes: vec![],
        observations: vec![observation],
    };
    let failures = compare_trace_expectations(
        None,
        &[TraceExpectation::NoPendingWork {
            clients: vec!["alice".into()],
        }],
        &trace,
    );
    assert_eq!(failures.len(), 1, "expected publish blocker: {failures:#?}");
    assert!(
        failures[0].message.contains("engine"),
        "engine subsystem should be named: {failures:#?}"
    );

    alice.fail(pending_invite).await;
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
        outcomes
            .iter()
            .all(|outcome| { !matches!(outcome, Ok(IngestOutcome::TransportDeferred { .. })) }),
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
        decryptability_probes: vec![],
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
            decryptability_probes: vec![],
            observations: vec![
                cgka_conformance_simulator::ClientObservation {
                    client: "alice".into(),
                    epoch: 1,
                    member_count: 3,
                    group_name: "vector-smoke".into(),
                    group_description: String::new(),
                    canonical_state: None,
                    scenario_input_ledger: vec![],
                    pending_work: None,
                    event_counts: cgka_conformance_simulator::ClientEventCounts {
                        message_received: 2,
                        ..Default::default()
                    },
                    received_payloads: vec!["bob:hello".into(), "carol:hello".into()],
                    added_members: vec![],
                    removed_members: vec![],
                    epoch_changes: vec![],
                    app_invalidations: vec![],
                    convergence_decisions: vec![],
                },
                cgka_conformance_simulator::ClientObservation {
                    client: "bob".into(),
                    epoch: 1,
                    member_count: 3,
                    group_name: "vector-smoke".into(),
                    group_description: String::new(),
                    canonical_state: None,
                    scenario_input_ledger: vec![],
                    pending_work: None,
                    event_counts: cgka_conformance_simulator::ClientEventCounts {
                        message_received: 2,
                        ..Default::default()
                    },
                    received_payloads: vec!["alice:hello".into(), "carol:hello".into()],
                    added_members: vec![],
                    removed_members: vec![],
                    epoch_changes: vec![],
                    app_invalidations: vec![],
                    convergence_decisions: vec![],
                },
                cgka_conformance_simulator::ClientObservation {
                    client: "carol".into(),
                    epoch: 1,
                    member_count: 3,
                    group_name: "vector-smoke".into(),
                    group_description: String::new(),
                    canonical_state: None,
                    scenario_input_ledger: vec![],
                    pending_work: None,
                    event_counts: cgka_conformance_simulator::ClientEventCounts {
                        message_received: 2,
                        ..Default::default()
                    },
                    received_payloads: vec!["alice:hello".into(), "bob:hello".into()],
                    added_members: vec![],
                    removed_members: vec![],
                    epoch_changes: vec![],
                    app_invalidations: vec![],
                    convergence_decisions: vec![],
                },
            ],
        }
    );
}

#[tokio::test]
async fn scenario_spec_runs_three_client_message_exchange() {
    let spec = ScenarioSpec {
        name: "three-client-message-exchange/v1".into(),
        spec_version: "2".into(),
        topology: Default::default(),
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
            ScenarioStep::accept_publication("alice", "create"),
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
        spec_version: "2".into(),
        topology: Default::default(),
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
            ScenarioStep::fail_publication("alice", "create"),
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
async fn definite_publish_failure_retracts_commit_before_local_rollback() {
    let spec = ScenarioSpec {
        name: "transported-commit-after-local-rollback/minimal/v1".into(),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: vec!["alice".into(), "bob".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "before".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::accept_publication("alice", "create"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::UpdateGroupData {
                client: "alice".into(),
                name: "after".into(),
                pending: "update".into(),
            },
            ScenarioStep::fail_publication("alice", "update"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::ObserveExact {
                clients: vec!["alice".into(), "bob".into()],
            },
        ],
    };

    let report = run_scenario_report_with_outcomes(
        &spec,
        None,
        vec![
            TraceExpectation::PendingResolution {
                step_index: 1,
                client: "alice".into(),
                pending: "create".into(),
                resolution: "confirmed".into(),
            },
            TraceExpectation::PendingResolution {
                step_index: 5,
                client: "alice".into(),
                pending: "update".into(),
                resolution: "rolled_back".into(),
            },
            TraceExpectation::ClientsExactlyEquivalent {
                clients: vec!["alice".into(), "bob".into()],
            },
            TraceExpectation::NoPendingWork {
                clients: vec!["alice".into(), "bob".into()],
            },
        ],
    )
    .await
    .expect("definite-failure scenario reports");

    assert!(
        report.expectation_failures.is_empty(),
        "definite failure must leave no transported commit: {:?}",
        report.expectation_failures
    );
    let trace = report.observed_trace.as_ref().expect("observed trace");
    assert!(
        trace
            .observations
            .iter()
            .all(|observation| observation.epoch == 1),
        "both clients must remain at the pre-publish epoch"
    );
    let bob = trace
        .observations
        .iter()
        .find(|observation| observation.client == "bob")
        .expect("bob observation");
    assert!(
        bob.scenario_input_ledger.is_empty(),
        "bob must never observe the retracted commit"
    );
}

#[tokio::test]
async fn definite_publish_failure_retracts_commit_and_welcome() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice")).attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob")).attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"carol")).attach(&bus);
    let (_group_id, create_pending) = alice
        .create_group(
            "retract-invite-artifacts",
            vec![bob.fresh_key_package().await],
            vec![],
        )
        .await;
    alice.confirm(create_pending).await;
    bus.deliver_all();
    bob.tick().await;

    let invite_pending = alice.invite(vec![carol.fresh_key_package().await]).await;
    assert_eq!(bus.queued_len(), 2, "invite commit and Welcome are queued");
    assert!(
        bus.delay_queued(0, "pending-welcome"),
        "hold the Welcome in the delayed set"
    );
    alice.fail(invite_pending).await;
    assert_eq!(
        bus.queued_len(),
        0,
        "definite failure must retract the complete publication"
    );
    assert!(
        !bus.release_delayed("pending-welcome"),
        "definite failure must retract delayed publication artifacts too"
    );
    bus.deliver_all();
    carol.tick().await;
    assert_eq!(alice.epoch(), EpochId(1));
    assert_eq!(alice.members().len(), 2);
}

#[tokio::test]
async fn publication_failure_rejects_artifact_that_already_reached_a_recipient() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice")).attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob")).attach(&bus);
    let (_group_id, create_pending) = alice
        .create_group(
            "ambiguous-exposure-guard",
            vec![bob.fresh_key_package().await],
            vec![],
        )
        .await;
    alice.confirm(create_pending).await;
    bus.deliver_all();
    bob.tick().await;

    let pending = alice.update_group_data("after").await;
    bus.deliver_all();
    bob.tick().await;
    let error = alice
        .try_fail(pending)
        .await
        .expect_err("mailbox exposure is not a definite failure");
    assert!(
        error.to_string().contains("reached a recipient mailbox"),
        "unexpected error: {error}"
    );

    alice.confirm(pending).await;
    assert_eq!(alice.epoch(), EpochId(2));
    assert_eq!(bob.epoch(), EpochId(2));
    assert_eq!(alice.group_name(), "after");
    assert_eq!(bob.group_name(), "after");
}

#[tokio::test]
async fn scenario_spec_supports_leave_and_clear_partition() {
    let spec = ScenarioSpec {
        name: "leave-and-clear-partition/v1".into(),
        spec_version: "2".into(),
        topology: Default::default(),
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
            ScenarioStep::accept_publication("alice", "create"),
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
async fn scenario_spec_can_omit_semantically_selected_message() {
    let spec = ScenarioSpec {
        name: "drop-queued/v1".into(),
        spec_version: "2".into(),
        topology: Default::default(),
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
            ScenarioStep::accept_publication("alice", "create"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: "bob:dropped".into(),
            },
            ScenarioStep::OmitMessage {
                selector: application_selector("bob"),
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
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn scenario_spec_can_duplicate_withhold_and_reorder_selected_messages() {
    let spec = ScenarioSpec {
        name: "queue-faults/v1".into(),
        spec_version: "2".into(),
        topology: Default::default(),
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
            ScenarioStep::accept_publication("alice", "create"),
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
            ScenarioStep::DuplicateMessage {
                selector: application_selector("bob"),
            },
            ScenarioStep::WithholdMessage {
                selector: ScenarioMessageSelectorV2 {
                    occurrence: 1,
                    ..application_selector("bob")
                },
                label: "delayed-copy".into(),
            },
            ScenarioStep::ReorderMessages {
                order: vec![application_selector("carol"), application_selector("bob")],
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            ScenarioStep::ReleaseWithheld {
                label: "delayed-copy".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            ScenarioStep::ObserveExact {
                clients: vec!["alice".into()],
            },
        ],
    };

    let trace = run_scenario_spec(&spec).await.expect("scenario runs");

    assert_eq!(
        trace.observations[0].received_payloads,
        vec!["carol:second", "bob:first"]
    );
    let bob_message = trace.observations[0]
        .scenario_input_ledger
        .iter()
        .find(|entry| entry.payload == "bob:first")
        .expect("bob's logical message is tracked");
    assert_eq!(bob_message.ingest_attempts, 2);
    assert_eq!(bob_message.ingest_accepted, 1);
    assert_eq!(bob_message.delivered, 1);
    assert_eq!(bob_message.deduplicated, 1);
    assert!(!bob_message.pending);
}

#[tokio::test]
async fn exact_observation_ledgers_commit_proposal_and_application_dispositions() {
    let spec = ScenarioSpec {
        name: "generalized-scenario-input-ledger/v1".into(),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: vec!["alice".into(), "bob".into()],
        steps: vec![
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "ledger".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: None,
                pending: "create".into(),
            },
            ScenarioStep::accept_publication("alice", "create"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::UpdateGroupData {
                client: "alice".into(),
                name: "ledger-updated".into(),
                pending: "rename".into(),
            },
            ScenarioStep::accept_publication("alice", "rename"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::SendAppMessage {
                sender: "alice".into(),
                payload: "ledger-message".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::Leave {
                client: "bob".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            ScenarioStep::ObserveExact {
                clients: vec!["alice".into()],
            },
        ],
    };

    let trace = run_scenario_spec(&spec).await.expect("scenario runs");
    let ledger = &trace.observations[0].scenario_input_ledger;

    let commit = ledger
        .iter()
        .find(|entry| entry.scenario_id == "step-4:update_group_data")
        .expect("named commit input");
    assert_eq!(commit.kind, ScenarioInputKind::Commit);
    assert_eq!(commit.disposition, ScenarioInputDisposition::Accepted);

    let application = ledger
        .iter()
        .find(|entry| entry.scenario_id == "step-8:send_app_message")
        .expect("named application input");
    assert_eq!(application.kind, ScenarioInputKind::Application);
    assert_eq!(application.payload, "ledger-message");
    assert_eq!(application.disposition, ScenarioInputDisposition::Accepted);

    let proposal = ledger
        .iter()
        .find(|entry| entry.scenario_id == "step-11:leave")
        .expect("named proposal input");
    assert_eq!(proposal.kind, ScenarioInputKind::Proposal);
    assert!(
        matches!(
            proposal.disposition,
            ScenarioInputDisposition::Pending
                | ScenarioInputDisposition::Deferred
                | ScenarioInputDisposition::Accepted
        ),
        "the ledger must expose the proposal's current durable disposition: {proposal:?}"
    );
}

#[tokio::test]
async fn send_leave_family_records_seed_and_runs_generated_cases() {
    let cases = generate_send_leave_family(42, 3);

    assert_eq!(cases, generate_send_leave_family(42, 3));
    assert_eq!(cases.len(), 3);
    for (case_index, case) in cases.iter().enumerate() {
        assert_eq!(case.family_name, "send-leave/v1");
        assert_eq!(case.generator_version, "2");
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
    assert_eq!(json["generator_version"], "2");

    for case in cases {
        assert!(
            case.scenario
                .steps
                .iter()
                .any(|step| matches!(step, ScenarioStep::ObserveExact { .. }))
        );
        assert!(case.expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::ClientsExactlyEquivalent { .. }
        )));
        assert!(
            case.expected_outcomes
                .iter()
                .any(|expectation| matches!(expectation, TraceExpectation::NoPendingWork { .. }))
        );
        let report = run_generated_case_report(&case, None)
            .await
            .expect("strict send/leave case report runs");
        assert!(
            report.expectation_failures.is_empty(),
            "send/leave case {} failed strict expectations: {:?}",
            case.case_index,
            report.expectation_failures
        );
    }
}

/// The bounded convergence-pressure campaign generates a deterministic,
/// schedule-legal case per seed index, and every case carries the full shape
/// the campaign is defined by: a same-epoch commit race, application sends
/// issued inside the quiescence window, a committer restart taken
/// mid-resolution, a finite self-update/profile/admin tail, a bounded-queue
/// resource assertion, and an active decryptability probe placed before the
/// terminal `observe_exact`.
#[test]
fn bounded_convergence_pressure_family_generates_the_declared_campaign_shape() {
    let cases = generate_bounded_convergence_pressure_family(2026, 6);

    assert_eq!(cases, generate_bounded_convergence_pressure_family(2026, 6));
    assert_eq!(cases.len(), 6);
    for (case_index, case) in cases.iter().enumerate() {
        assert_eq!(case.family_name, "bounded-convergence-pressure/v1");
        assert_eq!(case.generator_version, "2");
        assert_eq!(case.seed, 2026);
        assert_eq!(case.case_index, case_index as u64);
        compile_scenario(&case.scenario)
            .unwrap_or_else(|error| panic!("{}: {error}", case.scenario.name));
    }

    for case in &cases {
        let steps = &case.scenario.steps;
        let position = |predicate: fn(&ScenarioStep) -> bool| {
            steps.iter().position(predicate).unwrap_or_else(|| {
                panic!("{} is missing a required campaign step", case.scenario.name)
            })
        };

        // A same-epoch rival race, both branches withheld until release.
        assert_eq!(
            steps
                .iter()
                .filter(|step| matches!(step, ScenarioStep::WithholdMessage { .. }))
                .count(),
            2,
            "{} must withhold both rival commits",
            case.scenario.name
        );
        // Application sends land after the rival branch is ingested, so they sit
        // inside the quiescence window the committers wait out.
        let window_open = position(|step| matches!(step, ScenarioStep::ReleaseWithheld { .. }));
        let first_send = position(|step| matches!(step, ScenarioStep::SendAppMessage { .. }));
        let restart = position(|step| matches!(step, ScenarioStep::RestartClient { .. }));
        assert!(
            window_open < first_send && first_send < restart,
            "{}: sends must open inside the window and precede the mid-resolution restart",
            case.scenario.name
        );
        // Finite pressure, never an unbounded stream.
        assert_eq!(
            steps
                .iter()
                .filter(|step| matches!(step, ScenarioStep::SelfUpdate { .. }))
                .count(),
            3,
            "{} must apply exactly the finite self-update budget",
            case.scenario.name
        );
        assert!(
            steps
                .iter()
                .any(|step| matches!(step, ScenarioStep::UpdateAdminPolicy { .. })),
            "{} must apply an admin-policy commit",
            case.scenario.name
        );
        // Bounded queue behavior, and the bounded-time claim carried by the
        // quiescence driver's own watchdog budget.
        assert!(
            steps
                .iter()
                .any(|step| matches!(step, ScenarioStep::Assert { .. })),
            "{} must bound the pending-input queue",
            case.scenario.name
        );
        assert!(
            steps
                .iter()
                .any(|step| matches!(step, ScenarioStep::AwaitQuiescence { .. })),
            "{} must settle through the bounded quiescence driver",
            case.scenario.name
        );
        // The probe mutates, so it must precede the terminal exact observation.
        let probe =
            position(|step| matches!(step, ScenarioStep::ProbeBidirectionalDecryptability { .. }));
        let observe_exact = steps
            .iter()
            .rposition(|step| matches!(step, ScenarioStep::ObserveExact { .. }))
            .expect("the strict oracle appends a terminal exact observation");
        assert!(
            probe < observe_exact,
            "{}: the mutating probe must run before the terminal observe_exact",
            case.scenario.name
        );

        assert!(
            case.expected_outcomes.iter().any(|expectation| matches!(
                expectation,
                TraceExpectation::ClientsExactlyEquivalent { .. }
            )),
            "{} must pin exact canonical equivalence",
            case.scenario.name
        );
        assert!(
            case.expected_outcomes
                .iter()
                .any(|expectation| matches!(expectation, TraceExpectation::NoPendingWork { .. })),
            "{} must pin no-pending-work",
            case.scenario.name
        );
    }
}

/// Runnable acceptance gate for the unified fork-resolution route under
/// **finite** pressure. Every seed must reach quiescence with exact canonical
/// equivalence, active bidirectional decryptability, and a bounded input queue.
/// It deliberately claims nothing about progress under an unbounded
/// self-update stream.
///
/// This gate was ignored while the engine stranded application sends accepted
/// inside the convergence quiescence window (mdk#1472): a drain that ran
/// before the pass settled consumed the one-shot schedule edge, pass
/// completion never re-armed it, and once the re-arm existed the repeated
/// drain re-prepared the still-unconfirmed intent and double-published it.
/// The engine now re-arms the drain when a pass closes with queued intents
/// outstanding and skips intents that are already regenerated and awaiting
/// the host's confirm or retry.
#[tokio::test(flavor = "multi_thread")]
async fn bounded_convergence_pressure_family_settles_every_seeded_permutation() {
    for case in &generate_bounded_convergence_pressure_family(2026, 6) {
        let report = run_generated_case_report(case, None)
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
    }
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
            .any(|step| matches!(step, ScenarioStep::DuplicateMessage { .. }))),
        "generated cases should include duplicate-delivery variants"
    );
    assert!(
        cases.iter().any(|case| case
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::WithholdMessage { .. }))),
        "generated cases should include delayed-delivery variants"
    );
    assert!(
        cases.iter().any(|case| case
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::ReorderMessages { .. }))),
        "generated cases should include reordered-delivery variants"
    );

    for (case_index, case) in cases.iter().enumerate() {
        assert_eq!(case.family_name, "convergence-e2e-delivery/v1");
        assert_eq!(case.generator_version, "2");
        assert_eq!(case.seed, 99);
        assert_eq!(case.case_index, case_index as u64);

        let report = run_generated_case_report(case, None)
            .await
            .expect("generated convergence variant reports");
        assert!(report.invariant_failures.is_empty());
        assert!(
            report.expectation_failures.is_empty(),
            "case {case_index} failed generated expectations: {:?}",
            report.expectation_failures
        );
        assert_real_peeler_convergence_trace(report.observed_trace.as_ref().expect("trace"));
        assert!(
            !report.epoch_change_observations.is_empty(),
            "case {case_index} produced no epoch-change observations; steps={:?}",
            report.step_log,
        );
    }
}

/// Runs independent generated chaos cases concurrently across the multi-thread
/// runtime's worker threads, applying `check` to each `(case, report)` pair.
///
/// Each chaos case is a self-contained, CPU-bound simulation, so the previous
/// serial `for … .await` loops left every core but one idle (the 24-case suite
/// ran for 8+ minutes on CI). Spawning one task per case bounds real
/// concurrency at the runtime's worker-thread count. A panic inside any case
/// (e.g. an expectation assertion) is re-raised with its original message and
/// backtrace preserved, so failures read exactly as they did when serial.
async fn for_each_chaos_case_concurrently<F>(cases: Vec<GeneratedScenarioCase>, check: F)
where
    F: Fn(&GeneratedScenarioCase, &ScenarioReport) + Send + Sync + 'static,
{
    let check = std::sync::Arc::new(check);
    let mut handles = Vec::with_capacity(cases.len());
    for case in cases {
        let check = std::sync::Arc::clone(&check);
        handles.push(tokio::spawn(async move {
            let report = run_generated_case_report(&case, None)
                .await
                .expect("generated chaos case report runs");
            check(&case, &report);
        }));
    }
    for handle in handles {
        if let Err(err) = handle.await {
            // Re-raise the case's panic so the test fails with the original
            // assertion message rather than an opaque JoinError.
            match err.try_into_panic() {
                Ok(panic) => std::panic::resume_unwind(panic),
                Err(_) => panic!("chaos case task was cancelled before completion"),
            }
        }
    }
}

fn without_strict_reliability_outcomes(mut case: GeneratedScenarioCase) -> GeneratedScenarioCase {
    case.expected_outcomes.retain(|expectation| {
        !matches!(
            expectation,
            TraceExpectation::ClientsExactlyEquivalent { .. }
                | TraceExpectation::NoPendingWork { .. }
        )
    });
    case
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_churn_family_generates_deterministic_arms_that_pass() {
    let cases = generate_admin_churn_family(123, 4);

    assert_eq!(cases, generate_admin_churn_family(123, 4));
    assert_eq!(cases.len(), 4);
    assert!(
        cases.iter().all(|case| !case.expected_outcomes.is_empty()),
        "admin-churn cases should carry semantic expectations"
    );
    assert!(cases[..3].iter().all(|case| {
        case.scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::UpdateAdminPolicy { .. }))
    }));
    assert!(
        cases[2]
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::RestartClient { .. }))
    );
    assert!(
        cases[3]
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::InviteMembers { .. }))
    );
    assert!(
        cases[3]
            .scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::Assert { .. })),
        "the latecomer arm carries pre-join mailbox-isolation zero-count assertions"
    );
    let pending_scope = |case: &GeneratedScenarioCase| {
        case.expected_outcomes
            .iter()
            .find_map(|expectation| match expectation {
                TraceExpectation::NoPendingWork { clients } => Some(clients.clone()),
                _ => None,
            })
            .expect("every admin-churn case carries a no-pending-work expectation")
    };
    for case in &cases[..3] {
        let mut expected_clients = case.scenario.clients.clone();
        expected_clients.sort();
        let mut scoped_clients = pending_scope(case);
        scoped_clients.sort();
        assert_eq!(
            scoped_clients, expected_clients,
            "non-latecomer arms keep the whole-roster pending-work oracle"
        );
    }
    assert_eq!(
        pending_scope(&cases[3]),
        vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()],
        "the latecomer arm scopes strict pending work to the founders"
    );
    assert!(
        cases[3].expected_outcomes.iter().any(|expectation| matches!(
            expectation,
            TraceExpectation::NoPendingWorkExceptRetainedJoinCommit { client } if client == "dave"
        )),
        "the latecomer arm pins the joiner to exactly its retained join commit"
    );

    for case in &cases {
        let report = run_generated_case_report(case, None)
            .await
            .expect("admin-churn case reports");
        assert!(
            report.expectation_failures.is_empty(),
            "case {} failed: {:?}",
            case.case_index,
            report.expectation_failures
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn convergence_chaos_family_generates_specs_with_semantic_expectations() {
    let cases = generate_convergence_chaos_family(123, 24);

    assert_eq!(cases, generate_convergence_chaos_family(123, 24));
    assert_eq!(cases.len(), 24);
    assert!(
        cases.iter().all(|case| !case.expected_outcomes.is_empty()),
        "chaos cases should carry semantic expectations"
    );
    assert!(cases.iter().all(|case| {
        case.scenario
            .steps
            .iter()
            .any(|step| matches!(step, ScenarioStep::ObserveExact { .. }))
    }));
    assert!(cases.iter().all(|case| {
        case.expected_outcomes
            .iter()
            .any(|expectation| matches!(expectation, TraceExpectation::NoPendingWork { .. }))
    }));
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
        cases
            .iter()
            .any(|case| case.scenario.steps.iter().any(|step| matches!(
                step,
                ScenarioStep::AcknowledgeOutbound {
                    outcome: SubjectOutboundOutcome::ReachedNoEndpoint,
                    ..
                }
            ))),
        "chaos cases should include publish rollback"
    );
    assert!(
        cases
            .iter()
            .any(|case| case.scenario.steps.iter().any(|step| matches!(
                step,
                ScenarioStep::DuplicateMessage { .. }
                    | ScenarioStep::WithholdMessage { .. }
                    | ScenarioStep::ReorderMessages { .. }
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
        assert_eq!(case.generator_version, "6");
        assert_eq!(case.seed, 123);
        assert_eq!(case.case_index, case_index as u64);
    }

    let baseline_cases = cases
        .into_iter()
        .map(without_strict_reliability_outcomes)
        .collect();
    for_each_chaos_case_concurrently(baseline_cases, |case, report| {
        assert_eq!(report.expected_outcomes, case.expected_outcomes);
        assert!(
            report.expectation_failures.is_empty(),
            "case {} failed expectations: {:?}",
            case.case_index,
            report.expectation_failures
        );
        assert!(report.invariant_failures.is_empty());
        assert_eq!(report.scenario, case.scenario);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn convergence_chaos_family_seed_changes_scenarios() {
    // Regression for mdk#166: distinct seeds must produce distinct
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
    // semantic reorder schedule) must differ across seeds. This is the
    // regression guard for mdk#166's blocking review finding — before
    // the fix, arm 2's only rng use was a random u16 appended to a payload, so
    // normalizing the payload made both seeds' scenarios identical.
    let reorder_order = |case: &GeneratedScenarioCase| -> Vec<ScenarioMessageSelectorV2> {
        case.scenario
            .steps
            .iter()
            .find_map(|step| match step {
                ScenarioStep::ReorderMessages { order } => Some(order.clone()),
                _ => None,
            })
            .expect("rollback arm should carry a seed-driven semantic reorder step")
    };
    assert_ne!(
        reorder_order(&seed_a[2]),
        reorder_order(&seed_b[2]),
        "arm 2 rollback delivery schedule must vary with the seed, not just the payload string",
    );

    // Every seed-driven scenario must still satisfy its pinned expectations,
    // so the divergence reflects real behavior variation, not breakage.
    let seeded_cases: Vec<GeneratedScenarioCase> = seed_a
        .iter()
        .chain(seed_b.iter())
        .cloned()
        .map(without_strict_reliability_outcomes)
        .collect();
    for_each_chaos_case_concurrently(seeded_cases, |case, report| {
        assert!(
            report.expectation_failures.is_empty(),
            "case {} (seed {}) failed expectations: {:?}",
            case.case_index,
            case.seed,
            report.expectation_failures
        );
        assert!(report.invariant_failures.is_empty());
    })
    .await;
}

#[tokio::test]
async fn convergence_chaos_rollback_fault_duplicates_post_rollback_app_message() {
    // Regression for mdk#163: the rollback arm must duplicate and delay
    // a Bob app message that Alice actually ticks. The definitely failed
    // group-data commit must already have been retracted from the bus.
    let cases = generate_convergence_chaos_family(123, 3);
    let case = &cases[2];

    let duplicate_selector = case
        .scenario
        .steps
        .iter()
        .find_map(|step| match step {
            ScenarioStep::DuplicateMessage { selector } => Some(selector),
            _ => None,
        })
        .expect("rollback arm should duplicate a queued message");
    assert_eq!(
        duplicate_selector.class,
        Some(ScenarioTransportClass::Application)
    );
    assert_eq!(duplicate_selector.occurrence, 0);

    let delayed_copy = case
        .scenario
        .steps
        .iter()
        .find_map(|step| match step {
            ScenarioStep::WithholdMessage { selector, label } => Some((selector, label.as_str())),
            _ => None,
        })
        .expect("rollback arm should delay the duplicate copy");
    assert_eq!(delayed_copy.0.action_id, duplicate_selector.action_id);
    assert_eq!(delayed_copy.0.occurrence, 1);
    assert_eq!(delayed_copy.1, "duplicate-app");

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
async fn sender_ratchet_policy_preserves_reordered_rollback_floods_past_openmls_default() {
    // Seed 2001 places generation 5 ahead of generation 0 in both instances
    // of the rollback-fault family. OpenMLS's unconfigured tolerance of 5
    // irreversibly dropped generation 0 when it arrived sixth; Marmot's pinned
    // tolerance must retain all six application messages.
    let cases = generate_convergence_chaos_family(2001, 14);
    for case_index in [2, 13] {
        let report = run_generated_case_report(&cases[case_index], None)
            .await
            .expect("sender-ratchet regression case reports");
        assert!(
            report.expectation_failures.is_empty(),
            "case {case_index} failed expectations: {:?}",
            report.expectation_failures
        );
        assert!(
            report.invariant_failures.is_empty(),
            "case {case_index} failed invariants: {:?}",
            report.invariant_failures
        );
    }
}

#[tokio::test]
async fn strict_chaos_boundary_retires_pre_join_opaque_resource_work() {
    let cases = generate_convergence_chaos_family(123, 5);

    let repaired = run_generated_case_report(&cases[2], None)
        .await
        .expect("repaired rollback case reports");
    assert!(
        repaired.expectation_failures.is_empty(),
        "definite publish rollback must retract transport artifacts before the strict drain: {:?}",
        repaired.expectation_failures
    );

    let repaired_pre_join = run_generated_case_report(&cases[4], None)
        .await
        .expect("strict pre-join case reports");
    assert!(
        repaired_pre_join.expectation_failures.is_empty(),
        "pre-join opaque input must leave no pending resource work after the controlled deadline: {:?}",
        repaired_pre_join.expectation_failures
    );

    let self_remove_report = run_generated_case_report(&cases[3], None)
        .await
        .expect("strict self-remove case reports");
    assert!(
        self_remove_report.expectation_failures.is_empty(),
        "strict self-remove case must retire consumed proposal work: {:?}",
        self_remove_report.expectation_failures
    );
}

#[tokio::test]
async fn failing_generated_case_records_bounded_minimization_outcome() {
    let mut scenario = ScenarioSpec {
        name: "convergence-chaos/minimizer-smoke/v1".into(),
        spec_version: "2".into(),
        topology: Default::default(),
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
            ScenarioStep::accept_publication("alice", "create"),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: vec!["bob".into()],
            },
            ScenarioStep::ClearEvents {
                clients: vec!["alice".into(), "bob".into()],
            },
        ],
    };
    for index in 0..24 {
        scenario.steps.push(ScenarioStep::SendAppMessage {
            sender: "bob".into(),
            payload: format!("irrelevant storm message {index}"),
        });
    }
    scenario.steps.extend([
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: vec!["alice".into()],
        },
        ScenarioStep::Observe {
            clients: vec!["alice".into()],
        },
    ]);
    let case = GeneratedScenarioCase {
        family_name: "convergence-chaos/v1".into(),
        generator_version: "1".into(),
        seed: 99,
        case_index: 0,
        workload_profile: None,
        subject: cgka_conformance_simulator::GeneratedSubjectKind::Engine,
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
    let generated = report
        .metadata
        .generated
        .as_ref()
        .expect("failing generated case should record generated metadata");
    assert!(matches!(
        generated.minimization.status,
        cgka_conformance_simulator::GeneratedScenarioMinimizationStatus::Complete
            | cgka_conformance_simulator::GeneratedScenarioMinimizationStatus::BudgetExhausted
    ));
    assert!(generated.minimization.trials >= 1);
    if generated.minimization.status
        == cgka_conformance_simulator::GeneratedScenarioMinimizationStatus::Complete
    {
        assert!(generated.minimization.trials > 1);
    }
    let Some(minimized) = generated.minimized_case.as_ref() else {
        assert_eq!(
            generated.minimization.status,
            cgka_conformance_simulator::GeneratedScenarioMinimizationStatus::BudgetExhausted,
            "only budget exhaustion may omit a reduced case"
        );
        return;
    };
    assert!(
        minimized.steps.len() < case.scenario.steps.len(),
        "minimized case should remove irrelevant delivery noise"
    );
    if generated.minimization.status
        == cgka_conformance_simulator::GeneratedScenarioMinimizationStatus::Complete
    {
        assert!(
            minimized
                .steps
                .iter()
                .all(|step| !matches!(step, ScenarioStep::SendAppMessage { .. })),
            "a completed semantic reduction should remove all irrelevant application-message noise"
        );
    }
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
async fn scenario_report_records_trace_log_and_failures() {
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
}

#[tokio::test]
async fn vector_fixture_report_records_semantic_expectation_failures() {
    let fixture = VectorFixture {
        scenario_name: "group-data-fork-recovery/v1".into(),
        vector_version: "1".into(),
        conformance_version: env!("CARGO_PKG_VERSION").into(),
        seed: None,
        application_profile: None,
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
        spec_version: "2".into(),
        topology: Default::default(),
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
            ScenarioStep::accept_publication("alice", "create"),
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
            ScenarioStep::accept_publication("alice", "alice-update"),
            ScenarioStep::accept_publication("bob", "bob-update"),
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
        spec_version: "2".into(),
        topology: Default::default(),
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
            ScenarioStep::accept_publication("alice", "create"),
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
            ScenarioStep::accept_publication("alice", "alice-invite"),
            ScenarioStep::accept_publication("bob", "bob-invite"),
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
        spec_version: "2".into(),
        topology: Default::default(),
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
            ScenarioStep::accept_publication("alice", "create"),
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
        decryptability_probes: vec![],
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
    let case = generate_send_leave_family(42, 1).remove(0);

    let report = run_generated_case_report(&case, None)
        .await
        .expect("generated case reports");
    let generated = report
        .metadata
        .generated
        .as_ref()
        .expect("generated metadata");

    assert_eq!(generated.family_name, "send-leave/v1");
    assert_eq!(generated.generator_version, "2");
    assert_eq!(generated.seed, 42);
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
        decryptability_probes: vec![],
        observations: vec![
            observe_client("alice", &mut alice),
            observe_client("bob", &mut bob),
            observe_client("carol", &mut carol),
        ],
    }
}

#[tokio::test]
async fn refused_leave_releases_named_scenario_input_reservation() {
    // A refused leave must release the id reserved by
    // name_next_scenario_input; otherwise the next named action panics on the
    // unconsumed-id assertion or inherits the failed leave's id.
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let (_gid, pending) = alice
        .create_group("leave-refusal", vec![bob_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;

    // Alice is the sole admin, so the engine refuses her SelfRemove.
    alice.name_next_scenario_input("refused-leave");
    alice
        .leave()
        .await
        .expect_err("sole admin self-remove must be refused");

    // Naming the next action must not trip the unconsumed-id assertion, and
    // the app send consumes the fresh reservation (proven by naming again).
    alice.name_next_scenario_input("post-refusal-app");
    alice.send_app(b"still alive".to_vec()).await;
    alice.name_next_scenario_input("post-refusal-consumed");
    alice.send_app(b"second".to_vec()).await;
}

#[tokio::test]
async fn add_then_self_remove_via_harness() {
    // Alice creates with Bob and Carol; Bob, a non-admin, leaves; remaining
    // members may both publish SelfRemove-only commits, and convergence handles
    // the same-epoch race.
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
    bob.leave().await.expect("leave");
    bus.deliver_all();
    let alice_proposal_outcomes = alice.tick().await; // ingests proposal + auto-commits
    let carol_proposal_outcomes = carol.tick().await; // same: no deterministic election
    assert!(
        alice_proposal_outcomes.iter().all(Result::is_ok),
        "alice proposal outcomes: {alice_proposal_outcomes:?}"
    );
    assert!(
        carol_proposal_outcomes.iter().all(Result::is_ok),
        "carol proposal outcomes: {carol_proposal_outcomes:?}"
    );

    // Both SelfRemove-only commits go onto the bus. Competing same-epoch
    // commits are expected; convergence chooses the canonical one.
    bus.deliver_all();
    let bob_outcomes = bob.tick().await; // ingests alice's commit
    let alice_outcomes = alice.tick().await;
    let carol_outcomes = carol.tick().await;

    assert!(
        alice_outcomes.iter().all(Result::is_ok),
        "alice outcomes: {alice_outcomes:?}"
    );
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
    assert_canonical_scenario_input_ledger(
        "carol",
        &carol.scenario_input_ledger(),
        &expected_payload,
        &losing_payload,
    );
    assert_canonical_scenario_input_ledger(
        "frank",
        &frank.scenario_input_ledger(),
        &expected_payload,
        &losing_payload,
    );

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

    // The losing branch leaves nothing behind. Its transport object is peeled
    // under its own branch state, adjudicated, and resolved, so both observers
    // end the schedule fully quiescent.
    let settled_trace = ScenarioTrace {
        name: "convergence-e2e/settled-losing-transport".into(),
        pending_resolutions: vec![],
        errors: vec![],
        admin_policies: vec![],
        decryptability_probes: vec![],
        observations: vec![
            observe_client_exact("carol", &mut carol),
            observe_client_exact("frank", &mut frank),
        ],
    };
    for observation in &settled_trace.observations {
        let pending = observation
            .pending_work
            .as_ref()
            .expect("exact pending snapshot");
        assert_eq!(
            pending.engine.stored_transport_deferred_messages, 0,
            "{} should retain no unpeeled transport object: {pending:#?}",
            observation.client
        );
        assert_eq!(
            pending.scenario_inputs_pending, 0,
            "{} should leave no unresolved scenario input: {pending:#?}",
            observation.client
        );
    }
    let failures = compare_trace_expectations(
        None,
        &[TraceExpectation::NoPendingWork {
            clients: vec!["carol".into(), "frank".into()],
        }],
        &settled_trace,
    );
    assert!(
        failures.is_empty(),
        "both observers should reach quiescence: {failures:#?}"
    );
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
    // Each observer retracts bob's losing-branch payload exactly once; the
    // report must attribute both retractions.
    assert_eq!(
        report
            .app_invalidation_observations
            .iter()
            .map(|invalidation| (invalidation.client.as_str(), invalidation.reason.as_str()))
            .collect::<Vec<_>>(),
        vec![("carol", "losing_branch"), ("frank", "losing_branch")],
        "{:#?}",
        report.app_invalidation_observations
    );
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
    fixtures.extend(
        std::fs::read_dir(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/incidents"),
        )
        .expect("incident vectors dir exists")
        .map(|entry| entry.expect("incident vector entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".v1.json"))
        }),
    );
    fixtures.sort();

    for path in fixtures {
        let fixture_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture file name");
        let fixture: VectorFixture =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture contents"))
                .unwrap_or_else(|e| panic!("{fixture_name} parses: {e}"));
        let observed_trace = run_vector_fixture_report(&fixture)
            .await
            .expect("fixture scenario runs")
            .observed_trace
            .expect("successful fixture report has an observed trace");
        assert_vector_fixture_matches(fixture_name, &fixture, observed_trace);
    }
}

fn convergence_e2e_group_events_spec() -> ScenarioSpec {
    ScenarioSpec {
        name: "convergence-e2e-group-events/v1".into(),
        spec_version: "2".into(),
        topology: Default::default(),
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
            ScenarioStep::accept_publication("alice", "create"),
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
            ScenarioStep::accept_publication("alice", "alice-invite-david"),
            ScenarioStep::InviteMembers {
                inviter: "alice".into(),
                invitees: vec!["grace".into()],
                pending: "alice-invite-grace".into(),
            },
            ScenarioStep::accept_publication("alice", "alice-invite-grace"),
            ScenarioStep::InviteMembers {
                inviter: "bob".into(),
                invitees: vec!["eve".into()],
                pending: "bob-invite-eve".into(),
            },
            ScenarioStep::accept_publication("bob", "bob-invite-eve"),
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

fn assert_canonical_scenario_input_ledger(
    client: &str,
    ledger: &[ScenarioInputLedgerEntry],
    expected_payload: &[u8],
    losing_payload: &[u8],
) {
    let expected_payload = String::from_utf8_lossy(expected_payload);
    let losing_payload = String::from_utf8_lossy(losing_payload);
    let expected = ledger
        .iter()
        .find(|entry| entry.payload == expected_payload)
        .unwrap_or_else(|| panic!("{client} missing selected logical message: {ledger:#?}"));
    let losing = ledger
        .iter()
        .find(|entry| entry.payload == losing_payload)
        .unwrap_or_else(|| panic!("{client} missing losing logical message: {ledger:#?}"));

    assert_eq!(
        expected.delivered, 1,
        "{client} must deliver the selected branch exactly once: {ledger:#?}"
    );
    assert_eq!(
        losing.delivered, 0,
        "{client} must not project losing-branch application output: {ledger:#?}"
    );
    assert!(
        losing
            .invalidated
            .iter()
            .any(|reason| reason == "losing_branch")
            || (losing.transport_deferred > 0 && losing.pending),
        "{client} must classify losing output as invalidated or visibly transport-pending: \
         {ledger:#?}"
    );
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

/// Pins this client's application timeline across branch selection: exactly the
/// selected branch's payload reaches the application, it is never taken back,
/// and the rival branch's payload is retracted explicitly.
///
/// Branch-relative peel makes the rival branch's traffic decryptable under that
/// branch's own state, so the losing payload is now decrypted and adjudicated
/// instead of sitting undecryptable. That turns "no invalidation ever" into a
/// live obligation: convergence owes the application a `LosingBranch`
/// retraction for it.
fn assert_canonical_application_event(
    client: &str,
    events: Vec<GroupEvent>,
    expected_payload: &[u8],
    losing_payload: &[u8],
) {
    let delivered: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived {
                message_id,
                payload,
                ..
            } => Some((
                message_id,
                cgka_conformance_simulator::client::decode_harness_app_payload(payload),
            )),
            _ => None,
        })
        .collect();
    let retractions: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::AppMessageInvalidated {
                message_id, reason, ..
            } => Some((message_id, *reason)),
            _ => None,
        })
        .collect();

    let received_payloads: Vec<Vec<u8>> = delivered
        .iter()
        .map(|(_, payload)| payload.clone())
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
    // A payload the application was shown and then lost is a failure here,
    // retracted or not: on this schedule the selected branch is the only one
    // that ever reaches delivery, so its delivery must stand. A schedule that
    // legitimately delivers the rival branch first trips this by design.
    for (message_id, _) in &delivered {
        assert!(
            !retractions
                .iter()
                .any(|(retracted, _)| retracted == message_id),
            "{client} retracted a payload it had already delivered: {events:?}"
        );
    }
    assert_eq!(
        retractions.len(),
        1,
        "{client} should retract the losing branch payload exactly once: {events:?}"
    );
    assert!(
        retractions
            .iter()
            .all(|(_, reason)| matches!(reason, AppMessageInvalidationReason::LosingBranch)),
        "{client} should retract only for losing-branch selection: {events:?}"
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

/// Pins the settled branch every legacy observation in the convergence-E2E
/// shape must report: alice's branch carries two invites to bob's one, so
/// depth decides it for every observer that has been handed both.
fn assert_real_peeler_convergence_trace(trace: &ScenarioTrace) {
    // The settle tail observes the founders with `observe_client_exact` after
    // canonical branch selection; those snapshots must agree with each other,
    // and the family's own `clients_exactly_equivalent` expectation carries
    // the exact claim. The branch-shape checks below apply to the legacy
    // observations only.
    let settled = trace
        .observations
        .iter()
        .filter(|observation| observation.canonical_state.is_some())
        .collect::<Vec<_>>();
    if let Some(first) = settled.first() {
        for observation in &settled {
            assert_eq!(observation.epoch, first.epoch);
            assert_eq!(observation.member_count, first.member_count);
        }
    }
    for observation in &trace.observations {
        if observation.canonical_state.is_some() {
            continue;
        }
        // Every observer here has been handed both branches and ticked, so it
        // has settled on the deeper one: alice's two invites, epoch 3, and her
        // payload as the only application output.
        assert_eq!(
            observation.received_payloads,
            vec!["alice canonical payload"],
            "{observation:?}"
        );
        assert_eq!(observation.epoch, 3, "{observation:?}");
        assert_eq!(observation.member_count, 6, "{observation:?}");
        assert_eq!(
            observation.epoch_changes,
            vec![
                EpochChangeObservation { from: 1, to: 2 },
                EpochChangeObservation { from: 2, to: 3 },
            ],
            "{observation:?}"
        );
        // Whether the rival branch was adopted first is a delivery-order
        // detail, so the membership claim is the net diff: anything withdrawn
        // must be something this client had adopted, and what survives is
        // exactly the selected branch's addition.
        for removed in &observation.removed_members {
            assert!(
                observation.added_members.contains(removed),
                "{observation:?}"
            );
        }
        let net_added: Vec<&str> = observation
            .added_members
            .iter()
            .filter(|member| !observation.removed_members.contains(member))
            .map(String::as_str)
            .collect();
        assert_eq!(net_added, vec!["david", "grace"], "{observation:?}");
        // Bob's payload decrypts under his own branch state, so it must be
        // retracted rather than silently dropped.
        let invalidation_reasons: Vec<&str> = observation
            .app_invalidations
            .iter()
            .map(|invalidation| invalidation.reason.as_str())
            .collect();
        assert_eq!(
            invalidation_reasons,
            vec!["losing_branch"],
            "{observation:?}"
        );
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
    // treats the group-message echo as transport-deferred because the
    // outer wrapper was encrypted for the pre-join epoch.
    bus.deliver_all();
    let outcomes = carol.tick().await;
    let saw_welcome = outcomes
        .iter()
        .any(|o| matches!(o, Ok(cgka_traits::ingest::IngestOutcome::Processed)));
    let saw_transport_deferred = outcomes.iter().any(|o| {
        matches!(
            o,
            Ok(cgka_traits::ingest::IngestOutcome::TransportDeferred { .. })
        )
    });
    assert!(
        saw_welcome,
        "expected welcome to be processed: {outcomes:?}"
    );
    assert!(
        saw_transport_deferred,
        "expected transport-deferred commit echo: {outcomes:?}"
    );
}

/// End-to-end #1176 coverage through the production-shaped Nostr wrapper. A
/// seven-member observer misses one epoch advance, retains 47 future-epoch
/// applications, and must durably queue its own send without emitting wire.
/// Restart preserves both work sets; the missing commit then unlocks the
/// complete backlog and regenerates the queued send.
#[tokio::test]
async fn seven_member_future_epoch_backlog_queues_send_and_regenerates_after_restart() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut observer = ClientBuilder::new(pad32(b"observer"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut additional = Vec::new();
    for index in 0..5 {
        additional.push(
            ClientBuilder::new(pad32(format!("member-{index}").as_bytes()))
                .registry(selfremove_registry())
                .attach(&bus),
        );
    }

    let mut key_packages = vec![observer.fresh_key_package().await];
    for client in &mut additional {
        key_packages.push(client.fresh_key_package().await);
    }
    let (_group_id, pending) = alice
        .create_group("foreground-deferred-budget", key_packages, vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    observer.tick().await;
    assert_eq!(observer.members().len(), 7);

    let epoch_advance = alice.self_update().await;
    alice.confirm(epoch_advance).await;
    for index in 0..47 {
        alice
            .send_app(format!("future-epoch-application-{index}").into_bytes())
            .await;
    }
    assert_eq!(bus.queued_len(), 48, "one commit plus 47 applications");
    assert!(bus.delay_queued(0, "missing-epoch-advance"));
    bus.deliver_all();

    let outcomes = observer.tick_ingest_only().await;
    assert_eq!(outcomes.len(), 47);
    assert!(
        outcomes
            .iter()
            .all(|outcome| matches!(outcome, Ok(IngestOutcome::TransportDeferred { .. })))
    );
    assert_eq!(bus.queued_len(), 0);

    observer
        .send_app(b"observer-accepted-pending".to_vec())
        .await;
    assert_eq!(bus.queued_len(), 0, "queued acceptance must emit no wire");
    let pending_work = observer.pending_work_observation();
    assert_eq!(pending_work.engine.stored_transport_deferred_messages, 47);
    assert_eq!(pending_work.engine.queued_outbound_intents, 1);
    let metrics = observer.engine_metrics();
    assert_eq!(metrics.foreground_deferred_budget_exhausted, 1);
    assert_eq!(metrics.foreground_deferred_rows_attempted.sample_count(), 1);
    assert_eq!(
        metrics
            .foreground_deferred_rows_attempted
            .approx_percentile(1.0),
        Some(4)
    );
    assert_eq!(metrics.outbound_wire_prepare_ms.sample_count(), 0);
    assert_eq!(metrics.outbound_queue_accept_ms.sample_count(), 1);

    observer.restart();
    let after_restart = observer.pending_work_observation();
    assert_eq!(after_restart.engine.stored_transport_deferred_messages, 47);
    assert_eq!(after_restart.engine.queued_outbound_intents, 1);
    assert_eq!(
        observer
            .engine_metrics()
            .foreground_deferred_budget_exhausted,
        1,
        "foreground metrics survive the harness restart rollup"
    );

    assert!(bus.release_delayed("missing-epoch-advance"));
    bus.deliver_all();
    observer.tick().await;
    assert_eq!(observer.epoch(), EpochId(2));
    let drained = observer.pending_work_observation();
    assert_eq!(drained.engine.stored_transport_deferred_messages, 0);
    assert_eq!(
        drained.engine.queued_outbound_intents, 1,
        "durable intent remains until publication acknowledgement"
    );
    assert!(
        bus.queued_len() >= 1,
        "the regenerated observer application is now publishable"
    );
}

/// End-to-end proof of the convergence assert surface: an observer's engine
/// makes a real `convergence_decision`, the harness recorder captures it, and it
/// is asserted through `TraceExpectation::ConvergenceDecision`. Two admins invite
/// different members at the same epoch, so carol's convergence selects the
/// canonical branch by authenticated committer identity — deterministic, and
/// distinct from a witness-decided win (covered by the vector.rs unit tests).
#[tokio::test]
async fn harness_captures_and_asserts_convergence_decision() {
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
    let mut eve = ClientBuilder::new(pad32(b"eve"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let carol_kp = carol.fresh_key_package().await;
    let (_group_id, pending) = alice
        .create_group_with_admins(
            "convergence-decision-capture",
            vec![bob_kp, carol_kp],
            vec![],
            vec![bob.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;
    // Discard setup-phase captures so the assertion sees only the contested
    // convergence decision under test.
    for client in [&mut alice, &mut bob, &mut carol] {
        client.drain_events();
        client.clear_audit_capture();
    }

    // Two admins invite different members at the same source epoch: two branches.
    let david_kp = david.fresh_key_package().await;
    let eve_kp = eve.fresh_key_package().await;
    let alice_pending = alice.invite(vec![david_kp]).await;
    let bob_pending = bob.invite(vec![eve_kp]).await;
    alice.confirm(alice_pending).await;
    bob.confirm(bob_pending).await;

    // Carol ingests both commits and runs convergence, which selects the
    // canonical branch. Both commits are privileged admin invites with no
    // app-witness quorum, so the committer-identity rule is decisive.
    bus.deliver_all();
    let carol_outcomes = carol.tick().await;
    assert_tick_reached_convergence("carol", &carol_outcomes);

    let observed = ScenarioTrace {
        name: "convergence-decision-capture".into(),
        pending_resolutions: Vec::new(),
        errors: Vec::new(),
        admin_policies: Vec::new(),
        decryptability_probes: Vec::new(),
        observations: vec![observe_client("carol", &mut carol)],
    };
    let failures = compare_trace_expectations(
        None,
        &[TraceExpectation::ConvergenceDecision {
            client: Some("carol".into()),
            selected_branch_id: None,
            selected_tip_epoch: Some(2),
            decisive_rule: Some("tip_committer".into()),
            witness_quorum_met: Some(false),
            min_app_witness_score: None,
        }],
        &observed,
    );
    assert!(
        failures.is_empty(),
        "carol should observe the committer-decided convergence decision: {failures:#?}"
    );
}

#[tokio::test]
async fn cross_route_own_commit_recovery_survives_restart_with_exact_agreement() {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors/cross-route-own-commit-recovery.v1.json");
    let fixture: VectorFixture = serde_json::from_str(
        &std::fs::read_to_string(&fixture_path).expect("cross-route fixture contents"),
    )
    .expect("cross-route fixture parses");

    let report = run_vector_fixture_report_with_storage_mode(
        &fixture,
        HarnessStorageMode::TempFileBackedSqlite,
    )
    .await
    .expect("cross-route fixture executes");

    assert!(
        report.expectation_failures.is_empty(),
        "cross-route expectations must pass: {:#?}",
        report.expectation_failures
    );
    assert!(
        report.invariant_failures.is_empty(),
        "cross-route invariants must pass: {:#?}",
        report.invariant_failures
    );

    let trace = report.observed_trace.expect("cross-route trace");
    // Portable expectations cover recovery, restart progression, exact state,
    // and decryptability. Keep only this semantic ledger subset harness-local:
    // a complete portable ledger would also pin unrelated probe ids/counters.
    for observation in &trace.observations {
        for (scenario_id, disposition) in [
            (
                "step-5:update_group_data",
                ScenarioInputDisposition::Accepted,
            ),
            (
                "step-6:update_group_data",
                ScenarioInputDisposition::Invalidated,
            ),
            (
                "step-12:update_group_data",
                ScenarioInputDisposition::Accepted,
            ),
        ] {
            let entry = observation
                .scenario_input_ledger
                .iter()
                .find(|entry| entry.scenario_id == scenario_id)
                .unwrap_or_else(|| {
                    panic!(
                        "{} missing durable disposition for {scenario_id}",
                        observation.client
                    )
                });
            assert_eq!(
                entry.disposition, disposition,
                "{} disposition for {scenario_id}",
                observation.client
            );
        }
    }
    assert_own_commit_was_withdrawn(&trace, "alpha", "step-6:update_group_data");
}

/// Pin the own-commit withdrawal as the engine's event pair, not just as a
/// terminal disposition.
///
/// `Invalidated` alone is reachable from several ledger transitions (an epoch
/// invalidation observed on a peer, an expiry that lost its race). The property
/// a cross-route recovery vector claims is narrower: the displaced commit's own
/// author observed `GroupEvent::CommitRolledBack` *and*
/// `GroupEvent::GroupStateInvalidated { reason: SupersededByBranchSelection }`
/// for that exact commit. `client.rs` records those two events under the
/// reasons asserted here, so requiring both names the pair by the only
/// portable handle the ledger carries.
fn assert_own_commit_was_withdrawn(
    trace: &cgka_conformance_simulator::ScenarioTrace,
    committer: &str,
    scenario_id: &str,
) {
    let observation = trace
        .observations
        .iter()
        .rev()
        .find(|observation| observation.client == committer)
        .unwrap_or_else(|| panic!("missing observation for {committer}"));
    let entry = observation
        .scenario_input_ledger
        .iter()
        .find(|entry| entry.scenario_id == scenario_id)
        .unwrap_or_else(|| panic!("{committer} missing ledger entry for {scenario_id}"));
    for reason in ["commit_rolled_back", "group_state_invalidated_superseded"] {
        assert!(
            entry.invalidated.iter().any(|observed| observed == reason),
            "{committer}'s own {scenario_id} must record {reason}; recorded {:?}",
            entry.invalidated
        );
    }
}

#[tokio::test]
async fn cross_route_recovery_uses_retained_history_after_restart() {
    let input_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "vectors/generated-inputs/cross-route-retained-history-recovery.generated-input.json",
    );
    let input: GeneratedScenarioInputV1 = serde_json::from_str(
        &std::fs::read_to_string(&input_path).expect("retained cross-route input contents"),
    )
    .expect("retained cross-route input parses");
    input
        .validate()
        .expect("generated input version is supported");
    assert_eq!(input.case.subject, GeneratedSubjectKind::RetainedRelay);

    let report = run_generated_case_report_with_storage_mode(
        &input.case,
        None,
        HarnessStorageMode::TempFileBackedSqlite,
    )
    .await
    .expect("retained cross-route scenario executes");
    assert!(
        report.expectation_failures.is_empty(),
        "retained cross-route expectations must pass: {:#?}",
        report.expectation_failures
    );
    assert!(
        report.invariant_failures.is_empty(),
        "retained cross-route invariants must pass: {:#?}",
        report.invariant_failures
    );

    let full_history = report
        .relay_sync_observations
        .iter()
        .filter(|observation| {
            observation.completeness == RelayHistoryCompletenessClaimV2::FullHistoryQueried
        })
        .collect::<Vec<_>>();
    assert_eq!(
        full_history.len(),
        4,
        "every participant queries full history"
    );
    assert!(
        full_history
            .iter()
            .all(|observation| observation.injected_objects > 0),
        "the final settlement must consume retained relay objects: {full_history:#?}"
    );
    for (client, events_returned) in [("yankee", 1), ("zeta", 2)] {
        let partial_view = report
            .relay_sync_observations
            .iter()
            .rfind(|observation| {
                observation.client == client
                    && observation.completeness == RelayHistoryCompletenessClaimV2::RelayEoseOnly
            })
            .unwrap_or_else(|| panic!("{client} is missing its partial retained-history view"));
        assert_eq!(
            (partial_view.events_returned, partial_view.injected_objects),
            (events_returned, 1),
            "{client}'s last pre-full-history sync must be the deliberate partial view"
        );
    }

    let trace = report.observed_trace.expect("retained cross-route trace");
    for observation in &trace.observations {
        for (scenario_id, disposition) in [
            (
                "step-5:update_group_data",
                ScenarioInputDisposition::Accepted,
            ),
            (
                "step-6:update_group_data",
                ScenarioInputDisposition::Invalidated,
            ),
            (
                "step-12:update_group_data",
                ScenarioInputDisposition::Accepted,
            ),
        ] {
            let entry = observation
                .scenario_input_ledger
                .iter()
                .find(|entry| entry.scenario_id == scenario_id)
                .unwrap_or_else(|| {
                    panic!(
                        "{} missing retained-route disposition for {scenario_id}",
                        observation.client
                    )
                });
            assert_eq!(
                entry.disposition, disposition,
                "{} disposition for {scenario_id}",
                observation.client
            );
        }
    }
    assert_own_commit_was_withdrawn(&trace, "alpha", "step-6:update_group_data");
}

#[tokio::test]
async fn failed_invite_staging_does_not_poison_fork_detection_via_harness() {
    // Harness mirror of the cgka-engine regression test
    // `failed_invite_staging_does_not_poison_fork_detection`: a send-path
    // staging failure must leave no phantom "we committed from this epoch"
    // bookkeeping behind. Historically it did, and once the client advanced
    // past that epoch via a PEER's commit (settled through convergence, so
    // no fork-recovery incumbent of its own exists), a legitimate sibling
    // commit for the poisoned epoch failed closed with ForkedEpoch and stuck
    // the group in Recovering.
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"phantom-alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"phantom-bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut carol = ClientBuilder::new(pad32(b"phantom-carol"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut dave = ClientBuilder::new(pad32(b"phantom-dave"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut erin = ClientBuilder::new(pad32(b"phantom-erin"))
        .registry(selfremove_registry())
        .attach(&bus);

    // Bob and Dave are admins: each later commits an invite from epoch 1.
    let bob_kp = bob.fresh_key_package().await;
    let dave_kp = dave.fresh_key_package().await;
    let (_group_id, pending) = alice
        .create_group_with_admins(
            "phantom-committed-from",
            vec![bob_kp, dave_kp],
            vec![],
            vec![bob.member_id(), dave.member_id()],
        )
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    dave.tick().await;
    assert_eq!(alice.epoch().0, 1);
    assert_eq!(bob.epoch().0, 1);
    assert_eq!(dave.epoch().0, 1);

    // Alice's invite fails DURING commit staging: the duplicate-Bob
    // KeyPackage carries Bob's existing leaf signature key, which OpenMLS
    // rejects inside add_members — after capability validation, before the
    // pending-publish state transition. Nothing reaches the bus.
    let duplicate_bob_kp = bob.fresh_key_package().await;
    let failed = alice.try_invite(vec![duplicate_bob_kp]).await;
    assert!(
        failed.is_err(),
        "duplicate-member invite must fail during staging"
    );

    // Partition Dave away so he stays at epoch 1 and never sees Bob's
    // commit. Bob invites Carol; Alice advances to epoch 2 purely by
    // settling Bob's commit through convergence (peer-driven advance — no
    // own commit, no fork-recovery incumbent at epoch 1).
    bus.set_partition(Some(vec![alice.bus_id, bob.bus_id, carol.bus_id]));
    let carol_kp = carol.fresh_key_package().await;
    let bob_pending = bob.invite(vec![carol_kp]).await;
    bob.confirm(bob_pending).await;
    bus.deliver_all();
    carol.tick().await;
    let alice_outcomes = alice.tick().await;
    assert_eq!(
        alice.epoch().0,
        2,
        "alice must settle bob's commit via convergence: {alice_outcomes:?}"
    );

    // Heal the partition. Dave — still at epoch 1 — commits a sibling
    // invite from the epoch Alice's failed staging attempt touched.
    bus.set_partition(None);
    let erin_kp = erin.fresh_key_package().await;
    let dave_pending = dave.invite(vec![erin_kp]).await;
    dave.confirm(dave_pending).await;
    bus.deliver_all();

    // Alice must classify the sibling (stale losing branch, or a
    // deterministic reorg onto the winning branch) — never fail closed with
    // ForkedEpoch, which left the group stuck in Recovering.
    let alice_outcomes = alice.tick().await;
    let alice_forked = alice_outcomes
        .iter()
        .any(|o| matches!(o, Err(cgka_traits::EngineError::ForkedEpoch { .. })));
    assert!(
        !alice_forked,
        "sibling commit after failed staging must not fail closed: {alice_outcomes:?}"
    );
    assert_eq!(alice.epoch().0, 2);

    // Whichever branch won deterministically, alice holds exactly one of
    // the two invitees and the group remains operational.
    let members = alice.members();
    let has_carol = members.iter().any(|m| m.id == carol.member_id());
    let has_erin = members.iter().any(|m| m.id == erin.member_id());
    assert_ne!(
        has_carol, has_erin,
        "exactly one branch must win: {members:?}"
    );
    // Usability probe: a fresh valid invite from Alice must stage normally.
    // A group stuck in Recovering rejects the send outright.
    let mut frank = ClientBuilder::new(pad32(b"phantom-frank"))
        .registry(selfremove_registry())
        .attach(&bus);
    let frank_kp = frank.fresh_key_package().await;
    let probe_pending = alice
        .try_invite(vec![frank_kp])
        .await
        .expect("group must remain usable after failed staging + sibling commit");
    alice.confirm(probe_pending).await;
    assert_eq!(alice.epoch().0, 3);
}

#[tokio::test]
async fn removed_member_rejoins_via_fresh_welcome() {
    // Alice removes Carol, then re-invites her with a fresh KeyPackage. The
    // re-add is product-legal (leaver.rb re-add leg); Carol must land on the
    // new epoch and exchange application traffic again.
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
        .create_group("readd", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    let pending = alice.remove_members(vec![carol.member_id()]).await;
    alice.confirm(pending).await;
    bus.deliver_all();
    let bob_outcomes = bob.tick().await;
    assert!(
        bob_outcomes.iter().all(Result::is_ok),
        "bob removal outcomes: {bob_outcomes:?}"
    );
    let carol_outcomes = carol.tick().await;
    assert!(
        carol_outcomes.iter().all(Result::is_ok),
        "carol removal outcomes: {carol_outcomes:?}"
    );
    assert_eq!(alice.members().len(), 2);

    let carol_kp2 = carol.fresh_key_package().await;
    let pending = alice.invite(vec![carol_kp2]).await;
    alice.confirm(pending).await;
    bus.deliver_all();
    let bob_outcomes = bob.tick().await;
    assert!(
        bob_outcomes.iter().all(Result::is_ok),
        "bob re-add outcomes: {bob_outcomes:?}"
    );
    let carol_outcomes = carol.tick().await;
    assert!(
        carol_outcomes.iter().all(Result::is_ok),
        "carol re-add outcomes: {carol_outcomes:?}"
    );

    assert_eq!(alice.epoch().0, 3);
    assert_eq!(carol.epoch().0, 3);
    assert_eq!(alice.members().len(), 3);
    assert_eq!(carol.members().len(), 3);

    carol.send_app(b"carol is back".to_vec()).await;
    bus.deliver_all();
    let alice_outcomes = alice.tick().await;
    assert!(
        alice_outcomes.iter().all(Result::is_ok),
        "alice app outcomes: {alice_outcomes:?}"
    );
    let received = alice
        .drain_events()
        .into_iter()
        .filter(|e| matches!(e, GroupEvent::MessageReceived { .. }))
        .count();
    assert_eq!(
        received, 1,
        "alice must receive carol's post-rejoin message"
    );
}

#[tokio::test]
async fn commit_missing_proposal_defers_and_applies_after_proposal_backfill() {
    // Carol's SelfRemove proposal never reaches Bob (partition drop), so
    // Alice's removal commit arrives at Bob referencing a proposal he does
    // not hold. The commit must stay deferred, and a later re-delivery of
    // the proposal (relay backfill) must complete the removal at Bob.
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
        .create_group("missing-proposal", vec![bob_kp, carol_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;
    carol.tick().await;

    // Carol leaves while only Alice can hear her.
    bus.set_partition(Some(vec![alice.bus_id]));
    let proposal_msg = carol.leave_capture().await.expect("leave proposal");
    bus.deliver_all();
    bus.set_partition(None);
    let alice_outcomes = alice.tick().await; // ingest proposal + auto-commit
    assert!(
        alice_outcomes.iter().all(Result::is_ok),
        "alice outcomes: {alice_outcomes:?}"
    );

    // The removal commit reaches Bob without its proposal.
    bus.deliver_all();
    let bob_outcomes = bob.tick().await;
    assert!(
        bob_outcomes.iter().all(Result::is_ok),
        "bob outcomes: {bob_outcomes:?}"
    );
    assert_eq!(alice.epoch().0, 2);
    assert_eq!(
        bob.epoch().0,
        1,
        "bob cannot apply a commit whose proposal he never saw"
    );

    // Relay backfill: the proposal is re-delivered, and Bob completes.
    bus.send(carol.bus_id, proposal_msg);
    bus.deliver_all();
    let bob_backfill = bob.tick().await;
    assert!(
        bob_backfill.iter().all(Result::is_ok),
        "bob backfill outcomes: {bob_backfill:?}"
    );
    let bob_settle = bob.tick().await;
    assert!(
        bob_settle.iter().all(Result::is_ok),
        "bob settle outcomes: {bob_settle:?}"
    );
    assert_eq!(
        bob.epoch().0,
        2,
        "backfilled proposal must let bob apply the retained commit"
    );
    assert_eq!(bob.members().len(), 2);
}

#[tokio::test]
async fn late_welcome_join_catches_up_via_redelivered_commits() {
    // Dave's Welcome is delayed while the group advances, so the commits
    // reach him before he can resolve the group and are dropped without a
    // durable record (#740 unknown-route posture). Once he joins, relay
    // redelivery of those same events must process rather than dedup
    // against the pre-join drop.
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(&bus);
    let mut dave = ClientBuilder::new(pad32(b"dave"))
        .registry(selfremove_registry())
        .attach(&bus);

    let bob_kp = bob.fresh_key_package().await;
    let (_gid, pending) = alice
        .create_group("late-welcome", vec![bob_kp], vec![])
        .await;
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick().await;

    // Invite Dave but delay his Welcome; the invite commit still broadcasts.
    let dave_kp = dave.fresh_key_package().await;
    let pending = alice.invite(vec![dave_kp]).await;
    alice.confirm(pending).await;
    assert!(bus.delay_queued(0, "dave-welcome"), "welcome sits first");
    bus.deliver_all();
    bob.tick().await;
    dave.tick().await; // pre-join commit lands as unknown-group input

    // The group moves on without Dave. Keep a delayed duplicate of every
    // post-invite commit: it stands in for relay redelivery after his join.
    for (name, backfill) in [("rename-1", "bf-1"), ("rename-2", "bf-2")] {
        let pending = alice.update_group_data(name).await;
        alice.confirm(pending).await;
        assert!(bus.duplicate_queued(0), "commit sits first in the queue");
        assert!(bus.delay_queued(1, backfill));
        bus.deliver_all();
        bob.tick().await;
        dave.tick().await; // pre-join commit is dropped without a record
    }
    assert_eq!(alice.epoch().0, 4);

    // The Welcome finally arrives; Dave joins at the invite epoch.
    assert!(bus.release_delayed("dave-welcome"));
    bus.deliver_all();
    let join_outcomes = dave.tick().await;
    assert!(
        join_outcomes.iter().all(Result::is_ok),
        "dave join outcomes: {join_outcomes:?}"
    );
    assert_eq!(dave.epoch().0, 2);

    // Relay redelivery of the commits he dropped pre-join.
    assert!(bus.release_delayed("bf-1"));
    assert!(bus.release_delayed("bf-2"));
    bus.deliver_all();
    let catchup_outcomes = dave.tick().await;
    assert!(
        catchup_outcomes.iter().all(Result::is_ok),
        "dave catchup outcomes: {catchup_outcomes:?}"
    );
    assert_eq!(
        dave.epoch().0,
        4,
        "redelivered commits must catch dave up after his late join"
    );
    assert_eq!(dave.members().len(), 3);
}
