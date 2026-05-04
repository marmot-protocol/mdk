//! Canonical scripted scenarios driven through the harness bus.
//!
//! Each scenario corresponds to a Phase 6 task in the production refactor
//! plan. These are the tests the proptest layer (Phase 6.8-6.9) generalizes
//! into seeded random sequences.

use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::GroupEvent;
use cgka_traits::types::MemberId;
use test_harness::{ClientBuilder, ScenarioTrace, TransportBus, observe_client};

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
    fn count_app_msgs(c: &mut test_harness::HarnessClient) -> usize {
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
                test_harness::ClientObservation {
                    client: "alice".into(),
                    epoch: 1,
                    member_count: 3,
                    received_payloads: vec!["bob:hello".into(), "carol:hello".into()],
                    removed_members: vec![],
                    recoveries: vec![],
                },
                test_harness::ClientObservation {
                    client: "bob".into(),
                    epoch: 1,
                    member_count: 3,
                    received_payloads: vec!["alice:hello".into(), "carol:hello".into()],
                    removed_members: vec![],
                    recoveries: vec![],
                },
                test_harness::ClientObservation {
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
