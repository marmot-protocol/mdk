//! Regression tests for darkmatter#494.
//!
//! After an admin-promote commit, the promoted peer must receive subsequent
//! messages from the promoter without sending first. Production clients ingest
//! commits into stored convergence and apply them on a scheduled pass; the
//! harness `tick()` helper masks that boundary by forcing convergence with a
//! far-future clock. These tests model the production ingest + scheduled
//! convergence path using the real Nostr peeler.

use cgka_conformance_simulator::{ClientBuilder, HarnessClient, TransportBus};
use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::types::MemberId;
use std::time::Duration;

fn pad32(name: &[u8]) -> Vec<u8> {
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

const PRODUCTION_QUIESCENCE_MS: u64 = 1_000;

fn production_convergence_policy() -> CanonicalizationPolicy {
    CanonicalizationPolicy {
        settlement_quiescence_ms: PRODUCTION_QUIESCENCE_MS,
        ..CanonicalizationPolicy::default()
    }
}

async fn two_member_group(
    bus: &TransportBus,
) -> (HarnessClient, HarnessClient, MemberId, MemberId) {
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .registry(selfremove_registry())
        .attach(bus);
    let mut bob = ClientBuilder::new(pad32(b"bob"))
        .registry(selfremove_registry())
        .attach(bus);

    let bob_kp = bob.fresh_key_package().await;
    let (_gid, pending) = alice
        .create_group_with_admins("494-repro", vec![bob_kp], vec![], vec![alice.member_id()])
        .await;
    alice.confirm(pending).await;

    bus.deliver_all();
    bob.tick().await;

    let alice_id = alice.member_id();
    let bob_id = bob.member_id();
    (alice, bob, alice_id, bob_id)
}

async fn alice_promotes_bob_and_sends_three_messages(
    alice: &mut HarnessClient,
    bob: &mut HarnessClient,
    bus: &TransportBus,
    alice_id: MemberId,
    bob_id: MemberId,
) {
    let pending = alice
        .update_admin_policy(vec![alice_id, bob_id])
        .await
        .expect("alice promotes bob");
    alice.confirm(pending).await;

    bus.deliver_all();
    bob.tick_ingest_only().await;

    for payload in ["one", "two", "three"] {
        alice.send_app(payload).await;
    }
    bus.deliver_all();
    bob.tick_ingest_only().await;
}

/// darkmatter#494: the fixed app worker retries scheduled convergence when the
/// first pass does not settle. The promoted peer must receive all post-promote
/// messages without sending first.
#[tokio::test]
async fn fixed_app_worker_retry_delivers_post_promote_messages() {
    let bus = TransportBus::ordered();
    let (mut alice, mut bob, alice_id, bob_id) = two_member_group(&bus).await;

    bob.set_convergence_policy(production_convergence_policy());
    bob.drain_events();

    alice_promotes_bob_and_sends_three_messages(&mut alice, &mut bob, &bus, alice_id, bob_id).await;

    bob.advance_convergence_with_app_retry(PRODUCTION_QUIESCENCE_MS)
        .await
        .expect("fixed app worker scheduled convergence");

    assert_eq!(bob.epoch().0, 2);
    assert!(bob.admin_labels().contains(&"bob".to_owned()));
    let payloads = bob.received_app_payloads();
    assert_eq!(
        payloads.len(),
        3,
        "promoted peer must receive all post-promote messages; got {payloads:?}"
    );
}

/// A single premature pass without retry leaves the peer stuck and silent.
#[tokio::test]
async fn premature_scheduled_convergence_without_retry_leaves_peer_stuck() {
    let bus = TransportBus::ordered();
    let (mut alice, mut bob, alice_id, bob_id) = two_member_group(&bus).await;

    bob.set_convergence_policy(production_convergence_policy());

    alice_promotes_bob_and_sends_three_messages(&mut alice, &mut bob, &bus, alice_id, bob_id).await;

    bob.advance_convergence()
        .await
        .expect("premature scheduled convergence returns Ok even when not settled");

    tokio::time::sleep(Duration::from_millis(1_100)).await;

    assert_eq!(bob.epoch().0, 1);
    assert!(bob.has_pending_convergence_inputs());
    assert!(bob.received_app_payloads().is_empty());
}

/// When the scheduled pass fires after quiescence, the engine path already
/// delivers post-promote messages without the peer sending first.
#[tokio::test]
async fn scheduled_convergence_after_quiescence_delivers_post_promote_messages() {
    let bus = TransportBus::ordered();
    let (mut alice, mut bob, alice_id, bob_id) = two_member_group(&bus).await;

    bob.set_convergence_policy(production_convergence_policy());
    bob.drain_events();

    alice_promotes_bob_and_sends_three_messages(&mut alice, &mut bob, &bus, alice_id, bob_id).await;

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    bob.advance_convergence()
        .await
        .expect("scheduled convergence after quiescence");

    assert_eq!(bob.epoch().0, 2);
    assert_eq!(bob.received_app_payloads().len(), 3);
}

/// Bob sending after quiescence forces send-path preflight convergence and
/// unsticks the group. Deferred post-promote messages are replayed on that path.
#[tokio::test]
async fn bob_send_after_quiescence_replays_deferred_post_promote_messages() {
    let bus = TransportBus::ordered();
    let (mut alice, mut bob, alice_id, bob_id) = two_member_group(&bus).await;

    bob.set_convergence_policy(production_convergence_policy());

    let pending = alice
        .update_admin_policy(vec![alice_id, bob_id])
        .await
        .expect("promote bob");
    alice.confirm(pending).await;
    bus.deliver_all();
    bob.tick_ingest_only().await;

    alice.send_app("lost-while-stuck").await;
    bus.deliver_all();
    bob.tick_ingest_only().await;

    bob.advance_convergence()
        .await
        .expect("premature scheduled convergence");

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    bob.send_app("after-unstick").await;

    assert_eq!(bob.epoch().0, 2);
    assert!(bob.admin_labels().contains(&"bob".to_owned()));
    let payloads = bob.received_app_payloads();
    assert!(
        payloads
            .iter()
            .any(|payload| payload == b"lost-while-stuck"),
        "send-path preflight should replay deferred post-promote messages after quiescence; got {payloads:?}"
    );
}
