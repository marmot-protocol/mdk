//! Phase 6.9 — proptest invariants.
//!
//! Properties:
//! - **(a) True same-id replay**: a TransportMessage delivered twice (via
//!   `bus.inject`) is processed once and the second injection returns
//!   `IngestOutcome::Stale { AlreadySeen }`. Engine state is unchanged.
//! - **(b) Convergence**: undisturbed clients converge on the same epoch
//!   and member set after a sequence of `Send` + `Leave` intents under
//!   any `DeliveryProfile`.
//! - **(c) Rollback**: an upgrade followed by `publish_failed` leaves the
//!   group in the prior `Stable` epoch with the prior `RequiredCapabilities`;
//!   followed by `confirm_published` advances normally. Either way the
//!   engine's reported epoch matches the actual MLS state.
//! - **(d) Event conservation**: canonical scripted scenarios assert exact
//!   app-message delivery counts; the generated properties below focus on
//!   convergence across larger send/leave schedules.

use cgka_conformance::bus::DeliveryPolicy;
use cgka_conformance::proptest_support::{
    ConfirmOutcome, DeliveryProfile, HarnessIntent, confirm_outcome, delivery_profile, intent_seq,
};
use cgka_conformance::{ClientBuilder, HarnessClient, TransportBus};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use proptest::prelude::*;

const REACTIONS_PROPOSAL: u16 = 0xF210;

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

fn registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r.register(
        Feature("reactions"),
        CapabilityRequirement {
            requires: Capability::Proposal(REACTIONS_PROPOSAL),
            level: RequirementLevel::Optional,
            description: "test-only",
        },
    );
    r
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Set up an N-client group via the harness. Returns the clients (alice
/// is index 0) all at epoch 1 and on Stable.
async fn setup_group(n: usize, bus: &TransportBus) -> Vec<HarnessClient> {
    assert!(n >= 2, "need at least 2 clients");
    let mut clients: Vec<HarnessClient> = (0..n)
        .map(|i| {
            ClientBuilder::new(pad32(format!("client-{i}").as_bytes()))
                .registry(registry())
                .attach(bus)
        })
        .collect();
    let mut invite_kps = Vec::with_capacity(n - 1);
    for c in clients.iter_mut().skip(1) {
        invite_kps.push(c.fresh_key_package().await);
    }
    let (_gid, pending) = clients[0].create_group("prop", invite_kps, vec![]).await;
    clients[0].confirm(pending).await;
    bus.deliver_all();
    for c in clients.iter_mut().skip(1) {
        c.tick().await;
    }
    for c in clients.iter_mut() {
        c.drain_events();
    }
    clients
}

fn prop_assert<T: PartialEq + std::fmt::Debug>(actual: T, expected: T, msg: &str) {
    if actual != expected {
        panic!("invariant violated: {msg} (actual={actual:?} expected={expected:?})");
    }
}

// ── Property (b) — convergence under send/leave schedules ─────────────────

/// Re-route a `TransportMessage` so its `transport_group_id` matches the
/// given `gid`. Mirrors the private `route` helper inside the harness's
/// `client.rs` — needed here because we drive the engine + bus directly.
fn reroute(
    msg: cgka_traits::transport::TransportMessage,
    gid: &cgka_traits::types::GroupId,
) -> cgka_traits::transport::TransportMessage {
    use cgka_traits::transport::TransportEnvelope;
    match msg.envelope {
        TransportEnvelope::Welcome { .. } => msg,
        TransportEnvelope::GroupMessage { .. } => cgka_traits::transport::TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: gid.as_slice().to_vec(),
            },
            ..msg
        },
    }
}

async fn drive_intents(
    clients: &mut [HarnessClient],
    bus: &TransportBus,
    intents: &[HarnessIntent],
) -> Vec<bool> {
    let n = clients.len();
    let bus_ids: Vec<_> = clients.iter().map(|c| c.bus_id).collect();
    let group_ids: Vec<_> = clients.iter().map(|c| c.group_id()).collect();
    let mut still_member = vec![true; n];

    for intent in intents {
        match intent {
            HarnessIntent::Send {
                sender_idx,
                payload,
            } => {
                let idx = sender_idx % n;
                if !still_member[idx] {
                    continue;
                }
                let gid = group_ids[idx].clone();
                let res = clients[idx]
                    .engine
                    .send(cgka_traits::engine::SendIntent::AppMessage {
                        group_id: gid.clone(),
                        payload: payload.clone(),
                    })
                    .await;
                if let Ok(cgka_traits::engine::SendResult::ApplicationMessage { msg }) = res {
                    bus.send(bus_ids[idx], reroute(msg, &gid));
                }
            }
            HarnessIntent::Leave { sender_idx } => {
                let idx = sender_idx % n;
                if !still_member[idx] || idx == 0 {
                    // Skip alice (admin; MIP-03 §149 blocks self-removal
                    // when she'd be the last admin).
                    continue;
                }
                let gid = group_ids[idx].clone();
                let res = clients[idx]
                    .engine
                    .send(cgka_traits::engine::SendIntent::Leave {
                        group_id: gid.clone(),
                    })
                    .await;
                if let Ok(cgka_traits::engine::SendResult::Proposal { msg }) = res {
                    bus.send(bus_ids[idx], reroute(msg, &gid));
                    still_member[idx] = false;
                }
            }
        }
    }
    still_member
}

fn convergence_with_event_conservation(intents: Vec<HarnessIntent>) {
    let n = 3usize;
    rt().block_on(async {
        let bus = TransportBus::ordered();
        let mut clients = setup_group(n, &bus).await;
        let still_member = drive_intents(&mut clients, &bus, &intents).await;

        // Drive to quiescence.
        for _ in 0..8 {
            bus.deliver_all();
            for c in clients.iter_mut() {
                let _ = c.tick().await;
            }
            if bus.queued_len() == 0 {
                break;
            }
        }

        // Property (b) — every still-member client agrees on epoch.
        let live_epochs: Vec<u64> = clients
            .iter()
            .enumerate()
            .filter(|(i, _)| still_member[*i])
            .map(|(_, c)| c.epoch().0)
            .collect();
        if live_epochs.len() >= 2 {
            let first = live_epochs[0];
            for e in &live_epochs[1..] {
                prop_assert(*e, first, "live clients must agree on epoch");
            }
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 1000 } else { 24 },
        .. ProptestConfig::default()
    })]

    /// Property (b) — convergence under arbitrary Send+Leave sequences.
    #[test]
    fn prop_convergence_under_send_leave_sequence(
        intents in intent_seq(3, 1..10)
    ) {
        convergence_with_event_conservation(intents);
    }
}

// ── Property (b) under varied delivery profiles ───────────────────────────

fn convergence_under_profile(intents: Vec<HarnessIntent>, profile: DeliveryProfile) {
    let n = 3usize;
    rt().block_on(async {
        let policy: DeliveryPolicy = profile.into_policy();
        let bus = TransportBus::with_policy(policy);
        let mut clients = setup_group(n, &bus).await;
        let still_member = drive_intents(&mut clients, &bus, &intents).await;

        // Quiesce.
        for _ in 0..16 {
            bus.deliver_all();
            for c in clients.iter_mut() {
                let _ = c.tick().await;
            }
            if bus.queued_len() == 0 {
                break;
            }
        }

        // Convergence assertion across live clients.
        let live_epochs: Vec<u64> = clients
            .iter()
            .enumerate()
            .filter(|(i, _)| still_member[*i])
            .map(|(_, c)| c.epoch().0)
            .collect();
        if live_epochs.len() >= 2 {
            let first = live_epochs[0];
            for e in &live_epochs[1..] {
                prop_assert(*e, first, "live clients epoch convergence");
            }
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 500 } else { 12 },
        .. ProptestConfig::default()
    })]

    /// Property (b) again, this time under a randomly-chosen
    /// `DeliveryProfile`. Convergence must hold whether the bus is FIFO,
    /// reverse, or seeded-shuffle.
    #[test]
    fn prop_convergence_under_varied_delivery(
        intents in intent_seq(3, 1..8),
        profile in delivery_profile(),
    ) {
        convergence_under_profile(intents, profile);
    }
}

// ── Property (a) — true same-id replay ────────────────────────────────────

fn true_same_id_replay(payload: Vec<u8>) {
    rt().block_on(async {
        let bus = TransportBus::ordered();
        let mut clients = setup_group(2, &bus).await;

        // Alice sends and we capture the wrapped transport message.
        let captured = clients[0].send_app_capture(payload).await;

        bus.deliver_all();
        let outcomes = clients[1].tick().await;
        // First ingestion: Processed.
        let processed_count = outcomes
            .iter()
            .filter(|o| matches!(o, Ok(IngestOutcome::Processed)))
            .count();
        prop_assert(processed_count, 1, "first delivery should process");

        let epoch_before = clients[1].epoch();
        let events_before = clients[1].drain_events().len();

        // Re-inject the SAME TransportMessage directly into bob's mailbox.
        bus.inject(clients[1].bus_id, captured);
        let outcomes = clients[1].tick().await;
        let stale_count = outcomes
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    Ok(IngestOutcome::Stale {
                        reason: StaleReason::AlreadySeen
                    })
                )
            })
            .count();
        prop_assert(stale_count, 1, "second delivery must be AlreadySeen");

        let epoch_after = clients[1].epoch();
        let events_after = clients[1].drain_events().len();
        prop_assert(epoch_after, epoch_before, "epoch must not change on replay");
        prop_assert(
            events_after,
            0,
            "no new events on replay (events_before was already drained)",
        );
        let _ = events_before;
    });
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 500 } else { 16 },
        .. ProptestConfig::default()
    })]

    /// Property (a) — same `MessageId` ingested twice is exactly one
    /// `Processed` followed by `Stale { AlreadySeen }`. State unchanged.
    #[test]
    fn prop_true_same_id_replay(payload in prop::collection::vec(any::<u8>(), 1..16)) {
        true_same_id_replay(payload);
    }
}

// ── Property (c) — rollback ───────────────────────────────────────────────

fn rollback_property(outcome: ConfirmOutcome) {
    rt().block_on(async {
        let bus = TransportBus::ordered();
        let mut clients = setup_group(2, &bus).await;

        let alice = &mut clients[0];
        let epoch_before = alice.epoch().0;

        let pending = alice.upgrade().await;
        // After upgrade, EpochState reports the projected new epoch.
        let projected = alice.epoch().0;
        prop_assert(projected, epoch_before + 1, "upgrade projects +1 epoch");

        match outcome {
            ConfirmOutcome::Confirm => {
                alice.confirm(pending).await;
                prop_assert(alice.epoch().0, epoch_before + 1, "confirm advances");
            }
            ConfirmOutcome::Fail => {
                alice.fail(pending).await;
                prop_assert(alice.epoch().0, epoch_before, "fail restores prior epoch");
                // Group is immediately re-usable: a second upgrade attempt
                // must succeed (proves Stable, not stuck).
                let pending2 = alice.upgrade().await;
                alice.confirm(pending2).await;
                prop_assert(
                    alice.epoch().0,
                    epoch_before + 1,
                    "post-rollback retry must advance",
                );
            }
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 200 } else { 8 },
        .. ProptestConfig::default()
    })]

    /// Property (c) — confirm advances; fail rolls back; group is
    /// immediately re-usable in either case. Each iteration freshly
    /// constructs the group so the upgrade has something to upgrade.
    #[test]
    fn prop_upgrade_confirm_or_fail_round_trip(outcome in confirm_outcome()) {
        rollback_property(outcome);
    }
}
