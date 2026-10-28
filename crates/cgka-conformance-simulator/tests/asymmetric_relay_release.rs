//! Releasing a group on one relay's coverage (#2660 phase 5).
//!
//! A recovering member, carol, is offline while alice and bob produce history.
//! Relay A holds every event except a chosen set that only relay B holds.
//! Carol is released on A's coverage: she ingests A's events oldest first, one
//! per tick, and B's events arrive afterwards. How far behind B's events land
//! decides whether carol absorbs them, which is the engine's side of the
//! recovery runner's release rule.
//!
//! The ordinary tests pin each window from both sides. The ignored sweeps walk
//! the same windows across a range and assert where they flip:
//!
//! ```sh
//! cargo test -p cgka-conformance-simulator --features test-policy-overrides \
//!     --test asymmetric_relay_release -- --ignored --nocapture
//! ```

use std::collections::HashSet;

use cgka_conformance_simulator::client::decode_harness_app_payload;
use cgka_conformance_simulator::{ClientBuilder, HarnessClient, TransportBus};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::engine::GroupEvent;
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::MessageId;

/// marmot-app's `EPOCH_STALL_BACKFILL_THRESHOLD`: undecryptable events at one
/// stalled epoch before the app arms an account-wide full-history backfill.
const STALL_BACKFILL_THRESHOLD: usize = 8;
/// The engine's past-epoch window (`DEFAULT_MAX_PAST_EPOCHS`).
const PAST_EPOCHS: usize = 5;
/// The sender ratchet's out-of-order tolerance: a message opens only while
/// fewer than this many later generations from its sender were decrypted.
const OUT_OF_ORDER_TOLERANCE: usize = 100;
/// The sender ratchet's maximum forward distance.
const MAX_FORWARD_DISTANCE: usize = 1_000;

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

/// Three members: `alice` and `bob` stay online, `carol` recovers.
struct Group {
    bus: TransportBus,
    alice: HarnessClient,
    bob: HarnessClient,
    carol: HarnessClient,
    /// Transport ids only relay B holds.
    b_only: HashSet<MessageId>,
}

impl Group {
    async fn new(name: &str) -> Self {
        let bus = TransportBus::ordered();
        let mut alice = ClientBuilder::new(pad32(b"alice"))
            .registry(FeatureRegistry::new())
            .attach(&bus);
        let mut bob = ClientBuilder::new(pad32(b"bob"))
            .registry(FeatureRegistry::new())
            .attach(&bus);
        let mut carol = ClientBuilder::new(pad32(b"carol"))
            .registry(FeatureRegistry::new())
            .attach(&bus);
        let bob_kp = bob.fresh_key_package().await;
        let carol_kp = carol.fresh_key_package().await;
        let (_group_id, pending) = alice
            .create_group(name, vec![bob_kp, carol_kp], vec![])
            .await;
        alice.confirm(pending).await;
        bus.deliver_all();
        bob.tick().await;
        carol.tick().await;
        let _ = carol.drain_events();
        Self {
            bus,
            alice,
            bob,
            carol,
            b_only: HashSet::new(),
        }
    }

    /// Deliver to the online members; carol's copies wait in her mailbox.
    async fn settle_online(&mut self) {
        self.bus.deliver_all();
        self.alice.tick().await;
        self.bob.tick().await;
        self.bus.deliver_all();
    }

    fn queued_ids(&self) -> HashSet<MessageId> {
        self.bus
            .queued_messages()
            .into_iter()
            .map(|m| m.id)
            .collect()
    }

    fn queued_since(&self, before: &HashSet<MessageId>) -> Vec<TransportMessage> {
        self.bus
            .queued_messages()
            .into_iter()
            .filter(|m| !before.contains(&m.id))
            .collect()
    }

    async fn bob_says(&mut self, payload: &str, b_only: bool) {
        let msg = self.bob.send_app_capture(payload.as_bytes().to_vec()).await;
        if b_only {
            self.b_only.insert(msg.id);
        }
        self.settle_online().await;
    }

    async fn alice_commits(&mut self, b_only: bool) {
        let before = self.queued_ids();
        let pending = self.alice.self_update().await;
        let commit = self.queued_since(&before);
        assert_eq!(commit.len(), 1, "one commit per self-update");
        if b_only {
            self.b_only.extend(commit.into_iter().map(|m| m.id));
        }
        self.alice.confirm(pending).await;
        self.settle_online().await;
    }

    /// Release carol on relay A, then deliver relay B's extra events.
    async fn release_on_a_then_b(&mut self) -> Release {
        let history = self.bus.mailbox(self.carol.bus_id);
        let (late, on_a): (Vec<TransportMessage>, Vec<TransportMessage>) = history
            .into_iter()
            .partition(|m| self.b_only.contains(&m.id));
        let mut deferred_on_a = 0;
        for msg in on_a {
            self.bus.inject(self.carol.bus_id, msg);
            deferred_on_a += self
                .carol
                .tick()
                .await
                .iter()
                .filter(|o| matches!(o, Ok(IngestOutcome::TransportDeferred { .. })))
                .count();
        }
        let epoch_before_late = self.carol.epoch().0;
        for msg in late {
            self.bus.inject(self.carol.bus_id, msg);
            self.carol.tick().await;
        }
        // Give the engine further turns, as a running device would.
        for _ in 0..3 {
            self.carol.tick().await;
        }
        let payloads = self
            .carol
            .drain_events()
            .into_iter()
            .filter_map(|event| match event {
                GroupEvent::MessageReceived { payload, .. } => Some(
                    String::from_utf8_lossy(&decode_harness_app_payload(&payload)).into_owned(),
                ),
                _ => None,
            })
            .collect();
        Release {
            agrees_with_alice: self.carol.canonical_group_snapshot().group_context_sha256
                == self.alice.canonical_group_snapshot().group_context_sha256,
            epoch_before_late,
            deferred_on_a,
            payloads,
        }
    }
}

#[derive(Debug)]
struct Release {
    /// Carol selected the same group state as alice.
    agrees_with_alice: bool,
    /// Carol's epoch once A's events were in, before B's arrived.
    epoch_before_late: u64,
    /// Relay A events carol could not peel when they arrived.
    deferred_on_a: usize,
    payloads: Vec<String>,
}

impl Release {
    fn received(&self, payload: &str) -> bool {
        self.payloads.iter().any(|p| p == payload)
    }

    fn received_all(&self, prefix: &str, count: usize) -> usize {
        (0..count)
            .filter(|i| self.received(&format!("{prefix}-{i}")))
            .count()
    }
}

/// Bob's message only B holds, then `commits` of alice's commits on A, each
/// followed by one of bob's messages.
async fn old_app_message(commits: usize) -> Release {
    let mut group = Group::new("old-app").await;
    group.bob_says("late", true).await;
    for i in 0..commits {
        group.alice_commits(false).await;
        group.bob_says(&format!("after-{i}"), false).await;
    }
    group.release_on_a_then_b().await
}

/// A run of `run` messages from bob that only B holds, followed by `after` of
/// his messages on A, all in one epoch.
async fn sender_run(run: usize, after: usize) -> Release {
    let mut group = Group::new("sender-run").await;
    for i in 0..run {
        group.bob_says(&format!("late-{i}"), true).await;
    }
    for i in 0..after {
        group.bob_says(&format!("next-{i}"), false).await;
    }
    group.release_on_a_then_b().await
}

/// Alice's commit only B holds, then `rounds` of one of bob's messages and
/// one of alice's commits on A, then bob's `tail`: carol climbs `rounds`
/// epochs once the gap fills.
async fn missing_commit_chain(rounds: usize) -> Release {
    let mut group = Group::new("missing-chain").await;
    group.alice_commits(true).await;
    for i in 0..rounds {
        group.bob_says(&format!("after-{i}"), false).await;
        group.alice_commits(false).await;
    }
    group.bob_says("tail", false).await;
    group.release_on_a_then_b().await
}

/// Alice and bob commit concurrently at one epoch and the selector adopts
/// one. `b_holds_alices` picks whose commit only B holds. Then `rounds` of
/// one of alice's commits and one of bob's messages on the adopted branch go
/// to A, then bob's `tail`.
async fn rival_commit(b_holds_alices: bool, rounds: usize) -> Release {
    let mut group = Group::new("rival").await;
    let before = group.queued_ids();
    let alice_pending = group.alice.self_update().await;
    let alice_commit = group.queued_since(&before);
    let before = group.queued_ids();
    let bob_pending = group.bob.self_update().await;
    let bob_commit = group.queued_since(&before);
    assert_eq!((alice_commit.len(), bob_commit.len()), (1, 1));
    group.alice.confirm(alice_pending).await;
    group.bob.confirm(bob_pending).await;
    let late = if b_holds_alices {
        alice_commit
    } else {
        bob_commit
    };
    group.b_only.extend(late.into_iter().map(|m| m.id));
    group.settle_online().await;
    group.settle_online().await;
    for i in 0..rounds {
        group.alice_commits(false).await;
        group.bob_says(&format!("after-{i}"), false).await;
    }
    group.bob_says("tail", false).await;
    group.release_on_a_then_b().await
}

/// Alice and bob fork while partitioned. Alice's branch (`alice_depth`
/// commits) reaches A; bob's longer branch reaches only B. They heal before
/// carol is released, and bob sends `tail`. Also returns whether alice and bob
/// themselves agree.
async fn deep_fork(alice_depth: usize) -> (Release, bool) {
    let mut group = Group::new("deep-fork").await;
    let (alice_id, bob_id, carol_id) = (group.alice.bus_id, group.bob.bus_id, group.carol.bus_id);
    let mut alice_branch = Vec::new();
    group.bus.set_partition(Some(vec![alice_id, carol_id]));
    for _ in 0..alice_depth {
        let before = group.queued_ids();
        let pending = group.alice.self_update().await;
        alice_branch.extend(group.queued_since(&before));
        group.alice.confirm(pending).await;
        group.bus.deliver_all();
    }
    let mut bob_branch = Vec::new();
    group.bus.set_partition(Some(vec![bob_id, carol_id]));
    for _ in 0..=alice_depth {
        let before = group.queued_ids();
        let pending = group.bob.self_update().await;
        let commit = group.queued_since(&before);
        group.b_only.extend(commit.iter().map(|m| m.id.clone()));
        bob_branch.extend(commit);
        group.bob.confirm(pending).await;
        group.bus.deliver_all();
    }
    group.bus.set_partition(None);
    for msg in bob_branch {
        group.bus.inject(alice_id, msg);
    }
    for msg in alice_branch {
        group.bus.inject(bob_id, msg);
    }
    for _ in 0..3 {
        group.alice.tick().await;
        group.bob.tick().await;
    }
    let online_agree = group.alice.canonical_group_snapshot().group_context_sha256
        == group.bob.canonical_group_snapshot().group_context_sha256;
    group.bob_says("tail", false).await;
    (group.release_on_a_then_b().await, online_agree)
}

#[tokio::test]
async fn late_app_message_opens_five_epochs_back_but_not_six() {
    let mut group = Group::new("late-app-epochs").await;
    group.bob_says("six-back", true).await;
    group.alice_commits(false).await;
    group.bob_says("five-back", true).await;
    for _ in 0..PAST_EPOCHS {
        group.alice_commits(false).await;
    }
    let r = group.release_on_a_then_b().await;
    assert!(r.agrees_with_alice);
    assert!(r.received("five-back"), "{r:?}");
    assert!(!r.received("six-back"), "{r:?}");
}

#[tokio::test]
async fn late_sender_message_opens_99_generations_back_but_not_100() {
    // late-0 and late-1 are 100 and 99 generations behind bob's last message.
    let after = OUT_OF_ORDER_TOLERANCE - 1;
    let r = sender_run(2, after).await;
    assert_eq!(r.received_all("next", after), after);
    assert!(r.received("late-1"), "{r:?}");
    assert!(!r.received("late-0"), "{r:?}");
}

#[tokio::test]
async fn late_gap_commit_releases_every_event_deferred_behind_it() {
    let mut group = Group::new("late-gap-commit").await;
    group.alice_commits(true).await;
    for i in 0..STALL_BACKFILL_THRESHOLD {
        group.bob_says(&format!("after-{i}"), false).await;
    }
    let r = group.release_on_a_then_b().await;
    // Every A event behind the gap was unreadable on arrival: enough for the
    // app to arm a full-history backfill. The gap commit then releases them.
    assert_eq!(r.epoch_before_late, 1);
    assert_eq!(r.deferred_on_a, STALL_BACKFILL_THRESHOLD);
    assert_eq!(
        r.received_all("after", STALL_BACKFILL_THRESHOLD),
        STALL_BACKFILL_THRESHOLD
    );
    assert!(r.agrees_with_alice);
}

#[tokio::test]
async fn late_rival_commit_is_adjudicated_as_online_members_did() {
    let mut held_behind_late_winner = 0;
    for b_holds_alices in [true, false] {
        let r = rival_commit(b_holds_alices, PAST_EPOCHS).await;
        assert!(
            r.agrees_with_alice,
            "b_holds_alices={b_holds_alices}: {r:?}"
        );
        assert_eq!(r.received_all("after", PAST_EPOCHS), PAST_EPOCHS);
        assert!(r.received("tail"));
        // When B holds the winner, carol applies the loser and defers the
        // winner's whole branch until it arrives.
        if r.epoch_before_late == 2 {
            held_behind_late_winner += 1;
            assert_eq!(r.deferred_on_a, 2 * PAST_EPOCHS + 1);
        }
    }
    assert_eq!(held_behind_late_winner, 1);
}

#[tokio::test]
async fn fork_at_the_rewind_horizon_resolves_the_same_after_release() {
    let (r, online_agree) = deep_fork(PAST_EPOCHS).await;
    assert!(online_agree);
    assert!(r.agrees_with_alice, "{r:?}");
    assert!(r.received("tail"));
}

#[tokio::test]
#[ignore = "sweep: run with --ignored --nocapture"]
async fn sweep_old_app_message_epochs() {
    for commits in 0..=8 {
        let r = old_app_message(commits).await;
        eprintln!("old-app commits={commits} absorbed={}", r.received("late"));
        assert_eq!(r.received("late"), commits <= PAST_EPOCHS, "{r:?}");
        assert!(r.agrees_with_alice);
    }
}

#[tokio::test]
#[ignore = "sweep: run with --ignored --nocapture"]
async fn sweep_sender_runs() {
    for (run, after) in [
        (1, 0),
        (1, 50),
        (1, 99),
        (1, 100),
        (1, 150),
        (10, 90),
        (10, 95),
        (50, 60),
        (101, 0),
        (150, 1),
    ] {
        let r = sender_run(run, after).await;
        let absorbed = r.received_all("late", run);
        eprintln!("sender-run run={run} after={after} absorbed={absorbed}/{run}");
        // With nothing after it the run arrives in order; otherwise late-i is
        // `run - 1 - i + after` generations behind bob's last message.
        let expected = if after == 0 {
            run
        } else {
            (0..run)
                .filter(|i| run - 1 - i + after < OUT_OF_ORDER_TOLERANCE)
                .count()
        };
        assert_eq!(absorbed, expected);
        assert_eq!(r.received_all("next", after), after);
    }
}

#[tokio::test]
#[ignore = "sweep: run with --ignored --nocapture"]
async fn sweep_forward_jump() {
    for run in [
        MAX_FORWARD_DISTANCE - 1,
        MAX_FORWARD_DISTANCE,
        MAX_FORWARD_DISTANCE + 1,
    ] {
        let r = sender_run(run, 1).await;
        let absorbed = r.received_all("late", run);
        eprintln!(
            "forward-jump run={run} next_received={} absorbed={absorbed}/{run}",
            r.received("next-0")
        );
        // Past the forward distance bob's A message cannot be opened, so the
        // late run arrives in order and opens whole.
        let jumps = run <= MAX_FORWARD_DISTANCE;
        assert_eq!(r.received("next-0"), jumps);
        let expected = if jumps {
            OUT_OF_ORDER_TOLERANCE - 1
        } else {
            run
        };
        assert_eq!(absorbed, expected);
    }
}

#[tokio::test]
#[ignore = "sweep: run with --ignored --nocapture"]
async fn sweep_missing_commit_chain() {
    // An event sealed d epochs above the gap opens only for d <= 31: each
    // epoch climbed charges every still-unreadable row one of its 32 live
    // retry contexts.
    for rounds in [8, 30, 31, 32] {
        let r = missing_commit_chain(rounds).await;
        eprintln!(
            "missing-chain rounds={rounds} received={}/{rounds} tail={} agrees={} deferred_on_a={}",
            r.received_all("after", rounds),
            r.received("tail"),
            r.agrees_with_alice,
            r.deferred_on_a
        );
        assert_eq!(r.epoch_before_late, 1);
        assert_eq!(r.deferred_on_a, 2 * rounds + 1);
        assert_eq!(r.received("tail"), rounds <= 30, "{r:?}");
        assert_eq!(r.received_all("after", rounds), rounds.min(31));
    }
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
#[ignore = "sweep: run with --ignored --nocapture"]
async fn sweep_missing_commit_deferral_cap() {
    const ROWS: usize = 16;
    for after in [ROWS - 1, ROWS, ROWS + 1, 2 * ROWS] {
        let mut group = Group::new("missing-commit-cap").await;
        group
            .carol
            .set_deferred_peel_limits_for_tests(ROWS, 16 * 1024 * 1024, 64 * 1024 * 1024);
        group.alice_commits(true).await;
        for i in 0..after {
            group.bob_says(&format!("after-{i}"), false).await;
        }
        let r = group.release_on_a_then_b().await;
        let received = r.received_all("after", after);
        eprintln!("missing-commit rows={ROWS} after={after} received={received}/{after}");
        // Rows past the cap are refused, not stored; only a refetch returns them.
        assert_eq!(received, after.min(ROWS));
    }
}

#[tokio::test]
#[ignore = "sweep: run with --ignored --nocapture"]
async fn sweep_rival_commit() {
    for b_holds_alices in [true, false] {
        for rounds in [0, 1, 4, 5, 6, 8] {
            let r = rival_commit(b_holds_alices, rounds).await;
            eprintln!(
                "rival b_holds_alices={b_holds_alices} rounds={rounds} agrees={} before_late={}",
                r.agrees_with_alice, r.epoch_before_late
            );
            assert!(r.agrees_with_alice, "{r:?}");
            assert_eq!(r.received_all("after", rounds), rounds);
            assert!(r.received("tail"));
        }
    }
}

#[tokio::test]
#[ignore = "sweep: run with --ignored --nocapture"]
async fn sweep_deep_fork() {
    for depth in 1..=7 {
        let (r, online_agree) = deep_fork(depth).await;
        eprintln!(
            "deep-fork alice_depth={depth} online_agree={online_agree} carol_agrees_with_alice={}",
            r.agrees_with_alice
        );
        // Past the horizon alice keeps her branch; carol, who saw the same
        // order, does too.
        assert_eq!(online_agree, depth <= PAST_EPOCHS);
        assert!(r.agrees_with_alice, "{r:?}");
    }
}
