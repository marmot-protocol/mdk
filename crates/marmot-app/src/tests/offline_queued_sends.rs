//! Offline-queued local sends after the host reports restored connectivity (mdk#2762).
//!
//! A device that drops offline mid-conversation keeps admitting text sends. Each one is
//! durably accepted and owned by the engine. When the host reports a usable network again,
//! every accepted send must publish promptly, once and in order, without another send,
//! a restart or a retry from the user.

use super::*;

/// How the relay fails while the device is offline.
#[derive(Clone, Copy, Debug)]
enum OfflineFailure {
    /// The dial fails before any frame leaves the device.
    Unavailable,
    /// A stale socket swallows the frame and no acknowledgement arrives.
    PossiblyExposed,
}

/// The sender's own sends in `group_id`, in send order, as `(plaintext, published id)`.
/// Tokens are `token-online` then `token-offline-<n>`, so token order is send order.
fn timeline_rows(app: &MarmotApp, group_id: &GroupId) -> Vec<(String, Option<String>)> {
    let mut messages: Vec<_> = app
        .timeline_messages_with_query(
            "sender",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group_id.as_slice())),
                ..TimelineMessageQuery::default()
            },
        )
        .unwrap()
        .messages
        .into_iter()
        .filter_map(|message| {
            let order = match message.client_token.as_deref()? {
                "token-online" => 0,
                token => {
                    token
                        .strip_prefix("token-offline-")?
                        .parse::<usize>()
                        .ok()?
                        + 1
                }
            };
            Some((order, message.plaintext, message.source_message_id_hex))
        })
        .collect();
    messages.sort_by_key(|(order, _, _)| *order);
    messages
        .into_iter()
        .map(|(_, plaintext, published)| (plaintext, published))
        .collect()
}

/// Wait until every row in `group_id` carries a published id, or `budget` runs out.
async fn wait_for_all_published(
    app: &MarmotApp,
    group_id: &GroupId,
    expected: usize,
    budget: Duration,
) -> bool {
    tokio::time::timeout(budget, async {
        loop {
            let rows = timeline_rows(app, group_id);
            if rows.len() == expected && rows.iter().all(|(_, published)| published.is_some()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .is_ok()
}

/// One sender, one group with no other members, and a running account worker.
struct OfflineQueue {
    _dir: tempfile::TempDir,
    relay: Arc<ScriptedPushRelayClient>,
    app: MarmotApp,
    runtime: MarmotAppRuntime,
    group_id: GroupId,
    offline_sends: usize,
    relay_count: usize,
}

impl OfflineQueue {
    /// Create the group on one relay and publish one send while online.
    async fn online() -> Self {
        Self::online_on(&["wss://offline-queue.example"]).await
    }

    /// Create the group on `relays` and publish one send while online.
    async fn online_on(relays: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("sender")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relays(
            dir.path(),
            relays.iter().map(|relay| (*relay).to_owned()).collect(),
        )
        .with_test_relay_client(relay.clone());
        let mut setup_client = app.client("sender").await.unwrap();
        let group_id = setup_client
            .create_group("offline queue", &[])
            .await
            .unwrap();
        drop(setup_client);
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        runtime
            .submit_text("sender", &group_id, "online".into(), "token-online".into())
            .await
            .unwrap();
        assert!(
            wait_for_all_published(&app, &group_id, 1, Duration::from_secs(5)).await,
            "the online send must publish: {:?}",
            timeline_rows(&app, &group_id)
        );
        Self {
            _dir: dir,
            relay,
            app,
            runtime,
            group_id,
            offline_sends: 0,
            relay_count: relays.len(),
        }
    }

    /// Admit one text send while the relay fails as `failure`, and let the worker attempt it.
    async fn send_offline(&mut self, failure: OfflineFailure) {
        // Switch failure modes without passing through an allowed state: a publish that
        // lands in such a gap would be accepted while the device is meant to be offline.
        // Unavailability is checked first, so it covers the moment both flags are set.
        let ordering = std::sync::atomic::Ordering::SeqCst;
        match failure {
            OfflineFailure::Unavailable => {
                self.relay.fail_publishes_as_unavailable();
                self.relay
                    .fail_publish_possibly_exposed
                    .store(false, ordering);
            }
            OfflineFailure::PossiblyExposed => {
                self.relay.fail_publishes_as_unavailable();
                self.relay.fail_publishes_as_possibly_exposed();
                self.relay.fail_publish_unavailable.store(false, ordering);
            }
        }
        let index = self.offline_sends;
        let earlier: std::collections::HashSet<String> =
            self.relay.attempted_event_ids().into_iter().collect();
        self.runtime
            .submit_text(
                "sender",
                &self.group_id,
                format!("offline {index}"),
                format!("token-offline-{index}"),
            )
            .await
            .unwrap();
        self.offline_sends += 1;
        // The relay records an attempt before it fails it, so this proves the send was
        // tried on every relay while offline rather than after connectivity returned. It
        // waits for this send's own event: with several relays, the previous send's later
        // attempts would satisfy a bare count and leave this one untried.
        let relays = self.relay_count;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let attempted = self.relay.attempted_event_ids();
                let tried_everywhere = attempted
                    .iter()
                    .filter(|id| !earlier.contains(*id))
                    .any(|id| attempted.iter().filter(|other| *other == id).count() >= relays);
                if tried_everywhere {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the worker must attempt the offline send on every relay while it fails");
        // The worker records the failure after the relay sees the attempt. A command queued
        // behind that pass returns once it is stored, so a restart cannot find the send
        // still mid-attempt.
        self.runtime.drain_in_flight_work().await.unwrap();
    }

    /// Restart the process while still offline, after the stored fanouts have failed
    /// `extra_attempts` more times, as a long offline period leaves them.
    async fn restart_after_long_offline(&mut self, extra_attempts: u32) {
        self.runtime.shutdown().await;
        {
            let client = self.app.client("sender").await.unwrap();
            let now_ms = u64::try_from(notifications::unix_now_ms()).unwrap();
            for mut fanout in client
                .runtime
                .session()
                .outbound_fanouts_for_group(&self.group_id)
                .unwrap()
            {
                for index in fanout.outstanding_target_indexes() {
                    let Some(failure) = fanout.target_failure(index).cloned() else {
                        continue;
                    };
                    for _ in 0..extra_attempts {
                        fanout.mark_attempt_started_at(index, now_ms).unwrap();
                        fanout
                            .record_target_failure(index, failure.clone())
                            .unwrap();
                    }
                }
                client
                    .runtime
                    .session()
                    .put_outbound_fanout(&fanout)
                    .unwrap();
            }
            drop(client);
        }
        self.runtime = MarmotAppRuntime::new(self.app.clone());
        self.runtime.reconcile_accounts().await.unwrap();
    }

    /// Report restored connectivity to the running account worker.
    async fn reconnect(&self) {
        self.runtime
            .notify_connectivity_restored()
            .await
            .expect("the host connectivity signal must reach the account worker");
    }

    /// Require every send to publish within `budget`, accepted at most once per relay and
    /// first accepted in send order.
    async fn assert_all_published_once_in_order(&self, budget: Duration, context: &str) {
        let published =
            wait_for_all_published(&self.app, &self.group_id, self.offline_sends + 1, budget).await;
        let rows = timeline_rows(&self.app, &self.group_id);
        assert!(
            published,
            "{context}: every offline-queued send must publish after reconnect; rows={rows:?}"
        );
        let published_ids = self.relay.published_event_ids();
        let mut positions = Vec::new();
        for (content, id) in &rows {
            let id = id.as_ref().unwrap();
            let count = published_ids
                .iter()
                .filter(|published| *published == id)
                .count();
            assert!(
                (1..=self.relay_count).contains(&count),
                "{context}: {content} must be accepted at most once per relay, got {count}"
            );
            positions.push(
                published_ids
                    .iter()
                    .position(|published| published == id)
                    .unwrap(),
            );
        }
        assert!(
            positions.windows(2).all(|pair| pair[0] < pair[1]),
            "{context}: queued sends must publish in send order: {rows:?} at {positions:?}; \
             attempts={:?}; published={:?}",
            self.relay
                .attempted_events()
                .iter()
                .zip(self.relay.attempted_routes())
                .map(|(event, (kind, routes))| (
                    event.id.chars().take(8).collect::<String>(),
                    kind,
                    routes.len()
                ))
                .collect::<Vec<_>>(),
            published_ids
                .iter()
                .map(|id| id.chars().take(8).collect::<String>())
                .collect::<Vec<_>>()
        );
    }

    /// The number of sends still waiting for a published id.
    fn unpublished(&self) -> usize {
        timeline_rows(&self.app, &self.group_id)
            .iter()
            .filter(|(_, published)| published.is_none())
            .count()
    }
}

/// Queue three sends that all fail as `failure`, reconnect, and require prompt publication.
async fn offline_batch_publishes_after_reconnect(failure: OfflineFailure) {
    let mut queue = OfflineQueue::online().await;
    for _ in 0..3 {
        queue.send_offline(failure).await;
    }
    queue.relay.allow_publishes();
    queue.reconnect().await;
    queue
        .assert_all_published_once_in_order(Duration::from_secs(8), &format!("{failure:?}"))
        .await;
    queue.runtime.shutdown().await;
}

/// Offline dials that never reached a relay all publish on the reconnect wake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_offline_batch_publishes_after_reconnect() {
    offline_batch_publishes_after_reconnect(OfflineFailure::Unavailable).await;
}

/// Sends swallowed by a stale socket while offline all publish on the reconnect wake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn possibly_exposed_offline_batch_publishes_after_reconnect() {
    offline_batch_publishes_after_reconnect(OfflineFailure::PossiblyExposed).await;
}

/// The reported shape: the first offline send fails its dial, later ones are swallowed by a
/// socket the device has not yet noticed is dead. None may wait behind another's clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_offline_failures_all_publish_after_reconnect() {
    let mut queue = OfflineQueue::online().await;
    queue.send_offline(OfflineFailure::Unavailable).await;
    for _ in 0..3 {
        queue.send_offline(OfflineFailure::PossiblyExposed).await;
    }
    queue.send_offline(OfflineFailure::Unavailable).await;
    queue.relay.allow_publishes();
    queue.reconnect().await;
    queue
        .assert_all_published_once_in_order(Duration::from_secs(8), "mixed")
        .await;
    queue.runtime.shutdown().await;
}

/// A long offline period backs the retry clocks off towards an hour, and a cold restart
/// keeps them. The stuck sends stay pending until the host reports connectivity, then all
/// publish at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn long_offline_batch_survives_restart_and_publishes_on_reconnect() {
    let mut queue = OfflineQueue::online().await;
    queue.send_offline(OfflineFailure::Unavailable).await;
    queue.send_offline(OfflineFailure::PossiblyExposed).await;
    queue.send_offline(OfflineFailure::PossiblyExposed).await;
    queue.restart_after_long_offline(7).await;
    queue.relay.allow_publishes();
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(
        queue.unpublished() > 0,
        "without a connectivity edge the restarted batch keeps its backed-off clocks"
    );
    queue.reconnect().await;
    queue
        .assert_all_published_once_in_order(Duration::from_secs(8), "after restart")
        .await;
    queue.runtime.shutdown().await;
}

/// A connectivity edge that arrives while the relay still fails spends one retry and keeps
/// every send; the next real edge releases them all, once each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_connectivity_edges_release_the_batch_once() {
    let mut queue = OfflineQueue::online().await;
    for _ in 0..3 {
        queue.send_offline(OfflineFailure::PossiblyExposed).await;
    }
    queue.reconnect().await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        queue.unpublished(),
        3,
        "a failing edge must keep every send"
    );
    queue.send_offline(OfflineFailure::PossiblyExposed).await;
    queue.relay.allow_publishes();
    queue.reconnect().await;
    queue
        .assert_all_published_once_in_order(Duration::from_secs(8), "second edge")
        .await;
    queue.reconnect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    queue
        .assert_all_published_once_in_order(Duration::from_secs(1), "a later edge")
        .await;
    queue.runtime.shutdown().await;
}

/// A group on two relays where one relay stays down after the device reconnects. The first
/// send meets quorum on the other relay and keeps retrying the dead one; the later sends
/// must not wait behind that secondary replication (mdk#2762).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sends_behind_a_quorum_met_send_publish_while_another_relay_stays_down() {
    let mut queue =
        OfflineQueue::online_on(&["wss://relay-a.example", "wss://relay-b.example"]).await;
    for _ in 0..3 {
        queue.send_offline(OfflineFailure::PossiblyExposed).await;
    }
    queue.relay.allow_publishes();
    queue
        .relay
        .make_endpoints_unavailable(&["wss://relay-b.example"]);
    queue.reconnect().await;
    queue
        .assert_all_published_once_in_order(Duration::from_secs(8), "relay b down")
        .await;
    queue.runtime.shutdown().await;
}

/// A cold start opens groups only seeded. An edge that lands before a group with retained
/// sends is hydrated must still wake that group's sends, not skip them (mdk#2762).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connectivity_wake_reaches_retained_sends_of_an_unhydrated_group() {
    let mut queue = OfflineQueue::online().await;
    for _ in 0..2 {
        queue.send_offline(OfflineFailure::PossiblyExposed).await;
    }
    queue.runtime.shutdown().await;

    // Open the account the way a cold start does: every group seeded, none hydrated.
    let plane = transport_nostr::MarmotRelayPlane::new(None, queue.relay.clone());
    let mut client = queue
        .app
        .local_client_with_relay_plane_and_hydration("sender", &plane, None, true, None)
        .await
        .unwrap();
    assert!(
        client
            .runtime
            .unhydrated_group_ids()
            .contains(&queue.group_id),
        "the cold open must leave the group seeded only"
    );
    assert!(
        client.runtime.outbound_fanouts().unwrap().is_empty(),
        "an unhydrated group hides its fanouts until it is hydrated"
    );
    let woken = client.note_connectivity_restored().unwrap();
    assert_eq!(woken, 2, "both retained sends must be woken");
    for fanout in client
        .runtime
        .session()
        .outbound_fanouts_for_group(&queue.group_id)
        .unwrap()
    {
        for index in fanout.outstanding_target_indexes() {
            assert_eq!(fanout.target_last_attempt_at_ms(index), None);
        }
    }
}

/// The group's retry cutoff follows the same barrier as the drain. A send that met quorum and
/// owes only another relay must not hold the group's wakeup on its own clock while a later
/// send behind it is already due (mdk#2762).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_cutoff_skips_a_send_that_only_owes_secondary_replication() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("sender")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays(
        dir.path(),
        vec![
            "wss://relay-a.example".to_owned(),
            "wss://relay-b.example".to_owned(),
        ],
    )
    .with_test_relay_client(relay.clone());
    let mut client = app.client("sender").await.unwrap();
    let group_id = client.create_group("cutoff", &[]).await.unwrap();

    relay.make_endpoints_unavailable(&["wss://relay-b.example"]);
    client.send(&group_id, b"met quorum").await.unwrap();
    relay.fail_publishes_as_unavailable();
    client.send(&group_id, b"behind it").await.unwrap();

    let fanouts = client
        .runtime
        .session()
        .outbound_fanouts_for_group(&group_id)
        .unwrap();
    assert_eq!(fanouts.len(), 2, "both sends keep a retained fanout");
    let first = fanouts[0].outcome();
    assert!(
        first.accepted_targets >= 1 && first.outstanding_targets >= 1,
        "the first send met quorum and still owes relay b"
    );
    let mut behind = fanouts[1].clone();
    assert!(behind.wake_targets_for_restored_connectivity() > 0);
    client
        .runtime
        .session()
        .put_outbound_fanout(&behind)
        .unwrap();

    assert_eq!(
        client
            .runtime
            .outbound_fanout_retry_delay_ms(&group_id)
            .unwrap(),
        Some(0),
        "the due send behind a quorum-met send sets the group's cutoff"
    );
}
