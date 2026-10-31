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
}

impl OfflineQueue {
    /// Create the group and publish one send while online.
    async fn online() -> Self {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("sender")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://offline-queue.example")
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
        }
    }

    /// Admit one text send while the relay fails as `failure`, and let the worker attempt it.
    async fn send_offline(&mut self, failure: OfflineFailure) {
        match failure {
            OfflineFailure::Unavailable => {
                self.relay.allow_publishes();
                self.relay.fail_publishes_as_unavailable();
            }
            OfflineFailure::PossiblyExposed => {
                self.relay.allow_publishes();
                self.relay.fail_publishes_as_possibly_exposed();
            }
        }
        let index = self.offline_sends;
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
        tokio::time::sleep(Duration::from_millis(400)).await;
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

    /// Require every send to publish within `budget`, each accepted once and in send order.
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
            assert_eq!(
                count, 1,
                "{context}: {content} must be accepted exactly once"
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
            "{context}: queued sends must publish in send order: {rows:?} at {positions:?}"
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
