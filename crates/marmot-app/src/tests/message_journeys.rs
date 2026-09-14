//! Send boundaries exercised against file-backed SQLCipher and the real account runtime.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

const CHILD_ROOT: &str = "MDK_MESSAGE_JOURNEY_ROOT";
const CHILD_PHASE: &str = "MDK_MESSAGE_JOURNEY_PHASE";
const CRASH_EXIT: i32 = 73;

struct CrashRelay {
    inner: ScriptedPushRelayClient,
    root: PathBuf,
    phase: String,
    armed: AtomicBool,
}

#[async_trait]
impl crate::relay_plane::DirectoryRelayFetcher for CrashRelay {
    async fn fetch_directory_events(
        &self,
        request: crate::relay_plane::DirectoryFetchRequest,
    ) -> Result<Vec<crate::relay_plane::DirectoryRelayEventRecord>, String> {
        self.inner.fetch_directory_events(request).await
    }
}

#[async_trait]
impl NostrRelayClient for CrashRelay {
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.inner.subscribe(subscription).await
    }

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.inner.unsubscribe(subscription).await
    }

    async fn unsubscribe_account(
        &self,
        account: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.inner.unsubscribe_account(account).await
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        if !self.armed.load(Ordering::SeqCst) {
            return self
                .inner
                .publish_event(endpoints, event, required_acks)
                .await;
        }
        fs_private::write_private(
            &self.root.join("attempt.json"),
            &serde_json::to_vec(event).unwrap(),
        )
        .unwrap();
        if self.phase == "durable" {
            // The account has persisted the exact fanout, but no relay accepted it.
            std::process::exit(CRASH_EXIT);
        }
        let result = self
            .inner
            .publish_event(endpoints, event, required_acks)
            .await;
        if self.phase == "relay" {
            assert!(result.is_ok());
            fs_private::write_private(
                &self.root.join("accepted.json"),
                &serde_json::to_vec(event).unwrap(),
            )
            .unwrap();
            // Relay acceptance survives independently of the sender's missing OK.
            std::process::exit(CRASH_EXIT);
        }
        result
    }
}

#[tokio::test]
async fn message_journey_crash_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let phase = std::env::var(CHILD_PHASE).unwrap();
    AccountHome::open(&root).create_account("sender").unwrap();
    let relay = Arc::new(CrashRelay {
        inner: ScriptedPushRelayClient::default(),
        root: root.clone(),
        phase: phase.clone(),
        armed: AtomicBool::new(false),
    });
    let app =
        MarmotApp::with_relay(&root, "wss://journey.example").with_test_relay_client(relay.clone());
    let mut client = app.client("sender").await.unwrap();
    let group = client.create_group("journey", &[]).await.unwrap();
    fs_private::write_private(&root.join("group"), group.as_slice()).unwrap();
    relay.armed.store(true, Ordering::SeqCst);
    let mut updates = 0;
    client
        .send_with_local_projection(&group, b"one interrupted send", |_| {
            updates += 1;
            if (phase == "projection" && updates == 1) || (phase == "response" && updates == 2) {
                // Exit without destructors or graceful shutdown, before the send returns.
                std::process::exit(CRASH_EXIT);
            }
        })
        .await
        .unwrap();
    panic!("crash boundary was not reached");
}

#[tokio::test]
async fn message_journey_crash_reopen() {
    for phase in ["projection", "durable", "relay", "response"] {
        let root = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::message_journeys::message_journey_crash_child",
                "--nocapture",
            ])
            .env(CHILD_ROOT, root.path())
            .env(CHILD_PHASE, phase)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{phase}: crash child stalled");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(
            status.code(),
            Some(CRASH_EXIT),
            "{phase}: child must reach the selected boundary"
        );
        let group = GroupId::new(std::fs::read(root.path().join("group")).unwrap());
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(root.path(), "wss://journey.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("sender").await.unwrap();
        client.note_connectivity_restored().unwrap();
        client.retry_group_convergence(&group).await.unwrap();
        client.retry_group_convergence(&group).await.unwrap();
        let timeline = app
            .timeline_messages_with_query(
                "sender",
                TimelineMessageQuery {
                    group_id_hex: Some(hex::encode(group.as_slice())),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            timeline.messages.len(),
            1,
            "{phase}: reopening must not duplicate the bubble"
        );
        let message = &timeline.messages[0];
        if phase == "projection" {
            assert!(
                message.source_message_id_hex.is_none(),
                "optimistic projection is not publication evidence"
            );
            assert!(
                relay.published_event_ids().is_empty(),
                "no durable send was accepted"
            );
        } else {
            let attempted: NostrTransportEvent =
                serde_json::from_slice(&std::fs::read(root.path().join("attempt.json")).unwrap())
                    .unwrap();
            assert_eq!(
                message.source_message_id_hex.as_deref(),
                Some(attempted.id.as_str()),
                "{phase}: recover the original exact event"
            );
            assert!(message.invalidation_status.is_none());
            let publishes = relay.published_event_ids();
            assert!(publishes.iter().all(|id| id == &attempted.id));
            let expected_publishes = match phase {
                "response" => 0,
                "durable" | "relay" => 1,
                _ => unreachable!(),
            };
            assert_eq!(
                publishes.len(),
                expected_publishes,
                "{phase}: retry only unconfirmed publications, exactly once"
            );
            if phase == "relay" {
                let accepted: NostrTransportEvent = serde_json::from_slice(
                    &std::fs::read(root.path().join("accepted.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    accepted.id, attempted.id,
                    "retry after an unknown outcome must preserve relay identity"
                );
            }
        }
        drop(client);
        app.close_storage().unwrap();
    }
}

#[tokio::test]
async fn message_journey_queue_cancel() {
    let root = tempfile::tempdir().unwrap();
    AccountHome::open(root.path())
        .create_account("sender")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(root.path(), "wss://journey.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("sender").await.unwrap();
    let group = client.create_group("journey", &[]).await.unwrap();
    drop(client);
    let runtime = app.runtime();
    runtime.reconcile_accounts().await.unwrap();
    relay.block_next_publish();
    let sender = runtime.clone();
    let first_group = group.clone();
    let first = tokio::spawn(async move {
        sender
            .send_message("sender", &first_group, b"first".to_vec())
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish())
        .await
        .unwrap();
    let snapshot = runtime.app_performance_snapshot();
    assert_eq!(snapshot.outbound_message_local_projection.successes, 1);
    assert_eq!(snapshot.outbound_message_response.attempts, 0);
    assert_eq!(
        snapshot.host_outbound_message_visible.attempts, 0,
        "SDK projection must not invent host rendering"
    );
    let second = runtime.send_message("sender", &group, b"second".to_vec());
    let mut second = std::pin::pin!(second);
    assert!(
        tokio::time::timeout(Duration::from_millis(60), &mut second)
            .await
            .is_err()
    );
    assert_eq!(
        runtime
            .app_performance_snapshot()
            .outbound_message_queue_wait
            .attempts,
        1
    );
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    relay.release_publish();
    tokio::time::timeout(Duration::from_secs(5), &mut second)
        .await
        .unwrap()
        .unwrap();
    let snapshot = runtime.app_performance_snapshot();
    assert_eq!(snapshot.outbound_message_queue_wait.attempts, 2);
    assert!(snapshot.outbound_message_queue_wait.duration_ms.sum_ms >= 50);
    assert_eq!(snapshot.outbound_message_local_projection.successes, 2);
    assert_eq!(snapshot.outbound_message_local_accept.successes, 2);
    assert_eq!(snapshot.outbound_message_publish.successes, 2);
    assert_eq!(
        snapshot.outbound_message_response.successes, 1,
        "cancelled host received no response"
    );
    let timeline = app
        .timeline_messages_with_query(
            "sender",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group.as_slice())),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(timeline.messages.len(), 2);
    assert!(
        timeline
            .messages
            .iter()
            .all(|m| m.source_message_id_hex.is_some())
    );
    let echo = relay
        .published_events
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    let route = &echo
        .tags
        .iter()
        .find(|tag| tag.first().is_some_and(|name| name == "h"))
        .unwrap()[1];
    // Own relay echoes are suppressed before ingestion. A fresh signed probe
    // exercises the live-delivery measurement without inventing a peer message.
    let inbound = epoch_gap_probe(route, crate::unix_now_seconds(), "journey-metric");
    let received = runtime
        .shared_services()
        .relay_plane()
        .handle_relay_event_for_test(NostrRelayEvent {
            endpoint: TransportEndpoint("wss://journey.example".into()),
            subscription_id: None,
            event: inbound,
        })
        .await
        .unwrap();
    assert_eq!(received, 1);
    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime
            .app_performance_snapshot()
            .inbound_delivery_projection
            .successes
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("live ingestion must record its projection handoff");
    assert_eq!(
        runtime
            .app_performance_snapshot()
            .host_inbound_message_visible
            .attempts,
        0
    );
    runtime.shutdown_and_close().await.unwrap();
}
