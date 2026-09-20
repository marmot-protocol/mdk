//! Publication barriers pin the navigation regression without latency thresholds
//! tied to a particular device. Performance measurements use disk-backed encrypted
//! fixtures (not tmpfs); workstation measurements are not iPhone benchmarks.
use super::*;

#[tokio::test]
async fn return_to_latest_from_history_uses_send_checkpoint_before_relay_release() {
    let h = History::new(60).await;
    let runtime = MarmotAppRuntime::new(h.app.clone());
    let mut window = runtime
        .open_conversation_window(
            "alice",
            &h.group,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Message(format!("{:064x}", 10)),
                limit: 10,
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while window.snapshot.presentation.header.epoch.is_none() {
            window.snapshot = window.recv().await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
    h.relay.block_next_publish();
    let sender = runtime.clone();
    let group = h.group.clone();
    let sending = tokio::spawn(async move {
        sender
            .send_message("alice", &group, b"latest checkpoint message".to_vec())
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), h.relay.wait_for_blocked_publish())
        .await
        .unwrap();
    // Wait for a background read queued behind publication, so navigation must
    // supersede that read rather than relying on favorable executor ordering.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if runtime
                .app_performance_snapshot()
                .runtime_operations
                .iter()
                .any(|metric| {
                    metric.operation == crate::RuntimePerformanceOperation::ConversationCaptureQueue
                        && metric.in_flight > 0
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let handle = window.window_handle();
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match handle.return_to_latest(&window.snapshot.revision).await {
                Ok(snapshot) => break snapshot,
                Err(crate::ConversationWindowError::StaleWindow) => {
                    window.snapshot = window.recv().await.unwrap().unwrap();
                }
                Err(error) => panic!("navigation failed: {error:?}"),
            }
        }
    })
    .await;
    h.relay.release_publish();
    sending.await.unwrap().unwrap();
    let snapshot = result.expect("navigation waited for relay publication");
    assert!(
        snapshot
            .page
            .page()
            .messages
            .iter()
            .any(|row| row.plaintext == "latest checkpoint message"
                && row.source_message_id_hex.is_none())
    );
    runtime.shutdown_and_close().await.unwrap();
}
