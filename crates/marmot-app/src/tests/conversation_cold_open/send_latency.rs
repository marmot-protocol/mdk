//! Opt-in, file-backed send-path measurements. No latency assertions: these are
//! host diagnostics, not iOS performance budgets. Fixtures never use real relays.
use super::*;
use std::sync::Mutex;
use std::time::Instant;
use storage_sqlite::SqliteTimingOperation;

fn report(name: &str, samples: &mut [Duration]) {
    samples.sort_unstable();
    let millis = |value: Duration| value.as_secs_f64() * 1_000.0;
    eprintln!(
        "send_latency phase={name} n={} p50_ms={:.3} p95_ms={:.3} max_ms={:.3}",
        samples.len(),
        millis(samples[samples.len() / 2]),
        millis(samples[(samples.len() * 95 / 100).min(samples.len() - 1)]),
        millis(*samples.last().unwrap()),
    );
}

#[tokio::test]
#[ignore = "opt-in file-backed latency investigation; run serially with --nocapture"]
async fn measure_draft_save_latency() {
    let h = History::new(200).await;
    let group = hex::encode(h.group.as_slice());
    let storage = h.app.account_storage("alice").unwrap();
    let timings = Arc::new(Mutex::new(Vec::new()));
    let captured = timings.clone();
    storage.set_timing_observer(Some(Arc::new(move |operation, elapsed, success| {
        captured.lock().unwrap().push((operation, elapsed, success));
    })));
    for bytes in [0, 4 * 1024 * 1024, 16 * 1024 * 1024] {
        let mut selected = h.app.selected_message_draft("alice", &group).unwrap();
        let attachments = if bytes == 0 {
            vec![]
        } else {
            vec![crate::MessageDraftAttachment {
                id: "attachment".into(),
                file_name: "fixture.bin".into(),
                media_type: "application/octet-stream".into(),
                plaintext: vec![42; bytes],
                dim: None,
                thumbhash: None,
                duration_seconds: None,
                waveform_samples: vec![],
            }]
        };
        let mut saves = Vec::new();
        let mut reads = Vec::new();
        timings.lock().unwrap().clear();
        for sample in 0..30 {
            // Include the app-owned attachment clone, as the FFI caller also
            // transfers owned bytes. Only the caption changes between saves.
            let start = Instant::now();
            selected = h
                .app
                .save_message_draft_if_revision(
                    "alice",
                    &selected.revision,
                    &format!("draft {sample}"),
                    None,
                    attachments.clone(),
                )
                .unwrap();
            saves.push(start.elapsed());
            let start = Instant::now();
            let read = h.app.selected_message_draft("alice", &group).unwrap();
            assert!(read.revision == selected.revision);
            reads.push(start.elapsed());
        }
        eprintln!("send_latency attachment_bytes={bytes}");
        report("draft_save", &mut saves);
        report("draft_selected_read", &mut reads);
        for operation in [
            SqliteTimingOperation::ConnectionWait,
            SqliteTimingOperation::WriteBegin,
            SqliteTimingOperation::Transaction,
        ] {
            let mut samples: Vec<_> = timings
                .lock()
                .unwrap()
                .iter()
                .filter(|(op, _, _)| *op == operation)
                .map(|(_, duration, success)| {
                    assert!(*success);
                    *duration
                })
                .collect();
            if !samples.is_empty() {
                report(&format!("sqlite_{operation:?}"), &mut samples);
            }
        }
    }
    storage.set_timing_observer(None);
    h.app.close_storage().unwrap();
}

#[tokio::test]
#[ignore = "opt-in controlled transaction contention; run serially with --nocapture"]
async fn measure_draft_save_under_transaction_contention() {
    let h = History::new(200).await;
    let group = hex::encode(h.group.as_slice());
    let selected = h.app.selected_message_draft("alice", &group).unwrap();
    let storage = h.app.account_storage("alice").unwrap();
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        cgka_traits::StorageProvider::with_transaction(&storage, |_| {
            held_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            Ok::<_, cgka_traits::StorageError>(())
        })
        .unwrap();
    });
    held_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let app = h.app.clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let saver = std::thread::spawn(move || {
        let start = Instant::now();
        started_tx.send(()).unwrap();
        app.save_message_draft_if_revision("alice", &selected.revision, "contended", None, vec![])
            .unwrap();
        start.elapsed()
    });
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    // Deliberate workload, not a performance threshold or synchronization guess:
    // the holder signalled transaction ownership before the save was started.
    std::thread::sleep(Duration::from_millis(500));
    let blocked = !saver.is_finished();
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    report(
        "draft_save_500ms_transaction_hold",
        &mut [saver.join().unwrap()],
    );
    assert!(
        blocked,
        "draft save must respect the outstanding transaction"
    );
    h.app.close_storage().unwrap();
}

#[tokio::test]
#[ignore = "opt-in pending-window latency with relay barrier; run serially with --nocapture"]
async fn measure_pending_window_latency() {
    for history in [0, 2_000] {
        let h = History::new(history).await;
        let runtime = MarmotAppRuntime::new(h.app.clone());
        let mut window = runtime
            .open_conversation_window(
                "alice",
                &h.group,
                ConversationOpenQuery {
                    target: ConversationOpenTarget::Latest,
                    limit: 50,
                },
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            while window.snapshot.presentation.header.epoch.is_none() {
                window.snapshot = window.recv().await.unwrap().unwrap();
            }
        })
        .await
        .unwrap();
        let group_hex = hex::encode(h.group.as_slice());
        let before = runtime.app_performance_snapshot();
        let mut visible = Vec::new();
        let mut responses = Vec::new();
        for sample in 0..10 {
            let text = format!("latency fixture {sample}");
            let selected = runtime.selected_message_draft("alice", &group_hex).unwrap();
            let revision = runtime
                .save_message_draft_if_revision("alice", &selected.revision, &text, None, vec![])
                .unwrap()
                .revision;
            h.relay.block_next_publish();
            let sender = runtime.clone();
            let group = h.group.clone();
            let start = Instant::now();
            let send = tokio::spawn(async move {
                sender
                    .send_message_draft("alice", &group, revision, vec![])
                    .await
            });
            let pending = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let snapshot = window.recv().await.unwrap().unwrap();
                    if snapshot
                        .page
                        .page()
                        .messages
                        .iter()
                        .any(|row| row.plaintext == text)
                    {
                        break start.elapsed();
                    }
                }
            })
            .await;
            let barrier =
                tokio::time::timeout(Duration::from_secs(10), h.relay.wait_for_blocked_publish())
                    .await;
            let still_sending = !send.is_finished();
            // Always release before asserting so a failed observation cannot
            // strand a worker in the injected transport barrier.
            h.relay.release_publish();
            let result = tokio::time::timeout(Duration::from_secs(10), send)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            responses.push(start.elapsed());
            visible.push(pending.expect("pending row must arrive before relay release"));
            barrier.unwrap();
            assert!(still_sending);
            assert_eq!(result.published, 1);
        }
        eprintln!("send_latency history_rows={history}");
        report("submit_to_pending_window", &mut visible);
        report("submit_to_response_including_barrier", &mut responses);
        let snapshot = runtime.app_performance_snapshot();
        for (name, metric) in [
            ("worker_queue", snapshot.outbound_message_queue_wait),
            (
                "local_projection",
                snapshot.outbound_message_local_projection,
            ),
            ("local_accept", snapshot.outbound_message_local_accept),
        ] {
            eprintln!(
                "send_latency phase={name} attempts={} sum_ms={}",
                metric.attempts, metric.duration_ms.sum_ms
            );
        }
        for metric in snapshot.runtime_operations {
            let name = metric.operation.as_str();
            if matches!(
                name,
                "conversation_capture_queue"
                    | "conversation_capture"
                    | "conversation_presentation"
                    | "storage_connection_wait"
                    | "storage_transaction"
                    | "storage_write_begin"
            ) {
                let previous = before
                    .runtime_operations
                    .iter()
                    .find(|old| old.operation == metric.operation);
                eprintln!(
                    "send_latency phase={name} completed={} sum_ms={}",
                    metric.completed - previous.map_or(0, |old| old.completed),
                    metric.duration_ms.sum_ms - previous.map_or(0, |old| old.duration_ms.sum_ms)
                );
            }
        }
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "opt-in worker head-of-line measurement; run serially with --nocapture"]
async fn measure_send_queued_behind_blocked_publish() {
    let h = History::new(200).await;
    let runtime = MarmotAppRuntime::new(h.app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let group_hex = hex::encode(h.group.as_slice());
    h.relay.block_next_publish();
    let sender = runtime.clone();
    let group = h.group.clone();
    let first = tokio::spawn(async move {
        sender
            .send_message("alice", &group, b"first send".to_vec())
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), h.relay.wait_for_blocked_publish())
        .await
        .unwrap();
    // These synchronous app APIs bypass the worker RPC. Test them while the
    // worker is actually suspended in relay publication, not before it starts.
    let start = Instant::now();
    let selected = runtime.selected_message_draft("alice", &group_hex).unwrap();
    let saved = runtime
        .save_message_draft_if_revision("alice", &selected.revision, "second send", None, vec![])
        .unwrap();
    report(
        "draft_read_and_save_during_blocked_publish",
        &mut [start.elapsed()],
    );
    let second = runtime.send_message_draft("alice", &h.group, saved.revision, vec![]);
    let mut second = std::pin::pin!(second);
    let start = Instant::now();
    let held = tokio::time::timeout(Duration::from_millis(500), &mut second).await;
    let before_release = runtime.app_performance_snapshot();
    h.relay.release_publish();
    assert!(
        held.is_err(),
        "second send should wait behind the first mutation"
    );
    assert_eq!(
        before_release.outbound_message_local_projection.successes, 1,
        "queued send has not produced its own pending projection"
    );
    tokio::time::timeout(Duration::from_secs(10), &mut second)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    report(
        "second_send_including_500ms_relay_hold",
        &mut [start.elapsed()],
    );
    let metric = runtime
        .app_performance_snapshot()
        .outbound_message_queue_wait;
    eprintln!(
        "send_latency phase=blocked_worker_queue attempts={} first_queue_ms={} second_queue_ms={}",
        metric.attempts,
        before_release
            .outbound_message_queue_wait
            .duration_ms
            .sum_ms,
        metric.duration_ms.sum_ms
            - before_release
                .outbound_message_queue_wait
                .duration_ms
                .sum_ms
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
#[ignore = "opt-in latest-window command racing send; run serially with --nocapture"]
async fn measure_latest_command_racing_send() {
    let h = History::new(200).await;
    let runtime = MarmotAppRuntime::new(h.app.clone());
    let mut window = runtime
        .open_conversation_window(
            "alice",
            &h.group,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Latest,
                limit: 50,
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        while window.snapshot.presentation.header.epoch.is_none() {
            window.snapshot = window.recv().await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
    let mut delayed = 0;
    let mut stale = 0;
    let mut accepted_delayed = 0;
    for sample in 0..10 {
        let text = format!("navigation race {sample}");
        let group_hex = hex::encode(h.group.as_slice());
        let selected = runtime.selected_message_draft("alice", &group_hex).unwrap();
        let saved = runtime
            .save_message_draft_if_revision("alice", &selected.revision, &text, None, vec![])
            .unwrap();
        h.relay.block_next_publish();
        // iOS enqueues follow-latest immediately before its outgoing send.
        // Exercise both executor orderings rather than relying on spawn order.
        let handle = window.window_handle();
        let revision = window.snapshot.revision.clone();
        let navigation = async move { handle.return_to_latest(&revision).await };
        let sender = runtime.clone();
        let group = h.group.clone();
        let sending = async move {
            sender
                .send_message_draft("alice", &group, saved.revision, vec![])
                .await
        };
        let (send, navigate) = if sample % 2 == 0 {
            let navigate = tokio::spawn(navigation);
            (tokio::spawn(sending), navigate)
        } else {
            let send = tokio::spawn(sending);
            (send, tokio::spawn(navigation))
        };
        let start = Instant::now();
        let pending = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                window.snapshot = window.recv().await.unwrap().unwrap();
                if window
                    .snapshot
                    .page
                    .page()
                    .messages
                    .iter()
                    .any(|row| row.plaintext == text)
                {
                    return start.elapsed();
                }
            }
        })
        .await;
        let barrier =
            tokio::time::timeout(Duration::from_secs(10), h.relay.wait_for_blocked_publish()).await;
        h.relay.release_publish();
        tokio::time::timeout(Duration::from_secs(10), send)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let navigated = tokio::time::timeout(Duration::from_secs(10), navigate)
            .await
            .unwrap()
            .unwrap();
        barrier.unwrap();
        let navigated = match navigated {
            Ok(snapshot) => Some(snapshot),
            Err(crate::runtime::ConversationWindowError::StaleWindow) => {
                stale += 1;
                None
            }
            Err(_) => panic!("unexpected navigation failure"),
        };
        eprintln!(
            "send_latency phase=latest_race_order send_enqueued_first={} navigation_stale={} pending_before_release={}",
            sample % 2 != 0,
            navigated.is_none(),
            pending.is_ok()
        );
        match pending {
            Ok(elapsed) => report("latest_race_pending_before_release", &mut [elapsed]),
            Err(_) => {
                delayed += 1;
                if let Some(navigated) = navigated {
                    accepted_delayed += 1;
                    assert!(
                        navigated
                            .page
                            .page()
                            .messages
                            .iter()
                            .any(|row| row.plaintext == text),
                        "delayed navigation must eventually include the sent message"
                    );
                }
            }
        }
    }
    eprintln!(
        "send_latency phase=latest_race samples=10 stale_commands={stale} pending_not_observed_within_500ms={delayed} accepted_commands_with_delayed_pending={accepted_delayed}"
    );
    runtime.shutdown_and_close().await.unwrap();
}
