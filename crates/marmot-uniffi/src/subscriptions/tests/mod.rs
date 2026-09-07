use super::*;

#[test]
fn take_snapshot_recovers_from_poisoned_lock() {
    let snapshot = StdMutex::new(Some("initial"));
    let _ = std::panic::catch_unwind(|| {
        let _guard = snapshot.lock().unwrap();
        panic!("poison snapshot lock");
    });

    assert_eq!(take_snapshot(&snapshot), Some("initial"));
    assert_eq!(take_snapshot(&snapshot), None);
}

fn record(id: &str, plaintext: &str) -> TimelineMessageRecord {
    TimelineMessageRecord {
        message_id_hex: id.to_string(),
        source_message_id_hex: None,
        source_epoch: None,
        retention_seconds: None,
        retention_expires_at: None,
        direction: "received".to_string(),
        group_id_hex: "aa".to_string(),
        sender: "bb".to_string(),
        plaintext: plaintext.to_string(),
        kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        timeline_at: 1,
        received_at: 1,
        reply_to_message_id_hex: None,
        reply_preview: None,
        media: None,
        agent_text_stream: None,
        reactions: marmot_app::TimelineReactionSummary::default(),
        deleted: false,
        deleted_by_message_id_hex: None,
        invalidation_status: None,
    }
}

#[test]
fn cached_conversion_reuses_unchanged_rows_and_never_serves_stale_content() {
    fn page(messages: Vec<TimelineMessageRecord>) -> TimelinePage {
        TimelinePage {
            messages,
            has_more_before: false,
            has_more_after: false,
        }
    }

    let cache = StdMutex::new(HashMap::new());

    let first = convert_timeline_page_cached(
        &cache,
        page(vec![record("m1", "hello"), record("m2", "world")]),
    );
    assert_eq!(first.messages.len(), 2);
    assert_eq!(cache.lock().unwrap().len(), 2);

    // Unchanged rows come back identical from the cache.
    let second = convert_timeline_page_cached(
        &cache,
        page(vec![record("m1", "hello"), record("m2", "world")]),
    );
    assert_eq!(second.messages[0].plaintext, "hello");
    assert_eq!(second.messages[1].plaintext, "world");

    // A changed row is re-converted, never served stale: the new markdown
    // shows up in the tokens, not just the plaintext.
    let third = convert_timeline_page_cached(
        &cache,
        page(vec![record("m1", "edited **bold**"), record("m2", "world")]),
    );
    assert_eq!(third.messages[0].plaintext, "edited **bold**");
    assert!(!third.messages[0].content_tokens.blocks.is_empty());

    // Rows that leave the window are pruned so the cache tracks the
    // window cap, not history.
    let fourth = convert_timeline_page_cached(&cache, page(vec![record("m2", "world")]));
    assert_eq!(fourth.messages.len(), 1);
    let cache = cache.lock().unwrap();
    assert_eq!(cache.len(), 1);
    assert!(cache.contains_key("m2"));
}

/// Measures Rust conversion and UniFFI wire serialization, excluding storage
/// and Swift/Kotlin decoding or rendering. Both paths change one row.
#[test]
#[ignore = "release-mode live timeline conversion benchmark"]
fn bench_live_timeline_updates() {
    use std::hint::black_box;
    use std::time::Instant;

    use marmot_app::{AppProjectionUpdate, TimelineMessageChange, TimelineUpdateTrigger};

    for count in [25, 100, 500] {
        let text = "A **bold** update with [a link](https://example.com) and `code`. ".repeat(16);
        let mut page = TimelinePage {
            messages: (0..count)
                .map(|id| record(&id.to_string(), &text))
                .collect(),
            has_more_before: true,
            has_more_after: false,
        };
        let cache = StdMutex::new(HashMap::new());
        black_box(convert_timeline_page_cached(&cache, page.clone()));
        let mut full_times = Vec::new();
        let mut delta_times = Vec::new();
        let mut original_times = Vec::new();
        let mut sizes = [0; 3];
        // Full-page allocation churn is not part of a delta-only consumer.
        for paths in [&[0][..], &[1, 2][..]] {
            for sample in 0..110 {
                let message = page.messages.last_mut().unwrap();
                message.plaintext = format!("{text}{sample}");
                let update = marmot_app::RuntimeTimelineMessageUpdate::Projection(
                    marmot_app::RuntimeProjectionUpdate {
                        account_id_hex: "account".into(),
                        account_label: "account".into(),
                        update: AppProjectionUpdate {
                            group_id_hex: message.group_id_hex.clone(),
                            timeline_messages: vec![message.clone()],
                            timeline_changes: vec![TimelineMessageChange::Upsert {
                                trigger: TimelineUpdateTrigger::MessageEditedOrReprojected,
                                message: Box::new(message.clone()),
                            }],
                            chat_list_row: None,
                            chat_list_trigger: Default::default(),
                        },
                    },
                );
                // Alternate old/new delta order; discard warm-up samples.
                for offset in 0..paths.len() {
                    let path = paths[(sample + offset) % paths.len()];
                    let start = Instant::now();
                    let mut bytes = Vec::new();
                    if path == 0 {
                        let ffi = convert_timeline_page_cached(&cache, black_box(page.clone()));
                        <TimelinePageFfi as uniffi::Lower<crate::UniFfiTag>>::write(
                            ffi, &mut bytes,
                        );
                    } else {
                        let source = black_box(update.clone());
                        let ffi = if path == 1 {
                            TimelineSubscriptionUpdateFfi::from(source)
                        } else {
                            // Original independent conversion of both fields.
                            let marmot_app::RuntimeTimelineMessageUpdate::Projection(source) =
                                source
                            else {
                                unreachable!();
                            };
                            TimelineSubscriptionUpdateFfi::Projection {
                                update: crate::conversions::RuntimeProjectionUpdateFfi {
                                    account_id_hex: source.account_id_hex,
                                    account_label: source.account_label,
                                    update: crate::conversions::TimelineProjectionUpdateFfi {
                                        group_id_hex: source.update.group_id_hex,
                                        messages: source
                                            .update
                                            .timeline_messages
                                            .into_iter()
                                            .map(Into::into)
                                            .collect(),
                                        changes: source
                                            .update
                                            .timeline_changes
                                            .into_iter()
                                            .map(Into::into)
                                            .collect(),
                                        chat_list_row: source.update.chat_list_row.map(Into::into),
                                        chat_list_trigger: source.update.chat_list_trigger.into(),
                                    },
                                },
                            }
                        };
                        <TimelineSubscriptionUpdateFfi as uniffi::Lower<crate::UniFfiTag>>::write(
                            ffi, &mut bytes,
                        );
                    }
                    sizes[path] = black_box(bytes).len();
                    let elapsed = start.elapsed().as_nanos();
                    if sample >= 10 {
                        if path == 0 {
                            full_times.push(elapsed);
                        } else if path == 1 {
                            delta_times.push(elapsed);
                        } else {
                            original_times.push(elapsed);
                        }
                    }
                }
            }
        }
        full_times.sort_unstable();
        delta_times.sort_unstable();
        original_times.sort_unstable();
        assert_eq!(sizes[1], sizes[2]);
        eprintln!(
            "rows={count} full_p50_ns={} full_p95_ns={} delta_p50_ns={} delta_p95_ns={} original_p50_ns={} original_p95_ns={} full_bytes={} delta_bytes={}",
            full_times[49],
            full_times[94],
            delta_times[49],
            delta_times[94],
            original_times[49],
            original_times[94],
            sizes[0],
            sizes[1],
        );
    }
}

// The timeline window's projection/cap/anchoring contract now lives and is
// tested in `marmot-app` (`apply_projection_to_window`, `merge_timeline_window`,
// `paginate_*`); the FFI no longer re-materializes the window, so its former
// delta-application tests moved there.
