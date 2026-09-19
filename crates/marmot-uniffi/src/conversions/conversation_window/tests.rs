use super::*;
#[tokio::test]
async fn prepared_cache_keeps_snapshot_metadata_fresh_and_prunes_paged_rows() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = app::MarmotApp::with_relay(dir.path(), relay.url().await.as_str());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("conversion cache", &[]).await.unwrap();
    for i in 0..3 {
        client
            .send(&group, format!("**message {i}**").as_bytes())
            .await
            .unwrap();
    }
    drop(client);
    let runtime = app.runtime();
    let window = runtime
        .open_conversation_window(
            "alice",
            &group,
            app::ConversationOpenQuery {
                target: app::ConversationOpenTarget::Latest,
                limit: 3,
            },
        )
        .await
        .unwrap();
    let mut snapshot = window.snapshot.clone();
    let mut cache = ConversationConversionCache::default();
    let wire = |snapshot| {
        let mut bytes = vec![];
        <ConversationWindowSnapshotFfi as uniffi::Lower<crate::UniFfiTag>>::write(
            snapshot, &mut bytes,
        );
        // Balance the lowered object handle retained by the draft revision.
        drop(
            <ConversationWindowSnapshotFfi as uniffi::Lift<crate::UniFfiTag>>::try_read(
                &mut bytes.as_slice(),
            )
            .unwrap(),
        );
        bytes
    };
    let equivalent = |actual: ConversationWindowSnapshotFfi,
                      mut expected: ConversationWindowSnapshotFfi| {
        assert!(actual.draft.revision.inner == expected.draft.revision.inner);
        // Object handles encode allocation identity, not the revision value.
        expected.draft.revision = actual.draft.revision.clone();
        assert_eq!(wire(actual), wire(expected));
    };
    equivalent(cache.convert(&snapshot), (&snapshot).into());
    assert_eq!((cache.conversions, cache.parses), (3, 3));
    snapshot.revision.sequence += 1;
    snapshot.presentation.header.archived = true;
    snapshot.read_state.manually_marked_unread = true;
    snapshot
        .presentation
        .identities
        .values_mut()
        .next()
        .unwrap()
        .display_name = "new profile name".into();
    snapshot.presentation.messages[0].reactions.total_count += 1;
    equivalent(cache.convert(&snapshot), (&snapshot).into());
    assert_eq!((cache.conversions, cache.parses), (3, 3));
    let selected = app
        .selected_message_draft("alice", &hex::encode(group.as_slice()))
        .unwrap();
    snapshot.draft = app
        .save_message_draft_if_revision("alice", &selected.revision, "draft changed", None, vec![])
        .unwrap();
    equivalent(cache.convert(&snapshot), (&snapshot).into());
    assert_eq!((cache.conversions, cache.parses), (3, 3));
    let small = runtime
        .open_conversation_window(
            "alice",
            &group,
            app::ConversationOpenQuery {
                target: app::ConversationOpenTarget::Latest,
                limit: 1,
            },
        )
        .await
        .unwrap();
    let mut paged = small.snapshot.clone();
    paged.revision = snapshot.revision.clone();
    paged.revision.sequence += 1;
    equivalent(cache.convert(&paged), (&paged).into());
    assert_eq!(cache.rows.len(), 1);
    assert_eq!((cache.conversions, cache.parses), (3, 3));
    // An older command reply is still correct, but cannot repopulate rows
    // removed by the newer stream replacement.
    equivalent(cache.convert(&snapshot), (&snapshot).into());
    assert_eq!(cache.rows.len(), 1);
    assert_eq!(cache.sequence, Some(paged.revision.sequence));
    cache.close();
    equivalent(cache.convert(&paged), (&paged).into());
    assert!(cache.rows.is_empty());
    runtime.shutdown_and_close().await.unwrap();
}
fn record(id: usize) -> app::TimelineMessageRecord {
    serde_json::from_value(serde_json::json!({
        "message_id_hex":id.to_string(),"direction":"received","group_id_hex":"11","sender":"alice",
        "plaintext":"**unchanged** message","kind":9,"tags":[],"timeline_at":1,"received_at":1,
        "reactions":{"by_emoji":{},"user_reactions":[]},"deleted":false
    }))
    .unwrap()
}
fn wire(value: TimelineMessageRecordFfi) -> Vec<u8> {
    let mut bytes = vec![];
    <TimelineMessageRecordFfi as uniffi::Lower<crate::UniFfiTag>>::write(value, &mut bytes);
    bytes
}
#[test]
fn prepared_conversion_reuses_rows_and_text_but_keeps_all_visible_changes() {
    for size in [50, 200] {
        let mut cache = ConversationConversionCache::default();
        let mut rows: Vec<_> = (0..size).map(record).collect();
        for row in &rows {
            assert_eq!(
                wire(cache.row(row, false)),
                wire(presented_timeline(row, false))
            );
        }
        assert_eq!((cache.conversions, cache.parses), (size, size));
        // Reactions live in the references sidecar; raw tags/reactor lists
        // must neither invalidate nor enter the prepared-row cache.
        rows[0]
            .reactions
            .by_emoji
            .insert("👍".into(), vec!["alice".into(); 5000]);
        rows[0].tags.push(vec!["irrelevant".into()]);
        for row in &rows {
            cache.row(row, false);
        }
        assert_eq!((cache.conversions, cache.parses), (size, size));
        assert!(cache.rows["0"].source.tags.is_empty());
        assert!(cache.rows["0"].source.reactions.by_emoji.is_empty());
        rows[0].source_message_id_hex = Some("delivered".into());
        rows[0].source_epoch = Some(2);
        assert_eq!(
            wire(cache.row(&rows[0], false)),
            wire(presented_timeline(&rows[0], false))
        );
        assert_eq!((cache.conversions, cache.parses), (size + 1, size));
        rows[0].plaintext = "**edited**".into();
        assert_eq!(
            wire(cache.row(&rows[0], false)),
            wire(presented_timeline(&rows[0], false))
        );
        assert_eq!(cache.parses, size + 1);
        rows[0].deleted = true;
        rows[0].invalidation_status = Some("invalidated".into());
        assert_eq!(
            wire(cache.row(&rows[0], false)),
            wire(presented_timeline(&rows[0], false))
        );
        assert_eq!(cache.parses, size + 1);
        cache.close();
        assert!(cache.rows.is_empty());
    }
}
#[test]
fn prepared_conversion_does_not_cache_stale_system_provenance() {
    let mut row = record(0);
    row.kind = 1210;
    row.plaintext = r#"{"v":1,"system_type":"admin_added","text":"added","data":{}}"#.into();
    row.group_system = app::group_system_event_from_message(1210, &row.plaintext);
    assert!(row.group_system.is_some());
    let mut cache = ConversationConversionCache::default();
    assert!(cache.row(&row, false).group_system.is_none());
    assert_eq!(
        wire(cache.row(&row, true)),
        wire(presented_timeline(&row, true))
    );
    assert!(cache.row(&row, false).group_system.is_none());
    assert_eq!(cache.parses, 1);
}

#[test]
#[ignore = "host conversion timing; excludes FFI serialization and native UI work"]
fn bench_prepared_conversation_conversion() {
    use std::{hint::black_box, time::Instant};
    for with_media in [false, true] {
        for size in [50, 200] {
            let mut rows: Vec<_> = (0..size).map(record).collect();
            for row in &mut rows {
                row.plaintext = "**Bold** and _italic_ with [a link](https://example.com).\n\n- first\n- second\n\n".repeat(32);
                if with_media {
                    let tag = vec![
                        "imeta".to_owned(),
                        "v encrypted-media-v1".into(),
                        format!(
                            "locator blossom-v1 https://media.example/{}.bin",
                            "22".repeat(32)
                        ),
                        format!("ciphertext_sha256 {}", "22".repeat(32)),
                        format!("plaintext_sha256 {}", "23".repeat(32)),
                        format!("nonce {}", "22".repeat(12)),
                        "m video/mp4".into(),
                        "filename clip.mp4".into(),
                    ];
                    row.source_epoch = Some(7);
                    row.media = Some(serde_json::json!({"imeta": [tag.clone(), tag]}));
                    assert!(
                        presented_timeline(row, false)
                            .media
                            .iter()
                            .all(|outcome| matches!(
                                outcome,
                                MediaAttachmentOutcomeFfi::Accepted { .. }
                            ))
                    );
                }
            }
            let mut cache = ConversationConversionCache::default();
            for row in &rows {
                black_box(cache.row(row, false));
            }
            for change_one in [false, true] {
                let started = Instant::now();
                let parses = cache.parses;
                for i in 0..20 {
                    if change_one {
                        rows[i % size].plaintext.push('x');
                    }
                    for row in &rows {
                        black_box(cache.row(row, false));
                    }
                }
                let cached = started.elapsed();
                assert_eq!(cache.parses - parses, if change_one { 20 } else { 0 });
                // Benchmark the smaller token-only alternative separately:
                // it still converts media and the rest of every row.
                let mut tokens: std::collections::HashMap<_, _> = rows
                    .iter()
                    .map(|row| {
                        (
                            row.message_id_hex.clone(),
                            (
                                row.kind,
                                row.plaintext.clone(),
                                super::super::common::markdown_content_tokens(
                                    row.kind,
                                    &row.plaintext,
                                ),
                            ),
                        )
                    })
                    .collect();
                let started = Instant::now();
                for i in 0..20 {
                    if change_one {
                        rows[i % size].plaintext.push('x');
                    }
                    for row in &rows {
                        let cached = tokens.get_mut(&row.message_id_hex).unwrap();
                        if cached.0 != row.kind || cached.1 != row.plaintext {
                            *cached = (
                                row.kind,
                                row.plaintext.clone(),
                                super::super::common::markdown_content_tokens(
                                    row.kind,
                                    &row.plaintext,
                                ),
                            );
                        }
                        black_box(presented_timeline_with_tokens(row, false, cached.2.clone()));
                    }
                }
                let token_only = started.elapsed();
                let started = Instant::now();
                for i in 0..20 {
                    if change_one {
                        rows[i % size].plaintext.push('x');
                    }
                    for row in &rows {
                        black_box(presented_timeline(row, false));
                    }
                }
                eprintln!(
                    "prepared rows={size} media={with_media} change_one={change_one} updates=20 cached_ms={} token_only_ms={} uncached_ms={}",
                    cached.as_millis(),
                    token_only.as_millis(),
                    started.elapsed().as_millis()
                );
            }
        }
    }
}

#[test]
fn prepared_conversion_refreshes_report_indicator_without_reparsing_text() {
    let mut row = record(0);
    let mut cache = ConversationConversionCache::default();
    for (index, reported) in [false, true, false].into_iter().enumerate() {
        row.has_reports = reported;
        let converted = cache.row(&row, false);
        assert_eq!(converted.has_reports, reported);
        assert_eq!(wire(converted), wire(presented_timeline(&row, false)));
        assert_eq!((cache.conversions, cache.parses), (index + 1, 1));
    }
}

#[test]
fn custom_tags_and_deletion_provenance_invalidate_prepared_conversion() {
    let mut cache = ConversationConversionCache::default();
    let mut row = record(0);
    row.kind = 30402;
    row.plaintext = "Classified listing".into();
    row.tags = vec![
        vec!["title".into(), "Bicycle".into()],
        vec!["price".into(), "100".into(), "EUR".into()],
    ];
    let first = cache.row(&row, false);
    assert_eq!(first.kind, row.kind);
    assert_eq!(first.plaintext, row.plaintext);
    assert_eq!(
        first
            .tags
            .iter()
            .map(|t| t.values.clone())
            .collect::<Vec<_>>(),
        row.tags
    );
    row.tags[1][1] = "90".into();
    assert_eq!(cache.row(&row, false).tags[1].values[1], "90");
    row.deleted = true;
    row.plaintext.clear();
    row.deletion_source = app::DeletionSource::Author;
    assert!(cache.row(&row, false).tags.is_empty());
    assert_eq!(
        cache.row(&row, false).deletion_source,
        super::super::timeline::DeletionSourceFfi::Author
    );
    row.deletion_source = app::DeletionSource::Admin;
    let admin = cache.row(&row, false);
    assert_eq!(
        admin.deletion_source,
        super::super::timeline::DeletionSourceFfi::Admin
    );
    assert_eq!(wire(admin), wire(presented_timeline(&row, false)));
    assert_eq!(cache.conversions, 4);
}

#[test]
fn legacy_deleted_record_defaults_to_unknown_provenance() {
    let mut row = record(0);
    row.deleted = true;
    row.plaintext.clear();
    row.deleted_by_message_id_hex = Some("legacy-delete".into());
    assert_eq!(row.deletion_source, app::DeletionSource::Unknown);
    let converted = presented_timeline(&row, false);
    assert!(converted.deleted && converted.plaintext.is_empty());
    assert_eq!(
        converted.deleted_by_message_id_hex.as_deref(),
        Some("legacy-delete")
    );
    assert_eq!(
        converted.deletion_source,
        super::super::timeline::DeletionSourceFfi::Unknown
    );
}
