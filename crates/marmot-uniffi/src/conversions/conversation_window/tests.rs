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
    // Prime each row before changing exactly one visible source field. Cold
    // conversion and cache equivalence are different binding contracts.
    fn changed(
        mut row: app::TimelineMessageRecord,
        change: impl FnOnce(&mut app::TimelineMessageRecord),
        expected: impl FnOnce(&TimelineMessageRecordFfi),
    ) {
        let mut cache = ConversationConversionCache::default();
        cache.row(&row, false);
        change(&mut row);
        let actual = cache.row(&row, false);
        expected(&actual);
        assert_eq!(wire(actual), wire(presented_timeline(&row, false)));
    }
    // Replacement snapshots coalesce: the cache can miss a send's temporary
    // local_publish_failed state and see pending -> peer-confirmed endpoints
    // with the same absent invalidation status and source id.
    let mut confirmed = record(0);
    confirmed.direction = "sent".into();
    changed(
        confirmed,
        |row| row.recipient_confirmed = true,
        |row| {
            assert!(
                row.recipient_confirmed,
                "recipient confirmation stayed stale"
            )
        },
    );
    // Already-sourced rows from before the retention migration have no
    // pinned decision. Finalizing the same published send can learn disabled
    // retention without changing its source, epoch, or timestamps.
    let mut retention = record(0);
    retention.direction = "sent".into();
    retention.source_epoch = Some(7);
    retention.source_message_id_hex = Some("22".repeat(32));
    changed(
        retention.clone(),
        |row| row.retention_seconds = Some(0),
        |row| {
            assert_eq!(
                row.retention_seconds,
                Some(0),
                "retention policy stayed stale"
            );
            assert_eq!(row.retention_expires_at, None);
        },
    );
    // A finite decision pins policy and expiry together; a real producer
    // does not independently repair an expiry once its policy is known.
    changed(
        retention,
        |row| {
            row.retention_seconds = Some(400);
            row.retention_expires_at = Some(401);
        },
        |row| {
            assert_eq!(row.retention_seconds, Some(400));
            assert_eq!(row.retention_expires_at, Some(401));
        },
    );

    let mut reply_row = record(0);
    reply_row.reply_to_message_id_hex = Some("reply-source".into());
    reply_row.tags = vec![vec!["q".into(), "reply-source".into()]];
    changed(
        reply_row,
        |row| {
            row.reply_preview = Some(app::TimelineReplyPreview {
                message_id_hex: "reply-source".into(),
                sender: "bob".into(),
                plaintext: "visible reply **new**".into(),
                kind: 9,
                tags: vec![],
                source_epoch: None,
                media: None,
                agent_text_stream: None,
                deleted: false,
                deletion_source: Default::default(),
                invalidation_status: None,
            })
        },
        |row| {
            let preview = row
                .reply_preview
                .as_ref()
                .expect("reply preview stayed stale");
            assert_eq!(preview.message_id_hex, "reply-source");
            assert_eq!(preview.plaintext, "visible reply **new**");
        },
    );

    let mut poll_row = record(0);
    poll_row.kind = 1068;
    poll_row.plaintext = "Which?".into();
    poll_row.tags = vec![
        vec!["option".into(), "up".into(), "Up".into()],
        vec!["option".into(), "down".into(), "Down".into()],
        vec!["polltype".into(), "singlechoice".into()],
    ];
    poll_row.poll = Some(app::PollProjection {
        question: "Which?".into(),
        options: vec![
            app::PollOptionResult {
                id: "up".into(),
                label: "Up".into(),
                votes: 0,
            },
            app::PollOptionResult {
                id: "down".into(),
                label: "Down".into(),
                votes: 0,
            },
        ],
        poll_type: app::PollType::SingleChoice,
        participants: 0,
        local_selection: vec![],
        creator: "alice".into(),
        ends_at: None,
        open: true,
    });
    changed(
        poll_row,
        |row| {
            let poll = row.poll.as_mut().unwrap();
            poll.options[0].votes = 1;
            poll.participants = 1;
            poll.local_selection = vec!["up".into()];
        },
        |row| {
            let poll = row.poll.as_ref().unwrap();
            assert_eq!(poll.participants, 1, "poll stayed stale");
            assert_eq!(poll.options[0].votes, 1);
            assert_eq!(poll.local_selection, ["up"]);
        },
    );

    // An accepted edit can leave the displayed text unchanged (a no-op or
    // reversion); its history metadata still has to advance.
    let mut edited = record(0);
    edited.edit = Some(app::TimelineEditSummary {
        edit_count: 1,
        latest_edit_message_id_hex: "edit-one".into(),
        edited_at: 2,
    });
    changed(
        edited,
        |row| {
            row.edit = Some(app::TimelineEditSummary {
                edit_count: 2,
                latest_edit_message_id_hex: "edit-two".into(),
                edited_at: 3,
            })
        },
        |row| {
            let edit = row.edit.as_ref().unwrap();
            assert_eq!(edit.edit_count, 2, "edit history stayed stale");
            assert_eq!(edit.latest_edit_message_id_hex, "edit-two");
            assert_eq!(edit.edited_at, 3);
        },
    );
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
        // An imported row's source device, renamed, is a visible change.
        for label in ["Phone", "Old phone"] {
            rows[0].imported_from = Some(app::HistoryImportSource {
                device_slot_id_hex: "77".repeat(32),
                device_label: label.into(),
            });
            assert_eq!(
                wire(cache.row(&rows[0], false)),
                wire(presented_timeline(&rows[0], false))
            );
        }
        assert_eq!(cache.conversions, size + 5);
        // Provenance changes independently of content and sibling labels.
        // Prime the live row first, so an ignored source key cannot pass by
        // incidentally invalidating on another field's change.
        rows[0].imported_from = None;
        cache.row(&rows[0], false);
        for written_at in [41, 42] {
            rows[0].history_import_provenance = Some(app::HistoryImportProvenance::Backup(
                app::BackupHistorySource {
                    recovery_public_key: [2; 32],
                    backup_id: [3; 16],
                    head_sha256: [4; 32],
                    written_at,
                },
            ));
            let prepared = cache.row(&rows[0], false);
            assert!(prepared.imported_from.is_none());
            assert!(matches!(&prepared.history_import_provenance,
                Some(super::super::HistoryImportProvenanceFfi::Backup { source })
                if source.recovery_public_key_hex == "02".repeat(32)
                    && source.backup_id_hex == "03".repeat(16)
                    && source.head_sha256_hex == "04".repeat(32)
                    && source.written_at == written_at));
            let direct = TimelineMessageRecordFfi::from(rows[0].clone());
            assert_eq!(
                prepared.history_import_provenance,
                direct.history_import_provenance
            );
            assert_eq!(wire(prepared), wire(presented_timeline(&rows[0], false)));
        }
        rows[0].history_import_provenance = None;
        assert!(
            cache
                .row(&rows[0], false)
                .history_import_provenance
                .is_none()
        );
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

/// Manual timing only: `cargo nextest run -p marmot-uniffi --run-ignored only -E 'test(=conversions::conversation_window::conversion_cache_tests::bench_prepared_conversation_conversion)'`.
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
                        black_box(presented_timeline_with_tokens(
                            row,
                            false,
                            cached.2.clone(),
                            if row.deleted {
                                None
                            } else {
                                marmot_app::sticker_ref_from_tags(row.kind, &row.tags)
                                    .map(Into::into)
                            },
                        ));
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
fn sticker_only_tag_change_invalidates_prepared_conversion() {
    let mut cache = ConversationConversionCache::default();
    let mut row = record(0);
    let coordinate = format!("30031:{}:pack", "aa".repeat(32));
    let digest = "bb".repeat(32);
    let sticker = |shortcode: &str| {
        vec![
            "sticker".to_owned(),
            coordinate.clone(),
            shortcode.to_owned(),
            digest.clone(),
        ]
    };
    row.tags = vec![sticker("wave")];
    let first = cache.row(&row, false);
    assert_eq!(
        first
            .sticker
            .as_ref()
            .map(|sticker| sticker.shortcode.as_str()),
        Some("wave")
    );
    assert_eq!(cache.conversions, 1);
    row.tags = vec![sticker("nod")];
    let second = cache.row(&row, false);
    assert_eq!(
        second
            .sticker
            .as_ref()
            .map(|sticker| sticker.shortcode.as_str()),
        Some("nod")
    );
    assert_eq!(
        wire(second),
        wire(presented_timeline(&row, false)),
        "a sticker-only tag change must not reuse the cached conversion"
    );
    assert_eq!(cache.conversions, 2);
    assert_eq!(cache.parses, 1);
    row.tags.clear();
    let cleared = cache.row(&row, false);
    assert!(cleared.sticker.is_none());
    assert_eq!(
        wire(cleared),
        wire(presented_timeline(&row, false)),
        "removing the sticker must not reuse the cached sticker row"
    );
    assert_eq!(cache.conversions, 3);
}

#[test]
fn chat_rows_keep_only_emoji_tags() {
    let mut cache = ConversationConversionCache::default();
    let mut row = record(0);
    let emoji = vec!["emoji".to_owned(), "party".into(), "https://blob/x".into()];
    row.tags = vec![
        vec!["imeta".into(), "url https://blob/x".into()],
        vec!["p".into(), "ab".repeat(32)],
        vec!["emoji".into(), "short".into()],
        emoji.clone(),
    ];
    let values = |row: TimelineMessageRecordFfi| {
        row.tags
            .into_iter()
            .map(|tag| tag.values)
            .collect::<Vec<_>>()
    };
    assert_eq!(values(cache.row(&row, false)), vec![emoji.clone()]);
    row.tags.pop();
    assert!(values(cache.row(&row, false)).is_empty());
    row.tags.push(emoji);
    row.kind = cgka_traits::app_event::MARMOT_APP_EVENT_KIND_REACTION;
    assert!(values(cache.row(&row, false)).is_empty());
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
