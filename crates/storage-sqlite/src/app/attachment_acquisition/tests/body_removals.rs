use super::*;
use crate::{AttachmentBodyRemoval, AttachmentBodyRemovalState};

fn expected(message: &str, state: AttachmentBodyRemovalState) -> AttachmentBodyRemoval {
    AttachmentBodyRemoval {
        group_id_hex: GROUP.into(),
        message_id_hex: message.into(),
        source_message_id_hex: format!("source-{message}"),
        attachment_index: 0,
        state,
    }
}

fn baseline(app: &SqliteAppStorage) -> String {
    let page = app.attachment_removals(None, 1).unwrap();
    assert!(page.reset_required);
    assert!(page.removals.is_empty());
    assert!(!page.has_more);
    page.next_cursor
}

#[test]
fn removal_losses_no_duplicates() {
    use AttachmentBodyRemovalState::{CleanedBySetting, Removed, Unavailable};
    for (action, state) in [
        ("explicit", Removed),
        ("bulk", Removed),
        ("setting", CleanedBySetting),
        ("delete", Unavailable),
        ("invalidate", Unavailable),
        ("expire", Unavailable),
        ("raw_delete", Unavailable),
        ("source_change", Unavailable),
        ("hidden", Unavailable),
    ] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        seed(&store, "one");
        let asset = request(&app, "one");
        publish(&app, &asset);
        let cursor = baseline(&app);
        app.rebuild_message_timeline_for_group(GROUP).unwrap();
        assert!(
            app.attachment_removals(Some(&cursor), 1)
                .unwrap()
                .removals
                .is_empty()
        );
        match action {
            "explicit" => {
                app.remove_local_attachment(GROUP, "one", 0).unwrap();
            }
            "bulk" => {
                assert_eq!(
                    app.remove_retained_attachments(12, None, None)
                        .unwrap()
                        .removed,
                    1
                );
            }
            "setting" => {
                app.set_attachment_keep_media(AttachmentKeepMedia::ThirtyDays)
                    .unwrap();
                assert_eq!(
                    app.clean_attachments_past_keep_window(40 * 86400)
                        .unwrap()
                        .removed,
                    1
                );
            }
            "delete" => {
                let mut deletion = source("deletion");
                deletion.kind = 5;
                deletion.tags = vec![vec!["e".into(), "one".into()]];
                app.record_app_event(&deletion).unwrap();
            }
            "invalidate" => {
                app.invalidate_app_event_by_message_id(GROUP, "one", "branch_selection_withdrawn")
                    .unwrap();
            }
            "expire" => {
                sql(
                    &store,
                    "UPDATE app_events SET retention_expires_at=20 WHERE message_id_hex='one'",
                );
                assert!(
                    app.read_retained_attachment(&asset, 20, 0, 100)
                        .unwrap()
                        .is_none()
                );
                assert!(
                    app.attachment_removals(Some(&cursor), 1)
                        .unwrap()
                        .removals
                        .is_empty()
                );
                assert_eq!(app.prune_expired_attachment_acquisitions(20, 1).unwrap(), 1);
            }
            "raw_delete" => sql(&store, "DELETE FROM app_events WHERE message_id_hex='one'"),
            "source_change" => sql(
                &store,
                "UPDATE message_timeline SET media_json='{\"imeta\":[[\"imeta\",\"m audio/ogg\"]]}'",
            ),
            "hidden" => sql(&store, "UPDATE attachment_history SET visible=0"),
            _ => unreachable!(),
        }
        let page = app.attachment_removals(Some(&cursor), 256).unwrap();
        assert_eq!(page.removals, vec![expected("one", state)], "{action}");
        assert!(!page.reset_required && !page.has_more, "{action}");
        assert!(
            app.read_retained_attachment(&asset, 20, 0, 100)
                .unwrap()
                .is_none(),
            "{action}"
        );

        // Removing demand that never retained a body must not claim a loss.
        seed(&store, "unfinished");
        request(&app, "unfinished");
        app.remove_local_attachment(GROUP, "unfinished", 0).unwrap();
        assert!(
            app.attachment_removals(Some(&page.next_cursor), 1)
                .unwrap()
                .removals
                .is_empty()
        );
    }
}

#[test]
fn removal_rollback_atomic() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "one");
    let asset = request(&app, "one");
    publish(&app, &asset);
    let cursor = baseline(&app);
    let result: StorageResult<()> = store.connection.with_transaction(|| {
        app.remove_local_attachment(GROUP, "one", 0)?;
        Err(invalid("removal rollback"))
    });
    assert_failed_with(result, "removal rollback");
    assert_eq!(read(&app, &asset), BODY);
    assert_eq!(request(&app, "one"), asset);
    let page = app.attachment_removals(Some(&cursor), 1).unwrap();
    assert!(page.removals.is_empty());
    assert_eq!(page.next_cursor, cursor);

    sql(
        &store,
        "CREATE TRIGGER refuse_removal_journal BEFORE INSERT ON attachment_body_removals BEGIN SELECT RAISE(ABORT,'journal fault'); END;",
    );
    assert_failed_with(
        app.remove_local_attachment(GROUP, "one", 0),
        "journal fault",
    );
    assert_eq!(read(&app, &asset), BODY);
    assert_eq!(request(&app, "one"), asset);
    sql(&store, "DROP TRIGGER refuse_removal_journal");
    app.remove_local_attachment(GROUP, "one", 0).unwrap();
    assert_eq!(
        app.attachment_removals(Some(&cursor), 1).unwrap().removals,
        vec![expected("one", AttachmentBodyRemovalState::Removed)]
    );
}

#[test]
fn removal_migration_and_loss() {
    use media_store::MediaCatalog;
    for (action, chunked) in [
        ("corrupt_legacy", false),
        ("corrupt_legacy", true),
        ("lost_media", false),
        ("lost_media", true),
        ("detached_media", false),
        ("deleted_legacy_file", true),
    ] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        seed(&store, "one");
        let asset = request(&app, "one");
        if chunked {
            let job = app
                .claim_attachment_acquisition(&asset, 12, 100)
                .unwrap()
                .unwrap();
            assert_eq!(
                app.complete_attachment_acquisition_from_reader(
                    &job,
                    &mut std::io::Cursor::new(BODY),
                    BODY.len() as u64,
                    12,
                    10000,
                    &|| false,
                )
                .unwrap(),
                AttachmentPublishResult::Published
            );
        } else {
            publish(&app, &asset);
        }
        let body = app.legacy_attachment_bodies(1).unwrap().remove(0);
        let cursor = baseline(&app);
        if action == "corrupt_legacy" {
            assert!(app.drop_corrupt_legacy_body(&body).unwrap());
        } else if action == "deleted_legacy_file" {
            sql(&store, "DELETE FROM retained_attachment_files");
        } else {
            // The catalog owns metadata, not file I/O. A ready catalog row is
            // the database boundary of successful media-store publication.
            let file = [7u8; 16];
            {
                let conn = store.lock().unwrap();
                conn.execute("INSERT INTO media_files(id,file_key,state,category,byte_len,plaintext_digest,created_at,last_used_at)
                    VALUES(?1,zeroblob(32),1,1,?2,?3,12,12)", params![file.as_slice(), BODY.len() as i64, digest().as_slice()]).unwrap();
                conn.execute(
                    "INSERT INTO media_file_refs(token,file_id) VALUES(?1,?2)",
                    params![asset.token, file.as_slice()],
                )
                .unwrap();
            }
            assert!(app.drop_migrated_legacy_body(&body).unwrap());
            assert!(
                app.attachment_removals(Some(&cursor), 1)
                    .unwrap()
                    .removals
                    .is_empty(),
                "migration is not loss"
            );
            match action {
                "lost_media" => {
                    let catalog = crate::SqliteMediaCatalog::new(app.clone());
                    assert!(
                        catalog
                            .mark_lost(media_store::FileId::from_slice(&file).unwrap())
                            .unwrap()
                    );
                }
                "detached_media" => sql(&store, "DELETE FROM media_file_refs"),
                _ => unreachable!(),
            }
        }
        let page = app.attachment_removals(Some(&cursor), 256).unwrap();
        assert_eq!(
            page.removals,
            vec![expected("one", AttachmentBodyRemovalState::Unavailable)],
            "{action}"
        );
        assert!(!page.has_more && !page.reset_required);
    }
}

#[test]
fn shared_file_loss_pages() {
    use media_store::MediaCatalog;

    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let file = [7u8; 16];
    store.lock().unwrap().execute(
        "INSERT INTO media_files(id,file_key,state,category,byte_len,plaintext_digest,created_at,last_used_at)
         VALUES(?1,zeroblob(32),1,1,?2,?3,12,12)",
        params![file.as_slice(), BODY.len() as i64, digest().as_slice()],
    ).unwrap();
    for message in ["one", "two"] {
        seed(&store, message);
        let asset = request(&app, message);
        publish(&app, &asset);
        let body = app.legacy_attachment_bodies(1).unwrap().remove(0);
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO media_file_refs(token,file_id) VALUES(?1,?2)",
                params![asset.token, file.as_slice()],
            )
            .unwrap();
        assert!(app.drop_migrated_legacy_body(&body).unwrap());
    }
    let cursor = baseline(&app);
    assert!(
        crate::SqliteMediaCatalog::new(app.clone())
            .mark_lost(media_store::FileId::from_slice(&file).unwrap())
            .unwrap()
    );

    assert_loss_pages(&app, &cursor);
}

#[test]
fn expiry_batch_loss_pages() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    for message in ["one", "two"] {
        seed(&store, message);
        publish(&app, &request(&app, message));
    }
    sql(&store, "UPDATE app_events SET retention_expires_at=20");
    let cursor = baseline(&app);
    assert_eq!(
        app.prune_expired_attachment_acquisitions(20, 64).unwrap(),
        2
    );
    assert_loss_pages(&app, &cursor);
}

fn assert_loss_pages(app: &SqliteAppStorage, cursor: &str) {
    let first = app.attachment_removals(Some(cursor), 1).unwrap();
    assert!(first.has_more && !first.reset_required);
    let second = app
        .attachment_removals(Some(&first.next_cursor), 1)
        .unwrap();
    assert!(!second.has_more && !second.reset_required);
    let caught_up = app
        .attachment_removals(Some(&second.next_cursor), 1)
        .unwrap();
    assert!(caught_up.removals.is_empty() && !caught_up.has_more && !caught_up.reset_required);

    let mut removals = first.removals;
    removals.extend(second.removals);
    removals.sort_by(|left, right| left.message_id_hex.cmp(&right.message_id_hex));
    assert_eq!(
        removals,
        vec![
            expected("one", AttachmentBodyRemovalState::Unavailable),
            expected("two", AttachmentBodyRemovalState::Unavailable),
        ]
    );
}

#[test]
fn removal_waits_for_settlement() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let cursor = baseline(&app);
    for (message, retain) in [("unretained", false), ("retained", true)] {
        seed(&store, message);
        let asset = automatic_request(&app, message, true)
            .0
            .unwrap()
            .reference
            .unwrap();
        let job = app
            .claim_attachment_acquisition(&asset, 12, 100)
            .unwrap()
            .unwrap();
        assert!(app.mark_attachment_body_completed(&job, 12).unwrap());
        let before = app.attachment_removals(Some(&cursor), 256).unwrap();
        assert_eq!(before.removals.len(), usize::from(retain));
        if retain {
            assert_eq!(
                app.complete_attachment_acquisition(&job, BODY, 12, 10000)
                    .unwrap(),
                AttachmentPublishResult::Published
            );
        } else {
            assert!(app.fail_attachment_acquisition(&job, None).unwrap());
        }
    }
    let page = app.attachment_removals(Some(&cursor), 256).unwrap();
    assert_eq!(
        page.removals,
        vec![expected(
            "unretained",
            AttachmentBodyRemovalState::CompletedUnretained
        )]
    );
    let debug = format!("{page:?} {:?}", page.removals[0]);
    for private in [GROUP, "source-unretained", page.next_cursor.as_str()] {
        assert!(!debug.contains(private));
    }
}

#[test]
fn removal_pages_gap_idle() {
    use crate::base::query_work_test_support::{QUERY_MEASUREMENT, measured};
    let _measurement = QUERY_MEASUREMENT.lock().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let initial = baseline(&app);
    // This fixture exercises the durable journal reader and its trim trigger;
    // the writer contracts above own the reasons and source identities.
    sql(&store, "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096)
        INSERT INTO attachment_body_removals(group_id_hex,message_id_hex,source_message_id_hex,attachment_index,state)
        SELECT 'aa',printf('m%d',x),'source',0,3 FROM n;");
    let first = app.attachment_removals(Some(&initial), 1).unwrap();
    assert!(!first.reset_required && first.has_more);
    assert_eq!(first.removals[0].message_id_hex, "m1");
    sql(&store, "INSERT INTO attachment_body_removals(group_id_hex,message_id_hex,source_message_id_hex,attachment_index,state)
        VALUES('aa','m4097','source',0,3)");
    let gap = app.attachment_removals(Some(&initial), 256).unwrap();
    assert!(gap.reset_required && gap.removals.is_empty() && !gap.has_more);
    let mut cursor = first.next_cursor;
    let mut seen = Vec::new();
    loop {
        let page = app.attachment_removals(Some(&cursor), 256).unwrap();
        assert!(!page.reset_required);
        seen.extend(page.removals.into_iter().map(|row| row.message_id_hex));
        cursor = page.next_cursor;
        if !page.has_more {
            break;
        }
    }
    assert_eq!(
        seen,
        (2..=4097).map(|n| format!("m{n}")).collect::<Vec<_>>()
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM attachment_body_removals", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        4096
    );
    sql(&store, "PRAGMA query_only=ON");
    let idle = measured(&store, "idle removal journal", 500, || {
        app.attachment_removals(Some(&cursor), 1).unwrap()
    });
    assert!(idle.removals.is_empty() && !idle.reset_required && !idle.has_more);
    assert_eq!(idle.next_cursor, cursor);
    assert!(
        app.attachment_removals(Some("unrecognized"), 1)
            .unwrap()
            .reset_required
    );
    for limit in [0, 257] {
        assert_failed_with(
            app.attachment_removals(Some(&cursor), limit),
            "invalid attachment body removal page limit",
        );
    }
}

#[test]
fn removal_cursor_reopen_reset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("removals.sqlite");
    let key = SqlCipherKey::raw([0x6d; 32]);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    let cursor = baseline(&app);
    seed(&store, "one");
    publish(&app, &request(&app, "one"));
    app.remove_local_attachment(GROUP, "one", 0).unwrap();
    let page = app.attachment_removals(Some(&cursor), 1).unwrap();
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    assert_eq!(app.attachment_removals(Some(&cursor), 1).unwrap(), page);
    let other = SqliteAccountStorage::in_memory().unwrap();
    assert!(
        other
            .app_storage()
            .attachment_removals(Some(&page.next_cursor), 1)
            .unwrap()
            .reset_required
    );

    for reverse in [false, true] {
        seed(&store, "reset");
        let asset = request(&app, "reset");
        publish(&app, &asset);
        if reverse {
            let conn = store.lock().unwrap();
            conn.execute("INSERT INTO media_files(id,file_key,state,category,byte_len,plaintext_digest,created_at,last_used_at)
                VALUES(zeroblob(16),zeroblob(32),1,1,?1,?2,12,12)", params![BODY.len() as i64, digest().as_slice()]).unwrap();
            conn.execute(
                "INSERT INTO media_file_refs(token,file_id) VALUES(?1,zeroblob(16))",
                [&asset.token],
            )
            .unwrap();
            conn.execute(
                "DELETE FROM retained_attachment_bytes WHERE token=?1",
                [&asset.token],
            )
            .unwrap();
        }
        // Recreate older AFTER reset triggers in both orders. The journal's
        // BEFORE reset and epoch binding must not depend on their order.
        let mut triggers: Vec<String> = {
            let conn = store.lock().unwrap();
            [
                "attachment_acquisition_store_reset",
                "media_files_store_reset",
            ]
            .into_iter()
            .map(|name| {
                conn.query_row(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                    [name],
                    |r| r.get(0),
                )
                .unwrap()
            })
            .collect()
        };
        if reverse {
            triggers.reverse();
        }
        sql(
            &store,
            "DROP TRIGGER attachment_acquisition_store_reset; DROP TRIGGER media_files_store_reset;",
        );
        for trigger in triggers {
            sql(&store, &trigger);
        }
        let old = baseline(&app);
        let high_water: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT high_water FROM attachment_body_removal_meta",
                [],
                |r| r.get(0),
            )
            .unwrap();
        sql(
            &store,
            "UPDATE chat_presentation_meta SET store_epoch=randomblob(16)",
        );
        let reset = app.attachment_removals(Some(&old), 256).unwrap();
        assert!(reset.reset_required && reset.removals.is_empty());
        let fresh = reset.next_cursor;
        seed(&store, "after-reset");
        publish(&app, &request(&app, "after-reset"));
        app.remove_local_attachment(GROUP, "after-reset", 0)
            .unwrap();
        let next = app.attachment_removals(Some(&fresh), 256).unwrap();
        assert_eq!(
            next.removals,
            vec![expected("after-reset", AttachmentBodyRemovalState::Removed)]
        );
        assert!(!next.reset_required && !next.has_more);
        let sequence: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT max(sequence) FROM attachment_body_removals",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(sequence > high_water, "reset must never reuse a sequence");
    }
}
