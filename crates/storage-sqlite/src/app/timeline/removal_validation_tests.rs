//! Real recording, upgrade, projection and encrypted reopen boundaries (#3016).
use super::*;
use crate::{SqlCipherKey, SqliteAccountStorage};
use cgka_traits::app_event::AppMessageAuthority;

const GROUP: &str = "legacy-removal-group";

fn source(kind: u64, at: u64, tags: Vec<Vec<String>>, text: &str) -> StoredAppEvent {
    let inner = MarmotAppEvent::new("aa".repeat(32), at, kind, tags, text);
    // The same canonical constructor/decoder used by real message producers.
    let inner = MarmotAppEvent::decode(&inner.encode().unwrap()).unwrap();
    StoredAppEvent {
        group_id_hex: GROUP.into(),
        message_id_hex: inner.id.clone(),
        source_message_id_hex: Some(format!("source-{}", inner.id)),
        source_epoch: None,
        direction: "received".into(),
        sender: inner.pubkey,
        plaintext: inner.content,
        kind: inner.kind,
        tags: inner.tags,
        recorded_at: inner.created_at,
        received_at: at,
        origin_commit_id: None,
        moderation_grant: kind == MARMOT_APP_EVENT_KIND_REMOVE,
    }
}
fn removal(target: &StoredAppEvent, at: u64, duplicate: bool) -> StoredAppEvent {
    let tag = vec![
        "e".into(),
        target.message_id_hex.clone(),
        "permitted-extra-field".into(),
    ];
    let mut tags = vec![
        tag.clone(),
        vec!["alt".into(), "permitted optional tag".into()],
    ];
    if duplicate {
        tags.push(tag);
    }
    source(4891, at, tags, r#"{"v":1,"action":"remove"}"#)
}
fn authority() -> AppMessageAuthority {
    AppMessageAuthority {
        source_context: [7; 32],
        moderation_grant: true,
    }
}
fn assert_deleted(app: &SqliteAppStorage, target: &StoredAppEvent, deleted: bool) {
    let row = app
        .timeline_message(GROUP, &target.message_id_hex)
        .unwrap()
        .expect("retained target");
    assert_eq!(row.deleted, deleted);
    assert_eq!(row.plaintext, if deleted { "" } else { &target.plaintext });
}
fn damage(app: &SqliteAppStorage, control: &StoredAppEvent) {
    assert_eq!(app.lock().unwrap().execute("UPDATE app_events SET tags_json='damaged' WHERE group_id_hex=?1 AND message_id_hex=?2",
        params![GROUP,control.message_id_hex]).unwrap(),1);
}

#[test]
fn original_removal_validation_survives_tag_loss_pruning_and_encrypted_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("removal.db");
    let key = SqlCipherKey::raw([0x63; 32]);
    let target = source(9, 10, vec![], "retained target");
    let control = removal(&target, 11, false);
    {
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let app = store.app_storage();
        app.record_app_event(&target).unwrap();
        app.record_app_event_with_source(
            &control,
            Some(AppMessageRetentionDecision::new(11, 10)),
            Some(authority()),
        )
        .unwrap();
        assert_deleted(&app, &target, true);
        damage(&app, &control);
        app.secure_prune_expired_app_events(GROUP, 25, "local", &|_, _| false)
            .unwrap();
        app.rebuild_message_timeline_for_group(GROUP).unwrap();
        assert_deleted(&app, &target, true);
    }
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    app.rebuild_message_timeline_for_group(GROUP).unwrap();
    assert_deleted(&app, &target, true);
    app.invalidate_app_event_by_message_id(GROUP, &control.message_id_hex, "withdrawn")
        .unwrap();
    assert_deleted(&app, &target, false);
}

// Frozen pre-178 fixture: complete sources, deduplicated edges and the exact
// old projection/retained-control evidence the upgrade is allowed to trust.
fn insert_legacy(conn: &Connection, event: &StoredAppEvent, tags: &str) {
    conn.execute("INSERT INTO app_events(group_id_hex,message_id_hex,source_message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at,moderation_grant,authority_state)
        VALUES (?1,?2,?3,'received',?4,?5,?6,?7,?8,?8,?9,2)",
        params![GROUP,event.message_id_hex,event.source_message_id_hex,event.sender,event.plaintext,u64_to_i64(event.kind).unwrap(),tags,u64_to_i64(event.recorded_at).unwrap(),event.moderation_grant]).unwrap();
    for tag in &event.tags {
        if tag.first().is_some_and(|s| s == "e") {
            conn.execute("INSERT OR IGNORE INTO message_modifier_edges(group_id_hex,modifier_message_id_hex,target_message_id_hex,kind,sender,recorded_at) VALUES(?1,?2,?3,?4,?5,?6)",
                params![GROUP,event.message_id_hex,tag[1],u64_to_i64(event.kind).unwrap(),event.sender,u64_to_i64(event.recorded_at).unwrap()]).unwrap();
        }
    }
}
fn legacy_projection(conn: &Connection, target: &StoredAppEvent, control: Option<&StoredAppEvent>) {
    conn.execute("INSERT INTO message_timeline(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json,deleted,deleted_by_message_id_hex)
        VALUES(?1,?2,'received',?3,?4,9,'[]',?5,?5,'{}',?6,?7)",
        params![GROUP,target.message_id_hex,target.sender,if control.is_some(){""}else{&target.plaintext},u64_to_i64(target.recorded_at).unwrap(),control.is_some(),control.map(|c|&c.message_id_hex)]).unwrap();
}

#[test]
fn legacy_upgrade_preserves_only_existing_uncertain_hides_through_rebuild_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let key = SqlCipherKey::raw([0x64; 32]);
    let cases = [
        // intact valid / intact invalid / damaged visible / damaged hidden /
        // previously scrubbed hidden / previously scrubbed visible / absent.
        (false, false, false, false),
        (true, false, false, false),
        (true, true, false, false),
        (false, true, false, true),
        (true, false, true, true),
        (true, false, true, false),
        (true, true, false, false),
        // Exact canonical reconstruction proves these reduced candidates.
        (false, true, false, true),
        (false, false, true, true),
    ];
    let mut fixtures = Vec::new();
    {
        fs_private::ensure_private_db_files(&path).unwrap();
        let mut conn = Connection::open(&path).unwrap();
        crate::open_hardened_sqlcipher(&conn, &key, crate::SqlCipherHardening::live_cache())
            .unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        crate::base::migrations::run_through(&mut conn, 177).unwrap();
        for (i, (duplicate, damaged, pruned, hidden)) in cases.into_iter().enumerate() {
            let target = source(9, 10 + i as u64, vec![], &format!("target {i}"));
            let control = if i >= 7 {
                source(
                    4891,
                    30 + i as u64,
                    vec![vec!["e".into(), target.message_id_hex.clone()]],
                    r#"{"v":1,"action":"remove"}"#,
                )
            } else {
                removal(&target, 30 + i as u64, duplicate)
            };
            let absent = i == 6;
            if !absent {
                insert_legacy(&conn, &target, "[]");
                legacy_projection(&conn, &target, hidden.then_some(&control));
            }
            let tags = if damaged {
                "damaged".into()
            } else if pruned {
                serde_json::to_string(&vec![vec!["e".to_owned(), target.message_id_hex.clone()]])
                    .unwrap()
            } else {
                serde_json::to_string(&control.tags).unwrap()
            };
            insert_legacy(&conn, &control, &tags);
            if i == 3 {
                conn.execute(
                    "UPDATE app_events SET retention_seconds=10,retention_expires_at=43
                     WHERE group_id_hex=?1 AND message_id_hex=?2",
                    params![GROUP, control.message_id_hex],
                )
                .unwrap();
            }
            if absent {
                conn.execute("UPDATE app_events SET authority_state=1,moderation_grant=0 WHERE group_id_hex=?1 AND message_id_hex=?2",params![GROUP,control.message_id_hex]).unwrap();
            }
            if pruned {
                conn.execute(
                    "INSERT INTO content_pruned_controls VALUES(?1,?2)",
                    params![GROUP, control.message_id_hex],
                )
                .unwrap();
            }
            fixtures.push((target, control));
        }
    }
    let assert_expired_hold = |app: &SqliteAppStorage| {
        let (body,tags,seconds,expires,pruned): (String,String,Option<i64>,Option<i64>,bool) = app.lock().unwrap().query_row(
            "SELECT plaintext,tags_json,retention_seconds,retention_expires_at,
             EXISTS(SELECT 1 FROM content_pruned_controls p WHERE p.group_id_hex=e.group_id_hex AND p.message_id_hex=e.message_id_hex)
             FROM app_events e WHERE group_id_hex=?1 AND message_id_hex=?2",
            params![GROUP,fixtures[3].1.message_id_hex],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).unwrap();
        assert_eq!(body, "");
        assert_eq!(
            tags,
            serde_json::to_string(&vec![vec!["e", fixtures[3].0.message_id_hex.as_str()]]).unwrap()
        );
        assert_eq!((seconds, expires, pruned), (None, None, true));
        assert_deleted(app, &fixtures[3].0, true);
    };
    {
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let app = store.app_storage();
        app.rebuild_message_timeline_for_group(GROUP).unwrap();
        for (i, (target, _)) in fixtures.iter().enumerate().filter(|(i, _)| *i != 6) {
            assert_deleted(&app, target, [0, 3, 4, 7, 8].contains(&i));
        }
        // No hold for a target absent from the pre-upgrade projection.
        app.record_app_event(&fixtures[6].0).unwrap();
        app.finalize_app_event_authority(GROUP, &fixtures[6].1.message_id_hex, Some(authority()))
            .unwrap();
        assert_deleted(&app, &fixtures[6].0, false);
        for (i, (_, control)) in fixtures.iter().enumerate() {
            let (state,holds): (u8,u32) = app.lock().unwrap().query_row("SELECT state,(SELECT count(*) FROM content_removal_legacy_holds h WHERE h.group_id_hex=v.group_id_hex AND h.message_id_hex=v.message_id_hex) FROM content_removal_validation v WHERE group_id_hex=?1 AND message_id_hex=?2",params![GROUP,control.message_id_hex],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
            assert_eq!(state, [2, 1, 0, 0, 0, 0, 0, 2, 2][i]);
            assert_eq!(holds, u32::from([3, 4].contains(&i)));
        }
        // Replay with a reduced, valid-looking tag list must not bless UNKNOWN.
        let mut replay = fixtures[2].1.clone();
        replay.tags = vec![vec!["e".into(), fixtures[2].0.message_id_hex.clone()]];
        app.record_app_event_with_source(&replay, None, Some(authority()))
            .unwrap();
        assert_deleted(&app, &fixtures[2].0, false);
        // The once-only hold is separate from both original validity and body.
        let body: String = app
            .lock()
            .unwrap()
            .query_row(
                "SELECT plaintext FROM app_events WHERE group_id_hex=?1 AND message_id_hex=?2",
                params![GROUP, fixtures[4].1.message_id_hex],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(body, "");
        // A failed rewrite must roll back the source and cascading hold deletion.
        app.lock().unwrap().execute_batch("CREATE TEMP TRIGGER fail_removal_projection BEFORE UPDATE ON message_timeline BEGIN SELECT RAISE(ABORT,'injected removal projection failure'); END;").unwrap();
        let mut rewrite = fixtures[3].1.clone();
        rewrite.kind = 9;
        let err = app.record_app_event(&rewrite).unwrap_err();
        assert!(
            err.to_string()
                .contains("injected removal projection failure"),
            "{err}"
        );
        app.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_removal_projection")
            .unwrap();
        app.rebuild_message_timeline_for_group(GROUP).unwrap();
        assert_deleted(&app, &fixtures[3].0, true);
        // Expiring the UNKNOWN control itself must retain its exact hold and
        // scrub the original body and optional tags while the target remains.
        app.secure_prune_expired_app_events(GROUP, 43, "local", &|_, _| false)
            .unwrap();
        app.rebuild_message_timeline_for_group(GROUP).unwrap();
        assert_expired_hold(&app);
    }
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    app.rebuild_message_timeline_for_group(GROUP).unwrap();
    assert_expired_hold(&app);
    for (i, (target, _)) in fixtures.iter().enumerate() {
        assert_deleted(&app, target, [0, 3, 4, 7, 8].contains(&i));
    }
    app.invalidate_app_event_by_message_id(GROUP, &fixtures[3].1.message_id_hex, "withdrawn")
        .unwrap();
    assert_deleted(&app, &fixtures[3].0, false);
    // Expiry of a visible UNKNOWN target must not acquire a replay fence.
    app.secure_prune_app_events_before(GROUP, 29, "local", &|_, _| false)
        .unwrap();
    // The held target's expiry fence must reject redelivery; the visible
    // UNKNOWN target beside it remains eligible for ordinary redelivery.
    let replay = app.record_app_event(&fixtures[4].0).unwrap();
    assert!(replay.messages.is_empty() && replay.changes.is_empty());
    assert!(
        app.timeline_message(GROUP, &fixtures[4].0.message_id_hex)
            .unwrap()
            .is_none()
    );
    app.record_app_event(&fixtures[5].0).unwrap();
    assert_deleted(&app, &fixtures[5].0, false);
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    app.record_app_event(&fixtures[4].0).unwrap();
    app.rebuild_message_timeline_for_group(GROUP).unwrap();
    assert!(
        app.timeline_message(GROUP, &fixtures[4].0.message_id_hex)
            .unwrap()
            .is_none()
    );
    assert_deleted(&app, &fixtures[5].0, false);
}

#[test]
fn removal_validation_and_source_edges_roll_back_with_failed_projection() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let target = source(9, 10, vec![], "visible");
    let control = removal(&target, 11, false);
    app.record_app_event(&target).unwrap();
    app.lock().unwrap().execute_batch("CREATE TEMP TRIGGER fail_removal_projection BEFORE UPDATE ON message_timeline BEGIN SELECT RAISE(ABORT,'injected removal projection failure'); END;").unwrap();
    let err = app
        .record_app_event_with_source(&control, None, Some(authority()))
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("injected removal projection failure"),
        "{err}"
    );
    let conn = app.lock().unwrap();
    for table in [
        "app_events",
        "content_removal_validation",
        "content_removal_legacy_holds",
    ] {
        let count: i64 = conn
            .query_row(
                &format!(
                    "SELECT count(*) FROM {table} WHERE group_id_hex=?1 AND message_id_hex=?2"
                ),
                params![GROUP, control.message_id_hex],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    let edges: i64 = conn.query_row("SELECT count(*) FROM message_modifier_edges WHERE group_id_hex=?1 AND modifier_message_id_hex=?2",params![GROUP,control.message_id_hex],|r|r.get(0)).unwrap();
    assert_eq!(edges, 0);
    drop(conn);
    assert_deleted(&app, &target, false);
}
