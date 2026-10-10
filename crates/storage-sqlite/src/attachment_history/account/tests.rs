use super::*;
use rusqlite::params;
fn seed(s: &SqliteAccountStorage, group: &str, id: usize, slots: usize, at: i64) {
    s.lock().unwrap().execute("INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,
        source_epoch,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json,media_json)
        VALUES(?1,?2,?2,0,'received',?3,'private body',9,'[]',?4,?4,'[]',?5)",
        params![group,format!("{id:064x}"),"11".repeat(32),at,
            serde_json::json!({"imeta":(0..slots).map(|_|serde_json::json!(["imeta","v future"])).collect::<Vec<_>>()}).to_string()]).unwrap();
}
#[test]
fn global_albums_equal_times_and_sparse_chats_page_once() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    for (group, at) in [("aa", 9), ("bb", 9), ("cc", 8)] {
        for id in 0..12 {
            seed(&s, group, id, 3, at);
        }
    }
    for limit in [1, 2, 7, 100] {
        let mut cursor = None;
        let mut result = Vec::new();
        loop {
            let page = s
                .account_attachment_history_page(
                    &AccountAttachmentQuery::default(),
                    limit,
                    cursor.as_ref(),
                )
                .unwrap();
            assert!(page.entries.len() <= limit);
            result.extend(page.entries.iter().map(|e| {
                (
                    e.group_id_hex.clone(),
                    e.attachment.message_id_hex.clone(),
                    e.attachment.attachment_index,
                )
            }));
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        let expected: Vec<_> = ["bb", "aa", "cc"]
            .into_iter()
            .flat_map(|g| {
                (0..12).rev().flat_map(move |id| {
                    (0..3).map(move |slot| (g.to_owned(), format!("{id:064x}"), slot))
                })
            })
            .collect();
        assert_eq!(result, expected);
    }
}
#[test]
fn filtered_empty_page_keeps_its_authoritative_continuation() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    seed(&s, "aa", 1, 3, 10);
    seed(&s, "bb", 2, 2, 9);
    let query = AccountAttachmentQuery {
        groups: vec!["BB".into(), "bb".into()],
        senders: vec!["11".repeat(32)],
        after: Some(9),
        before: Some(10),
    };
    let first = s.account_attachment_history_page(&query, 3, None).unwrap();
    assert!(first.entries.is_empty());
    let next = s
        .account_attachment_history_page(&query, 3, first.next_cursor.as_ref())
        .unwrap();
    assert_eq!(next.entries.len(), 2);
    assert!(next.next_cursor.is_none());
    assert!(next.entries.iter().all(|e| e.group_id_hex == "bb"));
    let other = AccountAttachmentQuery {
        groups: vec!["aa".into()],
        ..query.clone()
    };
    assert!(matches!(
        s.account_attachment_history_page(&other, 3, first.next_cursor.as_ref()),
        Err(AccountAttachmentHistoryError::CursorMismatch)
    ));
}
#[test]
fn every_source_visibility_role_and_incarnation_change_fences_old_pages() {
    for mutation in [
        "UPDATE message_timeline SET deleted=1 WHERE group_id_hex='bb'",
        "UPDATE message_timeline SET invalidation_status='branch_selection_withdrawn' WHERE group_id_hex='bb'",
        "UPDATE message_timeline SET media_json='{}' WHERE group_id_hex='bb'",
        "UPDATE message_timeline SET tags_json='[[\"emoji\",\"x\",\"https://example.com/a\"]]' WHERE group_id_hex='bb'",
        "DELETE FROM attachment_history_versions WHERE group_id_hex='bb'",
    ] {
        let s = SqliteAccountStorage::in_memory().unwrap();
        seed(&s, "aa", 1, 1, 12);
        seed(&s, "bb", 2, 1, 11);
        let first = s
            .account_attachment_history_page(&AccountAttachmentQuery::default(), 1, None)
            .unwrap();
        s.lock().unwrap().execute_batch(mutation).unwrap();
        assert!(matches!(
            s.account_attachment_history_page(
                &AccountAttachmentQuery::default(),
                1,
                first.next_cursor.as_ref()
            ),
            Err(AccountAttachmentHistoryError::RestartRequired)
        ));
        assert_ne!(
            s.account_attachment_history_version().unwrap(),
            first.version
        );
    }
    let s = SqliteAccountStorage::in_memory().unwrap();
    seed(&s, "aa", 1, 2, 1);
    let first = s
        .account_attachment_history_page(&AccountAttachmentQuery::default(), 1, None)
        .unwrap();
    let other = SqliteAccountStorage::in_memory().unwrap();
    assert!(matches!(
        other.account_attachment_history_page(
            &AccountAttachmentQuery::default(),
            1,
            first.next_cursor.as_ref()
        ),
        Err(AccountAttachmentHistoryError::CursorMismatch)
    ));
}
#[test]
fn reactions_are_quiet_and_additions_keep_old_seek_boundaries() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    seed(&s, "aa", 1, 2, 1);
    let first = s
        .account_attachment_history_page(&AccountAttachmentQuery::default(), 1, None)
        .unwrap();
    s.lock()
        .unwrap()
        .execute_batch("UPDATE message_timeline SET reactions_json='[1]'")
        .unwrap();
    assert_eq!(
        s.account_attachment_history_version().unwrap(),
        first.version
    );
    seed(&s, "bb", 2, 1, 2);
    assert!(
        !s.account_attachment_history_version()
            .unwrap()
            .requires_restart_since(&first.version)
    );
    let next = s
        .account_attachment_history_page(
            &AccountAttachmentQuery::default(),
            1,
            first.next_cursor.as_ref(),
        )
        .unwrap();
    assert_eq!(next.entries[0].attachment.attachment_index, 1);
    let refresh = s
        .account_attachment_history_page(&AccountAttachmentQuery::default(), 1, None)
        .unwrap();
    assert_eq!(refresh.entries[0].group_id_hex, "bb");
}
#[test]
fn invalid_bounds_ids_ceilings_and_oversized_metadata_fail_without_partial_results() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    for limit in [0, 101, usize::MAX] {
        assert!(matches!(
            s.account_attachment_history_page(&AccountAttachmentQuery::default(), limit, None),
            Err(AccountAttachmentHistoryError::InvalidLimit)
        ));
    }
    for query in [
        AccountAttachmentQuery {
            groups: vec!["not-hex".into()],
            ..Default::default()
        },
        AccountAttachmentQuery {
            senders: vec!["aa".into()],
            ..Default::default()
        },
        AccountAttachmentQuery {
            groups: vec!["aa".into(); 101],
            ..Default::default()
        },
        AccountAttachmentQuery {
            after: Some(10),
            before: Some(9),
            ..Default::default()
        },
    ] {
        assert!(matches!(
            s.account_attachment_history_page(&query, 100, None),
            Err(AccountAttachmentHistoryError::InvalidQuery)
        ));
    }
    seed(&s, "aa", 1, 1, 1);
    s.lock()
        .unwrap()
        .execute(
            "UPDATE message_timeline SET media_json=?1",
            [serde_json::json!({"imeta":[["imeta","x".repeat(40000)]]}).to_string()],
        )
        .unwrap();
    assert!(matches!(
        s.account_attachment_history_page(&AccountAttachmentQuery::default(), 100, None),
        Err(AccountAttachmentHistoryError::ResponseTooLarge)
    ));
}
#[test]
fn account_seek_uses_index_without_a_history_sized_sort() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    for id in 0..2000 {
        seed(&s, "aa", id, 1, id as i64);
    }
    let conn = s.lock().unwrap();
    let explain = format!("EXPLAIN QUERY PLAN {}", sql(true));
    let mut stmt = conn.prepare(&explain).unwrap();
    let plan: Vec<String> = stmt
        .query_map(params![0, i64::MAX, 51, 1999, "aa", "ff", 0], |r| r.get(3))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|line| line.contains("idx_account_attachment_history_page"))
    );
    assert!(
        !plan.iter().any(|line| line.contains("TEMP B-TREE")),
        "{plan:?}"
    );
}

#[test]
fn expiry_fences_existing_cursors_before_maintenance_erases_sources() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    for id in [1u64, 2] {
        s.record_app_event(&crate::StoredAppEvent {
            group_id_hex: "aa".into(),
            message_id_hex: format!("{id:064x}"),
            source_message_id_hex: Some(format!("{id:064x}")),
            source_epoch: Some(0),
            direction: "received".into(),
            sender: "11".repeat(32),
            plaintext: "private".into(),
            kind: 9,
            tags: vec![vec!["imeta".into(), "v future".into()]],
            recorded_at: id,
            received_at: id,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    }
    s.lock()
        .unwrap()
        .execute(
            "UPDATE app_events SET retention_expires_at=11 WHERE message_id_hex=?1",
            [format!("{:064x}", 2)],
        )
        .unwrap();
    let first = s
        .account_attachment_history_page_at(&AccountAttachmentQuery::default(), 1, None, 10)
        .unwrap();
    assert_eq!(first.version.next_expiry, Some(11));
    assert!(matches!(
        s.account_attachment_history_page_at(
            &AccountAttachmentQuery::default(),
            1,
            first.next_cursor.as_ref(),
            11
        ),
        Err(AccountAttachmentHistoryError::RestartRequired)
    ));
    let fresh = s
        .account_attachment_history_page_at(&AccountAttachmentQuery::default(), 10, None, 11)
        .unwrap();
    assert_eq!(fresh.entries.len(), 1);
    assert_eq!(
        fresh.entries[0].attachment.message_id_hex,
        format!("{:064x}", 1)
    );
}
