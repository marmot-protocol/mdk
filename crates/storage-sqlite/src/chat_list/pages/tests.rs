use super::*;
use crate::SqliteAccountStorage;
use cgka_traits::storage::{DisbandFailureReason, DisbandRequestStorage, LeaveRequestStorage};
use cgka_traits::types::GroupId;
use rusqlite::params;

fn seed(
    store: &SqliteAccountStorage,
    id: &str,
    archived: bool,
    membership: &str,
    unread: i64,
    pending: bool,
) {
    let conn = store.lock().unwrap();
    conn.execute("INSERT INTO account_groups(group_id_hex, endpoint, updated_at, archived, self_membership, pending_confirmation) VALUES (?1, '', 0, ?2, ?3, ?4)", params![id, archived, membership, pending]).unwrap();
    conn.execute("INSERT INTO chat_list_rows(group_id_hex, updated_at, archived, self_membership, unread_count, pending_confirmation) VALUES (?1, 0, ?2, ?3, ?4, ?5)", params![id, archived, membership, unread, pending]).unwrap();
}
fn page(store: &SqliteAccountStorage, view: ChatListView) -> ChatListPage {
    store
        .chat_list_page(ChatListPageQuery {
            view,
            limit: 100,
            direction: ChatListPageDirection::Forward,
            cursor: None,
        })
        .unwrap()
}
fn ids(page: &ChatListPage) -> Vec<&str> {
    page.rows.iter().map(|r| r.group_id_hex.as_str()).collect()
}

#[test]
fn four_lists_partition_terminal_and_archive_state_and_suppress_invites_from_unread() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", false, "member", 0, false);
    seed(&store, "02", false, "member", 1, false);
    seed(&store, "03", true, "member", 1, false);
    seed(&store, "04", false, "left", 1, false);
    seed(&store, "05", true, "removed", 1, false);
    seed(&store, "06", false, "member", 9, true);
    assert_eq!(ids(&page(&store, ChatListView::Chats)), ["01", "02", "06"]);
    assert_eq!(ids(&page(&store, ChatListView::Unread)), ["02"]);
    assert_eq!(ids(&page(&store, ChatListView::Archived)), ["03"]);
    assert_eq!(ids(&page(&store, ChatListView::Left)), ["04", "05"]);
}

fn engine_group(store: &SqliteAccountStorage, id: &str) -> GroupId {
    let bytes = hex::decode(id).unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_groups(id, epoch, record) VALUES (?1, 0, x'00')",
            [&bytes],
        )
        .unwrap();
    GroupId::new(bytes)
}
fn query(
    view: ChatListView,
    limit: usize,
    direction: ChatListPageDirection,
    cursor: Option<ChatListCursor>,
) -> ChatListPageQuery {
    ChatListPageQuery {
        view,
        limit,
        direction,
        cursor,
    }
}

#[test]
fn mixed_case_ids_follow_engine_lifecycle_writes_and_read_operation_overlays() {
    for id in ["ABCD", "aBcD"] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store, id, false, "member", 4, false);
        let group = engine_group(&store, id);
        store
            .put_leave_request(&LeaveRequest {
                group_id: group.clone(),
                requested_at_ms: 123,
                last_proposed_epoch: None,
            })
            .unwrap();
        assert!(page(&store, ChatListView::Chats).rows.is_empty(), "{id}");
        assert_eq!(
            page(&store, ChatListView::Left).rows[0].leave_requested_at_ms,
            Some(123)
        );
        store.clear_leave_request(&group).unwrap();
        assert_eq!(ids(&page(&store, ChatListView::Chats)), [id]);
        let mut request = DisbandRequest {
            group_id: group.clone(),
            requested_at_ms: 124,
            status: DisbandRequestStatus::Pending,
            last_prepared_epoch: None,
        };
        store.put_disband_request(&request).unwrap();
        assert!(page(&store, ChatListView::Left).rows[0].disbanding);
        request.status = DisbandRequestStatus::Failed(DisbandFailureReason::NoLongerAdmin);
        store.put_disband_request(&request).unwrap();
        assert_eq!(
            page(&store, ChatListView::Chats).rows[0].disband_request,
            Some(request)
        );
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_disband_candidates VALUES (?1, x'01', x'00')",
                [group.as_slice()],
            )
            .unwrap();
        assert!(page(&store, ChatListView::Left).rows[0].disbanding);
        store
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM cgka_disband_candidates WHERE group_id = ?1",
                [group.as_slice()],
            )
            .unwrap();
        assert_eq!(ids(&page(&store, ChatListView::Chats)), [id]);
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_disband_tombstones VALUES (?1, x'00')",
                [group.as_slice()],
            )
            .unwrap();
        assert!(page(&store, ChatListView::Chats).rows.is_empty());
        assert_eq!(
            page(&store, ChatListView::Left).rows[0].lifecycle_state,
            cgka_traits::GroupLifecycleState::Disbanded
        );
        store
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM cgka_disband_tombstones WHERE group_id = ?1",
                [group.as_slice()],
            )
            .unwrap();
        assert_eq!(ids(&page(&store, ChatListView::Chats)), [id]);
    }
}

#[test]
fn queued_leave_and_disband_states_follow_engine_writes_without_subscribers() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", false, "member", 4, false);
    let group = engine_group(&store, "01");
    let cursor = page(&store, ChatListView::Chats).last;
    store
        .put_leave_request(&LeaveRequest {
            group_id: group.clone(),
            requested_at_ms: 123,
            last_proposed_epoch: None,
        })
        .unwrap();
    assert!(page(&store, ChatListView::Chats).rows.is_empty());
    let left = page(&store, ChatListView::Left);
    assert_eq!(left.rows[0].leave_requested_at_ms, Some(123));
    assert_eq!(left.rows[0].self_membership, crate::SelfMembership::Member);
    assert!(matches!(
        store.chat_list_page(query(
            ChatListView::Chats,
            1,
            ChatListPageDirection::Forward,
            cursor
        )),
        Err(ChatListPageError::StaleCursor)
    ));
    store.clear_leave_request(&group).unwrap();
    assert_eq!(ids(&page(&store, ChatListView::Chats)), ["01"]);
    let mut request = DisbandRequest {
        group_id: group.clone(),
        requested_at_ms: 124,
        status: DisbandRequestStatus::Pending,
        last_prepared_epoch: None,
    };
    store.put_disband_request(&request).unwrap();
    assert!(page(&store, ChatListView::Left).rows[0].disbanding);
    request.status = DisbandRequestStatus::Failed(DisbandFailureReason::NoLongerAdmin);
    store.put_disband_request(&request).unwrap();
    let active = page(&store, ChatListView::Chats);
    assert!(!active.rows[0].disbanding);
    assert_eq!(active.rows[0].disband_request, Some(request));
    // An authenticated candidate gates work even when our own request failed.
    store.lock().unwrap().execute("INSERT INTO cgka_disband_candidates(group_id, commit_id, record) VALUES (?1, x'01', x'00')", [group.as_slice()]).unwrap();
    assert!(page(&store, ChatListView::Left).rows[0].disbanding);
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM cgka_disband_candidates WHERE group_id = ?1",
            [group.as_slice()],
        )
        .unwrap();
    assert_eq!(ids(&page(&store, ChatListView::Chats)), ["01"]);
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_disband_tombstones(group_id, record) VALUES (?1, x'00')",
            [group.as_slice()],
        )
        .unwrap();
    assert_eq!(
        page(&store, ChatListView::Left).rows[0].lifecycle_state,
        cgka_traits::GroupLifecycleState::Disbanded
    );
}

#[test]
fn pins_filter_before_paging_and_keep_normalized_positions_with_gaps() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for id in ["01", "02", "03", "04", "05"] {
        seed(
            &store,
            id,
            false,
            "member",
            if id == "02" { 0 } else { 1 },
            false,
        );
    }
    {
        let conn = store.lock().unwrap();
        conn.execute_batch(
            "INSERT INTO chat_pin_positions VALUES ('03', 10), ('02', 20), ('01', 30);
            UPDATE chat_list_rows SET activity_sort_at = 50 WHERE group_id_hex = '05';",
        )
        .unwrap();
    }
    let all = page(&store, ChatListView::Chats);
    assert_eq!(ids(&all), ["03", "02", "01", "05", "04"]);
    assert_eq!(
        all.rows
            .iter()
            .map(|r| r.pinned_position)
            .collect::<Vec<_>>(),
        [Some(0), Some(1), Some(2), None, None]
    );
    assert_eq!(
        ids(&page(&store, ChatListView::Unread)),
        ["03", "01", "05", "04"]
    );
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET archived = 1 WHERE group_id_hex = '02'",
            [],
        )
        .unwrap();
    let all = page(&store, ChatListView::Chats);
    assert_eq!(all.rows[1].pinned_position, Some(1));
    // Changing ordinal and inserting ahead maintain ranks without a read-time pin scan.
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_pin_positions SET ordinal = 5 WHERE group_id_hex = '01'",
            [],
        )
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute("INSERT INTO chat_pin_positions VALUES ('04', 1)", [])
        .unwrap();
    let all = page(&store, ChatListView::Chats);
    assert_eq!(ids(&all), ["04", "01", "03", "05"]);
    assert_eq!(all.rows[2].pinned_position, Some(2));
    let first = store
        .chat_list_page(query(
            ChatListView::Chats,
            2,
            ChatListPageDirection::Forward,
            None,
        ))
        .unwrap();
    assert_eq!(ids(&first), ["04", "01"]);
    assert!(!first.has_more_before && first.has_more_after);
    let second = store
        .chat_list_page(query(
            ChatListView::Chats,
            2,
            ChatListPageDirection::Forward,
            first.last.clone(),
        ))
        .unwrap();
    assert_eq!(ids(&second), ["03", "05"]);
    assert!(second.has_more_before && !second.has_more_after);
    let back = store
        .chat_list_page(query(
            ChatListView::Chats,
            2,
            ChatListPageDirection::Backward,
            second.first,
        ))
        .unwrap();
    assert_eq!(ids(&back), ids(&first));
    let tail = store
        .chat_list_page(query(
            ChatListView::Chats,
            2,
            ChatListPageDirection::Backward,
            None,
        ))
        .unwrap();
    assert_eq!(ids(&tail), ["03", "05"]);
    let empty = store
        .chat_list_page(query(
            ChatListView::Chats,
            2,
            ChatListPageDirection::Forward,
            tail.last,
        ))
        .unwrap();
    assert!(empty.rows.is_empty() && empty.has_more_before && !empty.has_more_after);
}

#[test]
fn manual_unread_invite_acceptance_and_source_membership_change_are_immediate() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", false, "member", 0, false);
    seed(&store, "02", false, "member", 8, true);
    let conn = store.lock().unwrap();
    conn.execute(
        "UPDATE chat_list_rows SET manually_marked_unread = 1 WHERE group_id_hex = '01'",
        [],
    )
    .unwrap();
    drop(conn);
    assert_eq!(ids(&page(&store, ChatListView::Unread)), ["01"]);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET pending_confirmation = 0 WHERE group_id_hex = '02'",
            [],
        )
        .unwrap();
    let unread = page(&store, ChatListView::Unread);
    assert_eq!(ids(&unread), ["01", "02"]);
    assert!(!unread.rows[1].pending_confirmation);
    assert_eq!(unread.rows[1].unread_count, 8);
    // A source membership update is visible before the legacy chat row is refreshed.
    store
        .set_group_self_membership("01", crate::SelfMembership::Removed)
        .unwrap();
    assert_eq!(ids(&page(&store, ChatListView::Unread)), ["02"]);
    assert_eq!(
        page(&store, ChatListView::Left).rows[0].self_membership,
        crate::SelfMembership::Removed
    );
    store
        .set_group_self_membership("01", crate::SelfMembership::Member)
        .unwrap();
    assert_eq!(ids(&page(&store, ChatListView::Unread)), ["01", "02"]);
}

#[test]
fn cursor_rejects_cross_store_view_and_mutation_but_not_presentation_only_change() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", false, "member", 1, false);
    seed(&store, "02", false, "member", 1, false);
    let cursor = page(&store, ChatListView::Chats).first;
    for limit in [0, 101, usize::MAX] {
        assert!(matches!(
            store.chat_list_page(query(
                ChatListView::Chats,
                limit,
                ChatListPageDirection::Forward,
                None
            )),
            Err(ChatListPageError::InvalidLimit)
        ));
    }
    let other = SqliteAccountStorage::in_memory().unwrap();
    assert!(matches!(
        other.chat_list_page(query(
            ChatListView::Chats,
            1,
            ChatListPageDirection::Forward,
            cursor.clone()
        )),
        Err(ChatListPageError::CursorMismatch)
    ));
    assert!(matches!(
        store.chat_list_page(query(
            ChatListView::Unread,
            1,
            ChatListPageDirection::Forward,
            cursor.clone()
        )),
        Err(ChatListPageError::CursorMismatch)
    ));
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_list_rows SET title = 'changed' WHERE group_id_hex = '02'",
            [],
        )
        .unwrap();
    assert_eq!(
        store
            .chat_list_page(query(
                ChatListView::Chats,
                1,
                ChatListPageDirection::Forward,
                cursor.clone()
            ))
            .unwrap()
            .rows[0]
            .title,
        "changed"
    );
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_list_rows SET activity_sort_at = 90 WHERE group_id_hex = '02'",
            [],
        )
        .unwrap();
    assert!(matches!(
        store.chat_list_page(query(
            ChatListView::Chats,
            1,
            ChatListPageDirection::Forward,
            cursor
        )),
        Err(ChatListPageError::StaleCursor)
    ));
}

#[test]
fn navigation_and_cursor_revision_roll_back_with_failed_source_write() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", false, "member", 1, false);
    let cursor = page(&store, ChatListView::Chats).last;
    {
        let conn = store.lock().unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        tx.execute("UPDATE account_groups SET archived = 1", [])
            .unwrap();
        assert_eq!(
            tx.query_row("SELECT list_scope FROM chat_list_rows", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        // Dropping without commit simulates an aborted source mutation.
    }
    assert_eq!(ids(&page(&store, ChatListView::Chats)), ["01"]);
    assert!(
        store
            .chat_list_page(query(
                ChatListView::Chats,
                1,
                ChatListPageDirection::Forward,
                cursor
            ))
            .is_ok()
    );
}

#[test]
fn page_does_not_decode_unrelated_operation_records() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", false, "member", 0, false);
    let group = engine_group(&store, "02");
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_leave_requests VALUES (?1, x'00')",
            [group.as_slice()],
        )
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_disband_requests VALUES (?1, x'00')",
            [group.as_slice()],
        )
        .unwrap();
    assert_eq!(ids(&page(&store, ChatListView::Chats)), ["01"]);
}

#[test]
fn reopening_preserves_queued_leave_and_bounded_navigation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite3");
    let key = crate::SqlCipherKey::new("07".repeat(32)).unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "01", true, "member", 3, false);
    let group = engine_group(&store, "01");
    store
        .put_leave_request(&LeaveRequest {
            group_id: group,
            requested_at_ms: 123,
            last_proposed_epoch: None,
        })
        .unwrap();
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(page(&store, ChatListView::Archived).rows.is_empty());
    assert_eq!(
        page(&store, ChatListView::Left).rows[0].leave_requested_at_ms,
        Some(123)
    );
}

#[test]
fn filtered_page_query_work_stays_bounded_with_unrelated_rows_and_history() {
    use crate::query_work_test_support::measure;
    for (count, pin_cap) in [(256, 8), (4096, 8), (256, 256), (4096, 4096)] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute_batch(&format!("CREATE TEMP TABLE numbers(x INTEGER PRIMARY KEY);
                WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < {count}) INSERT INTO numbers SELECT x FROM n;
                INSERT INTO account_groups(group_id_hex, endpoint, updated_at, archived, self_membership)
                    SELECT printf('%032x',x), '', 0, x % 4 = 0, CASE WHEN x % 4 = 1 THEN 'left' ELSE 'member' END FROM numbers;
                INSERT INTO chat_list_rows(group_id_hex, updated_at, activity_sort_at, unread_count)
                    SELECT printf('%032x',x), 0, x, x % 7 = 0 FROM numbers;
                INSERT INTO chat_pin_positions(group_id_hex, ordinal) SELECT printf('%032x',x), x FROM numbers WHERE x % 4 = 2 AND x <= {pin_cap};
                INSERT INTO app_events(group_id_hex, message_id_hex, direction, sender, plaintext, kind, tags_json, recorded_at, received_at)
                    SELECT 'unrelated', printf('%064x',x), 'received', 'sender', 'text', 9, '[]', x, x FROM numbers;
                INSERT INTO cgka_groups(id, epoch, record) SELECT CAST(printf('unrelated-%06d',x) AS BLOB), 0, x'00' FROM numbers;
                INSERT INTO cgka_leave_requests SELECT id, x'00' FROM cgka_groups;
                INSERT INTO cgka_disband_requests SELECT id, x'00' FROM cgka_groups;
                INSERT INTO cgka_disband_candidates SELECT id, x'01', x'00' FROM cgka_groups;
                DROP TABLE numbers;")).unwrap();
        }
        for view in [
            ChatListView::Chats,
            ChatListView::Unread,
            ChatListView::Archived,
            ChatListView::Left,
        ] {
            let tail = store
                .chat_list_page(query(view, 10, ChatListPageDirection::Backward, None))
                .unwrap();
            for limit in [10, 100] {
                for (direction, cursor) in [
                    (ChatListPageDirection::Forward, None),
                    (ChatListPageDirection::Backward, tail.first.clone()),
                ] {
                    let (result, steps) = measure(&store, || {
                        store
                            .chat_list_page(query(view, limit, direction, cursor.clone()))
                            .unwrap()
                    });
                    assert!(
                        steps < if limit == 10 { 2200 } else { 19000 },
                        "{count} pins={pin_cap} limit={limit} {view:?} {direction:?}: {steps} VM steps"
                    );
                    assert!(!result.rows.is_empty() && result.rows.len() <= limit);
                    eprintln!(
                        "rows={count} pins={pin_cap} limit={limit} view={view:?} direction={direction:?} vm_steps={steps}"
                    );
                    let relation = cursor.as_ref().map(|_| "<");
                    let sql = format!(
                        "EXPLAIN QUERY PLAN {}",
                        navigation_sql(view, relation, direction, false)
                    );
                    let mut values = cursor
                        .as_ref()
                        .map(|c| key_params(&c.key))
                        .unwrap_or_default();
                    values.push((limit as i64).into());
                    let conn = store.lock().unwrap();
                    let mut stmt = conn.prepare(&sql).unwrap();
                    let plan = stmt
                        .query_map(params_from_iter(values), |r| r.get::<_, String>(3))
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap()
                        .join("\n");
                    assert!(!plan.contains("TEMP B-TREE"), "{plan}");
                    assert!(plan.contains(view.index()), "{plan}");
                }
            }
        }
        // Test late pinned and unpinned rows: ordinary message/read writes must not
        // scan pin ranks or unrelated conversations while maintaining the navigation keys.
        for id in [count - 2, count - 1] {
            let group = format!("{id:032x}");
            let (_, steps) = measure(&store, || {
                store.lock().unwrap().execute(
                    "UPDATE chat_list_rows SET unread_count = unread_count + 1, activity_sort_at = activity_sort_at + 1 WHERE group_id_hex = ?1", [&group]).unwrap();
            });
            eprintln!("rows={count} source_update_vm_steps={steps}");
            assert!(steps < 1000, "{count} source write: {steps} VM steps");
            let group = engine_group(&store, &group);
            let (_, steps) = measure(&store, || {
                store
                    .put_leave_request(&LeaveRequest {
                        group_id: group.clone(),
                        requested_at_ms: 123,
                        last_proposed_epoch: None,
                    })
                    .unwrap();
            });
            eprintln!("rows={count} engine_write_vm_steps={steps}");
            assert!(steps < 1000, "{count} engine write: {steps} VM steps");
        }
    }
}

#[test]
fn missing_projected_pin_and_row_recreation_keep_authoritative_global_pin_ranks() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for id in ["01", "02", "03"] {
        seed(&store, id, false, "member", 1, false);
    }
    store
        .lock()
        .unwrap()
        .execute_batch(
            "INSERT INTO chat_pin_positions VALUES ('01',0), ('02',5), ('03',9);
        DELETE FROM chat_list_rows WHERE group_id_hex = '02';",
        )
        .unwrap();
    assert_eq!(
        page(&store, ChatListView::Chats).rows[1].pinned_position,
        Some(2)
    );
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM chat_pin_positions WHERE group_id_hex = '02'",
            [],
        )
        .unwrap();
    assert_eq!(
        page(&store, ChatListView::Chats).rows[1].pinned_position,
        Some(1)
    );
    store
        .lock()
        .unwrap()
        .execute_batch(
            "INSERT INTO chat_pin_positions VALUES ('02',5);
        INSERT INTO chat_list_rows(group_id_hex, updated_at) VALUES('02',0);",
        )
        .unwrap();
    let result = page(&store, ChatListView::Chats);
    assert_eq!(ids(&result), ["01", "02", "03"]);
    assert_eq!(
        result
            .rows
            .iter()
            .map(|r| r.pinned_position)
            .collect::<Vec<_>>(),
        [Some(0), Some(1), Some(2)]
    );
}

#[test]
fn legacy_disband_record_without_status_retains_pending_semantics() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", false, "member", 0, false);
    let group = engine_group(&store, "01");
    store
        .put_disband_request(&DisbandRequest {
            group_id: group,
            requested_at_ms: 123,
            status: DisbandRequestStatus::Pending,
            last_prepared_epoch: None,
        })
        .unwrap();
    store.lock().unwrap().execute_batch("UPDATE cgka_disband_requests SET record = CAST(json_remove(CAST(record AS TEXT),'$.status') AS BLOB)").unwrap();
    assert!(page(&store, ChatListView::Left).rows[0].disbanding);
    assert!(page(&store, ChatListView::Chats).rows.is_empty());
}

#[test]
fn stable_anchor_recovers_deep_page_after_unrelated_traffic_without_restarting_at_top() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for n in 1..=260 {
        seed(&store, &format!("{n:04x}"), false, "member", 1, false);
    }
    for tick in 1..=3 {
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE chat_list_rows SET activity_sort_at = ?1 WHERE group_id_hex = '0001'",
                [tick],
            )
            .unwrap();
        let anchored = store
            .chat_list_page_from_anchor(
                ChatListView::Chats,
                "00c8",
                50,
                ChatListPageDirection::Forward,
            )
            .unwrap();
        assert_eq!(anchored.rows.first().unwrap().group_id_hex, "00c8");
        assert_eq!(anchored.rows.len(), 50);
        assert!(anchored.has_more_before && anchored.has_more_after);
        let preceding = store
            .chat_list_page_from_anchor(
                ChatListView::Chats,
                "00c8",
                50,
                ChatListPageDirection::Backward,
            )
            .unwrap();
        assert_eq!(preceding.rows.last().unwrap().group_id_hex, "00c8");
    }
    assert!(matches!(
        store.chat_list_page_from_anchor(
            ChatListView::Archived,
            "00c8",
            50,
            ChatListPageDirection::Forward
        ),
        Err(ChatListPageError::AnchorUnavailable)
    ));
    store
        .lock()
        .unwrap()
        .execute("DELETE FROM chat_list_rows WHERE group_id_hex = '00c8'", [])
        .unwrap();
    assert!(matches!(
        store.chat_list_page_from_anchor(
            ChatListView::Chats,
            "00c8",
            50,
            ChatListPageDirection::Forward
        ),
        Err(ChatListPageError::AnchorUnavailable)
    ));
}

#[test]
fn accepting_an_archived_invite_preserves_archive_and_source_fields() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", true, "member", 7, true);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET pending_confirmation = 0 WHERE group_id_hex = '01'",
            [],
        )
        .unwrap();
    let archived = page(&store, ChatListView::Archived);
    assert_eq!(ids(&archived), ["01"]);
    assert!(archived.rows[0].archived);
    assert!(!archived.rows[0].pending_confirmation);
    assert_eq!(archived.rows[0].unread_count, 7);
    assert!(page(&store, ChatListView::Chats).rows.is_empty());
    assert!(page(&store, ChatListView::Unread).rows.is_empty());
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET archived = 0 WHERE group_id_hex = '01'",
            [],
        )
        .unwrap();
    let active = page(&store, ChatListView::Unread);
    assert!(!active.rows[0].archived);
    // The source overlay is observable even before the legacy row is refreshed.
    assert!(store.chat_list_row("01").unwrap().unwrap().archived);
}
