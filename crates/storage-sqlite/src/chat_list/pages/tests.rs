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
fn pages_share_outer_transaction_without_committing_or_rolling_it_back() {
    use cgka_traits::storage::StorageProvider;
    for commit in [false, true] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        for id in ["01", "02", "03"] {
            seed(&store, id, false, "member", 0, false);
        }
        let before = page(&store, ChatListView::Chats).first;
        let result =
            StorageProvider::with_transaction(&store, |store| -> Result<(), ChatListPageError> {
                store
                    .lock()?
                    .execute(
                        "UPDATE chat_list_rows SET activity_sort_at = 99 WHERE group_id_hex = '03'",
                        [],
                    )
                    .storage()?;
                let first = store.chat_list_page(query(
                    ChatListView::Chats,
                    1,
                    ChatListPageDirection::Forward,
                    None,
                ))?;
                assert_eq!(ids(&first), ["03"]);
                let next = store.chat_list_page(query(
                    ChatListView::Chats,
                    1,
                    ChatListPageDirection::Forward,
                    first.last,
                ))?;
                assert_eq!(ids(&next), ["01"]);
                let anchored = store.chat_list_page_from_anchor(
                    ChatListView::Chats,
                    "02",
                    2,
                    ChatListPageDirection::Backward,
                )?;
                assert_eq!(ids(&anchored), ["01", "02"]);
                assert!(matches!(
                    store.chat_list_page_from_anchor(
                        ChatListView::Chats,
                        "missing",
                        2,
                        ChatListPageDirection::Forward,
                    ),
                    Err(ChatListPageError::AnchorUnavailable)
                ));
                assert!(!store.lock()?.is_autocommit());
                if commit {
                    Ok(())
                } else {
                    Err(ChatListPageError::InvalidLimit)
                }
            });
        assert_eq!(result.is_ok(), commit);
        if !commit {
            assert!(matches!(result, Err(ChatListPageError::InvalidLimit)));
        }
        assert!(store.lock().unwrap().is_autocommit());
        assert_eq!(
            ids(&page(&store, ChatListView::Chats)),
            if commit {
                vec!["03", "01", "02"]
            } else {
                vec!["01", "02", "03"]
            }
        );
        let resumed = store.chat_list_page(query(
            ChatListView::Chats,
            1,
            ChatListPageDirection::Forward,
            before,
        ));
        if commit {
            assert!(matches!(resumed, Err(ChatListPageError::StaleCursor)));
        } else {
            assert_eq!(ids(&resumed.unwrap()), ["02"]);
        }
    }
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
            let (_, anchor_steps) = measure(&store, || {
                store
                    .chat_list_page_from_anchor(
                        view,
                        &tail.rows.last().unwrap().group_id_hex,
                        10,
                        ChatListPageDirection::Backward,
                    )
                    .unwrap()
            });
            assert!(
                anchor_steps < 2400,
                "{count} pins={pin_cap} {view:?}: anchor used {anchor_steps} VM steps"
            );
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
                    if cursor.is_some() {
                        assert!(plan.contains("SEARCH"), "{plan}");
                        assert!(!plan.contains("SCAN"), "{plan}");
                    }
                }
            }
        }
        // Pin commands return/rewrite the complete pin set. Measure this separately from
        // bounded page and ordinary-write work; the budget rejects per-pin rank rebuilds.
        let new_pin = format!("{:032x}", count - 1);
        let (pin_state, pin_steps) =
            measure(&store, || store.set_chat_pinned(&new_pin, true).unwrap());
        let mut reordered = pin_state.ordered_group_ids.clone();
        reordered.reverse();
        let (_, reorder_steps) =
            measure(&store, || store.set_pinned_chat_order(&reordered).unwrap());
        let (_, unpin_steps) = measure(&store, || store.set_chat_pinned(&new_pin, false).unwrap());
        eprintln!(
            "rows={count} pins={} pin_vm_steps={pin_steps} reorder_vm_steps={reorder_steps} unpin_vm_steps={unpin_steps}",
            pin_state.ordered_group_ids.len()
        );
        for steps in [pin_steps, reorder_steps, unpin_steps] {
            assert!(
                steps < 5000 + 1500 * pin_state.ordered_group_ids.len() as i64,
                "pin command: {steps}"
            );
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
fn stable_anchor_accepts_normalized_ids_for_mixed_case_rows() {
    for id in ["ABCD", "aBcD"] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store, id, false, "member", 1, false);
        for direction in [
            ChatListPageDirection::Forward,
            ChatListPageDirection::Backward,
        ] {
            let anchored = store
                .chat_list_page_from_anchor(ChatListView::Chats, "abcd", 10, direction)
                .unwrap();
            assert_eq!(ids(&anchored), [id]);
            assert!(matches!(
                store.chat_list_page_from_anchor(ChatListView::Archived, "abcd", 10, direction),
                Err(ChatListPageError::AnchorUnavailable)
            ));
        }
    }
}

#[test]
fn legacy_disband_record_without_status_retains_pending_semantics() {
    assert_eq!(
        serde_json::to_value(DisbandRequestStatus::Pending).unwrap(),
        serde_json::json!("pending"),
        "migration 0072 freezes this durable status literal in trigger DDL"
    );
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

#[test]
fn batched_pin_rewrite_preserves_missing_rows_and_rolls_back_inside_outer_transaction() {
    use cgka_traits::StorageProvider;
    let store = SqliteAccountStorage::in_memory().unwrap();
    for id in ["01", "02", "03", "04"] {
        seed(&store, id, false, "member", 1, false);
    }
    for id in ["01", "02", "03"] {
        store.set_chat_pinned(id, true).unwrap();
    }
    store
        .lock()
        .unwrap()
        .execute("DELETE FROM chat_list_rows WHERE group_id_hex = '02'", [])
        .unwrap();
    let order = ["01", "02", "03"].map(String::from);
    store.set_pinned_chat_order(&order).unwrap();
    let current = page(&store, ChatListView::Chats);
    assert_eq!(ids(&current), ["01", "03", "04"]);
    assert_eq!(
        current
            .rows
            .iter()
            .map(|r| r.pinned_position)
            .collect::<Vec<_>>(),
        [Some(0), Some(2), None]
    );
    let boundary = current.last;
    store
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_pin_rebuild BEFORE UPDATE OF list_pin_ordinal ON chat_list_rows
        WHEN NEW.group_id_hex = '04' AND NEW.list_pin_ordinal = 0
        BEGIN SELECT RAISE(ABORT, 'injected pin rebuild failure'); END;",
        )
        .unwrap();
    StorageProvider::with_transaction(&store, |store| -> Result<(), StorageError> {
        assert!(store.set_chat_pinned("04", true).is_err());
        // Catching the command error must not commit a disabled trigger or half-rebuilt pins.
        assert_eq!(
            store
                .lock()?
                .query_row(
                    "SELECT pin_rewrite_in_progress FROM chat_list_navigation_meta",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .storage()?,
            0
        );
        assert_eq!(
            store.set_chat_pinned("01", true).unwrap().ordered_group_ids,
            order
        );
        Ok(())
    })
    .unwrap();
    assert!(
        store
            .chat_list_page(query(
                ChatListView::Chats,
                1,
                ChatListPageDirection::Backward,
                boundary
            ))
            .is_ok()
    );
    store
        .lock()
        .unwrap()
        .execute_batch(
            "DROP TRIGGER reject_pin_rebuild;
        INSERT INTO chat_list_rows(group_id_hex, updated_at) VALUES ('02',0);",
        )
        .unwrap();
    store.set_chat_pinned("03", false).unwrap();
    let current = page(&store, ChatListView::Chats);
    assert_eq!(ids(&current), ["01", "02", "03", "04"]);
    assert_eq!(
        current
            .rows
            .iter()
            .map(|r| r.pinned_position)
            .collect::<Vec<_>>(),
        [Some(0), Some(1), None, None]
    );
    // Ordinary source writes still maintain ranks after the batched path, without a caller.
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM chat_pin_positions WHERE group_id_hex = '01'",
            [],
        )
        .unwrap();
    let current = page(&store, ChatListView::Chats);
    assert_eq!(current.rows[0].group_id_hex, "02");
    assert_eq!(current.rows[0].pinned_position, Some(0));
}

fn window_query(
    limit: usize,
    anchors: &[&str],
    before_anchor: usize,
) -> crate::ChatListWindowQuery {
    crate::ChatListWindowQuery {
        view: ChatListView::Chats,
        limit,
        anchors: anchors.iter().map(|s| (*s).into()).collect(),
        before_anchor,
    }
}
fn prepare_window_fixture(store: &SqliteAccountStorage, id: &str) {
    use crate::{
        ConversationPresentation, PresentationResolution, PresentationSource, PresentationText,
        SelectedAvatar, StoredChatPresentation,
    };
    let input = store.chat_presentation_input(id).unwrap().unwrap();
    store
        .store_chat_presentation(
            &input,
            &StoredChatPresentation {
                presentation: ConversationPresentation {
                    title: PresentationText::Literal("Fixture".into()),
                    avatar: SelectedAvatar::Placeholder {
                        stable_seed: "fixture".into(),
                        source: PresentationSource::GroupFallback,
                    },
                    title_source: PresentationSource::Group,
                    avatar_source: PresentationSource::GroupFallback,
                    peer_id: None,
                    resolution: PresentationResolution::Cached,
                },
                profile_version: None,
            },
        )
        .unwrap();
}

#[test]
fn window_read_shares_one_snapshot_and_limits_only_required_selected_preparation() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for i in 0..250 {
        seed(&store, &format!("{i:04x}"), false, "member", 1, false);
    }
    prepare_window_fixture(&store, "0000");
    let read = store
        .read_chat_list_window(window_query(2, &[], 0))
        .unwrap();
    assert!(read.snapshot.is_none());
    assert_eq!(read.pending_presentations, ["0001"]);
    prepare_window_fixture(&store, "0001");
    let read = store
        .read_chat_list_window(window_query(2, &[], 0))
        .unwrap();
    assert_eq!(read.snapshot.unwrap().rows.len(), 2);
    assert!(read.pending_presentations.is_empty());
    assert_eq!(ids(&read.page), ["0000", "0001"]);
    // Fallback anchors are resolved in the same snapshot as both sides of the window.
    let read = store
        .read_chat_list_window(window_query(200, &["ffff", "007d"], 50))
        .unwrap();
    assert_eq!(read.anchor.as_deref(), Some("007d"));
    assert_eq!(read.page.rows.len(), 200);
    assert_eq!(
        read.page.rows[75].group_id_hex, "007d",
        "end fill retains the anchor while using available capacity"
    );
    assert!(!read.page.has_more_after);
    assert!(read.page.has_more_before);
    let reset = store
        .read_chat_list_window(window_query(20, &["ffff"], 4))
        .unwrap();
    assert!(reset.anchor.is_none());
    assert_eq!(reset.page.rows[0].group_id_hex, "0000");
}

#[test]
fn bounded_window_composes_with_caller_transaction_and_rolls_back_as_one_unit() {
    use cgka_traits::storage::{StorageError, StorageProvider};
    let store = SqliteAccountStorage::in_memory().unwrap();
    for i in 0..20 {
        let id = format!("{i:04x}");
        seed(&store, &id, false, "member", 1, false);
        prepare_window_fixture(&store, &id);
    }
    let result: Result<(), StorageError> = store.with_transaction(|s| {
        s.lock()?
            .execute(
                "UPDATE account_groups SET archived=1 WHERE group_id_hex='0004'",
                [],
            )
            .storage()?;
        let read = s
            .read_chat_list_window(window_query(10, &["0004", "0005"], 4))
            .unwrap();
        assert_eq!(read.anchor.as_deref(), Some("0005"));
        assert_eq!(read.snapshot.unwrap().rows[4].row.group_id_hex, "0005");
        Err(StorageError::NotFound)
    });
    assert!(result.is_err());
    let read = store
        .read_chat_list_window(window_query(10, &["0004"], 4))
        .unwrap();
    assert_eq!(read.anchor.as_deref(), Some("0004"));
}

#[test]
fn ready_window_sql_work_is_bounded_across_account_and_history_sizes() {
    use crate::query_work_test_support::measure;
    let mut measurements = Vec::new();
    for count in [20, 100, 200, 4096] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        for i in 0..count {
            let id = format!("{i:04x}");
            seed(&store, &id, false, "member", 1, false);
            prepare_window_fixture(&store, &id);
        }
        // Real retained app-event history in a visible conversation must not be hydrated by this read.
        store.lock().unwrap().execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<5000) INSERT INTO app_events(group_id_hex, message_id_hex, direction, sender, plaintext, kind, tags_json, recorded_at, received_at) SELECT '0000', printf('%064x',x), 'received', 'sender', 'retained history', 9, '[]', x, x FROM n;").unwrap();
        let (read, steps) = measure(&store, || {
            store
                .read_chat_list_window(window_query(20, &[], 0))
                .unwrap()
        });
        assert_eq!(read.snapshot.unwrap().rows.len(), 20);
        assert!(
            steps < 6500,
            "20-row window: {steps} SQL steps for {count} conversations"
        );
        measurements.push(steps);
        if count >= 200 {
            let (read, steps) = measure(&store, || {
                store
                    .read_chat_list_window(window_query(200, &["0096"], 150))
                    .unwrap()
            });
            assert_eq!(read.snapshot.unwrap().rows.len(), 200);
            assert!(
                steps < 60000,
                "200-row window: {steps} SQL steps for {count} conversations"
            );
        }
    }
    assert!(
        measurements.iter().max().unwrap() - measurements.iter().min().unwrap() < 500,
        "work should depend on window size: {measurements:?}"
    );
}

#[test]
fn authoritative_self_arrival_restores_departed_archive_once_and_preserves_ordinary_archive() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", true, "left", 4, false);
    seed(&store, "02", true, "removed", 3, false);
    seed(&store, "03", true, "member", 2, true);
    for id in ["01", "02"] {
        assert!(store.restore_group_self_membership(id).unwrap());
        assert_eq!(
            store.group_self_membership(id).unwrap(),
            Some(crate::SelfMembership::Member)
        );
    }
    assert!(!store.restore_group_self_membership("03").unwrap());
    assert_eq!(ids(&page(&store, ChatListView::Chats)), ["01", "02"]);
    assert_eq!(ids(&page(&store, ChatListView::Archived)), ["03"]);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET archived=1 WHERE group_id_hex='01'",
            [],
        )
        .unwrap();
    assert!(!store.restore_group_self_membership("01").unwrap());
    assert_eq!(ids(&page(&store, ChatListView::Archived)), ["01", "03"]);
}

#[test]
fn account_attention_adds_invites_without_changing_unread_list_or_mute_policy() {
    for archived in [false, true] {
        for pending in [false, true] {
            for membership in ["member", "left", "removed"] {
                for unread in [0, 3] {
                    for manual in [false, true] {
                        let store = SqliteAccountStorage::in_memory().unwrap();
                        seed(&store, "01", archived, membership, unread, pending);
                        store.lock().unwrap().execute("UPDATE chat_list_rows SET manually_marked_unread=?1 WHERE group_id_hex='01'", [manual]).unwrap();
                        store.lock().unwrap().execute("UPDATE account_groups SET pending_confirmation=?1 WHERE group_id_hex='01'",[pending]).unwrap();
                        store.lock().unwrap().execute("UPDATE chat_list_rows SET unread_mention_count=?1 WHERE group_id_hex='01'",[if unread>0 {2} else {0}]).unwrap();
                        store
                            .set_chat_muted("01", Some(crate::unix_now_ms() + 100000))
                            .unwrap();
                        let total = store.account_attention_total().unwrap();
                        let rows = page(&store, ChatListView::Unread).rows;
                        let invite = !archived && pending && membership == "member";
                        assert_eq!(
                            total.unread_conversations,
                            rows.len() as u64 + u64::from(invite)
                        );
                        let eligible = !archived
                            && !pending
                            && membership == "member"
                            && (unread > 0 || manual);
                        assert_eq!(total.has_unread(), eligible || invite);
                        assert_eq!(total.unread_count, if eligible { unread as u64 } else { 0 });
                        assert_eq!(
                            total.unread_mention_count,
                            if eligible && unread > 0 { 2 } else { 0 }
                        );
                        assert_eq!(
                            total.attention_only_conversations,
                            u64::from(invite || (eligible && unread == 0))
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn account_attention_tracks_queued_departure_cancellation_and_caller_rollback() {
    use cgka_traits::storage::{StorageError, StorageProvider};
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", false, "member", 3, false);
    let group = engine_group(&store, "01");
    let baseline = store.account_attention_total().unwrap();
    let result = store.with_transaction(|s| -> Result<(), StorageError> {
        s.put_leave_request(&LeaveRequest {
            group_id: group.clone(),
            requested_at_ms: 123,
            last_proposed_epoch: None,
        })?;
        assert!(!s.account_attention_total()?.has_unread());
        Err(StorageError::NotFound)
    });
    assert!(result.is_err());
    assert_eq!(store.account_attention_total().unwrap(), baseline);
    let mut request = DisbandRequest {
        group_id: group.clone(),
        requested_at_ms: 123,
        status: DisbandRequestStatus::Pending,
        last_prepared_epoch: None,
    };
    store.put_disband_request(&request).unwrap();
    assert!(!store.account_attention_total().unwrap().has_unread());
    request.status = DisbandRequestStatus::Failed(DisbandFailureReason::NoLongerAdmin);
    store.put_disband_request(&request).unwrap();
    assert_eq!(store.account_attention_total().unwrap(), baseline);
}

#[test]
fn account_attention_query_work_is_independent_of_retained_history_and_skips_quiet_rows() {
    use crate::query_work_test_support::measure;
    let mut work = vec![];
    for count in [20, 4096] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.lock().unwrap().execute_batch(&format!("CREATE TEMP TABLE numbers(x INTEGER PRIMARY KEY);
            WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<{count}) INSERT INTO numbers SELECT x FROM n;
            INSERT INTO account_groups(group_id_hex,endpoint,updated_at) SELECT printf('%032x',x),'',0 FROM numbers;
            INSERT INTO chat_list_rows(group_id_hex,updated_at,unread_count) SELECT printf('%032x',x),0,CASE WHEN x<=2 THEN 3 ELSE 0 END FROM numbers;
            WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5000)
            INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at)
                SELECT printf('%032x',1),printf('%064x',x),'received','sender','large retained history',9,'[]',x,x FROM n;")).unwrap();
        seed(&store, "invite", false, "member", 30, true);
        store.lock().unwrap().execute_batch("UPDATE account_groups SET pending_confirmation=1, archived=1 WHERE group_id_hex IN (SELECT printf('%032x',x) FROM numbers WHERE x>10);").unwrap();
        let (total, steps) = measure(&store, || store.account_attention_total().unwrap());
        assert_eq!(total.unread_count, 6);
        assert_eq!(total.unread_conversations, 3);
        assert_eq!(total.attention_only_conversations, 1);
        assert!(
            steps < 500,
            "summary must use attention indexes; steps={steps}"
        );
        work.push(steps);
    }
    assert!(work[0].abs_diff(work[1]) < 100);
}

#[test]
fn invite_attention_follows_source_acceptance_archive_and_departure_before_row_refresh() {
    use cgka_traits::storage::{StorageError, StorageProvider};
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", false, "member", 3, true);
    let group = engine_group(&store, "01");
    let invite = store.account_attention_total().unwrap();
    assert_eq!(invite.unread_count, 0);
    assert_eq!(invite.attention_only_conversations, 1);
    // Keep a deliberately stale invitation display row through each source update.
    for (pending, archived, messages, attention) in [
        (false, false, 3, 0),
        (true, false, 0, 1),
        (true, true, 0, 0),
        (true, false, 0, 1),
    ] {
        store.lock().unwrap().execute("UPDATE account_groups SET pending_confirmation=?1, archived=?2 WHERE group_id_hex='01'", params![pending, archived]).unwrap();
        let total = store.account_attention_total().unwrap();
        assert_eq!(total.unread_count, messages);
        assert_eq!(total.attention_only_conversations, attention);
    }
    let result = store.with_transaction(|s| -> Result<(), StorageError> {
        s.put_leave_request(&LeaveRequest {
            group_id: group.clone(),
            requested_at_ms: 123,
            last_proposed_epoch: None,
        })?;
        assert!(!s.account_attention_total()?.has_unread());
        Err(StorageError::NotFound)
    });
    assert!(result.is_err());
    assert_eq!(store.account_attention_total().unwrap(), invite);
    store
        .put_disband_request(&DisbandRequest {
            group_id: group,
            requested_at_ms: 123,
            status: DisbandRequestStatus::Pending,
            last_prepared_epoch: None,
        })
        .unwrap();
    assert!(!store.account_attention_total().unwrap().has_unread());
}
