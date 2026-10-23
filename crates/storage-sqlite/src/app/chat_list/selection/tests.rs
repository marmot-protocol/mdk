use super::*;
#[cfg(test)]
use crate::SqliteAccountStorage;
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
    // This fixture installs the complete authoritative base row directly.
    conn.execute(
        "DELETE FROM chat_presentation_row_work WHERE group_id_hex = ?1",
        [id],
    )
    .unwrap();
}

fn ids(store: &SqliteAppStorage, snapshot: &ChatListSelectionSnapshot) -> Vec<String> {
    let count = store.chat_list_selection_count(snapshot).unwrap();
    (0..count)
        .step_by(50)
        .flat_map(|offset| {
            store
                .chat_list_selection_page(snapshot, offset, 50)
                .unwrap()
        })
        .collect()
}

#[test]
fn complete_selection_is_independent_of_the_display_limit() {
    for count in [0, 1, 49, 50, 51, 100, 101, 201, 500] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        for n in 0..count {
            seed(&store, &format!("{n:032x}"), false, "member", 0, false);
        }
        let display = app
            .chat_list_page(crate::ChatListPageQuery {
                view: ChatListView::Chats,
                limit: 50,
                direction: crate::ChatListPageDirection::Forward,
                cursor: None,
            })
            .unwrap();
        assert_eq!(display.rows.len(), count.min(50));
        let selection = app
            .chat_list_selection_snapshot(ChatListView::Chats)
            .unwrap();
        assert_eq!(app.chat_list_selection_count(&selection).unwrap(), count);
        assert_eq!(
            ids(&app, &selection),
            (0..count).map(|n| format!("{n:032x}")).collect::<Vec<_>>()
        );
        assert!(
            app.chat_list_selection_page(&selection, count, 200)
                .unwrap()
                .is_empty()
        );
        for (offset, limit) in [(0, 0), (0, 201), (count + 1, 1), (usize::MAX, 1)] {
            assert!(matches!(
                app.chat_list_selection_page(&selection, offset, limit),
                Err(ChatListSelectionError::InvalidPage)
            ));
        }
    }
}

#[test]
fn native_view_predicates_exclude_ineligible_ids() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for (id, archive, membership, unread, pending) in [
        ("01", false, "member", 0, false),
        ("02", false, "member", 1, false),
        ("03", true, "member", 1, false),
        ("04", false, "left", 1, false),
        ("05", true, "removed", 1, false),
        ("06", false, "member", 9, true),
    ] {
        seed(&store, id, archive, membership, unread, pending);
    }
    seed(&store, "07", false, "member", 9, true);
    store
        .lock()
        .unwrap()
        .execute("INSERT INTO blocked_pending_invites VALUES ('07')", [])
        .unwrap();
    for (view, expected) in [
        (ChatListView::Chats, vec!["01", "02", "06"]),
        (ChatListView::Unread, vec!["02"]),
        (ChatListView::Archived, vec!["03"]),
        (ChatListView::Left, vec!["04", "05"]),
    ] {
        let selection = store
            .app_storage()
            .chat_list_selection_snapshot(view)
            .unwrap();
        assert_eq!(ids(&store.app_storage(), &selection), expected);
    }
}

#[test]
fn frozen_intent_survives_reordering_and_revalidation_only_removes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    for id in ["01", "02", "03"] {
        seed(&store, id, false, "member", 1, false);
    }
    let selection = app
        .chat_list_selection_snapshot(ChatListView::Chats)
        .unwrap();
    seed(&store, "04", false, "member", 1, false);
    store.lock().unwrap().execute_batch("UPDATE chat_list_rows SET activity_sort_at = 999 WHERE group_id_hex = '03'; UPDATE account_groups SET archived = 1 WHERE group_id_hex = '02'; DELETE FROM chat_list_rows WHERE group_id_hex = '01';").unwrap();
    assert_eq!(ids(&app, &selection), ["01", "02", "03"]);
    let validated = app.revalidate_chat_list_selection(&selection).unwrap();
    assert_eq!(ids(&app, &validated), ["03"]);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET archived = 0 WHERE group_id_hex = '02'",
            [],
        )
        .unwrap();
    assert_eq!(
        ids(
            &app,
            &app.revalidate_chat_list_selection(&validated).unwrap()
        ),
        ["03"]
    );
}

#[test]
fn incomplete_base_projection_never_claims_complete_selection() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "01", false, "member", 0, false);
    let selection = app
        .chat_list_selection_snapshot(ChatListView::Chats)
        .unwrap();
    store.lock().unwrap().execute("INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('missing', '', 0)", []).unwrap();
    assert!(matches!(
        app.chat_list_selection_snapshot(ChatListView::Chats),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
    assert!(matches!(
        app.revalidate_chat_list_selection(&selection),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
    assert_eq!(app.chat_list_selection_count(&selection).unwrap(), 1);
}

#[test]
fn foreign_reopened_and_closed_stores_cannot_use_old_intent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite3");
    let key = crate::SqlCipherKey::new("07".repeat(32)).unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "01", false, "member", 0, false);
    let selection = store
        .app_storage()
        .chat_list_selection_snapshot(ChatListView::Chats)
        .unwrap();
    assert_eq!(
        store
            .clone()
            .app_storage()
            .chat_list_selection_count(&selection)
            .unwrap(),
        1
    );
    let foreign = SqliteAccountStorage::in_memory().unwrap();
    let epoch = selection.store_epoch.clone();
    foreign
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_presentation_meta SET store_epoch = ?1",
            [epoch],
        )
        .unwrap();
    assert!(matches!(
        foreign.app_storage().chat_list_selection_count(&selection),
        Err(ChatListSelectionError::StaleSelection)
    ));
    store.close().unwrap();
    assert!(matches!(
        store.app_storage().chat_list_selection_count(&selection),
        Err(ChatListSelectionError::Storage(StorageError::Closed(_)))
    ));
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key)
        .unwrap()
        .app_storage();
    assert!(matches!(
        reopened.chat_list_selection_count(&selection),
        Err(ChatListSelectionError::StaleSelection)
    ));
    assert_eq!(
        reopened
            .chat_list_selection_count(
                &reopened
                    .chat_list_selection_snapshot(ChatListView::Chats)
                    .unwrap()
            )
            .unwrap(),
        1
    );
    assert!(!format!("{selection:?}").contains("01"));
}

#[test]
fn caller_transaction_is_preserved() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "01", false, "member", 1, false);
    store
        .lock()
        .unwrap()
        .execute_batch("BEGIN IMMEDIATE")
        .unwrap();
    seed(&store, "02", false, "member", 1, false);
    let selection = app
        .chat_list_selection_snapshot(ChatListView::Chats)
        .unwrap();
    assert_eq!(ids(&app, &selection), ["01", "02"]);
    assert!(!store.lock().unwrap().is_autocommit());
    store.lock().unwrap().execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        ids(
            &app,
            &app.revalidate_chat_list_selection(&selection).unwrap()
        ),
        ["01"]
    );
}

#[test]
fn cancelled_capture_or_revalidation_returns_no_prefix_and_releases_transaction() {
    use std::cell::Cell;
    let store = SqliteAccountStorage::in_memory().unwrap();
    for n in 0..500 {
        seed(&store, &format!("{n:04x}"), false, "member", 0, false);
    }
    let app = store.app_storage();
    let calls = Cell::new(0);
    let cancelled = || {
        calls.set(calls.get() + 1);
        calls.get() > 51
    };
    assert!(matches!(
        app.chat_list_selection_snapshot_cancellable(ChatListView::Chats, &cancelled),
        Err(ChatListSelectionError::Cancelled)
    ));
    let selection = app
        .chat_list_selection_snapshot(ChatListView::Chats)
        .unwrap();
    calls.set(0);
    assert!(matches!(
        app.revalidate_chat_list_selection_cancellable(&selection, &cancelled),
        Err(ChatListSelectionError::Cancelled)
    ));
    assert_eq!(app.chat_list_selection_count(&selection).unwrap(), 500);
    assert_eq!(
        app.chat_list_selection_snapshot(ChatListView::Chats)
            .and_then(|s| app.chat_list_selection_count(&s))
            .unwrap(),
        500
    );
}

#[test]
fn capture_count_page_and_revalidation_only_query_compact_navigation_state() {
    static QUERIES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    fn record(event: rusqlite::trace::TraceEvent<'_>) {
        if let rusqlite::trace::TraceEvent::Stmt(_, sql) = event {
            QUERIES.lock().unwrap().push(sql.to_owned());
        }
    }
    let store = SqliteAccountStorage::in_memory().unwrap();
    for id in [
        "01",
        "abcdef",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345",
    ] {
        seed(&store, id, false, "member", 0, false);
    }
    store.lock().unwrap().trace_v2(
        rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
        Some(record),
    );
    let app = store.app_storage();
    let selection = app
        .chat_list_selection_snapshot(ChatListView::Chats)
        .unwrap();
    assert_eq!(app.chat_list_selection_count(&selection).unwrap(), 3);
    assert_eq!(
        app.chat_list_selection_page(&selection, 0, 200)
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        app.chat_list_selection_count(&app.revalidate_chat_list_selection(&selection).unwrap())
            .unwrap(),
        3
    );
    store
        .lock()
        .unwrap()
        .trace_v2(rusqlite::trace::TraceEventCodes::empty(), None);
    let queries = QUERIES.lock().unwrap();
    let reads = queries
        .iter()
        .filter(|q| q.trim_start().starts_with("SELECT"))
        .collect::<Vec<_>>();
    assert!(!reads.is_empty());
    for sql in reads {
        assert!(
            sql.contains("chat_presentation_meta")
                || sql.contains("chat_presentation_row_work")
                || sql.contains("SELECT group_id_hex FROM chat_list_rows"),
            "unexpected read: {sql}"
        );
        assert!(
            !sql.contains("profile")
                && !sql.contains("message_timeline")
                && !sql.contains("cgka_groups"),
            "hydration: {sql}"
        );
    }
}
