use super::*;
use crate::ChatListView;
use crate::SqliteAccountStorage;
use crate::base::test_support::chat_list_window_page;
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

fn strings(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}

#[test]
fn ids_cover_the_whole_view_past_the_display_limit() {
    for count in [0, 1, 50, 51, 200, 201, 500] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        for n in 0..count {
            seed(&store, &format!("{n:032x}"), false, "member", 0, false);
        }
        let display = chat_list_window_page(&app, ChatListView::Chats, 50).unwrap();
        assert_eq!(display.rows.len(), count.min(50));
        assert_eq!(
            app.chat_list_ids(ChatListView::Chats).unwrap(),
            (0..count).map(|n| format!("{n:032x}")).collect::<Vec<_>>()
        );
    }
}

#[test]
fn ids_match_each_native_view_and_its_display_page() {
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
    let app = store.app_storage();
    for (view, expected) in [
        (ChatListView::Chats, vec!["01", "02", "06"]),
        (ChatListView::Unread, vec!["02"]),
        (ChatListView::Archived, vec!["03"]),
        (ChatListView::Left, vec!["04", "05"]),
    ] {
        assert_eq!(app.chat_list_ids(view).unwrap(), expected, "{view:?}");
        let page = chat_list_window_page(&app, view, 100).unwrap();
        assert_eq!(
            page.rows
                .iter()
                .map(|row| row.group_id_hex.as_str())
                .collect::<Vec<_>>(),
            expected,
            "{view:?}"
        );
    }
}

#[test]
fn revalidation_only_removes_and_keeps_the_callers_order() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    for id in ["01", "02", "03", "04"] {
        seed(&store, id, false, "member", 1, false);
    }
    let selected = strings(&["04", "03", "02", "01", "03", "unknown"]);
    seed(&store, "05", false, "member", 1, false);
    store.lock().unwrap().execute_batch("UPDATE chat_list_rows SET activity_sort_at = 999 WHERE group_id_hex = '01'; UPDATE account_groups SET archived = 1 WHERE group_id_hex = '02'; DELETE FROM chat_list_rows WHERE group_id_hex = '03';").unwrap();
    assert_eq!(
        app.revalidate_chat_list_ids(ChatListView::Chats, &selected)
            .unwrap(),
        ["04", "01"]
    );
    assert_eq!(
        app.revalidate_chat_list_ids(ChatListView::Archived, &selected)
            .unwrap(),
        ["02"]
    );
    assert!(
        app.revalidate_chat_list_ids(ChatListView::Chats, &[])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn pending_base_rows_return_not_ready_instead_of_a_partial_set() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "01", false, "member", 0, false);
    store.lock().unwrap().execute("INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('missing', '', 0)", []).unwrap();
    assert!(matches!(
        app.chat_list_ids(ChatListView::Chats),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
    assert!(matches!(
        app.revalidate_chat_list_ids(ChatListView::Chats, &strings(&["01"])),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
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
    assert_eq!(
        app.chat_list_ids(ChatListView::Chats).unwrap(),
        ["01", "02"]
    );
    assert!(!store.lock().unwrap().is_autocommit());
    store.lock().unwrap().execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        app.revalidate_chat_list_ids(ChatListView::Chats, &strings(&["01", "02"]))
            .unwrap(),
        ["01"]
    );
}
