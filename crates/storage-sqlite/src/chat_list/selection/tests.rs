use super::*;
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

fn ids(store: &SqliteAccountStorage, snapshot: &ChatListSelectionSnapshot) -> Vec<String> {
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
        for n in 0..count {
            seed(&store, &format!("{n:032x}"), false, "member", 0, false);
        }
        let display = store
            .chat_list_page(crate::ChatListPageQuery {
                view: ChatListView::Chats,
                limit: 50,
                direction: crate::ChatListPageDirection::Forward,
                cursor: None,
            })
            .unwrap();
        assert_eq!(display.rows.len(), count.min(50));
        let selection = store
            .chat_list_selection_snapshot(ChatListView::Chats)
            .unwrap();
        assert_eq!(store.chat_list_selection_count(&selection).unwrap(), count);
        assert_eq!(
            ids(&store, &selection),
            (0..count).map(|n| format!("{n:032x}")).collect::<Vec<_>>()
        );
        assert!(
            store
                .chat_list_selection_page(&selection, count, 200)
                .unwrap()
                .is_empty()
        );
        for (offset, limit) in [(0, 0), (0, 201), (count + 1, 1), (usize::MAX, 1)] {
            assert!(matches!(
                store.chat_list_selection_page(&selection, offset, limit),
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
    for (view, expected) in [
        (ChatListView::Chats, vec!["01", "02", "06"]),
        (ChatListView::Unread, vec!["02"]),
        (ChatListView::Archived, vec!["03"]),
        (ChatListView::Left, vec!["04", "05"]),
    ] {
        let selection = store.chat_list_selection_snapshot(view).unwrap();
        assert_eq!(ids(&store, &selection), expected);
    }
}

#[test]
fn frozen_intent_survives_reordering_and_revalidation_only_removes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for id in ["01", "02", "03"] {
        seed(&store, id, false, "member", 1, false);
    }
    let selection = store
        .chat_list_selection_snapshot(ChatListView::Chats)
        .unwrap();
    seed(&store, "04", false, "member", 1, false);
    store.lock().unwrap().execute_batch("UPDATE chat_list_rows SET activity_sort_at = 999 WHERE group_id_hex = '03'; UPDATE account_groups SET archived = 1 WHERE group_id_hex = '02'; DELETE FROM chat_list_rows WHERE group_id_hex = '01';").unwrap();
    assert_eq!(ids(&store, &selection), ["01", "02", "03"]);
    let validated = store.revalidate_chat_list_selection(&selection).unwrap();
    assert_eq!(ids(&store, &validated), ["03"]);
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
            &store,
            &store.revalidate_chat_list_selection(&validated).unwrap()
        ),
        ["03"]
    );
}

#[test]
fn incomplete_base_projection_never_claims_complete_selection() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01", false, "member", 0, false);
    let selection = store
        .chat_list_selection_snapshot(ChatListView::Chats)
        .unwrap();
    store.lock().unwrap().execute("INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('missing', '', 0)", []).unwrap();
    assert!(matches!(
        store.chat_list_selection_snapshot(ChatListView::Chats),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
    assert!(matches!(
        store.revalidate_chat_list_selection(&selection),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
    assert_eq!(store.chat_list_selection_count(&selection).unwrap(), 1);
}

#[test]
fn foreign_reopened_and_closed_stores_cannot_use_old_intent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite3");
    let key = crate::SqlCipherKey::new("07".repeat(32)).unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "01", false, "member", 0, false);
    let selection = store
        .chat_list_selection_snapshot(ChatListView::Chats)
        .unwrap();
    assert_eq!(
        store.clone().chat_list_selection_count(&selection).unwrap(),
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
        foreign.chat_list_selection_count(&selection),
        Err(ChatListSelectionError::StaleSelection)
    ));
    store.close().unwrap();
    assert!(matches!(
        store.chat_list_selection_count(&selection),
        Err(ChatListSelectionError::Storage(StorageError::Closed(_)))
    ));
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
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
    seed(&store, "01", false, "member", 1, false);
    store
        .lock()
        .unwrap()
        .execute_batch("BEGIN IMMEDIATE")
        .unwrap();
    seed(&store, "02", false, "member", 1, false);
    let selection = store
        .chat_list_selection_snapshot(ChatListView::Chats)
        .unwrap();
    assert_eq!(ids(&store, &selection), ["01", "02"]);
    assert!(!store.lock().unwrap().is_autocommit());
    store.lock().unwrap().execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        ids(
            &store,
            &store.revalidate_chat_list_selection(&selection).unwrap()
        ),
        ["01"]
    );
}
