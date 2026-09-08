use super::*;
use crate::SqlCipherKey;

fn seed(store: &SqliteAccountStorage, id: &str) {
    let conn = store.lock().unwrap();
    conn.execute("INSERT INTO account_groups(group_id_hex, endpoint, profile_name, updated_at, member_count) VALUES (?1, 'fixture', '', 7, 2)", [id]).unwrap();
    conn.execute(
        "INSERT INTO chat_list_rows(group_id_hex, activity_sort_at, updated_at) VALUES (?1, 19, 7)",
        [id],
    )
    .unwrap();
    drop(conn);
    store
        .set_chat_presentation_members(id, &["aa".into(), "bb".into()])
        .unwrap();
}
fn value(peer: &str, name: &str, rev: u64) -> StoredChatPresentation {
    StoredChatPresentation {
        presentation: ConversationPresentation {
            title: PresentationText::Literal(name.into()),
            avatar: SelectedAvatar::Placeholder {
                stable_seed: "fixture-seed".into(),
                source: PresentationSource::PeerFallback,
            },
            title_source: PresentationSource::PeerProfile,
            avatar_source: PresentationSource::PeerFallback,
            peer_id: Some(peer.into()),
            resolution: PresentationResolution::Cached,
        },
        profile_version: Some(ChatPresentationVersion {
            store_epoch: vec![3; 16],
            revision: rev,
        }),
    }
}
#[test]
fn selected_value_reopens_without_mutation_and_keeps_activity() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("presentation.db");
    let key = SqlCipherKey::new("presentation fixture key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "11");
    let input = store.chat_presentation_input("11").unwrap().unwrap();
    let expected = value("bb", "Peer name", 4);
    assert_eq!(
        store.store_chat_presentation(&input, &expected).unwrap(),
        ChatPresentationWrite::Applied
    );
    let version = store.chat_presentation_version().unwrap();
    assert_eq!(
        store.store_chat_presentation(&input, &expected).unwrap(),
        ChatPresentationWrite::Unchanged
    );
    assert_eq!(store.chat_presentation_version().unwrap(), version);
    drop(store);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(
        store.chat_presentation("11").unwrap(),
        ChatPresentationRead::Ready(Box::new(expected))
    );
    assert_eq!(store.chat_presentation_version().unwrap(), version);
    assert_eq!(
        store.chat_presentation_dependents("bb", None).unwrap(),
        ["11"]
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT activity_sort_at FROM chat_list_rows", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        19
    );
    assert!(store.pending_chat_presentation_inputs().unwrap().is_empty());
}
#[test]
fn source_generation_and_store_epoch_reject_stale_preparation() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "11");
    let other = SqliteAccountStorage::in_memory().unwrap();
    seed(&other, "11");
    let old = store.chat_presentation_input("11").unwrap().unwrap();
    let v = value("bb", "Old peer", 1);
    assert_eq!(
        other.store_chat_presentation(&old, &v).unwrap(),
        ChatPresentationWrite::Stale
    );
    store.store_chat_presentation(&old, &v).unwrap();
    store
        .set_chat_presentation_members("11", &["aa".into(), "cc".into()])
        .unwrap();
    assert_eq!(
        store.chat_presentation("11").unwrap(),
        ChatPresentationRead::Pending
    );
    assert!(
        store
            .chat_presentation_dependents("bb", None)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.store_chat_presentation(&old, &v).unwrap(),
        ChatPresentationWrite::Stale
    );
    let current = store.chat_presentation_input("11").unwrap().unwrap();
    store
        .store_chat_presentation(&current, &value("cc", "New peer", 2))
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET profile_name = 'Custom' WHERE group_id_hex = '11'",
            [],
        )
        .unwrap();
    assert_eq!(
        store
            .store_chat_presentation(&current, &value("cc", "New peer", 2))
            .unwrap(),
        ChatPresentationWrite::Stale
    );
    assert_eq!(
        store
            .chat_presentation_input("11")
            .unwrap()
            .unwrap()
            .group_name,
        "Custom"
    );
}
#[test]
fn backfill_is_bounded_and_resumes_from_persisted_pending_rows() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("backfill.db");
    let key = SqlCipherKey::new("backfill fixture key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    for i in 0..57 {
        seed(&store, &format!("{i:04x}"));
    }
    let first = store.pending_chat_presentation_inputs().unwrap();
    assert_eq!(first.len(), 50);
    for input in first.iter().take(13) {
        store
            .store_chat_presentation(input, &value("bb", "Peer", 0))
            .unwrap();
    }
    drop(store);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let next = store.pending_chat_presentation_inputs().unwrap();
    assert_eq!(next.len(), 44);
    assert_eq!(next[0].group_id_hex, "000d");
    for input in next {
        store
            .store_chat_presentation(&input, &value("bb", "Peer", 0))
            .unwrap();
    }
    assert!(store.pending_chat_presentation_inputs().unwrap().is_empty());
    seed(&store, "0000a"); // New work can sort before the previous completion boundary.
    assert_eq!(store.pending_chat_presentation_inputs().unwrap().len(), 1);
}
#[test]
fn failed_dependency_write_rolls_back_value_and_revision() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "11");
    let before = store.chat_presentation_version().unwrap();
    store.lock().unwrap().execute_batch("CREATE TRIGGER fail_dependency BEFORE INSERT ON chat_presentation_dependencies BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    let input = store.chat_presentation_input("11").unwrap().unwrap();
    assert!(
        store
            .store_chat_presentation(&input, &value("bb", "Peer", 1))
            .is_err()
    );
    assert_eq!(
        store.chat_presentation("11").unwrap(),
        ChatPresentationRead::Pending
    );
    assert_eq!(store.chat_presentation_version().unwrap(), before);
}
#[test]
fn profile_order_and_missing_unknown_format_are_explicit() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "11");
    let input = store.chat_presentation_input("11").unwrap().unwrap();
    store
        .store_chat_presentation(&input, &value("bb", "New", 9))
        .unwrap();
    assert_eq!(
        store
            .store_chat_presentation(&input, &value("bb", "Old", 8))
            .unwrap(),
        ChatPresentationWrite::Stale
    );
    assert_eq!(
        store.chat_presentation("absent").unwrap(),
        ChatPresentationRead::Missing
    );
    let json = serde_json::to_value(Envelope {
        format: 99,
        value: value("bb", "Peer", 0),
    })
    .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_list_rows SET presentation_json = ?1",
            [serde_json::to_vec(&json).unwrap()],
        )
        .unwrap();
    assert!(store.chat_presentation("11").is_err());
    assert!(
        store
            .store_chat_presentation(&input, &value("bb", "Peer", 10))
            .is_err()
    );
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_list_rows SET presentation_json = ?1",
            [br#"{"format":"private profile sentinel"}"#.as_slice()],
        )
        .unwrap();
    let error = store.chat_presentation("11").unwrap_err();
    assert!(!format!("{error:?}").contains("private profile sentinel"));
    // Reset/deletion cannot leave a dependency behind.
    store
        .lock()
        .unwrap()
        .execute("DELETE FROM account_groups WHERE group_id_hex = '11'", [])
        .unwrap();
    assert!(
        store
            .chat_presentation_dependents("bb", None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn deleted_and_recreated_row_rejects_old_prepared_value() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "11");
    let old = store.chat_presentation_input("11").unwrap().unwrap();
    store
        .lock()
        .unwrap()
        .execute("DELETE FROM account_groups WHERE group_id_hex = '11'", [])
        .unwrap();
    seed(&store, "11");
    assert_eq!(
        store
            .store_chat_presentation(&old, &value("bb", "Old display", 1))
            .unwrap(),
        ChatPresentationWrite::Stale
    );
}

#[test]
fn bookkeeping_only_profile_progress_does_not_notify_or_allow_unversioned_rollback() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "11");
    let input = store.chat_presentation_input("11").unwrap().unwrap();
    store
        .store_chat_presentation(&input, &value("bb", "Same name", 1))
        .unwrap();
    let version = store.chat_presentation_version().unwrap();
    store
        .store_chat_presentation(&input, &value("bb", "Same name", 2))
        .unwrap();
    assert_eq!(store.chat_presentation_version().unwrap(), version);
    let mut unversioned = value("bb", "Old name", 0);
    unversioned.profile_version = None;
    assert_eq!(
        store.store_chat_presentation(&input, &unversioned).unwrap(),
        ChatPresentationWrite::Stale
    );
}

#[test]
fn unchanged_source_observations_keep_a_ready_selection_and_generation() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "11");
    let input = store.chat_presentation_input("11").unwrap().unwrap();
    let selected = value("bb", "Peer", 1);
    store.store_chat_presentation(&input, &selected).unwrap();
    let version = store.chat_presentation_version().unwrap();
    store
        .set_chat_presentation_members("11", &["BB".into(), "aa".into()])
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET updated_at = 9, profile_name = '' WHERE group_id_hex = '11'",
            [],
        )
        .unwrap();
    assert_eq!(
        store.chat_presentation("11").unwrap(),
        ChatPresentationRead::Ready(Box::new(selected))
    );
    assert_eq!(store.chat_presentation_version().unwrap(), version);
    assert_eq!(
        store
            .chat_presentation_input("11")
            .unwrap()
            .unwrap()
            .source_version,
        input.source_version
    );
}
