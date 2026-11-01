use super::*;
use crate::SqlCipherKey;
#[cfg(test)]
use crate::SqliteAccountStorage;

#[test]
fn presented_rows_expose_draft_versions_for_identical_edits_and_deletion() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let input = app.chat_presentation_input("11").unwrap().unwrap();
    app.store_chat_presentation(&input, &value("bb", "Peer", 1))
        .unwrap();
    let read = || {
        app.read_presented_chat_list(crate::ChatListQuery::default(), Some("11"))
            .unwrap()
            .unwrap()
            .rows
            .remove(0)
    };
    app.save_message_draft("11", "same", None, &[]).unwrap();
    let selected = app.selected_message_draft("11").unwrap();
    let first = read();
    assert!(matches!(first.preview, SelectedChatPreview::Draft(_)));
    assert!(
        selected
            .revision
            .includes_chat_list_version(first.draft_version.as_ref().unwrap())
    );
    app.save_message_draft("11", "same", None, &[]).unwrap();
    let edited = read();
    assert_eq!(first.preview, edited.preview);
    assert!(
        !selected
            .revision
            .includes_chat_list_version(edited.draft_version.as_ref().unwrap())
    );
    app.delete_message_draft("11").unwrap();
    let deleted = read();
    assert!(!matches!(deleted.preview, SelectedChatPreview::Draft(_)));
    assert!(
        !selected
            .revision
            .includes_chat_list_version(deleted.draft_version.as_ref().unwrap())
    );
    let json = serde_json::to_vec(&deleted).unwrap();
    let round_trip: PresentedChatRow = serde_json::from_slice(&json).unwrap();
    assert_eq!(deleted, round_trip);
    let mut legacy_json = serde_json::to_value(&deleted).unwrap();
    legacy_json.as_object_mut().unwrap().remove("draft_version");
    let legacy: PresentedChatRow = serde_json::from_value(legacy_json).unwrap();
    assert!(legacy.draft_version.is_none());
    assert_eq!(
        format!("{:?}", deleted.draft_version.as_ref().unwrap()),
        "ChatListDraftVersion { .. }"
    );
    // Debug output carries no names, ids, text or per-database store epoch.
    let secret_presentation = ConversationPresentation {
        title: PresentationText::Literal("secret-title".into()),
        avatar: SelectedAvatar::RemoteImage {
            url: "https://example.com/secret.png".into(),
            cache_key: "secret-cache-key".into(),
        },
        peer_id: Some("f1".repeat(32)),
        ..value("bb", "Peer", 1).presentation
    };
    let secret_version = ChatPresentationVersion {
        store_epoch: vec![0xEE; 16],
        revision: 7,
    };
    let secret_preview = SelectedChatPreview::Draft(ChatListDraftPreview {
        text: "secret-draft".into(),
        text_truncated: false,
        attachment_count: 0,
        attachment_kind: None,
    });
    let mut secret_row = deleted.clone();
    secret_row.presentation = secret_presentation.clone();
    secret_row.preview = secret_preview.clone();
    secret_row.row.last_message = Some(crate::ChatListMessagePreview {
        message_id_hex: "message".into(),
        sender: "sender".into(),
        sender_display_name: None,
        plaintext: "secret-plaintext".into(),
        media_json: None,
        kind: 9,
        tags: Vec::new(),
        timeline_at: 7,
        retention_seconds: None,
        retention_expires_at: None,
        deleted: false,
        deletion_source: crate::DeletionSource::Unknown,
        group_system: None,
        attachment_kind: None,
        attachment_count: 0,
        delivery_state: crate::ChatListMessageDeliveryState::NotApplicable,
    });
    let stored = StoredChatPresentation {
        presentation: secret_presentation,
        profile_version: Some(secret_version.clone()),
    };
    let snapshot = PresentedChatListSnapshot {
        rows: vec![secret_row.clone()],
        presentation_version: secret_version.clone(),
    };
    for (kind, debug) in [
        ("StoredChatPresentation", format!("{stored:?}")),
        ("ChatPresentationVersion", format!("{secret_version:?}")),
        ("PresentedChatRow", format!("{secret_row:?}")),
        ("PresentedChatListSnapshot", format!("{snapshot:?}")),
        ("SelectedChatPreview", format!("{secret_preview:?}")),
    ] {
        // 238 is how Debug prints the store epoch's 0xEE bytes.
        for secret in ["secret", "f1f1", "238"] {
            assert!(
                !debug.contains(secret),
                "{kind} Debug shows {secret:?}: {debug}"
            );
        }
    }
    assert_ne!(
        first, edited,
        "identical text still changes the full snapshot row"
    );
}

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
        .app_storage()
        .set_chat_presentation_members(id, &["aa".repeat(32), "bb".repeat(32)])
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
            peer_id: Some(peer.repeat(32)),
            resolution: PresentationResolution::Cached,
        },
        profile_version: Some(ChatPresentationVersion {
            store_epoch: vec![3; 16],
            revision: rev,
        }),
    }
}

#[test]
fn presented_chat_preview_retention_comes_from_selected_message() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let event = crate::StoredAppEvent {
        group_id_hex: "11".to_owned(),
        message_id_hex: "message".to_owned(),
        source_message_id_hex: Some("source".to_owned()),
        source_epoch: Some(1),
        direction: "received".to_owned(),
        sender: "bb".repeat(32),
        plaintext: "hello".to_owned(),
        kind: 9,
        tags: Vec::new(),
        recorded_at: 10,
        received_at: 10,
        origin_commit_id: None,
        moderation_grant: false,
    };
    app.record_app_event_with_retention(
        &event,
        Some(cgka_traits::app_event::AppMessageRetentionDecision::new(
            10, 300,
        )),
    )
    .unwrap();
    app.refresh_chat_list_rows(&"aa".repeat(32), &|_, _| false)
        .unwrap();
    let input = app.chat_presentation_input("11").unwrap().unwrap();
    app.store_chat_presentation(&input, &value("bb", "Peer", 1))
        .unwrap();
    for group in [None, Some("11")] {
        let snapshot = app
            .read_presented_chat_list(crate::ChatListQuery::default(), group)
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.rows.len(), 1);
        assert_eq!(snapshot.rows[0].preview, SelectedChatPreview::Message);
        let preview = snapshot.rows[0].row.last_message.as_ref().unwrap();
        assert_eq!(preview.retention_seconds, Some(300));
        assert_eq!(preview.retention_expires_at, Some(310));
    }
}

#[test]
fn selected_value_reopens_without_mutation_and_keeps_activity() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("presentation.db");
    let key = SqlCipherKey::raw([0x21; 32]);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "11");
    let input = store
        .app_storage()
        .chat_presentation_input("11")
        .unwrap()
        .unwrap();
    let expected = value("bb", "Peer name", 4);
    assert_eq!(
        store
            .app_storage()
            .store_chat_presentation(&input, &expected)
            .unwrap(),
        ChatPresentationWrite::Applied
    );
    let version = store.app_storage().chat_presentation_version().unwrap();
    assert_eq!(
        store
            .app_storage()
            .store_chat_presentation(&input, &expected)
            .unwrap(),
        ChatPresentationWrite::Unchanged
    );
    assert_eq!(
        store.app_storage().chat_presentation_version().unwrap(),
        version
    );
    drop(store);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    assert_eq!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Ready(Box::new(expected))
    );
    assert_eq!(app.chat_presentation_version().unwrap(), version);
    assert_eq!(
        app.chat_presentation_dependents(&"bb".repeat(32), None)
            .unwrap(),
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
    assert!(app.pending_chat_presentation_inputs().unwrap().is_empty());
}
#[test]
fn source_generation_and_store_epoch_reject_stale_preparation() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let other = SqliteAccountStorage::in_memory().unwrap();
    seed(&other, "11");
    let old = app.chat_presentation_input("11").unwrap().unwrap();
    let v = value("bb", "Old peer", 1);
    assert_eq!(
        other
            .app_storage()
            .store_chat_presentation(&old, &v)
            .unwrap(),
        ChatPresentationWrite::Stale
    );
    app.store_chat_presentation(&old, &v).unwrap();
    app.set_chat_presentation_members("11", &["aa".repeat(32), "cc".repeat(32)])
        .unwrap();
    assert_eq!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Pending
    );
    assert!(
        app.chat_presentation_dependents(&"bb".repeat(32), None)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        app.store_chat_presentation(&old, &v).unwrap(),
        ChatPresentationWrite::Stale
    );
    let current = app.chat_presentation_input("11").unwrap().unwrap();
    app.store_chat_presentation(&current, &value("cc", "New peer", 2))
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
        app.store_chat_presentation(&current, &value("cc", "New peer", 2))
            .unwrap(),
        ChatPresentationWrite::Stale
    );
    assert_eq!(
        app.chat_presentation_input("11")
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
    let key = SqlCipherKey::raw([0x22; 32]);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    for i in 0..57 {
        seed(&store, &format!("{i:04x}"));
    }
    let first = store
        .app_storage()
        .pending_chat_presentation_inputs()
        .unwrap();
    assert_eq!(first.len(), 50);
    for input in first.iter().take(13) {
        store
            .app_storage()
            .store_chat_presentation(input, &value("bb", "Peer", 0))
            .unwrap();
    }
    drop(store);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    let next = app.pending_chat_presentation_inputs().unwrap();
    assert_eq!(next.len(), 44);
    assert_eq!(next[0].group_id_hex, "000d");
    for input in next {
        app.store_chat_presentation(&input, &value("bb", "Peer", 0))
            .unwrap();
    }
    assert!(app.pending_chat_presentation_inputs().unwrap().is_empty());
    seed(&store, "0000a"); // New work can sort before the previous completion boundary.
    assert_eq!(app.pending_chat_presentation_inputs().unwrap().len(), 1);
}
#[test]
fn failed_dependency_write_rolls_back_value_and_revision() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let before = app.chat_presentation_version().unwrap();
    store.lock().unwrap().execute_batch("CREATE TRIGGER fail_dependency BEFORE INSERT ON chat_presentation_dependencies BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    let input = app.chat_presentation_input("11").unwrap().unwrap();
    assert_fails_with(
        app.store_chat_presentation(&input, &value("bb", "Peer", 1)),
        "injected",
    );
    assert_eq!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Pending
    );
    assert_eq!(app.chat_presentation_version().unwrap(), before);
}
#[test]
fn oversized_presentation_is_refused_before_it_is_stored() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let before = app.chat_presentation_version().unwrap();
    let input = app.chat_presentation_input("11").unwrap().unwrap();
    assert_fails_with(
        app.store_chat_presentation(&input, &value("bb", &"x".repeat(70_000), 1)),
        "oversized chat presentation",
    );
    assert_eq!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Pending
    );
    assert_eq!(app.chat_presentation_version().unwrap(), before);
}
#[test]
fn profile_order_and_missing_unknown_format_are_explicit() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let input = app.chat_presentation_input("11").unwrap().unwrap();
    app.store_chat_presentation(&input, &value("bb", "New", 9))
        .unwrap();
    assert_eq!(
        app.store_chat_presentation(&input, &value("bb", "Old", 8))
            .unwrap(),
        ChatPresentationWrite::Stale
    );
    assert_eq!(
        app.chat_presentation("absent").unwrap(),
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
    assert_fails_with(
        app.chat_presentation("11"),
        "unsupported chat presentation format",
    );
    assert_eq!(
        app.store_chat_presentation(&input, &value("bb", "Peer", 10))
            .unwrap(),
        ChatPresentationWrite::Applied
    );
    assert!(matches!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Ready(_)
    ));
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_list_rows SET presentation_json = ?1",
            [br#"{"format":"private profile sentinel"}"#.as_slice()],
        )
        .unwrap();
    let error = app.chat_presentation("11").unwrap_err();
    assert!(!format!("{error:?}").contains("private profile sentinel"));
    let before_repair = app.chat_presentation_version().unwrap();
    assert_eq!(
        app.store_chat_presentation(&input, &value("bb", "Peer", 11))
            .unwrap(),
        ChatPresentationWrite::Applied
    );
    assert!(app.chat_presentation_version().unwrap().revision > before_repair.revision);
    assert!(matches!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Ready(_)
    ));
    // Reset/deletion cannot leave a dependency behind.
    store
        .lock()
        .unwrap()
        .execute("DELETE FROM account_groups WHERE group_id_hex = '11'", [])
        .unwrap();
    assert!(
        app.chat_presentation_dependents(&"bb".repeat(32), None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn deleted_and_recreated_row_rejects_old_prepared_value() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "11");
    let old = store
        .app_storage()
        .chat_presentation_input("11")
        .unwrap()
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute("DELETE FROM account_groups WHERE group_id_hex = '11'", [])
        .unwrap();
    assert!(
        store
            .app_storage()
            .chat_presentation_input("11")
            .unwrap()
            .is_none(),
        "a chat deleted after listing is skipped, not an error"
    );
    seed(&store, "11");
    assert_eq!(
        store
            .app_storage()
            .store_chat_presentation(&old, &value("bb", "Old display", 1))
            .unwrap(),
        ChatPresentationWrite::Stale
    );
}

#[test]
fn bookkeeping_only_profile_progress_does_not_notify_or_allow_unversioned_rollback() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let input = app.chat_presentation_input("11").unwrap().unwrap();
    app.store_chat_presentation(&input, &value("bb", "Same name", 1))
        .unwrap();
    let version = app.chat_presentation_version().unwrap();
    app.store_chat_presentation(&input, &value("bb", "Same name", 2))
        .unwrap();
    assert_eq!(app.chat_presentation_version().unwrap(), version);
    let mut unversioned = value("bb", "Old name", 0);
    unversioned.profile_version = None;
    assert_eq!(
        app.store_chat_presentation(&input, &unversioned).unwrap(),
        ChatPresentationWrite::Stale
    );
}

#[test]
fn unchanged_source_observations_keep_a_ready_selection_and_generation() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let input = app.chat_presentation_input("11").unwrap().unwrap();
    let selected = value("bb", "Peer", 1);
    app.store_chat_presentation(&input, &selected).unwrap();
    let version = app.chat_presentation_version().unwrap();
    app.set_chat_presentation_members("11", &["BB".repeat(32), "aa".repeat(32)])
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
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Ready(Box::new(selected))
    );
    assert_eq!(app.chat_presentation_version().unwrap(), version);
    assert_eq!(
        app.chat_presentation_input("11")
            .unwrap()
            .unwrap()
            .source_version,
        input.source_version
    );
}

#[test]
fn same_subject_source_changes_reopen_as_last_known_and_identical_repair_does_not_notify() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("last-known.db");
    let key = SqlCipherKey::raw([0x23; 32]);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "11");
    let input = store
        .app_storage()
        .chat_presentation_input("11")
        .unwrap()
        .unwrap();
    let selected = value("bb", "Peer", 1);
    store
        .app_storage()
        .store_chat_presentation(&input, &selected)
        .unwrap();
    let version = store.app_storage().chat_presentation_version().unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET image_media_type='image/jpeg' WHERE group_id_hex='11'",
            [],
        )
        .unwrap();
    drop(store);
    let store = SqliteAccountStorage::open_encrypted(&path, &key)
        .unwrap()
        .app_storage();
    let mut last_known = selected.clone();
    last_known.presentation.resolution = PresentationResolution::LastKnown;
    assert_eq!(
        store.chat_presentation("11").unwrap(),
        ChatPresentationRead::Ready(Box::new(last_known))
    );
    assert_eq!(store.chat_presentation_version().unwrap(), version);
    let pending = store.pending_chat_presentation_inputs().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        store
            .store_chat_presentation(&pending[0], &selected)
            .unwrap(),
        ChatPresentationWrite::Applied
    ); // Applied can mean only that durable source progress became clean.
    assert!(store.pending_chat_presentation_inputs().unwrap().is_empty());
    assert_eq!(store.chat_presentation_version().unwrap(), version);
    assert_eq!(
        store.chat_presentation("11").unwrap(),
        ChatPresentationRead::Ready(Box::new(selected))
    );
}

#[test]
fn malformed_member_identity_clears_peer_evidence() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "11");
    store
        .app_storage()
        .set_chat_presentation_members("11", &["aa".repeat(32), "bb".repeat(16)])
        .unwrap();
    assert!(
        store
            .app_storage()
            .chat_presentation_input("11")
            .unwrap()
            .unwrap()
            .members
            .is_empty()
    );
}

#[track_caller]
fn assert_fails_with<T: std::fmt::Debug, E: std::fmt::Display>(
    result: Result<T, E>,
    expected: &str,
) {
    let error = result.expect_err("the operation must fail");
    assert!(
        error.to_string().contains(expected),
        "expected an error containing {expected:?}, got: {error}"
    );
}

fn save_selected(store: &SqliteAppStorage, selected: &StoredChatPresentation) {
    let input = store.chat_presentation_input("11").unwrap().unwrap();
    store.store_chat_presentation(&input, selected).unwrap();
}
fn put_avatar_component(store: &SqliteAccountStorage, url: &str) {
    use cgka_traits::app_components::{GroupAvatarUrlV1, encode_group_avatar_url_v1};
    let bytes = encode_group_avatar_url_v1(&GroupAvatarUrlV1 {
        url: url.into(),
        dim: Vec::new(),
        thumbhash: Vec::new(),
    })
    .unwrap();
    store.lock().unwrap().execute(
        "INSERT INTO account_group_app_components
            (group_id_hex, component_id, component_name, component_data_hex, updated_at)
         VALUES ('11', ?1, 'avatar fixture', ?2, 1)
         ON CONFLICT(group_id_hex, component_id) DO UPDATE SET component_data_hex=excluded.component_data_hex",
        params![GROUP_AVATAR_URL_COMPONENT_ID, hex::encode(bytes)],
    ).unwrap();
}
#[test]
fn avatar_component_insert_replace_clear_and_delete_keep_work_and_display_consistent() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let peer = value("bb", "Peer", 1);
    save_selected(&app, &peer);
    let initial = app.chat_presentation_version().unwrap();
    put_avatar_component(&store, "https://example.com/first.png");
    assert_eq!(app.pending_chat_presentation_inputs().unwrap().len(), 1);
    let ChatPresentationRead::Ready(retained) = app.chat_presentation("11").unwrap() else {
        panic!("lost peer display");
    };
    assert_eq!(
        retained.presentation.resolution,
        PresentationResolution::LastKnown
    );
    assert_eq!(app.chat_presentation_version().unwrap(), initial);
    let mut group = peer.clone();
    group.presentation.avatar_source = PresentationSource::Group;
    group.presentation.avatar = SelectedAvatar::RemoteImage {
        url: "https://example.com/first.png".into(),
        cache_key: "group fixture".into(),
    };
    save_selected(&app, &group);
    let ready = app.chat_presentation_version().unwrap();
    put_avatar_component(&store, "https://example.com/first.png");
    assert!(app.pending_chat_presentation_inputs().unwrap().is_empty());
    put_avatar_component(&store, "https://example.com/second.png");
    assert_eq!(app.pending_chat_presentation_inputs().unwrap().len(), 1);
    assert_eq!(app.chat_presentation_version().unwrap(), ready);
    let ChatPresentationRead::Ready(retained) = app.chat_presentation("11").unwrap() else {
        panic!("lost replacement display");
    };
    assert!(retained.presentation.avatar == group.presentation.avatar);
    group.presentation.avatar = SelectedAvatar::RemoteImage {
        url: "https://example.com/second.png".into(),
        cache_key: "second fixture".into(),
    };
    save_selected(&app, &group);
    // Clearing uses a valid encoded absent component, not just deletion of its row.
    put_avatar_component(&store, "");
    assert_eq!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Pending
    );
    assert!(
        app.chat_presentation_dependents(&"bb".repeat(32), None)
            .unwrap()
            .is_empty()
    );
    assert_eq!(app.pending_chat_presentation_inputs().unwrap().len(), 1);
    save_selected(&app, &peer);
    put_avatar_component(&store, "https://example.com/second.png");
    save_selected(&app, &group);
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM account_group_app_components WHERE group_id_hex='11' AND component_id=?1",
            [GROUP_AVATAR_URL_COMPONENT_ID],
        )
        .unwrap();
    assert_eq!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Pending
    );
    assert_eq!(app.pending_chat_presentation_inputs().unwrap().len(), 1);
}
#[test]
fn removing_group_name_or_required_image_material_never_returns_removed_display() {
    for column in [
        "profile_name",
        "image_hash_hex",
        "image_key_hex",
        "image_nonce_hex",
        "image_upload_key_hex",
    ] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let app = store.app_storage();
        seed(&store, "11");
        store.lock().unwrap().execute(
            "UPDATE account_groups SET profile_name='Custom', image_hash_hex=?1, image_key_hex=?2,
                image_nonce_hex=?3, image_upload_key_hex=?4 WHERE group_id_hex='11'",
            params!["01".repeat(32), "02".repeat(32), "03".repeat(12), "04".repeat(32)],
        ).unwrap();
        let input = app.chat_presentation_input("11").unwrap().unwrap();
        let mut selected = value("bb", "Custom", 1);
        selected.presentation.title_source = PresentationSource::Group;
        selected.presentation.avatar_source = PresentationSource::Group;
        selected.presentation.avatar = SelectedAvatar::EncryptedGroupImage {
            image: input.avatar.unwrap(),
            cache_key: "group fixture".into(),
        };
        save_selected(&app, &selected);
        store
            .lock()
            .unwrap()
            .execute(
                &format!("UPDATE account_groups SET {column}='' WHERE group_id_hex='11'"),
                [],
            )
            .unwrap();
        assert_eq!(
            app.chat_presentation("11").unwrap(),
            ChatPresentationRead::Pending,
            "{column}"
        );
        assert_eq!(app.pending_chat_presentation_inputs().unwrap().len(), 1);
    }
}

#[test]
fn catchup_checkpoint_and_batch_roll_back_together_and_fence_old_workers() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    seed(&store, "22");
    let initial = app.chat_presentation_checkpoint().unwrap();
    let mut next = initial.state.clone();
    next.shared_epoch = vec![3; 16];
    let first = app.chat_presentation_input("11").unwrap().unwrap();
    let second = app.chat_presentation_input("22").unwrap().unwrap();
    assert_fails_with(
        app.commit_chat_presentation_batch(
            &initial,
            &next,
            &[
                (first.clone(), value("bb", "First", 1)),
                (second, value("cc", "Invalid peer", 1)),
            ],
        ),
        "presentation peer is not in captured roster",
    );
    assert!(matches!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Pending
    ));
    assert_eq!(
        app.chat_presentation_checkpoint().unwrap().generation,
        initial.generation
    );
    // A value prepared under another directory incarnation never commits.
    let mut other_directory = value("bb", "Other directory", 1);
    other_directory
        .profile_version
        .as_mut()
        .unwrap()
        .store_epoch = vec![4; 16];
    assert_fails_with(
        app.commit_chat_presentation_batch(&initial, &next, &[(first.clone(), other_directory)]),
        "presentation batch directory epoch mismatch",
    );
    assert!(matches!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Pending
    ));
    let unchanged = app.chat_presentation_checkpoint().unwrap();
    assert_eq!(unchanged.generation, initial.generation);
    assert!(unchanged.state == initial.state);
    assert!(
        app.commit_chat_presentation_batch(
            &initial,
            &next,
            &[(first.clone(), value("bb", "Current", 2))]
        )
        .unwrap()
    );
    assert!(
        !app.commit_chat_presentation_batch(&initial, &next, &[(first, value("bb", "Old", 1))])
            .unwrap()
    );
    assert_eq!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Ready(Box::new(value("bb", "Current", 2)))
    );
}

#[test]
fn initialization_completes_an_upsert_over_an_existing_chat_row() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    // Inject overlapping queued/existing state defensively. Normal snapshot
    // pruning cascades the chat row; it does not create this overlap.
    store
        .lock()
        .unwrap()
        .execute("INSERT INTO chat_presentation_row_work VALUES ('11')", [])
        .unwrap();
    app.refresh_chat_list_row(&"aa".repeat(32), "11", &|_, _| false)
        .unwrap();
    assert_eq!(
        app.pending_chat_presentation_rows().unwrap(),
        ["11"],
        "an upsert alone does not run the INSERT-only completion trigger"
    );
    let row_epoch = app
        .chat_presentation_input("11")
        .unwrap()
        .unwrap()
        .row_epoch;
    assert!(
        app.initialize_chat_presentation_row(&"aa".repeat(32), "11", &|_, _| false)
            .unwrap()
    );
    assert!(app.pending_chat_presentation_rows().unwrap().is_empty());
    assert_eq!(
        app.chat_presentation_input("11")
            .unwrap()
            .unwrap()
            .row_epoch,
        row_epoch
    );
    let row = app.chat_list_row("11").unwrap();
    assert!(
        !app.initialize_chat_presentation_row(&"aa".repeat(32), "11", &|_, _| false)
            .unwrap()
    );
    assert_eq!(app.chat_list_row("11").unwrap(), row);
}

#[test]
fn initialization_completion_failure_rolls_back_refresh_and_retries_after_reopen() {
    for (fail_with, expected) in [
        (
            "ABORT, 'injected completion failure'",
            "injected completion failure",
        ),
        ("IGNORE", "presentation initialization did not complete"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("initialization.db");
        let key = SqlCipherKey::raw([0x24; 32]);
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        seed(&store, "11");
        store
            .lock()
            .unwrap()
            .execute_batch(&format!(
                "INSERT INTO chat_presentation_row_work VALUES ('11');
             UPDATE account_groups SET profile_name='Changed' WHERE group_id_hex='11';
             CREATE TRIGGER prevent_completion BEFORE DELETE ON chat_presentation_row_work
             BEGIN SELECT RAISE({fail_with}); END;"
            ))
            .unwrap();
        let before = store.app_storage().chat_list_row("11").unwrap();
        assert_fails_with(
            store.app_storage().initialize_chat_presentation_row(
                &"aa".repeat(32),
                "11",
                &|_, _| false,
            ),
            expected,
        );
        assert_eq!(
            store.app_storage().chat_list_row("11").unwrap(),
            before,
            "refresh and completion must roll back together"
        );
        assert_eq!(
            store
                .app_storage()
                .pending_chat_presentation_rows()
                .unwrap(),
            ["11"]
        );
        drop(store);
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let app = store.app_storage();
        assert_eq!(app.pending_chat_presentation_rows().unwrap(), ["11"]);
        assert_eq!(app.chat_list_row("11").unwrap(), before);
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER prevent_completion")
            .unwrap();
        assert!(
            app.initialize_chat_presentation_row(&"aa".repeat(32), "11", &|_, _| false)
                .unwrap()
        );
        assert!(app.pending_chat_presentation_rows().unwrap().is_empty());
        assert_ne!(app.chat_list_row("11").unwrap(), before);
    }
}

#[test]
fn initialization_completes_a_new_row_and_ignores_deleted_work() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    store.lock().unwrap().execute("INSERT INTO account_groups(group_id_hex,endpoint,profile_name,updated_at) VALUES ('11','fixture','New',7)", []).unwrap();
    assert_eq!(app.pending_chat_presentation_rows().unwrap(), ["11"]);
    assert!(
        app.initialize_chat_presentation_row(&"aa".repeat(32), "11", &|_, _| false)
            .unwrap()
    );
    assert!(app.chat_list_row("11").unwrap().is_some());
    assert!(app.pending_chat_presentation_rows().unwrap().is_empty());
    store.lock().unwrap().execute("INSERT INTO account_groups(group_id_hex,endpoint,profile_name,updated_at) VALUES ('22','fixture','Removed',7)", []).unwrap();
    store
        .lock()
        .unwrap()
        .execute("DELETE FROM account_groups WHERE group_id_hex='22'", [])
        .unwrap();
    assert!(
        !app.initialize_chat_presentation_row(&"aa".repeat(32), "22", &|_, _| false)
            .unwrap()
    );
    assert!(app.chat_list_row("22").unwrap().is_none());
}

#[test]
fn presented_snapshot_is_complete_read_only_and_clears_replaced_peer() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let query = crate::ChatListQuery {
        include_archived: true,
    };
    assert!(
        app.read_presented_chat_list(query.clone(), None)
            .unwrap()
            .is_none()
    );
    let input = app.chat_presentation_input("11").unwrap().unwrap();
    app.store_chat_presentation(&input, &value("bb", "Peer", 1))
        .unwrap();
    let before: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT total_changes()", [], |r| r.get(0))
        .unwrap();
    let snapshot = app
        .read_presented_chat_list(query.clone(), None)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.rows.len(), 1);
    assert_eq!(snapshot.rows[0].row.activity_sort_at, 19);
    assert_eq!(snapshot.rows[0].presentation.peer_id, Some("bb".repeat(32)));
    assert_eq!(
        snapshot.presentation_version,
        app.chat_presentation_version().unwrap()
    );
    assert!(
        app.read_presented_chat_list(query.clone(), Some("22"))
            .unwrap()
            .unwrap()
            .rows
            .is_empty()
    );
    let after: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT total_changes()", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after, "ready reads must not repair or write");
    app.set_chat_presentation_members("11", &["aa".repeat(32), "cc".repeat(32)])
        .unwrap();
    assert!(
        app.read_presented_chat_list(query, None).unwrap().is_none(),
        "a new peer must not inherit the old selection"
    );
}

#[test]
fn dirty_fallback_remains_fallback_in_both_presentation_reads() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let input = app.chat_presentation_input("11").unwrap().unwrap();
    let mut fallback = value("bb", "Peer", 1);
    fallback.presentation.resolution = PresentationResolution::Fallback;
    fallback.presentation.title_source = PresentationSource::PeerFallback;
    app.store_chat_presentation(&input, &fallback).unwrap();
    store.lock().unwrap().execute(
        "UPDATE chat_list_rows SET presentation_source_revision = presentation_source_revision + 1",
        [],
    ).unwrap();
    let ChatPresentationRead::Ready(retained) = app.chat_presentation("11").unwrap() else {
        panic!("same-subject fallback remains renderable");
    };
    assert_eq!(
        retained.presentation.resolution,
        PresentationResolution::Fallback
    );
    let snapshot = app
        .read_presented_chat_list(
            crate::ChatListQuery {
                include_archived: true,
            },
            None,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot.rows[0].presentation.resolution,
        PresentationResolution::Fallback
    );
}

#[test]
fn selected_avatar_and_demand_commit_atomically_even_for_pending_invitations() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_list_rows SET pending_confirmation = 1 WHERE group_id_hex = '11'",
            [],
        )
        .unwrap();
    let input = app.chat_presentation_input("11").unwrap().unwrap();
    let mut selected = value("bb", "Invite", 1);
    selected.presentation.avatar = SelectedAvatar::RemoteImage {
        url: "https://example.com/a.png".into(),
        cache_key: "a".into(),
    };
    app.store_chat_presentation(&input, &selected).unwrap();
    let reference = app.chat_avatar_reference("11").unwrap().unwrap();
    let job = app.claim_avatar_acquisition(0).unwrap().unwrap();
    assert_eq!(job.reference, reference);
    store.lock().unwrap().execute_batch("CREATE TRIGGER reject_avatar_demand BEFORE INSERT ON avatar_acquisition BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    let mut changed = selected.clone();
    changed.presentation.avatar = SelectedAvatar::RemoteImage {
        url: "https://example.com/b.png".into(),
        cache_key: "b".into(),
    };
    assert_fails_with(app.store_chat_presentation(&input, &changed), "injected");
    assert_eq!(
        app.chat_presentation("11").unwrap(),
        ChatPresentationRead::Ready(Box::new(selected))
    );
    assert_eq!(app.chat_avatar_reference("11").unwrap(), Some(reference));
    store
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_avatar_demand;")
        .unwrap();
    app.store_chat_presentation(&input, &changed).unwrap();
    let image = crate::AvatarImage::new(vec![1; 8], crate::AvatarImageFormat::Png, 1, 1).unwrap();
    assert_eq!(
        app.complete_avatar_acquisition(&job, &image, None).unwrap(),
        crate::AvatarPublishResult::Superseded
    );
}

#[test]
fn avatar_ownership_does_not_limit_opaque_group_id_length() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let group = "ab".repeat(300);
    seed(&store, &group);
    let input = store
        .app_storage()
        .chat_presentation_input(&group)
        .unwrap()
        .unwrap();
    let mut selected = value("bb", "Group", 1);
    selected.presentation.avatar = SelectedAvatar::RemoteImage {
        url: "https://example.com/avatar.png".into(),
        cache_key: "source".into(),
    };
    store
        .app_storage()
        .store_chat_presentation(&input, &selected)
        .expect("avatar ownership must not impose a new MLS group ID bound");
}

#[test]
fn chat_list_draft_preview_reopens_from_encrypted_store_without_projection_write() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("draft-preview.db");
    let key = SqlCipherKey::raw([0x25; 32]);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    seed(&store, "11");
    let input = app.chat_presentation_input("11").unwrap().unwrap();
    app.store_chat_presentation(&input, &value("bb", "Peer", 1))
        .unwrap();
    app.save_message_draft("11", "persisted draft", None, &[])
        .unwrap();
    store.close().unwrap();
    drop(app);
    drop(store);
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let before: i64 = reopened
        .lock()
        .unwrap()
        .query_row("SELECT total_changes()", [], |r| r.get(0))
        .unwrap();
    let snapshot = reopened
        .app_storage()
        .read_presented_chat_list(
            crate::ChatListQuery {
                include_archived: true,
            },
            Some("11"),
        )
        .unwrap()
        .unwrap();
    assert!(
        matches!(&snapshot.rows[0].preview, SelectedChatPreview::Draft(d) if d.text == "persisted draft")
    );
    assert_eq!(snapshot.rows[0].row.activity_sort_at, 19);
    let after: i64 = reopened
        .lock()
        .unwrap()
        .query_row("SELECT total_changes()", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after);
}
