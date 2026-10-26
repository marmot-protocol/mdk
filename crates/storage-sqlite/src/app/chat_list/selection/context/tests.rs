use super::*;
use crate::SqliteAccountStorage;
use std::cell::Cell;

fn seed(store: &SqliteAccountStorage, id: &str) {
    let conn = store.lock().unwrap();
    conn.execute(
        "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES (?1,'',0)",
        [id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO chat_list_rows(group_id_hex,updated_at) VALUES (?1,0)",
        [id],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM chat_presentation_row_work WHERE group_id_hex=?1",
        [id],
    )
    .unwrap();
}
fn ready_presentation(store: &SqliteAccountStorage) {
    // This primitive checks metadata freshness only, never decodes/exposes titles.
    store.lock().unwrap().execute("UPDATE chat_list_rows SET presentation_json=x'00',presentation_applied_source_revision=presentation_source_revision",[]).unwrap();
}
fn capture(
    store: &SqliteAccountStorage,
    request: SelectionContextRequest,
    cancelled: &impl Fn() -> bool,
    matches: &mut impl FnMut(&SelectionSourceContext<'_>) -> bool,
) -> Result<Vec<String>, ContextError> {
    store.app_storage().connection.with_deferred_read(|conn| {
        context_filtered_ids(conn, ChatListView::Chats, request, 1000, cancelled, matches)
    })
}

#[test]
fn compact_context_visits_beyond_display_limit_in_frozen_view_order() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for n in 0..301 {
        seed(&store, &format!("{n:032x}"));
    }
    let seen = Cell::new(0);
    let ids = capture(
        &store,
        SelectionContextRequest::default(),
        &|| false,
        &mut |context| {
            seen.set(seen.get() + 1);
            u64::from_str_radix(context.group_id, 16).unwrap() >= 250
        },
    )
    .unwrap();
    assert_eq!(seen.get(), 301);
    assert_eq!(
        ids,
        (250..301).map(|n| format!("{n:032x}")).collect::<Vec<_>>()
    );
}

#[test]
fn unsupported_context_and_missing_readiness_never_return_prefixes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01");
    seed(&store, "02");
    let called = Cell::new(0);
    for unsupported in [
        RequiredContext::Participants,
        RequiredContext::Title,
        RequiredContext::Legacy,
    ] {
        assert!(matches!(
            capture(
                &store,
                SelectionContextRequest {
                    unsupported: Some(unsupported),
                    ..Default::default()
                },
                &|| false,
                &mut |_| {
                    called.set(called.get() + 1);
                    true
                }
            ),
            Err(ContextError::Unsupported(_))
        ));
    }
    assert_eq!(called.get(), 0);
    store.lock().unwrap().execute("UPDATE chat_list_rows SET presentation_json=x'00',presentation_applied_source_revision=presentation_source_revision WHERE group_id_hex='01'",[]).unwrap();
    assert!(matches!(
        capture(
            &store,
            SelectionContextRequest {
                presentation_readiness: true,
                ..Default::default()
            },
            &|| false,
            &mut |_| {
                called.set(called.get() + 1);
                true
            }
        ),
        Err(ContextError::NotReady(RequiredContext::Presentation))
    ));
    assert_eq!(called.get(), 1);
    store.lock().unwrap().execute("UPDATE chat_list_rows SET presentation_json=x'00',presentation_applied_source_revision=presentation_source_revision-1 WHERE group_id_hex='02'",[]).unwrap();
    assert!(matches!(
        capture(
            &store,
            SelectionContextRequest {
                presentation_readiness: true,
                ..Default::default()
            },
            &|| false,
            &mut |_| true
        ),
        Err(ContextError::NotReady(RequiredContext::Presentation))
    ));
    // No readiness claim is implied when selected presentation is not requested.
    assert_eq!(
        capture(
            &store,
            SelectionContextRequest::default(),
            &|| false,
            &mut |_| true
        )
        .unwrap()
        .len(),
        2
    );
}

#[test]
fn cancellation_after_native_callback_discards_matching_prefix() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01");
    seed(&store, "02");
    let cancelled = Cell::new(false);
    let seen = Cell::new(0);
    let result = capture(
        &store,
        SelectionContextRequest::default(),
        &|| cancelled.get(),
        &mut |_| {
            seen.set(seen.get() + 1);
            cancelled.set(true);
            true
        },
    );
    assert!(matches!(
        result,
        Err(ContextError::Selection(ChatListSelectionError::Cancelled))
    ));
    assert_eq!(seen.get(), 1);
    assert!(matches!(
        capture(
            &store,
            SelectionContextRequest::default(),
            &|| true,
            &mut |_| panic!("callback on cancelled capture")
        ),
        Err(ContextError::Selection(ChatListSelectionError::Cancelled))
    ));
}

#[test]
fn selected_draft_truth_matches_exact_native_prefix_and_kotlin_whitespace() {
    use crate::app::chat_presentation::row_contract::{
        CHAT_LIST_DRAFT_PREVIEW_CHARS, SelectedChatPreview, selected_preview_tx,
    };
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01");
    ready_presentation(&store);
    for (text, expected, selected) in [
        ("".to_owned(), false, false),
        (" \t\n".to_owned(), false, false),
        ("\u{001c}\u{001d}\u{001e}\u{001f}".to_owned(), false, true),
        ("\u{0085}".to_owned(), false, false),
        ("\u{00a0}".to_owned(), false, false),
        ("\0text".to_owned(), true, true),
        (
            format!("{}x", "\u{001c}".repeat(CHAT_LIST_DRAFT_PREVIEW_CHARS)),
            false,
            true,
        ),
        (
            format!("{}\0", "\u{001c}".repeat(CHAT_LIST_DRAFT_PREVIEW_CHARS - 1)),
            true,
            true,
        ),
        ("🦀".repeat(1025), true, true),
    ] {
        store
            .app_storage()
            .save_message_draft("01", &text, None, &[])
            .unwrap();
        // Source snapshot/preview uses the same bounded helper as the visitor.
        let conn = store.lock().unwrap();
        let row = crate::app::chat_list::chat_list_row_tx(&conn, "01")
            .unwrap()
            .unwrap();
        let preview = selected_preview_tx(&conn, &row).unwrap();
        assert_eq!(matches!(preview, SelectedChatPreview::Draft(_)), selected);
        if let SelectedChatPreview::Draft(draft) = preview {
            assert!(draft.text.chars().count() <= 1024);
            assert!(draft.text.len() <= 4096);
        }
        drop(conn);
        capture(
            &store,
            SelectionContextRequest {
                draft: true,
                ..Default::default()
            },
            &|| false,
            &mut |c| {
                assert_eq!(c.selected_preview_has_draft, Some(expected));
                true
            },
        )
        .unwrap();
    }
    store
        .app_storage()
        .save_message_draft("01", "", None, &[])
        .unwrap();
    store.lock().unwrap().execute("INSERT INTO message_draft_attachments(group_id_hex,position,attachment_id,file_name,media_type,plaintext,waveform_samples_json) VALUES ('01',0,'private','private','image/png',zeroblob(8000000),'invalid-json')",[]).unwrap();
    capture(
        &store,
        SelectionContextRequest {
            draft: true,
            ..Default::default()
        },
        &|| false,
        &mut |c| {
            assert_eq!(c.selected_preview_has_draft, Some(true));
            true
        },
    )
    .unwrap();
}

#[test]
fn native_scalar_facts_keep_mute_pin_kind_and_last_message_boundaries() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01");
    let conn = store.lock().unwrap();
    conn.execute(
        "UPDATE account_groups SET member_count=2 WHERE group_id_hex='01'",
        [],
    )
    .unwrap();
    conn.execute("UPDATE chat_list_rows SET unread_count=2,manually_marked_unread=1,unread_mention_count=3,last_message_id_hex='message',last_message_sender='aa',last_message_deleted=0,last_message_delivery_state='pending',group_name=?1 WHERE group_id_hex='01'",["\u{2003}\u{00a0}"]).unwrap();
    conn.execute("DELETE FROM chat_presentation_row_work", [])
        .unwrap();
    conn.execute(
        "INSERT INTO chat_notification_settings(group_id_hex,muted_until_ms,updated_at_ms) VALUES ('01',1000,0)",
        [],
    )
    .unwrap();
    // Pin ordinal is independent of the legacy stored pinned flag.
    conn.execute(
        "INSERT INTO chat_pin_positions(group_id_hex,ordinal) VALUES ('01',0)",
        [],
    )
    .unwrap();
    drop(conn);
    capture(
        &store,
        SelectionContextRequest::default(),
        &|| false,
        &mut |c| {
            assert!(c.projection.pinned);
            assert!(!c.projection.muted);
            assert_eq!(c.projection.unread_count, 2);
            assert!(c.projection.manually_marked_unread);
            assert_eq!(c.projection.unread_mention_count, 3);
            assert_eq!(c.projection.conversation_kind, ChatConversationKind::Direct);
            assert!(c.native_sending);
            true
        },
    )
    .unwrap();
    for (update, expected) in [
        ("UPDATE chat_list_rows SET last_message_deleted=1", false),
        (
            "UPDATE chat_list_rows SET last_message_deleted=0,last_message_delivery_state='failed'",
            false,
        ),
        (
            "UPDATE chat_list_rows SET last_message_delivery_state='delivered'",
            false,
        ),
        (
            "UPDATE chat_list_rows SET last_message_delivery_state='pending'",
            true,
        ),
        (
            "INSERT INTO user_blocks(public_key,is_private,created_at_ms) VALUES ('aa',0,0)",
            false,
        ),
    ] {
        store.lock().unwrap().execute(update, []).unwrap();
        capture(
            &store,
            SelectionContextRequest::default(),
            &|| false,
            &mut |c| {
                assert_eq!(c.native_sending, expected);
                true
            },
        )
        .unwrap();
    }
    for count in ["-1", "2.5"] {
        store
            .lock()
            .unwrap()
            .execute(
                &format!("UPDATE account_groups SET member_count={count}"),
                [],
            )
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute("DELETE FROM chat_presentation_row_work", [])
            .unwrap();
        capture(
            &store,
            SelectionContextRequest::default(),
            &|| false,
            &mut |c| {
                assert_eq!(
                    c.projection.conversation_kind,
                    ChatConversationKind::Unknown
                );
                true
            },
        )
        .unwrap();
    }
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_notification_settings SET muted_until_ms=1001",
            [],
        )
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute("UPDATE chat_list_rows SET group_name=?1", ["\0"])
        .unwrap();
    capture(
        &store,
        SelectionContextRequest::default(),
        &|| false,
        &mut |c| {
            assert!(c.projection.muted);
            assert_eq!(c.projection.conversation_kind, ChatConversationKind::Group);
            true
        },
    )
    .unwrap();
}

#[test]
fn accepted_raw_sources_read_durable_leave_disband_and_tombstone_gates() {
    use crate::base::test_support::{gid, sample_group};
    use cgka_traits::storage::{
        DisbandFailureReason, DisbandRequest, DisbandRequestStatus, DisbandRequestStorage,
        GroupStorage, LeaveRequest, LeaveRequestStorage,
    };
    let store = SqliteAccountStorage::in_memory().unwrap();
    let group = sample_group(gid(1), 3, 0);
    store.put_group(&group).unwrap();
    let id = hex::encode(group.id.as_slice());
    seed(&store, &id);
    store
        .put_leave_request(&LeaveRequest {
            group_id: group.id.clone(),
            requested_at_ms: 1,
            last_proposed_epoch: None,
        })
        .unwrap();
    for (status, expected) in [
        (DisbandRequestStatus::Pending, true),
        (
            DisbandRequestStatus::Failed(DisbandFailureReason::NoLongerAdmin),
            false,
        ),
    ] {
        store
            .put_disband_request(&DisbandRequest {
                group_id: group.id.clone(),
                requested_at_ms: 2,
                status,
                last_prepared_epoch: None,
            })
            .unwrap();
        capture(
            &store,
            SelectionContextRequest {
                accepted_sources: true,
                ..Default::default()
            },
            &|| false,
            &mut |c| {
                let a = c.accepted_sources.unwrap();
                assert!(a.leave_request_pending);
                assert_eq!(a.disbanding, expected);
                assert!(!a.disbanded);
                true
            },
        )
        .unwrap();
    }
    store.lock().unwrap().execute("INSERT INTO cgka_disband_candidates(group_id,commit_id,record) VALUES (?1,x'01',x'00')",[group.id.as_slice()]).unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_disband_tombstones(group_id,record) VALUES (?1,x'00')",
            [group.id.as_slice()],
        )
        .unwrap();
    store.clear_leave_request(&group.id).unwrap();
    capture(
        &store,
        SelectionContextRequest {
            accepted_sources: true,
            ..Default::default()
        },
        &|| false,
        &mut |c| {
            let a = c.accepted_sources.unwrap();
            assert!(!a.leave_request_pending);
            assert!(a.disbanding);
            assert!(a.disbanded);
            true
        },
    )
    .unwrap();
}

#[test]
fn compact_visitor_queries_and_debug_do_not_hydrate_private_bodies_or_rosters() {
    static QUERIES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    fn record(event: rusqlite::trace::TraceEvent<'_>) {
        if let rusqlite::trace::TraceEvent::Stmt(_, sql) = event {
            QUERIES.lock().unwrap().push(sql.to_owned());
        }
    }
    let store = SqliteAccountStorage::in_memory().unwrap();
    let id = "1234567890abcdef1234567890abcdef";
    seed(&store, id);
    ready_presentation(&store);
    store
        .app_storage()
        .save_message_draft(id, "private-draft-sentinel", None, &[])
        .unwrap();
    store.lock().unwrap().trace_v2(
        rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
        Some(record),
    );
    capture(
        &store,
        SelectionContextRequest {
            draft: true,
            ..Default::default()
        },
        &|| false,
        &mut |c| {
            let debug = format!("{c:?}");
            assert!(!debug.contains(id));
            assert!(!debug.contains("private-draft-sentinel"));
            true
        },
    )
    .unwrap();
    store
        .lock()
        .unwrap()
        .trace_v2(rusqlite::trace::TraceEventCodes::empty(), None);
    let queries = QUERIES.lock().unwrap();
    assert!(!queries.is_empty());
    for sql in queries
        .iter()
        .filter(|s| s.trim_start().starts_with("SELECT"))
    {
        for forbidden in [
            "last_message_preview",
            "media_json",
            "avatar_asset",
            "cgka_groups",
            "chat_presentation_members",
            "waveform_samples_json",
            "SELECT plaintext",
        ] {
            assert!(
                !sql.contains(forbidden),
                "unexpected hydration query: {sql}"
            );
        }
        if sql.contains("content") {
            assert!(sql.contains("substr(CAST(trim(content"));
        }
    }
}

#[test]
fn draft_request_derives_presentation_readiness_even_without_explicit_flag() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01");
    let called = Cell::new(0);
    for dirty in [false, true] {
        if dirty {
            store.lock().unwrap().execute("UPDATE chat_list_rows SET presentation_json=x'00',presentation_applied_source_revision=presentation_source_revision-1",[]).unwrap();
        }
        let result = capture(
            &store,
            SelectionContextRequest {
                draft: true,
                presentation_readiness: false,
                ..Default::default()
            },
            &|| false,
            &mut |_| {
                called.set(called.get() + 1);
                true
            },
        );
        assert!(
            matches!(
                result,
                Err(ContextError::NotReady(RequiredContext::Presentation))
            ),
            "draft must not infer FALSE without selected-context readiness"
        );
    }
    assert_eq!(called.get(), 0);
}

#[test]
fn members_are_optional_but_required_readiness_failure_discards_matched_prefix() {
    use crate::base::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;
    let store = SqliteAccountStorage::in_memory().unwrap();
    for n in 1..=2 {
        let group = sample_group(gid(n), 0, 1);
        store.put_group(&group).unwrap();
        seed(&store, &hex::encode(group.id.as_slice()));
    }
    let checks = Cell::new(0);
    let ids = store
        .app_storage()
        .capture_chat_list_context_ids_with_members::<&str>(
            ChatListView::Chats,
            SelectionContextRequest::default(),
            1000,
            &|| false,
            None,
            &mut |_| {
                checks.set(checks.get() + 1);
                Err("must not run")
            },
            &mut |row| {
                assert!(row.selected_members.is_none());
                true
            },
        )
        .unwrap();
    assert_eq!(ids.len(), 2);
    assert_eq!(checks.get(), 0);
    let keys = crate::SelectedMemberKeys::new(&[[0; 32]]).unwrap();
    let local = std::collections::HashSet::new();
    let matched = Cell::new(0);
    let result = store
        .app_storage()
        .capture_chat_list_context_ids_with_members(
            ChatListView::Chats,
            SelectionContextRequest::default(),
            1000,
            &|| false,
            Some((
                &keys,
                crate::PeerInputs {
                    active: None,
                    local_profile_ids: &local,
                },
            )),
            &mut |_| {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    Err("not ready")
                } else {
                    Ok(())
                }
            },
            &mut |row| {
                assert!(row.selected_members.is_some());
                matched.set(matched.get() + 1);
                true
            },
        );
    assert!(matches!(
        result,
        Err(ContextCaptureError::Readiness("not ready"))
    ));
    assert_eq!(checks.get(), 2);
    assert_eq!(matched.get(), 1);
}

#[test]
fn foreign_sqlite_commit_during_capture_does_not_mix_eligibility_and_roster() {
    use crate::base::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;
    use cgka_traits::{GroupId, Member, MemberId, StorageProvider};
    use std::sync::mpsc;
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot.sqlite");
    let key = crate::SqlCipherKey::new("native snapshot fixture").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let foreign = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut group = sample_group(gid(1), 0, 0);
    group.members = vec![Member {
        id: MemberId::new(vec![1; 32]),
        credential: vec![],
    }];
    store.put_group(&group).unwrap();
    let id = hex::encode(group.id.as_slice());
    seed(&store, &id);
    let mut replacement = group.clone();
    replacement.members[0].id = MemberId::new(vec![2; 32]);
    let (go_tx, go_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let changed_id = id.clone();
    let writer = std::thread::spawn(move || {
        go_rx.recv().unwrap();
        foreign
            .with_transaction::<_, StorageError, _>(|exact| {
                exact.put_group(&replacement)?;
                let conn = exact.lock()?;
                // Navigation keys are derived from account_groups; update its
                // authoritative archive fact before the row's scalar mirror.
                conn.execute(
                    "UPDATE account_groups SET archived=1 WHERE group_id_hex=?1",
                    [&changed_id],
                )
                .storage()?;
                conn.execute(
                    "UPDATE chat_list_rows SET archived=1 WHERE group_id_hex=?1",
                    [&changed_id],
                )
                .storage()?;
                let scope: i64 = conn
                    .query_row(
                        "SELECT list_scope FROM chat_list_rows WHERE group_id_hex=?1",
                        [&changed_id],
                        |row| row.get(0),
                    )
                    .storage()?;
                assert_eq!(scope, 1);
                Ok(())
            })
            .unwrap();
        done_tx.send(()).unwrap();
    });
    let keys = crate::SelectedMemberKeys::new(&[[1; 32]]).unwrap();
    let local = std::collections::HashSet::new();
    let result = store
        .app_storage()
        .capture_chat_list_context_ids_with_members::<&str>(
            ChatListView::Chats,
            SelectionContextRequest::default(),
            1000,
            &|| false,
            Some((
                &keys,
                crate::PeerInputs {
                    active: None,
                    local_profile_ids: &local,
                },
            )),
            &mut |_: &GroupId| {
                // Eligibility and scalar SQL have already established the snapshot.
                // This test-only scheduling hook is not a production host callback.
                go_tx.send(()).unwrap();
                done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                Ok(())
            },
            &mut |row| {
                assert!(!row.projection.archived);
                row.selected_members.unwrap().contains(0)
            },
        )
        .unwrap();
    writer.join().unwrap();
    assert_eq!(result, vec![id]);
    assert!(
        store
            .app_storage()
            .capture_chat_list_context_ids_with_members::<&str>(
                ChatListView::Chats,
                SelectionContextRequest::default(),
                1000,
                &|| false,
                None,
                &mut |_| Ok(()),
                &mut |_| true,
            )
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.get_group(&group.id).unwrap().members[0].id.as_slice(),
        &[2; 32]
    );
}

#[test]
fn same_handle_writer_waits_until_compact_members_capture_releases_connection() {
    use crate::base::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;
    use cgka_traits::{Member, MemberId};
    use std::sync::mpsc;
    use std::time::Duration;
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut group = sample_group(gid(1), 0, 0);
    group.members = vec![Member {
        id: MemberId::new(vec![1; 32]),
        credential: vec![],
    }];
    store.put_group(&group).unwrap();
    let id = hex::encode(group.id.as_slice());
    seed(&store, &id);
    let writer_store = store.clone();
    let mut replacement = group.clone();
    replacement.members.clear();
    let (go_tx, go_rx) = mpsc::channel();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        go_rx.recv().unwrap();
        started_tx.send(()).unwrap();
        writer_store.put_group(&replacement).unwrap();
        done_tx.send(()).unwrap();
    });
    let keys = crate::SelectedMemberKeys::new(&[[1; 32]]).unwrap();
    let local = std::collections::HashSet::new();
    let result = store
        .app_storage()
        .capture_chat_list_context_ids_with_members::<&str>(
            ChatListView::Chats,
            SelectionContextRequest::default(),
            1000,
            &|| false,
            Some((
                &keys,
                crate::PeerInputs {
                    active: None,
                    local_profile_ids: &local,
                },
            )),
            &mut |_| {
                go_tx.send(()).unwrap();
                started_rx.recv().unwrap();
                assert!(matches!(
                    done_rx.recv_timeout(Duration::from_millis(50)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ));
                Ok(())
            },
            &mut |row| row.selected_members.unwrap().contains(0),
        )
        .unwrap();
    assert_eq!(result, vec![id]);
    done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    writer.join().unwrap();
    assert!(store.get_group(&group.id).unwrap().members.is_empty());
}

fn complete_capture_encoded_title() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"format":1,"value":{"presentation":{"title":{"Literal":"chosen-title"},"avatar":{"Placeholder":{"stable_seed":"private-avatar-sentinel","source":"Group"}},"title_source":"Group","avatar_source":"Group","peer_id":null,"resolution":"Cached"},"profile_version":null}})).unwrap()
}
#[test]
fn complete_capture_union_and_original_ids_are_keyed_and_never_add_arrivals() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for id in ["01", "02", "03"] {
        seed(&store, id);
    }
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "UPDATE account_groups SET archived=1 WHERE group_id_hex='02'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE chat_list_rows SET archived=1 WHERE group_id_hex='02'",
            [],
        )
        .unwrap();
    }
    let run = |base, original: Option<&[String]>| {
        store.app_storage().visit_selection_scope_context(
            base,
            original,
            SelectionContextRequest::default(),
            1000,
            &|| false,
            None,
            &mut |_| Ok::<_, std::convert::Infallible>(()),
            &mut |_| Ok(true),
        )
    };
    assert_eq!(
        run(SelectionBaseScope::ActiveAndArchived, None)
            .unwrap()
            .len(),
        3
    );
    let original = vec!["02".into(), "01".into(), "99".into()];
    assert_eq!(
        run(
            SelectionBaseScope::View(ChatListView::Chats),
            Some(&original)
        )
        .unwrap(),
        vec!["01"]
    );
    assert!(
        run(
            SelectionBaseScope::ActiveAndArchived,
            Some(&["01".into(), "01".into()])
        )
        .is_err()
    );
}
#[test]
fn complete_capture_title_length_preflight_counts_nul_and_retains_no_avatar() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01");
    {
        let conn = store.lock().unwrap();
        conn.execute("UPDATE chat_list_rows SET group_name=?1,title='projected',presentation_json=?2,presentation_applied_source_revision=presentation_source_revision WHERE group_id_hex='01'",params!["raw\0suffix",complete_capture_encoded_title()]).unwrap();
    }
    let request = SelectionContextRequest {
        title: true,
        text_budget: Some(1),
        ..Default::default()
    };
    let called = Cell::new(0);
    assert!(
        capture(&store, request, &|| false, &mut |_| {
            called.set(called.get() + 1);
            true
        })
        .is_err()
    );
    assert_eq!(called.get(), 0);
    let mut request = request;
    request.text_budget = Some(1024);
    let ids = capture(&store, request, &|| false, &mut |context| {
        let input = context.title_inputs.unwrap();
        assert_eq!(input.row_group_name, "raw\0suffix");
        assert!(input.selected.title == crate::PresentationText::Literal("chosen-title".into()));
        assert!(!format!("{input:?}").contains("sentinel"));
        true
    })
    .unwrap();
    assert_eq!(ids, vec!["01"]);
}
#[test]
fn complete_capture_known_kind_only_filter_skips_envelope_and_roster() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "01");
    // This named row is canonically Group. It deliberately has neither a
    // usable envelope nor a protocol Group record; a real fallback decode
    // would fail rather than let this test pass.
    store.lock().unwrap().execute("UPDATE chat_list_rows SET group_name='Named',presentation_json=x'00' WHERE group_id_hex='01'",[]).unwrap();
    let empty = crate::SelectedMemberKeys::for_legacy_catalog(&[]).unwrap();
    let local = std::collections::HashSet::new();
    let checks = Cell::new(0);
    let result = store
        .app_storage()
        .visit_selection_scope_context(
            SelectionBaseScope::ActiveAndArchived,
            None,
            SelectionContextRequest {
                title: true,
                title_unknown_kind_only: true,
                text_budget: Some(1024),
                ..Default::default()
            },
            1000,
            &|| false,
            Some((
                &empty,
                crate::PeerInputs {
                    active: Some([1; 32]),
                    local_profile_ids: &local,
                },
            )),
            &mut |_| {
                checks.set(checks.get() + 1);
                Ok::<_, std::convert::Infallible>(())
            },
            &mut |context| {
                assert!(context.title_inputs.is_none());
                assert!(context.selected_members.is_none());
                Ok(true)
            },
        )
        .unwrap();
    assert_eq!(result, vec!["01"]);
    assert_eq!(checks.get(), 0);
}
