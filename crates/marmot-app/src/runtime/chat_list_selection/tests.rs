use super::*;
use crate::*;
use marmot_account::AccountHome;
use storage_sqlite::StoredAccountState;

struct Fixture {
    _dir: tempfile::TempDir,
    app: MarmotApp,
    runtime: MarmotAppRuntime,
    store: SqliteAccountStorage,
    account_id: String,
}
impl Fixture {
    fn new(count: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
        app.ensure_account_state("alice").unwrap();
        let store = app.account_storage("alice").unwrap();
        let groups = (0..count)
            .map(|i| {
                let mut group = AppGroupRecord::new(
                    format!("{i:04x}"),
                    AppGroupNostrRoutingComponent::new(
                        cgka_traits::app_components::NostrRoutingV1 {
                            nostr_group_id: [1; 32],
                            relays: vec!["wss://relay.example".into()],
                        },
                    )
                    .unwrap(),
                    format!("Chat {i}"),
                    String::new(),
                    AppGroupImageInput::default(),
                    AppGroupAdminPolicyComponent::new(vec![]),
                    AppGroupMessageRetentionComponent::disabled(),
                );
                group.member_count = Some(3);
                crate::conversions::stored_group_from_app_group(&group)
            })
            .collect();
        store
            .save_account_projection_state(
                &StoredAccountState {
                    label: "alice".into(),
                    groups,
                    ..Default::default()
                },
                100,
                120,
            )
            .unwrap();
        store
            .refresh_chat_list_rows(&account.account_id_hex, &|_, _| false)
            .unwrap();
        let runtime = MarmotAppRuntime::new(app.clone());
        Self {
            _dir: dir,
            app,
            runtime,
            store,
            account_id: account.account_id_hex,
        }
    }
}

#[tokio::test]
async fn folder_capture_uses_full_native_scope_and_freezes_the_rule() {
    let f = Fixture::new(501);
    let shared = f.app.shared_storage().unwrap();
    for _ in 0..24 {
        crate::chat_presentation::maintenance::prepare_batch(&f.store, &shared, &f.account_id)
            .unwrap();
    }
    let rule = ChatFolderSelectionRule {
        keyword: Some("Chat".into()),
        ..Default::default()
    };
    let handle = f
        .runtime
        .capture_chat_folder_selection("alice", rule)
        .await
        .unwrap();
    assert_eq!(handle.count().await.unwrap().count, 501);
    assert_eq!(handle.page(0, 400, 200).await.unwrap().group_ids.len(), 101);
    f.store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_list_rows SET folder_title_fold='other' WHERE group_id_hex='0001'",
            [],
        )
        .unwrap();
    assert_eq!(handle.count().await.unwrap().count, 501);
    let checked = handle.revalidate(0).await.unwrap();
    assert_eq!(checked.count, 500);
    assert_eq!(checked.revision, 1);
    assert!(matches!(
        handle.page(0, 0, 1).await,
        Err(ChatSelectionError::StaleRevision)
    ));
    handle.close();
}

#[tokio::test]
async fn invalid_folder_is_rejected_before_capture_and_manual_scope_needs_no_roster() {
    let f = Fixture::new(3);
    assert!(matches!(
        f.runtime
            .capture_chat_folder_selection(
                "alice",
                ChatFolderSelectionRule {
                    version: 2,
                    ..Default::default()
                }
            )
            .await,
        Err(ChatSelectionError::Selection(
            ChatListSelectionError::InvalidFilter
        ))
    ));
    let handle = f
        .runtime
        .capture_chat_folder_selection(
            "alice",
            ChatFolderSelectionRule {
                manual_include_ids: vec!["0000".into(), "0001".into(), "ffff".into()],
                manual_exclude_ids: vec!["0001".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(handle.page(0, 0, 200).await.unwrap().group_ids, ["0000"]);
    handle.close();
}

#[tokio::test]
async fn keyword_revalidation_waits_for_shared_profile_catch_up_without_mutating_intent() {
    let f = Fixture::new(3);
    let shared = f.app.shared_storage().unwrap();
    for _ in 0..6 {
        crate::chat_presentation::maintenance::prepare_batch(&f.store, &shared, &f.account_id)
            .unwrap();
    }
    let handle = f
        .runtime
        .capture_chat_folder_selection(
            "alice",
            ChatFolderSelectionRule {
                keyword: Some("chat".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    shared
        .put_public_directory_user(&storage_sqlite::PublicDirectoryUserRecord {
            account_id_hex: "bb".repeat(32),
            npub: "fixture".into(),
            profile_json: Some("{\"name\":\"Changed\"}".into()),
            relay_lists_json: "{}".into(),
            key_package_json: None,
            event_id_hex: None,
            event_kind: None,
            event_created_at: None,
            follows: vec![],
        })
        .unwrap();
    assert!(matches!(
        handle.revalidate(0).await,
        Err(ChatSelectionError::Selection(
            ChatListSelectionError::ProjectionNotReady
        ))
    ));
    assert_eq!(
        handle.count().await.unwrap(),
        ChatSelectionSummary {
            revision: 0,
            count: 3
        }
    );
    for _ in 0..6 {
        crate::chat_presentation::maintenance::prepare_batch(&f.store, &shared, &f.account_id)
            .unwrap();
    }
    assert_eq!(
        handle.revalidate(0).await.unwrap(),
        ChatSelectionSummary {
            revision: 1,
            count: 3
        }
    );
    handle.close();
}

#[tokio::test]
async fn complete_selection_pages_all_ids_without_hydrating_presentation() {
    let f = Fixture::new(501);
    let handle = f
        .runtime
        .capture_chat_list_selection("alice", ChatListView::Chats)
        .await
        .unwrap();
    let summary = handle.count().await.unwrap();
    assert_eq!(
        summary,
        ChatSelectionSummary {
            revision: 0,
            count: 501
        }
    );
    let mut all = Vec::new();
    for offset in [0, 200, 400] {
        let page = handle.page(0, offset, 200).await.unwrap();
        assert_eq!(page.summary, summary);
        all.extend(page.group_ids);
    }
    assert_eq!(
        all,
        (0..501).map(|i| format!("{i:04x}")).collect::<Vec<_>>()
    );
    assert!(matches!(
        f.store.chat_presentation("0000").unwrap(),
        storage_sqlite::ChatPresentationRead::Pending
    ));
    assert!(matches!(
        handle.page(0, 0, 201).await,
        Err(ChatSelectionError::Selection(
            storage_sqlite::ChatListSelectionError::InvalidPage
        ))
    ));
    handle.close();
}

#[tokio::test]
async fn deselection_revision_rejects_old_pages_and_never_admits_foreign_ids() {
    let f = Fixture::new(3);
    let handle = f
        .runtime
        .capture_chat_list_selection("alice", ChatListView::Chats)
        .await
        .unwrap();
    assert_eq!(handle.deselect(0, "ffff").await.unwrap().revision, 0);
    let changed = handle.deselect(0, "0001").await.unwrap();
    assert_eq!(
        changed,
        ChatSelectionSummary {
            revision: 1,
            count: 2
        }
    );
    assert!(matches!(
        handle.page(0, 0, 200).await,
        Err(ChatSelectionError::StaleRevision)
    ));
    assert!(matches!(
        handle.deselect(0, "0000").await,
        Err(ChatSelectionError::StaleRevision)
    ));
    assert_eq!(
        handle.page(1, 0, 200).await.unwrap().group_ids,
        ["0000", "0002"]
    );
    handle.close();
}

#[tokio::test]
async fn action_revalidation_preserves_frozen_intent_and_supersedes_pages() {
    let f = Fixture::new(3);
    let handle = f
        .runtime
        .capture_chat_list_selection("alice", ChatListView::Chats)
        .await
        .unwrap();
    let mut projection = f.store.load_account_projection_state("alice", 100).unwrap();
    projection.groups[1].archived = true;
    let mut late = projection.groups[0].clone();
    late.group_id_hex = "ffff".into();
    projection.groups.push(late);
    f.store
        .save_account_projection_state(&projection, 100, 120)
        .unwrap();
    f.store
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    assert_eq!(handle.count().await.unwrap().count, 3);
    let checked = handle.revalidate(0).await.unwrap();
    assert_eq!(
        checked,
        ChatSelectionSummary {
            revision: 1,
            count: 2
        }
    );
    assert_eq!(
        handle.page(1, 0, 200).await.unwrap().group_ids,
        ["0000", "0002"]
    );
    assert!(matches!(
        handle.page(0, 0, 200).await,
        Err(ChatSelectionError::StaleRevision)
    ));
    projection.groups[1].archived = false;
    f.store
        .save_account_projection_state(&projection, 100, 120)
        .unwrap();
    f.store
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    assert_eq!(handle.revalidate(1).await.unwrap().count, 2);
    handle.close();
}

#[tokio::test]
async fn close_is_idempotent_and_all_shared_handles_reject_commands() {
    let f = Fixture::new(1);
    let handle = f
        .runtime
        .capture_chat_list_selection("alice", ChatListView::Chats)
        .await
        .unwrap();
    let clone = handle.clone();
    handle.close();
    clone.close();
    assert!(matches!(
        clone.count().await,
        Err(ChatSelectionError::Closed)
    ));
    assert!(matches!(
        clone.revalidate(0).await,
        Err(ChatSelectionError::Closed)
    ));
}

#[tokio::test]
async fn reset_and_shutdown_close_instead_of_rebinding() {
    for shutdown in [false, true] {
        let f = Fixture::new(1);
        let handle = f
            .runtime
            .capture_chat_list_selection("alice", ChatListView::Chats)
            .await
            .unwrap();
        if shutdown {
            f.runtime.shared.lifecycle().begin_shutdown();
        } else {
            f.app
                .presentation_signals
                .account_resets
                .send("alice".into())
                .unwrap();
        }
        assert!(matches!(
            handle.page(0, 0, 200).await,
            Err(ChatSelectionError::Closed)
        ));
        assert!(matches!(
            handle.count().await,
            Err(ChatSelectionError::Closed)
        ));
    }
}

#[tokio::test]
async fn dropping_last_handle_releases_the_actor_and_reset_receiver() {
    let f = Fixture::new(1);
    let before = f.app.presentation_signals.account_resets.receiver_count();
    let handle = f
        .runtime
        .capture_chat_list_selection("alice", ChatListView::Chats)
        .await
        .unwrap();
    assert_eq!(
        f.app.presentation_signals.account_resets.receiver_count(),
        before + 2
    );
    drop(handle);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while f.app.presentation_signals.account_resets.receiver_count() != before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_queued_deselection_does_not_change_intent() {
    let f = Fixture::new(1);
    let handle = f
        .runtime
        .capture_chat_list_selection("alice", ChatListView::Chats)
        .await
        .unwrap();
    let (reply, receiver) = oneshot::channel();
    drop(receiver);
    handle
        .commands
        .send(Command {
            revision: Some(0),
            action: Action::Deselect("0000".into()),
            reply,
        })
        .await
        .unwrap();
    assert_eq!(
        handle.count().await.unwrap(),
        ChatSelectionSummary {
            revision: 0,
            count: 1
        }
    );
    handle.close();
}

#[tokio::test]
async fn queued_success_is_discarded_at_delivery_after_terminal_transition() {
    // A controlled responder makes the dangerous interval deterministic:
    // success has been published, but the awaiting host has not consumed it.
    for shutdown in [false, true] {
        let (commands, mut received) = mpsc::channel(1);
        let (closing, _) = watch::channel(false);
        let (reset_tx, reset_rx) = broadcast::channel(4);
        let lifecycle = RuntimeLifecycle::new();
        let handle = ChatListSelectionHandle {
            commands,
            closing: Arc::new(closing),
            lifecycle: lifecycle.clone(),
            resets: Arc::new(Mutex::new(reset_rx)),
            account_label: "alice".into(),
        };
        let call = handle.page(0, 0, 200);
        tokio::pin!(call);
        let command = tokio::select! {
            command = received.recv() => command.unwrap(),
            result = &mut call => panic!("returned before response: {result:?}"),
        };
        command
            .reply
            .send(Ok(ChatSelectionPage {
                summary: ChatSelectionSummary {
                    revision: 0,
                    count: 1,
                },
                group_ids: vec!["0000".into()],
            }))
            .unwrap();
        if shutdown {
            lifecycle.begin_shutdown();
        } else {
            reset_tx.send("alice".into()).unwrap();
        }
        assert!(matches!(call.await, Err(ChatSelectionError::Closed)));
        assert!(matches!(
            handle.clone().count().await,
            Err(ChatSelectionError::Closed)
        ));
    }
}

#[tokio::test]
async fn delivery_observer_ignores_other_accounts_but_fails_closed_on_lag() {
    let f = Fixture::new(1);
    let handle = f
        .runtime
        .capture_chat_list_selection("alice", ChatListView::Chats)
        .await
        .unwrap();
    f.app
        .presentation_signals
        .account_resets
        .send("bob".into())
        .unwrap();
    assert_eq!(handle.count().await.unwrap().count, 1);
    // Even if the actor consumes these, the delivery cursor must independently
    // retain evidence; a lost reset cannot authorize returning stale account IDs.
    for _ in 0..65 {
        f.app
            .presentation_signals
            .account_resets
            .send("bob".into())
            .unwrap();
    }
    assert!(matches!(
        handle.ensure_open(),
        Err(ChatSelectionError::Closed)
    ));
    assert!(matches!(
        handle.clone().count().await,
        Err(ChatSelectionError::Closed)
    ));
}
