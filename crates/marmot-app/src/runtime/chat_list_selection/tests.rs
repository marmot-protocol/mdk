use super::*;
use crate::*;
use cgka_traits::storage::StorageProvider;
use marmot_account::AccountHome;
use storage_sqlite::StoredAccountState;

struct Fixture {
    _dir: tempfile::TempDir,
    app: MarmotApp,
    runtime: MarmotAppRuntime,
    store: SqliteAccountStorage,
    account_id: String,
    relay: Arc<crate::tests::ScriptedPushRelayClient>,
}
impl Fixture {
    fn new(count: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(crate::tests::ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        app.ensure_account_state("alice").unwrap();
        let store = app.account_storage("alice").unwrap();
        let groups = (0..count)
            .map(|i| {
                let group = AppGroupRecord::new(
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
                crate::conversions::stored_group_from_app_group(&group)
            })
            .collect();
        store
            .app_storage()
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
            .app_storage()
            .refresh_chat_list_rows(&account.account_id_hex, &|_, _| false)
            .unwrap();
        let runtime = MarmotAppRuntime::new(app.clone());
        Self {
            _dir: dir,
            app,
            runtime,
            store,
            account_id: account.account_id_hex,
            relay,
        }
    }
    async fn open(&self) -> RuntimeChatListSelection {
        self.runtime
            .open_chat_list_selection("alice", ChatListView::Chats)
            .await
            .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_count_and_bounded_pages_are_not_a_display_window() {
    for count in [0, 1, 49, 50, 51, 100, 101, 201, 500] {
        let f = Fixture::new(count);
        let handle = f.open().await;
        let summary = handle.count().await.unwrap();
        assert_eq!(summary.count, count);
        let mut ids = vec![];
        for offset in (0..count).step_by(200) {
            let page = handle.page(summary.revision, offset, 200).await.unwrap();
            assert!(page.group_ids.len() <= 200);
            ids.extend(page.group_ids);
        }
        assert_eq!(
            ids,
            (0..count).map(|i| format!("{i:04x}")).collect::<Vec<_>>()
        );
        assert!(
            handle
                .page(0, count, 200)
                .await
                .unwrap()
                .group_ids
                .is_empty()
        );
        assert!(matches!(
            handle.page(0, 0, 201).await,
            Err(ChatListSelectionError::Query(
                storage_sqlite::ChatListSelectionError::InvalidPage
            ))
        ));
        handle.close();
        f.runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_arrival_and_removal_only_shrink_on_revalidation() {
    let f = Fixture::new(51);
    let handle = f.open().await;
    let before = handle.page(0, 0, 200).await.unwrap().group_ids;
    let mut state = f
        .store
        .app_storage()
        .load_account_projection_state("alice", 100)
        .unwrap();
    state.groups[0].profile_name = "Renamed".into();
    let mut arrival = state.groups[0].clone();
    arrival.group_id_hex = "abcdef".into();
    state.groups.push(arrival);
    state.groups[1].archived = true;
    f.store
        .app_storage()
        .save_account_projection_state(&state, 100, 120)
        .unwrap();
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    assert_eq!(handle.page(0, 0, 200).await.unwrap().group_ids, before);
    assert_eq!(handle.count().await.unwrap().count, 51);
    let after = handle.revalidate(0).await.unwrap();
    assert_eq!(after.count, 50);
    assert_eq!(after.revision, 1);
    assert!(matches!(
        handle.page(0, 0, 200).await,
        Err(ChatListSelectionError::StaleRevision)
    ));
    let ids = handle.page(1, 0, 200).await.unwrap().group_ids;
    assert!(!ids.contains(&"0001".into()));
    assert!(!ids.contains(&"abcdef".into()));
    f.runtime.shutdown_and_close().await.unwrap();
    assert!(handle.count().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_and_cache_replacement_never_rebind_the_selection() {
    let f = Fixture::new(1);
    let cancelled = f.open().await;
    cancelled.cancel();
    cancelled.cancel();
    assert!(matches!(
        cancelled.count().await,
        Err(ChatListSelectionError::Closed)
    ));
    let old = f.open().await;
    // Same identity and same on-disk epoch, but a replacement cached connection.
    f.app.account_storages.lock().unwrap().remove("alice");
    let replacement = f.app.account_storage("alice").unwrap();
    assert!(!replacement.shares_connection_with(&f.store));
    assert!(old.count().await.is_err());
    let new = f.open().await;
    assert_eq!(new.count().await.unwrap().count, 1);
    f.app.drop_account_caches("alice");
    assert!(new.count().await.is_err());
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_for_another_account_does_not_close_selection() {
    let f = Fixture::new(1);
    let handle = f.open().await;
    f.app.account_home().create_account("bob").unwrap();
    f.app.ensure_account_state("bob").unwrap();
    let other = f
        .runtime
        .open_chat_list_selection("bob", ChatListView::Chats)
        .await
        .unwrap();
    assert_eq!(other.count().await.unwrap().count, 0);
    f.app
        .presentation_signals
        .account_resets
        .send("bob".into())
        .unwrap();
    assert_eq!(handle.count().await.unwrap().count, 1);
    f.app
        .presentation_signals
        .account_resets
        .send("alice".into())
        .unwrap();
    assert!(handle.count().await.is_err());
    f.runtime.shutdown_and_close().await.unwrap();
}

// One thread keeps the admitted read queued until cancellation in this deliberate first-poll race.
#[tokio::test(flavor = "current_thread")]
async fn cancelled_queued_read_cannot_publish_a_late_page() {
    let f = Fixture::new(201);
    let handle = f.open().await;
    let page = handle.page(0, 0, 200);
    tokio::pin!(page);
    std::future::poll_fn(|cx| {
        assert!(page.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    handle.cancel();
    assert!(matches!(page.await, Err(ChatListSelectionError::Closed)));
    assert!(handle.count().await.is_err());
    f.runtime.shutdown_and_close().await.unwrap();
}

fn complete_capture_request(account: &str) -> crate::chat_selection::capture::CaptureRequest {
    use crate::chat_selection::{
        capture::*, presentation::HostContextIdentity, scope::ScopeRequest,
    };
    CaptureRequest {
        scope: ScopeRequest {
            selected_folder: None,
            filter_folders: None,
            named_chats: None,
            direct: false,
            groups: false,
            search: None,
        },
        base: storage_sqlite::SelectionBaseScope::View(ChatListView::Chats),
        original_ids: None,
        action_hints: false,
        excluded_cost: (0, 0),
        host: HostContextIdentity {
            account_id_hex: account.into(),
            runtime_generation: 1,
            selection_generation: 1,
            presentation_context_id: 1,
        },
        overlays: HostOverlays::default(),
        revision: 1,
        capture_now_ms: 1000,
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
// One worker is required to prove block_in_place yields the only async executor.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn complete_capture_worker_yields_one_thread_and_discards_aborted_response() {
    let f = Fixture::new(0);
    let manager = f.runtime.accounts();
    manager.catch_up_accounts().await.unwrap();
    let worker_id = manager
        .workers
        .lock()
        .await
        .get(&f.account_id)
        .unwrap()
        .handle
        .id();
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let waits = observed.clone();
    f.store
        .set_timing_observer(Some(Arc::new(move |operation, duration, success| {
            if success
                && operation == storage_sqlite::SqliteTimingOperation::ConnectionWait
                && duration >= std::time::Duration::from_millis(5)
            {
                eprintln!(
                    "selection connection-wait diagnostic: actual_worker={} async_task={} elapsed_ms={}",
                    tokio::task::try_id() == Some(worker_id),
                    tokio::task::try_id().is_some(),
                    duration.as_millis(),
                );
            }
            if success
                && operation == storage_sqlite::SqliteTimingOperation::ConnectionWait
                && tokio::task::try_id() == Some(worker_id)
                && duration >= std::time::Duration::from_millis(5)
            {
                waits.lock().unwrap().push(std::thread::current().id());
            }
        })));
    let ready = manager
        .capture_selection_context("alice", complete_capture_request(&f.account_id))
        .await
        .unwrap();
    assert!(ready.complete().unwrap().is_empty());
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let store = f.store.clone();
    let holder = std::thread::spawn(move || {
        store
            .with_read_snapshot(|_| {
                locked_tx.send(()).unwrap();
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(3))
                    .unwrap();
                Ok::<_, cgka_traits::StorageError>(())
            })
            .unwrap();
    });
    locked_rx.recv().unwrap();
    let progressed = Arc::new(AtomicBool::new(false));
    let mark = progressed.clone();
    let other = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        mark.store(true, Ordering::Release);
        release_tx.send(()).unwrap();
        std::thread::current().id()
    });
    let captured = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        manager.capture_selection_context("alice", complete_capture_request(&f.account_id)),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(progressed.load(Ordering::Acquire));
    assert!(captured.complete().unwrap().is_empty());
    let unrelated_thread = other.await.unwrap();
    holder.join().unwrap();
    assert!(
        !observed.lock().unwrap().is_empty(),
        "actual worker must have waited on this cached connection"
    );
    assert!(
        observed
            .lock()
            .unwrap()
            .iter()
            .all(|worker_thread| *worker_thread != unrelated_thread)
    );
    // Gate an actual worker cached-owner preflight through the existing public
    // observer. This proves in-progress receiver abandonment, not SQL interruption.
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let entered = std::sync::Mutex::new(Some(entered_tx));
    let release = std::sync::Mutex::new(release_rx);
    f.store
        .set_timing_observer(Some(Arc::new(move |operation, _, success| {
            if success
                && operation == storage_sqlite::SqliteTimingOperation::ConnectionWait
                && tokio::task::try_id() == Some(worker_id)
                && let Some(entered) = entered.lock().unwrap().take()
            {
                let _ = entered.send(());
                // Never reenter storage. Timeout guarantees eventual release if
                // the async assertion fails or the request is cancelled early.
                let _ = release
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(3));
            }
        })));
    let mut pending = Box::pin(
        manager.capture_selection_context("alice", complete_capture_request(&f.account_id)),
    );
    let entered_result = tokio::select! {
        result = &mut pending => Err(format!("capture completed before actual preflight gate: {result:?}")),
        entered = tokio::time::timeout(std::time::Duration::from_secs(3), entered_rx) => {
            entered.map_err(|_| "preflight gate timed out".to_owned())
                .and_then(|entry| entry.map_err(|_| "preflight gate closed".to_owned()))
        },
    };
    // Release on every ordinary assertion path, including an entry timeout.
    drop(pending);
    let _ = release_tx.send(());
    f.store.set_timing_observer(None);
    entered_result.unwrap();
    let after = manager
        .capture_selection_context("alice", complete_capture_request(&f.account_id))
        .await
        .unwrap();
    assert!(after.complete().unwrap().is_empty());
    f.store.set_timing_observer(None);
    f.runtime.shutdown_and_close().await.unwrap();
}
// This operation must explicitly refuse real current-thread worker dispatch.
#[tokio::test(flavor = "current_thread")]
async fn complete_capture_worker_current_thread_refuses_before_scan() {
    let f = Fixture::new(0);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    let result = f
        .runtime
        .accounts()
        .capture_selection_context("alice", complete_capture_request(&f.account_id))
        .await;
    assert!(
        matches!(
            result,
            Err(crate::chat_selection::capture::CaptureError::UnsupportedRuntime)
        ),
        "{result:?}"
    );
    f.runtime.shutdown_and_close().await.unwrap();
}

fn complete_handle_open(account: &str) -> ChatSelectionOpen {
    let request = complete_capture_request(account);
    ChatSelectionOpen {
        scope: request.scope,
        base: storage_sqlite::SelectionBaseScope::ActiveAndArchived,
        context: ChatSelectionContext {
            host: request.host,
            overlays: request.overlays,
            capture_now_ms: request.capture_now_ms,
        },
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_handle_archive_uses_frozen_ids_and_retains_operation_result_across_refresh() {
    let f = Fixture::new(0);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    f.runtime
        .create_group("alice", "Alpha", &[], None)
        .await
        .unwrap();
    f.runtime
        .create_group("alice", "Beta", &[], None)
        .await
        .unwrap();
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(&f).await;
    let open = complete_handle_open(&f.account_id);
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    assert_eq!(handle.count().await.unwrap().count, 2);
    // This real worker-created arrival must not be archived by the frozen set.
    f.runtime
        .create_group("alice", "Gamma", &[], None)
        .await
        .unwrap();
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(&f).await;
    let mut events = f.runtime.events.subscribe();
    let mutation = ChatSelectionMutation::Archive { archived: true };
    let report = handle
        .apply(100, 1, 0, context.clone(), mutation)
        .await
        .unwrap();
    assert_eq!(report.operation_id, 100);
    assert_eq!(report.attempt_id, 1);
    assert_eq!(report.applied_group_ids.len(), 2);
    assert_eq!(report.remaining, 0);
    assert!(!report.uncertain);
    let mut archive_events = 0;
    while let Ok(event) = events.try_recv() {
        if matches!(
            event,
            MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate {
                update: AppProjectionUpdate {
                    chat_list_trigger: ChatListUpdateTrigger::ArchiveChanged,
                    ..
                },
                ..
            })
        ) {
            archive_events += 1;
        }
    }
    assert_eq!(archive_events, 2);
    // Old revision plus the same completed attempt returns evidence, not a retry.
    assert_eq!(
        handle
            .apply(100, 1, 0, context.clone(), mutation)
            .await
            .unwrap(),
        report
    );
    assert!(events.try_recv().is_err());
    let mut changed = context.clone();
    changed.host.presentation_context_id += 1;
    let status = handle
        .refresh_scope(report.revision, changed.clone())
        .await
        .unwrap();
    assert_eq!(status.count, Some(0));
    assert_eq!(status.operation_id, Some(100));
    assert_eq!(
        handle
            .apply(100, 1, 0, changed.clone(), mutation)
            .await
            .unwrap(),
        report
    );
    assert!(
        handle
            .apply(101, 2, status.revision, changed.clone(), mutation)
            .await
            .is_err()
    );
    assert!(
        handle
            .apply(
                100,
                2,
                status.revision,
                changed,
                ChatSelectionMutation::DeleteLocal
            )
            .await
            .is_err()
    );
    let archived = f
        .runtime
        .open_chat_list_selection("alice", ChatListView::Archived)
        .await
        .unwrap();
    let chats = f
        .runtime
        .open_chat_list_selection("alice", ChatListView::Chats)
        .await
        .unwrap();
    assert_eq!(archived.count().await.unwrap().count, 2);
    assert_eq!(chats.count().await.unwrap().count, 1);
    f.runtime.shutdown_and_close().await.unwrap();
}

fn store_complete_handle_title(store: &SqliteAccountStorage, id: &str, title: &str) {
    let input = store
        .app_storage()
        .chat_presentation_input(id)
        .unwrap()
        .unwrap();
    // Preserve the selected cache's actual source-owned profile epoch/version,
    // avatar and provenance. Maintenance has already established their CAS.
    let mut value = match store.app_storage().chat_presentation(id).unwrap() {
        storage_sqlite::ChatPresentationRead::Ready(value) => *value,
        _ => panic!("source-selected fixture presentation must be ready"),
    };
    value.presentation.title = PresentationText::Literal(title.into());
    assert!(!matches!(
        store
            .app_storage()
            .store_chat_presentation(&input, &value)
            .unwrap(),
        storage_sqlite::ChatPresentationWrite::Stale
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_handle_changed_title_reissues_answers_under_same_operation_before_any_write() {
    let f = Fixture::new(0);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    let group = f
        .runtime
        .create_group("alice", "Alpha", &[], None)
        .await
        .unwrap();
    let id = hex::encode(group.as_slice());
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(&f).await;
    store_complete_handle_title(&f.store, &id, "original selected title");
    let mut open = complete_handle_open(&f.account_id);
    open.scope.selected_folder = Some(ChatSelectionFolder {
        manual: Default::default(),
        excluded: Default::default(),
        automatic: ChatSelectionAutomaticRule::Smart(ChatSelectionPredicate::Condition {
            field: ChatSelectionField::Title,
            mode: ChatSelectionMode::Contains,
            values: vec!["original".into()],
            not: false,
        }),
    });
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    assert_eq!(handle.status().await.unwrap().count, None);
    let page = handle.presentation_page(0, 0, 200).await.unwrap();
    assert_eq!(page.len(), 1);
    let answers = page
        .iter()
        .flat_map(|operand| {
            operand.leaves.iter().map(|leaf| ChatSelectionAnswer {
                candidate_slot: operand.candidate_slot,
                leaf_slot: leaf.slot,
                matches: true,
            })
        })
        .collect();
    handle
        .submit_presentation(0, context.host.clone(), answers)
        .await
        .unwrap();
    assert_eq!(handle.resolve_presentation(0).await.unwrap().count, 1);
    // A real selected-cache input changes after the host's answer.
    store_complete_handle_title(&f.store, &id, "replacement selected title");
    assert!(matches!(
        handle
            .apply(
                500,
                1,
                0,
                context.clone(),
                ChatSelectionMutation::Archive { archived: true }
            )
            .await,
        Err(ChatListSelectionError::IncompletePresentation)
    ));
    let status = handle.status().await.unwrap();
    assert_eq!(status.operation_id, Some(500));
    assert_eq!(status.last_attempt, Some(1));
    assert!(!status.mutation_uncertain);
    let archived = f
        .runtime
        .open_chat_list_selection("alice", ChatListView::Archived)
        .await
        .unwrap();
    assert_eq!(archived.count().await.unwrap().count, 0);
    let page = handle
        .presentation_page(status.revision, 0, 200)
        .await
        .unwrap();
    assert!(
        matches!(&page[0].selected_title,Some(PresentationText::Literal(text)) if text=="replacement selected title")
    );
    let answers = page
        .iter()
        .flat_map(|operand| {
            operand.leaves.iter().map(|leaf| ChatSelectionAnswer {
                candidate_slot: operand.candidate_slot,
                leaf_slot: leaf.slot,
                matches: false,
            })
        })
        .collect();
    handle
        .submit_presentation(status.revision, context.host.clone(), answers)
        .await
        .unwrap();
    assert_eq!(
        handle
            .resolve_presentation(status.revision)
            .await
            .unwrap()
            .count,
        0
    );
    // Same operation/attempt resumes a proven no-effect presentation reissue.
    let report = handle
        .apply(
            500,
            1,
            status.revision,
            context,
            ChatSelectionMutation::Archive { archived: true },
        )
        .await
        .unwrap();
    assert_eq!(report.operation_id, 500);
    assert_eq!(report.attempt_id, 1);
    assert!(report.applied_group_ids.is_empty());
    assert!(!report.uncertain);
    assert_eq!(
        f.runtime
            .open_chat_list_selection("alice", ChatListView::Archived)
            .await
            .unwrap()
            .count()
            .await
            .unwrap()
            .count,
        0
    );
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_handle_one_operation_continues_bounded_batches_without_replaying_attempts() {
    // Existing app-local projected conversations do not require MLS hydration to
    // archive. The default scope deliberately avoids roster/title acquisition.
    let f = Fixture::new(205);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    let open = complete_handle_open(&f.account_id);
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    assert_eq!(handle.count().await.unwrap().count, 205);
    let mutation = ChatSelectionMutation::Archive { archived: true };
    let first = handle
        .apply(900, 1, 0, context.clone(), mutation)
        .await
        .unwrap();
    assert_eq!(first.applied_group_ids.len(), 200);
    assert_eq!(first.remaining, 5);
    assert!(!first.uncertain);
    assert_eq!(
        handle
            .apply(900, 1, 0, context.clone(), mutation)
            .await
            .unwrap(),
        first
    );
    let second = handle
        .apply(900, 2, first.revision, context, mutation)
        .await
        .unwrap();
    assert_eq!(second.operation_id, first.operation_id);
    assert_eq!(second.applied_group_ids.len(), 5);
    assert_eq!(second.remaining, 0);
    assert!(!second.uncertain);
    assert!(
        first
            .applied_group_ids
            .iter()
            .all(|id| !second.applied_group_ids.contains(id))
    );
    let archived = f
        .runtime
        .open_chat_list_selection("alice", ChatListView::Archived)
        .await
        .unwrap();
    assert_eq!(archived.count().await.unwrap().count, 205);
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_handle_deselection_is_bounded_shrink_only_and_rejects_stale_membership() {
    let f = Fixture::new(205);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    let open = complete_handle_open(&f.account_id);
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    let page = handle.page(0, 0, 200).await.unwrap();
    let removed = page.group_ids[0].clone();
    let kept = page.group_ids[1].clone();
    assert_eq!(
        handle
            .membership(
                0,
                vec![
                    removed.clone(),
                    "not-a-candidate".into(),
                    kept.clone(),
                    kept.clone()
                ]
            )
            .await
            .unwrap(),
        vec![true, false, true, true]
    );
    assert!(matches!(
        handle.membership(0, vec![kept.clone(); 201]).await,
        Err(ChatListSelectionError::Presentation(_))
    ));
    let status = handle
        .exclude(
            0,
            vec![removed.clone(), removed.clone(), "not-a-candidate".into()],
        )
        .await
        .unwrap();
    assert_eq!(status.count, Some(204));
    assert_eq!(status.revision, 1);
    assert!(matches!(
        handle.membership(0, vec![kept.clone()]).await,
        Err(ChatListSelectionError::StaleRevision)
    ));
    assert_eq!(
        handle
            .membership(1, vec![removed.clone(), kept.clone()])
            .await
            .unwrap(),
        vec![false, true]
    );
    // A nonexistent ID cannot widen the scope or invalidate a stable revision.
    assert_eq!(
        handle
            .exclude(1, vec!["not-a-candidate".into()])
            .await
            .unwrap()
            .revision,
        1
    );
    let refreshed = handle.refresh_scope(1, context.clone()).await.unwrap();
    assert_eq!(refreshed.count, Some(204));
    assert_eq!(
        handle
            .membership(refreshed.revision, vec![removed.clone()])
            .await
            .unwrap(),
        vec![false]
    );
    let first = handle
        .apply(
            901,
            1,
            refreshed.revision,
            context.clone(),
            ChatSelectionMutation::Archive { archived: true },
        )
        .await
        .unwrap();
    let second = handle
        .apply(
            901,
            2,
            first.revision,
            context,
            ChatSelectionMutation::Archive { archived: true },
        )
        .await
        .unwrap();
    assert_eq!(
        first.applied_group_ids.len() + second.applied_group_ids.len(),
        204
    );
    assert!(!first.applied_group_ids.contains(&removed));
    assert!(!second.applied_group_ids.contains(&removed));
    assert_eq!(second.remaining, 0);
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_handle_actual_worker_witness_cannot_rebind_after_capture_before_admission() {
    let f = Fixture::new(0);
    let manager = f.runtime.accounts();
    manager.catch_up_accounts().await.unwrap();
    let bound = manager
        .capture_selection_context("alice", complete_capture_request(&f.account_id))
        .await
        .unwrap();
    f.app.account_storages.lock().unwrap().remove("alice");
    let replacement = f.app.account_storage("alice").unwrap();
    assert!(!replacement.shares_connection_with(&bound.owner));
    let app = f.app.clone();
    let account = f.account_id.clone();
    let result = blocking_app_task(move || {
        complete::admit_owner_witness(
            app,
            "alice".into(),
            account,
            bound.owner,
            &bound.owner_epoch,
            &AtomicBool::new(false),
        )
    })
    .await;
    assert!(matches!(result, Err(AppError::RuntimeStopping)));
    f.runtime.shutdown_and_close().await.unwrap();
}

/// Actual create responds before its Welcome fanout releases the live client.
/// A raw row rebuild also does not acknowledge pending presentation work. Use
/// the same FIFO drain and bounded CAS maintenance as production, then prove
/// readiness through the actual selection query rather than assuming false.
async fn settle_complete_created_fixture(f: &Fixture) {
    f.runtime.accounts().drain_in_flight_work().await.unwrap();
    let app = f.app.clone();
    let store = f.store.clone();
    let local = f.account_id.clone();
    blocking_app_task(move || {
        let before = store
            .app_storage()
            .chat_list_selection_snapshot(ChatListView::Chats);
        let pending = matches!(
            before,
            Err(storage_sqlite::ChatListSelectionError::ProjectionNotReady)
        );
        assert!(
            before.is_ok() || pending,
            "unexpected base readiness classification"
        );
        eprintln!(
            "complete-handle fixture after FIFO drain: presentation row work pending={pending}"
        );
        let shared = app.shared_storage()?;
        let mut exhausted = true;
        for _ in 0..32 {
            if !crate::chat_presentation::maintenance::prepare_batch(&store, &shared, &local)? {
                exhausted = false;
                break;
            }
        }
        assert!(
            !exhausted,
            "synthetic fixture exceeded bounded existing preparation steps"
        );
        store
            .app_storage()
            .chat_list_selection_snapshot(ChatListView::Chats)
            .expect("actual base row readiness after source-owned maintenance");
        Ok(())
    })
    .await
    .unwrap();
    // Drain can snapshot zero workers and is not a readiness barrier. Use the
    // production reconciliation/catch-up handoff after fixture writes/preparation.
    let accounts = f.runtime.accounts();
    accounts.catch_up_accounts().await.unwrap();
    assert!(
        accounts
            .workers
            .lock()
            .await
            .get(&f.account_id)
            .is_some_and(|worker| worker.ready)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_handle_search_captures_complete_history_and_reissues_changed_body_proof() {
    let f = Fixture::new(0);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    let group = f
        .runtime
        .create_group("alice", "Alpha", &[], None)
        .await
        .unwrap();
    let group_hex = hex::encode(group.as_slice());
    f.runtime.accounts().drain_in_flight_work().await.unwrap();
    let full = format!(
        "needle {} https://example.org/private-search-sentinel",
        "x".repeat(4500)
    );
    let event = |index: u64, body: &str| storage_sqlite::StoredAppEvent {
        group_id_hex: group_hex.clone(),
        message_id_hex: format!("selection-message-{index}"),
        source_message_id_hex: None,
        source_epoch: None,
        direction: "received".into(),
        sender: f.account_id.clone(),
        plaintext: body.into(),
        kind: 9,
        tags: Vec::new(),
        recorded_at: index + 1000,
        received_at: index + 1000,
        origin_commit_id: None,
        moderation_grant: false,
    };
    f.store
        .with_transaction(|store| {
            for index in 0..1001 {
                store.app_storage().record_app_event(&event(
                    index,
                    if index == 1000 { &full } else { "needle" },
                ))?;
            }
            Ok::<_, cgka_traits::StorageError>(())
        })
        .unwrap();
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(&f).await;
    let mut open = complete_handle_open(&f.account_id);
    open.scope.search = Some(ChatSelectionSearchScope {
        raw_query: "needle".into(),
        sql_needle: Some("needle".into()),
        message_only: true,
    });
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    assert_eq!(handle.status().await.unwrap().count, None);
    let page = handle.presentation_page(0, 0, 200).await.unwrap();
    assert_eq!(page.len(), 1);
    let search = page[0].search.as_ref().unwrap();
    assert_eq!(search.messages.len(), 1001);
    assert!(
        search
            .messages
            .iter()
            .any(|message| message.plaintext == full)
    );
    assert!(!format!("{search:?}").contains("private-search-sentinel"));
    let old_preview = search.last_message.clone();
    let answers = page
        .iter()
        .flat_map(|operand| {
            operand.leaves.iter().map(|leaf| {
                assert_eq!(leaf.kind, ChatSelectionLeafKind::ChatSearch);
                ChatSelectionAnswer {
                    candidate_slot: operand.candidate_slot,
                    leaf_slot: leaf.slot,
                    matches: true,
                }
            })
        })
        .collect();
    handle
        .submit_presentation(0, context.host.clone(), answers)
        .await
        .unwrap();
    assert_eq!(handle.resolve_presentation(0).await.unwrap().count, 1);
    // Same rendered preview inputs, one extra qualifying older-history input.
    // The old body boolean alone cannot authorize the mutation.
    f.store
        .app_storage()
        .record_app_event(&event(1001, &full))
        .unwrap();
    settle_complete_created_fixture(&f).await;
    assert!(matches!(
        handle
            .apply(
                902,
                1,
                0,
                context.clone(),
                ChatSelectionMutation::Archive { archived: true }
            )
            .await,
        Err(ChatListSelectionError::IncompletePresentation)
    ));
    let status = handle.status().await.unwrap();
    assert_eq!(status.operation_id, Some(902));
    assert!(!status.mutation_uncertain);
    let fresh = handle
        .presentation_page(status.revision, 0, 200)
        .await
        .unwrap();
    assert_eq!(fresh[0].search.as_ref().unwrap().last_message, old_preview);
    assert_eq!(fresh[0].search.as_ref().unwrap().messages.len(), 1002);
    let archived = f
        .runtime
        .open_chat_list_selection("alice", ChatListView::Archived)
        .await
        .unwrap();
    assert_eq!(archived.count().await.unwrap().count, 0);
    let answers = fresh
        .iter()
        .flat_map(|operand| {
            operand.leaves.iter().map(|leaf| ChatSelectionAnswer {
                candidate_slot: operand.candidate_slot,
                leaf_slot: leaf.slot,
                matches: false,
            })
        })
        .collect();
    handle
        .submit_presentation(status.revision, context.host.clone(), answers)
        .await
        .unwrap();
    assert_eq!(
        handle
            .resolve_presentation(status.revision)
            .await
            .unwrap()
            .count,
        0
    );
    let report = handle
        .apply(
            902,
            1,
            status.revision,
            context,
            ChatSelectionMutation::Archive { archived: true },
        )
        .await
        .unwrap();
    assert!(report.applied_group_ids.is_empty());
    assert!(!report.uncertain);
    assert_eq!(
        f.runtime
            .open_chat_list_selection("alice", ChatListView::Archived)
            .await
            .unwrap()
            .count()
            .await
            .unwrap()
            .count,
        0
    );
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_handle_departure_local_cleanup_retains_attempt_and_never_admits_unselected_target()
 {
    let f = Fixture::new(2);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    let open = complete_handle_open(&f.account_id);
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    let ids = handle.page(0, 0, 200).await.unwrap().group_ids;
    assert!(
        handle
            .depart(
                1100,
                1,
                0,
                "not-selected".into(),
                context.clone(),
                ChatSelectionDepartureStep::DeleteLocal
            )
            .await
            .is_err()
    );
    let first = handle
        .depart(
            1100,
            1,
            0,
            ids[0].clone(),
            context.clone(),
            ChatSelectionDepartureStep::DeleteLocal,
        )
        .await
        .unwrap();
    assert!(!first.uncertain && !first.skipped && first.refusal.is_none());
    assert_eq!(handle.count().await.unwrap().count, 1);
    let readback = handle
        .depart(
            1100,
            1,
            0,
            ids[0].clone(),
            context.clone(),
            ChatSelectionDepartureStep::DeleteLocal,
        )
        .await
        .unwrap();
    assert_eq!(readback.revision, first.revision);
    assert_eq!(readback.changed, first.changed);
    assert!(
        handle
            .depart(
                1100,
                2,
                first.revision,
                ids[0].clone(),
                context.clone(),
                ChatSelectionDepartureStep::DeleteLocal
            )
            .await
            .is_err()
    );
    let second = handle
        .depart(
            1100,
            2,
            first.revision,
            ids[1].clone(),
            context,
            ChatSelectionDepartureStep::DeleteLocal,
        )
        .await
        .unwrap();
    assert!(!second.uncertain && second.refusal.is_none());
    assert_eq!(handle.count().await.unwrap().count, 0);
    assert_eq!(
        handle.last_departure().await.unwrap().unwrap().attempt_id,
        2
    );
    assert!(!format!("{first:?} {second:?}").contains(&ids[0]));
    f.runtime.shutdown_and_close().await.unwrap();
}

async fn complete_invited_nonadmin(f: &Fixture) -> (GroupId, crate::tests::ScriptedEosePump) {
    // The creator is an administrator and cannot SelfRemove. Exercise the
    // actual invited non-admin account, preserving the engine's real gate.
    let bob = f.app.account_home().create_account("bob").unwrap();
    crate::tests::remember_test_member_inbox(&f.app, &f.account_id, "wss://relay.example");
    let plane = f.runtime.shared.relay_plane.clone();
    let eose = crate::tests::scripted_eose_pump(
        plane.clone(),
        f.relay.clone(),
        crate::tests::every_subscription,
    );
    let mut alice_client = f
        .app
        .client_with_relay_plane("alice", &plane, None)
        .await
        .unwrap();
    let mut bob_client = f
        .app
        .client_with_relay_plane("bob", &plane, None)
        .await
        .unwrap();
    alice_client.sync().await.unwrap();
    let group = bob_client
        .create_group("Alpha", &[f.account_id.as_str()])
        .await
        .unwrap();
    assert!(
        alice_client
            .sync()
            .await
            .unwrap()
            .joined_groups
            .contains(&group)
    );
    drop(alice_client);
    drop(bob_client);
    assert_ne!(bob.account_id_hex, f.account_id);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(f).await;
    (group, eose)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_handle_departure_continues_admitted_leave_without_reusing_folder_answers() {
    let f = Fixture::new(0);
    let (group, _eose) = complete_invited_nonadmin(&f).await;
    let id = hex::encode(group.as_slice());
    store_complete_handle_title(&f.store, &id, "original selected title");
    let mut open = complete_handle_open(&f.account_id);
    open.scope.selected_folder = Some(ChatSelectionFolder {
        manual: Default::default(),
        excluded: Default::default(),
        automatic: ChatSelectionAutomaticRule::Smart(ChatSelectionPredicate::Condition {
            field: ChatSelectionField::Title,
            mode: ChatSelectionMode::Contains,
            values: vec!["original".into()],
            not: false,
        }),
    });
    let mut context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    let operands = handle.presentation_page(0, 0, 200).await.unwrap();
    let answers = operands
        .iter()
        .flat_map(|operand| {
            operand.leaves.iter().map(|leaf| ChatSelectionAnswer {
                candidate_slot: operand.candidate_slot,
                leaf_slot: leaf.slot,
                matches: true,
            })
        })
        .collect();
    handle
        .submit_presentation(0, context.host.clone(), answers)
        .await
        .unwrap();
    handle.resolve_presentation(0).await.unwrap();
    let left = handle
        .depart(
            1200,
            1,
            0,
            id.clone(),
            context.clone(),
            ChatSelectionDepartureStep::Leave,
        )
        .await
        .unwrap();
    assert!(
        !left.uncertain && left.refusal.is_none() && left.summary.is_some(),
        "{left:?}"
    );
    // The intent's own committed leave updates native presentation. A changed
    // host identity also makes the previous folder proof unusable. Continuing
    // cleanup must require neither that old answer nor a second folder grant.
    context.host.presentation_context_id += 1;
    assert!(matches!(
        handle.refresh_scope(left.revision, context.clone()).await,
        Err(ChatListSelectionError::IncompletePresentation)
    ));
    assert!(matches!(
        handle
            .prepare_action_hints(left.revision, context.clone())
            .await,
        Err(ChatListSelectionError::IncompletePresentation)
    ));
    assert!(matches!(
        handle
            .reselect(left.revision, context.clone(), vec![id.clone()])
            .await,
        Err(ChatListSelectionError::IncompletePresentation)
    ));
    assert_eq!(handle.status().await.unwrap().count, Some(1));
    let removed = handle
        .depart(
            1200,
            2,
            left.revision,
            id.clone(),
            context.clone(),
            ChatSelectionDepartureStep::DeleteLocal,
        )
        .await
        .unwrap();
    assert!(
        !removed.uncertain && removed.refusal.is_none() && !removed.skipped,
        "{removed:?}"
    );
    assert_eq!(handle.count().await.unwrap().count, 0);
    let replay = handle
        .depart(
            1200,
            2,
            0,
            id,
            context,
            ChatSelectionDepartureStep::DeleteLocal,
        )
        .await
        .unwrap();
    assert_eq!(replay.revision, removed.revision);
    assert_eq!(replay.changed, removed.changed);
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_handle_departure_generic_engine_refusal_is_retained_and_never_replayed_as_cleanup()
 {
    let f = Fixture::new(0);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    let group = f
        .runtime
        .create_group("alice", "Admin group", &[], None)
        .await
        .unwrap();
    let id = hex::encode(group.as_slice());
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(&f).await;
    let open = complete_handle_open(&f.account_id);
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    handle
        .check_runtime_account(&f.runtime.clone(), "alice")
        .unwrap();
    let foreign = MarmotAppRuntime::new(f.app.clone());
    assert!(handle.check_runtime_account(&foreign, "alice").is_err());
    assert!(
        handle
            .check_runtime_account(&f.runtime, "missing-account")
            .is_err()
    );
    let refused = handle
        .depart(
            1300,
            1,
            0,
            id.clone(),
            context.clone(),
            ChatSelectionDepartureStep::Leave,
        )
        .await
        .unwrap();
    assert!(matches!(
        refused
            .refusal
            .as_ref()
            .and_then(|error| error.as_engine_error()),
        Some(cgka_traits::error::EngineError::AdminCannotSelfRemove { .. })
    ));
    // Generic engine errors are conservatively unresolved; only the explicit
    // two advisory next-change errors authorize an acknowledged higher attempt.
    assert!(refused.uncertain && !refused.changed && !refused.skipped);
    let readback = handle
        .depart(
            1300,
            1,
            0,
            id.clone(),
            context.clone(),
            ChatSelectionDepartureStep::Leave,
        )
        .await
        .unwrap();
    assert_eq!(readback.revision, refused.revision);
    assert!(readback.uncertain);
    assert!(
        handle
            .depart(
                1300,
                2,
                refused.revision,
                id,
                context,
                ChatSelectionDepartureStep::DeleteLocal
            )
            .await
            .is_err()
    );
    assert_eq!(handle.status().await.unwrap().count, Some(1));
    f.runtime.shutdown_and_close().await.unwrap();
}

struct ReleaseSelectionPublish(Arc<crate::tests::ScriptedPushRelayClient>);
impl Drop for ReleaseSelectionPublish {
    fn drop(&mut self) {
        self.0.release_publish();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_departure_abandoned_persisted_leave_wait_retains_exact_result() {
    use cgka_traits::storage::LeaveRequestStorage;
    let f = Fixture::new(0);
    let (group, _eose) = complete_invited_nonadmin(&f).await;
    let id = hex::encode(group.as_slice());
    let open = complete_handle_open(&f.account_id);
    let context = open.context.clone();
    let handle = Arc::new(
        f.runtime
            .open_complete_chat_list_selection("alice", open)
            .await
            .unwrap(),
    );
    f.relay.block_next_publish();
    let release = ReleaseSelectionPublish(f.relay.clone());
    let waiting = {
        let handle = handle.clone();
        let context = context.clone();
        let id = id.clone();
        tokio::spawn(async move {
            handle
                .depart(1400, 1, 0, id, context, ChatSelectionDepartureStep::Leave)
                .await
        })
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        f.relay.wait_for_blocked_publish(),
    )
    .await
    .unwrap();
    // This exact group's durable intent and unfinished waiter distinguish a
    // Leave result lost by its UI from an unrelated publication latch.
    assert!(f.store.leave_request(&group).unwrap().is_some());
    assert!(!waiting.is_finished());
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    drop(release);
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), handle.last_departure())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!((result.operation_id, result.attempt_id), (1400, 1));
    assert!(
        result.summary.is_some() && result.refusal.is_none() && !result.uncertain,
        "{result:?}"
    );
    let replay = handle
        .depart(
            1400,
            1,
            0,
            id.clone(),
            context.clone(),
            ChatSelectionDepartureStep::Leave,
        )
        .await
        .unwrap();
    assert_eq!(replay.revision, result.revision);
    assert!(replay.summary.is_some());
    assert!(
        handle
            .depart(
                1400,
                2,
                result.revision,
                id,
                context,
                ChatSelectionDepartureStep::Leave
            )
            .await
            .is_err()
    );
    handle.close();
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_departure_continuation_rejects_replaced_cached_owner_before_cleanup() {
    let f = Fixture::new(0);
    let (group, _eose) = complete_invited_nonadmin(&f).await;
    let id = hex::encode(group.as_slice());
    let open = complete_handle_open(&f.account_id);
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    let left = handle
        .depart(
            1500,
            1,
            0,
            id.clone(),
            context.clone(),
            ChatSelectionDepartureStep::Leave,
        )
        .await
        .unwrap();
    assert!(
        left.summary.is_some() && left.refusal.is_none() && !left.uncertain,
        "{left:?}"
    );
    assert!(f.store.app_storage().chat_list_row(&id).unwrap().is_some());
    f.app.account_storages.lock().unwrap().remove("alice");
    let replacement = f.app.account_storage("alice").unwrap();
    assert!(!replacement.shares_connection_with(&f.store));
    let cleanup = handle
        .depart(
            1500,
            2,
            left.revision,
            id.clone(),
            context,
            ChatSelectionDepartureStep::DeleteLocal,
        )
        .await;
    assert!(cleanup.is_err() || cleanup.is_ok_and(|r| r.refusal.is_some() && !r.changed));
    assert!(f.store.app_storage().chat_list_row(&id).unwrap().is_some());
    handle.close();
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_folder_assignment_progresses_past_freshly_ineligible_originals_without_new_arrivals()
 {
    let f = Fixture::new(205);
    settle_complete_created_fixture(&f).await;
    let mut open = complete_handle_open(&f.account_id);
    open.base = storage_sqlite::SelectionBaseScope::View(ChatListView::Chats);
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    let mut state = f
        .store
        .app_storage()
        .load_account_projection_state("alice", 100)
        .unwrap();
    for group in state.groups.iter_mut().take(200) {
        group.archived = true;
    }
    let mut arrival = state.groups[204].clone();
    arrival.group_id_hex = "ffffff".into();
    state.groups.push(arrival);
    f.store
        .app_storage()
        .save_account_projection_state(&state, 100, 120)
        .unwrap();
    assert!(matches!(
        f.store
            .app_storage()
            .chat_list_selection_snapshot(ChatListView::Chats),
        Err(storage_sqlite::ChatListSelectionError::ProjectionNotReady)
    ));
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(&f).await;
    let first = handle
        .folder_assignment_page(0, context.clone(), None, 200)
        .await
        .unwrap();
    assert!(first.group_ids.is_empty());
    assert!(!first.done);
    assert!(first.next_after.is_some());
    let second = handle
        .folder_assignment_page(0, context, first.next_after, 200)
        .await
        .unwrap();
    assert_eq!(second.group_ids.len(), 5);
    assert!(second.done);
    assert!(!second.group_ids.iter().any(|id| id == "ffffff"));
    assert_eq!(handle.count().await.unwrap().count, 205); // handoff never consumes a preference mutation
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_selection_affordances_cover_unloaded_mixed_archive_set_and_explicit_exclusion() {
    let f = Fixture::new(51);
    let mut state = f
        .store
        .app_storage()
        .load_account_projection_state("alice", 100)
        .unwrap();
    for g in state.groups.iter_mut().take(50) {
        g.archived = true;
    }
    f.store
        .app_storage()
        .save_account_projection_state(&state, 100, 120)
        .unwrap();
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    f.store
        .app_storage()
        .chat_list_selection_snapshot(ChatListView::Chats)
        .expect("archive-only source update does not enqueue new-row preparation");
    settle_complete_created_fixture(&f).await;
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", complete_handle_open(&f.account_id))
        .await
        .unwrap();
    let status = handle.status().await.unwrap();
    assert_eq!(status.count, Some(51));
    assert_eq!(status.all_archived, Some(false));
    assert_eq!(status.all_direct, Some(false));
    assert_eq!(status.all_abandonable, None);
    let excluded = handle.exclude(0, vec!["0032".into()]).await.unwrap();
    assert_eq!(excluded.count, Some(50));
    assert_eq!(excluded.all_archived, Some(true));
    let hints = handle
        .prepare_action_hints(
            excluded.revision,
            complete_handle_open(&f.account_id).context,
        )
        .await
        .unwrap();
    assert_eq!(hints.count, Some(50));
    assert_eq!(hints.all_archived, Some(true));
    assert_eq!(hints.all_direct, Some(false));
    assert_eq!(hints.all_abandonable, Some(true));
    handle.close();
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_folder_handoff_discards_old_revision_on_host_or_actual_overlay_change_without_operands()
 {
    let f = Fixture::new(2);
    settle_complete_created_fixture(&f).await;
    let open = complete_handle_open(&f.account_id);
    let mut context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    let old = handle
        .folder_assignment_page(0, context.clone(), None, 1)
        .await
        .unwrap();
    assert_eq!(old.group_ids.len(), 1);
    assert!(!old.done);
    context.host.presentation_context_id += 1;
    assert!(matches!(
        handle
            .folder_assignment_page(0, context.clone(), old.next_after, 1)
            .await,
        Err(ChatListSelectionError::IncompletePresentation)
    ));
    let status = handle.status().await.unwrap();
    assert_eq!(status.revision, 1);
    assert_eq!(status.count, Some(2));
    assert!(matches!(
        handle
            .folder_assignment_page(0, context.clone(), None, 200)
            .await,
        Err(ChatListSelectionError::StaleRevision)
    ));
    let fresh = handle
        .folder_assignment_page(1, context.clone(), None, 200)
        .await
        .unwrap();
    assert_eq!(fresh.group_ids.len(), 2);
    assert!(fresh.done);
    context
        .overlays
        .muted
        .insert(fresh.group_ids[0].clone(), true);
    assert!(matches!(
        handle
            .folder_assignment_page(1, context.clone(), None, 200)
            .await,
        Err(ChatListSelectionError::IncompletePresentation)
    ));
    assert_eq!(handle.status().await.unwrap().revision, 2);
    let current = handle
        .folder_assignment_page(2, context, None, 200)
        .await
        .unwrap();
    assert_eq!(current.group_ids.len(), 2);
    assert!(current.done);
    handle.close();
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_unknown_default_count_does_not_require_roster_and_failed_hint_preparation_preserves_it()
 {
    use cgka_traits::storage::GroupStorage;
    let f = Fixture::new(1);
    let mut state = f
        .store
        .app_storage()
        .load_account_projection_state("alice", 100)
        .unwrap();
    state.groups[0].profile_name = String::new();
    state.groups[0].member_count = None;
    f.store
        .app_storage()
        .save_account_projection_state(&state, 100, 120)
        .unwrap();
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(&f).await;
    assert!(matches!(
        f.store.get_group(&cgka_traits::GroupId::new(vec![0, 0])),
        Err(cgka_traits::storage::StorageError::NotFound)
    ));
    let open = complete_handle_open(&f.account_id);
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    let status = handle.status().await.unwrap();
    assert_eq!(status.count, Some(1));
    assert_eq!(status.presentation_operands, 0);
    assert_eq!(status.all_direct, None);
    assert_eq!(status.all_archived, Some(false));
    assert_eq!(
        handle.membership(0, vec!["0000".into()]).await.unwrap(),
        vec![true]
    );
    assert!(matches!(
        handle.prepare_action_hints(0, context).await,
        Err(ChatListSelectionError::Capture(
            ChatSelectionCaptureError::NotReady
        ))
    ));
    let retained = handle.status().await.unwrap();
    assert_eq!(retained.revision, 0);
    assert_eq!(retained.count, Some(1));
    handle.close();
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_reselect_restores_only_explicit_originals_before_operation_and_keeps_readback() {
    let f = Fixture::new(51);
    settle_complete_created_fixture(&f).await;
    let context = complete_handle_open(&f.account_id).context;
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", complete_handle_open(&f.account_id))
        .await
        .unwrap();
    let shrunk = handle
        .exclude(0, vec!["0032".into(), "0032".into()])
        .await
        .unwrap();
    assert_eq!(shrunk.count, Some(50));
    assert!(matches!(
        handle
            .reselect(
                shrunk.revision,
                context.clone(),
                vec!["0032".into(), "ffff".into()]
            )
            .await,
        Err(ChatListSelectionError::UnsupportedScope)
    ));
    assert_eq!(handle.status().await.unwrap(), shrunk); // atomic whole-request refusal
    let restored = handle
        .reselect(
            shrunk.revision,
            context.clone(),
            vec!["0032".into(), "0032".into()],
        )
        .await
        .unwrap();
    assert_eq!(restored.count, Some(51));
    assert_eq!(
        handle
            .membership(restored.revision, vec!["0032".into()])
            .await
            .unwrap(),
        vec![true]
    );
    assert_eq!(
        handle
            .reselect(restored.revision, context.clone(), vec!["0032".into()])
            .await
            .unwrap(),
        restored
    );
    assert!(matches!(
        handle
            .reselect(shrunk.revision, context.clone(), vec!["0032".into()])
            .await,
        Err(ChatListSelectionError::StaleRevision)
    ));
    let shrunk = handle
        .exclude(restored.revision, vec!["0031".into()])
        .await
        .unwrap();
    let report = handle
        .apply(
            991,
            1,
            shrunk.revision,
            context.clone(),
            ChatSelectionMutation::Archive { archived: true },
        )
        .await
        .unwrap();
    let status = handle.status().await.unwrap();
    assert_eq!(status.operation_id, Some(991));
    assert!(matches!(
        handle
            .reselect(status.revision, context.clone(), vec!["0031".into()])
            .await,
        Err(ChatListSelectionError::IncompletePresentation)
    ));
    let retained = handle
        .apply(
            991,
            1,
            shrunk.revision,
            context,
            ChatSelectionMutation::Archive { archived: true },
        )
        .await
        .unwrap();
    assert_eq!(retained, report);
    assert_eq!(
        handle
            .membership(status.revision, vec!["0031".into()])
            .await
            .unwrap(),
        vec![false]
    );
    handle.close();
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_reselect_rechecks_scope_and_preserves_state_on_capture_failure() {
    let f = Fixture::new(2);
    settle_complete_created_fixture(&f).await;
    let context = complete_handle_open(&f.account_id).context;
    let mut open = complete_handle_open(&f.account_id);
    open.base = storage_sqlite::SelectionBaseScope::View(ChatListView::Chats);
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    let shrunk = handle.exclude(0, vec!["0001".into()]).await.unwrap();
    let mut wrong = context.clone();
    wrong.host.account_id_hex = "wrong-owner".into();
    assert!(matches!(
        handle
            .reselect(shrunk.revision, wrong, vec!["0001".into()])
            .await,
        Err(ChatListSelectionError::Closed)
    ));
    assert_eq!(handle.status().await.unwrap(), shrunk);
    let mut state = f
        .store
        .app_storage()
        .load_account_projection_state("alice", 100)
        .unwrap();
    let mut arrival = state.groups[0].clone();
    arrival.group_id_hex = "ffff".into();
    state.groups.push(arrival);
    state
        .groups
        .iter_mut()
        .find(|g| g.group_id_hex == "0001")
        .unwrap()
        .archived = true;
    f.store
        .app_storage()
        .save_account_projection_state(&state, 100, 120)
        .unwrap();
    assert!(matches!(
        f.store
            .app_storage()
            .chat_list_selection_snapshot(ChatListView::Chats),
        Err(storage_sqlite::ChatListSelectionError::ProjectionNotReady)
    ));
    assert!(matches!(
        handle
            .reselect(shrunk.revision, context.clone(), vec!["0001".into()])
            .await,
        Err(ChatListSelectionError::Capture(
            crate::chat_selection::capture::CaptureError::NotReady
        ))
    ));
    assert_eq!(handle.status().await.unwrap(), shrunk);
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(&f).await;
    let refused = handle
        .reselect(shrunk.revision, context.clone(), vec!["0001".into()])
        .await
        .unwrap();
    assert!(matches!(
        handle
            .reselect(refused.revision, context.clone(), vec!["ffff".into()])
            .await,
        Err(ChatListSelectionError::UnsupportedScope)
    ));
    assert_eq!(refused.count, Some(1)); // explicit click cannot override current base scope
    assert_eq!(
        handle
            .membership(refused.revision, vec!["0001".into()])
            .await
            .unwrap(),
        vec![false]
    );
    state
        .groups
        .iter_mut()
        .find(|g| g.group_id_hex == "0001")
        .unwrap()
        .archived = false;
    f.store
        .app_storage()
        .save_account_projection_state(&state, 100, 120)
        .unwrap();
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(&f).await;
    // An ineligible requested original remains explicitly excluded until a
    // later click; fresh eligible arrivals never become restoration inputs.
    let restored = handle
        .reselect(refused.revision, context, vec!["0001".into()])
        .await
        .unwrap();
    assert_eq!(restored.count, Some(2));
    handle.close();
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_reselect_reissues_presentation_and_removes_only_restored_tombstones() {
    let f = Fixture::new(0);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    let group = f
        .runtime
        .create_group("alice", "Alpha", &[], None)
        .await
        .unwrap();
    let id = hex::encode(group.as_slice());
    settle_complete_created_fixture(&f).await;
    store_complete_handle_title(&f.store, &id, "before");
    let mut open = complete_handle_open(&f.account_id);
    open.scope.selected_folder = Some(ChatSelectionFolder {
        manual: Default::default(),
        excluded: Default::default(),
        automatic: ChatSelectionAutomaticRule::Smart(ChatSelectionPredicate::Condition {
            field: ChatSelectionField::Title,
            mode: ChatSelectionMode::Contains,
            values: vec!["before".into()],
            not: false,
        }),
    });
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    async fn answer(
        handle: &RuntimeChatListSelection,
        revision: u64,
        context: &ChatSelectionContext,
        matches: bool,
    ) -> usize {
        let answers = handle
            .presentation_page(revision, 0, 200)
            .await
            .unwrap()
            .iter()
            .flat_map(|operand| {
                operand.leaves.iter().map(|leaf| ChatSelectionAnswer {
                    candidate_slot: operand.candidate_slot,
                    leaf_slot: leaf.slot,
                    matches,
                })
            })
            .collect();
        handle
            .submit_presentation(revision, context.host.clone(), answers)
            .await
            .unwrap();
        handle.resolve_presentation(revision).await.unwrap().count
    }
    assert_eq!(answer(&handle, 0, &context, true).await, 1);
    let unchecked = handle.exclude(0, vec![id.clone()]).await.unwrap();
    store_complete_handle_title(&f.store, &id, "after");
    let pending = handle
        .reselect(unchecked.revision, context.clone(), vec![id.clone()])
        .await
        .unwrap();
    assert_eq!(pending.count, None);
    assert_eq!(answer(&handle, pending.revision, &context, false).await, 0);
    // A false answer did not consume its explicit exclusion provenance.
    store_complete_handle_title(&f.store, &id, "before again");
    let pending = handle
        .reselect(pending.revision, context.clone(), vec![id.clone()])
        .await
        .unwrap();
    assert_eq!(pending.count, None);
    assert_eq!(answer(&handle, pending.revision, &context, true).await, 1);
    assert_eq!(
        handle
            .reselect(pending.revision, context, vec![id])
            .await
            .unwrap()
            .revision,
        pending.revision
    );
    handle.close();
    f.runtime.shutdown_and_close().await.unwrap();
}

// Inject only worker outcomes, not actor state or production capture hooks. The
// first outcome is a known non-effect; failure of its follow-up must stay so.
async fn assert_failed_reissue_is_known_non_effect(departure: bool) {
    let f = Fixture::new(0);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    let group = f
        .runtime
        .create_group("alice", "Reissue test", &[], None)
        .await
        .unwrap();
    let id = hex::encode(group.as_slice());
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(&f).await;
    let manager = f.runtime.accounts();
    let open = complete_handle_open(&f.account_id);
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    let bound = manager
        .capture_selection_context("alice", complete_capture_request(&f.account_id))
        .await
        .unwrap();
    let before = handle.status().await.unwrap();
    let original_ids = handle
        .page(before.revision, 0, 200)
        .await
        .unwrap()
        .group_ids;
    let (commands, mut injected) = mpsc::channel(4);
    let original = {
        let mut workers = manager.workers.lock().await;
        let worker = workers.get_mut(&f.account_id).unwrap();
        std::mem::replace(&mut worker.commands, commands)
    };
    let forward = original.clone();
    let responder = tokio::spawn(async move {
        use super::super::AccountWorkerCommand;
        loop {
            match injected.recv().await.unwrap() {
                AccountWorkerCommand::ApplySelection { respond, .. } if !departure => {
                    assert!(
                        respond
                            .send(Ok(crate::client::SelectionApplyOutcome::NeedsPresentation(
                                bound
                            )))
                            .is_ok()
                    );
                    break;
                }
                AccountWorkerCommand::DepartSelection { respond, .. } if departure => {
                    assert!(
                        respond
                            .send(Ok(
                                crate::client::SelectionDepartureOutcome::NeedsPresentation(
                                    Box::new(bound)
                                )
                            ))
                            .is_ok()
                    );
                    break;
                }
                AccountWorkerCommand::ApplySelection { .. }
                | AccountWorkerCommand::DepartSelection { .. }
                | AccountWorkerCommand::CaptureSelection { .. } => {
                    panic!("unexpected selection command before reissue")
                }
                other => assert!(forward.send(other).await.is_ok()),
            }
        }
        loop {
            match injected.recv().await.unwrap() {
                AccountWorkerCommand::CaptureSelection { respond, .. } => {
                    assert!(
                        respond
                            .send(Err(
                                crate::chat_selection::capture::CaptureError::ResourceExhausted
                            ))
                            .is_ok()
                    );
                    break;
                }
                AccountWorkerCommand::ApplySelection { .. }
                | AccountWorkerCommand::DepartSelection { .. } => {
                    panic!("expected full reissue capture before another effect")
                }
                other => assert!(forward.send(other).await.is_ok()),
            }
        }
    });
    let failed = if departure {
        handle
            .depart(
                901,
                1,
                0,
                id.clone(),
                context.clone(),
                ChatSelectionDepartureStep::DeleteLocal,
            )
            .await
            .map(|_| ())
    } else {
        handle
            .apply(
                901,
                1,
                0,
                context.clone(),
                ChatSelectionMutation::Archive { archived: true },
            )
            .await
            .map(|_| ())
    };
    responder.await.unwrap();
    {
        let mut workers = manager.workers.lock().await;
        workers.get_mut(&f.account_id).unwrap().commands = original;
    }
    assert!(matches!(
        failed,
        Err(ChatListSelectionError::Capture(
            crate::chat_selection::capture::CaptureError::ResourceExhausted
        ))
    ));
    let status = handle.status().await.unwrap();
    assert_eq!(status.operation_id, Some(901));
    assert_eq!(status.last_attempt, Some(1));
    assert_eq!(status.count, Some(1));
    assert!(!status.mutation_uncertain);
    assert_eq!(status.revision, before.revision);
    assert_eq!(
        handle
            .page(status.revision, 0, 200)
            .await
            .unwrap()
            .group_ids,
        original_ids
    );
    assert!(
        !f.store
            .app_storage()
            .chat_list_row(&id)
            .unwrap()
            .unwrap()
            .archived
    );
    // Same operation and attempt now reach the actual worker primitive once.
    // No new intent, handle or arrival can be introduced to recover this refusal.
    if departure {
        let report = handle
            .depart(
                901,
                1,
                status.revision,
                id.clone(),
                context,
                ChatSelectionDepartureStep::DeleteLocal,
            )
            .await
            .unwrap();
        assert!(!report.uncertain);
        assert!(report.refusal.is_none());
        assert!(report.changed);
    } else {
        let report = handle
            .apply(
                901,
                1,
                status.revision,
                context,
                ChatSelectionMutation::Archive { archived: true },
            )
            .await
            .unwrap();
        assert_eq!(report.applied_group_ids, vec![id]);
        assert!(!report.uncertain);
    }
    assert_eq!(handle.status().await.unwrap().count, Some(0));
    handle.close();
    f.runtime.shutdown_and_close().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_apply_known_reissue_failure_does_not_become_uncertain() {
    assert_failed_reissue_is_known_non_effect(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_departure_known_reissue_failure_does_not_become_uncertain() {
    assert_failed_reissue_is_known_non_effect(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_archive_projection_failure_retains_known_commit_and_dirty_recovery() {
    let f = Fixture::new(0);
    f.runtime.accounts().catch_up_accounts().await.unwrap();
    let group = f
        .runtime
        .create_group("alice", "Projection fault", &[], None)
        .await
        .unwrap();
    let id = hex::encode(group.as_slice());
    f.store
        .app_storage()
        .refresh_chat_list_rows(&f.account_id, &|_, _| false)
        .unwrap();
    settle_complete_created_fixture(&f).await;
    let account = f.app.account_home().account("alice").unwrap();
    f.app.ensure_chat_list_projection(&account).unwrap();
    assert!(
        !f.app
            .chat_list_projection_stale
            .lock()
            .unwrap()
            .contains("alice")
    );
    let open = complete_handle_open(&f.account_id);
    let context = open.context.clone();
    let handle = f
        .runtime
        .open_complete_chat_list_selection("alice", open)
        .await
        .unwrap();
    // Existing SQLCipher fixture convention: a second connection installs a
    // projection-only fault. Never print or retain this synthetic fixture key.
    let path = f.app.account_storage_path("alice");
    let keys = f.app.account_home().load_signing_keys("alice").unwrap();
    let key = f
        .app
        .sqlcipher_key("alice", &keys, &path, SqlcipherDatabaseKind::Session)
        .unwrap();
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection.execute_batch("CREATE TRIGGER selection_fail_archive_insert BEFORE INSERT ON chat_list_rows
        WHEN NEW.archived = 1 BEGIN SELECT RAISE(ABORT, 'injected archive projection failure'); END;
        CREATE TRIGGER selection_fail_archive_update BEFORE UPDATE ON chat_list_rows
        WHEN NEW.archived = 1 BEGIN SELECT RAISE(ABORT, 'injected archive projection failure'); END;").unwrap();
    let report = handle
        .apply(
            903,
            1,
            0,
            context.clone(),
            ChatSelectionMutation::Archive { archived: true },
        )
        .await
        .unwrap();
    assert_eq!(report.applied_group_ids, vec![id.clone()]);
    assert!(!report.uncertain);
    assert_eq!(report.remaining, 0);
    let state = f
        .store
        .app_storage()
        .load_account_projection_state("alice", 100)
        .unwrap();
    assert!(
        state
            .groups
            .iter()
            .find(|stored| stored.group_id_hex == id)
            .unwrap()
            .archived
    );
    assert!(f.app.refresh_chat_list_row("alice", &id).is_err());
    assert!(
        !f.store
            .app_storage()
            .chat_list_row(&id)
            .unwrap()
            .unwrap()
            .archived
    );
    assert!(
        f.app
            .chat_list_projection_stale
            .lock()
            .unwrap()
            .contains("alice")
    );
    assert!(f.app.ensure_chat_list_projection(&account).is_err());
    assert!(
        f.app
            .chat_list_projection_stale
            .lock()
            .unwrap()
            .contains("alice"),
        "failed refresh retains the existing source-owned stale marker"
    );
    connection.execute_batch("DROP TRIGGER selection_fail_archive_insert; DROP TRIGGER selection_fail_archive_update;").unwrap();
    f.app.ensure_chat_list_projection(&account).unwrap();
    assert!(
        !f.app
            .chat_list_projection_stale
            .lock()
            .unwrap()
            .contains("alice")
    );
    assert!(
        f.store
            .app_storage()
            .chat_list_row(&id)
            .unwrap()
            .unwrap()
            .archived
    );
    let retained = handle
        .apply(
            903,
            1,
            0,
            context,
            ChatSelectionMutation::Archive { archived: true },
        )
        .await
        .unwrap();
    assert_eq!(retained.applied_group_ids, report.applied_group_ids);
    assert!(!retained.uncertain);
    handle.close();
    f.runtime.shutdown_and_close().await.unwrap();
}
