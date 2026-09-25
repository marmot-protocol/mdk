use super::*;
use crate::runtime::account_worker::ManagedAccountWorker;
use marmot_account::AccountHome;
use std::sync::atomic::{AtomicUsize, Ordering};
use storage_sqlite::{SqliteAccountStorage, StoredAppEvent};
use tokio::sync::{Notify, Semaphore};
use tokio::time::timeout;

#[tokio::test]
async fn rejected_open_does_not_start_readiness_waits() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
    let result = runtime
        .open_conversation_window(
            "unknown",
            &GroupId::new(vec![1; 16]),
            ConversationOpenQuery {
                limit: 0,
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(result, Err(ConversationWindowError::InvalidLimit)));
    let snapshot = runtime.shared.app_performance_telemetry().snapshot();
    for operation in [
        RuntimeOp::ConversationAuthorityReady,
        RuntimeOp::ConversationSendReady,
    ] {
        let sample = snapshot
            .runtime_operations
            .iter()
            .find(|s| s.operation == operation)
            .unwrap();
        assert_eq!(sample.started, 0);
        assert_eq!(sample.cancelled, 0);
    }
    let open = snapshot
        .runtime_operations
        .iter()
        .find(|s| s.operation == RuntimeOp::ConversationOpen)
        .unwrap();
    assert_eq!((open.started, open.failures), (1, 1));
}

struct Fixture {
    _dir: tempfile::TempDir,
    app: MarmotApp,
    runtime: MarmotAppRuntime,
    group: GroupId,
    account: String,
    store: SqliteAccountStorage,
    mode: Arc<AtomicUsize>,
    captures: Arc<AtomicUsize>,
    captured: Arc<Notify>,
    release: Arc<Notify>,
}
impl Fixture {
    async fn new(count: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("window test", &[]).await.unwrap();
        let store = app.account_storage("alice").unwrap();
        let runtime = MarmotAppRuntime::new(app.clone());
        let mode = Arc::new(AtomicUsize::new(0));
        let captures = Arc::new(AtomicUsize::new(0));
        let captured = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (commands, mut rx) = mpsc::channel(8);
        let (shutdown, mut stop) = oneshot::channel();
        let m = mode.clone();
        let n = captures.clone();
        let reached = captured.clone();
        let resume = release.clone();
        // Exercise the real worker capture, with controllable contention and
        // delivery barriers. Separate dispatch tests cover actual sync arbitration.
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stop => return,
                    command = rx.recv() => match command {
                        Some(AccountWorkerCommand::CaptureConversation { group_id, query, store_epoch, observer, respond, queued }) => {
                            n.fetch_add(1, Ordering::SeqCst);
                            client.register_conversation_capture(observer);
                            let mode = m.load(Ordering::SeqCst);
                            if mode == 5 {
                                reached.notify_one();
                                tokio::select! { _ = resume.notified() => {}, _ = &mut stop => return }
                            }
                            let result = match mode {
                                1 => Err(ConversationWindowError::NotReady),
                                2 => Err(StorageError::Busy("test contention".into()).into()),
                                4 => Err(AppError::BlockingTask("test task failure".into()).into()),
                                _ => capture_conversation(&mut client, &group_id, query, &store_epoch),
                            };
                            if mode == 3 {
                                reached.notify_one();
                                tokio::select! { _ = resume.notified() => {}, _ = &mut stop => return }
                            }
                            if let Some(queued) = queued { queued.finish(telemetry_outcome(&result)); }
                            let _ = respond.send(result);
                        }
                        None => return,
                        _ => panic!("unexpected fixture command"),
                    }
                }
            }
        });
        runtime.accounts.workers.lock().await.insert(
            account.account_id_hex.clone(),
            ManagedAccountWorker {
                ready: true,
                handle,
                commands,
                media_admission: Arc::new(Semaphore::new(1)),
                shutdown,
            },
        );
        let f = Self {
            _dir: dir,
            app,
            runtime,
            group,
            account: account.account_id_hex,
            store,
            mode,
            captures,
            captured,
            release,
        };
        for i in 0..count {
            f.add(i);
        }
        f
    }
    fn group_hex(&self) -> String {
        hex::encode(self.group.as_slice())
    }
    fn add(&self, i: usize) {
        self.add_sender(i, &"bb".repeat(32));
    }
    fn add_sender(&self, i: usize, sender: &str) {
        self.store
            .record_app_event(&StoredAppEvent {
                group_id_hex: self.group_hex(),
                message_id_hex: id(i),
                source_message_id_hex: Some(id(i + 10000)),
                source_epoch: Some(1),
                direction: "received".into(),
                sender: sender.to_owned(),
                plaintext: format!("message {i}"),
                kind: 9,
                tags: vec![],
                recorded_at: 100 + i as u64,
                received_at: 100 + i as u64,
                origin_commit_id: None,
                moderation_grant: false,
            })
            .unwrap();
    }
    fn signal(&self) {
        let _ = self
            .app
            .presentation_signals
            .updates
            .send(PresentationInvalidation {
                account_label: "alice".into(),
                version: self.store.chat_presentation_version().unwrap(),
            });
    }
    fn projection_event(&self, account_id: &str, group_hex: &str) {
        self.runtime
            .events
            .send(MarmotAppEvent::ProjectionUpdated(
                crate::RuntimeProjectionUpdate {
                    account_id_hex: account_id.to_owned(),
                    account_label: "alice".into(),
                    update: crate::AppProjectionUpdate {
                        group_id_hex: group_hex.to_owned(),
                        timeline_messages: vec![],
                        timeline_changes: vec![],
                        chat_list_row: None,
                        chat_list_trigger: Default::default(),
                    },
                },
            ))
            .unwrap();
    }
    fn draft(&self, text: &str) {
        self.app
            .save_message_draft("alice", &self.group_hex(), text, None, vec![])
            .unwrap();
    }
    async fn open(
        &self,
        target: ConversationOpenTarget,
        limit: usize,
    ) -> RuntimeConversationWindowSubscription {
        let mut subscription = timeout(
            Duration::from_secs(10),
            self.runtime.open_conversation_window(
                "alice",
                &self.group,
                ConversationOpenQuery { target, limit },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        // Existing tests exercise the live-authority contract; dedicated cold
        // tests assert the immediately returned local-only initial snapshot.
        while subscription.snapshot.presentation.header.epoch.is_none() {
            subscription.snapshot = next(&mut subscription).await;
        }
        subscription
    }
    async fn close(self) {
        self.runtime.shutdown_and_close().await.unwrap();
    }
}
fn id(i: usize) -> String {
    format!("{i:064x}")
}
fn ids(s: &ConversationWindowSnapshot) -> Vec<String> {
    s.page
        .page()
        .messages
        .iter()
        .map(|m| m.message_id_hex.clone())
        .collect()
}
async fn next_with_draft(sub: &mut RuntimeConversationWindowSubscription, content: &str) {
    while next(sub)
        .await
        .draft
        .draft
        .is_none_or(|draft| draft.content != content)
    {}
}
async fn next(sub: &mut RuntimeConversationWindowSubscription) -> ConversationWindowSnapshot {
    timeout(Duration::from_secs(5), sub.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn open_combines_first_unread_draft_identity_and_permissions_without_marking_read() {
    let f = Fixture::new(12).await;
    f.store
        .refresh_chat_list_row(&f.account, &f.group_hex(), &|_, _| false)
        .unwrap();
    f.store
        .mark_timeline_message_read(&f.account, &f.group_hex(), &id(3), &|_, _| false)
        .unwrap();
    f.draft("unsent");
    let mut sub = f
        .runtime
        .open_conversation_window(
            "alice",
            &f.group,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Automatic,
                limit: 5,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        sub.snapshot.anchor,
        ConversationOpenAnchorOutcome::FirstUnread { .. }
    ));
    let index = anchor_index(sub.snapshot.anchor).unwrap();
    assert_eq!(sub.snapshot.anchors[index].message_id_hex(), id(4));
    assert_eq!(sub.snapshot.read_state.unread_count, 8);
    assert_eq!(sub.snapshot.draft.draft.as_ref().unwrap().content, "unsent");
    assert!(!sub.snapshot.presentation.header.capabilities.is_self_admin);
    assert!(
        sub.snapshot
            .presentation
            .identities
            .contains_key(&"bb".repeat(32))
    );
    assert_eq!(sub.snapshot.page.page().messages.len(), 5);
    while sub.snapshot.presentation.header.epoch.is_none() {
        sub.snapshot = next(&mut sub).await;
    }
    assert!(sub.snapshot.presentation.header.capabilities.is_self_admin);
    let handle = sub.window_handle();
    let page = handle
        .page(&sub.snapshot.revision, ConversationPageDirection::Older, 3)
        .await
        .unwrap();
    assert_eq!(page.read_state.last_read_message_id_hex, Some(id(3)));
    assert_eq!(page.read_state.unread_count, 8);
    assert_eq!(
        page.anchors[anchor_index(page.anchor).unwrap()].message_id_hex(),
        id(4)
    );
    f.close().await;
}

#[tokio::test]
async fn receive_and_commands_are_independent_and_paging_retains_anchor_with_a_row_cap() {
    let f = Fixture::new(230).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 50).await;
    let handle = sub.window_handle();
    let anchored = handle
        .set_visible_anchor(&sub.snapshot.revision, &id(210))
        .await
        .unwrap();
    let _ = next(&mut sub).await;
    let (received, paged) = tokio::join!(
        sub.recv(),
        handle.page(&anchored.revision, ConversationPageDirection::Older, 200)
    );
    let paged = paged.unwrap();
    assert_eq!(
        received.unwrap().unwrap().revision.sequence,
        paged.revision.sequence
    );
    assert_eq!(paged.page.page().messages.len(), 200);
    assert_eq!(
        paged.anchors[anchor_index(paged.anchor).unwrap()].message_id_hex(),
        id(210)
    );
    assert!(matches!(
        handle.return_to_latest(&anchored.revision).await,
        Err(ConversationWindowError::StaleWindow)
    ));
    let newer = handle
        .page(&paged.revision, ConversationPageDirection::Newer, 40)
        .await
        .unwrap();
    assert_eq!(newer.page.page().messages.len(), 200);
    assert_eq!(
        newer.anchors[anchor_index(newer.anchor).unwrap()].message_id_hex(),
        id(210)
    );
    assert_eq!(ids(&newer).last(), Some(&id(229)));
    let latest = handle.return_to_latest(&newer.revision).await.unwrap();
    assert_eq!(ids(&latest).last(), Some(&id(229)));
    assert!(!latest.page.page().has_more_after);
    let mut alien = latest.revision.clone();
    alien.generation.push('x');
    assert!(matches!(
        handle.return_to_latest(&alien).await,
        Err(ConversationWindowError::StaleWindow)
    ));
    f.close().await;
}

#[tokio::test]
async fn commands_quoting_a_revision_replaced_only_by_new_content_apply_to_the_current_viewport() {
    let f = Fixture::new(20).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    let handle = sub.window_handle();
    let quoted = sub.snapshot.revision.clone();
    f.draft("first");
    next_with_draft(&mut sub, "first").await;
    let paged = handle
        .page(&quoted, ConversationPageDirection::Older, 5)
        .await
        .unwrap();
    assert_eq!(ids(&paged), (10..20).map(id).collect::<Vec<_>>());
    assert_eq!(paged.draft.draft.unwrap().content, "first");
    f.draft("second");
    next_with_draft(&mut sub, "second").await;
    let latest = handle.return_to_latest(&paged.revision).await.unwrap();
    assert!(matches!(
        latest.anchor,
        ConversationOpenAnchorOutcome::Latest { .. }
    ));
    assert_eq!(ids(&latest).last(), Some(&id(19)));
    f.draft("third");
    next_with_draft(&mut sub, "third").await;
    let anchored = handle
        .set_visible_anchor(&latest.revision, &id(17))
        .await
        .unwrap();
    assert_eq!(
        anchored.anchors[anchor_index(anchored.anchor).unwrap()].message_id_hex(),
        id(17)
    );
    f.close().await;
}

#[tokio::test]
async fn a_command_that_leaves_the_viewport_in_place_does_not_supersede_revisions() {
    let f = Fixture::new(20).await;
    let sub = f.open(ConversationOpenTarget::Latest, 5).await;
    let handle = sub.window_handle();
    let quoted = sub.snapshot.revision.clone();
    let latest = handle.return_to_latest(&quoted).await.unwrap();
    assert!(latest.revision.sequence > quoted.sequence);
    let paged = handle
        .page(&quoted, ConversationPageDirection::Older, 5)
        .await
        .unwrap();
    assert_eq!(ids(&paged), (10..20).map(id).collect::<Vec<_>>());
    f.close().await;
}

#[tokio::test]
async fn commands_quoting_an_unpublished_sequence_are_stale() {
    let f = Fixture::new(5).await;
    let sub = f.open(ConversationOpenTarget::Latest, 3).await;
    let mut ahead = sub.snapshot.revision.clone();
    ahead.sequence += 1;
    assert!(matches!(
        sub.window_handle().return_to_latest(&ahead).await,
        Err(ConversationWindowError::StaleWindow)
    ));
    f.close().await;
}

#[tokio::test]
async fn mutations_during_initial_capture_are_reconciled_after_delivery() {
    let f = Fixture::new(5).await;
    f.mode.store(3, Ordering::SeqCst);
    let open =
        f.runtime
            .open_conversation_window("alice", &f.group, ConversationOpenQuery::default());
    let mutate = async {
        timeout(Duration::from_secs(5), f.captured.notified())
            .await
            .unwrap();
        f.add_sender(5, &"cc".repeat(32));
        f.draft("arrived during capture");
        f.mode.store(0, Ordering::SeqCst);
        f.release.notify_one();
    };
    let (sub, ()) = tokio::join!(open, mutate);
    let mut sub = sub.unwrap();
    assert!(sub.snapshot.draft.draft.is_none());
    // A coherent live-authority upgrade captured before the mutation may
    // arrive first. It must not consume invalidations queued during capture.
    let updated = loop {
        let update = next(&mut sub).await;
        if update.draft.draft.is_some() {
            break update;
        }
    };
    assert_eq!(
        updated.draft.draft.as_ref().unwrap().content,
        "arrived during capture"
    );
    assert!(
        updated
            .presentation
            .identities
            .contains_key(&"cc".repeat(32))
    );
    assert_eq!(ids(&updated).last(), Some(&id(5)));
    f.close().await;
}

#[tokio::test]
async fn quiet_busy_retries_keep_cancelled_command_position() {
    let f = Fixture::new(20).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    let handle = sub.window_handle();
    f.mode.store(3, Ordering::SeqCst);
    let revision = sub.snapshot.revision.clone();
    let caller = tokio::spawn(async move { handle.jump_to_message(&revision, &id(4)).await });
    timeout(Duration::from_secs(5), f.captured.notified())
        .await
        .unwrap();
    caller.abort();
    let _ = caller.await;
    tokio::time::sleep(Duration::from_millis(100)).await; // exceed the display budget
    f.mode.store(0, Ordering::SeqCst);
    f.release.notify_one();
    let jumped = next(&mut sub).await;
    assert_eq!(
        jumped.anchors[anchor_index(jumped.anchor).unwrap()].message_id_hex(),
        id(4)
    );
    f.mode.store(2, Ordering::SeqCst);
    f.draft("retry me");
    assert!(matches!(
        timeout(Duration::from_secs(3), sub.recv()).await.unwrap(),
        Err(ConversationWindowError::App(_))
    ));
    f.mode.store(0, Ordering::SeqCst); // no further signal
    let recovered = next(&mut sub).await;
    assert_eq!(recovered.draft.draft.unwrap().content, "retry me");
    assert_eq!(
        recovered.anchors[anchor_index(recovered.anchor).unwrap()].message_id_hex(),
        id(4)
    );
    f.close().await;
}

#[tokio::test]
async fn transient_command_failure_keeps_target_until_quiet_retry() {
    let f = Fixture::new(20).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    f.mode.store(2, Ordering::SeqCst);
    assert!(matches!(
        sub.window_handle()
            .jump_to_message(&sub.snapshot.revision, &id(3))
            .await,
        Err(ConversationWindowError::App(_))
    ));
    assert!(matches!(
        sub.recv().await,
        Err(ConversationWindowError::App(_))
    ));
    f.mode.store(0, Ordering::SeqCst);
    let recovered = next(&mut sub).await;
    assert_eq!(
        recovered.anchors[anchor_index(recovered.anchor).unwrap()].message_id_hex(),
        id(3)
    );
    f.close().await;
}

#[tokio::test]
async fn viewport_move_kept_through_a_transient_failure_supersedes_revisions_once_published() {
    let f = Fixture::new(20).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    let handle = sub.window_handle();
    let before_move = sub.snapshot.revision.clone();
    f.mode.store(2, Ordering::SeqCst);
    for _ in 0..2 {
        // Until the move is published, the installed revision stays current.
        assert!(matches!(
            handle
                .page(&before_move, ConversationPageDirection::Older, 5)
                .await,
            Err(ConversationWindowError::App(_))
        ));
    }
    assert!(matches!(
        sub.recv().await,
        Err(ConversationWindowError::App(_))
    ));
    f.mode.store(0, Ordering::SeqCst);
    let moved = next(&mut sub).await;
    assert_eq!(ids(&moved), (5..20).map(id).collect::<Vec<_>>());
    assert!(matches!(
        handle.return_to_latest(&before_move).await,
        Err(ConversationWindowError::StaleWindow)
    ));
    let paged = handle
        .page(&moved.revision, ConversationPageDirection::Older, 5)
        .await
        .unwrap();
    assert_eq!(ids(&paged), (0..20).map(id).collect::<Vec<_>>());
    f.close().await;
}

#[tokio::test]
async fn viewport_moves_undone_before_publication_do_not_supersede_revisions() {
    let f = Fixture::new(20).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    let handle = sub.window_handle();
    let quoted = sub.snapshot.revision.clone();
    f.mode.store(2, Ordering::SeqCst);
    assert!(matches!(
        handle.set_visible_anchor(&quoted, &id(17)).await,
        Err(ConversationWindowError::App(_))
    ));
    assert!(matches!(
        handle.return_to_latest(&quoted).await,
        Err(ConversationWindowError::App(_))
    ));
    assert!(matches!(
        sub.recv().await,
        Err(ConversationWindowError::App(_))
    ));
    f.draft("saved after returning to the published viewport");
    f.mode.store(0, Ordering::SeqCst);
    next_with_draft(&mut sub, "saved after returning to the published viewport").await;
    let paged = handle
        .page(&quoted, ConversationPageDirection::Older, 5)
        .await
        .unwrap();
    assert_eq!(ids(&paged), (10..20).map(id).collect::<Vec<_>>());
    f.close().await;
}

#[tokio::test]
async fn viewport_move_abandoned_after_its_target_expires_does_not_supersede_revisions() {
    let f = Fixture::new(20).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    let handle = sub.window_handle();
    let before_jump = sub.snapshot.revision.clone();
    f.mode.store(2, Ordering::SeqCst);
    assert!(matches!(
        handle.jump_to_message(&before_jump, &id(3)).await,
        Err(ConversationWindowError::App(_))
    ));
    assert!(sub.recv().await.is_err());
    f.store
        .prune_app_events_before(&f.group_hex(), 105, &f.account, &|_, _| false)
        .unwrap();
    f.draft("saved while the jump target expired");
    f.mode.store(0, Ordering::SeqCst);
    assert!(matches!(
        timeout(Duration::from_secs(3), sub.recv()).await.unwrap(),
        Err(ConversationWindowError::Query(_))
    ));
    next_with_draft(&mut sub, "saved while the jump target expired").await;
    let paged = handle
        .page(&before_jump, ConversationPageDirection::Older, 5)
        .await
        .unwrap();
    assert_eq!(ids(&paged), (10..20).map(id).collect::<Vec<_>>());
    f.close().await;
}

#[tokio::test]
async fn lag_recovers_newer_draft_and_missing_explicit_target_does_not_close_handle() {
    let f = Fixture::new(12).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    let handle = sub.window_handle();
    assert!(matches!(
        handle
            .jump_to_message(&sub.snapshot.revision, &id(999))
            .await,
        Err(ConversationWindowError::Query(_))
    ));
    assert!(
        timeout(Duration::from_millis(20), sub.recv())
            .await
            .is_err()
    );
    f.store
        .save_message_draft(&f.group_hex(), "newest", None, &[])
        .unwrap();
    // Overwrite the relevant signal with unrelated traffic. Lag itself requires a read.
    for _ in 0..1500 {
        let _ = f
            .app
            .presentation_signals
            .drafts
            .send(MessageDraftInvalidation {
                account_label: "other".into(),
                group_id_hex: "other".into(),
            });
    }
    let refreshed = next(&mut sub).await;
    assert_eq!(refreshed.draft.draft.unwrap().content, "newest");
    let latest = handle.return_to_latest(&refreshed.revision).await.unwrap();
    assert_eq!(ids(&latest).last(), Some(&id(11)));
    f.close().await;
}

#[tokio::test]
async fn reset_and_subscription_drop_close_surviving_command_handles() {
    let f = Fixture::new(5).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 3).await;
    let handle = sub.window_handle();
    let _ = f
        .app
        .presentation_signals
        .account_resets
        .send("alice".into());
    assert!(
        timeout(Duration::from_secs(2), sub.recv())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        handle.return_to_latest(&sub.snapshot.revision).await,
        Err(ConversationWindowError::Closed)
    ));
    let sub = f.open(ConversationOpenTarget::Latest, 3).await;
    let handle = sub.window_handle();
    let revision = sub.snapshot.revision.clone();
    drop(sub);
    assert!(matches!(
        timeout(Duration::from_secs(2), handle.return_to_latest(&revision))
            .await
            .unwrap(),
        Err(ConversationWindowError::Closed)
    ));
    f.close().await;
}

#[tokio::test]
async fn retained_anchor_recovers_after_expiry_and_profile_only_updates_refresh_header_dictionary()
{
    let f = Fixture::new(15).await;
    let mut sub = f.open(ConversationOpenTarget::Message(id(5)), 5).await;
    f.store
        .prune_app_events_before(&f.group_hex(), 106, &f.account, &|_, _| false)
        .unwrap();
    f.signal();
    let recovered = next(&mut sub).await;
    assert!(matches!(
        recovered.anchor,
        ConversationOpenAnchorOutcome::RecoveredNext { .. }
    ));
    assert_eq!(
        recovered.anchors[anchor_index(recovered.anchor).unwrap()].message_id_hex(),
        id(6)
    );
    let mut record = f.app.empty_directory_record(&"bb".repeat(32));
    record.profile = Some(crate::UserProfileMetadata {
        display_name: Some("Updated sender".into()),
        created_at: 42,
        ..Default::default()
    });
    f.app.save_directory_entry(&record).unwrap();
    let refreshed = next(&mut sub).await;
    assert_eq!(
        refreshed.presentation.identities[&"bb".repeat(32)].display_name,
        "Updated sender"
    );
    assert_eq!(
        refreshed.anchors[anchor_index(refreshed.anchor).unwrap()].message_id_hex(),
        id(6)
    );
    f.close().await;
}

#[tokio::test]
async fn draft_acceptance_cannot_erase_newer_edit_and_unrelated_signals_do_not_redraw() {
    let f = Fixture::new(6).await;
    f.draft("accepted draft");
    let mut sub = f.open(ConversationOpenTarget::Latest, 3).await;
    let accepted = sub.snapshot.draft.revision.clone();
    f.draft("new edit");
    assert!(f.store.clear_message_draft_if_revision(&accepted).is_err());
    let refreshed = next(&mut sub).await;
    assert_eq!(refreshed.draft.draft.unwrap().content, "new edit");
    // An unchanged account-wide invalidation may read once but must not create a redraw loop.
    let before = f.captures.load(Ordering::SeqCst);
    f.signal();
    assert!(
        timeout(Duration::from_millis(100), sub.recv())
            .await
            .is_err()
    );
    assert_eq!(f.captures.load(Ordering::SeqCst), before + 1);
    f.close().await;
}

#[tokio::test]
async fn production_worker_opens_and_shutdown_closes_window() {
    let f = Fixture::new(8).await;
    let worker = f
        .runtime
        .accounts
        .workers
        .lock()
        .await
        .remove(&f.account)
        .unwrap();
    worker.shutdown().await; // releases the real AppClient before ordinary worker startup
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    assert_eq!(ids(&sub.snapshot).last(), Some(&id(7)));
    assert!(sub.snapshot.presentation.header.capabilities.can_send);
    f.runtime.shutdown_and_close().await.unwrap();
    assert!(sub.recv().await.unwrap().is_none());
}

#[tokio::test]
async fn invitation_acceptance_archive_and_departure_refresh_capabilities_with_retained_history() {
    use crate::conversation_presentation::ConversationParticipation;
    let f = Fixture::new(9).await;
    let mut state = f.app.load_state("alice").unwrap();
    state.groups[0].pending_confirmation = true;
    state.groups[0].archived = true;
    f.app.save_state(&state).unwrap();
    let mut sub = f.open(ConversationOpenTarget::Automatic, 4).await;
    assert!(matches!(
        sub.snapshot.anchor,
        ConversationOpenAnchorOutcome::Latest { .. }
    ));
    assert_eq!(
        sub.snapshot.presentation.header.capabilities.participation,
        ConversationParticipation::PendingInvitation
    );
    assert!(!sub.snapshot.presentation.header.capabilities.can_send);
    state.groups[0].pending_confirmation = false;
    f.app.save_state(&state).unwrap();
    f.signal();
    let accepted = next(&mut sub).await;
    assert!(!accepted.pending_confirmation);
    assert!(accepted.presentation.header.archived);
    assert!(accepted.presentation.header.capabilities.can_send);
    f.app
        .set_group_self_membership("alice", &f.group_hex(), crate::SelfMembership::Left)
        .unwrap();
    f.signal();
    let left = next(&mut sub).await;
    assert_eq!(
        left.presentation.header.capabilities.participation,
        ConversationParticipation::Left
    );
    assert!(!left.presentation.header.capabilities.can_send);
    assert_eq!(ids(&left), ids(&accepted));
    f.close().await;
}

#[tokio::test]
async fn eviction_and_lost_reset_are_terminal_even_if_same_store_can_reopen() {
    let f = Fixture::new(3).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 3).await;
    f.app.drop_account_caches("alice");
    for i in 0..100 {
        let _ = f
            .app
            .presentation_signals
            .account_resets
            .send(format!("other-{i}"));
    }
    let _ = f.app.account_storage("alice").unwrap();
    assert!(
        timeout(Duration::from_secs(2), sub.recv())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        sub.window_handle()
            .return_to_latest(&sub.snapshot.revision)
            .await,
        Err(ConversationWindowError::Closed)
    ));
    f.close().await;
}

#[tokio::test]
async fn closed_session_storage_terminates_retry_and_missing_jump_recovers_original_viewport() {
    let f = Fixture::new(20).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    f.mode.store(2, Ordering::SeqCst);
    assert!(matches!(
        sub.window_handle()
            .jump_to_message(&sub.snapshot.revision, &id(3))
            .await,
        Err(ConversationWindowError::App(_))
    ));
    assert!(sub.recv().await.is_err());
    f.store
        .prune_app_events_before(&f.group_hex(), 105, &f.account, &|_, _| false)
        .unwrap();
    f.mode.store(0, Ordering::SeqCst);
    assert!(matches!(
        timeout(Duration::from_secs(3), sub.recv()).await.unwrap(),
        Err(ConversationWindowError::Query(_))
    ));
    let recovered = next(&mut sub).await;
    assert_eq!(ids(&recovered).last(), Some(&id(19)));
    f.store.close().unwrap();
    let _ = f
        .app
        .presentation_signals
        .drafts
        .send(MessageDraftInvalidation {
            account_label: "alice".into(),
            group_id_hex: f.group_hex(),
        });
    assert!(
        timeout(Duration::from_secs(3), sub.recv())
            .await
            .unwrap()
            .is_err()
    );
    assert!(sub.recv().await.unwrap().is_none());
    f.close().await;
}

#[tokio::test]
async fn latest_follows_arrivals_but_history_paging_retains_the_viewport() {
    let f = Fixture::new(12).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    f.add_sender(12, &"cc".repeat(32));
    let captures = f.captures.load(Ordering::SeqCst);
    // Matching labels must not accidentally cross account or group boundaries.
    f.projection_event("alice", &f.group_hex());
    f.projection_event(&f.account, &hex::encode([99; 16]));
    assert!(
        timeout(Duration::from_millis(100), sub.recv())
            .await
            .is_err()
    );
    assert_eq!(f.captures.load(Ordering::SeqCst), captures);
    // This is the production projection event bus, with no presentation/draft wakeup.
    f.projection_event(&f.account, &f.group_hex());
    let latest = next(&mut sub).await;
    assert_eq!(ids(&latest), (8..=12).map(id).collect::<Vec<_>>());
    assert!(
        latest
            .presentation
            .identities
            .contains_key(&"cc".repeat(32))
    );
    assert!(!latest.page.page().has_more_after);
    let handle = sub.window_handle();
    let older = handle
        .page(&latest.revision, ConversationPageDirection::Older, 5)
        .await
        .unwrap();
    assert_eq!(
        older.anchors[anchor_index(older.anchor).unwrap()].message_id_hex(),
        id(12)
    );
    let _ = next(&mut sub).await;
    f.add(13);
    f.runtime
        .events
        .send(MarmotAppEvent::GroupStateUpdated {
            account_id_hex: f.account.clone(),
            account_label: "alice".into(),
            group_id: f.group.clone(),
        })
        .unwrap();
    let held = next(&mut sub).await;
    assert_eq!(ids(&held), ids(&older));
    assert!(held.page.page().has_more_after);
    let tail = handle.return_to_latest(&held.revision).await.unwrap();
    assert_eq!(ids(&tail).last(), Some(&id(13)));
    f.close().await;
}

#[tokio::test]
async fn provenance_only_change_is_not_suppressed_as_unchanged_content() {
    let f = Fixture::new(1).await;
    let sub = f.open(ConversationOpenTarget::Latest, 1).await;
    let mut raw = sub.snapshot.page.page().clone();
    let row = &mut raw.messages[0];
    row.message_id_hex = id(100);
    row.kind = cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM;
    row.direction = "system".into();
    row.source_message_id_hex = None;
    row.plaintext = "unrecognized future system payload".into();
    let event = StoredAppEvent {
        group_id_hex: row.group_id_hex.clone(),
        message_id_hex: row.message_id_hex.clone(),
        source_message_id_hex: None,
        source_epoch: row.source_epoch,
        direction: row.direction.clone(),
        sender: row.sender.clone(),
        plaintext: row.plaintext.clone(),
        kind: row.kind,
        tags: vec![],
        recorded_at: 200,
        received_at: 200,
        origin_commit_id: Some(id(900)),
        moderation_grant: false,
    };
    let untrusted = f.store.conversation_presentation_page(raw.clone()).unwrap();
    f.store.record_app_event(&event).unwrap();
    let trusted = f.store.conversation_presentation_page(raw).unwrap();
    assert!(untrusted.authenticated_system_content(0).is_none());
    assert!(trusted.authenticated_system_content(0).is_some());
    // Even if the presentation parser does not yet interpret this system payload,
    // the provenance-bearing page has changed and must reach its consumer.
    let mut before = sub.snapshot.clone();
    before.page = untrusted;
    let mut after = before.clone();
    after.page = trusted;
    assert!(!after.same_content(&before));
    f.close().await;
}

#[tokio::test]
async fn saturated_history_paging_continues_after_reporting_the_new_visible_anchor() {
    let f = Fixture::new(430).await;
    let sub = f.open(ConversationOpenTarget::Latest, 50).await;
    let handle = sub.window_handle();
    let mut page = sub.snapshot.clone();
    for _ in 0..4 {
        page = handle
            .page(&page.revision, ConversationPageDirection::Older, 50)
            .await
            .unwrap();
    }
    assert_eq!(page.anchors.len(), CONVERSATION_WINDOW_MAX_ROWS);
    assert!(page.page.page().has_more_before);
    let saturated = handle
        .page(&page.revision, ConversationPageDirection::Older, 50)
        .await
        .unwrap();
    assert_eq!(ids(&saturated), ids(&page));
    let visible = handle
        .set_visible_anchor(&saturated.revision, &id(230))
        .await
        .unwrap();
    let advanced = handle
        .page(&visible.revision, ConversationPageDirection::Older, 50)
        .await
        .unwrap();
    assert_eq!(ids(&advanced).first(), Some(&id(180)));
    assert_eq!(
        advanced.anchors[anchor_index(advanced.anchor).unwrap()].message_id_hex(),
        id(230)
    );
    assert_eq!(advanced.anchors.len(), CONVERSATION_WINDOW_MAX_ROWS);
    f.close().await;
}

#[tokio::test]
async fn terminal_task_failure_after_transient_failure_is_reported_and_stops_retrying() {
    let f = Fixture::new(3).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 3).await;
    f.mode.store(2, Ordering::SeqCst);
    f.signal();
    assert!(matches!(
        timeout(Duration::from_secs(3), sub.recv()).await.unwrap(),
        Err(ConversationWindowError::App(_))
    ));
    f.mode.store(4, Ordering::SeqCst);
    assert!(
        matches!(timeout(Duration::from_secs(3), sub.recv()).await.unwrap(), Err(ConversationWindowError::App(e)) if matches!(e.as_ref(), AppError::BlockingTask(_)))
    );
    assert!(sub.recv().await.unwrap().is_none());
    assert!(matches!(
        sub.window_handle()
            .return_to_latest(&sub.snapshot.revision)
            .await,
        Err(ConversationWindowError::Closed)
    ));
    f.close().await;
}

#[tokio::test]
async fn production_reconnect_backoff_keeps_conversation_captures_retryable() {
    let f = Fixture::new(3).await;
    let worker = f
        .runtime
        .accounts
        .workers
        .lock()
        .await
        .remove(&f.account)
        .unwrap();
    worker.shutdown().await;
    let sub = f.open(ConversationOpenTarget::Latest, 3).await;
    let commands = f
        .runtime
        .accounts
        .workers
        .lock()
        .await
        .get(&f.account)
        .unwrap()
        .commands
        .clone();
    tokio::time::pause();
    f.runtime
        .shared_services()
        .relay_plane()
        .simulate_notification_recovery_for_test(1);
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        match f.runtime.unhydrated_group_count_for_test("alice").await {
            Err(AppError::TransportClosed) => break,
            Ok(_) => tokio::task::yield_now().await,
            Err(error) => panic!("unexpected reconnect probe error: {error:?}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "worker did not enter reconnect backoff"
        );
    }
    let capture = || {
        let (respond, response) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::CaptureConversation {
                queued: None,
                group_id: f.group.clone(),
                query: Default::default(),
                store_epoch: f.store.chat_presentation_version().unwrap().store_epoch,
                observer: None,
                respond,
            })
            .unwrap();
        response
    };
    // The ordinary backoff arm must not close the responder.
    assert!(matches!(
        capture().await.unwrap(),
        Err(ConversationWindowError::NotReady)
    ));
    let (respond, recovery) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::CatchUp { respond })
        .unwrap();
    // Queue without yielding so capture is drained by the recovery coalesce arm.
    let response = capture();
    assert!(matches!(
        response.await.unwrap(),
        Err(ConversationWindowError::NotReady)
    ));
    tokio::time::resume();
    timeout(Duration::from_secs(10), recovery)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let recovered = sub
        .window_handle()
        .return_to_latest(&sub.snapshot.revision)
        .await
        .unwrap();
    assert_eq!(ids(&recovered), ids(&sub.snapshot));
    f.close().await;
}

#[tokio::test]
async fn conversation_viewer_reaction_updates_after_add_and_remove() {
    use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION};
    let f = Fixture::new(1).await;
    let record = |number: usize, sender: &str, kind: u64, target: String| {
        f.store
            .record_app_event(&StoredAppEvent {
                group_id_hex: f.group_hex(),
                message_id_hex: id(number),
                source_message_id_hex: Some(id(number + 10000)),
                source_epoch: Some(1),
                direction: "received".into(),
                sender: sender.into(),
                plaintext: if kind == MARMOT_APP_EVENT_KIND_REACTION {
                    "👍".into()
                } else {
                    String::new()
                },
                kind,
                tags: vec![vec!["e".into(), target]],
                recorded_at: number as u64 + 200,
                received_at: number as u64 + 200,
                origin_commit_id: None,
                moderation_grant: false,
            })
            .unwrap();
    };
    let peer = id(1);
    record(20, &peer, MARMOT_APP_EVENT_KIND_REACTION, id(0));
    let mut sub = f.open(ConversationOpenTarget::Latest, 1).await;
    assert!(!sub.snapshot.presentation.messages[0].reactions.items[0].viewer_reacted);
    let initial = sub.snapshot.revision.sequence;
    record(21, &f.account, MARMOT_APP_EVENT_KIND_REACTION, id(0));
    f.projection_event(&f.account, &f.group_hex());
    let added = next(&mut sub).await;
    assert!(added.revision.sequence > initial);
    assert!(added.presentation.messages[0].reactions.items[0].viewer_reacted);
    assert_eq!(added.presentation.messages[0].reactions.items[0].count, 2);
    record(22, &f.account, MARMOT_APP_EVENT_KIND_DELETE, id(21));
    f.projection_event(&f.account, &f.group_hex());
    let removed = next(&mut sub).await;
    assert!(removed.revision.sequence > added.revision.sequence);
    assert!(!removed.presentation.messages[0].reactions.items[0].viewer_reacted);
    assert_eq!(removed.presentation.messages[0].reactions.items[0].count, 1);
    assert_eq!(
        removed.presentation.messages[0].reactions.items[0].reactors,
        vec![peer]
    );
    drop(sub);
    f.close().await;
}

// The window must render retained local rows even when a live capture cannot
// run. This is the public first-open boundary, not just a SQL paging test.
#[tokio::test]
async fn cold_open_returns_stored_history_while_authority_is_not_ready() {
    let f = Fixture::new(200).await;
    f.store
        .refresh_chat_list_row(&f.account, &f.group_hex(), &|_, _| false)
        .unwrap();
    f.mode.store(1, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let result = timeout(
        Duration::from_millis(500),
        f.runtime.open_conversation_window(
            "alice",
            &f.group,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Latest,
                limit: 50,
            },
        ),
    )
    .await;
    eprintln!(
        "cold local open: history=200 elapsed_ms={} completed={}",
        started.elapsed().as_millis(),
        result.is_ok()
    );
    let mut sub = result
        .expect("stored messages must not wait for engine/relay readiness")
        .unwrap();
    assert_eq!(sub.snapshot.page.page().messages.len(), 50);
    assert_eq!(ids(&sub.snapshot).last(), Some(&id(199)));
    assert!(!sub.snapshot.presentation.header.capabilities.can_send);
    assert!(sub.snapshot.presentation.header.epoch.is_none());
    let telemetry = f.runtime.shared.app_performance_telemetry();
    let sample = |op| {
        telemetry
            .snapshot()
            .runtime_operations
            .into_iter()
            .find(|s| s.operation == op)
            .unwrap()
    };
    assert_eq!(sample(RuntimeOp::ConversationOpen).successes, 1);
    assert_eq!(sample(RuntimeOp::ConversationAuthorityReady).in_flight, 1);
    assert_eq!(sample(RuntimeOp::ConversationSendReady).successes, 0);
    // Wait for the first authority attempt to settle into quiet retry, then
    // ensure local draft invalidation is not held behind that one-second timer.
    tokio::time::sleep(Duration::from_millis(100)).await;
    f.draft("local update during catch-up");
    let local = timeout(Duration::from_millis(500), sub.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        local.draft.draft.as_ref().unwrap().content,
        "local update during catch-up"
    );
    assert!(local.presentation.header.epoch.is_none());
    f.mode.store(0, Ordering::SeqCst);
    let ready = next(&mut sub).await;
    assert!(ready.presentation.header.capabilities.can_send);
    assert!(ready.presentation.header.epoch.is_some());
    assert_eq!(ids(&ready), ids(&sub.snapshot));
    assert_eq!(sample(RuntimeOp::ConversationAuthorityReady).successes, 1);
    assert_eq!(sample(RuntimeOp::ConversationAuthorityReady).in_flight, 0);
    assert_eq!(sample(RuntimeOp::ConversationSendReady).successes, 1);
    assert!(sample(RuntimeOp::ConversationAuthorityAttempt).not_ready > 0);
    f.close().await;
}

#[tokio::test]
async fn cold_capture_does_not_force_group_hydration() {
    let f = Fixture::new(200).await;
    let worker = f
        .runtime
        .accounts
        .workers
        .lock()
        .await
        .remove(&f.account)
        .unwrap();
    worker.shutdown().await;
    let plane = f.runtime.shared_services().relay_plane().clone();
    let mut client = f
        .app
        .local_client_with_relay_plane_and_hydration("alice", &plane, None, true)
        .await
        .unwrap();
    assert_eq!(
        client.runtime.session().unhydrated_group_ids(),
        vec![f.group.clone()]
    );
    let result = capture_conversation(
        &mut client,
        &f.group,
        Default::default(),
        &f.store.chat_presentation_version().unwrap().store_epoch,
    );
    assert!(matches!(result, Err(ConversationWindowError::NotReady)));
    assert_eq!(
        client.runtime.session().unhydrated_group_ids(),
        vec![f.group.clone()]
    );
    drop(client);
    f.close().await;
}

#[tokio::test]
async fn send_checkpoints_are_query_scoped_coherent_and_released_on_close() {
    let f = Fixture::new(20).await;
    let worker = f
        .runtime
        .accounts
        .workers
        .lock()
        .await
        .remove(&f.account)
        .unwrap();
    worker.shutdown().await;
    let mut client = f.app.client("alice").await.unwrap();
    let query = ConversationWindowQuery {
        opening: ConversationOpenQuery {
            target: ConversationOpenTarget::Latest,
            limit: 5,
        },
        before_anchor: None,
    };
    let observer = Arc::new(SendCapture::new(
        f.group.clone(),
        f.store.chat_presentation_version().unwrap().store_epoch,
        query.clone(),
    ));
    client.register_conversation_capture(Some(Arc::downgrade(&observer)));
    client.register_conversation_capture(Some(Arc::downgrade(&observer)));
    assert_eq!(client.conversation_captures.len(), 1);
    client.publish_conversation_captures(&f.group);
    let captured = observer.take().unwrap();
    assert!(captured.authority.is_some());
    assert_eq!(captured.account.page.page().messages.len(), 5);

    client.publish_conversation_captures(&f.group);
    let (_, generation) = observer.checkpoint().unwrap();
    client.publish_conversation_captures(&f.group);
    observer.acknowledge(generation);
    assert!(
        observer.take().is_some(),
        "old presentation cannot clear a newer send"
    );

    let mut history = query.clone();
    history.opening.target = ConversationOpenTarget::Message(id(10));
    observer.set_query(&history);
    client.publish_conversation_captures(&f.group);
    assert!(observer.take().is_some());
    observer.set_query(&query);
    assert!(
        observer.take().is_some(),
        "matching tail query consumes checkpoint"
    );
    observer.set_query(&history);
    client.publish_conversation_captures(&f.group);
    history.opening.target = ConversationOpenTarget::Message(id(11));
    observer.set_query(&history);
    assert!(
        observer.take().is_none(),
        "another viewport cannot consume the tail capture"
    );
    observer.set_query(&query);
    assert!(
        observer.take().is_none(),
        "intermediate navigation invalidates the speculative tail capture"
    );

    let other_group = client.create_group("unrelated window", &[]).await.unwrap();
    f.store
        .refresh_chat_list_row(&f.account, &hex::encode(other_group.as_slice()), &|_, _| {
            false
        })
        .unwrap();
    let other = Arc::new(SendCapture::new(
        other_group.clone(),
        f.store.chat_presentation_version().unwrap().store_epoch,
        query.clone(),
    ));
    client.register_conversation_capture(Some(Arc::downgrade(&other)));
    client.publish_conversation_captures(&f.group);
    assert!(
        other.take().is_none(),
        "sending must not recapture unrelated groups"
    );
    client.publish_conversation_captures(&other_group);
    assert!(
        other.take().is_some(),
        "the unrelated window is a valid registered capture"
    );
    drop(other);

    // A viewport change invalidates the previous capture, including a change
    // that fails to resolve. It must not fall back to the previous viewport.
    client.publish_conversation_captures(&f.group);
    let mut missing = query.clone();
    missing.opening.target = ConversationOpenTarget::Message("ff".repeat(32));
    observer.set_query(&missing);
    assert!(observer.take().is_none());
    client.publish_conversation_captures(&f.group);
    assert!(observer.take().is_none());
    observer.set_query(&query);
    f.app
        .set_group_self_membership("alice", &f.group_hex(), crate::SelfMembership::Removed)
        .unwrap();
    client.publish_conversation_captures(&f.group);
    let captured = observer.take().unwrap();
    assert_eq!(
        captured.account.presentation_input.self_membership,
        crate::SelfMembership::Removed
    );
    assert!(captured.authority.is_some());
    client.publish_conversation_captures(&f.group);
    client.register_conversation_capture(Some(Arc::downgrade(&observer)));
    assert!(
        observer.take().is_none(),
        "normal reads supersede earlier checkpoints"
    );
    let weak = Arc::downgrade(&observer);
    drop(observer);
    client.publish_conversation_captures(&f.group);
    assert!(weak.upgrade().is_none());
    assert!(client.conversation_captures.is_empty());
    drop(client);
    f.close().await;
}

#[tokio::test]
async fn checkpoint_older_than_drained_draft_invalidation_is_followed_by_a_fresh_read() {
    let f = Fixture::new(5).await;
    let initial = f.open(ConversationOpenTarget::Latest, 5).await.snapshot;
    let worker = f.runtime.accounts.workers.lock().await[&f.account]
        .commands
        .clone();
    let query = ConversationWindowQuery {
        opening: ConversationOpenQuery {
            target: ConversationOpenTarget::Latest,
            limit: 5,
        },
        before_anchor: None,
    };
    let epoch = f.store.chat_presentation_version().unwrap().store_epoch;
    let (respond, response) = oneshot::channel();
    worker
        .send(AccountWorkerCommand::CaptureConversation {
            queued: None,
            group_id: f.group.clone(),
            query: query.clone(),
            store_epoch: epoch.clone(),
            observer: None,
            respond,
        })
        .await
        .unwrap();
    let checkpoint = response.await.unwrap().unwrap();
    let capture = Arc::new(SendCapture::new(
        f.group.clone(),
        epoch.clone(),
        query.clone(),
    ));
    capture.state.lock().unwrap().pending = Some(checkpoint);
    let reader = Reader {
        telemetry: f.runtime.shared.app_performance_telemetry().clone(),
        authority_ready: None,
        send_ready: None,
        app: f.app.clone(),
        label: "alice".into(),
        account_id: f.account.clone(),
        group: f.group.clone(),
        store_epoch: epoch,
        worker: watch::channel(Some(Ok(worker))).1,
        send_capture: capture,
    };
    let sources = Sources {
        avatars: f.app.presentation_signals.avatars.subscribe(),
        events: f.runtime.events.subscribe(),
        profiles: f.app.presentation_signals.profile_updates.subscribe(),
        presentation: f.app.presentation_signals.updates.subscribe(),
        drafts: f.app.presentation_signals.drafts.subscribe(),
        stopping: f.runtime.shared.lifecycle().subscribe_shutdown(),
    };
    let resets = f.app.presentation_signals.account_resets.subscribe();
    // Deliberately enqueue this between the checkpoint and run's first drain.
    // No subsequent invalidation or send completion will rescue a stale read.
    f.draft("written after checkpoint");
    let (commands, command_rx) = mpsc::channel(8);
    let (updates, mut changes) = watch::channel(Ok(initial.clone()));
    let actor = tokio::spawn(run(
        reader, query, initial, sources, resets, command_rx, updates,
    ));
    let updated = timeout(Duration::from_secs(3), async {
        loop {
            changes.changed().await.unwrap();
            let snapshot = changes.borrow_and_update().clone().unwrap();
            if snapshot
                .draft
                .draft
                .as_ref()
                .is_some_and(|draft| draft.content == "written after checkpoint")
            {
                return snapshot;
            }
        }
    })
    .await;
    drop(commands);
    drop(changes);
    actor.await.unwrap();
    f.close().await;
    assert!(
        updated.is_ok(),
        "a checkpoint must not swallow a later draft invalidation"
    );
}

#[tokio::test]
async fn busy_live_window_keeps_complete_snapshot_until_coherent_membership_update() {
    let f = Fixture::new(8).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    assert!(sub.snapshot.presentation.header.capabilities.can_send);
    f.mode.store(5, Ordering::SeqCst);
    let handle = sub.window_handle();
    let revision = sub.snapshot.revision.clone();
    let mut read = tokio::spawn(async move { handle.return_to_latest(&revision).await });
    timeout(Duration::from_secs(5), f.captured.notified())
        .await
        .unwrap();
    f.app
        .set_group_self_membership("alice", &f.group_hex(), crate::SelfMembership::Removed)
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), &mut read)
            .await
            .is_err()
    );
    // A delayed live capture must not publish either downgraded permissions
    // or fresh membership combined with the old live authority.
    assert!(
        timeout(Duration::from_millis(100), sub.recv())
            .await
            .is_err()
    );
    f.mode.store(0, Ordering::SeqCst);
    f.release.notify_one();
    let updated = timeout(Duration::from_millis(500), read)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(updated.presentation.header.epoch.is_some());
    assert!(!updated.presentation.header.capabilities.can_send);
    assert_eq!(
        updated.presentation.header.capabilities.participation,
        crate::conversation_presentation::ConversationParticipation::Removed
    );
    let streamed = next(&mut sub).await;
    assert_eq!(streamed.revision.sequence, updated.revision.sequence);
    assert!(!streamed.presentation.header.capabilities.can_send);
    f.close().await;
}

#[tokio::test]
async fn busy_live_window_does_not_disable_composer() {
    let f = Fixture::new(8).await;
    let mut sub = f.open(ConversationOpenTarget::Latest, 5).await;
    f.mode.store(1, Ordering::SeqCst);
    f.draft("changed while sync is busy");
    assert!(
        timeout(Duration::from_millis(150), sub.recv())
            .await
            .is_err()
    );
    assert!(sub.snapshot.presentation.header.capabilities.can_send);
    f.mode.store(2, Ordering::SeqCst);
    assert!(
        matches!(
            timeout(Duration::from_secs(3), sub.recv()).await.unwrap(),
            Err(ConversationWindowError::App(_))
        ),
        "quiet NotReady must not hide a later storage failure"
    );
    f.mode.store(0, Ordering::SeqCst);
    let updated = next(&mut sub).await;
    assert!(updated.presentation.header.capabilities.can_send);
    assert!(updated.presentation.header.epoch.is_some());
    assert_eq!(
        updated.draft.draft.as_ref().unwrap().content,
        "changed while sync is busy"
    );
    f.close().await;
}

#[tokio::test]
async fn transient_worker_acquisition_failure_retries_without_closing_local_window() {
    let f = Fixture::new(8).await;
    let worker = f
        .runtime
        .accounts
        .workers
        .lock()
        .await
        .remove(&f.account)
        .unwrap();
    worker.shutdown().await;
    f.runtime
        .accounts
        .set_account_tearing_down(&f.account, true);
    let mut sub = f
        .runtime
        .open_conversation_window(
            "alice",
            &f.group,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Latest,
                limit: 5,
            },
        )
        .await
        .unwrap();
    // Reconcile deliberately cannot start this account yet. That temporary
    // missing-worker result must not become a terminal stream error.
    assert!(
        timeout(Duration::from_millis(150), sub.recv())
            .await
            .is_err()
    );
    f.draft("still usable locally");
    let local = next(&mut sub).await;
    assert!(local.presentation.header.epoch.is_none());
    assert_eq!(
        local.draft.draft.as_ref().unwrap().content,
        "still usable locally"
    );
    f.runtime
        .accounts
        .set_account_tearing_down(&f.account, false);
    let live = next(&mut sub).await;
    assert!(live.presentation.header.epoch.is_some());
    assert!(live.presentation.header.capabilities.can_send);
    f.close().await;
}

#[tokio::test]
async fn closing_window_cannot_abandon_reconcile_worker_teardown() {
    let f = Fixture::new(8).await;
    // A missing requested worker forces reconciliation of the stale worker.
    f.runtime
        .accounts
        .workers
        .lock()
        .await
        .remove(&f.account)
        .unwrap()
        .shutdown()
        .await;
    let (commands, _rx) = mpsc::channel(8);
    let (shutdown, stopping) = oneshot::channel();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let entered_task = entered.clone();
    let release_task = release.clone();
    let handle = tokio::spawn(async move {
        let _ = stopping.await;
        entered_task.notify_one();
        release_task.notified().await;
    });
    f.runtime.accounts.workers.lock().await.insert(
        "stale account".into(),
        ManagedAccountWorker {
            ready: true,
            handle,
            commands,
            shutdown,
            media_admission: Arc::new(Semaphore::new(1)),
        },
    );
    let mut sub = f
        .runtime
        .open_conversation_window(
            "alice",
            &f.group,
            ConversationOpenQuery {
                target: ConversationOpenTarget::Latest,
                limit: 5,
            },
        )
        .await
        .unwrap();
    timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    // Reconcile is awaiting stale-worker teardown inside worker_transactions.
    // Local invalidations must stay usable while that lifecycle work progresses.
    f.draft("local during worker teardown");
    let local = timeout(Duration::from_millis(500), sub.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(local.presentation.header.epoch.is_none());
    assert_eq!(
        local.draft.draft.as_ref().unwrap().content,
        "local during worker teardown"
    );
    drop(sub);
    let runtime = f.runtime.clone();
    let mut closing = tokio::spawn(async move { runtime.shutdown_and_close().await });
    assert!(
        timeout(Duration::from_millis(150), &mut closing)
            .await
            .is_err(),
        "shutdown must still own the stale worker until its teardown finishes"
    );
    release.notify_one();
    timeout(Duration::from_secs(10), closing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn live_window_waits_for_queue_capacity_without_a_display_retry_delay() {
    let f = Fixture::new(8).await;
    let sub = f.open(ConversationOpenTarget::Latest, 5).await;
    let sender = f
        .runtime
        .accounts
        .workers
        .lock()
        .await
        .get(&f.account)
        .unwrap()
        .commands
        .clone();
    let permits = sender.reserve_many(8).await.unwrap();
    let handle = sub.window_handle();
    let revision = sub.snapshot.revision.clone();
    let mut read = tokio::spawn(async move { handle.return_to_latest(&revision).await });
    assert!(
        timeout(Duration::from_millis(100), &mut read)
            .await
            .is_err(),
        "an established window must retain its queued capture beyond the display budget"
    );
    f.add(8);
    f.draft("stored while command queue was full");
    drop(permits);
    let updated = timeout(Duration::from_millis(500), read)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(updated.presentation.header.capabilities.can_send);
    assert!(updated.presentation.header.epoch.is_some());
    assert_eq!(ids(&updated).last(), Some(&id(8)));
    assert_eq!(
        updated.draft.draft.as_ref().unwrap().content,
        "stored while command queue was full"
    );

    // Waiting for capacity is still interrupted by window closure, even if
    // an outstanding command clone keeps its own channel alive.
    let permits = sender.reserve_many(8).await.unwrap();
    let handle = sub.window_handle();
    let mut closing_read =
        tokio::spawn(async move { handle.return_to_latest(&updated.revision).await });
    assert!(
        timeout(Duration::from_millis(100), &mut closing_read)
            .await
            .is_err()
    );
    drop(sub);
    assert!(matches!(
        timeout(Duration::from_millis(500), closing_read)
            .await
            .unwrap()
            .unwrap(),
        Err(ConversationWindowError::Closed)
    ));
    drop(permits);
    f.close().await;
}

#[tokio::test]
async fn avatar_identity_sidecar_tracks_local_bytes_without_new_timeline_activity() {
    let f = Fixture::new(2).await;
    let member = "bb".repeat(32);
    let mut record = f.app.empty_directory_record(&member);
    record.profile = Some(crate::UserProfileMetadata {
        picture: Some("https://example.com/avatar.png".into()),
        created_at: 42,
        ..Default::default()
    });
    f.app.save_directory_entry(&record).unwrap();
    let mut sub = f.open(ConversationOpenTarget::Latest, 2).await;
    let asset = sub.snapshot.presentation.identities[&member]
        .avatar_asset
        .clone()
        .unwrap();
    assert!(asset.reference.is_none());
    let requested = f
        .runtime
        .request_avatar_assets("alice", vec![asset.target])
        .await
        .unwrap();
    let reference = requested[0].reference.clone().unwrap();
    let image =
        storage_sqlite::AvatarImage::new(vec![1; 8], storage_sqlite::AvatarImageFormat::Png, 1, 1)
            .unwrap();
    f.store.publish_avatar(&reference, 0, &image, None).unwrap();
    for _ in 0..100 {
        let _ = f.app.presentation_signals.avatars.send("alice".into());
    }
    let update = next(&mut sub).await;
    assert_eq!(
        update.presentation.identities[&member]
            .avatar_asset
            .as_ref()
            .unwrap()
            .status
            .availability,
        storage_sqlite::AvatarAvailability::Ready
    );
    assert_eq!(update.page.page(), sub.snapshot.page.page());
    let bytes = f
        .runtime
        .read_avatar_assets("alice", vec![reference.clone()], 8)
        .await
        .unwrap();
    assert_eq!(bytes[0].result.image, Some(image));
    f.runtime.clear_avatar_cache("alice").await.unwrap();
    let removed = next(&mut sub).await;
    assert!(
        removed.presentation.identities[&member]
            .avatar_asset
            .as_ref()
            .unwrap()
            .reference
            .is_none()
    );
    f.close().await;
}

#[tokio::test]
async fn closing_a_cold_window_accounts_for_unfinished_readiness() {
    let f = Fixture::new(1).await;
    f.mode.store(1, Ordering::SeqCst);
    let sub = f
        .runtime
        .open_conversation_window("alice", &f.group, ConversationOpenQuery::default())
        .await
        .unwrap();
    let handle = sub.window_handle();
    let revision = sub.snapshot.revision.clone();
    let telemetry = f.runtime.shared.app_performance_telemetry();
    drop(sub);
    assert!(matches!(
        timeout(Duration::from_secs(2), handle.return_to_latest(&revision))
            .await
            .unwrap(),
        Err(ConversationWindowError::Closed)
    ));
    // The actor closes commands as it exits; allow its remaining fields to drop.
    timeout(Duration::from_secs(2), async {
        loop {
            let snapshots = telemetry.snapshot().runtime_operations;
            if snapshots
                .iter()
                .filter(|s| {
                    matches!(
                        s.operation,
                        RuntimeOp::ConversationAuthorityReady | RuntimeOp::ConversationSendReady
                    )
                })
                .all(|s| s.in_flight == 0 && s.cancelled == 1 && s.successes == 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    f.close().await;
}

#[tokio::test]
async fn authoritative_removed_conversation_finishes_send_readiness_as_unavailable() {
    let f = Fixture::new(1).await;
    f.app
        .set_group_self_membership("alice", &f.group_hex(), crate::SelfMembership::Removed)
        .unwrap();
    let sub = f.open(ConversationOpenTarget::Latest, 50).await;
    assert!(!sub.snapshot.presentation.header.capabilities.can_send);
    let snapshot = f.runtime.shared.app_performance_telemetry().snapshot();
    let readiness = snapshot
        .runtime_operations
        .iter()
        .find(|s| s.operation == RuntimeOp::ConversationSendReady)
        .unwrap();
    assert_eq!(
        (
            readiness.started,
            readiness.not_ready,
            readiness.in_flight,
            readiness.successes
        ),
        (1, 1, 0, 0)
    );
    f.close().await;
}

#[test]
fn return_to_latest_reuses_checkpoint_when_background_presentation_is_cancelled() {
    // Occupy the only blocking thread after setup, so presentation suspends
    // after acquiring its at-tail checkpoint. No timing race or production hook.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap()
        .block_on(async {
            let f = Fixture::new(5).await;
            let initial = f.open(ConversationOpenTarget::Latest, 5).await.snapshot;
            let worker = f.runtime.accounts.workers.lock().await[&f.account]
                .commands
                .clone();
            let query = ConversationWindowQuery {
                opening: ConversationOpenQuery {
                    target: ConversationOpenTarget::Latest,
                    limit: 5,
                },
                before_anchor: None,
            };
            let epoch = f.store.chat_presentation_version().unwrap().store_epoch;
            f.draft("checkpoint composer");
            let (respond, response) = oneshot::channel();
            worker
                .send(AccountWorkerCommand::CaptureConversation {
                    queued: None,
                    group_id: f.group.clone(),
                    query: query.clone(),
                    store_epoch: epoch.clone(),
                    observer: None,
                    respond,
                })
                .await
                .unwrap();
            let capture = Arc::new(SendCapture::new(
                f.group.clone(),
                epoch.clone(),
                query.clone(),
            ));
            capture.state.lock().unwrap().pending = Some(response.await.unwrap().unwrap());
            assert!(capture.state.lock().unwrap().latest.is_none());
            // Any fallback worker read stays blocked, like relay publication.
            f.mode.store(5, Ordering::SeqCst);
            let telemetry = f.runtime.shared.app_performance_telemetry().clone();
            let reader = Reader {
                telemetry: telemetry.clone(),
                authority_ready: None,
                send_ready: None,
                app: f.app.clone(),
                label: "alice".into(),
                account_id: f.account.clone(),
                group: f.group.clone(),
                store_epoch: epoch,
                worker: watch::channel(Some(Ok(worker))).1,
                send_capture: capture.clone(),
            };
            let sources = Sources {
                avatars: f.app.presentation_signals.avatars.subscribe(),
                events: f.runtime.events.subscribe(),
                profiles: f.app.presentation_signals.profile_updates.subscribe(),
                presentation: f.app.presentation_signals.updates.subscribe(),
                drafts: f.app.presentation_signals.drafts.subscribe(),
                stopping: f.runtime.shared.lifecycle().subscribe_shutdown(),
            };
            let resets = f.app.presentation_signals.account_resets.subscribe();
            let (commands, command_rx) = mpsc::channel(8);
            let (updates, changes) = watch::channel(Ok(initial.clone()));
            let (entered, blocked) = oneshot::channel();
            let (release, hold) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                let _ = hold.recv();
            });
            blocked.await.unwrap();
            let actor = tokio::spawn(run(
                reader,
                query,
                initial.clone(),
                sources,
                resets,
                command_rx,
                updates,
            ));
            timeout(Duration::from_secs(10), async {
                loop {
                    if telemetry
                        .snapshot()
                        .runtime_operations
                        .iter()
                        .any(|metric| {
                            metric.operation == RuntimeOp::ConversationPresentation
                                && metric.in_flight > 0
                        })
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let (reply, response) = oneshot::channel();
            commands
                .send(Command {
                    revision: initial.revision,
                    action: Action::Latest,
                    reply,
                })
                .await
                .unwrap();
            // Wait until run has cancelled the suspended background read and
            // begun presentation for the explicit Latest command.
            timeout(Duration::from_secs(10), async {
                loop {
                    if telemetry
                        .snapshot()
                        .runtime_operations
                        .iter()
                        .any(|metric| {
                            metric.operation == RuntimeOp::ConversationPresentation
                                && metric.cancelled > 0
                        })
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            release.send(()).unwrap();
            blocker.await.unwrap();
            let result = timeout(Duration::from_secs(10), response).await;
            drop(commands);
            drop(changes);
            actor.await.unwrap();
            f.close().await;
            let snapshot = result
                .expect("Latest waited for a worker read")
                .unwrap()
                .unwrap();
            assert_eq!(snapshot.draft.draft.unwrap().content, "checkpoint composer");
            assert!(
                capture.checkpoint().is_none(),
                "completed presentation consumes its checkpoint"
            );
        });
}

#[tokio::test]
#[ignore = "workstation capture-cost diagnostic; not a device latency threshold"]
async fn send_checkpoint_capture_cost() {
    let f = Fixture::new(200).await;
    let worker = f
        .runtime
        .accounts
        .workers
        .lock()
        .await
        .remove(&f.account)
        .unwrap();
    worker.shutdown().await;
    let mut client = f.app.client("alice").await.unwrap();
    let epoch = f.store.chat_presentation_version().unwrap().store_epoch;
    for (label, target) in [
        ("tail", ConversationOpenTarget::Latest),
        ("history", ConversationOpenTarget::Message(id(50))),
    ] {
        let query = ConversationWindowQuery {
            opening: ConversationOpenQuery { target, limit: 50 },
            before_anchor: None,
        };
        let observer = Arc::new(SendCapture::new(
            f.group.clone(),
            epoch.clone(),
            query.clone(),
        ));
        client.register_conversation_capture(Some(Arc::downgrade(&observer)));
        let mut baseline = Vec::new();
        let mut checkpoint = Vec::new();
        for trial in 0..105 {
            let start = std::time::Instant::now();
            let captured =
                capture_conversation(&mut client, &f.group, query.clone(), &epoch).unwrap();
            let single_us = start.elapsed().as_micros();
            drop(captured);
            let start = std::time::Instant::now();
            client.publish_conversation_captures(&f.group);
            let publish_us = start.elapsed().as_micros();
            assert!(observer.take().is_some());
            if trial >= 5 {
                baseline.push(single_us);
                checkpoint.push(publish_us);
            }
        }
        baseline.sort_unstable();
        checkpoint.sort_unstable();
        eprintln!(
            "{label}: single capture p50/p95={}/{} us; send checkpoints p50/p95={}/{} us",
            baseline[49], baseline[94], checkpoint[49], checkpoint[94]
        );
    }
    drop(client);
    f.close().await;
}
