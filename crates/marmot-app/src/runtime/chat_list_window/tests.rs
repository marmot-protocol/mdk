use super::*;
use crate::*;
use marmot_account::AccountHome;
use storage_sqlite::{ChatPresentationRead, SqliteAccountStorage, StoredAccountState};

struct Fixture {
    _dir: tempfile::TempDir,
    app: MarmotApp,
    runtime: MarmotAppRuntime,
    account_id: String,
    store: SqliteAccountStorage,
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
                if i % 3 == 1 {
                    group.profile.name.clear();
                    group.member_count = Some(2);
                    group.presentation_member_ids_hex =
                        Some(vec![account.account_id_hex.clone(), "bb".repeat(32)]);
                } else {
                    group.avatar_url = AppGroupAvatarUrlComponent::new(
                        "https://example.com/avatar.png".into(),
                        None,
                        None,
                    )
                    .unwrap();
                    if i % 3 == 0 {
                        group.image = AppGroupImageComponent::new(AppGroupImageInput {
                            image_hash_hex: "11".repeat(32),
                            image_key_hex: "22".repeat(32),
                            image_nonce_hex: "33".repeat(12),
                            image_upload_key_hex: "44".repeat(32),
                            media_type: Some("image/png".into()),
                        });
                    }
                }
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
            account_id: account.account_id_hex,
            store,
        }
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
    fn mutate(&self, id: &str, change: impl FnOnce(&mut storage_sqlite::StoredAccountGroup)) {
        let mut state = self
            .store
            .load_account_projection_state("alice", 100)
            .unwrap();
        change(
            state
                .groups
                .iter_mut()
                .find(|g| g.group_id_hex == id)
                .unwrap(),
        );
        self.store
            .save_account_projection_state(&state, 100, 120)
            .unwrap();
        self.signal();
    }
}
async fn next(sub: &mut RuntimeChatListWindowSubscription) -> ChatListWindowSnapshot {
    tokio::time::timeout(Duration::from_secs(10), sub.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}
fn ids(window: &ChatListWindowSnapshot) -> Vec<&str> {
    window
        .rows
        .iter()
        .map(|r| r.row.group_id_hex.as_str())
        .collect()
}

#[tokio::test]
async fn first_window_prepares_only_selected_rows_and_never_opens_legacy_list() {
    let f = Fixture::new(240);
    let before = f.runtime.events.receiver_count();
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(20))
        .await
        .unwrap();
    assert_eq!(sub.snapshot.rows.len(), 20);
    assert!(
        matches!(
            sub.snapshot.rows[0].presentation.avatar,
            SelectedAvatar::EncryptedGroupImage { .. }
        ),
        "encrypted avatar wins over the simultaneous URL"
    );
    assert!(
        sub.snapshot.rows[1].presentation.peer_id.is_some(),
        "unnamed direct chats use selected peer presentation"
    );
    assert!(matches!(
        sub.snapshot.rows[2].presentation.avatar,
        SelectedAvatar::RemoteImage { .. }
    ));
    assert!(!sub.snapshot.has_more_before);
    assert!(sub.snapshot.has_more_after);
    assert_eq!(f.runtime.events.receiver_count(), before + 1);
    assert!(
        f.app.chat_list_projection_warmed.lock().unwrap().is_empty(),
        "bounded path must not warm a legacy full list"
    );
    assert!(matches!(
        f.store.chat_presentation("0013").unwrap(),
        ChatPresentationRead::Ready(_)
    ));
    assert!(matches!(
        f.store.chat_presentation("0014").unwrap(),
        ChatPresentationRead::Pending
    ));
    // Commit after initial snapshot, before receiver begins: no handoff gap.
    f.store
        .set_chat_manually_unread(&f.account_id, "0000", true, &|_, _| false)
        .unwrap();
    f.signal();
    let update = next(&mut sub).await;
    assert!(update.rows[0].row.has_unread);
    assert!(update.sequence > 0);
    assert_eq!(
        update.subscription_generation,
        sub.snapshot.subscription_generation
    );
    let handle = sub.window_handle();
    drop(sub);
    tokio::time::timeout(Duration::from_secs(5), async {
        while f.runtime.events.receiver_count() != before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        handle.return_to_top(update.sequence).await,
        Err(ChatListWindowError::Closed)
    ));
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn paging_while_recv_waits_slides_capped_window_and_rejects_old_commands() {
    let f = Fixture::new(450);
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(100))
        .await
        .unwrap();
    let handle = sub.window_handle();
    let (paged, received) = tokio::join!(
        handle.page(0, ChatListPageDirection::Forward, 100),
        next(&mut sub)
    );
    let paged = paged.unwrap();
    assert_eq!(paged, received);
    assert_eq!(paged.rows.len(), 200);
    assert_eq!(paged.anchor, ChatListAnchorOutcome::Top);
    assert!(matches!(
        handle.return_to_top(0).await,
        Err(ChatListWindowError::StaleWindow)
    ));
    assert!(matches!(
        handle
            .page(paged.sequence, ChatListPageDirection::Forward, 101)
            .await,
        Err(ChatListWindowError::InvalidLimit)
    ));
    let anchor = paged.rows[150].row.group_id_hex.clone();
    let anchored = handle
        .set_visible_anchor(paged.sequence, &anchor)
        .await
        .unwrap();
    let paged = handle
        .page(anchored.sequence, ChatListPageDirection::Forward, 100)
        .await
        .unwrap();
    assert_eq!(paged.rows.len(), 200);
    assert_eq!(paged.rows[50].row.group_id_hex, anchor);
    assert_eq!(ids(&paged).first().copied(), Some("0064"));
    assert!(paged.has_more_before && paged.has_more_after);
    let backwards = handle
        .page(paged.sequence, ChatListPageDirection::Backward, 100)
        .await
        .unwrap();
    assert_eq!(backwards.rows[150].row.group_id_hex, anchor);
    assert_eq!(ids(&backwards).first().copied(), Some("0000"));
    // Anchor cannot be evicted even when a request would overflow both sides.
    let protected = handle
        .set_visible_anchor(backwards.sequence, "00c7")
        .await
        .unwrap();
    let backwards = handle
        .page(protected.sequence, ChatListPageDirection::Backward, 100)
        .await
        .unwrap();
    assert!(ids(&backwards).contains(&"00c7"));
    let top = handle.return_to_top(backwards.sequence).await.unwrap();
    assert_eq!(top.anchor, ChatListAnchorOutcome::Top);
    assert_eq!(top.rows.len(), 200);
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn archive_and_anchor_loss_recover_neighbors_then_reset_without_stale_splicing() {
    let f = Fixture::new(20);
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(5))
        .await
        .unwrap();
    let h = sub.window_handle();
    let anchored = h.set_visible_anchor(0, "0002").await.unwrap();
    let _ = next(&mut sub).await;
    f.mutate("0002", |g| g.archived = true);
    let recovered = next(&mut sub).await;
    assert!(recovered.sequence > anchored.sequence);
    assert!(
        matches!(&recovered.anchor,ChatListAnchorOutcome::Recovered{group_id_hex,index:2} if group_id_hex == "0003")
    );
    assert!(!ids(&recovered).contains(&"0002"));
    assert_eq!(ids(&recovered), ["0000", "0001", "0003", "0004", "0005"]);
    // Remove anchor and every following prior neighbor: prefer the previous neighbor.
    for id in ["0003", "0004", "0005"] {
        f.mutate(id, |g| g.archived = true);
    }
    let recovered = next(&mut sub).await;
    assert!(
        matches!(&recovered.anchor,ChatListAnchorOutcome::Recovered{group_id_hex,..} if group_id_hex == "0001")
    );
    let retained_ids = ids(&recovered)
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for id in retained_ids {
        f.mutate(&id, |g| g.archived = true);
    }
    let reset = next(&mut sub).await;
    assert_eq!(reset.anchor, ChatListAnchorOutcome::Reset);
    assert!(!reset.has_more_before);
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn lag_and_cancelled_receiver_recover_without_new_events_and_mutes_expire() {
    let f = Fixture::new(20);
    f.store
        .set_chat_muted("0000", Some(crate::notifications::unix_now_ms() + 1500))
        .unwrap();
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(10))
        .await
        .unwrap();
    assert!(sub.snapshot.rows[0].row.muted);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), sub.recv())
            .await
            .is_err()
    );
    f.store
        .set_chat_manually_unread(&f.account_id, "0000", true, &|_, _| false)
        .unwrap();
    // Overflow with unrelated account events. The lost invalidation must still refresh.
    for _ in 0..1000 {
        let _ = f
            .app
            .presentation_signals
            .updates
            .send(PresentationInvalidation {
                account_label: "other".into(),
                version: f.store.chat_presentation_version().unwrap(),
            });
    }
    let unread = next(&mut sub).await;
    assert!(unread.rows[0].row.has_unread);
    let unmuted = next(&mut sub).await;
    assert!(!unmuted.rows[0].row.muted);
    assert!(unmuted.sequence > unread.sequence);
    f.runtime.shutdown_and_close().await.unwrap();
    assert!(sub.recv().await.unwrap().is_none());
}

#[tokio::test]
async fn four_views_suppress_invite_and_left_badges_without_erasing_read_intent() {
    let f = Fixture::new(4);
    for id in ["0000", "0001", "0002", "0003"] {
        f.store
            .set_chat_manually_unread(&f.account_id, id, true, &|_, _| false)
            .unwrap();
    }
    f.mutate("0001", |g| g.pending_confirmation = true);
    f.mutate("0002", |g| g.archived = true);
    f.store
        .set_group_self_membership("0003", storage_sqlite::SelfMembership::Removed)
        .unwrap();
    for (view, expected) in [
        (ChatListView::Chats, vec!["0000", "0001"]),
        (ChatListView::Unread, vec!["0000"]),
        (ChatListView::Archived, vec!["0002"]),
        (ChatListView::Left, vec!["0003"]),
    ] {
        let sub = f
            .runtime
            .open_chat_list_window("alice", view, Some(10))
            .await
            .unwrap();
        assert_eq!(sub.snapshot.view, view);
        assert_eq!(ids(&sub.snapshot), expected);
        for row in &sub.snapshot.rows {
            assert_eq!(
                row.row.has_unread,
                !row.row.pending_confirmation && view != ChatListView::Left
            );
        }
    }
    assert!(
        f.store
            .chat_list_row("0001")
            .unwrap()
            .unwrap()
            .manually_marked_unread
    );
    assert!(
        f.store
            .chat_list_row("0003")
            .unwrap()
            .unwrap()
            .manually_marked_unread
    );
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn failed_local_preparation_retries_without_another_invalidation() {
    let f = Fixture::new(20);
    let peer = "cc".repeat(32);
    let mut profile = storage_sqlite::PublicDirectoryUserRecord {
        account_id_hex: peer.clone(),
        npub: "fixture".into(),
        profile_json: Some("broken json".into()),
        relay_lists_json: "{}".into(),
        key_package_json: None,
        event_id_hex: None,
        event_kind: None,
        event_created_at: None,
        follows: vec![],
    };
    f.app
        .shared_storage()
        .unwrap()
        .put_public_directory_user(&profile)
        .unwrap();
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(10))
        .await
        .unwrap();
    f.mutate("0000", |g| {
        g.profile_name.clear();
        g.member_count = Some(2);
        g.presentation_member_ids_hex = Some(vec![f.account_id.clone(), peer.clone()]);
    });
    let error = tokio::time::timeout(Duration::from_secs(5), sub.recv())
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, ChatListWindowError::App(_)));
    // Shared persistence does not send a runtime/presentation notification. Recovery
    // must be driven by the retained failed-read obligation, not a new event.
    profile.profile_json = Some(r#"{"display_name":"Recovered peer"}"#.into());
    f.app
        .shared_storage()
        .unwrap()
        .put_public_directory_user(&profile)
        .unwrap();
    let recovered = next(&mut sub).await;
    assert!(
        matches!(&recovered.rows[0].presentation.title,PresentationText::Literal(t) if t=="Recovered peer")
    );
    assert!(recovered.sequence > sub.snapshot.sequence);
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn accepted_command_outlives_caller_and_reopen_uses_new_generation() {
    let f = Fixture::new(20);
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(5))
        .await
        .unwrap();
    let generation = sub.snapshot.subscription_generation.clone();
    let (reply, reply_rx) = oneshot::channel();
    sub.window_handle()
        .commands
        .send(Command {
            action: Action::Page(ChatListPageDirection::Forward, 5),
            sequence: 0,
            reply,
        })
        .await
        .unwrap();
    drop(reply_rx);
    let completed = next(&mut sub).await;
    assert_eq!(completed.rows.len(), 10);
    assert_eq!(completed.sequence, 1);
    drop(sub);
    f.runtime.shutdown_and_close().await.unwrap();
    // A new runtime/database incarnation invalidates old handles, but durable rows survive.
    let runtime = MarmotAppRuntime::new(
        MarmotApp::with_relay(f._dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default())),
    );
    let reopened = runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(10))
        .await
        .unwrap();
    assert_ne!(reopened.snapshot.subscription_generation, generation);
    assert_eq!(reopened.snapshot.sequence, 0);
    assert_eq!(reopened.snapshot.rows, completed.rows);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn runtime_projection_and_lifecycle_routes_update_each_view_directly() {
    let f = Fixture::new(20);
    let mut chats = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(10))
        .await
        .unwrap();
    let mut unread = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Unread, Some(10))
        .await
        .unwrap();
    let mut left = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Left, Some(10))
        .await
        .unwrap();
    f.runtime
        .set_chat_manually_unread("alice", "0000", true)
        .unwrap();
    assert!(next(&mut chats).await.rows[0].row.has_unread);
    assert_eq!(ids(&next(&mut unread).await), ["0000"]);
    // The durable operation overlay alone moves a row immediately; no full-list
    // subscription refresh or changed selected-presentation revision is needed.
    f.store
        .set_group_self_membership("0000", storage_sqlite::SelfMembership::Left)
        .unwrap();
    let _ = f.runtime.events.send(MarmotAppEvent::GroupStateUpdated {
        account_id_hex: f.account_id.clone(),
        account_label: "alice".into(),
        group_id: cgka_traits::GroupId::new(hex::decode("0000").unwrap()),
    });
    assert_eq!(ids(&next(&mut left).await), ["0000"]);
    assert!(next(&mut unread).await.rows.is_empty());
    assert!(!ids(&next(&mut chats).await).contains(&"0000"));
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn account_deactivation_closes_idle_window_even_with_surviving_command_handle() {
    let f = Fixture::new(20);
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(5))
        .await
        .unwrap();
    let handle = sub.window_handle();
    f.runtime
        .accounts
        .deactivate_account("alice")
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        handle.return_to_top(0).await,
        Err(ChatListWindowError::Closed)
    ));
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_subscription_is_attached_before_a_concurrent_storage_commit() {
    use cgka_traits::storage::{StorageError, StorageProvider};
    let f = Fixture::new(20);
    let (held_tx, held_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let store = f.store.clone();
    let account = f.account_id.clone();
    let writer = std::thread::spawn(move || {
        store
            .with_transaction(|s| -> Result<(), StorageError> {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                s.set_chat_manually_unread(&account, "0000", true, &|_, _| false)?;
                Ok(())
            })
            .unwrap();
    });
    held_rx.await.unwrap();
    let before = f.runtime.events.receiver_count();
    let runtime = f.runtime.clone();
    let opening = tokio::spawn(async move {
        runtime
            .open_chat_list_window("alice", ChatListView::Unread, Some(10))
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while f.runtime.events.receiver_count() == before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !opening.is_finished(),
        "first read must still be waiting for the writer"
    );
    release_tx.send(()).unwrap();
    writer.join().unwrap();
    let mut sub = opening.await.unwrap().unwrap();
    assert_eq!(ids(&sub.snapshot), ["0000"]);
    f.store
        .set_chat_manually_unread(&f.account_id, "0001", true, &|_, _| false)
        .unwrap();
    f.signal();
    assert_eq!(ids(&next(&mut sub).await), ["0000", "0001"]);
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn authoritative_worker_acceptance_preserves_archive_and_rejoin_restores_owner_state() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("Invite", &[]).await.unwrap();
    let id = hex::encode(group.as_slice());
    // Install the invitation's persisted confirmation state, as inbound projection does.
    client.state.groups[0].pending_confirmation = true;
    app.save_state(&client.state).unwrap();
    client.set_group_archived(&group, true).unwrap();
    let accepted = client.accept_group_invite(&group).unwrap();
    assert!(accepted.archived);
    assert!(!accepted.pending_confirmation);
    let storage = app.account_storage("alice").unwrap();
    storage
        .set_group_self_membership(&id, storage_sqlite::SelfMembership::Removed)
        .unwrap();
    let mut summary = SyncSummary::default();
    client
        .observe_event_projection_effects(
            &cgka_traits::engine::GroupEvent::GroupJoined {
                group_id: group.clone(),
                via_welcome: cgka_traits::MessageId::new(vec![2; 32]),
                welcomer: None,
                explicitly_confirmed: false,
            },
            &account.account_id_hex,
            &mut summary,
        )
        .unwrap();
    assert!(!client.state.groups[0].archived);
    app.save_state(&client.state).unwrap();
    assert!(!app.group("alice", &id).unwrap().unwrap().archived);
    assert_eq!(
        storage.group_self_membership(&id).unwrap(),
        Some(storage_sqlite::SelfMembership::Member)
    );
    // An ordinary self-arrival replay must not undo an explicit subsequent archive.
    client.set_group_archived(&group, true).unwrap();
    client
        .observe_event_projection_effects(
            &cgka_traits::engine::GroupEvent::GroupJoined {
                group_id: group,
                via_welcome: cgka_traits::MessageId::new(vec![2; 32]),
                welcomer: None,
                explicitly_confirmed: false,
            },
            &account.account_id_hex,
            &mut summary,
        )
        .unwrap();
    assert!(client.state.groups[0].archived);
    MarmotAppRuntime::new(app)
        .shutdown_and_close()
        .await
        .unwrap();
}

#[tokio::test]
async fn closing_storage_directly_terminates_an_idle_window() {
    let f = Fixture::new(20);
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(10))
        .await
        .unwrap();
    f.app.close_storage().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn preview_sender_profile_commits_refresh_at_unchanged_selected_revision() {
    let f = Fixture::new(20);
    let sender = nostr::Keys::generate().public_key().to_hex();
    f.store
        .record_app_event(&storage_sqlite::StoredAppEvent {
            group_id_hex: "0000".into(),
            message_id_hex: "11".repeat(32),
            source_message_id_hex: None,
            source_epoch: None,
            direction: "received".into(),
            sender: sender.clone(),
            plaintext: "Preview".into(),
            kind: 9,
            tags: vec![],
            recorded_at: 100,
            received_at: 100,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    f.store
        .refresh_chat_list_row(&f.account_id, "0000", &|_, _| false)
        .unwrap();
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(10))
        .await
        .unwrap();
    let version = f.store.chat_presentation_version().unwrap();
    f.app
        .save_directory_entry(&UserDirectoryRecord {
            account_id_hex: sender,
            npub: "fixture".into(),
            local_account: None,
            profile: Some(UserProfileMetadata {
                display_name: Some("New sender name".into()),
                created_at: 200,
                ..Default::default()
            }),
            follows: vec![],
            follow_source_relays: vec![],
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        })
        .unwrap();
    let updated = next(&mut sub).await;
    assert_eq!(
        f.store.chat_presentation_version().unwrap(),
        version,
        "group selection did not change"
    );
    assert_eq!(
        updated.rows[0]
            .row
            .last_message
            .as_ref()
            .unwrap()
            .sender_display_name
            .as_deref(),
        Some("New sender name")
    );
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn outside_view_navigation_changes_do_not_invalidate_visible_window_sequences() {
    let f = Fixture::new(20);
    f.mutate("0013", |g| g.archived = true);
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(5))
        .await
        .unwrap();
    f.store
        .set_group_self_membership("0013", storage_sqlite::SelfMembership::Left)
        .unwrap();
    f.signal();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), sub.recv())
            .await
            .is_err(),
        "boundary revision alone must not redraw an unchanged window"
    );
    let current = sub.window_handle().return_to_top(0).await.unwrap();
    assert_eq!(current.sequence, 1);
    assert_eq!(current.rows, sub.snapshot.rows);
    f.runtime.shutdown_and_close().await.unwrap();
}
