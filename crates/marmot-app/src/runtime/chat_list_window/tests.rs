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
        Self::with_base_rows(count, true)
    }
    fn with_base_rows(count: usize, prepared: bool) -> Self {
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
        if prepared {
            store
                .refresh_chat_list_rows(&account.account_id_hex, &|_, _| false)
                .unwrap();
        }
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
    let sender = nostr::prelude::Keys::generate().public_key().to_hex();
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
            account_id_hex: sender.clone(),
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
    // Pin the invalidation boundary independently of the producer's current
    // lowercase normalization, using a committed profile with no other wakeup.
    let shared = f.app.shared_storage().unwrap();
    let mut record = shared.public_directory_user(&sender).unwrap().unwrap();
    record.profile_json = Some(
        serde_json::to_string(&UserProfileMetadata {
            display_name: Some("Case-insensitive update".into()),
            created_at: 201,
            ..Default::default()
        })
        .unwrap(),
    );
    shared.put_public_directory_user(&record).unwrap();
    let _ = f
        .app
        .presentation_signals
        .profile_updates
        .send(sender.to_uppercase());
    let updated = next(&mut sub).await;
    assert_eq!(
        updated.rows[0]
            .row
            .last_message
            .as_ref()
            .unwrap()
            .sender_display_name
            .as_deref(),
        Some("Case-insensitive update")
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

#[tokio::test]
async fn initial_open_repairs_multiple_base_batches_without_a_worker_or_full_list_warm() {
    let f = Fixture::with_base_rows(120, false);
    assert!(!f.store.pending_chat_presentation_rows().unwrap().is_empty());
    let sub = tokio::time::timeout(
        Duration::from_secs(10),
        f.runtime
            .open_chat_list_window("alice", ChatListView::Chats, Some(20)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(sub.snapshot.rows.len(), 20);
    assert_eq!(ids(&sub.snapshot).first().copied(), Some("0000"));
    assert!(sub.snapshot.has_more_after);
    assert!(f.store.pending_chat_presentation_rows().unwrap().is_empty());
    assert!(matches!(
        f.store.chat_presentation("0014").unwrap(),
        ChatPresentationRead::Pending
    ));
    assert!(f.app.chat_list_projection_warmed.lock().unwrap().is_empty());
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn invalid_window_query_is_distinct_from_readiness() {
    let f = Fixture::new(20);
    let reader = Reader {
        app: f.app.clone(),
        label: "alice".into(),
        account_id: f.account_id.clone(),
        store_epoch: vec![],
        view: ChatListView::Chats,
    };
    let result = reader
        .read(
            &Position {
                limit: 5,
                before: 5,
                anchor: None,
            },
            &[],
        )
        .await;
    assert!(matches!(result, Err(ChatListWindowError::Query(error))
        if matches!(error.as_ref(), storage_sqlite::ChatListPageError::InvalidWindowQuery)));
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn lost_reset_signal_closes_window_even_when_the_durable_epoch_is_unchanged() {
    let f = Fixture::new(20);
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(5))
        .await
        .unwrap();
    let epoch = f.store.chat_presentation_version().unwrap().store_epoch;
    // Eviction of the same account database must end this handle, even when
    // its signal is subsequently overwritten by unrelated account teardowns.
    f.app.drop_account_caches("alice");
    for i in 0..100 {
        let _ = f
            .app
            .presentation_signals
            .account_resets
            .send(format!("other-{i}"));
    }
    assert_eq!(
        f.app
            .account_storage("alice")
            .unwrap()
            .chat_presentation_version()
            .unwrap()
            .store_epoch,
        epoch
    );
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
async fn group_source_changes_refresh_selected_display_without_legacy_rebuild() {
    let f = Fixture::new(20);
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(5))
        .await
        .unwrap();
    f.mutate("0000", |g| g.profile_name = "Renamed group".into());
    crate::chat_presentation::maintenance::prepare_window(
        &f.store,
        &f.app.shared_storage().unwrap(),
        &f.account_id,
        &["0000".into()],
    )
    .unwrap();
    f.signal();
    let updated = next(&mut sub).await;
    assert!(
        matches!(&updated.rows[0].presentation.title, PresentationText::Literal(name) if name == "Renamed group")
    );
    assert!(f.app.chat_list_projection_warmed.lock().unwrap().is_empty());
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn declined_invitation_rejoins_through_real_client_flow_and_restores_chats() {
    use crate::tests::{ScriptedPushRelayClient, remember_test_member_inbox};
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
    let plane = MarmotRelayPlane::new(None, relay);
    let mut alice = app
        .client_with_relay_plane("alice", &plane, None)
        .await
        .unwrap();
    let mut bob_client = app
        .client_with_relay_plane("bob", &plane, None)
        .await
        .unwrap();
    bob_client.sync().await.unwrap();
    let group = alice
        .create_group("Invite", &[&bob.account_id_hex])
        .await
        .unwrap();
    assert!(
        bob_client
            .sync()
            .await
            .unwrap()
            .joined_groups
            .contains(&group)
    );
    let id = hex::encode(group.as_slice());
    let first = app.group("bob", &id).unwrap().unwrap();
    assert!(first.pending_confirmation);
    bob_client.decline_group_invite(&group).await.unwrap();
    let departed = app.group("bob", &id).unwrap().unwrap();
    assert!(departed.archived);
    assert_eq!(departed.self_membership, SelfMembership::Left);
    let runtime = MarmotAppRuntime::new(app.clone());
    let mut chats = runtime
        .open_chat_list_window("bob", ChatListView::Chats, Some(5))
        .await
        .unwrap();
    let mut left = runtime
        .open_chat_list_window("bob", ChatListView::Left, Some(5))
        .await
        .unwrap();
    assert!(chats.snapshot.rows.is_empty());
    assert_eq!(ids(&left.snapshot), [id.as_str()]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !bob_client.runtime.group_record(&group).unwrap().removed {
        alice.sync().await.unwrap();
        alice.retry_group_convergence(&group).await.unwrap();
        bob_client.sync().await.unwrap();
        bob_client
            .advance_convergence_after_runtime_sync(&group)
            .await
            .unwrap();
        assert!(tokio::time::Instant::now() < deadline, "leave must settle");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bob_client.rotate_key_package().await.unwrap();
    alice
        .invite_members(&group, &[&bob.account_id_hex])
        .await
        .unwrap();
    assert!(
        bob_client
            .sync()
            .await
            .unwrap()
            .joined_groups
            .contains(&group)
    );
    let rejoined = app.group("bob", &id).unwrap().unwrap();
    assert!(rejoined.pending_confirmation);
    assert!(!rejoined.archived);
    assert_eq!(rejoined.self_membership, SelfMembership::Member);
    assert_ne!(
        rejoined.via_welcome_message_id_hex,
        first.via_welcome_message_id_hex
    );
    // Direct AppClient use has no runtime event relay; notify the already-open
    // windows after the real engine and worker projection path has committed.
    let _ = app
        .presentation_signals
        .updates
        .send(PresentationInvalidation {
            account_label: "bob".into(),
            version: app
                .account_storage("bob")
                .unwrap()
                .chat_presentation_version()
                .unwrap(),
        });
    assert_eq!(ids(&next(&mut chats).await), [id.as_str()]);
    assert!(next(&mut left).await.rows.is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn system_preview_resolves_subject_fallback_and_refreshes_profile_without_new_activity() {
    let f = Fixture::new(1);
    let actor = "bb".repeat(32);
    let subject = "cc".repeat(32);
    f.store.record_app_event(&storage_sqlite::StoredAppEvent {
        group_id_hex: "0000".into(), message_id_hex: "system-preview".into(),
        source_message_id_hex: None, source_epoch: Some(2), direction: "system".into(),
        sender: actor.clone(), kind: 1210,
        plaintext: serde_json::json!({"v":1,"system_type":"member_added","text":"Member added", "data":{"actor":actor,"subject":subject}}).to_string(),
        tags: vec![vec!["system".into(), "member_added".into()]],
        recorded_at: 100, received_at: 100, origin_commit_id: Some("commit".into()), moderation_grant: false,
    }).unwrap();
    f.store
        .refresh_chat_list_row(&f.account_id, "0000", &|_, _| false)
        .unwrap();
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(10))
        .await
        .unwrap();
    let preview = sub.snapshot.rows[0].row.last_message.as_ref().unwrap();
    let system = preview.group_system.as_ref().unwrap();
    assert_eq!(
        system.provenance,
        GroupSystemEventProvenance::AuthenticatedGroupState
    );
    assert_eq!(
        system.subject_account_id_hex.as_deref(),
        Some(subject.as_str())
    );
    assert_eq!(
        system.subject_display_name.as_deref(),
        Some(crate::profile_pseudonyms::default_profile_pseudonym(&subject).as_str())
    );
    let activity = sub.snapshot.rows[0].row.activity_sort_at;
    f.app
        .save_directory_entry(&UserDirectoryRecord {
            account_id_hex: subject.clone(),
            npub: "fixture".into(),
            local_account: None,
            profile: Some(UserProfileMetadata {
                display_name: Some("  New member  ".into()),
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
    let preview = updated.rows[0].row.last_message.as_ref().unwrap();
    let system = preview.group_system.as_ref().unwrap();
    assert_eq!(system.subject_display_name.as_deref(), Some("New member"));
    assert_eq!(system.actor_account_id_hex.as_deref(), Some(actor.as_str()));
    assert_eq!(preview.message_id_hex, "system-preview");
    assert_eq!(updated.rows[0].row.activity_sort_at, activity);
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn avatar_batches_are_local_bounded_and_update_attached_windows_after_lag() {
    let f = Fixture::new(3);
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(3))
        .await
        .unwrap();
    let asset = sub
        .snapshot
        .rows
        .iter()
        .find_map(|r| r.avatar_asset.clone())
        .unwrap();
    let requested = f
        .runtime
        .request_avatar_assets("alice", vec![asset.target.clone()])
        .await
        .unwrap();
    let reference = requested[0].reference.clone().unwrap();
    let mut signals = f.app.presentation_signals.avatars.subscribe();
    for _ in 0..3 {
        f.runtime
            .request_avatar_assets("alice", vec![asset.target.clone()])
            .await
            .unwrap();
        let missing = f
            .runtime
            .read_avatar_assets("alice", vec![reference.clone()], 16)
            .await
            .unwrap();
        assert_eq!(
            missing[0].result.status.availability,
            AvatarAvailability::Missing
        );
        assert!(!missing[0].result.repaired);
    }
    f.runtime
        .request_avatar_assets("alice", vec![])
        .await
        .unwrap();
    assert!(matches!(
        signals.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let image =
        storage_sqlite::AvatarImage::new(vec![8; 16], storage_sqlite::AvatarImageFormat::Png, 1, 1)
            .unwrap();
    f.store.publish_avatar(&reference, 0, &image, None).unwrap();
    // A paused consumer loses individual notifications, then converges from storage.
    for _ in 0..100 {
        let _ = f.app.presentation_signals.avatars.send("alice".into());
    }
    let update = next(&mut sub).await;
    assert!(update.rows.iter().any(|r| {
        r.avatar_asset
            .as_ref()
            .is_some_and(|a| a.status.availability == AvatarAvailability::Ready)
    }));
    let reads = f
        .runtime
        .read_avatar_assets("alice", vec![reference.clone(), reference.clone()], 16)
        .await
        .unwrap();
    assert_eq!(reads[0].result.image, Some(image.clone()));
    assert!(reads[1].deferred);
    assert!(reads[1].result.image.is_none());
    assert_eq!(
        reads[1].result.status.availability,
        AvatarAvailability::Ready
    );
    assert!(
        f.runtime
            .read_avatar_assets("alice", vec![reference.clone(); 17], 16)
            .await
            .is_err()
    );
    assert!(
        f.runtime
            .read_avatar_assets("alice", vec![], MAX_AVATAR_BATCH_BYTES + 1)
            .await
            .is_err()
    );
    assert!(
        f.runtime
            .request_avatar_assets("alice", vec![asset.target.clone(); 17])
            .await
            .is_err()
    );
    f.runtime.clear_avatar_cache("alice").await.unwrap();
    let cleared = next(&mut sub).await;
    assert!(
        cleared
            .rows
            .iter()
            .filter_map(|r| r.avatar_asset.as_ref())
            .all(|a| a.reference.is_none())
    );
    assert_eq!(
        f.runtime
            .read_avatar_assets("alice", vec![reference], 16)
            .await
            .unwrap()[0]
            .result
            .status
            .availability,
        AvatarAvailability::Invalidated
    );
    let new = f
        .runtime
        .request_avatar_assets("alice", vec![asset.target])
        .await
        .unwrap();
    let restored = new[0].reference.clone().unwrap();
    f.store.publish_avatar(&restored, 0, &image, None).unwrap();
    f.runtime.shutdown_and_close().await.unwrap();
    assert!(sub.recv().await.unwrap().is_none());
    // Reconstruct only the local app/runtime. No worker or relay is started.
    let reopened = MarmotApp::with_relay(f._dir.path(), "wss://relay.example").runtime();
    let retained = reopened
        .read_avatar_assets("alice", vec![restored], 16)
        .await
        .unwrap();
    assert_eq!(retained[0].result.image, Some(image));
    reopened.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn draft_preview_updates_both_list_contracts_without_reordering_or_network() {
    let f = Fixture::with_base_rows(3, true);
    let mut window = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(3))
        .await
        .unwrap();
    let mut legacy = f
        .runtime
        .open_presented_chat_list("alice", false)
        .await
        .unwrap();
    let original = window.snapshot.clone();
    let group = original.rows[0].row.group_id_hex.clone();
    f.app
        .save_message_draft("alice", &group, "first draft", None, vec![])
        .unwrap();
    let changed = next(&mut window).await;
    assert_eq!(ids(&changed), ids(&original));
    assert_eq!(
        changed.rows[0].row.activity_sort_at,
        original.rows[0].row.activity_sort_at
    );
    assert_eq!(
        changed.rows[0].row.unread_count,
        original.rows[0].row.unread_count
    );
    assert!(
        matches!(&changed.rows[0].preview, crate::SelectedChatPreview::Draft(d) if d.text == "first draft")
    );
    let update = tokio::time::timeout(Duration::from_secs(5), legacy.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(update.snapshot.rows.iter().any(|r| r.row.group_id_hex == group && matches!(&r.preview, crate::SelectedChatPreview::Draft(d) if d.text == "first draft")));
    // Revision protection is shared with the composer, not a second list cache.
    let old = f.app.selected_message_draft("alice", &group).unwrap();
    f.app
        .save_message_draft("alice", &group, "newer edit", None, vec![])
        .unwrap();
    assert!(
        f.app
            .clear_message_draft_if_revision("alice", &old.revision)
            .is_err()
    );
    assert!(
        matches!(&next(&mut window).await.rows[0].preview, crate::SelectedChatPreview::Draft(d) if d.text == "newer edit")
    );
    f.app.delete_message_draft("alice", &group).unwrap();
    let cleared = next(&mut window).await;
    assert_eq!(cleared.rows[0].preview, original.rows[0].preview);
    assert_eq!(ids(&cleared), ids(&original));
    // A one-shot keyed read has exactly the same selection contract.
    f.app
        .save_message_draft("alice", &group, "after reopen", None, vec![])
        .unwrap();
    let row = f
        .runtime
        .presented_chat_list_row("alice", &group)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(&row.preview, crate::SelectedChatPreview::Draft(d) if d.text == "after reopen")
    );
    drop(window);
    let reopened = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(3))
        .await
        .unwrap();
    assert_eq!(reopened.snapshot.rows[0].preview, row.preview);
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn chat_list_draft_acceptance_rollback_and_lag_use_authoritative_store() {
    use cgka_traits::storage::{
        GroupStorage, OutboundIntentStorage, QueuedOutboundIntent, StorageProvider,
    };
    use cgka_traits::{GroupId, MessageId, SendIntent};
    let f = Fixture::new(1);
    f.app
        .save_message_draft("alice", "0000", "send", None, vec![])
        .unwrap();
    let selected = f.app.selected_message_draft("alice", "0000").unwrap();
    let mut sub = f
        .runtime
        .open_chat_list_window("alice", ChatListView::Chats, Some(1))
        .await
        .unwrap();
    let group_id = GroupId::new(vec![0, 0]);
    f.store
        .put_group(&cgka_traits::group::Group {
            id: group_id.clone(),
            name: "fixture".into(),
            description: String::new(),
            epoch: cgka_traits::EpochId(0),
            members: vec![],
            required_capabilities: Default::default(),
            protocol_profile: cgka_traits::group::ProtocolProfile::Legacy,
            removed: false,
            unrecoverable: false,
            disbanded: None,
            join_epoch: cgka_traits::EpochId(0),
            local_copy_install_epoch: cgka_traits::EpochId(0),
            local_copy_welcome_created_at: None,
        })
        .unwrap();
    let intent = QueuedOutboundIntent {
        id: MessageId::new(vec![3; 32]),
        group_id: group_id.clone(),
        intent: SendIntent::AppMessage {
            group_id,
            payload: b"payload".to_vec(),
            expected_epoch: None,
        },
        created_at_ms: 1,
        reissue_attempts: 0,
    };
    // Production draft send installs this observer on the accepting engine session.
    f.store
        .set_message_draft_commit_observer(f.app.draft_commit_observer("alice"));
    f.store
        .stage_message_draft_submission(&selected.revision, "event", b"payload")
        .unwrap();
    let result: Result<(), cgka_traits::storage::StorageError> = f.store.with_transaction(|s| {
        s.put_queued_outbound_intent(&intent)?;
        assert!(s.selected_message_draft("0000")?.draft.is_none());
        Err(cgka_traits::storage::StorageError::Backend(
            "rollback".into(),
        ))
    });
    assert!(result.is_err());
    assert!(
        f.app
            .selected_message_draft("alice", "0000")
            .unwrap()
            .draft
            .is_some()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), sub.recv())
            .await
            .is_err()
    );
    // Acceptance commits the queue+clear and invokes the existing after-commit observer.
    f.store.put_queued_outbound_intent(&intent).unwrap();
    assert_eq!(
        next(&mut sub).await.rows[0].preview,
        crate::SelectedChatPreview::Empty
    );
    // Saturate the draft channel without relying on another external message to wake it.
    for _ in 0..2048 {
        let _ = f
            .app
            .presentation_signals
            .drafts
            .send(crate::drafts::MessageDraftInvalidation {
                account_label: "alice".into(),
                group_id_hex: "0000".into(),
            });
    }
    f.app
        .save_message_draft("alice", "0000", "after lag", None, vec![])
        .unwrap();
    assert!(
        matches!(&next(&mut sub).await.rows[0].preview, crate::SelectedChatPreview::Draft(d) if d.text == "after lag")
    );
    f.runtime.shutdown_and_close().await.unwrap();
}

#[test]
fn chat_list_leave_hint_agrees_with_conversation_authority_for_projected_states() {
    use crate::conversation_presentation::{ConversationAuthority, ConversationParticipation};
    use cgka_traits::GroupLifecycleState as L;
    let f = Fixture::new(1);
    let mut row = f.store.chat_list_row("0000").unwrap().unwrap();
    // Compare independently implemented public policies, including admin preflight.
    // Engine-only facts are deliberately tested separately below: list rendering
    // must not hydrate an engine just to obtain those facts.
    for membership in [
        SelfMembership::Member,
        SelfMembership::Left,
        SelfMembership::Removed,
    ] {
        for lifecycle in [
            L::Stable,
            L::PendingPublish,
            L::Merging,
            L::Recovering,
            L::Unrecoverable,
            L::Disbanded,
        ] {
            for pending in [false, true] {
                for leaving in [false, true] {
                    for disbanding in [false, true] {
                        for admin in [false, true] {
                            row.self_membership = membership;
                            row.lifecycle_state = lifecycle;
                            row.pending_confirmation = pending;
                            row.leave_requested_at_ms = leaving.then_some(1);
                            row.disbanding = disbanding;
                            let authority = ConversationAuthority {
                                is_member: membership == SelfMembership::Member,
                                self_membership: membership,
                                is_admin: admin,
                                admin_count: 1,
                                pending_confirmation: pending,
                                leave_request_pending: leaving,
                                lifecycle: lifecycle.into(),
                                unrecoverable: false,
                                disbanding,
                                disbanding_enabled: false,
                                has_disbanding_blockers: false,
                            };
                            let capabilities = authority.capabilities();
                            assert_eq!(
                                ChatListRowActions::for_row(&row).can_start_leave,
                                capabilities.can_leave
                                    || capabilities.requires_self_demote_before_leave,
                                "{authority:?}"
                            );
                        }
                    }
                }
            }
        }
    }
    let row = f.store.chat_list_row("0000").unwrap().unwrap();
    assert!(ChatListRowActions::for_row(&row).can_start_leave);
    for (is_member, unrecoverable, participation) in [
        (false, false, ConversationParticipation::Unavailable),
        (true, true, ConversationParticipation::Active),
    ] {
        let capabilities = ConversationAuthority {
            is_member,
            self_membership: row.self_membership,
            is_admin: false,
            admin_count: 1,
            pending_confirmation: false,
            leave_request_pending: false,
            lifecycle: row.lifecycle_state.into(),
            unrecoverable,
            disbanding: false,
            disbanding_enabled: false,
            has_disbanding_blockers: false,
        }
        .capabilities();
        assert_eq!(capabilities.participation, participation);
        assert!(!capabilities.can_leave && !capabilities.requires_self_demote_before_leave);
    }
}
