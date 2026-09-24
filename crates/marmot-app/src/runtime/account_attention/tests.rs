use super::*;
use crate::*;
use marmot_account::AccountHome;
use storage_sqlite::{SqliteAccountStorage, StoredAccountState};
use tokio::sync::oneshot;

struct Fixture {
    _dir: tempfile::TempDir,
    runtime: MarmotAppRuntime,
    alice: AccountSummary,
    bob: AccountSummary,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let alice = home.create_account("alice").unwrap();
        let bob = home.create_account("bob").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
        let runtime = MarmotAppRuntime::new(app);
        Self {
            _dir: dir,
            runtime,
            alice,
            bob,
        }
    }
    fn app(&self) -> &MarmotApp {
        &self.runtime.accounts.app
    }
    fn seed(&self, account: &AccountSummary, count: usize, prepare: bool) -> SqliteAccountStorage {
        self.app().ensure_account_state(&account.label).unwrap();
        let storage = self.app().account_storage(&account.label).unwrap();
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
                    "Group".into(),
                    String::new(),
                    AppGroupImageInput::default(),
                    AppGroupAdminPolicyComponent::new(vec![]),
                    AppGroupMessageRetentionComponent::disabled(),
                );
                crate::conversions::stored_group_from_app_group(&group)
            })
            .collect();
        storage
            .save_account_projection_state(
                &StoredAccountState {
                    label: account.label.clone(),
                    groups,
                    ..Default::default()
                },
                100,
                120,
            )
            .unwrap();
        if prepare {
            storage
                .refresh_chat_list_rows(&account.account_id_hex, &|_, _| false)
                .unwrap();
        }
        storage
    }
    fn signal(&self, account: &AccountSummary) {
        let _ = self.runtime.events.send(MarmotAppEvent::GroupStateUpdated {
            account_id_hex: account.account_id_hex.clone(),
            account_label: account.label.clone(),
            group_id: cgka_traits::GroupId::new(vec![0, 0]),
        });
    }
}
async fn next(sub: &mut RuntimeAccountAttentionSubscription) -> AccountAttentionSnapshot {
    tokio::time::timeout(Duration::from_secs(10), sub.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}
fn state<'a>(snapshot: &'a AccountAttentionSnapshot, id: &str) -> &'a AccountAttentionState {
    &snapshot
        .accounts
        .iter()
        .find(|a| a.account_id_hex == id)
        .unwrap()
        .state
}
fn ready(snapshot: &AccountAttentionSnapshot, id: &str) -> AccountAttentionTotal {
    let AccountAttentionState::Ready(total) = state(snapshot, id) else {
        panic!("ready account");
    };
    *total
}

#[tokio::test]
async fn independent_initial_snapshot_manual_updates_and_cancelled_recv() {
    let f = Fixture::new();
    let store = f.seed(&f.alice, 2, true);
    let before = f.runtime.events.receiver_count();
    let mut sub = f.runtime.subscribe_account_attention().await.unwrap();
    assert_eq!(sub.snapshot.accounts.len(), 2);
    assert_eq!(
        f.runtime.events.receiver_count(),
        before + 1,
        "no hidden list subscription"
    );
    assert_eq!(
        ready(&sub.snapshot, &f.alice.account_id_hex),
        AccountAttentionTotal::default()
    );
    assert!(
        f.app()
            .chat_list_projection_warmed
            .lock()
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        store.chat_presentation("0000").unwrap(),
        storage_sqlite::ChatPresentationRead::Pending
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), sub.recv())
            .await
            .is_err()
    );
    f.runtime
        .set_chat_manually_unread("alice", "0000", true)
        .unwrap();
    let update = next(&mut sub).await;
    assert!(ready(&update, &f.alice.account_id_hex).has_unread());
    assert_eq!(ready(&update, &f.alice.account_id_hex).unread_count, 0);
    assert_eq!(
        ready(&update, &f.alice.account_id_hex).attention_only_conversations,
        1
    );
    assert_eq!(
        ready(&update, &f.bob.account_id_hex),
        AccountAttentionTotal::default()
    );
    let generation = update.subscription_generation.clone();
    drop(sub);
    tokio::time::timeout(Duration::from_secs(5), async {
        while f.runtime.events.receiver_count() != before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let reopened = f.runtime.subscribe_account_attention().await.unwrap();
    assert_ne!(reopened.snapshot.subscription_generation, generation);
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn incomplete_base_rows_are_unavailable_then_retry_without_worker_or_new_event() {
    let f = Fixture::new();
    let storage = f.seed(&f.alice, 120, false);
    let mut sub = f.runtime.subscribe_account_attention().await.unwrap();
    assert!(matches!(
        state(&sub.snapshot, &f.alice.account_id_hex),
        AccountAttentionState::Unavailable(AccountAttentionUnavailable::Preparing)
    ));
    let update = next(&mut sub).await;
    assert_eq!(
        ready(&update, &f.alice.account_id_hex),
        AccountAttentionTotal::default()
    );
    assert!(storage.pending_chat_presentation_rows().unwrap().is_empty());
    assert!(matches!(
        storage.chat_presentation("0000").unwrap(),
        storage_sqlite::ChatPresentationRead::Pending
    ));
    assert!(
        f.app()
            .chat_list_projection_warmed
            .lock()
            .unwrap()
            .is_empty()
    );
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn account_read_failure_is_not_zero_or_removal_and_recovers_without_notification() {
    let f = Fixture::new();
    let storage = f.seed(&f.alice, 1, true);
    f.runtime
        .set_chat_manually_unread("alice", "0000", true)
        .unwrap();
    let mut sub = f.runtime.subscribe_account_attention().await.unwrap();
    assert!(ready(&sub.snapshot, &f.alice.account_id_hex).has_unread());
    storage.close().unwrap();
    f.signal(&f.alice);
    let unavailable = next(&mut sub).await;
    assert_eq!(unavailable.accounts.len(), 2);
    assert!(matches!(
        state(&unavailable, &f.alice.account_id_hex),
        AccountAttentionState::Unavailable(AccountAttentionUnavailable::ReadFailed)
    ));
    assert_eq!(
        ready(&unavailable, &f.bob.account_id_hex),
        AccountAttentionTotal::default()
    );
    // Repair the fixture's cached closed handle without an external invalidation.
    f.app().account_storages.lock().unwrap().remove("alice");
    // Continuous traffic for another ready account must not postpone retries.
    let events = f.runtime.events.clone();
    let bob = f.bob.clone();
    let traffic = tokio::spawn(async move {
        let mut ticks = tokio::time::interval(Duration::from_millis(5));
        loop {
            ticks.tick().await;
            let _ = events.send(MarmotAppEvent::GroupStateUpdated {
                account_id_hex: bob.account_id_hex.clone(),
                account_label: bob.label.clone(),
                group_id: cgka_traits::GroupId::new(vec![0, 0]),
            });
        }
    });
    let recovered = next(&mut sub).await;
    traffic.abort();
    let _ = traffic.await;
    assert!(ready(&recovered, &f.alice.account_id_hex).has_unread());
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn event_lag_recovers_effective_invite_archive_and_departure_state() {
    let f = Fixture::new();
    let storage = f.seed(&f.alice, 1, true);
    let mut sub = f.runtime.subscribe_account_attention().await.unwrap();
    assert_eq!(
        ready(&sub.snapshot, &f.alice.account_id_hex),
        AccountAttentionTotal::default()
    );
    let mut was_eligible = false;
    for (pending, archived, membership) in [
        (true, false, SelfMembership::Member),
        (false, false, SelfMembership::Member),
        (true, true, SelfMembership::Member),
        (true, false, SelfMembership::Member),
        (true, false, SelfMembership::Left),
        (true, false, SelfMembership::Member),
    ] {
        let mut account = storage.load_account_projection_state("alice", 100).unwrap();
        account.groups[0].pending_confirmation = pending;
        account.groups[0].archived = archived;
        storage
            .save_account_projection_state(&account, 100, 120)
            .unwrap();
        storage
            .set_group_self_membership("0000", membership)
            .unwrap();
        // Overflow only unrelated presentation invalidations; recovery must re-read
        // truth even though the account-specific notification was missed entirely.
        for _ in 0..200 {
            let _ = f
                .app()
                .presentation_signals
                .updates
                .send(PresentationInvalidation {
                    account_label: "other".into(),
                    version: storage.chat_presentation_version().unwrap(),
                });
        }
        let eligible = pending && !archived && membership == SelfMembership::Member;
        // The invitation is the sole attention source; equal suppressed totals coalesce.
        if eligible != was_eligible {
            assert_eq!(
                ready(&next(&mut sub).await, &f.alice.account_id_hex),
                AccountAttentionTotal {
                    unread_conversations: u64::from(eligible),
                    attention_only_conversations: u64::from(eligible),
                    ..Default::default()
                }
            );
        } else {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), sub.recv())
                    .await
                    .is_err()
            );
        }
        was_eligible = eligible;
    }
    assert!(
        !storage
            .chat_list_row("0000")
            .unwrap()
            .unwrap()
            .manually_marked_unread
    );
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_account_database_is_not_read_on_another_accounts_update() {
    use cgka_traits::storage::{StorageError, StorageProvider};
    let f = Fixture::new();
    f.seed(&f.alice, 1, true);
    let bob = f.seed(&f.bob, 1, true);
    let mut sub = f.runtime.subscribe_account_attention().await.unwrap();
    let (held_tx, held_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        bob.with_transaction(|_| -> Result<(), StorageError> {
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(())
        })
        .unwrap()
    });
    held_rx.await.unwrap();
    f.runtime
        .set_chat_manually_unread("alice", "0000", true)
        .unwrap();
    let update = tokio::time::timeout(Duration::from_secs(2), sub.recv()).await;
    release_tx.send(()).unwrap();
    writer.join().unwrap();
    assert!(ready(&update.unwrap().unwrap().unwrap(), &f.alice.account_id_hex).has_unread());
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn catalog_tracks_creation_sign_out_removal_and_external_accounts_without_workers() {
    let f = Fixture::new();
    let mut sub = f.runtime.subscribe_account_attention().await.unwrap();
    let (new_account, _) = f
        .runtime
        .accounts
        .create_nostr_account_from_setup(&AccountSetupRequest::default())
        .unwrap();
    let added = next(&mut sub).await;
    assert!(
        added
            .accounts
            .iter()
            .any(|a| a.account_id_hex == new_account.account_id_hex)
    );
    f.runtime
        .accounts
        .deactivate_account(&f.bob.label)
        .await
        .unwrap();
    let removed = next(&mut sub).await;
    assert!(
        !removed
            .accounts
            .iter()
            .any(|a| a.account_id_hex == f.bob.account_id_hex)
    );
    f.runtime
        .accounts
        .remove_account(&new_account.account_id_hex)
        .await
        .unwrap();
    // Teardown may emit an intermediate unavailable state before removal.
    let removed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let s = next(&mut sub).await;
            if !s
                .accounts
                .iter()
                .any(|a| a.account_id_hex == new_account.account_id_hex)
            {
                break s;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(removed.accounts.len(), 1);
    let external = f
        .app()
        .account_home()
        .add_external_signer_account(&nostr::prelude::Keys::generate().public_key().to_hex())
        .unwrap();
    // Public AccountHome writes are observed when callers reconcile runtime membership.
    f.runtime.reconcile_accounts().await.unwrap();
    let added = next(&mut sub).await;
    assert!(
        added
            .accounts
            .iter()
            .any(|a| a.account_id_hex == external.account_id_hex)
    );
    f.runtime.shutdown_and_close().await.unwrap();
    assert!(sub.recv().await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_snapshot_attaches_before_a_concurrent_commit() {
    use cgka_traits::storage::{StorageError, StorageProvider};
    let f = Fixture::new();
    let storage = f.seed(&f.alice, 1, true);
    let id = f.alice.account_id_hex.clone();
    let (held_tx, held_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        storage
            .with_transaction(|s| -> Result<(), StorageError> {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                s.set_chat_manually_unread(&id, "0000", true, &|_, _| false)?;
                Ok(())
            })
            .unwrap()
    });
    held_rx.await.unwrap();
    let before = f.runtime.events.receiver_count();
    let runtime = f.runtime.clone();
    let opening = tokio::spawn(async move { runtime.subscribe_account_attention().await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while f.runtime.events.receiver_count() == before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!opening.is_finished());
    release_tx.send(()).unwrap();
    writer.join().unwrap();
    let sub = opening.await.unwrap().unwrap();
    assert!(ready(&sub.snapshot, &f.alice.account_id_hex).has_unread());
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn unreadable_catalog_is_explicit_and_retries_all_lost_dirty_work() {
    let f = Fixture::new();
    f.seed(&f.alice, 1, true);
    let mut sub = f.runtime.subscribe_account_attention().await.unwrap();
    let record = f
        .app()
        .account_home()
        .account_dir(&f.bob.label)
        .join("account.json");
    let original = std::fs::read(&record).unwrap();
    std::fs::write(&record, b"{").unwrap();
    f.app().presentation_signals.catalog_changed();
    let error = tokio::time::timeout(Duration::from_secs(5), sub.recv())
        .await
        .unwrap();
    assert!(
        matches!(error, Err(e) if matches!(&*e, AppError::AccountHome(marmot_account::AccountHomeError::Json(_))))
    );
    // A committed update while catalog reads fail must not lose its retry obligation.
    f.runtime
        .set_chat_manually_unread("alice", "0000", true)
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    std::fs::write(&record, original).unwrap();
    let recovered = next(&mut sub).await;
    assert_eq!(recovered.accounts.len(), 2);
    assert!(ready(&recovered, &f.alice.account_id_hex).has_unread());
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn empty_subscription_closes_on_terminal_storage_close() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
    let mut sub = runtime.subscribe_account_attention().await.unwrap();
    assert!(sub.snapshot.accounts.is_empty());
    runtime.accounts.app.close_storage().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        runtime.subscribe_account_attention().await,
        Err(AppError::RuntimeStopping)
    ));
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn message_and_mention_totals_change_while_unread_membership_stays_true() {
    let f = Fixture::new();
    let storage = f.seed(&f.alice, 1, true);
    f.runtime
        .set_chat_manually_unread("alice", "0000", true)
        .unwrap();
    let mut sub = f.runtime.subscribe_account_attention().await.unwrap();
    for i in 1..=3 {
        storage
            .record_app_event(&storage_sqlite::StoredAppEvent {
                group_id_hex: "0000".into(),
                message_id_hex: format!("{i:064x}"),
                source_message_id_hex: None,
                source_epoch: None,
                direction: "received".into(),
                sender: f.bob.account_id_hex.clone(),
                plaintext: "message".into(),
                kind: 9,
                tags: vec![],
                recorded_at: 100 + i,
                received_at: 100 + i,
                origin_commit_id: None,
                moderation_grant: false,
            })
            .unwrap();
        storage
            .refresh_chat_list_row(&f.alice.account_id_hex, "0000", &|_, _| true)
            .unwrap();
        f.signal(&f.alice);
        let update = next(&mut sub).await;
        let total = ready(&update, &f.alice.account_id_hex);
        assert_eq!(total.unread_count, i);
        assert_eq!(total.unread_mention_count, i);
        assert_eq!(total.unread_conversations, 1);
        assert_eq!(total.attention_only_conversations, 0);
    }
    storage
        .mark_timeline_message_read(
            &f.alice.account_id_hex,
            "0000",
            &format!("{:064x}", 1),
            &|_, _| true,
        )
        .unwrap();
    f.signal(&f.alice);
    let total = ready(&next(&mut sub).await, &f.alice.account_id_hex);
    assert_eq!(total.unread_count, 2);
    assert_eq!(total.unread_mention_count, 2);
    assert_eq!(total.unread_conversations, 1);
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn retry_does_not_reenumerate_unrelated_account_records() {
    let f = Fixture::new();
    let storage = f.seed(&f.alice, 1, true);
    f.runtime
        .set_chat_manually_unread("alice", "0000", true)
        .unwrap();
    let mut sub = f.runtime.subscribe_account_attention().await.unwrap();
    storage.close().unwrap();
    f.signal(&f.alice);
    assert!(matches!(
        state(&next(&mut sub).await, &f.alice.account_id_hex),
        AccountAttentionState::Unavailable(AccountAttentionUnavailable::ReadFailed)
    ));
    // A corrupt, unrelated record would make an unnecessary catalog scan fail.
    let path = f
        .app()
        .account_home()
        .account_dir("bob")
        .join("account.json");
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"{").unwrap();
    f.app().account_storages.lock().unwrap().remove("alice");
    let recovered = next(&mut sub).await;
    assert!(ready(&recovered, &f.alice.account_id_hex).has_unread());
    // The catalog still fails explicitly when its own invalidation arrives.
    f.app().presentation_signals.catalog_changed();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .is_err()
    );
    std::fs::write(&path, original).unwrap();
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn unknown_presentation_label_discovers_account_without_catalog_notification() {
    let f = Fixture::new();
    let mut sub = f.runtime.subscribe_account_attention().await.unwrap();
    let catalog_signal = f.app().presentation_signals.subscribe_catalog();
    let carol = f.app().account_home().create_account("carol").unwrap();
    let store = f.seed(&carol, 1, true);
    store
        .set_chat_manually_unread(&carol.account_id_hex, "0000", true, &|_, _| false)
        .unwrap();
    assert!(!catalog_signal.has_changed().unwrap());
    assert!(
        f.app()
            .presentation_signals
            .updates
            .send(PresentationInvalidation {
                account_label: carol.label.clone(),
                version: store.chat_presentation_version().unwrap(),
            })
            .is_ok()
    );
    let added = next(&mut sub).await;
    assert!(ready(&added, &carol.account_id_hex).has_unread());
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn teardown_after_catalog_read_is_a_transition_and_can_recover_without_new_catalog() {
    let f = Fixture::new();
    let known = catalog(&f.runtime.accounts).await.unwrap();
    let account = known[&f.alice.account_id_hex].clone();
    assert!(!account.resetting);
    f.runtime
        .accounts
        .set_account_tearing_down(&f.alice.account_id_hex, true);
    let during = read_accounts(&f.runtime.accounts, vec![account.clone()])
        .await
        .unwrap();
    assert_eq!(
        during.states[&f.alice.account_id_hex],
        AccountAttentionState::Unavailable(AccountAttentionUnavailable::Resetting)
    );
    let captured_during =
        catalog(&f.runtime.accounts).await.unwrap()[&f.alice.account_id_hex].clone();
    f.runtime
        .accounts
        .set_account_tearing_down(&f.alice.account_id_hex, false);
    let after = read_accounts(&f.runtime.accounts, vec![captured_during])
        .await
        .unwrap();
    assert!(matches!(
        after.states[&f.alice.account_id_hex],
        AccountAttentionState::Ready(_)
    ));
    f.app()
        .account_home()
        .set_account_signed_out("alice", true)
        .unwrap();
    let signed_out = read_accounts(&f.runtime.accounts, vec![account])
        .await
        .unwrap();
    assert_eq!(
        signed_out.states[&f.alice.account_id_hex],
        AccountAttentionState::Unavailable(AccountAttentionUnavailable::Resetting)
    );
    f.runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn stalled_retry_backoff_is_capped_and_progress_resets_it() {
    let mut retry = None;
    for seconds in [1, 2, 4, 8, 16, 30, 30] {
        let scheduled = Retry::next(retry.as_ref(), false);
        assert_eq!(
            scheduled.at - tokio::time::Instant::now(),
            Duration::from_secs(seconds)
        );
        tokio::time::advance(Duration::from_secs(seconds)).await;
        retry = Some(scheduled);
    }
    let progressing = Retry::next(retry.as_ref(), true);
    assert_eq!(
        progressing.at - tokio::time::Instant::now(),
        Duration::from_secs(1)
    );
}

#[tokio::test]
async fn pending_invitation_attention_updates_without_an_account_worker() {
    let f = Fixture::new();
    let storage = f.seed(&f.alice, 1, true);
    let mut sub = f.runtime.subscribe_account_attention().await.unwrap();
    assert!(!ready(&sub.snapshot, &f.alice.account_id_hex).has_unread());
    // Arrival, archive, restore, acceptance. No message or manual unread is required.
    for (pending, archived, attention) in [
        (true, false, 1),
        (true, true, 0),
        (true, false, 1),
        (false, false, 0),
    ] {
        let mut account = storage.load_account_projection_state("alice", 100).unwrap();
        account.groups[0].pending_confirmation = pending;
        account.groups[0].archived = archived;
        storage
            .save_account_projection_state(&account, 100, 120)
            .unwrap();
        f.signal(&f.alice);
        let total = ready(&next(&mut sub).await, &f.alice.account_id_hex);
        assert_eq!(total.unread_count, 0);
        assert_eq!(total.unread_mention_count, 0);
        assert_eq!(total.unread_conversations, attention);
        assert_eq!(total.attention_only_conversations, attention);
        assert_eq!(total.has_unread(), attention > 0);
    }
    f.runtime.shutdown_and_close().await.unwrap();
}
