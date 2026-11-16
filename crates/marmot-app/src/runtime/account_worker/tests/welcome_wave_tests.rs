//! The account worker's detached Welcome waves (mdk#3466 PR 1): what a
//! wave beside the writer keeps of a wave on it. The session's tests own
//! the wave's terms, one publisher per Welcome, the abandoned wave's owed
//! Welcomes and the counted inputs a run leaves alone. These own what only
//! the worker decides: a wave of a group gone before it settles, the
//! pending-deliveries read that waits for earlier waves (W8), and the client
//! replacement and worker exits a wave can meet.
//!
//! Each test holds a create's founding gift wrap on the relays, as hold 4's
//! flip does, and the worker answers commands while it is held.

use super::writer_hold_tests::{Alice, SETTLE, alice_with_groups};
use super::*;
use tokio::sync::Notify;

/// Alice's create with bob, whose founding Welcome waits on the relays.
async fn held_founding_wave(dir: &tempfile::TempDir) -> (Alice<0>, GroupId) {
    let bob = AccountHome::open(dir.path()).create_account("bob").unwrap();
    let alice = alice_with_groups(dir, []).await;
    crate::tests::remember_test_member_inbox(
        &alice.app,
        &bob.account_id_hex,
        "wss://relay.example",
    );
    alice.runtime.publish_key_package("bob").await.unwrap();
    alice
        .relay
        .block_next_publish_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    let group = alice
        .runtime
        .create_group(
            "alice",
            "held wave",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, alice.relay.wait_for_blocked_publish())
        .await
        .expect("the founding Welcome reaches its relays");
    (alice, group)
}

/// Send a `Drain` to alice's worker, answered once every wave it started
/// before has settled.
pub(super) async fn drain(runtime: &crate::MarmotAppRuntime) -> oneshot::Receiver<()> {
    let lane = runtime.accounts().worker_lane("alice").await.unwrap();
    let (respond, drained) = oneshot::channel();
    lane.commands
        .send(AccountWorkerCommand::Drain { respond })
        .await
        .unwrap();
    drained
}

/// A hold the worker of one account, by id, enters after it settles a wave
/// and before it answers the waits on it: the notifiers it enters and waits
/// on.
type SettleHold = (String, Arc<Notify>, Arc<Notify>);
static HOLD_AFTER_SETTLE: std::sync::Mutex<Option<SettleHold>> = std::sync::Mutex::new(None);

/// Hold the worker of the account `account_id_hex` after it next settles a
/// wave.
fn hold_after_settle(account_id_hex: &str) -> (Arc<Notify>, Arc<Notify>) {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    *HOLD_AFTER_SETTLE.lock().unwrap() =
        Some((account_id_hex.to_owned(), entered.clone(), release.clone()));
    (entered, release)
}

/// The worker's side of [`hold_after_settle`].
pub(in crate::runtime::account_worker) async fn held_after_settle(account_id_hex: &str) {
    let held = HOLD_AFTER_SETTLE
        .lock()
        .unwrap()
        .take_if(|(held, ..)| held == account_id_hex);
    if let Some((_, entered, release)) = held {
        entered.notify_one();
        release.notified().await;
    }
}

/// Send a pending-deliveries read to alice's worker, answered once every
/// wave it started before has settled (W8).
pub(super) async fn read_pending(
    runtime: &crate::MarmotAppRuntime,
) -> oneshot::Receiver<Result<Vec<crate::PendingWelcomeDelivery>, AppError>> {
    let lane = runtime.accounts().worker_lane("alice").await.unwrap();
    let (respond, listed) = ReadReply::unobserved();
    lane.commands
        .send(AccountWorkerCommand::PendingWelcomeDeliveries { respond })
        .await
        .unwrap();
    listed
}

/// Stop the workers, then close storage. A settled wave's own Welcome comes
/// back as a local copy that the worker ingests after the `Drain` answers;
/// stopping first keeps terminal close from landing inside that ingest,
/// whose failure the read-state oracle would then meet with closed storage.
pub(super) async fn close(runtime: &crate::MarmotAppRuntime) {
    runtime.shutdown().await;
    runtime.shutdown_and_close().await.unwrap();
}

/// How many times a gift wrap reached the relays.
fn gift_wraps_published(relay: &ScriptedPushRelayClient) -> usize {
    let gift_wraps = relay
        .attempted_events()
        .into_iter()
        .filter(|event| event.kind == transport_nostr_peeler::KIND_NIP59_GIFT_WRAP)
        .map(|event| event.id)
        .collect::<std::collections::HashSet<_>>();
    relay
        .published_event_ids()
        .iter()
        .filter(|id| gift_wraps.contains(*id))
        .count()
}

/// The undelivered Welcomes of `group` the host is shown.
async fn pending_of(
    runtime: &crate::MarmotAppRuntime,
    group: &GroupId,
) -> Vec<crate::PendingWelcomeDelivery> {
    runtime
        .pending_welcome_deliveries("alice")
        .await
        .unwrap()
        .into_iter()
        .filter(|pending| pending.group_id_hex == hex::encode(group.as_slice()))
        .collect()
}

/// W5: a wave whose chat the host deletes while it runs changes nothing of
/// the group when it settles. Its Welcome fails, which would leave a pending
/// delivery and its event for a chat the host no longer shows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wave_settling_after_its_chat_is_deleted_leaves_it_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (Alice { relay, runtime, .. }, group) = held_founding_wave(&dir).await;
    relay.fail_publishes_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    assert!(runtime.delete_group_local("alice", &group).await.unwrap());
    let mut events = runtime.subscribe();

    let drained = drain(&runtime).await;
    relay.release_publish();
    timeout(SETTLE, drained).await.unwrap().unwrap();
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(
                &event,
                MarmotAppEvent::WelcomeDeliveryPending { group_id, .. } if group_id == &group
            ),
            "a deleted chat's settle emits no pending delivery"
        );
    }
    // The engine still owes the Welcome, as it did while the wave ran: a
    // read then would have listed it the same way.
    assert_eq!(pending_of(&runtime, &group).await.len(), 1);
    close(&runtime).await;
}

/// W5 for a wave with no group of its own: the startup retry's wave carries
/// each Welcome's group, and a Welcome whose chat the host deletes while the
/// wave runs settles to nothing. The engine keeps the group and its owed
/// Welcome, so only the settle can leave the deleted chat alone. Alice's first Welcome to bob failed, so the next
/// start retries it, and that retry fails too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_startup_retry_settling_after_its_chat_is_deleted_leaves_it_alone() {
    let dir = tempfile::tempdir().unwrap();
    let bob = AccountHome::open(dir.path()).create_account("bob").unwrap();
    let Alice {
        app,
        relay,
        runtime,
        ..
    } = alice_with_groups(&dir, []).await;
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
    runtime.publish_key_package("bob").await.unwrap();
    relay.fail_publishes_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    let group = runtime
        .create_group(
            "alice",
            "retried",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !pending_of(&runtime, &group).await.is_empty(),
        "the first Welcome failed"
    );
    close(&runtime).await;

    relay.block_next_publish_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = crate::MarmotAppRuntime::new(app);
    let mut events = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    timeout(SETTLE, relay.wait_for_blocked_publish())
        .await
        .expect("the startup retry reaches the relays");
    assert!(runtime.delete_group_local("alice", &group).await.unwrap());

    let drained = drain(&runtime).await;
    relay.release_publish();
    timeout(SETTLE, drained).await.unwrap().unwrap();
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(
                &event,
                MarmotAppEvent::WelcomeDeliveryPending { group_id, .. } if group_id == &group
            ),
            "a deleted chat's settle emits no pending delivery"
        );
    }
    assert_eq!(pending_of(&runtime, &group).await.len(), 1);
    close(&runtime).await;
}

/// W8: a pending-deliveries read waits only for the waves started before
/// the worker took it up. A wave the next create starts, held on the relays,
/// doesn't extend the wait: the read answers once the earlier wave settles,
/// with that wave's Welcome delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_wave_does_not_extend_a_pending_deliveries_read() {
    let dir = tempfile::tempdir().unwrap();
    let carol = AccountHome::open(dir.path())
        .create_account("carol")
        .unwrap();
    let (
        Alice {
            app,
            relay,
            runtime,
            ..
        },
        group,
    ) = held_founding_wave(&dir).await;
    crate::tests::remember_test_member_inbox(&app, &carol.account_id_hex, "wss://relay.example");
    runtime.publish_key_package("carol").await.unwrap();

    let mut listed = read_pending(&runtime).await;
    let (later_entered, later_release) =
        relay.hold_next_publish_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    runtime
        .create_group(
            "alice",
            "later wave",
            std::slice::from_ref(&carol.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, later_entered.notified())
        .await
        .expect("the later wave reaches its relays");
    assert!(
        matches!(listed.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
        "the read waits for the earlier wave"
    );

    relay.release_publish();
    let listed = timeout(SETTLE, listed)
        .await
        .expect("the read answers while the later wave is held")
        .unwrap()
        .unwrap();
    assert!(
        listed
            .iter()
            .all(|pending| pending.group_id_hex != hex::encode(group.as_slice())),
        "the earlier wave delivered its Welcome before the read answered"
    );
    assert_eq!(
        gift_wraps_published(&relay),
        1,
        "the later wave is still held"
    );

    later_release.notify_one();
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    close(&runtime).await;
}

/// L1: a client replacement during a held wave abandons it on the client
/// that started it, and a `Drain` and a pending-deliveries read waiting for
/// the wave answer on that client, before the worker backs off to reopen:
/// an outage never holds them. Its Welcome stays owed, the next client's
/// maintenance sends it, and it reaches the relays once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_replacement_abandons_a_held_wave_and_its_welcome_is_sent_once() {
    let dir = tempfile::tempdir().unwrap();
    let (Alice { relay, runtime, .. }, _) = held_founding_wave(&dir).await;
    let drained = drain(&runtime).await;
    let listed = read_pending(&runtime).await;
    let mut events = runtime.subscribe();
    runtime
        .shared_services()
        .relay_plane()
        .simulate_notification_consumer_exit_for_test();
    timeout(SETTLE, async {
        loop {
            match events.recv().await {
                Ok(MarmotAppEvent::AccountError(error))
                    if error.message.starts_with("runtime receive failed") =>
                {
                    break;
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    panic!("runtime events closed before the failed receive")
                }
            }
        }
    })
    .await
    .expect("the consumer exit fails the worker's receive");
    timeout(SETTLE, drained)
        .await
        .expect("the replacement settles the held wave")
        .unwrap();
    timeout(SETTLE, listed)
        .await
        .expect("the replacement answers the waiting read")
        .unwrap()
        .unwrap();
    // Both answered before the reopen: the backoff, two seconds at least,
    // drops a command unanswered, and the worker is still in it.
    assert!(
        timeout(SETTLE, drain(&runtime).await)
            .await
            .expect("the worker takes the probe up")
            .is_err(),
        "the replacement answers its waits before the worker backs off to reopen"
    );
    assert_eq!(gift_wraps_published(&relay), 0);

    runtime.notify_connectivity_restored().await.unwrap();
    timeout(SETTLE, async {
        while runtime.run_due_maintenance("alice").await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the next client takes commands");
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gift_wraps_published(&relay), 1, "maintenance sends it");
    // A publish the abandoned wave left parked would reach the relays now.
    relay.release_publish();
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gift_wraps_published(&relay), 1);
    close(&runtime).await;
}

/// L2, shutdown: a held wave doesn't keep the worker from returning, and
/// its Welcome stays owed. A pending-deliveries read waiting for the wave is
/// answered with the error a queued command gets (W8). The next start's
/// startup retry sends the Welcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_ends_a_held_wave_and_the_next_start_sends_its_welcome() {
    let dir = tempfile::tempdir().unwrap();
    let (Alice { relay, runtime, .. }, _) = held_founding_wave(&dir).await;
    let listed = read_pending(&runtime).await;
    // The worker takes commands in order: once this one answers, it has
    // taken the read, which waits for the held wave.
    runtime.publish_key_package("alice").await.unwrap();
    timeout(SETTLE, runtime.shutdown_and_close())
        .await
        .expect("shutdown ends the held wave")
        .unwrap();
    assert!(
        matches!(
            timeout(SETTLE, listed)
                .await
                .expect("shutdown answers the read"),
            Ok(Err(AppError::TransportClosed))
        ),
        "the read is answered, not dropped"
    );
    relay.release_publish();
    assert_eq!(gift_wraps_published(&relay), 0);

    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let runtime = crate::MarmotAppRuntime::new(app);
    runtime.reconcile_accounts().await.unwrap();
    crate::worker_fences::worker_startup_finished(&runtime, "alice")
        .await
        .unwrap();
    timeout(SETTLE, drain(&runtime).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gift_wraps_published(&relay), 1);
    close(&runtime).await;
}

/// W8 at shutdown: a read whose wave settles as shutdown begins is
/// answered, with its list or with the error a queued command gets. Which
/// one is not a host contract; that it never hangs is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_whose_wave_settles_as_shutdown_begins_is_answered() {
    let dir = tempfile::tempdir().unwrap();
    let (
        Alice {
            account,
            relay,
            runtime,
            ..
        },
        _,
    ) = held_founding_wave(&dir).await;
    let listed = read_pending(&runtime).await;
    // Once this answers, the worker has taken the read up.
    runtime.publish_key_package("alice").await.unwrap();
    let (settled, resume) = hold_after_settle(&account.account_id_hex);
    relay.release_publish();
    timeout(SETTLE, settled.notified())
        .await
        .expect("the worker settles the released wave");

    let stopping = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.shutdown().await }
    });
    timeout(SETTLE, async {
        while !runtime.is_stopping() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown begins");
    resume.notify_one();
    assert!(
        matches!(
            timeout(SETTLE, listed)
                .await
                .expect("the worker answers the read"),
            Ok(Ok(_) | Err(AppError::TransportClosed))
        ),
        "the read answers with its list or the shutdown error"
    );
    timeout(SETTLE, stopping).await.unwrap().unwrap();
    runtime.shutdown_and_close().await.unwrap();
}

/// L2, sign-out: a held wave doesn't hold the sign-out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_out_ends_a_held_wave() {
    let dir = tempfile::tempdir().unwrap();
    let (Alice { runtime, .. }, _) = held_founding_wave(&dir).await;
    timeout(
        SETTLE,
        runtime.sign_out(
            "alice",
            crate::SignOutOptions {
                delete_key_packages: false,
            },
        ),
    )
    .await
    .expect("sign-out ends the held wave")
    .unwrap();
    runtime.shutdown_and_close().await.unwrap();
}

/// L2, unlink: a held wave doesn't hold the device's removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlinking_ends_a_held_wave() {
    let dir = tempfile::tempdir().unwrap();
    let (Alice { runtime, .. }, _) = held_founding_wave(&dir).await;
    timeout(SETTLE, runtime.accounts().unlink_device_for_test("alice"))
        .await
        .expect("unlinking ends the held wave")
        .unwrap();
    runtime.shutdown_and_close().await.unwrap();
}
