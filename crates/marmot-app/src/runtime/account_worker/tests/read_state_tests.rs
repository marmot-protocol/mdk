//! A, the account's published read state, on the account worker (mdk#3273
//! PR 2). A host that awaited a mutation's reply, or saw an event, reads at
//! least the state it describes: the worker's two exits, `reply` and `emit`,
//! publish A before the answer or event leaves, and every reply and event in
//! the worker goes through one of them or names why it does not. The backup
//! restore watch wakes only once A holds the status it announces.

use super::*;
use crate::client::read_state::{ReadState, UploadsInFlight, read_state_channel};
use std::sync::atomic::{AtomicBool, Ordering};

/// How long a step of the restore watch test may take.
const SETTLE: Duration = Duration::from_secs(30);

/// A client that publishes A, with the receiver a host would read.
async fn publishing_client(app: &MarmotApp) -> (AppClient, watch::Receiver<Arc<ReadState>>) {
    let mut client = app.client("alice").await.unwrap();
    client.start_read_state(read_state_channel().0, UploadsInFlight::default());
    let state = client
        .subscribe_read_state()
        .expect("the client publishes A");
    (client, state)
}

fn app(dir: &tempfile::TempDir) -> MarmotApp {
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()))
}

/// A reply leaves after the publish that holds the write before it: the
/// group a unit created is in A when its caller has the answer.
#[tokio::test]
async fn a_reply_follows_the_publish_that_holds_its_write() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(&dir);
    let (mut client, state) = publishing_client(&app).await;
    let group = client
        .create_group("replied", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    assert!(!state.borrow().groups.contains_key(&group));

    let (respond, mut answer) = oneshot::channel();
    reply(respond, group.clone(), &client).unwrap();

    let answered = answer.try_recv().unwrap();
    assert!(state.borrow().groups.contains_key(&answered));
}

/// An event at a quiescent point leaves after the publish that holds the
/// write before it; one emitted mid-unit leaves without a publish.
#[tokio::test]
async fn an_event_follows_the_publish_that_holds_its_write() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(&dir);
    let (mut client, state) = publishing_client(&app).await;
    let (events, mut received) = broadcast::channel(4);

    let echoed = client
        .create_group("echoed", &[])
        .await
        .unwrap()
        .operation
        .unwrap();
    publish_app_runtime_group_state_updated(
        Emit::Unpublished(Unpublished::LocalEcho),
        &events,
        "account",
        "alice",
        &echoed,
    );
    assert!(matches!(
        received.try_recv().unwrap(),
        MarmotAppEvent::GroupStateUpdated { .. }
    ));
    assert!(!state.borrow().groups.contains_key(&echoed));

    publish_app_runtime_group_state_updated(
        Emit::Quiescent(&client),
        &events,
        "account",
        "alice",
        &echoed,
    );
    let MarmotAppEvent::GroupStateUpdated { group_id, .. } = received.try_recv().unwrap() else {
        panic!("one group state event");
    };
    assert!(state.borrow().groups.contains_key(&group_id));
}

/// Every reply and every host event the worker sends goes through `reply`
/// or `emit`, which publish A first, or through a helper that names why it
/// does not. A new raw send fails here.
#[test]
fn every_reply_and_event_leaves_the_worker_through_a_named_exit() {
    let source = include_str!("../../account_worker.rs");
    let worker = source
        .split("\n#[cfg(test)]\nmod tests {")
        .next()
        .expect("the worker module has a test module");
    let raw_events: Vec<_> = worker
        .match_indices("events.send(")
        .map(|(at, _)| at)
        .collect();
    assert_eq!(raw_events.len(), 1, "only `emit` sends a host event");
    let emit = worker.find("fn emit(").expect("the worker has an `emit`");
    assert!(raw_events[0] > emit && raw_events[0] - emit < 600);
    for raw in ["respond.send(", "respond.send_with(", ".send_reply("] {
        let sites: Vec<_> = worker.match_indices(raw).collect();
        let allowed = match raw {
            // `answer_off_quiescent`'s own send.
            "respond.send(" => 1,
            // `reply`'s own send.
            ".send_reply(" => 1,
            _ => 0,
        };
        assert_eq!(
            sites.len(),
            allowed,
            "a reply that bypasses `reply`, `respond_diagnosed` and the named exemptions: {raw}"
        );
    }
}

/// On the worker, A is live: a host that awaited a create's reply finds
/// the group in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_publishes_a() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(&dir);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let (respond, subscribed) = oneshot::channel();
    runtime
        .accounts()
        .worker_commands("alice")
        .await
        .unwrap()
        .send(AccountWorkerCommand::SubscribeReadStateForTest { respond })
        .await
        .unwrap();
    let state = subscribed.await.unwrap().expect("the worker publishes A");
    let group = runtime
        .create_group("alice", "replied", &[], None)
        .await
        .unwrap()
        .operation
        .unwrap();
    assert!(state.borrow().groups.contains_key(&group));
    runtime.shutdown().await;
}

/// A discarded failed send's removal reaches the host's subscription by the
/// time the discard's reply does: the worker holds the update until the
/// discard returns, emits it at that quiescent point, then replies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_discarded_sends_removal_is_heard_by_its_reply() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let group = runtime
        .create_group("alice", "discard", &[], None)
        .await
        .unwrap()
        .operation
        .unwrap();
    let group_id_hex = hex::encode(group.as_slice());
    let failed = "44".repeat(32);
    app.record_account_app_event(
        "alice",
        &crate::AppMessageProjection {
            authority: None,
            message_id_hex: failed.clone(),
            source_message_id_hex: None,
            direction: "sent".to_owned(),
            group_id_hex: group_id_hex.clone(),
            sender: account.account_id_hex.clone(),
            plaintext: "never left".to_owned(),
            kind: cgka_traits::MARMOT_APP_EVENT_KIND_CHAT,
            tags: Vec::new(),
            source_epoch: None,
            retention: None,
            recorded_at: Some(1),
            origin_commit_id: None,
            moderation_grant: false,
        },
    )
    .unwrap();
    app.invalidate_timeline_app_event(
        "alice",
        &group_id_hex,
        &failed,
        crate::LOCAL_PUBLISH_FAILED_REASON,
    )
    .unwrap();
    let mut received = runtime.subscribe();

    let discarded = runtime
        .discard_failed_send("alice", &group, &failed)
        .await
        .unwrap();

    assert_eq!(
        discarded.outcome,
        crate::DiscardFailedSendOutcome::Discarded
    );
    let heard = std::iter::from_fn(|| received.try_recv().ok()).any(|event| {
        matches!(
            event,
            MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate { update, .. })
                if update.timeline_changes.iter().any(|change| matches!(
                    change,
                    crate::TimelineMessageChange::Remove {
                        message_id_hex,
                        reason: storage_sqlite::TimelineRemoveReason::Cleared,
                    } if message_id_hex == &failed
                ))
        )
    });
    assert!(heard, "the removal is out when the reply arrives");
    runtime.shutdown().await;
}

/// Holds a restore's backup pointer read while `holding`, so the restore
/// stays in Discovering until cancelled or released.
struct HeldPointerFetcher {
    relay: Arc<ScriptedPushRelayClient>,
    holding: AtomicBool,
    /// How many pointer reads reached the hold.
    entered: watch::Sender<usize>,
    release: tokio::sync::Notify,
}

impl HeldPointerFetcher {
    async fn hold(&self, request: &transport_nostr::DirectoryFetchRequest) {
        if !request
            .queries
            .iter()
            .any(|query| query.kind == crate::client::backup_writer::KIND_BACKUP_POINTER)
        {
            return;
        }
        let released = self.release.notified();
        tokio::pin!(released);
        released.as_mut().enable();
        if !self.holding.load(Ordering::SeqCst) {
            return;
        }
        self.entered.send_modify(|entered| *entered += 1);
        released.await;
    }
}

#[async_trait::async_trait]
impl transport_nostr::DirectoryRelayFetcher for HeldPointerFetcher {
    async fn fetch_directory_events(
        &self,
        request: transport_nostr::DirectoryFetchRequest,
    ) -> Result<Vec<transport_nostr::DirectoryRelayEventRecord>, String> {
        self.hold(&request).await;
        self.relay.fetch_directory_events(request).await
    }

    async fn fetch_directory_events_with_completion(
        &self,
        request: transport_nostr::DirectoryFetchRequest,
    ) -> Result<transport_nostr::DirectoryFetchOutcome, String> {
        self.hold(&request).await;
        self.relay
            .fetch_directory_events_with_completion(request)
            .await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observer {
    /// A task on the runtime the worker runs on.
    SameRuntime,
    /// A host thread, as a binding's `next()` polls on the caller and its
    /// status call is spawned onto the runtime.
    HostThread,
}

/// What a host saw: the status the watch woke with, the status it read
/// right after, and how long after the wake a read first matched it.
type Observation = (
    crate::BackupRestoreStatus,
    crate::BackupRestoreStatus,
    Duration,
);

/// How long after `woke_at` the status read first reaches `woke`.
async fn caught_up(
    runtime: &crate::MarmotAppRuntime,
    woke: &crate::BackupRestoreStatus,
    woke_at: std::time::Instant,
) -> Duration {
    loop {
        let read = runtime.backup_restore_status("alice").await.unwrap();
        if read.revision >= woke.revision || woke_at.elapsed() > Duration::from_secs(5) {
            return woke_at.elapsed();
        }
        tokio::task::yield_now().await;
    }
}

/// Park an observer on `watch` (marked seen first); it wakes on the next
/// change, even one made before it waits, reads `backup_restore_status` at
/// once, and hands the watch back.
async fn park_observer(
    runtime: &crate::MarmotAppRuntime,
    mut watch: crate::BackupRestoreWatch,
    observer: Observer,
) -> tokio::sync::oneshot::Receiver<(crate::BackupRestoreWatch, Observation)> {
    drop(watch.receiver.borrow_and_update());
    let (done, observed) = oneshot::channel();
    let (parked, is_parked) = oneshot::channel();
    match observer {
        Observer::SameRuntime => {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                parked.send(()).unwrap();
                let woke = watch.changed().await.unwrap();
                let woke_at = std::time::Instant::now();
                let read = runtime.backup_restore_status("alice").await.unwrap();
                let lag = caught_up(&runtime, &woke, woke_at).await;
                let _ = done.send((watch, (woke, read, lag)));
            });
        }
        Observer::HostThread => {
            let runtime = runtime.clone();
            let handle = tokio::runtime::Handle::current();
            std::thread::spawn(move || {
                let host = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                host.block_on(async move {
                    parked.send(()).unwrap();
                    let woke = watch.changed().await.unwrap();
                    let woke_at = std::time::Instant::now();
                    let reader = runtime.clone();
                    let read = handle
                        .spawn(async move { reader.backup_restore_status("alice").await })
                        .await
                        .unwrap()
                        .unwrap();
                    let target = woke.clone();
                    let lag = handle
                        .spawn(async move { caught_up(&runtime, &target, woke_at).await })
                        .await
                        .unwrap();
                    let _ = done.send((watch, (woke, read, lag)));
                });
            });
        }
    }
    is_parked.await.unwrap();
    observed
}

/// Whether the status read after the wake is older than the wake's.
fn stale((woke, read, _): &Observation) -> bool {
    read.revision < woke.revision
}

/// The restore watch is an exit from the account worker: it wakes only once
/// A holds the status it announces, so a host that reads the status when the
/// watch wakes reads that status, never the one before. A status a host
/// missed this way stays on screen: no further wake follows the final
/// Cancelled or Complete. Checked for begin (wakes on Discovering), cancel
/// (wakes on Cancelled) and completion (the discovery finishing), over many
/// rounds, from a task on the worker's runtime and from a host thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backup_restore_watch_wakes_once_the_status_reads_its_change() {
    const ROUNDS: usize = 40;
    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon about";
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let fetcher = Arc::new(HeldPointerFetcher {
        relay: relay.clone(),
        holding: AtomicBool::new(true),
        entered: watch::Sender::new(0),
        release: tokio::sync::Notify::new(),
    });
    let mut app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    app.relay_plane = crate::MarmotRelayPlane::new_with_directory_fetcher_for_test(
        None,
        relay.clone(),
        fetcher.clone(),
        app.config.allow_loopback_relay_endpoints,
    );
    let runtime = crate::MarmotAppRuntime::new(app);
    runtime.reconcile_accounts().await.unwrap();
    crate::worker_fences::worker_startup_finished(&runtime, "alice")
        .await
        .unwrap();
    let mut watch = runtime.watch_backup_restore("alice").await.unwrap();

    // (observer, step) -> (stale, total)
    let mut tally: std::collections::BTreeMap<(String, &str), (usize, usize)> =
        std::collections::BTreeMap::new();
    let mut examples: Vec<String> = Vec::new();
    let mut lags: Vec<Duration> = Vec::new();
    let mut record = |observer: Observer, step: &'static str, observation: &Observation| {
        let entry = tally.entry((format!("{observer:?}"), step)).or_default();
        entry.1 += 1;
        lags.push(observation.2);
        if stale(observation) {
            entry.0 += 1;
            if examples.len() < 6 {
                examples.push(format!(
                    "{observer:?}/{step}: woke {:?}@{} read {:?}@{}",
                    observation.0.phase,
                    observation.0.revision,
                    observation.1.phase,
                    observation.1.revision
                ));
            }
        }
    };
    let wait_entered = |count: usize| {
        let mut entered = fetcher.entered.subscribe();
        async move {
            timeout(SETTLE, entered.wait_for(|entered| *entered >= count))
                .await
                .expect("the restore's pointer read reaches the hold")
                .unwrap();
        }
    };

    for round in 0..ROUNDS {
        let observer = if round % 2 == 0 {
            Observer::HostThread
        } else {
            Observer::SameRuntime
        };
        // Begin: the watch wakes on Discovering.
        let observed = park_observer(&runtime, watch, observer).await;
        let entered_before = *fetcher.entered.borrow();
        let operation = runtime
            .begin_backup_restore("alice", crate::BackupRestoreWords::new(WORDS.to_owned()))
            .await
            .unwrap()
            .operation
            .unwrap();
        let (returned, observation) = timeout(SETTLE, observed).await.unwrap().unwrap();
        watch = returned;
        record(observer, "begin", &observation);
        if round == 0 {
            // The relay plane coalesces later rounds' identical pointer reads
            // onto the one held here, so only the first one reaches it.
            wait_entered(entered_before + 1).await;
        }

        if round % 4 < 2 {
            // Cancel: the watch wakes on Cancelled.
            let observed = park_observer(&runtime, watch, observer).await;
            assert!(
                runtime
                    .cancel_backup_restore("alice", operation)
                    .await
                    .unwrap(),
                "the held restore is still running"
            );
            let (returned, observation) = timeout(SETTLE, observed).await.unwrap().unwrap();
            watch = returned;
            assert_eq!(observation.0.phase, crate::BackupRestorePhase::Cancelled);
            record(observer, "cancel", &observation);
        } else {
            // Completion: release the pointer read; the worker settles the
            // discovery off a media completion.
            let observed = park_observer(&runtime, watch, observer).await;
            fetcher.holding.store(false, Ordering::SeqCst);
            fetcher.release.notify_waiters();
            let (returned, observation) = timeout(SETTLE, observed).await.unwrap().unwrap();
            watch = returned;
            record(observer, "complete", &observation);
            fetcher.holding.store(true, Ordering::SeqCst);
        }
        // Let the worker settle the round before the next begin.
        crate::worker_fences::worker_round_trip(&runtime, "alice")
            .await
            .unwrap();
    }
    fetcher.holding.store(false, Ordering::SeqCst);
    fetcher.release.notify_waiters();
    runtime.shutdown().await;

    let total_stale: usize = tally.values().map(|(stale, _)| stale).sum();
    let summary = tally
        .iter()
        .map(|((observer, step), (stale, total))| format!("{observer}/{step}: {stale}/{total}"))
        .collect::<Vec<_>>()
        .join(", ");
    lags.sort();
    assert_eq!(
        total_stale,
        0,
        "a status read on the watch's wake read the previous status: {summary}; \
         {examples:?}; wake-to-A lag median {:?} max {:?}",
        lags[lags.len() / 2],
        lags[lags.len() - 1]
    );
}
