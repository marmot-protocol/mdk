//! A naturally pending startup comparison selected by an ordinary delivery's
//! Receive tail must leave the account worker available during its SDK wait.

use super::*;
use nostr_relay_builder::prelude::{
    BoxedFuture, Filter as RelayFilter, MemoryDatabase, MemoryDatabaseOptions, NostrDatabase,
    PolicyResult, QueryPolicy,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp as SdkTimestamp};
use std::net::SocketAddr;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[derive(Clone, Debug, Default)]
struct HeldExact {
    target: Arc<Mutex<Option<String>>>,
    hold: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    hits: Arc<AtomicUsize>,
}

impl HeldExact {
    fn release(&self) {
        self.hold.store(false, Ordering::SeqCst);
        self.release.notify_waiters();
    }
}

struct ReleaseOnDrop(HeldExact);

struct ActiveQuery(Arc<AtomicUsize>);

impl Drop for ActiveQuery {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl QueryPolicy for HeldExact {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let wanted = self.target.lock().unwrap().clone();
            if wanted.as_ref().is_some_and(|wanted| {
                query
                    .ids
                    .as_ref()
                    .is_some_and(|ids| ids.iter().any(|id| id.to_hex() == *wanted))
            }) {
                self.hits.fetch_add(1, Ordering::SeqCst);
                if self.hold.load(Ordering::SeqCst) {
                    let release = self.release.notified();
                    tokio::pin!(release);
                    release.as_mut().enable();
                    self.active.fetch_add(1, Ordering::SeqCst);
                    let _active = ActiveQuery(self.active.clone());
                    self.entered.notify_one();
                    release.await;
                }
            }
            PolicyResult::Accept
        })
    }
}

#[tokio::test]
async fn receive_selected_comparison_serves_status_during_held_sdk_request() {
    run_receive_selected_comparison(false).await;
}

#[tokio::test]
async fn receive_selected_comparison_shutdown_reaps_held_request() {
    run_receive_selected_comparison(true).await;
}

async fn run_receive_selected_comparison(shutdown_while_held: bool) {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = HeldExact::default();
    let _release_on_drop = ReleaseOnDrop(gate.clone());
    let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
        events: true,
        max_events: Some(64),
    });
    let relay = LocalRelay::new(
        RelayBuilder::default()
            .query_policy(gate.clone())
            .database(database.clone()),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let live_relay = LocalRelay::new(RelayBuilder::default());
    live_relay.run().await.unwrap();
    let live_url = live_relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("receive_target").unwrap();
    let bob = home.create_account("receive_sender").unwrap();
    let config = crate::MarmotAppConfig::default()
        .with_allow_loopback_relay_endpoints(true)
        .with_dev_settlement_quiescence_ms(100)
        .with_dev_epoch_backfill_retry_backoff_ms(100);
    let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config.clone());
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&bob.label).await.unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "receive comparison",
            std::slice::from_ref(&bob.account_id_hex),
            AppCreateGroupOptions {
                relays: Some(vec![url.clone(), live_url]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    timeout(Duration::from_secs(15), async {
        loop {
            runtime.catch_up_accounts().await.unwrap();
            if app
                .group(&bob.label, &hex::encode(&group))
                .unwrap()
                .is_some()
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("sender joins the real MLS group");
    runtime
        .accounts()
        .deactivate_account(&bob.label)
        .await
        .unwrap();
    assert!(app.account_home().account(&bob.label).unwrap().signed_out);

    let route: [u8; 32] = hex::decode(
        app.group(&alice.label, &hex::encode(&group))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    // The old candidate is outside the ordinary reopened subscription's
    // overlap. It causes a real request-local comparison without inventing a
    // recovery demand or suppressing a production selector.
    let candidate = EventBuilder::new(Kind::MlsGroupMessage, "comparison-only probe")
        .tags([Tag::custom("h", [hex::encode(route)])])
        .custom_created_at(SdkTimestamp::from_secs(crate::unix_now_seconds() - 3_600))
        .finalize(&Keys::generate())
        .unwrap();
    database
        .save_event(&serde_json::from_str(candidate.as_json().as_str()).unwrap())
        .await
        .unwrap();
    *gate.target.lock().unwrap() = Some(candidate.id.to_hex());
    runtime.shutdown_and_close().await.unwrap();
    drop(runtime);
    drop(app);

    let reopened_app = MarmotApp::with_relay_and_config(dir.path(), url, config);
    let reopened = crate::MarmotAppRuntime::new(reopened_app.clone());
    let pool = reopened
        .shared_services()
        .use_private_recovery_credit_pool_for_test();
    let selections = Arc::new(Mutex::new(Vec::new()));
    *reopened
        .shared_services()
        .recovery_selection_witness
        .lock()
        .unwrap() = Some(crate::runtime::RecoverySelectionWitnessTarget {
        account_label: alice.label.clone(),
        sink: selections.clone(),
    });
    let first_request = gate.entered.notified();
    tokio::pin!(first_request);
    first_request.as_mut().enable();
    gate.hold.store(true, Ordering::SeqCst);
    reopened.reconcile_accounts().await.unwrap();
    assert!(
        !reopened
            .accounts()
            .workers
            .lock()
            .await
            .contains_key(&bob.account_id_hex)
    );
    timeout(Duration::from_secs(20), &mut first_request)
        .await
        .expect("natural startup comparison reaches the exact SDK query");
    assert!(gate.active.load(Ordering::SeqCst) > 0);
    // Allow the original acquisition quantum to expire. The comparison must
    // remain pending for a later naturally selected Receive attempt.
    timeout(Duration::from_secs(35), async {
        loop {
            let trace = reopened
                .shared_services()
                .comparison_test_trace
                .lock()
                .unwrap()
                .clone();
            if trace.contains(&"task_started")
                && trace
                    .iter()
                    .any(|kind| matches!(*kind, "route_relay_failed" | "route_timed_out"))
                && bounded_recovery::available_credits(&pool)
                    == bounded_recovery::MAX_CONCURRENT_JOBS
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first comparison attempt finishes and releases its credit");
    gate.release();
    timeout(Duration::from_secs(2), async {
        while gate.active.load(Ordering::SeqCst) > 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first held relay handler is released");
    let baseline_commands = reopened
        .accounts()
        .worker_commands(&alice.label)
        .await
        .unwrap();
    let (respond, baseline_status) = oneshot::channel();
    baseline_commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: group.clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(2), baseline_status)
        .await
        .expect("initial periodic comparison has joined the worker")
        .unwrap()
        .unwrap();
    let storage = reopened_app.account_storage(&alice.label).unwrap();
    let slot = storage.recovery_comparison().unwrap();
    assert!(slot.pending());
    assert_ne!(
        slot.blocked_route_revision,
        Some(storage.recovery_revision_fence().unwrap().route_revision)
    );
    let prior_attempt = slot.attempt_serial;
    assert!(selections.lock().unwrap().iter().any(|selection| {
        selection.seam == EpochBackfillExecutionSeam::Maintenance
            && selection.attempt_serial == prior_attempt
            && selection.comparison_revision == Some(slot.revision)
    }));
    selections.lock().unwrap().clear();
    let retry = storage.recovery_retry_state().unwrap();
    let due_in = retry
        .not_before_ms
        .saturating_sub(crate::client::recovery::wall_now_ms().unwrap());
    sleep(Duration::from_millis(due_in + 200)).await;

    // A one-shot sender has no worker comparison path. The target account is
    // the only live worker that can issue the held exact-ID request.
    let mut sender = reopened_app.client(&bob.label).await.unwrap();
    let mut events = reopened.subscribe();
    let second_request = gate.entered.notified();
    tokio::pin!(second_request);
    second_request.as_mut().enable();
    gate.hold.store(true, Ordering::SeqCst);
    sender
        .send_custom_event(&group, 22_222, Vec::new(), "receive trigger".into())
        .await
        .unwrap();
    timeout(Duration::from_secs(8), &mut second_request)
        .await
        .expect("Receive-selected comparison enters held exact SDK query");
    assert_eq!(gate.active.load(Ordering::SeqCst), 1);
    let commands = reopened
        .accounts()
        .worker_commands(&alice.label)
        .await
        .unwrap();
    let (respond, mut status) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: group.clone(),
            respond,
        })
        .unwrap();
    let status_during_hold = timeout(Duration::from_millis(300), &mut status).await;
    assert_eq!(
        gate.active.load(Ordering::SeqCst),
        1,
        "the same request-local SDK query remains active through the status probe"
    );
    let records = reopened_app.messages(&alice.label).unwrap();
    assert!(
        records
            .iter()
            .any(|record| { record.kind == 22_222 && record.plaintext == "receive trigger" })
    );
    let mut published = false;
    while let Ok(event) = events.try_recv() {
        if let MarmotAppEvent::MessageReceived(update) = event {
            published |= update.account_label == alice.label
                && update.message.plaintext == "receive trigger";
        }
    }
    assert!(
        published,
        "ordinary delivery was published before comparison"
    );
    let selected = selections.lock().unwrap().clone();
    assert_eq!(
        selected.len(),
        1,
        "only Receive selects after the baseline attempt"
    );
    assert_eq!(selected[0].seam, EpochBackfillExecutionSeam::Receive);
    assert_eq!(selected[0].comparison_revision, Some(slot.revision));
    assert!(selected[0].attempt_serial > prior_attempt);
    assert_eq!(
        storage.recovery_retry_state().unwrap().attempt_serial,
        selected[0].attempt_serial
    );
    assert_eq!(
        storage.recovery_comparison().unwrap().attempt_serial,
        selected[0].attempt_serial
    );
    status_during_hold
        .expect("status command completes while Receive SDK query is still held")
        .unwrap()
        .unwrap();
    assert_eq!(gate.active.load(Ordering::SeqCst), 1);
    assert_eq!(
        bounded_recovery::available_credits(&pool),
        bounded_recovery::MAX_CONCURRENT_JOBS - 1,
        "the selected comparison task still owns its credit through the status probe"
    );
    if shutdown_while_held {
        assert!(storage.recovery_comparison().unwrap().pending());
        drop(sender);
        timeout(Duration::from_secs(15), reopened.shutdown_and_close())
            .await
            .expect("shutdown reaps the Receive comparison without relay release")
            .unwrap();
        assert_eq!(
            bounded_recovery::available_credits(&pool),
            bounded_recovery::MAX_CONCURRENT_JOBS
        );
        gate.release();
        relay.shutdown();
        live_relay.shutdown();
        return;
    }
    // The first owned comparison keeps its grant while a second normal MLS
    // delivery is committed. This Receive tail must defer without selecting
    // or overwriting another attempt, and its visible publication still runs.
    sender
        .send_custom_event(&group, 22_222, Vec::new(), "while held".into())
        .await
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            if reopened_app
                .messages(&alice.label)
                .unwrap()
                .iter()
                .any(|record| record.kind == 22_222 && record.plaintext == "while held")
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "second delivery absent while comparison held: records={:?} trace={:?} active={} selections={:?}",
            reopened_app
                .messages(&alice.label)
                .unwrap()
                .iter()
                .map(|record| (record.kind, record.plaintext.clone()))
                .collect::<Vec<_>>(),
            reopened.shared_services().comparison_test_trace.lock().unwrap(),
            gate.active.load(Ordering::SeqCst),
            selections.lock().unwrap(),
        )
    });
    let mut second_published = false;
    while let Ok(event) = events.try_recv() {
        if let MarmotAppEvent::MessageReceived(update) = event {
            second_published |=
                update.account_label == alice.label && update.message.plaintext == "while held";
        }
    }
    assert!(second_published);
    assert_eq!(selections.lock().unwrap().len(), 1);
    assert_eq!(
        storage.recovery_retry_state().unwrap().attempt_serial,
        selected[0].attempt_serial
    );
    assert_eq!(gate.active.load(Ordering::SeqCst), 1);
    gate.release();
    timeout(Duration::from_secs(15), async {
        while bounded_recovery::available_credits(&pool) != bounded_recovery::MAX_CONCURRENT_JOBS {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Receive comparison joins and releases its shared credit");
    drop(sender);
    reopened.shutdown_and_close().await.unwrap();
    relay.shutdown();
    live_relay.shutdown();
}
