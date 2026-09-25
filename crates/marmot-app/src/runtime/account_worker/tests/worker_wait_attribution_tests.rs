//! Attribution witness for a legacy owner-granted network wait on the account worker.
//! P5 should invert the pending assertion: the queued command must be served while
//! a broad relay request is held. Keep this fixture when replacing that wait.

use super::*;
use nostr_relay_builder::prelude::{
    BoxedFuture, Filter as RelayFilter, PolicyResult, QueryPolicy, SingleLetterTag,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{Client as NostrSdkClient, Filter, Kind, RelayCapabilities, ReqTarget};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Clone, Debug, Default)]
struct HeldBroadRequest {
    armed: Arc<AtomicBool>,
    group_route: Arc<Mutex<Option<String>>>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    held_requests: Arc<AtomicUsize>,
    inside_gate: Arc<AtomicBool>,
}

impl HeldBroadRequest {
    fn release(&self) {
        self.armed.store(false, Ordering::SeqCst);
        self.release.notify_waiters();
    }
}

struct ReleaseGateOnDrop(HeldBroadRequest);

impl Drop for ReleaseGateOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl QueryPolicy for HeldBroadRequest {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let route = self.group_route.lock().unwrap().clone();
            let for_group = route.as_ref().is_some_and(|route| {
                query
                    .generic_tags
                    .get(&SingleLetterTag::from_char('h').expect("h is a valid tag"))
                    .is_some_and(|values| values.contains(route))
            });
            if self.armed.load(Ordering::SeqCst)
                && query.ids.is_none()
                && for_group
                && self
                    .held_requests
                    .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                let released = self.release.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                self.inside_gate.store(true, Ordering::SeqCst);
                self.entered.notify_one();
                released.await;
                self.inside_gate.store(false, Ordering::SeqCst);
            }
            PolicyResult::Accept
        })
    }
}

#[tokio::test]
async fn owner_granted_broad_recovery_wait_holds_queued_worker_command() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let gate = HeldBroadRequest::default();
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(gate.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        crate::MarmotAppConfig::default()
            .with_allow_loopback_relay_endpoints(true)
            .with_dev_epoch_backfill_eose_wait_ms(30_000)
            .with_dev_epoch_backfill_execution_quantum_ms(30_000),
    );
    let runtime = super::super::super::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package(&account.label).await.unwrap();
    let lifecycle = runtime
        .key_package_maintenance_status(&account.label)
        .await
        .unwrap()
        .expect("publication establishes key-package lifecycle state");
    assert!(lifecycle.pending_replacement.is_none());
    assert!(lifecycle.current_key_package.is_some());
    assert!(
        lifecycle
            .refresh_at
            .is_some_and(|deadline| deadline.0 > crate::unix_now_seconds())
    );
    assert!(lifecycle.upgrade_rotation_recorded);
    assert!(
        lifecycle.generation_revision >= cgka_traits::maintenance::KEY_PACKAGE_GENERATION_REVISION
    );
    let group = runtime
        .create_group_with_options(
            &account.label,
            "wait attribution",
            &[],
            AppCreateGroupOptions {
                relays: Some(vec![url.clone()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    *gate.group_route.lock().unwrap() = Some(
        app.group(&account.label, &hex::encode(&group))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex,
    );
    timeout(Duration::from_secs(20), runtime.catch_up_accounts())
        .await
        .expect("initial catch-up must settle before the gate is armed")
        .unwrap();
    runtime
        .send_message(&account.label, &group, b"retained probe".to_vec())
        .await
        .unwrap();
    let inspector = NostrSdkClient::builder().build();
    inspector
        .add_relay(url.clone())
        .capabilities(RelayCapabilities::READ)
        .await
        .unwrap();
    inspector.connect().await;
    let events = inspector
        .fetch_events(ReqTarget::single(
            url.as_str(),
            [Filter::new().kind(Kind::MlsGroupMessage)],
        ))
        .timeout(Duration::from_secs(5))
        .await
        .unwrap();
    let event_id = events
        .into_iter()
        .next()
        .expect("the real relay retained the published group event")
        .id
        .to_bytes();
    timeout(Duration::from_secs(20), runtime.catch_up_accounts())
        .await
        .expect("the published event's live echo settles before the test demand")
        .unwrap();
    let commands = runtime
        .accounts()
        .worker_commands(&account.label)
        .await
        .unwrap();
    let (respond, baseline_status) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: group.clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(2), baseline_status)
        .await
        .expect("the same status command runs before the relay gate")
        .unwrap()
        .unwrap();
    let storage = app.account_storage(&account.label).unwrap();
    let ticket = storage
        .request_recovery(
            storage_sqlite::RecoveryRequest::KnownEvent {
                group_id: group.as_slice(),
                event_id: &event_id,
            },
            crate::client::recovery::wall_now_ms().unwrap(),
        )
        .unwrap();
    let prior_attempt = storage.recovery_retry_state().unwrap().attempt_serial;
    let mut entered = Box::pin(gate.entered.notified());
    entered.as_mut().enable();
    gate.armed.store(true, Ordering::SeqCst);
    let release_on_drop = ReleaseGateOnDrop(gate.clone());
    let (respond, advanced) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::AdvanceRecoveryClock {
            elapsed: Duration::from_secs(600),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(5), advanced)
        .await
        .expect("clock command reaches the worker")
        .unwrap();
    // Either due convergence or periodic maintenance can enter the same
    // legacy backfill helper with the Maintenance seam.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16)).await;
    tokio::time::resume();
    timeout(Duration::from_secs(5), entered.as_mut())
        .await
        .expect("the owner-granted broad REQ reached the real relay");
    let held_since = TokioInstant::now();
    let retry = storage.recovery_retry_state().unwrap();
    assert_eq!(retry.attempt_serial, prior_attempt + 1);
    let scopes = storage.recovery_scope_snapshots(ticket.id).unwrap();
    assert!(scopes.iter().any(|scope| {
        scope.attempt_serial == retry.attempt_serial && scope.plan.known_event_id == Some(event_id)
    }));
    assert_eq!(gate.held_requests.load(Ordering::SeqCst), 1);
    assert!(gate.inside_gate.load(Ordering::SeqCst));
    let (respond, mut status) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: group.clone(),
            respond,
        })
        .expect("the command entered the same account worker queue");
    assert!(
        timeout(Duration::from_millis(150), &mut status)
            .await
            .is_err(),
        "the queued command unexpectedly completed during the held broad network wait"
    );
    assert!(gate.inside_gate.load(Ordering::SeqCst));
    assert!(
        held_since.elapsed() < Duration::from_secs(1),
        "the held-window observation must finish before the executor's own deadline"
    );
    gate.release();
    timeout(Duration::from_secs(2), status)
        .await
        .expect("the queued command completes after release and before the executor timeout")
        .unwrap()
        .unwrap();
    drop(release_on_drop);
    runtime.shutdown_and_close().await.unwrap();
}
