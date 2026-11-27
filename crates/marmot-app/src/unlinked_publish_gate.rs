//! The publish gate of an account whose device group unlinked this device
//! (mdk#2628 D67).
//!
//! Every account-signed publication this crate makes goes through
//! [`crate::MarmotApp::relay_client_for_account_id`], the account adapter's
//! included. The client it hands out refuses every publish once the account
//! is unlinked here, whichever path the publish came from: a retained
//! client, a catch-up still admitting input, or maintenance. Subscriptions
//! and reads still pass, so the account's transport can be torn down.
//!
//! The engine stores a removal before the app marks the account unlinked,
//! so a crash between the two leaves a removal no record shows. Before it
//! hands out a publisher for an account the first time in a process, the
//! app looks for one; a client open notes it before it returns.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use cgka_traits::{MemberId, TransportAdapterError, TransportEndpoint, TransportEndpointFailure};
use transport_nostr_adapter::{
    NostrAcquisitionCancellation, NostrAcquisitionError, NostrAcquisitionRequest,
    NostrAcquisitionResult, NostrEventPublishRequest, NostrNotificationLoss, NostrPublishBatch,
    NostrPublishOutcome, NostrRelayClient, NostrSubscribeReport, NostrSubscription,
    RelayConnection,
};
use transport_nostr_peeler::NostrTransportEvent;

#[derive(Default)]
struct PublishStopState {
    /// Whether this process has resolved the account's on-disk unlinked flag
    /// and any stored device-group removal cleanly.
    checked: bool,
    /// Whether an explicit stop (in-process unlink, on-disk `unlinked`, stored
    /// device-group removal, or sign-out removal hold) is currently active.
    explicit_stop: bool,
}

/// One account's publish stop while this app is open.
#[derive(Clone, Default)]
pub(crate) struct AccountPublishStop {
    stop: Arc<AtomicBool>,
    /// Held while looking for an on-disk unlink or stored removal and across
    /// explicit stop/lift transitions, so one look runs at a time and cannot
    /// race an explicit stop or lift.
    state: Arc<Mutex<PublishStopState>>,
    #[cfg(test)]
    checks: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::MarmotApp {
    /// The stop every publisher of this account checks: set once its device
    /// group unlinked this device (D67), or, until a client open tells it
    /// apart, once a removal the engine stored is found here.
    ///
    /// Always returns the account's shared `entry.stop` handle, even on
    /// transient lookup errors (failing closed while uncertain without
    /// permanently bricking handed-out handles once the error clears or a
    /// failed-link undo lifts the stop). Once resolved cleanly for an open
    /// account, subsequent calls reuse the cached handle without rescanning
    /// `account.json` from disk (mdk#3801).
    pub(crate) fn account_publish_stop(&self, account_id_hex: &str) -> Arc<AtomicBool> {
        let entry = self.account_publish_stop_entry(account_id_hex);
        let mut state = entry
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.checked {
            return entry.stop;
        }
        // A label is not an account id, so find the record among them all once
        // until resolved cleanly.
        let Ok(accounts) = self.account_home().accounts() else {
            entry.stop.store(true, Ordering::Release);
            return entry.stop;
        };
        let Some(account) = accounts
            .into_iter()
            .find(|account| account.account_id_hex == account_id_hex)
        else {
            entry.stop.store(state.explicit_stop, Ordering::Release);
            return entry.stop;
        };
        // An account unlinked before this app opened has no stop set here yet.
        if account.unlinked {
            state.explicit_stop = true;
            state.checked = true;
            entry.stop.store(true, Ordering::Release);
            return entry.stop;
        }
        if !self.device_groups_enabled() {
            state.checked = true;
            entry.stop.store(state.explicit_stop, Ordering::Release);
            return entry.stop;
        }
        #[cfg(test)]
        entry.checks.fetch_add(1, Ordering::Relaxed);
        match self.removed_device_group(&account.label) {
            Ok(Some(_)) => {
                state.explicit_stop = true;
                state.checked = true;
                entry.stop.store(true, Ordering::Release);
            }
            Ok(None) => {
                state.checked = true;
                entry.stop.store(state.explicit_stop, Ordering::Release);
            }
            Err(error) => {
                // Fail closed on the shared stop and leave `checked = false`
                // so a later lookup or `lift_failed_link_publish_stop` can
                // recover every existing handle.
                entry.stop.store(true, Ordering::Release);
                tracing::warn!(
                    target: "marmot_app::unlinked_publish_gate",
                    method = "check_stored_device_group_removal",
                    error_kind = error.privacy_safe_kind(),
                    "could not look for this device's removal; refusing to publish"
                );
            }
        }
        entry.stop
    }

    /// Whether this device may no longer publish for the account. For
    /// publishers that do not come from
    /// [`crate::MarmotApp::relay_client_for_account_id`].
    pub(crate) fn account_publishing_stopped(&self, account_id_hex: &str) -> bool {
        self.account_publish_stop(account_id_hex)
            .load(Ordering::Acquire)
    }

    fn account_publish_stop_entry(&self, account_id_hex: &str) -> AccountPublishStop {
        self.unlinked_publish_stops
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(account_id_hex.to_owned())
            .or_default()
            .clone()
    }

    /// This account's trusted device group, when its stored copy records
    /// this device's removal.
    pub(crate) fn removed_device_group(
        &self,
        label: &str,
    ) -> Result<Option<cgka_traits::GroupId>, crate::AppError> {
        use cgka_traits::storage::{GroupStorage as _, StorageError};
        // An account with no database yet holds no device group, so the look
        // answers without opening one, which would create it (and, for an
        // external signer, its database secret). Creating it early no longer
        // misleads the KeyPackage cutover (mdk#3486). A path it cannot tell is
        // absent fails the look, so publishing stays refused.
        if !self.account_storage_path(label).try_exists()? {
            return Ok(None);
        }
        let storage = self.account_storage(label)?;
        let Some(record) = storage
            .app_storage()
            .device_groups()?
            .into_iter()
            .find(|record| record.trust.is_trusted())
        else {
            return Ok(None);
        };
        let group_id = cgka_traits::GroupId::new(hex::decode(record.group_id_hex)?);
        match storage.get_group(&group_id) {
            Ok(group) if group.removed => Ok(Some(group_id)),
            Ok(_) | Err(StorageError::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Refuse every publish of this account on this device from now on: its
    /// device group unlinked this device (mdk#2628 D67).
    pub(crate) fn stop_unlinked_account_publishing(&self, account_id_hex: &str) {
        let entry = self.account_publish_stop_entry(account_id_hex);
        let mut state = entry
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.explicit_stop = true;
        state.checked = true;
        entry.stop.store(true, Ordering::Release);
    }

    /// Lift the stop a stored removal set: a client found that the removal
    /// undid a failed link (D40), which stops nothing.
    pub(crate) fn lift_failed_link_publish_stop(&self, account_id_hex: &str) {
        let entry = self.account_publish_stop_entry(account_id_hex);
        let mut state = entry
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.explicit_stop = false;
        state.checked = true;
        entry.stop.store(false, Ordering::Release);
    }

    /// Forget a removed account's publish stop. Publishers already handed
    /// out keep it.
    pub(crate) fn forget_unlinked_publish_stop(&self, account_id_hex: &str) {
        self.unlinked_publish_stops
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(account_id_hex);
    }

    /// How many times this process has looked for the account's stored
    /// removal.
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn stored_device_group_checks(&self, account_id_hex: &str) -> usize {
        self.account_publish_stop_entry(account_id_hex)
            .checks
            .load(Ordering::Relaxed)
    }
}

tokio::task_local! {
    /// The publish stop the sign-out step being polled may pass (mdk#2628
    /// D67). It is set only while that step's own future is polled, so no
    /// task it spawns and no future polled beside it passes.
    static SIGN_OUT_STEP: Arc<AtomicBool>;
}

/// Run `step`, one step of a sign-out that its device group's removal of
/// this device interrupted, so that its own publishes pass `stop` while the
/// account's other publishers stay refused.
pub(crate) async fn publish_as_sign_out_step<F: std::future::Future>(
    stop: Arc<AtomicBool>,
    step: F,
) -> F::Output {
    SIGN_OUT_STEP.scope(stop, step).await
}

/// An account publisher that refuses to publish once `unlinked` is set.
pub(crate) struct UnlinkedPublishGate {
    inner: Arc<dyn NostrRelayClient>,
    unlinked: Arc<AtomicBool>,
}

impl UnlinkedPublishGate {
    pub(crate) fn new(inner: Arc<dyn NostrRelayClient>, unlinked: Arc<AtomicBool>) -> Self {
        Self { inner, unlinked }
    }

    /// Whether this publish is refused: the stop is set and no sign-out
    /// step that may pass it is being polled. Read once per publish: a
    /// failed link's undo lifts the stop (D40), so a batch is refused whole
    /// or not at all.
    fn stopped(&self) -> bool {
        self.unlinked.load(Ordering::Acquire)
            && !SIGN_OUT_STEP
                .try_with(|stop| Arc::ptr_eq(stop, &self.unlinked))
                .unwrap_or(false)
    }
}

#[async_trait]
impl NostrRelayClient for UnlinkedPublishGate {
    /// A connect sends nothing, so the gate leaves it alone.
    async fn connect_for_publish(
        &self,
        endpoint: &TransportEndpoint,
    ) -> Result<(), TransportEndpointFailure> {
        self.inner.connect_for_publish(endpoint).await
    }

    fn relay_connection(
        &self,
        account: &MemberId,
        endpoint: &TransportEndpoint,
    ) -> Option<RelayConnection> {
        self.inner.relay_connection(account, endpoint)
    }

    async fn reply_sent_nothing(
        &self,
        account: Option<&MemberId>,
        endpoint: &TransportEndpoint,
        subscription_id: &str,
    ) -> bool {
        self.inner
            .reply_sent_nothing(account, endpoint, subscription_id)
            .await
    }

    async fn acquire_history(
        &self,
        request: NostrAcquisitionRequest,
        cancellation: NostrAcquisitionCancellation,
    ) -> Result<NostrAcquisitionResult, NostrAcquisitionError> {
        self.inner.acquire_history(request, cancellation).await
    }

    fn notification_loss(
        &self,
    ) -> Result<tokio::sync::watch::Receiver<Option<NostrNotificationLoss>>, NostrAcquisitionError>
    {
        self.inner.notification_loss()
    }

    async fn notification_loss_for_account(
        &self,
        account_id: &MemberId,
    ) -> Result<tokio::sync::watch::Receiver<Option<NostrNotificationLoss>>, NostrAcquisitionError>
    {
        self.inner.notification_loss_for_account(account_id).await
    }

    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        self.inner.subscribe(subscription).await
    }

    async fn subscribe_reporting(
        &self,
        subscription: NostrSubscription,
    ) -> Result<NostrSubscribeReport, TransportAdapterError> {
        self.inner.subscribe_reporting(subscription).await
    }

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        self.inner.unsubscribe(subscription).await
    }

    fn supports_scoped_subscriptions(&self) -> bool {
        self.inner.supports_scoped_subscriptions()
    }

    async fn subscribe_scoped(
        &self,
        subscription: NostrSubscription,
        subscription_id: String,
    ) -> Result<(), TransportAdapterError> {
        self.inner
            .subscribe_scoped(subscription, subscription_id)
            .await
    }

    async fn unsubscribe_scoped(
        &self,
        subscription: NostrSubscription,
        subscription_id: String,
    ) -> Result<(), TransportAdapterError> {
        self.inner
            .unsubscribe_scoped(subscription, subscription_id)
            .await
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
        replacements: &[NostrSubscription],
    ) -> Result<(), TransportAdapterError> {
        self.inner
            .unsubscribe_account(account_id, replacements)
            .await
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        if self.stopped() {
            return Err(unlinked_refusal());
        }
        self.inner
            .publish_event(endpoints, event, required_acks)
            .await
    }

    async fn publish_event_for_account(
        &self,
        account_id: &MemberId,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        if self.stopped() {
            return Err(unlinked_refusal());
        }
        self.inner
            .publish_event_for_account(account_id, endpoints, event, required_acks)
            .await
    }

    async fn publish_events_for_account(
        &self,
        account_id: &MemberId,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        if self.stopped() {
            return refuse_all(requests);
        }
        self.inner
            .publish_events_for_account(account_id, requests)
            .await
    }

    async fn publish_events_for_account_with_timings(
        &self,
        account_id: &MemberId,
        requests: &[NostrEventPublishRequest],
    ) -> NostrPublishBatch {
        if self.stopped() {
            return refused_batch(requests);
        }
        self.inner
            .publish_events_for_account_with_timings(account_id, requests)
            .await
    }

    async fn publish_events(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        if self.stopped() {
            return refuse_all(requests);
        }
        self.inner.publish_events(requests).await
    }

    async fn publish_events_with_timings(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> NostrPublishBatch {
        if self.stopped() {
            return refused_batch(requests);
        }
        self.inner.publish_events_with_timings(requests).await
    }
}

fn unlinked_refusal() -> TransportAdapterError {
    TransportAdapterError::Publish("this device is unlinked".to_owned())
}

fn refuse_all(
    requests: &[NostrEventPublishRequest],
) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
    requests.iter().map(|_| Err(unlinked_refusal())).collect()
}

fn refused_batch(requests: &[NostrEventPublishRequest]) -> NostrPublishBatch {
    NostrPublishBatch {
        request_durations: vec![std::time::Duration::ZERO; requests.len()],
        outcomes: refuse_all(requests),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::ScriptedPushRelayClient;

    /// A batch is refused whole or published whole, though a failed link's
    /// undo lifts the stop while the batch is decided (D40).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_is_refused_whole_while_the_stop_lifts() {
        let unlinked = Arc::new(AtomicBool::new(true));
        let gate = UnlinkedPublishGate::new(
            Arc::new(ScriptedPushRelayClient::default()),
            unlinked.clone(),
        );
        let requests: Vec<_> = (0..64)
            .map(|_| NostrEventPublishRequest {
                endpoints: Vec::new(),
                event: NostrTransportEvent::new_unsigned(
                    "00".repeat(32),
                    1,
                    Vec::new(),
                    String::new(),
                    &cgka_traits::SystemWallClock,
                ),
                required_acks: 1,
            })
            .collect();
        let done = Arc::new(AtomicBool::new(false));
        let toggler = std::thread::spawn({
            let (unlinked, done) = (unlinked.clone(), done.clone());
            move || {
                while !done.load(Ordering::Relaxed) {
                    unlinked.fetch_xor(true, Ordering::AcqRel);
                }
            }
        });
        let mut refused = 0;
        for _ in 0..2_000 {
            let outcomes = gate.publish_events(&requests).await;
            let refusals = outcomes
                .iter()
                .filter(|outcome| {
                    outcome
                        .as_ref()
                        .is_err_and(|error| error.to_string().contains("unlinked"))
                })
                .count();
            assert!(refusals == 0 || refusals == requests.len());
            if refusals > 0 {
                refused += 1;
            }
            let batch = gate.publish_events_with_timings(&requests).await;
            assert_eq!(batch.outcomes.len(), requests.len());
        }
        done.store(true, Ordering::Relaxed);
        toggler.join().unwrap();
        assert!(refused > 0, "some batches were decided while stopped");
    }

    /// A handle handed out during a transient storage/filesystem lookup failure
    /// must share `entry.stop` so publishing recovers once the error clears or
    /// `lift_failed_link_publish_stop` runs, and subsequent lookups reuse the
    /// cached per-account entry without rescanning `account.json` from disk.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publish_gate_recovers_after_transient_error_and_caches_resolved_state() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = crate::MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.example",
            crate::MarmotAppConfig::white_noise()
                .with_allow_loopback_relay_endpoints(true)
                .with_device_groups(true),
        )
        .with_test_relay_client(relay.clone());
        let alice = app.account_home().create_account("alice").unwrap();
        let bob = app.account_home().create_account("bob").unwrap();
        let sample_event = NostrTransportEvent::new_unsigned(
            "00".repeat(32),
            1,
            Vec::new(),
            String::new(),
            &cgka_traits::SystemWallClock,
        );
        let endpoints = vec![TransportEndpoint("wss://relay.example".to_owned())];

        // 1. Transient failure on alice: symlink loop makes DB existence check fail.
        let alice_db = app.account_storage_path(&alice.label);
        std::os::unix::fs::symlink(&alice_db, &alice_db).unwrap();
        let alice_stop = app.account_publish_stop(&alice.account_id_hex);
        let alice_gate = UnlinkedPublishGate::new(relay.clone(), alice_stop.clone());
        let err = alice_gate
            .publish_event(&endpoints, &sample_event, 1)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unlinked"),
            "transient error must fail closed: {err}"
        );

        // Once the transient error clears, rechecking updates the shared stop so
        // the ALREADY-HANDED-OUT gate recovers without being permanently bricked.
        std::fs::remove_file(&alice_db).unwrap();
        assert!(
            !app.account_publishing_stopped(&alice.account_id_hex),
            "recheck after transient error clears must succeed"
        );
        assert!(
            Arc::ptr_eq(
                &alice_stop,
                &app.account_publish_stop(&alice.account_id_hex)
            ),
            "transient failure must return the shared entry.stop"
        );
        alice_gate
            .publish_event(&endpoints, &sample_event, 1)
            .await
            .expect("existing gate handle must recover once transient error clears");

        // 2. Cached resolution avoids rescanning `account.json` from disk.
        let account_json = app.account_dir(&alice.label).join("account.json");
        let original_mode = std::fs::metadata(&account_json).unwrap().permissions();
        std::fs::set_permissions(&account_json, std::fs::Permissions::from_mode(0o000)).unwrap();
        let cached_stopped = app.account_publishing_stopped(&alice.account_id_hex);
        std::fs::set_permissions(&account_json, original_mode).unwrap();
        assert!(
            !cached_stopped,
            "resolved publish stop must be served from cache without rereading account.json"
        );

        // 3. `lift_failed_link_publish_stop` also unblocks a handle handed out during a transient error.
        let bob_db = app.account_storage_path(&bob.label);
        std::os::unix::fs::symlink(&bob_db, &bob_db).unwrap();
        let bob_stop = app.account_publish_stop(&bob.account_id_hex);
        let bob_gate = UnlinkedPublishGate::new(relay.clone(), bob_stop);
        assert!(
            bob_gate
                .publish_event(&endpoints, &sample_event, 1)
                .await
                .is_err()
        );
        app.lift_failed_link_publish_stop(&bob.account_id_hex);
        bob_gate
            .publish_event(&endpoints, &sample_event, 1)
            .await
            .expect("lift_failed_link_publish_stop must unblock an existing handle");
        std::fs::remove_file(&bob_db).unwrap();
    }
}
