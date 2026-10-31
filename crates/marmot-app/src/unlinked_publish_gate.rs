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
#[cfg(feature = "unreleased-device-pairing")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use cgka_traits::{MemberId, TransportAdapterError, TransportEndpoint};
use transport_nostr_adapter::{
    NostrAcquisitionCancellation, NostrAcquisitionError, NostrAcquisitionRequest,
    NostrAcquisitionResult, NostrEventPublishRequest, NostrNotificationLoss, NostrPublishBatch,
    NostrPublishOutcome, NostrRelayClient, NostrSubscribeReport, NostrSubscription,
    RelayConnection,
};
use transport_nostr_peeler::NostrTransportEvent;

/// One account's publish stop while this app is open.
#[derive(Clone, Default)]
pub(crate) struct AccountPublishStop {
    stop: Arc<AtomicBool>,
    /// Whether this process has looked for a removal the engine stored and
    /// the app never noted. Held while looking, so one look runs at a time.
    #[cfg(feature = "unreleased-device-pairing")]
    checked: Arc<Mutex<bool>>,
    #[cfg(all(test, feature = "unreleased-device-pairing"))]
    checks: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::MarmotApp {
    /// The stop every publisher of this account checks: set once its device
    /// group unlinked this device (D67), or, until a client open tells it
    /// apart, once a removal the engine stored is found here.
    pub(crate) fn account_publish_stop(&self, account_id_hex: &str) -> Arc<AtomicBool> {
        // A label is not an account id, so find the record among them all.
        let Ok(accounts) = self.account_home().accounts() else {
            return Arc::new(AtomicBool::new(true));
        };
        let Some(account) = accounts
            .into_iter()
            .find(|account| account.account_id_hex == account_id_hex)
        else {
            return self.account_publish_stop_entry(account_id_hex).stop;
        };
        // An account unlinked before this app opened has no stop set here.
        if account.unlinked {
            return Arc::new(AtomicBool::new(true));
        }
        let entry = self.account_publish_stop_entry(account_id_hex);
        #[cfg(feature = "unreleased-device-pairing")]
        if !self.check_stored_device_group_removal(&account.label, &entry) {
            return Arc::new(AtomicBool::new(true));
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

    /// Look, once per account per process, for this device's removal from
    /// its device group that the engine stored and the app never noted, and
    /// stop the account's publishing if there is one. Only a client can tell
    /// an unlink from a failed link's undo (D40), so its open decides and
    /// lifts the stop for a failed link. False when the look failed: the
    /// caller refuses, and the next publisher looks again.
    #[cfg(feature = "unreleased-device-pairing")]
    fn check_stored_device_group_removal(&self, label: &str, entry: &AccountPublishStop) -> bool {
        if !self.device_groups_enabled() {
            return true;
        }
        let mut checked = entry
            .checked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *checked {
            return true;
        }
        #[cfg(test)]
        entry.checks.fetch_add(1, Ordering::Relaxed);
        match self.removed_device_group(label) {
            Ok(removed) => {
                if removed.is_some() {
                    entry.stop.store(true, Ordering::Release);
                }
                *checked = true;
                true
            }
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::unlinked_publish_gate",
                    method = "check_stored_device_group_removal",
                    error_kind = error.privacy_safe_kind(),
                    "could not look for this device's removal; refusing to publish"
                );
                false
            }
        }
    }

    /// This account's trusted device group, when its stored copy records
    /// this device's removal.
    #[cfg(feature = "unreleased-device-pairing")]
    pub(crate) fn removed_device_group(
        &self,
        label: &str,
    ) -> Result<Option<cgka_traits::GroupId>, crate::AppError> {
        use cgka_traits::storage::{GroupStorage as _, StorageError};
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
    #[cfg(any(test, feature = "unreleased-device-pairing"))]
    pub(crate) fn stop_unlinked_account_publishing(&self, account_id_hex: &str) {
        self.account_publish_stop_entry(account_id_hex)
            .stop
            .store(true, Ordering::Release);
    }

    /// Lift the stop a stored removal set: a client found that the removal
    /// undid a failed link (D40), which stops nothing.
    #[cfg(feature = "unreleased-device-pairing")]
    pub(crate) fn lift_failed_link_publish_stop(&self, account_id_hex: &str) {
        self.account_publish_stop_entry(account_id_hex)
            .stop
            .store(false, Ordering::Release);
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
    #[cfg(all(test, feature = "unreleased-device-pairing"))]
    pub(crate) fn stored_device_group_checks(&self, account_id_hex: &str) -> usize {
        self.account_publish_stop_entry(account_id_hex)
            .checks
            .load(Ordering::Relaxed)
    }
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

    fn refusal(&self) -> Option<TransportAdapterError> {
        self.unlinked
            .load(Ordering::Acquire)
            .then(|| TransportAdapterError::Publish("this device is unlinked".to_owned()))
    }
}

#[async_trait]
impl NostrRelayClient for UnlinkedPublishGate {
    fn relay_connection(
        &self,
        account: &MemberId,
        endpoint: &TransportEndpoint,
    ) -> Option<RelayConnection> {
        self.inner.relay_connection(account, endpoint)
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
        if let Some(refusal) = self.refusal() {
            return Err(refusal);
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
        if let Some(refusal) = self.refusal() {
            return Err(refusal);
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
        if self.refusal().is_some() {
            return refuse_all(self, requests);
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
        if self.refusal().is_some() {
            return refused_batch(self, requests);
        }
        self.inner
            .publish_events_for_account_with_timings(account_id, requests)
            .await
    }

    async fn publish_events(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        if self.refusal().is_some() {
            return refuse_all(self, requests);
        }
        self.inner.publish_events(requests).await
    }

    async fn publish_events_with_timings(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> NostrPublishBatch {
        if self.refusal().is_some() {
            return refused_batch(self, requests);
        }
        self.inner.publish_events_with_timings(requests).await
    }
}

fn refuse_all(
    gate: &UnlinkedPublishGate,
    requests: &[NostrEventPublishRequest],
) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
    requests
        .iter()
        .map(|_| Err(gate.refusal().expect("the gate is closed for good")))
        .collect()
}

fn refused_batch(
    gate: &UnlinkedPublishGate,
    requests: &[NostrEventPublishRequest],
) -> NostrPublishBatch {
    NostrPublishBatch {
        request_durations: vec![std::time::Duration::ZERO; requests.len()],
        outcomes: refuse_all(gate, requests),
    }
}
