//! Coalesced process-local wakeups. Durable revisions remain the recovery authority.
use storage_sqlite::ChatPresentationVersion;
use tokio::sync::{broadcast, watch};

#[derive(Clone)]
pub(crate) struct PresentationInvalidation {
    pub(crate) account_label: String,
    pub(crate) version: ChatPresentationVersion,
}
pub(crate) struct PresentationSignals {
    pub(crate) avatars: broadcast::Sender<String>,
    pub(crate) drafts: broadcast::Sender<crate::drafts::MessageDraftInvalidation>,
    /// Terminal invalidation for handles using an evicted account store.
    pub(crate) account_resets: broadcast::Sender<String>,
    /// Shared profile commits also affect preview sender names outside peer selection.
    pub(crate) profile_updates: broadcast::Sender<String>,
    /// App-wide work: a shared profile or directory change, or a control
    /// every account worker reads.
    wakeups: watch::Sender<()>,
    /// Work for one account, by label. Waking one account no longer runs
    /// every other account's passes (mdk#2923).
    account_wakeups: std::sync::Mutex<std::collections::HashMap<String, watch::Sender<()>>>,
    catalog: watch::Sender<()>,
    pub(crate) updates: broadcast::Sender<PresentationInvalidation>,
}
impl Default for PresentationSignals {
    fn default() -> Self {
        Self {
            avatars: broadcast::channel(64).0,
            drafts: broadcast::channel(64).0,
            account_resets: broadcast::channel(64).0,
            profile_updates: broadcast::channel(64).0,
            wakeups: watch::channel(()).0,
            account_wakeups: Default::default(),
            catalog: watch::channel(()).0,
            updates: broadcast::channel(64).0,
        }
    }
}
impl PresentationSignals {
    pub(crate) fn catalog_changed(&self) {
        self.catalog.send_modify(|_| {});
    }
    pub(crate) fn subscribe_catalog(&self) -> watch::Receiver<()> {
        self.catalog.subscribe()
    }

    /// Wakes every account worker's passes.
    pub(crate) fn wake(&self) {
        self.wakeups.send_modify(|_| {});
    }
    pub(crate) fn subscribe_work(&self) -> watch::Receiver<()> {
        self.wakeups.subscribe()
    }
    /// Wakes the passes of `label`'s worker only. With no worker listening
    /// for `label` there is nothing to wake, and its entry goes, so a wake
    /// for a closed or unknown account leaves nothing behind.
    pub(crate) fn wake_account(&self, label: &str) {
        let mut wakeups = self
            .account_wakeups
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(sender) = wakeups.get(label) {
            if sender.receiver_count() == 0 {
                wakeups.remove(label);
            } else {
                sender.send_modify(|_| {});
            }
        }
    }
    /// What [`Self::wake_account`] sends for `label`.
    pub(crate) fn subscribe_account_work(&self, label: &str) -> watch::Receiver<()> {
        self.account_wakeups
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(label.to_owned())
            .or_insert_with(|| watch::channel(()).0)
            .subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An account wake reaches that account's workers only; the app-wide
    /// wake reaches every account (mdk#2923).
    #[test]
    fn an_account_wake_reaches_only_that_account() {
        let signals = PresentationSignals::default();
        let mut alice = signals.subscribe_account_work("alice");
        let mut bob = signals.subscribe_account_work("bob");
        let mut all = signals.subscribe_work();
        alice.mark_unchanged();
        bob.mark_unchanged();
        all.mark_unchanged();

        signals.wake_account("alice");
        assert!(alice.has_changed().unwrap());
        assert!(!bob.has_changed().unwrap());
        assert!(!all.has_changed().unwrap());

        signals.wake();
        assert!(all.has_changed().unwrap());
        assert!(
            !bob.has_changed().unwrap(),
            "app-wide work has its own watch"
        );
    }

    /// A wake for an account no worker listens for leaves no entry, and an
    /// account's entry goes once its worker has stopped listening.
    #[test]
    fn account_wakes_keep_no_entry_without_a_listener() {
        let signals = PresentationSignals::default();
        let entries = |signals: &PresentationSignals| signals.account_wakeups.lock().unwrap().len();
        signals.wake_account("nobody");
        assert_eq!(entries(&signals), 0);

        let alice = signals.subscribe_account_work("alice");
        assert_eq!(entries(&signals), 1);
        drop(alice);
        signals.wake_account("alice");
        assert_eq!(entries(&signals), 0);
    }
}
