//! Coalesced process-local wakeups. Durable revisions remain the recovery authority.
use storage_sqlite::ChatPresentationVersion;
use tokio::sync::{broadcast, watch};

#[derive(Clone)]
pub(crate) struct PresentationInvalidation {
    pub(crate) account_label: String,
    pub(crate) version: ChatPresentationVersion,
}
pub(crate) struct PresentationSignals {
    /// Terminal invalidation for handles using an evicted account store.
    pub(crate) account_resets: broadcast::Sender<String>,
    /// Shared profile commits also affect preview sender names outside peer selection.
    pub(crate) profile_updates: broadcast::Sender<String>,
    wakeups: watch::Sender<()>,
    pub(crate) updates: broadcast::Sender<PresentationInvalidation>,
}
impl Default for PresentationSignals {
    fn default() -> Self {
        Self {
            account_resets: broadcast::channel(64).0,
            profile_updates: broadcast::channel(64).0,
            wakeups: watch::channel(()).0,
            updates: broadcast::channel(64).0,
        }
    }
}
impl PresentationSignals {
    pub(crate) fn wake(&self) {
        self.wakeups.send_modify(|_| {});
    }
    pub(crate) fn subscribe_work(&self) -> watch::Receiver<()> {
        self.wakeups.subscribe()
    }
}
