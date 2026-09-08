//! Coalesced process-local wakeups. Durable revisions remain the recovery authority.
use storage_sqlite::ChatPresentationVersion;
use tokio::sync::{broadcast, watch};

// P3 consumes the fields; P2 publishes and tests the handoff.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone)]
pub(crate) struct PresentationInvalidation {
    pub(crate) account_label: String,
    pub(crate) version: ChatPresentationVersion,
}
pub(crate) struct PresentationSignals {
    wakeups: watch::Sender<()>,
    pub(crate) updates: broadcast::Sender<PresentationInvalidation>,
}
impl Default for PresentationSignals {
    fn default() -> Self {
        Self {
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
