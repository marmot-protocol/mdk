//! Coalesced process-local wakeups. Durable revisions remain the recovery authority.
use storage_sqlite::ChatPresentationVersion;
use tokio::sync::{broadcast, watch};

#[derive(Clone)]
pub(crate) struct PresentationInvalidation {
    pub(crate) account_label: String,
    pub(crate) version: ChatPresentationVersion,
}
// P3 consumes these fields in the presented-snapshot subscription; P2 publishes and tests the handoff.
#[allow(dead_code)]
impl PresentationInvalidation {
    pub(crate) fn account_label(&self) -> &str {
        &self.account_label
    }
    pub(crate) fn version(&self) -> &ChatPresentationVersion {
        &self.version
    }
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
