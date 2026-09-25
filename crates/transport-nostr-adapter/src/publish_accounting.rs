//! Device-wide logical publish counters for one relay-plane adapter.
//!
//! One attempt is one validated publish that has entered its relay client.
//! Endpoint fanout and SDK retries stay inside that call. Every attempt ends as
//! exactly one success, failure, or cancellation. The mutex is synchronous and
//! is never held across `.await` or inside a user callback, so dropping an
//! in-flight publish can record its cancellation without an async runtime.

use std::sync::{Arc, Mutex, MutexGuard};

/// Coherent view of the aggregate publish counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PublishCounterSnapshot {
    pub attempts: usize,
    pub successes: usize,
    pub failures: usize,
    pub cancellations: usize,
}

pub(crate) struct PublishAccounting {
    inner: Mutex<PublishCounterSnapshot>,
}

impl PublishAccounting {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(PublishCounterSnapshot::default()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, PublishCounterSnapshot> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Increment attempts and arm a guard that records one terminal outcome.
    pub(crate) fn begin(self: &Arc<Self>) -> PublishAttemptGuard {
        {
            let mut counters = self.lock();
            counters.attempts = counters.attempts.saturating_add(1);
        }
        PublishAttemptGuard {
            accounting: Arc::clone(self),
            open: true,
        }
    }

    pub(crate) fn snapshot(&self) -> PublishCounterSnapshot {
        *self.lock()
    }
}

pub(crate) struct PublishAttemptGuard {
    accounting: Arc<PublishAccounting>,
    open: bool,
}

impl PublishAttemptGuard {
    pub(crate) fn succeed(&mut self) {
        self.finish(|counters| &mut counters.successes);
    }

    pub(crate) fn fail(&mut self) {
        self.finish(|counters| &mut counters.failures);
    }

    fn finish(&mut self, counter: fn(&mut PublishCounterSnapshot) -> &mut usize) {
        if !self.open {
            return;
        }
        // Disarm before the increment so a panic in this section cannot also
        // count a cancellation from `Drop`.
        self.open = false;
        let mut counters = self.accounting.lock();
        let value = counter(&mut counters);
        *value = value.saturating_add(1);
    }
}

impl Drop for PublishAttemptGuard {
    /// The caller dropped a started publish before the client returned.
    fn drop(&mut self) {
        self.finish(|counters| &mut counters.cancellations);
    }
}

/// Same threshold as [`cgka_traits::TransportPublishReport::met_required_acks`].
pub(crate) fn outcome_met_required_acks(accepted: usize, required_acks: usize) -> bool {
    accepted >= required_acks.max(1)
}
