//! Device-wide logical publish counters for one relay-plane adapter.
//!
//! One attempt is one validated publish that has entered its relay client.
//! Endpoint fanout and SDK retries stay inside that call. The mutex is
//! synchronous and is never held across `.await` or inside a user callback, so
//! dropping an in-flight publish can record its failure without an async
//! runtime.

use std::sync::{Arc, Mutex, MutexGuard};

/// Coherent view of the three aggregate publish counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PublishCounterSnapshot {
    pub attempts: usize,
    pub successes: usize,
    pub failures: usize,
}

#[derive(Default)]
struct PublishCounters {
    attempts: usize,
    successes: usize,
    failures: usize,
}

pub(crate) struct PublishAccounting {
    inner: Mutex<PublishCounters>,
}

impl PublishAccounting {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(PublishCounters::default()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, PublishCounters> {
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
        let counters = self.lock();
        PublishCounterSnapshot {
            attempts: counters.attempts,
            successes: counters.successes,
            failures: counters.failures,
        }
    }
}

pub(crate) struct PublishAttemptGuard {
    accounting: Arc<PublishAccounting>,
    open: bool,
}

impl PublishAttemptGuard {
    pub(crate) fn succeed(&mut self) {
        self.finish(true);
    }

    pub(crate) fn fail(&mut self) {
        self.finish(false);
    }

    fn finish(&mut self, success: bool) {
        if !self.open {
            return;
        }
        // Disarm before the increment so a panic in this section cannot also
        // count a failure from `Drop`.
        self.open = false;
        let mut counters = self.accounting.lock();
        if success {
            counters.successes = counters.successes.saturating_add(1);
        } else {
            counters.failures = counters.failures.saturating_add(1);
        }
    }
}

impl Drop for PublishAttemptGuard {
    fn drop(&mut self) {
        if !self.open {
            return;
        }
        self.open = false;
        let mut counters = self.accounting.lock();
        counters.failures = counters.failures.saturating_add(1);
    }
}

/// Same threshold as [`cgka_traits::TransportPublishReport::met_required_acks`].
pub(crate) fn outcome_met_required_acks(accepted: usize, required_acks: usize) -> bool {
    accepted >= required_acks.max(1)
}
