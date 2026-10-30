//! The attempts a runner began and has not settled (mdk#2660 phase 4, PR 5a).
//!
//! Beginning a required quantum charges one attempt to the account's rolling
//! hour; its settle refunds it or keeps it, with the relay's verdict. A
//! runner stopped between the two never sends its settle, so its owner
//! refunds what is left as `Unanswered` once the runner can send no more
//! turns ([`OpenAttempts::refund`]): the charge goes back and the relay gets
//! no verdict. A process crash refunds nothing, and neither does a stop after
//! `shutdown_and_close` has closed storage: that charge stays until it ages
//! out of the hour, which caps a reply that crashes the process.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use storage_sqlite::{RecoveryUnitOutcome, RecoveryUnitPolicy, SqliteAppStorage};

use super::{TARGET, UnitKey, log_failure};

/// Which settle an open attempt owes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AttemptKind {
    /// A debt quantum (`settle_recovery_unit`).
    Debt,
    /// A re-check quantum (`settle_recovery_recheck`).
    Recheck,
}

/// One runner's open attempts, shared with its owner. Its begin and settle
/// turns keep it in the same worker turn as the charge and the settle, so it
/// matches the ledger as of the last turn its owner served.
#[derive(Clone, Default)]
pub(crate) struct OpenAttempts(Arc<Mutex<BTreeMap<UnitKey, AttemptKind>>>);

impl OpenAttempts {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<UnitKey, AttemptKind>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A begin turn charged an attempt on `key`.
    pub(super) fn begun(&self, key: &UnitKey, kind: AttemptKind) {
        self.lock().insert(key.clone(), kind);
    }

    /// `key`'s settle turn runs: its outcome, not a refund, decides the
    /// charge, even when its write fails.
    pub(super) fn settled(&self, key: &UnitKey) {
        self.lock().remove(key);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Settle every attempt still open as `Unanswered`: refund its charge and
    /// give its relay no verdict. A storage write, no waiting. Call it only
    /// once the runner can send no more turns.
    pub(crate) fn refund(&self, app: &SqliteAppStorage, policy: &RecoveryUnitPolicy, now: u64) {
        let open = std::mem::take(&mut *self.lock());
        if open.is_empty() {
            return;
        }
        let mut failed = 0_usize;
        for (key, kind) in &open {
            let outcome = RecoveryUnitOutcome::Unanswered;
            let refunded = match kind {
                AttemptKind::Debt => app
                    .settle_recovery_unit(&key.route, &key.relay, outcome, policy, now)
                    .map(drop),
                AttemptKind::Recheck => {
                    app.settle_recovery_recheck(&key.route, &key.relay, outcome, policy, now)
                }
            };
            if let Err(error) = refunded {
                failed += 1;
                log_failure("refund_open_attempt", error);
            }
        }
        tracing::debug!(
            target: TARGET,
            method = "refund_open_attempts",
            refunded = open.len() - failed,
            failed,
            "recovery runner stopped with attempts open; refunded them"
        );
    }
}
