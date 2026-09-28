//! The process-wide pool of recovery credits. Every recovery job reserves one
//! before it spends a durable attempt, and keeps it through admission and
//! checkpoint. The worker never waits for one; an explicit caller may.

use std::sync::{Arc, LazyLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(super) const MAX_CONCURRENT_JOBS: usize = 2;
static RECOVERY_CREDITS: LazyLock<Arc<RecoveryCreditPool>> =
    LazyLock::new(|| Arc::new(RecoveryCreditPool::new()));

/// One process pool in production. A test fixture may explicitly substitute
/// another two-credit pool while all accounts in that runtime still share it.
pub(crate) struct RecoveryCreditPool {
    semaphore: Arc<Semaphore>,
}

impl RecoveryCreditPool {
    fn new() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_JOBS)),
        }
    }
}

pub(crate) fn shared_recovery_credit_pool() -> Arc<RecoveryCreditPool> {
    RECOVERY_CREDITS.clone()
}

#[cfg(test)]
pub(crate) fn private_recovery_credit_pool_for_test() -> Arc<RecoveryCreditPool> {
    Arc::new(RecoveryCreditPool::new())
}

pub(crate) fn try_acquire_recovery_credit(
    pool: &Arc<RecoveryCreditPool>,
) -> Option<OwnedSemaphorePermit> {
    pool.semaphore.clone().try_acquire_owned().ok()
}

/// An explicit caller waits for its credit instead of deferring.
pub(crate) async fn acquire_recovery_credit(
    pool: &Arc<RecoveryCreditPool>,
) -> OwnedSemaphorePermit {
    pool.semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("the recovery credit pool is never closed")
}

#[cfg(test)]
pub(crate) fn available_credits(pool: &Arc<RecoveryCreditPool>) -> usize {
    pool.semaphore.available_permits()
}

#[cfg(test)]
pub(crate) fn hold_all_credits_for_test(pool: &Arc<RecoveryCreditPool>) -> OwnedSemaphorePermit {
    pool.semaphore
        .clone()
        .try_acquire_many_owned(MAX_CONCURRENT_JOBS as u32)
        .expect("fixture owns all recovery credits")
}
