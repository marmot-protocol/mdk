//! In-memory, account-local admission for managed worker startup.
//!
//! The caller serializes mutations with `worker_transactions`. Deadlines use
//! Tokio's monotonic clock so paused-time tests and clock changes are safe.

use std::collections::HashMap;
use std::time::Duration;

use tokio::time::Instant;

const RETRY_BASE: Duration = Duration::from_secs(1);
/// A failed worker is eligible again on the next trigger after at most 60 s.
const RETRY_CAP: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug)]
pub(super) struct StartupFailure {
    failures: u32,
    retry_at: Instant,
}

#[derive(Default)]
pub(super) struct WorkerStartupRetries {
    failures: HashMap<String, StartupFailure>,
}

impl WorkerStartupRetries {
    pub(super) fn allows(&self, account_id: &str, now: Instant) -> bool {
        self.failures
            .get(account_id)
            .is_none_or(|failure| now >= failure.retry_at)
    }

    pub(super) fn fail(&mut self, account_id: String, now: Instant) {
        let failures = self
            .failures
            .get(&account_id)
            .map_or(1, |prior| prior.failures.saturating_add(1));
        let multiplier = 1_u64 << failures.saturating_sub(1).min(6);
        let delay = (RETRY_BASE * multiplier as u32).min(RETRY_CAP);
        self.failures.insert(
            account_id,
            StartupFailure {
                failures,
                retry_at: now + delay,
            },
        );
    }

    pub(super) fn clear(&mut self, account_id: &str) {
        self.failures.remove(account_id);
    }

    pub(super) fn retain_eligible(&mut self, eligible: &std::collections::HashSet<String>) {
        self.failures
            .retain(|account_id, _| eligible.contains(account_id));
    }

    pub(super) fn clear_all(&mut self) {
        self.failures.clear();
    }

    #[cfg(test)]
    pub(super) fn extend_deadline_for_test(&mut self, account_id: &str, delay: Duration) {
        self.failures
            .get_mut(account_id)
            .expect("startup failure is recorded")
            .retry_at = Instant::now() + delay;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_delay_is_per_account_capped_and_success_resets_it() {
        let mut retries = WorkerStartupRetries::default();
        let now = Instant::now();
        assert!(retries.allows("alice", now));
        for (attempt, expected_seconds) in [1, 2, 4, 8, 16, 32, 60, 60].into_iter().enumerate() {
            retries.fail("alice".into(), now);
            let deadline = now + Duration::from_secs(expected_seconds);
            assert!(
                !retries.allows("alice", deadline - Duration::from_nanos(1)),
                "attempt {attempt}"
            );
            assert!(retries.allows("alice", deadline), "attempt {attempt}");
            assert!(retries.allows("bob", now));
        }
        retries.clear("alice");
        retries.fail("alice".into(), now);
        assert!(retries.allows("alice", now + Duration::from_secs(1)));
        assert!(!retries.allows("alice", now + Duration::from_millis(999)));
    }

    #[test]
    fn suppression_does_not_extend_an_accounts_deadline() {
        let mut retries = WorkerStartupRetries::default();
        let now = Instant::now();
        retries.fail("alice".into(), now);
        retries.fail("bob".into(), now + Duration::from_millis(500));
        for _ in 0..100 {
            assert!(!retries.allows("alice", now + Duration::from_millis(999)));
        }
        assert!(retries.allows("alice", now + Duration::from_secs(1)));
        assert!(!retries.allows("bob", now + Duration::from_secs(1)));
        assert!(retries.allows("bob", now + Duration::from_millis(1500)));
    }

    #[test]
    fn ineligible_account_loses_old_failure_without_affecting_another() {
        let mut retries = WorkerStartupRetries::default();
        let now = Instant::now();
        retries.fail("alice".into(), now);
        retries.fail("bob".into(), now);
        retries.retain_eligible(&["bob".to_owned()].into_iter().collect());
        assert!(retries.allows("alice", now));
        assert!(!retries.allows("bob", now));
    }
}
