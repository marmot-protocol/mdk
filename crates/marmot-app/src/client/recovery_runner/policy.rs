//! The runner's starting values (decision 7 of mdk#2660's phase 4 plan),
//! registered as convergence-ledger decision A19. They are tuned in the
//! simulator once the runner admits what it fetches (PR 4b or PR 5).

use std::time::Duration;

use storage_sqlite::RecoveryUnitPolicy;
use transport_nostr_adapter::sweep::SweepPolicy;

/// The first no-progress backoff of a unit; each further one doubles it.
pub(crate) const RUNNER_BACKOFF_BASE_SECS: u64 = 30;
pub(crate) const RUNNER_BACKOFF_CAP_SECS: u64 = 60 * 60;
/// No-progress answers in a row before a unit breaks. With the backoff above,
/// six answers take about 15 minutes.
pub(crate) const RUNNER_BREAK_AFTER_NO_PROGRESS: u32 = 6;
/// How long a unit whose relay was unreachable waits before its next attempt.
pub(crate) const RUNNER_UNREACHABLE_RETRY_SECS: u64 = 30;
/// Unreachable results in a row before the relay cools down.
pub(crate) const RUNNER_COOLDOWN_AFTER_UNREACHABLE: u32 = 3;
/// The first relay cooldown; each further one doubles it. A reconnect ends it.
pub(crate) const RUNNER_COOLDOWN_BASE_SECS: u64 = 60;
pub(crate) const RUNNER_COOLDOWN_CAP_SECS: u64 = 60 * 60;
/// Quanta per rolling hour before the account breaker pauses the runner.
pub(crate) const RUNNER_MAX_QUANTA_PER_HOUR: u64 = 720;
/// Fetched event bytes per rolling hour before the account breaker pauses.
pub(crate) const RUNNER_MAX_EVENT_BYTES_PER_HOUR: u64 = 256 * 1024 * 1024;
/// One quantum's network deadline.
pub(crate) const RUNNER_QUANTUM: Duration = Duration::from_secs(10);
/// One relay request's own timeout. Shorter than [`RUNNER_QUANTUM`], so a
/// quantum the deadline cut before any answer was preempted, never slow.
pub(crate) const RUNNER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// A local failure (staging or a ledger write) holds its unit back in memory,
/// doubling from the base to the cap, as worker retries do.
pub(crate) const RUNNER_LOCAL_FAILURE_BACKOFF_BASE_SECS: u64 = 1;
pub(crate) const RUNNER_LOCAL_FAILURE_BACKOFF_CAP_SECS: u64 = 60;
/// Staged events one relay may hold for a group before it waits for the
/// group's laggard (PR 4b).
pub(crate) const RUNNER_STAGED_GROUP_EVENTS: u64 = 2_048;
pub(crate) const RUNNER_STAGED_GROUP_BYTES: u64 = 8 * 1024 * 1024;
/// Staged bytes the whole account may hold (PR 4b).
pub(crate) const RUNNER_STAGED_ACCOUNT_BYTES: u64 = 64 * 1024 * 1024;

/// How much fetched history may wait in staging (PR 4b reads these).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryStagingBounds {
    pub(crate) group_events: u64,
    pub(crate) group_bytes: u64,
    pub(crate) account_bytes: u64,
}

/// Every value the runner schedules by, in one place.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecoveryRunnerPolicy {
    /// The outcome table's budgets and the account caps, as storage applies them.
    pub(crate) unit: RecoveryUnitPolicy,
    pub(crate) quantum: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) local_failure_backoff_base_seconds: u64,
    pub(crate) local_failure_backoff_cap_seconds: u64,
    pub(crate) staging: RecoveryStagingBounds,
    pub(crate) sweep: SweepPolicy,
}

impl Default for RecoveryRunnerPolicy {
    fn default() -> Self {
        Self {
            unit: RecoveryUnitPolicy {
                backoff_base_seconds: RUNNER_BACKOFF_BASE_SECS,
                backoff_cap_seconds: RUNNER_BACKOFF_CAP_SECS,
                break_after_no_progress: RUNNER_BREAK_AFTER_NO_PROGRESS,
                unreachable_retry_seconds: RUNNER_UNREACHABLE_RETRY_SECS,
                cooldown_after_unreachable: RUNNER_COOLDOWN_AFTER_UNREACHABLE,
                cooldown_base_seconds: RUNNER_COOLDOWN_BASE_SECS,
                cooldown_cap_seconds: RUNNER_COOLDOWN_CAP_SECS,
                max_attempts_per_hour: RUNNER_MAX_QUANTA_PER_HOUR,
                max_event_bytes_per_hour: RUNNER_MAX_EVENT_BYTES_PER_HOUR,
            },
            quantum: RUNNER_QUANTUM,
            request_timeout: RUNNER_REQUEST_TIMEOUT,
            local_failure_backoff_base_seconds: RUNNER_LOCAL_FAILURE_BACKOFF_BASE_SECS,
            local_failure_backoff_cap_seconds: RUNNER_LOCAL_FAILURE_BACKOFF_CAP_SECS,
            staging: RecoveryStagingBounds {
                group_events: RUNNER_STAGED_GROUP_EVENTS,
                group_bytes: RUNNER_STAGED_GROUP_BYTES,
                account_bytes: RUNNER_STAGED_ACCOUNT_BYTES,
            },
            sweep: SweepPolicy::default(),
        }
    }
}

impl RecoveryRunnerPolicy {
    /// The in-memory hold after `failures` local failures in a row.
    pub(crate) fn local_failure_backoff_seconds(&self, failures: u32) -> u64 {
        let doubled = 1u64
            .checked_shl(failures.saturating_sub(1))
            .unwrap_or(u64::MAX);
        self.local_failure_backoff_base_seconds
            .saturating_mul(doubled)
            .min(self.local_failure_backoff_cap_seconds)
    }
}
