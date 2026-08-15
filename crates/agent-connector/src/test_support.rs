//! Test-only output support for the ignored reconciliation benchmark
//! (`bench_idle_reconciliation_scaling`, mdk#1380). Kept in a file named
//! exactly `test_support.rs` so the workspace direct-output audit
//! (`tracing_audit.rs`) treats the explicit benchmark report as artifact
//! output, matching the storage-upgrade benchmark convention.

use std::sync::atomic::AtomicU64;

pub(crate) fn emit_benchmark_line(line: String) {
    println!("{line}");
}

/// Test-only fault-injection hooks for the invite-policy worker (mdk#1380).
/// Kept behind `#[cfg(test)]` so production builds carry no test surface.
#[derive(Debug)]
pub(crate) struct ConnectorTestHooks {
    /// Remaining successful invite-policy enumerations before every later one
    /// fails (simulates a locked/closed account database).
    pub(crate) invite_enumeration_successes_before_failure: AtomicU64,
    /// Milliseconds each invite-policy apply attempt sleeps before running,
    /// simulating a slow account-worker response.
    pub(crate) invite_apply_delay_ms: AtomicU64,
    /// Remaining apply attempts that honor `invite_apply_delay_ms`.
    pub(crate) invite_apply_delays_remaining: AtomicU64,
}

impl Default for ConnectorTestHooks {
    fn default() -> Self {
        Self {
            invite_enumeration_successes_before_failure: AtomicU64::new(u64::MAX),
            invite_apply_delay_ms: AtomicU64::new(0),
            invite_apply_delays_remaining: AtomicU64::new(u64::MAX),
        }
    }
}
