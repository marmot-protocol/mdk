//! Privacy-safe aggregate counters for the connector's background
//! reconciliation loops (mdk#1380): the shared inbound catch-up driver and the
//! welcomer-allowlist invite-policy worker.
//!
//! Everything here is a process-local cumulative counter — no account ids,
//! group ids, message ids, relay URLs, endpoints, or content. Per-pass
//! duration/outcome detail is emitted through `tracing` at the call sites with
//! an explicit `source` label; this module owns only the counters that the
//! large-session regression harness asserts on and that operators can diff
//! between scrapes.

use std::sync::atomic::{AtomicU64, Ordering};

/// Which background reconciliation source a scheduled pass belongs to. Used as
/// the `source` field on per-pass tracing events so operators can attribute
/// cost without any per-account or per-group label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReconcileSource {
    /// The shared catch-up driver serving `SubscribeInbound` clients.
    InboundCatchUp,
    /// The welcomer-allowlist invite-policy worker.
    InvitePolicy,
}

impl ReconcileSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InboundCatchUp => "inbound_catch_up",
            Self::InvitePolicy => "invite_policy",
        }
    }
}

/// Cumulative counters for the connector's background reconciliation loops.
/// All counters are monotonically increasing for the process lifetime.
#[derive(Default)]
pub(crate) struct ReconcileTelemetry {
    // ---- Inbound catch-up driver ----
    /// Scheduled/safety-net or activity-triggered passes started.
    pub(crate) catch_up_passes_started: AtomicU64,
    pub(crate) catch_up_passes_completed: AtomicU64,
    pub(crate) catch_up_passes_failed: AtomicU64,
    /// Completed passes that observed qualifying runtime activity at wake time
    /// or while running (these keep the safety net at its base interval).
    pub(crate) catch_up_passes_with_activity: AtomicU64,
    /// Sum of running account workers considered across completed passes.
    pub(crate) catch_up_accounts_considered: AtomicU64,
    /// Explicit out-of-band requests (a subscription's initial catch-up).
    pub(crate) catch_up_explicit_requests: AtomicU64,

    // ---- Invite-policy worker ----
    /// Full enumerations of pending invite candidates started.
    pub(crate) invite_enumerations_started: AtomicU64,
    pub(crate) invite_enumerations_completed: AtomicU64,
    pub(crate) invite_enumerations_failed: AtomicU64,
    /// Sum of local-signing accounts enumerated across passes.
    pub(crate) invite_accounts_considered: AtomicU64,
    /// Sum of pending-invite projection rows read across enumerations. This is
    /// the database-read amplification gauge for this source: on an idle
    /// session it must stay zero, independent of retained history size.
    pub(crate) invite_candidate_rows_considered: AtomicU64,
    /// Policy decisions applied (invite accepted or declined).
    pub(crate) invite_policy_applied: AtomicU64,
    /// Policy apply attempts that failed and are retry-pending.
    pub(crate) invite_policy_apply_failures: AtomicU64,
}

/// Point-in-time copy of [`ReconcileTelemetry`], for harness assertions.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReconcileTelemetrySnapshot {
    pub(crate) catch_up_passes_started: u64,
    pub(crate) catch_up_passes_completed: u64,
    pub(crate) catch_up_passes_failed: u64,
    pub(crate) catch_up_passes_with_activity: u64,
    pub(crate) catch_up_accounts_considered: u64,
    pub(crate) catch_up_explicit_requests: u64,
    pub(crate) invite_enumerations_started: u64,
    pub(crate) invite_enumerations_completed: u64,
    pub(crate) invite_enumerations_failed: u64,
    pub(crate) invite_accounts_considered: u64,
    pub(crate) invite_candidate_rows_considered: u64,
    pub(crate) invite_policy_applied: u64,
    pub(crate) invite_policy_apply_failures: u64,
}

impl ReconcileTelemetry {
    pub(crate) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn add(counter: &AtomicU64, value: usize) {
        counter.fetch_add(value as u64, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> ReconcileTelemetrySnapshot {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        ReconcileTelemetrySnapshot {
            catch_up_passes_started: load(&self.catch_up_passes_started),
            catch_up_passes_completed: load(&self.catch_up_passes_completed),
            catch_up_passes_failed: load(&self.catch_up_passes_failed),
            catch_up_passes_with_activity: load(&self.catch_up_passes_with_activity),
            catch_up_accounts_considered: load(&self.catch_up_accounts_considered),
            catch_up_explicit_requests: load(&self.catch_up_explicit_requests),
            invite_enumerations_started: load(&self.invite_enumerations_started),
            invite_enumerations_completed: load(&self.invite_enumerations_completed),
            invite_enumerations_failed: load(&self.invite_enumerations_failed),
            invite_accounts_considered: load(&self.invite_accounts_considered),
            invite_candidate_rows_considered: load(&self.invite_candidate_rows_considered),
            invite_policy_applied: load(&self.invite_policy_applied),
            invite_policy_apply_failures: load(&self.invite_policy_apply_failures),
        }
    }
}
