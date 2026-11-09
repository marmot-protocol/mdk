//! What the account worker's scheduled jobs owe, read cheaply, so each runs
//! on its own wake or deadline instead of on every maintenance tick
//! (mdk#2923 step B). Memory and at most a few indexed reads; a failed read
//! counts as owed, so the job still runs.
use super::AppClient;

impl AppClient {
    /// Whether the content-report backfill has batches left for the opened
    /// database. Memory only once it has finished.
    pub(crate) fn content_report_backfill_owed(&self) -> bool {
        self.app
            .account_storage(&self.state.label)
            .map_or(true, |storage| {
                self.content_report_backfill_done != Some(storage.app_storage().connection_serial())
            })
    }

    /// Whether linking has anything its timers still run: state in memory,
    /// or a device group, join, move or link stored. Never with device
    /// pairing compiled out or device groups off.
    pub(crate) fn device_pairing_owed(&self) -> bool {
        #[cfg(feature = "unreleased-device-pairing")]
        if self.app.device_groups_enabled() && !self.signing_out() {
            return self.device_pairing.has_state()
                || self
                    .app
                    .account_storage(&self.state.label)
                    .and_then(|storage| Ok(storage.app_storage().device_pairing_state_exists()?))
                    .unwrap_or(true);
        }
        false
    }

    /// Whether push gossip waits on fetch time: a join window open, an
    /// announce owed, or a repair ask held. The fetch clock counts only when
    /// sampled, so the worker samples it every 15 s while this holds.
    pub(crate) fn push_timing_owed(&self) -> bool {
        self.push_repairs.holds_asks()
            || self
                .app
                .account_storage(&self.state.label)
                .and_then(|storage| Ok(storage.app_storage().push_gossip_timing_pending()?))
                .unwrap_or(true)
    }

    /// When the KeyPackage catch-up next comes due by time alone, in unix
    /// seconds. A failed read gives none; the catch-up check itself still
    /// runs on its wakes.
    pub(crate) fn key_package_catch_up_next_at(&self) -> Option<u64> {
        if self.app.cursor_persistence() != crate::CursorPersistence::Advance {
            return None;
        }
        self.runtime
            .key_package_maintenance_next_due()
            .ok()
            .flatten()
            .map(|at| at.0)
    }

    /// When history dispatch next has work, in unix seconds: a restore
    /// waiting for a slot now; with device groups on and maintenance
    /// running, the earliest history upload, fetch, backup pass or condemned
    /// blob deadline. `None` when nothing is owed.
    pub(crate) fn history_dispatch_next_at(&self) -> Option<u64> {
        if self.backup_restore.waiting() {
            return Some(0);
        }
        if !self.app.device_groups_enabled() || self.runtime.maintenance_is_paused() {
            return None;
        }
        self.app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.app_storage().history_dispatch_next_at()?))
            .unwrap_or(Some(0))
    }

    /// A history delivery was owed, parked or backed off: the worker
    /// re-reads the dispatch deadline on its next turn.
    pub(crate) fn note_history_dispatch_changed(&self) {
        self.history_dispatch_changed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether an app-owned local submission waits to be published.
    pub(crate) fn local_submission_pending(&self) -> bool {
        self.app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.app_storage().next_local_submission()?))
            .map_or(true, |next| next.is_some())
    }
}
