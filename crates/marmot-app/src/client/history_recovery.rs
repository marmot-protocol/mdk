//! History recovery's ledger side under one parent (mdk#2782): the recovery
//! runner, the coverage-ledger recorder, epoch-gap detection and the "history
//! may be incomplete" notices. Native replay ingress, the delivery spill and
//! the transport cursor are ingest and stay in `client`.
//!
//! [`HistoryRecovery`] holds the ledger side's state as one `AppClient`
//! field. Its fields are private to this subtree: code outside it records a
//! fact or drains an output through one of the component's methods, and a
//! test outside it reaches the state through [`HistoryRecovery::test_state`].

mod epoch_backfill;
pub(crate) mod epoch_stall;
pub(crate) mod history_notices;
pub(in crate::client) mod recovery_coverage;
pub(crate) mod recovery_runner;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cgka_traits::GroupId;

/// Recovery's ledger side (mdk#2782). Its one field is private, so outside
/// this subtree its state is reachable only through the methods below.
pub(crate) struct HistoryRecovery {
    state: HistoryRecoveryState,
}

/// The ledger side's state. Outside this subtree it is reachable only while
/// building a client, before any [`HistoryRecovery`] holds it, or through the
/// test-only [`HistoryRecovery::test_state`].
pub(crate) struct HistoryRecoveryState {
    /// The process credits recovery jobs share. A managed worker installs
    /// its runtime's pool; a directly owned client uses the process pool.
    pub(crate) recovery_credits:
        Arc<crate::runtime::account_worker::recovery_credits::RecoveryCreditPool>,
    /// A directly owned client's in-place recovery runner (mdk#2660 phase 4).
    /// A worker account's runner is the worker's own task, so its client's
    /// seat stays empty.
    pub(crate) recovery_runner: recovery_runner::host::RunnerSeat,
    /// Recovery status has its own notification queue; saving a projection must not consume it.
    pub(crate) pending_recovery_status_updates: HashSet<GroupId>,
    /// The parked recovery set as last announced to hosts ("history may be
    /// incomplete"): one small entry per parked occurrence, compared at each
    /// publication seam so a change raises `HistoryNoticesChanged`.
    pub(crate) history_notice_baseline: Option<history_notices::HistoryNoticeBaseline>,
    /// The recovery runner's survey changed what is catching up since hosts
    /// last heard; the worker's account-level seam drains it into one
    /// `RecoveryStatusChanged` (mdk#2660 phase 4). Only a runner sets it.
    pub(crate) recovery_status_owed: bool,
    /// The coverage ledger's live-boundary recorder state (mdk#2660).
    pub(crate) live_coverage: tokio::sync::Mutex<recovery_coverage::LiveCoverage>,
    /// Epoch-stall escalations the detector has raised but no caller has been
    /// handed yet.
    ///
    /// The detector latches `escalated` one-shot per unrecovered run, so an
    /// escalation dropped by a later `?` on the recording pass is never raised
    /// again. Escalations therefore land here and move onto either a successful
    /// summary or a partial-progress failure before a managed client is rebuilt
    /// (see `AppClient::drain_epoch_stall_escalations`).
    pub(crate) pending_epoch_stall_escalations: Vec<crate::EpochStallEscalation>,
    /// The recovery runner's ownership preparation failed and none has
    /// succeeded since. While it is owed the worker starts no runner; the
    /// paced subscription-refresh retry prepares again.
    pub(crate) runner_preparation_owed: bool,
    /// The retention floor the recovery runner's debt turns last pruned the
    /// ledger to in this process, if any did.
    pub(crate) runner_pruned_floor: Option<u64>,
    /// Each group's local copy (its install epoch) the recovery runner's debt
    /// turns settled in this process, with the relays its routes carried then
    /// (mdk#2660 row 11), so a turn reads the durable copy only for a group
    /// whose copy or carried relays changed since. At most one entry per group
    /// with a current route: each settle drops the rest, and forgetting a
    /// group drops its entry. A missing entry costs one durable read.
    pub(crate) settled_recovery_copies:
        std::collections::HashMap<Vec<u8>, (u64, super::CarriedRoutes)>,
    /// A debt turn settled a changed copy, which raises or clears a rejoin
    /// notice, since the account worker last published account-level
    /// changes. The runner's survey may not change with it (a group already
    /// catching up stays so), so the worker publishes after that turn.
    pub(crate) recovery_copy_settled: bool,
    /// The clock (Unix seconds) the runner's next prune takes its retention
    /// floor from: its previous debt turn's, or before its first, the one the
    /// open seeded standing goals with. It moves only past a prune that
    /// succeeded, so the seconds of a goal seeded since at its own floor wait
    /// for a debt turn to sweep them instead of being parked before one could.
    pub(crate) runner_prune_clock: u64,
    /// Per-group detector for the epoch-gap backfill (commit-loss recovery): it
    /// counts the distinct undecryptable messages a group accumulates at a
    /// stalled epoch. Ephemeral session state, like the pending sets above.
    pub(crate) epoch_stall: epoch_stall::EpochStallDetector,
    /// Detector observations whose SQL write failed. At most one epoch per
    /// group; this buffer owns no dispatch, completion or retry policy.
    pub(crate) pending_recovery_arm_writes: HashMap<GroupId, u64>,
    /// Initial account open or release consumption requires a backfill reload.
    /// Keep this armed after a failed read even if the journal is already empty;
    /// the next synchronized receipt access retries on this same client.
    pub(crate) released_backfill_reload_pending: bool,
    pub(crate) runner_post_join: HashMap<GroupId, recovery_runner::post_join::Collection>,
}

impl HistoryRecovery {
    pub(crate) fn new(state: HistoryRecoveryState) -> Self {
        Self { state }
    }

    /// The state, for a test outside this subtree.
    #[cfg(test)]
    pub(crate) fn test_state(&mut self) -> &mut HistoryRecoveryState {
        &mut self.state
    }

    /// Install the credit pool recovery jobs share, a managed worker's
    /// runtime pool.
    pub(crate) fn set_recovery_credits(
        &mut self,
        pool: Arc<crate::runtime::account_worker::recovery_credits::RecoveryCreditPool>,
    ) {
        self.state.recovery_credits = pool;
    }

    /// The runner's survey changed what is catching up: the worker's
    /// account-level seam owes hosts one `RecoveryStatusChanged`.
    pub(crate) fn owe_recovery_status(&mut self) {
        self.state.recovery_status_owed = true;
    }

    /// Queue a host-visible group's recovery-status notice.
    pub(crate) fn note_recovery_status_update(&mut self, group_id: &GroupId) {
        self.state
            .pending_recovery_status_updates
            .insert(group_id.clone());
    }

    /// Drain the queued recovery-status notices, for the worker's
    /// account-level seam.
    pub(crate) fn take_recovery_status_updates(&mut self) -> HashSet<GroupId> {
        std::mem::take(&mut self.state.pending_recovery_status_updates)
    }

    /// Drain whether a debt turn settled a changed copy since the worker last
    /// published account-level changes.
    pub(crate) fn take_recovery_copy_settled(&mut self) -> bool {
        std::mem::take(&mut self.state.recovery_copy_settled)
    }

    /// Drop the epoch-gap run of a group whose recovery cleared.
    pub(crate) fn clear_recovered_group(&mut self, group_id: &GroupId) {
        self.state.epoch_stall.clear_recovered_group(group_id);
    }

    /// Whether a detector observation's SQL write failed and waits to be
    /// retried, which keeps the recovery seam owed (mdk#2923).
    pub(crate) fn has_buffered_epoch_gap_arms(&self) -> bool {
        !self.state.pending_recovery_arm_writes.is_empty()
    }

    /// Whether a post-join collection is in progress (mdk#2923).
    pub(crate) fn has_post_join_collections(&self) -> bool {
        !self.state.runner_post_join.is_empty()
    }

    /// Drop every post-join collection: frozen cursors and paused maintenance
    /// hold none.
    pub(crate) fn clear_post_join_collections(&mut self) {
        self.state.runner_post_join.clear();
    }

    /// Forget a forgotten group's queued recovery-status notice.
    pub(crate) fn forget_recovery_status_update(&mut self, group_id: &GroupId) {
        self.state.pending_recovery_status_updates.remove(group_id);
    }

    /// Forget a forgotten group's epoch-gap evidence: its unreported
    /// escalations, its detector run and its buffered arm.
    pub(crate) fn forget_epoch_gap(&mut self, group_id: &GroupId) {
        self.state
            .pending_epoch_stall_escalations
            .retain(|event| &event.group_id != group_id);
        self.state.epoch_stall.clear_recovered_group(group_id);
        self.state.pending_recovery_arm_writes.remove(group_id);
    }

    /// Forget a forgotten group's settled copy.
    pub(crate) fn forget_settled_recovery_copy(&mut self, group_id: &GroupId) {
        self.state
            .settled_recovery_copies
            .remove(group_id.as_slice());
    }

    /// The undecryptable-message count that arms an epoch-gap backfill.
    pub(crate) fn epoch_stall_threshold(&self) -> usize {
        self.state.epoch_stall.threshold()
    }

    /// The arm count after which an unrecovered run escalates.
    pub(crate) fn epoch_stall_escalation_arm_threshold(&self) -> u32 {
        self.state.epoch_stall.escalation_arm_threshold()
    }

    /// The detector observations whose SQL write failed, as durable arms to
    /// retry.
    pub(crate) fn buffered_epoch_gap_arms(&self) -> Vec<storage_sqlite::StoredEpochBackfillIntent> {
        self.state
            .pending_recovery_arm_writes
            .iter()
            .map(|(group, epoch)| storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(group.as_slice()),
                stalled_epoch: *epoch,
            })
            .collect::<Vec<_>>()
    }

    /// Drop the buffered arms once their retry succeeded.
    pub(crate) fn clear_buffered_epoch_gap_arms(&mut self) {
        self.state.pending_recovery_arm_writes.clear();
    }

    /// Note consumed release receipts: any released receipt owes a backfill
    /// reload.
    pub(crate) fn note_released_receipts(&mut self, released: bool) {
        self.state.released_backfill_reload_pending |= released;
    }

    /// Whether a backfill reload is owed.
    pub(crate) fn released_backfill_reload_pending(&self) -> bool {
        self.state.released_backfill_reload_pending
    }

    /// The owed backfill reload succeeded.
    pub(crate) fn finish_released_backfill_reload(&mut self) {
        self.state.released_backfill_reload_pending = false;
    }
}
