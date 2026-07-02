//! RAII guard for snapshot lifecycle.
//!
//! The engine creates short-lived snapshots in several places to safely
//! probe past state (peeling against retained epoch contexts; replaying
//! candidate paths; canonicalize-and-apply windows). The pattern is:
//!
//! 1. Create a snapshot of the live group state.
//! 2. Mutate storage (rollback to a different snapshot, replay messages).
//! 3. Roll back to the snapshot from step 1 to restore the live state.
//! 4. Release the snapshot.
//!
//! If anything between steps 1 and 3 panics or the future is dropped
//! while this guard is live, the snapshot is leaked AND the storage is in
//! mid-mutation state. The next operation on the group sees corrupted
//! state.
//!
//! [`SnapshotRollbackGuard`] turns this into a `Drop`-based RAII pattern.
//! On creation it makes the snapshot. On `Drop` (panic, early error,
//! or scope exit) it rolls back to that snapshot and releases it,
//! restoring the live state regardless of the unwind path. Happy-path
//! callers explicitly call [`SnapshotRollbackGuard::commit`] which runs
//! the rollback + release once and disarms the `Drop` so it doesn't
//! repeat the work.

use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};
use cgka_traits::types::GroupId;

const TRACE_TARGET: &str = "cgka_engine::snapshot_guard";

/// Owns a freshly-created snapshot. Drop rolls back to the snapshot and
/// releases it. Call [`Self::commit`] on the happy path to perform the
/// rollback + release explicitly; that disarms the guard so Drop is a
/// no-op afterwards.
pub(crate) struct SnapshotRollbackGuard<'a, S: StorageProvider> {
    storage: &'a S,
    group_id: GroupId,
    name: String,
    armed: bool,
}

impl<'a, S: StorageProvider> SnapshotRollbackGuard<'a, S> {
    /// Create a snapshot named `name` for `group_id` and return a guard.
    pub(crate) fn create(storage: &'a S, group_id: GroupId, name: String) -> StorageResult<Self> {
        storage.create_group_snapshot(&group_id, &name)?;
        Ok(Self {
            storage,
            group_id,
            name,
            armed: true,
        })
    }

    /// Run rollback + release once and disarm the guard. Returns
    /// `Ok(())` if the snapshot is no longer needed; the guard is
    /// consumed.
    pub(crate) fn commit(mut self) -> StorageResult<()> {
        self.storage
            .rollback_group_to_snapshot(&self.group_id, &self.name)?;
        match self
            .storage
            .release_group_snapshot(&self.group_id, &self.name)
        {
            Ok(()) | Err(StorageError::SnapshotMissing(_)) => {
                self.armed = false;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl<'a, S: StorageProvider> Drop for SnapshotRollbackGuard<'a, S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Best-effort cleanup on panic / early-return paths. If the
        // rollback fails the database is in mid-mutation state, but
        // there is nothing more we can do from Drop. Surface a
        // privacy-safe trace so the failure is visible.
        if let Err(_e) = self
            .storage
            .rollback_group_to_snapshot(&self.group_id, &self.name)
        {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "drop",
                "snapshot rollback on panic-unwind failed"
            );
        }
        if let Err(_e) = self
            .storage
            .release_group_snapshot(&self.group_id, &self.name)
        {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "drop",
                "snapshot release on panic-unwind failed"
            );
        }
    }
}
