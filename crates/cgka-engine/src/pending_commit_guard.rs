//! RAII cleanup for locally staged OpenMLS pending commits.
//!
//! Commit-producing send paths stage an OpenMLS pending commit before they
//! cross transport wrapping and storage boundaries. Until the engine creates a
//! `PendingStateRef`, callers have no handle they can later pass to
//! `publish_failed`. This guard closes that orphan window: if the future is
//! dropped or returns early after staging but before the pending lifecycle is
//! handed off, `Drop` clears the OpenMLS pending commit best-effort.
//!
//! Several send paths (invite, auto-commit, remove-members, upgrade,
//! group-data-update) also create a fork-recovery snapshot via
//! `ForkRecoveryManager::create_snapshot` in the same orphan window. The normal
//! failure path `do_publish_failed` releases that snapshot through
//! `forget_pending_commit_for_recovery -> release_group_snapshot`; the guard
//! mirrors that so an early return / cancellation does not leak the
//! `fork-{epoch}-{n}-{hash}` snapshot row. Callers arm the guard *before*
//! creating the snapshot and attach the snapshot name with
//! [`PendingCommitCleanupGuard::set_snapshot`] once `create_snapshot` succeeds,
//! so the create-snapshot-then-stage-commit window is fully covered.
//!
//! `Drop` releases the snapshot only after it has *confirmed* the staged
//! OpenMLS pending commit is gone (the group loads and either has no pending
//! commit or `clear_pending_commit` returns `Ok`). If cleanup cannot be
//! confirmed — the group fails to load, is absent, or clearing errors under
//! transient storage pressure — the snapshot is retained and a warning is
//! logged. Releasing the recovery snapshot while an orphaned staged commit
//! remains would strand that commit with no recovery path, which is strictly
//! worse than the bounded snapshot leak this guard exists to prevent.

use crate::provider::EngineOpenMlsProvider;
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::types::GroupId;
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider as _;

const TRACE_TARGET: &str = "cgka_engine::pending_commit_guard";

/// Clears an OpenMLS pending commit (and releases any attached pre-commit
/// fork-recovery snapshot) on early return / cancellation unless the caller
/// disarms it after creating the engine-level pending state.
pub(crate) struct PendingCommitCleanupGuard<S: StorageProvider> {
    // Raw pointers intentionally avoid extending an immutable borrow of
    // `Engine::storage` across the guarded fallible section; those sections
    // need `&mut self` for message records, recovery tracking, and pending
    // state bookkeeping. The guard is created from `&self.storage` (aggregate,
    // for snapshot release) and `self.storage.mls_storage()` (OpenMLS, for
    // clearing the staged commit), and is dropped before the engine/storage
    // can be dropped.
    storage: *const S,
    mls_storage: *const S::Mls,
    group_id: GroupId,
    // Name of the pre-commit fork-recovery snapshot to release on Drop, if the
    // caller created one. `None` for paths that stage a commit without a
    // snapshot (e.g. group creation).
    snapshot_name: Option<String>,
    armed: bool,
}

// SAFETY: `S` and `StorageProvider::Mls` are `Send + Sync`; the raw pointers
// are only dereferenced from `Drop` while the guarded engine future is alive,
// and all access uses shared-reference (`&self`) storage methods.
unsafe impl<S: StorageProvider> Send for PendingCommitCleanupGuard<S> {}

impl<S: StorageProvider> PendingCommitCleanupGuard<S> {
    pub(crate) fn arm(
        storage: &S,
        provider: &EngineOpenMlsProvider<'_, S>,
        group_id: GroupId,
    ) -> Self {
        Self {
            storage: storage as *const S,
            mls_storage: provider.storage() as *const S::Mls,
            group_id,
            snapshot_name: None,
            armed: true,
        }
    }

    /// Attach the pre-commit fork-recovery snapshot name created in the guarded
    /// window so `Drop` releases it on early return / cancellation. Call this
    /// immediately after `ForkRecoveryManager::create_snapshot` succeeds.
    pub(crate) fn set_snapshot(&mut self, snapshot_name: String) {
        self.snapshot_name = Some(snapshot_name);
    }

    /// The staged commit (and its snapshot) is now tracked by `EpochManager`
    /// and can be cleaned up by the normal `publish_failed` path. Leave it
    /// attached to OpenMLS / storage.
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

impl<S: StorageProvider> Drop for PendingCommitCleanupGuard<S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        // SAFETY: the pointers reference `Engine::storage` (and its
        // `mls_storage()`) from the engine owning the guarded send future. The
        // guard never outlives that future, and the future cannot outlive the
        // engine borrow that created it.
        let storage = unsafe { &*self.storage };
        let mls_storage = unsafe { &*self.mls_storage };

        // Confirm the staged OpenMLS pending commit is actually gone before we
        // release its recovery snapshot. If we cannot prove cleanup succeeded
        // (group fails to load, is absent, or `clear_pending_commit` errors),
        // we must KEEP the snapshot: dropping it while a staged pending commit
        // is still orphaned would strand that commit with no recovery path —
        // strictly worse than the bounded leak this guard exists to prevent.
        let mls_gid = openmls::group::GroupId::from_slice(self.group_id.as_slice());
        let pending_commit_cleared = match MlsGroup::load(mls_storage, &mls_gid) {
            Ok(Some(mut mls_group)) => {
                if mls_group.pending_commit().is_none() {
                    true
                } else {
                    let clear_result: Result<(), StorageError> =
                        storage.with_transaction(|storage| {
                            mls_group
                                .clear_pending_commit(storage.mls_storage())
                                .map_err(|e| StorageError::Backend(format!("clear_pending: {e:?}")))
                        });
                    match clear_result {
                        Ok(()) => true,
                        Err(_e) => {
                            tracing::warn!(
                                target: TRACE_TARGET,
                                method = "drop",
                                "pending commit guard could not clear staged commit"
                            );
                            false
                        }
                    }
                }
            }
            Ok(None) => {
                // No group to clear a pending commit from. We cannot confirm
                // the staged commit is gone, so treat cleanup as unconfirmed
                // and retain the snapshot.
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "drop",
                    "pending commit guard found no group for cleanup"
                );
                false
            }
            Err(_e) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "drop",
                    "pending commit guard could not load group for cleanup"
                );
                false
            }
        };

        // Release the pre-commit fork-recovery snapshot only after confirming
        // the staged pending commit is gone, mirroring
        // `forget_pending_commit_for_recovery` on the normal failure path. A
        // missing snapshot is benign (already released, or never created). If
        // cleanup is unconfirmed, keep the snapshot so the orphaned commit
        // remains recoverable.
        if pending_commit_cleared && let Some(snapshot_name) = self.snapshot_name.as_deref() {
            match storage.release_group_snapshot(&self.group_id, snapshot_name) {
                Ok(()) | Err(StorageError::SnapshotMissing(_)) => {}
                Err(_e) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "drop",
                        "pending commit guard could not release recovery snapshot"
                    );
                }
            }
        } else if self.snapshot_name.is_some() {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "drop",
                "pending commit guard retained recovery snapshot; staged commit cleanup unconfirmed"
            );
        }
    }
}
