//! RAII cleanup for locally staged OpenMLS pending commits.
//!
//! Commit-producing send paths stage an OpenMLS pending commit before they
//! cross transport wrapping and storage boundaries. Until the engine creates a
//! `PendingStateRef`, callers have no handle they can later pass to
//! `publish_failed`. This guard closes that orphan window: if the future is
//! dropped or returns early after staging but before the pending lifecycle is
//! handed off, `Drop` clears the OpenMLS pending commit best-effort.

use crate::provider::EngineOpenMlsProvider;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::GroupId;
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider as _;

const TRACE_TARGET: &str = "cgka_engine::pending_commit_guard";

/// Clears an OpenMLS pending commit on early return / cancellation unless the
/// caller disarms it after creating the engine-level pending state.
pub(crate) struct PendingCommitCleanupGuard<S: StorageProvider> {
    // Raw pointer intentionally avoids extending an immutable borrow of
    // `Engine::storage` across the guarded fallible section; those sections
    // need `&mut self` for message records, recovery tracking, and pending
    // state bookkeeping. The guard is created from `self.storage.mls_storage()`
    // and is dropped before the engine/storage can be dropped.
    storage: *const S::Mls,
    group_id: GroupId,
    armed: bool,
}

// SAFETY: `StorageProvider::Mls` is `Send + Sync`; the raw pointer is only
// dereferenced from `Drop` while the guarded engine future is alive, and all
// access uses the OpenMLS storage API's shared-reference methods.
unsafe impl<S: StorageProvider> Send for PendingCommitCleanupGuard<S> {}

impl<S: StorageProvider> PendingCommitCleanupGuard<S> {
    pub(crate) fn arm(provider: &EngineOpenMlsProvider<'_, S>, group_id: GroupId) -> Self {
        Self {
            storage: provider.storage() as *const S::Mls,
            group_id,
            armed: true,
        }
    }

    /// The staged commit is now tracked by `EpochManager` and can be cleaned up
    /// by the normal `publish_failed` path. Leave it attached to OpenMLS.
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

impl<S: StorageProvider> Drop for PendingCommitCleanupGuard<S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        // SAFETY: `storage` points at `Engine::storage.mls_storage()` from the
        // engine owning the guarded send future. The guard never outlives that
        // future, and the future cannot outlive the engine borrow that created
        // it.
        let storage = unsafe { &*self.storage };
        let mls_gid = openmls::group::GroupId::from_slice(self.group_id.as_slice());
        let mut mls_group = match MlsGroup::load(storage, &mls_gid) {
            Ok(Some(group)) => group,
            Ok(None) => return,
            Err(_e) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "drop",
                    "pending commit guard could not load group for cleanup"
                );
                return;
            }
        };

        if mls_group.pending_commit().is_none() {
            return;
        }

        if let Err(_e) = mls_group.clear_pending_commit(storage) {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "drop",
                "pending commit guard could not clear staged commit"
            );
        }
    }
}
