//! RAII cleanup for locally staged OpenMLS pending commits.
//!
//! Commit-producing send paths stage an OpenMLS pending commit before they
//! cross transport wrapping and storage boundaries. Until the engine creates a
//! `PendingStateRef`, callers have no handle they can later pass to
//! `publish_failed`. This guard closes that orphan window: if the future is
//! dropped or returns early after staging but before the pending lifecycle is
//! handed off, `Drop` clears the OpenMLS pending commit best-effort.

use crate::provider::EngineOpenMlsProvider;
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::types::GroupId;
use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::group::{MlsGroup, RemoveProposalError};
use openmls_traits::OpenMlsProvider as _;

const TRACE_TARGET: &str = "cgka_engine::pending_commit_guard";

/// Clears an OpenMLS pending commit on early return / cancellation unless the
/// caller disarms it after creating the engine-level pending state.
pub(crate) struct PendingCommitCleanupGuard<S: StorageProvider> {
    // Raw pointers intentionally avoid extending an immutable borrow of
    // `Engine::storage` across the guarded fallible section; those sections
    // need `&mut self` for message records, recovery tracking, and pending
    // state bookkeeping. The guard is created from `&self.storage` (aggregate,
    // for the transactional clear) and `self.storage.mls_storage()` (OpenMLS,
    // for clearing the staged commit), and is dropped before the
    // engine/storage can be dropped.
    storage: *const S,
    mls_storage: *const S::Mls,
    group_id: GroupId,
    // Proposals this staging attempt stored via `store_pending_proposal`, to
    // remove from the OpenMLS proposal store on Drop. Empty for send paths,
    // which commit proposals they did not store themselves.
    stored_proposal_refs: Vec<ProposalRef>,
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
            stored_proposal_refs: Vec::new(),
            armed: true,
        }
    }

    /// Attach the reference of a proposal the guarded path stored via
    /// `store_pending_proposal`, so `Drop` restores the proposal store to its
    /// pre-attempt state. A stale stored proposal is not benign residue:
    /// OpenMLS 0.8.1 panics when a later `remove_members` commit filters a
    /// leftover SelfRemove proposal against a Remove for the same leaf.
    pub(crate) fn set_stored_proposal_ref(&mut self, proposal_ref: ProposalRef) {
        self.stored_proposal_refs.push(proposal_ref);
    }

    /// The staged commit is now tracked by `EpochManager` and can be cleaned
    /// up by the normal `publish_failed` path. Leave it attached to
    /// OpenMLS / storage.
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

        // Clear the staged OpenMLS pending commit best-effort. A failure is
        // logged but must not panic in Drop.
        let mls_gid = openmls::group::GroupId::from_slice(self.group_id.as_slice());
        let mut loaded_group = match MlsGroup::load(mls_storage, &mls_gid) {
            Ok(Some(mls_group)) => Some(mls_group),
            Ok(None) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "drop",
                    "pending commit guard found no group for cleanup"
                );
                None
            }
            Err(_e) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "drop",
                    "pending commit guard could not load group for cleanup"
                );
                None
            }
        };
        if let Some(mls_group) = loaded_group.as_mut()
            && mls_group.pending_commit().is_some()
        {
            let clear_result: Result<(), StorageError> = storage.with_transaction(|storage| {
                mls_group
                    .clear_pending_commit(storage.mls_storage())
                    .map_err(|e| StorageError::Backend(format!("clear_pending: {e:?}")))
            });
            if clear_result.is_err() {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "drop",
                    "pending commit guard could not clear staged commit"
                );
            }
        }

        // Restore the proposal store to its pre-attempt state when this path
        // stored the proposal itself. Best-effort: a proposal that is already
        // gone is benign (`clear_pending_commit` does not remove stored
        // proposals, but a concurrent merge would have consumed it).
        if let Some(mls_group) = loaded_group.as_mut() {
            for proposal_ref in &self.stored_proposal_refs {
                match mls_group.remove_pending_proposal(mls_storage, proposal_ref) {
                    Ok(()) | Err(RemoveProposalError::ProposalNotFound) => {}
                    Err(_e) => {
                        tracing::warn!(
                            target: TRACE_TARGET,
                            method = "drop",
                            "pending commit guard could not remove stored proposal"
                        );
                    }
                }
            }
        }
    }
}
