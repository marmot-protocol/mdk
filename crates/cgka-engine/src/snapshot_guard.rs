//! RAII guard for snapshot lifecycle.
//!
//! The engine creates short-lived snapshots in several places to safely
//! probe past state (peeling against retained epoch contexts; replaying
//! candidate paths; reading historical group state). The pattern is:
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

/// Owns a freshly-created canonical-group-state snapshot. Drop rolls back to
/// the snapshot and releases it. Call [`Self::commit`] on the happy path to
/// perform the rollback + release explicitly; that disarms the guard so Drop
/// is a no-op afterwards.
pub(crate) struct SnapshotRollbackGuard<'a, S: StorageProvider> {
    storage: &'a S,
    group_id: GroupId,
    name: String,
    armed: bool,
}

impl<'a, S: StorageProvider> SnapshotRollbackGuard<'a, S> {
    /// Create a canonical-group-state snapshot named `name` for `group_id` and
    /// return a guard. The message ledger and outbound queue are deliberately
    /// excluded: callers use this guard only around temporary canonical-state
    /// mutations and must leave live input/work collections untouched.
    pub(crate) fn create_group_state(
        storage: &'a S,
        group_id: GroupId,
        name: String,
    ) -> StorageResult<Self> {
        storage.create_group_state_snapshot(&group_id, &name)?;
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
            .rollback_group_state_to_snapshot(&self.group_id, &self.name)?;
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
            .rollback_group_state_to_snapshot(&self.group_id, &self.name)
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

#[cfg(test)]
mod tests {
    use super::SnapshotRollbackGuard;
    use cgka_traits::capabilities::GroupCapabilities;
    use cgka_traits::engine::SendIntent;
    use cgka_traits::group::{Group, ProtocolProfile};
    use cgka_traits::message::{MessageRecord, MessageState};
    use cgka_traits::storage::{
        GroupStorage, MessageStorage, OutboundIntentStorage, QueuedOutboundIntent,
    };
    use cgka_traits::types::{EpochId, GroupId, MessageId};
    use storage_sqlite::SqliteAccountStorage;

    fn group(group_id: &GroupId, epoch: u64, name: &str) -> Group {
        Group {
            id: group_id.clone(),
            name: name.into(),
            description: String::new(),
            epoch: EpochId(epoch),
            members: Vec::new(),
            required_capabilities: GroupCapabilities::default(),
            protocol_profile: ProtocolProfile::Legacy,
            removed: false,
            unrecoverable: false,
            disbanded: None,
            join_epoch: EpochId(0),
        }
    }

    fn message(group_id: &GroupId, id: u8, epoch: u64) -> MessageRecord {
        MessageRecord {
            id: MessageId::new(vec![id]),
            group_id: group_id.clone(),
            epoch: EpochId(epoch),
            state: MessageState::Processed,
            payload: vec![id],
            deferred_peel: None,
        }
    }

    fn queued(group_id: &GroupId, id: u8) -> QueuedOutboundIntent {
        QueuedOutboundIntent {
            id: MessageId::new(vec![id]),
            group_id: group_id.clone(),
            intent: SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: vec![id],
            },
            created_at_ms: u64::from(id),
        }
    }

    #[test]
    fn group_state_guard_does_not_rewrite_live_message_or_queue_rows() {
        let storage = SqliteAccountStorage::in_memory().expect("storage");
        let group_id = GroupId::new(vec![7; 16]);
        let live_group = group(&group_id, 3, "live");
        let original_message = message(&group_id, 1, 2);
        let original_queued = queued(&group_id, 11);
        storage.put_group(&live_group).expect("put live group");
        storage
            .put_message(&original_message)
            .expect("put original message");
        storage
            .put_queued_outbound_intent(&original_queued)
            .expect("put original queued intent");

        let guard = SnapshotRollbackGuard::create_group_state(
            &storage,
            group_id.clone(),
            "temporary-probe".into(),
        )
        .expect("capture live state");

        storage
            .put_group(&group(&group_id, 2, "temporary"))
            .expect("mutate canonical group state");
        let live_message = message(&group_id, 2, 3);
        storage
            .put_message(&live_message)
            .expect("put message while probe is active");
        storage
            .delete_queued_outbound_intent(&original_queued.id)
            .expect("delete original queued intent");
        let live_queued = queued(&group_id, 12);
        storage
            .put_queued_outbound_intent(&live_queued)
            .expect("put live queued intent");

        guard.commit().expect("restore canonical group state");

        assert_eq!(storage.get_group(&group_id).unwrap(), live_group);
        assert_eq!(
            storage.list_messages(&group_id, EpochId(0)).unwrap(),
            vec![original_message, live_message],
            "temporary group-state replay must not restore a captured ledger image"
        );
        assert_eq!(
            storage.list_queued_outbound_intents(&group_id).unwrap(),
            vec![live_queued],
            "temporary group-state replay must not restore a captured queue image"
        );
    }
}
