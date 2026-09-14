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
//!
//! Process termination runs neither. The surviving snapshot is then the
//! only copy of the live state, so it must be recognizable at the next
//! open: [`RewindSite`] is the closed set of guard sites that both names
//! the snapshots and drives that recovery
//! (`openmls_projection::recover_interrupted_rewind_guard`).

use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};
use cgka_traits::types::GroupId;

const TRACE_TARGET: &str = "cgka_engine::snapshot_guard";

/// Every engine site that mutates live group state behind a
/// [`SnapshotRollbackGuard`].
///
/// A guard's snapshot name is built only from this closed set, and open-time
/// recovery classifies orphaned snapshots through the same set
/// ([`RewindSite::classify`]). A site therefore cannot exist without being
/// recoverable: the pair that used to drift — six naming sites, two recognized
/// by recovery — is now one enumeration.
///
/// The prefixes are durable. A snapshot row written by an earlier build must
/// still classify after upgrade, because that is what restores the live state
/// of a device whose process died inside a rewind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RewindSite {
    /// Ingest rewinds onto a retained anchor to derive the exporter context
    /// that reads a message from a past epoch.
    PastPeelContext,
    /// Ingest rewinds onto a retained anchor to read the retention policy that
    /// was authenticated at a delayed message's source epoch.
    RetentionSource,
    /// Hydration processes a stored proposal to decide whether it is a
    /// deferred SelfRemove.
    HydrateSelfRemove,
    /// A candidate path is replayed forward onto the current state to observe
    /// its tip.
    Replay,
    /// The convergence pass rewinds onto the retained anchor before replaying
    /// the stored graph.
    RetainedAnchorPass,
    /// The deferred-peel sweep rewinds onto the retained anchor to enumerate
    /// candidate branches.
    CandidateBranchSweep,
}

impl RewindSite {
    const ALL: [Self; 6] = [
        Self::PastPeelContext,
        Self::RetentionSource,
        Self::HydrateSelfRemove,
        Self::Replay,
        Self::RetainedAnchorPass,
        Self::CandidateBranchSweep,
    ];

    /// Durable snapshot-name prefix. No prefix is a prefix of another, so
    /// classification is unambiguous.
    const fn prefix(self) -> &'static str {
        match self {
            Self::PastPeelContext => "peel-restore-",
            Self::RetentionSource => "retention-restore-",
            Self::HydrateSelfRemove => "hydrate-selfremove-probe-",
            Self::Replay => "openmls-probe-",
            Self::RetainedAnchorPass => "openmls-retained-probe-",
            Self::CandidateBranchSweep => "openmls-branch-probe-",
        }
    }

    /// The site that wrote `name`, or `None` for a snapshot no guard created
    /// (retained anchors, convergence-apply snapshots, test fixtures).
    pub(crate) fn classify(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|site| name.starts_with(site.prefix()))
    }

    /// Whether this site's guard window can open inside another site's.
    ///
    /// Only the forward replay of a candidate path can: the convergence pass
    /// and the deferred-peel sweep each replay candidates while rewound onto a
    /// retained anchor, and it also runs on its own. Recovery needs the
    /// distinction because a crash inside a nested window strands two
    /// snapshots: only the outer one holds live state, so the inner one is
    /// released rather than restored.
    pub(crate) const fn may_nest_inside_another_guard(self) -> bool {
        matches!(self, Self::Replay)
    }
}

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
    /// Create a canonical-group-state snapshot for `group_id` and return a
    /// guard. The message ledger and outbound queue are deliberately excluded:
    /// callers use this guard only around temporary canonical-state mutations
    /// and must leave live input/work collections untouched.
    ///
    /// The name is composed from `site` and a caller-chosen `suffix` that
    /// separates concurrent windows of the same site, so every guard snapshot
    /// is classifiable by open-time recovery.
    pub(crate) fn create_group_state(
        storage: &'a S,
        group_id: GroupId,
        site: RewindSite,
        suffix: &str,
    ) -> StorageResult<Self> {
        let name = format!("{}{suffix}", site.prefix());
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
        //
        // Release the snapshot even then. Keeping it looks safer — a failed
        // rollback means live state was not restored — but the guard cannot
        // tell whether this window mutated anything at all. At most sites the
        // first step inside the window is itself a rollback onto a retained
        // anchor, which can fail before changing a byte; the early return then
        // drops an armed guard over untouched live state. A snapshot kept
        // there is stale the moment the group advances, and open-time recovery
        // restores a surviving guard snapshot unconditionally — so it would be
        // written over newer live state at the next open, which is the durable
        // self-rollback this recovery exists to prevent. Keeping the snapshot
        // becomes correct only once the guard knows the window mutated.
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
    use super::{RewindSite, SnapshotRollbackGuard};
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
            local_copy_install_epoch: EpochId(0),
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
                expected_epoch: None,
            },
            created_at_ms: u64::from(id),
            reissue_attempts: 0,
        }
    }

    #[test]
    fn every_guard_snapshot_is_classified_by_the_recovery_set() {
        let storage = SqliteAccountStorage::in_memory().expect("storage");
        let group_id = GroupId::new(vec![9; 16]);
        storage
            .put_group(&group(&group_id, 4, "live"))
            .expect("put live group");

        for site in RewindSite::ALL {
            let guard = SnapshotRollbackGuard::create_group_state(
                &storage,
                group_id.clone(),
                site,
                "0011223344556677",
            )
            .expect("capture live state");
            let classified = storage
                .list_group_snapshots(&group_id)
                .expect("list snapshots")
                .iter()
                .filter_map(|name| RewindSite::classify(name))
                .collect::<Vec<_>>();
            assert_eq!(
                classified,
                vec![site],
                "a guard must leave exactly one snapshot that open-time recovery classifies"
            );
            guard.commit().expect("release guard snapshot");
        }
    }

    /// A device that died inside a rewind is healed by the FIRST open after
    /// upgrade, which requires the prefixes an earlier build wrote to still
    /// classify. These literals are therefore durable, not internal.
    #[test]
    fn snapshot_names_written_by_earlier_builds_stay_classifiable() {
        for (name, site) in [
            ("peel-restore-a1b2c3d4e5f60718", RewindSite::PastPeelContext),
            (
                "retention-restore-81-a1b2c3d4e5f60718",
                RewindSite::RetentionSource,
            ),
            (
                "hydrate-selfremove-probe-a1b2c3d4e5f60718",
                RewindSite::HydrateSelfRemove,
            ),
            ("openmls-probe-a1b2c3d4e5f60718", RewindSite::Replay),
            (
                "openmls-retained-probe-a1b2c3d4e5f60718",
                RewindSite::RetainedAnchorPass,
            ),
            (
                "openmls-branch-probe-a1b2c3d4e5f60718",
                RewindSite::CandidateBranchSweep,
            ),
        ] {
            assert_eq!(RewindSite::classify(name), Some(site), "name: {name}");
        }
        assert_eq!(RewindSite::classify("openmls-retained-anchor-81"), None);
        assert_eq!(RewindSite::classify("openmls-apply-a1b2c3d4"), None);
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
            RewindSite::Replay,
            "temporary-probe",
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
