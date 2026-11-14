//! Rollback guards around temporary rewinds of live group state.
//!
//! The engine reads past group state by rewinding the live group record and
//! OpenMLS state onto a retained anchor or replaying candidate commits onto it,
//! reading, and restoring the live state. Every such window runs behind a
//! [`SnapshotRollbackGuard`]: it snapshots the live state first and restores it
//! on every exit path, panic included.
//!
//! A window is one of two kinds, and the constructor its site calls is the
//! classification, so no window opens without one (mdk#3272):
//!
//! - **Contained** ([`SnapshotRollbackGuard::contained`]): the window runs
//!   inside a group savepoint that also holds the snapshot, so nothing it
//!   writes commits before its restore. A failed restore fails the savepoint,
//!   which undoes the whole window and leaves live state as it was, wherever
//!   the caller's transaction boundary is. Tracking backends use this boundary
//!   for short historical peel-context captures, before any async peeler runs.
//!   This needs a backend with atomic group savepoints
//!   (`StorageProvider::has_atomic_group_savepoints`). Elsewhere nothing can
//!   contain the window, so it commits as it goes and writes only the guard's
//!   own snapshot, the one open-time recovery restores after a crash: the
//!   savepoint's fallback snapshot would be a second, and recovery refuses to
//!   choose between two (mdk#3278). Such a window fails as a committing one
//!   does: a restore that fails keeps the snapshot, the only copy of the live
//!   state, and records the group in the session's [`Rewinds`], and so does a
//!   release that fails. Inside an enclosing committing window the enclosing
//!   snapshot holds that state instead, so the nested one is released and the
//!   enclosing window answers for the group.
//! - **Committing** ([`SnapshotRollbackGuard::rewind`]): the window opens with
//!   a rewind onto a retained anchor outside any transaction, so its writes
//!   commit as they happen. The convergence pass and the deferred-peel sweep
//!   replay whole commit graphs in these windows, too long to hold one write
//!   transaction. A rewind that fails commits nothing, so the guard releases
//!   its snapshot and the group stays live. Once the rewind has succeeded, a
//!   restore that fails leaves the group on anchor state: the guard keeps its
//!   snapshot, the only copy of the live state, and records the group in the
//!   session's [`Rewinds`]. The engine quarantines it for
//!   `RewindRestoreFailed`, which nothing clears for the rest of the session,
//!   and the next engine built on the storage restores the snapshot before it
//!   reads any group state
//!   (`openmls_projection::recover_interrupted_rewind_guards_at_open`). A snapshot
//!   that survives because its release failed is recorded too: it refuses
//!   every later committing window and the next open restores it, so the
//!   group must not advance past it meanwhile. Without atomic group savepoints
//!   a committing window also releases the snapshots its nested windows left
//!   before its own, and keeps its own when it cannot: the next open must not
//!   find a nested snapshot alone and restore it as if it held live state.
//!
//! Process termination inside a committing window leaves the same evidence: the
//! surviving snapshot is the only copy of the live state, so it must be
//! recognizable at the next open, and restored there before anything reads the
//! anchor's record. [`RewindSite`] is the closed set of guard
//! sites that both names the snapshots and drives that recovery. A contained
//! window strands nothing: its savepoint never committed. Without atomic
//! savepoints it strands its one snapshot, as a committing window does.

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
    /// that reads a message from a past epoch. Tracking backends contain this
    /// window. Its prefix also recovers committing windows on other backends
    /// and windows stranded by earlier builds.
    PastPeelContext,
    /// Ingest rewinds onto a retained anchor to read the retention policy that
    /// was authenticated at a delayed message's source epoch.
    RetentionSource,
    /// The app, or canonical apply before it merges commits that could prune
    /// the anchor, rewinds onto a retained anchor to derive the
    /// encrypted-media exporter secret of a past epoch that a received media
    /// message names.
    EncryptedMediaSource,
    /// Authenticate delayed moderation policy outside any replay guard.
    ModerationSource,
    /// The app rewinds onto a retained anchor to read the device tag of the
    /// leaf that sent a device-group message in a past epoch.
    DeviceTagSource,
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
    const ALL: [Self; 9] = [
        Self::PastPeelContext,
        Self::RetentionSource,
        Self::EncryptedMediaSource,
        Self::ModerationSource,
        Self::DeviceTagSource,
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
            Self::EncryptedMediaSource => "encrypted-media-source-restore-",
            Self::ModerationSource => "moderation-source-restore-",
            Self::DeviceTagSource => "device-tag-source-restore-",
            Self::HydrateSelfRemove => "hydrate-selfremove-probe-",
            Self::Replay => "openmls-probe-",
            Self::RetainedAnchorPass => "openmls-retained-probe-",
            Self::CandidateBranchSweep => "openmls-branch-probe-",
        }
    }

    /// Every site's durable prefix, for finding interrupted windows in all
    /// groups at once.
    pub(crate) fn prefixes() -> [&'static str; 9] {
        Self::ALL.map(Self::prefix)
    }

    /// The durable name of this site's snapshot for `suffix`.
    pub(crate) fn snapshot_name(self, suffix: &str) -> String {
        format!("{}{suffix}", self.prefix())
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
    /// retained anchor, and it also runs on its own. Its window is contained
    /// now, so a crash inside it strands nothing on a backend with atomic
    /// group savepoints. Earlier builds committed it, as backends without them
    /// still do, and a crash inside a nested window then strands two
    /// snapshots: only the outer one holds live state, so recovery releases
    /// the inner one rather than restoring it.
    pub(crate) const fn may_nest_inside_another_guard(self) -> bool {
        matches!(self, Self::Replay)
    }
}

/// Groups whose committing-window restore failed, or whose committing-window
/// snapshot survived a failed release, and that the engine has not yet
/// quarantined (mdk#3272). A new engine starts with the groups whose
/// interrupted rewind its construction could not restore.
///
/// The engine owns one for each session and hands it to every committing
/// window. A guard cannot reach the engine's quarantine, so it records the
/// failure here and `Engine::quarantine_failed_rewinds` moves the group into
/// quarantine for `RewindRestoreFailed`. Until then the engine's quarantine
/// lookup reads this list too. Once moved, the kept snapshot alone refuses
/// new committing windows on the group.
#[derive(Debug, Default)]
pub(crate) struct Rewinds {
    failed: std::sync::Mutex<std::collections::HashSet<GroupId>>,
}

impl Rewinds {
    /// The list a new engine starts with: the groups whose interrupted rewind
    /// open-time recovery could not restore.
    pub(crate) fn failed_at_open(groups: Vec<GroupId>) -> Self {
        Self {
            failed: std::sync::Mutex::new(groups.into_iter().collect()),
        }
    }

    /// Whether a committing window's restore failed on `group_id` and the
    /// engine has not yet quarantined it.
    pub(crate) fn failed(&self, group_id: &GroupId) -> bool {
        self.lock().contains(group_id)
    }

    /// Every recorded failure the engine has not yet quarantined.
    pub(crate) fn pending(&self) -> Vec<GroupId> {
        self.lock().iter().cloned().collect()
    }

    /// Hand every recorded failure to the engine, emptying the list.
    pub(crate) fn take_failed(&self) -> Vec<GroupId> {
        self.lock().drain().collect()
    }

    /// Drop `group_id`'s recorded failure: forgetting the group deleted its
    /// kept snapshot with the group record.
    pub(crate) fn forget(&self, group_id: &GroupId) {
        self.lock().remove(group_id);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<GroupId>> {
        self.failed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn fail(&self, group_id: &GroupId) {
        self.lock().insert(group_id.clone());
    }

    /// Record `group_id` as a failed restore would, for tests of the gates
    /// that read it.
    #[cfg(test)]
    pub(crate) fn fail_for_test(&self, group_id: &GroupId) {
        self.fail(group_id);
    }
}

/// Refuse an uncontained window on `group_id` when its snapshot, beside the
/// guard snapshots already there, would strand a set open-time recovery
/// cannot resolve after a crash. Recovery restores the one outermost snapshot
/// and releases the nested ones inside it, so the only snapshot this window
/// may join is one enclosing window's, and only as the nesting site.
///
/// This also keeps a snapshot an earlier failed restore kept, where no
/// session registry recorded it: a second window of its site would overwrite
/// it, and a window of another site would be restored over it, and either
/// loses the only copy of the live state.
fn refuse_unrecoverable_snapshot<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    site: RewindSite,
) -> StorageResult<()> {
    let surviving: Vec<RewindSite> = storage
        .list_group_snapshots(group_id)?
        .iter()
        .filter_map(|name| RewindSite::classify(name))
        .collect();
    let recoverable = match surviving.as_slice() {
        [] => true,
        [enclosing] => {
            site.may_nest_inside_another_guard() && !enclosing.may_nest_inside_another_guard()
        }
        _ => false,
    };
    if recoverable {
        Ok(())
    } else {
        Err(StorageError::Backend(
            "contained window refused: a guard snapshot of this group survives".into(),
        ))
    }
}

/// What a guard's window runs inside, which decides what a failed restore
/// leaves (see the module docs).
#[derive(Clone, Copy)]
enum Window<'a> {
    /// A group savepoint, which a failed restore fails, undoing the window.
    Savepoint,
    /// Nothing: a contained window on a backend without atomic group
    /// savepoints commits as it goes, and records a failure it cannot leave
    /// to an enclosing window in the session registry.
    Uncontained(&'a Rewinds),
    /// Nothing: a committing window, which records a failed restore in the
    /// session registry.
    Committing(&'a Rewinds),
}

/// Owns a guard snapshot of the canonical group state: the group record,
/// OpenMLS state, convergence policy and validated-tree marker. The message
/// ledger and outbound queue are deliberately excluded: windows mutate only
/// canonical state and must leave live input and work collections untouched.
///
/// [`Self::commit`] restores the snapshot and releases it; `Drop` does the same
/// on a panic or early return. A committing window's guard keeps the snapshot
/// instead when its restore fails, and records the group when the snapshot
/// survives either way; an uncontained window's does the same unless an
/// enclosing window's snapshot holds the live state (see the module docs).
pub(crate) struct SnapshotRollbackGuard<'a, S: StorageProvider> {
    storage: &'a S,
    group_id: GroupId,
    name: String,
    armed: bool,
    window: Window<'a>,
    /// Whether the window may have changed live state: from the start for an
    /// uncontained window, once its rewind succeeds for a committing one. A
    /// guard keeps its snapshot after a failed restore only then: a snapshot
    /// kept over unchanged state is stale once the group advances, and
    /// open-time recovery restores a surviving guard snapshot unconditionally.
    changed: bool,
}

impl<'a, S: StorageProvider> SnapshotRollbackGuard<'a, S> {
    /// Run a contained window: `window` reads past state by mutating the live
    /// canonical state of `group_id`, and nothing it writes may commit before
    /// that state is restored.
    ///
    /// The snapshot, the window and the restore share one group savepoint, so
    /// they commit together or not at all. A failed restore returns its error,
    /// and the savepoint undoes the window and the snapshot with it. That holds
    /// inside a caller's transaction too, whatever the caller then does with
    /// the error, so a contained window never leaves the group on past state
    /// and never strands a snapshot. `window`'s own error is returned after the
    /// restore and likewise undoes the window.
    ///
    /// This rests on `with_group_savepoint`'s undo contract, as canonical
    /// apply does, so it holds only on a backend with atomic group savepoints,
    /// such as SQLite, where `rewinds` goes unread. Elsewhere the window
    /// commits as it goes behind the guard's snapshot alone, which open-time
    /// recovery restores after a crash, and a failed restore keeps that
    /// snapshot and records the group in `rewinds`, the session's registry,
    /// when no enclosing window holds the live state (mdk#3278). There it is
    /// refused, as a committing window is, on a group recorded in `rewinds`.
    pub(crate) fn contained<T, E>(
        storage: &S,
        rewinds: &Rewinds,
        group_id: &GroupId,
        site: RewindSite,
        suffix: &str,
        window: impl FnOnce(&S) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<StorageError>,
    {
        let name = site.snapshot_name(suffix);
        if !storage.has_atomic_group_savepoints() {
            // The savepoint's fallback snapshot would survive a crash beside
            // the guard's, and open-time recovery cannot choose between them.
            if rewinds.failed(group_id) {
                return Err(StorageError::Backend(
                    "contained window refused: an earlier restore of this group failed".into(),
                )
                .into());
            }
            refuse_unrecoverable_snapshot(storage, group_id, site)?;
            let guard = SnapshotRollbackGuard::create(
                storage,
                group_id.clone(),
                name,
                Window::Uncontained(rewinds),
            )?;
            let result = window(storage);
            guard.commit()?;
            return result;
        }
        let undo = site.snapshot_name(&format!("{suffix}-undo"));
        storage.with_group_savepoint(group_id, &undo, |storage| {
            let guard =
                SnapshotRollbackGuard::create(storage, group_id.clone(), name, Window::Savepoint)?;
            let result = window(storage);
            guard.commit()?;
            result
        })
    }

    /// Open a committing window: snapshot the live canonical state of
    /// `group_id`, then rewind it onto the retained snapshot `anchor`. Call
    /// only outside a transaction, so the rewind is one storage unit of its own.
    ///
    /// Refused on a group recorded in `rewinds`, and while any guard snapshot
    /// of the group survives: an open window's, or one a failed restore kept.
    /// Open-time recovery restores a single outermost snapshot and cannot
    /// order two, so a second one never gets written.
    ///
    /// The outer error is the guard's own: the snapshot, the refusal, or the
    /// restore after a failed rewind. The inner error is the rewind's
    /// (`SnapshotMissing` when the anchor is gone); the guard has then restored
    /// and released its snapshot, since a rewind that fails commits nothing.
    pub(crate) fn rewind(
        storage: &'a S,
        rewinds: &'a Rewinds,
        group_id: GroupId,
        site: RewindSite,
        suffix: &str,
        anchor: &str,
    ) -> StorageResult<Result<Self, StorageError>> {
        if rewinds.failed(&group_id) {
            return Err(StorageError::Backend(
                "rewind refused: an earlier restore of this group failed".into(),
            ));
        }
        if storage
            .list_group_snapshots(&group_id)?
            .iter()
            .any(|name| RewindSite::classify(name).is_some())
        {
            return Err(StorageError::Backend(
                "rewind refused: a guard snapshot of this group survives".into(),
            ));
        }
        let mut guard = Self::create(
            storage,
            group_id,
            site.snapshot_name(suffix),
            Window::Committing(rewinds),
        )?;
        match storage.rollback_group_state_keeping_live_records(&guard.group_id, anchor) {
            Ok(()) => {
                guard.changed = true;
                Ok(Ok(guard))
            }
            Err(error) => {
                guard.commit()?;
                Ok(Err(error))
            }
        }
    }

    /// A bare guard with no window classification, for tests that drive a
    /// window by hand.
    #[cfg(test)]
    pub(crate) fn create_for_test(
        storage: &'a S,
        group_id: GroupId,
        site: RewindSite,
        suffix: &str,
    ) -> StorageResult<Self> {
        Self::create(
            storage,
            group_id,
            site.snapshot_name(suffix),
            Window::Savepoint,
        )
    }

    fn create(
        storage: &'a S,
        group_id: GroupId,
        name: String,
        window: Window<'a>,
    ) -> StorageResult<Self> {
        storage.create_group_state_snapshot(&group_id, &name)?;
        Ok(Self {
            storage,
            group_id,
            name,
            armed: true,
            window,
            changed: matches!(window, Window::Uncontained(_)),
        })
    }

    /// Whether another guard snapshot of the group survives beside this one,
    /// such as an enclosing window's. A failed listing answers `false`, so
    /// the guard keeps a snapshot that may be the only copy of live state and
    /// records the group; an enclosing committing window then keeps its own
    /// too (see [`Self::release`]).
    fn another_guard_snapshot_survives(&self) -> bool {
        self.storage
            .list_group_snapshots(&self.group_id)
            .is_ok_and(|names| {
                names
                    .iter()
                    .any(|name| *name != self.name && RewindSite::classify(name).is_some())
            })
    }

    /// Restore the live state and release the snapshot, disarming the guard.
    /// On an error the guard stays armed, and its `Drop` tries the restore
    /// once more.
    pub(crate) fn commit(mut self) -> StorageResult<()> {
        self.storage
            .rollback_group_state_to_snapshot(&self.group_id, &self.name)?;
        self.release()?;
        self.armed = false;
        Ok(())
    }

    /// Release this guard's snapshot once the live state is restored.
    ///
    /// Without atomic group savepoints a committing window first releases the
    /// guard snapshots its nested windows left behind a failed restore or
    /// release. Its own release would otherwise leave one alone, and the next
    /// open would restore it as if it held live state. When it cannot, it
    /// keeps its own, so the next open finds the enclosing snapshot, restores
    /// it, and releases the nested ones inside it. Nothing else can be there:
    /// a committing window opens only on a group with no guard snapshot.
    fn release(&self) -> StorageResult<()> {
        if matches!(self.window, Window::Committing(_))
            && !self.storage.has_atomic_group_savepoints()
        {
            for name in self.storage.list_group_snapshots(&self.group_id)? {
                if name == self.name || RewindSite::classify(&name).is_none() {
                    continue;
                }
                match self.storage.release_group_snapshot(&self.group_id, &name) {
                    Ok(()) | Err(StorageError::SnapshotMissing(_)) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        match self
            .storage
            .release_group_snapshot(&self.group_id, &self.name)
        {
            Ok(()) | Err(StorageError::SnapshotMissing(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl<'a, S: StorageProvider> Drop for SnapshotRollbackGuard<'a, S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Panic, early return, or a failed `commit`: try the restore again.
        let restored = self
            .storage
            .rollback_group_state_to_snapshot(&self.group_id, &self.name);
        if restored.is_err() {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "drop",
                "snapshot rollback on panic-unwind failed"
            );
            match self.window {
                // The rewind committed and the restore did not: the group is
                // on anchor state and this snapshot is the only copy of its
                // live state. Keep it for the next open and refuse the group
                // until then.
                Window::Committing(rewinds) if self.changed => {
                    rewinds.fail(&self.group_id);
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "drop",
                        "rewind restore failed; snapshot kept and group refused until the next open"
                    );
                    return;
                }
                // The window committed as it went too. Keep the snapshot and
                // refuse the group the same way, unless an enclosing window's
                // snapshot holds the live state: its restore brings that back
                // and it answers for the group, and this one, kept beside it,
                // would be restored over newer live state.
                Window::Uncontained(rewinds) if !self.another_guard_snapshot_survives() => {
                    rewinds.fail(&self.group_id);
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "drop",
                        "contained restore failed without a savepoint; snapshot kept and group refused until the next open"
                    );
                    return;
                }
                Window::Committing(_) | Window::Uncontained(_) | Window::Savepoint => {}
            }
        }
        // Either restored, or nothing here committed past state: a contained
        // window's savepoint undoes it, a committing window that never rewound
        // changed nothing, and an enclosing window restores what an
        // uncontained one nested in it changed. A snapshot kept over such
        // state would be stale once the group advances, and open-time recovery
        // would restore it over newer live state.
        match self.release() {
            Ok(()) => {}
            Err(_e) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "drop",
                    "snapshot release on panic-unwind failed"
                );
                // A surviving snapshot refuses every later committing window,
                // and the next open restores it. It matches the live state
                // now, so refuse the group until then, before anything
                // advances past it. A nested uncontained window leaves that
                // to its enclosing window, whose release clears this one or
                // keeps its own.
                match self.window {
                    Window::Committing(rewinds) => rewinds.fail(&self.group_id),
                    Window::Uncontained(rewinds) if !self.another_guard_snapshot_survives() => {
                        rewinds.fail(&self.group_id);
                    }
                    Window::Uncontained(_) | Window::Savepoint => {}
                }
            }
        }
    }
}

#[cfg(test)]
// Tests read stored records directly (see clippy.toml).
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::{RewindSite, Rewinds, SnapshotRollbackGuard};
    use cgka_traits::capabilities::GroupCapabilities;
    use cgka_traits::engine::SendIntent;
    use cgka_traits::group::{Group, ProtocolProfile};
    use cgka_traits::message::{MessageRecord, MessageState};
    use cgka_traits::storage::{
        GroupStorage, MessageStorage, OutboundIntentStorage, QueuedOutboundIntent, StorageError,
        StorageResult,
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
            self_removed_sibling_slots: Default::default(),
            local_copy_welcome_created_at: None,
            device_roster_departures: Vec::new(),
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
        let storage = SqliteAccountStorage::in_memory_for_test().expect("storage");
        let group_id = GroupId::new(vec![9; 16]);
        storage
            .put_group(&group(&group_id, 4, "live"))
            .expect("put live group");

        for site in RewindSite::ALL {
            let classified = SnapshotRollbackGuard::contained(
                &storage,
                &Rewinds::default(),
                &group_id,
                site,
                "0011223344556677",
                |storage| {
                    Ok::<_, StorageError>(
                        storage
                            .list_group_snapshots(&group_id)?
                            .iter()
                            .filter_map(|name| RewindSite::classify(name))
                            .collect::<Vec<_>>(),
                    )
                },
            )
            .expect("capture and restore live state");
            assert_eq!(
                classified,
                vec![site],
                "a guard must hold exactly one snapshot that open-time recovery classifies"
            );
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
                "encrypted-media-source-restore-a1b2c3d4e5f60718",
                RewindSite::EncryptedMediaSource,
            ),
            (
                "moderation-source-restore-a1b2c3d4e5f60718",
                RewindSite::ModerationSource,
            ),
            (
                "device-tag-source-restore-a1b2c3d4e5f60718",
                RewindSite::DeviceTagSource,
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
        let storage = SqliteAccountStorage::in_memory_for_test().expect("storage");
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

        let live_message = message(&group_id, 2, 3);
        let live_queued = queued(&group_id, 12);
        SnapshotRollbackGuard::contained(
            &storage,
            &Rewinds::default(),
            &group_id,
            RewindSite::Replay,
            "temporary-probe",
            |storage| {
                storage.put_group(&group(&group_id, 2, "temporary"))?;
                storage.put_message(&live_message)?;
                storage.delete_queued_outbound_intent(&original_queued.id)?;
                storage.put_queued_outbound_intent(&live_queued)
            },
        )
        .expect("restore canonical group state");

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

    /// Recovery restores a lone outermost guard snapshot and fails closed on
    /// two, so after a restore fails no second committing window may open on
    /// the group, and none may open beside an open one (mdk#3272).
    const ANCHOR: &str = "openmls-retained-anchor-2";

    /// A group at epoch 4 with its epoch-2 anchor retained.
    fn anchored() -> (SqliteAccountStorage, GroupId) {
        let storage = SqliteAccountStorage::in_memory_for_test().expect("storage");
        let group_id = GroupId::new(vec![5; 16]);
        storage.put_group(&group(&group_id, 2, "anchor")).unwrap();
        storage
            .create_group_state_snapshot(&group_id, ANCHOR)
            .unwrap();
        storage.put_group(&group(&group_id, 4, "live")).unwrap();
        (storage, group_id)
    }

    fn guards(storage: &SqliteAccountStorage, group_id: &GroupId) -> Vec<String> {
        storage
            .list_group_snapshots(group_id)
            .unwrap()
            .into_iter()
            .filter(|name| RewindSite::classify(name).is_some())
            .collect()
    }

    /// Fail every restore of a snapshot whose name starts with `prefix`.
    fn fail_restores(storage: &SqliteAccountStorage, prefix: &'static str) {
        storage.fail_snapshot_restores_for_test(Some(std::sync::Arc::new(move |_, name, _| {
            if name.starts_with(prefix) {
                return Err(StorageError::Busy("injected restore fault".into()));
            }
            Ok(())
        })));
    }

    fn rewind<'a>(
        storage: &'a SqliteAccountStorage,
        rewinds: &'a Rewinds,
        group_id: &GroupId,
        suffix: &str,
    ) -> StorageResult<Result<SnapshotRollbackGuard<'a, SqliteAccountStorage>, StorageError>> {
        SnapshotRollbackGuard::rewind(
            storage,
            rewinds,
            group_id.clone(),
            RewindSite::RetainedAnchorPass,
            suffix,
            ANCHOR,
        )
    }

    // mdk#3272: once a committing window's rewind has succeeded, the guard
    // snapshot is the only copy of the live state. A restore that fails on
    // `commit` and again on `Drop`, or on `Drop` alone after an unwind or early
    // return, keeps it for the next open and records the group for the engine
    // to quarantine.
    #[test]
    fn a_failed_committing_restore_keeps_its_snapshot_and_records_the_group() {
        for commit in [true, false] {
            let (storage, group_id) = anchored();
            let rewinds = Rewinds::default();
            let window = rewind(&storage, &rewinds, &group_id, "pass")
                .unwrap()
                .unwrap();
            assert_eq!(storage.get_group(&group_id).unwrap().epoch, EpochId(2));

            fail_restores(&storage, "openmls-retained-probe-");
            if commit {
                assert!(window.commit().is_err());
            } else {
                drop(window);
            }
            storage.fail_snapshot_restores_for_test(None);

            assert!(rewinds.failed(&group_id), "commit path: {commit}");
            assert_eq!(
                guards(&storage, &group_id),
                vec![RewindSite::RetainedAnchorPass.snapshot_name("pass")],
            );
            assert_eq!(storage.get_group(&group_id).unwrap().epoch, EpochId(2));
        }
    }

    // A restore that succeeds and a release that fails on `commit` and again
    // on `Drop` leave a snapshot of the live state. It refuses every later
    // committing window and the next open restores it, so the guard records
    // the group then too, before anything advances past it.
    #[test]
    fn a_committing_snapshot_that_survives_its_release_records_the_group() {
        for commit in [true, false] {
            let (storage, group_id) = anchored();
            let rewinds = Rewinds::default();
            let window = rewind(&storage, &rewinds, &group_id, "pass")
                .unwrap()
                .unwrap();
            storage.fail_snapshot_releases_for_test(Some(std::sync::Arc::new(|_, name, _| {
                if name.starts_with("openmls-retained-probe-") {
                    return Err(StorageError::Busy("injected release fault".into()));
                }
                Ok(())
            })));
            if commit {
                assert!(window.commit().is_err());
            } else {
                drop(window);
            }
            storage.fail_snapshot_releases_for_test(None);

            assert!(rewinds.failed(&group_id), "commit path: {commit}");
            assert_eq!(
                guards(&storage, &group_id),
                vec![RewindSite::RetainedAnchorPass.snapshot_name("pass")],
            );
            assert_eq!(storage.get_group(&group_id).unwrap().epoch, EpochId(4));
        }
    }

    // A second outermost snapshot is never written: not beside an open window,
    // not over a kept one, and not under another session's registry, which
    // knows nothing of the first.
    #[test]
    fn a_committing_window_never_opens_beside_another_guard_snapshot() {
        let (storage, group_id) = anchored();
        let rewinds = Rewinds::default();
        let open = rewind(&storage, &rewinds, &group_id, "open")
            .unwrap()
            .unwrap();
        assert!(rewind(&storage, &rewinds, &group_id, "beside").is_err());

        fail_restores(&storage, "openmls-retained-probe-");
        drop(open);
        storage.fail_snapshot_restores_for_test(None);
        assert!(rewind(&storage, &rewinds, &group_id, "recorded").is_err());
        let other_session = Rewinds::default();
        assert!(rewind(&storage, &other_session, &group_id, "unrecorded").is_err());
        assert_eq!(guards(&storage, &group_id).len(), 1);
        assert!(!other_session.failed(&group_id));
    }

    // A rewind that fails commits nothing, and a restore over unchanged state
    // has nothing to protect: both release the snapshot and leave the group
    // live and unrecorded.
    #[test]
    fn a_window_that_changed_nothing_releases_its_snapshot() {
        let (storage, group_id) = anchored();
        let rewinds = Rewinds::default();
        fail_restores(&storage, ANCHOR);
        assert!(matches!(
            rewind(&storage, &rewinds, &group_id, "first-step"),
            Ok(Err(StorageError::Busy(_)))
        ));
        storage.fail_snapshot_restores_for_test(None);
        assert!(!rewinds.failed(&group_id));
        assert!(guards(&storage, &group_id).is_empty());
        assert_eq!(storage.get_group(&group_id).unwrap().epoch, EpochId(4));

        // The rewind fails and so does the guard's own restore: still nothing
        // changed, so `Drop` releases rather than keeping a stale image.
        fail_restores(&storage, "openmls-retained-");
        assert!(matches!(
            rewind(&storage, &rewinds, &group_id, "both-fail"),
            Err(StorageError::Busy(_))
        ));
        storage.fail_snapshot_restores_for_test(None);
        assert!(!rewinds.failed(&group_id));
        assert!(guards(&storage, &group_id).is_empty());
        assert_eq!(storage.get_group(&group_id).unwrap().epoch, EpochId(4));
    }
}
