//! Deterministic fork recovery for same-epoch competing commits.
//!
//! The engine snapshots the local group before it applies any commit that
//! advances epoch `N -> N + 1`. If a second commit later arrives for epoch
//! `N`, this manager compares ordering keys built from authenticated commit
//! metadata plus a same-committer digest fallback. A better candidate rolls
//! storage back to the pre-commit snapshot so the caller can process the
//! candidate against the correct MLS epoch.
//!
//! ## Storage row identity
//!
//! The ordering key is derived from MLS-authenticated commit metadata plus the
//! serialized MLS bytes; the storage row identity for marking an invalidated
//! commit is the transport-layer `MessageId`. The two are kept separate inside
//! `CommitRecoveryRecord` so the ordering key remains transport-independent
//! while the engine can still reach back to the storage record that needs
//! parking as `MessageState::ConvergenceDeferred` (reconsiderable by a later
//! distributed-convergence pass, not terminal).

use crate::engine::Engine;
use crate::message_processor::ForkProbeError;
use crate::openmls_projection::{OpenMlsContentKind, project_mls_message};
use cgka_traits::engine::{CommitOrderingKey, CommitOrderingPriority};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::storage::{MessageStorage, StorageError, StorageProvider};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use marmot_forensics::{AuditEventKind, ForkWinner};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Debug)]
struct CommitRecoveryRecord {
    group_id: GroupId,
    source_epoch: EpochId,
    ordering_key: CommitOrderingKey,
    /// Storage-layer identity of the commit. Used to park the row
    /// `MessageState::ConvergenceDeferred` when this commit loses a fork
    /// (its branch stays reconsiderable for distributed convergence).
    storage_id: MessageId,
    snapshot_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ForkResolution {
    CandidateWins {
        winner: CommitOrderingKey,
        invalidated: CommitOrderingKey,
        /// `MessageId` of the now-displaced incumbent, for the storage
        /// write that parks its row `ConvergenceDeferred`.
        invalidated_storage_id: MessageId,
        /// The row `resolve` actually re-persisted `ConvergenceDeferred`, if
        /// any. `None` when the incumbent had no stored row to capture before
        /// the rollback (`get_message` → `NotFound`), in which case nothing was
        /// parked and no `message_state_changed` audit row may claim otherwise.
        parked: Option<MessageId>,
    },
    IncumbentWins {
        /// Ordering key of the commit this node kept. Carried so the
        /// `fork_resolution` audit row can record WHICH branch survived —
        /// without it, incumbent-wins rows are unverifiable against other
        /// nodes' logs (cross-node convergence cannot be proven from
        /// forensics alone).
        kept: CommitOrderingKey,
    },
    MissingSnapshot,
}

#[derive(Default)]
pub(crate) struct ForkRecoveryManager {
    snapshot_counter: u64,
    pending: HashMap<PendingStateRef, CommitRecoveryRecord>,
    incumbents: HashMap<(GroupId, EpochId), CommitRecoveryRecord>,
}

impl ForkRecoveryManager {
    fn next_snapshot_name(&mut self, group_id: &GroupId, source_epoch: EpochId) -> String {
        self.snapshot_counter += 1;
        // Hash the group_id rather than embedding it as hex: snapshot
        // names appear in storage error messages and could leak through
        // tracing if storage tracing ever expands. Per the privacy rule
        // in `docs/marmot-architecture/overview/observability.md`,
        // group_ids must not appear in operational identifiers.
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-fork-recovery/v1");
        hasher.update(group_id.as_slice());
        hasher.update(source_epoch.0.to_be_bytes());
        hasher.update(self.snapshot_counter.to_be_bytes());
        let digest = hasher.finalize();
        format!(
            "fork-{}-{}-{}",
            source_epoch.0,
            self.snapshot_counter,
            hex::encode(&digest[..8])
        )
    }

    pub(crate) fn create_snapshot<S: MessageStorage>(
        &mut self,
        storage: &S,
        group_id: &GroupId,
        source_epoch: EpochId,
    ) -> Result<String, EngineError> {
        let name = self.next_snapshot_name(group_id, source_epoch);
        storage.create_group_snapshot(group_id, &name)?;
        Ok(name)
    }

    /// Advance the snapshot-name allocator past a durable snapshot's counter,
    /// so a name minted after restart can never collide with one already on
    /// disk (a `create_group_snapshot` under an existing name would fail or
    /// clobber, depending on the backend).
    fn observe_snapshot_counter(&mut self, snapshot_name: &str) {
        // Real fork snapshots are `fork-<epoch>-<counter>-<digest>`. Require
        // the epoch field to parse as a number too: transient
        // `fork-probe-<epoch>-<digest>` guard names share the `fork-` prefix,
        // and taking `.nth(1)` alone would mis-read their EPOCH field as a
        // counter (the same mis-parse the hydrate scan and the
        // `fork_snapshot_counters` test helper already guard against).
        let Some(suffix) = snapshot_name.strip_prefix("fork-") else {
            return;
        };
        let mut parts = suffix.split('-');
        let (Some(_source_epoch), Some(counter)) = (
            parts.next().and_then(|part| part.parse::<u64>().ok()),
            parts.next().and_then(|part| part.parse::<u64>().ok()),
        ) else {
            return;
        };
        self.observe_snapshot_counter_value(counter);
    }

    /// [`Self::observe_snapshot_counter`] for a counter that has already been
    /// parsed out of a durable snapshot name — used by the hydrate-time scan,
    /// which must advance the allocator for EVERY snapshot it parses, not just
    /// the ones it goes on to rebuild.
    fn observe_snapshot_counter_value(&mut self, counter: u64) {
        self.snapshot_counter = self.snapshot_counter.max(counter);
    }

    pub(crate) fn record_pending(
        &mut self,
        pending: PendingStateRef,
        group_id: GroupId,
        source_epoch: EpochId,
        storage_id: MessageId,
        ordering_key: CommitOrderingKey,
        snapshot_name: String,
    ) {
        self.observe_snapshot_counter(&snapshot_name);
        self.pending.insert(
            pending,
            CommitRecoveryRecord {
                group_id,
                source_epoch,
                ordering_key,
                storage_id,
                snapshot_name,
            },
        );
    }

    fn peek_pending(&self, pending: PendingStateRef) -> Option<MessageId> {
        self.pending.get(&pending).map(|r| r.storage_id.clone())
    }

    fn peek_pending_snapshot(&self, pending: PendingStateRef) -> Option<String> {
        self.pending.get(&pending).map(|r| r.snapshot_name.clone())
    }

    fn promote_pending(&mut self, pending: PendingStateRef) -> Option<MessageId> {
        if let Some(record) = self.pending.remove(&pending) {
            let storage_id = record.storage_id.clone();
            self.incumbents
                .insert((record.group_id.clone(), record.source_epoch), record);
            Some(storage_id)
        } else {
            None
        }
    }

    fn forget_pending(&mut self, pending: PendingStateRef) -> Option<CommitRecoveryRecord> {
        self.pending.remove(&pending)
    }

    fn record_applied(&mut self, record: CommitRecoveryRecord) {
        self.observe_snapshot_counter(&record.snapshot_name);
        self.incumbents
            .insert((record.group_id.clone(), record.source_epoch), record);
    }

    fn has_incumbent(&self, group_id: &GroupId, source_epoch: EpochId) -> bool {
        self.incumbents
            .contains_key(&(group_id.clone(), source_epoch))
    }

    /// Snapshot names currently owned by restored pending publishes for this
    /// group. Hydration must not hand these to a rebuilt incumbent: after a
    /// fork rewind, an unconfirmed re-commit from the same source epoch owns
    /// the NEWEST `fork-<epoch>-…` snapshot while the previously applied
    /// incumbent keeps an older one.
    fn pending_snapshot_names(&self, group_id: &GroupId) -> BTreeSet<String> {
        self.pending
            .values()
            .filter(|record| &record.group_id == group_id)
            .map(|record| record.snapshot_name.clone())
            .collect()
    }

    /// Decide the pairwise race and, when the candidate wins, displace the
    /// incumbent atomically.
    ///
    /// Bounded by `StorageProvider` rather than `MessageStorage` specifically
    /// so the displacement can run inside `with_transaction`: capture,
    /// rollback, re-persist and release are one durable unit. Nothing weaker
    /// works — see the ordering comment below.
    fn resolve<S: StorageProvider>(
        &mut self,
        storage: &S,
        group_id: &GroupId,
        source_epoch: EpochId,
        candidate_priority: CommitOrderingPriority,
        candidate_committer: MemberId,
        candidate_mls_bytes: &[u8],
    ) -> Result<ForkResolution, EngineError> {
        let key = (group_id.clone(), source_epoch);
        let Some(incumbent) = self.incumbents.get(&key).cloned() else {
            return Ok(ForkResolution::MissingSnapshot);
        };

        let candidate_key = CommitOrderingKey::from_commit_bytes(
            source_epoch,
            candidate_priority,
            candidate_committer,
            candidate_mls_bytes,
        );
        if candidate_key >= incumbent.ordering_key {
            return Ok(ForkResolution::IncumbentWins {
                kept: incumbent.ordering_key,
            });
        }

        // Atomicity rationale (durability of the displaced branch). Capture,
        // rollback, re-persist and release are ONE durable unit.
        //
        // They have to be. The rollback sweeps the incumbent's stored row away
        // (the pre-commit snapshot predates that row's own persist), so if the
        // re-persist failed on its own the displaced branch would be gone with
        // no way back: a later `resolve` cannot repair it, because (1) the
        // rollback already removed the row so the capture would read
        // `NotFound` and silently park nothing, and (2) there typically IS no
        // later resolve — storage now sits at the pre-incumbent epoch, so a
        // redelivery of the same candidate applies cleanly with no WrongEpoch
        // and no fork resolution at all. The branch would vanish silently.
        //
        // SQLite snapshot ops JOIN an outer transaction rather than driving
        // their own (`storage_sqlite::storage::snapshots::
        // snapshot_rollback_joins_outer_transaction` /
        // `snapshot_create_joins_outer_transaction`), which is what makes this
        // grouping possible; `apply_openmls_canonicalization_result` relies on
        // the same property. A failure anywhere inside therefore unwinds the
        // rollback too, leaving the incumbent applied, its row intact and its
        // snapshot retained — genuinely retryable.
        //
        // The in-memory `incumbents.remove` stays OUTSIDE, after the commit:
        // it is the point of no return and must not be reached for a
        // transaction that rolled back.
        //
        // Park the pairwise-losing incumbent `ConvergenceDeferred`, not
        // terminally `EpochInvalidated` — the mirror of the incumbent-wins
        // seam in `ingest_group_message`. The losing branch may still gain
        // follow-on commits from peers that applied it and never saw the
        // candidate; distributed convergence then selects the DEEPER branch,
        // and every convergence-only node reorgs onto it. A terminal (or
        // missing) row is excluded from convergence input, so this node could
        // never materialize that branch's root and would diverge from the
        // fleet forever.
        //
        // If the incumbent's branch loses in convergence too, its commits are
        // NOT terminalized there: an eligible-but-unselected branch's commits
        // are re-deferred `ConvergenceDeferred`
        // (`NonSelectedEligibleBranch` in
        // `classify_losing_materialized_candidate_commits`), so they stay
        // reconsiderable pass after pass. (`LosingBranch` is an APP-message
        // invalidation reason, not a commit disposition.) Terminalization
        // happens only at the rewind horizon —
        // `BeyondRollbackHorizon`/`BeyondAnchor`, or the
        // `beyond_retained_anchor` retirement in
        // `seed_convergence_pass_members`.
        //
        // The row is re-keyed at the commit's SOURCE epoch (convergence
        // derives its rewind target from `record.epoch`) and its payload is
        // preserved verbatim — for an own commit it carries the convergence
        // ordering stamp (`stamp_processed_own_commit_record`) that replay
        // needs to rebuild the ordering key (MLS refuses to process own
        // commits).
        let snapshot_name = incumbent.snapshot_name.clone();
        let incumbent_storage_id = incumbent.storage_id.clone();
        let incumbent_source_epoch = incumbent.source_epoch;
        let parked =
            storage.with_transaction(|storage| -> Result<Option<MessageId>, EngineError> {
                let displaced_incumbent_row = match storage.get_message(&incumbent_storage_id) {
                    Ok(record) => Some(record),
                    Err(StorageError::NotFound) => None,
                    Err(e) => return Err(EngineError::Storage(e)),
                };
                storage.rollback_group_to_snapshot(group_id, &snapshot_name)?;

                let parked = match displaced_incumbent_row {
                    Some(mut record) => {
                        record.epoch = incumbent_source_epoch;
                        record.state = MessageState::ConvergenceDeferred;
                        storage.put_message(&record)?;
                        Some(record.id)
                    }
                    None => None,
                };

                match storage.release_group_snapshot(group_id, &snapshot_name) {
                    Ok(()) | Err(StorageError::SnapshotMissing(_)) => {}
                    Err(e) => return Err(EngineError::Storage(e)),
                }
                Ok(parked)
            })?;
        self.incumbents.remove(&key);

        Ok(ForkResolution::CandidateWins {
            winner: candidate_key,
            invalidated: incumbent.ordering_key,
            invalidated_storage_id: incumbent.storage_id,
            parked,
        })
    }

    fn recovery_snapshot_name(&self, group_id: &GroupId, source_epoch: EpochId) -> Option<String> {
        self.incumbents
            .get(&(group_id.clone(), source_epoch))
            .map(|record| record.snapshot_name.clone())
    }

    fn retained_snapshots(&self, group_id: &GroupId) -> Vec<(EpochId, String)> {
        self.incumbents
            .values()
            .filter(|record| &record.group_id == group_id)
            .map(|record| (record.source_epoch, record.snapshot_name.clone()))
            .collect()
    }

    fn prune_before<S: MessageStorage>(
        &mut self,
        storage: &S,
        group_id: &GroupId,
        oldest_retained_epoch: EpochId,
    ) {
        let stale: Vec<_> = self
            .incumbents
            .iter()
            .filter(|((record_group_id, source_epoch), _)| {
                record_group_id == group_id && source_epoch.0 < oldest_retained_epoch.0
            })
            .map(|(key, record)| (key.clone(), record.snapshot_name.clone()))
            .collect();

        for (key, snapshot_name) in stale {
            match storage.release_group_snapshot(group_id, &snapshot_name) {
                Ok(()) | Err(StorageError::SnapshotMissing(_)) => {
                    self.incumbents.remove(&key);
                }
                Err(_e) => {
                    tracing::warn!(
                        target: "cgka_engine::fork_recovery",
                        method = "prune_before",
                        source_epoch = key.1.0,
                        "failed to release pruned fork recovery snapshot; retaining incumbent for retry"
                    );
                }
            }
        }
    }
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn track_pending_commit_for_recovery(
        &mut self,
        pending: PendingStateRef,
        group_id: GroupId,
        source_epoch: EpochId,
        storage_id: MessageId,
        ordering_key: CommitOrderingKey,
        snapshot_name: String,
    ) {
        self.fork_recovery.record_pending(
            pending,
            group_id,
            source_epoch,
            storage_id,
            ordering_key,
            snapshot_name,
        );
    }

    pub(crate) fn promote_pending_commit_for_recovery(
        &mut self,
        pending: PendingStateRef,
    ) -> Option<MessageId> {
        self.fork_recovery.promote_pending(pending)
    }

    /// Read the origin-commit storage id for a pending entry **without**
    /// consuming the recovery record. `do_confirm_published` needs this id to
    /// mark the commit `Processed` inside its durable transaction, but it must
    /// not promote the pending → incumbent until the transaction has committed
    /// (promotion is in-memory state that a rolled-back, retried confirm would
    /// otherwise have already mutated).
    pub(crate) fn peek_pending_commit_for_recovery(
        &self,
        pending: PendingStateRef,
    ) -> Option<MessageId> {
        self.fork_recovery.peek_pending(pending)
    }

    /// Read the fork-recovery snapshot name a pending entry owns, without
    /// consuming the record. `do_confirm_published` persists this name in the
    /// [`cgka_traits::message::OwnCommitConvergenceStamp`] so the hydrate-time
    /// routing rebuild can MATCH the (own commit → fork snapshot) pairing
    /// against durable evidence instead of inferring it from snapshot-name
    /// recency.
    pub(crate) fn peek_pending_snapshot_name_for_recovery(
        &self,
        pending: PendingStateRef,
    ) -> Option<String> {
        self.fork_recovery.peek_pending_snapshot(pending)
    }

    pub(crate) fn forget_pending_commit_for_recovery(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<(), EngineError> {
        if let Some(record) = self.fork_recovery.forget_pending(pending) {
            match self
                .storage
                .release_group_snapshot(&record.group_id, &record.snapshot_name)
            {
                Ok(()) | Err(StorageError::SnapshotMissing(_)) => {}
                Err(e) => return Err(EngineError::Storage(e)),
            }
        }
        Ok(())
    }

    pub(crate) fn record_applied_commit_for_recovery(
        &mut self,
        group_id: GroupId,
        source_epoch: EpochId,
        storage_id: MessageId,
        ordering_key: CommitOrderingKey,
        snapshot_name: String,
    ) {
        self.fork_recovery.record_applied(CommitRecoveryRecord {
            group_id,
            source_epoch,
            ordering_key,
            storage_id,
            snapshot_name,
        });
    }

    pub(crate) fn recovery_snapshot_name_for_fork(
        &self,
        group_id: &GroupId,
        source_epoch: EpochId,
    ) -> Option<String> {
        self.fork_recovery
            .recovery_snapshot_name(group_id, source_epoch)
    }

    pub(crate) fn resolve_fork_candidate(
        &mut self,
        group_id: &GroupId,
        source_epoch: EpochId,
        candidate_priority: CommitOrderingPriority,
        candidate_committer: MemberId,
        candidate_mls_bytes: &[u8],
    ) -> Result<ForkResolution, EngineError> {
        let candidate_digest_hex = hex::encode(Sha256::digest(candidate_mls_bytes));
        let resolution = self.fork_recovery.resolve(
            &self.storage,
            group_id,
            source_epoch,
            candidate_priority,
            candidate_committer,
            candidate_mls_bytes,
        )?;
        let (winner, incumbent_digest_hex, invalidated_msg_id) = match &resolution {
            ForkResolution::CandidateWins {
                invalidated,
                invalidated_storage_id,
                ..
            } => (
                ForkWinner::Candidate,
                Some(hex::encode(invalidated.commit_digest)),
                Some(hex::encode(invalidated_storage_id.as_slice())),
            ),
            ForkResolution::IncumbentWins { kept } => (
                ForkWinner::Incumbent,
                Some(hex::encode(kept.commit_digest)),
                None,
            ),
            ForkResolution::MissingSnapshot => (ForkWinner::MissingSnapshot, None, None),
        };
        self.audit_group(
            group_id,
            AuditEventKind::ForkResolution {
                source_epoch: source_epoch.0,
                candidate_digest: candidate_digest_hex,
                incumbent_digest: incumbent_digest_hex,
                winner,
                invalidated_msg_id,
            },
        );
        if let ForkResolution::CandidateWins { parked, .. } = &resolution {
            self.epoch_manager
                .set_stable(group_id.clone(), source_epoch);
            // Record the transition for forensics — but ONLY for a row that
            // was really re-persisted. `resolve` parks nothing when the
            // incumbent had no stored row to capture before the rollback, and
            // a `message_state_changed` row naming a msg_id that has no
            // storage row would make the audit log describe a transition that
            // never happened.
            if let Some(parked) = parked {
                self.audit_group(
                    group_id,
                    crate::audit_helpers::message_state_changed_event(
                        hex::encode(parked.as_slice()),
                        MessageState::ConvergenceDeferred,
                        "fork_loser",
                    ),
                );
            }
        }
        Ok(resolution)
    }

    pub(crate) fn retained_fork_snapshots(&self, group_id: &GroupId) -> Vec<(EpochId, String)> {
        self.fork_recovery.retained_snapshots(group_id)
    }

    pub(crate) fn prune_fork_recovery_for_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), EngineError> {
        let current_epoch = self.storage.get_group(group_id)?.epoch;
        let policy = self
            .convergence_policy_for_group(group_id)
            .map_err(|e| EngineError::Backend(format!("load convergence policy: {e}")))?;
        let oldest_retained_epoch = EpochId(
            current_epoch
                .0
                .saturating_sub(policy.convergence.max_rewind_commits),
        );
        self.fork_recovery
            .prune_before(&self.storage, group_id, oldest_retained_epoch);
        self.epoch_manager
            .prune_committed_from_before(group_id, oldest_retained_epoch);
        Ok(())
    }

    /// Rebuild the two fork-routing structures that live only in memory —
    /// `EpochManager::committed_from` and the fork-recovery `incumbents` map —
    /// from their durable evidence on session open. Without this, a restarted
    /// member routes a same-epoch rival through distributed convergence while
    /// the same member before the restart would have resolved it pairwise;
    /// convergence eventually reaches the same branch, but the detour (and the
    /// divergent intermediate states it produces) is avoidable.
    ///
    /// Durable evidence, per fork snapshot `fork-<source_epoch>-<counter>-…`
    /// still on disk:
    /// - the applied commit at that source epoch is the group's single
    ///   `Processed` commit row whose MLS wire bytes carry that epoch;
    /// - an own commit's ordering metadata comes from its confirm-time
    ///   [`cgka_traits::message::OwnCommitConvergenceStamp`] (MLS cannot
    ///   replay a device's own commit), and its snapshot pairing from the
    ///   stamp's recorded `fork_snapshot_name` (matched against the on-disk
    ///   names; a stamp predating the field falls back to newest-at-epoch
    ///   inference). An inbound commit's metadata comes from replaying it
    ///   against the fork snapshot (the same probe the pairwise router uses),
    ///   which incidentally proves its pairing;
    /// - `committed_from` is re-owned only for epochs whose stored applied
    ///   evidence includes a stamped own-commit row, and only alongside a
    ///   rebuilt incumbent — so the pairwise router can never be steered into
    ///   the fail-closed `MissingSnapshot` arm by a half-rebuilt map.
    ///
    /// The rewind-horizon bound of [`Self::prune_fork_recovery_for_group`]
    /// carries over: epochs below `current - max_rewind_commits` are not
    /// rebuilt and their snapshots are released (best-effort), exactly as
    /// `prune_before` would have done had the process kept running.
    ///
    /// Must run after any pending-publish restore for the group: an
    /// unconfirmed re-commit staged from a rewound epoch owns the newest
    /// `fork-` snapshot at that epoch, which this rebuild must skip.
    pub(crate) fn rebuild_fork_routing_state_on_hydrate(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), EngineError> {
        let pending_snapshots = self.fork_recovery.pending_snapshot_names(group_id);
        // Newest fork snapshot per source epoch (mirrors `newest_fork_snapshot`
        // in the pending-publish hydration path). Names that fail to parse —
        // including transient `fork-probe-…` guards — are ignored. All parsed
        // non-pending names are also kept per epoch so an own-commit stamp
        // that RECORDS its snapshot name can be matched exactly, even when a
        // newer snapshot exists at the same epoch.
        let mut newest_by_epoch: BTreeMap<u64, (u64, String)> = BTreeMap::new();
        let mut scanned_names_by_epoch: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for name in self.storage.list_group_snapshots(group_id)? {
            if pending_snapshots.contains(&name) {
                continue;
            }
            let Some(suffix) = name.strip_prefix("fork-") else {
                continue;
            };
            let mut parts = suffix.split('-');
            let (Some(source_epoch), Some(counter)) = (
                parts.next().and_then(|part| part.parse::<u64>().ok()),
                parts.next().and_then(|part| part.parse::<u64>().ok()),
            ) else {
                continue;
            };
            // Advance the snapshot-name allocator for EVERY parsed durable
            // name, before any filtering. Only rebuilt incumbents reach
            // `record_applied` (which observes their counter); a snapshot
            // skipped here as an orphan, dropped below the rewind horizon, or
            // abandoned after a failed replay probe would otherwise leave the
            // allocator behind the highest counter on disk, and the next
            // `next_snapshot_name` after restart could mint a colliding name.
            self.fork_recovery.observe_snapshot_counter_value(counter);
            scanned_names_by_epoch
                .entry(source_epoch)
                .or_default()
                .insert(name.clone());
            let entry = newest_by_epoch
                .entry(source_epoch)
                .or_insert((counter, name.clone()));
            if counter > entry.0 {
                *entry = (counter, name);
            }
        }
        if newest_by_epoch.is_empty() {
            return Ok(());
        }

        let current_epoch = self.storage.get_group(group_id)?.epoch;
        // Ungated: this rebuild also runs inside
        // `retry_hydrate_quarantined_group`, where the group stays quarantined
        // until hydration succeeds — the gated read maps quarantine to
        // `MissingGroup` and would forfeit the pairwise fast-path rebuild on
        // every quarantine-retry hydration.
        let policy = self
            .convergence_policy_for_group_ungated(group_id)
            .map_err(|e| EngineError::Backend(format!("load convergence policy: {e}")))?;
        let oldest_retained_epoch = EpochId(
            current_epoch
                .0
                .saturating_sub(policy.convergence.max_rewind_commits),
        );

        // One decode pass over the horizon's stored rows: the single
        // `Processed` commit per source epoch (the applied incumbent), and the
        // source epochs holding a stamped own-commit row (stamps are written
        // only at confirm, so a stamped row proves "we ourselves committed
        // from this epoch" regardless of the row's current state — a
        // fork-invalidated own commit keeps its `committed_from` entry, same
        // as the in-memory map).
        type AppliedRow = (
            MessageId,
            Vec<u8>,
            Option<cgka_traits::message::OwnCommitConvergenceStamp>,
        );
        let mut applied_by_epoch: BTreeMap<u64, AppliedRow> = BTreeMap::new();
        let mut own_commit_epochs: BTreeSet<u64> = BTreeSet::new();
        for record in self
            .storage
            .list_messages(group_id, oldest_retained_epoch)?
        {
            let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
                continue;
            };
            let Some(message) = payload.as_openmls_wire() else {
                continue;
            };
            let Ok(projection) = project_mls_message(&message.payload) else {
                continue;
            };
            if projection.kind != OpenMlsContentKind::Commit {
                continue;
            }
            let Some(source_epoch) = projection.source_epoch else {
                continue;
            };
            let stamp = payload.own_commit_stamp().cloned();
            if stamp.is_some() {
                own_commit_epochs.insert(source_epoch);
            }
            if record.state != MessageState::Processed {
                continue;
            }
            let row = (record.id.clone(), message.payload.clone(), stamp);
            // Steady state holds one Processed commit per source epoch; if a
            // crash left more, prefer the own-stamped row (its ordering
            // metadata was authenticated at confirm time and needs no replay).
            // The vacant arm MOVES the row (the MLS payload is not cloned);
            // the occupied arm only replaces when the newcomer is the
            // own-stamped one.
            match applied_by_epoch.entry(source_epoch) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(row);
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    if slot.get().2.is_none() && row.2.is_some() {
                        slot.insert(row);
                    }
                }
            }
        }

        let mut rebuilt_source_epochs: Vec<u64> = Vec::new();
        let mut restored_committed_from_epochs: Vec<u64> = Vec::new();
        for (source_epoch_raw, (_, snapshot_name)) in newest_by_epoch {
            let source_epoch = EpochId(source_epoch_raw);
            if source_epoch < oldest_retained_epoch {
                // Outside the rewind horizon: had the process kept running,
                // `prune_before` would have released this snapshot already.
                match self
                    .storage
                    .release_group_snapshot(group_id, &snapshot_name)
                {
                    Ok(()) | Err(StorageError::SnapshotMissing(_)) => {}
                    Err(_e) => tracing::warn!(
                        target: "cgka_engine::fork_recovery",
                        method = "rebuild_fork_routing_state_on_hydrate",
                        source_epoch = source_epoch.0,
                        "failed to release a fork snapshot outside the rewind horizon"
                    ),
                }
                continue;
            }
            if self.fork_recovery.has_incumbent(group_id, source_epoch) {
                continue;
            }
            let Some((storage_id, mls_bytes, stamp)) = applied_by_epoch.remove(&source_epoch_raw)
            else {
                // No applied commit row: the snapshot is an orphan of a crash
                // between snapshot creation and the apply transaction. Leave
                // it; the horizon prune retires it once the group advances.
                continue;
            };
            let mut snapshot_name = snapshot_name;
            let (priority, committer) = match stamp {
                Some(stamp) => {
                    // An inbound commit proves its snapshot pairing by
                    // replaying against it (the probe below). An own commit
                    // cannot be replayed, so its pairing is proven by MATCH:
                    // the confirm-time stamp records the snapshot name its
                    // recovery record owned, and the rebuild adopts exactly
                    // that snapshot — it is the snapshot, not the ordering
                    // key, that a later `resolve()` rolls back to. A recorded
                    // name that is no longer on disk (or is owned by a
                    // restored pending publish) means the pairing cannot be
                    // proven; leave the epoch on the convergence path rather
                    // than pair the commit with a snapshot it never owned.
                    // Stamps written before the field existed fall back to
                    // the newest-snapshot inference below, which is safe
                    // today only by exclusion (pending-owned snapshots are
                    // skipped and a displaced incumbent is parked, not left
                    // `Processed`) — the recorded name makes it exact.
                    if let Some(recorded) = stamp.fork_snapshot_name {
                        let retained = scanned_names_by_epoch
                            .get(&source_epoch_raw)
                            .is_some_and(|names| names.contains(&recorded));
                        if !retained {
                            tracing::warn!(
                                target: "cgka_engine::fork_recovery",
                                method = "rebuild_fork_routing_state_on_hydrate",
                                source_epoch = source_epoch.0,
                                "own-commit stamp names a fork snapshot that is no longer retained; not rebuilding this incumbent"
                            );
                            continue;
                        }
                        snapshot_name = recorded;
                    }
                    (stamp.priority, stamp.committer)
                }
                None => match self.probe_commit_ordering_metadata_for_recovery(
                    group_id,
                    source_epoch,
                    &snapshot_name,
                    &mls_bytes,
                ) {
                    Ok(metadata) => metadata,
                    Err(ForkProbeError::InvalidCandidate) => {
                        // The stored applied commit no longer replays against
                        // its own pre-commit snapshot; without a trustworthy
                        // ordering key, leave this epoch on the convergence
                        // path (the pre-rebuild restart behavior).
                        tracing::warn!(
                            target: "cgka_engine::fork_recovery",
                            method = "rebuild_fork_routing_state_on_hydrate",
                            source_epoch = source_epoch.0,
                            "stored applied commit failed its fork-snapshot replay; not rebuilding this incumbent"
                        );
                        continue;
                    }
                    Err(ForkProbeError::Engine(error)) => return Err(error),
                },
            };
            let ordering_key =
                CommitOrderingKey::from_commit_bytes(source_epoch, priority, committer, &mls_bytes);
            self.fork_recovery.record_applied(CommitRecoveryRecord {
                group_id: group_id.clone(),
                source_epoch,
                ordering_key,
                storage_id,
                snapshot_name,
            });
            rebuilt_source_epochs.push(source_epoch.0);
            if own_commit_epochs.contains(&source_epoch_raw) {
                self.epoch_manager
                    .restore_committed_from(group_id.clone(), source_epoch);
                restored_committed_from_epochs.push(source_epoch.0);
            }
        }
        // Forensics: distinguish post-restart reconstruction from in-flight
        // fork resolution — an incumbent whose epoch appears here was
        // recovered from durable evidence, not freshly applied.
        if !rebuilt_source_epochs.is_empty() {
            self.audit_group(
                group_id,
                AuditEventKind::ForkRoutingRebuilt {
                    rebuilt_source_epochs,
                    restored_committed_from_epochs,
                },
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::message::{MessageRecord, MessageState};
    use cgka_traits::storage::StorageResult;
    use std::sync::Mutex;

    #[derive(Default)]
    struct HardFailingReleaseStorage {
        release_attempts: Mutex<Vec<String>>,
    }

    fn unused<T>() -> StorageResult<T> {
        unreachable!("unused in prune_before release-failure test")
    }

    impl MessageStorage for HardFailingReleaseStorage {
        fn put_message(&self, _record: &MessageRecord) -> StorageResult<()> {
            unused()
        }

        fn get_message(&self, _id: &MessageId) -> StorageResult<MessageRecord> {
            unused()
        }

        fn delete_message(&self, _id: &MessageId) -> StorageResult<()> {
            unused()
        }

        fn update_message_state(
            &self,
            _id: &MessageId,
            _new_state: MessageState,
        ) -> StorageResult<()> {
            unused()
        }

        fn list_messages(
            &self,
            _group_id: &GroupId,
            _at_or_after_epoch: EpochId,
        ) -> StorageResult<Vec<MessageRecord>> {
            unused()
        }

        fn put_ingress_dedup_marker(&self, _id: &MessageId) -> StorageResult<()> {
            unused()
        }

        fn has_ingress_dedup_marker(&self, _id: &MessageId) -> StorageResult<bool> {
            unused()
        }

        fn create_group_snapshot(&self, _group_id: &GroupId, _name: &str) -> StorageResult<()> {
            unused()
        }

        fn list_group_snapshots(&self, _group_id: &GroupId) -> StorageResult<Vec<String>> {
            unused()
        }

        fn rollback_group_to_snapshot(
            &self,
            _group_id: &GroupId,
            _name: &str,
        ) -> StorageResult<()> {
            unused()
        }

        fn release_group_snapshot(&self, _group_id: &GroupId, name: &str) -> StorageResult<()> {
            self.release_attempts.lock().unwrap().push(name.to_string());
            Err(StorageError::Backend("release failed".into()))
        }
    }

    #[test]
    fn observe_snapshot_counter_ignores_fork_probe_guard_names() {
        let mut manager = ForkRecoveryManager::default();
        let group_id = GroupId::new(b"group".to_vec());

        // `fork-probe-<epoch>-<digest>` shares the `fork-` prefix; its epoch
        // field (7) sits exactly where a real name's counter would be, and
        // must not advance the allocator.
        manager.observe_snapshot_counter("fork-probe-7-aabbccdd00112233");
        // A name whose epoch field is not numeric must be ignored too.
        manager.observe_snapshot_counter("fork-x-9-aabbccdd00112233");
        let first = manager.next_snapshot_name(&group_id, EpochId(1));
        assert!(
            first.starts_with("fork-1-1-"),
            "allocator advanced by a non-fork name: {first}"
        );

        // A real durable name does advance it past its counter.
        manager.observe_snapshot_counter("fork-3-9-0011223344556677");
        let next = manager.next_snapshot_name(&group_id, EpochId(3));
        assert!(
            next.starts_with("fork-3-10-"),
            "allocator did not advance past a real durable counter: {next}"
        );
    }

    #[test]
    fn prune_before_keeps_incumbent_when_snapshot_release_hard_fails() {
        let mut manager = ForkRecoveryManager::default();
        let group_id = GroupId::new(b"group".to_vec());
        manager.record_applied(CommitRecoveryRecord {
            group_id: group_id.clone(),
            source_epoch: EpochId(1),
            ordering_key: CommitOrderingKey::from_commit_bytes(
                EpochId(1),
                CommitOrderingPriority::Ordinary,
                MemberId::new(b"alice".to_vec()),
                b"commit",
            ),
            storage_id: MessageId::new(b"message".to_vec()),
            snapshot_name: "fork-1".to_string(),
        });

        let storage = HardFailingReleaseStorage::default();
        manager.prune_before(&storage, &group_id, EpochId(2));

        assert_eq!(
            storage.release_attempts.lock().unwrap().as_slice(),
            &[String::from("fork-1")]
        );
        assert_eq!(
            manager.recovery_snapshot_name(&group_id, EpochId(1)),
            Some("fork-1".to_string())
        );
    }
}
