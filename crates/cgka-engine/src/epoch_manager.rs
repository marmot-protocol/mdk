//! EpochManager — single owner of every per-group [`EpochState`] mutation.
//!
//! This module is the only place that mutates per-group engine epoch state.
//! It:
//!
//! - Owns the `epoch_states` map.
//! - Issues `PendingStateRef`s and tracks the reverse `pending_ref → group_id`
//!   index.
//! - Records pre-commit epochs for fork detection.
//! - Wraps the legal transitions on [`EpochState`] so engine subsystems
//!   can't construct non-`Stable` variants directly.
//!
//! Pending publishes record `prior_epoch` so `rollback_publish` can restore
//! the engine to its pre-stage `Stable` state. MLS-side
//! `clear_pending_commit` and Marmot/cache rewrites happen in the engine;
//! this module tracks state-machine bookkeeping only.

use cgka_traits::engine_state::{EpochState, PendingStateRef, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::ingest::PeeledMessage;
use cgka_traits::types::{EpochId, GroupId};
use marmot_forensics::AuditEventContext;
use std::collections::{BTreeSet, HashMap};

/// Per-pending sidecar so `confirm_publish` / `rollback_publish` can find
/// the originating group AND the epoch to revert to on failure. Replaces
/// the simpler `pending_to_group` map.
#[derive(Clone, Debug)]
struct PendingMeta {
    group_id: GroupId,
    prior_epoch: EpochId,
    kind: PendingKind,
    /// Audit context of the operation that staged this commit, captured at
    /// `begin_pending`. Re-attached to the `epoch_confirmed` / `epoch_rolled_back`
    /// rows, which are emitted on a later publish-confirm call after the
    /// engine's ambient context has cleared.
    audit_context: Option<AuditEventContext>,
}

/// Discriminator the engine uses when emitting the post-confirm event.
/// `CreateGroup` becomes `GroupEvent::GroupCreated`; `GroupEvolution`
/// becomes `GroupEvent::EpochChanged`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingKind {
    CreateGroup,
    GroupEvolution,
}

#[derive(Default)]
pub(crate) struct EpochManager {
    states: HashMap<GroupId, EpochState>,
    pending_counter: u64,
    pending: HashMap<PendingStateRef, PendingMeta>,
    /// Pre-commit epochs from which we ourselves committed. Used by the
    /// fork-detection path: when a WrongEpoch arrives for an epoch we
    /// committed from, AND we've since advanced, the histories have
    /// forked.
    committed_from: HashMap<GroupId, BTreeSet<EpochId>>,
}

impl EpochManager {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    // ── Read-only queries ──────────────────────────────────────────────────

    pub(crate) fn state(&self, group_id: &GroupId) -> Option<&EpochState> {
        self.states.get(group_id)
    }

    pub(crate) fn epoch(&self, group_id: &GroupId) -> Option<EpochId> {
        self.states.get(group_id).map(|s| s.epoch())
    }

    pub(crate) fn can_ingest(&self, group_id: &GroupId) -> bool {
        // A group with no recorded state is treated as ingestible — needed
        // for first-time welcomes that arrive before we have any state.
        self.states.get(group_id).is_none_or(|s| s.can_ingest())
    }

    pub(crate) fn we_committed_from(&self, group_id: &GroupId, epoch: EpochId) -> bool {
        self.committed_from
            .get(group_id)
            .map(|s| s.contains(&epoch))
            .unwrap_or(false)
    }

    // ── Mutation: pending-ref allocation ────────────────────────────────────

    pub(crate) fn next_pending_ref(&mut self) -> PendingStateRef {
        self.pending_counter += 1;
        PendingStateRef::new(self.pending_counter)
    }

    // ── Mutation: state transitions ────────────────────────────────────────

    /// Set a group's state to `Stable { epoch }`. Used by the join-welcome
    /// path (no prior state) and by the merge-to-stable path post-confirm.
    pub(crate) fn set_stable(&mut self, group_id: GroupId, epoch: EpochId) {
        self.states.insert(group_id, EpochState::stable(epoch));
    }

    /// Begin a pending publish for the given group. Caller must have
    /// allocated the `pending_ref` via `next_pending_ref` first.
    ///
    /// Records `pre_commit_epoch` in `committed_from` so the fork-detection
    /// path can later distinguish "we committed at this epoch" from "this
    /// is a benign late-arriving commit." Also stashes `pre_commit_epoch`
    /// as the rollback target for `rollback_publish`.
    // Each argument is a distinct piece of the pending-publish transition; a
    // wrapper struct would only move the same fields behind a name.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_pending(
        &mut self,
        group_id: GroupId,
        pre_commit_epoch: EpochId,
        new_epoch: EpochId,
        pending: StagedCommitHandle,
        pending_ref: PendingStateRef,
        kind: PendingKind,
        audit_context: Option<AuditEventContext>,
    ) -> Result<(), EngineError> {
        // Record the pre-commit epoch BEFORE the transition so fork
        // detection works even if the transition fails.
        self.committed_from
            .entry(group_id.clone())
            .or_default()
            .insert(pre_commit_epoch);

        let prev = self
            .states
            .remove(&group_id)
            .unwrap_or_else(|| EpochState::stable(pre_commit_epoch));
        let new_state = prev.begin_pending(new_epoch, pending, pending_ref)?;
        self.states.insert(group_id.clone(), new_state);
        self.pending.insert(
            pending_ref,
            PendingMeta {
                group_id,
                prior_epoch: pre_commit_epoch,
                kind,
                audit_context,
            },
        );
        Ok(())
    }

    /// Peek at which group a pending publish belongs to without consuming
    /// the entry. Used by `do_confirm_published` / `do_publish_failed` so
    /// the engine can load the MLS group BEFORE we burn the state-machine
    /// slot — keeps the failure mode "load failed → state untouched."
    pub(crate) fn group_for_pending(&self, pending: PendingStateRef) -> Option<GroupId> {
        self.pending.get(&pending).map(|m| m.group_id.clone())
    }

    /// Peek at the per-pending kind tag (Create vs. Evolution).
    pub(crate) fn kind_for_pending(&self, pending: PendingStateRef) -> Option<PendingKind> {
        self.pending.get(&pending).map(|m| m.kind)
    }

    /// Peek at the audit context captured when this pending was staged, so the
    /// post-confirm/rollback rows can carry the originating `human_action`.
    pub(crate) fn audit_context_for_pending(
        &self,
        pending: PendingStateRef,
    ) -> Option<AuditEventContext> {
        self.pending
            .get(&pending)
            .and_then(|m| m.audit_context.clone())
    }

    /// `PendingPublish → Merging → Stable{new_epoch}` in one step. Caller
    /// (engine `confirm_published`) is responsible for the OpenMLS
    /// `merge_pending_commit` + Marmot/cache rewrites.
    ///
    /// Atomic in the state map: if either inner state-machine transition
    /// fails, both `pending` and `states` retain their pre-call values
    /// so a retry sees the same legal moves.
    ///
    /// Returns `(group_id, new_epoch)` so the caller can emit events.
    pub(crate) fn confirm_publish(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<(GroupId, EpochId), EngineError> {
        let meta = self
            .pending
            .get(&pending)
            .cloned()
            .ok_or(EngineError::UnknownPending)?;
        let group_id = meta.group_id;
        let prev = self
            .states
            .get(&group_id)
            .cloned()
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let merging = prev.confirm_publish()?;
        let merging_epoch = merging.epoch();
        let stable = merging.merge_to_stable(merging_epoch)?;
        // Both transitions succeeded — commit the swap.
        self.pending.remove(&pending);
        self.states.insert(group_id.clone(), stable);
        Ok((group_id, merging_epoch))
    }

    /// `PendingPublish → Stable{prior_epoch}`. Counterpart to
    /// `confirm_publish` for the publish-failed path. The engine still owns
    /// the OpenMLS `clear_pending_commit` + any Marmot/cache rewinds — this
    /// only handles the state-machine bookkeeping.
    ///
    /// Atomic in the state map: a failed `rollback_pending` leaves both
    /// `pending` and `states` untouched.
    ///
    /// Returns `(group_id, prior_epoch)` so the caller can target the
    /// matching MLS group.
    pub(crate) fn rollback_publish(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<(GroupId, EpochId), EngineError> {
        let meta = self
            .pending
            .get(&pending)
            .cloned()
            .ok_or(EngineError::UnknownPending)?;
        let group_id = meta.group_id;
        let prior_epoch = meta.prior_epoch;
        let prev = self
            .states
            .get(&group_id)
            .cloned()
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let stable = prev.rollback_pending(prior_epoch)?;
        self.pending.remove(&pending);
        self.states.insert(group_id.clone(), stable);
        Ok((group_id, prior_epoch))
    }

    /// Record a committed-from epoch outside the begin_pending path (used
    /// by the auto-committer, which doesn't go through PendingPublish).
    pub(crate) fn record_committed_from(&mut self, group_id: &GroupId, epoch: EpochId) {
        self.committed_from
            .entry(group_id.clone())
            .or_default()
            .insert(epoch);
    }

    /// Transition the named group into `Recovering` due to a detected fork.
    /// Always legal regardless of current state.
    pub(crate) fn detect_fork(&mut self, group_id: &GroupId, buffered: Vec<PeeledMessage>) {
        let prev = self
            .states
            .remove(group_id)
            .unwrap_or_else(|| EpochState::stable(EpochId(0)));
        let new = prev.detect_fork(buffered);
        self.states.insert(group_id.clone(), new);
    }

    /// Transition the named group into `Unrecoverable`. Always legal. Called
    /// when convergence reports a `MissingRetainedAnchor` inside the rollback
    /// horizon: canonical state is frozen and the engine stops applying or
    /// ingesting group-state changes until a verified repair path
    /// (`spec/protocol-core/group-state.md:54-66`).
    pub(crate) fn mark_unrecoverable(&mut self, group_id: &GroupId) {
        let prev = self
            .states
            .remove(group_id)
            .unwrap_or_else(|| EpochState::stable(EpochId(0)));
        self.states
            .insert(group_id.clone(), prev.to_unrecoverable());
    }

    /// Whether the named group is currently `Unrecoverable`.
    pub(crate) fn is_unrecoverable(&self, group_id: &GroupId) -> bool {
        self.states
            .get(group_id)
            .is_some_and(|s| s.is_unrecoverable())
    }
}
