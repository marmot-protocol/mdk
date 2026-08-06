//! EpochManager — single owner of every per-group [`EpochState`] mutation.
//!
//! This module is the only place that mutates per-group engine epoch state.
//! It:
//!
//! - Owns the `epoch_states` map.
//! - Issues `PendingStateRef`s and tracks the reverse `pending_ref → group_id`
//!   index.
//! - Wraps the legal transitions on [`EpochState`] so engine subsystems
//!   can't construct non-`Stable` variants directly.
//!
//! Pending publishes record `prior_epoch` so `rollback_publish` can restore
//! the engine to its pre-stage `Stable` state. MLS-side
//! `clear_pending_commit` and Marmot/cache rewrites happen in the engine;
//! this module tracks state-machine bookkeeping only.

use cgka_traits::engine_state::{EpochState, PendingStateRef, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::types::{EpochId, GroupId};
use marmot_forensics::AuditEventContext;
use std::collections::HashMap;

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
    Disband,
}

#[derive(Default)]
pub(crate) struct EpochManager {
    states: HashMap<GroupId, EpochState>,
    pending_counter: u64,
    pending: HashMap<PendingStateRef, PendingMeta>,
}

impl EpochManager {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    // ── Read-only queries ──────────────────────────────────────────────────

    pub(crate) fn state(&self, group_id: &GroupId) -> Option<&EpochState> {
        self.states.get(group_id)
    }

    /// Drop a group's in-memory epoch entry: the retraction path for the
    /// session-open cheap pass's provisional `Stable` seed (mdk#1161).
    ///
    /// Two callers only. `ensure_hydrated` retracts the seed immediately
    /// before running full per-group hydration, so hydration derives the real
    /// entry (`set_stable` / `restore_pending` / `restore_unrecoverable`)
    /// from exactly the entry-absent conditions the open-time loop always
    /// had — a projected-forward record mirror must not become the
    /// `begin_pending` base. And `quarantine_stored_group_on_hydrate` clears
    /// whatever entry remains when hydration fails, because a quarantined
    /// group must have no epoch entry: `live_group_ids` filters on entry
    /// presence, and every convergence/ingest gate treats "no state" as "not
    /// live". Durable halt markers are unaffected:
    /// `sync_unrecoverable_halt_from_storage` re-syncs them on demand.
    pub(crate) fn clear_group_state(&mut self, group_id: &GroupId) {
        self.states.remove(group_id);
    }

    pub(crate) fn epoch(&self, group_id: &GroupId) -> Option<EpochId> {
        self.states.get(group_id).map(|s| s.epoch())
    }

    pub(crate) fn can_ingest(&self, group_id: &GroupId) -> bool {
        // A group with no recorded state is treated as ingestible — needed
        // for first-time welcomes that arrive before we have any state.
        self.states.get(group_id).is_none_or(|s| s.can_ingest())
    }

    // ── Mutation: pending-ref allocation ────────────────────────────────────

    pub(crate) fn next_pending_ref(&mut self) -> PendingStateRef {
        self.pending_counter += 1;
        PendingStateRef::new(self.pending_counter)
    }

    // ── Mutation: state transitions ────────────────────────────────────────

    /// Set a group's state to `Stable { epoch }`. Used by the join-welcome
    /// path (no prior state) and by the merge-to-stable path post-confirm.
    ///
    /// Only `Stable` and `Recovering` may be overwritten. Every other state owes
    /// its exit to a specific transition, and this refuses to steal it:
    ///
    /// - `Unrecoverable` exits only through [`Self::repair_to_stable`] after a
    ///   verified repair path (mdk#971);
    /// - an unresolved local publication (`PendingPublish` / `Merging`) exits
    ///   only through [`Self::confirm_publish`] or [`Self::rollback_publish`],
    ///   which carry the per-pending bookkeeping — the pending slot and its
    ///   `committed_from` ownership — that a blind overwrite would strand;
    /// - `Disbanded` has no outgoing transition.
    ///
    /// Callers are already gated to the two overwritable states, so a fired
    /// refusal means a caller lost its gate; see the invariant in
    /// `crates/cgka-engine/AGENTS.md`.
    pub(crate) fn set_stable(&mut self, group_id: GroupId, epoch: EpochId) {
        if self.is_unrecoverable(&group_id) || self.is_disbanded(&group_id) {
            tracing::warn!(
                target: "cgka_engine::epoch_manager",
                method = "set_stable",
                "refusing set_stable while Unrecoverable or Disbanded; verified repair must use repair_to_stable"
            );
            return;
        }
        if self.is_resolving_local_publish(&group_id) {
            tracing::warn!(
                target: "cgka_engine::epoch_manager",
                method = "set_stable",
                "refusing set_stable while a local publication is unresolved; its outcome must use confirm_publish or rollback_publish"
            );
            return;
        }
        self.states.insert(group_id, EpochState::stable(epoch));
    }

    /// Begin a pending publish for the given group. Caller must have
    /// allocated the `pending_ref` via `next_pending_ref` first.
    ///
    /// Stashes `pre_commit_epoch` as the rollback target for
    /// `rollback_publish`.
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
        // Atomic in the state map (mirrors the Sm1 fix applied to
        // confirm_publish / rollback_publish): clone the prior state and run
        // the fallible transition BEFORE mutating any of self.states /
        // self.pending. A failing inner transition (e.g. a non-Stable prev →
        // InvalidTransition) must leave every map untouched so the group's
        // EpochState entry is never orphaned. Previously the entry was
        // removed before the transition and never re-inserted on error,
        // dropping the group to UnknownGroup (mdk#146).
        let prev = self
            .states
            .get(&group_id)
            .cloned()
            .unwrap_or_else(|| EpochState::stable(pre_commit_epoch));
        let new_state = prev.begin_pending(new_epoch, pending, pending_ref)?;

        // The transition succeeded — commit every mutation together.
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

    /// Recreate a pending-publish slot from its durable frozen fanout after a
    /// process restart. The restored ref also advances the allocator so a new
    /// pending operation cannot reuse it in this session.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn restore_pending(
        &mut self,
        group_id: GroupId,
        pre_commit_epoch: EpochId,
        new_epoch: EpochId,
        pending: StagedCommitHandle,
        pending_ref: PendingStateRef,
        kind: PendingKind,
    ) -> Result<(), EngineError> {
        self.pending_counter = self.pending_counter.max(pending_ref.as_u64());
        self.begin_pending(
            group_id,
            pre_commit_epoch,
            new_epoch,
            pending,
            pending_ref,
            kind,
            None,
        )
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
    /// Atomic in the state map: a failed `rollback_pending` leaves
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

    /// Restore `Unrecoverable` at a known frozen epoch (session-open hydration
    /// of a durable halt marker). Overwrites any prior in-memory state for the
    /// group — the persisted marker is authoritative across restart (mdk#971).
    pub(crate) fn restore_unrecoverable(&mut self, group_id: GroupId, last_stable_epoch: EpochId) {
        self.states.insert(
            group_id,
            EpochState::stable(last_stable_epoch).to_unrecoverable(),
        );
    }

    /// `Unrecoverable → Stable` after a verified repair path (authenticated
    /// re-join welcome). The only legal exit from `Unrecoverable`.
    pub(crate) fn repair_to_stable(
        &mut self,
        group_id: &GroupId,
        epoch: EpochId,
    ) -> Result<(), EngineError> {
        // Atomic in the state map (mirrors Sm1): fallible transition before
        // mutating so a non-Unrecoverable prev cannot orphan the entry.
        let prev = self
            .states
            .get(group_id)
            .cloned()
            .unwrap_or_else(|| EpochState::stable(EpochId(0)).to_unrecoverable());
        let new = prev
            .repair_to_stable(epoch)
            .map_err(EngineError::InvalidTransition)?;
        self.states.insert(group_id.clone(), new);
        Ok(())
    }

    /// Whether the named group is currently `Unrecoverable`.
    pub(crate) fn is_unrecoverable(&self, group_id: &GroupId) -> bool {
        self.states
            .get(group_id)
            .is_some_and(|s| s.is_unrecoverable())
    }

    pub(crate) fn is_disbanded(&self, group_id: &GroupId) -> bool {
        self.states
            .get(group_id)
            .is_some_and(EpochState::is_disbanded)
    }

    /// Whether the named group is mid-way through resolving a publication this
    /// client staged (`PendingPublish` awaiting the transport outcome, or
    /// `Merging` awaiting the local merge that outcome authorizes).
    fn is_resolving_local_publish(&self, group_id: &GroupId) -> bool {
        self.states
            .get(group_id)
            .is_some_and(EpochState::is_resolving_local_publish)
    }

    pub(crate) fn mark_disbanded(
        &mut self,
        group_id: &GroupId,
        epoch: EpochId,
    ) -> Result<(), EngineError> {
        let previous = self
            .states
            .get(group_id)
            .cloned()
            .unwrap_or_else(|| EpochState::stable(epoch));
        let next = previous
            .detect_fork(Vec::new())
            .settle_to_disbanded(epoch)
            .map_err(EngineError::InvalidTransition)?;
        self.states.insert(group_id.clone(), next);
        Ok(())
    }

    pub(crate) fn restore_disbanded(
        &mut self,
        group_id: GroupId,
        epoch: EpochId,
    ) -> Result<(), EngineError> {
        let recovering = EpochState::stable(epoch).detect_fork(Vec::new());
        let disbanded = recovering
            .settle_to_disbanded(epoch)
            .map_err(EngineError::InvalidTransition)?;
        self.states.insert(group_id, disbanded);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gid() -> GroupId {
        GroupId::new(vec![0xAB; 4])
    }

    fn handle() -> StagedCommitHandle {
        StagedCommitHandle::from_bytes(vec![0xCD; 4])
    }

    /// Regression for mdk#146: `begin_pending` from a non-Stable state
    /// must be atomic. A failing inner transition (Unrecoverable →
    /// InvalidTransition) must leave `states` and `pending` untouched so the
    /// group is never orphaned to UnknownGroup.
    #[test]
    fn begin_pending_failure_leaves_state_intact() {
        let mut em = EpochManager::new();
        let group_id = gid();

        // Drive the group into Unrecoverable — a state from which
        // begin_pending is illegal.
        em.set_stable(group_id.clone(), EpochId(3));
        em.mark_unrecoverable(&group_id);
        assert!(em.is_unrecoverable(&group_id));
        assert_eq!(em.epoch(&group_id), Some(EpochId(3)));

        let pending_ref = em.next_pending_ref();
        let result = em.begin_pending(
            group_id.clone(),
            EpochId(3),
            EpochId(4),
            handle(),
            pending_ref,
            PendingKind::GroupEvolution,
            None,
        );

        // The transition is rejected ...
        assert!(
            result.is_err(),
            "begin_pending from Unrecoverable must fail"
        );
        // ... and crucially the group's state map entry survives unchanged.
        assert!(
            em.is_unrecoverable(&group_id),
            "state must not be orphaned on failed begin_pending"
        );
        assert_eq!(em.epoch(&group_id), Some(EpochId(3)));
        // The pending meta was never inserted, so the ref is unknown.
        assert!(em.group_for_pending(pending_ref).is_none());
    }

    /// The happy path records the pending meta and enters PendingPublish.
    #[test]
    fn begin_pending_success_records_all_bookkeeping() {
        let mut em = EpochManager::new();
        let group_id = gid();
        em.set_stable(group_id.clone(), EpochId(7));

        let pending_ref = em.next_pending_ref();
        em.begin_pending(
            group_id.clone(),
            EpochId(7),
            EpochId(8),
            handle(),
            pending_ref,
            PendingKind::GroupEvolution,
            None,
        )
        .expect("begin_pending from Stable succeeds");

        assert_eq!(
            em.state(&group_id).map(|s| s.name()),
            Some("PendingPublish")
        );
        assert_eq!(em.epoch(&group_id), Some(EpochId(8)));
        assert_eq!(em.group_for_pending(pending_ref), Some(group_id.clone()));
    }

    /// `rollback_publish` restores the pre-stage Stable state and frees the
    /// pending slot.
    #[test]
    fn rollback_publish_restores_prior_stable_state() {
        let mut em = EpochManager::new();
        let group_id = gid();
        em.set_stable(group_id.clone(), EpochId(7));

        let pending_ref = em.next_pending_ref();
        em.begin_pending(
            group_id.clone(),
            EpochId(7),
            EpochId(8),
            handle(),
            pending_ref,
            PendingKind::GroupEvolution,
            None,
        )
        .expect("begin_pending from Stable succeeds");

        let (rolled_group, prior) = em
            .rollback_publish(pending_ref)
            .expect("rollback_publish succeeds");
        assert_eq!(rolled_group, group_id);
        assert_eq!(prior, EpochId(7));
        assert_eq!(em.state(&group_id).map(|s| s.name()), Some("Stable"));
        assert_eq!(em.epoch(&group_id), Some(EpochId(7)));
        assert!(em.group_for_pending(pending_ref).is_none());
    }

    /// mdk#971: `set_stable` must not silently clear Unrecoverable.
    #[test]
    fn set_stable_refuses_while_unrecoverable() {
        let mut em = EpochManager::new();
        let group_id = gid();
        em.set_stable(group_id.clone(), EpochId(4));
        em.mark_unrecoverable(&group_id);
        assert!(em.is_unrecoverable(&group_id));
        em.set_stable(group_id.clone(), EpochId(9));
        assert!(
            em.is_unrecoverable(&group_id),
            "set_stable must leave Unrecoverable intact"
        );
        assert_eq!(em.epoch(&group_id), Some(EpochId(4)));
    }

    /// A held publication is nobody else's to steal: while a staged commit is
    /// still awaiting its transport outcome, `set_stable` must not overwrite it.
    /// The publication's own outcome — `confirm_publish` or `rollback_publish` —
    /// is the only way out, and it must still work afterwards.
    #[test]
    fn set_stable_refuses_while_a_local_publication_is_unresolved() {
        let mut em = EpochManager::new();
        let group_id = gid();
        em.set_stable(group_id.clone(), EpochId(7));
        let pending_ref = em.next_pending_ref();
        em.begin_pending(
            group_id.clone(),
            EpochId(7),
            EpochId(8),
            handle(),
            pending_ref,
            PendingKind::GroupEvolution,
            None,
        )
        .expect("begin_pending from Stable succeeds");

        em.set_stable(group_id.clone(), EpochId(9));

        assert_eq!(
            em.state(&group_id).map(|s| s.name()),
            Some("PendingPublish"),
            "set_stable must leave an unresolved local publication intact"
        );
        assert_eq!(em.epoch(&group_id), Some(EpochId(8)));

        // The publication still resolves through its own transition.
        let (confirmed_group, confirmed_epoch) = em
            .confirm_publish(pending_ref)
            .expect("confirm_publish still exits the held publication");
        assert_eq!(confirmed_group, group_id);
        assert_eq!(confirmed_epoch, EpochId(8));
        assert_eq!(em.state(&group_id).map(|s| s.name()), Some("Stable"));
    }

    /// mdk#971: verified repair is the only Unrecoverable exit.
    #[test]
    fn repair_to_stable_exits_unrecoverable() {
        let mut em = EpochManager::new();
        let group_id = gid();
        em.restore_unrecoverable(group_id.clone(), EpochId(4));
        assert!(em.is_unrecoverable(&group_id));
        em.repair_to_stable(&group_id, EpochId(5))
            .expect("repair_to_stable from Unrecoverable");
        assert_eq!(em.state(&group_id).map(|s| s.name()), Some("Stable"));
        assert_eq!(em.epoch(&group_id), Some(EpochId(5)));
        assert!(!em.is_unrecoverable(&group_id));
    }

    #[test]
    fn repair_to_stable_rejects_non_unrecoverable_without_orphaning() {
        let mut em = EpochManager::new();
        let group_id = gid();
        em.set_stable(group_id.clone(), EpochId(3));
        assert!(em.repair_to_stable(&group_id, EpochId(4)).is_err());
        assert_eq!(em.state(&group_id).map(|s| s.name()), Some("Stable"));
        assert_eq!(em.epoch(&group_id), Some(EpochId(3)));
    }
}
