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

/// A validated, pre-allocated `Stable -> PendingPublish` transition ready to
/// install infallibly once its durable staging transaction commits.
#[must_use = "commit a prepared pending publish after its durable staging transaction succeeds"]
pub(crate) struct PreparedPendingPublish {
    group_id: GroupId,
    pre_commit_epoch: EpochId,
    new_state: EpochState,
    pending_ref: PendingStateRef,
    kind: PendingKind,
    audit_context: Option<AuditEventContext>,
}

impl PreparedPendingPublish {
    pub(crate) fn pending_ref(&self) -> PendingStateRef {
        self.pending_ref
    }

    pub(crate) fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    pub(crate) fn new_epoch(&self) -> EpochId {
        self.new_state.epoch()
    }
}

#[derive(Default)]
pub(crate) struct EpochManager {
    states: HashMap<GroupId, EpochState>,
    pending_counter: u64,
    pending: HashMap<PendingStateRef, PendingMeta>,
    #[cfg(test)]
    fail_next_prepare_pending: bool,
}

impl EpochManager {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn fail_next_prepare_pending_for_test(&mut self) {
        self.fail_next_prepare_pending = true;
    }

    pub(crate) fn pending_refs_for_group(&self, group_id: &GroupId) -> Vec<PendingStateRef> {
        self.pending
            .iter()
            .filter(|(_, meta)| &meta.group_id == group_id)
            .map(|(reference, _)| *reference)
            .collect()
    }

    /// Drop both halves of a group's epoch bookkeeping: its `EpochState` entry
    /// and the pending metas that index into it. Used by `forget_group_local`
    /// (the group's rows are gone) and by the hydration-failure compensation
    /// (`Engine::discard_hydration_side_effects`), whose refs can no longer
    /// resolve. Prefer [`Self::clear_group_state`] where the pending lifecycle
    /// must survive the retraction.
    pub(crate) fn forget_group(&mut self, group_id: &GroupId) {
        self.states.remove(group_id);
        self.pending.retain(|_, meta| &meta.group_id != group_id);
    }

    // ── Read-only queries ──────────────────────────────────────────────────

    pub(crate) fn state(&self, group_id: &GroupId) -> Option<&EpochState> {
        self.states.get(group_id)
    }

    pub(crate) fn unrecoverable_group_ids(&self) -> Vec<GroupId> {
        self.states
            .iter()
            .filter(|(_, state)| matches!(state, EpochState::Unrecoverable { .. }))
            .map(|(group_id, _)| group_id.clone())
            .collect()
    }

    /// Drop a group's in-memory epoch entry: the retraction path for the
    /// session-open cheap pass's provisional `Stable` seed (mdk#1161).
    ///
    /// One caller. `ensure_hydrated` retracts the seed immediately
    /// before running full per-group hydration, so hydration derives the real
    /// entry (`set_stable` / `restore_pending` / `restore_unrecoverable`)
    /// from exactly the entry-absent conditions the open-time loop always
    /// had — a projected-forward record mirror must not become the
    /// `begin_pending` base. A hydration *failure* uses [`Self::forget_group`]
    /// instead (through `Engine::discard_hydration_side_effects`): a
    /// quarantined group must have no epoch entry — `live_group_ids` filters on
    /// entry presence (over and above the durable terminal markers), and every
    /// convergence/ingest gate treats "no state" as "not live" — and no pending
    /// meta either, because a ref a partial hydration handed out can never
    /// resolve once the entry it indexes is gone. Durable halt markers are
    /// unaffected: `sync_unrecoverable_halt_from_storage` re-syncs them on
    /// demand.
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

    /// Staging paths check before any durable or MLS mutation. The allocation
    /// remains fallible as a final guard, but must not introduce a late failure
    /// after a commit and its Welcomes have been written.
    pub(crate) fn ensure_pending_space(&self) -> Result<(), EngineError> {
        if self.pending_counter == u64::MAX {
            return Err(EngineError::Backend(
                "pending reference space exhausted".into(),
            ));
        }
        Ok(())
    }

    /// Reserve a durable handle without installing a group's pending state.
    /// Construction must reserve every restorable handle before any group
    /// hydrates or stages new work; per-group restoration alone is too late.
    pub(crate) fn reserve_pending_ref(&mut self, pending_ref: PendingStateRef) {
        self.pending_counter = self.pending_counter.max(pending_ref.as_u64());
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
    ///   the two transitions that also retire the group's `self.pending` entry.
    ///   A blind overwrite drops the staged commit handle and strands that
    ///   entry: its rollback epoch is gone, and both exits then fail
    ///   `InvalidTransition` off the `Stable` we just wrote;
    /// - `Disbanded` has no outgoing transition.
    ///
    /// Callers already reach this only from the two overwritable states, or
    /// from no state at all — every guard here reads through `is_some_and`, so
    /// create/join and hydration pass by construction. The convergence caller
    /// is gated a step earlier than it looks: a held publication and an
    /// unresolved convergence input cannot coexist, because the outbound
    /// preflight settles convergence before it stages anything and `can_ingest`
    /// keeps new input out afterwards, so a pass entered under a held
    /// publication has no branch to select. A fired refusal means a caller lost
    /// its gate; see the invariant in `crates/cgka-engine/AGENTS.md`.
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

    /// Validate that `group_id` can enter `PendingPublish` and allocate its
    /// `PendingStateRef` *before* committing durable staging rows.
    ///
    /// On failure, `states`, `pending`, and `pending_counter` remain untouched
    /// so callers return before writing `Sent` / `DisbandCandidate` / projected
    /// `group_record` rows to storage. On success, call [`Self::commit_pending`]
    /// infallibly once the durable staging transaction commits.
    pub(crate) fn prepare_pending(
        &mut self,
        group_id: GroupId,
        pre_commit_epoch: EpochId,
        new_epoch: EpochId,
        pending: StagedCommitHandle,
        kind: PendingKind,
        audit_context: Option<AuditEventContext>,
    ) -> Result<PreparedPendingPublish, EngineError> {
        #[cfg(test)]
        if self.fail_next_prepare_pending {
            self.fail_next_prepare_pending = false;
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "FaultInjected",
                    to: "PendingPublish",
                    reason: "injected prepare_pending failure",
                },
            ));
        }
        let next_counter = self
            .pending_counter
            .checked_add(1)
            .ok_or_else(|| EngineError::Backend("pending reference space exhausted".into()))?;
        let prepared = self.prepare_pending_with_ref(
            group_id,
            pre_commit_epoch,
            new_epoch,
            pending,
            PendingStateRef::new(next_counter),
            kind,
            audit_context,
        )?;
        self.pending_counter = next_counter;
        Ok(prepared)
    }

    /// Validate that `group_id` can enter `PendingPublish` under an explicit
    /// `pending_ref` without mutating any manager state.
    #[allow(clippy::too_many_arguments)]
    fn prepare_pending_with_ref(
        &self,
        group_id: GroupId,
        pre_commit_epoch: EpochId,
        new_epoch: EpochId,
        pending: StagedCommitHandle,
        pending_ref: PendingStateRef,
        kind: PendingKind,
        audit_context: Option<AuditEventContext>,
    ) -> Result<PreparedPendingPublish, EngineError> {
        let prev = self
            .states
            .get(&group_id)
            .cloned()
            .unwrap_or_else(|| EpochState::stable(pre_commit_epoch));
        let new_state = prev.begin_pending(new_epoch, pending, pending_ref)?;
        Ok(PreparedPendingPublish {
            group_id,
            pre_commit_epoch,
            new_state,
            pending_ref,
            kind,
            audit_context,
        })
    }

    /// Infallibly install a transition previously validated by
    /// [`Self::prepare_pending`].
    pub(crate) fn commit_pending(&mut self, prepared: PreparedPendingPublish) {
        debug_assert!(
            self.states
                .get(&prepared.group_id)
                .is_none_or(EpochState::is_stable),
            "group epoch state changed between prepare_pending and commit_pending"
        );
        self.states
            .insert(prepared.group_id.clone(), prepared.new_state);
        self.pending.insert(
            prepared.pending_ref,
            PendingMeta {
                group_id: prepared.group_id,
                prior_epoch: prepared.pre_commit_epoch,
                kind: prepared.kind,
                audit_context: prepared.audit_context,
            },
        );
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
        self.reserve_pending_ref(pending_ref);
        let prepared = self.prepare_pending_with_ref(
            group_id,
            pre_commit_epoch,
            new_epoch,
            pending,
            pending_ref,
            kind,
            None,
        )?;
        self.commit_pending(prepared);
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

    #[test]
    fn pending_ref_does_not_wrap() {
        let mut manager = EpochManager::new();
        manager.reserve_pending_ref(PendingStateRef::new(u64::MAX - 1));
        let final_prepared = manager
            .prepare_pending(
                gid(),
                EpochId(0),
                EpochId(1),
                handle(),
                PendingKind::GroupEvolution,
                None,
            )
            .expect("final pending ref allocates");
        assert_eq!(final_prepared.pending_ref().as_u64(), u64::MAX);
        for _ in 0..2 {
            assert!(matches!(
                manager.prepare_pending(
                    gid(),
                    EpochId(0),
                    EpochId(1),
                    handle(),
                    PendingKind::GroupEvolution,
                    None,
                ),
                Err(EngineError::Backend(message)) if message == "pending reference space exhausted"
            ));
        }
        // Exhaustion prevents new allocations, not restoration/confirmation of
        // the exact final handle that was already persisted.
        manager
            .restore_pending(
                gid(),
                EpochId(0),
                EpochId(1),
                handle(),
                PendingStateRef::new(u64::MAX),
                PendingKind::GroupEvolution,
            )
            .unwrap();
        assert_eq!(
            manager.group_for_pending(PendingStateRef::new(u64::MAX)),
            Some(gid())
        );
    }

    /// `rollback_publish` restores the pre-stage Stable state and frees the
    /// pending slot.
    #[test]
    fn rollback_publish_restores_prior_stable_state() {
        let mut em = EpochManager::new();
        let group_id = gid();
        em.set_stable(group_id.clone(), EpochId(7));

        let prepared = em
            .prepare_pending(
                group_id.clone(),
                EpochId(7),
                EpochId(8),
                handle(),
                PendingKind::GroupEvolution,
                None,
            )
            .expect("prepare_pending from Stable succeeds");
        let pending_ref = prepared.pending_ref();
        em.commit_pending(prepared);

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
        let prepared = em
            .prepare_pending(
                group_id.clone(),
                EpochId(7),
                EpochId(8),
                handle(),
                PendingKind::GroupEvolution,
                None,
            )
            .expect("prepare_pending from Stable succeeds");
        let pending_ref = prepared.pending_ref();
        em.commit_pending(prepared);

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
        assert!(matches!(
            em.repair_to_stable(&group_id, EpochId(4)),
            Err(EngineError::InvalidTransition(transition))
                if transition.from == "Stable" && transition.to == "Stable"
        ));
        assert_eq!(em.state(&group_id).map(|s| s.name()), Some("Stable"));
        assert_eq!(em.epoch(&group_id), Some(EpochId(3)));
    }

    /// Regression for mdk#146 and mdk#3794: `prepare_pending` validates without
    /// mutating `states`, `pending`, or `pending_counter`, and `commit_pending`
    /// installs the validated transition infallibly.
    #[test]
    fn prepare_pending_validates_without_mutating_and_commits_infallibly() {
        let mut em = EpochManager::new();
        let group_id = gid();
        em.set_stable(group_id.clone(), EpochId(5));
        em.mark_unrecoverable(&group_id);

        let rejected = em.prepare_pending(
            group_id.clone(),
            EpochId(5),
            EpochId(6),
            handle(),
            PendingKind::GroupEvolution,
            None,
        );
        assert!(matches!(
            rejected,
            Err(EngineError::InvalidTransition(t))
                if t.from == "Unrecoverable" && t.to == "PendingPublish"
        ));
        assert_eq!(
            em.pending_counter, 0,
            "rejected prepare must not burn a ref"
        );
        assert!(em.is_unrecoverable(&group_id));
        assert_eq!(em.epoch(&group_id), Some(EpochId(5)));

        em.repair_to_stable(&group_id, EpochId(5)).unwrap();
        let prepared = em
            .prepare_pending(
                group_id.clone(),
                EpochId(5),
                EpochId(6),
                handle(),
                PendingKind::GroupEvolution,
                None,
            )
            .expect("prepare_pending from Stable succeeds");
        let pending_ref = prepared.pending_ref();
        // Before commit_pending, EpochManager still shows Stable and no pending slot.
        assert_eq!(em.state(&group_id).map(|s| s.name()), Some("Stable"));
        assert!(em.group_for_pending(pending_ref).is_none());

        em.commit_pending(prepared);
        assert_eq!(
            em.state(&group_id).map(|s| s.name()),
            Some("PendingPublish")
        );
        assert_eq!(em.epoch(&group_id), Some(EpochId(6)));
        assert_eq!(em.group_for_pending(pending_ref), Some(group_id));
    }
}
