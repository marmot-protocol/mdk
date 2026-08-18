//! Publish-confirm and publish-failed paths for `CgkaEngine`.
//!
//! Together with `EpochManager::confirm_publish` / `rollback_publish`,
//! these implement publish-before-apply: the staged commit only lands on
//! local MLS state once the application reports the transport succeeded.
//!
//! ### Confirm flow
//! 1. Load `MlsGroup`. The pending commit is still attached.
//! 2. If a pending commit exists: cache invitee capabilities from the
//!    staged commit's `add_proposals`, then `merge_pending_commit`.
//! 3. Refresh own-leaf capability cache + Marmot record (epoch + members
//!    + RequiredCapabilities derived from post-merge group context).
//! 4. Hand off to `EpochManager::confirm_publish` for the state-machine
//!    bookkeeping. Emit the event.
//!
//! ### Fail flow
//! 1. Load `MlsGroup`. The pending commit is still attached.
//! 2. If a pending commit exists: `clear_pending_commit` discards it.
//! 3. Marmot record + capability cache: nothing to rewind, because the
//!    send paths defer all such writes to confirm.
//! 4. Hand off to `EpochManager::rollback_publish` for the state-machine
//!    bookkeeping.
//!
//! ### Founding `create_group`
//! Current-profile founding creation is completed atomically in
//! `group_lifecycle::do_create_group` and never enters these confirm/fail
//! paths. The temporary explicit-legacy path still does: a solo legacy create
//! has no pending commit, so confirm + fail are state-machine-only at epoch 0.

use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::OutboundFanout;
use cgka_traits::engine::GroupEvent;
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::message::MessageState;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::{EpochId, GroupId};
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider as _;

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn do_confirm_published(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<GroupEvent, EngineError> {
        self.do_confirm_published_with_fanout(pending, None).await
    }

    pub(crate) async fn do_confirm_published_with_fanout(
        &mut self,
        pending: PendingStateRef,
        mut fanout: Option<&mut OutboundFanout>,
    ) -> Result<GroupEvent, EngineError> {
        let confirmed_fanout = fanout
            .as_deref()
            .map(|fanout| {
                if fanout.pending_ref() != Some(pending) || fanout.outcome().accepted_targets == 0 {
                    return Err(EngineError::Other(
                        "fanout does not contain an accepted matching pending publish".into(),
                    ));
                }
                let mut confirmed = fanout.clone();
                confirmed.mark_mls_confirmed().map_err(|_| {
                    EngineError::Other("fanout MLS confirmation transition failed".into())
                })?;
                Ok(confirmed)
            })
            .transpose()?;
        // Look up which group this pending belongs to without consuming the
        // entry — we need the MlsGroup load to succeed before we burn the
        // state-machine slot.
        let group_id = self
            .epoch_manager
            .group_for_pending(pending)
            .ok_or(EngineError::UnknownPending)?;
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());

        // Read the bookkeeping a successful confirm needs BEFORE any mutation,
        // so the durable transaction below can do every storage write while the
        // in-memory state-machine transition stays strictly afterwards. `kind`
        // and `audit_context` are reads; `origin_commit_id` is a non-consuming
        // peek (promotion happens post-commit).
        let kind = self
            .epoch_manager
            .kind_for_pending(pending)
            .ok_or(EngineError::UnknownPending)?;
        // The originating operation's context, captured at `begin_pending`. The
        // engine's ambient context has cleared by now (this is a later
        // publish-confirm call), so re-attach it explicitly.
        let audit_context = self.epoch_manager.audit_context_for_pending(pending);
        let origin_commit_id = self.peek_pending_origin_commit(pending);
        let queued_intent = self.queued_intent_by_pending.get(&pending).cloned();

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let has_pending_commit = mls_group.pending_commit().is_some();

        // Snapshot the pre-commit epoch as a fork-recovery anchor. Done outside
        // the durable transaction below because snapshot capture opens its own
        // backend transaction (it cannot nest) — but the write is keyed by epoch
        // and idempotent (`INSERT OR REPLACE`), so a retried confirm re-running
        // it is harmless.
        if has_pending_commit {
            self.retain_current_epoch_snapshot_for_group(&group_id)?;
        }

        // One durable transaction for the plain-row writes this confirm performs
        // — merge the staged commit, mirror the Marmot record, refresh the
        // capability caches, and mark the origin commit `Processed`. If the
        // backend is locked (`SQLITE_BUSY`) anywhere in here, the whole unit
        // rolls back and the typed transient error propagates *before* the
        // in-memory state-machine transition below. The pending entry is left
        // intact, so a retried `confirm_published` re-runs cleanly: the merge is
        // guarded by the still-attached staged commit, and every other write is
        // idempotent. This is the fix for the prior orphan, where the
        // `Processed` write ran AFTER the slot was consumed and a lock there
        // left an unrecoverable `UnknownPending` on retry.
        self.storage
            .with_transaction(|storage| -> Result<(), EngineError> {
                let mut own_commit_stamp = None;
                if has_pending_commit {
                    // `staged` borrows `mls_group`; scope it so the subsequent
                    // `merge_pending_commit` can take `&mut mls_group`.
                    {
                        let staged = mls_group
                            .pending_commit()
                            .expect("pending commit presence checked above");
                        crate::capability_manager::cache_from_staged_commit(
                            storage, &group_id, staged,
                        )?;
                        // Capture the convergence ordering stamp while the
                        // staged commit is still attached: stored convergence
                        // cannot re-derive priority or consumed proposal refs
                        // from the wire bytes later (MLS refuses to process
                        // own commits), so this is the only durable source.
                        own_commit_stamp = Some(crate::openmls_projection::own_commit_stamp(
                            staged,
                            self.identity.self_id().clone(),
                        )?);
                        if let (Some(stamp), Some(message_id)) =
                            (own_commit_stamp.as_mut(), origin_commit_id.as_ref())
                        {
                            stamp.checkpoint_id =
                                Some(crate::openmls_projection::own_commit_checkpoint_id(
                                    storage, message_id,
                                )?);
                        }
                    }
                    let source_epoch = EpochId(mls_group.epoch().as_u64());
                    crate::openmls_projection::mark_consumed_proposal_records_processed(
                        storage,
                        &self.crypto,
                        &mut mls_group,
                        &group_id,
                        source_epoch,
                        &own_commit_stamp
                            .as_ref()
                            .expect("pending commit produced a stamp")
                            .consumed_proposal_refs,
                    )?;
                    // Existing-group invites retain exact, non-deliverable
                    // Welcome artifacts while the Add commit is merely staged.
                    // Promote only artifacts owned by this exact commit in the
                    // transaction that makes its membership canonical.
                    if kind == crate::epoch_manager::PendingKind::GroupEvolution
                        && let Some(origin_commit_id) = origin_commit_id.as_ref()
                    {
                        crate::message_processor::transition_staged_invite_welcomes(
                            storage,
                            &group_id,
                            source_epoch,
                            Some(origin_commit_id),
                            MessageState::Sent,
                        )?;
                    }
                    let tx_provider =
                        EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                    mls_group
                        .merge_pending_commit(&tx_provider)
                        .map_err(|e| EngineError::Backend(format!("merge_pending: {e:?}")))?;
                    crate::app_components::validate_current_profile_group_invariants(&mls_group)?;
                    if let Some(stamp) = own_commit_stamp.as_mut() {
                        stamp.resulting_epoch_authenticator = Some(
                            crate::openmls_projection::own_commit_post_merge_epoch_authenticator(
                                &mls_group,
                            ),
                        );
                    }
                }

                // Now the MLS group is at the new epoch. Mirror the Marmot
                // record (epoch + members + RequiredCapabilities + app-component
                // state) and refresh the self-cache (commits can rotate own leaf
                // via force_self_update). The record is always written at create
                // time (group_lifecycle::do_create_group), so propagate a read
                // failure here rather than swallowing it: a transient backend
                // error must roll back the whole transaction and stay retryable,
                // never commit the merge + `Processed` write with a stale record.
                let mut g = storage.get_group(&group_id)?;
                g.epoch = EpochId(mls_group.epoch().as_u64());
                if kind != crate::epoch_manager::PendingKind::Disband {
                    g.members = crate::group_lifecycle::marmot_members(&mls_group);
                }
                g.required_capabilities = required_capabilities_from_group(&mls_group);
                crate::group_lifecycle::mirror_app_components_into_record(&mls_group, &mut g);
                storage.put_group(&g)?;
                crate::capability_manager::cache_self_capabilities(
                    storage,
                    &group_id,
                    &mls_group,
                    self.identity.self_id(),
                    self.ciphersuite,
                )?;
                if let Some(stamp) = own_commit_stamp.as_ref()
                    && let Some(checkpoint_id) = stamp.checkpoint_id.as_ref()
                {
                    storage.create_group_state_checkpoint(
                        &group_id,
                        &cgka_traits::storage::GroupStateCheckpointRef {
                            id: checkpoint_id.clone(),
                            resulting_epoch: EpochId(mls_group.epoch().as_u64()),
                        },
                    )?;
                }
                if let Some(message_id) = origin_commit_id.as_ref() {
                    // Enrich the stored wire record with the convergence stamp
                    // (when one was captured above) in the same write that marks
                    // it `Processed`, so a post-restart stored-convergence pass
                    // can rebuild this commit's branch as a pre-validated
                    // candidate instead of silently pruning it.
                    crate::openmls_projection::stamp_processed_own_commit_record(
                        storage,
                        message_id,
                        own_commit_stamp.take(),
                    )?;
                    if let Some(maintenance) = storage.maintenance_storage()
                        && let Some(mut evolution) = maintenance
                            .list_group_evolutions()?
                            .into_iter()
                            .find(|evolution| {
                                evolution.signed_message_id.as_ref() == Some(message_id)
                            })
                    {
                        evolution.phase = cgka_traits::maintenance::GroupEvolutionPhase::Confirmed;
                        maintenance.put_group_evolution(&evolution)?;
                    }
                }
                if let Some((_, intent_id)) = queued_intent.as_ref() {
                    storage.delete_queued_outbound_intent(intent_id)?;
                }
                if let Some(fanout) = confirmed_fanout.as_ref() {
                    storage.put_outbound_fanout(fanout)?;
                }
                Ok(())
            })?;

        // Post-merge fork-recovery anchor (idempotent, own transaction).
        self.retain_current_epoch_snapshot_for_group(&group_id)?;

        // #740 rotation: a confirmed local UpdateAppComponents commit may have
        // changed this group's Nostr routing component; additively refresh the
        // transport-id index so the new nostr_group_id resolves on the inbound
        // path (the prior id stays mapped for the overlap window).
        self.reindex_transport_group_id(&group_id);

        // Durable state has committed. From here on the steps are in-memory
        // state-machine transitions (idempotent-unsafe but infallible w.r.t. the
        // backend) plus best-effort cleanup. Kind discriminates create (always
        // `GroupCreated`) from evolution (always `EpochChanged`).
        let (group_id, new_epoch) = self.epoch_manager.confirm_publish(pending)?;
        if let (Some(fanout), Some(confirmed)) = (fanout.take(), confirmed_fanout) {
            *fanout = confirmed;
        }
        self.queued_intent_by_pending.remove(&pending);
        if has_pending_commit {
            // A proposal-arrival signal only resets scheduling for its source
            // epoch. Confirming any commit crosses that boundary, so no
            // signal from the prior epoch remains actionable.
            self.valid_proposal_groups.remove(&group_id);
        }
        self.audit_with_context(
            Some(&group_id),
            audit_context.clone(),
            crate::audit_helpers::epoch_confirmed_event(
                EpochId(new_epoch.0.saturating_sub(1)),
                new_epoch,
                crate::audit_helpers::pending_kind_str(kind),
            ),
        );
        self.audit_with_context(
            Some(&group_id),
            audit_context.clone(),
            crate::audit_helpers::epoch_state_changed_event(
                Some("pending_publish"),
                "stable",
                new_epoch,
                "publish_confirmed",
                Some(pending),
                Some(crate::audit_helpers::pending_kind_str(kind)),
            ),
        );
        // The transport id of the commit we just confirmed. It identifies the
        // rows the upcoming `GroupStateChanged` events synthesize, so they can be
        // invalidated by origin commit if this commit later loses a fork. The
        // `Processed` state write already landed in the durable transaction
        // above; here we only consume the in-memory pending entry and emit the
        // audit line.
        let origin_commit_id = self.take_pending_origin_commit(pending);
        if let Some(message_id) = origin_commit_id.as_ref() {
            self.audit_with_context(
                Some(&group_id),
                audit_context.clone(),
                crate::audit_helpers::message_state_changed_event(
                    hex::encode(message_id.as_slice()),
                    MessageState::Processed,
                    "publish_confirmed",
                ),
            );
        }
        self.schedule_drain_for_retained_outbound_intents(&group_id);
        let event = match kind {
            crate::epoch_manager::PendingKind::CreateGroup => GroupEvent::GroupCreated { group_id },
            crate::epoch_manager::PendingKind::GroupEvolution => GroupEvent::EpochChanged {
                group_id,
                from: EpochId(new_epoch.0.saturating_sub(1)),
                to: new_epoch,
            },
            crate::epoch_manager::PendingKind::Disband => GroupEvent::EpochChanged {
                group_id,
                from: EpochId(new_epoch.0.saturating_sub(1)),
                to: new_epoch,
            },
        };
        let replay_group_id = match &event {
            GroupEvent::GroupCreated { group_id } | GroupEvent::EpochChanged { group_id, .. } => {
                group_id.clone()
            }
            _ => unreachable!("confirm only emits create/evolution events"),
        };
        self.events_buf.push_back(event.clone());
        if kind == crate::epoch_manager::PendingKind::Disband {
            self.pending_state_changes.remove(&pending);
            self.schedule_pending_convergence_group(&replay_group_id);
            return Ok(event);
        }
        if let Some(changes) = self.pending_state_changes.remove(&pending) {
            for pending_change in changes {
                self.push_group_state_change(
                    &replay_group_id,
                    new_epoch,
                    pending_change.actor,
                    pending_change.change,
                    origin_commit_id.clone(),
                );
            }
        }
        self.replay_buffered_messages(&replay_group_id).await?;
        Ok(event)
    }

    pub(crate) async fn do_publish_failed(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<(), EngineError> {
        self.do_publish_failed_with_fanout(pending, None).await
    }

    pub(crate) async fn do_publish_failed_with_fanout(
        &mut self,
        pending: PendingStateRef,
        mut fanout: Option<&mut OutboundFanout>,
    ) -> Result<(), EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let origin_commit_id = self.peek_pending_origin_commit(pending);

        let group_id = self
            .epoch_manager
            .group_for_pending(pending)
            .ok_or(EngineError::UnknownPending)?;
        let kind = self
            .epoch_manager
            .kind_for_pending(pending)
            .ok_or(EngineError::UnknownPending)?;

        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        let rolled_back_fanout = fanout
            .as_deref()
            .map(|fanout| {
                let outcome = fanout.outcome();
                if fanout.pending_ref() != Some(pending)
                    || outcome.accepted_targets != 0
                    || !outcome.fanout_complete
                {
                    return Err(EngineError::Other(
                        "fanout is not a complete all-failed matching pending publish".into(),
                    ));
                }
                let mut rolled_back = fanout.clone();
                rolled_back.mark_mls_rolled_back().map_err(|_| {
                    EngineError::Other("fanout MLS rollback transition failed".into())
                })?;
                Ok(rolled_back)
            })
            .transpose()?;

        let has_pending_commit = mls_group.pending_commit().is_some();
        let pending_was_self_remove_only = mls_group.pending_commit().is_some_and(|staged| {
            let mut count = 0usize;
            staged.queued_proposals().all(|queued| {
                count += 1;
                matches!(queued.proposal(), openmls::prelude::Proposal::SelfRemove)
            }) && count > 0
        });
        self.storage
            .with_transaction(|storage| -> Result<(), EngineError> {
                if has_pending_commit {
                    let source_epoch = EpochId(mls_group.epoch().as_u64());
                    // No endpoint accepted this staged evolution. Retire its
                    // exact Welcomes in the same transaction as the MLS rewind
                    // so a higher-layer repair index cannot deliver an orphan.
                    if kind == crate::epoch_manager::PendingKind::GroupEvolution {
                        crate::message_processor::transition_staged_invite_welcomes(
                            storage,
                            &group_id,
                            source_epoch,
                            origin_commit_id.as_ref(),
                            MessageState::Failed,
                        )?;
                    }
                    let tx_provider =
                        EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                    mls_group
                        .clear_pending_commit(tx_provider.storage())
                        .map_err(|e| EngineError::Backend(format!("clear_pending: {e:?}")))?;
                    if pending_was_self_remove_only {
                        // Auto-commit preparation started from an empty
                        // OpenMLS proposal store and queued only its selected
                        // SelfRemove references. Drop that staging residue so
                        // the durable retained-message scan can deterministically
                        // rebuild the same selection after publish failure.
                        mls_group
                            .clear_pending_proposals(tx_provider.storage())
                            .map_err(|e| {
                                EngineError::Backend(format!("clear_pending_proposals: {e:?}"))
                            })?;
                    }
                }

                // Re-derive the Marmot projection in the same durable unit as the
                // MLS clear and fanout terminal state.
                let mut g = storage.get_group(&group_id)?;
                g.epoch = EpochId(mls_group.epoch().as_u64());
                g.members = crate::group_lifecycle::marmot_members(&mls_group);
                g.required_capabilities = required_capabilities_from_group(&mls_group);
                crate::group_lifecycle::mirror_app_components_into_record(&mls_group, &mut g);
                storage.put_group(&g)?;
                if let Some(fanout) = rolled_back_fanout.as_ref() {
                    storage.put_outbound_fanout(fanout)?;
                }
                if let Some(message_id) = origin_commit_id.as_ref()
                    && let Some(maintenance) = storage.maintenance_storage()
                    && let Some(evolution) = maintenance
                        .list_group_evolutions_for_group(&group_id)?
                        .into_iter()
                        .find(|evolution| evolution.signed_message_id.as_ref() == Some(message_id))
                {
                    // No relay accepted the event, so compensate the staged
                    // evolution in the same transaction as the MLS clear.
                    maintenance.delete_group_evolution(&evolution.id)?;
                }
                if kind == crate::epoch_manager::PendingKind::Disband {
                    storage.clear_disband_candidates(&group_id)?;
                    if let Some(mut request) = storage.disband_request(&group_id)? {
                        request.last_prepared_epoch = None;
                        storage.put_disband_request(&request)?;
                    }
                }
                Ok(())
            })?;

        if let (Some(fanout), Some(rolled_back)) = (fanout.take(), rolled_back_fanout) {
            *fanout = rolled_back;
        }
        let pending_epoch_pre = EpochId(mls_group.epoch().as_u64());
        let audit_context = self.epoch_manager.audit_context_for_pending(pending);
        let (group_id, prior_epoch) = self.epoch_manager.rollback_publish(pending)?;
        self.audit_with_context(
            Some(&group_id),
            audit_context.clone(),
            crate::audit_helpers::epoch_rolled_back_event(
                pending_epoch_pre,
                prior_epoch,
                crate::audit_helpers::pending_kind_str(kind),
            ),
        );
        self.audit_with_context(
            Some(&group_id),
            audit_context,
            crate::audit_helpers::epoch_state_changed_event(
                Some("pending_publish"),
                "stable",
                prior_epoch,
                "publish_failed",
                Some(pending),
                Some(crate::audit_helpers::pending_kind_str(kind)),
            ),
        );
        self.pending_state_changes.remove(&pending);
        if kind == crate::epoch_manager::PendingKind::Disband {
            self.schedule_pending_convergence_group(&group_id);
        }
        if let Some((queued_group_id, _)) = self.queued_intent_by_pending.remove(&pending) {
            self.schedule_pending_convergence_group(&queued_group_id);
        }
        self.schedule_drain_for_retained_outbound_intents(&group_id);
        self.take_pending_origin_commit(pending);
        self.restore_self_remove_auto_commit_schedules_for_group(
            &group_id,
            prior_epoch,
            self.convergence_now_ms(),
        )?;
        self.replay_buffered_messages(&group_id).await?;
        Ok(())
    }

    /// Put a group back on the runtime's drain list when it still holds durable
    /// outbound intents.
    ///
    /// Retained application payloads are released by the next convergence drain
    /// (`converge_and_drain_queued_outbound_intents`). `queue_outbound_intent`
    /// arms that drain as it writes the row, but only for a `Stable` group, and
    /// only as an edge a host consumes once.
    ///
    /// Three conditions hold a queue past that arm. `PendingPublish` and halted
    /// `Unrecoverable` hold it through the caller gates — ingest buffers rather
    /// than advances the state, and the drain and send paths both return early
    /// on non-`Stable` — so arming into them would spend a schedule on a drain
    /// that returns early, and the seam that ends each re-arms on its way out
    /// instead: a publish outcome and a verified repair Welcome through this
    /// helper, quarantine recovery (`retry_hydrate_quarantined_group`)
    /// unconditionally because it has already read the group. `Stable` with an
    /// unsettled convergence pass holds it too: the pass-close seam calls this
    /// helper to re-arm (mdk#1472), and the level signal keeps the group visible
    /// as runnable work until it releases (`has_queued_outbound_intents`), which
    /// is what a scheduler re-reads once it has consumed the edge. (Across a
    /// restart, session-open hydration re-arms the drain from the same durable
    /// queue whatever state the group landed in.)
    ///
    /// Best-effort by construction: this runs after the outcome is durable, so
    /// a transient backend lock here must not fail already-committed work.
    /// Skipping the schedule is not free, though: the intents stay durable, but
    /// their release then waits until unrelated traffic happens to schedule this
    /// group or the process restarts. So a failed read — which cannot prove the
    /// queue is empty — schedules the drain anyway; a spurious no-op pass is
    /// cheaper than a stranded payload.
    pub(crate) fn schedule_drain_for_retained_outbound_intents(&mut self, group_id: &GroupId) {
        match self.storage.list_queued_outbound_intents(group_id) {
            Ok(retained) if !retained.is_empty() => {
                self.schedule_pending_convergence_group(group_id);
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    target: "cgka_engine::publish",
                    method = "schedule_drain_for_retained_outbound_intents",
                    transient = error.is_transient(),
                    "retained-intent read failed while returning a group to Stable; scheduling the drain anyway"
                );
                self.schedule_pending_convergence_group(group_id);
            }
        }
    }
}

/// Read the `RequiredCapabilities` extension off the (post-merge) MLS
/// group context and translate it into the Marmot-side
/// `GroupCapabilities` shape used in the `Group` record.
fn required_capabilities_from_group(
    mls_group: &MlsGroup,
) -> cgka_traits::capabilities::GroupCapabilities {
    use openmls::extensions::Extension;
    let mut caps = cgka_traits::capabilities::GroupCapabilities::default();
    for ext in mls_group.extensions().iter() {
        if let Extension::RequiredCapabilities(rc) = ext {
            for t in rc.extension_types() {
                caps.extensions.insert(u16::from(*t));
            }
            for t in rc.proposal_types() {
                caps.proposals.insert(u16::from(*t));
            }
        }
    }
    if let Ok(components) = crate::app_components::required_app_components_of_group(mls_group) {
        caps.app_components = components;
    }
    caps
}
