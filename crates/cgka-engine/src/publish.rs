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
//! ### Solo `create_group`
//! Solo create has no pending commit (no `add_members` was called). Both
//! confirm + fail are state-machine-only — confirm transitions to Stable
//! at epoch 0, fail rewinds to Stable at epoch 0 (no-op MLS-side, but the
//! group record stays around).

use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::GroupEvent;
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::message::MessageState;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::EpochId;
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider as _;

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn do_confirm_published(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<GroupEvent, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());

        // Look up which group this pending belongs to without consuming the
        // entry — we need the MlsGroup load to succeed before we burn the
        // state-machine slot.
        let group_id = self
            .epoch_manager
            .group_for_pending(pending)
            .ok_or(EngineError::UnknownPending)?;

        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        // Cache invitee capabilities from the staged commit BEFORE merge —
        // staged_commit.add_proposals() exposes each new member's KeyPackage
        // leaf node. After merge the staged commit is consumed.
        if let Some(staged) = mls_group.pending_commit() {
            self.retain_current_epoch_snapshot_for_group(&group_id)?;
            crate::capability_manager::cache_from_staged_commit(
                &self.storage,
                &group_id,
                staged,
                self.ciphersuite,
            )?;
            mls_group
                .merge_pending_commit(&provider)
                .map_err(|e| EngineError::Backend(format!("merge_pending: {e:?}")))?;
        }

        // Now the MLS group is at the new epoch. Mirror the Marmot record
        // (epoch + members + RequiredCapabilities + app-component state)
        // and refresh the self-cache (commits can rotate own leaf via
        // force_self_update).
        if let Ok(mut g) = self.storage.get_group(&group_id) {
            g.epoch = EpochId(mls_group.epoch().as_u64());
            g.members = crate::group_lifecycle::marmot_members(&mls_group);
            g.required_capabilities = required_capabilities_from_group(&mls_group);
            crate::group_lifecycle::mirror_app_components_into_record(&mls_group, &mut g);
            self.storage.put_group(&g)?;
        }
        crate::capability_manager::cache_self_capabilities(
            &self.storage,
            &group_id,
            &mls_group,
            self.identity.self_id(),
            self.ciphersuite,
        )?;
        self.retain_current_epoch_snapshot_for_group(&group_id)?;

        // State-machine transition + event. Kind discriminates create
        // (always `GroupCreated`) from evolution (always `EpochChanged`).
        let kind = self
            .epoch_manager
            .kind_for_pending(pending)
            .ok_or(EngineError::UnknownPending)?;
        // The originating operation's context, captured at `begin_pending`. The
        // engine's ambient context has cleared by now (this is a later
        // publish-confirm call), so re-attach it explicitly.
        let audit_context = self.epoch_manager.audit_context_for_pending(pending);
        let (group_id, new_epoch) = self.epoch_manager.confirm_publish(pending)?;
        self.audit_with_context(
            Some(&group_id),
            audit_context.clone(),
            crate::audit_helpers::epoch_confirmed_event(
                EpochId(new_epoch.0.saturating_sub(1)),
                new_epoch,
                crate::audit_helpers::pending_kind_str(kind),
            ),
        );
        if let Some(message_id) = self.promote_pending_commit_for_recovery(pending) {
            self.storage
                .update_message_state(&message_id, MessageState::Processed)?;
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
        let event = match kind {
            crate::epoch_manager::PendingKind::CreateGroup => GroupEvent::GroupCreated { group_id },
            crate::epoch_manager::PendingKind::GroupEvolution => GroupEvent::EpochChanged {
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
        if let Some(changes) = self.pending_state_changes.remove(&pending) {
            for pending_change in changes {
                self.push_group_state_change(
                    &replay_group_id,
                    new_epoch,
                    pending_change.actor,
                    pending_change.change,
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
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());

        let group_id = self
            .epoch_manager
            .group_for_pending(pending)
            .ok_or(EngineError::UnknownPending)?;

        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        if mls_group.pending_commit().is_some() {
            mls_group
                .clear_pending_commit(provider.storage())
                .map_err(|e| EngineError::Backend(format!("clear_pending: {e:?}")))?;
        }

        // Roll back the Marmot record's projected fields. The send paths
        // wrote a projected `members` list (+ for upgrade, projected
        // `required_capabilities`); after `clear_pending_commit` the MLS
        // group is back to its pre-stage shape, so re-deriving from MLS
        // restores the prior projection. The capability cache for newly-
        // invited members stays — it's not visible via `members()` once
        // we drop them from the Marmot record, and the next successful
        // invite simply overwrites.
        if let Ok(mut g) = self.storage.get_group(&group_id) {
            g.epoch = EpochId(mls_group.epoch().as_u64());
            g.members = crate::group_lifecycle::marmot_members(&mls_group);
            g.required_capabilities = required_capabilities_from_group(&mls_group);
            crate::group_lifecycle::mirror_app_components_into_record(&mls_group, &mut g);
            self.storage.put_group(&g)?;
        }

        let kind = self
            .epoch_manager
            .kind_for_pending(pending)
            .ok_or(EngineError::UnknownPending)?;
        let pending_epoch_pre = EpochId(mls_group.epoch().as_u64());
        let audit_context = self.epoch_manager.audit_context_for_pending(pending);
        let (group_id, prior_epoch) = self.epoch_manager.rollback_publish(pending)?;
        self.audit_with_context(
            Some(&group_id),
            audit_context,
            crate::audit_helpers::epoch_rolled_back_event(
                pending_epoch_pre,
                prior_epoch,
                crate::audit_helpers::pending_kind_str(kind),
            ),
        );
        self.pending_state_changes.remove(&pending);
        self.forget_pending_commit_for_recovery(pending)?;
        self.replay_buffered_messages(&group_id).await?;
        Ok(())
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
