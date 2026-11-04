//! Applying retained invitation intent through existing consent and Leave owners.

use super::AppClient;
use crate::{AppError, AppGroupRecord, SelfMembership};
use cgka_traits::storage::{GroupStorage, LeaveRequestStorage};
use cgka_traits::{EngineError, GroupId};
use storage_sqlite::InvitationDecision;

/// Invocation, not persisted state: only User creates a new replicated choice.
#[derive(Clone, Copy)]
pub(super) enum AccountLeaveReason<'a> {
    User,
    SignOut,
    ReceivedDecline(&'a InvitationDecision),
}

impl AppClient {
    /// Read current local membership and distinct active administrator accounts
    /// before a new choice or departure publication. Native send still validates.
    pub(super) fn account_leave_needs_demotion(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let (authority, membership, mut admins, leaving) = self
            .runtime
            .group_authority_view()
            .with_group_authority_snapshot(group_id, |_, authority| {
                Ok::<_, AppError>((
                    authority,
                    self.runtime.canonical_group_membership(group_id)?,
                    self.runtime.admin_pubkeys(group_id)?,
                    self.runtime
                        .leave_in_progress(group_id)
                        .map_err(marmot_session::SessionError::from)?,
                ))
            })?;
        let refusal = |error| AppError::from(marmot_session::SessionError::Engine(error));
        if authority.facts.unrecoverable {
            return Err(refusal(EngineError::GroupUnrecoverableRepairRequired {
                group_id: group_id.clone(),
            }));
        }
        if !membership.local_leaf_active {
            return Err(refusal(EngineError::NotAMember {
                group_id: group_id.clone(),
            }));
        }
        if authority.disbanding || authority.facts.disbanded {
            return Err(refusal(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: "Disbanding",
                    to: "Leave",
                    reason: "disband is terminal or requested",
                },
            )));
        }
        if leaving {
            return Err(refusal(EngineError::LeaveAlreadyRequested {
                group_id: group_id.clone(),
            }));
        }
        admins.sort();
        admins.dedup();
        admins.retain(|admin| {
            membership
                .member_leaves
                .iter()
                .any(|leaf| leaf.member.as_slice() == admin.as_slice())
        });
        let own = self.runtime.self_id();
        let is_admin = admins
            .iter()
            .any(|admin| admin.as_slice() == own.as_slice());
        if is_admin && admins.len() == 1 {
            return Err(refusal(EngineError::AdminDepletion {
                group_id: group_id.clone(),
            }));
        }
        Ok(is_admin)
    }

    /// Ordinary UserLeave includes an already accepted current copy. Unknown
    /// identity/trust and a held MAX leave ordinary leaf departure independent.
    pub(super) fn record_user_leave_decision(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InvitationDecision>, AppError> {
        if !self.app.device_groups_enabled()
            || group_id.as_slice().is_empty()
            || group_id.as_slice().len() > 256
            || self.trusted_device_group()?.is_none()
            || self.is_device_group(group_id)?
        {
            return Ok(None);
        }
        let account = self.app.account_storage(&self.state.label)?;
        let Some(admission) = account.invitation_admission(group_id)? else {
            return Ok(None);
        };
        let chat = hex::encode(group_id.as_slice());
        let store = account.app_storage();
        if store
            .invitation_decision(&chat, &admission.generation)?
            .is_some_and(|held| held.version == storage_sqlite::MAX_SMALL_STATE_NUMBER)
        {
            return Ok(None);
        }
        Ok(Some(store.record_invitation_decision(
            &chat,
            admission.generation,
            true,
        )?))
    }

    /// An existing automatic Add obligation never spreads an invitation this
    /// copy's current authenticated generation already declined. Unknown
    /// legacy admissions and decisions for another generation stay independent.
    pub(super) fn invitation_allows_sibling_add(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let account = self.app.account_storage(&self.state.label)?;
        let Some(admission) = account.invitation_admission(group_id)? else {
            return Ok(true);
        };
        Ok(account
            .app_storage()
            .invitation_decision(&hex::encode(group_id.as_slice()), &admission.generation)?
            .is_none_or(|decision| !decision.declined))
    }

    /// Pending invitation acceptance uses its existing presentation guard.
    /// UserLeave records its current admission separately, including accepted copies.
    pub(super) fn record_local_invitation_decision(
        &self,
        group_id: &GroupId,
        declined: bool,
    ) -> Result<Option<InvitationDecision>, AppError> {
        if !self.app.device_groups_enabled()
            || (group_id.as_slice().is_empty() || group_id.as_slice().len() > 256)
        {
            return Ok(None);
        }
        let chat = hex::encode(group_id.as_slice());
        let Some(group) = self.app.group(&self.state.label, &chat)? else {
            return Ok(None);
        };
        if group.self_membership != SelfMembership::Member || !group.pending_confirmation {
            return Ok(None);
        }
        let account = self.app.account_storage(&self.state.label)?;
        let Some(admission) = account.invitation_admission(group_id)? else {
            return Ok(None);
        };
        Ok(Some(account.app_storage().record_invitation_decision(
            &chat,
            admission.generation,
            declined,
        )?))
    }

    /// Called from the real admitted lifecycle event, including durable replay.
    pub(super) fn note_invitation_admission(
        &mut self,
        group_id: &GroupId,
        via_welcome: Option<&cgka_traits::MessageId>,
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() || self.is_device_group(group_id)? {
            return Ok(());
        }
        let account = self.app.account_storage(&self.state.label)?;
        let Some(admission) = account.invitation_admission(group_id)? else {
            return Ok(());
        };
        if admission.via_welcome.as_ref() != via_welcome {
            return Ok(());
        }
        let storage = account.app_storage();
        let chat = hex::encode(group_id.as_slice());
        if admission.created_locally {
            storage.ensure_founding_invitation_decision(&chat, admission.generation)?;
        }
        storage.owe_installed_invitation_decision(&chat, &admission.generation)?;
        // The enclosing projection batch persists any presentation change.
        if self.accepted_invitation_projection(group_id)?.is_some() {
            let chat = hex::encode(group_id.as_slice());
            if let Some(group) = self
                .state
                .groups
                .iter_mut()
                .find(|group| group.group_id_hex == chat)
            {
                group.pending_confirmation = false;
                self.mark_group_projection_dirty(group_id);
            }
        }
        Ok(())
    }

    /// Native founding can be recovered by the ordinary projection reconcile
    /// even if a crash preceded delivery of its non-Welcome creation event.
    pub(super) fn remember_founding_invitation(&self, group_id: &GroupId) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() || self.is_device_group(group_id)? {
            return Ok(());
        }
        let account = self.app.account_storage(&self.state.label)?;
        if let Some(admission) = account.invitation_admission(group_id)?
            && admission.created_locally
        {
            account.app_storage().ensure_founding_invitation_decision(
                &hex::encode(group_id.as_slice()),
                admission.generation,
            )?;
        }
        Ok(())
    }

    fn accepted_invitation_projection(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<AppGroupRecord>, AppError> {
        let account = self.app.account_storage(&self.state.label)?;
        let Some(admission) = account.invitation_admission(group_id)? else {
            return Ok(None);
        };
        let Some(decision) = account
            .app_storage()
            .invitation_decision(&hex::encode(group_id.as_slice()), &admission.generation)?
        else {
            return Ok(None);
        };
        if decision.declined || account.leave_request(group_id)?.is_some() {
            return Ok(None);
        }
        let native = self.runtime.group_record(group_id)?;
        if native.removed || native.unrecoverable || native.disbanded.is_some() {
            return Ok(None);
        }

        let Some(group) = self.state_group_record(group_id) else {
            return Ok(None);
        };
        if group.self_membership != SelfMembership::Member || !group.pending_confirmation {
            return Ok(None);
        }
        if let Some(sender) = group.welcomer_account_id_hex.as_ref()
            && account.app_storage().is_user_blocked(sender)?
        {
            return Ok(None);
        }
        Ok(Some(group))
    }

    fn invitation_generation_matches(
        &self,
        group_id: &GroupId,
        generation: &[u8; 32],
    ) -> Result<bool, AppError> {
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .invitation_admission(group_id)?
            .is_some_and(|admission| admission.generation == *generation))
    }

    /// Recheck after the Leave path's sync, immediately before handing work
    /// to the native owner. A newer accept cancels unrequested work only.
    pub(super) fn invitation_decline_is_current(
        &self,
        expected: &InvitationDecision,
    ) -> Result<bool, AppError> {
        let group_id = GroupId::new(hex::decode(&expected.group_id_hex)?);
        let account = self.app.account_storage(&self.state.label)?;
        if !self.invitation_generation_matches(&group_id, &expected.generation)? {
            return Ok(false);
        }
        if account.leave_request(&group_id)?.is_some() {
            return Ok(true);
        }
        Ok(account
            .app_storage()
            .invitation_decision(&expected.group_id_hex, &expected.generation)?
            .is_some_and(|decision| decision.declined))
    }

    pub(crate) async fn drive_invitation_decisions(&mut self) {
        if !self.app.device_groups_enabled() || self.runtime.maintenance_is_paused() {
            return;
        }
        if let Err(error) = self.try_invitation_decisions().await {
            tracing::warn!(target: "marmot_app::client::invitation_decisions", method = "drive_invitation_decisions", error_kind = error.privacy_safe_kind(), "invitation work remains for ordinary maintenance");
        }
    }

    async fn try_invitation_decisions(&mut self) -> Result<(), AppError> {
        let account = self.app.account_storage(&self.state.label)?;
        let storage = account.app_storage();
        let mut first_error = None;
        for work in storage.invitation_decision_work()? {
            let result = self.apply_invitation_work(&work).await;
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn apply_invitation_work(
        &mut self,
        work: &storage_sqlite::InvitationDecisionWork,
    ) -> Result<(), AppError> {
        let decision = &work.decision;
        let group_id = GroupId::new(hex::decode(&decision.group_id_hex)?);
        let account = self.app.account_storage(&self.state.label)?;
        let storage = account.app_storage();
        if !self.invitation_generation_matches(&group_id, &decision.generation)? {
            // Retain the value, with no work until an exact native admission
            // re-arms it. Unknown values never cause a join or a fetch.
            storage.defer_uninstalled_invitation_decision(decision)?;
            return Ok(());
        }
        // The queued projection is newer than the saved row. Let its existing
        // checkpoint commit before adopting that row or applying this choice.
        if self
            .pending_group_projection_updates
            .contains(&decision.group_id_hex)
        {
            return Ok(());
        }
        let group = self.app.group(&self.state.label, &decision.group_id_hex)?;
        if self.is_device_group(&group_id)? {
            storage.defer_uninstalled_invitation_decision(decision)?;
            return Ok(());
        }
        if group.is_none() {
            // Only an actual local deletion retires this copy's application
            // work. A native admission can precede its App checkpoint; keep
            // its existing debt while that ordinary projection is missing.
            // A pending clear belongs to a new admission crossing an older
            // deletion frontier, not to a deletion of the newly joined copy.
            if !self
                .pending_local_group_deletion_frontier_clears
                .contains_key(&decision.group_id_hex)
                && self.has_local_group_deletion_frontier(&group_id)?
            {
                storage.defer_uninstalled_invitation_decision(decision)?;
            }
            return Ok(());
        }
        // Winning values durably owe this pass. Reuse its retry ownership to
        // wake an existing gap even if only application state changed, with no
        // chat epoch or device-group eligibility change. A failed read above
        // keeps the work owed; a duplicate/losing value never re-arms it.
        self.invitation_decision_changes_sibling_gaps(&group_id);
        if let Some(group) = &group
            && let Some(cached) = self
                .state
                .groups
                .iter_mut()
                .find(|cached| cached.group_id_hex == decision.group_id_hex)
        {
            *cached = group.clone();
        }
        if work.decline_owed && decision.declined {
            let mut leave_requested = account.leave_request(&group_id)?.is_some();
            let mut native_member = false;
            if !leave_requested {
                // Recheck native eligibility before push drain or send sync.
                // A refused attempt keeps the decision work owed.
                let authority = self
                    .runtime
                    .group_authority_view()
                    .with_group_authority_snapshot(&group_id, |_, authority| {
                        Ok::<_, AppError>(authority)
                    })?;
                native_member = authority.facts.is_member;
                let last_admin = if native_member {
                    match self.account_leave_needs_demotion(&group_id) {
                        Ok(_) => false,
                        Err(error)
                            if matches!(
                                error.as_engine_error(),
                                Some(EngineError::AdminDepletion { .. })
                            ) =>
                        {
                            true
                        }
                        Err(error) => return Err(error),
                    }
                } else {
                    false
                };
                if native_member
                    && (last_admin
                        || authority.disbanding
                        || authority.lifecycle != cgka_traits::GroupLifecycleState::Stable
                        || !self.group_quiet(&group_id)?)
                {
                    // Keep the exact work owed before push drain, sync or a
                    // queued refusal. The native send rechecks after send sync.
                    return Ok(());
                }
            }
            if native_member && !leave_requested {
                // Foreground Leave boxes this same large operation. Keep its
                // future out of every maintenance frame, including idle passes.
                let result = Box::pin(self.leave_group_with_audit_context(
                    &group_id,
                    Default::default(),
                    AccountLeaveReason::ReceivedDecline(decision),
                ))
                .await;
                leave_requested = account.leave_request(&group_id)?.is_some();
                if !leave_requested {
                    result?;
                }
            }
            if leave_requested || !native_member {
                if group.is_some() {
                    self.set_group_invite_confirmation(&group_id, false, true)?;
                }
                // Native Leave owns the departure already, but application
                // work stays owed until its fallible presentation save succeeds.
                storage
                    .invitation_decline_handed_off(&decision.group_id_hex, &decision.generation)?;
                storage.mark_invitation_decision_applied(decision)?;
            }
        } else if work.apply_owed {
            if let Some(projection) = self.accepted_invitation_projection(&group_id)? {
                self.set_group_invite_confirmation(&group_id, false, projection.archived)?;
                storage.mark_invitation_decision_applied(decision)?;
            } else if group.as_ref().is_none_or(|group| {
                !group.pending_confirmation || group.self_membership != SelfMembership::Member
            }) || account.leave_request(&group_id)?.is_some()
            {
                storage.mark_invitation_decision_applied(decision)?;
            }
        }
        Ok(())
    }
}
