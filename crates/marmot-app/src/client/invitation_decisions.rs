//! Applying retained invitation intent through existing consent and Leave owners.

use super::AppClient;
use crate::{AppError, AppGroupRecord, SelfMembership};
use cgka_traits::GroupId;
use cgka_traits::storage::{GroupStorage, LeaveRequestStorage};
use storage_sqlite::InvitationDecision;

impl AppClient {
    /// Only an actual pending invitation action is replicated; the existing
    /// decline entry point also supports ordinary departure and stays local then.
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
        let Some(group) = self.app.group(&self.state.label, &decision.group_id_hex)? else {
            return Ok(());
        };
        if let Some(cached) = self
            .state
            .groups
            .iter_mut()
            .find(|cached| cached.group_id_hex == decision.group_id_hex)
        {
            *cached = group.clone();
        }
        if work.decline_owed && decision.declined {
            if group.self_membership == SelfMembership::Member
                && account.leave_request(&group_id)?.is_none()
            {
                // Foreground Leave boxes this same large operation. Keep its
                // future out of every maintenance frame, including idle passes.
                let result = Box::pin(self.leave_group_with_audit_context(
                    &group_id,
                    Default::default(),
                    Some(decision),
                ))
                .await;
                if account.leave_request(&group_id)?.is_none() {
                    result?;
                }
            }
            let current = self.app.group(&self.state.label, &decision.group_id_hex)?;
            if account.leave_request(&group_id)?.is_some()
                || current.is_some_and(|current| current.self_membership != SelfMembership::Member)
            {
                storage
                    .invitation_decline_handed_off(&decision.group_id_hex, &decision.generation)?;
                self.set_group_invite_confirmation(&group_id, false, true)?;
                storage.mark_invitation_decision_applied(decision)?;
            }
        } else if work.apply_owed {
            if let Some(projection) = self.accepted_invitation_projection(&group_id)? {
                self.set_group_invite_confirmation(&group_id, false, projection.archived)?;
                storage.mark_invitation_decision_applied(decision)?;
            } else if !group.pending_confirmation
                || group.self_membership != SelfMembership::Member
                || account.leave_request(&group_id)?.is_some()
            {
                storage.mark_invitation_decision_applied(decision)?;
            }
        }
        Ok(())
    }
}
