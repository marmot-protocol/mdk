//! Durable invitation recovery. Relay discovery stays in the app; the engine
//! validates identities and atomically transfers fresh intent into its queue.
use super::AppClient;
use crate::AppError;
use cgka_traits::engine::{
    SendIntent, SupersededIntentKind, SupersededIntentOutcome, SupersededIntentReport,
};

impl AppClient {
    pub fn group_recovery_status(
        &self,
        group_id: &cgka_traits::GroupId,
    ) -> Result<crate::GroupRecoveryStatus, AppError> {
        let group = self.runtime.group_record(group_id)?;
        let rejoin_invitations = self
            .runtime
            .session()
            .pending_group_rejoins()?
            .into_iter()
            .filter(|candidate| &candidate.group_id == group_id)
            .filter_map(|candidate| {
                candidate.rejoin.map(|rejoin| crate::GroupRejoinInvitation {
                    welcome_id_hex: hex::encode(candidate.message_id.as_slice()),
                    welcomer_account_id_hex: hex::encode(rejoin.welcomer.as_slice()),
                    epoch: rejoin.epoch.0,
                    local_state_token: hex::encode(rejoin.local_state_token),
                })
            })
            .collect();
        let records = self.runtime.session().reinvite_recovery_records()?;
        let mut pending_reinvites = 0u32;
        let mut failed_reinvites = 0u32;
        for record in records.iter().filter(|record| &record.group_id == group_id) {
            if let SendIntent::Invite { key_packages, .. } = &record.intent {
                let mut missing = false;
                for package in key_packages {
                    let metadata = self
                        .runtime
                        .session()
                        .key_package_metadata(package)
                        .map_err(cgka_session::SessionError::from)?;
                    missing |= !group.members.iter().any(|member| {
                        hex::encode(member.id.as_slice()) == metadata.credential_identity_hex
                    });
                }
                if !missing || group.is_terminal() {
                    continue;
                }
            }
            if record
                .reinvite
                .as_ref()
                .is_some_and(|retry| retry.abandoned)
            {
                failed_reinvites = failed_reinvites.saturating_add(1);
            } else {
                pending_reinvites = pending_reinvites.saturating_add(1);
            }
        }
        Ok(crate::GroupRecoveryStatus {
            pending_reinvites,
            failed_reinvites,
            group_id_hex: hex::encode(group_id.as_slice()),
            membership_unconfirmed: self
                .app
                .account_storage(&self.state.label)?
                .membership_unconfirmed(group_id)?,
            rejoin_invitations,
        })
    }

    pub async fn confirm_group_rejoin(
        &mut self,
        welcome_id: &cgka_traits::MessageId,
        token: &[u8],
    ) -> Result<crate::GroupRecoveryStatus, AppError> {
        let group_id = self
            .runtime
            .session_mut()
            .confirm_group_rejoin(welcome_id, token)
            .await?;
        // GroupJoined is durably journaled by the engine, so a failed app
        // projection refresh is repaired by the ordinary reopen/drain path.
        let summary = self.drain_pending_session_events().await?;
        self.pending_applied_sync_summary.merge(summary);
        self.app
            .account_storage(&self.state.label)?
            .clear_membership_uncertainty(&group_id)?;
        self.mark_group_projection_dirty_hex(hex::encode(group_id.as_slice()));
        self.group_recovery_status(&group_id)
    }

    pub fn decline_group_rejoin(
        &mut self,
        welcome_id: &cgka_traits::MessageId,
    ) -> Result<(), AppError> {
        let candidate = self
            .runtime
            .session()
            .pending_group_rejoins()?
            .into_iter()
            .find(|candidate| &candidate.message_id == welcome_id)
            .ok_or(AppError::Session(cgka_session::SessionError::Engine(
                cgka_traits::EngineError::InvalidWelcome,
            )))?;
        self.runtime
            .session_mut()
            .decline_group_rejoin(welcome_id)?;
        self.mark_group_projection_dirty_hex(hex::encode(candidate.group_id.as_slice()));
        Ok(())
    }

    pub(crate) fn observe_membership_health(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        for event in &effects.events {
            let group = match event {
                cgka_traits::engine::GroupEvent::GroupJoined { group_id, .. } => Some(group_id),
                cgka_traits::engine::GroupEvent::MessageReceived {
                    group_id,
                    sender,
                    epoch,
                    ..
                } if sender != &self.runtime.session().self_id()
                    && self
                        .runtime
                        .group_record(group_id)
                        .is_ok_and(|group| group.epoch == *epoch) =>
                {
                    Some(group_id)
                }
                _ => None,
            };
            if let Some(group_id) = group
                && self
                    .app
                    .account_storage(&self.state.label)?
                    .clear_membership_uncertainty(group_id)?
            {
                self.mark_group_projection_dirty_hex(hex::encode(group_id.as_slice()));
            }
        }
        Ok(())
    }

    pub(crate) async fn recover_superseded_invites(&mut self) -> Result<(), AppError> {
        if self.runtime.maintenance_is_paused()
            || self.app.cursor_persistence() == crate::CursorPersistence::Frozen
        {
            return Ok(());
        }
        if self
            .runtime
            .session_mut()
            .retry_rejoins_after_trusted_removal()
            .await?
        {
            let summary = self.drain_pending_session_events().await?;
            self.pending_applied_sync_summary.merge(summary);
        }
        let now_ms = super::sync::epoch_stall_now_ms();
        // One bounded lookup per seam; reserve before await so cancellations,
        // restarts and relay failures cannot spin or lose the original intent.
        for record in self.runtime.session().pending_reinvites()? {
            if record
                .reinvite
                .as_ref()
                .is_some_and(|retry| retry.next_attempt_at_ms > now_ms)
            {
                continue;
            }
            if !self
                .runtime
                .session_mut()
                .ensure_group_hydrated(&record.group_id)?
            {
                continue;
            }
            if !self
                .runtime
                .session_mut()
                .reserve_reinvite_lookup(&record.commit_id, now_ms)?
            {
                if record
                    .reinvite
                    .as_ref()
                    .is_some_and(|retry| retry.lookup_attempts >= 8)
                {
                    self.mark_group_projection_dirty_hex(hex::encode(record.group_id.as_slice()));
                    self.pending_superseded_change_events.push(SupersededIntentReport {
                        group_id: record.group_id, commit_id: record.commit_id,
                        kind: SupersededIntentKind::Invite, outcome: SupersededIntentOutcome::Abandoned,
                        reason: "fresh invitation material remained unavailable after bounded retries",
                    });
                }
                continue;
            }
            let SendIntent::Invite { key_packages, .. } = &record.intent else {
                continue;
            };
            let group = match self.runtime.group_record(&record.group_id) {
                Ok(group) => Some(group),
                Err(marmot_account::AccountError::Session(cgka_session::SessionError::Engine(
                    cgka_traits::EngineError::Storage(cgka_traits::storage::StorageError::NotFound),
                ))) => None,
                Err(error) => return Err(error.into()),
            };
            let mut members = Vec::new();
            for package in key_packages {
                let metadata = self
                    .runtime
                    .session()
                    .key_package_metadata(package)
                    .map_err(cgka_session::SessionError::from)?;
                if !group.as_ref().is_some_and(|group| {
                    group.members.iter().any(|member| {
                        hex::encode(member.id.as_slice()) == metadata.credential_identity_hex
                    })
                }) {
                    members.push(metadata.credential_identity_hex);
                }
            }
            let packages =
                if members.is_empty() || group.as_ref().is_none_or(|group| group.is_terminal()) {
                    vec![]
                } else {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        self.app.resolve_fresh_reinvite_key_packages(&members),
                    )
                    .await
                    {
                        Ok(Ok(packages)) => packages,
                        _ => break,
                    }
                };
            match self
                .runtime
                .session_mut()
                .reissue_invite_with_key_packages(&record.commit_id, packages)
            {
                Ok(Some(report)) => {
                    self.mark_group_projection_dirty_hex(hex::encode(record.group_id.as_slice()));
                    self.pending_convergence_groups.insert(record.group_id);
                    self.pending_superseded_change_events.push(report);
                }
                Ok(None) => {}
                Err(cgka_session::SessionError::Engine(cgka_traits::EngineError::Storage(
                    error,
                ))) => {
                    return Err(error.into());
                }
                Err(error) => {
                    tracing::debug!(target: "marmot_app::client", method = "recover_superseded_invites",
                        "fresh invitation recovery remains pending");
                    let _ = error;
                }
            }
            break;
        }
        Ok(())
    }
}
