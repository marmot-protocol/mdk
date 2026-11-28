//! Applying retained invitation intent through existing consent and Leave owners.

use super::AppClient;
use crate::{AppError, AppGroupRecord, SelfMembership};
use cgka_traits::app_components::{DeviceRosterV1, DeviceSlotId};
use cgka_traits::engine::ForwardedInvitation;
use cgka_traits::storage::{GroupStorage, LeaveRequestStorage};
use cgka_traits::{EngineError, GroupId};
use storage_sqlite::InvitationDecision;

/// Invocation, not persisted state: only User creates a new replicated choice.
#[derive(Clone, Copy)]
pub(super) enum AccountLeaveReason<'a> {
    User,
    /// Signing out of a chat its account is not an admin of.
    SignOut,
    /// Signing out of a chat its account is an admin of and another
    /// account is too: it steps down first (mdk#2818).
    SignOutAsAdmin,
    ReceivedDecline(&'a InvitationDecision),
}

/// Whether a row's or frontier's recorded `via_welcome_message_id_hex` belongs
/// to `admission`. A mismatch means the projection predates a replacement
/// admission (or predates migration 0223), so its inviter cannot be trusted to
/// evaluate local blocks for `admission`.
pub(super) fn standing_matches_admission(
    via_welcome_hex: Option<&str>,
    admission: &cgka_traits::group::InvitationAdmission,
) -> bool {
    match &admission.via_welcome {
        None => admission.created_locally && via_welcome_hex.is_none(),
        Some(welcome) => via_welcome_hex == Some(hex::encode(welcome.as_slice()).as_str()),
    }
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

    /// Whether this Leave first takes its account off the admin list (D99),
    /// through the engine's `StepDownAndLeave`. With device groups off an
    /// admin's Leave is refused here, before any choice, push token removal
    /// or departure, as before 0.15: the host demotes first (mdk#3014
    /// interim). Sign-out steps down only from a chat stage 1 chose to
    /// (mdk#2818), whether or not device groups are on: the device wipes once
    /// its sign-out ends, so no leave outlives it.
    pub(super) fn leave_steps_admin_down(
        &self,
        group_id: &GroupId,
        reason: AccountLeaveReason<'_>,
    ) -> Result<bool, AppError> {
        match reason {
            AccountLeaveReason::SignOut => return Ok(false),
            AccountLeaveReason::SignOutAsAdmin => {
                return self.account_leave_needs_demotion(group_id);
            }
            AccountLeaveReason::User | AccountLeaveReason::ReceivedDecline(_) => {}
        }
        let needs_demotion = self.account_leave_needs_demotion(group_id);
        if self.app.admin_leave_steps_down() {
            return needs_demotion;
        }
        let admin = match needs_demotion {
            Ok(admin) => admin,
            Err(error)
                if matches!(
                    error.as_engine_error(),
                    Some(EngineError::AdminDepletion { .. })
                ) =>
            {
                true
            }
            Err(error) => return Err(error),
        };
        if admin {
            return Err(AppError::from(marmot_session::SessionError::Engine(
                EngineError::AdminCannotSelfRemove {
                    group_id: group_id.clone(),
                },
            )));
        }
        Ok(false)
    }

    /// Ordinary UserLeave includes an already accepted current copy. Unknown
    /// identity/trust and a held MAX leave ordinary leaf departure independent.
    pub(super) fn record_user_leave_decision(
        &mut self,
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
        let decision = store.record_invitation_decision(&chat, admission.generation, true)?;
        self.send_invitation_decisions_next_turn();
        Ok(Some(decision))
    }

    /// This device owes its siblings invitation decisions: its user answered
    /// one, or branch selection withdrew the update that carried them. They
    /// get them on the worker's next turn, through the same send a sibling
    /// Add's acceptance takes ([`Self::send_recorded_acceptances`]), not at
    /// the next maintenance pass (mdk#3566).
    pub(super) fn send_invitation_decisions_next_turn(&mut self) {
        self.acceptances_recorded = true;
        self.invitation_decisions_changed = true;
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
        &mut self,
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
        let decision = account.app_storage().record_invitation_decision(
            &chat,
            admission.generation,
            declined,
        )?;
        self.send_invitation_decisions_next_turn();
        Ok(Some(decision))
    }

    /// Clear `pending_confirmation` on the in-memory row so the enclosing
    /// projection batch persists it settled.
    fn clear_pending_confirmation_in_batch(&mut self, group_id: &GroupId, chat: &str) {
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

    /// Re-arm `admission`'s retained decision and settle an acceptable accept
    /// in the enclosing projection batch.
    fn owe_and_settle_admission(
        &mut self,
        group_id: &GroupId,
        chat: &str,
        admission: &cgka_traits::group::InvitationAdmission,
    ) -> Result<(), AppError> {
        let account = self.app.account_storage(&self.state.label)?;
        account
            .app_storage()
            .owe_installed_invitation_decision(chat, &admission.generation)?;
        // A decision this admission makes actionable applies on the worker's
        // next turn (mdk#3566).
        self.invitation_decisions_changed = true;
        if self.accepted_invitation_projection(group_id)?.is_some() {
            self.clear_pending_confirmation_in_batch(group_id, chat);
        }
        Ok(())
    }

    /// A sibling's decision that arrived while this chat was deleted locally
    /// was set aside with no work, because there was no row to apply it to,
    /// and only an exact admission re-arms it. A message that recreates the
    /// row is not an admission, so re-arm the current admission's decision
    /// here, settle an acceptable retained accept in the same batch (as
    /// [`Self::note_invitation_admission`] does), and let the ordinary
    /// decision pass finish any decline or gap bookkeeping (mdk#3555).
    pub(super) fn owe_decision_set_aside_while_deleted(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() || self.is_device_group(group_id)? {
            return Ok(());
        }
        let account = self.app.account_storage(&self.state.label)?;
        let Some(admission) = account.invitation_admission(group_id)? else {
            return Ok(());
        };
        let chat = hex::encode(group_id.as_slice());
        let standing_matches = self.state_group_record(group_id).is_some_and(|group| {
            standing_matches_admission(group.via_welcome_message_id_hex.as_deref(), &admission)
        });
        if !standing_matches {
            // Without this admission's own Welcome/inviter on the recreated
            // row (a pre-0223 frontier, or a replacement Welcome whose join
            // checkpoint failed before deletion), we cannot verify the inviter
            // against local blocks for an accept. Still re-arm a retained
            // decline so Leave runs as the sibling decided.
            if account
                .app_storage()
                .invitation_decision(&chat, &admission.generation)?
                .is_some_and(|decision| decision.declined)
            {
                account
                    .app_storage()
                    .owe_installed_invitation_decision(&chat, &admission.generation)?;
                self.invitation_decisions_changed = true;
            }
            return Ok(());
        }
        self.owe_and_settle_admission(group_id, &chat, &admission)
    }

    /// Called from the real admitted lifecycle event, including durable replay.
    pub(super) fn note_invitation_admission(
        &mut self,
        group_id: &GroupId,
        via_welcome: Option<&cgka_traits::MessageId>,
        forwarded: &ForwardedInvitation,
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() || self.is_device_group(group_id)? {
            return Ok(());
        }
        let account = self.app.account_storage(&self.state.label)?;
        let chat = hex::encode(group_id.as_slice());
        match account.invitation_admission(group_id)? {
            // An unidentified copy stays local-only. Only the sibling that
            // added it can say it is confirmed there (mdk#3546).
            None => {
                if forwarded.confirmed && self.acceptable_pending_invitation(group_id)?.is_some() {
                    self.clear_pending_confirmation_in_batch(group_id, &chat);
                }
            }
            Some(admission) => {
                if admission.via_welcome.as_ref() != via_welcome {
                    return Ok(());
                }
                if admission.created_locally {
                    account
                        .app_storage()
                        .ensure_founding_invitation_decision(&chat, admission.generation)?;
                }
                self.owe_and_settle_admission(group_id, &chat, &admission)?;
            }
        }
        Ok(())
    }

    /// Before a sibling Add of `chat`, which makes no claim or KeyPackage
    /// spend first: a confirmed copy holding no decision for its generation,
    /// such as one accepted while device groups were off, records the
    /// acceptance a founder records (mdk#3546). Returns whether it did; the
    /// caller then leaves the Add to a later pass, and sends what it recorded
    /// once its scan ends ([`Self::send_recorded_acceptances`]), so the
    /// sibling installs its copy settled and no send takes in device-group
    /// traffic mid-scan. Only a copy founded here, or whose presented
    /// invitation is that admission's own Welcome, counts as accepted: a row
    /// rebuilt after a local deletion carries the standing and Welcome the
    /// deleted row had, or none if its deletion predates that record
    /// (mdk#3555).
    pub(super) fn record_unrecorded_acceptance(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let Some(group) = self.state_group_record(group_id) else {
            return Ok(false);
        };
        if group.pending_confirmation {
            return Ok(false);
        }
        let account = self.app.account_storage(&self.state.label)?;
        let Some(admission) = account.invitation_admission(group_id)? else {
            return Ok(false);
        };
        let chat = hex::encode(group_id.as_slice());
        let storage = account.app_storage();
        if storage
            .invitation_decision(&chat, &admission.generation)?
            .is_some()
        {
            return Ok(false);
        }
        if !standing_matches_admission(group.via_welcome_message_id_hex.as_deref(), &admission) {
            return Ok(false);
        }
        storage.ensure_founding_invitation_decision(&chat, admission.generation)?;
        // A value the decision format cannot hold is not recorded.
        if storage
            .invitation_decision(&chat, &admission.generation)?
            .is_none()
        {
            return Ok(false);
        }
        self.acceptances_recorded = true;
        Ok(true)
    }

    /// Whether `sibling` holds this device's decision for `chat`'s current
    /// generation, so an Add of it there installs the chat as that decision
    /// settles it, not as an invitation (mdk#3556): this device's last
    /// broadcast was made for `sibling` as `roster` lists it, and the
    /// decision has gone out since. A chat with no decision here has none to
    /// wait for. Until then the caller leaves the Add to a later pass.
    pub(super) fn sibling_holds_decision(
        &self,
        chat: &GroupId,
        roster: &DeviceRosterV1,
        sibling: &DeviceSlotId,
    ) -> Result<bool, AppError> {
        let account = self.app.account_storage(&self.state.label)?;
        let Some(admission) = account.invitation_admission(chat)? else {
            return Ok(true);
        };
        let storage = account.app_storage();
        let Some(unsent) = storage
            .invitation_decision_unsent(&hex::encode(chat.as_slice()), &admission.generation)?
        else {
            return Ok(true);
        };
        let Some(schedule) = storage.small_state_schedule()? else {
            return Ok(false);
        };
        Ok(!unsent && crate::small_state::broadcast_reached(&schedule, roster, sibling))
    }

    /// Send, once a sibling-Add scan has ended, the acceptances it recorded,
    /// with any other owed small state. Other owed state alone waits for
    /// ordinary maintenance.
    pub(super) async fn send_recorded_acceptances(&mut self) {
        if !std::mem::take(&mut self.acceptances_recorded) {
            return;
        }
        if let Err(error) = self.send_owed_small_state().await
            && !self.answers_await_epoch(&error)
        {
            tracing::warn!(target: "marmot_app::client::invitation_decisions", method = "send_recorded_acceptances", error_kind = error.privacy_safe_kind(), "recorded acceptances wait for ordinary small-state sending");
        }
    }

    /// Note a small-state send the engine refused, before anything was
    /// encrypted, because the device group's epoch moves or is about to, as
    /// while a fork between linked devices resolves, with invitation answers
    /// left unsent. The worker's invitation turn after the epoch settles
    /// sends them ([`Self::drive_changed_invitation_decisions`]), not the
    /// next maintenance pass (mdk#3573). Returns whether it noted one.
    pub(super) fn answers_await_epoch(&mut self, error: &AppError) -> bool {
        let waiting = matches!(
            error.as_engine_error(),
            Some(
                EngineError::AppMessageEpochUnsettled { .. }
                    | EngineError::AppMessageEpochMismatch { .. }
            )
        ) && self
            .app
            .account_storage(&self.state.label)
            .and_then(|account| Ok(account.app_storage().unsent_invitation_decisions()?))
            .is_ok_and(|unsent| !unsent.is_empty());
        self.invitation_answers_await_epoch |= waiting;
        waiting
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
        if decision.declined {
            return Ok(None);
        }
        let Some(group) = self.acceptable_pending_invitation(group_id)? else {
            return Ok(None);
        };
        if !standing_matches_admission(group.via_welcome_message_id_hex.as_deref(), &admission) {
            return Ok(None);
        }
        Ok(Some(group))
    }

    /// A pending invitation on an active local copy that an acceptance may
    /// resolve: no Leave requested, still a member, and its inviter not
    /// blocked here.
    fn acceptable_pending_invitation(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<AppGroupRecord>, AppError> {
        let account = self.app.account_storage(&self.state.label)?;
        if account.leave_request(group_id)?.is_some() {
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

    /// Send and apply the invitation decisions changed since the last call:
    /// one this device's user made goes to the siblings, and a sibling's that
    /// won here is applied, on the worker's turn after the change instead of
    /// at the next maintenance pass (mdk#3566). What is left owed retries
    /// with maintenance. Returns whether it ran.
    ///
    /// Not while maintenance is paused or runs no pass
    /// ([`Self::maintenance_passes`]): the flag stays set and the work
    /// stays stored, for the next run that does.
    pub(crate) async fn drive_changed_invitation_decisions(&mut self) -> bool {
        if self.runtime.maintenance_is_paused()
            || !matches!(self.maintenance_passes(), Ok(super::MaintenancePasses::Run))
            || !self.invitation_turn_owed()
        {
            return false;
        }
        self.invitation_decisions_changed = false;
        self.acceptances_recorded |= std::mem::take(&mut self.invitation_answers_await_epoch);
        self.send_recorded_acceptances().await;
        self.drive_invitation_decisions().await;
        true
    }

    /// Whether the worker's next turn drives invitation decisions: one
    /// changed, or answers a settling epoch refused are ready to be sent now
    /// that the device group's epoch is no longer settling (mdk#3573).
    pub(crate) fn invitation_turn_owed(&self) -> bool {
        self.invitation_decisions_changed
            || (self.invitation_answers_await_epoch && !self.device_group_epoch_settling())
    }

    /// Whether the trusted device group is still settling its epoch — either
    /// resolving a local commit or holding pending convergence inputs — so an
    /// epoch-pinned small-state send would be refused with
    /// [`EngineError::AppMessageEpochUnsettled`].
    fn device_group_epoch_settling(&self) -> bool {
        let Ok(Some(group_id)) = self.trusted_device_group() else {
            return false;
        };
        self.runtime
            .epoch_state(&group_id)
            .is_some_and(|state| state.is_resolving_local_publish())
            || self
                .runtime
                .has_pending_convergence_inputs(&group_id)
                .unwrap_or(false)
    }

    pub(crate) async fn drive_invitation_decisions(&mut self) {
        if !self.app.device_groups_enabled() || self.runtime.maintenance_is_paused() {
            return;
        }
        if let Err(error) = self.try_invitation_decisions().await {
            self.invitation_work_held = true;
            tracing::warn!(target: "marmot_app::client::invitation_decisions", method = "drive_invitation_decisions", error_kind = error.privacy_safe_kind(), "invitation work remains for ordinary maintenance");
        }
    }

    /// Apply each owed decision once. Work a pass leaves for a reason that
    /// passes on its own is held, and maintenance retries it 15 s later
    /// (mdk#3265); work that waits for an event is not.
    async fn try_invitation_decisions(&mut self) -> Result<(), AppError> {
        let account = self.app.account_storage(&self.state.label)?;
        let storage = account.app_storage();
        let mut first_error = None;
        let mut held = false;
        for work in storage.invitation_decision_work()? {
            match self.apply_invitation_work(&work).await {
                Ok(left) => held |= left,
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        self.invitation_work_held = held;
        if first_error.is_some() {
            // A failure retries with maintenance, not on every worker turn
            // a pending projection would have asked for.
            self.invitation_decisions_changed = false;
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Apply one decision's work. Returns whether it is left owed for a
    /// reason that passes on its own: its chat's projection still saving,
    /// the chat not yet quiet or stable for a Leave, or its copy not yet
    /// projected.
    async fn apply_invitation_work(
        &mut self,
        work: &storage_sqlite::InvitationDecisionWork,
    ) -> Result<bool, AppError> {
        let decision = &work.decision;
        let group_id = GroupId::new(hex::decode(&decision.group_id_hex)?);
        let account = self.app.account_storage(&self.state.label)?;
        let storage = account.app_storage();
        if !self.invitation_generation_matches(&group_id, &decision.generation)? {
            // Retain the value, with no work until an exact native admission
            // re-arms it. Unknown values never cause a join or a fetch.
            storage.defer_uninstalled_invitation_decision(decision)?;
            return Ok(false);
        }
        // The queued projection is newer than the saved row. Let its existing
        // checkpoint commit before adopting that row or applying this choice.
        if self
            .pending_group_projection_updates
            .contains(&decision.group_id_hex)
        {
            // The worker saves it as this turn ends: try again on its next.
            self.invitation_decisions_changed = true;
            return Ok(true);
        }
        let group = self.app.group(&self.state.label, &decision.group_id_hex)?;
        if self.is_device_group(&group_id)? {
            storage.defer_uninstalled_invitation_decision(decision)?;
            return Ok(false);
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
                return Ok(false);
            }
            return Ok(true);
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
                if native_member {
                    let settling = authority.disbanding
                        || authority.lifecycle != cgka_traits::GroupLifecycleState::Stable
                        || !self.group_quiet(&group_id)?;
                    if last_admin || settling {
                        // Keep the exact work owed before push drain, sync or
                        // a queued refusal. The native send rechecks after
                        // send sync. A last admin is not retried: nothing
                        // re-arms this work when the chat's admins change, so
                        // it waits for the next maintenance run, up to an
                        // hour (the linked account's heartbeat).
                        return Ok(settling);
                    }
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
                    self.invitations_settled.push(group_id.clone());
                }
                // Native Leave owns the departure already, but application
                // work stays owed until its fallible presentation save succeeds.
                storage
                    .invitation_decline_handed_off(&decision.group_id_hex, &decision.generation)?;
                storage.mark_invitation_decision_applied(decision)?;
            } else {
                // The Leave was not requested: the decline stays owed.
                return Ok(true);
            }
        } else if work.apply_owed {
            if let Some(projection) = self.accepted_invitation_projection(&group_id)? {
                self.set_group_invite_confirmation(&group_id, false, projection.archived)?;
                self.invitations_settled.push(group_id.clone());
                storage.mark_invitation_decision_applied(decision)?;
            } else if group.as_ref().is_none_or(|group| {
                !group.pending_confirmation || group.self_membership != SelfMembership::Member
            }) || account.leave_request(&group_id)?.is_some()
                || self.runtime.group_record(&group_id)?.disbanded.is_some()
            {
                // Canonical disband can retain a pending Member projection.
                // Retire only this exact decision's work, not its retained value.
                storage.mark_invitation_decision_applied(decision)?;
            }
        }
        Ok(false)
    }
}
