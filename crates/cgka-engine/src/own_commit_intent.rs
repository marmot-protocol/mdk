//! Re-issuing the intent behind an own commit that convergence superseded
//! (mdk#1734).
//!
//! When two devices commit at the same epoch, branch selection keeps one and
//! parks the other. The parked committer already told its caller the change
//! saved, so dropping the intent silently is a product defect. The send path
//! records every own group-evolution commit's intent, together with the state
//! it was authored against, from staging through the rewind horizon. When a supersession is announced or later derived from stored
//! dispositions, [`Engine::reissue_superseded_own_commit`] decides:
//!
//! - a profile edit or component update is re-queued only when the winning
//!   branch left every field it touches exactly as the author saw it, and is
//!   otherwise reported as a conflict so the winner's value stands;
//! - a removal is re-queued for the targets that are still members, or
//!   reported as already satisfied when none remain;
//! - a lost invite retains its recipients while the host resolves fresh
//!   KeyPackages; consumed material is rejected and recovery survives restart
//!   (mdk#1735);
//! - re-issue is bounded by [`MAX_OWN_COMMIT_REISSUE_ATTEMPTS`].
//!
//! Re-queued intents flow through the ordinary queued-intent drain, so they
//! are regenerated against the canonical state with every existing gate.

use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::app_components::AppComponentData;
use cgka_traits::engine::{
    SendIntent, SupersededIntentKind, SupersededIntentOutcome, SupersededIntentReport,
};
use cgka_traits::error::EngineError;
use cgka_traits::message::MessageState;
use cgka_traits::storage::{
    OwnCommitBaseline, OwnCommitIntent, QueuedOutboundIntent, StorageProvider,
};
use cgka_traits::types::{GroupId, MessageId};
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider;

/// How many times one intent may be re-queued after losing a same-epoch race.
pub const MAX_OWN_COMMIT_REISSUE_ATTEMPTS: u32 = 2;

impl<S: StorageProvider> Engine<S> {
    /// The kind and authoring baseline to retain for an intent that is about
    /// to stage a group evolution, or `None` for intents that never need
    /// re-issue (application messages, leaves, self-updates, disband).
    pub(crate) fn own_commit_recording(
        &self,
        intent: &SendIntent,
    ) -> Result<Option<(SupersededIntentKind, OwnCommitBaseline)>, EngineError> {
        Ok(match intent {
            SendIntent::Invite { .. } => {
                Some((SupersededIntentKind::Invite, OwnCommitBaseline::None))
            }
            SendIntent::RemoveMembers { .. } => {
                Some((SupersededIntentKind::RemoveMembers, OwnCommitBaseline::None))
            }
            SendIntent::UpdateGroupData { group_id, .. } => {
                let mls_group = self.load_mls_group(group_id)?;
                let (name, description) =
                    crate::app_components::group_profile_of_group(&mls_group)?.unwrap_or_default();
                Some((
                    SupersededIntentKind::GroupProfile,
                    OwnCommitBaseline::GroupProfile { name, description },
                ))
            }
            SendIntent::UpdateAppComponents { group_id, updates } => {
                let mls_group = self.load_mls_group(group_id)?;
                let components = updates
                    .iter()
                    .map(|update| AppComponentData {
                        component_id: update.component_id,
                        data: crate::app_components::app_component_data_of_group(
                            &mls_group,
                            update.component_id,
                        )
                        .unwrap_or_default(),
                    })
                    .collect();
                Some((
                    SupersededIntentKind::AppComponents,
                    OwnCommitBaseline::AppComponents { components },
                ))
            }
            SendIntent::AppMessage { .. }
            | SendIntent::Leave { .. }
            | SendIntent::SelfUpdate { .. }
            | SendIntent::EnableDisbanding { .. }
            | SendIntent::Disband { .. } => None,
        })
    }

    fn load_mls_group(&self, group_id: &GroupId) -> Result<MlsGroup, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load group: {error:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))
    }

    /// Decide what becomes of the intent behind `commit_id` now that
    /// convergence has superseded that commit. Returns `None` when this device
    /// recorded no intent for it (a peer's commit, a self-update, or a record
    /// already consumed). Successful decisions consume the record; a re-queued
    /// intent replaces it atomically. Storage errors leave the original retryable.
    pub fn reissue_superseded_own_commit(
        &mut self,
        commit_id: &MessageId,
    ) -> Result<Option<SupersededIntentReport>, EngineError> {
        let Some(mut record) = self.storage.own_commit_intent(commit_id)? else {
            return Ok(None);
        };
        if record.reinvite.is_some() {
            return Ok(None);
        }
        // Reading canonical state and preparing a replacement must succeed
        // before consuming the only durable copy of the caller's intent.
        let decision = self.prepare_superseded_own_commit(&record)?;
        self.storage
            .with_transaction(|storage| -> Result<(), EngineError> {
                if let Some((_, Some(queued))) = &decision {
                    storage.put_queued_outbound_intent(queued)?;
                }
                if decision.as_ref().is_some_and(|(report, _)| {
                    report.outcome == SupersededIntentOutcome::ReinviteRequired
                }) {
                    record.reinvite = Some(cgka_traits::storage::ReinviteRetry::default());
                    storage.put_own_commit_intent(&record)?;
                } else {
                    storage.delete_own_commit_intent(commit_id)?;
                }
                Ok(())
            })?;
        if let Some((_, Some(queued))) = &decision
            && self
                .epoch_manager
                .state(&queued.group_id)
                .is_some_and(cgka_traits::engine_state::EpochState::is_stable)
        {
            self.schedule_pending_convergence_group(&queued.group_id);
        }
        Ok(decision.map(|(report, _)| report))
    }

    fn prepare_superseded_own_commit(
        &self,
        record: &OwnCommitIntent,
    ) -> Result<Option<(SupersededIntentReport, Option<QueuedOutboundIntent>)>, EngineError> {
        let commit_id = &record.commit_id;
        let kind = match &record.intent {
            SendIntent::Invite { .. } => SupersededIntentKind::Invite,
            SendIntent::RemoveMembers { .. } => SupersededIntentKind::RemoveMembers,
            SendIntent::UpdateGroupData { .. } => SupersededIntentKind::GroupProfile,
            SendIntent::UpdateAppComponents { .. } => SupersededIntentKind::AppComponents,
            _ => return Ok(None),
        };
        let report = |outcome, reason| SupersededIntentReport {
            group_id: record.group_id.clone(),
            commit_id: commit_id.clone(),
            kind,
            outcome,
            reason,
        };

        let group = self.stored_group_record(&record.group_id)?;
        let Some(group) = group else {
            return Ok(Some((
                report(
                    SupersededIntentOutcome::NotMember,
                    "the group no longer exists on this device",
                ),
                None,
            )));
        };
        if group.is_terminal() {
            return Ok(Some((
                report(
                    SupersededIntentOutcome::NotMember,
                    "this device is no longer a member of the group",
                ),
                None,
            )));
        }
        if record.reissue_attempts >= MAX_OWN_COMMIT_REISSUE_ATTEMPTS {
            return Ok(Some((
                report(
                    SupersededIntentOutcome::Abandoned,
                    "the change lost more concurrent commits than the engine retries",
                ),
                None,
            )));
        }

        let intent = match &record.intent {
            SendIntent::Invite { .. } => {
                return Ok(Some((
                    report(
                        SupersededIntentOutcome::ReinviteRequired,
                        "the invite's KeyPackages were consumed by the parked Welcome; re-invite with fresh material",
                    ),
                    None,
                )));
            }
            SendIntent::RemoveMembers { group_id, members } => {
                let remaining = members
                    .iter()
                    .filter(|member| group.members.iter().any(|current| current.id == **member))
                    .cloned()
                    .collect::<Vec<_>>();
                if remaining.is_empty() {
                    return Ok(Some((
                        report(
                            SupersededIntentOutcome::AlreadySatisfied,
                            "the winning branch already removed every requested member",
                        ),
                        None,
                    )));
                }
                SendIntent::RemoveMembers {
                    group_id: group_id.clone(),
                    members: remaining,
                }
            }
            SendIntent::UpdateGroupData {
                group_id,
                name,
                description,
            } => {
                let OwnCommitBaseline::GroupProfile {
                    name: baseline_name,
                    description: baseline_description,
                } = &record.baseline
                else {
                    return Ok(Some((
                        report(
                            SupersededIntentOutcome::Conflict,
                            "the profile edit carried no authoring baseline to compare against",
                        ),
                        None,
                    )));
                };
                let mls_group = self.load_mls_group(group_id)?;
                let (current_name, current_description) =
                    crate::app_components::group_profile_of_group(&mls_group)?.unwrap_or_default();
                let name_untouched = name.is_none() || current_name == *baseline_name;
                let description_untouched =
                    description.is_none() || current_description == *baseline_description;
                if !(name_untouched && description_untouched) {
                    return Ok(Some((
                        report(
                            SupersededIntentOutcome::Conflict,
                            "the winning branch changed the same profile field; its value stands",
                        ),
                        None,
                    )));
                }
                record.intent.clone()
            }
            SendIntent::UpdateAppComponents { group_id, updates } => {
                let OwnCommitBaseline::AppComponents { components } = &record.baseline else {
                    return Ok(Some((
                        report(
                            SupersededIntentOutcome::Conflict,
                            "the component update carried no authoring baseline to compare against",
                        ),
                        None,
                    )));
                };
                let mls_group = self.load_mls_group(group_id)?;
                let untouched = updates.iter().all(|update| {
                    let baseline = components
                        .iter()
                        .find(|component| component.component_id == update.component_id)
                        .map(|component| component.data.as_slice())
                        .unwrap_or_default();
                    crate::app_components::app_component_data_of_group(
                        &mls_group,
                        update.component_id,
                    )
                    .unwrap_or_default()
                        == baseline
                });
                if !untouched {
                    return Ok(Some((
                        report(
                            SupersededIntentOutcome::Conflict,
                            "the winning branch changed the same component; its value stands",
                        ),
                        None,
                    )));
                }
                record.intent.clone()
            }
            _ => return Ok(None),
        };

        match self.prepare_queued_outbound_intent(
            record.group_id.clone(),
            intent,
            record.reissue_attempts.saturating_add(1),
        ) {
            Ok(queued) => Ok(Some((
                report(
                    SupersededIntentOutcome::Reissued,
                    "the change is still valid against the canonical state and has been queued again",
                ),
                Some(queued),
            ))),
            Err(EngineError::QueuedOutboundAtCapacity { .. }) => Ok(Some((
                report(
                    SupersededIntentOutcome::Abandoned,
                    "the group's outbound queue is full",
                ),
                None,
            ))),
            Err(error) => Err(error),
        }
    }

    /// Re-derive supersessions from stored dispositions for every retained
    /// own-commit intent, for reconcilers that may have missed the
    /// announcement, and garbage-collect records whose commit can no longer
    /// be superseded. A confirmed commit stays reconsiderable while its
    /// source epoch is within the group's rewind horizon, so its record is
    /// kept until the group has advanced past that horizon. Live or in-flight
    /// commits are left alone.
    pub fn reissue_superseded_own_commits_from_state(
        &mut self,
    ) -> Result<Vec<SupersededIntentReport>, EngineError> {
        let mut reports = Vec::new();
        for record in self.storage.list_own_commit_intents(None)? {
            if record.reinvite.is_some() {
                continue;
            }
            let state = match self.storage.get_message(&record.commit_id) {
                Ok(message) => message.state,
                Err(cgka_traits::storage::StorageError::NotFound) => continue,
                Err(error) => return Err(error.into()),
            };
            match state {
                MessageState::ConvergenceDeferred | MessageState::EpochInvalidated => {
                    if let Some(report) = self.reissue_superseded_own_commit(&record.commit_id)? {
                        reports.push(report);
                    }
                }
                MessageState::Processed if self.own_commit_is_beyond_rewind_horizon(&record)? => {
                    self.storage.delete_own_commit_intent(&record.commit_id)?;
                }
                _ => {}
            }
        }
        Ok(reports)
    }

    /// Whether a confirmed commit staged from `record.source_epoch` can no
    /// longer be rolled back by a late rival: the group has advanced more than
    /// `max_rewind_commits` epochs past it.
    fn own_commit_is_beyond_rewind_horizon(
        &self,
        record: &OwnCommitIntent,
    ) -> Result<bool, EngineError> {
        let Some(group) = self.stored_group_record(&record.group_id)? else {
            return Ok(true);
        };
        let max_rewind = self
            .convergence_policy_for_group(&record.group_id)
            .map_err(|error| EngineError::Backend(format!("convergence policy: {error:?}")))?
            .convergence
            .max_rewind_commits;
        Ok(group.epoch.0 > record.source_epoch.0.saturating_add(max_rewind))
    }

    /// Durable fresh-material recovery records, including exhausted retries.
    pub fn reinvite_recovery_records(&self) -> Result<Vec<OwnCommitIntent>, EngineError> {
        Ok(self
            .storage
            .list_own_commit_intents(None)?
            .into_iter()
            .filter(|record| record.reinvite.is_some())
            .collect())
    }

    /// Pending fresh-material recovery is durable and independent of runtime events.
    pub fn pending_reinvites(&self) -> Result<Vec<OwnCommitIntent>, EngineError> {
        Ok(self
            .reinvite_recovery_records()?
            .into_iter()
            .filter(|record| {
                record
                    .reinvite
                    .as_ref()
                    .is_some_and(|retry| !retry.abandoned)
            })
            .collect())
    }

    /// Reserve a bounded lookup before awaiting the network, so cancellation and
    /// reopen cannot reset either the retry budget or its wall-clock pacing.
    pub fn reserve_reinvite_lookup(
        &mut self,
        commit_id: &MessageId,
        now_ms: u64,
    ) -> Result<bool, EngineError> {
        let Some(mut record) = self.storage.own_commit_intent(commit_id)? else {
            return Ok(false);
        };
        let Some(retry) = record.reinvite.as_mut() else {
            return Ok(false);
        };
        if retry.abandoned || retry.next_attempt_at_ms > now_ms {
            return Ok(false);
        }
        retry.lookup_attempts = retry.lookup_attempts.saturating_add(1);
        // Keep fast initial recovery, but leave a sleeping recipient time to
        // replenish its consumed package without exhausting the durable budget.
        const RETRY_DELAYS_MS: [u64; 8] = [
            5_000, 30_000, 120_000, 600_000, 3_600_000, 21_600_000, 86_400_000, 86_400_000,
        ];
        retry.next_attempt_at_ms = now_ms.saturating_add(
            RETRY_DELAYS_MS[retry.lookup_attempts.saturating_sub(1).min(7) as usize],
        );
        if retry.lookup_attempts > 8 {
            retry.abandoned = true;
        }
        let reserved = !retry.abandoned;
        self.storage.put_own_commit_intent(&record)?;
        Ok(reserved)
    }

    /// Transfer a lost invite to the ordinary outbound queue with newly resolved
    /// packages. Never reuse its consumed packages or change the requested identities.
    pub fn reissue_invite_with_key_packages(
        &mut self,
        commit_id: &MessageId,
        key_packages: Vec<cgka_traits::engine::KeyPackage>,
    ) -> Result<Option<SupersededIntentReport>, EngineError> {
        let Some(mut record) = self.storage.own_commit_intent(commit_id)? else {
            return Ok(None);
        };
        if record.reinvite.as_ref().is_none_or(|retry| retry.abandoned) {
            return Ok(None);
        }
        let SendIntent::Invite {
            key_packages: old,
            initial_admins,
            ..
        } = &record.intent
        else {
            return Ok(None);
        };
        let group = self.stored_group_record(&record.group_id)?;
        let mut expected = std::collections::BTreeSet::new();
        let mut consumed = std::collections::BTreeSet::new();
        for package in old {
            let metadata = crate::key_package::key_package_metadata(package)?;
            consumed.insert(metadata.key_package_ref_hex);
            if !group.as_ref().is_some_and(|group| {
                group.members.iter().any(|member| {
                    hex::encode(member.id.as_slice()) == metadata.credential_identity_hex
                })
            }) {
                expected.insert(metadata.credential_identity_hex);
            }
        }
        let report = |outcome, reason| SupersededIntentReport {
            group_id: record.group_id.clone(),
            commit_id: commit_id.clone(),
            kind: SupersededIntentKind::Invite,
            outcome,
            reason,
        };
        if group.as_ref().is_none_or(|group| group.is_terminal()) {
            self.storage.delete_own_commit_intent(commit_id)?;
            return Ok(Some(report(
                SupersededIntentOutcome::NotMember,
                "this device is no longer a member of the group",
            )));
        }
        let mls_group = self.load_mls_group(&record.group_id)?;
        let admins = crate::app_components::admins_of_group(&mls_group)?;
        let unapplied_existing_admin_grant = initial_admins.iter().any(|id| {
            !expected.contains(&hex::encode(id.as_slice()))
                && !admins.iter().any(|admin| admin.as_slice() == id.as_slice())
        });
        if expected.is_empty() {
            self.storage.delete_own_commit_intent(commit_id)?;
            if unapplied_existing_admin_grant {
                return Ok(Some(report(
                    SupersededIntentOutcome::Conflict,
                    "the requested members joined elsewhere; their admin grants require a new action",
                )));
            }
            return Ok(Some(report(
                SupersededIntentOutcome::AlreadySatisfied,
                "the requested members are already on the canonical branch",
            )));
        }
        if let Err(error) = crate::app_components::require_admin(
            &mls_group,
            &record.group_id,
            self.identity.self_id(),
        ) {
            if !matches!(error, EngineError::NotGroupAdmin { .. }) {
                return Err(error);
            }
            let report = report(
                SupersededIntentOutcome::Conflict,
                "the inviter no longer has permission to add members",
            );
            if let Some(retry) = &mut record.reinvite {
                retry.abandoned = true;
            }
            self.storage.put_own_commit_intent(&record)?;
            return Ok(Some(report));
        }
        let mut actual = std::collections::BTreeSet::new();
        for package in &key_packages {
            let metadata = crate::key_package::key_package_metadata(package)?;
            if consumed.contains(&metadata.key_package_ref_hex)
                || !actual.insert(metadata.credential_identity_hex)
            {
                return Err(EngineError::InvalidWelcome);
            }
        }
        if actual != expected {
            return Err(EngineError::InvalidWelcome);
        }
        let intent = SendIntent::Invite {
            group_id: record.group_id.clone(),
            key_packages,
            initial_admins: initial_admins
                .iter()
                .filter(|id| expected.contains(&hex::encode(id.as_slice())))
                .cloned()
                .collect(),
        };
        let queued = self.prepare_queued_outbound_intent(
            record.group_id.clone(),
            intent,
            record.reissue_attempts.saturating_add(1),
        )?;
        self.storage
            .with_transaction(|storage| -> Result<(), EngineError> {
                storage.put_queued_outbound_intent(&queued)?;
                storage.delete_own_commit_intent(commit_id)?;
                Ok(())
            })?;
        self.schedule_pending_convergence_group(&record.group_id);
        if unapplied_existing_admin_grant {
            return Ok(Some(report(
                SupersededIntentOutcome::Conflict,
                "missing members were queued for reinvitation; admin grants for existing members require a new action",
            )));
        }
        Ok(Some(report(
            SupersededIntentOutcome::Reissued,
            "a fresh invitation has been queued against canonical membership",
        )))
    }

    /// Retain the intent behind a commit this device just staged.
    pub(crate) fn record_own_commit_intent(
        &mut self,
        commit_id: MessageId,
        group_id: GroupId,
        source_epoch: cgka_traits::types::EpochId,
        intent: SendIntent,
        baseline: OwnCommitBaseline,
        reissue_attempts: u32,
    ) -> Result<(), EngineError> {
        let created_at_ms = self.convergence_now_ms();
        self.storage.put_own_commit_intent(&OwnCommitIntent {
            commit_id,
            group_id,
            source_epoch,
            intent,
            baseline,
            reinvite: None,
            reissue_attempts,
            created_at_ms,
        })?;
        Ok(())
    }
}
