//! Durable invitation recovery. Relay discovery stays in the app; the engine
//! validates identities and atomically transfers fresh intent into its queue.
use super::AppClient;
use super::history_recovery::history_notices::{GroupFacts, LiveFacts, RecoveryRead};
use crate::AppError;
use cgka_traits::engine::{
    SendIntent, SupersededIntentKind, SupersededIntentOutcome, SupersededIntentReport,
};
use cgka_traits::group::Group;
use cgka_traits::storage::OwnCommitIntent;
use cgka_traits::transport::Timestamp;
use cgka_traits::welcome::PendingWelcome;
use marmot_session::WallClockWindow;

use cgka_traits::storage::WelcomeStorage;
use cgka_traits::{GroupId, MessageId};
use std::collections::{HashMap, HashSet};

impl AppClient {
    /// Queue the host notification independently from the storage projection delta.
    pub(crate) fn mark_recovery_status_changed(&mut self, group_id: &GroupId) {
        self.mark_group_projection_dirty(group_id);
        if self.host_may_see_group(group_id) {
            self.history_recovery.note_recovery_status_update(group_id);
        }
    }

    /// Read only bounded offer metadata, without loading any MLS group.
    pub(crate) fn rejoin_offer_snapshot(&self) -> Result<HashMap<MessageId, GroupId>, AppError> {
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .list_welcomes()?
            .into_iter()
            .filter(|offer| offer.rejoin.is_some())
            .map(|offer| (offer.message_id, offer.group_id))
            .collect())
    }

    pub(crate) fn reconcile_rejoin_offer_changes(
        &mut self,
        before: HashMap<MessageId, GroupId>,
    ) -> Result<(), AppError> {
        let after = self.rejoin_offer_snapshot()?;
        let changed: HashSet<_> = before
            .iter()
            .chain(after.iter())
            .filter(|(id, _)| before.get(*id) != after.get(*id))
            .map(|(_, group)| group.clone())
            .collect();
        for group in changed {
            self.mark_recovery_status_changed(&group);
        }
        Ok(())
    }

    pub fn group_recovery_status(
        &self,
        group_id: &cgka_traits::GroupId,
    ) -> Result<crate::GroupRecoveryStatus, AppError> {
        let read = self.read_recovery()?;
        let group = self.runtime.group_record(group_id)?;
        let judged_at = crate::client::read_state::system_clock_now();
        self.group_recovery_status_in(group_id, &group, &read, &LiveFacts(self), None, judged_at)
            .map(|(status, _)| status)
    }

    /// The account's invitation-recovery rows, by group: one read of every
    /// stored re-join Welcome and every fresh-material reinvite record, for
    /// a publish that rebuilds many groups' recovery statuses (mdk#3273).
    pub(crate) fn invitation_rows(&self) -> Result<InvitationRows, AppError> {
        let mut rows = InvitationRows::default();
        for candidate in self.runtime.stored_rejoin_welcomes()? {
            rows.rejoins
                .entry(candidate.group_id.clone())
                .or_default()
                .push(candidate);
        }
        for record in self.runtime.reinvite_recovery_records()? {
            rows.reinvites
                .entry(record.group_id.clone())
                .or_default()
                .push(record);
        }
        Ok(rows)
    }

    /// [`Self::group_recovery_status`] from the group's engine record, a
    /// recovery read, and the group's facts the caller has: A builds a
    /// group's entry with the record and facts it holds (mdk#3273). `rows`
    /// are the account's invitation-recovery rows when the caller read them
    /// once for many groups; `None` reads this group's. KeyPackage lifetimes
    /// are judged against the system clock, which read `judged_at` before
    /// the call. The status comes with what keeping it rests on besides the
    /// group's change stamp.
    pub(crate) fn group_recovery_status_in(
        &self,
        group_id: &cgka_traits::GroupId,
        group: &Group,
        read: &RecoveryRead,
        facts: &dyn GroupFacts,
        rows: Option<&InvitationRows>,
        judged_at: Timestamp,
    ) -> Result<(crate::GroupRecoveryStatus, StatusInputs), AppError> {
        let candidates = match rows {
            Some(rows) => rows.rejoins.get(group_id).cloned().unwrap_or_default(),
            None => {
                let mut candidates = self.runtime.stored_rejoin_welcomes()?;
                candidates.retain(|candidate| &candidate.group_id == group_id);
                candidates
            }
        };
        let offers = self.runtime.rejoin_offers(candidates);
        let rejoin_invitations = offers
            .offers
            .into_iter()
            .filter_map(|candidate| {
                candidate.rejoin.map(|rejoin| crate::GroupRejoinInvitation {
                    welcome_id_hex: hex::encode(candidate.message_id.as_slice()),
                    welcomer_account_id_hex: hex::encode(rejoin.welcomer.as_slice()),
                    epoch: rejoin.epoch.0,
                    local_state_token: hex::encode(rejoin.local_state_token),
                })
            })
            .collect();
        let read_here;
        let records = match rows {
            Some(rows) => rows.reinvites.get(group_id).map_or(&[][..], Vec::as_slice),
            None => {
                read_here = self.runtime.reinvite_recovery_records()?;
                &read_here[..]
            }
        };
        let mut inputs = StatusInputs {
            reusable: offers.every_offer_read,
            key_packages: WallClockWindow {
                from: judged_at,
                until: None,
            },
        };
        let mut pending_reinvites = 0u32;
        let mut failed_reinvites = 0u32;
        for record in records.iter().filter(|record| &record.group_id == group_id) {
            if let SendIntent::Invite { key_packages, .. } = &record.intent {
                let mut missing = false;
                for package in key_packages {
                    let metadata = self
                        .runtime
                        .key_package_metadata(package)
                        .map_err(marmot_session::SessionError::from)?;
                    inputs.judged(metadata.not_before, metadata.not_after);
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
        let storage = self.app.account_storage(&self.state.label)?;
        let history_notice_ids = read.group_notice_ids(group_id, facts);
        let status = crate::GroupRecoveryStatus {
            pending_reinvites,
            failed_reinvites,
            group_id_hex: hex::encode(group_id.as_slice()),
            automatic_recovery_failed: !group.is_terminal()
                && (storage.app_storage().automatic_recovery_failed(group_id)?
                    || matches!(
                        self.runtime.group_rejoin_status(group_id)?,
                        marmot_session::GroupRejoinStatus::Parked { .. }
                    )),
            rejoin_invitations,
            history_may_be_incomplete: !history_notice_ids.is_empty(),
            history_notice_ids,
        };
        Ok((status, inputs))
    }

    pub async fn confirm_group_rejoin(
        &mut self,
        welcome_id: &cgka_traits::MessageId,
        token: &[u8],
    ) -> Result<crate::GroupRecoveryStatus, AppError> {
        // Rejoining unwraps the retained Welcome again. Keep block updates out
        // until both the native replacement and its app projection have settled.
        let policy_lock = self.app.block_update_lock(&self.state.label).await;
        let _policy_guard = policy_lock.lock().await;
        // A confirmation that fails can still retire offers: one whose
        // carriers were all withdrawn, or a Welcome it refuses.
        let offers = self.rejoin_offer_snapshot()?;
        let confirmed = self.runtime.confirm_group_rejoin(welcome_id, token).await;
        self.reconcile_rejoin_offer_changes(offers)?;
        let group_id = confirmed?;
        // GroupJoined is durably journaled by the engine, so a failed app
        // projection refresh is repaired by the ordinary reopen/drain path.
        let summary = self.drain_pending_session_events().await?;
        self.pending_applied_sync_summary.merge(summary);
        self.app
            .account_storage(&self.state.label)?
            .app_storage()
            .clear_recovery_failure(&group_id)?;
        self.mark_group_projection_dirty_hex(hex::encode(group_id.as_slice()));
        self.group_recovery_status(&group_id)
    }

    pub fn decline_group_rejoin(
        &mut self,
        welcome_id: &cgka_traits::MessageId,
    ) -> Result<(), AppError> {
        let candidate = self
            .app
            .account_storage(&self.state.label)?
            .list_welcomes()?
            .into_iter()
            .find(|candidate| &candidate.message_id == welcome_id && candidate.rejoin.is_some())
            .ok_or(AppError::Session(marmot_session::SessionError::Engine(
                cgka_traits::EngineError::InvalidWelcome,
            )))?;
        self.runtime.decline_group_rejoin(welcome_id)?;
        self.mark_recovery_status_changed(&candidate.group_id);
        Ok(())
    }

    pub(crate) fn observe_recovery_health(
        &mut self,
        effects: &marmot_session::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        for event in &effects.events {
            let group = match event {
                cgka_traits::engine::GroupEvent::GroupJoined { group_id, .. } => Some(group_id),
                // MLS never decrypts this device's own messages, so every received
                // message came from another leaf. One from a sibling device of this
                // account proves current-epoch health like any other member's.
                cgka_traits::engine::GroupEvent::MessageReceived {
                    group_id, epoch, ..
                } if self
                    .runtime
                    .group_record(group_id)
                    .is_ok_and(|group| group.epoch == *epoch) =>
                {
                    Some(group_id)
                }
                _ => None,
            };
            if let Some(group_id) = group {
                let changed = self
                    .app
                    .account_storage(&self.state.label)?
                    .app_storage()
                    .clear_recovery_failure(group_id)?;
                self.history_recovery.clear_recovered_group(group_id);
                if changed {
                    self.mark_recovery_status_changed(group_id);
                }
            }
        }
        Ok(())
    }

    /// Retry durable invitation and halted-copy work without replacing an
    /// already-observed maintenance or convergence result.
    pub(crate) async fn recover_superseded_invites_best_effort(&mut self) {
        if self.recover_superseded_invites().await.is_err() {
            tracing::warn!(
                target: "marmot_app::client",
                method = "recover_superseded_invites_best_effort",
                "invitation recovery failed; durable work remains pending"
            );
        }
        if self.advance_auto_recovery().await.is_err() {
            tracing::warn!(
                target: "marmot_app::client",
                method = "advance_auto_recovery",
                "automatic group recovery deferred; durable work remains pending"
            );
        }
    }

    /// Run one durable recovery turn under the ordinary account-worker owner.
    /// The runtime reserves bounded lookup work before any cancellable I/O and
    /// owns authentication, retry pacing, membership checks and publication.
    async fn advance_auto_recovery(&mut self) -> Result<(), AppError> {
        if self.runtime.maintenance_is_paused()
            || self.maintenance_passes()? != super::MaintenancePasses::Run
        {
            return Ok(());
        }
        self.app.ensure_storage_open("automatic group recovery")?;
        let mut before = Vec::new();
        for group_id in self.runtime.live_group_ids()? {
            if matches!(
                self.runtime.epoch_state(&group_id),
                Some(cgka_traits::EpochState::Unrecoverable { .. })
            ) {
                let parked = matches!(
                    self.runtime.group_rejoin_status(&group_id)?,
                    marmot_session::GroupRejoinStatus::Parked { .. }
                );
                before.push((group_id, parked));
            }
        }
        let peers = self.runtime.prepare_group_recovery();
        // Preparation can commit earlier groups before a later group fails.
        let mut status_changes = Ok(());
        for (group_id, parked) in before {
            let changed = match self.runtime.group_rejoin_status(&group_id) {
                Ok(status) => {
                    parked != matches!(status, marmot_session::GroupRejoinStatus::Parked { .. })
                }
                Err(error) => {
                    // A later snapshot cannot recover a missed refresh cue.
                    if status_changes.is_ok() {
                        status_changes = Err(error);
                    }
                    true
                }
            };
            if changed {
                self.mark_recovery_status_changed(&group_id);
            }
        }
        let peers = peers?;
        status_changes?;
        let directory = self.app.directory();
        for peer in peers {
            let member = hex::encode(peer.as_slice());
            // This resolver follows advertised outboxes and applies the same
            // host-safety policy as ordinary member discovery. A failed lookup
            // is not success: advance retains and paces the durable job.
            if directory
                .resolve_account_relay_list_status_for_account_id(
                    &member,
                    self.app.relay_endpoints(),
                )
                .await
                .is_err()
            {
                continue;
            }
            self.refresh_member_inbox_routes(std::iter::once(member.as_str()))?;
        }
        if self.runtime.maintenance_is_paused()
            || self.maintenance_passes()? != super::MaintenancePasses::Run
        {
            return Ok(());
        }
        self.app.ensure_storage_open("automatic group recovery")?;
        self.sync_key_package_announcement_group()?;
        self.sync_device_tag_group()?;
        let held = self.epoch_gap_held_groups()?;
        let mut effects = marmot_session::AccountDeviceEffects::default();
        let result = self
            .runtime
            .advance_group_recovery(&held, &mut effects)
            .await;
        if effects.events.is_empty()
            && effects.failed_app_messages.is_empty()
            && effects.published_app_messages.is_empty()
        {
            self.retain_applied_effects(&effects);
            return result.map_err(AppError::from);
        }
        // Reuse native maintenance projection, group-route refresh and buffered
        // summaries; control envelopes themselves never become chat entries.
        self.observe_native_membership_effects(&effects).await?;
        result?;
        Ok(())
    }

    pub(crate) fn retry_parked_rejoins(&mut self) -> Result<(), AppError> {
        for group_id in self.runtime.live_group_ids()? {
            if matches!(
                self.runtime.epoch_state(&group_id),
                Some(cgka_traits::EpochState::Unrecoverable { .. })
            ) && matches!(
                self.runtime.group_rejoin_status(&group_id)?,
                marmot_session::GroupRejoinStatus::Parked { .. }
            ) {
                self.runtime.retry_group_rejoin(&group_id)?;
                self.mark_recovery_status_changed(&group_id);
            }
        }
        Ok(())
    }

    pub(crate) async fn recover_superseded_invites(&mut self) -> Result<(), AppError> {
        if self.runtime.maintenance_is_paused()
            || self.maintenance_passes()? != super::MaintenancePasses::Run
        {
            return Ok(());
        }
        {
            // Normal inbox admission owns this lock itself; this separate retry
            // seam must hold it through projection without nesting that path.
            let policy_lock = self.app.block_update_lock(&self.state.label).await;
            let _policy_guard = policy_lock.lock().await;
            // The retry also retires offers it cannot join, which the host
            // shows until it is told.
            let offers = self.rejoin_offer_snapshot()?;
            let joined = self.runtime.retry_rejoins_after_trusted_removal().await;
            self.reconcile_rejoin_offer_changes(offers)?;
            if joined? {
                let summary = self.drain_pending_session_events().await?;
                self.pending_applied_sync_summary.merge(summary);
            }
        }
        let now_ms = super::sync::epoch_stall_now_ms();
        // One bounded lookup per seam; reserve before await so cancellations,
        // restarts and relay failures cannot spin or lose the original intent.
        for record in self.runtime.pending_reinvites()? {
            if record
                .reinvite
                .as_ref()
                .is_some_and(|retry| retry.next_attempt_at_ms > now_ms)
            {
                continue;
            }
            if !self.runtime.ensure_group_hydrated(&record.group_id)? {
                continue;
            }
            if !self
                .runtime
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
                Err(error)
                    if matches!(
                        error.as_engine_error(),
                        Some(cgka_traits::EngineError::Storage(
                            cgka_traits::storage::StorageError::NotFound
                        ))
                    ) =>
                {
                    None
                }
                Err(error) => return Err(error.into()),
            };
            // Only accounts with no device on the canonical roster are looked
            // up again. A lost device of an account still in the group, or one
            // left out below, is reported by the engine as needing a new
            // invite (mdk#2628, D13).
            let mut members = Vec::new();
            for package in key_packages {
                let metadata = self
                    .runtime
                    .key_package_metadata(package)
                    .map_err(marmot_session::SessionError::from)?;
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
                    let requirements = match self
                        .runtime
                        .invite_key_package_requirements(&record.group_id)
                    {
                        Ok(requirements) => requirements,
                        Err(error @ cgka_traits::EngineError::Storage(_)) => {
                            return Err(marmot_session::SessionError::from(error).into());
                        }
                        Err(_) => break,
                    };
                    let resolution =
                        self.lane_step(crate::RuntimePerformanceOperation::KeyPackageResolution);
                    let resolved = self
                        .app
                        .directory()
                        .resolve_compatible_member_key_packages(
                            members,
                            &requirements,
                            nostr_directory::MemberResolutionPurpose::CommitFresh,
                            nostr_directory::MemberResolutionPolicy::Atomic,
                        )
                        .await;
                    resolution.finish(&resolved);
                    let resolved = match resolved {
                        Ok(resolved) => {
                            self.record_key_package_read_coverage(resolved.stats.key_package_reads);
                            resolved.key_packages
                        }
                        Err(_) => break,
                    };
                    let refs = |package: &cgka_traits::engine::KeyPackage| {
                        self.runtime
                            .key_package_metadata(package)
                            .map(|metadata| {
                                (
                                    metadata.credential_identity_hex,
                                    metadata.key_package_ref_hex,
                                )
                            })
                            .map_err(marmot_session::SessionError::from)
                    };
                    let consumed = key_packages
                        .iter()
                        .map(|package| refs(package).map(|(_, reference)| reference))
                        .collect::<Result<HashSet<_>, _>>()?;
                    let mut tagged = Vec::with_capacity(resolved.len());
                    for package in resolved {
                        let (account, reference) = refs(&package)?;
                        tagged.push((account, consumed.contains(&reference), package));
                    }
                    without_consumed_packages(tagged)
                };
            match self
                .runtime
                .reissue_invite_with_key_packages(&record.commit_id, packages)
            {
                Ok(Some(report)) => {
                    self.mark_group_projection_dirty_hex(hex::encode(record.group_id.as_slice()));
                    self.pending_convergence_groups.insert(record.group_id);
                    self.pending_superseded_change_events.push(report);
                }
                Ok(None) => {}
                Err(error)
                    if matches!(
                        error.as_engine_error(),
                        cgka_traits::EngineError::Storage(_)
                    ) =>
                {
                    return Err(error.into());
                }
                Err(_) => {
                    tracing::debug!(target: "marmot_app::client", method = "recover_superseded_invites",
                        "fresh invitation recovery remains pending");
                }
            }
            break;
        }
        Ok(())
    }
}

/// The lost invite consumed its packages, and the engine refuses to reissue
/// one. A device that has not replaced its consumed package sits the reissue
/// out while another device of its account can join, and the engine reports
/// that device as needing a new invite. An account left with
/// only consumed packages keeps them, so the reissue waits for a replacement
/// as it does for a single-device account.
fn without_consumed_packages<T>(packages: Vec<(String, bool, T)>) -> Vec<T> {
    let joinable = packages
        .iter()
        .filter(|(_, consumed, _)| !consumed)
        .map(|(account, _, _)| account.clone())
        .collect::<HashSet<_>>();
    packages
        .into_iter()
        .filter(|(account, consumed, _)| !consumed || !joinable.contains(account))
        .map(|(_, _, package)| package)
        .collect()
}

/// The account's invitation-recovery rows by group ([`AppClient::invitation_rows`]).
#[derive(Default)]
pub(crate) struct InvitationRows {
    rejoins: HashMap<GroupId, Vec<PendingWelcome>>,
    reinvites: HashMap<GroupId, Vec<OwnCommitIntent>>,
}

/// What keeping a group's recovery status rests on besides its group's
/// change stamp (mdk#3273).
#[derive(Clone, Debug)]
pub(crate) struct StatusInputs {
    /// False when the read left out something that can come back with no
    /// write: a re-join offer whose group's MLS state failed to load on a
    /// failure that can clear, or a KeyPackage lifetime the clock crossed
    /// between the reading and OpenMLS's own check.
    pub(crate) reusable: bool,
    /// The system-clock window the KeyPackage lifetimes judged leave the
    /// status in: from the reading they were judged against until the first
    /// `not_after` ahead. A KeyPackage past it fails the status.
    pub(crate) key_packages: WallClockWindow,
}

impl StatusInputs {
    /// Note a KeyPackage OpenMLS accepted, so valid at its own check, with
    /// lifetime `not_before..not_after` (OpenMLS's rule: valid from
    /// `not_before` until before `not_after`).
    fn judged(&mut self, not_before: u64, not_after: u64) {
        let at = self.key_packages.from.0;
        if at < not_before || at >= not_after {
            // The clock crossed a bound between the reading and the check.
            self.reusable = false;
        }
        self.key_packages.until = self
            .key_packages
            .until
            .into_iter()
            .chain([Timestamp(not_after)])
            .min();
    }
}

#[cfg(test)]
mod tests {
    use super::{StatusInputs, without_consumed_packages};
    use cgka_traits::transport::Timestamp;
    use marmot_session::WallClockWindow;

    /// The KeyPackages a status judged bound it until the first `not_after`
    /// ahead of the reading. One OpenMLS accepted on the other side of a
    /// bound from that reading means the clock moved between the two, and
    /// the status is not kept.
    #[test]
    fn judged_key_packages_bound_the_status_and_a_crossed_bound_ends_its_reuse() {
        let at = |reading| StatusInputs {
            reusable: true,
            key_packages: WallClockWindow {
                from: Timestamp(reading),
                until: None,
            },
        };
        let mut inputs = at(100);
        inputs.judged(50, 200);
        inputs.judged(90, 150);
        assert!(inputs.reusable);
        assert_eq!(inputs.key_packages.until, Some(Timestamp(150)));

        for (not_before, not_after) in [(101, 200), (50, 100)] {
            let mut inputs = at(100);
            inputs.judged(not_before, not_after);
            assert!(
                !inputs.reusable,
                "accepted at {not_before}..{not_after}, outside the reading"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn partial_prepare_keeps_notice() {
        use crate::tests::ScriptedPushRelayClient;
        use crate::{AccountHome, MarmotApp};
        use cgka_traits::storage::GroupStorage;
        use std::sync::Arc;
        use storage_sqlite::{GroupRecoveryPhase, GroupRecoveryRole};

        const SPENT_ATTEMPTS: u32 = 32;

        for fail_status_read in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            AccountHome::open(dir.path())
                .create_account("alice")
                .unwrap();
            let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
                .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
            let mut client = app.client("alice").await.unwrap();
            let mut groups = [
                client
                    .create_group("first", &[])
                    .await
                    .unwrap()
                    .operation
                    .expect("eligible fixture members"),
                client
                    .create_group("second", &[])
                    .await
                    .unwrap()
                    .operation
                    .expect("eligible fixture members"),
            ];
            groups.sort_by(|left, right| left.as_slice().cmp(right.as_slice()));
            drop(client);

            let storage = app.account_storage("alice").unwrap();
            for group in &groups {
                let mut halted = storage.get_group(group).unwrap();
                halted.unrecoverable = true;
                storage.put_group(&halted).unwrap();
            }
            let mut client = app.client("alice").await.unwrap();
            for group in &groups {
                client.runtime.retry_group_rejoin(group).unwrap();
            }
            let mut records = storage.list_group_recoveries().unwrap();
            for record in &mut records {
                assert_eq!(record.role, GroupRecoveryRole::Recipient);
                record.total_attempts = SPENT_ATTEMPTS;
                record.expires_at = 0;
                record.message.expires_at = 0;
                storage.put_group_recovery(record).unwrap();
            }
            client
                .history_recovery
                .test_state()
                .pending_recovery_status_updates
                .clear();

            let path = app.account_storage_path("alice");
            let keys = app.account_home().load_signing_keys("alice").unwrap();
            let key = app
                .sqlcipher_key("alice", &keys, &path, crate::SqlcipherDatabaseKind::Session)
                .unwrap();
            storage_sqlite::expect_uncounted_writes_for_test(&path);
            let connection = rusqlite::Connection::open(path).unwrap();
            storage_sqlite::open_hardened_sqlcipher(
                &connection,
                &key,
                storage_sqlite::SqlCipherHardening::cipher_only(),
            )
            .unwrap();
            connection
                .execute_batch(&format!(
                    "CREATE TRIGGER fail_second_prepare BEFORE INSERT ON cgka_group_rejoin
             WHEN NEW.group_id = x'{}'
             BEGIN SELECT RAISE(FAIL, 'injected second preparation failure'); END;",
                    hex::encode(groups[1].as_slice()),
                ))
                .unwrap();
            if fail_status_read {
                connection
                    .execute_batch(&format!(
                        "CREATE TRIGGER fail_status_read AFTER UPDATE ON cgka_group_rejoin
                 WHEN NEW.group_id = x'{}' AND NEW.role = 0
                 BEGIN INSERT INTO cgka_group_rejoin (group_id, role, request_id, record)
                 VALUES (NEW.group_id, 1, zeroblob(32), x'00'); END;",
                        hex::encode(groups[0].as_slice()),
                    ))
                    .unwrap();
            }

            let error = client.advance_auto_recovery().await.unwrap_err();
            assert!(
                matches!(
                    error.as_engine_error(),
                    Some(cgka_traits::EngineError::Storage(cgka_traits::storage::StorageError::Backend(message)))
                        if message.contains("injected second preparation failure")
                ),
                "preparation failure remains authoritative: {error:?}"
            );
            if fail_status_read {
                assert!(matches!(
                    storage.list_group_recoveries(),
                    Err(cgka_traits::storage::StorageError::Serialization(_))
                ));
                connection
                    .execute("DELETE FROM cgka_group_rejoin WHERE role = 1", [])
                    .unwrap();
            }
            let after = storage.list_group_recoveries().unwrap();
            assert_eq!(after[0].phase, GroupRecoveryPhase::Parked);
            assert_eq!(after[1].phase, records[1].phase);
            assert_eq!(after[0].total_attempts, SPENT_ATTEMPTS);
            assert_eq!(after[1].total_attempts, SPENT_ATTEMPTS);
            assert!(
                client
                    .group_recovery_status(&groups[0])
                    .unwrap()
                    .automatic_recovery_failed
            );
            assert!(
                !client
                    .group_recovery_status(&groups[1])
                    .unwrap()
                    .automatic_recovery_failed
            );
            let notified = if fail_status_read {
                &groups[..]
            } else {
                &groups[..1]
            };
            assert_eq!(
                client
                    .history_recovery
                    .test_state()
                    .pending_recovery_status_updates,
                notified.iter().cloned().collect()
            );
        }
    }

    #[test]
    fn a_device_with_a_consumed_package_sits_out_while_its_account_can_join() {
        let package = |account: &str, consumed, name| (account.to_owned(), consumed, name);
        assert_eq!(
            without_consumed_packages(vec![
                package("bob", false, "bob laptop"),
                package("bob", true, "bob phone"),
                package("carol", true, "carol phone"),
                package("dave", false, "dave phone"),
            ]),
            vec!["bob laptop", "carol phone", "dave phone"]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unfinished_interactive_onboarding_defers_recipient_challenge_key_package_publication()
    {
        use crate::tests::ScriptedPushRelayClient;
        use crate::{AccountHome, MarmotApp};
        use cgka_traits::group_recovery::{GroupRecoveryBody, GroupRecoverySource};
        use cgka_traits::storage::GroupStorage;
        use std::sync::Arc;
        use storage_sqlite::{GroupRecoveryPhase, GroupRecoveryRole};

        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("alice").await.unwrap();
        let group = client
            .create_group("recovery-deferral", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        drop(client);

        let storage = app.account_storage("alice").unwrap();
        let mut halted = storage.get_group(&group).unwrap();
        halted.unrecoverable = true;
        storage.put_group(&halted).unwrap();

        let mut client = app.client("alice").await.unwrap();
        client.runtime.retry_group_rejoin(&group).unwrap();
        let mut record = storage.list_group_recoveries().unwrap().pop().unwrap();
        assert_eq!(record.role, GroupRecoveryRole::Recipient);
        let GroupRecoveryBody::Request { device_key_hash } = record.message.body else {
            panic!("expected initial recipient Request body");
        };
        record.phase = GroupRecoveryPhase::Challenge;
        record.retry_at = 0;
        record.expires_at = u64::MAX / 2;
        record.message.expires_at = u64::MAX / 2;
        record.message.body = GroupRecoveryBody::Challenge {
            source: GroupRecoverySource {
                epoch: halted.epoch,
                epoch_authenticator_hash: [7u8; 32],
                leaf_index: 0,
                leaf_hash: [8u8; 32],
                device_key_hash,
                coordinator_key_hash: [10u8; 32],
            },
        };
        storage.put_group_recovery(&record).unwrap();

        // Mark interactive onboarding unfinished: neither advance_auto_recovery nor
        // run_due_maintenance may publish a KeyPackage for the Challenge.
        home.begin_account_setup_with(
            &account,
            false,
            marmot_account::AccountSetupKind::InteractiveIdentity,
            marmot_account::AccountSetupPhase::KeyPackagePublicationStarted,
        )
        .unwrap();
        let before_events = relay.published_event_ids().len();
        let before_kp = client
            .runtime
            .key_package_maintenance_status()
            .unwrap()
            .and_then(|s| s.authored_event_id);

        client.advance_auto_recovery().await.unwrap();
        let after_auto_recovery = storage.list_group_recoveries().unwrap();
        assert_eq!(after_auto_recovery[0].phase, GroupRecoveryPhase::Challenge);
        assert_eq!(relay.published_event_ids().len(), before_events);
        assert_eq!(
            client
                .runtime
                .key_package_maintenance_status()
                .unwrap()
                .and_then(|s| s.authored_event_id),
            before_kp
        );

        // Once interactive onboarding completes, recovery proceeds and publishes.
        home.complete_account_setup("alice").unwrap();
        client.advance_auto_recovery().await.unwrap();
        assert_ne!(
            client
                .runtime
                .key_package_maintenance_status()
                .unwrap()
                .and_then(|s| s.authored_event_id),
            before_kp
        );
        assert!(relay.published_event_ids().len() > before_events);
    }
}
