use cgka_traits::{GroupId, TransportEndpoint};
use futures::{StreamExt, stream::FuturesUnordered};
use std::collections::HashSet;

use crate::AppError;
use crate::messages::AppMessageIntent;
use crate::notifications;

use super::AppClient;

mod announce;
mod repair;
#[cfg(test)]
mod tests;

use announce::PushShareForm;
pub(crate) use announce::{AcceptedPushAnnounce, PushAnnounceTiming, PushFetchClock};
pub(crate) use repair::PushRepairs;

const PUSH_PUBLISH_CONCURRENCY: usize = 4;

/// The group a merged Commit may have grown: a member add, or a Commit that
/// branch selection re-adopted after withdrawing it. Either way a member may
/// now hold no record of this device's token.
///
/// The re-share is edge-triggered from these in-memory engine events. A crash
/// or a failed queue write at a narrow moment loses it, and the new member
/// then misses this token as before mdk#2604; token requests (mdk#2611) are
/// what repair that. `MemberAdded` is per account, so a new device of an
/// existing member never triggers it.
pub(crate) fn member_add_group(event: &cgka_traits::engine::GroupEvent) -> Option<&GroupId> {
    match event {
        cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id,
            change: cgka_traits::engine::GroupStateChange::MemberAdded { .. },
            ..
        }
        | cgka_traits::engine::GroupEvent::GroupStateRevalidated { group_id, .. } => Some(group_id),
        _ => None,
    }
}

/// A merged Commit by this account that added a member: its group and the
/// epoch it started from. This device then owes the group a push snapshot.
///
/// `actor` names an account, not a device, so once an account has several
/// devices, each of them sends a snapshot after any one of them adds a member.
fn own_member_add<'a>(
    event: &'a cgka_traits::engine::GroupEvent,
    self_id: &cgka_traits::MemberId,
) -> Option<(&'a GroupId, u64)> {
    match event {
        cgka_traits::engine::GroupEvent::GroupStateChanged {
            group_id,
            epoch,
            actor: Some(actor),
            change: cgka_traits::engine::GroupStateChange::MemberAdded { .. },
            ..
        } if actor == self_id => Some((group_id, epoch.0.saturating_sub(1))),
        _ => None,
    }
}

/// The owed push snapshot one leaf-adding Commit recorded, and what to put back
/// if that Commit never merges.
pub(crate) struct RecordedPushSnapshot {
    group_id_hex: String,
    previous: Option<u64>,
    recorded: u64,
}

/// What one owed push snapshot or announce needs now.
enum PushGossipGate {
    /// Send it: the group can take messages, and a snapshot's adding Commit
    /// has merged.
    Due,
    /// The Commit has not merged, or the group cannot take messages yet.
    NotYet,
    /// The group ended: nobody is left to send it to.
    Void,
}

impl AppClient {
    pub(crate) async fn upsert_and_share_push_registration(
        &mut self,
        platform: notifications::PushPlatform,
        raw_token: &str,
        server_pubkey_hex: &str,
        relay_hint: Option<String>,
    ) -> Result<notifications::PushRegistrationSyncResult, AppError> {
        let observation = self.app.product_analytics.begin(
            crate::ProductFamily::Notification,
            "register",
            crate::ProductUnit::Action,
        );
        let result = Box::pin(self.upsert_and_share_push_registration_unobserved(
            platform,
            raw_token,
            server_pubkey_hex,
            relay_hint,
        ))
        .await;
        if let Some(observation) = observation {
            observation.finish(if result.is_ok() { "success" } else { "failure" });
        }
        result
    }

    async fn upsert_and_share_push_registration_unobserved(
        &mut self,
        platform: notifications::PushPlatform,
        raw_token: &str,
        server_pubkey_hex: &str,
        relay_hint: Option<String>,
    ) -> Result<notifications::PushRegistrationSyncResult, AppError> {
        let registration = self.app.upsert_push_registration(
            &self.state.label,
            platform,
            raw_token,
            server_pubkey_hex,
            relay_hint,
        )?;
        let share = self.share_push_registration().await?;
        Ok(notifications::PushRegistrationSyncResult {
            registration,
            share,
        })
    }

    pub(crate) async fn share_push_registration(
        &mut self,
    ) -> Result<notifications::PushRegistrationShareOutcome, AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let settings = self.app.notification_settings(&account.label)?;
        let registration = self.app.stored_push_registration(&account.label)?;
        let pending_removals = self
            .app
            .pending_push_registration_removals(&account.label)?;
        if registration.is_none() && pending_removals.is_empty() {
            return Ok(notifications::PushRegistrationShareOutcome::from_counts(
                0, 0, 0, 0,
            ));
        }
        let signer = self.app.account_signer_for_summary(&account)?;
        let nostr_signer = signer.as_nostr_signer();
        let mut attempted_groups = HashSet::new();

        for (group_id_hex, retired_registration) in pending_removals {
            attempted_groups.insert(group_id_hex.clone());
            self.app.mark_push_registration_removal_attempted(
                &account.label,
                &group_id_hex,
                &retired_registration,
                notifications::unix_now_ms(),
            )?;
            let Ok(group_id_bytes) = hex::decode(&group_id_hex) else {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "share_push_registration",
                    skipped_groups = 1_u64,
                    "push token removal skipped because its group id is invalid",
                );
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            let Ok((member_id_hex, leaf_index)) = self.local_member_leaf(&group_id) else {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "share_push_registration",
                    skipped_groups = 1_u64,
                    "push token removal skipped because the local member leaf is unavailable",
                );
                continue;
            };
            let payload_and_record = notifications::local_token_removal_payload(
                &group_id_hex,
                member_id_hex,
                leaf_index,
                &retired_registration,
                nostr_signer.as_ref(),
            )
            .await;
            let (payload, removal_record) = match payload_and_record {
                Ok(value) => value,
                Err(err) => {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "share_push_registration",
                        error_kind = err.privacy_safe_kind(),
                        "push token removal gossip preparation failed",
                    );
                    continue;
                }
            };
            let content = match serde_json::to_string(&payload) {
                Ok(content) => content,
                Err(err) => {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "share_push_registration",
                        error_kind = AppError::from(err).privacy_safe_kind(),
                        "push token removal gossip serialization failed",
                    );
                    continue;
                }
            };
            match self
                .send_app_event(&group_id, AppMessageIntent::PushTokenRemoval { content })
                .await
            {
                Ok((_event, summary))
                    if summary.accept_disposition
                        == cgka_traits::SendAcceptDisposition::Published =>
                {
                    if let Err(err) = self.app.apply_local_push_removal(
                        &account.label,
                        &group_id_hex,
                        &removal_record,
                    ) {
                        tracing::warn!(
                            target: "marmot_app::notifications",
                            method = "share_push_registration",
                            error_kind = err.privacy_safe_kind(),
                            "push token removal local projection failed",
                        );
                        continue;
                    }
                    let _ = self.app.complete_push_registration_removal(
                        &account.label,
                        &group_id_hex,
                        &retired_registration,
                    )?;
                }
                Ok((_event, _summary)) => {
                    tracing::debug!(
                        target: "marmot_app::notifications",
                        method = "share_push_registration",
                        "push token removal remains durable while publication is unresolved",
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "share_push_registration",
                        error_kind = err.privacy_safe_kind(),
                        "push token removal gossip publish failed",
                    );
                }
            }
        }

        let mut pending_share_groups = Vec::new();
        if settings.native_push_enabled
            && let Some(registration) = &registration
        {
            pending_share_groups = self.app.pending_push_registration_shares(
                &account.label,
                &registration.registration.token_fingerprint,
                registration.registration.updated_at_ms,
            )?;
            for group_id_hex in &pending_share_groups {
                attempted_groups.insert(group_id_hex.clone());
                self.app.mark_push_registration_share_attempted(
                    &account.label,
                    group_id_hex,
                    &registration.registration.token_fingerprint,
                    registration.registration.updated_at_ms,
                    notifications::unix_now_ms(),
                )?;
                let Ok(group_id_bytes) = hex::decode(group_id_hex) else {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "share_push_registration",
                        skipped_groups = 1_u64,
                        "push token update skipped because its group id is invalid",
                    );
                    continue;
                };
                let group_id = GroupId::new(group_id_bytes);
                let Ok((member_id_hex, leaf_index)) = self.local_member_leaf(&group_id) else {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "share_push_registration",
                        skipped_groups = 1_u64,
                        "push token update skipped because the local member leaf is unavailable",
                    );
                    continue;
                };
                let payload_and_record = notifications::local_token_gossip_payload(
                    group_id_hex.clone(),
                    member_id_hex,
                    leaf_index,
                    registration,
                    nostr_signer.as_ref(),
                )
                .await;
                let (payload, record) = match payload_and_record {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::warn!(
                            target: "marmot_app::notifications",
                            method = "share_push_registration",
                            error_kind = err.privacy_safe_kind(),
                            "push token gossip preparation failed",
                        );
                        continue;
                    }
                };
                let form = self.push_share_form(&group_id, &record);
                let content = match form {
                    PushShareForm::Defer => {
                        tracing::debug!(
                            target: "marmot_app::notifications",
                            method = "share_push_registration",
                            skipped_groups = 1_u64,
                            "push token update waits until its owed announce is recorded",
                        );
                        continue;
                    }
                    PushShareForm::Announce { .. } => {
                        self.build_push_announce(&group_id, std::slice::from_ref(&record))
                    }
                    PushShareForm::Plain => serde_json::to_string(&payload).map_err(AppError::from),
                };
                let content = match content {
                    Ok(content) => content,
                    Err(err) => {
                        tracing::warn!(
                            target: "marmot_app::notifications",
                            method = "share_push_registration",
                            error_kind = err.privacy_safe_kind(),
                            "push token gossip serialization failed",
                        );
                        continue;
                    }
                };
                match self
                    .send_app_event(&group_id, AppMessageIntent::PushTokenUpdate { content })
                    .await
                {
                    Ok((_event, summary))
                        if summary.accept_disposition
                            == cgka_traits::SendAcceptDisposition::Published =>
                    {
                        if let PushShareForm::Announce { settles_owed } = form {
                            self.record_push_announce(&group_id, Some(settles_owed));
                        }
                        if let Err(err) = self.app.upsert_group_push_token(&account.label, &record)
                        {
                            tracing::warn!(
                                target: "marmot_app::notifications",
                                method = "share_push_registration",
                                error_kind = err.privacy_safe_kind(),
                                "push token local projection failed",
                            );
                            continue;
                        }
                        let _ = self.app.complete_push_registration_share(
                            &account.label,
                            group_id_hex,
                            &registration.registration.token_fingerprint,
                            registration.registration.updated_at_ms,
                        )?;
                    }
                    Ok((event, _summary)) => {
                        if let PushShareForm::Announce { settles_owed } = form {
                            self.note_push_announce_left_in_outbox(
                                &group_id,
                                event.id,
                                Some(settles_owed),
                            );
                        }
                        tracing::debug!(
                            target: "marmot_app::notifications",
                            method = "share_push_registration",
                            "push token update remains durable while publication is unresolved",
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            target: "marmot_app::notifications",
                            method = "share_push_registration",
                            error_kind = err.privacy_safe_kind(),
                            "push token gossip publish failed",
                        );
                    }
                }
            }
        }

        let remaining_share_groups = if let Some(registration) = &registration {
            self.app.pending_push_registration_shares(
                &account.label,
                &registration.registration.token_fingerprint,
                registration.registration.updated_at_ms,
            )?
        } else {
            Vec::new()
        };
        if remaining_share_groups.is_empty()
            && !pending_share_groups.is_empty()
            && let Some(registration) = &registration
        {
            let _ = self.app.mark_push_registration_shared(
                &account.label,
                &registration.registration.token_fingerprint,
                registration.registration.updated_at_ms,
                notifications::unix_now_ms(),
            )?;
        }
        let remaining_removal_groups = self
            .app
            .pending_push_registration_removals(&account.label)?
            .into_iter()
            .map(|(group_id_hex, _)| group_id_hex);
        let pending_groups = remaining_share_groups
            .into_iter()
            .chain(remaining_removal_groups)
            .collect::<HashSet<_>>();
        let failed_groups = attempted_groups.intersection(&pending_groups).count();
        let succeeded_groups = attempted_groups.len().saturating_sub(failed_groups);
        Ok(notifications::PushRegistrationShareOutcome::from_counts(
            attempted_groups.len(),
            succeeded_groups,
            failed_groups,
            pending_groups.len(),
        ))
    }

    pub(crate) async fn retry_pending_push_registration_shares_best_effort(&mut self) -> bool {
        let snapshots_pending = self.send_owed_push_snapshots().await;
        let shares_pending = self.retry_pending_push_registration_shares().await;
        // After the shares: one sent after a join window ends is the announce.
        let announces_pending = self.send_due_push_announces().await;
        // After the announces, which look at the fetch clock first. A repair
        // reply is not an announce and settles no announce owed.
        let repairs_pending = self.send_due_push_repairs().await;
        snapshots_pending || shares_pending || announces_pending || repairs_pending
    }

    async fn retry_pending_push_registration_shares(&mut self) -> bool {
        match self.share_push_registration().await {
            Ok(outcome) if outcome.failed_groups > 0 => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "retry_pending_push_registration_shares_best_effort",
                    attempted_groups = outcome.attempted_groups,
                    succeeded_groups = outcome.succeeded_groups,
                    failed_groups = outcome.failed_groups,
                    pending_groups = outcome.pending_groups,
                    "push token gossip remains pending",
                );
                outcome.pending_groups > 0
            }
            Ok(outcome) => outcome.pending_groups > 0,
            Err(err) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "retry_pending_push_registration_shares_best_effort",
                    error_kind = err.privacy_safe_kind(),
                    "push token gossip retry failed",
                );
                true
            }
        }
    }

    pub(crate) fn has_pending_push_registration_work(&self) -> bool {
        match self
            .app
            .has_pending_push_registration_work(&self.state.label)
        {
            Ok(pending) => {
                pending
                    || self.has_due_push_snapshot()
                    || self.has_due_push_announce()
                    || self.has_due_push_repair()
            }
            Err(err) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "has_pending_push_registration_work",
                    error_kind = err.privacy_safe_kind(),
                    "push token gossip pending-state read failed",
                );
                true
            }
        }
    }

    /// A merged Commit added a member, who cannot read this device's earlier
    /// shares: queue the current registration for the group again. One queue
    /// row per group absorbs every add in a batch.
    pub(crate) fn queue_push_registration_share_after_member_added(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), AppError> {
        if self
            .runtime
            .leave_in_progress(group_id)
            .map_err(marmot_session::SessionError::from)?
        {
            return Ok(());
        }
        let queued = self.app.queue_current_push_registration_share_for_group(
            &self.state.label,
            &hex::encode(group_id.as_slice()),
        )?;
        if queued {
            self.push_registration_share_queued = true;
            tracing::debug!(
                target: "marmot_app::notifications",
                method = "queue_push_registration_share_after_member_added",
                queued_groups = 1_u64,
                "push token share queued for a member add",
            );
        }
        Ok(())
    }

    /// Queue one share per group that `events` may have grown. A
    /// group whose queue write fails is kept for the account worker to retry.
    pub(crate) fn queue_push_registration_shares_for_member_adds(
        &mut self,
        events: &[cgka_traits::engine::GroupEvent],
    ) {
        for event in events {
            if let Some(group_id) = member_add_group(event) {
                self.pending_member_add_push_shares.insert(group_id.clone());
            }
            self.note_own_member_add(event);
        }
        self.retry_pending_member_add_push_shares();
    }

    /// Record the snapshots owed for own member adds whose earlier write
    /// failed.
    fn retry_pending_own_add_push_snapshots(&mut self) {
        let snapshots: Vec<_> = self
            .pending_own_add_push_snapshots
            .iter()
            .map(|(group_id, after_epoch)| (group_id.clone(), *after_epoch))
            .collect();
        for (group_id, after_epoch) in snapshots {
            match self.app.record_group_push_snapshot_owed(
                &self.state.label,
                &hex::encode(group_id.as_slice()),
                after_epoch,
            ) {
                Ok(recorded) => {
                    self.pending_own_add_push_snapshots.remove(&group_id);
                    self.push_registration_share_queued |= recorded;
                }
                Err(error) => tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "retry_pending_own_add_push_snapshots",
                    error_kind = error.privacy_safe_kind(),
                    "push snapshot owed after a member add was not recorded"
                ),
            }
        }
    }

    /// Queue the shares owed for member adds whose earlier queue write failed,
    /// and record the snapshots owed for own adds whose earlier write failed.
    pub(crate) fn retry_pending_member_add_push_shares(&mut self) {
        self.retry_pending_own_add_push_snapshots();
        let groups: Vec<_> = self
            .pending_member_add_push_shares
            .iter()
            .cloned()
            .collect();
        for group_id in groups {
            match self.queue_push_registration_share_after_member_added(&group_id) {
                Ok(()) => {
                    self.pending_member_add_push_shares.remove(&group_id);
                }
                Err(error) => tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "retry_pending_member_add_push_shares",
                    error_kind = error.privacy_safe_kind(),
                    "push token share after a member add was not queued"
                ),
            }
        }
    }

    /// Whether a member add queued a share or owed a snapshot since the last
    /// call.
    pub(crate) fn take_queued_push_registration_share(&mut self) -> bool {
        std::mem::take(&mut self.push_registration_share_queued)
    }

    /// Record that `event`, if it is a merged Commit by this account adding a
    /// member, owes the group a push snapshot. The invite command recorded it
    /// before staging or queueing the Commit; this records the epoch the
    /// Commit started from, which a queued invite cannot know in advance, and
    /// wakes the account worker to send it. A failed write is retried with
    /// the member-add shares.
    pub(crate) fn note_own_member_add(&mut self, event: &cgka_traits::engine::GroupEvent) {
        if let Some((group_id, after_epoch)) = own_member_add(event, &self.runtime.self_id()) {
            let owed = self
                .pending_own_add_push_snapshots
                .entry(group_id.clone())
                .or_insert(after_epoch);
            *owed = (*owed).max(after_epoch);
            self.retry_pending_own_add_push_snapshots();
        }
    }

    /// Record, before a Commit that adds leaves is published from
    /// `source_epoch`, that this device owes the group a push snapshot once the
    /// Commit merges.
    pub(crate) fn record_push_snapshot_owed(
        &self,
        group_id: &GroupId,
        source_epoch: u64,
    ) -> Result<RecordedPushSnapshot, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let previous = self
            .app
            .group_push_snapshot_owed(&self.state.label, &group_id_hex)?;
        let recorded = previous.map_or(source_epoch, |previous| previous.max(source_epoch));
        self.app
            .record_group_push_snapshot_owed(&self.state.label, &group_id_hex, source_epoch)?;
        Ok(RecordedPushSnapshot {
            group_id_hex,
            previous,
            recorded,
        })
    }

    /// Put back the owed snapshot that `snapshot` replaced: its Commit will
    /// never merge. Best effort, since a snapshot that stays owed is sent once
    /// the group's epoch next passes, to members who already hold it.
    pub(crate) fn restore_push_snapshot_owed(&self, snapshot: RecordedPushSnapshot) {
        if snapshot.previous == Some(snapshot.recorded) {
            return;
        }
        if let Err(error) = self.app.replace_group_push_snapshot_owed(
            &self.state.label,
            &snapshot.group_id_hex,
            snapshot.recorded,
            snapshot.previous,
        ) {
            tracing::warn!(
                target: "marmot_app::notifications",
                method = "restore_push_snapshot_owed",
                error_kind = error.privacy_safe_kind(),
                "owed push snapshot of an unmerged commit was not restored"
            );
        }
    }

    /// Whether a snapshot this device owes can be sent now.
    pub(crate) fn has_due_push_snapshot(&self) -> bool {
        match self.app.owed_group_push_snapshots(&self.state.label) {
            Ok(owed) => owed.into_iter().any(|(group_id_hex, after_epoch)| {
                !matches!(
                    self.push_gossip_gate(&group_id_hex, Some(after_epoch)),
                    PushGossipGate::NotYet
                )
            }),
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "has_due_push_snapshot",
                    error_kind = error.privacy_safe_kind(),
                    "owed push snapshot read failed",
                );
                true
            }
        }
    }

    /// Whether `group_id_hex` can take push gossip now, and for an owed
    /// snapshot, whether the group's merged epoch has passed `after_epoch`.
    ///
    /// Leaving the group, or losing membership, deletes its owed snapshot and
    /// join window with the rest of its gossip state, so a row here belongs to
    /// a group this device is still in, though perhaps not hydrated yet.
    fn push_gossip_gate(&self, group_id_hex: &str, after_epoch: Option<u64>) -> PushGossipGate {
        let Ok(group_id) = hex::decode(group_id_hex).map(GroupId::new) else {
            return PushGossipGate::Void;
        };
        match self.runtime.epoch_state(&group_id) {
            Some(cgka_traits::EpochState::Disbanded(_)) => return PushGossipGate::Void,
            Some(cgka_traits::EpochState::Stable { epoch })
                if after_epoch.is_none_or(|after_epoch| epoch.0 > after_epoch) => {}
            // Not hydrated or quarantined, still resolving a publish, or
            // recovering.
            _ => return PushGossipGate::NotYet,
        }
        if self
            .runtime
            .group_record(&group_id)
            .is_ok_and(|group| group.is_terminal())
        {
            return PushGossipGate::Void;
        }
        // A queued invite, or one convergence superseded that waits for fresh
        // KeyPackages, has not added its members yet, and a disband or block
        // can still be undone.
        let waiting = self.runtime.leave_in_progress(&group_id).unwrap_or(true)
            || self
                .runtime
                .disbanding_in_progress(&group_id)
                .unwrap_or(true)
            || self
                .runtime
                .has_queued_outbound_intents(&group_id)
                .unwrap_or(true)
            || self
                .runtime
                .pending_reinvites()
                .map(|reinvites| reinvites.iter().any(|record| record.group_id == group_id))
                .unwrap_or(true)
            || self
                .app
                .account_storage(&self.state.label)
                .and_then(|storage| {
                    Ok(storage
                        .app_storage()
                        .direct_conversation_has_blocked_user(group_id_hex)?)
                })
                .unwrap_or(true);
        if waiting {
            PushGossipGate::NotYet
        } else {
            PushGossipGate::Due
        }
    }

    /// Send every owed push snapshot whose adding Commit has merged: kind 448
    /// lists of the token records this device holds in the group, then kind
    /// 449 lists of its relayable tombstones. A device that holds neither sends
    /// nothing. Returns whether a snapshot that could be sent remains owed.
    ///
    /// A list counts as sent once the runtime accepts it, including into the
    /// group's durable outbox. A snapshot that fails part way is sent whole
    /// again later; recipients apply what they already hold as a no-op.
    pub(crate) async fn send_owed_push_snapshots(&mut self) -> bool {
        let owed = match self.app.owed_group_push_snapshots(&self.state.label) {
            Ok(owed) => owed,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "send_owed_push_snapshots",
                    error_kind = error.privacy_safe_kind(),
                    "owed push snapshot read failed",
                );
                return true;
            }
        };
        let mut pending = false;
        for (group_id_hex, after_epoch) in owed {
            let settle = match self.push_gossip_gate(&group_id_hex, Some(after_epoch)) {
                PushGossipGate::NotYet => continue,
                PushGossipGate::Void => true,
                PushGossipGate::Due => match self.send_push_snapshot(&group_id_hex).await {
                    Ok(()) => true,
                    // The group's state changed since it was checked; the
                    // next check settles or sends the snapshot.
                    Err(
                        AppError::GroupRemoved(_)
                        | AppError::GroupDisbanding(_)
                        | AppError::UserBlocked,
                    ) => false,
                    Err(error) => {
                        tracing::warn!(
                            target: "marmot_app::notifications",
                            method = "send_owed_push_snapshots",
                            error_kind = error.privacy_safe_kind(),
                            "push snapshot remains owed",
                        );
                        pending = true;
                        false
                    }
                },
            };
            if settle
                && let Err(error) = self.app.replace_group_push_snapshot_owed(
                    &self.state.label,
                    &group_id_hex,
                    after_epoch,
                    None,
                )
            {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "send_owed_push_snapshots",
                    error_kind = error.privacy_safe_kind(),
                    "sent push snapshot was not settled",
                );
                pending = true;
            }
        }
        pending
    }

    async fn send_push_snapshot(&mut self, group_id_hex: &str) -> Result<(), AppError> {
        let group_id = GroupId::new(
            hex::decode(group_id_hex)
                .map_err(|_| AppError::InvalidPushGossip("invalid group id".into()))?,
        );
        let tokens = self
            .app
            .stored_group_push_tokens(&self.state.label, group_id_hex)?;
        let tombstones = self
            .app
            .group_push_token_tombstones(&self.state.label, group_id_hex)?;
        let sender_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let lists = notifications::push_gossip_lists(
            &tokens,
            &tombstones,
            &sender_hex,
            group_id.as_slice().len(),
        )?;
        if lists.unverified_records + lists.unsigned_tombstones + lists.oversized_entries > 0 {
            tracing::debug!(
                target: "marmot_app::notifications",
                method = "send_push_snapshot",
                unverified_records = lists.unverified_records,
                unsigned_tombstones = lists.unsigned_tombstones,
                oversized_entries = lists.oversized_entries,
                "push snapshot leaves out entries it cannot relay",
            );
        }
        let token_lists = lists.token_lists.len();
        let removal_lists = lists.removal_lists.len();
        let intents = lists
            .token_lists
            .into_iter()
            .map(|content| AppMessageIntent::PushTokenList { content })
            .chain(
                lists
                    .removal_lists
                    .into_iter()
                    .map(|content| AppMessageIntent::PushTokenRemoval { content }),
            );
        for intent in intents {
            self.send_app_event(&group_id, intent).await?;
        }
        if token_lists + removal_lists > 0 {
            tracing::debug!(
                target: "marmot_app::notifications",
                method = "send_push_snapshot",
                token_lists,
                removal_lists,
                "push snapshot sent",
            );
        }
        Ok(())
    }

    pub(crate) fn queue_current_push_registration_removal_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<crate::PushRegistration>, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let registration = self.app.push_registration(&self.state.label)?;
        if let Some(registration) = &registration {
            self.app.queue_push_registration_removal_for_group(
                &self.state.label,
                &group_id_hex,
                registration,
            )?;
        }
        Ok(registration)
    }

    pub(crate) async fn drain_push_registration_removal_before_departure(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Option<crate::PushRegistration>, AppError> {
        let registration = self.queue_current_push_registration_removal_for_group(group_id)?;
        self.drain_existing_push_registration_removals_for_group(group_id)
            .await?;
        Ok(registration)
    }

    pub(crate) async fn drain_existing_push_registration_removals_for_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let had_pending_removal = self
            .app
            .pending_push_registration_removals(&self.state.label)?
            .iter()
            .any(|(pending_group_id, _)| pending_group_id == &group_id_hex);
        if !had_pending_removal {
            return Ok(());
        }
        let _ = self.share_push_registration().await?;
        let remains_pending = self
            .app
            .pending_push_registration_removals(&self.state.label)?
            .iter()
            .any(|(pending_group_id, _)| pending_group_id == &group_id_hex);
        if remains_pending {
            return Err(AppError::Transport(
                cgka_traits::TransportAdapterError::Publish(
                    "push registration removal remains pending".to_owned(),
                ),
            ));
        }
        Ok(())
    }

    pub(crate) fn compensate_group_push_registration_removal(
        &self,
        group_id: &GroupId,
        registration: Option<&crate::PushRegistration>,
    ) {
        let Some(registration) = registration else {
            return;
        };
        let group_id_hex = hex::encode(group_id.as_slice());
        if let Err(err) = self.app.queue_push_registration_share_for_group(
            &self.state.label,
            &group_id_hex,
            registration,
        ) {
            tracing::warn!(
                target: "marmot_app::notifications",
                method = "compensate_group_push_registration_removal",
                error_kind = err.privacy_safe_kind(),
                "push token gossip compensation queue failed",
            );
        }
    }

    pub(crate) async fn remove_push_registration(
        &mut self,
        registration: crate::PushRegistration,
    ) -> Result<usize, AppError> {
        self.app
            .queue_push_registration_removals(&self.state.label, registration)?;
        Ok(self.share_push_registration().await?.succeeded_groups as usize)
    }

    pub(crate) async fn clear_and_share_push_registration(
        &mut self,
    ) -> Result<notifications::PushRegistrationShareOutcome, AppError> {
        self.app.clear_push_registration(&self.state.label)?;
        self.share_push_registration().await
    }

    pub(crate) fn snapshot_group_push_tokens_for_members(
        &self,
        group_id: &GroupId,
        member_id_hexes: &[String],
    ) -> Vec<notifications::GroupPushTokenRecord> {
        let Ok(account) = self.app.account_home().account(&self.state.label) else {
            return Vec::new();
        };
        let group_id_hex = hex::encode(group_id.as_slice());
        let Ok(tokens) = self.app.group_push_tokens(&account.label, &group_id_hex) else {
            return Vec::new();
        };
        notifications::tokens_for_member_ids(tokens, member_id_hexes.iter().map(String::as_str))
    }

    pub(crate) async fn publish_targeted_group_state_wake_best_effort(
        &self,
        _group_id: &GroupId,
        snapshot: Vec<notifications::GroupPushTokenRecord>,
        events: &[cgka_traits::engine::GroupEvent],
    ) {
        let Ok(account) = self.app.account_home().account(&self.state.label) else {
            return;
        };
        let wake_ids =
            notifications::wake_member_ids_from_group_events(&account.account_id_hex, events);
        let tokens =
            notifications::tokens_for_member_ids(snapshot, wake_ids.iter().map(String::as_str));
        if tokens.is_empty() {
            return;
        }
        self.publish_notification_trigger_tokens_best_effort(tokens)
            .await;
    }

    pub(crate) async fn publish_notification_trigger_best_effort(
        &self,
        group_id: &GroupId,
        trigger: notifications::NotificationTrigger,
    ) {
        if let Err(err) = self.publish_notification_trigger(group_id, trigger).await {
            tracing::warn!(
                target: "marmot_app::notifications",
                method = "publish_notification_trigger_best_effort",
                error_kind = err.privacy_safe_kind(),
                "notification trigger publish failed",
            );
        }
    }

    async fn publish_notification_trigger_tokens_best_effort(
        &self,
        tokens: Vec<notifications::GroupPushTokenRecord>,
    ) {
        if let Err(err) = self.publish_notification_trigger_tokens(tokens).await {
            tracing::warn!(
                target: "marmot_app::notifications",
                method = "publish_notification_trigger_tokens_best_effort",
                error_kind = err.privacy_safe_kind(),
                "notification trigger publish failed",
            );
        }
    }

    async fn publish_notification_trigger(
        &self,
        group_id: &GroupId,
        _trigger: notifications::NotificationTrigger,
    ) -> Result<(), AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let tokens = self.app.group_push_tokens(&account.label, &group_id_hex)?;
        self.publish_notification_trigger_tokens(tokens).await
    }

    async fn publish_notification_trigger_tokens(
        &self,
        tokens: Vec<notifications::GroupPushTokenRecord>,
    ) -> Result<(), AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let by_server = notifications::token_records_by_server(tokens, &account.account_id_hex);
        if by_server.is_empty() {
            return Ok(());
        }
        let signer = self.app.account_signer_for_summary(&account)?;
        let nostr_signer = signer.as_nostr_signer();
        let fallback = self
            .app
            .relay_client_for_account_id(&account.account_id_hex, nostr_signer);
        let mut first_error = None;
        for (server_pubkey_hex, records) in by_server {
            let endpoints =
                self.notification_trigger_target_relays(&server_pubkey_hex, &records)?;
            let endpoints = self
                .relay_plane
                .sanitize_relay_endpoints(endpoints, "notification trigger publish")
                .map_err(|err| {
                    AppError::Transport(cgka_traits::TransportAdapterError::Publish(err))
                })?;
            if endpoints.is_empty() {
                // No relay hint and no published kind-10050 inbox list for this
                // server: it is unreachable, so skip it as the genuine last
                // resort.
                continue;
            }
            let encrypted_tokens = records
                .into_iter()
                .map(|record| record.encrypted_token)
                .collect::<Vec<_>>();
            let mut chunks = notifications::padded_notification_trigger_chunks(&encrypted_tokens);
            let server = &server_pubkey_hex;
            let endpoints = &endpoints;
            let fallback = fallback.as_ref();
            // Keep each event's relay race independent; SDK batch pre-connect
            // waits for every endpoint, including unreachable relay hints.
            let mut publishes = FuturesUnordered::new();
            loop {
                while publishes.len() < PUSH_PUBLISH_CONCURRENCY {
                    let Some(chunk) = chunks.next() else { break };
                    publishes.push(async move {
                        let event =
                            notifications::build_notification_gift_wrap(server, &chunk).await?;
                        let observation = self.app.product_analytics.begin(
                            crate::ProductFamily::Notification,
                            "trigger",
                            crate::ProductUnit::Attempt,
                        );
                        let result = self
                            .adapter
                            .publish_signed_event(fallback, endpoints, &event, 1)
                            .await;
                        if let Some(observation) = observation {
                            observation.finish(if result.is_ok() {
                                "confirmed"
                            } else {
                                "failure"
                            });
                        }
                        result.map(|_| ()).map_err(AppError::Transport)
                    });
                }
                let Some(result) = publishes.next().await else {
                    break;
                };
                if let Err(error) = result {
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Relays to publish the gift-wrapped trigger to for `server_pubkey_hex`.
    /// Prefers the relay hints carried in the stored token records; when none
    /// exist, falls back to the server account's published kind-10050 NIP-17
    /// inbox relays (cached in the user directory). Returns empty when neither
    /// is available, i.e. the server is unreachable.
    fn notification_trigger_target_relays(
        &self,
        server_pubkey_hex: &str,
        records: &[notifications::GroupPushTokenRecord],
    ) -> Result<Vec<TransportEndpoint>, AppError> {
        let record_relay_hints = records
            .iter()
            .filter_map(|record| record.relay_hint.clone())
            .collect::<Vec<_>>();
        let server_inbox_relays = if record_relay_hints.is_empty() {
            self.app
                .directory()
                .directory_entry_for_account_id(server_pubkey_hex)?
                .map(|entry| entry.relay_lists.inbox.relays)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(self.app.retain_safe_discovered_endpoints(
            notifications::select_notification_trigger_relays(
                &record_relay_hints,
                &server_inbox_relays,
            )
            .into_iter()
            .map(TransportEndpoint)
            .collect(),
            "notification trigger relay discovery",
        ))
    }

    fn local_member_leaf(&self, group_id: &GroupId) -> Result<(String, u32), AppError> {
        let local_account = self.app.account_home().account(&self.state.label)?;
        let leaf_index = self.runtime.own_leaf_index(group_id)?;
        self.runtime
            .members(group_id)?
            .into_iter()
            .find_map(|member| {
                let member_id_hex = hex::encode(member.id.as_slice());
                (member_id_hex == local_account.account_id_hex)
                    .then_some((member_id_hex, leaf_index))
            })
            .ok_or_else(|| AppError::UnknownGroup(hex::encode(group_id.as_slice())))
    }

    /// Diagnostics only: trigger selection reads stored records directly. Uses
    /// the canonical leaf roster that push-token leaf reconciliation uses.
    pub(crate) fn group_push_debug_info(
        &self,
        group_id: &GroupId,
    ) -> Result<notifications::GroupPushDebugInfo, AppError> {
        self.ensure_group(group_id)?;
        let membership = self.runtime.canonical_group_membership(group_id)?;
        let local_leaf_index = if membership.local_leaf_active {
            Some(self.runtime.own_leaf_index(group_id)?)
        } else {
            None
        };
        self.app.group_push_debug_info(
            &self.state.label,
            &hex::encode(group_id.as_slice()),
            &membership.member_leaves,
            local_leaf_index,
        )
    }

    pub(crate) fn cleanup_stale_push_tokens_best_effort(&mut self, group_id: &GroupId) {
        match self.reconcile_push_token_leaves(group_id) {
            Ok(()) => {
                self.pending_push_leaf_reconciliations.remove(group_id);
            }
            Err(_) => {
                self.pending_push_leaf_reconciliations
                    .insert(group_id.clone());
                tracing::warn!(target: "marmot_app::push",
                    method = "cleanup_stale_push_tokens_best_effort",
                    error_code = "leaf_reconciliation_failed",
                    "retained canonical push reconciliation for retry");
            }
        }
    }

    /// Read current membership again on retry; never turn an unavailable tree
    /// into an empty roster or apply a roster captured before a later join.
    fn reconcile_push_token_leaves(&self, group_id: &GroupId) -> Result<(), AppError> {
        let record = self.runtime.group_record(group_id)?;
        if record.removed || record.disbanded.is_some() {
            return Ok(());
        }
        let membership = self.runtime.canonical_group_membership(group_id)?;
        self.app.reconcile_group_push_token_leaves(
            &self.state.label,
            &hex::encode(group_id.as_slice()),
            &membership.member_leaves,
        )?;
        Ok(())
    }

    /// Retry only groups whose earlier canonical sweep failed.
    pub(crate) fn retry_pending_push_leaf_reconciliations(&mut self) -> Result<(), AppError> {
        let groups = self
            .pending_push_leaf_reconciliations
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let mut first_error = None;
        for group_id in groups {
            match self.reconcile_push_token_leaves(&group_id) {
                Ok(()) => {
                    self.pending_push_leaf_reconciliations.remove(&group_id);
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

pub(crate) fn notification_trigger_for_intent(
    intent: &AppMessageIntent,
) -> Option<notifications::NotificationTrigger> {
    match intent {
        AppMessageIntent::Chat { .. }
        | AppMessageIntent::TaggedChat { .. }
        | AppMessageIntent::Reply { .. }
        | AppMessageIntent::Media { .. }
        | AppMessageIntent::Poll { .. }
        | AppMessageIntent::StreamFinal { .. } => {
            Some(notifications::NotificationTrigger::NewMessage)
        }
        AppMessageIntent::Report { .. }
        | AppMessageIntent::DismissReports { .. }
        | AppMessageIntent::RemoveMessage { .. }
        | AppMessageIntent::Reaction { .. }
        | AppMessageIntent::Unreact { .. }
        | AppMessageIntent::DeleteReactions { .. }
        | AppMessageIntent::Edit { .. }
        | AppMessageIntent::Delete { .. }
        | AppMessageIntent::PollResponse { .. }
        | AppMessageIntent::StreamStart { .. }
        | AppMessageIntent::AgentActivity { .. }
        | AppMessageIntent::AgentOperation { .. }
        | AppMessageIntent::GroupSystem { .. }
        | AppMessageIntent::Custom { .. }
        | AppMessageIntent::PushTokenUpdate { .. }
        | AppMessageIntent::PushTokenList { .. }
        | AppMessageIntent::PushTokenRemoval { .. } => None,
    }
}
