use std::collections::{HashMap, HashSet};

use cgka_traits::TransportAdapter;
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
use cgka_traits::ingest::IngestOutcome;
use tokio::time::timeout;
use transport_nostr_peeler::NostrTransportEvent;

use crate::groups::{EventGroupProjection, event_group_id, fail_if_publish_failed, observe_event};
use crate::media::media_imeta_tags_are_valid;
use crate::notifications;
use crate::{
    AppError, AppGroupAdminPolicyComponent, AppMessageProjection, SDK_DRAIN_WAIT,
    SDK_FIRST_SYNC_WAIT, SyncSummary, TRANSPORT_CURSOR_MAX_FUTURE_SKEW,
    refresh_seen_lookup_if_needed, remember_seen_event, unix_now_seconds,
};

use super::AppClient;

impl AppClient {
    pub(crate) fn take_pending_convergence_groups(&mut self) -> Vec<cgka_traits::GroupId> {
        self.pending_convergence_groups.drain().collect()
    }

    pub(crate) fn has_pending_convergence_inputs(&self, group_id: &cgka_traits::GroupId) -> bool {
        self.runtime
            .has_pending_convergence_inputs(group_id)
            .unwrap_or(false)
    }

    fn remember_buffered_convergence_outcome(&mut self, outcome: &IngestOutcome) {
        if let IngestOutcome::Buffered { group_id, .. } = outcome {
            self.pending_convergence_groups.insert(group_id.clone());
        }
    }

    fn remember_pending_convergence_effects(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) {
        self.pending_convergence_groups
            .extend(effects.pending_convergence.iter().cloned());
    }

    pub(crate) async fn sync_runtime_groups(&self) -> Result<(), AppError> {
        let rebuild_since = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp);
        self.cache_current_encrypted_media_epoch_secrets();
        self.runtime.sync_transport_groups(rebuild_since).await?;
        self.cache_current_encrypted_media_epoch_secrets();
        Ok(())
    }

    pub async fn sync(&mut self) -> Result<SyncSummary, AppError> {
        let rebuild_since = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp);
        self.runtime.activate_transport(rebuild_since).await?;
        self.sync_runtime_groups().await?;
        let mut summary = self.sync_sdk_relay().await?;
        // Surface engine events queued without an inbound delivery — most
        // importantly `GroupHydrationQuarantined`, queued during session
        // `open()` hydration (darkmatter#426). If no relay delivery arrived
        // above, `sync_sdk_relay` never drained the engine, so these would stay
        // buffered and invisible to runtime subscribers until some later
        // unrelated send/ingest. Fold any pending events into this summary.
        let drained = self.drain_pending_session_events().await?;
        summary.merge(drained);
        Ok(summary)
    }

    /// Drain engine events that were queued without an inbound transport
    /// delivery and project them into a [`SyncSummary`] the same way
    /// `ingest_delivery` does, minus the delivery-specific message decoding.
    ///
    /// This is the no-inbound counterpart to `sync_sdk_relay`: session `open()`
    /// hydration queues `GroupHydrationQuarantined`, and a successful
    /// `retry_hydrate_quarantined_group` queues `GroupHydrationRecovered`. Both
    /// rely on a drain to reach app/runtime subscribers; without an explicit
    /// path they only surface when unrelated relay traffic happens to trigger
    /// one (darkmatter#426). There is no source delivery here, so events that
    /// reference a not-yet-live (quarantined) group must not abort the drain —
    /// projection lookups are best-effort.
    pub(crate) async fn drain_pending_session_events(&mut self) -> Result<SyncSummary, AppError> {
        let effects = self.runtime.drain().await?;
        fail_if_publish_failed(&effects)?;
        let mut summary = SyncSummary::default();
        if effects.events.is_empty() {
            return Ok(summary);
        }
        let display_names = self.app.display_names_by_id()?;
        // Synthetic source identity: drained events have no inbound transport
        // message. A zeroed id / now-timestamp keeps audit + observation happy
        // without inventing a real delivery.
        let source_message_id_hex = String::new();
        let source_recorded_at = unix_now_seconds();
        for event in &effects.events {
            let before = self.state.groups.len();
            let previous_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            // Best-effort projection: a quarantined group is not live, so its
            // routing/metadata components may be unavailable. Skip projection
            // rather than propagate — the event must still reach subscribers.
            let group_projection = event_group_id(event)
                .and_then(|group_id| self.event_group_projection_best_effort(group_id));
            observe_event(
                &mut self.state,
                &display_names,
                &mut summary,
                event,
                group_projection.as_ref(),
                &source_message_id_hex,
                source_recorded_at,
                self.app.allow_loopback_blob_endpoints(),
            );
            let updated_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            self.audit_observed_group_event(
                event,
                previous_group.as_ref(),
                updated_group.as_ref(),
                &source_message_id_hex,
            );
            if self.state.groups.len() != before {
                self.refresh_group_routes()?;
                self.sync_runtime_groups().await?;
            }
        }
        self.app.save_state(&self.state)?;
        Ok(summary)
    }

    /// Build an [`EventGroupProjection`] for `group_id`, returning `None` if any
    /// component lookup fails (e.g. the group is quarantined and not live).
    /// Used by the no-inbound drain path where a missing projection must not
    /// abort processing.
    fn event_group_projection_best_effort(
        &self,
        group_id: &cgka_traits::GroupId,
    ) -> Option<EventGroupProjection<'static>> {
        let nostr_routing = self.nostr_routing_for_group(group_id).ok()?;
        Some(EventGroupProjection {
            nostr_routing,
            group_metadata: None,
            admin_policy: self
                .runtime
                .admin_pubkeys(group_id)
                .map(AppGroupAdminPolicyComponent::new)
                .unwrap_or_else(|_| AppGroupAdminPolicyComponent::new(Vec::new())),
            message_retention: self.message_retention_for_group(group_id),
            agent_text_stream: self.agent_text_stream_for_group(group_id),
            avatar_url: self.avatar_url_for_group(group_id),
            encrypted_media: self.encrypted_media_for_group(group_id),
            image: self.image_for_group(group_id),
        })
    }

    pub async fn next_event(&mut self) -> Result<SyncSummary, AppError> {
        let display_names = self.app.display_names_by_id()?;
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let mut seen = self
            .state
            .seen_events
            .iter()
            .cloned()
            .collect::<HashSet<_>>();

        loop {
            let delivery = self
                .adapter
                .receive()
                .await?
                .ok_or(AppError::TransportClosed)?;
            let event_id = hex::encode(delivery.message.id.as_slice());
            if is_own_relay_echo(&delivery, &local_account_id_hex, &seen) {
                continue;
            }
            if seen.contains(&event_id) {
                continue;
            }
            seen.insert(event_id.clone());
            remember_seen_event(&mut self.state, event_id);
            refresh_seen_lookup_if_needed(&mut seen, &self.state);

            let mut summary = SyncSummary::default();
            self.ingest_delivery(delivery, &display_names, &mut summary)
                .await?;
            self.app.save_state(&self.state)?;
            if summary.joined_groups.is_empty()
                && summary.messages.is_empty()
                && summary.events.is_empty()
                && self.pending_convergence_groups.is_empty()
            {
                continue;
            }
            return Ok(summary);
        }
    }

    async fn sync_sdk_relay(&mut self) -> Result<SyncSummary, AppError> {
        let display_names = self.app.display_names_by_id()?;
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let mut summary = SyncSummary::default();
        let mut seen = self
            .state
            .seen_events
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let mut first_wait = true;

        loop {
            let wait = if first_wait {
                SDK_FIRST_SYNC_WAIT
            } else {
                SDK_DRAIN_WAIT
            };
            first_wait = false;

            let delivery = match timeout(wait, self.adapter.receive()).await {
                Ok(Ok(Some(delivery))) => delivery,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            };
            let event_id = hex::encode(delivery.message.id.as_slice());
            if is_own_relay_echo(&delivery, &local_account_id_hex, &seen) {
                continue;
            }
            if seen.contains(&event_id) {
                continue;
            }
            seen.insert(event_id.clone());
            remember_seen_event(&mut self.state, event_id);
            refresh_seen_lookup_if_needed(&mut seen, &self.state);
            self.ingest_delivery(delivery, &display_names, &mut summary)
                .await?;
        }

        self.app.save_state(&self.state)?;
        Ok(summary)
    }

    async fn ingest_delivery(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
        display_names: &HashMap<String, String>,
        summary: &mut SyncSummary,
    ) -> Result<(), AppError> {
        let source_message_id_hex = hex::encode(delivery.message.id.as_slice());
        let source_recorded_at = delivery.message.timestamp.0;
        let effects = self.runtime.ingest_delivery(delivery).await?;
        fail_if_publish_failed(&effects.effects)?;
        self.remember_buffered_convergence_outcome(&effects.outcome);
        self.remember_pending_convergence_effects(&effects.effects);
        self.remember_transport_cursor(source_recorded_at);
        self.observe_account_device_effects(
            &effects.effects,
            display_names,
            summary,
            &source_message_id_hex,
            source_recorded_at,
        )
        .await
    }

    pub(crate) async fn advance_convergence_after_runtime_sync(
        &mut self,
        group_id: &cgka_traits::GroupId,
    ) -> Result<SyncSummary, AppError> {
        // The account worker refreshes transport groups once for the scheduled
        // convergence batch before calling this per-group path.
        let effects = self.runtime.advance_convergence(group_id).await?;
        fail_if_publish_failed(&effects)?;
        self.remember_pending_convergence_effects(&effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group_id);

        let display_names = self.app.display_names_by_id()?;
        let mut summary = SyncSummary::default();
        let source_message_id_hex = String::new();
        let source_recorded_at = unix_now_seconds();
        self.observe_account_device_effects(
            &effects,
            &display_names,
            &mut summary,
            &source_message_id_hex,
            source_recorded_at,
        )
        .await?;
        self.prune_plaintext_retention_for_group(group_id)?;
        self.app.save_state(&self.state)?;
        Ok(summary)
    }

    async fn observe_account_device_effects(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
        display_names: &HashMap<String, String>,
        summary: &mut SyncSummary,
        source_message_id_hex: &str,
        source_recorded_at: u64,
    ) -> Result<(), AppError> {
        // MLS member ids in this design are the Nostr account pubkey hex, so a
        // membership change whose subject matches the local account id hex is
        // the local account leaving / being removed (or, for joins, returning).
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        for event in &effects.events {
            let before = self.state.groups.len();
            let previous_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            let group_metadata =
                event_group_id(event).and_then(|group_id| self.runtime.group_record(group_id).ok());
            let group_projection = event_group_id(event)
                .map(|group_id| {
                    Ok::<_, AppError>(EventGroupProjection {
                        nostr_routing: self.nostr_routing_for_group(group_id)?,
                        group_metadata: group_metadata.as_ref(),
                        admin_policy: self
                            .runtime
                            .admin_pubkeys(group_id)
                            .map(AppGroupAdminPolicyComponent::new)
                            .unwrap_or_else(|_| AppGroupAdminPolicyComponent::new(Vec::new())),
                        message_retention: self.message_retention_for_group(group_id),
                        agent_text_stream: self.agent_text_stream_for_group(group_id),
                        avatar_url: self.avatar_url_for_group(group_id),
                        encrypted_media: self.encrypted_media_for_group(group_id),
                        image: self.image_for_group(group_id),
                    })
                })
                .transpose()?;
            if let Some(message) = observe_event(
                &mut self.state,
                display_names,
                summary,
                event,
                group_projection.as_ref(),
                source_message_id_hex,
                source_recorded_at,
                self.app.allow_loopback_blob_endpoints(),
            ) {
                if notifications::is_push_gossip_kind(message.kind) {
                    if let Err(err) = self
                        .app
                        .ingest_push_gossip_message(&self.state.label, &message)
                    {
                        tracing::warn!(
                            target: "marmot_app::notifications",
                            method = "ingest_delivery",
                            "ignoring malformed push token gossip: {err}",
                        );
                    }
                    summary
                        .messages
                        .retain(|candidate| candidate.message_id_hex != message.message_id_hex);
                    continue;
                }
                if message.kind == MARMOT_APP_EVENT_KIND_CHAT
                    && media_imeta_tags_are_valid(
                        &message.tags,
                        self.app.allow_loopback_blob_endpoints(),
                    )
                    && self
                        .remember_current_encrypted_media_secret(&message.group_id)
                        .is_err()
                {
                    tracing::warn!(
                        target: "marmot_app::media",
                        method = "ingest_delivery",
                        error_code = "encrypted_media_secret_cache_skipped",
                        "failed to cache encrypted media source epoch secret",
                    );
                }
                self.app.remember_directory_message_sender(&message)?;
                let message_projection = AppMessageProjection {
                    message_id_hex: message.message_id_hex.clone(),
                    source_message_id_hex: Some(message.source_message_id_hex.clone()),
                    direction: "received".to_owned(),
                    group_id_hex: hex::encode(message.group_id.as_slice()),
                    sender: message.sender.clone(),
                    plaintext: message.plaintext.clone(),
                    kind: message.kind,
                    tags: message.tags.clone(),
                    source_epoch: Some(message.source_epoch),
                    recorded_at: Some(source_recorded_at),
                    // Received app messages are not synthesized system rows.
                    origin_commit_id: None,
                };
                let projection_update = self
                    .app
                    .record_account_app_event(&self.state.label, &message_projection)?;
                summary.projection_updates.push(projection_update);
                self.prune_plaintext_retention_for_group(&message.group_id)?;
            }
            let updated_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            self.audit_observed_group_event(
                event,
                previous_group.as_ref(),
                updated_group.as_ref(),
                source_message_id_hex,
            );
            if let cgka_traits::engine::GroupEvent::AppMessageInvalidated {
                message_id, reason, ..
            } = event
                && let Some(projection_update) = self.app.invalidate_timeline_source_message(
                    &self.state.label,
                    &hex::encode(message_id.as_slice()),
                    &format!("{reason:?}"),
                )?
            {
                summary.projection_updates.push(projection_update);
            }
            // A rolled-back commit on a losing branch invalidates any kind-1210
            // group system rows it synthesized (one commit → many rows). The
            // winning branch's fresh rows are synthesized below from this
            // current effect's `GroupStateChanged` events, so the timeline
            // converges to the canonical branch without stale losing-branch rows.
            if let cgka_traits::engine::GroupEvent::ForkRecovered {
                invalidated_commit_id,
                ..
            } = event
                && let Some(projection_update) = self.app.invalidate_timeline_origin_commit(
                    &self.state.label,
                    &hex::encode(invalidated_commit_id.as_slice()),
                    "LosingBranch",
                )?
            {
                summary.projection_updates.push(projection_update);
            }
            // Convergence-path analog of `ForkRecovered`: a commit first applied
            // through stored convergence (so its synthesized kind-1210 rows carry
            // `origin_commit_id`) later lost a same-epoch fork and was rolled
            // back. `ForkRecovered` only fires on the direct staged-commit seam,
            // so without this the convergence-born losing rows would survive.
            // Invalidate every row whose origin commit matches.
            if let cgka_traits::engine::GroupEvent::CommitRolledBack {
                invalidated_commit_id,
                ..
            } = event
                && let Some(projection_update) = self.app.invalidate_timeline_origin_commit(
                    &self.state.label,
                    &hex::encode(invalidated_commit_id.as_slice()),
                    "LosingBranch",
                )?
            {
                summary.projection_updates.push(projection_update);
            }
            if self.state.groups.len() != before {
                self.refresh_group_routes()?;
                self.sync_runtime_groups().await?;
            }
            if let cgka_traits::engine::GroupEvent::GroupStateChanged {
                group_id,
                change:
                    cgka_traits::engine::GroupStateChange::MemberRemoved { member }
                    | cgka_traits::engine::GroupStateChange::MemberLeft { member },
                ..
            } = event
            {
                let group_id_hex = hex::encode(group_id.as_slice());
                let member_id_hex = hex::encode(member.as_slice());
                let _ = self.app.remove_group_push_tokens_for_member(
                    &self.state.label,
                    &group_id_hex,
                    &member_id_hex,
                );
                // Only the local account leaving / being removed suppresses our
                // own unread aggregate for the group; a peer removal must not.
                // This projection write is the source of truth for the account
                // unread aggregate, so propagate its error (matching the nearby
                // timeline/message projection writes) instead of swallowing it:
                // silently leaving the flag stale would keep
                // `account_unread_total()` returning an inflated badge after a
                // self-removal that sync otherwise reports as successful.
                if member_id_hex.eq_ignore_ascii_case(&local_account_id_hex) {
                    self.app
                        .set_group_self_membership(&self.state.label, &group_id_hex, true)?;
                }
            }
            // A (re-)join or create restores the local account's membership so a
            // re-add after removal un-suppresses the group's unread count. Same
            // source-of-truth write as the removal path above: propagate the
            // error rather than swallow it.
            if let cgka_traits::engine::GroupEvent::GroupJoined { group_id, .. }
            | cgka_traits::engine::GroupEvent::GroupCreated { group_id } = event
            {
                let group_id_hex = hex::encode(group_id.as_slice());
                self.app
                    .set_group_self_membership(&self.state.label, &group_id_hex, false)?;
            }
        }
        // Synthesize durable kind-1210 system rows from authenticated state
        // changes (peer commits, auto-commits, and scheduled convergence).
        let system_updates = self.project_group_system_rows(&effects.events, source_recorded_at);
        summary.projection_updates.extend(system_updates);
        Ok(())
    }

    /// Advance the persisted transport cursor from an inbound message.
    ///
    /// `timestamp` is the sender-controlled Nostr `created_at` of the outer
    /// kind-445 event and is never validated upstream. The cursor is a
    /// monotonic-max, persisted value that becomes a relay-level `since` filter
    /// on subscription rebuild and account open, so an unbounded far-future
    /// value would push `since` into the future and silently halt all message
    /// reception across restarts (darkmatter#182). Clamp the advance to local
    /// wall-clock plus a bounded skew so a hostile or clock-skewed sender can
    /// move the cursor no further than `now + TRANSPORT_CURSOR_MAX_FUTURE_SKEW`.
    fn remember_transport_cursor(&mut self, timestamp: u64) {
        self.state.last_transport_timestamp = Some(clamped_transport_cursor(
            self.state.last_transport_timestamp,
            timestamp,
            unix_now_seconds(),
            TRANSPORT_CURSOR_MAX_FUTURE_SKEW.as_secs(),
        ));
    }
}

pub(crate) fn is_own_relay_echo(
    delivery: &cgka_traits::TransportDelivery,
    local_account_id_hex: &str,
    known_event_ids: &HashSet<String>,
) -> bool {
    let event_id = hex::encode(delivery.message.id.as_slice());
    if !known_event_ids.contains(&event_id) {
        return false;
    }
    NostrTransportEvent::from_transport_message(&delivery.message)
        .ok()
        .is_some_and(|event| event.pubkey == local_account_id_hex)
}

/// Compute the next persisted transport cursor from a candidate inbound
/// timestamp.
///
/// `candidate` is the sender-controlled Nostr `created_at` and is untrusted. It
/// is first clamped to `now + max_future_skew_secs` so a far-future value
/// cannot poison the cursor (which would push the relay `since` filter into the
/// future and silently halt message reception — darkmatter#182), then folded
/// into the existing monotonic-max cursor. The existing `current` is clamped
/// the same way before the max, so a cursor that was already poisoned before
/// this guard existed is *healed* back down to `now + max_future_skew_secs`
/// here instead of being preserved forever by the monotonic max. A benign
/// in-range timestamp is unaffected; the skew margin tolerates ordinary sender
/// clock drift.
fn clamped_transport_cursor(
    current: Option<u64>,
    candidate: u64,
    now: u64,
    max_future_skew_secs: u64,
) -> u64 {
    let max_allowed = now.saturating_add(max_future_skew_secs);
    let clamped = candidate.min(max_allowed);
    current
        .map(|current| current.min(max_allowed).max(clamped))
        .unwrap_or(clamped)
}

#[cfg(test)]
mod transport_cursor_tests {
    use super::clamped_transport_cursor;

    const SKEW: u64 = 5 * 60;
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn in_range_timestamp_advances_cursor_unchanged() {
        // A normal present-dated message advances the cursor to its own value.
        assert_eq!(
            clamped_transport_cursor(Some(NOW - 100), NOW, NOW, SKEW),
            NOW
        );
        assert_eq!(clamped_transport_cursor(None, NOW, NOW, SKEW), NOW);
    }

    #[test]
    fn far_future_timestamp_is_clamped_to_now_plus_skew() {
        // A malicious far-future created_at must not move the cursor past
        // now + skew, so the relay `since` filter can never jump into the
        // future and halt reception (darkmatter#182).
        let poisoned = NOW + 10 * 365 * 24 * 60 * 60; // ~10 years ahead
        assert_eq!(
            clamped_transport_cursor(Some(NOW - 100), poisoned, NOW, SKEW),
            NOW + SKEW
        );
        assert_eq!(
            clamped_transport_cursor(None, poisoned, NOW, SKEW),
            NOW + SKEW
        );
    }

    #[test]
    fn cursor_stays_monotonic_against_older_timestamps() {
        // An older message never rewinds the persisted cursor.
        assert_eq!(
            clamped_transport_cursor(Some(NOW), NOW - 500, NOW, SKEW),
            NOW
        );
    }

    #[test]
    fn timestamp_just_inside_skew_window_is_accepted() {
        let within = NOW + SKEW - 1;
        assert_eq!(
            clamped_transport_cursor(Some(NOW), within, NOW, SKEW),
            within
        );
    }

    #[test]
    fn already_poisoned_cursor_is_healed_down_not_preserved() {
        // A cursor poisoned before this guard existed (a far-future value
        // persisted by a vulnerable version) must not be preserved forever by
        // the monotonic max. When a present-dated message arrives, the stored
        // cursor is clamped back to now + skew and then folded in, so the
        // account recovers to wall-clock instead of staying degraded
        // (darkmatter#182 — blocking adversarial finding).
        let poisoned = NOW + 10 * 365 * 24 * 60 * 60; // ~10 years ahead
        assert_eq!(
            clamped_transport_cursor(Some(poisoned), NOW, NOW, SKEW),
            NOW + SKEW,
            "a present-dated message must heal a poisoned future cursor down to now + skew"
        );
        // Once wall-clock advances past the healed value, a present-dated
        // message advances the cursor normally, proving the account is no
        // longer stuck in the future.
        let healed = clamped_transport_cursor(Some(poisoned), NOW, NOW, SKEW);
        let later = healed + 1_000;
        assert_eq!(
            clamped_transport_cursor(Some(healed), later, later, SKEW),
            later,
            "after healing, the cursor tracks present-dated messages again"
        );
    }
}
