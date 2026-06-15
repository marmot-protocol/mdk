use std::collections::{HashMap, HashSet};

use cgka_traits::TransportAdapter;
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
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
        self.sync_sdk_relay().await
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
        self.remember_transport_cursor(source_recorded_at);
        for event in &effects.effects.events {
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
                &source_message_id_hex,
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
                &source_message_id_hex,
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
            // delivery's `GroupStateChanged` events, so the timeline converges
            // to the canonical branch without stale losing-branch rows.
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
            }
        }
        // Synthesize durable kind-1210 system rows from this delivery's
        // authenticated state changes (peer commits and auto-commits).
        let system_updates =
            self.project_group_system_rows(&effects.effects.events, source_recorded_at);
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
