use std::collections::{HashMap, HashSet};
use std::time::Instant;

use cgka_traits::TransportAdapter;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE};
use cgka_traits::ingest::IngestOutcome;
use storage_sqlite::clamp_to_max_future_skew;
use tokio::time::timeout;
use transport_nostr_peeler::NostrTransportEvent;

use crate::app_telemetry::AppPerformanceOperation;
use crate::groups::{
    EventGroupProjection, decode_received_event, event_group_id, fail_if_publish_failed,
    observe_event,
};
use crate::media::media_imeta_tags_are_valid;
use crate::notifications;
use crate::{
    AppError, AppGroupAdminPolicyComponent, AppMessageProjection, AppPerformanceTelemetry,
    SDK_DRAIN_WAIT, SDK_FIRST_SYNC_WAIT, SelfMembership, SyncSummary,
    TRANSPORT_CURSOR_MAX_FUTURE_SKEW, remember_seen_event, unix_now_seconds,
};

use super::AppClient;
use super::epoch_stall::BackfillDecision;
use crate::config::CursorPersistence;

/// What the convergence scheduler should do next for a group, derived from
/// the engine's durable pass state. Expected collection time is not an error;
/// storage and projection failures are, and they surface as `Err` from
/// [`AppClient::convergence_schedule_state`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConvergenceScheduleState {
    /// No active pass and no pending inputs: cancel scheduled wakeups.
    Idle,
    /// A pass is collecting or local deferred-peel residence is pending; wake
    /// when the earliest cutoff elapses.
    Collecting { remaining_ms: u64 },
    /// A pass is frozen/resolving or its cutoff already elapsed: run now.
    Ready,
    /// Pending inputs exist but no pass can open yet (epoch not `Stable`, an
    /// admin reservation holds the boundary, or the retained input has no
    /// trigger). Re-check on the fallback delay; only this state counts
    /// toward the unsettled re-arm cap.
    PendingUnopenable,
    /// No convergence work, but durable queued outbound intents remain. The
    /// scheduled drain regenerates and publishes them (and a failed sync on
    /// that tick triggers transport reactivation), so the wakeup stays armed
    /// on the fallback delay — but a healthy waiting queue is not unsettled
    /// convergence and never counts toward the re-arm cap.
    PendingOutbound,
}

impl AppClient {
    pub(crate) fn take_pending_convergence_groups(&mut self) -> Vec<cgka_traits::GroupId> {
        self.pending_convergence_groups.drain().collect()
    }

    /// Engine-derived convergence scheduling state for one group.
    ///
    /// Errors propagate: a storage or engine failure must schedule a retry at
    /// the caller, never read as "no pending work" (the previous
    /// `unwrap_or(false)` wrapper let an error cancel future wakeups).
    /// `prepare_convergence_cutoff_delay_ms` is a command, not a query — it
    /// may open a pass or persist deadline rebasing before reporting.
    pub(crate) fn convergence_schedule_state(
        &mut self,
        group_id: &cgka_traits::GroupId,
    ) -> Result<ConvergenceScheduleState, AppError> {
        let convergence_delay = self.runtime.prepare_convergence_cutoff_delay_ms(group_id)?;
        match convergence_delay {
            Some(0) => Ok(ConvergenceScheduleState::Ready),
            Some(remaining_ms) => {
                let remaining_ms = self
                    .runtime
                    .deferred_peel_cutoff_delay_ms(group_id)?
                    .map_or(remaining_ms, |deferred| remaining_ms.min(deferred));
                if remaining_ms == 0 {
                    Ok(ConvergenceScheduleState::Ready)
                } else {
                    Ok(ConvergenceScheduleState::Collecting { remaining_ms })
                }
            }
            None => {
                if self.runtime.has_pending_convergence_inputs(group_id)? {
                    Ok(ConvergenceScheduleState::PendingUnopenable)
                } else if self.runtime.has_queued_outbound_intents(group_id)? {
                    Ok(ConvergenceScheduleState::PendingOutbound)
                } else {
                    match self.runtime.deferred_peel_cutoff_delay_ms(group_id)? {
                        Some(0) => Ok(ConvergenceScheduleState::Ready),
                        Some(remaining_ms) => {
                            Ok(ConvergenceScheduleState::Collecting { remaining_ms })
                        }
                        None => Ok(ConvergenceScheduleState::Idle),
                    }
                }
            }
        }
    }

    fn remember_buffered_convergence_outcome(&mut self, outcome: &IngestOutcome) {
        if let IngestOutcome::Buffered { group_id, .. } = outcome {
            self.pending_convergence_groups.insert(group_id.clone());
        }
    }

    fn remember_pending_convergence_groups(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) {
        self.pending_convergence_groups
            .extend(effects.pending_convergence.iter().cloned());
    }

    fn arm_recovery_from_effects(&mut self, effects: &marmot_account::AccountDeviceEffects) {
        if self.app.cursor_persistence() != CursorPersistence::Advance {
            return;
        }
        for event in &effects.events {
            let cgka_traits::engine::GroupEvent::TransportObjectResourceRefused {
                group_id, ..
            } = event
            else {
                continue;
            };
            let Ok(record) = self.runtime.group_record(group_id) else {
                continue;
            };
            // Recording the recovery intent before the worker performs the
            // external full-history replay, and recording an escalation this
            // arm raises, are both the shared decision handler's job: a
            // resource-refusal arm counts toward the same unrecovered run as a
            // deferred-delivery arm, and the detector raises the run's
            // escalation only once, at whichever path happens to arm third.
            let decision = self
                .epoch_stall
                .observe_resource_refusal(group_id.clone(), record.epoch);
            self.apply_backfill_decision(group_id, record.epoch.0, decision);
        }
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

    pub(crate) async fn prepare_transport(&self) -> Result<(), AppError> {
        self.prepare_transport_with_telemetry(None).await
    }

    async fn prepare_transport_with_telemetry(
        &self,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<(), AppError> {
        // Before any subscription goes out: auth-gated relays (NIP-42)
        // withhold gift-wrapped welcomes from unauthenticated subscribers.
        let activation_started = Instant::now();
        self.relay_plane
            .set_transport_signer(self.transport_signer.clone())
            .await;
        let rebuild_since = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp);
        let activation = self.runtime.activate_transport(rebuild_since).await;
        if let Some(telemetry) = telemetry {
            telemetry.record(
                AppPerformanceOperation::AccountTransportActivation,
                activation_started.elapsed(),
                activation.is_ok(),
            );
        }
        activation?;

        let registration_started = Instant::now();
        let registration = self.sync_runtime_groups().await;
        if let Some(telemetry) = telemetry {
            telemetry.record(
                AppPerformanceOperation::AccountSubscriptionRegistration,
                registration_started.elapsed(),
                registration.is_ok(),
            );
        }
        registration
    }

    pub async fn sync(&mut self) -> Result<SyncSummary, AppError> {
        self.sync_inner(None).await
    }

    pub(crate) async fn sync_with_startup_stage_telemetry(
        &mut self,
        telemetry: &AppPerformanceTelemetry,
    ) -> Result<SyncSummary, AppError> {
        self.sync_inner(Some(telemetry)).await
    }

    async fn sync_inner(
        &mut self,
        telemetry: Option<&AppPerformanceTelemetry>,
    ) -> Result<SyncSummary, AppError> {
        // Reconcile epoch-bounded prior routes before issuing the first relay
        // subscriptions. This makes retirement deterministic even for a quiet
        // group that has no new inbound events after restart.
        if self.refresh_group_routes()? {
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        }
        let rebuild_since_secs = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp)
            .map(|timestamp| timestamp.0);
        self.prepare_transport_with_telemetry(telemetry).await?;
        // Both the inbox/group activation and the group-subscription refresh
        // have now registered on relays; emit the rebuild audit row from the
        // drained registration log before draining inbound deliveries.
        self.record_subscription_rebuild(rebuild_since_secs).await;
        let mut summary = self.sync_sdk_relay().await?;
        // Surface engine events queued without an inbound delivery — most
        // importantly `GroupHydrationQuarantined`, queued during session
        // `open()` hydration (mdk#426). If no relay delivery arrived
        // above, `sync_sdk_relay` never drained the engine, so these would stay
        // buffered and invisible to runtime subscribers until some later
        // unrelated send/ingest. Fold any pending events into this summary.
        let drained = match self.drain_pending_session_events().await {
            Ok(drained) => drained,
            Err(error) => return self.preserve_applied_summary_on_error(summary, error),
        };
        summary.merge(drained);
        self.drain_epoch_stall_escalations(&mut summary);
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
    /// one (mdk#426). There is no source delivery here, so events that
    /// reference a not-yet-live (quarantined) group must not abort the drain —
    /// projection lookups are best-effort.
    pub(crate) async fn drain_pending_session_events(&mut self) -> Result<SyncSummary, AppError> {
        let effects = self.runtime.drain().await?;
        self.observe_drained_session_events(&effects).await
    }

    /// Project one drained batch of engine events, split from the drain itself
    /// so the projection is exercisable against a given batch of effects.
    pub(crate) async fn observe_drained_session_events(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<SyncSummary, AppError> {
        // Session open seeds this list from durable queued/convergence input.
        // Preserve that scheduling edge even when hydration emitted no app
        // events; the worker drains this set immediately after startup sync.
        self.remember_pending_convergence_groups(effects);
        // Arm before the publish gate, not after. `drain()` empties the engine's
        // in-memory event buffer one-shot and is these events' only source, and
        // a `TransportObjectResourceRefused` is buffered only after its durable
        // retention row is already deleted — so a refusal this pass does not arm
        // on can never be re-observed. The arm survives the `?` because it is a
        // field mutation plus a durable audit row, not summary state. The two
        // conditions are correlated rather than independent: this drain
        // publishes, so the failure and the refusal ride the same effects.
        self.arm_recovery_from_effects(effects);
        fail_if_publish_failed(effects)?;
        let mut summary = SyncSummary::default();
        if effects.events.is_empty() {
            self.drain_epoch_stall_escalations(&mut summary);
            return Ok(summary);
        }
        let display_names = self.app.display_names_by_id()?;
        // Synthetic source identity: drained events have no inbound transport
        // message. The empty id signals "no source message"; the audit recorder
        // drops it rather than emitting a schema-invalid `message_ids` entry
        // (see `schema_valid_message_ids`).
        let source_message_id_hex = String::new();
        let source_received_at = unix_now_seconds();
        let local_group_deletion_frontiers =
            self.local_group_deletion_frontiers_at_batch_start(effects)?;
        let mut routes_dirty = false;
        let mut gossip_message_ids = HashSet::new();
        for event in &effects.events {
            let batch_start_frontier = event_group_id(event)
                .and_then(|group_id| {
                    local_group_deletion_frontiers.get(&hex::encode(group_id.as_slice()))
                })
                .copied();
            let crosses_frontier = match batch_start_frontier {
                Some(frontier) => self.local_deleted_group_event_crosses_frontier(
                    event,
                    frontier,
                    &source_message_id_hex,
                    source_received_at,
                )?,
                None => false,
            };
            if !crosses_frontier
                && let Some(changed) =
                    self.suppress_local_deleted_group_event(event, batch_start_frontier)?
            {
                routes_dirty |= changed;
                self.prepare_pending_application_event_ack(event);
                continue;
            }
            let before = self.state.groups.len();
            let previous_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            // Best-effort projection: a quarantined group is not live, so its
            // routing/metadata components may be unavailable. Skip projection
            // rather than propagate — the event must still reach subscribers.
            let group_metadata =
                event_group_id(event).and_then(|group_id| self.runtime.group_record(group_id).ok());
            let group_projection = event_group_id(event).and_then(|group_id| {
                self.event_group_projection_best_effort(group_id, group_metadata.as_ref())
            });
            if let Some(message) = observe_event(
                &mut self.state,
                &display_names,
                &mut summary,
                event,
                group_projection.as_ref(),
                &source_message_id_hex,
                source_received_at,
                None,
                self.app.allow_loopback_blob_endpoints(),
            ) && let Some(gossip_message_id) =
                self.project_received_message(message, group_metadata.as_ref(), &mut summary)?
            {
                gossip_message_ids.insert(gossip_message_id);
            }
            let updated_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            self.audit_observed_group_event(
                event,
                previous_group.as_ref(),
                updated_group.as_ref(),
                &source_message_id_hex,
            );
            let can_ack_application_event = if crosses_frontier {
                self.prepare_local_group_deletion_frontier_clear(
                    event,
                    batch_start_frontier.expect("crossing event has a frontier"),
                )?
            } else {
                true
            };
            if can_ack_application_event {
                self.prepare_pending_application_event_ack(event);
            }
            if self.state.groups.len() != before {
                routes_dirty = true;
            }
        }
        if !gossip_message_ids.is_empty() {
            summary
                .messages
                .retain(|message| !gossip_message_ids.contains(&message.message_id_hex));
        }
        self.clear_terminal_local_group_deletion_frontiers(effects)?;
        // Reconcile transport routes once after the batch drains instead of per
        // membership-changing event. This installs a join's current route and
        // retains any still-live address displaced by a routing rotation.
        let routes_changed = self.refresh_group_routes()?;
        if routes_dirty || routes_changed {
            self.sync_runtime_groups().await?;
        }
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.drain_epoch_stall_escalations(&mut summary);
        Ok(summary)
    }

    /// Observe group events the engine applied as a side effect of an outbound
    /// send and buffer them for the account worker to broadcast.
    ///
    /// A send that lands while inbound convergence input is retained folds the
    /// retained commits before publishing, so its effects can carry peer
    /// `GroupStateChanged` / `EpochChanged` events (e.g. a group rename applied
    /// mid-window). Those events never pass through the inbound ingest or
    /// scheduled-convergence seams, so without this pass they reach no runtime
    /// subscriber: storage shows the new state while chat-list and group-state
    /// subscriptions stay silent. Runs the same observe pipeline as those seams
    /// — state group refresh, push-gossip handling, kind-1210 system-row
    /// synthesis (a deterministic upsert) — and merges the result into
    /// `pending_applied_sync_summary`. The caller persists state afterwards.
    pub(crate) async fn observe_send_applied_effects(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        if effects.events.is_empty() {
            return Ok(());
        }
        let display_names = self.app.display_names_by_id()?;
        let mut summary = SyncSummary::default();
        // Synthetic source identity: these events have no single inbound
        // transport message (see `drain_pending_session_events`).
        let source_message_id_hex = String::new();
        let source_received_at = unix_now_seconds();
        let routes_dirty = self
            .observe_account_device_effects(
                effects,
                &display_names,
                &mut summary,
                &source_message_id_hex,
                source_received_at,
                None,
            )
            .await?;
        let routes_changed = self.refresh_group_routes()?;
        if routes_dirty || routes_changed {
            self.sync_runtime_groups().await?;
        }
        self.pending_applied_sync_summary.merge(summary);
        Ok(())
    }

    /// Best-effort wrapper over [`Self::observe_send_applied_effects`] for the
    /// outbound send paths: a projection or route-refresh failure here must
    /// not fail a publish that already completed (or mask a publish error on
    /// the failure path), so it is logged rather than propagated.
    pub(crate) async fn observe_send_applied_effects_best_effort(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) {
        if let Err(_err) = self.observe_send_applied_effects(effects).await {
            tracing::warn!(
                target: "marmot_app::messages",
                method = "observe_send_applied_effects",
                error_code = "send_applied_observe_failed",
                "failed to observe group events applied during a send"
            );
        }
    }

    /// Drain durable effects retained outside their originating operation.
    /// Called by the account worker after commands and before reporting a sync
    /// error so the corresponding live events are never stranded.
    pub(crate) fn take_pending_applied_sync_summary(&mut self) -> SyncSummary {
        std::mem::take(&mut self.pending_applied_sync_summary)
    }

    /// Keep effects that completed before a later sync failure available to the
    /// account worker. The worker broadcasts this buffer before reporting the
    /// error, so durable partial progress is never hidden from live subscribers.
    fn preserve_applied_summary_on_error(
        &mut self,
        summary: SyncSummary,
        error: AppError,
    ) -> Result<SyncSummary, AppError> {
        self.pending_applied_sync_summary.merge(summary);
        Err(error)
    }

    /// Build an [`EventGroupProjection`] for `group_id`, returning `None` if any
    /// component lookup fails (e.g. the group is quarantined and not live).
    /// Used by the no-inbound drain path where a missing projection must not
    /// abort processing.
    fn event_group_projection_best_effort<'a>(
        &self,
        group_id: &cgka_traits::GroupId,
        group_metadata: Option<&'a cgka_traits::group::Group>,
    ) -> Option<EventGroupProjection<'a>> {
        #[cfg(test)]
        if self.force_event_group_projection_unavailable {
            return None;
        }
        let nostr_routing = self.nostr_routing_for_group(group_id).ok()?;
        Some(EventGroupProjection {
            nostr_routing,
            group_metadata,
            profile: self.profile_for_group(group_id),
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
        loop {
            let delivery = self.receive_next_delivery().await?;
            let summary = self.ingest_received_delivery(delivery).await?;
            if summary.joined_groups.is_empty()
                && summary.messages.is_empty()
                && summary.events.is_empty()
                && summary.epoch_stall_escalations.is_empty()
                && self.pending_convergence_groups.is_empty()
                && !self.epoch_backfill_pending
            {
                continue;
            }
            return Ok(summary);
        }
    }

    /// Wait only for the next non-echo, non-duplicate transport delivery.
    ///
    /// The account worker selects this transport-only receive phase against
    /// commands. Once a delivery is returned, it calls
    /// [`Self::ingest_received_delivery`] outside the `select!`, so durable
    /// engine ingest, incidental publish, and app projection cannot be dropped
    /// halfway through when a command arrives.
    pub(crate) async fn receive_next_delivery(
        &mut self,
    ) -> Result<cgka_traits::TransportDelivery, AppError> {
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
            remember_seen_event(&mut seen, &mut self.state, event_id);
            return Ok(delivery);
        }
    }

    pub(crate) async fn ingest_received_delivery(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
    ) -> Result<SyncSummary, AppError> {
        let display_names = self.app.display_names_by_id()?;
        let mut summary = SyncSummary::default();
        let routes_dirty = self
            .ingest_delivery(delivery, &display_names, &mut summary)
            .await?;
        let routes_changed = self.refresh_group_routes()?;
        if routes_dirty || routes_changed {
            self.sync_runtime_groups().await?;
        }
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        self.drain_epoch_stall_escalations(&mut summary);
        Ok(summary)
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
        // Forensic drain accounting: wall-clock span, count of deliveries
        // actually ingested (echoes and already-seen duplicates are skipped and
        // not counted), and the durable cursor before/after so an analyzer can
        // compare the persisted floor against the ingested `created_at`s.
        let drain_started = std::time::Instant::now();
        let cursor_before_secs = self.state.last_transport_timestamp;
        let mut deliveries: u64 = 0;
        let mut routes_dirty = false;

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
                Ok(Err(error)) => {
                    return self.preserve_applied_summary_on_error(summary, error.into());
                }
                Err(_) => break,
            };
            let event_id = hex::encode(delivery.message.id.as_slice());
            if is_own_relay_echo(&delivery, &local_account_id_hex, &seen) {
                continue;
            }
            if seen.contains(&event_id) {
                continue;
            }
            remember_seen_event(&mut seen, &mut self.state, event_id);
            let mut delivery_summary = SyncSummary::default();
            let delivery_routes_dirty = match self
                .ingest_delivery(delivery, &display_names, &mut delivery_summary)
                .await
            {
                Ok(routes_dirty) => routes_dirty,
                Err(error) => return self.preserve_applied_summary_on_error(summary, error),
            };
            routes_dirty |= delivery_routes_dirty;
            deliveries = deliveries.saturating_add(1);
            summary.merge(delivery_summary);
            // A later delivery may fail after these effects are already durable.
            // Persist the matching seen-id/cursor state at the same per-delivery
            // boundary used by the live tail instead of deferring every advance
            // to the end of the drain. Membership-changing ingest already saves
            // before its route-refresh await.
            if !delivery_routes_dirty
                && let Err(error) =
                    self.save_state_with_pending_local_group_deletion_frontier_clears()
            {
                return self.preserve_applied_summary_on_error(summary, error);
            }
            if cfg!(feature = "test-policy-overrides")
                && self
                    .app
                    .config
                    .dev_fail_sync_after_messages
                    .is_some_and(|limit| summary.messages.len() as u64 >= limit)
            {
                return self.preserve_applied_summary_on_error(
                    summary,
                    AppError::BlockingTask("injected catch-up drain failure".to_owned()),
                );
            }
        }

        let routes_changed = match self.refresh_group_routes() {
            Ok(routes_changed) => routes_changed,
            Err(error) => return self.preserve_applied_summary_on_error(summary, error),
        };
        if (routes_dirty || routes_changed)
            && let Err(error) = self.sync_runtime_groups().await
        {
            return self.preserve_applied_summary_on_error(summary, error);
        }
        self.record_sync_drain(
            drain_started.elapsed().as_millis() as u64,
            deliveries,
            cursor_before_secs,
            self.state.last_transport_timestamp,
        );
        if let Err(error) = self.save_state_with_pending_local_group_deletion_frontier_clears() {
            return self.preserve_applied_summary_on_error(summary, error);
        }
        Ok(summary)
    }

    async fn ingest_delivery(
        &mut self,
        delivery: cgka_traits::TransportDelivery,
        display_names: &HashMap<String, String>,
        summary: &mut SyncSummary,
    ) -> Result<bool, AppError> {
        let source_message_id_hex = hex::encode(delivery.message.id.as_slice());
        let outer_transport_at = delivery.message.timestamp.0;
        let source_received_at = delivery.received_at.0;
        let group_id_hint = delivery.group_id_hint.clone();
        let effects = self.runtime.ingest_delivery(delivery).await?;
        let publish_error = fail_if_publish_failed(&effects.effects).err();
        self.remember_buffered_convergence_outcome(&effects.outcome);
        self.remember_pending_convergence_groups(&effects.effects);
        self.arm_recovery_from_effects(&effects.effects);
        self.remember_transport_cursor(outer_transport_at);
        self.detect_epoch_stall(group_id_hint, &source_message_id_hex, &effects.outcome);
        let routes_dirty = self
            .observe_account_device_effects(
                &effects.effects,
                display_names,
                summary,
                &source_message_id_hex,
                source_received_at,
                Some(outer_transport_at),
            )
            .await?;
        if routes_dirty {
            // The engine join/leave is already durable; persist the matching
            // app-state projection (a fresh join's pending invite row) before
            // the callers' route-refresh network awaits. A process exit in
            // that window would otherwise tear the durable membership change
            // from its app-state row, and the consumed welcome is never
            // re-emitted to repair it.
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        }

        // Publishing here is incidental work triggered by the inbound
        // delivery. A hard publish failure may roll that pending commit back,
        // but it must not discard the already-authenticated inbound message or
        // roster effects. They are projected above and the transport cursor is
        // allowed to advance; the failed work remains represented by the
        // engine's rollback/failure effects rather than turning relay
        // redelivery into an AlreadySeen projection hole.
        if let Some(err) = publish_error {
            tracing::warn!(
                target: "marmot_app",
                method = "ingest_delivery",
                error_kind = err.privacy_safe_kind(),
                "incidental auto-publish failed after inbound effects were projected"
            );
        }
        Ok(routes_dirty)
    }

    /// Feed an unavailable group delivery to the epoch-stall detector.
    /// Transport-deferred input arms a backfill after the stalled-epoch
    /// threshold; resource refusal arms it immediately because it directly
    /// proves the fetched history was not fully retained. Repeated arming that
    /// never recovers the group escalates onto the next successful sync summary,
    /// the seam every worker surface already publishes. Only observed under
    /// `CursorPersistence::Advance`: a `Frozen` wake-collection pass must not
    /// own recovery, and the main app sees the same evidence on its own next
    /// sync.
    fn detect_epoch_stall(
        &mut self,
        group_id_hint: Option<cgka_traits::GroupId>,
        message_id_hex: &str,
        outcome: &IngestOutcome,
    ) {
        if self.app.cursor_persistence() != CursorPersistence::Advance {
            return;
        }
        let Some(group_id) = group_id_hint else {
            return;
        };
        // A group we cannot resolve (unknown or quarantined) has its own recovery
        // surface; do not track it here.
        let Ok(record) = self.runtime.group_record(&group_id) else {
            return;
        };
        let decision = match outcome {
            IngestOutcome::TransportDeferred { .. } => self.epoch_stall.observe_undecryptable(
                group_id.clone(),
                message_id_hex.to_owned(),
                record.epoch,
            ),
            IngestOutcome::ResourceRefused { .. } => self
                .epoch_stall
                .observe_resource_refusal(group_id.clone(), record.epoch),
            // Any other outcome carries no stall evidence, but it does tell the
            // detector where this device now sits: a tracked group that leaves an
            // epoch without arming at it has stopped failing to catch up, which
            // ends its escalation run.
            _ => {
                self.epoch_stall
                    .observe_group_epoch(&group_id, record.epoch);
                BackfillDecision::Skip
            }
        };
        self.apply_backfill_decision(&group_id, record.epoch.0, decision);
    }

    /// Apply an epoch-stall backfill decision: arm the replay, and record an
    /// escalation the detector raises.
    ///
    /// Every site that takes a [`BackfillDecision`] must route it through here.
    /// The detector latches `escalated` when it raises
    /// [`BackfillDecision::ArmAndEscalate`], so it raises that decision exactly
    /// once per unrecovered run. That makes reporting exactly-once by
    /// construction rather than by caller discipline: the escalation lands in
    /// `pending_epoch_stall_escalations` instead of on whatever [`SyncSummary`]
    /// the calling pass is building, so a later `?` on that pass cannot drop it
    /// — it rides out on the next seam that returns `Ok` (see
    /// [`Self::drain_epoch_stall_escalations`]).
    pub(crate) fn apply_backfill_decision(
        &mut self,
        group_id: &cgka_traits::GroupId,
        stalled_epoch: u64,
        decision: BackfillDecision,
    ) {
        if decision.arms_backfill() {
            // Record the arm decision before the replay side effect runs (the
            // worker seam calls run_pending_epoch_backfill after this returns).
            // Best-effort, fire-and-forget: recording can never block or fail
            // the backfill.
            self.record_epoch_stall_backfill_armed(group_id, stalled_epoch);
            self.epoch_backfill_pending = true;
        }
        if let BackfillDecision::ArmAndEscalate { arms } = decision {
            // The replay is armed above regardless: escalating reports that
            // replay alone is not repairing this group, it does not replace the
            // attempt. The stronger repair (key-package rotation plus a full
            // re-activation) publishes new key material, so it stays the app's
            // decision — MDK reports the condition and names the repair.
            tracing::warn!(
                target: "marmot_app::epoch_stall",
                method = "apply_backfill_decision",
                arms,
                arm_threshold = self.epoch_stall.escalation_arm_threshold(),
                "epoch-gap backfill armed repeatedly without recovering a group; escalating"
            );
            self.record_epoch_stall_backfill_escalated(group_id, stalled_epoch, arms);
            self.pending_epoch_stall_escalations
                .push(crate::EpochStallEscalation {
                    group_id: group_id.clone(),
                    stalled_epoch,
                    arms,
                });
        }
    }

    /// Move every recorded escalation onto the summary a seam is about to
    /// return.
    ///
    /// Call this as the LAST step before `Ok(summary)`, at every outermost seam
    /// — the ones whose `Ok` is handed to a caller rather than followed by more
    /// fallible work. An interior `?` returns before the move runs, so the stash
    /// simply rides the next successful seam instead of being lost with the
    /// failed pass's summary. Moving (not copying) is what keeps delivery
    /// exactly-once. Because the stash is shared, a seam that omits this call
    /// *defers* delivery to the next seam that does; it does not lose it.
    ///
    /// One nested case needs care: [`Self::drain_pending_session_events`] drains
    /// while nested inside `sync_inner`, so its escalations leave the stash and
    /// ride `summary` from the merge onwards. Nothing fallible may be inserted
    /// between that merge and `sync_inner`'s `Ok` — past the merge they sit on a
    /// local summary again, and a `?` would take them down with the pass. (Which
    /// also makes `sync_inner`'s own call belt-and-braces rather than
    /// load-bearing: the nested drain has already emptied the stash.)
    ///
    /// Residual: the receive arm drops the whole client on a failed pass, so the
    /// replacement starts with an empty stash and a fresh detector; the
    /// `epoch_stall_backfill_escalated` row recorded just before the push is the
    /// only trace that outlives them, and only where audit logging is on (opt-in,
    /// off by default). Re-escalating then costs a whole fresh three-arm run, and
    /// only its first arm can land at the epoch the device already sits at — an
    /// arm at an epoch already fired at is a `Skip` — so arms two and three each
    /// need the local epoch to genuinely advance. A group that is still advancing
    /// therefore re-escalates roughly two epochs later, delayed rather than lost;
    /// a group frozen at one local epoch arms once and never escalates again.
    /// That second case is a pre-existing blind spot of the arm counter, not a
    /// rebuild artifact — a group frozen from its first arm never escalates in a
    /// fresh process either — and is tracked for a follow-up.
    fn drain_epoch_stall_escalations(&mut self, summary: &mut SyncSummary) {
        summary
            .epoch_stall_escalations
            .append(&mut self.pending_epoch_stall_escalations);
    }

    /// Whether an epoch-gap backfill is armed and awaiting its replay. Read by
    /// the account worker to schedule a forensic audit-tracker upload for the
    /// just-recorded `epoch_stall_backfill_armed` row without poking the field.
    pub(crate) fn has_pending_epoch_backfill(&self) -> bool {
        self.epoch_backfill_pending
    }

    /// Consume a pending epoch-gap replay after an unfloored transport
    /// activation has succeeded. Shared by the automatic replay path and the
    /// explicit full-history repair path, which already performed the same
    /// account-wide replay and must not issue it twice.
    pub(crate) fn finish_pending_epoch_backfill_after_replay(&mut self) {
        if !self.epoch_backfill_pending {
            return;
        }
        self.epoch_stall.mark_replayed();
        self.epoch_backfill_pending = false;
    }

    /// Recover any group that stalled below its live epoch during ingest by
    /// replaying the account's full transport history (`since = None`). One replay
    /// re-fetches every group, so the detector collapses simultaneously-stuck
    /// groups into a single replay. A no-op when nothing stalled.
    pub(crate) async fn run_pending_epoch_backfill(&mut self) -> Result<(), AppError> {
        if !self.epoch_backfill_pending {
            return Ok(());
        }
        self.runtime.activate_transport(None).await?;
        self.finish_pending_epoch_backfill_after_replay();
        Ok(())
    }

    /// Explicit account-wide repair for a host that has independent evidence
    /// its incremental cursor may be incomplete (for example, a long-offline
    /// participant that has no new traffic capable of arming epoch-stall
    /// detection). Unlike the automatic detector path, this is a caller-owned
    /// operation and therefore does not mutate the detector's debounce state.
    pub(crate) async fn repair_full_history(&mut self) -> Result<SyncSummary, AppError> {
        if self.refresh_group_routes()? {
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        }
        // Caller-directed repair is a fresh transport preparation, not an
        // assumption that startup ordering already installed the signer and
        // current group subscriptions.
        self.relay_plane
            .set_transport_signer(self.transport_signer.clone())
            .await;
        self.runtime.activate_transport(None).await?;
        self.sync_runtime_groups().await?;
        self.record_subscription_rebuild(None).await;
        let mut summary = self.sync_sdk_relay().await?;
        let drained = match self.drain_pending_session_events().await {
            Ok(drained) => drained,
            Err(error) => return self.preserve_applied_summary_on_error(summary, error),
        };
        summary.merge(drained);
        Ok(summary)
    }

    pub(crate) async fn advance_convergence_after_runtime_sync(
        &mut self,
        group_id: &cgka_traits::GroupId,
    ) -> Result<SyncSummary, AppError> {
        // The account worker refreshes transport groups once for the scheduled
        // convergence batch before calling this per-group path.
        let effects = self.runtime.advance_convergence(group_id).await?;
        fail_if_publish_failed(&effects)?;
        self.remember_pending_convergence_groups(&effects);
        let mut summary = SyncSummary::default();
        self.arm_recovery_from_effects(&effects);
        self.remember_published_reports(&effects);
        let finalize_updates = self.finalize_published_app_message_source_retention(&effects)?;
        let publish_new_message_notification =
            effects.published_app_messages.iter().any(|published| {
                let group_id_hex = hex::encode(published.group_id.as_slice());
                self.app
                    .reaction_target(&self.state.label, &group_id_hex, &published.app_event_id)
                    .ok()
                    .flatten()
                    .is_some_and(|message| {
                        message.kind == MARMOT_APP_EVENT_KIND_CHAT
                            && !message.deleted
                            && !message.invalidated
                    })
            });
        self.refresh_group(group_id);

        let display_names = self.app.display_names_by_id()?;
        summary.projection_updates.extend(finalize_updates);
        let source_message_id_hex = String::new();
        let source_received_at = unix_now_seconds();
        let routes_dirty = self
            .observe_account_device_effects(
                &effects,
                &display_names,
                &mut summary,
                &source_message_id_hex,
                source_received_at,
                None,
            )
            .await?;
        let routes_changed = self.refresh_group_routes()?;
        if routes_dirty || routes_changed {
            self.sync_runtime_groups().await?;
        }
        self.prune_plaintext_retention_for_group(group_id)?;
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        if publish_new_message_notification {
            self.publish_notification_trigger_best_effort(
                group_id,
                notifications::NotificationTrigger::NewMessage,
            )
            .await;
        }
        self.drain_epoch_stall_escalations(&mut summary);
        Ok(summary)
    }

    /// Snapshot each affected group's durable local-delete frontier before any
    /// event in the effects batch mutates projection state. Every event is then
    /// classified against this same authority, independent of batch order.
    fn local_group_deletion_frontiers_at_batch_start(
        &self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<HashMap<String, u64>, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let mut frontiers = HashMap::new();
        let mut seen_group_ids = HashSet::new();
        for event in &effects.events {
            let Some(group_id) = event_group_id(event) else {
                continue;
            };
            let group_id_hex = hex::encode(group_id.as_slice());
            if !seen_group_ids.insert(group_id_hex.clone()) {
                continue;
            }
            if let Some(frontier) = storage.local_group_deletion_frontier(&group_id_hex)? {
                frontiers.insert(group_id_hex, frontier);
            }
        }
        Ok(frontiers)
    }

    fn local_deleted_group_event_crosses_frontier(
        &self,
        event: &cgka_traits::engine::GroupEvent,
        frontier: u64,
        source_message_id_hex: &str,
        source_received_at: u64,
    ) -> Result<bool, AppError> {
        let Some(group_id) = event_group_id(event) else {
            return Ok(false);
        };
        if self
            .runtime
            .group_record(group_id)
            .is_ok_and(|group| group.removed || group.disbanded.is_some())
        {
            return Ok(false);
        }
        if matches!(event, cgka_traits::engine::GroupEvent::GroupJoined { .. }) {
            return Ok(true);
        }
        let cgka_traits::engine::GroupEvent::MessageReceived {
            group_id,
            message_id,
            sender,
            epoch,
            payload,
            retention,
        } = event
        else {
            return Ok(false);
        };
        // One delivery can release buffered effects for several groups, so its
        // outer timestamp is not valid provenance for every event in the batch.
        // The authenticated engine message id resolves to a durable local ingress
        // order. Strict app decoding then prevents malformed or sender-mismatched
        // payloads from resurrecting a deliberately hidden group.
        let sender_hex = hex::encode(sender.as_slice());
        let Some(message) = decode_received_event(
            payload,
            &sender_hex,
            None,
            group_id,
            epoch.0,
            *retention,
            source_message_id_hex,
            source_received_at,
            None,
            self.app.allow_loopback_blob_endpoints(),
        ) else {
            return Ok(false);
        };
        if message.kind != MARMOT_APP_EVENT_KIND_CHAT {
            return Ok(false);
        }
        let group_id_hex = hex::encode(group_id.as_slice());
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .local_group_deletion_message_is_newer_than(&group_id_hex, message_id, frontier)?)
    }

    fn prepare_local_group_deletion_frontier_clear(
        &mut self,
        event: &cgka_traits::engine::GroupEvent,
        frontier: u64,
    ) -> Result<bool, AppError> {
        let Some(group_id) = event_group_id(event) else {
            return Ok(false);
        };
        if !self.adopt_local_deleted_group_prior_routes(group_id)? {
            return Ok(false);
        }
        self.pending_local_group_deletion_frontier_clears
            .entry(hex::encode(group_id.as_slice()))
            .or_insert(frontier);
        Ok(true)
    }

    fn project_received_message(
        &mut self,
        message: crate::ReceivedMessage,
        group_metadata: Option<&cgka_traits::Group>,
        summary: &mut SyncSummary,
    ) -> Result<Option<String>, AppError> {
        if notifications::is_push_gossip_kind(message.kind) {
            let ingest_result = group_metadata
                .map(|group| group.protocol_profile)
                .ok_or_else(|| {
                    AppError::InvalidPushGossip("group profile unavailable for push gossip".into())
                })
                .and_then(|profile| {
                    self.runtime
                        .members(&message.group_id)
                        .map_err(AppError::from)
                        .map(|members| {
                            (
                                profile,
                                members
                                    .into_iter()
                                    .map(|member| hex::encode(member.id.as_slice()))
                                    .collect::<Vec<_>>(),
                            )
                        })
                })
                .and_then(|(profile, active_member_ids)| {
                    self.app.ingest_push_gossip_message(
                        &self.state.label,
                        &message,
                        &active_member_ids,
                        profile,
                    )
                });
            if let Err(err) = ingest_result {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "project_received_message",
                    error_kind = err.privacy_safe_kind(),
                    "ignoring malformed push token gossip",
                );
            }
            return Ok(Some(message.message_id_hex));
        }
        let retains_encrypted_media = message.kind == MARMOT_APP_EVENT_KIND_CHAT
            && media_imeta_tags_are_valid(&message.tags, self.app.allow_loopback_blob_endpoints());
        self.app.remember_directory_message_sender(&message)?;
        let moderation_grant = message.kind == MARMOT_APP_EVENT_KIND_DELETE
            && self.delete_moderation_grant(&message.group_id, &message.sender);
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
            retention: message.retention,
            recorded_at: Some(message.recorded_at),
            origin_commit_id: None,
            moderation_grant,
        };
        let projection_update = self.app.record_account_app_event_at(
            &self.state.label,
            &message_projection,
            message.received_at,
        )?;
        if retains_encrypted_media
            && self
                .remember_current_encrypted_media_secret(&message.group_id)
                .is_err()
        {
            tracing::warn!(
                target: "marmot_app::media",
                method = "project_received_message",
                error_code = "encrypted_media_secret_cache_skipped",
                "failed to cache encrypted media source epoch secret",
            );
        }
        summary.projection_updates.push(projection_update);
        self.prune_plaintext_retention_for_group(&message.group_id)?;
        Ok(None)
    }

    fn prepare_pending_application_event_ack(&mut self, event: &cgka_traits::engine::GroupEvent) {
        if let cgka_traits::engine::GroupEvent::MessageReceived { message_id, .. } = event {
            self.pending_application_event_acks
                .insert(message_id.clone());
        }
    }

    pub(crate) fn save_state_with_pending_local_group_deletion_frontier_clears(
        &mut self,
    ) -> Result<(), AppError> {
        let frontiers_to_clear = self
            .pending_local_group_deletion_frontier_clears
            .iter()
            .map(|(group_id_hex, frontier)| (group_id_hex.clone(), *frontier))
            .collect::<Vec<_>>();
        let application_event_ids_to_ack = self
            .pending_application_event_acks
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        self.app
            .save_state_clearing_local_group_deletion_frontiers_and_acking_application_events(
                &self.state,
                &frontiers_to_clear,
                &application_event_ids_to_ack,
            )?;
        self.pending_local_group_deletion_frontier_clears.clear();
        self.pending_application_event_acks.clear();
        Ok(())
    }
    async fn observe_account_device_effects(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
        display_names: &HashMap<String, String>,
        summary: &mut SyncSummary,
        source_message_id_hex: &str,
        source_received_at: u64,
        outer_transport_at: Option<u64>,
    ) -> Result<bool, AppError> {
        // MLS member ids in this design are the Nostr account pubkey hex, so a
        // membership change whose subject matches the local account id hex is
        // the local account leaving / being removed (or, for joins, returning).
        let local_account_id_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let mut routes_dirty = false;
        // #760: collect push-gossip ids and strip them from `summary.messages` in
        // ONE pass after the loop. The previous per-message `retain` was O(n) per
        // gossip event → O(n²) over a batch a relay could flood with kind-448s.
        let mut gossip_message_ids: HashSet<String> = HashSet::new();
        let local_group_deletion_frontiers =
            self.local_group_deletion_frontiers_at_batch_start(effects)?;
        for event in &effects.events {
            let batch_start_frontier = event_group_id(event)
                .and_then(|group_id| {
                    local_group_deletion_frontiers.get(&hex::encode(group_id.as_slice()))
                })
                .copied();
            let crosses_frontier = match batch_start_frontier {
                Some(frontier) => self.local_deleted_group_event_crosses_frontier(
                    event,
                    frontier,
                    source_message_id_hex,
                    source_received_at,
                )?,
                None => false,
            };
            if !crosses_frontier
                && let Some(changed) =
                    self.suppress_local_deleted_group_event(event, batch_start_frontier)?
            {
                routes_dirty |= changed;
                self.prepare_pending_application_event_ack(event);
                continue;
            }
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
                        profile: self.profile_for_group(group_id),
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
                source_received_at,
                outer_transport_at,
                self.app.allow_loopback_blob_endpoints(),
            ) && let Some(gossip_message_id) =
                self.project_received_message(message, group_metadata.as_ref(), summary)?
            {
                gossip_message_ids.insert(gossip_message_id);
            }
            let updated_group =
                event_group_id(event).and_then(|group_id| self.state_group_record(group_id));
            self.audit_observed_group_event(
                event,
                previous_group.as_ref(),
                updated_group.as_ref(),
                source_message_id_hex,
            );
            // Timeline invalidation dispatch: `AppMessageInvalidated` withdraws
            // the delivered source row; `GroupStateInvalidated` withdraws every
            // kind-1210 system row stamped with the superseded commit's
            // `origin_commit_id`. The engine pairs `GroupStateInvalidated` with
            // both commit-rollback seams (`ForkRecovered` on the direct
            // staged-commit seam, `CommitRolledBack` on the stored-convergence
            // seam), so those events no longer trigger tombstoning here — the
            // explicit withdrawal event is the single authoritative signal and
            // one rollback produces exactly one projection update.
            if let Some(projection_update) = self
                .app
                .projection_update_for_invalidation_event(&self.state.label, event)?
            {
                summary.projection_updates.push(projection_update);
            }
            if self.state.groups.len() != before {
                routes_dirty = true;
            }
            if let cgka_traits::engine::GroupEvent::GroupStateChanged {
                group_id, change, ..
            } = event
                && let Some((member, membership)) = member_departure(change)
            {
                let group_id_hex = hex::encode(group_id.as_slice());
                let member_id_hex = hex::encode(member.as_slice());
                let _ = self.app.remove_group_push_tokens_for_member(
                    &self.state.label,
                    &group_id_hex,
                    &member_id_hex,
                );
                // Only the local account leaving / being removed suppresses our
                // own unread aggregate for the group; a peer departure must not.
                // The recorded membership distinguishes a voluntary `Left` from
                // an involuntary `Removed` so the chat list can tell them apart.
                // This projection write is the source of truth for the account
                // unread aggregate, so propagate its error (matching the nearby
                // timeline/message projection writes) instead of swallowing it:
                // silently leaving the flag stale would keep
                // `account_unread_total()` returning an inflated badge after a
                // self-removal that sync otherwise reports as successful.
                if member_id_hex.eq_ignore_ascii_case(&local_account_id_hex) {
                    self.app.set_group_self_membership(
                        &self.state.label,
                        &group_id_hex,
                        membership,
                    )?;
                }
            }
            if let cgka_traits::engine::GroupEvent::GroupStateChanged {
                group_id,
                change: cgka_traits::engine::GroupStateChange::GroupDisbanded,
                ..
            } = event
            {
                routes_dirty = true;
                let group_id_hex = hex::encode(group_id.as_slice());
                // Terminal groups never advertise notification destinations
                // again. Queue the current registration's removal and discard
                // every cached peer token immediately; publishing the removal
                // rumor remains restart-safe in the normal outbox.
                let _ = self.queue_current_push_registration_removal_for_group(group_id);
                let _ =
                    self.app
                        .remove_stale_group_push_tokens(&self.state.label, &group_id_hex, &[]);
            }
            // A (re-)join or create restores the local account's membership so a
            // re-add after removal un-suppresses the group's unread count. Same
            // source-of-truth write as the departure path above: propagate the
            // error rather than swallow it.
            if let cgka_traits::engine::GroupEvent::GroupJoined { group_id, .. }
            | cgka_traits::engine::GroupEvent::GroupCreated { group_id } = event
            {
                let group_id_hex = hex::encode(group_id.as_slice());
                self.app.set_group_self_membership(
                    &self.state.label,
                    &group_id_hex,
                    SelfMembership::Member,
                )?;
            }
            let can_ack_application_event = if crosses_frontier {
                self.prepare_local_group_deletion_frontier_clear(
                    event,
                    batch_start_frontier.expect("crossing event has a frontier"),
                )?
            } else {
                true
            };
            if can_ack_application_event {
                self.prepare_pending_application_event_ack(event);
            }
        }
        self.clear_terminal_local_group_deletion_frontiers(effects)?;
        // #760: strip all collected push-gossip messages in one pass.
        if !gossip_message_ids.is_empty() {
            summary
                .messages
                .retain(|candidate| !gossip_message_ids.contains(&candidate.message_id_hex));
        }
        // Synthesize durable kind-1210 system rows from authenticated state
        // changes (peer commits, auto-commits, and scheduled convergence).
        let system_updates = self.project_group_system_rows(&effects.events, source_received_at);
        summary.projection_updates.extend(system_updates);
        Ok(routes_dirty)
    }

    /// Advance the persisted transport cursor from an inbound message —
    /// unless this runtime was constructed with
    /// [`CursorPersistence::Frozen`](crate::CursorPersistence), in which case
    /// this is a no-op and the cursor stays at the value loaded from the store.
    ///
    /// `timestamp` is the sender-controlled Nostr `created_at` of the outer
    /// kind-445 event and is never validated upstream. The cursor is a
    /// monotonic-max, persisted value that becomes a relay-level `since` filter
    /// on subscription rebuild and account open, so an unbounded far-future
    /// value would push `since` into the future and silently halt all message
    /// reception across restarts (mdk#182). Clamp the advance to local
    /// wall-clock plus a bounded skew so a hostile or clock-skewed sender can
    /// move the cursor no further than `now + TRANSPORT_CURSOR_MAX_FUTURE_SKEW`.
    fn remember_transport_cursor(&mut self, timestamp: u64) {
        self.state.last_transport_timestamp = next_transport_cursor(
            self.app.cursor_persistence(),
            self.state.last_transport_timestamp,
            timestamp,
            unix_now_seconds(),
            TRANSPORT_CURSOR_MAX_FUTURE_SKEW.as_secs(),
        );
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

/// Apply the runtime's [`CursorPersistence`] policy to a candidate inbound
/// timestamp: the policy seam behind `remember_transport_cursor`.
///
/// Under [`CursorPersistence::Frozen`] (the wake-collection posture — see the
/// enum docs in `config.rs` for the full semantics) the cursor is returned
/// unchanged, `None` included: the pass still ingests, decrypts, and projects
/// everything, but the durable `since` floor never ratchets, so `save_state`
/// writes back the loaded value and the storage-side clamp-then-max merge
/// keeps a concurrent `Advance` runtime's progress intact. Deliberate
/// consequences visible in the forensic audit rows: a frozen pass's
/// `sync_drain` records `cursor_before == cursor_after`, and its
/// `subscription_rebuild` rows keep recording the loaded floor — exactly the
/// evidence that a wake pass did not move the floor.
///
/// Under [`CursorPersistence::Advance`] this delegates to
/// [`clamped_transport_cursor`] unchanged.
fn next_transport_cursor(
    policy: crate::CursorPersistence,
    current: Option<u64>,
    candidate: u64,
    now: u64,
    max_future_skew_secs: u64,
) -> Option<u64> {
    match policy {
        crate::CursorPersistence::Frozen => current,
        crate::CursorPersistence::Advance => Some(clamped_transport_cursor(
            current,
            candidate,
            now,
            max_future_skew_secs,
        )),
    }
}

/// Compute the next persisted transport cursor from a candidate inbound
/// timestamp.
///
/// `candidate` is the sender-controlled Nostr `created_at` and is untrusted. It
/// is first clamped to `now + max_future_skew_secs` so a far-future value
/// cannot poison the cursor (which would push the relay `since` filter into the
/// future and silently halt message reception — mdk#182), then folded
/// into the existing monotonic-max cursor. The existing `current` is clamped
/// the same way before the max, so a cursor that was already poisoned before
/// this guard existed is *healed* back down to `now + max_future_skew_secs`
/// here instead of being preserved forever by the monotonic max. A benign
/// in-range timestamp is unaffected; the skew margin tolerates ordinary sender
/// clock drift.
///
/// The clamp itself is [`storage_sqlite::clamp_to_max_future_skew`] — the one
/// definition shared with the save-time durable-cursor merge in
/// `save_account_projection_state`, so ingest and persistence can never
/// disagree on the ceiling.
fn clamped_transport_cursor(
    current: Option<u64>,
    candidate: u64,
    now: u64,
    max_future_skew_secs: u64,
) -> u64 {
    let clamped = clamp_to_max_future_skew(candidate, now, max_future_skew_secs);
    current
        .map(|current| clamp_to_max_future_skew(current, now, max_future_skew_secs).max(clamped))
        .unwrap_or(clamped)
}

/// Classify a group state change that ends a member's participation, returning
/// the departing member alongside how that departure should be recorded for the
/// member: a `MemberLeft` self-removal is a voluntary [`SelfMembership::Left`];
/// a `MemberRemoved` eviction by another member is [`SelfMembership::Removed`].
/// Returns `None` for changes that are not departures.
fn member_departure(
    change: &cgka_traits::engine::GroupStateChange,
) -> Option<(&cgka_traits::MemberId, SelfMembership)> {
    use cgka_traits::engine::GroupStateChange;
    match change {
        GroupStateChange::MemberLeft { member } => Some((member, SelfMembership::Left)),
        GroupStateChange::MemberRemoved { member } => Some((member, SelfMembership::Removed)),
        _ => None,
    }
}

#[cfg(test)]
mod membership_change_tests {
    use super::member_departure;
    use crate::SelfMembership;
    use cgka_traits::MemberId;
    use cgka_traits::engine::GroupStateChange;

    #[test]
    fn member_departure_distinguishes_self_leave_from_eviction() {
        let member = MemberId::new(vec![0xaa]);

        // A SelfRemove proposal is a voluntary departure.
        let left = GroupStateChange::MemberLeft {
            member: member.clone(),
        };
        let (subject, membership) = member_departure(&left).expect("MemberLeft is a departure");
        assert_eq!(subject, &member);
        assert_eq!(membership, SelfMembership::Left);

        // An eviction by another member is an involuntary removal.
        let removed = GroupStateChange::MemberRemoved {
            member: member.clone(),
        };
        let (subject, membership) =
            member_departure(&removed).expect("MemberRemoved is a departure");
        assert_eq!(subject, &member);
        assert_eq!(membership, SelfMembership::Removed);
    }

    #[test]
    fn member_departure_ignores_non_departures() {
        let member = MemberId::new(vec![0xaa]);
        let added = GroupStateChange::MemberAdded {
            member: member.clone(),
        };
        let admin = GroupStateChange::AdminAdded { member };
        assert!(member_departure(&added).is_none());
        assert!(member_departure(&admin).is_none());
    }
}

#[cfg(test)]
mod transport_cursor_tests {
    use super::{clamped_transport_cursor, next_transport_cursor};
    use crate::CursorPersistence;

    const SKEW: u64 = 5 * 60;
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn frozen_policy_never_moves_the_cursor() {
        // A wake-collection runtime ingests but must
        // not ratchet the durable floor. Under `Frozen` the cursor is exactly
        // the loaded value regardless of what the delivery carries — a newer
        // in-range timestamp, an older one, or a far-future one.
        let loaded = Some(NOW - 100);
        assert_eq!(
            next_transport_cursor(CursorPersistence::Frozen, loaded, NOW, NOW, SKEW),
            loaded,
            "a newer in-range delivery must not advance a frozen cursor"
        );
        assert_eq!(
            next_transport_cursor(CursorPersistence::Frozen, loaded, NOW - 500, NOW, SKEW),
            loaded,
            "an older delivery must not move a frozen cursor either"
        );
        // A store that has never advanced stays `None`: `Frozen` means "never
        // advance", not "initialize". The save-time merge treats a `None`
        // in-memory side as "keep stored", so this can never wipe a
        // concurrently-advanced durable cursor.
        assert_eq!(
            next_transport_cursor(CursorPersistence::Frozen, None, NOW, NOW, SKEW),
            None,
            "a frozen cursor that never existed must stay absent"
        );
    }

    #[test]
    fn advance_policy_is_the_unchanged_clamped_monotonic_max() {
        // `Advance` is byte-for-byte the historical behavior: delegate to
        // `clamped_transport_cursor` (monotonic max with the mdk#182
        // future-skew clamp and poison heal, pinned by the tests below).
        assert_eq!(
            next_transport_cursor(CursorPersistence::Advance, Some(NOW - 100), NOW, NOW, SKEW),
            Some(NOW),
            "an in-range delivery advances the cursor under Advance"
        );
        assert_eq!(
            next_transport_cursor(CursorPersistence::Advance, None, NOW, NOW, SKEW),
            Some(NOW),
            "a first delivery initializes the cursor under Advance"
        );
        let poisoned = NOW + 10 * 365 * 24 * 60 * 60;
        assert_eq!(
            next_transport_cursor(CursorPersistence::Advance, Some(NOW), poisoned, NOW, SKEW),
            Some(NOW + SKEW),
            "the future-skew clamp still bounds a hostile created_at"
        );
    }

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
        // future and halt reception (mdk#182).
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
        // (mdk#182 — blocking adversarial finding).
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
