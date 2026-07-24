use std::collections::{HashMap, HashSet};

use cgka_traits::TransportAdapter;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE};
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use storage_sqlite::clamp_to_max_future_skew;
use tokio::time::timeout;
use transport_nostr_peeler::NostrTransportEvent;

use crate::groups::{EventGroupProjection, event_group_id, fail_if_publish_failed, observe_event};
use crate::media::media_imeta_tags_are_valid;
use crate::notifications;
use crate::{
    AppError, AppGroupAdminPolicyComponent, AppMessageProjection, SDK_DRAIN_WAIT,
    SDK_FIRST_SYNC_WAIT, SelfMembership, SyncSummary, TRANSPORT_CURSOR_MAX_FUTURE_SKEW,
    remember_seen_event, unix_now_seconds,
};

use super::AppClient;
use crate::config::CursorPersistence;

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
        // Reconcile epoch-bounded prior routes before issuing the first relay
        // subscriptions. This makes retirement deterministic even for a quiet
        // group that has no new inbound events after restart.
        if self.refresh_group_routes()? {
            self.app.save_state(&self.state)?;
        }
        let rebuild_since = self
            .relay_plane
            .subscription_rebuild_since(self.state.last_transport_timestamp);
        // Capture the derived `since` floor before it is moved into activation;
        // the forensic `subscription_rebuild` row records it alongside the
        // per-relay registration outcome the activation produces.
        let rebuild_since_secs = rebuild_since.map(|timestamp| timestamp.0);
        self.runtime.activate_transport(rebuild_since).await?;
        self.sync_runtime_groups().await?;
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
    /// one (mdk#426). There is no source delivery here, so events that
    /// reference a not-yet-live (quarantined) group must not abort the drain —
    /// projection lookups are best-effort.
    pub(crate) async fn drain_pending_session_events(&mut self) -> Result<SyncSummary, AppError> {
        let effects = self.runtime.drain().await?;
        // Session open seeds this list from durable queued/convergence input.
        // Preserve that scheduling edge even when hydration emitted no app
        // events; the worker drains this set immediately after startup sync.
        self.remember_pending_convergence_effects(&effects);
        fail_if_publish_failed(&effects)?;
        let mut summary = SyncSummary::default();
        if effects.events.is_empty() {
            return Ok(summary);
        }
        let display_names = self.app.display_names_by_id()?;
        // Synthetic source identity: drained events have no inbound transport
        // message. The empty id signals "no source message"; the audit recorder
        // drops it rather than emitting a schema-invalid `message_ids` entry
        // (see `schema_valid_message_ids`).
        let source_message_id_hex = String::new();
        let source_received_at = unix_now_seconds();
        let mut routes_dirty = false;
        for event in &effects.events {
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
            observe_event(
                &mut self.state,
                &display_names,
                &mut summary,
                event,
                group_projection.as_ref(),
                &source_message_id_hex,
                source_received_at,
                None,
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
                routes_dirty = true;
            }
        }
        // Reconcile transport routes once after the batch drains instead of per
        // membership-changing event. This installs a join's current route and
        // retains any still-live address displaced by a routing rotation.
        let routes_changed = self.refresh_group_routes()?;
        if routes_dirty || routes_changed {
            self.sync_runtime_groups().await?;
        }
        self.app.save_state(&self.state)?;
        Ok(summary)
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
        let nostr_routing = self.nostr_routing_for_group(group_id).ok()?;
        Some(EventGroupProjection {
            nostr_routing,
            group_metadata,
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
        self.app.save_state(&self.state)?;
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
            remember_seen_event(&mut seen, &mut self.state, event_id);
            routes_dirty |= self
                .ingest_delivery(delivery, &display_names, &mut summary)
                .await?;
            deliveries = deliveries.saturating_add(1);
        }

        let routes_changed = self.refresh_group_routes()?;
        if routes_dirty || routes_changed {
            self.sync_runtime_groups().await?;
        }
        self.record_sync_drain(
            drain_started.elapsed().as_millis() as u64,
            deliveries,
            cursor_before_secs,
            self.state.last_transport_timestamp,
        );
        self.app.save_state(&self.state)?;
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
        self.remember_pending_convergence_effects(&effects.effects);
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

    /// Feed an undecryptable group delivery to the epoch-stall detector, arming a
    /// backfill once a group has accumulated enough undecryptable traffic at a
    /// stalled epoch (see [`super::epoch_stall`]). Only observed under
    /// `CursorPersistence::Advance`: a `Frozen` wake-collection pass must not own
    /// recovery, and the main app sees the same evidence on its own next sync.
    fn detect_epoch_stall(
        &mut self,
        group_id_hint: Option<cgka_traits::GroupId>,
        message_id_hex: &str,
        outcome: &IngestOutcome,
    ) {
        if self.app.cursor_persistence() != CursorPersistence::Advance {
            return;
        }
        if !matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::PeelFailed
            }
        ) {
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
        if self.epoch_stall.observe_undecryptable(
            group_id.clone(),
            message_id_hex.to_owned(),
            record.epoch,
        ) {
            // Record the arm decision before the replay side effect runs (the
            // worker seam calls run_pending_epoch_backfill after this returns).
            // Best-effort, fire-and-forget: recording can never block or fail
            // the backfill.
            self.record_epoch_stall_backfill_armed(&group_id, record.epoch.0);
            self.epoch_backfill_pending = true;
        }
    }

    /// Whether an epoch-gap backfill is armed and awaiting its replay. Read by
    /// the account worker to schedule a forensic audit-tracker upload for the
    /// just-recorded `epoch_stall_backfill_armed` row without poking the field.
    pub(crate) fn has_pending_epoch_backfill(&self) -> bool {
        self.epoch_backfill_pending
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
        self.epoch_stall.mark_replayed();
        self.epoch_backfill_pending = false;
        Ok(())
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
        let finalize_updates = self.finalize_published_app_message_source_retention(&effects)?;
        self.refresh_group(group_id);

        let display_names = self.app.display_names_by_id()?;
        let mut summary = SyncSummary::default();
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
        self.app.save_state(&self.state)?;
        Ok(summary)
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
                source_received_at,
                outer_transport_at,
                self.app.allow_loopback_blob_endpoints(),
            ) {
                if notifications::is_push_gossip_kind(message.kind) {
                    // Bind inbound gossip to the carrying group's authenticated MLS
                    // member set; owner signatures are then verified per record so
                    // a kind 448 may apply other members' records (offline-member
                    // bootstrap) without trusting the relaying sender.
                    let ingest_result = self
                        .runtime
                        .members(&message.group_id)
                        .map_err(AppError::from)
                        .map(|members| {
                            members
                                .into_iter()
                                .map(|member| hex::encode(member.id.as_slice()))
                                .collect::<Vec<_>>()
                        })
                        .and_then(|active_member_ids| {
                            self.app.ingest_push_gossip_message(
                                &self.state.label,
                                &message,
                                &active_member_ids,
                            )
                        });
                    if let Err(err) = ingest_result {
                        tracing::warn!(
                            target: "marmot_app::notifications",
                            method = "ingest_delivery",
                            error_kind = err.privacy_safe_kind(),
                            "ignoring malformed push token gossip",
                        );
                    }
                    gossip_message_ids.insert(message.message_id_hex.clone());
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
                // Evaluated against the signed MLS group state while the
                // delete's epoch context is live, then persisted with the
                // event so later admin-set changes cannot flip the verdict.
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
                    // Received app messages are not synthesized system rows.
                    origin_commit_id: None,
                    moderation_grant,
                };
                let projection_update = self.app.record_account_app_event_at(
                    &self.state.label,
                    &message_projection,
                    message.received_at,
                )?;
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
        }
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
