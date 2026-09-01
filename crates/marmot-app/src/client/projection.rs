use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID, GROUP_MESSAGE_RETENTION_COMPONENT_ID,
    GROUP_PROFILE_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID,
};
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE, MarmotAppEvent as MarmotInnerEvent,
};
use cgka_traits::group::ProtocolProfile;
use cgka_traits::storage::GroupStorage;
use cgka_traits::{GroupId, TransportGroupSubscription};
use storage_sqlite::StoredNostrRoute;

use crate::groups::{EventGroupProjection, GroupConfirmationProjection, add_group, event_group_id};
use crate::{
    AppAgentTextStreamComponent, AppError, AppGroupAdminPolicyComponent,
    AppGroupAvatarUrlComponent, AppGroupEncryptedMediaComponent, AppGroupImageInput,
    AppGroupMessageRetentionComponent, AppGroupNostrRoutingComponent, AppGroupProfileComponent,
    AppGroupRecord, AppMessageProjection, AppPriorNostrRoute, AppTransportRouting,
    SecureDeleteExpiredResult, unix_now_seconds,
};

use super::AppClient;

impl AppClient {
    /// `advance_read_marker`: pre-publish projections must pass `false` so a
    /// failed publish never leaves the group read marker advanced past inbound
    /// unreads or pointing at an invalidated own message (#338); only the
    /// post-publish success projection advances it.
    pub(crate) fn record_local_app_event_projection(
        &self,
        group_id: &GroupId,
        sender: &str,
        event: &MarmotInnerEvent,
        source_message_id_hex: Option<String>,
        source_state: Option<(u64, crate::AppMessageRetentionDecision)>,
        advance_read_marker: bool,
    ) -> Result<crate::AppProjectionUpdate, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let (source_epoch, retention) = source_state
            .map(|(epoch, retention)| (Some(epoch), Some(retention)))
            .unwrap_or((None, None));
        // Stamped on the sender's own store too, so a moderation delete of
        // another member's message survives local reprojection instead of
        // resurrecting the target.
        let moderation_grant = event.kind == MARMOT_APP_EVENT_KIND_DELETE
            && self.delete_moderation_grant(group_id, sender);
        let message_projection = AppMessageProjection {
            message_id_hex: event.id.clone(),
            source_message_id_hex,
            direction: "sent".to_owned(),
            group_id_hex: group_id_hex.clone(),
            sender: sender.to_owned(),
            plaintext: event.content.clone(),
            kind: event.kind,
            tags: event.tags.clone(),
            source_epoch,
            retention,
            recorded_at: Some(event.created_at),
            // Only synthesized kind-1210 system rows carry an origin commit;
            // ordinary sent app events do not.
            origin_commit_id: None,
            moderation_grant,
        };
        // The reconciling post-publish projection (advance_read_marker) runs
        // after group sync, so its recomputed moderation grant supersedes the
        // optimistic pre-send one; the pre-send projection keeps the default
        // freeze so a later no-op re-record can't downgrade it.
        let update = if advance_read_marker {
            self.app
                .record_account_app_event_refreshing_moderation_grant(
                    &self.state.label,
                    &message_projection,
                )?
        } else {
            self.app
                .record_account_app_event(&self.state.label, &message_projection)?
        };
        if advance_read_marker && event.kind == MARMOT_APP_EVENT_KIND_CHAT {
            let read_marker =
                self.app
                    .mark_timeline_message_read(&self.state.label, &group_id_hex, &event.id);
            if let Err(err) = read_marker {
                let error_code = read_marker_error_code(&err);
                tracing::warn!(
                    target: "marmot_app::messages",
                    method = "record_local_app_event_projection",
                    error_code = %error_code,
                    "local read marker update skipped after local send projection",
                );
            }
        }
        Ok(update)
    }

    /// Fail-closed: a group or admin-policy lookup failure yields no grant, so
    /// the delete degrades to self-retraction semantics.
    ///
    /// Accepted trade-off: the grant is evaluated against the admin set this
    /// device sees now (current signed group state), not the admin set as of
    /// the delete's epoch, and it is then frozen at first record. Two devices
    /// that first observe the same delete at different points in their own sync
    /// — one already past an admin-adding commit, the other not, or one while
    /// the group is quarantined — can therefore disagree permanently on whether
    /// it is honored, a milder echo of the cross-device divergence #873
    /// addresses. This is the deliberate fail-closed / frozen posture; an
    /// epoch-anchored admin evaluation is future work.
    pub(crate) fn delete_moderation_grant(&self, group_id: &GroupId, sender_hex: &str) -> bool {
        let Ok(group) = self.runtime.group_record(group_id) else {
            return false;
        };
        let Ok(admins) = self.runtime.admin_pubkeys(group_id) else {
            return false;
        };
        crate::groups::delete_moderation_grant(&group, &admins, sender_hex)
    }

    pub(crate) fn state_group_record(&self, group_id: &GroupId) -> Option<AppGroupRecord> {
        let group_id_hex = hex::encode(group_id.as_slice());
        self.state
            .groups
            .iter()
            .find(|group| group.group_id_hex == group_id_hex)
            .cloned()
    }

    pub(crate) fn has_local_group_deletion_frontier(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .local_group_deletion_frontier(&group_id_hex)?
            .is_some())
    }
    /// Suppress projection updates for an intentionally hidden live group while
    /// keeping its durable transport routes active. `batch_start_frontier`
    /// remains authoritative for the whole effects batch, even if an earlier
    /// fresh event has already rebuilt the in-memory group. A terminal disband
    /// removes both the routes and the now-redundant app-only deletion marker.
    pub(crate) fn suppress_local_deleted_group_event(
        &mut self,
        event: &cgka_traits::engine::GroupEvent,
        batch_start_frontier: Option<u64>,
    ) -> Result<Option<bool>, AppError> {
        let Some(group_id) = event_group_id(event) else {
            return Ok(None);
        };
        if batch_start_frontier.is_none() && self.state_group_record(group_id).is_some() {
            return Ok(None);
        }
        if batch_start_frontier.is_none() && !self.has_local_group_deletion_frontier(group_id)? {
            return Ok(None);
        }
        let terminal = matches!(
            event,
            cgka_traits::engine::GroupEvent::GroupStateChanged {
                change: cgka_traits::engine::GroupStateChange::GroupDisbanded,
                ..
            }
        ) || self
            .runtime
            .group_record(group_id)
            .ok()
            .is_some_and(|group| group.removed || group.disbanded.is_some());
        if terminal {
            return Ok(Some(self.routing.replace_group_routes(
                group_id,
                Vec::<TransportGroupSubscription>::new(),
            )));
        }
        if self.state_group_record(group_id).is_some() {
            // rebuilt the in-memory group. Historical events are still judged
            // against the batch-start frontier and stay suppressed.
            return Ok(Some(false));
        }
        Ok(Some(self.ensure_local_deleted_group_route(group_id)?))
    }

    /// Terminal events in one engine-effects batch all stay suppressed by the
    /// marker. Remove it only after that batch drains so a trailing epoch/state
    /// event cannot rebuild the projection or reinstall a terminal route.
    pub(crate) fn clear_terminal_local_group_deletion_frontiers(
        &self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        for event in &effects.events {
            let cgka_traits::engine::GroupEvent::GroupStateChanged {
                group_id,
                change: cgka_traits::engine::GroupStateChange::GroupDisbanded,
                ..
            } = event
            else {
                continue;
            };
            if self.state_group_record(group_id).is_none() {
                storage.clear_local_group_deletion_frontier(&hex::encode(group_id.as_slice()))?;
            }
        }
        Ok(())
    }

    pub(crate) fn refresh_group(&mut self, group_id: &GroupId) {
        if self.state_group_record(group_id).is_none() {
            match self.has_local_group_deletion_frontier(group_id) {
                Ok(true) => {
                    let _ = self.ensure_local_deleted_group_route(group_id);
                    return;
                }
                // Refresh is best-effort. Fail closed instead of letting a
                // storage read failure resurrect a deliberately deleted group.
                Err(_) => return,
                Ok(false) => {}
            }
        }
        let previous = self.state_group_record(group_id);
        let group_metadata = self.runtime.group_record(group_id).ok();
        let protocol_profile = group_metadata
            .as_ref()
            .map(|group| group.protocol_profile)
            .unwrap_or(ProtocolProfile::Legacy);
        let components = self.read_group_components(group_id, protocol_profile);
        let Ok(nostr_routing) = components.nostr_routing else {
            return;
        };
        let projection = EventGroupProjection {
            nostr_routing,
            group_metadata: group_metadata.as_ref(),
            profile: components.profile,
            admin_policy: self.admin_policy_for_group(group_id),
            message_retention: components.message_retention,
            agent_text_stream: components.agent_text_stream,
            avatar_url: components.avatar_url,
            encrypted_media: components.encrypted_media,
            image: components.image,
        };
        add_group(
            &mut self.state,
            group_id,
            &projection,
            GroupConfirmationProjection::Preserve,
        );
        if previous != self.state_group_record(group_id) {
            self.mark_group_projection_dirty(group_id);
        }
    }

    pub(crate) fn add_group(&mut self, group_id: &GroupId) -> Result<(), AppError> {
        let previous = self.state_group_record(group_id);
        let group_metadata = self.runtime.group_record(group_id).ok();
        let protocol_profile = group_metadata
            .as_ref()
            .map(|group| group.protocol_profile)
            .unwrap_or(ProtocolProfile::Legacy);
        let components = self.read_group_components(group_id, protocol_profile);
        let nostr_routing = components.nostr_routing?;
        let projection = EventGroupProjection {
            nostr_routing,
            group_metadata: group_metadata.as_ref(),
            profile: components.profile,
            admin_policy: self.admin_policy_for_group(group_id),
            message_retention: components.message_retention,
            agent_text_stream: components.agent_text_stream,
            avatar_url: components.avatar_url,
            encrypted_media: components.encrypted_media,
            image: components.image,
        };
        add_group(
            &mut self.state,
            group_id,
            &projection,
            GroupConfirmationProjection::Accepted,
        );
        if previous != self.state_group_record(group_id) {
            self.mark_group_projection_dirty(group_id);
        }
        let group_id_hex = hex::encode(group_id.as_slice());
        let subscriptions = self
            .state
            .groups
            .iter()
            .find(|group| group.group_id_hex == group_id_hex)
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex))?
            .transport_subscriptions(group_id)?;
        self.routing.replace_group_routes(group_id, subscriptions);
        Ok(())
    }

    /// Build the current and retained-prior subscriptions for an intentionally
    /// hidden live group. The deletion frontier keeps each authenticated prior
    /// route paired with the relay set that carried it.
    fn local_deleted_group_subscriptions(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<TransportGroupSubscription>, AppError> {
        if self
            .runtime
            .group_record(group_id)
            .map_err(AppError::from)
            .is_ok_and(|group| group.removed || group.disbanded.is_some())
        {
            return Ok(Vec::new());
        }
        let routing = self.nostr_routing_for_group(group_id)?;
        let current = routing.subscription(group_id)?;
        let storage = self.app.account_storage(&self.state.label)?;
        if storage
            .retain_local_group_deletion_nostr_routes(
                &hex::encode(group_id.as_slice()),
                &[StoredNostrRoute {
                    nostr_group_id_hex: routing.nostr_group_id_hex,
                    relays: routing.relays,
                    last_epoch: self
                        .runtime
                        .group_record(group_id)
                        .map(|group| group.epoch.0)
                        .unwrap_or_default(),
                }],
            )
            .is_err()
        {
            tracing::warn!(
                target: "marmot_app::client::projection",
                method = "local_deleted_group_subscriptions",
                "could not retain the current route for a locally deleted group",
            );
        }
        let indexed_routes = storage
            .list_transport_group_routes()?
            .into_iter()
            .filter(|route| route.group_id == *group_id)
            .collect::<Vec<_>>();
        let mut subscriptions = Vec::new();
        for route in
            storage.local_group_deletion_prior_nostr_routes(&hex::encode(group_id.as_slice()))?
        {
            let route = AppPriorNostrRoute {
                nostr_group_id_hex: route.nostr_group_id_hex,
                relays: route.relays,
                last_epoch: route.last_epoch,
            };
            match route.subscription(group_id) {
                Ok(subscription)
                    if indexed_routes.iter().any(|route| {
                        route.transport_group_id == subscription.transport_group_id
                    }) =>
                {
                    subscriptions.push(subscription);
                }
                Ok(_) => {}
                Err(_) => tracing::warn!(
                    target: "marmot_app::client::projection",
                    method = "local_deleted_group_subscriptions",
                    error_kind = "invalid_prior_nostr_route",
                    "skipping invalid prior Nostr route",
                ),
            }
        }
        subscriptions.push(current.clone());

        // Legacy deletion markers have no exact prior-route payload. Keep the
        // old route-id coverage in that case by pairing only still-unrepresented
        // ids with the authenticated current component's relay set.
        for route in indexed_routes {
            if !subscriptions
                .iter()
                .any(|subscription| subscription.transport_group_id == route.transport_group_id)
            {
                subscriptions.push(TransportGroupSubscription {
                    group_id: group_id.clone(),
                    transport_group_id: route.transport_group_id,
                    endpoints: current.endpoints.clone(),
                });
            }
        }
        Ok(subscriptions)
    }

    /// Keep every still-valid transport route active while the app projection
    /// is intentionally deleted. This is the path by which a fresh chat message
    /// can cross the deletion frontier and restore the conversation.
    pub(crate) fn ensure_local_deleted_group_route(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let subscriptions = self.local_deleted_group_subscriptions(group_id)?;
        Ok(self.routing.replace_group_routes(group_id, subscriptions))
    }

    /// Move exact route history out of the deletion marker and into the
    /// recreated app group before the marker is cleared transactionally.
    pub(crate) fn adopt_local_deleted_group_prior_routes(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let routes = self
            .app
            .account_storage(&self.state.label)?
            .local_group_deletion_prior_nostr_routes(&group_id_hex)?
            .into_iter()
            .map(|route| AppPriorNostrRoute {
                nostr_group_id_hex: route.nostr_group_id_hex,
                relays: route.relays,
                last_epoch: route.last_epoch,
            })
            .collect::<Vec<_>>();
        let Some(group) = self
            .state
            .groups
            .iter_mut()
            .find(|group| group.group_id_hex == group_id_hex)
        else {
            return Ok(false);
        };
        let previous_routes = group.prior_nostr_routes.clone();
        group.adopt_prior_nostr_routes(routes);
        let changed = group.prior_nostr_routes != previous_routes;
        if changed {
            self.mark_group_projection_dirty_hex(group_id_hex);
        }
        Ok(true)
    }

    /// Add intentionally hidden live-group routes to a freshly rebuilt routing
    /// snapshot before it atomically replaces the active snapshot.
    pub(crate) fn preserve_local_deleted_group_routes(
        &self,
        routing: &AppTransportRouting,
    ) -> Result<(), AppError> {
        for group_id in self.runtime.live_group_ids()? {
            if self.state_group_record(&group_id).is_some()
                || !self.has_local_group_deletion_frontier(&group_id)?
            {
                continue;
            }
            routing.replace_group_routes(
                &group_id,
                self.local_deleted_group_subscriptions(&group_id)?,
            );
        }
        Ok(())
    }

    /// Repair an engine/projection tear left by a previously confirmed group
    /// mutation whose trailing app-state write failed, and hydrate the durable
    /// roster-count projection introduced for chat-list classification.
    /// Quarantined groups are absent from `live_group_ids` and retain their
    /// dedicated recovery path.
    pub(crate) fn reconcile_live_engine_groups(&mut self) -> Result<bool, AppError> {
        let projected = self
            .state
            .groups
            .iter()
            .map(|group| group.group_id_hex.clone())
            .collect::<std::collections::HashSet<_>>();
        let live_group_ids = self.runtime.live_group_ids()?;
        let mut changed = false;
        for group_id in live_group_ids {
            let group_id_hex = hex::encode(group_id.as_slice());
            if !projected.contains(group_id_hex.as_str()) {
                if self
                    .app
                    .account_storage(&self.state.label)?
                    .local_group_deletion_frontier(&group_id_hex)?
                    .is_some()
                {
                    self.ensure_local_deleted_group_route(&group_id)?;
                    continue;
                }
                self.add_group(&group_id)?;
                changed = true;
                continue;
            }
            let Some(projected_group) = self
                .state
                .groups
                .iter_mut()
                .find(|group| group.group_id_hex == group_id_hex)
            else {
                continue;
            };
            let mut dirty = false;
            if let Ok(group) = self.runtime.group_record(&group_id) {
                let live_count = u64::try_from(group.members.len()).ok();
                if projected_group.member_count != live_count {
                    projected_group.member_count = live_count;
                    dirty = true;
                }
                let previous_direct_members = projected_group.direct_member_ids_hex.clone();
                projected_group.set_direct_member_ids_from_roster(&group.members);
                dirty |= projected_group.direct_member_ids_hex != previous_direct_members;
            }
            if dirty {
                self.mark_group_projection_dirty_hex(group_id_hex);
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Finish the projection repairs that require fully hydrated group state.
    /// Deferred runtime opens call this after their background hydration
    /// pipeline; eager clients call it before returning from open.
    pub(crate) fn reconcile_hydrated_account_state(&mut self) -> Result<(), AppError> {
        if self.reconcile_live_engine_groups()? {
            self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        }
        self.reconcile_disband_drafts();
        self.backfill_self_membership_once()?;
        self.backfill_direct_conversation_members_once()
    }

    /// Finish the app-local half of durable disband acceptance after a crash
    /// or a transient projection write failure. The engine request/tombstone is
    /// the source of truth, so composer drafts must not reappear on reopen.
    pub(crate) fn reconcile_disband_drafts(&self) {
        for projected_group in &self.state.groups {
            let Ok(group_id_bytes) = hex::decode(&projected_group.group_id_hex) else {
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            let request_exists = self
                .runtime
                .disband_request(&group_id)
                .ok()
                .flatten()
                .is_some();
            let is_disbanded = self
                .runtime
                .group_record(&group_id)
                .ok()
                .is_some_and(|group| group.disbanded.is_some());
            if (request_exists || is_disbanded)
                && let Err(error) = self
                    .app
                    .delete_message_draft(&self.state.label, &projected_group.group_id_hex)
            {
                tracing::warn!(
                    target: "marmot_app::client",
                    method = "reconcile_disband_drafts",
                    error_kind = error.privacy_safe_kind(),
                    "composer draft cleanup remains pending"
                );
            }
        }
    }

    pub(crate) fn profile_for_group(&self, group_id: &GroupId) -> AppGroupProfileComponent {
        parse_profile_component(
            self.runtime
                .app_component(group_id, GROUP_PROFILE_COMPONENT_ID)
                .ok()
                .flatten(),
        )
    }

    /// One batched engine read for every component the group projection needs:
    /// 7 components on a single engine state load instead of 7 loads.
    /// Per-component fallbacks match the individual `*_for_group` helpers.
    pub(crate) fn read_group_components(
        &self,
        group_id: &GroupId,
        protocol_profile: ProtocolProfile,
    ) -> GroupComponentReads {
        let media_component_id = Self::encrypted_media_component_id(protocol_profile);
        let component_ids = [
            NOSTR_ROUTING_COMPONENT_ID,
            GROUP_PROFILE_COMPONENT_ID,
            GROUP_MESSAGE_RETENTION_COMPONENT_ID,
            AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
            GROUP_AVATAR_URL_COMPONENT_ID,
            media_component_id,
            GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
        ];
        let components = match self.runtime.app_components(group_id, &component_ids) {
            Ok(components) => components,
            Err(error) => {
                return GroupComponentReads::unavailable(error.into(), protocol_profile);
            }
        };

        // `next()` consumes in `component_ids` order; struct-literal fields
        // evaluate in source order, which matches.
        let mut components = components.into_iter();
        let mut next = || components.next().flatten();
        GroupComponentReads {
            nostr_routing: parse_routing_component(next()),
            profile: parse_profile_component(next()),
            message_retention: parse_retention_component(next()),
            agent_text_stream: parse_agent_stream_component(next()),
            avatar_url: parse_avatar_component(next()),
            encrypted_media: parse_media_component(media_component_id, protocol_profile, next()),
            image: parse_image_component(next()),
        }
    }

    pub(crate) fn admin_policy_for_group(
        &self,
        group_id: &GroupId,
    ) -> AppGroupAdminPolicyComponent {
        self.runtime
            .admin_pubkeys(group_id)
            .map(AppGroupAdminPolicyComponent::new)
            .unwrap_or_else(|_| AppGroupAdminPolicyComponent::new(Vec::new()))
    }

    pub(crate) fn message_retention_for_group(
        &self,
        group_id: &GroupId,
    ) -> AppGroupMessageRetentionComponent {
        parse_retention_component(
            self.runtime
                .app_component(group_id, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
                .ok()
                .flatten(),
        )
    }

    pub(crate) fn finalize_published_app_message_source_retention(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) -> Result<Vec<crate::AppProjectionUpdate>, AppError> {
        let mut updates = Vec::new();
        for published in &effects.published_app_messages {
            let group_id_hex = hex::encode(published.group_id.as_slice());
            let source_message_id_hex = hex::encode(published.message_id.as_slice());
            if let Some(update) = self.app.finalize_account_app_event_source_retention(
                &self.state.label,
                &group_id_hex,
                &published.app_event_id,
                Some(source_message_id_hex.as_str()),
                published.source_epoch.0,
                published.retention,
            )? {
                updates.push(update);
            }
        }
        let fail_acknowledgement = cfg!(feature = "test-policy-overrides")
            && std::mem::take(&mut self.fail_next_published_app_message_acknowledgement);
        let acknowledgement = if fail_acknowledgement {
            Err(AppError::BlockingTask(
                "injected published application-message acknowledgement failure".to_owned(),
            ))
        } else {
            self.runtime
                .acknowledge_published_app_messages(&effects.published_app_messages)
                .map_err(AppError::from)
        };
        if let Err(error) = acknowledgement {
            // Projection is already durable, and the accepted fanout remains
            // durable when acknowledgement fails. Schedule its group so a
            // cleanup-only replay runs without waiting for unrelated traffic;
            // resume recognizes this terminal fanout and never republishes its
            // network bytes.
            for published in &effects.published_app_messages {
                self.pending_convergence_groups
                    .insert(published.group_id.clone());
            }
            tracing::warn!(
                target: "marmot_app::client::projection",
                method = "finalize_published_app_message_source_retention",
                error_kind = error.privacy_safe_kind(),
                "published application-message cleanup deferred",
            );
        }
        Ok(updates)
    }

    /// Invalidates local projections for application messages whose durable
    /// fanouts reached a terminal publish failure.
    ///
    /// A direct send excludes its own optimistic row because the caller owns
    /// that row's callback-delivered retraction. Sibling failures and recovery
    /// batches have no such caller, so their updates are returned for the
    /// account worker to broadcast.
    pub(crate) fn invalidate_failed_app_message_projections(
        &self,
        effects: &marmot_account::AccountDeviceEffects,
        excluded: Option<(&GroupId, &str)>,
    ) -> Result<Vec<crate::AppProjectionUpdate>, AppError> {
        let mut updates = Vec::new();
        for failed in &effects.failed_app_messages {
            if excluded.is_some_and(|(group_id, app_event_id)| {
                failed.group_id == *group_id && failed.app_event_id == app_event_id
            }) {
                continue;
            }
            if let Some(update) = self.app.invalidate_timeline_app_event(
                &self.state.label,
                &hex::encode(failed.group_id.as_slice()),
                &failed.app_event_id,
                crate::LOCAL_PUBLISH_FAILED_REASON,
            )? {
                updates.push(update);
            }
        }
        Ok(updates)
    }

    pub(crate) fn prune_plaintext_retention_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<(), AppError> {
        self.secure_delete_expired_plaintext_for_group(group_id)
            .map(|_| ())
    }

    pub fn secure_delete_expired_plaintext_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<SecureDeleteExpiredResult, AppError> {
        self.secure_delete_expired_plaintext_for_group_at(group_id, unix_now_seconds())
    }

    pub(crate) fn secure_delete_expired_plaintext_for_group_at(
        &self,
        group_id: &GroupId,
        now_seconds: u64,
    ) -> Result<SecureDeleteExpiredResult, AppError> {
        self.app.secure_prune_expired_account_app_events(
            &self.state.label,
            &hex::encode(group_id.as_slice()),
            now_seconds,
        )
    }

    pub(crate) fn agent_text_stream_for_group(
        &self,
        group_id: &GroupId,
    ) -> AppAgentTextStreamComponent {
        parse_agent_stream_component(
            self.runtime
                .app_component(group_id, AGENT_TEXT_STREAM_QUIC_COMPONENT_ID)
                .ok()
                .flatten(),
        )
    }

    pub(crate) fn avatar_url_for_group(&self, group_id: &GroupId) -> AppGroupAvatarUrlComponent {
        parse_avatar_component(
            self.runtime
                .app_component(group_id, GROUP_AVATAR_URL_COMPONENT_ID)
                .ok()
                .flatten(),
        )
    }

    pub(crate) fn encrypted_media_component_id(profile: ProtocolProfile) -> u16 {
        match profile {
            ProtocolProfile::Legacy => GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
            ProtocolProfile::Current => GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
        }
    }

    pub(crate) fn encrypted_media_for_group(
        &self,
        group_id: &GroupId,
    ) -> AppGroupEncryptedMediaComponent {
        let profile = self
            .runtime
            .group_record(group_id)
            .map(|group| group.protocol_profile)
            .unwrap_or(ProtocolProfile::Legacy);
        let component_id = Self::encrypted_media_component_id(profile);
        parse_media_component(
            component_id,
            profile,
            self.runtime
                .app_component(group_id, component_id)
                .ok()
                .flatten(),
        )
    }

    /// Authoritative encrypted-media component lookup for the epoch-secret warm
    /// path. Unlike [`Self::encrypted_media_for_group`], lookup failures are NOT
    /// collapsed into "disabled": a transient storage read failure must keep the
    /// warm pass retryable instead of being latched as an authoritative
    /// negative for the group's whole epoch.
    pub(crate) fn try_encrypted_media_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<AppGroupEncryptedMediaComponent, AppError> {
        let profile = self.runtime.group_record(group_id)?.protocol_profile;
        let component_id = Self::encrypted_media_component_id(profile);
        match self.runtime.app_component(group_id, component_id)? {
            Some(bytes) => Ok(AppGroupEncryptedMediaComponent::from_bytes(
                component_id,
                &bytes,
            )),
            None => Ok(AppGroupEncryptedMediaComponent::disabled_for_profile(
                profile.into(),
            )),
        }
    }

    pub(crate) fn image_for_group(&self, group_id: &GroupId) -> AppGroupImageInput {
        parse_image_component(
            self.runtime
                .app_component(group_id, GROUP_BLOSSOM_IMAGE_COMPONENT_ID)
                .ok()
                .flatten(),
        )
    }

    /// Persist and queue kind-1210 system rows for our own authenticated commits.
    /// Call only after the caller's final fallible persistence step succeeds so
    /// failed commands do not leave stale buffered timeline updates.
    pub(crate) fn queue_own_group_system_projection_updates(
        &mut self,
        effects: &marmot_account::AccountDeviceEffects,
    ) {
        // Gate on having published a commit: own send paths always carry a
        // report, while reportless paths (e.g. convergence retry) re-emit the
        // same changes unattributed. Those are already synthesized — attributed —
        // on the inbound path, so skipping here avoids a duplicate, actor-less row.
        if effects.reports.is_empty() {
            return;
        }
        self.pending_projection_updates
            .extend(self.project_group_system_rows(&effects.events, unix_now_seconds()));
    }

    pub(crate) fn take_pending_projection_updates(&mut self) -> Vec<crate::AppProjectionUpdate> {
        std::mem::take(&mut self.pending_projection_updates)
    }

    /// Synthesize a durable kind-1210 group system row for each
    /// `GroupStateChanged` event and persist it to the timeline. Used by both
    /// the inbound delivery path (peer commits) and our own send path (local
    /// commits). Failures are logged, not propagated: a missing system row must
    /// never fail message delivery.
    ///
    /// A change whose `origin_commit_id` the same batch withdraws is skipped.
    /// Every seam runs this once at its tail, *after* its projection loop has
    /// already dispatched each `GroupStateInvalidated` through
    /// [`MarmotApp::projection_update_for_invalidation_event`] — so by the time
    /// the upsert below runs, the batch's withdrawals are all applied and it
    /// would be the last writer. The storage upsert clears `invalidated` on
    /// conflict, so without this filter the tail either revives a row the batch
    /// just tombstoned or synthesizes one for a change that canonically never
    /// happened (the withdrawal swept a row that did not exist yet).
    ///
    /// One batch carries both because the engine buffers convergence passes:
    /// `events_buf` has a single take site and
    /// `advance_convergence_inputs_with_execution` runs up to
    /// `MAX_CONVERGENCE_REPROCESSING_PASSES` passes without one, so an earlier
    /// pass's accepted commit can be superseded by a later pass's reorg before
    /// anything drains. Within a *single* pass the two are disjoint by
    /// construction — the change's origin is the accepted commit and the
    /// superseded emitter skips accepted commits — so the single-pass shape is
    /// not what this guards.
    ///
    /// Membership is the test rather than event order: a batch may carry the
    /// withdrawal before or after the change it names, and neither ordering
    /// makes the change canonical.
    pub(crate) fn project_group_system_rows(
        &self,
        events: &[cgka_traits::engine::GroupEvent],
        recorded_at: u64,
    ) -> Vec<crate::AppProjectionUpdate> {
        let superseded_commits: std::collections::HashSet<&[u8]> = events
            .iter()
            .filter_map(|event| match event {
                cgka_traits::engine::GroupEvent::GroupStateInvalidated {
                    invalidated_commit_id,
                    ..
                } => Some(invalidated_commit_id.as_slice()),
                _ => None,
            })
            .collect();
        let mut updates = Vec::new();
        for event in events {
            if let cgka_traits::engine::GroupEvent::GroupStateChanged {
                group_id,
                epoch,
                actor,
                change,
                origin_commit_id,
            } = event
            {
                // An unattributed change carries no commit link, so nothing in
                // this batch can name it and it is never withheld here.
                if origin_commit_id
                    .as_ref()
                    .is_some_and(|id| superseded_commits.contains(id.as_slice()))
                {
                    continue;
                }
                let projection = match build_group_system_projection(
                    group_id,
                    epoch.0,
                    actor.as_ref(),
                    change,
                    recorded_at,
                    origin_commit_id
                        .as_ref()
                        .map(|id| hex::encode(id.as_slice())),
                ) {
                    Ok(projection) => projection,
                    Err(_err) => {
                        tracing::warn!(
                            target: "marmot_app::groups",
                            method = "project_group_system_rows",
                            error_code = "projection_build_failed",
                            "failed to build group system row",
                        );
                        continue;
                    }
                };
                match self.app.record_account_app_event_at(
                    &self.state.label,
                    &projection,
                    recorded_at,
                ) {
                    Ok(update) => updates.push(update),
                    Err(_err) => {
                        tracing::warn!(
                            target: "marmot_app::groups",
                            method = "project_group_system_rows",
                            error_code = "projection_apply_failed",
                            "failed to project group system row",
                        );
                    }
                }
            }
        }
        updates
    }

    pub(crate) fn nostr_routing_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<AppGroupNostrRoutingComponent, AppError> {
        parse_routing_component(
            self.runtime
                .app_component(group_id, NOSTR_ROUTING_COMPONENT_ID)?,
        )
    }
}

/// Every component the group projection reads, from one batched engine call.
/// Only routing distinguishes error from absence; the rest fall back the way
/// their `*_for_group` helpers do.
pub(crate) struct GroupComponentReads {
    pub(crate) nostr_routing: Result<AppGroupNostrRoutingComponent, AppError>,
    pub(crate) profile: AppGroupProfileComponent,
    pub(crate) message_retention: AppGroupMessageRetentionComponent,
    pub(crate) agent_text_stream: AppAgentTextStreamComponent,
    pub(crate) avatar_url: AppGroupAvatarUrlComponent,
    pub(crate) encrypted_media: AppGroupEncryptedMediaComponent,
    pub(crate) image: AppGroupImageInput,
}

impl GroupComponentReads {
    fn unavailable(error: AppError, protocol_profile: ProtocolProfile) -> Self {
        Self {
            nostr_routing: Err(error),
            profile: AppGroupProfileComponent::absent(),
            message_retention: AppGroupMessageRetentionComponent::disabled(),
            agent_text_stream: AppAgentTextStreamComponent::disabled(),
            avatar_url: AppGroupAvatarUrlComponent::absent(),
            encrypted_media: AppGroupEncryptedMediaComponent::disabled_for_profile(
                protocol_profile.into(),
            ),
            image: AppGroupImageInput::default(),
        }
    }
}

fn parse_routing_component(
    bytes: Option<Vec<u8>>,
) -> Result<AppGroupNostrRoutingComponent, AppError> {
    let bytes = bytes.ok_or_else(|| {
        AppError::InvalidNostrRouting("group is missing marmot.transport.nostr.routing.v1".into())
    })?;
    AppGroupNostrRoutingComponent::from_bytes(&bytes)
}

fn parse_profile_component(bytes: Option<Vec<u8>>) -> AppGroupProfileComponent {
    bytes
        .map(|bytes| AppGroupProfileComponent::from_bytes(&bytes))
        .unwrap_or_else(AppGroupProfileComponent::absent)
}

fn parse_retention_component(bytes: Option<Vec<u8>>) -> AppGroupMessageRetentionComponent {
    bytes
        .map(|bytes| AppGroupMessageRetentionComponent::from_bytes(&bytes))
        .unwrap_or_else(AppGroupMessageRetentionComponent::disabled)
}

fn parse_agent_stream_component(bytes: Option<Vec<u8>>) -> AppAgentTextStreamComponent {
    bytes
        .map(|bytes| AppAgentTextStreamComponent::from_bytes(&bytes))
        .unwrap_or_else(AppAgentTextStreamComponent::disabled)
}

fn parse_avatar_component(bytes: Option<Vec<u8>>) -> AppGroupAvatarUrlComponent {
    bytes
        .map(|bytes| AppGroupAvatarUrlComponent::from_bytes(&bytes))
        .unwrap_or_else(AppGroupAvatarUrlComponent::absent)
}

fn parse_media_component(
    component_id: u16,
    protocol_profile: ProtocolProfile,
    bytes: Option<Vec<u8>>,
) -> AppGroupEncryptedMediaComponent {
    bytes
        .map(|bytes| AppGroupEncryptedMediaComponent::from_bytes(component_id, &bytes))
        .unwrap_or_else(|| {
            AppGroupEncryptedMediaComponent::disabled_for_profile(protocol_profile.into())
        })
}

fn parse_image_component(bytes: Option<Vec<u8>>) -> AppGroupImageInput {
    bytes
        .and_then(|bytes| AppGroupImageInput::from_component_bytes(&bytes))
        .unwrap_or_default()
}

/// Build the durable kind-1210 group system row projection for one
/// authenticated [`GroupStateChange`]. The row is synthesized locally
/// (Approach A) — no kind-1210 message is sent on the wire. The message id is
/// deterministic over (actor, epoch, system_type, content) so re-processing the
/// same change upserts instead of duplicating. The row carries a null
/// `source_message_id_hex` (one commit can synthesize several rows, which would
/// collide on the partial unique source index); instead `origin_commit_id`
/// links the row back to the commit that produced it, so losing-branch fork
/// recovery can invalidate every row derived from a rolled-back commit (1:N).
fn build_group_system_projection(
    group_id: &cgka_traits::types::GroupId,
    epoch: u64,
    actor: Option<&cgka_traits::types::MemberId>,
    change: &cgka_traits::engine::GroupStateChange,
    recorded_at: u64,
    origin_commit_id: Option<String>,
) -> Result<AppMessageProjection, cgka_traits::app_event::MarmotAppEventError> {
    use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_GROUP_SYSTEM, group_system_event_material};

    let material = group_system_event_material(group_id, epoch, actor, change)?;

    Ok(AppMessageProjection {
        message_id_hex: material.message_id_hex,
        // Synthesized rows carry no source: several rows can come from one
        // commit, which would collide on the partial unique source index, and
        // commit ids are never targeted by source-based invalidation anyway.
        source_message_id_hex: None,
        direction: "system".to_owned(),
        group_id_hex: material.group_id_hex,
        sender: material.sender,
        plaintext: material.content,
        kind: MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        tags: material.tags,
        source_epoch: Some(epoch),
        retention: None,
        recorded_at: Some(recorded_at),
        moderation_grant: false,
        // Non-unique link to the origin commit so a losing-branch rollback can
        // invalidate every row this commit synthesized (1:N).
        origin_commit_id,
    })
}

fn read_marker_error_code(error: &AppError) -> &'static str {
    match error {
        AppError::Account(_) => "read_marker_failed:account",
        AppError::AccountHome(_) => "read_marker_failed:account_home",
        AppError::Session(_) => "read_marker_failed:session",
        AppError::Storage(_) => "read_marker_failed:storage",
        AppError::Transport(_) => "read_marker_failed:transport",
        AppError::Io(_) => "read_marker_failed:io",
        AppError::Json(_) => "read_marker_failed:json",
        AppError::Sqlite(_) => "read_marker_failed:sqlite",
        AppError::Hex(_) => "read_marker_failed:hex",
        AppError::MissingKeyPackage(_) => "read_marker_failed:missing_key_package",
        AppError::UnknownGroup(_) => "read_marker_failed:unknown_group",
        AppError::CreatedGroupProjectionUnavailable(_) => {
            "read_marker_failed:created_group_projection_unavailable"
        }
        AppError::InvalidGroupMembershipPage(_) => {
            "read_marker_failed:invalid_group_membership_page"
        }
        AppError::DirectConversationIndexNotReady => {
            "read_marker_failed:direct_conversation_index_not_ready"
        }
        AppError::InvalidCachedIdentityPage(_) => "read_marker_failed:invalid_cached_identity_page",
        AppError::InvalidChatPin(_) => "read_marker_failed:invalid_chat_pin",
        AppError::GroupDisbanding(_) => "read_marker_failed:group_disbanding",
        AppError::InvalidMessageDraft(_) => "read_marker_failed:invalid_message_draft",
        AppError::AgentStreamMissingStart => "read_marker_failed:agent_stream_missing_start",
        AppError::AgentStreamStartNotConfirmed => {
            "read_marker_failed:agent_stream_start_not_confirmed"
        }
        AppError::AgentStreamUnsupportedRoute => {
            "read_marker_failed:agent_stream_unsupported_route"
        }
        AppError::AgentStreamMissingCandidate => {
            "read_marker_failed:agent_stream_missing_candidate"
        }
        AppError::AgentStreamInvalidCandidate(_) => {
            "read_marker_failed:agent_stream_invalid_candidate"
        }
        AppError::Publish(_) => "read_marker_failed:publish",
        AppError::MissingDefaultRelays => "read_marker_failed:missing_default_relays",
        AppError::MissingRelayLists(_) => "read_marker_failed:missing_relay_lists",
        AppError::FollowListUnavailable => "read_marker_failed:follow_list_unavailable",
        AppError::RelayDirectory(_) => "read_marker_failed:relay_directory",
        AppError::AccountCatchUp(_) => "read_marker_failed:account_catch_up",
        AppError::InvalidPublicKey => "read_marker_failed:invalid_public_key",
        AppError::UnexpectedPrivateKey => "read_marker_failed:unexpected_private_key",
        AppError::IdentityKeyMismatch => "read_marker_failed:identity_key_mismatch",
        AppError::ExternalSignerUnavailable(_) => "read_marker_failed:external_signer_unavailable",
        AppError::ExternalSignerMismatch => "read_marker_failed:external_signer_mismatch",
        AppError::ExternalSignerRejected => "read_marker_failed:external_signer_rejected",
        AppError::InvalidKeyPackageEvent(_) => "read_marker_failed:invalid_key_package_event",
        AppError::MissingDirectoryEntry(_) => "read_marker_failed:missing_directory_entry",
        AppError::InvalidDirectorySearch(_) => "read_marker_failed:invalid_directory_search",
        AppError::InvalidGroupProfile(_) => "read_marker_failed:invalid_group_profile",
        AppError::InvalidNostrRouting(_) => "read_marker_failed:invalid_nostr_routing",
        AppError::InvalidGroupAvatarUrl(_) => "read_marker_failed:invalid_group_avatar_url",
        AppError::InvalidAgentTextStreamPolicy(_) => {
            "read_marker_failed:invalid_agent_text_stream_policy"
        }
        AppError::InvalidEncryptedMedia(_) => "read_marker_failed:invalid_encrypted_media",
        AppError::BlobStore(_) => "read_marker_failed:blob_store",
        AppError::UnsafeMediaFetch(_) => "read_marker_failed:unsafe_media_fetch",
        AppError::InvalidAppMessagePayload(_) => "read_marker_failed:invalid_app_message_payload",
        AppError::InvalidPushToken(_) => "read_marker_failed:invalid_push_token",
        AppError::InvalidPushServer(_) => "read_marker_failed:invalid_push_server",
        AppError::InvalidPushGossip(_) => "read_marker_failed:invalid_push_gossip",
        AppError::InvalidRelayTelemetrySettings(_) => {
            "read_marker_failed:invalid_relay_telemetry_settings"
        }
        AppError::InvalidAuditLogFile(_) => "read_marker_failed:invalid_audit_log_file",
        AppError::AuditLogUpload(_) => "read_marker_failed:audit_log_upload",
        AppError::NotificationsDisabled => "read_marker_failed:notifications_disabled",
        AppError::SqlcipherKeyDerivation(_) => "read_marker_failed:sqlcipher_key_derivation",
        AppError::BlockingTask(_) => "read_marker_failed:blocking_task",
        AppError::RuntimeBusy => "read_marker_failed:runtime_busy",
        AppError::AccountSessionBusy => "read_marker_failed:account_session_busy",
        AppError::AccountWorkerBusy => "read_marker_failed:account_worker_busy",
        AppError::AccountWorkerResponseTimedOut => {
            "read_marker_failed:account_worker_response_timed_out"
        }
        AppError::AccountSetupRecoveryRequired => {
            "read_marker_failed:account_setup_recovery_required"
        }
        AppError::AccountSetupRetryRequired => "read_marker_failed:account_setup_retry_required",
        AppError::AccountSetupResetNotApplicable => {
            "read_marker_failed:account_setup_reset_not_applicable"
        }
        AppError::AccountSetupKeyPackageRecoveryAvailable => {
            "read_marker_failed:account_setup_key_package_recovery_available"
        }
        AppError::RuntimeStopping => "read_marker_failed:runtime_stopping",
        AppError::ReactionNotFound => "read_marker_failed:reaction_not_found",
        AppError::TransportClosed => "read_marker_failed:transport_closed",
    }
}
