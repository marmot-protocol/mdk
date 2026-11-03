//! Post-join collection belongs to the same runner as ordinary history debt.
//! A Welcome copy gets a fresh ordinary activation, never a comparison grant
//! or native backward pager. Raw EOSE starts maintenance grace; only the
//! admitted coverage ledger ends that copy's history fetch.

use std::collections::HashSet;

use cgka_traits::storage::StorageProvider;
use cgka_traits::{GroupId, MaintenancePhase, MaintenanceStorage, MaintenanceTrigger, MessageId};
use storage_sqlite::{TRANSPORT_RECONCILIATION_RETENTION_SECS, TransportReconciliationRoute};

use crate::AppError;
use crate::client::AppClient;

/// Ephemeral observation of a durable joined-copy fetch. A restart reconstructs
/// it with a fresh query; it never moves the durable grace or fetch deadline.
/// No identities from this structure are diagnostics.
pub(crate) struct Collection {
    copy: MessageId,
    pub(super) route: TransportReconciliationRoute,
    since: u64,
    required: Vec<String>,
    boundary: bool,
    pub(super) until: u64,
    pub(super) active: bool,
    pub(super) collecting: bool,
}

impl AppClient {
    pub(crate) fn advance_runner_post_join(
        &mut self,
    ) -> futures::future::BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let storage = self.app.account_storage(&self.state.label)?;
            let app = storage.app_storage();
            // The old comparison owner no longer services these requests.
            // Durable domain fetches below are the new owner's source of work.
            app.retain_recovery_maintenance_jobs(&[])?;
            let now = super::host::unix_now();
            let routes = self.recovery_runner_routes();
            let mut waiting = HashSet::new();
            for group in self.state.groups.clone() {
                let Ok(bytes) = hex::decode(&group.group_id_hex) else {
                    continue;
                };
                let group_id = GroupId::new(bytes);
                if self
                    .runtime
                    .group_record(&group_id)
                    .is_ok_and(|record| record.is_terminal())
                    || self.group_unrecoverable(group_id.as_slice())
                {
                    continue;
                }
                let fetch = self.runtime.post_join_history_fetch(&group_id)?;
                let obligations = self.runtime.maintenance_obligations_for_group(&group_id)?;
                let prerequisite = obligations.iter().find(|job| {
                    job.trigger == MaintenanceTrigger::PostJoin
                        && matches!(
                            job.phase,
                            MaintenancePhase::CatchUp
                                | MaintenancePhase::EoseTimeout
                                | MaintenancePhase::Grace
                        )
                });
                let owed = fetch
                    .as_ref()
                    .is_some_and(|fetch| fetch.completion.is_none());
                if !owed && prerequisite.is_none_or(|job| job.phase == MaintenancePhase::Grace) {
                    continue;
                }
                // Keep the current copy's identity even after its fetch ends. An
                // earlier copy's still-early self-update obligation cannot name it.
                let Some(copy) = fetch
                    .as_ref()
                    .map(|fetch| fetch.obligation_id.clone())
                    .or_else(|| prerequisite.map(|job| job.id.clone()))
                else {
                    continue;
                };
                let Some(route) = routes.iter().find(|route| {
                    route.group_id.as_deref() == Some(group_id.as_slice())
                        && route.goal_until.is_none()
                }) else {
                    continue;
                };
                if route.required.is_empty() {
                    continue;
                }
                waiting.insert(group_id.clone());
                if self
                    .runner_post_join
                    .get(&group_id)
                    .is_some_and(|collection| {
                        collection.copy == copy
                            && collection.route == route.route
                            && collection.required == route.required
                    })
                {
                    continue;
                }
                let since = self
                    .post_join_maintenance_since(&group_id)
                    .map_or(0, |stamp| stamp.0)
                    .max(now.saturating_sub(TRANSPORT_RECONCILIATION_RETENTION_SECS));
                // Earlier-copy coverage is not a query for this copy. The mark
                // also prevents an already-running old quantum from re-crediting
                // it. This creates debt without resetting any retry budget.
                app.uncover_recovery_coverage(std::slice::from_ref(&route.route), since)?;
                self.runner_post_join.insert(
                    group_id,
                    Collection {
                        copy,
                        route: route.route.clone(),
                        since,
                        required: route.required.clone(),
                        boundary: false,
                        until: now,
                        active: false,
                        collecting: true,
                    },
                );
            }
            self.runner_post_join
                .retain(|group, _| waiting.contains(group));
            if self.runner_post_join.is_empty() {
                return Ok(());
            }
            if self
                .runner_post_join
                .values()
                .any(|collection| !collection.active)
            {
                // Consume the invalidation against the OLD generations before
                // replacing them. New ordinary generations retain healthy future
                // tails, so finishing collection never turns into idle polling.
                self.record_native_coverage(&app).await;
                self.adapter.require_fresh_activation().await;
                self.prepare_transport().await?;
                for collection in self.runner_post_join.values_mut() {
                    collection.active = true;
                }
                self.routing.wake_recovery_runner();
            }
            // Installation is the engine's collection-start hook. Under this
            // owner it means the fresh ordinary activation and its runnable debt,
            // rather than a grant-owned temporary subscription.
            for group_id in self.runner_post_join.keys() {
                if self
                    .runtime
                    .post_join_history_fetch(group_id)?
                    .is_some_and(|fetch| fetch.completion.is_none() && fetch.deadline_at.is_none())
                {
                    self.runtime.start_post_join_history_fetch(group_id)?;
                }
                self.runtime
                    .mark_post_join_subscription_installed(group_id)?;
            }
            self.synchronize_native_replay().await?;
            self.synchronize_recovery_loss(&app)?;
            self.record_native_coverage(&app).await;
            let observation = self.adapter.replay_admission().await;
            let staged = app.staged_recovery_routes()?;
            for (group_id, collection) in &mut self.runner_post_join {
                let Some(route) = routes.iter().find(|route| route.route == collection.route)
                else {
                    continue;
                };
                let TransportReconciliationRoute::Group(route_id) = collection.route else {
                    continue;
                };
                let sources = observation
                    .sources()
                    .filter(|source| source.group_routes().any(|id| *id == route_id))
                    .collect::<Vec<_>>();
                let boundary = observation.loss.is_none()
                    && !sources.is_empty()
                    && route.required.iter().all(|relay| {
                        sources
                            .iter()
                            .flat_map(|source| source.endpoints())
                            .any(|endpoint| {
                                transport_nostr::canonical_relay(&endpoint.endpoint().0) == *relay
                                    && endpoint.live_count().is_some()
                            })
                    });
                collection.boundary |= boundary;
                let covered = collection.boundary
                    && !staged.contains(&collection.route)
                    && sources.iter().all(|source| source.placed())
                    && app.recovery_coverage_covers(
                        &collection.route,
                        &route.required,
                        collection.since,
                        collection.until,
                    )?;
                let updates = if collection.boundary {
                    self.runtime.post_join_eose_updates(group_id)?
                } else {
                    Vec::new()
                };
                storage.with_transaction(|storage| {
                    for update in &updates {
                        storage.put_maintenance_obligation(update)?;
                    }
                    Ok::<_, cgka_traits::storage::StorageError>(())
                })?;
                let fetch = self.runtime.post_join_history_fetch(group_id)?;
                if fetch.is_some_and(|fetch| {
                    fetch.obligation_id == collection.copy && fetch.completion.is_none()
                }) {
                    if covered {
                        self.runtime
                            .finish_post_join_history_fetch(group_id, &collection.copy)?;
                        collection.collecting = false;
                    } else if !collection.boundary
                        && self
                            .runtime
                            .expire_post_join_history_fetch(group_id, &collection.copy)?
                            .is_some()
                    {
                        collection.collecting = false;
                    }
                } else if collection.boundary {
                    collection.collecting = false;
                }
            }
            Ok(())
        })
    }
}
