//! Immutable comparison I/O for a worker-owned recovery grant. The task has no
//! account storage, engine, session, or event-queue authority.

use super::*;
use std::sync::{Arc, Mutex};
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;
use transport_nostr_adapter::{NostrReconciliationProgress, SubscriptionAttempt};

/// The bounded off-worker shape. A larger route retains the existing inline
/// executor with its complete endpoint set.
pub(crate) const MAX_COMPARISON_ENDPOINTS_PER_ROUTE: usize = 4;

struct MemoryProgress {
    cursor: Mutex<Option<[u8; 32]>>,
}

impl NostrReconciliationProgress for MemoryProgress {
    fn load_cursor(&self) -> Result<Option<[u8; 32]>, cgka_traits::TransportAdapterError> {
        Ok(*self.cursor.lock().expect("comparison progress mutex"))
    }

    fn save_cursor(
        &self,
        cursor: Option<[u8; 32]>,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        *self.cursor.lock().expect("comparison progress mutex") = cursor;
        Ok(())
    }
}

struct FrozenRoute {
    inventory: super::super::recovery::FrozenRecoveryInventory,
    initial_cursor: Option<[u8; 32]>,
}

pub(crate) enum ComparisonRouteWorkResult {
    Skipped,
    TimedOut,
    Returned(OwnedComparisonResult),
}

pub(crate) struct ComparisonRouteResult {
    route: TransportReconciliationRoute,
    initial_cursor: Option<[u8; 32]>,
    cursor: Option<[u8; 32]>,
    result: ComparisonRouteWorkResult,
}

pub(crate) struct ComparisonNetworkResult {
    routes: Vec<ComparisonRouteResult>,
}

#[cfg(test)]
impl ComparisonNetworkResult {
    pub(crate) fn outcome_kinds_for_test(&self) -> Vec<&'static str> {
        self.routes
            .iter()
            .map(|route| match &route.result {
                ComparisonRouteWorkResult::Skipped => "route_skipped",
                ComparisonRouteWorkResult::TimedOut => "route_timed_out",
                ComparisonRouteWorkResult::Returned(Ok(None)) => "route_unsupported",
                ComparisonRouteWorkResult::Returned(Err(_)) => "route_error",
                ComparisonRouteWorkResult::Returned(Ok(Some((summary, events)))) => {
                    if summary.relays_failed > 0 {
                        "route_relay_failed"
                    } else if events.is_empty() {
                        "route_no_events"
                    } else {
                        "route_events"
                    }
                }
            })
            .collect()
    }
}

/// Dropping the worker's handle cancels I/O and drops all unadmitted events.
pub(crate) struct ComparisonNetworkJob {
    handle: JoinHandle<(OwnedSemaphorePermit, ComparisonNetworkResult)>,
}

impl Drop for ComparisonNetworkJob {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl ComparisonNetworkJob {
    pub(crate) fn start(
        client: &AppClient,
        grant: &AttemptGrant,
        credit: OwnedSemaphorePermit,
    ) -> Result<Self, AppError> {
        let storage = client.app.account_storage(&client.state.label)?;
        let routes = grant
            .inventory
            .iter()
            .map(|inventory| {
                Ok(FrozenRoute {
                    inventory: inventory.clone(),
                    initial_cursor: storage
                        .transport_reconciliation_replay_cursor(&inventory.route)?,
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let adapter = client.adapter.clone();
        let handle = tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + TRANSPORT_RECONCILIATION_QUANTUM;
            let mut results = Vec::with_capacity(routes.len());
            for frozen in routes {
                let FrozenRoute {
                    inventory,
                    initial_cursor,
                } = frozen;
                if tokio::time::Instant::now() >= deadline {
                    results.push(ComparisonRouteResult {
                        route: inventory.route,
                        initial_cursor,
                        cursor: initial_cursor,
                        result: ComparisonRouteWorkResult::Skipped,
                    });
                    continue;
                }
                let progress = Arc::new(MemoryProgress {
                    cursor: Mutex::new(initial_cursor),
                });
                let run = async {
                    match inventory.work {
                        TransportReconciliationWork::Inbox(endpoints) => {
                            adapter
                                .reconcile_inbox_history(
                                    endpoints,
                                    &inventory.items,
                                    inventory.since,
                                    inventory.until,
                                    progress.as_ref(),
                                )
                                .await
                        }
                        TransportReconciliationWork::Group(group) => {
                            adapter
                                .reconcile_group_history(
                                    group,
                                    &inventory.items,
                                    inventory.since,
                                    inventory.until,
                                    progress.as_ref(),
                                )
                                .await
                        }
                    }
                };
                let result = match tokio::time::timeout_at(deadline, run).await {
                    Ok(value) => ComparisonRouteWorkResult::Returned(value),
                    Err(_) => ComparisonRouteWorkResult::TimedOut,
                };
                let cursor = *progress.cursor.lock().expect("comparison progress mutex");
                results.push(ComparisonRouteResult {
                    route: inventory.route,
                    initial_cursor,
                    cursor,
                    result,
                });
            }
            (credit, ComparisonNetworkResult { routes: results })
        });
        Ok(Self { handle })
    }

    pub(crate) async fn wait(
        &mut self,
    ) -> Result<(OwnedSemaphorePermit, ComparisonNetworkResult), tokio::task::JoinError> {
        (&mut self.handle).await
    }
}

impl AppClient {
    /// An advisory preflight used only when the shared credit pool is empty.
    /// Independent debt still reaches the legacy executor. The actual frozen
    /// grant is checked again after authorization when a credit exists.
    pub(crate) fn comparison_only_waiting_for_credit(&self) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        if !storage.recovery_comparison()?.pending()
            || storage
                .pending_recovery_demands()?
                .iter()
                .any(|demand| demand.cause != storage_sqlite::RecoveryCause::IncrementalHistory)
            || !storage
                .recovery_loss_snapshot(
                    &self.state.label,
                    storage_sqlite::RecoveryLossCause::Queue,
                )?
                .is_empty()
            || !storage
                .recovery_loss_snapshot(
                    &self.state.label,
                    storage_sqlite::RecoveryLossCause::NotificationConsumer,
                )?
                .is_empty()
        {
            return Ok(false);
        }
        let routes = self.routing.snapshot();
        Ok(
            routes.local_inbox_endpoints.len() <= MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                && routes
                    .group_routes
                    .iter()
                    .all(|route| route.endpoints.len() <= MAX_COMPARISON_ENDPOINTS_PER_ROUTE),
        )
    }

    /// The sole eligible automatic selection is the comparison and, when
    /// present, its own IncrementalHistory obligation. The frozen grant is the
    /// authority; an earlier pending-demand probe never decides this.
    pub(crate) fn comparison_offload_eligible(
        &self,
        grant: &AttemptGrant,
    ) -> Result<bool, AppError> {
        if grant.comparison_revision.is_none()
            || grant.inventory.len() > TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS
            || grant.comparison_plan.as_ref().is_none_or(|plan| {
                plan.routes.len() > TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS
                    || plan.routes.iter().any(|route| {
                        route.admitted_endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                            || route.required_endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                    })
            })
            || grant.inventory.iter().any(|route| match &route.work {
                TransportReconciliationWork::Inbox(endpoints) => {
                    endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                }
                TransportReconciliationWork::Group(group) => {
                    group.endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                }
            })
        {
            return Ok(false);
        }
        let Some(plan) = grant.plan() else {
            return Ok(false);
        };
        if plan.len() > 1
            || plan.iter().any(|item| {
                item.cause != storage_sqlite::RecoveryCause::IncrementalHistory
                    || item.scopes.iter().any(|scope| {
                        scope.goal.admitted_endpoints.len() > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                            || scope.goal.required_endpoints.len()
                                > MAX_COMPARISON_ENDPOINTS_PER_ROUTE
                    })
            })
        {
            return Ok(false);
        }
        let selected = plan.iter().map(|item| item.id).collect::<Vec<_>>();
        if selected.len() != grant.fence.obligations.len()
            || !selected.iter().all(|id| {
                grant
                    .fence
                    .obligations
                    .iter()
                    .any(|(candidate, _)| candidate == id)
            })
        {
            return Ok(false);
        }
        let storage = self.app.account_storage(&self.state.label)?;
        let pending = storage.pending_recovery_demands()?;
        Ok(grant.fence.obligations.iter().all(|(id, revision)| {
            pending.iter().any(|demand| {
                demand.ticket.id == *id
                    && demand.ticket.revision == *revision
                    && demand.cause == storage_sqlite::RecoveryCause::IncrementalHistory
            })
        }))
    }

    pub(crate) async fn activate_comparison_grant(
        &mut self,
        grant: &AttemptGrant,
    ) -> Result<SubscriptionAttempt, AppError> {
        let mut activation = EpochBackfillActivationOutcome::Failed;
        self.activate_recovery_grant_inner(grant, None, &mut activation)
            .await
            .map_err(|failure| failure.source)?;
        self.adapter
            .account_subscription_attempt()
            .await
            .ok_or_else(|| {
                cgka_traits::TransportAdapterError::Subscription(
                    "activated comparison subscription disappeared".into(),
                )
                .into()
            })
    }

    pub(crate) async fn finish_comparison_grant(
        &mut self,
        grant: AttemptGrant,
        attempt: SubscriptionAttempt,
        network: ComparisonNetworkResult,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        storage.synchronize_account_delivery_loss(&self.state.label)?;
        drop(self.transport_receipts()?);
        self.observe_recovery_route_policy()?;
        let current = storage.recovery_revision_fence()?;
        let slot = storage.recovery_comparison()?;
        let stable = current.loss_revision == grant.fence.loss_revision
            && current.route_revision == grant.fence.route_revision
            && current.inventory_revision == grant.fence.inventory_revision
            && grant
                .fence
                .obligations
                .iter()
                .all(|selected| current.obligations.contains(selected))
            && slot.pending()
            && Some(slot.revision) == grant.comparison_revision
            && slot.attempt_serial == grant.reservation.attempt_serial
            && slot.frozen_revision == slot.revision
            && self.adapter.account_subscription_attempt().await == Some(attempt);
        if !stable {
            // The network task never wrote to SQLCipher or the delivery queue.
            // A changed grant or activation discards every proposed byte and
            // leaves durable comparison and coverage debt for the next owner.
            return Ok(EpochBackfillRunOutcome::Deferred);
        }
        // Acquisition may have consumed its entire quantum before the worker
        // joins. Give delivery of the already owned batch a separate bounded
        // admission window.
        let admission_deadline = tokio::time::Instant::now() + TRANSPORT_RECONCILIATION_QUANTUM;
        let mut outcomes = Vec::with_capacity(network.routes.len());
        for route in network.routes {
            outcomes.push(
                self.admit_comparison_route(&storage, route, admission_deadline)
                    .await?,
            );
        }
        let mut counts = DrainCounts::default();
        let mut verdict = None;
        let summary = self
            .complete_recovery_grant_inner(&grant, None, &mut counts, &mut verdict, outcomes)
            .await
            .map_err(|failure| {
                self.pending_failed_sync_summary
                    .merge(failure.partial_summary);
                failure.source
            })?;
        Ok(EpochBackfillRunOutcome::Incomplete(summary))
    }

    async fn admit_comparison_route(
        &self,
        storage: &storage_sqlite::SqliteAccountStorage,
        route: ComparisonRouteResult,
        admission_deadline: tokio::time::Instant,
    ) -> Result<
        (
            TransportReconciliationRoute,
            storage_sqlite::RecoveryComparisonOutcome,
        ),
        AppError,
    > {
        let mut cursor_safe_to_advance = true;
        let outcome = match route.result {
            ComparisonRouteWorkResult::Skipped => {
                storage_sqlite::RecoveryComparisonOutcome::ServicedPartial
            }
            ComparisonRouteWorkResult::TimedOut => {
                storage_sqlite::RecoveryComparisonOutcome::TransientFailure
            }
            ComparisonRouteWorkResult::Returned(Ok(None)) => {
                storage_sqlite::RecoveryComparisonOutcome::Unsupported
            }
            ComparisonRouteWorkResult::Returned(Err(_)) => {
                storage_sqlite::RecoveryComparisonOutcome::TransientFailure
            }
            ComparisonRouteWorkResult::Returned(Ok(Some((summary, events)))) => {
                let mut submitted = true;
                for event in events {
                    let queue = async {
                        #[cfg(test)]
                        if let Ok(Some(action)) = TEST_COMPARISON_QUEUE_ACTIONS
                            .try_with(|actions| actions.borrow_mut().pop_front())
                        {
                            match action {
                                TestComparisonQueueAction::Fail => {
                                    return Err(cgka_traits::TransportAdapterError::Subscription(
                                        "injected comparison queue failure".into(),
                                    ));
                                }
                                TestComparisonQueueAction::Block => {
                                    std::future::pending::<()>().await;
                                }
                            }
                        }
                        self.adapter.queue_reconciled_event(event).await
                    };
                    if !matches!(
                        tokio::time::timeout_at(admission_deadline, queue).await,
                        Ok(Ok(_))
                    ) {
                        submitted = false;
                        break;
                    }
                }
                if !submitted || summary.relays_failed > 0 {
                    cursor_safe_to_advance = submitted;
                    storage_sqlite::RecoveryComparisonOutcome::TransientFailure
                } else {
                    storage_sqlite::RecoveryComparisonOutcome::ServicedUnknown
                }
            }
        };
        // A failed or timed-out queue step leaves an unqueued suffix whose
        // IDs cannot be mapped back to individual cursor positions. Keep
        // the entire pre-pass cursor so the next attempt can replay it.
        if cursor_safe_to_advance && route.cursor != route.initial_cursor {
            storage.advance_transport_reconciliation_replay_cursor(&route.route, route.cursor)?;
        }
        Ok((route.route, outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{
        ScriptedEosePump, ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
        scripted_eose_pump,
    };
    use cgka_traits::GroupStorage;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
    use std::cell::RefCell;
    use std::future::Future as _;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    fn candidate_for_route(route: [u8; 32]) -> transport_nostr_adapter::NostrRelayEvent {
        let signed = EventBuilder::new(Kind::MlsGroupMessage, "queue boundary")
            .tags([Tag::custom("h", [hex::encode(route)])])
            .finalize(&Keys::generate())
            .unwrap();
        transport_nostr_adapter::NostrRelayEvent {
            endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
            subscription_id: None,
            event: transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&signed).unwrap(),
        }
    }

    fn candidate() -> transport_nostr_adapter::NostrRelayEvent {
        candidate_for_route([7; 32])
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abort_request_keeps_credit_until_network_future_is_dropped() {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let credit = capacity.clone().try_acquire_owned().unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let waiting = entered.notified();
        tokio::pin!(waiting);
        waiting.as_mut().enable();
        let handle = tokio::spawn({
            let entered = entered.clone();
            async move {
                entered.notify_one();
                std::future::pending::<()>().await;
                (credit, ComparisonNetworkResult { routes: Vec::new() })
            }
        });
        let job = ComparisonNetworkJob { handle };
        waiting.await;
        drop(job);
        // abort() has only requested cancellation. The task still owns the
        // permit until Tokio drops its future on the next scheduler turn.
        assert_eq!(capacity.available_permits(), 0);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while capacity.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled task releases its own permit");
        assert_eq!(capacity.available_permits(), 1);
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        _pump: ScriptedEosePump,
        client: AppClient,
        storage: storage_sqlite::SqliteAccountStorage,
    }

    async fn fixture() -> Fixture {
        fixture_with_group_relays(None).await
    }

    async fn fixture_with_group_relays(relays: Option<Vec<String>>) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let pump = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        client
            .create_group_with_options(
                "comparison offload",
                &[],
                crate::AppCreateGroupOptions {
                    relays,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        client.request_bounded_comparison().unwrap();
        let storage = app.account_storage("alice").unwrap();
        Fixture {
            _dir: dir,
            _pump: pump,
            client,
            storage,
        }
    }

    fn network_result(
        route: TransportReconciliationRoute,
        cursor: Option<[u8; 32]>,
    ) -> ComparisonNetworkResult {
        ComparisonNetworkResult {
            routes: vec![ComparisonRouteResult {
                route,
                initial_cursor: None,
                cursor,
                result: ComparisonRouteWorkResult::Returned(Ok(Some((
                    transport_nostr_adapter::NostrReconciliationSummary {
                        relays_succeeded: 1,
                        ..Default::default()
                    },
                    Vec::new(),
                )))),
            }],
        }
    }

    #[tokio::test]
    async fn comparison_more_than_four_endpoints_keeps_inline_grant() {
        let relays = (0..5)
            .map(|index| format!("wss://relay-{index}.example"))
            .collect();
        let mut fixture = fixture_with_group_relays(Some(relays)).await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        assert!(grant.inventory.iter().any(|route| match &route.work {
            TransportReconciliationWork::Group(group) => group.endpoints.len() == 5,
            TransportReconciliationWork::Inbox(_) => false,
        }));
        assert!(!fixture.client.comparison_offload_eligible(&grant).unwrap());
        let serial = grant.reservation.attempt_serial;
        fixture
            .client
            .execute_pending_epoch_backfill_grant(grant)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .storage
                .recovery_retry_state()
                .unwrap()
                .attempt_serial,
            serial,
            "inline fallback executes the selected grant without a second authorization"
        );
    }

    #[tokio::test]
    async fn comparison_stale_result_preserves_cursor_and_debt() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        assert!(fixture.client.comparison_offload_eligible(&grant).unwrap());
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant)
            .await
            .unwrap();
        let new_goals = fixture
            .client
            .comparison_route_goals(unix_now_seconds())
            .unwrap();
        fixture
            .storage
            .join_recovery_comparison(
                &[9; 16],
                crate::client::recovery::wall_now_ms().unwrap(),
                &new_goals,
            )
            .unwrap();
        let result = fixture
            .client
            .finish_comparison_grant(grant, attempt, network_result(route.clone(), Some([8; 32])))
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None
        );
        assert!(fixture.storage.recovery_comparison().unwrap().pending());
    }

    #[tokio::test]
    async fn comparison_inventory_change_rejects_owned_result() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant
            .inventory
            .iter()
            .find_map(|item| match item.route {
                TransportReconciliationRoute::Group(id) => Some(id),
                TransportReconciliationRoute::Inbox => None,
            })
            .unwrap();
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant)
            .await
            .unwrap();
        let before = fixture
            .storage
            .recovery_revision_fence()
            .unwrap()
            .inventory_revision;
        fixture
            .storage
            .record_transport_reconciliation_item(
                &TransportReconciliationRoute::Group(route),
                &TransportReconciliationItem {
                    event_id: [5; 32],
                    created_at: unix_now_seconds(),
                },
            )
            .unwrap();
        fixture
            .storage
            .delete_transport_group_route(&route)
            .unwrap();
        assert!(
            fixture
                .storage
                .recovery_revision_fence()
                .unwrap()
                .inventory_revision
                > before
        );
        let result = fixture
            .client
            .finish_comparison_grant(
                grant,
                attempt,
                network_result(TransportReconciliationRoute::Inbox, Some([8; 32])),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&TransportReconciliationRoute::Inbox)
                .unwrap(),
            None
        );
        assert!(fixture.storage.recovery_comparison().unwrap().pending());
    }

    #[tokio::test]
    async fn comparison_subscription_change_rejects_owned_result() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant)
            .await
            .unwrap();
        fixture.client.adapter.require_fresh_activation().await;
        fixture
            .client
            .runtime
            .activate_transport(None)
            .await
            .unwrap();
        assert_ne!(
            fixture.client.adapter.account_subscription_attempt().await,
            Some(attempt)
        );
        let result = fixture
            .client
            .finish_comparison_grant(grant, attempt, network_result(route.clone(), Some([8; 32])))
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None
        );
        assert!(fixture.storage.recovery_comparison().unwrap().pending());
    }

    #[tokio::test]
    async fn comparison_worker_join_persists_advisory_cursor_before_settlement() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        assert!(fixture.client.comparison_offload_eligible(&grant).unwrap());
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant)
            .await
            .unwrap();
        let result = fixture
            .client
            .finish_comparison_grant(grant, attempt, network_result(route.clone(), Some([8; 32])))
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32])
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn comparison_join_admits_owned_event_after_real_delivery_backpressure() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let (route, group_route) = grant
            .inventory
            .iter()
            .find_map(|item| match item.route {
                TransportReconciliationRoute::Group(id) => Some((item.route.clone(), id)),
                TransportReconciliationRoute::Inbox => None,
            })
            .expect("fixture has a selected group route");
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant)
            .await
            .unwrap();
        let event = candidate_for_route(group_route);
        // Saturate the shared transport queue with another account's route.
        // Its account queue can hold this prefix; Alice's queue stays empty
        // until the comparison result is admitted and owner-drained.
        crate::AccountHome::open(fixture._dir.path())
            .create_account("bob")
            .unwrap();
        let mut bob = client_on_app_relay_plane(&fixture.client.app, "bob").await;
        let bob_group = bob.create_group("backpressure source", &[]).await.unwrap();
        let bob_record = fixture
            .client
            .app
            .group("bob", &hex::encode(bob_group))
            .unwrap()
            .unwrap();
        let bob_route: [u8; 32] = hex::decode(bob_record.nostr_routing.nostr_group_id_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let bob_event = candidate_for_route(bob_route);
        let adapter = bob.adapter.clone();
        let mut context = Context::from_waker(Waker::noop());
        tokio::task::unconstrained(async {
            for _ in 0..1024 {
                assert_eq!(
                    adapter
                        .queue_reconciled_event(bob_event.clone())
                        .await
                        .unwrap(),
                    1
                );
            }
            // Keep Tokio's cooperative yield from running the router during
            // the fill. The next real adapter send must pend on its buffer.
            let mut blocked = Box::pin(adapter.queue_reconciled_event(bob_event.clone()));
            assert!(matches!(blocked.as_mut().poll(&mut context), Poll::Pending));
        })
        .await;

        let mut network = network_result(route.clone(), Some([8; 32]));
        network.routes[0].result = ComparisonRouteWorkResult::Returned(Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            vec![event],
        ))));
        let mut finish = Box::pin(
            fixture
                .client
                .finish_comparison_grant(grant, attempt, network),
        );
        assert!(matches!(finish.as_mut().poll(&mut context), Poll::Pending));
        let result = tokio::time::timeout(Duration::from_secs(15), finish)
            .await
            .expect("the owner drains after its real queue send pends")
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32]),
        );
        assert!(fixture.client.adapter.pending_delivery_overflow().is_none());
        assert!(bob.adapter.pending_delivery_overflow().is_none());
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                fixture.client.adapter.receive_account_delivery()
            )
            .await
            .is_err(),
            "owner continuation drained Alice's admitted event"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn comparison_join_timeout_keeps_cursor_and_retry_debt_after_real_queue_block() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let (route, group_route) = grant
            .inventory
            .iter()
            .find_map(|item| match item.route {
                TransportReconciliationRoute::Group(id) => Some((item.route.clone(), id)),
                TransportReconciliationRoute::Inbox => None,
            })
            .expect("fixture has a selected group route");
        fixture
            .client
            .activate_comparison_grant(&grant)
            .await
            .unwrap();
        let event = candidate_for_route(group_route);
        let adapter = fixture.client.adapter.clone();
        let router_pause = fixture.client.app.relay_plane.pause_router_for_test().await;
        let mut context = Context::from_waker(Waker::noop());
        tokio::task::unconstrained(async {
            for _ in 0..1024 {
                assert_eq!(
                    adapter.queue_reconciled_event(event.clone()).await.unwrap(),
                    1
                );
            }
            let mut blocked = Box::pin(adapter.queue_reconciled_event(event.clone()));
            assert!(matches!(blocked.as_mut().poll(&mut context), Poll::Pending));
        })
        .await;
        let mut network = network_result(route.clone(), Some([8; 32]));
        network.routes[0].result = ComparisonRouteWorkResult::Returned(Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            vec![event],
        ))));
        let route_result = network.routes.remove(0);
        let admission = fixture.client.admit_comparison_route(
            &fixture.storage,
            route_result,
            tokio::time::Instant::now() - Duration::from_millis(1),
        );
        // The elapsed admission deadline meets the same genuinely pending
        // production send while the test holds only the router task. Tokio's
        // real timeout fires before that task is restarted.
        let (route_key, outcome) = tokio::time::timeout(Duration::from_secs(1), admission)
            .await
            .expect("elapsed admission timeout fires on the real queue send")
            .unwrap();
        assert!(matches!(
            outcome,
            storage_sqlite::RecoveryComparisonOutcome::TransientFailure
        ));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None
        );
        drop(router_pause);
        let mut counts = DrainCounts::default();
        let mut verdict = None;
        tokio::time::timeout(
            Duration::from_secs(15),
            fixture.client.complete_recovery_grant_inner(
                &grant,
                None,
                &mut counts,
                &mut verdict,
                vec![(route_key, outcome)],
            ),
        )
        .await
        .expect("owner drains and checkpoints after timed-out admission")
        .unwrap();
        let slot = fixture.storage.recovery_comparison().unwrap();
        assert!(slot.pending());
        assert!(!slot.plan.unwrap().retry_routes.is_empty());
        assert!(fixture.client.adapter.pending_delivery_overflow().is_none());
    }

    #[tokio::test]
    async fn comparison_failed_queue_keeps_prepass_cursor_for_unqueued_suffix() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant)
            .await
            .unwrap();
        let mut network = network_result(route.clone(), Some([8; 32]));
        network.routes[0].result = ComparisonRouteWorkResult::Returned(Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            vec![candidate()],
        ))));
        let result = TEST_COMPARISON_QUEUE_ACTIONS
            .scope(
                RefCell::new([TestComparisonQueueAction::Fail].into()),
                async {
                    fixture
                        .client
                        .finish_comparison_grant(grant, attempt, network)
                        .await
                },
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None,
        );
        assert!(fixture.storage.recovery_comparison().unwrap().pending());
    }

    #[tokio::test]
    async fn comparison_partial_pass_rotates_cursor_and_keeps_retry_debt() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture
            .client
            .activate_comparison_grant(&grant)
            .await
            .unwrap();
        let mut network = network_result(route.clone(), Some([8; 32]));
        network.routes[0].result = ComparisonRouteWorkResult::Returned(Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_failed: 1,
                ..Default::default()
            },
            Vec::new(),
        ))));
        fixture
            .client
            .finish_comparison_grant(grant, attempt, network)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .storage
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32])
        );
        let slot = fixture.storage.recovery_comparison().unwrap();
        assert!(slot.pending());
        assert!(!slot.plan.unwrap().retry_routes.is_empty());
    }
}
