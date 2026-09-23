//! One owner-authorized, exact group-event acquisition through the account worker.
//! Production activation waits for the conforming SDK backend. The controlled
//! worker fixture enables this path explicitly; Unsupported never starts replay.

use super::*;
use crate::client::recovery::AttemptGrant;
use cgka_traits::transport::{Timestamp, TransportSource};
use cgka_traits::{
    TransportDelivery, TransportDeliveryPlane, TransportDeliverySource, TransportEndpoint,
};
use std::collections::VecDeque;
use tokio::sync::SemaphorePermit;
use transport_nostr_adapter::{
    NostrAcquisitionCancellation, NostrAcquisitionEnd, NostrAcquisitionError,
    NostrAcquisitionLimits, NostrAcquisitionRequest, NostrAcquisitionResult, NostrAcquisitionScope,
};
use transport_nostr_peeler::NostrTransportEvent;

pub(super) const MAX_ENDPOINTS: usize = 2;
pub(super) const MAX_EVENTS_PER_ENDPOINT: usize = 16;
pub(super) const MAX_BYTES_PER_ENDPOINT: usize = 128 * 1024;
pub(super) const MAX_ADMISSION_PER_TURN: usize = 1;
pub(super) const MAX_CONCURRENT_JOBS: usize = 2;
pub(super) const ADMISSION_YIELD_DELAY: Duration = Duration::from_millis(1);
const MAX_REQUEST_DURATION: Duration = Duration::from_secs(5);
static ACQUISITION_CREDITS: Semaphore = Semaphore::const_new(MAX_CONCURRENT_JOBS);

pub(super) struct Plan {
    credit: Option<SemaphorePermit<'static>>,
    grant: AttemptGrant,
    group: GroupId,
    route: [u8; 32],
    event_id: [u8; 32],
    request: NostrAcquisitionRequest,
}

pub(super) struct Job {
    plan: Plan,
    cancellation: NostrAcquisitionCancellation,
    handle: Option<
        JoinHandle<(
            SemaphorePermit<'static>,
            Result<NostrAcquisitionResult, NostrAcquisitionError>,
        )>,
    >,
    credit: Option<SemaphorePermit<'static>>,
    pending: VecDeque<(TransportEndpoint, NostrTransportEvent)>,
    ends: Vec<(TransportEndpoint, NostrAcquisitionEnd)>,
    unsupported: bool,
    invalid: bool,
    admitted: usize,
}

impl Drop for Job {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

/// Select before reserving so unrelated or broad demand stays with its existing
/// executor. A single known ID is eligible without guessing unknown history.
pub(super) fn prepare(
    client: &mut AppClient,
    seam: EpochBackfillExecutionSeam,
) -> Result<Option<Plan>, AppError> {
    let storage = client.app.account_storage(&client.state.label)?;
    let demands = storage.pending_recovery_demands()?;
    let Some(required) = demands
        .iter()
        .find(|demand| {
            demand.cause == storage_sqlite::RecoveryCause::KnownEvent
                && demand.group_id.is_some()
                && demand.known_event_id.is_some()
        })
        .map(|demand| demand.ticket.id)
    else {
        return Ok(None);
    };
    // Reserve process capacity before spending the owner's durable attempt.
    // No waiter or completed result can exist without a credit.
    let Ok(credit) = ACQUISITION_CREDITS.try_acquire() else {
        return Ok(None);
    };
    // The owner selects one predicate for this request without changing the
    // configured executor mode for unrelated recovery work.
    let Some(grant) = client.authorize_account_recovery_for(None, seam, Some(required))? else {
        return Ok(None);
    };
    let Some(obligation) = grant.plan().and_then(|plan| plan.first()) else {
        return Err(cgka_traits::storage::StorageError::Serialization(
            "bounded grant was not frozen".into(),
        )
        .into());
    };
    if grant.plan().is_none_or(|plan| plan.len() != 1)
        || obligation.scopes.len() != 1
        || obligation.cause != storage_sqlite::RecoveryCause::KnownEvent
    {
        return Err(cgka_traits::storage::StorageError::Serialization(
            "bounded grant changed selection".into(),
        )
        .into());
    }
    let scope = &obligation.scopes[0].goal;
    let (Some(route), Some(event_id), Some(group)) = (
        scope.transport_group_id,
        scope.known_event_id,
        obligation.group_id.clone(),
    ) else {
        return Err(cgka_traits::storage::StorageError::Serialization(
            "bounded group route disappeared".into(),
        )
        .into());
    };
    if scope.route_kind != 1
        || scope.admitted_endpoints.is_empty()
        || scope.admitted_endpoints.len() > MAX_ENDPOINTS
        || scope.required_endpoints != scope.admitted_endpoints
    {
        return Err(cgka_traits::storage::StorageError::Serialization(
            "bounded route is not eligible".into(),
        )
        .into());
    }
    let request = NostrAcquisitionRequest {
        account_id: client.adapter.account_id().clone(),
        scope: NostrAcquisitionScope::KnownEventIds(vec![event_id]),
        endpoints: scope
            .admitted_endpoints
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect(),
        limits: NostrAcquisitionLimits {
            max_endpoints: MAX_ENDPOINTS,
            max_requested_event_ids: 1,
            max_received_items_per_endpoint: MAX_EVENTS_PER_ENDPOINT,
            max_serialized_event_bytes_per_endpoint: MAX_BYTES_PER_ENDPOINT,
            max_duration: MAX_REQUEST_DURATION,
        },
    };
    request.validate().map_err(|_| {
        cgka_traits::storage::StorageError::Serialization("bounded request invalid".into())
    })?;
    Ok(Some(Plan {
        credit: Some(credit),
        grant,
        group,
        route,
        event_id,
        request,
    }))
}

impl Job {
    pub(super) fn start(client: &AppClient, mut plan: Plan) -> Self {
        let adapter = client.adapter.clone();
        let request = plan.request.clone();
        let credit = plan.credit.take().expect("authorized plan owns capacity");
        let cancellation = NostrAcquisitionCancellation::new();
        let token = cancellation.clone();
        let handle = tokio::spawn(async move {
            let result = adapter.acquire_history(request, token).await;
            (credit, result)
        });
        Self {
            plan,
            cancellation,
            handle: Some(handle),
            credit: None,
            pending: VecDeque::new(),
            ends: Vec::new(),
            unsupported: false,
            invalid: false,
            admitted: 0,
        }
    }

    pub(super) fn waiting(&self) -> bool {
        self.handle.is_some()
    }
    pub(super) async fn wait(
        &mut self,
    ) -> Result<
        (
            SemaphorePermit<'static>,
            Result<NostrAcquisitionResult, NostrAcquisitionError>,
        ),
        tokio::task::JoinError,
    > {
        self.handle
            .as_mut()
            .expect("waiting job has a handle")
            .await
    }

    pub(super) fn accept(
        &mut self,
        completed: Result<
            (
                SemaphorePermit<'static>,
                Result<NostrAcquisitionResult, NostrAcquisitionError>,
            ),
            tokio::task::JoinError,
        >,
    ) {
        self.handle.take();
        match completed {
            Ok((credit, Ok(result))) => {
                self.credit = Some(credit); // Held until the last admission/checkpoint.
                if result.endpoints.len() != self.plan.request.endpoints.len() {
                    self.invalid = true;
                    return;
                }
                for endpoint in result.endpoints {
                    if !self.plan.request.endpoints.contains(&endpoint.endpoint)
                        || self.ends.iter().any(|(seen, _)| *seen == endpoint.endpoint)
                        || endpoint.events.len() > MAX_EVENTS_PER_ENDPOINT
                        || endpoint.stats.retained_high_water_event_bytes > MAX_BYTES_PER_ENDPOINT
                        || endpoint
                            .events
                            .iter()
                            .try_fold(0usize, |sum, event| {
                                serde_json::to_vec(event)
                                    .ok()
                                    .and_then(|bytes| sum.checked_add(bytes.len()))
                            })
                            .is_none_or(|bytes| bytes > MAX_BYTES_PER_ENDPOINT)
                    {
                        self.invalid = true;
                        self.pending.clear();
                        return;
                    }
                    let relay = endpoint.endpoint;
                    self.ends.push((relay.clone(), endpoint.end));
                    self.pending.extend(
                        endpoint
                            .events
                            .into_iter()
                            .map(|event| (relay.clone(), event)),
                    );
                }
            }
            Ok((credit, Err(NostrAcquisitionError::Unsupported))) => {
                self.credit = Some(credit);
                self.unsupported = true;
            }
            Ok((credit, Err(_))) => {
                self.credit = Some(credit);
                self.invalid = true;
            }
            Err(_) => {
                self.invalid = true;
            }
        }
    }

    pub(super) fn ready(&self) -> bool {
        self.handle.is_none()
    }
    pub(super) fn has_input(&self) -> bool {
        !self.pending.is_empty()
    }

    pub(super) async fn admit_one(
        &mut self,
        client: &mut AppClient,
    ) -> Result<SyncSummary, AppError> {
        let Some((endpoint, event)) = self.pending.pop_front() else {
            return Ok(SyncSummary::default());
        };
        let storage = client.app.account_storage(&client.state.label)?;
        storage.synchronize_account_delivery_loss(&client.state.label)?;
        client.observe_recovery_route_policy()?;
        let current = storage.recovery_revision_fence()?;
        let expected = &self.plan.grant.fence;
        if current.loss_revision != expected.loss_revision
            || current.route_revision != expected.route_revision
            || (self.admitted == 0 && current.inventory_revision != expected.inventory_revision)
            || !expected
                .obligations
                .iter()
                .all(|entry| current.obligations.contains(entry))
        {
            self.invalid = true;
            self.pending.clear();
            return Ok(SyncSummary::default());
        }
        if !event
            .id
            .eq_ignore_ascii_case(&hex::encode(self.plan.event_id))
        {
            self.invalid = true;
            self.pending.clear();
            return Ok(SyncSummary::default());
        }
        let scope = &self.plan.grant.plan().expect("frozen bounded grant")[0].scopes[0].goal;
        if event.created_at > scope.until_seconds
            || scope
                .since_seconds
                .is_some_and(|since| event.created_at < since)
        {
            self.invalid = true;
            self.pending.clear();
            return Ok(SyncSummary::default());
        }
        let message = match event.to_transport_message() {
            Ok(message) => message,
            Err(_) => {
                self.invalid = true;
                self.pending.clear();
                return Ok(SyncSummary::default());
            }
        };
        if !matches!(&message.envelope, cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id } if transport_group_id.as_slice() == self.plan.route)
        {
            self.invalid = true;
            self.pending.clear();
            return Ok(SyncSummary::default());
        }
        let summary = client
            .ingest_received_delivery(TransportDelivery {
                account_id: self.plan.request.account_id.clone(),
                group_id_hint: Some(self.plan.group.clone()),
                message,
                received_at: Timestamp(crate::unix_now_seconds()),
                source: TransportDeliverySource {
                    transport: TransportSource(transport_nostr_peeler::NOSTR_SOURCE.into()),
                    plane: TransportDeliveryPlane::Group,
                    endpoint: Some(endpoint),
                    subscription_id: None,
                    wire: None,
                },
            })
            .await?;
        self.admitted += 1;
        Ok(summary)
    }

    pub(super) fn finish(self, client: &mut AppClient) -> Result<(), AppError> {
        let storage = client.app.account_storage(&client.state.label)?;
        storage.synchronize_account_delivery_loss(&client.state.label)?;
        client.observe_recovery_route_policy()?;
        let obligation = &self.plan.grant.plan().expect("frozen bounded grant")[0];
        let scope = &obligation.scopes[0];
        let retained = storage.retained_recovery_event(
            &storage_sqlite::TransportReconciliationRoute::Group(self.plan.route),
            &self.plan.event_id,
            scope.goal.since_seconds,
            scope.goal.until_seconds,
        )?;
        let endpoints = self
            .plan
            .request
            .endpoints
            .iter()
            .map(|endpoint| {
                let end = self
                    .ends
                    .iter()
                    .find(|(seen, _)| seen == endpoint)
                    .map(|(_, end)| *end);
                storage_sqlite::RecoveryEndpointCheckpoint {
                    endpoint: endpoint.0.clone(),
                    outcome: if self.unsupported {
                        storage_sqlite::RecoveryScopeOutcome::Unsupported
                    } else if self.invalid {
                        storage_sqlite::RecoveryScopeOutcome::Unknown
                    } else if end == Some(NostrAcquisitionEnd::RequestPolicySatisfied) {
                        storage_sqlite::RecoveryScopeOutcome::Partial
                    } else {
                        storage_sqlite::RecoveryScopeOutcome::Unavailable
                    },
                    exhaustive: false,
                    admission_complete: false,
                    first_boundary: end == Some(NostrAcquisitionEnd::RequestPolicySatisfied),
                }
            })
            .collect();
        storage.checkpoint_recovery_obligation(
            &self.plan.grant.fence,
            self.plan.grant.reservation.attempt_serial,
            obligation.id,
            &[storage_sqlite::RecoveryScopeCheckpoint {
                token: scope.token.clone(),
                endpoints,
                retained_known_event: retained,
            }],
            if self.unsupported {
                storage_sqlite::RecoveryEligibility::WaitingCapability
            } else {
                storage_sqlite::RecoveryEligibility::Retry
            },
        )?;
        Ok(())
    }
}
