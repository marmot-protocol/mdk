//! Immutable comparison I/O for a worker-owned recovery grant. The task has no
//! account storage, engine, session, or event-queue authority. The worker
//! admits what it fetched a few events per turn, never through the live queue.
//! Native and comparison frames share that admission budget and the known
//! same-group `(timestamp, id)` minimum. An unfinished native range fences
//! comparison admission for its group without spending acquisition credit.
//! This orders available input, not history a relay has not returned yet.

use super::super::{EpochGapBound, EpochGapWindow, EpochGapWindowKey, EpochGapWindows};
use super::*;
use futures::{StreamExt, stream};
use std::collections::VecDeque;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use storage_sqlite::RecoveryComparisonOutcome as Outcome;
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;
use transport_nostr::MarmotRelayPlane;
use transport_nostr_adapter::{
    NostrAcquisitionCancellation, NostrAcquisitionEnd, NostrAcquisitionRequest,
    NostrAcquisitionScope, NostrReconciliationProgress, ReplayCapturePlan, SubscriptionAttempt,
};

/// Owned events one worker turn admits before commands and live input run.
pub(crate) const MAX_COMPARISON_ADMISSION_PER_TURN: usize = 4;

/// Newest-first raw REQ page size, below common relay filter clamps.
const EPOCH_GAP_WINDOW_PAGE_EVENTS: usize = 256;
/// Raw events per relay and pass, including overlapping boundaries.
const EPOCH_GAP_WINDOW_MAX_EVENTS_PER_RELAY: usize = 16_384;
/// Serialized event bytes a window fetch takes from each relay.
const EPOCH_GAP_WINDOW_MAX_BYTES_PER_RELAY: usize = 4 * 1024 * 1024;
/// Longest a window fetch may run, inside what remains of the pass deadline.
const EPOCH_GAP_WINDOW_MAX_DURATION: Duration = Duration::from_secs(3);
/// Eviction only restarts acquisition; no durable budget belongs to a hint.
const EPOCH_GAP_WINDOW_MAX_HINTS: usize = 1024;
/// At most 32 KiB of two-u64 range boundaries per hint.
const EPOCH_GAP_WINDOW_MAX_BOUNDARIES: usize = 2048;

type WindowProgress = Vec<WindowObservation>;

struct WindowObservation {
    key: EpochGapWindowKey,
    hint: EpochGapWindow,
    reached: bool,
    /// Includes copies deduplicated in favor of comparison or another peer.
    offered: HashMap<[u8; 32], WindowOffer>,
}

enum WindowOffer {
    Unconverted,
    /// One raw event may route to several account-scoped deliveries.
    Pending(usize),
    Unretained,
}

#[cfg(test)]
mod window_paging_tests;

/// What the worker keeps while a comparison runs off the worker: the live
/// subscription attempt admission must still own, and the job's execution
/// bracket (loss attempt and audit rows). The bracket is boxed so worker enums
/// that park a pass stay small.
pub(crate) struct ComparisonExecution {
    attempt: Option<SubscriptionAttempt>,
    execution: Box<RecoveryExecutionState>,
}

/// A finished network pass the worker is admitting.
#[derive(Default)]
pub(crate) struct ComparisonAdmission {
    routes: Vec<AdmissionRoute>,
    pending: VecDeque<(usize, PendingSource, cgka_traits::TransportDelivery)>,
    summary: SyncSummary,
    /// Whether the last bounded turn advanced either input. A blocked native
    /// frontier waits on the existing source watch, not a retry or busy loop.
    pub(crate) progressed: bool,
    prefer_native: bool,
    conversion_error: Option<AppError>,
    /// The grant changed mid-admission. The admitted prefix stays durable,
    /// but the pass certifies nothing.
    invalid: bool,
}

/// Where an owned event came from. Only comparison events bear on the
/// route's certificate and replay cursor; a window fetch certifies nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingSource {
    Comparison,
    Window,
}

enum OrderedInput {
    Native,
    Comparison(usize),
}

struct AdmissionRoute {
    route: TransportReconciliationRoute,
    window_progress: WindowProgress,
    initial_cursor: Option<[u8; 32]>,
    cursor: Option<[u8; 32]>,
    outcome: Outcome,
    /// Every endpoint finished an untruncated comparison.
    certified: bool,
    /// Every required relay answered, whatever admission later did.
    answered: bool,
    reached_endpoints: Vec<String>,
    /// Every event this route fetched was durably admitted.
    admitted: bool,
    /// Local ingest kept no durable trace, distinct from an invalid event or
    /// unknown remote coverage. The comparison slot must retry this work.
    retry_admission: bool,
    /// Owned comparison events still to attempt. No successful network result
    /// means no cursor progress; refusals and definitive rejections finish an
    /// attempt, but an ingest error leaves this count unchanged.
    remaining: Option<usize>,
    /// Events durably admitted: progress, even without a certificate.
    fetched: usize,
    /// What the relays returned, for the attempt's audit row only.
    acquisition: super::super::audit_recovery::RouteAcquisition,
}

fn comparison_failure(error: AppError) -> ClassifiedSyncFailure {
    ClassifiedSyncFailure::at_stage(SyncSummary::default(), error, SyncFailureStage::Unknown)
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct TestComparisonActivityWitness {
    pub(crate) attempt_serial: Arc<AtomicU64>,
    pub(crate) active_jobs: Arc<AtomicUsize>,
    pub(crate) active_requests: Arc<AtomicUsize>,
    pub(crate) target_event_id: Arc<Mutex<Option<String>>>,
    pub(crate) returned_events: Arc<AtomicUsize>,
    pub(crate) matching_events: Arc<AtomicUsize>,
}

#[cfg(test)]
struct ActiveCounter(Arc<AtomicUsize>);

#[cfg(test)]
impl ActiveCounter {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

#[cfg(test)]
impl Drop for ActiveCounter {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

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
    /// An epoch-gap group route: a relay that fails its comparison is asked
    /// for its history window, under this demand's frozen revision.
    window: Option<([u8; 32], storage_sqlite::RecoveryDemandTicket)>,
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
    /// What a window fetch returned from relays that failed the comparison.
    window: Vec<transport_nostr_adapter::NostrRelayEvent>,
    window_progress: WindowProgress,
}

impl ComparisonRouteWorkResult {
    /// The relays among `endpoints` a window fetch may stand in for: all of
    /// them when the comparison did not return, else every failed relay that
    /// did not answer its comparison. A relay that answered but left claimed
    /// IDs for a later pass is fetching that backlog oldest first, and while
    /// any compared relay still owes older history (or the pass could not
    /// order what it was missing), a newest page would skip the unfetched
    /// middle (#2086), so none is fetched. A route the deadline skipped has
    /// no time left to fetch anything.
    fn uncompared_endpoints(
        &self,
        endpoints: &[cgka_traits::TransportEndpoint],
    ) -> Vec<cgka_traits::TransportEndpoint> {
        use transport_nostr::same_relay;
        match self {
            Self::Skipped => Vec::new(),
            Self::TimedOut | Self::Returned(Err(_) | Ok(None)) => endpoints.to_vec(),
            Self::Returned(Ok(Some((summary, _)))) => {
                if summary.order_unproven || summary.received_items < summary.remote_items {
                    return Vec::new();
                }
                let unattributed = summary.failed_endpoints.len() < summary.relays_failed;
                let named =
                    |set: &[cgka_traits::TransportEndpoint],
                     endpoint: &cgka_traits::TransportEndpoint| {
                        set.iter()
                            .any(|named| same_relay(endpoint.as_str(), named.as_str()))
                    };
                endpoints
                    .iter()
                    .filter(|endpoint| unattributed || named(&summary.failed_endpoints, endpoint))
                    .filter(|endpoint| !named(&summary.incomplete_endpoints, endpoint))
                    .cloned()
                    .collect()
            }
        }
    }
}

pub(crate) struct ComparisonNetworkResult {
    routes: Vec<ComparisonRouteResult>,
    capture_error: Option<cgka_traits::TransportAdapterError>,
}

impl ComparisonNetworkResult {
    /// What each route's relays returned, for a pass discarded before any
    /// admission exists: counts only, nothing admitted or certified. A route
    /// counts as answered only when its comparison ran and every failed relay
    /// still answered.
    fn unsettled_routes(
        &self,
    ) -> impl Iterator<Item = (bool, super::super::audit_recovery::RouteAcquisition)> + '_ {
        self.routes.iter().map(|route| match &route.result {
            ComparisonRouteWorkResult::Returned(Ok(Some((summary, events)))) => {
                let mut acquisition =
                    super::super::audit_recovery::RouteAcquisition::from_summary(summary);
                acquisition.retrieved = events.len();
                (
                    summary.failed_endpoints.len() == summary.incomplete_endpoints.len(),
                    acquisition,
                )
            }
            _ => (false, Default::default()),
        })
    }
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
    handle: JoinHandle<(Arc<OwnedSemaphorePermit>, ComparisonNetworkResult)>,
}

impl Drop for ComparisonNetworkJob {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Search older ranges without releasing a newer suffix. Each peer offers at
/// most one completed oldest page; only worker admission checkpoints its hint.
async fn fetch_epoch_gap_window(
    plane: &MarmotRelayPlane,
    request: NostrAcquisitionRequest,
    local: &[transport_nostr_adapter::NostrReconciliationItem],
    cache: &EpochGapWindows,
    generation: (u64, u64, u64),
    goal: storage_sqlite::RecoveryDemandTicket,
    turn_ends: tokio::time::Instant,
) -> (
    Vec<transport_nostr_adapter::NostrRelayEvent>,
    WindowProgress,
) {
    let NostrAcquisitionScope::GroupWindow {
        transport_group_id,
        since,
        until,
        ..
    } = request.scope
    else {
        return (Vec::new(), Vec::new());
    };
    if request.endpoints.is_empty() || request.validate().is_err() {
        return (Vec::new(), Vec::new());
    }
    let deadline = turn_ends.min(tokio::time::Instant::now() + request.limits.max_duration);
    let local = local
        .iter()
        .map(|item| item.event_id)
        .collect::<HashSet<_>>();
    let hints = {
        let mut cache = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        request
            .endpoints
            .iter()
            .map(|endpoint| {
                let key = (transport_group_id, endpoint.as_str().to_owned());
                cache.tick = cache.tick.saturating_add(1);
                let tick = cache.tick;
                let mut hint = cache
                    .entries
                    .get_mut(&key)
                    .filter(|hint| {
                        hint.generation == generation
                            && hint.goal == goal
                            && hint.origin_since <= since
                            && hint.until <= until
                            && hint.until >= since
                    })
                    .map(|hint| {
                        hint.last_used = tick;
                        hint.clone()
                    })
                    .unwrap_or_else(|| EpochGapWindow {
                        generation,
                        goal,
                        origin_since: since,
                        until,
                        since,
                        bounds: vec![EpochGapBound::new(until)],
                        last_used: 0,
                    });
                hint.since = hint.since.max(since);
                hint.bounds.retain(|bound| bound.until >= hint.since);
                if hint.bounds.is_empty() {
                    hint.origin_since = since;
                    hint.since = since;
                    hint.until = until;
                    hint.bounds.push(EpochGapBound::new(until));
                }
                (key, endpoint.clone(), hint)
            })
            .collect::<Vec<_>>()
    };
    let relays = hints.len();
    let scans = hints.into_iter().map(|(key, endpoint, hint)| {
        let page_request = NostrAcquisitionRequest {
            account_id: request.account_id.clone(),
            scope: request.scope.clone(),
            endpoints: vec![endpoint],
            limits: transport_nostr_adapter::NostrAcquisitionLimits {
                max_endpoints: 1,
                ..request.limits
            },
        };
        let local = &local;
        async move {
            let (events, hint, reached) =
                page_epoch_gap_window(plane, page_request, local, hint, deadline).await;
            let offered = events
                .iter()
                .filter_map(|event| {
                    let mut id = [0; 32];
                    hex::decode_to_slice(&event.event.id, &mut id)
                        .ok()
                        .map(|()| (id, WindowOffer::Unconverted))
                })
                .collect();
            (
                events,
                WindowObservation {
                    key,
                    hint,
                    reached,
                    offered,
                },
            )
        }
    });
    let mut events = Vec::new();
    let mut progress = Vec::with_capacity(relays);
    for (page, observation) in futures::future::join_all(scans).await {
        events.extend(page);
        progress.push(observation);
    }
    events.sort_unstable_by(|a, b| {
        (a.event.created_at, &a.event.id).cmp(&(b.event.created_at, &b.event.id))
    });
    events.dedup_by(|a, b| a.event.id == b.event.id);
    tracing::info!(
        target: "marmot_app::client::sync::comparison_job",
        method = "fetch_epoch_gap_window",
        relays,
        events = events.len(),
        timed_out = tokio::time::Instant::now() >= deadline,
        "paged an epoch-gap route's history from relays that failed to compare it"
    );
    (events, progress)
}

async fn page_epoch_gap_window(
    plane: &MarmotRelayPlane,
    request: NostrAcquisitionRequest,
    local: &HashSet<[u8; 32]>,
    mut hint: EpochGapWindow,
    deadline: tokio::time::Instant,
) -> (
    Vec<transport_nostr_adapter::NostrRelayEvent>,
    EpochGapWindow,
    bool,
) {
    let NostrAcquisitionScope::GroupWindow {
        transport_group_id, ..
    } = request.scope
    else {
        return (Vec::new(), hint, false);
    };
    let endpoint = &request.endpoints[0];
    let mut items_left = request.limits.max_received_items_per_endpoint;
    let mut bytes_left = request.limits.max_serialized_event_bytes_per_endpoint;
    let mut reached = false;
    // Only the current short page survives its strictly older probe. Its
    // bytes are already charged to the same pass budget, never a page stack.
    let mut buffered = None;
    while items_left > 2 && bytes_left > 0 {
        let Some(bound) = hint.bounds.last().copied() else {
            break;
        };
        let until = bound.until;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        // Leave room for EOSE and the SDK's counted first overflow EVENT, so
        // a relay ignoring `limit` cannot exceed the pass's raw allowance.
        let page_size = EPOCH_GAP_WINDOW_PAGE_EVENTS.min(items_left - 2);
        let page_request = NostrAcquisitionRequest {
            account_id: request.account_id.clone(),
            scope: NostrAcquisitionScope::GroupWindow {
                transport_group_id,
                since: hint.since,
                until,
                newest: Some(page_size),
            },
            endpoints: request.endpoints.clone(),
            limits: transport_nostr_adapter::NostrAcquisitionLimits {
                max_received_items_per_endpoint: page_size + 1,
                max_serialized_event_bytes_per_endpoint: bytes_left,
                max_duration: remaining,
                ..request.limits
            },
        };
        let Ok(Ok(mut result)) = tokio::time::timeout_at(
            deadline,
            plane.acquire_history(page_request, NostrAcquisitionCancellation::new()),
        )
        .await
        else {
            break;
        };
        let Some(page) = result.endpoints.pop() else {
            break;
        };
        reached |= page.end == NostrAcquisitionEnd::RequestPolicySatisfied
            || page.stats.raw_received_items > 0;
        if page.end != NostrAcquisitionEnd::RequestPolicySatisfied {
            break;
        }
        let received = page.stats.raw_received_items;
        let Some(left) = items_left.checked_sub(received) else {
            break;
        };
        items_left = left;
        let Some(left) = bytes_left.checked_sub(page.stats.serialized_event_bytes) else {
            break;
        };
        bytes_left = left;
        let oldest = page.stats.oldest_raw_created_at;
        if received < page.events.len()
            || (received == 0) != oldest.is_none()
            || oldest.is_some_and(|oldest| oldest < hint.since || oldest > until)
        {
            break;
        }
        let mut page_events = page.events;
        if received == 0 {
            hint.bounds.pop();
            hint.since = bound.resume_since;
            if let Some(events) = buffered.take() {
                // The empty probe proves this buffered page was oldest. Do
                // not download it again merely to climb one boundary.
                let parent = hint
                    .bounds
                    .pop()
                    .expect("the buffered page has a pending range");
                hint.since = parent.resume_since;
                page_events = events;
            } else {
                continue;
            }
        } else {
            buffered = None;
            if received >= page_size {
                let Some(oldest) = oldest else { break };
                if oldest < until
                    && page_events
                        .iter()
                        .all(|event| event_is_held(&event.id, local))
                {
                    // Preserve the held suffix's resume boundary while the
                    // oldest overlapping second still needs to be searched.
                    hint.bounds.last_mut().expect("the range is pending").until = oldest;
                    continue;
                }
                let next = if oldest < until {
                    oldest
                } else if hint.since < until {
                    until - 1
                } else {
                    break;
                };
                if hint.bounds.len() >= EPOCH_GAP_WINDOW_MAX_BOUNDARIES {
                    break;
                }
                hint.bounds.push(EpochGapBound::new(next));
                continue;
            }
            // Only a short raw page can be oldest; SDK filtering is not an
            // end-of-history signal. Keep one page while probing below it.
            if let Some(oldest) = oldest.filter(|oldest| *oldest > hint.since) {
                if hint.bounds.len() >= EPOCH_GAP_WINDOW_MAX_BOUNDARIES {
                    break;
                }
                hint.bounds.push(EpochGapBound::new(oldest - 1));
                buffered = Some(page_events);
                continue;
            }
            hint.bounds.pop();
            hint.since = bound.resume_since;
        }
        let events = page_events
            .into_iter()
            .filter(|event| !event_is_held(&event.id, local))
            .map(|event| transport_nostr_adapter::NostrRelayEvent {
                endpoint: endpoint.clone(),
                subscription_id: None,
                event,
            })
            .collect::<Vec<_>>();
        if !events.is_empty() {
            return (events, hint, reached);
        }
    }
    (Vec::new(), hint, reached)
}

fn event_is_held(id: &str, local: &HashSet<[u8; 32]>) -> bool {
    let mut decoded = [0; 32];
    hex::decode_to_slice(id, &mut decoded).is_ok() && local.contains(&decoded)
}

fn keep_window_progress(
    cache: &EpochGapWindows,
    live: &HashSet<([u8; 16], u64)>,
    progress: WindowProgress,
) {
    let mut cache = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache
        .entries
        .retain(|_, hint| live.contains(&(hint.goal.id, hint.goal.revision)));
    for WindowObservation {
        key,
        mut hint,
        offered,
        ..
    } in progress
    {
        if !offered.is_empty() || !live.contains(&(hint.goal.id, hint.goal.revision)) {
            continue;
        }
        if !cache.entries.contains_key(&key) && cache.entries.len() >= EPOCH_GAP_WINDOW_MAX_HINTS {
            let oldest = cache
                .entries
                .iter()
                .min_by_key(|(_, hint)| hint.last_used)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                cache.entries.remove(&oldest);
            }
        }
        cache.tick = cache.tick.saturating_add(1);
        hint.last_used = cache.tick;
        cache.entries.insert(key, hint);
    }
}

impl ComparisonNetworkJob {
    /// Cancel the request and wait until its future has dropped the shared credit.
    pub(crate) async fn abort_and_wait(mut self) {
        self.handle.abort();
        let _ = (&mut self.handle).await;
    }

    /// The deadline of an automatic pass: one account-wide quantum.
    pub(crate) fn automatic_deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + TRANSPORT_RECONCILIATION_QUANTUM
    }

    /// Start the grant's comparison off the worker. A route the pass has not
    /// reached by `deadline` is skipped and keeps its debt.
    pub(crate) fn start(
        client: &AppClient,
        grant: &AttemptGrant,
        credit: OwnedSemaphorePermit,
        deadline: tokio::time::Instant,
        #[cfg(test)] witness: Option<TestComparisonActivityWitness>,
    ) -> Result<Self, AppError> {
        let storage = client.app.account_storage(&client.state.label)?;
        let epoch_gap_routes = grant
            .plan()
            .into_iter()
            .flatten()
            .filter(|obligation| obligation.cause == storage_sqlite::RecoveryCause::EpochGap)
            .flat_map(|obligation| {
                let (_, revision) = grant
                    .fence
                    .obligations
                    .iter()
                    .find(|(id, _)| *id == obligation.id)
                    .expect("a selected epoch gap has a frozen revision");
                let ticket = storage_sqlite::RecoveryDemandTicket {
                    id: obligation.id,
                    revision: *revision,
                };
                obligation
                    .scopes
                    .iter()
                    .filter_map(move |scope| scope.goal.transport_group_id.map(|id| (id, ticket)))
            })
            .collect::<HashMap<_, _>>();
        let routes = grant
            .inventory
            .iter()
            .map(|inventory| {
                Ok(FrozenRoute {
                    inventory: inventory.clone(),
                    initial_cursor: storage
                        .app_storage()
                        .transport_reconciliation_replay_cursor(&inventory.route)?,
                    window: match inventory.route {
                        TransportReconciliationRoute::Group(id) => {
                            epoch_gap_routes.get(&id).map(|ticket| (id, *ticket))
                        }
                        _ => None,
                    },
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let adapter = client.adapter.clone();
        let plane = client.relay_plane.clone();
        let windows = client.epoch_gap_windows.clone();
        let generation = (
            grant.fence.loss_revision,
            grant.fence.route_revision,
            grant.fence.inventory_revision,
        );
        let attempt_serial = grant.reservation.attempt_serial;
        let credit = Arc::new(credit);
        let replay_capture = ReplayCapturePlan {
            attempt_serial,
            sources: grant.replay_capture.clone(),
            credit: credit.clone(),
        };
        #[cfg(test)]
        let (scripted, scripted_delay, scripted_cursor) = (
            client.test_comparison_results.clone(),
            client.test_comparison_delay,
            client.test_comparison_saved_cursor,
        );
        let handle = tokio::spawn(async move {
            #[cfg(test)]
            let _job_active = witness.as_ref().map(|witness| {
                witness
                    .attempt_serial
                    .store(attempt_serial, Ordering::SeqCst);
                ActiveCounter::new(witness.active_jobs.clone())
            });
            // Native capture and comparison share the cutoff, not each other's
            // wait. A quiet original REQ must not consume the whole pass first.
            let capture = async {
                if !replay_capture.sources.is_empty() && tokio::time::Instant::now() < deadline {
                    let cancellation = NostrAcquisitionCancellation::new();
                    let _cancel_on_drop = cancellation.clone().drop_guard();
                    let capture = adapter.capture_replay(replay_capture, cancellation.clone());
                    tokio::pin!(capture);
                    let captured = tokio::select! {
                        result = &mut capture => result,
                        () = tokio::time::sleep_until(deadline) => {
                            cancellation.cancel();
                            // Keep the credit until accepted acquisition has
                            // observed cancellation and released its request.
                            capture.await
                        }
                    };
                    return captured.err();
                }
                None
            };
            let compare = async {
                // Refill a completed slot even while an earlier route is stalled.
                // Indexed results keep admission and audit in inventory order.
                // These futures stay owned by this task, so abort drops every
                // request before returning its account-wide credit.
                let mut results = (0..routes.len()).map(|_| None).collect::<Vec<_>>();
                let mut pending =
                    stream::iter(routes.into_iter().enumerate().map(|(index, frozen)| {
                        let adapter = &adapter;
                        let plane = &plane;
                        let windows = &windows;
                        #[cfg(test)]
                        let (witness, scripted) = (&witness, &scripted);
                        async move {
                            let result = async move {
                                let FrozenRoute {
                                    inventory,
                                    initial_cursor,
                                    window,
                                } = frozen;
                                if tokio::time::Instant::now() >= deadline {
                                    return ComparisonRouteResult {
                                        route: inventory.route,
                                        initial_cursor,
                                        cursor: initial_cursor,
                                        result: ComparisonRouteWorkResult::Skipped,
                                        window: Vec::new(),
                                        window_progress: Vec::new(),
                                    };
                                }
                                let endpoints = inventory.work.endpoints().to_vec();
                                let (since, until) = (inventory.since, inventory.until);
                                let progress = Arc::new(MemoryProgress {
                                    cursor: Mutex::new(initial_cursor),
                                });
                                // The hard guard must not cancel an SDK-owned partial prefix.
                                // Leave time for its handoff, or for an epoch-gap relay's
                                // history window when that relay could not compare.
                                let remaining =
                                    deadline.saturating_duration_since(tokio::time::Instant::now());
                                let reserve = if window.is_some() {
                                    (remaining / 2).min(EPOCH_GAP_WINDOW_MAX_DURATION)
                                } else {
                                    (remaining / 5).min(Duration::from_millis(400))
                                };
                                let comparison_deadline = deadline - reserve;
                                let run = async {
                                    #[cfg(test)]
                                    let _request_active = witness.as_ref().map(|witness| {
                                        ActiveCounter::new(witness.active_requests.clone())
                                    });
                                    #[cfg(test)]
                                    if let Some(scripted) = &scripted {
                                        let (delay, timed) =
                                            match scripted.timed_answer(&inventory.route) {
                                                Some((delay, answer)) => (delay, Some(answer)),
                                                None => (None, None),
                                            };
                                        if let Some(cursor) = scripted_cursor {
                                            progress.save_cursor(Some(cursor))?;
                                        }
                                        if let Some(delay) = delay.or(scripted_delay) {
                                            tokio::time::sleep(delay).await;
                                        }
                                        return timed
                                            .unwrap_or_else(|| scripted.answer(&inventory.route));
                                    }
                                    match inventory.work {
                                        TransportReconciliationWork::Inbox(endpoints) => {
                                            adapter
                                                .reconcile_inbox_history(
                                                    endpoints,
                                                    &inventory.items,
                                                    inventory.since,
                                                    inventory.until,
                                                    progress.as_ref(),
                                                    comparison_deadline,
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
                                                    comparison_deadline,
                                                )
                                                .await
                                        }
                                    }
                                };
                                let result = match tokio::time::timeout_at(deadline, run).await {
                                    Ok(value) => ComparisonRouteWorkResult::Returned(value),
                                    Err(_) => ComparisonRouteWorkResult::TimedOut,
                                };
                                #[cfg(test)]
                                if let Some(witness) = &witness
                                    && let ComparisonRouteWorkResult::Returned(Ok(Some((
                                        _,
                                        events,
                                    )))) = &result
                                {
                                    witness
                                        .returned_events
                                        .fetch_add(events.len(), Ordering::SeqCst);
                                    if let Some(target) =
                                        witness.target_event_id.lock().unwrap().as_ref()
                                    {
                                        witness.matching_events.fetch_add(
                                            events
                                                .iter()
                                                .filter(|event| {
                                                    event.event.id.eq_ignore_ascii_case(target)
                                                })
                                                .count(),
                                            Ordering::SeqCst,
                                        );
                                    }
                                }
                                let (window, window_progress) = match window {
                                    Some((transport_group_id, goal)) => {
                                        let endpoints = result.uncompared_endpoints(&endpoints);
                                        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                                        fetch_epoch_gap_window(
                                            plane,
                                            NostrAcquisitionRequest {
                                                account_id: adapter.account_id().clone(),
                                                scope: NostrAcquisitionScope::GroupWindow {
                                                    transport_group_id,
                                                    since,
                                                    until,
                                                    newest: Some(EPOCH_GAP_WINDOW_PAGE_EVENTS),
                                                },
                                                limits: transport_nostr_adapter::NostrAcquisitionLimits {
                                                    max_endpoints: endpoints.len(),
                                                    max_requested_event_ids: 1,
                                                    max_received_items_per_endpoint: EPOCH_GAP_WINDOW_MAX_EVENTS_PER_RELAY,
                                                    max_serialized_event_bytes_per_endpoint: EPOCH_GAP_WINDOW_MAX_BYTES_PER_RELAY,
                                                    max_duration: remaining.min(EPOCH_GAP_WINDOW_MAX_DURATION),
                                                },
                                                endpoints,
                                            },
                                            &inventory.items,
                                            windows,
                                            generation,
                                            goal,
                                            deadline,
                                        )
                                        .await
                                    }
                                    None => (Vec::new(), Vec::new()),
                                };
                                let cursor =
                                    *progress.cursor.lock().expect("comparison progress mutex");
                                ComparisonRouteResult {
                                    route: inventory.route,
                                    initial_cursor,
                                    cursor,
                                    result,
                                    window,
                                    window_progress,
                                }
                            }
                            .await;
                            (index, result)
                        }
                    }))
                    .buffer_unordered(TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS);
                while let Some((index, result)) = pending.next().await {
                    results[index] = Some(result);
                }
                results
                    .into_iter()
                    .map(|result| result.expect("every frozen route returned"))
                    .collect()
            };
            let (capture_error, routes) = tokio::join!(capture, compare);
            (
                credit,
                ComparisonNetworkResult {
                    routes,
                    capture_error,
                },
            )
        });
        Ok(Self { handle })
    }

    pub(crate) async fn wait(
        &mut self,
    ) -> Result<(Arc<OwnedSemaphorePermit>, ComparisonNetworkResult), tokio::task::JoinError> {
        (&mut self.handle).await
    }
}

impl ComparisonAdmission {
    /// Publish a successful bounded turn without waiting for the whole pass.
    /// Accounting stays in the execution/routes; settlement returns only the
    /// unconsumed output, so an already published prefix cannot repeat.
    pub(crate) fn take_committed_summary(&mut self) -> SyncSummary {
        std::mem::take(&mut self.summary)
    }

    /// What each accepted route's relays returned, for a pass that ends
    /// before settlement.
    fn unsettled_routes(
        &self,
    ) -> impl Iterator<Item = (bool, super::super::audit_recovery::RouteAcquisition)> + '_ {
        self.routes.iter().map(|route| {
            (
                route.answered && route.outcome != Outcome::Unsupported,
                route.acquisition.clone(),
            )
        })
    }
}

impl AppClient {
    /// Whether recovery has any work a grant could select, asked without
    /// spending a reservation: a direct caller asks before it waits for a
    /// credit, and the worker asks when none is free.
    pub(crate) fn recovery_pending(&self) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        Ok(!self.pending_recovery_arm_writes.is_empty()
            || !self.pending_recovery_capacity_writes.is_empty()
            || !storage.pending_recovery_demands()?.is_empty()
            || storage.recovery_comparison()?.pending())
    }

    /// Open the job's execution bracket and install the grant's maintenance
    /// subscriptions. A pass never touches the live subscriptions: it reuses
    /// the live tail, so it re-downloads no history the account already holds.
    pub(crate) async fn begin_comparison_grant(
        &mut self,
        grant: &AttemptGrant,
    ) -> Result<ComparisonExecution, AppError> {
        self.synchronize_native_replay().await?;
        let mut execution = self
            .begin_recovery_execution(grant)
            .map_err(|failure| failure.source)?;
        // A maintenance boundary is its own REQ's end of stored events. It is
        // installed here, under this grant's scope tokens, and observed later.
        // Installing it is the job's only activation.
        if let Err(error) = self.install_granted_post_join_subscriptions(grant).await {
            let failure = ClassifiedSyncFailure::at_stage(
                SyncSummary::default(),
                error,
                SyncFailureStage::GroupSubscriptionSync,
            );
            return match self.finish_recovery_execution(grant, execution, Err(failure)) {
                Ok(_) => unreachable!("a failed installation cannot complete"),
                Err(failure) => Err(failure.source),
            };
        }
        execution.activation = marmot_forensics::EpochBackfillActivationOutcome::Succeeded;
        Ok(ComparisonExecution {
            attempt: self.adapter.account_subscription_attempt().await,
            execution: Box::new(execution),
        })
    }

    /// The grant still owns its frozen debt, its comparison slot and the live
    /// subscription attempt it started under.
    async fn comparison_grant_stable(
        &mut self,
        grant: &AttemptGrant,
        execution: &ComparisonExecution,
        compare_inventory: bool,
    ) -> Result<bool, AppError> {
        self.synchronize_native_replay().await?;
        let storage = self.app.account_storage(&self.state.label)?;
        let app = storage.app_storage();
        self.synchronize_recovery_loss(&app)?;
        drop(self.transport_receipts()?);
        self.observe_recovery_route_policy()?;
        let current = app.recovery_revision_fence()?;
        let slot_stable = match grant.comparison_revision {
            Some(revision) => {
                let slot = app.recovery_comparison()?;
                slot.pending()
                    && slot.revision == revision
                    && slot.attempt_serial == grant.reservation.attempt_serial
                    && slot.frozen_revision == slot.revision
            }
            None => true,
        };
        for selected in &grant.fence.obligations {
            if current.obligations.contains(selected) {
                continue;
            }
            // Passive native placement may settle this exact selected goal
            // while the comparison runs. It must not discard another scope's
            // comparison result, nor authorize a successor native revision.
            let native = grant.plan().into_iter().flatten().any(|obligation| {
                obligation.id == selected.0
                    && obligation.cause == storage_sqlite::RecoveryCause::SubscriptionReplay
            });
            if !native
                || !app
                    .recovery_obligation_status(selected.0)?
                    .is_some_and(|status| {
                        status.revision == selected.1
                            && status.cause == storage_sqlite::RecoveryCause::SubscriptionReplay
                            && matches!(
                                status.state,
                                storage_sqlite::RecoveryObligationState::Satisfied
                                    | storage_sqlite::RecoveryObligationState::Retired
                            )
                    })
            {
                return Ok(false);
            }
        }
        Ok(current.loss_revision == grant.fence.loss_revision
            && current.route_revision == grant.fence.route_revision
            && (!compare_inventory || current.inventory_revision == grant.fence.inventory_revision)
            && slot_stable
            && self.adapter.account_subscription_attempt().await == execution.attempt)
    }

    /// Take ownership of a finished network pass. `None` means the grant
    /// changed while it ran, so none of its bytes may be admitted.
    pub(crate) async fn accept_comparison_network(
        &mut self,
        grant: &AttemptGrant,
        execution: &mut ComparisonExecution,
        mut network: ComparisonNetworkResult,
    ) -> Result<Option<ComparisonAdmission>, AppError> {
        if let Some(error) = network.capture_error.take() {
            return Err(error.into());
        }
        let stable = self.comparison_grant_stable(grant, execution, true).await;
        if !matches!(stable, Ok(true)) {
            // The result is discarded unadmitted; its finish row still says
            // what the relays returned.
            execution
                .execution
                .tally
                .observe_unsettled_routes(network.unsettled_routes());
            return stable.map(|_| None);
        }
        let mut admission = ComparisonAdmission::default();
        for (index, route) in network.routes.into_iter().enumerate() {
            let inventory = grant
                .inventory
                .iter()
                .find(|inventory| inventory.route == route.route);
            // A route the cutoff timed out, or whose request failed, lost the
            // events it collected with its future, though the adapter may
            // already have saved a cursor past them. It admitted nothing, so
            // its replay cursor must not move.
            let admitted = !matches!(
                route.result,
                ComparisonRouteWorkResult::TimedOut | ComparisonRouteWorkResult::Returned(Err(_))
            );
            let returned = matches!(
                route.result,
                ComparisonRouteWorkResult::Returned(Ok(Some(_)))
            );
            let mut acquisition = super::super::audit_recovery::RouteAcquisition::default();
            let mut reached_endpoints = Vec::new();
            let (outcome, certified, answered, events) = match route.result {
                ComparisonRouteWorkResult::Skipped => {
                    (Outcome::TransientFailure, false, false, Vec::new())
                }
                ComparisonRouteWorkResult::TimedOut
                | ComparisonRouteWorkResult::Returned(Err(_)) => {
                    (Outcome::TransientFailure, false, false, Vec::new())
                }
                ComparisonRouteWorkResult::Returned(Ok(None)) => {
                    (Outcome::Unsupported, false, true, Vec::new())
                }
                ComparisonRouteWorkResult::Returned(Ok(Some((summary, events)))) => {
                    acquisition =
                        super::super::audit_recovery::RouteAcquisition::from_summary(&summary);
                    acquisition.retrieved = events.len();
                    if let Some(inventory) = inventory {
                        use transport_nostr::same_relay;
                        let endpoints = inventory.work.endpoints();
                        let unattributed = summary.failed_endpoints.len() < summary.relays_failed
                            || summary.failed_endpoints.iter().any(|failed| {
                                !endpoints
                                    .iter()
                                    .any(|endpoint| same_relay(endpoint.as_str(), failed.as_str()))
                            });
                        if !unattributed {
                            reached_endpoints.extend(endpoints.iter().filter_map(|endpoint| {
                                let failed = summary
                                    .failed_endpoints
                                    .iter()
                                    .any(|failed| same_relay(endpoint.as_str(), failed.as_str()));
                                let incomplete = summary
                                    .incomplete_endpoints
                                    .iter()
                                    .any(|relay| same_relay(endpoint.as_str(), relay.as_str()));
                                (!failed || incomplete).then(|| endpoint.as_str().to_owned())
                            }));
                        }
                    }
                    let (outcome, certified, answered) = inventory
                        .map_or((Outcome::TransientFailure, false, false), |inventory| {
                            inventory.judge(&summary)
                        });
                    (outcome, certified, answered, events)
                }
            };
            // The late commit is the oldest event a window recovers, and a
            // relay that compared can return a newer commit from the same
            // epoch. Queue the route's comparison and window events together,
            // oldest first, so no newer commit converges before the late one
            // is buffered. An event both returned is admitted once, as a
            // comparison event.
            let compared = events
                .iter()
                .map(|event| event.event.id.clone())
                .collect::<HashSet<_>>();
            let mut batch = events
                .into_iter()
                .map(|event| (PendingSource::Comparison, event))
                .chain(
                    route
                        .window
                        .into_iter()
                        .filter(|event| !compared.contains(&event.event.id))
                        .map(|event| (PendingSource::Window, event)),
                )
                .collect::<Vec<_>>();
            batch.sort_by(|(a_source, a), (b_source, b)| {
                (
                    a.event.created_at,
                    &a.event.id,
                    *a_source == PendingSource::Window,
                )
                    .cmp(&(
                        b.event.created_at,
                        &b.event.id,
                        *b_source == PendingSource::Window,
                    ))
            });
            batch.dedup_by(|(_, later), (_, kept)| later.event.id == kept.event.id);
            let remaining = returned.then_some(0);
            admission.routes.push(AdmissionRoute {
                route: route.route,
                window_progress: route.window_progress,
                initial_cursor: route.initial_cursor,
                cursor: route.cursor,
                outcome,
                certified,
                answered,
                reached_endpoints,
                admitted,
                retry_admission: false,
                remaining,
                fetched: 0,
                acquisition,
            });
            for (source, event) in batch {
                let event_id = if admission.routes[index].window_progress.is_empty() {
                    None
                } else {
                    let mut id = [0; 32];
                    hex::decode_to_slice(&event.event.id, &mut id)
                        .ok()
                        .map(|()| id)
                };
                let deliveries = match self.adapter.recovered_deliveries(event).await {
                    Ok(deliveries) => deliveries,
                    Err(
                        cgka_traits::TransportAdapterError::InvalidInboundEncoding
                        | cgka_traits::TransportAdapterError::InvalidInboundSignature,
                    ) => Vec::new(),
                    Err(error) => {
                        if source == PendingSource::Comparison
                            && let Some(remaining) = admission.routes[index].remaining.as_mut()
                        {
                            *remaining += 1;
                        }
                        admission
                            .conversion_error
                            .get_or_insert_with(|| error.into());
                        continue;
                    }
                };
                if let Some(event_id) = event_id {
                    for observation in &mut admission.routes[index].window_progress {
                        let Some(offered) = observation.offered.get_mut(&event_id) else {
                            continue;
                        };
                        match offered {
                            WindowOffer::Unconverted => {
                                *offered = WindowOffer::Pending(deliveries.len());
                            }
                            WindowOffer::Pending(remaining) => *remaining += deliveries.len(),
                            WindowOffer::Unretained => continue,
                        }
                        if matches!(offered, WindowOffer::Pending(0)) {
                            observation.offered.remove(&event_id);
                        }
                    }
                }
                if source == PendingSource::Comparison {
                    let route = &mut admission.routes[index];
                    if deliveries.is_empty() {
                        route.admitted = false;
                        route.acquisition.rejected = route.acquisition.rejected.saturating_add(1);
                    }
                    if let Some(remaining) = route.remaining.as_mut() {
                        *remaining += deliveries.len();
                    }
                }
                admission.pending.extend(
                    deliveries
                        .into_iter()
                        .map(|delivery| (index, source, delivery)),
                );
            }
        }
        // Different retained routes can resolve to the same MLS group. Their
        // known input must share the same minimum key, not route fetch order.
        admission.pending.make_contiguous().sort_by(|a, b| {
            (a.2.message.timestamp, a.2.message.id.as_slice())
                .cmp(&(b.2.message.timestamp, b.2.message.id.as_slice()))
        });
        Ok(Some(admission))
    }

    /// Admit at most a few owned events through the ordinary ingest path, then
    /// return so the worker serves commands and live input before the next
    /// turn. Returns true once nothing remains to admit.
    pub(crate) async fn admit_comparison_turn(
        &mut self,
        grant: &AttemptGrant,
        execution: &mut ComparisonExecution,
        admission: &mut ComparisonAdmission,
    ) -> Result<bool, AppError> {
        admission.progressed = false;
        if let Some(error) = admission.conversion_error.take() {
            return Err(error);
        }
        if admission.pending.is_empty() {
            return Ok(true);
        }
        if !self
            .comparison_grant_stable(grant, execution, false)
            .await?
        {
            admission.invalid = true;
            admission.pending.clear();
            return Ok(true);
        }
        // Both sources spend the same four actual-ingest slots. Native receipt
        // skips additionally count toward four examined native frames, so a
        // retained prefix cannot monopolize the worker.
        let mut spent = 0;
        let mut native_examined = 0;
        let mut blocked = HashSet::new();
        let mut inventory = super::InventoryBatch::default();
        while spent < MAX_COMPARISON_ADMISSION_PER_TURN
            && native_examined < MAX_COMPARISON_ADMISSION_PER_TURN
        {
            let Some(input) = self.ordered_input(admission, &mut blocked).await else {
                break;
            };
            // Alternate a fair native-group lookup with comparison's oldest
            // eligible group even when that comparison keeps selecting older
            // native frames. A large same-group prefix cannot monopolize both.
            admission.prefer_native = !admission.prefer_native;
            let OrderedInput::Comparison(position) = input else {
                native_examined += 1;
                let (ingested, record) = self.admit_native_frame().await?;
                inventory.stage(self, record);
                spent += usize::from(ingested);
                admission.progressed = true;
                continue;
            };
            inventory.flush(self);
            let (index, source, delivery) = &admission.pending[position];
            let expected_route = &admission.routes[*index].route;
            let window_scoped = source == &PendingSource::Window
                && delivery.group_id_hint.as_ref().is_some_and(|group| {
                    grant.plan().into_iter().flatten().any(|obligation| {
                        obligation.group_id.as_ref() == Some(group)
                            && obligation.scopes.iter().any(|scope| {
                                scope.goal.transport_group_id.is_some_and(|id| {
                                    expected_route == &TransportReconciliationRoute::Group(id)
                                })
                            })
                    })
                });
            let mut unretained = false;
            let mut window_fetched = 0_usize;
            let (summary, settled, _) = self
                .admit_recovered_delivery(delivery, super::InventoryWrite::Immediate)
                .await?;
            admission.summary.merge(summary);
            let mut route =
                (source == &PendingSource::Comparison).then(|| &mut admission.routes[*index]);
            let counts = &mut execution.execution.counts;
            match settled {
                super::RecoveredDelivery::AlreadyHeld => {
                    counts.skipped = counts.skipped.saturating_add(1);
                }
                super::RecoveredDelivery::Ingested {
                    unpersisted,
                    refused_group,
                } => {
                    spent += 1;
                    counts.deliveries = counts.deliveries.saturating_add(1);
                    if unpersisted {
                        counts.unpersisted = counts.unpersisted.saturating_add(1);
                        unretained = true;
                    } else if window_scoped {
                        window_fetched = window_fetched.saturating_add(1);
                    }
                    if let Some(route) = route.as_deref_mut() {
                        if unpersisted {
                            route.admitted = false;
                            route.retry_admission = true;
                        } else {
                            route.fetched = route.fetched.saturating_add(1);
                        }
                    }
                    if let Some(group) = refused_group {
                        counts.refused = counts.refused.saturating_add(1);
                        counts.refused_groups.insert(group);
                    }
                }
            }
            if let Some(route) = route
                && let Some(remaining) = route.remaining.as_mut()
            {
                *remaining -= 1;
            }
            let route = &mut admission.routes[*index];
            route.fetched = route.fetched.saturating_add(window_fetched);
            if !route.window_progress.is_empty() {
                let event_id: [u8; 32] = delivery
                    .message
                    .id
                    .as_slice()
                    .try_into()
                    .expect("the Nostr adapter validates 32-byte event IDs");
                for observation in &mut route.window_progress {
                    let std::collections::hash_map::Entry::Occupied(mut offered) =
                        observation.offered.entry(event_id)
                    else {
                        continue;
                    };
                    if unretained {
                        *offered.get_mut() = WindowOffer::Unretained;
                        continue;
                    }
                    if let WindowOffer::Pending(remaining) = offered.get_mut() {
                        *remaining -= 1;
                        if *remaining == 0 {
                            offered.remove();
                        }
                    }
                }
            }
            admission.pending.remove(position);
            admission.progressed = true;
            if admission.pending.is_empty() {
                break;
            }
        }
        inventory.flush(self);
        self.recovery_owner.native_batch = None;
        Ok(admission.pending.is_empty())
    }

    /// Select known input without crossing either source's same-group minimum.
    /// A Pending native range fences only that group; independent groups and
    /// the worker's command/live turn remain available.
    async fn ordered_input(
        &mut self,
        admission: &ComparisonAdmission,
        blocked: &mut HashSet<GroupId>,
    ) -> Option<OrderedInput> {
        use super::native_ingress::NativeFrontier;

        if admission.prefer_native {
            // Return the prior suffix to the ingress's fair group rotation.
            self.recovery_owner.native_batch = None;
            if matches!(self.take_native_batch(None).await, NativeFrontier::Ready) {
                return self.native_or_comparison(admission);
            }
        }
        for (position, (_, _, delivery)) in admission.pending.iter().enumerate() {
            let Some(group) = delivery.group_id_hint.as_ref() else {
                return Some(OrderedInput::Comparison(position));
            };
            if blocked.contains(group) {
                continue;
            }
            match self.take_native_batch(Some(group)).await {
                NativeFrontier::Ready => return self.native_or_comparison(admission),
                NativeFrontier::Empty => return Some(OrderedInput::Comparison(position)),
                NativeFrontier::Pending => {
                    blocked.insert(group.clone());
                }
            }
        }
        self.recovery_owner.native_batch = None;
        if matches!(self.take_native_batch(None).await, NativeFrontier::Ready) {
            self.native_or_comparison(admission)
        } else {
            None
        }
    }

    fn native_or_comparison(&self, admission: &ComparisonAdmission) -> Option<OrderedInput> {
        let native = self
            .recovery_owner
            .native_batch
            .as_ref()
            .and_then(|batch| batch.delivery())?;
        let comparison = admission.pending.iter().position(|(_, _, delivery)| {
            delivery.group_id_hint == native.group_id_hint
                && (delivery.message.timestamp, delivery.message.id.as_slice())
                    < (native.message.timestamp, native.message.id.as_slice())
        });
        Some(comparison.map_or(OrderedInput::Native, OrderedInput::Comparison))
    }

    /// Run one selected grant through the job and wait for it: the path of an
    /// explicit caller or a directly owned client, which has no worker loop to
    /// interleave. The comparison still runs in its own task under `credit`,
    /// and admission takes the same bounded turns. An explicit repair's
    /// `control` ends the network pass at its network deadline, and the
    /// routes that finished are admitted inside the admission reserve.
    /// Cancellation discards a pass in flight; cancellation or the whole
    /// budget stops admission at a turn boundary, keeping the admitted prefix
    /// and certifying nothing.
    pub(crate) async fn run_recovery_job(
        &mut self,
        grant: AttemptGrant,
        credit: OwnedSemaphorePermit,
        control: Option<&FullHistoryRepairControl<'_>>,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let execution = self.begin_comparison_grant(&grant).await?;
        let deadline = control.map_or_else(
            ComparisonNetworkJob::automatic_deadline,
            FullHistoryRepairControl::network_deadline,
        );
        let mut network = match ComparisonNetworkJob::start(
            self,
            &grant,
            credit,
            deadline,
            #[cfg(test)]
            None,
        ) {
            Ok(network) => network,
            Err(error) => {
                let _ = self.abandon_comparison_grant(grant, execution);
                return Err(error);
            }
        };
        let completed = loop {
            let mut native_changes = self.adapter.replay_changes().await;
            let native_progress = match self.admit_native_turn().await {
                Ok(progress) => progress,
                Err(error) => {
                    network.abort_and_wait().await;
                    return Err(self.fail_comparison_grant(grant, execution, None, error));
                }
            };
            tokio::select! {
                completed = network.wait() => break completed.ok(),
                () = super::native_ingress::wait_native_change(&mut native_changes) => {}
                () = tokio::task::yield_now(), if native_progress => {}
                () = tokio::time::sleep(RECOVERY_JOB_CANCEL_POLL),
                    if control.is_some() =>
                {
                    // Only cancellation discards the pass. The network
                    // deadline ends it inside the task, which returns the
                    // routes that finished for admission.
                    if control.is_some_and(FullHistoryRepairControl::cancelled) {
                        network.abort_and_wait().await;
                        break None;
                    }
                }
            }
        };
        let Some((credit, result)) = completed else {
            return self.abandon_comparison_grant(grant, execution);
        };
        // Under a repair's control the only network deadline is its cutoff,
        // so a skipped or timed-out route is one that cutoff cut short.
        self.recovery_job_network_cut = control.is_some()
            && result.routes.iter().any(|route| {
                matches!(
                    route.result,
                    ComparisonRouteWorkResult::Skipped | ComparisonRouteWorkResult::TimedOut
                )
            });
        // The job counts against the process pool until admission and its
        // checkpoint finish, not only while the network request runs.
        let settled = self
            .admit_comparison_until(grant, execution, result, control, None)
            .await;
        drop(credit);
        settled
    }

    /// Run one selected grant through the job with a private credit.
    #[cfg(test)]
    pub(crate) async fn run_recovery_grant_for_test(
        &mut self,
        grant: AttemptGrant,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let credit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .expect("a private test credit");
        self.run_recovery_job(grant, credit, None).await
    }

    /// Admit a finished pass in bounded turns, yielding between them, then
    /// settle it. Startup uses this while its mutations are still deferred;
    /// the steady-state worker runs one turn per loop instead.
    pub(crate) async fn admit_comparison_inline(
        &mut self,
        on_progress: Option<&CommittedSyncProgress<'_>>,
        grant: AttemptGrant,
        execution: ComparisonExecution,
        network: ComparisonNetworkResult,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        self.admit_comparison_until(grant, execution, network, None, on_progress)
            .await
    }

    async fn admit_comparison_until(
        &mut self,
        grant: AttemptGrant,
        mut execution: ComparisonExecution,
        network: ComparisonNetworkResult,
        control: Option<&FullHistoryRepairControl<'_>>,
        on_progress: Option<&CommittedSyncProgress<'_>>,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let mut admission = match self
            .accept_comparison_network(&grant, &mut execution, network)
            .await
        {
            Ok(admission) => admission,
            Err(error) => return Err(self.fail_comparison_grant(grant, execution, None, error)),
        };
        if let Some(admission) = admission.as_mut() {
            loop {
                let mut native_changes = self.adapter.replay_changes().await;
                // Cancellation, or the whole budget spent past the admission
                // reserve, stops at a turn boundary. The admitted prefix stays
                // durable; the pass certifies nothing, so the debt waits for a
                // later grant.
                if let Some(reason) = control.and_then(FullHistoryRepairControl::stopped) {
                    self.recovery_job_admission_expired |=
                        reason == crate::FullHistoryRepairIncompleteReason::Deadline;
                    execution.execution.interruption = Some(
                        if reason == crate::FullHistoryRepairIncompleteReason::Deadline {
                            marmot_forensics::RecoveryPassOutcome::Deadline
                        } else {
                            marmot_forensics::RecoveryPassOutcome::Cancelled
                        },
                    );
                    admission.invalid = true;
                    admission.pending.clear();
                    break;
                }
                let turn = self
                    .admit_comparison_turn(&grant, &mut execution, admission)
                    .await;
                if turn.is_ok()
                    && let Some(on_progress) = on_progress
                {
                    let mut committed = admission.take_committed_summary();
                    committed.merge(self.take_pending_applied_sync_summary());
                    on_progress.publish(self, committed).await;
                }
                match turn {
                    Ok(true) => break,
                    Ok(false) => {
                        tokio::select! {
                            () = super::native_ingress::wait_native_change(&mut native_changes) => {}
                            () = tokio::task::yield_now(), if admission.progressed => {}
                            () = tokio::time::sleep(RECOVERY_JOB_CANCEL_POLL), if control.is_some() => {}
                        }
                    }
                    Err(error) => {
                        return Err(self.fail_comparison_grant(
                            grant,
                            execution,
                            Some(admission),
                            error,
                        ));
                    }
                }
            }
        }
        self.finish_comparison_grant(grant, execution, admission)
            .await
    }

    /// Settle the execution bracket after admission: checkpoints, loss
    /// acknowledgment and audit rows.
    pub(crate) async fn finish_comparison_grant(
        &mut self,
        grant: AttemptGrant,
        execution: ComparisonExecution,
        mut admission: Option<ComparisonAdmission>,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        if let Some(admission) = admission.as_mut()
            && !admission.invalid
            && admission.pending.is_empty()
            && admission
                .routes
                .iter()
                .any(|route| !route.window_progress.is_empty())
        {
            let stable = match self.comparison_grant_stable(&grant, &execution, true).await {
                Ok(stable) => stable,
                Err(error) => {
                    return Err(self.fail_comparison_grant(
                        grant,
                        execution,
                        Some(admission),
                        error,
                    ));
                }
            };
            if stable {
                // Waiting tickets still own their hints; eligibility only
                // decides which tickets this grant may service.
                let live = self
                    .app
                    .account_storage(&self.state.label)
                    .and_then(|storage| {
                        Ok(storage
                            .app_storage()
                            .pending_recovery_demands()?
                            .into_iter()
                            .filter(|demand| {
                                demand.cause == storage_sqlite::RecoveryCause::EpochGap
                            })
                            .map(|demand| (demand.ticket.id, demand.ticket.revision))
                            .collect::<HashSet<_>>())
                    });
                let live = match live {
                    Ok(live) => live,
                    Err(error) => {
                        return Err(self.fail_comparison_grant(
                            grant,
                            execution,
                            Some(admission),
                            error,
                        ));
                    }
                };
                let progress = admission
                    .routes
                    .iter_mut()
                    .flat_map(|route| {
                        // REQ reachability spends the existing unserved budget;
                        // raw traversal itself never counts as progress.
                        for observation in &route.window_progress {
                            if observation.reached
                                && !route.reached_endpoints.iter().any(|endpoint| {
                                    transport_nostr::same_relay(endpoint, &observation.key.1)
                                })
                            {
                                route.reached_endpoints.push(observation.key.1.clone());
                            }
                        }
                        std::mem::take(&mut route.window_progress)
                    })
                    .collect();
                keep_window_progress(&self.epoch_gap_windows, &live, progress);
            }
        }
        let mut execution = *execution.execution;
        let selected = grant.fence.obligations.clone();
        let comparison_selected = grant.comparison_revision.is_some();
        let settled = match admission {
            // The grant changed before admission; nothing was admitted.
            None => {
                execution.interruption = Some(marmot_forensics::RecoveryPassOutcome::Superseded);
                Ok(None)
            }
            // A change during admission keeps the durable prefix but certifies
            // nothing; the debt waits for a later grant.
            Some(admission) if admission.invalid => {
                // A repair stopped at a turn boundary already named why.
                execution.interruption = execution
                    .interruption
                    .or(Some(marmot_forensics::RecoveryPassOutcome::Superseded));
                // Settlement is skipped, but the finish row still reports
                // what the relays returned and the admitted prefix.
                execution
                    .tally
                    .observe_unsettled_routes(admission.unsettled_routes());
                Ok(Some(admission.summary))
            }
            Some(admission) => self
                .checkpoint_comparison_admission(&grant, &mut execution, admission)
                .await
                .map(Some),
        };
        let deferred = matches!(settled, Ok(None));
        let summary = self
            .finish_recovery_execution(&grant, execution, settled.map(Option::unwrap_or_default))
            .map_err(|failure| {
                self.pending_failed_sync_summary
                    .merge(failure.partial_summary);
                failure.source
            })?;
        if deferred {
            return Ok(EpochBackfillRunOutcome::Deferred);
        }
        let storage = self.app.account_storage(&self.state.label)?;
        let complete = !comparison_selected
            && selected.iter().all(|(id, revision)| {
                storage
                    .app_storage()
                    .recovery_obligation_is_satisfied(*id, *revision)
                    .unwrap_or(false)
            });
        Ok(if complete {
            EpochBackfillRunOutcome::Completed(summary)
        } else {
            EpochBackfillRunOutcome::Incomplete(summary)
        })
    }

    /// The network task ended without a result. Settle the bracket like an
    /// attempt that admitted nothing; the durable debt waits for a later grant.
    pub(crate) fn abandon_comparison_grant(
        &mut self,
        grant: AttemptGrant,
        execution: ComparisonExecution,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        let mut execution = *execution.execution;
        execution.interruption = Some(marmot_forensics::RecoveryPassOutcome::Cancelled);
        self.finish_recovery_execution(&grant, execution, Ok(SyncSummary::default()))
            .map_err(|failure| failure.source)?;
        Ok(EpochBackfillRunOutcome::Deferred)
    }

    /// Admission failed. Settle the bracket as a failed attempt; the durable
    /// prefix stays and the debt waits for a later grant.
    pub(crate) fn fail_comparison_grant(
        &mut self,
        grant: AttemptGrant,
        execution: ComparisonExecution,
        admission: Option<&mut ComparisonAdmission>,
        error: AppError,
    ) -> AppError {
        let mut execution = *execution.execution;
        let mut failure = comparison_failure(error);
        if let Some(admission) = admission {
            execution
                .tally
                .observe_unsettled_routes(admission.unsettled_routes());
            failure.partial_summary = std::mem::take(&mut admission.summary);
        }
        match self.finish_recovery_execution(&grant, execution, Err(failure)) {
            Ok(_) => unreachable!("a failed recovery cannot complete"),
            Err(failure) => {
                self.pending_failed_sync_summary
                    .merge(failure.partial_summary);
                failure.source
            }
        }
    }

    async fn checkpoint_comparison_admission(
        &mut self,
        grant: &AttemptGrant,
        execution: &mut RecoveryExecutionState,
        admission: ComparisonAdmission,
    ) -> Result<SyncSummary, ClassifiedSyncFailure> {
        let mut summary = admission.summary;
        let mut failure = |error| {
            ClassifiedSyncFailure::at_stage(
                std::mem::take(&mut summary),
                error,
                SyncFailureStage::Unknown,
            )
        };
        self.synchronize_native_replay()
            .await
            .map_err(&mut failure)?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(&mut failure)?;
        let mut outcomes = Vec::with_capacity(admission.routes.len());
        for route in admission.routes {
            // Rotate past completed attempts, including capacity refusals, so
            // later passes reach dependencies beyond them. Refused IDs stay
            // remote-only; an unattempted suffix keeps the pre-pass cursor.
            if route.remaining == Some(0) && route.cursor != route.initial_cursor {
                storage
                    .app_storage()
                    .advance_transport_reconciliation_replay_cursor(&route.route, route.cursor)
                    .map_err(|error| failure(error.into()))?;
            }
            outcomes.push(super::RouteComparison {
                route: route.route,
                outcome: if route.admitted {
                    route.outcome
                } else {
                    Outcome::TransientFailure
                },
                certified: route.certified && route.admitted,
                fetched: route.fetched,
                // Incomplete admission withholds the certificate and retries
                // the route, but the relays still answered.
                answered: route.answered,
                retry_admission: route.retry_admission,
                reached_endpoints: route.reached_endpoints,
                acquisition: route.acquisition,
            });
        }
        self.settle_recovery_grant(
            grant,
            &mut execution.counts,
            &mut execution.tally,
            outcomes,
            summary,
        )
        .await
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
    use std::sync::Arc;

    fn candidate_for_route(route: [u8; 32]) -> transport_nostr_adapter::NostrRelayEvent {
        candidate_for_route_at(route, crate::unix_now_seconds())
    }

    fn candidate_for_route_at(
        route: [u8; 32],
        created_at: u64,
    ) -> transport_nostr_adapter::NostrRelayEvent {
        let signed = EventBuilder::new(Kind::MlsGroupMessage, "queue boundary")
            .tags([Tag::custom("h", [hex::encode(route)])])
            .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(created_at))
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

    /// A signed event of a kind no transport message can carry.
    fn unreadable_for_route(route: [u8; 32]) -> transport_nostr_adapter::NostrRelayEvent {
        let signed = EventBuilder::new(Kind::TextNote, "not a transport message")
            .tags([Tag::custom("h", [hex::encode(route)])])
            .finalize(&Keys::generate())
            .unwrap();
        transport_nostr_adapter::NostrRelayEvent {
            endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
            subscription_id: None,
            event: transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&signed).unwrap(),
        }
    }

    // Observes the permit between abort() and the next scheduler turn; on more
    // than one thread a worker can drop the aborted future before the assert.
    #[tokio::test(flavor = "current_thread")]
    async fn abort_request_keeps_credit_until_network_future_is_dropped() {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let credit = Arc::new(capacity.clone().try_acquire_owned().unwrap());
        let entered = Arc::new(tokio::sync::Notify::new());
        let waiting = entered.notified();
        tokio::pin!(waiting);
        waiting.as_mut().enable();
        let handle = tokio::spawn({
            let entered = entered.clone();
            async move {
                entered.notify_one();
                std::future::pending::<()>().await;
                (
                    credit,
                    ComparisonNetworkResult {
                        routes: Vec::new(),
                        capture_error: None,
                    },
                )
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

    // Pairs with the test above: on one thread only abort_and_wait, not
    // another worker, can have dropped the future before the final assert.
    #[tokio::test(flavor = "current_thread")]
    async fn abort_and_wait_reaps_network_future_before_returning() {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let credit = Arc::new(capacity.clone().try_acquire_owned().unwrap());
        let entered = Arc::new(tokio::sync::Notify::new());
        let waiting = entered.notified();
        tokio::pin!(waiting);
        waiting.as_mut().enable();
        let handle = tokio::spawn({
            let entered = entered.clone();
            async move {
                entered.notify_one();
                std::future::pending::<()>().await;
                (
                    credit,
                    ComparisonNetworkResult {
                        routes: Vec::new(),
                        capture_error: None,
                    },
                )
            }
        });
        let job = ComparisonNetworkJob { handle };
        waiting.await;
        assert_eq!(capacity.available_permits(), 0);
        job.abort_and_wait().await;
        assert_eq!(capacity.available_permits(), 1);
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        _pump: ScriptedEosePump,
        relay: Arc<ScriptedPushRelayClient>,
        client: AppClient,
        storage: storage_sqlite::SqliteAccountStorage,
        group_id: GroupId,
    }

    // One thread makes the abort-and-reap boundary deterministic.
    #[tokio::test(flavor = "current_thread")]
    async fn aborted_job_keeps_credit_while_accepted_capture_owns_cleanup() {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let credit = Arc::new(capacity.clone().try_acquire_owned().unwrap());
        let capture_cleanup_credit = credit.clone();
        let handle = tokio::spawn(async move {
            std::future::pending::<()>().await;
            (
                credit,
                ComparisonNetworkResult {
                    routes: Vec::new(),
                    capture_error: None,
                },
            )
        });
        ComparisonNetworkJob { handle }.abort_and_wait().await;
        assert_eq!(capacity.available_permits(), 0);
        drop(capture_cleanup_credit);
        assert_eq!(capacity.available_permits(), 1);
    }

    async fn fixture() -> Fixture {
        fixture_with_group_relays(None).await
    }

    async fn fixture_with_group_relays(relays: Option<Vec<String>>) -> Fixture {
        fixture_with_group_relays_and_comparison(relays, true).await
    }

    async fn fixture_with_group_relays_and_comparison(
        relays: Option<Vec<String>>,
        comparison: bool,
    ) -> Fixture {
        fixture_with_options(relays, comparison, false).await
    }

    /// The default fixture, recording audit v5 from before the account opens.
    async fn audited_fixture() -> Fixture {
        fixture_with_options(None, true, true).await
    }

    async fn fixture_with_options(
        relays: Option<Vec<String>>,
        comparison: bool,
        audited: bool,
    ) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        crate::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        if audited {
            app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
                .unwrap();
        }
        let pump = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
        let mut client = client_on_app_relay_plane(&app, "alice").await;
        let group_id = client
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
        if comparison {
            client.request_bounded_comparison().unwrap();
        }
        let storage = app.account_storage("alice").unwrap();
        Fixture {
            _dir: dir,
            _pump: pump,
            relay,
            client,
            storage,
            group_id,
        }
    }

    async fn arm_test_epoch_gap(fixture: &mut Fixture) {
        // Settle the create-group history demand through the original
        // executor, leaving its NeedsDeepRepair debt ineligible as in the
        // online worker fixture. The next selection then belongs to one gap.
        let baseline = fixture
            .client
            .authorize_account_recovery(
                None,
                marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
            )
            .await
            .unwrap()
            .unwrap();
        fixture
            .client
            .run_recovery_grant_for_test(baseline)
            .await
            .unwrap();
        let epoch = fixture
            .client
            .group_mls_state(&fixture.group_id)
            .unwrap()
            .epoch;
        fixture
            .storage
            .app_storage()
            .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(fixture.group_id.as_slice()),
                stalled_epoch: epoch,
            }])
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_job_without_capture_tokens_does_not_scan_native_sources() {
        let mut fixture = fixture().await;
        let mut grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        grant.inventory.clear();
        grant.replay_capture.clear();
        let calls = fixture.relay.acquisition_calls.load(Ordering::SeqCst);
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let credit = capacity.clone().try_acquire_owned().unwrap();
        let mut job = ComparisonNetworkJob::start(
            &fixture.client,
            &grant,
            credit,
            ComparisonNetworkJob::automatic_deadline(),
            None,
        )
        .unwrap();
        let (credit, network) = job.wait().await.unwrap();
        assert!(network.routes.is_empty());
        assert!(network.capture_error.is_none());
        assert_eq!(
            fixture.relay.acquisition_calls.load(Ordering::SeqCst),
            calls
        );
        assert_eq!(capacity.available_permits(), 0);
        drop(credit);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_native_capture_failure_uses_the_job_failure_path() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        let result = fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                execution,
                ComparisonNetworkResult {
                    routes: Vec::new(),
                    capture_error: Some(cgka_traits::TransportAdapterError::InvalidInboundEncoding),
                },
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_recovery_waits_for_a_credit_without_spending_a_reservation() {
        let relays = (0..5)
            .map(|index| format!("wss://relay-{index}.example"))
            .collect();
        // Five relays on one route no longer change how the gap is served.
        for relays in [None, Some(relays)] {
            let mut fixture = fixture_with_group_relays_and_comparison(relays, false).await;
            arm_test_epoch_gap(&mut fixture).await;
            let serial = fixture
                .storage
                .app_storage()
                .recovery_retry_state()
                .unwrap()
                .attempt_serial;
            assert!(fixture.client.recovery_pending().unwrap());
            assert_eq!(
                fixture
                    .storage
                    .app_storage()
                    .recovery_retry_state()
                    .unwrap()
                    .attempt_serial,
                serial,
                "the preflight spends no reservation"
            );
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
                window: Vec::new(),
                window_progress: Vec::new(),
                cursor,
                result: ComparisonRouteWorkResult::Returned(Ok(Some((
                    transport_nostr_adapter::NostrReconciliationSummary {
                        relays_succeeded: 1,
                        ..Default::default()
                    },
                    Vec::new(),
                )))),
            }],
            capture_error: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_route_with_more_than_four_relays_is_compared_by_the_job() {
        let relays = (0..5)
            .map(|index| format!("wss://relay-{index}.example"))
            .collect();
        let mut fixture = fixture_with_group_relays(Some(relays)).await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        let route = grant
            .inventory
            .iter()
            .find(|route| match &route.work {
                TransportReconciliationWork::Group(group) => group.endpoints.len() == 5,
                TransportReconciliationWork::Inbox(_) => false,
            })
            .expect("every relay of the wide route is compared")
            .route
            .clone();
        let serial = grant.reservation.attempt_serial;
        let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        let result = fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                execution,
                network_result(route.clone(), Some([8; 32])),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .app_storage()
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32])
        );
        assert_eq!(
            fixture
                .storage
                .app_storage()
                .recovery_retry_state()
                .unwrap()
                .attempt_serial,
            serial,
            "the selected grant is settled without a second authorization"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn comparison_stale_result_preserves_cursor_and_debt() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        let activated_subscription = fixture.client.adapter.account_subscription_attempt().await;
        let new_goals = fixture
            .client
            .comparison_route_goals(unix_now_seconds())
            .unwrap();
        fixture
            .storage
            .app_storage()
            .join_recovery_comparison(
                &[9; 16],
                crate::client::recovery::wall_now_ms().unwrap(),
                &new_goals,
            )
            .unwrap();
        let result = fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                attempt,
                network_result(route.clone(), Some([8; 32])),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        assert_eq!(
            fixture
                .storage
                .app_storage()
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None
        );
        assert!(
            fixture
                .storage
                .app_storage()
                .recovery_comparison()
                .unwrap()
                .pending()
        );
        fixture
            .client
            .finish_deferred_comparison_sync(None)
            .await
            .unwrap();
        assert_eq!(
            fixture.client.adapter.account_subscription_attempt().await,
            activated_subscription,
            "a stale startup comparison drains its live activation without rebuilding subscriptions"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn comparison_inventory_change_rejects_owned_result() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
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
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        let before = fixture
            .storage
            .app_storage()
            .recovery_revision_fence()
            .unwrap()
            .inventory_revision;
        fixture
            .storage
            .app_storage()
            .record_reconciliation_items(std::iter::once((
                &TransportReconciliationRoute::Group(route),
                &TransportReconciliationItem {
                    event_id: [5; 32],
                    created_at: unix_now_seconds(),
                },
            )))
            .unwrap();
        fixture
            .storage
            .delete_transport_group_route(&route)
            .unwrap();
        assert!(
            fixture
                .storage
                .app_storage()
                .recovery_revision_fence()
                .unwrap()
                .inventory_revision
                > before
        );
        let result = fixture
            .client
            .admit_comparison_inline(
                None,
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
                .app_storage()
                .transport_reconciliation_replay_cursor(&TransportReconciliationRoute::Inbox)
                .unwrap(),
            None
        );
        assert!(
            fixture
                .storage
                .app_storage()
                .recovery_comparison()
                .unwrap()
                .pending()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn comparison_subscription_change_rejects_owned_result() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        fixture.client.adapter.require_fresh_activation().await;
        fixture
            .client
            .runtime
            .activate_transport(None)
            .await
            .unwrap();
        assert_ne!(
            fixture.client.adapter.account_subscription_attempt().await,
            attempt.attempt
        );
        let result = fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                attempt,
                network_result(route.clone(), Some([8; 32])),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        assert_eq!(
            fixture
                .storage
                .app_storage()
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None
        );
        assert!(
            fixture
                .storage
                .app_storage()
                .recovery_comparison()
                .unwrap()
                .pending()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn comparison_worker_join_persists_advisory_cursor_before_settlement() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        let result = fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                attempt,
                network_result(route.clone(), Some([8; 32])),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .app_storage()
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32])
        );
    }

    async fn group_route_grant(
        fixture: &mut Fixture,
    ) -> (
        AttemptGrant,
        ComparisonExecution,
        TransportReconciliationRoute,
        [u8; 32],
    ) {
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
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
        let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        (grant, execution, route, group_route)
    }

    fn fetched(
        route: TransportReconciliationRoute,
        events: Vec<transport_nostr_adapter::NostrRelayEvent>,
    ) -> ComparisonNetworkResult {
        let mut network = network_result(route, Some([8; 32]));
        network.routes[0].result = ComparisonRouteWorkResult::Returned(Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            events,
        ))));
        network
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum DeadlineFault {
        HeldFetch,
        PostReplyStall,
        RouteStall,
    }

    /// Proxy a real relay, delaying the first NEG reply path and then either
    /// holding a later exact-ID REQ or stalling after a valid NEG fingerprint.
    /// Ordinary group subscriptions cannot preload the SDK cache; only the
    /// owned comparison/window paths can recover the genuine peer traffic.
    struct DeadlineRelay {
        url: String,
        held_id: Arc<Mutex<Option<String>>>,
        stalled_groups: Arc<Mutex<Vec<String>>>,
        stalled: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    /// Holds every exact-ID query that names `id`, as a relay that never
    /// finishes serving it.
    #[derive(Clone, Debug, Default)]
    struct HeldId {
        id: Arc<Mutex<Option<String>>>,
        hits: Arc<AtomicUsize>,
    }

    impl nostr_relay_builder::prelude::QueryPolicy for HeldId {
        fn admit_query<'a>(
            &'a self,
            query: &'a nostr_relay_builder::prelude::Filter,
            _addr: &'a std::net::SocketAddr,
        ) -> nostr_relay_builder::prelude::BoxedFuture<'a, nostr_relay_builder::prelude::PolicyResult>
        {
            Box::pin(async move {
                let held = self.id.lock().unwrap().clone();
                if held.is_some_and(|held| {
                    query
                        .ids
                        .as_ref()
                        .is_some_and(|ids| ids.iter().any(|id| id.to_hex() == held))
                }) {
                    self.hits.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                }
                nostr_relay_builder::prelude::PolicyResult::Accept
            })
        }
    }

    /// A relay holds the inbox route's second exact-ID fetch. The SDK stops at
    /// the route's comparison deadline and returns the event it already
    /// fetched; the job's hard guard must not cancel that result. (A group
    /// route would also need a boundary probe the held connection cannot
    /// answer, and would rightly return nothing.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_held_fetch_keeps_the_fetched_prefix() {
        use nostr_relay_builder::prelude::{
            MemoryDatabase, MemoryDatabaseOptions, NostrDatabase, RelayBuilder,
        };
        let held = HeldId::default();
        let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
            events: true,
            max_events: Some(8),
        });
        let relay = nostr_relay_builder::LocalRelay::new(
            RelayBuilder::default()
                .query_policy(held.clone())
                .database(database.clone()),
        );
        relay.run().await.unwrap();
        let url = relay.url().await.to_string();
        let mut fixture = fixture_with_group_relays(Some(vec![url.clone()])).await;
        let inbox = hex::encode(fixture.client.runtime.session().self_id().as_slice());
        // The inbox pass fetches in ID order: the smaller ID goes first, alone.
        let at = crate::unix_now_seconds() - 60;
        let signed = |offset: u64, low_id: bool| loop {
            let event = EventBuilder::new(Kind::GiftWrap, "welcome")
                .tags([Tag::custom("p", [inbox.clone()])])
                .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(at + offset))
                .finalize(&Keys::generate())
                .unwrap();
            if (event.id.to_bytes()[0] < 128) == low_id {
                break event;
            }
        };
        let (fetched, withheld) = (signed(0, true), signed(1, false));
        for event in [&fetched, &withheld] {
            database
                .save_event(&serde_json::from_value(serde_json::to_value(event).unwrap()).unwrap())
                .await
                .unwrap();
        }
        *held.id.lock().unwrap() = Some(withheld.id.to_hex());
        drop(fixture.client);
        let real_app = crate::MarmotApp::with_relay_and_config(
            fixture._dir.path(),
            url,
            crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
        );
        fixture.client = client_on_app_relay_plane(&real_app, "alice").await;
        fixture.client.test_comparison_results = None;
        fixture.client.request_bounded_comparison().unwrap();
        let (grant, _execution, _, _) = group_route_grant(&mut fixture).await;
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let mut job = ComparisonNetworkJob::start(
            &fixture.client,
            &grant,
            capacity.try_acquire_owned().unwrap(),
            ComparisonNetworkJob::automatic_deadline(),
            None,
        )
        .unwrap();
        let (_credit, network) = job.wait().await.unwrap();
        assert!(
            held.hits.load(Ordering::SeqCst) > 0,
            "the relay held a fetch"
        );
        let result = network
            .routes
            .iter()
            .find(|result| result.route == TransportReconciliationRoute::Inbox)
            .unwrap();
        let ComparisonRouteWorkResult::Returned(Ok(Some((_, events)))) = &result.result else {
            panic!("the hard guard discarded the SDK's fetched prefix");
        };
        assert_eq!(
            events
                .iter()
                .map(|event| event.event.id.clone())
                .collect::<Vec<_>>(),
            [fetched.id.to_hex()]
        );
        relay.shutdown();
    }

    impl Drop for DeadlineRelay {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn deadline_relay(backend: String, fault: DeadlineFault) -> DeadlineRelay {
        use futures::{SinkExt, StreamExt};
        use serde_json::Value;
        use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};

        // Valid v1 whole-range fingerprint, matching the adapter limit relay's
        // FingerprintLoop: the peer must negotiate again, not fail parsing.
        const MISMATCHED_NEG_MSG: &str = "61000001ffeeddccbbaa99887766554433221100";

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let held_id = Arc::new(Mutex::new(None::<String>));
        let stalled_groups = Arc::new(Mutex::new(Vec::<String>::new()));
        let stalled = Arc::new(AtomicUsize::new(0));
        let held = held_id.clone();
        let group = stalled_groups.clone();
        let observed = stalled.clone();
        let first_neg = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let (backend, held, group, observed, first_neg) = (
                    backend.clone(),
                    held.clone(),
                    group.clone(),
                    observed.clone(),
                    first_neg.clone(),
                );
                connections.spawn(async move {
                    let Ok(client) = accept_async(stream).await else { return };
                    let Ok((upstream, _)) = connect_async(backend).await else { return };
                    let (mut client_write, mut client_read) = client.split();
                    let (mut upstream_write, mut upstream_read) = upstream.split();
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
                    let to_upstream = async {
                        let mut stalled_sessions = std::collections::HashSet::new();
                        while let Some(Ok(message)) = client_read.next().await {
                            if let Message::Text(text) = &message
                                && let Ok(frame) = serde_json::from_str::<Vec<Value>>(text)
                            {
                                match frame.first().and_then(Value::as_str) {
                                    Some("NEG-OPEN") => {
                                        if fault == DeadlineFault::RouteStall
                                            && frame.get(2).and_then(|filter| filter.get("#h"))
                                                .and_then(Value::as_array).is_some_and(|routes| {
                                                    group.lock().unwrap().iter().any(|group| {
                                                        routes.iter().any(|route| route.as_str() == Some(group.as_str()))
                                                    })
                                                })
                                        {
                                            let Some(id) = frame.get(1).and_then(Value::as_str) else { continue };
                                            stalled_sessions.insert(id.to_owned());
                                            tokio::time::sleep(Duration::from_millis(250)).await;
                                            observed.fetch_add(1, Ordering::SeqCst);
                                            let reply = serde_json::json!(["NEG-MSG", id, MISMATCHED_NEG_MSG]);
                                            if tx.send(Message::Text(reply.to_string().into())).is_err() { break }
                                            continue;
                                        }
                                        if fault != DeadlineFault::RouteStall
                                            && first_neg.fetch_add(1, Ordering::SeqCst) == 0 {
                                            tokio::time::sleep(Duration::from_secs(4)).await;
                                        }
                                        if fault == DeadlineFault::RouteStall {
                                            // Healthy history is not an instant empty answer:
                                            // each useful comparison crosses a WAN-like hop.
                                            tokio::time::sleep(Duration::from_millis(250)).await;
                                        }
                                        if fault == DeadlineFault::PostReplyStall {
                                            // Whole-range mismatched fingerprint: a real
                                            // NEG round follows, then the relay goes idle.
                                            let reply = serde_json::json!(["NEG-MSG", frame[1],
                                                MISMATCHED_NEG_MSG]);
                                            if tx.send(Message::Text(reply.to_string().into())).is_err() { break }
                                            continue;
                                        }
                                    }
                                    Some("NEG-MSG") if fault == DeadlineFault::RouteStall
                                        && frame.get(1).and_then(Value::as_str)
                                            .is_some_and(|id| stalled_sessions.contains(id)) => {
                                        // Keep the relevant negotiation active through both
                                        // SDK first-reply and idle timers. Only the caller's
                                        // existing route/pass cutoff can end this attempt.
                                        tokio::time::sleep(Duration::from_millis(250)).await;
                                        observed.fetch_add(1, Ordering::SeqCst);
                                        let reply = serde_json::json!(["NEG-MSG", frame[1], MISMATCHED_NEG_MSG]);
                                        if tx.send(Message::Text(reply.to_string().into())).is_err() { break }
                                        continue;
                                    }
                                    Some("NEG-MSG") if fault == DeadlineFault::PostReplyStall => {
                                        observed.fetch_add(1, Ordering::SeqCst);
                                        continue;
                                    }
                                    Some("NEG-CLOSE") => {
                                        if let Some(id) = frame.get(1).and_then(Value::as_str) {
                                            stalled_sessions.remove(id);
                                        }
                                    }
                                    Some("REQ") => {
                                        let blocked = frame.iter().skip(2).any(|filter| {
                                            if fault == DeadlineFault::RouteStall {
                                                if filter.get("#p").is_some() {
                                                    return true;
                                                }
                                                if filter.get("#h").and_then(Value::as_array).is_some_and(|routes| {
                                                    group.lock().unwrap().iter().any(|group| {
                                                        routes.iter().any(|route| route.as_str() == Some(group.as_str()))
                                                    })
                                                }) {
                                                    return true;
                                                }
                                            }
                                            if let Some(ids) = filter.get("ids").and_then(Value::as_array) {
                                                return held.lock().unwrap().as_ref().is_some_and(|held| {
                                                    ids.iter().any(|id| id.as_str() == Some(held.as_str()))
                                                });
                                            }
                                            filter.get("#h").is_some()
                                                && filter.get("limit").and_then(Value::as_u64)
                                                    != Some(EPOCH_GAP_WINDOW_PAGE_EVENTS as u64)
                                        });
                                        if blocked {
                                            if frame.iter().skip(2).any(|filter| filter.get("ids").is_some()) {
                                                observed.fetch_add(1, Ordering::SeqCst);
                                            }
                                            continue;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            if upstream_write.send(message).await.is_err() { break }
                        }
                    };
                    let to_client = async {
                        loop {
                            let message = tokio::select! {
                                message = rx.recv() => match message { Some(message) => message, None => break },
                                message = upstream_read.next() => match message { Some(Ok(message)) => message, _ => break },
                            };
                            if client_write.send(message).await.is_err() { break }
                        }
                    };
                    tokio::select! { _ = to_upstream => {}, _ = to_client => {} }
                });
            }
        });
        DeadlineRelay {
            url,
            held_id,
            stalled_groups,
            stalled,
            task,
        }
    }

    async fn settle_peer_epoch(client: &mut AppClient, group_id: &GroupId) {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                client
                    .advance_convergence_after_runtime_sync(group_id)
                    .await
                    .unwrap();
                if matches!(
                    client.group_mls_state(group_id).unwrap().lifecycle_state,
                    crate::AppGroupLifecycleState::Stable
                ) && !client
                    .runtime
                    .has_pending_convergence_inputs(group_id)
                    .unwrap()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the real authored epoch settles before another peer operation");
    }

    /// Both regressions enter through the real app job and admit genuine MLS
    /// traffic. Rewrapping changes only the transport timestamp/id, as when an
    /// offline peer's already-authored traffic reaches a relay much later.
    async fn recover_peer_at_caller_cutoff(fault: DeadlineFault) {
        use nostr_sdk::local_relay::LocalRelay;
        let epoch_gap = fault == DeadlineFault::PostReplyStall;
        let relay = LocalRelay::new();
        relay.run().await.unwrap();
        let proxy = deadline_relay(relay.url().await.to_string(), fault).await;
        let mut fixture = fixture_with_group_relays(Some(vec![proxy.url.clone()])).await;
        let app = fixture.client.app.clone();
        let bob = crate::AccountHome::open(fixture._dir.path())
            .create_account("bob")
            .unwrap();
        crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
        let mut peer = client_on_app_relay_plane(&app, "bob").await;
        peer.sync().await.unwrap();
        fixture
            .client
            .invite_members(&fixture.group_id, &[bob.account_id_hex.as_str()])
            .await
            .unwrap();
        peer.sync().await.unwrap();
        if epoch_gap {
            settle_peer_epoch(&mut fixture.client, &fixture.group_id).await;
            settle_peer_epoch(&mut peer, &fixture.group_id).await;
            fixture
                .client
                .promote_admin(&fixture.group_id, &bob.account_id_hex)
                .await
                .unwrap();
            settle_peer_epoch(&mut fixture.client, &fixture.group_id).await;
            peer.sync().await.unwrap();
            settle_peer_epoch(&mut peer, &fixture.group_id).await;
            assert_eq!(
                peer.group_mls_state(&fixture.group_id).unwrap().epoch,
                fixture
                    .client
                    .group_mls_state(&fixture.group_id)
                    .unwrap()
                    .epoch
            );
        }
        let initial_epoch = fixture
            .client
            .group_mls_state(&fixture.group_id)
            .unwrap()
            .epoch;
        let before = fixture
            .relay
            .attempted_events()
            .into_iter()
            .map(|event| event.id)
            .collect::<HashSet<_>>();
        let commit_id = if epoch_gap {
            let commit = peer
                .update_group_profile(&fixture.group_id, Some("late real commit"), None)
                .await
                .unwrap();
            assert_eq!(
                commit.published, 1,
                "Bob publishes the genuine late MLS commit"
            );
            let mut commits = fixture
                .relay
                .attempted_events()
                .into_iter()
                .filter(|event| !before.contains(&event.id))
                .collect::<Vec<_>>();
            assert_eq!(
                commits.len(),
                1,
                "the profile change publishes exactly its genuine MLS commit"
            );
            let commit_id = commits.pop().unwrap().id;
            settle_peer_epoch(&mut peer, &fixture.group_id).await;
            Some(commit_id)
        } else {
            None
        };
        let sent = peer
            .send(&fixture.group_id, b"peer recovered at caller cutoff")
            .await
            .unwrap();
        assert_eq!(
            sent.published, 1,
            "Bob's first genuine message reaches the relay"
        );
        let later = peer
            .send(&fixture.group_id, b"later peer held by relay")
            .await
            .unwrap();
        assert_eq!(
            later.published, 1,
            "Bob's later genuine message reaches the relay"
        );
        let peer_epoch = peer.group_mls_state(&fixture.group_id).unwrap().epoch;
        let route_hex = app
            .group("alice", &hex::encode(fixture.group_id.as_slice()))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex;
        let source = app
            .account_storage("bob")
            .unwrap()
            .app_storage()
            .timeline_message(
                &hex::encode(fixture.group_id.as_slice()),
                &sent.message_ids[0],
            )
            .unwrap()
            .unwrap()
            .source_message_id_hex
            .unwrap();
        let mut originals = fixture
            .relay
            .attempted_events()
            .into_iter()
            .filter(|event| !before.contains(&event.id))
            .collect::<Vec<_>>();
        // A commit precedes both messages. In the non-gap case the first
        // message's smaller ID also makes it the SDK's first exact-ID fetch.
        originals.sort_by_key(|event| {
            if commit_id.as_ref() == Some(&event.id) {
                0
            } else if event.id == source {
                1
            } else {
                2
            }
        });
        let at = crate::unix_now_seconds() - 60;
        let mut published = Vec::new();
        for (index, original) in originals.into_iter().enumerate() {
            let event = loop {
                let event = EventBuilder::new(Kind::MlsGroupMessage, original.content.clone())
                    .tags([Tag::custom("h", [route_hex.clone()])])
                    .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(at + index as u64))
                    .finalize(&Keys::generate())
                    .unwrap();
                if epoch_gap || (event.id.to_bytes()[0] < 128) == (index == 0) {
                    break event;
                }
            };
            relay.add_event(event.clone()).await.unwrap();
            published.push(event);
        }
        assert_eq!(published.len(), if epoch_gap { 3 } else { 2 });
        if !epoch_gap {
            *proxy.held_id.lock().unwrap() = Some(published[1].id.to_hex());
        }
        drop(peer);
        drop(fixture.client);
        let real_app = crate::MarmotApp::with_relay_and_config(
            fixture._dir.path(),
            proxy.url.clone(),
            crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
        );
        fixture.client = client_on_app_relay_plane(&real_app, "alice").await;
        fixture.client.test_comparison_results = None;
        assert!(
            !real_app
                .messages("alice")
                .unwrap()
                .iter()
                .any(|message| { sent.message_ids.contains(&message.message_id_hex) }),
            "Alice has not consumed the genuine peer message before recovery"
        );
        assert_eq!(
            fixture
                .client
                .group_mls_state(&fixture.group_id)
                .unwrap()
                .epoch,
            initial_epoch
        );
        if epoch_gap {
            // The peer's real post-commit message is undecryptable until the
            // window recovers the missing commit, not a synthetic gap probe.
            let event = transport_nostr_adapter::NostrRelayEvent {
                endpoint: cgka_traits::TransportEndpoint(proxy.url.clone()),
                subscription_id: None,
                event: transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&published[1])
                    .unwrap(),
            };
            for delivery in fixture
                .client
                .adapter
                .recovered_deliveries(event)
                .await
                .unwrap()
            {
                fixture
                    .client
                    .ingest_received_delivery(delivery)
                    .await
                    .unwrap();
            }
            arm_unpaced_epoch_gap(&fixture);
        } else {
            fixture.client.request_bounded_comparison().unwrap();
            let (grant, execution, _, _) = group_route_grant(&mut fixture).await;
            let capacity = Arc::new(tokio::sync::Semaphore::new(1));
            let mut job = ComparisonNetworkJob::start(
                &fixture.client,
                &grant,
                capacity.try_acquire_owned().unwrap(),
                tokio::time::Instant::now(),
                None,
            )
            .unwrap();
            let (credit, network) = job.wait().await.unwrap();
            assert!(
                network
                    .routes
                    .iter()
                    .all(|route| { matches!(route.result, ComparisonRouteWorkResult::Skipped) })
            );
            fixture
                .client
                .admit_comparison_inline(None, grant, execution, network)
                .await
                .unwrap();
            drop(credit);
            assert!(
                fixture
                    .storage
                    .app_storage()
                    .recovery_comparison()
                    .unwrap()
                    .pending(),
                "never-started acquisition keeps its automatic retry, without a new request"
            );
            fixture
                .client
                .recovery_owner
                .test_advance_to_retry(&fixture.storage);
        }
        let (mut grant, mut execution, route, _) = group_route_grant(&mut fixture).await;
        // Run the real group obligation first; an unrelated inbox's first NEG
        // must not consume the relay's deliberate WAN delay.
        grant
            .inventory
            .sort_by_key(|inventory| inventory.route != route);
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let mut job = ComparisonNetworkJob::start(
            &fixture.client,
            &grant,
            capacity.try_acquire_owned().unwrap(),
            ComparisonNetworkJob::automatic_deadline(),
            None,
        )
        .unwrap();
        let (_credit, network) = job.wait().await.unwrap();
        assert!(
            proxy.stalled.load(Ordering::SeqCst) > 0,
            "the real relay reached the stalled stage"
        );
        let result = &network.routes[0];
        if epoch_gap {
            assert!(
                result
                    .window
                    .iter()
                    .any(|event| event.event.id == published[0].id.to_hex()),
                "the caller left enough time to recover the genuine late commit"
            );
        } else {
            let ComparisonRouteWorkResult::Returned(Ok(Some((_, events)))) = &result.result else {
                panic!("the hard app guard discarded the SDK's owned prefix");
            };
            assert!(
                events
                    .iter()
                    .any(|event| event.event.id == published[0].id.to_hex()),
                "the SDK returns a nonempty owned prefix despite the later stalled fetch"
            );
            assert!(result.window.is_empty());
        }
        let mut admission = fixture
            .client
            .accept_comparison_network(&grant, &mut execution, network)
            .await
            .unwrap()
            .unwrap();
        while !fixture
            .client
            .admit_comparison_turn(&grant, &mut execution, &mut admission)
            .await
            .unwrap()
        {}
        fixture
            .client
            .finish_comparison_grant(grant, execution, Some(admission))
            .await
            .unwrap();
        if epoch_gap {
            // Window admission retains the real commit and future traffic;
            // the worker's ordinary convergence turns adopt that commit and
            // retry the deferred application backlog under the new context.
            // Drive only that retained work, without another network fetch.
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    fixture
                        .client
                        .advance_convergence_after_runtime_sync(&fixture.group_id)
                        .await
                        .unwrap();
                    if real_app.messages("alice").unwrap().iter().any(|message| {
                        message.sender == bob.account_id_hex
                            && sent.message_ids.contains(&message.message_id_hex)
                            && message.plaintext == "peer recovered at caller cutoff"
                    }) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("ordinary convergence adopts the recovered commit and projects Bob's message");
        }
        assert!(
            real_app.messages("alice").unwrap().iter().any(|message| {
                message.sender == bob.account_id_hex
                    && sent.message_ids.contains(&message.message_id_hex)
                    && message.plaintext == "peer recovered at caller cutoff"
            }),
            "the owned result reaches Alice's authenticated timeline"
        );
        if epoch_gap {
            assert!(peer_epoch > initial_epoch);
            assert_eq!(
                fixture
                    .client
                    .group_mls_state(&fixture.group_id)
                    .unwrap()
                    .epoch,
                peer_epoch
            );
            assert_eq!(
                real_app
                    .group("alice", &hex::encode(fixture.group_id.as_slice()))
                    .unwrap()
                    .unwrap()
                    .profile
                    .name,
                "late real commit"
            );
        }
        relay.shutdown();
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FairnessPass {
        Automatic,
        Explicit,
        RefillBoundary,
        ExpiredFloor,
    }

    async fn recover_stalled_routes(pass: FairnessPass) {
        use nostr_sdk::local_relay::LocalRelay;

        let relay = LocalRelay::new();
        relay.run().await.unwrap();
        let proxy = deadline_relay(relay.url().await.to_string(), DeadlineFault::RouteStall).await;
        let stalled_proxy = if pass == FairnessPass::RefillBoundary {
            Some(deadline_relay(relay.url().await.to_string(), DeadlineFault::RouteStall).await)
        } else {
            None
        };
        let stalled_relay = stalled_proxy.as_ref().unwrap_or(&proxy);
        let mut fixture =
            fixture_with_group_relays_and_comparison(Some(vec![stalled_relay.url.clone()]), false)
                .await;
        let app = fixture.client.app.clone();
        let mut stalled_groups = vec![fixture.group_id.clone()];
        if pass == FairnessPass::Explicit {
            for index in 0..3 {
                stalled_groups.push(
                    fixture
                        .client
                        .create_group_with_options(
                            &format!("stalled explicit {index}"),
                            &[],
                            crate::AppCreateGroupOptions {
                                relays: Some(vec![proxy.url.clone()]),
                                ..Default::default()
                            },
                        )
                        .await
                        .unwrap(),
                );
            }
        }
        let alice = hex::encode(fixture.client.runtime.session().self_id().as_slice());
        let bob = crate::AccountHome::open(fixture._dir.path())
            .create_account("bob")
            .unwrap();
        for member in [&alice, &bob.account_id_hex] {
            crate::tests::remember_test_member_inbox(&app, member, "wss://relay.example");
        }
        let mut peer = client_on_app_relay_plane(&app, "bob").await;
        peer.sync().await.unwrap();
        let mut messages = Vec::new();
        // Automatic work exceeds its three rotation slots. Explicit work has
        // four armed stalls and a healthy tail. Neither test reorders grants.
        let healthy = if matches!(pass, FairnessPass::Explicit | FairnessPass::ExpiredFloor) {
            1
        } else {
            4
        };
        for index in 0..healthy {
            let group = fixture
                .client
                .create_group_with_options(
                    &format!("healthy rotation {index}"),
                    &[],
                    crate::AppCreateGroupOptions {
                        relays: Some(vec![proxy.url.clone()]),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            fixture
                .client
                .invite_members(&group, &[bob.account_id_hex.as_str()])
                .await
                .unwrap();
            peer.sync().await.unwrap();
            settle_peer_epoch(&mut fixture.client, &group).await;
            settle_peer_epoch(&mut peer, &group).await;
            let plaintext = format!("healthy peer {index} survives stalled route");
            let sent = peer.send(&group, plaintext.as_bytes()).await.unwrap();
            assert_eq!(sent.published, 1);
            let source = app
                .account_storage("bob")
                .unwrap()
                .app_storage()
                .timeline_message(&hex::encode(group.as_slice()), &sent.message_ids[0])
                .unwrap()
                .unwrap()
                .source_message_id_hex
                .unwrap();
            let original = fixture
                .relay
                .attempted_events()
                .into_iter()
                .find(|event| event.id == source)
                .expect("Bob's actual outer transport publication");
            let route = app
                .group("alice", &hex::encode(group.as_slice()))
                .unwrap()
                .unwrap()
                .nostr_routing
                .nostr_group_id_hex;
            let event = EventBuilder::new(Kind::MlsGroupMessage, original.content)
                .tags([Tag::custom("h", [route])])
                .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(
                    crate::unix_now_seconds() - 60 + index,
                ))
                .finalize(&Keys::generate())
                .unwrap();
            relay.add_event(event).await.unwrap();
            messages.push((
                hex::encode(group.as_slice()),
                sent.message_ids[0].clone(),
                plaintext,
            ));
        }
        let inbox_group = if matches!(
            pass,
            FairnessPass::RefillBoundary | FairnessPass::ExpiredFloor
        ) {
            // Boundary modes isolate refill or retained-floor settlement. A
            // new-group welcome changes their fence, covered by the other modes.
            None
        } else {
            let inbox_group = peer
                .create_group_with_options(
                    "real inbox recovery",
                    &[],
                    crate::AppCreateGroupOptions {
                        relays: Some(vec![proxy.url.clone()]),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            peer.invite_members(&inbox_group, &[alice.as_str()])
                .await
                .unwrap();
            let welcome = fixture
                .relay
                .attempted_events()
                .into_iter()
                .rev()
                .find(|event| {
                    event.kind == 1059
                        && event.tags.iter().any(|tag| {
                            tag.first().is_some_and(|key| key == "p") && tag.get(1) == Some(&alice)
                        })
                })
                .expect("Bob published Alice's real encrypted welcome");
            let welcome: nostr_sdk::prelude::Event =
                serde_json::from_value(serde_json::to_value(welcome).unwrap()).unwrap();
            relay.add_event(welcome).await.unwrap();
            Some(inbox_group)
        };
        let stalled = stalled_groups
            .iter()
            .map(|group| {
                let route = app
                    .group("alice", &hex::encode(group.as_slice()))
                    .unwrap()
                    .unwrap()
                    .nostr_routing
                    .nostr_group_id_hex;
                stalled_relay
                    .stalled_groups
                    .lock()
                    .unwrap()
                    .push(route.clone());
                TransportReconciliationRoute::Group(hex::decode(route).unwrap().try_into().unwrap())
            })
            .collect::<Vec<_>>();
        drop(peer);
        drop(fixture.client);
        let real_app = crate::MarmotApp::with_relay_and_config(
            fixture._dir.path(),
            proxy.url.clone(),
            crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
        );
        // Persist the actual inbox before opening Alice: a saved kind-10050
        // declaration takes precedence over the app's constructor default.
        real_app
            .set_account_inbox_relays(
                "alice",
                vec![cgka_traits::TransportEndpoint(proxy.url.clone())],
                vec![cgka_traits::TransportEndpoint(proxy.url.clone())],
            )
            .await
            .unwrap();
        fixture.client = client_on_app_relay_plane(&real_app, "alice").await;
        fixture.client.test_comparison_results = None;
        let intents = stalled_groups
            .iter()
            .map(|group| storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(group.as_slice()),
                stalled_epoch: fixture.client.group_mls_state(group).unwrap().epoch,
            })
            .collect::<Vec<_>>();
        fixture
            .storage
            .app_storage()
            .arm_epoch_backfill_intents(&intents)
            .unwrap();
        // Join once: a pending comparison revision must preserve goals outside
        // its first batch while the failed leader keeps its retry ID.
        let mut excluded_evidence = None;
        if pass == FairnessPass::Automatic {
            fixture.client.request_bounded_comparison().unwrap();
        } else if pass == FairnessPass::ExpiredFloor {
            fixture.client.request_bounded_comparison().unwrap();
            let storage = fixture.storage.app_storage();
            let history = storage
                .pending_recovery_demands()
                .unwrap()
                .into_iter()
                .find(|demand| demand.cause == storage_sqlite::RecoveryCause::IncrementalHistory)
                .expect("the comparison joined real incremental debt");
            let scopes = storage.recovery_scope_snapshots(history.ticket.id).unwrap();
            let joined = scopes
                .iter()
                .find(|scope| match stalled[0] {
                    TransportReconciliationRoute::Group(id) => {
                        scope.plan.transport_group_id == Some(id)
                    }
                    TransportReconciliationRoute::Inbox => scope.plan.route_kind == 0,
                })
                .expect("the joined debt includes the stalled route");
            // Move this route's real retained inventory past the already joined
            // window through the retention API. Joining an older goal instead
            // would not narrow pre-existing debt, whose bounds merge by max.
            let retention_at = joined.plan.until_seconds
                + storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS
                + 1;
            let inventory = storage
                .transport_reconciliation_inventory(&stalled[0], retention_at)
                .unwrap();
            assert!(
                inventory.since > joined.plan.until_seconds,
                "the actual durable floor must exceed the actual stored goal before execution"
            );
            let before = storage
                .recovery_scope_snapshots(history.ticket.id)
                .unwrap()
                .into_iter()
                .find(|scope| match stalled[0] {
                    TransportReconciliationRoute::Group(id) => {
                        scope.plan.transport_group_id == Some(id)
                    }
                    TransportReconciliationRoute::Inbox => scope.plan.route_kind == 0,
                })
                .unwrap();
            excluded_evidence = Some((
                before.quiet_passes,
                before.window_certified,
                before.checkpoints,
            ));
        } else {
            fixture
                .storage
                .app_storage()
                .request_recovery(
                    storage_sqlite::RecoveryRequest::ExplicitHistory {
                        operation_id: &[44; 16],
                    },
                    crate::unix_now_seconds() * 1000,
                )
                .unwrap();
        }
        let revision = fixture
            .storage
            .app_storage()
            .recovery_comparison()
            .unwrap()
            .revision;
        assert!(messages.iter().all(|(group, id, plaintext)| {
            !real_app.messages("alice").unwrap().iter().any(|message| {
                &message.group_id_hex == group
                    && &message.message_id_hex == id
                    && message.sender == bob.account_id_hex
                    && &message.plaintext == plaintext
            })
        }));
        if let Some(group) = &inbox_group {
            assert!(
                real_app
                    .group("alice", &hex::encode(group.as_slice()))
                    .unwrap()
                    .is_none()
            );
        }
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let mut recovered = false;
        let max_passes = match pass {
            FairnessPass::Automatic => 4,
            FairnessPass::Explicit => 2,
            FairnessPass::RefillBoundary => 1,
            FairnessPass::ExpiredFloor => 2,
        };
        for _ in 0..max_passes {
            fixture
                .client
                .recovery_owner
                .test_advance_to_retry(&fixture.storage);
            let mut permit = ExplicitRecoveryPermit::full_history();
            let grant = fixture
                .client
                .authorize_account_recovery(
                    matches!(pass, FairnessPass::Explicit | FairnessPass::RefillBoundary)
                        .then_some(&mut permit),
                    EpochBackfillExecutionSeam::Maintenance,
                )
                .await
                .unwrap()
                .expect("unserved history remains automatically selectable");
            if matches!(pass, FairnessPass::Automatic | FairnessPass::ExpiredFloor) {
                assert_eq!(
                    grant.comparison_revision,
                    Some(revision),
                    "the same comparison revision retries without a new request"
                );
            }
            if pass == FairnessPass::ExpiredFloor {
                let joined = grant
                    .plan()
                    .unwrap()
                    .iter()
                    .filter(|obligation| {
                        obligation.cause == storage_sqlite::RecoveryCause::IncrementalHistory
                    })
                    .flat_map(|obligation| &obligation.scopes)
                    .find(|scope| match stalled[0] {
                        TransportReconciliationRoute::Group(id) => {
                            scope.goal.transport_group_id == Some(id)
                        }
                        TransportReconciliationRoute::Inbox => scope.goal.route_kind == 0,
                    })
                    .expect("the frozen grant preserves excluded coverage debt");
                let floor = fixture
                    .client
                    .transport_receipts()
                    .unwrap()
                    .inventory(&stalled[0], joined.goal.until_seconds)
                    .unwrap()
                    .since;
                assert!(
                    floor > joined.goal.until_seconds,
                    "the real frozen goal must still be below its durable floor before I/O"
                );
                assert!(
                    grant
                        .comparison_plan
                        .as_ref()
                        .unwrap()
                        .routes
                        .iter()
                        .all(|scope| {
                            match stalled[0] {
                                TransportReconciliationRoute::Group(id) => {
                                    scope.transport_group_id != Some(id)
                                }
                                TransportReconciliationRoute::Inbox => scope.route_kind != 0,
                            }
                        }),
                    "a goal below its observed retained floor cannot keep operational retries alive"
                );
            } else {
                assert!(
                    stalled.contains(&grant.inventory.first().unwrap().route),
                    "the persistently armed group remains the actual scheduler's leader"
                );
            }
            if matches!(pass, FairnessPass::Automatic | FairnessPass::ExpiredFloor) {
                assert!(grant.inventory.len() <= TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS);
            } else {
                assert!(grant.inventory.len() > TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS);
                let claim = fixture
                    .storage
                    .app_storage()
                    .transport_reconciliation_route_cursor()
                    .unwrap()
                    .unwrap();
                assert!(
                    grant
                        .inventory
                        .iter()
                        .take(TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS)
                        .any(|item| item.route == claim),
                    "the pre-I/O claim cannot include the unstarted explicit tail"
                );
            }
            let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
            let control = FullHistoryRepairControl {
                started: Instant::now(),
                timeout: if pass == FairnessPass::RefillBoundary {
                    Duration::from_secs(8)
                } else {
                    FULL_HISTORY_REPAIR_TIMEOUT
                },
                cancelled: &|| false,
            };
            let deadline = match pass {
                FairnessPass::Automatic | FairnessPass::ExpiredFloor => {
                    ComparisonNetworkJob::automatic_deadline()
                }
                FairnessPass::Explicit | FairnessPass::RefillBoundary => control.network_deadline(),
            };
            let mut job = ComparisonNetworkJob::start(
                &fixture.client,
                &grant,
                capacity.clone().try_acquire_owned().unwrap(),
                deadline,
                None,
            )
            .unwrap();
            let (credit, network) = job.wait().await.unwrap();
            fixture
                .client
                .admit_comparison_inline(None, grant, execution, network)
                .await
                .unwrap();
            drop(credit);
            let projected = real_app.messages("alice").unwrap();
            recovered = messages.iter().all(|(group, id, plaintext)| {
                projected.iter().any(|message| {
                    &message.group_id_hex == group
                        && &message.message_id_hex == id
                        && message.sender == bob.account_id_hex
                        && &message.plaintext == plaintext
                })
            }) && inbox_group.as_ref().is_none_or(|group| {
                real_app
                    .group("alice", &hex::encode(group.as_slice()))
                    .unwrap()
                    .is_some()
            });
            let operational_complete = if pass == FairnessPass::ExpiredFloor {
                let comparison = fixture.storage.app_storage().recovery_comparison().unwrap();
                !comparison.pending()
            } else {
                true
            };
            if recovered && operational_complete {
                break;
            }
        }
        if pass != FairnessPass::ExpiredFloor {
            assert!(
                stalled_relay.stalled.load(Ordering::SeqCst) >= 2,
                "the armed relay stayed stalled across rotation passes"
            );
        }
        assert!(
            recovered,
            "all genuine Bob messages and his welcome arrive within {max_passes} passes"
        );
        if pass == FairnessPass::ExpiredFloor {
            let comparison = fixture.storage.app_storage().recovery_comparison().unwrap();
            let remaining = comparison.plan.as_ref().map(|plan| {
                plan.routes
                    .iter()
                    .filter(|scope| plan.retry_routes.contains(&scope.scope_id))
                    .map(|scope| {
                        (
                            scope.scope_id,
                            scope.route_kind,
                            scope.transport_group_id.map(hex::encode),
                        )
                    })
                    .collect::<Vec<_>>()
            });
            let planned_route_revision = comparison
                .plan
                .as_ref()
                .map(|plan| plan.fence.route_revision);
            let current_route_revision = fixture
                .storage
                .app_storage()
                .recovery_revision_fence()
                .unwrap()
                .route_revision;
            assert!(
                !comparison.pending(),
                "known unsearchable history cannot leave an endless operational retry: remaining={remaining:?}, planned_route_revision={planned_route_revision:?}, current_route_revision={current_route_revision}"
            );
            let history = fixture
                .storage
                .app_storage()
                .pending_recovery_demands()
                .unwrap()
                .into_iter()
                .find(|demand| demand.cause == storage_sqlite::RecoveryCause::IncrementalHistory)
                .expect("excluded history still has coverage debt");
            let scopes = fixture
                .storage
                .app_storage()
                .recovery_scope_snapshots(history.ticket.id)
                .unwrap();
            let old = scopes
                .iter()
                .find(|scope| match stalled[0] {
                    TransportReconciliationRoute::Group(id) => {
                        scope.plan.transport_group_id == Some(id)
                    }
                    TransportReconciliationRoute::Inbox => scope.plan.route_kind == 0,
                })
                .unwrap();
            assert!(
                !old.window_certified,
                "excluding an old window must not certify its history"
            );
            let (quiet_before, certified_before, checkpoints_before) = excluded_evidence.unwrap();
            assert_eq!(
                old.quiet_passes, quiet_before,
                "excluding a window must not change its quiet history"
            );
            assert_eq!(
                old.window_certified, certified_before,
                "excluding a window must not change its certificate evidence"
            );
            assert!(
                old.checkpoints == checkpoints_before,
                "excluding a window must not change its endpoint evidence"
            );
        }
        relay.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_route_keeps_peers() {
        recover_stalled_routes(FairnessPass::Automatic).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn explicit_stalls_rotate_peers() {
        recover_stalled_routes(FairnessPass::Explicit).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refill_reaches_peer_tail() {
        recover_stalled_routes(FairnessPass::RefillBoundary).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_floor_keeps_peer() {
        recover_stalled_routes(FairnessPass::ExpiredFloor).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_keeps_peer_prefix() {
        recover_peer_at_caller_cutoff(DeadlineFault::HeldFetch).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_keeps_gap_window() {
        recover_peer_at_caller_cutoff(DeadlineFault::PostReplyStall).await;
    }
    /// A large refused first ID spends the SDK's request budget on a prefix.
    /// A fresh SDK must resume from SQLite, not its previous set-aside cache,
    /// to batch the small IDs first and recover Bob's genuine MLS message.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::disallowed_methods)]
    async fn refused_prefix_reaches_peer() {
        use base64::Engine as _;
        use nostr_sdk::local_relay::LocalRelay;
        use nostr_sdk::prelude::Client as SdkClient;
        use transport_nostr_adapter::{NostrSdkRelayClient, NostrSubscription};

        let relay = LocalRelay::new();
        relay.run().await.unwrap();
        let url = relay.url().await.to_string();
        let mut fixture = fixture_with_group_relays(Some(vec![url.clone()])).await;
        let app = fixture.client.app.clone();
        let bob = crate::AccountHome::open(fixture._dir.path())
            .create_account("bob")
            .unwrap();
        crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
        let mut peer = client_on_app_relay_plane(&app, "bob").await;
        peer.sync().await.unwrap();
        fixture
            .client
            .invite_members(&fixture.group_id, &[bob.account_id_hex.as_str()])
            .await
            .unwrap();
        peer.sync().await.unwrap();
        assert!(peer.group_mls_state(&fixture.group_id).is_ok());
        let sent = peer
            .send(&fixture.group_id, b"peer beyond refused prefix")
            .await
            .unwrap();
        assert_eq!(sent.published, 1, "Bob's message reached the relay");
        // SendSummary names the inner app event. Its durable projection links
        // that authenticated event to the exact outer transport publication.
        let source = app
            .account_storage("bob")
            .unwrap()
            .app_storage()
            .timeline_message(
                &hex::encode(fixture.group_id.as_slice()),
                &sent.message_ids[0],
            )
            .unwrap()
            .expect("Bob projected his sent message")
            .source_message_id_hex
            .expect("the sent message has a published transport source");
        let peer_event = fixture
            .relay
            .attempted_events()
            .into_iter()
            .find(|event| event.id == source)
            .expect("the relay captured Bob's exact transport publication");
        let group_route = app
            .group("alice", &hex::encode(fixture.group_id.as_slice()))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex;
        let at = crate::unix_now_seconds() - 60;
        let owned = |event| transport_nostr_adapter::NostrRelayEvent {
            endpoint: cgka_traits::TransportEndpoint(url.clone()),
            subscription_id: None,
            event,
        };
        for row in 0..cgka_engine::message_processor::MAX_PEEL_DEFERRED_ROWS_PER_GROUP {
            let event = crate::tests::epoch_gap_probe(&group_route, at - 1, &format!("fill-{row}"));
            let deliveries = fixture
                .client
                .adapter
                .recovered_deliveries(owned(event))
                .await
                .unwrap();
            assert_eq!(deliveries.len(), 1);
            for delivery in deliveries {
                fixture
                    .client
                    .ingest_received_delivery(delivery)
                    .await
                    .unwrap();
            }
        }
        // Separate seconds make the completed refusal prefix a safe time
        // prefix. ID ranges fix the first pass's request order without relying
        // on random event IDs or SDK process-local acquisition hints.
        let signed_in = |content: String, created_at, range: std::ops::Range<u8>| loop {
            let event = EventBuilder::new(Kind::MlsGroupMessage, content.clone())
                .tags([Tag::custom("h", [group_route.clone()])])
                .custom_created_at(nostr_sdk::prelude::Timestamp::from_secs(created_at))
                .finalize(&Keys::generate())
                .unwrap();
            if range.contains(&event.id.to_bytes()[0]) {
                break event;
            }
        };
        let large = base64::engine::general_purpose::STANDARD.encode(vec![0; 675 * 1024]);
        let mut events = vec![signed_in(large, at, 0..32)];
        for index in 0..30 {
            let (time, range) = if index < 15 {
                (at, 32..128)
            } else {
                (at + 1, 128..224)
            };
            let content =
                crate::tests::epoch_gap_probe(&group_route, time, &format!("refused-{index}"))
                    .content;
            events.push(signed_in(content, time, range));
        }
        events.push(signed_in(peer_event.content, at + 1, 224..255));
        let ids = events.iter().map(|event| event.id).collect::<Vec<_>>();
        for event in events {
            relay.add_event(event).await.unwrap();
        }
        let route_id: [u8; 32] = hex::decode(&group_route).unwrap().try_into().unwrap();
        let route = TransportReconciliationRoute::Group(route_id);
        let group_id_hex = hex::encode(fixture.group_id.as_slice());
        let peer_messages = || {
            app.messages("alice")
                .unwrap()
                .into_iter()
                .filter(|message| {
                    message.group_id_hex == group_id_hex
                        && message.sender == bob.account_id_hex
                        && sent.message_ids.contains(&message.message_id_hex)
                        && message.plaintext == "peer beyond refused prefix"
                })
                .count()
        };
        assert_eq!(peer_messages(), 0, "the peer is missing before replay");
        for pass in 0..2 {
            if pass > 0 {
                fixture
                    .client
                    .recovery_owner
                    .test_advance_to_retry(&fixture.storage);
                fixture
                    .client
                    .recovery_owner
                    .test_advance_clock(Duration::from_secs(60));
            }
            if pass == 0 {
                fixture.client.request_bounded_comparison().unwrap();
            }
            let (grant, mut execution, selected, _) = group_route_grant(&mut fixture).await;
            assert_eq!(selected, route);
            let inventory = grant
                .inventory
                .iter()
                .find(|item| item.route == route)
                .unwrap();
            let initial_cursor = fixture
                .storage
                .app_storage()
                .transport_reconciliation_replay_cursor(&route)
                .unwrap();
            let progress = MemoryProgress {
                cursor: Mutex::new(initial_cursor),
            };
            // Both the SDK and progress object are new on each pass. Otherwise
            // set-aside memory could hide a missing durable cursor checkpoint.
            let sdk = NostrSdkRelayClient::new(SdkClient::builder().build());
            sdk.client().add_relay(url.as_str()).await.unwrap();
            sdk.client().connect().await;
            let result = sdk
                .reconcile_subscription(
                    NostrSubscription::Group {
                        account_id: fixture.client.runtime.session().self_id(),
                        group_id: fixture.group_id.clone(),
                        transport_group_id: route_id.to_vec(),
                        endpoints: vec![cgka_traits::TransportEndpoint(url.clone())],
                        since: None,
                        attempt: SubscriptionAttempt::INITIAL,
                    },
                    &inventory.items,
                    inventory.since,
                    inventory.until,
                    &progress,
                    tokio::time::Instant::now() + Duration::from_secs(20),
                )
                .await
                .unwrap();
            sdk.client().shutdown().await;
            let network = ComparisonNetworkResult {
                capture_error: None,
                routes: vec![ComparisonRouteResult {
                    route: route.clone(),
                    initial_cursor,
                    cursor: progress.load_cursor().unwrap(),
                    result: ComparisonRouteWorkResult::Returned(Ok(Some(result))),
                    window: Vec::new(),
                    window_progress: Vec::new(),
                }],
            };
            let mut admission = fixture
                .client
                .accept_comparison_network(&grant, &mut execution, network)
                .await
                .unwrap()
                .unwrap();
            while !fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap()
            {}
            assert!(
                !admission.routes[0].admitted,
                "refusals cannot certify coverage"
            );
            if pass == 0 {
                assert!(
                    admission.routes[0].answered,
                    "the relays answered despite local refusals"
                );
                assert_eq!(
                    execution.execution.counts.refused, 16,
                    "the real SDK exhausted its request budget on refusals"
                );
                assert_eq!(peer_messages(), 0, "the first pass reached only refusals");
                assert!(
                    ids.iter()
                        .all(|id| { !fixture.client.state.seen_events.contains(&id.to_hex()) })
                );
                let inventory = fixture
                    .storage
                    .app_storage()
                    .transport_reconciliation_inventory(&route, crate::unix_now_seconds())
                    .unwrap();
                assert!(
                    ids.iter().all(|id| !inventory
                        .items
                        .iter()
                        .any(|item| item.event_id == id.to_bytes())),
                    "refused IDs stay remote-only"
                );
            }
            fixture
                .client
                .finish_comparison_grant(grant, execution, Some(admission))
                .await
                .unwrap();
            if pass == 0 {
                let comparison = fixture.storage.app_storage().recovery_comparison().unwrap();
                assert!(
                    comparison.pending(),
                    "answered but unadmitted work retains automatic acquisition"
                );
                assert!(!comparison.plan.unwrap().retry_routes.is_empty());
            }
        }
        assert_eq!(
            peer_messages(),
            1,
            "a new SDK must reach the peer using only durable replay progress"
        );
        relay.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreadable_event_withholds_the_route_without_failing_the_batch() {
        let mut fixture = fixture().await;
        let (grant, execution, route, group_route) = group_route_grant(&mut fixture).await;
        let result = fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                execution,
                fetched(
                    route.clone(),
                    vec![
                        unreadable_for_route(group_route),
                        candidate_for_route(group_route),
                    ],
                ),
            )
            .await;
        assert!(
            matches!(result, Ok(EpochBackfillRunOutcome::Incomplete(_))),
            "one unreadable event must not fail the whole pass"
        );
        assert_eq!(
            fixture
                .storage
                .app_storage()
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32]),
            "an unreadable event finished its attempt, so the replay rotates past it"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn comparison_admits_owned_events_directly_without_the_delivery_queue() {
        let mut fixture = fixture().await;
        let (grant, execution, route, group_route) = group_route_grant(&mut fixture).await;
        let result = fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                execution,
                fetched(route.clone(), vec![candidate_for_route(group_route)]),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .app_storage()
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32]),
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                fixture.client.adapter.receive_account_delivery()
            )
            .await
            .is_err(),
            "nothing passed through the live delivery queue"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn comparison_admission_runs_in_bounded_turns() {
        let mut fixture = fixture().await;
        let (grant, mut execution, route, group_route) = group_route_grant(&mut fixture).await;
        let events = (0..MAX_COMPARISON_ADMISSION_PER_TURN + 1)
            .map(|_| candidate_for_route(group_route))
            .collect();
        let mut admission = fixture
            .client
            .accept_comparison_network(&grant, &mut execution, fetched(route, events))
            .await
            .unwrap()
            .expect("an unchanged grant owns its result");
        assert!(
            !fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap(),
            "one turn admits at most its bound, then yields"
        );
        assert_eq!(admission.pending.len(), 1);
        assert!(
            fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap()
        );
        fixture
            .client
            .finish_comparison_grant(grant, execution, Some(admission))
            .await
            .unwrap();
    }

    /// A newest window starts with history the device already holds. Those
    /// events must not spend the turn's admission slots, or the late commit
    /// behind them waits a turn while live input runs (mdk#2256).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn already_held_events_do_not_spend_a_turns_admission_slots() {
        let mut fixture = fixture().await;
        let (grant, mut execution, route, group_route) = group_route_grant(&mut fixture).await;
        let held = (0..MAX_COMPARISON_ADMISSION_PER_TURN)
            .map(|_| candidate_for_route(group_route))
            .collect::<Vec<_>>();
        let mut admission = fixture
            .client
            .accept_comparison_network(&grant, &mut execution, fetched(route, held.clone()))
            .await
            .unwrap()
            .expect("an unchanged grant owns its result");
        assert!(
            fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap()
        );
        let late = candidate_for_route(group_route);
        for event in held.into_iter().chain([late.clone()]) {
            let deliveries = fixture
                .client
                .adapter
                .recovered_deliveries(event)
                .await
                .unwrap();
            admission.pending.extend(
                deliveries
                    .into_iter()
                    .map(|delivery| (0, PendingSource::Window, delivery)),
            );
        }
        assert!(
            fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap(),
            "held events pass without spending the turn"
        );
        assert!(
            fixture
                .client
                .transport_receipts()
                .unwrap()
                .contains(&late.event.id)
        );
        fixture
            .client
            .finish_comparison_grant(grant, execution, Some(admission))
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn comparison_change_between_turns_keeps_the_prefix_and_certifies_nothing() {
        let mut fixture = fixture().await;
        let (grant, mut execution, route, group_route) = group_route_grant(&mut fixture).await;
        let events = (0..MAX_COMPARISON_ADMISSION_PER_TURN + 1)
            .map(|_| candidate_for_route(group_route))
            .collect();
        let mut admission = fixture
            .client
            .accept_comparison_network(&grant, &mut execution, fetched(route.clone(), events))
            .await
            .unwrap()
            .unwrap();
        fixture
            .client
            .admit_comparison_turn(&grant, &mut execution, &mut admission)
            .await
            .unwrap();
        // A newer join revises the comparison slot this grant froze.
        let goals = fixture
            .client
            .comparison_route_goals(unix_now_seconds())
            .unwrap();
        fixture
            .storage
            .app_storage()
            .join_recovery_comparison(
                &[9; 16],
                crate::client::recovery::wall_now_ms().unwrap(),
                &goals,
            )
            .unwrap();
        assert!(
            fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap()
        );
        assert!(admission.invalid);
        let result = fixture
            .client
            .finish_comparison_grant(grant, execution, Some(admission))
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .app_storage()
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            None,
            "an invalidated pass records no cursor progress"
        );
        assert!(
            fixture
                .storage
                .app_storage()
                .recovery_comparison()
                .unwrap()
                .pending()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unrouted_keeps_coverage_debt() {
        let mut fixture = fixture().await;
        let (grant, execution, route, _) = group_route_grant(&mut fixture).await;
        // This event routes to no route of the account, so it is not admitted.
        let result = fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                execution,
                fetched(route.clone(), vec![candidate()]),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Incomplete(_)));
        assert_eq!(
            fixture
                .storage
                .app_storage()
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32]),
            "an unrouted event finished its attempt, so the replay rotates past it"
        );
        // The relays answered; only admission fell short. That withholds the
        // certificate but services this route's operational acquisition. The
        // fixture returned no inbox result, so that unattempted scope retries
        // independently; global slot completion would falsely service it.
        let TransportReconciliationRoute::Group(group_route) = route else {
            panic!("the fixture compares a group route");
        };
        let comparison = fixture.storage.app_storage().recovery_comparison().unwrap();
        let plan = comparison.plan.unwrap();
        let group = plan
            .routes
            .iter()
            .find(|scope| scope.transport_group_id == Some(group_route))
            .expect("the operational plan includes the compared group");
        assert!(
            !plan.retry_routes.contains(&group.scope_id),
            "a definitive unrouted event does not retry this route's acquisition"
        );
        let inbox = plan
            .routes
            .iter()
            .find(|scope| scope.route_kind == 0)
            .expect("the operational plan includes the unattempted inbox");
        assert!(
            plan.retry_routes.contains(&inbox.scope_id),
            "the separate unattempted inbox still needs acquisition"
        );
        let history = fixture
            .storage
            .app_storage()
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|demand| demand.cause == storage_sqlite::RecoveryCause::IncrementalHistory)
            .expect("the comparison debt stays pending")
            .ticket
            .id;
        let scope = fixture
            .storage
            .app_storage()
            .recovery_scope_snapshots(history)
            .unwrap()
            .into_iter()
            .find(|scope| scope.plan.transport_group_id == Some(group_route))
            .expect("the group route has a scope");
        assert_eq!(scope.quiet_passes, 1);
        assert!(
            !scope.window_certified,
            "unrouted bytes cannot certify the group's window"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn comparison_partial_pass_rotates_cursor_and_keeps_retry_debt() {
        let mut fixture = fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
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
            .admit_comparison_inline(None, grant, attempt, network)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .storage
                .app_storage()
                .transport_reconciliation_replay_cursor(&route)
                .unwrap(),
            Some([8; 32])
        );
        let slot = fixture.storage.app_storage().recovery_comparison().unwrap();
        assert!(slot.pending());
        assert!(!slot.plan.unwrap().retry_routes.is_empty());
    }

    /// The comparison answer for every route: the group route's relay failed,
    /// or every relay answered.
    fn group_route_comparison(group_relay_failed: bool) -> ScriptedComparisons {
        ScriptedComparisons::by_route(move |route| {
            let failed =
                group_relay_failed && matches!(route, TransportReconciliationRoute::Group(_));
            Ok(Some((
                transport_nostr_adapter::NostrReconciliationSummary {
                    relays_succeeded: usize::from(!failed),
                    relays_failed: usize::from(failed),
                    failed_endpoints: if failed {
                        vec![cgka_traits::TransportEndpoint("wss://relay.example".into())]
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                },
                Vec::new(),
            )))
        })
    }

    /// Script the relay's answer to a window fetch: `event`, then EOSE.
    fn script_window(fixture: &Fixture, event: &transport_nostr_adapter::NostrRelayEvent) {
        script_window_ending(
            fixture,
            event,
            transport_nostr_adapter::NostrAcquisitionEnd::RequestPolicySatisfied,
        );
    }

    /// Script the relay's answer to a window fetch: `event`, then `end`.
    fn script_window_ending(
        fixture: &Fixture,
        event: &transport_nostr_adapter::NostrRelayEvent,
        end: transport_nostr_adapter::NostrAcquisitionEnd,
    ) {
        *fixture.relay.acquisition_result.lock().unwrap() =
            Some(transport_nostr_adapter::NostrAcquisitionResult {
                endpoints: vec![transport_nostr_adapter::NostrAcquisitionEndpoint {
                    endpoint: event.endpoint.clone(),
                    session_generation: None,
                    events: vec![event.event.clone()],
                    end,
                    stats: transport_nostr_adapter::NostrAcquisitionStats {
                        received_items: 1,
                        raw_received_items: 1,
                        oldest_raw_created_at: Some(event.event.created_at),
                        serialized_event_bytes: serde_json::to_vec(&event.event).unwrap().len(),
                        ..Default::default()
                    },
                }],
            });
    }

    /// Arm a gap for the fixture's group, with no earlier pass pacing it.
    fn arm_unpaced_epoch_gap(fixture: &Fixture) {
        let epoch = fixture
            .client
            .group_mls_state(&fixture.group_id)
            .unwrap()
            .epoch;
        fixture
            .storage
            .app_storage()
            .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(fixture.group_id.as_slice()),
                stalled_epoch: epoch,
            }])
            .unwrap();
    }

    async fn epoch_gap_grant(fixture: &mut Fixture) -> (AttemptGrant, [u8; 32]) {
        // These cases measure comparison fallback, not independent native
        // capture of a startup REQ whose scripted EOSE has not run yet.
        crate::tests::report_scripted_eose(
            &fixture.client.relay_plane,
            &fixture.relay,
            every_subscription,
        )
        .await;
        fixture.client.synchronize_native_replay().await.unwrap();
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        let group_route = grant
            .inventory
            .iter()
            .find_map(|item| match item.route {
                TransportReconciliationRoute::Group(id) => Some(id),
                TransportReconciliationRoute::Inbox => None,
            })
            .expect("the gap selects its group route");
        (grant, group_route)
    }

    /// mdk#2256: a commit first accepted long after it was wrapped keeps its
    /// wrap-time `created_at`, so it sits below every live `since` and only
    /// history recovery can find it. When a relay fails the epoch-gap route's
    /// comparison, the job fetches that relay's newest events for the route
    /// and admits them, without certifying the route.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_epoch_gap_route_a_relay_failed_to_compare_fetches_its_newest_window() {
        let mut fixture = fixture_with_group_relays_and_comparison(None, false).await;
        arm_unpaced_epoch_gap(&fixture);
        let (grant, group_route) = epoch_gap_grant(&mut fixture).await;
        let late = candidate_for_route(group_route);
        script_window(&fixture, &late);
        fixture.client.test_comparison_results = Some(group_route_comparison(true));

        let outcome = fixture
            .client
            .run_recovery_grant_for_test(grant)
            .await
            .unwrap();

        assert!(
            fixture
                .relay
                .acquisition_calls
                .load(std::sync::atomic::Ordering::SeqCst)
                > 0,
            "the failed relay is asked for the route's history window"
        );
        assert!(
            fixture
                .client
                .transport_receipts()
                .unwrap()
                .contains(&late.event.id),
            "the late event is admitted"
        );
        assert!(
            matches!(outcome, EpochBackfillRunOutcome::Incomplete(_)),
            "a window fetch certifies nothing"
        );
    }

    fn endpoint(name: &str) -> cgka_traits::TransportEndpoint {
        cgka_traits::TransportEndpoint(format!("wss://{name}.example"))
    }

    fn compared(
        summary: transport_nostr_adapter::NostrReconciliationSummary,
    ) -> ComparisonRouteWorkResult {
        ComparisonRouteWorkResult::Returned(Ok(Some((summary, Vec::new()))))
    }

    /// A relay that answered its comparison but left claimed IDs for a later
    /// pass is not a relay the window should replace: the comparison is
    /// fetching that backlog oldest first, and a newest page would skip its
    /// unfetched middle (#2086).
    #[test]
    fn a_relay_that_answered_its_comparison_is_not_window_fetched() {
        let relays = [endpoint("silent"), endpoint("partial")];
        let result = compared(transport_nostr_adapter::NostrReconciliationSummary {
            relays_failed: 2,
            failed_endpoints: relays.to_vec(),
            incomplete_endpoints: vec![endpoint("partial")],
            ..Default::default()
        });
        assert_eq!(
            result.uncompared_endpoints(&relays),
            vec![endpoint("silent")]
        );
    }

    /// While a compared relay still owes older history, the pass keeps its
    /// oldest-first boundary: no window fetch jumps past what it has not
    /// fetched yet.
    #[test]
    fn a_known_unfetched_backlog_holds_the_window_fetch() {
        let relays = [endpoint("healthy"), endpoint("silent")];
        for summary in [
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                relays_failed: 1,
                failed_endpoints: vec![endpoint("silent")],
                remote_items: 600,
                received_items: 256,
                ..Default::default()
            },
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_failed: 1,
                failed_endpoints: vec![endpoint("silent")],
                order_unproven: true,
                ..Default::default()
            },
        ] {
            assert!(compared(summary).uncompared_endpoints(&relays).is_empty());
        }
        let caught_up = compared(transport_nostr_adapter::NostrReconciliationSummary {
            relays_succeeded: 1,
            relays_failed: 1,
            failed_endpoints: vec![endpoint("silent")],
            remote_items: 7,
            received_items: 7,
            ..Default::default()
        });
        assert_eq!(
            caught_up.uncompared_endpoints(&relays),
            vec![endpoint("silent")]
        );
    }

    /// Relays send the newest page newest first, so a page the byte budget
    /// or the deadline cut holds only the newer events and leaves the late
    /// commit behind. Only a page the relay itself ended is admitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_window_page_the_relay_did_not_finish_is_not_admitted() {
        for end in [
            transport_nostr_adapter::NostrAcquisitionEnd::ByteLimitReached,
            transport_nostr_adapter::NostrAcquisitionEnd::Deadline,
            transport_nostr_adapter::NostrAcquisitionEnd::ItemLimitReached,
        ] {
            let mut fixture = fixture_with_group_relays_and_comparison(None, false).await;
            arm_unpaced_epoch_gap(&fixture);
            let (grant, group_route) = epoch_gap_grant(&mut fixture).await;
            let newer = candidate_for_route(group_route);
            script_window_ending(&fixture, &newer, end);
            fixture.client.test_comparison_results = Some(group_route_comparison(true));

            fixture
                .client
                .run_recovery_grant_for_test(grant)
                .await
                .unwrap();

            assert!(
                !fixture
                    .client
                    .transport_receipts()
                    .unwrap()
                    .contains(&newer.event.id),
                "a page cut short ({end:?}) admits nothing"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_epoch_gap_route_every_relay_compared_fetches_no_window() {
        let mut fixture = fixture_with_group_relays_and_comparison(None, false).await;
        arm_unpaced_epoch_gap(&fixture);
        let (grant, group_route) = epoch_gap_grant(&mut fixture).await;
        script_window(&fixture, &candidate_for_route(group_route));
        fixture.client.test_comparison_results = Some(group_route_comparison(false));

        fixture
            .client
            .run_recovery_grant_for_test(grant)
            .await
            .unwrap();

        assert_eq!(
            fixture
                .relay
                .acquisition_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_history_route_a_relay_failed_to_compare_fetches_no_window() {
        let mut fixture = fixture().await;
        let (grant, group_route) = epoch_gap_grant(&mut fixture).await;
        assert!(
            grant
                .plan()
                .unwrap()
                .iter()
                .all(|obligation| { obligation.cause != storage_sqlite::RecoveryCause::EpochGap }),
            "the fixture owes history, not an epoch gap"
        );
        script_window(&fixture, &candidate_for_route(group_route));
        fixture.client.test_comparison_results = Some(group_route_comparison(true));

        fixture
            .client
            .run_recovery_grant_for_test(grant)
            .await
            .unwrap();

        assert_eq!(
            fixture
                .relay
                .acquisition_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn comparison_pass_records_acquisition_counts_and_verdicts() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let (grant, execution, route, group_route) = group_route_grant(&mut fixture).await;
        let serial = grant.reservation.attempt_serial;
        let obligations = grant.fence.obligations.len();
        fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                execution,
                fetched(
                    route,
                    vec![
                        unreadable_for_route(group_route),
                        candidate_for_route(group_route),
                    ],
                ),
            )
            .await
            .unwrap();
        let app = fixture.client.app.clone();
        let started = recorded_v5_rows(&app, "recovery_attempt_started");
        assert_eq!(started.len(), 1);
        let started = &started[0]["event"];
        assert_eq!(started["attempt_serial"], serial);
        assert_eq!(started["scope"], "history");
        assert_eq!(
            started["route_cap"],
            TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS
        );
        assert_eq!(
            started["admission_per_turn"],
            MAX_COMPARISON_ADMISSION_PER_TURN
        );
        assert_eq!(
            started["quantum_ms"],
            TRANSPORT_RECONCILIATION_QUANTUM.as_millis() as u64
        );

        let finished = recorded_v5_rows(&app, "recovery_attempt_finished");
        assert_eq!(finished.len(), 1);
        let finished = &finished[0]["event"];
        assert_eq!(finished["attempt_serial"], serial);
        assert_eq!(finished["obligation_count"], obligations);
        assert_eq!(finished["events_retrieved"], 2, "both handed-over events");
        assert_eq!(finished["events_rejected"], 1, "the unreadable one");
        assert_eq!(finished["routes_compared"], 1);
        // An unadmitted event withholds the route's certificate.
        assert_eq!(finished["routes_certified"], 0);
        assert_eq!(finished["routes_uncertified"], 1);
        assert!(finished.get("error_kind").is_none());

        let reassessed = recorded_v5_rows(&app, "recovery_obligation_reassessed");
        assert_eq!(reassessed.len(), obligations);
        for row in &reassessed {
            assert_eq!(row["event"]["attempt_serial"], serial);
            assert_eq!(
                row["event"]["record_context"]["operation_ref"],
                finished["record_context"]["operation_ref"]
            );
            assert!(
                row["event"]["scopes_certified"].as_u64() <= row["event"]["scopes_total"].as_u64()
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_changed_before_admission_records_a_superseded_pass() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        let route = grant.inventory.first().unwrap().route.clone();
        let attempt = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        fixture.client.adapter.require_fresh_activation().await;
        fixture
            .client
            .runtime
            .activate_transport(None)
            .await
            .unwrap();
        let result = fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                attempt,
                fetched(route, vec![candidate(), candidate()]),
            )
            .await
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        let app = fixture.client.app.clone();
        let finished = recorded_v5_rows(&app, "recovery_attempt_finished");
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0]["event"]["outcome"], "superseded");
        // The relays answered before the grant was found changed: the row
        // reports that, although nothing was admitted or certified.
        assert_eq!(finished[0]["event"]["routes_compared"], 1);
        assert_eq!(finished[0]["event"]["events_retrieved"], 2);
        assert_eq!(finished[0]["event"]["events_retained"], 0);
        assert_eq!(finished[0]["event"]["routes_certified"], 0);
        assert!(
            recorded_v5_rows(&app, "recovery_obligation_reassessed").is_empty(),
            "a pass that settled nothing records no verdicts"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_abandoned_network_pass_records_a_cancelled_pass() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let (grant, execution, _, _) = group_route_grant(&mut fixture).await;
        let result = fixture
            .client
            .abandon_comparison_grant(grant, execution)
            .unwrap();
        assert!(matches!(result, EpochBackfillRunOutcome::Deferred));
        let app = fixture.client.app.clone();
        let finished = recorded_v5_rows(&app, "recovery_attempt_finished");
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0]["event"]["outcome"], "cancelled");
        assert_eq!(finished[0]["event"]["routes_compared"], 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repair_stopped_by_its_deadline_reports_what_it_fetched_and_retained() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let (grant, execution, route, group_route) = group_route_grant(&mut fixture).await;
        let serial = grant.reservation.attempt_serial;
        let events = (0..MAX_COMPARISON_ADMISSION_PER_TURN + 1)
            .map(|_| candidate_for_route(group_route))
            .collect();
        // The first turn runs inside the budget; the repair's budget is spent
        // before the second, which stops admission at that boundary.
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let cancelled = || {
            if checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                std::thread::sleep(Duration::from_millis(400));
            }
            false
        };
        let control = FullHistoryRepairControl {
            started: Instant::now(),
            timeout: Duration::from_millis(300),
            cancelled: &cancelled,
        };
        fixture
            .client
            .admit_comparison_until(
                grant,
                execution,
                fetched(route, events),
                Some(&control),
                None,
            )
            .await
            .unwrap();
        let app = fixture.client.app.clone();
        let finished = recorded_v5_rows(&app, "recovery_attempt_finished");
        assert_eq!(finished.len(), 1);
        let finished = &finished[0]["event"];
        assert_eq!(finished["attempt_serial"], serial);
        assert_eq!(finished["outcome"], "deadline");
        assert_eq!(
            finished["events_retrieved"],
            MAX_COMPARISON_ADMISSION_PER_TURN + 1,
            "the relays' answer is reported although settlement was skipped"
        );
        assert!(
            finished["events_retained"].as_u64().unwrap() >= 1,
            "the first turn's durable prefix is reported: {finished}"
        );
        assert_eq!(finished["routes_compared"], 1);
        assert_eq!(finished["routes_certified"], 0);
        assert!(
            recorded_v5_rows(&app, "recovery_obligation_reassessed").is_empty(),
            "an unsettled pass writes no verdicts"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pass_whose_routes_timed_out_is_unserved_not_quiet() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        let routes = grant
            .inventory
            .iter()
            .map(|inventory| ComparisonRouteResult {
                route: inventory.route.clone(),
                initial_cursor: None,
                window: Vec::new(),
                window_progress: Vec::new(),
                cursor: None,
                result: ComparisonRouteWorkResult::TimedOut,
            })
            .collect();
        let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                execution,
                ComparisonNetworkResult {
                    routes,
                    capture_error: None,
                },
            )
            .await
            .unwrap();
        let app = fixture.client.app.clone();
        let finished = recorded_v5_rows(&app, "recovery_attempt_finished");
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0]["event"]["outcome"], "unserved");
        assert_eq!(finished[0]["event"]["routes_certified"], 0);
        assert_eq!(finished[0]["event"]["events_retrieved"], 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deadline_cuts_keep_retrying() {
        let mut fixture = fixture().await;
        for pass in 0..14 {
            let grant = fixture
                .client
                .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
                .await
                .unwrap()
                .expect("deadline-cut debt remains selectable");
            assert!(
                grant.comparison_revision.is_some(),
                "unstarted comparison work must retry without another request"
            );
            let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
            let network = if pass % 2 == 0 {
                let credit = Arc::new(tokio::sync::Semaphore::new(1))
                    .acquire_owned()
                    .await
                    .unwrap();
                let mut job = ComparisonNetworkJob::start(
                    &fixture.client,
                    &grant,
                    credit,
                    tokio::time::Instant::now(),
                    None,
                )
                .unwrap();
                let (_credit, network) = job.wait().await.unwrap();
                network
            } else {
                ComparisonNetworkResult {
                    routes: grant
                        .inventory
                        .iter()
                        .map(|inventory| ComparisonRouteResult {
                            route: inventory.route.clone(),
                            initial_cursor: None,
                            window: Vec::new(),
                            window_progress: Vec::new(),
                            cursor: None,
                            result: ComparisonRouteWorkResult::TimedOut,
                        })
                        .collect(),
                    capture_error: None,
                }
            };
            fixture
                .client
                .admit_comparison_inline(None, grant, execution, network)
                .await
                .unwrap();
            let comparison = fixture.storage.app_storage().recovery_comparison().unwrap();
            assert!(comparison.pending(), "a skipped route was never serviced");
            assert!(!comparison.plan.unwrap().retry_routes.is_empty());
            assert!(
                fixture
                    .storage
                    .app_storage()
                    .pending_recovery_demands()
                    .unwrap()
                    .iter()
                    .all(|demand| {
                        demand.eligibility == storage_sqlite::RecoveryEligibility::Retry
                    })
            );
            fixture
                .client
                .recovery_owner
                .test_advance_to_retry(&fixture.storage);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_comparison_only_pass_without_a_backend_is_unserved_not_quiet() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = fixture_with_options(None, false, true).await;
        // Settle the create-group history demand, as the epoch-gap fixture
        // does, so the next grant owns only the comparison slot.
        let baseline = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        fixture
            .client
            .run_recovery_grant_for_test(baseline)
            .await
            .unwrap();
        fixture.client.request_bounded_comparison().unwrap();
        fixture
            .client
            .recovery_owner
            .test_advance_to_retry(&fixture.storage);
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .expect("the comparison slot is selected");
        assert!(
            grant.fence.obligations.is_empty(),
            "a comparison-only grant"
        );
        assert!(grant.comparison_revision.is_some());
        let serial = grant.reservation.attempt_serial;
        let routes = grant
            .inventory
            .iter()
            .map(|inventory| ComparisonRouteResult {
                route: inventory.route.clone(),
                initial_cursor: None,
                window: Vec::new(),
                window_progress: Vec::new(),
                cursor: None,
                // No comparison backend: no relay comparison ran.
                result: ComparisonRouteWorkResult::Returned(Ok(None)),
            })
            .collect();
        let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                execution,
                ComparisonNetworkResult {
                    routes,
                    capture_error: None,
                },
            )
            .await
            .unwrap();
        let finished = recorded_v5_rows(&fixture.client.app.clone(), "recovery_attempt_finished")
            .into_iter()
            .find(|row| row["event"]["attempt_serial"] == serial)
            .expect("the comparison-only pass finished");
        assert_eq!(finished["event"]["obligation_count"], 0);
        assert_eq!(finished["event"]["outcome"], "unserved");
        assert_eq!(finished["event"]["routes_certified"], 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_obligation_compared_without_a_backend_is_unserved_and_spends_no_budget() {
        use crate::client::audit_recovery::recorded_v5_rows;
        let mut fixture = audited_fixture().await;
        let grant = fixture
            .client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .await
            .unwrap()
            .unwrap();
        let serial = grant.reservation.attempt_serial;
        let routes = grant
            .inventory
            .iter()
            .map(|inventory| ComparisonRouteResult {
                route: inventory.route.clone(),
                initial_cursor: None,
                window: Vec::new(),
                window_progress: Vec::new(),
                cursor: None,
                // No comparison backend: no relay comparison ran.
                result: ComparisonRouteWorkResult::Returned(Ok(None)),
            })
            .collect();
        let execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        fixture
            .client
            .admit_comparison_inline(
                None,
                grant,
                execution,
                ComparisonNetworkResult {
                    routes,
                    capture_error: None,
                },
            )
            .await
            .unwrap();
        let app = fixture.client.app.clone();
        let incremental = recorded_v5_rows(&app, "recovery_obligation_reassessed")
            .into_iter()
            .find(|row| {
                row["event"]["attempt_serial"] == serial
                    && row["event"]["cause"] == "incremental_history"
            })
            .expect("the startup history obligation is reassessed");
        // Storage waits for a capability change, and a pass no relay
        // answered spends none of the parking budget.
        assert_eq!(incremental["event"]["verdict"], "waiting_capability");
        assert_eq!(incremental["event"]["progress"], "unserved");
        assert_eq!(
            incremental["event"]["quiet_passes"], 0,
            "no quiet pass was counted for an uncompared scope"
        );
        let finished = recorded_v5_rows(&app, "recovery_attempt_finished")
            .into_iter()
            .find(|row| row["event"]["attempt_serial"] == serial)
            .unwrap();
        assert_eq!(finished["event"]["outcome"], "unserved");
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refusal_keeps_peer_frontier() {
        check_refused_window_frontier(PendingSource::Window).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dedup_refusal_keeps_frontier() {
        check_refused_window_frontier(PendingSource::Comparison).await;
    }

    async fn check_refused_window_frontier(source: PendingSource) {
        let shared = source == PendingSource::Comparison;
        let mut fixture = fixture_with_group_relays_and_comparison(None, false).await;
        let route_id: [u8; 32] = hex::decode(
            fixture
                .client
                .app
                .group("alice", &hex::encode(fixture.group_id.as_slice()))
                .unwrap()
                .unwrap()
                .nostr_routing
                .nostr_group_id_hex,
        )
        .unwrap()
        .try_into()
        .unwrap();
        let owned = |event| transport_nostr_adapter::NostrRelayEvent {
            endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
            subscription_id: None,
            event,
        };
        let at = crate::unix_now_seconds() - 60;
        for index in 0..cgka_engine::message_processor::MAX_PEEL_DEFERRED_ROWS_PER_GROUP {
            let event = owned(crate::tests::epoch_gap_probe(
                &hex::encode(route_id),
                at,
                &format!("cap-{index}"),
            ));
            for delivery in fixture
                .client
                .adapter
                .recovered_deliveries(event)
                .await
                .unwrap()
            {
                fixture
                    .client
                    .ingest_received_delivery(delivery)
                    .await
                    .unwrap();
            }
        }
        arm_unpaced_epoch_gap(&fixture);
        let (grant, _) = epoch_gap_grant(&mut fixture).await;
        let until = grant
            .inventory
            .iter()
            .find(|inventory| inventory.route == TransportReconciliationRoute::Group(route_id))
            .unwrap()
            .until;
        let refused = owned(crate::tests::epoch_gap_probe(
            &hex::encode(route_id),
            until - 1,
            "refused",
        ));
        script_window(&fixture, &refused);
        fixture.client.test_comparison_results = Some(group_route_comparison(true));
        let mut execution = fixture.client.begin_comparison_grant(&grant).await.unwrap();
        let credit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        let mut job = ComparisonNetworkJob::start(
            &fixture.client,
            &grant,
            credit,
            ComparisonNetworkJob::automatic_deadline(),
            None,
        )
        .unwrap();
        let (_credit, mut network) = job.wait().await.unwrap();
        let route = network
            .routes
            .iter_mut()
            .find(|route| route.route == TransportReconciliationRoute::Group(route_id))
            .unwrap();
        assert!(
            route
                .window
                .iter()
                .any(|event| event.event.id == refused.event.id)
        );
        if shared {
            route.result = ComparisonRouteWorkResult::Returned(Ok(Some((
                transport_nostr_adapter::NostrReconciliationSummary {
                    relays_succeeded: 1,
                    received_items: 1,
                    remote_items: 1,
                    ..Default::default()
                },
                vec![refused.clone()],
            ))));
            route.cursor = Some([9; 32]);
        }
        let mut admission = fixture
            .client
            .accept_comparison_network(&grant, &mut execution, network)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            admission.pending.len(),
            1,
            "comparison/window duplicates are attempted once"
        );
        assert_eq!(admission.pending[0].1, source);
        assert!(
            fixture
                .client
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap()
        );
        assert_eq!(
            execution.execution.counts.refused, 1,
            "the real deferred-row cap refused admission"
        );
        let index = admission
            .routes
            .iter()
            .position(|route| route.route == TransportReconciliationRoute::Group(route_id))
            .unwrap();
        let mut refused_id = [0; 32];
        hex::decode_to_slice(&refused.event.id, &mut refused_id).unwrap();
        assert!(
            admission.routes[index]
                .window_progress
                .iter()
                .any(|observation| { observation.offered.contains_key(&refused_id) }),
            "deduplication cannot forget which peer still owns the refused range"
        );
        if shared {
            assert_eq!(admission.routes[index].remaining, Some(0));
        }
        fixture
            .client
            .finish_comparison_grant(grant, execution, Some(admission))
            .await
            .unwrap();
        assert!(
            fixture
                .client
                .epoch_gap_windows
                .lock()
                .unwrap()
                .entries
                .is_empty(),
            "capacity refusal must refetch this peer's range, not checkpoint beyond it"
        );
        if shared {
            assert_eq!(
                fixture
                    .storage
                    .app_storage()
                    .transport_reconciliation_replay_cursor(&TransportReconciliationRoute::Group(
                        route_id
                    ),)
                    .unwrap(),
                Some([9; 32]),
                "completed comparison attempts retain master's replay rotation"
            );
        }
        assert!(
            !fixture
                .storage
                .app_storage()
                .pending_recovery_demands()
                .unwrap()
                .iter()
                .any(|demand| demand.cause == storage_sqlite::RecoveryCause::KnownEvent)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn waiting_gap_keeps_frontier() {
        let mut fixture = fixture_with_group_relays_and_comparison(None, false).await;
        let other = fixture
            .client
            .create_group("unrelated gap", &[])
            .await
            .unwrap();
        arm_unpaced_epoch_gap(&fixture);
        let (grant, _) = epoch_gap_grant(&mut fixture).await;
        let route = grant
            .plan()
            .unwrap()
            .iter()
            .find(|obligation| obligation.cause == storage_sqlite::RecoveryCause::EpochGap)
            .unwrap()
            .scopes
            .iter()
            .find_map(|scope| scope.goal.transport_group_id)
            .unwrap();
        let goal = fixture
            .storage
            .app_storage()
            .pending_recovery_demands()
            .unwrap()
            .into_iter()
            .find(|demand| demand.cause == storage_sqlite::RecoveryCause::EpochGap)
            .unwrap()
            .ticket;
        let start = crate::unix_now_seconds() - 1_000;
        let body = "old".repeat(3_000);
        let history = (0..512)
            .map(|index| crate::tests::epoch_gap_probe(&hex::encode(route), start + index, &body))
            .collect::<Vec<_>>();
        let oldest = history[0].id.clone();
        script_window(
            &fixture,
            &transport_nostr_adapter::NostrRelayEvent {
                endpoint: endpoint("relay"),
                subscription_id: None,
                event: history[0].clone(),
            },
        );
        fixture
            .relay
            .acquisition_result
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .endpoints[0]
            .events = history;
        fixture.client.test_comparison_results = Some(group_route_comparison(true));
        fixture
            .client
            .run_recovery_grant_for_test(grant)
            .await
            .unwrap();
        assert!(
            !fixture
                .client
                .transport_receipts()
                .unwrap()
                .contains(&oldest)
        );
        let key = (route, endpoint("relay").0);
        let before = fixture.client.epoch_gap_windows.lock().unwrap().entries[&key]
            .bounds
            .clone();
        assert!(
            !before.is_empty(),
            "the byte-limited scan needs another pass"
        );
        assert!(
            before.iter().any(|bound| bound.until < start + 511),
            "the first scan must advance below the newest raw page"
        );

        let epoch = fixture
            .client
            .group_mls_state(&fixture.group_id)
            .unwrap()
            .epoch;
        let due = fixture
            .storage
            .app_storage()
            .recovery_retry_state()
            .unwrap()
            .not_before_ms;
        fixture
            .storage
            .app_storage()
            .record_recovery_capacity_pressure(fixture.group_id.as_slice(), epoch, due)
            .unwrap();
        fixture
            .storage
            .app_storage()
            .arm_epoch_backfill_intents(&[storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(other.as_slice()),
                stalled_epoch: fixture.client.group_mls_state(&other).unwrap().epoch,
            }])
            .unwrap();
        fixture
            .client
            .recovery_owner
            .test_advance_to_retry(&fixture.storage);
        let (grant, _) = epoch_gap_grant(&mut fixture).await;
        assert!(!grant.fence.obligations.contains(&(goal.id, goal.revision)));
        fixture
            .client
            .run_recovery_grant_for_test(grant)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .client
                .epoch_gap_windows
                .lock()
                .unwrap()
                .entries
                .get(&key)
                .map(|hint| hint
                    .bounds
                    .iter()
                    .map(|bound| (bound.until, bound.resume_since))
                    .collect::<Vec<_>>()),
            Some(
                before
                    .iter()
                    .map(|bound| (bound.until, bound.resume_since))
                    .collect()
            ),
            "an unrelated grant must not erase a waiting ticket's frontier",
        );

        fixture
            .client
            .recovery_owner
            .test_advance_to_retry(&fixture.storage);
        fixture
            .client
            .recovery_owner
            .test_advance_clock(Duration::from_secs(60));
        let (grant, _) = epoch_gap_grant(&mut fixture).await;
        assert!(grant.fence.obligations.contains(&(goal.id, goal.revision)));
        fixture
            .client
            .run_recovery_grant_for_test(grant)
            .await
            .unwrap();
        assert!(
            fixture
                .client
                .transport_receipts()
                .unwrap()
                .contains(&oldest),
            "capacity relief must resume below the saved frontier and reach the oldest input"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reopened_scans_exhaust_budget() {
        let mut fixture = fixture_with_group_relays_and_comparison(None, false).await;
        arm_test_epoch_gap(&mut fixture).await;
        let app = fixture.client.app.clone();
        let route_id: [u8; 32] = hex::decode(
            app.group("alice", &hex::encode(fixture.group_id.as_slice()))
                .unwrap()
                .unwrap()
                .nostr_routing
                .nostr_group_id_hex,
        )
        .unwrap()
        .try_into()
        .unwrap();
        let marker = "held".repeat(1_400);
        let start = crate::unix_now_seconds() - 2_000;
        let mut history = Vec::with_capacity(1_024);
        for index in 0..1_024 {
            let event = transport_nostr_adapter::NostrRelayEvent {
                endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                subscription_id: None,
                event: crate::tests::epoch_gap_probe(
                    &hex::encode(route_id),
                    start + index,
                    &marker,
                ),
            };
            for delivery in fixture
                .client
                .adapter
                .recovered_deliveries(event.clone())
                .await
                .unwrap()
            {
                fixture
                    .client
                    .ingest_received_delivery(delivery)
                    .await
                    .unwrap();
            }
            history.push(event);
        }
        assert!(
            history
                .iter()
                .map(|event| serde_json::to_vec(&event.event).unwrap().len())
                .sum::<usize>()
                > EPOCH_GAP_WINDOW_MAX_BYTES_PER_RELAY,
            "each session must need multiple scan passes"
        );
        fixture
            .client
            .save_state_with_pending_local_group_deletion_frontier_clears()
            .unwrap();
        script_window(&fixture, &history[0]);
        fixture
            .relay
            .acquisition_result
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .endpoints[0]
            .events = history.into_iter().map(|event| event.event).collect();
        let durable = fixture.storage.clone();
        let gap = || {
            durable
                .app_storage()
                .pending_recovery_demands()
                .unwrap()
                .into_iter()
                .find(|demand| demand.cause == storage_sqlite::RecoveryCause::EpochGap)
                .expect("the unresolved gap keeps its durable demand")
        };
        let goal = gap().ticket;
        for pass in 1..=6 {
            // Two passes per session reproduce the old credit hole: the first
            // creates a hint; the second advances it through already-held data.
            if pass % 2 == 1 {
                drop(fixture.client);
                fixture.client = client_on_app_relay_plane(&app, "alice").await;
                assert!(
                    fixture
                        .client
                        .epoch_gap_windows
                        .lock()
                        .unwrap()
                        .entries
                        .is_empty()
                );
            } else {
                assert!(
                    fixture
                        .client
                        .epoch_gap_windows
                        .lock()
                        .unwrap()
                        .entries
                        .values()
                        .any(|hint| !hint.bounds.is_empty()),
                    "the first scan remains unfinished"
                );
            }
            fixture
                .client
                .recovery_owner
                .test_advance_to_retry(&fixture.storage);
            fixture
                .client
                .recovery_owner
                .test_advance_clock(Duration::from_secs(60));
            let (grant, _) = epoch_gap_grant(&mut fixture).await;
            fixture.client.test_comparison_results = Some(group_route_comparison(true));
            fixture
                .client
                .run_recovery_grant_for_test(grant)
                .await
                .unwrap();
            assert!(gap().ticket == goal);
            assert_eq!(
                gap().eligibility,
                if pass == 6 {
                    storage_sqlite::RecoveryEligibility::NeedsDeepRepair
                } else {
                    storage_sqlite::RecoveryEligibility::Retry
                },
                "held-only pass {pass}"
            );
        }
        drop(fixture.client);
        fixture.client = client_on_app_relay_plane(&app, "alice").await;
        assert_eq!(
            gap().eligibility,
            storage_sqlite::RecoveryEligibility::NeedsDeepRepair,
            "reopening cannot erase the six persisted unserved passes"
        );
    }

    /// A real admission repairs retained projection work before a later grant
    /// failure. Both the worker and inline checkpoint must deliver that prefix.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_comparison_retains_repaired_admission_prefix() {
        for checkpoint in [false, true] {
            let mut fixture = fixture().await;
            let app = fixture.client.app.clone();
            let connection =
                super::super::runtime_group_subscription_refresh_tests::projection_fault_connection(
                    &app,
                );
            connection.execute_batch("CREATE TRIGGER fail_repaired_activity BEFORE INSERT ON app_events WHEN NEW.kind = 1210 BEGIN SELECT RAISE(FAIL, 'injected activity'); END;").unwrap();
            let effects = marmot_account::AccountDeviceEffects {
                events: vec![cgka_traits::engine::GroupEvent::GroupStateChanged {
                    group_id: fixture.group_id.clone(),
                    epoch: cgka_traits::EpochId(1),
                    actor: Some(fixture.client.runtime.session().self_id()),
                    change: cgka_traits::engine::GroupStateChange::GroupRenamed {
                        name: "admitted repair".into(),
                        previous_name: None,
                    },
                    origin_commit_id: None,
                }],
                ..Default::default()
            };
            assert!(
                fixture
                    .client
                    .observe_drained_session_events(&effects)
                    .await
                    .is_err()
            );
            connection
                .execute_batch("DROP TRIGGER fail_repaired_activity")
                .unwrap();
            let (grant, mut execution, route, group_route) = group_route_grant(&mut fixture).await;
            let candidates = (0..MAX_COMPARISON_ADMISSION_PER_TURN + 1)
                .map(|_| candidate_for_route(group_route))
                .collect();
            let mut admission = fixture
                .client
                .accept_comparison_network(&grant, &mut execution, fetched(route, candidates))
                .await
                .unwrap()
                .unwrap();
            assert!(
                !fixture
                    .client
                    .admit_comparison_turn(&grant, &mut execution, &mut admission)
                    .await
                    .unwrap()
            );
            assert_eq!(admission.summary.projection_updates.len(), 1);
            if checkpoint {
                fixture
                    .client
                    .admit_comparison_turn(&grant, &mut execution, &mut admission)
                    .await
                    .unwrap();
                connection.execute_batch("CREATE TRIGGER fail_repair_cursor BEFORE UPDATE OF replay_after ON transport_reconciliation_route_state BEGIN SELECT RAISE(FAIL, 'injected cursor'); END;").unwrap();
                assert!(
                    fixture
                        .client
                        .finish_comparison_grant(grant, execution, Some(admission))
                        .await
                        .is_err()
                );
            } else {
                fixture.client.released_backfill_reload_pending = true;
                fixture.client.fail_next_released_backfill_reload = true;
                let error = fixture
                    .client
                    .admit_comparison_turn(&grant, &mut execution, &mut admission)
                    .await
                    .unwrap_err();
                fixture
                    .client
                    .fail_comparison_grant(grant, execution, Some(&mut admission), error);
                assert!(admission.summary.projection_updates.is_empty());
            }
            assert_eq!(
                std::mem::take(&mut fixture.client.pending_failed_sync_summary)
                    .projection_updates
                    .len(),
                1
            );
            assert!(
                std::mem::take(&mut fixture.client.pending_failed_sync_summary)
                    .projection_updates
                    .is_empty()
            );
        }
    }
}
