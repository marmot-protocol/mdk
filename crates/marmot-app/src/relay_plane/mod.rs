use std::collections::{BTreeMap, HashMap, HashSet};
use std::pin::Pin;
use std::sync::{
    Arc, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cgka_traits::transport::Timestamp;
use cgka_traits::{
    MemberId, MessageId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportDelivery, TransportDeliveryPlane, TransportEndpoint, TransportGroupSubscription,
    TransportGroupSync, TransportPublishReport, TransportPublishRequest,
};
use futures::{Stream, StreamExt};
use nostr_sdk::NotificationUpdate;
use nostr_sdk::prelude::{
    Client as NostrSdkClient, ClientNotification, Filter, Kind, PublicKey, RelayMessage, RelayUrl,
    SubscriptionId, Timestamp as NostrTimestamp,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use transport_nostr_adapter::{
    AccountSubscriptionEose, NostrAcquisitionCancellation, NostrAcquisitionError,
    NostrAcquisitionRequest, NostrAcquisitionResult, NostrNotificationLossFloor,
    NostrPublishOutcome, NostrReconciliationItem, NostrReconciliationSummary, NostrRelayClient,
    NostrSdkRelayClient, NostrSdkRelayHealth, NostrSubscription, NostrTransportAdapter,
    NotificationLagMark, RelayExportConsent, RelayLabelResolution, RelayRegistrationOutcome,
    SubscriptionAttempt,
};

use crate::config::RelayTelemetryExportConfig;
use transport_nostr_peeler::NostrTransportEvent;

use crate::directory::DirectorySyncPlan;

mod delivery_spill;
mod directory;
#[cfg(test)]
pub(crate) mod publish_accounting_tests;
mod safety;
mod telemetry;

pub use safety::{RelayEndpointClassification, RelayEndpointPolicy, retired_relay_hosts};
pub use telemetry::{
    EngineReorgMetrics, RelayRollupEntry, RelayTelemetryRollup, RelayTelemetrySnapshot,
};

pub(crate) use delivery_spill::{ACCOUNT_DELIVERY_SPILL_LIMITS, AccountDeliverySpillStore};
pub(crate) use directory::{
    DirectoryEventQuery, DirectoryFetchOutcome, DirectoryFetchRequest, DirectoryInspectionError,
    DirectoryRelayEventRecord, DirectoryRelayFetcher, DirectoryRelayPlane, DirectoryRelayStats,
    DirectorySubscriptionFilter, DirectorySubscriptionSyncSummary, NostrSdkDirectoryRelayFetcher,
};
pub(crate) use safety::{RelaySafetyPolicy, recovery_required_endpoints, same_relay};
pub(crate) use telemetry::rollup_from_snapshots;

// Re-exported so the in-tree `tests` module (which uses `super::*`) keeps
// reaching these names unchanged after the split moved their only non-test
// uses into the submodules above.
#[cfg(test)]
pub(crate) use cgka_traits::TransportPublishTarget;
#[cfg(test)]
pub(crate) use transport_nostr_adapter::{
    DurationHistogramSnapshot, NostrAdapterMetrics, RelayDeliverySpread, RelaySyncSnapshot,
};

pub(crate) const ACCOUNT_DELIVERY_BUFFER: usize = 1024;
const DIRECTORY_EVENT_BUFFER: usize = 1024;
pub(crate) const DIRECTORY_RELAY_CONNECT_WAIT: Duration = Duration::from_secs(5);
const RELAY_PLANE_SHUTDOWN_WAIT: Duration = Duration::from_secs(2);
const RELAY_PLANE_TASK_ABORT_WAIT: Duration = Duration::from_millis(250);
const RELAY_NOTIFICATION_RESTART_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const RELAY_NOTIFICATION_RESTART_MAX_BACKOFF: Duration = Duration::from_secs(30);
const RELAY_NOTIFICATION_RESTART_HEALTHY_RUNTIME: Duration = Duration::from_secs(5);
/// Notifications a relay consumer may queue for its event worker before the
/// backlog counts as receiver loss. A catch-up rebuild replays every stored
/// event inside the lookback window as a raw relay copy, plus a deduplicated
/// delivery for events the SDK client has not seen, so ordinary catch-ups
/// queue far more than a few hundred. Loss keeps the account route open but
/// costs a comparison recovery pass, because the SDK client has already marked
/// the lost events seen and will not deliver them again. Match the pinned SDK
/// client's per-receiver notification buffer, which bounded the inline
/// consumer this queue replaced.
const RELAY_NOTIFICATION_EVENT_QUEUE_CAPACITY: usize = 4096;
/// How long a relay notification receiver must run without another lag
/// before the REQs whose end-of-stored-events a lag may have lost are
/// re-issued. A re-issue restarts the relay's replay of that REQ, so it waits
/// out the burst that caused the lag. Under sustained overload lags recur
/// within seconds, and re-issuing at each one would keep restarting replays
/// that are still arriving. Waiting costs little: until the repair, the next
/// activation re-subscribes, as it did before the repair existed.
const NOTIFICATION_LAG_EOSE_REPAIR_SETTLE: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct MarmotRelayPlane {
    inner: Arc<MarmotRelayPlaneInner>,
}

struct MarmotRelayPlaneInner {
    subscription_rebuild_lookback: Option<Duration>,
    relay_safety: RelaySafetyPolicy,
    transport: Arc<RelayPlaneTransport>,
    directory: DirectoryRelayPlane,
    directory_subscription_sync: Mutex<()>,
}

struct RelayPlaneTransport {
    adapter: NostrTransportAdapter,
    sdk_relay_client: Option<NostrSdkRelayClient>,
    directory_client: Option<NostrSdkClient>,
    directory_events: broadcast::Sender<DirectoryRelayPlaneEvent>,
    account_deliveries: RwLock<HashMap<MemberId, AccountDeliveryRoute>>,
    /// Each account's overflow coordination, kept for the process lifetime. A
    /// spill writer can outlive its route; every later adapter for the account
    /// shares its fence, wakeup and pending loss instead of starting fresh.
    account_overflow_states: std::sync::Mutex<HashMap<MemberId, Arc<AccountDeliveryOverflowState>>>,
    account_delivery_metrics: Arc<AccountDeliveryMetrics>,
    router: Mutex<Option<JoinHandle<()>>>,
    notification_forwarder: Mutex<Option<JoinHandle<()>>>,
    account_notification_forwarders: Mutex<HashMap<MemberId, JoinHandle<()>>>,
    directory_notification_forwarder: Mutex<Option<JoinHandle<()>>>,
    notification_forwarder_health: Arc<RelayNotificationForwarderHealth>,
    /// Lag-lost EOSE repairs waiting for their receiver to settle, one per
    /// receiver scope: an account, or `None` for a receiver shared across
    /// accounts. A later lag in the same scope postpones the repair.
    eose_repairs: std::sync::Mutex<HashMap<Option<MemberId>, EoseRepairSchedule>>,
    /// [`NOTIFICATION_LAG_EOSE_REPAIR_SETTLE`] in milliseconds; tests shorten
    /// it.
    eose_repair_settle_ms: AtomicU64,
    shutting_down: AtomicBool,
}

/// A lag-lost EOSE repair waiting for its receiver to settle.
struct EoseRepairSchedule {
    /// When the repair may run, unless a later lag postpones it.
    due: tokio::time::Instant,
    /// The latest lag: only REQs issued by then are re-issued.
    lag: NotificationLagMark,
}

#[derive(Clone, Debug)]
pub(crate) enum DirectoryRelayPlaneEvent {
    Record(DirectoryRelayEventRecord),
    RecoveryRequired,
}

#[derive(Default)]
struct RelayNotificationForwarderHealth {
    running_count: AtomicU64,
    restarts: AtomicU64,
    lag_incidents: AtomicU64,
    lagged_notifications: AtomicU64,
    panics: AtomicU64,
    unexpected_exits: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RelayNotificationForwarderHealthSnapshot {
    running: bool,
    restarts: u64,
    lag_incidents: u64,
    lagged_notifications: u64,
    panics: u64,
    unexpected_exits: u64,
}

#[derive(PartialEq, Eq)]
struct IncrementalActivation {
    inbox_endpoints: Vec<TransportEndpoint>,
    since: Timestamp,
}

#[derive(Clone)]
pub struct MarmotRelayPlaneAccountAdapter {
    account_id: MemberId,
    relay_plane: MarmotRelayPlane,
    publish_client: Arc<dyn NostrRelayClient>,
    delivery_rx: Arc<Mutex<mpsc::Receiver<AccountDeliveryEvent>>>,
    delivery_overflow: Arc<AccountDeliveryOverflowState>,
    /// The queue generation `delivery_rx` belongs to.
    delivery_epoch: u64,
    incremental_activation: Arc<Mutex<Option<IncrementalActivation>>>,
}

#[derive(Clone)]
struct AccountDeliveryRoute {
    sender: mpsc::Sender<AccountDeliveryEvent>,
    overflow: Arc<AccountDeliveryOverflowState>,
    /// The queue generation `sender` feeds.
    epoch: u64,
    recovery_marker: Option<AccountDeliveryRecoveryMarker>,
    spill: Option<Arc<delivery_spill::AccountDeliverySpill>>,
}

/// Persists a queue-loss generation: its marker token, dropped count and the
/// earliest wire `created_at` among the dropped deliveries (`None` if any is
/// unknown).
pub(crate) type AccountDeliveryRecoveryMarker = Arc<
    dyn Fn(u64, u64, Option<u64>) -> Result<(), AccountDeliveryRecoveryMarkerError>
        + Send
        + Sync
        + 'static,
>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountDeliveryRecoveryMarkerError {
    Retryable,
    Closed,
}

#[derive(Debug)]
enum AccountDeliveryEvent {
    Delivery(Box<TransportDelivery>),
    Overflow { generation: u64 },
}

/// Aggregate, privacy-safe description of one unresolved per-account queue
/// overflow generation. The account identity never leaves the private route
/// registry; callers see only counts, queue depth, and elapsed time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AccountDeliveryOverflow {
    pub(crate) generation: u64,
    pub(crate) marker_token: u64,
    pub(crate) dropped: u64,
    /// Earliest wire `created_at` among this generation's dropped
    /// deliveries, or `None` when any of them is unknown.
    pub(crate) earliest_dropped: Option<u64>,
    pub(crate) notification_losses: u64,
    pub(crate) notification_token: u64,
    /// Lowest REQ `since` floor among this generation's notification lags, or
    /// `None` when any lag's floor is unknown.
    pub(crate) notification_floor: Option<u64>,
    pub(crate) queue_depth: usize,
    pub(crate) elapsed_ms: u64,
}

/// Cumulative placements one account queue made, as counts only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AccountDeliveryPlacementCounts {
    pub(crate) spilled_below_floor: u64,
    pub(crate) spilled_queue_full: u64,
    pub(crate) spill_already_seen: u64,
    pub(crate) queue_dropped: u64,
}

#[derive(Debug)]
pub(crate) enum AccountDeliveryReceive {
    Delivery(Box<TransportDelivery>),
    Overflow(AccountDeliveryOverflow),
}

/// What woke a waiting account consumer.
#[derive(Debug)]
pub(crate) enum AccountDeliveryWait {
    Received(AccountDeliveryReceive),
    /// Spilled rows became durable while the queue was empty.
    SpillReady,
    Closed,
}

#[derive(Default)]
struct AccountDeliveryOverflowState {
    inner: std::sync::Mutex<AccountDeliveryOverflowInner>,
    metrics: Arc<AccountDeliveryMetrics>,
    /// Notified by the spill writer after spilled rows become durable. Lives
    /// here, not on the adapter, so a replaced adapter still hears a writer
    /// that started under its predecessor.
    spill_ready: Arc<Notify>,
}

#[derive(Default)]
struct AccountDeliveryOverflowInner {
    generation: u64,
    pending: bool,
    signal_queued: bool,
    marker_signal_pending: bool,
    recovery_in_progress: bool,
    dropped: u64,
    notification_losses: u64,
    notification_token: u64,
    notification_imported: u64,
    queue_depth: usize,
    started_at: Option<Instant>,
    recovery_started_at: Option<Instant>,
    marker_token: u64,
    marker_in_progress: bool,
    marker_durable: bool,
    marker_closed: bool,
    /// Deliveries handed to the spill writer but not yet durable or lost.
    spill_in_flight: u64,
    /// A spill writer recorded loss after its route was retired, so no queue
    /// has carried its signal yet.
    retired_loss_unsignalled: bool,
    /// Running minimum of the dropped deliveries' wire `created_at`, and
    /// whether any dropped delivery's time was unknown.
    earliest_dropped: Option<u64>,
    earliest_dropped_unknown: bool,
    /// Running minimum of the notification lags' REQ floors, and whether any
    /// lag's floor was unknown.
    notification_floor: Option<u64>,
    notification_floor_unknown: bool,
    /// What the account queue holds, and the restart floors a cursor commit
    /// must keep over it.
    admission: AccountDeliveryAdmission,
}

/// The account queue as a restart would see it, and the restart floors a
/// transport-cursor commit guards. It sits under the overflow lock, which the
/// router holds while it places each delivery, so every commit's decision is
/// ordered against every placement: a delivery queued first caps the commit,
/// and one placed later sees the floor the commit raised.
///
/// Every value is a restart `since`: the group-route `since` a restart builds
/// from a cursor, which is the cursor minus the rebuild lookback. A delivery's
/// key is the lowest such `since` that still fetches it again: its
/// `created_at`, or for the inbox its `created_at` plus the NIP-59 widening
/// the inbox REQ adds.
#[derive(Debug, Default)]
struct AccountDeliveryAdmission {
    /// The queue generation `queued` describes. A replaced route's queue
    /// dies with its receiver.
    epoch: u64,
    /// Keys of the deliveries in the account queue, and of those its
    /// consumer took but has not yet ingested durably, with their counts.
    queued: BTreeMap<u64, u32>,
    /// The key in `queued` each taken delivery holds until its consumer
    /// releases it, by event. A delivery whose ingest failed is never
    /// released, so its key keeps capping commits for the rest of the queue
    /// generation, unless a redelivery of the same event is released.
    taken: HashMap<MessageId, u64>,
    /// The persisted cursor's restart `since`. Every seal raises it before
    /// its commit saves, so it covers a cursor still being written too.
    durable_since: Option<u64>,
    /// The part of `durable_since` that drain checkpoints, settled loss and
    /// the cursor the account opened with made durable, which is where a
    /// design without live promotion would have it. A delivery keyed between
    /// the two is one that only a live promotion, or a commit still saving,
    /// stopped a restart from fetching, so the router spills it instead of
    /// queueing it. `None` until the account's first settled cursor: before
    /// any cursor a restart relied on its comparison, not the cursor, for
    /// everything, so while this is `None` every delivery below
    /// `durable_since` is spilled.
    settled_since: Option<u64>,
}

impl AccountDeliveryAdmission {
    /// One delivery keyed `key` no longer caps a commit.
    fn remove_queued(&mut self, key: u64) {
        if let std::collections::btree_map::Entry::Occupied(mut count) = self.queued.entry(key) {
            if *count.get() > 1 {
                *count.get_mut() -= 1;
            } else {
                count.remove();
            }
        }
    }
}

/// Where the router puts one delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccountDeliveryPlacement {
    Queue,
    /// The durable spill. The cursor fence already counts it.
    Spill,
    /// Queue loss, because no spill can take it.
    Omit,
}

/// The lowest restart `since` that fetches `delivery` again.
fn account_delivery_restart_key(delivery: &TransportDelivery) -> u64 {
    let created_at = delivery.message.timestamp.0;
    if delivery.source.plane == TransportDeliveryPlane::AccountInbox {
        created_at.saturating_add(transport_nostr_adapter::NIP59_TIMESTAMP_TWEAK_SECS)
    } else {
        created_at
    }
}

/// What one omission charges to the current loss generation.
#[derive(Clone, Copy, Debug)]
enum AccountDeliveryLossCharge {
    /// A delivery the queue omitted, with its wire `created_at` if known.
    Drop { created_at: Option<u64> },
    /// A consumer lag, bounded by the REQ floors that could have delivered
    /// the lost notifications.
    Notification { floor: NostrNotificationLossFloor },
}

#[derive(Default)]
struct AccountDeliveryMetrics {
    max_queue_depth: AtomicU64,
    dropped: AtomicU64,
    spilled: AtomicU64,
    spill_already_seen: AtomicU64,
    /// Deliveries `place` sent to the spill because a cursor commit had
    /// raised the restart floor past them, and because the queue was full.
    /// Counted at placement; `spilled` counts what the writer stored.
    spill_diverted_below_floor: AtomicU64,
    spill_diverted_queue_full: AtomicU64,
    recovery_attempts: AtomicU64,
    recovery_successes: AtomicU64,
    recovery_failures: AtomicU64,
    recovery_elapsed_ms: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AccountDeliveryMetricsSnapshot {
    queue_depth: usize,
    max_queue_depth: u64,
    dropped: u64,
    spilled: u64,
    spill_already_seen: u64,
    recovery_attempts: u64,
    recovery_successes: u64,
    recovery_failures: u64,
    recovery_elapsed_ms: u64,
}

impl AccountDeliveryMetrics {
    fn snapshot(
        &self,
        routes: &RwLock<HashMap<MemberId, AccountDeliveryRoute>>,
    ) -> AccountDeliveryMetricsSnapshot {
        let queue_depth = account_deliveries_read(routes)
            .values()
            .map(|route| {
                route
                    .sender
                    .max_capacity()
                    .saturating_sub(route.sender.capacity())
            })
            .fold(0_usize, usize::saturating_add);
        AccountDeliveryMetricsSnapshot {
            queue_depth,
            max_queue_depth: self.max_queue_depth.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            spilled: self.spilled.load(Ordering::Relaxed),
            spill_already_seen: self.spill_already_seen.load(Ordering::Relaxed),
            recovery_attempts: self.recovery_attempts.load(Ordering::Relaxed),
            recovery_successes: self.recovery_successes.load(Ordering::Relaxed),
            recovery_failures: self.recovery_failures.load(Ordering::Relaxed),
            recovery_elapsed_ms: self.recovery_elapsed_ms.load(Ordering::Relaxed),
        }
    }
}

impl AccountDeliveryOverflowState {
    fn observe_queue_depth(&self, queue_depth: usize) {
        let depth = u64::try_from(queue_depth).unwrap_or(u64::MAX);
        self.metrics
            .max_queue_depth
            .fetch_max(depth, Ordering::Relaxed);
    }

    /// Decide where one delivery goes, under the lock every cursor commit
    /// decides under. A full queue, or a key below the durable floor and not
    /// below the settled one, sends it to the spill, or to loss when there is
    /// none. Before the first settled cursor every key below the durable
    /// floor goes there. A spilled delivery is counted in the cursor fence
    /// here, before the hand-off holds it, so no commit can pass it while it
    /// is in neither place.
    fn place(
        &self,
        epoch: u64,
        key: u64,
        queue_full: bool,
        spill: bool,
    ) -> AccountDeliveryPlacement {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let admission = &mut state.admission;
        let below_durable_floor = admission.durable_since.is_some_and(|durable| {
            key < durable && admission.settled_since.is_none_or(|settled| settled <= key)
        });
        if !queue_full && !below_durable_floor {
            if admission.epoch == epoch {
                *admission.queued.entry(key).or_default() += 1;
            }
            return AccountDeliveryPlacement::Queue;
        }
        if spill {
            state.spill_in_flight = state.spill_in_flight.saturating_add(1);
            RelayNotificationForwarderHealth::increment(
                if queue_full {
                    &self.metrics.spill_diverted_queue_full
                } else {
                    &self.metrics.spill_diverted_below_floor
                },
                1,
            );
            AccountDeliveryPlacement::Spill
        } else {
            AccountDeliveryPlacement::Omit
        }
    }

    /// A delivery `place` queued never reached the queue: its send failed.
    fn unqueue(&self, epoch: u64, key: u64) {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let admission = &mut state.admission;
        if admission.epoch == epoch {
            admission.remove_queued(key);
        }
    }

    /// The consumer took a queued delivery. It keeps its key, so it caps
    /// every commit until the consumer releases it: until then its ingest may
    /// still fail, and a restart must fetch it again. An event holds one key
    /// at a time, so a redelivery of one whose ingest failed takes over the
    /// pin that failure left.
    fn take(&self, epoch: u64, key: u64, id: &MessageId) {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let admission = &mut state.admission;
        if admission.epoch != epoch {
            return;
        }
        let spare = match admission.taken.get_mut(id) {
            Some(held) => {
                let spare = (*held).max(key);
                *held = (*held).min(key);
                spare
            }
            None => {
                admission.taken.insert(id.clone(), key);
                return;
            }
        };
        admission.remove_queued(spare);
    }

    /// A taken delivery's ingest is durable, or its consumer dropped it on
    /// purpose, so it no longer caps a commit.
    fn release(&self, epoch: u64, id: &MessageId) {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let admission = &mut state.admission;
        if admission.epoch != epoch {
            return;
        }
        if let Some(key) = admission.taken.remove(id) {
            admission.remove_queued(key);
        }
    }

    /// Start the generation of a new route's queue. The previous queue died
    /// with its receiver, and nothing in it can be taken any more. Its
    /// deliveries, and those its consumer took and never released, went with
    /// it: the new route's subscriptions start from a cursor no commit moved
    /// past them, so they fetch them again.
    fn open_queue(&self) -> u64 {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let admission = &mut state.admission;
        admission.epoch = admission.epoch.wrapping_add(1);
        admission.queued.clear();
        admission.taken.clear();
        admission.epoch
    }

    /// How far a commit may promote the cursor, decided under the placement
    /// lock: `candidate`, capped at the lowest key the persisted cursor still
    /// covers of a delivery queued or taken and not yet released, plus the
    /// lookback. `None` while loss or a spill hand-off is pending, and for a
    /// replaced adapter, whose queue is not the one tracked here. The restart
    /// floor rises here, before the commit's save starts, so any delivery
    /// placed while that save runs and falls below it goes to the spill. A
    /// settled commit moves the settled floor up once its save succeeds; a
    /// live one leaves it, so its spilling continues.
    fn seal_cursor(
        &self,
        epoch: u64,
        lookback: Option<u64>,
        candidate: Option<u64>,
    ) -> Option<u64> {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if state.pending || state.spill_in_flight > 0 || state.admission.epoch != epoch {
            return None;
        }
        let candidate = candidate?;
        let Some(lookback) = lookback else {
            // A full-history plane rebuilds unfloored, so no cursor can hide
            // a delivery from a restart.
            return Some(candidate);
        };
        let admission = &mut state.admission;
        let covered = admission.durable_since.unwrap_or(0);
        let cap = admission
            .queued
            .range(covered..)
            .next()
            .map(|(key, _)| key.saturating_add(lookback));
        let reached = cap.map_or(candidate, |cap| candidate.min(cap));
        let since = reached.saturating_sub(lookback);
        admission.durable_since = Some(admission.durable_since.map_or(since, |d| d.max(since)));
        Some(reached)
    }

    /// A commit's save failed, so `restored` is still the persisted cursor:
    /// lower the restart floor its seal raised back to it. The router queues
    /// what that floor covers again, and the next seal is capped by it.
    /// Deliveries spilled meanwhile stay in the spill.
    fn unseal_cursor(&self, lookback: Option<u64>, restored: Option<u64>) {
        let Some(lookback) = lookback else {
            return;
        };
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let admission = &mut state.admission;
        admission.durable_since = restored
            .map(|restored| restored.saturating_sub(lookback))
            .max(admission.settled_since);
    }

    /// Record a cursor that is durable without live promotion: one a settled
    /// commit reached on its own, never one an earlier live promotion left
    /// persisted, so the settled floor stays at or below where a design
    /// without live promotion would have it. `opened` is the cursor the
    /// account opened with: it seeds the settled floor only when this process
    /// has none, because a reopened client inherits whatever live promotion an
    /// earlier one made.
    fn settle_cursor(&self, lookback: Option<u64>, reached: Option<u64>, opened: bool) {
        let (Some(lookback), Some(reached)) = (lookback, reached) else {
            return;
        };
        let since = reached.saturating_sub(lookback);
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let admission = &mut state.admission;
        admission.durable_since = Some(admission.durable_since.map_or(since, |d| d.max(since)));
        admission.settled_since = match admission.settled_since {
            Some(settled) if opened => Some(settled),
            Some(settled) => Some(settled.max(since)),
            None => Some(since),
        };
    }

    fn finish_spill(&self, settled: u64, stored: u64, already_seen: u64) {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        state.spill_in_flight = state.spill_in_flight.saturating_sub(settled);
        RelayNotificationForwarderHealth::increment(&self.metrics.spilled, stored);
        RelayNotificationForwarderHealth::increment(&self.metrics.spill_already_seen, already_seen);
    }

    /// Record an omitted delivery and return the generation only when this
    /// caller must enqueue the generation's control record.
    fn record_drop(&self, queue_depth: usize, created_at: Option<u64>) -> Option<u64> {
        self.record_loss(queue_depth, AccountDeliveryLossCharge::Drop { created_at })
    }

    /// Record a consumer lag with the REQ floor read at the lag, returning the
    /// generation only when this caller must enqueue its control record.
    fn record_notification_loss(&self, floor: NostrNotificationLossFloor) -> Option<u64> {
        self.record_loss(0, AccountDeliveryLossCharge::Notification { floor })
    }

    fn record_loss(&self, queue_depth: usize, charge: AccountDeliveryLossCharge) -> Option<u64> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.pending {
            state.generation = state.generation.saturating_add(1);
            state.pending = true;
            state.dropped = 0;
            state.earliest_dropped = None;
            state.earliest_dropped_unknown = false;
            Self::reset_notification_loss(&mut state);
            state.started_at = Some(Instant::now());
            state.marker_token = rand::rngs::OsRng.next_u64() & i64::MAX as u64;
            state.marker_in_progress = false;
            state.marker_durable = false;
            state.marker_closed = false;
        }
        match charge {
            AccountDeliveryLossCharge::Notification { floor } => {
                state.notification_losses = state.notification_losses.saturating_add(1);
                // Each lag mints a token, so a changed floor always imports as
                // new loss and bumps the obligation's revision.
                state.notification_token = rand::rngs::OsRng.next_u64() & i64::MAX as u64;
                match floor.since_seconds() {
                    Some(since) => {
                        state.notification_floor =
                            Some(state.notification_floor.map_or(since, |f| f.min(since)))
                    }
                    None => state.notification_floor_unknown = true,
                }
            }
            AccountDeliveryLossCharge::Drop { created_at } => {
                state.dropped = state.dropped.saturating_add(1);
                match created_at {
                    Some(at) => {
                        state.earliest_dropped =
                            Some(state.earliest_dropped.map_or(at, |e| e.min(at)))
                    }
                    None => state.earliest_dropped_unknown = true,
                }
                state.marker_durable = false;
                RelayNotificationForwarderHealth::increment(&self.metrics.dropped, 1);
            }
        }
        state.queue_depth = state.queue_depth.max(queue_depth);
        self.observe_queue_depth(queue_depth);
        if state.signal_queued {
            None
        } else {
            state.signal_queued = true;
            Some(state.generation)
        }
    }

    /// A new generation starts with no notification loss.
    fn reset_notification_loss(state: &mut AccountDeliveryOverflowInner) {
        state.notification_losses = 0;
        state.notification_token = 0;
        state.notification_imported = 0;
        state.notification_floor = None;
        state.notification_floor_unknown = false;
    }

    fn record_retired_drop(&self, created_at: Option<u64>) {
        self.record_drop(0, created_at);
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retired_loss_unsignalled = true;
    }

    /// A control record queued on a route whose receiver is gone died with
    /// that queue, yet `signal_queued` still claims it, so `finish_recovery`
    /// could never clear the generation. Mark the signal unsent, as for loss a
    /// retired writer recorded while no route existed, so that the next route
    /// carries it. A deferred signal counts too: its marker writer holds the
    /// dead queue's sender. This assumes one live adapter per account, as the
    /// worker drops its client before it reopens.
    fn release_signal_of_closed_route(&self, sender: &mpsc::Sender<AccountDeliveryEvent>) {
        if !sender.is_closed() {
            return;
        }
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.pending && state.signal_queued {
            state.retired_loss_unsignalled = true;
        }
    }

    /// Claim the signal for loss a retired writer recorded while no route
    /// existed, or whose control record died with a replaced route's queue.
    /// Any other pending loss already had its route.
    fn claim_retired_loss_signal(&self) -> Option<u64> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !std::mem::take(&mut state.retired_loss_unsignalled) || !state.pending {
            return None;
        }
        state.signal_queued = true;
        state.marker_signal_pending = false;
        Some(state.generation)
    }

    fn cancel_signal(&self, generation: u64) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.generation == generation {
            state.signal_queued = false;
            state.marker_signal_pending = false;
        }
    }

    fn defer_marker_signal(&self, generation: u64) {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if state.generation == generation {
            state.marker_signal_pending = true;
        }
    }

    fn take_durable_marker_signal(&self, generation: u64) -> bool {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if state.generation == generation
            && state.marker_signal_pending
            && (state.marker_durable || state.marker_closed)
            && !state.marker_in_progress
        {
            state.marker_signal_pending = false;
            true
        } else {
            false
        }
    }

    /// Claim the one account-local marker worker for the current generation.
    /// Each increased queue count must become durable. One writer aggregates
    /// changes while active; notification incidents belong to the account worker.
    fn start_marker_persistence(&self) -> bool {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.dropped == 0
            || state.marker_durable
            || state.marker_closed
            || state.marker_in_progress
        {
            return false;
        }
        state.marker_in_progress = true;
        true
    }

    #[cfg(test)]
    fn marker_barrier_complete(&self) -> bool {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.dropped == 0 || state.marker_durable || state.marker_closed
    }

    /// Persist the generation marker on one account-local blocking worker while
    /// the shared relay router continues serving every other route. Retryable
    /// failures retain only this task and aggregate later omissions into the
    /// generation counter; terminal storage closure releases the task.
    async fn persist_marker_before_drop(&self, marker: AccountDeliveryRecoveryMarker) {
        let generation = {
            let state = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.generation
        };
        loop {
            let (marker_token, dropped, earliest) = {
                let state = self
                    .inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                (
                    state.marker_token,
                    state.dropped,
                    state
                        .earliest_dropped
                        .filter(|_| !state.earliest_dropped_unknown),
                )
            };
            let marker = marker.clone();
            match tokio::task::spawn_blocking(move || marker(marker_token, dropped, earliest)).await
            {
                Ok(Ok(())) => {
                    let mut state = self
                        .inner
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if state.generation == generation {
                        if state.dropped != dropped {
                            continue;
                        }
                        state.marker_in_progress = false;
                        state.marker_durable = true;
                    }
                    return;
                }
                Ok(Err(AccountDeliveryRecoveryMarkerError::Closed)) => {
                    let mut state = self
                        .inner
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if state.generation == generation {
                        state.marker_in_progress = false;
                        state.marker_closed = true;
                        tracing::debug!(
                            target: "marmot_app::relay_plane",
                            method = "persist_marker_before_drop",
                            error_kind = "storage_closed",
                            "account delivery overflow marker worker stopped after storage closure",
                        );
                    }
                    return;
                }
                Ok(Err(AccountDeliveryRecoveryMarkerError::Retryable)) | Err(_) => {
                    tracing::warn!(
                        target: "marmot_app::relay_plane",
                        method = "persist_marker_before_drop",
                        error_kind = "overflow_marker_persist_failed",
                        "durable account delivery overflow marker write failed; retrying",
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            let state = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.generation != generation {
                return;
            }
        }
    }

    fn notification_persisted(&self, observed: AccountDeliveryOverflow) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.generation == observed.generation
            && state.notification_token == observed.notification_token
        {
            state.notification_imported = observed.notification_losses;
        }
    }

    fn pending_snapshot(&self) -> Option<AccountDeliveryOverflow> {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (state.pending && !state.recovery_in_progress).then(|| Self::snapshot(&state))
    }

    fn consume_signal(&self, generation: u64) -> AccountDeliveryOverflow {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.generation == generation {
            state.signal_queued = false;
        }
        Self::snapshot(&state)
    }

    fn start_recovery(&self, durable_marker_token: u64) -> AccountDeliveryOverflow {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A durable marker can outlive the process-local route that detected
        // it. Recreate a synthetic pending generation on reopen so completion
        // still has a compare-and-clear guard against new local overflow.
        if !state.pending {
            state.generation = state.generation.saturating_add(1);
            state.pending = true;
            state.dropped = 0;
            state.earliest_dropped = None;
            state.earliest_dropped_unknown = false;
            // The resolved generation's lags must not charge this one's floor.
            Self::reset_notification_loss(&mut state);
            state.queue_depth = 0;
            state.started_at = Some(Instant::now());
            // This path exists only because the durable database marker was
            // loaded after a restart; the process-local generation is already
            // covered before its first recovery subscription is issued.
            state.marker_token = durable_marker_token;
            state.marker_durable = true;
            state.marker_closed = false;
        }
        state.recovery_in_progress = true;
        state.recovery_started_at = Some(Instant::now());
        RelayNotificationForwarderHealth::increment(&self.metrics.recovery_attempts, 1);
        Self::snapshot(&state)
    }

    fn restore_recovery_guard(&self, durable_marker_token: u64) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.pending {
            state.generation = state.generation.saturating_add(1);
            state.pending = true;
            state.dropped = 0;
            state.earliest_dropped = None;
            state.earliest_dropped_unknown = false;
            Self::reset_notification_loss(&mut state);
            state.queue_depth = 0;
            state.started_at = Some(Instant::now());
            state.marker_token = durable_marker_token;
            state.marker_durable = true;
            state.marker_closed = false;
            state.recovery_in_progress = false;
        }
    }

    /// Whether `observed` is still exactly the pending generation, with every
    /// omission it counts durable and imported and no control record queued,
    /// so the account owner may settle it.
    fn settles(state: &AccountDeliveryOverflowInner, observed: &AccountDeliveryOverflow) -> bool {
        state.pending
            && state.generation == observed.generation
            && state.marker_token == observed.marker_token
            && state.dropped == observed.dropped
            && state.notification_losses == observed.notification_losses
            && state.notification_imported == state.notification_losses
            && (state.dropped == 0 || state.marker_durable)
            && !state.marker_in_progress
            && !state.marker_closed
            && !state.signal_queued
    }

    fn finish_recovery(&self, attempt: AccountDeliveryOverflow) -> Option<u64> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let resolved = Self::settles(&state, &attempt);
        if resolved {
            state.pending = false;
            state.recovery_in_progress = false;
            state.marker_in_progress = false;
            state.marker_durable = false;
            state.marker_closed = false;
            state.started_at = None;
            let elapsed_ms = state
                .recovery_started_at
                .take()
                .map(|started| started.elapsed().as_millis() as u64)
                .unwrap_or_default();
            return Some(elapsed_ms);
        }
        None
    }

    /// Clear the generation the account owner retired as "history may be
    /// incomplete", under the same exact-generation guard as `finish_recovery`.
    /// It is not a recovery success: no success is counted, and an attempt
    /// still in flight records its own failure when it ends. Returns true when
    /// no generation is pending any more.
    fn retire_recovery(&self, observed: Option<AccountDeliveryOverflow>) -> bool {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.pending {
            return true;
        }
        if !observed.is_some_and(|observed| Self::settles(&state, &observed)) {
            return false;
        }
        state.pending = false;
        state.marker_durable = false;
        state.marker_closed = false;
        state.started_at = None;
        true
    }

    fn pending_generation(&self) -> Option<AccountDeliveryOverflow> {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.pending.then(|| Self::snapshot(&state))
    }

    fn record_recovery_success(&self, elapsed_ms: u64) {
        RelayNotificationForwarderHealth::increment(&self.metrics.recovery_successes, 1);
        RelayNotificationForwarderHealth::increment(&self.metrics.recovery_elapsed_ms, elapsed_ms);
    }

    fn fail_recovery(&self) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.recovery_in_progress = false;
        let elapsed_ms = state
            .recovery_started_at
            .take()
            .map(|started| started.elapsed().as_millis() as u64)
            .unwrap_or_default();
        RelayNotificationForwarderHealth::increment(&self.metrics.recovery_failures, 1);
        RelayNotificationForwarderHealth::increment(&self.metrics.recovery_elapsed_ms, elapsed_ms);
    }

    fn blocks_ordinary_eose(&self) -> bool {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.pending && !state.recovery_in_progress
    }

    fn snapshot(state: &AccountDeliveryOverflowInner) -> AccountDeliveryOverflow {
        AccountDeliveryOverflow {
            generation: state.generation,
            marker_token: state.marker_token,
            dropped: state.dropped,
            earliest_dropped: state
                .earliest_dropped
                .filter(|_| !state.earliest_dropped_unknown),
            notification_losses: state.notification_losses,
            notification_token: state.notification_token,
            notification_floor: state
                .notification_floor
                .filter(|_| !state.notification_floor_unknown),
            queue_depth: state.queue_depth,
            elapsed_ms: state
                .started_at
                .map(|started| started.elapsed().as_millis() as u64)
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPlaneHealth {
    pub sdk_backed: bool,
    pub total_relays: usize,
    pub initialized: usize,
    pub pending: usize,
    pub connecting: usize,
    pub connected: usize,
    pub disconnected: usize,
    pub terminated: usize,
    pub banned: usize,
    pub sleeping: usize,
    pub connection_attempts: usize,
    pub connection_successes: usize,
    pub notification_forwarder_running: bool,
    /// Relay notification consumers restarted after a lag or an unexpected
    /// exit. A lag resumes the same SDK receiver and leaves account delivery
    /// open; an unexpected exit replaces the receiver and closes account
    /// delivery, so the account worker reconnects.
    pub notification_forwarder_restarts: u64,
    /// Consumer lags, each recorded as notification loss on the affected
    /// accounts and recovered by comparison.
    pub notification_forwarder_lag_incidents: u64,
    /// Notifications those lags skipped or abandoned. A count of
    /// notifications, including raw relay copies, not of lost events.
    pub notification_forwarder_lagged_notifications: u64,
    pub notification_forwarder_panics: u64,
    pub notification_forwarder_unexpected_exits: u64,
    /// Current queued account-delivery records across active accounts.
    #[serde(default)]
    pub account_delivery_queue_depth: usize,
    /// High-water queue depth for any account since this plane started.
    #[serde(default)]
    pub account_delivery_max_queue_depth: u64,
    /// Deliveries neither queued nor spilled, and covered by an explicit
    /// recovery generation instead.
    #[serde(default)]
    pub account_delivery_dropped: u64,
    /// Deliveries stored in the durable account spill instead of the queue:
    /// because it was full, or because a transport-cursor checkpoint still
    /// saving, or a live promotion alone, had put them below the floor a
    /// restart fetches from.
    #[serde(default)]
    pub account_delivery_spilled: u64,
    /// Spill candidates discarded because the account had already seen them.
    #[serde(default)]
    pub account_delivery_spill_already_seen: u64,
    #[serde(default)]
    pub account_delivery_recovery_attempts: u64,
    #[serde(default)]
    pub account_delivery_recovery_successes: u64,
    #[serde(default)]
    pub account_delivery_recovery_failures: u64,
    /// Aggregate wall-clock time spent in completed/failed recovery attempts.
    #[serde(default)]
    pub account_delivery_recovery_elapsed_ms: u64,
    pub directory_inflight_fetches: usize,
    pub directory_active_subscriptions: usize,
    #[serde(default)]
    pub directory_auth_required_routes: usize,
    pub directory_completed_fetches: usize,
    pub directory_coalesced_waiters: usize,
    pub directory_failed_fetches: usize,
    pub directory_completed_subscription_syncs: usize,
    pub directory_subscriptions_created: usize,
    pub directory_subscriptions_removed: usize,
}

impl MarmotRelayPlane {
    pub fn runtime_default(subscription_rebuild_lookback: Duration) -> Self {
        Self::from_sdk(Some(subscription_rebuild_lookback), false)
    }

    /// Production runtime plane whose relay-safety chokepoint admits loopback
    /// endpoints only when `allow_loopback` is set
    /// (`MarmotAppConfig::allow_loopback_relay_endpoints`, off by default).
    pub fn runtime_default_with_loopback(
        subscription_rebuild_lookback: Duration,
        allow_loopback: bool,
    ) -> Self {
        Self::from_sdk(Some(subscription_rebuild_lookback), allow_loopback)
    }

    pub fn full_history() -> Self {
        Self::from_sdk(None, false)
    }

    /// Full-history plane whose relay-safety chokepoint admits loopback
    /// endpoints only when `allow_loopback` is set
    /// (`MarmotAppConfig::allow_loopback_relay_endpoints`, off by default).
    pub fn full_history_with_loopback(allow_loopback: bool) -> Self {
        Self::from_sdk(None, allow_loopback)
    }

    pub fn with_subscription_rebuild_lookback(lookback: Duration) -> Self {
        Self::from_sdk(Some(lookback), false)
    }

    pub fn new(
        subscription_rebuild_lookback: Option<Duration>,
        relay_client: Arc<dyn NostrRelayClient>,
    ) -> Self {
        Self::new_with_loopback(subscription_rebuild_lookback, relay_client, false)
    }

    pub(crate) fn new_with_loopback(
        subscription_rebuild_lookback: Option<Duration>,
        relay_client: Arc<dyn NostrRelayClient>,
        allow_loopback: bool,
    ) -> Self {
        let adapter = NostrTransportAdapter::new(relay_client);
        Self::from_adapter(
            subscription_rebuild_lookback,
            adapter,
            None,
            None,
            Arc::new(NostrSdkDirectoryRelayFetcher::standalone()),
            allow_loopback,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_directory_fetcher_for_test(
        subscription_rebuild_lookback: Option<Duration>,
        relay_client: Arc<dyn NostrRelayClient>,
        directory_fetcher: Arc<dyn DirectoryRelayFetcher>,
        allow_loopback: bool,
    ) -> Self {
        Self::from_adapter(
            subscription_rebuild_lookback,
            NostrTransportAdapter::new(relay_client),
            None,
            None,
            directory_fetcher,
            allow_loopback,
        )
    }

    fn from_sdk(subscription_rebuild_lookback: Option<Duration>, allow_loopback: bool) -> Self {
        let directory_client = directory::anonymous_directory_client();
        let relay_client = NostrSdkRelayClient::multi_account();
        let adapter = NostrTransportAdapter::new(Arc::new(relay_client.clone()));
        Self::from_adapter(
            subscription_rebuild_lookback,
            adapter,
            Some(relay_client),
            Some(directory_client.clone()),
            Arc::new(NostrSdkDirectoryRelayFetcher::standalone()),
            allow_loopback,
        )
    }

    fn from_adapter(
        subscription_rebuild_lookback: Option<Duration>,
        adapter: NostrTransportAdapter,
        sdk_relay_client: Option<NostrSdkRelayClient>,
        directory_client: Option<NostrSdkClient>,
        directory_fetcher: Arc<dyn DirectoryRelayFetcher>,
        allow_loopback: bool,
    ) -> Self {
        let transport = Arc::new(RelayPlaneTransport {
            adapter,
            sdk_relay_client,
            directory_client,
            directory_events: broadcast::channel(DIRECTORY_EVENT_BUFFER).0,
            account_deliveries: RwLock::new(HashMap::new()),
            account_overflow_states: std::sync::Mutex::new(HashMap::new()),
            account_delivery_metrics: Arc::new(AccountDeliveryMetrics::default()),
            router: Mutex::new(None),
            notification_forwarder: Mutex::new(None),
            account_notification_forwarders: Mutex::new(HashMap::new()),
            directory_notification_forwarder: Mutex::new(None),
            notification_forwarder_health: Arc::new(RelayNotificationForwarderHealth::default()),
            eose_repairs: std::sync::Mutex::new(HashMap::new()),
            eose_repair_settle_ms: AtomicU64::new(
                NOTIFICATION_LAG_EOSE_REPAIR_SETTLE.as_millis() as u64
            ),
            shutting_down: AtomicBool::new(false),
        });
        let this = Self {
            inner: Arc::new(MarmotRelayPlaneInner {
                subscription_rebuild_lookback,
                relay_safety: RelaySafetyPolicy::with_allow_loopback(allow_loopback),
                transport,
                directory: DirectoryRelayPlane::new(directory_fetcher),
                directory_subscription_sync: Mutex::new(()),
            }),
        };
        this.spawn_router();
        this
    }

    /// Build an account adapter without durable queue-overflow recovery.
    ///
    /// Production callers must use `account_adapter_with_recovery_marker` with
    /// a marker. This compatibility constructor is retained for tests and
    /// embedders that do not persist account projection state.
    pub fn account_adapter(
        &self,
        account_id: MemberId,
        publish_client: Arc<dyn NostrRelayClient>,
    ) -> MarmotRelayPlaneAccountAdapter {
        self.account_adapter_with_recovery_marker(account_id, publish_client, None, None)
    }

    pub(crate) fn account_adapter_with_recovery_marker(
        &self,
        account_id: MemberId,
        publish_client: Arc<dyn NostrRelayClient>,
        recovery_marker: Option<AccountDeliveryRecoveryMarker>,
        spill_store: Option<AccountDeliverySpillStore>,
    ) -> MarmotRelayPlaneAccountAdapter {
        self.spawn_router();
        // Keep one slot reserved for the overflow control record. Ordinary
        // deliveries stop at ACCOUNT_DELIVERY_BUFFER, so a full account queue
        // can always carry the explicit recovery signal without awaiting the
        // slow consumer or blocking the shared router.
        let (delivery_tx, delivery_rx) = mpsc::channel(ACCOUNT_DELIVERY_BUFFER + 1);
        let signal_tx = delivery_tx.clone();
        let mut routes = account_deliveries_write(&self.inner.transport.account_deliveries);
        let delivery_overflow = self
            .inner
            .transport
            .account_overflow_states
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(account_id.clone())
            .or_insert_with(|| {
                Arc::new(AccountDeliveryOverflowState {
                    inner: std::sync::Mutex::new(AccountDeliveryOverflowInner::default()),
                    metrics: self.inner.transport.account_delivery_metrics.clone(),
                    spill_ready: Arc::default(),
                })
            })
            .clone();
        // The route lock orders the new generation against the router, which
        // reads a route's generation with the route itself.
        let delivery_epoch = delivery_overflow.open_queue();
        let replaced = routes.insert(
            account_id.clone(),
            AccountDeliveryRoute {
                sender: delivery_tx,
                overflow: delivery_overflow.clone(),
                epoch: delivery_epoch,
                spill: spill_store.map(|store| {
                    delivery_spill::AccountDeliverySpill::new(
                        store,
                        account_id.clone(),
                        Arc::downgrade(&self.inner.transport),
                        delivery_overflow.clone(),
                        recovery_marker.clone(),
                    )
                }),
                recovery_marker,
            },
        );
        if let Some(replaced) = replaced {
            delivery_overflow.release_signal_of_closed_route(&replaced.sender);
        }
        // Loss a retired writer recorded while no route existed has not been
        // signalled to any consumer, nor has a record that died with the
        // replaced route's queue. The route lock orders this against that
        // writer's own check for a route.
        if let Some(generation) = delivery_overflow.claim_retired_loss_signal() {
            enqueue_account_delivery_overflow_signal(&signal_tx, &delivery_overflow, generation);
        }
        drop(routes);
        MarmotRelayPlaneAccountAdapter {
            account_id,
            relay_plane: self.clone(),
            publish_client,
            delivery_rx: Arc::new(Mutex::new(delivery_rx)),
            delivery_overflow,
            delivery_epoch,
            incremental_activation: Arc::new(Mutex::new(None)),
        }
    }

    /// Place one delivery exactly as the router does, synchronously, so a
    /// test can land it at a chosen point inside a cursor commit.
    #[cfg(test)]
    pub(crate) fn route_account_delivery_for_test(&self, delivery: TransportDelivery) {
        route_account_delivery(&self.inner.transport, delivery);
    }

    pub(crate) fn sanitize_relay_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Result<Vec<TransportEndpoint>, String> {
        self.inner
            .relay_safety
            .sanitize_endpoints(endpoints, context)
    }

    /// Check the production relay dial policy before a history request may
    /// register an endpoint absent from this account's current SDK pool.
    pub async fn acquire_history(
        &self,
        request: NostrAcquisitionRequest,
        cancellation: NostrAcquisitionCancellation,
    ) -> Result<NostrAcquisitionResult, NostrAcquisitionError> {
        request.validate()?;
        let checked = self
            .inner
            .relay_safety
            .sanitize_endpoints(request.endpoints.clone(), "history acquisition")
            .map_err(|_| NostrAcquisitionError::InvalidRequest)?;
        if checked.len() != request.endpoints.len() {
            return Err(NostrAcquisitionError::InvalidRequest);
        }
        self.inner
            .transport
            .adapter
            .acquire_history(request, cancellation)
            .await
    }

    /// Classify caller-owned relay URLs under the exact policy used at every
    /// relay-plane dial boundary. Results preserve input order and cardinality.
    pub fn classify_relay_endpoints(
        &self,
        endpoints: Vec<String>,
    ) -> Vec<RelayEndpointClassification> {
        self.inner.relay_safety.classify_endpoints(endpoints)
    }

    pub fn subscription_rebuild_since(
        &self,
        last_transport_timestamp: Option<u64>,
    ) -> Option<Timestamp> {
        let lookback = self.inner.subscription_rebuild_lookback?;
        let last_transport_timestamp = last_transport_timestamp?;
        // The persisted cursor is advanced from the sender-controlled inbound
        // `created_at`; a far-future value would push `since` past the present,
        // so relays return no present-dated events and reception silently halts
        // forever (the cursor is persisted and monotonic, so it survives
        // restarts — mdk#182).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // A cursor detectably in the future is corrupted, not authoritative.
        // Merely clamping it to wall-clock would yield `since = now - lookback`
        // and permanently skip any valid backlog older than the (short,
        // production-default 120s) lookback for an account whose cursor was
        // poisoned before the write-side clamp existed. Treat it as untrusted
        // and request a full-history replay (`None`) so the catch-up range is
        // never silently dropped; the write side then heals the stored value
        // back below wall-clock. A cursor at or behind wall-clock is trusted
        // and used as-is.
        if last_transport_timestamp > now {
            return None;
        }
        Some(Timestamp(
            last_transport_timestamp.saturating_sub(lookback.as_secs()),
        ))
    }

    /// The subscription-rebuild lookback in seconds, if this plane rebuilds
    /// from the durable cursor. `None` means the plane rebuilds with full
    /// history (no `since` floor). Surfaced for the `subscription_rebuild`
    /// forensic audit row so an analyzer sees the window subtracted from the
    /// cursor to derive the `since` floor.
    pub fn subscription_rebuild_lookback_secs(&self) -> Option<u64> {
        self.inner
            .subscription_rebuild_lookback
            .map(|lookback| lookback.as_secs())
    }

    /// Drain the per-relay subscription-registration outcomes `account`
    /// accumulated since its previous drain, for its `subscription_rebuild`
    /// forensic audit row.
    ///
    /// Delegates to the SDK relay client, which records each subscribe's
    /// per-endpoint acceptance bucketed by account. The drain is account-scoped
    /// so concurrent account workers sharing this one relay plane each attribute
    /// their own registrations to their own audit row; a group shared across
    /// accounts registers once, attributed to whichever account's client
    /// subscribed (an acceptable diagnostic attribution). A plane built on a
    /// custom (non-SDK) relay client does not track registration outcomes, so
    /// this returns empty for it — the audit row then carries `since`/`lookback`
    /// without relay rows.
    pub async fn take_subscription_registrations(
        &self,
        account: &MemberId,
    ) -> Vec<RelayRegistrationOutcome> {
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
            return sdk_relay_client
                .take_subscription_registrations(account)
                .await;
        }
        Vec::new()
    }

    /// Register the immutable NIP-42 context before any account subscription.
    /// A custom injected relay client owns its own authentication behavior.
    pub async fn set_transport_signer(
        &self,
        account_id: &MemberId,
        signer: Arc<dyn transport_nostr_peeler::MarmotNostrSigner>,
    ) -> Result<(), TransportAdapterError> {
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
            let account_client = sdk_relay_client
                .register_account(account_id.clone(), signer)
                .await?;
            let mut forwarders = self
                .inner
                .transport
                .account_notification_forwarders
                .lock()
                .await;
            if forwarders
                .get(account_id)
                .is_none_or(JoinHandle::is_finished)
                && !self.inner.transport.shutting_down.load(Ordering::SeqCst)
            {
                if forwarders.remove(account_id).is_some() {
                    recover_relay_notification_forwarder_scoped(
                        &self.inner.transport,
                        RelayNotificationConsumerExit::Closed,
                        NostrNotificationLossFloor::Unbounded,
                        Some(account_id),
                    );
                }
                forwarders.insert(
                    account_id.clone(),
                    spawn_relay_notification_forwarder_scoped(
                        account_client,
                        self.inner.transport.clone(),
                        Some(account_id.clone()),
                    ),
                );
            }
        }
        Ok(())
    }

    /// Retire one account session's immutable SDK authenticator and its
    /// notification forwarder before the same worker reopens that account. The
    /// reopened session registers a new signer, which the SDK refuses while
    /// the previous context is live. Keep the delivery route so the
    /// replacement adapter inherits unresolved loss evidence.
    ///
    /// This runs on the reopening worker and never outlives it. If the worker
    /// is cancelled first, the reaper's `deactivate_account_context` retires
    /// the same context before a replacement may register; detached work here
    /// could instead remove that replacement's context.
    pub(crate) async fn retire_account_session_transport(&self, account_id: &MemberId) {
        let forwarder = self
            .inner
            .transport
            .account_notification_forwarders
            .lock()
            .await
            .remove(account_id);
        if let Some(mut forwarder) = forwarder {
            forwarder.abort();
            let _ = timeout(RELAY_PLANE_TASK_ABORT_WAIT, &mut forwarder).await;
        }
        if let Some(sdk) = &self.inner.transport.sdk_relay_client {
            let _ = timeout(RELAY_PLANE_SHUTDOWN_WAIT, sdk.remove_account(account_id)).await;
        }
    }

    /// Retire a stopped account worker's subscriptions and immutable SDK
    /// authenticator before a replacement worker can register a fresh signer.
    pub(crate) async fn deactivate_account_context(
        &self,
        account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        let removed =
            account_deliveries_write(&self.inner.transport.account_deliveries).remove(account_id);
        if let Some(removed) = removed {
            // Once the worker has stopped, its queue is gone, and so is any
            // control record in it.
            removed
                .overflow
                .release_signal_of_closed_route(&removed.sender);
        }
        self.inner
            .transport
            .adapter
            .deactivate_account(account_id)
            .await?;
        if let Some(sdk) = &self.inner.transport.sdk_relay_client {
            sdk.remove_account(account_id).await;
        }
        if let Some(handle) = self
            .inner
            .transport
            .account_notification_forwarders
            .lock()
            .await
            .remove(account_id)
        {
            handle.abort();
        }
        Ok(())
    }

    pub async fn relay_health(&self) -> RelayPlaneHealth {
        let directory = self.inner.directory.stats().await;
        let forwarder = self
            .inner
            .transport
            .notification_forwarder_health
            .snapshot();
        let account_delivery = self
            .inner
            .transport
            .account_delivery_metrics
            .snapshot(&self.inner.transport.account_deliveries);
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
            return RelayPlaneHealth::from_sdk(
                sdk_relay_client.relay_health().await,
                directory,
                forwarder,
                account_delivery,
            );
        }
        RelayPlaneHealth::from_directory(directory, account_delivery)
    }

    /// Snapshot the device-local relay telemetry for local inspection.
    ///
    /// Aggregate and privacy-safe: counts, millisecond histogram buckets, and
    /// opaque relay indices only. There is a single shared adapter per device,
    /// so these counters already span every local account. Resolving the opaque
    /// indices to relay URLs is reserved for the opt-in export path.
    pub async fn relay_telemetry(&self) -> RelayTelemetrySnapshot {
        let adapter = &self.inner.transport.adapter;
        RelayTelemetrySnapshot {
            metrics: adapter.metrics().await,
            delivery_spread: adapter.delivery_spread().await,
            sync: adapter.relay_sync().await,
            health: self.relay_health().await,
        }
    }

    /// Resolve opaque relay indices to relay endpoints — the export label
    /// boundary.
    ///
    /// Crate-private and reachable only through the exporter. It returns `None`
    /// unless [`RelayTelemetryExportConfig::export_allowed`] holds (the same
    /// gate as [`MarmotRelayPlane::telemetry_exporter`]); only then does it mint
    /// a [`RelayExportConsent`] and ask the adapter to reverse-map indices to
    /// relay URLs. No other code path turns a device-local index into a relay
    /// URL. See the privacy contract in `relay-observability.md`.
    pub(crate) async fn resolve_relay_labels(
        &self,
        config: &RelayTelemetryExportConfig,
    ) -> Option<RelayLabelResolution> {
        // Same gate as `telemetry_exporter`: resolution cannot happen unless
        // export is opted in with a TLS/loopback endpoint, auth, and resource
        // metadata.
        if !config.export_allowed() {
            return None;
        }
        let consent = RelayExportConsent::affirm();
        Some(
            self.inner
                .transport
                .adapter
                .resolve_relay_labels(consent)
                .await,
        )
    }

    /// Aggregate the device-local per-relay telemetry into one export-ready
    /// rollup, optionally folding in engine-side reorg metrics.
    ///
    /// Keyed by opaque relay index — no relay URLs. The single shared adapter
    /// already merges across local accounts, so today this is a near-passthrough
    /// reshaping; it is the seam where multi-account dedup and engine metrics are
    /// combined for export. `engine` is `None` until the parallel
    /// `observed_reorg_rate` workstream lands.
    pub async fn telemetry_rollup(
        &self,
        engine: Option<EngineReorgMetrics>,
    ) -> RelayTelemetryRollup {
        let adapter = &self.inner.transport.adapter;
        let spread = adapter.delivery_spread().await;
        let sync = adapter.relay_sync().await;
        let metrics = adapter.metrics().await;
        let health = self.relay_health().await;
        rollup_from_snapshots(spread, sync, metrics, health, engine)
    }

    pub(crate) async fn fetch_directory_events(
        &self,
        endpoints: Vec<TransportEndpoint>,
        queries: Vec<DirectoryEventQuery>,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let endpoints = self
            .inner
            .relay_safety
            .sanitize_endpoints(endpoints, "directory fetch")?;
        self.inner
            .directory
            .fetch_events(DirectoryFetchRequest::new(endpoints, queries)?)
            .await
    }

    pub(crate) async fn fetch_directory_events_with_completion(
        &self,
        endpoints: Vec<TransportEndpoint>,
        queries: Vec<DirectoryEventQuery>,
    ) -> Result<DirectoryFetchOutcome, String> {
        let endpoints = self
            .inner
            .relay_safety
            .sanitize_endpoints(endpoints, "directory fetch")?;
        self.inner
            .directory
            .fetch_events_with_completion(DirectoryFetchRequest::new(endpoints, queries)?)
            .await
    }

    pub(crate) async fn inspect_directory_events(
        &self,
        endpoint: TransportEndpoint,
        query: DirectoryEventQuery,
        signer: Option<Arc<dyn transport_nostr_peeler::MarmotNostrSigner>>,
    ) -> Result<Vec<DirectoryRelayEventRecord>, directory::DirectoryInspectionError> {
        let endpoints = self
            .inner
            .relay_safety
            .sanitize_endpoints(vec![endpoint], "onboarding inspection")
            .map_err(|_| directory::DirectoryInspectionError::InvalidRequest)?;
        self.inner
            .directory
            .inspect_events(
                DirectoryFetchRequest::new(endpoints, vec![query])
                    .map_err(|_| directory::DirectoryInspectionError::InvalidRequest)?,
                signer,
            )
            .await
    }

    /// Narrow discovered relay endpoints to the safe ones, dropping the rest.
    ///
    /// Unlike the fail-closed sanitize on the dial path, this is for endpoints
    /// another account published; see
    /// [`RelaySafetyPolicy::retain_safe_endpoints`]. What survives is still
    /// sanitized at the dial chokepoint.
    pub(crate) fn retain_safe_discovered_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Vec<TransportEndpoint> {
        self.inner
            .relay_safety
            .retain_safe_endpoints(endpoints, context)
    }

    pub(crate) fn subscribe_directory_events(
        &self,
    ) -> broadcast::Receiver<DirectoryRelayPlaneEvent> {
        self.inner.transport.directory_events.subscribe()
    }

    pub(crate) async fn sync_directory_user_subscriptions(
        &self,
        plan: DirectorySyncPlan,
        force_rebuild: bool,
    ) -> Result<DirectorySubscriptionSyncSummary, String> {
        let _sync_guard = self.inner.directory_subscription_sync.lock().await;
        self.spawn_router();
        let endpoints = self
            .inner
            .relay_safety
            .sanitize_endpoints(plan.endpoints, "directory subscription")?;
        if plan.batches.is_empty() || endpoints.is_empty() {
            if let Some(client) = &self.inner.transport.directory_client {
                let (_, stale) = self
                    .inner
                    .directory
                    .subscription_diff(&HashSet::new())
                    .await;
                for subscription_id in stale {
                    client
                        .unsubscribe(&SubscriptionId::new(subscription_id))
                        .await
                        .map_err(|_| "directory unsubscribe failed".to_owned())?;
                }
            }
            return self
                .inner
                .directory
                .replace_subscriptions(HashMap::new())
                .await;
        }
        let directory_client = self
            .inner
            .transport
            .directory_client
            .as_ref()
            .ok_or_else(|| "directory subscription requires SDK relay plane".to_owned())?;
        let relay_urls = endpoints
            .iter()
            .map(|endpoint| {
                RelayUrl::parse(endpoint.as_str())
                    .map_err(|_| "directory subscription: invalid relay endpoint".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        for relay_url in &relay_urls {
            directory_client
                .add_relay(relay_url.clone())
                .await
                .map_err(|_| "directory subscription add relay failed".to_owned())?;
            timeout(
                DIRECTORY_RELAY_CONNECT_WAIT,
                directory_client.connect_relay(relay_url.clone()),
            )
            .await
            .map_err(|_| "directory subscription connect relay timed out".to_owned())?
            .map_err(|_| "directory subscription connect relay failed".to_owned())?;
        }
        let endpoints_changed = self
            .inner
            .directory
            .set_subscription_endpoints(&relay_urls)
            .await;

        let desired_ids = plan
            .batches
            .iter()
            .map(|batch| batch.subscription_id.clone())
            .collect::<HashSet<_>>();
        let (mut to_add, to_remove) = self.inner.directory.subscription_diff(&desired_ids).await;
        if force_rebuild || endpoints_changed {
            to_add = desired_ids;
            self.inner.directory.mark_rebuild_pending(&to_add).await;
        }
        for subscription_id in &to_remove {
            directory_client
                .unsubscribe(&SubscriptionId::new(subscription_id.clone()))
                .await
                .map_err(|_| "directory unsubscribe failed".to_owned())?;
        }
        if force_rebuild || endpoints_changed {
            for subscription_id in &to_add {
                directory_client
                    .unsubscribe(&SubscriptionId::new(subscription_id.clone()))
                    .await
                    .map_err(|_| "directory unsubscribe failed".to_owned())?;
            }
        }
        // The validation filter persisted for every batch (added or already
        // active) is keyed on the same canonical-hex authors and kinds the SDK
        // subscription is issued with, so a live notification is only forwarded
        // into the directory cache when it matches an active subscription's
        // requested authors and kinds (mdk#709).
        let mut desired = HashMap::with_capacity(plan.batches.len());
        let mut subscriptions_created = 0;
        for batch in &plan.batches {
            let authors = batch
                .authors
                .iter()
                .map(|author| PublicKey::parse(author).map_err(|_| "invalid directory author"))
                .collect::<Result<Vec<_>, _>>()?;
            let kinds = batch
                .kinds
                .iter()
                .map(|kind| {
                    u16::try_from(*kind)
                        .map(Kind::from)
                        .map_err(|_| format!("unsupported Nostr kind {kind}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            // Canonical lowercase hex matches the `event.pubkey` form a forwarded
            // SDK event carries, so the membership check is exact.
            let filter_authors = authors.iter().map(PublicKey::to_hex).collect::<Vec<_>>();
            let validation_filter =
                DirectorySubscriptionFilter::new(filter_authors, batch.kinds.clone());
            desired.insert(batch.subscription_id.clone(), validation_filter.clone());
            if !to_add.contains(&batch.subscription_id) {
                continue;
            }
            self.inner
                .directory
                .clear_auth_required(&batch.subscription_id)
                .await;
            let mut filter = Filter::new()
                .authors(authors)
                .kinds(kinds)
                .limit(batch.authors.len().saturating_mul(batch.kinds.len()).max(1));
            if let Some(since) = batch.since {
                filter = filter.since(NostrTimestamp::from_secs(since));
            }
            let previous = self
                .inner
                .directory
                .record_subscription_filter(batch.subscription_id.clone(), validation_filter)
                .await;
            let subscription = directory_client
                .subscribe(nostr_sdk::prelude::ReqTarget::manual(
                    relay_urls
                        .iter()
                        .cloned()
                        .map(|url| (url, vec![filter.clone()])),
                ))
                .with_id(SubscriptionId::new(batch.subscription_id.clone()))
                .await;
            if !subscription.is_ok_and(|output| !output.success.is_empty()) {
                self.inner
                    .directory
                    .restore_failed_subscription_filter(&batch.subscription_id, previous)
                    .await;
                return Err("directory subscription registered on no relays".to_owned());
            }
            subscriptions_created += usize::from(previous.is_none());
            self.inner
                .directory
                .mark_subscription_installed(&batch.subscription_id)
                .await;
        }

        self.inner
            .directory
            .complete_subscription_sync(desired, subscriptions_created)
            .await
    }

    pub async fn shutdown(&self) {
        self.inner
            .transport
            .shutting_down
            .store(true, Ordering::SeqCst);
        if let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client {
            let _ = timeout(
                RELAY_PLANE_SHUTDOWN_WAIT,
                sdk_relay_client.shutdown_accounts(),
            )
            .await;
            let timed_out = timeout(
                RELAY_PLANE_SHUTDOWN_WAIT,
                sdk_relay_client.client().shutdown(),
            )
            .await
            .is_err();
            if timed_out {
                tracing::warn!(
                    target: "marmot_app::relay_plane",
                    method = "shutdown",
                    "SDK relay pool shutdown timed out",
                );
            }
        }
        if let Some(directory_client) = &self.inner.transport.directory_client {
            let _ = timeout(RELAY_PLANE_SHUTDOWN_WAIT, directory_client.shutdown()).await;
        }
        account_deliveries_write(&self.inner.transport.account_deliveries).clear();
        if let Some(handle) = self.inner.transport.router.lock().await.take() {
            let mut handle = handle;
            handle.abort();
            let _ = timeout(RELAY_PLANE_TASK_ABORT_WAIT, &mut handle).await;
        }
        if let Some(handle) = self
            .inner
            .transport
            .notification_forwarder
            .lock()
            .await
            .take()
        {
            let mut handle = handle;
            handle.abort();
            let _ = timeout(RELAY_PLANE_TASK_ABORT_WAIT, &mut handle).await;
        }
        let account_forwarders = self
            .inner
            .transport
            .account_notification_forwarders
            .lock()
            .await
            .drain()
            .map(|(_, handle)| handle)
            .collect::<Vec<_>>();
        for mut handle in account_forwarders {
            handle.abort();
            let _ = timeout(RELAY_PLANE_TASK_ABORT_WAIT, &mut handle).await;
        }
        if let Some(handle) = self
            .inner
            .transport
            .directory_notification_forwarder
            .lock()
            .await
            .take()
        {
            let mut handle = handle;
            handle.abort();
            let _ = timeout(RELAY_PLANE_TASK_ABORT_WAIT, &mut handle).await;
        }
        self.inner
            .transport
            .notification_forwarder_health
            .running_count
            .store(0, Ordering::SeqCst);
    }

    fn spawn_router(&self) {
        if self.inner.transport.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if let Ok(mut notification_forwarder) =
            self.inner.transport.notification_forwarder.try_lock()
        {
            let needs_forwarder = match notification_forwarder.as_ref() {
                None => true,
                Some(forwarder) => forwarder.is_finished(),
            };
            if needs_forwarder
                && let Some(sdk_relay_client) = &self.inner.transport.sdk_relay_client
                && !sdk_relay_client.is_multi_account()
            {
                if sdk_relay_client.client().is_shutdown() {
                    notification_forwarder.take();
                } else {
                    if notification_forwarder.take().is_some() {
                        recover_relay_notification_forwarder(
                            &self.inner.transport,
                            RelayNotificationConsumerExit::Closed,
                        );
                    }
                    *notification_forwarder = Some(spawn_relay_notification_forwarder(
                        sdk_relay_client.clone(),
                        self.inner.transport.clone(),
                    ));
                }
            }
        }
        if let Ok(mut forwarder) = self
            .inner
            .transport
            .directory_notification_forwarder
            .try_lock()
            && forwarder.as_ref().is_none_or(JoinHandle::is_finished)
            && let Some(client) = &self.inner.transport.directory_client
            && !client.is_shutdown()
        {
            if forwarder.take().is_some() {
                let _ = self
                    .inner
                    .transport
                    .directory_events
                    .send(DirectoryRelayPlaneEvent::RecoveryRequired);
            }
            *forwarder = Some(spawn_directory_notification_forwarder(
                Arc::new(SdkRelayNotificationSource {
                    client: client.clone(),
                    loss: None,
                }),
                self.inner.transport.directory_events.clone(),
                self.inner.directory.clone(),
            ));
        }
        let Ok(mut router) = self.inner.transport.router.try_lock() else {
            return;
        };
        if router.is_some() {
            return;
        }
        let transport = self.inner.transport.clone();
        let adapter = transport.adapter.clone();
        let handle = handle.spawn(async move {
            while let Ok(Some(delivery)) = adapter.receive().await {
                route_account_delivery(&transport, delivery);
            }
        });
        *router = Some(handle);
    }

    #[cfg(test)]
    pub(crate) async fn handle_relay_event_for_test(
        &self,
        relay_event: transport_nostr_adapter::NostrRelayEvent,
    ) -> Result<usize, TransportAdapterError> {
        self.inner
            .transport
            .adapter
            .handle_relay_event(relay_event)
            .await
    }

    #[cfg(test)]
    pub(crate) fn set_account_delivery_recovery_marker_for_test(
        &self,
        account_id: &MemberId,
        marker: AccountDeliveryRecoveryMarker,
    ) -> bool {
        let mut routes = account_deliveries_write(&self.inner.transport.account_deliveries);
        let Some(route) = routes.get_mut(account_id) else {
            return false;
        };
        route.recovery_marker = Some(marker);
        true
    }

    /// Exercise the loss tier directly: a full queue omits instead of spilling.
    #[cfg(test)]
    pub(crate) fn disable_account_delivery_spill_for_test(&self, account_id: &MemberId) -> bool {
        let mut routes = account_deliveries_write(&self.inner.transport.account_deliveries);
        routes
            .get_mut(account_id)
            .map(|route| route.spill = None)
            .is_some()
    }

    /// Report end-of-stored-events for one subscription on one endpoint, the
    /// way [`handle_relay_notification`] does for an SDK-backed plane. An
    /// injected relay client produces no relay messages of its own, so tests
    /// that need a subscription's end of stored events drive this seam.
    #[cfg(test)]
    pub(crate) async fn handle_relay_eose_for_test(
        &self,
        endpoint: TransportEndpoint,
        subscription_id: String,
    ) {
        self.inner
            .transport
            .adapter
            .handle_relay_eose(endpoint, subscription_id)
            .await;
    }

    /// Drive every managed account worker through its receive-error reconnect
    /// path: an unexpected notification consumer exit closes inbound delivery.
    #[cfg(test)]
    pub(crate) fn simulate_notification_consumer_exit_for_test(&self) {
        recover_relay_notification_forwarder(
            &self.inner.transport,
            RelayNotificationConsumerExit::Closed,
        );
    }

    /// Record a lag on one account's notification consumer, as its scoped
    /// forwarder does with the floor its SDK context read at the lag. Inbound
    /// delivery stays open.
    #[cfg(test)]
    pub(crate) fn simulate_notification_lag_for_test(
        &self,
        account_id: &MemberId,
        skipped_notifications: u64,
        floor: NostrNotificationLossFloor,
    ) {
        recover_relay_notification_forwarder_scoped(
            &self.inner.transport,
            RelayNotificationConsumerExit::Lagged(skipped_notifications),
            floor,
            Some(account_id),
        );
    }

    /// Shorten how long a receiver must go without another lag before its
    /// lag-lost EOSE repair runs.
    #[cfg(test)]
    pub(crate) fn set_eose_repair_settle_for_test(&self, settle: Duration) {
        self.inner
            .transport
            .eose_repair_settle_ms
            .store(settle.as_millis() as u64, Ordering::Relaxed);
    }
}

impl RelayPlaneHealth {
    fn from_sdk(
        health: NostrSdkRelayHealth,
        directory: DirectoryRelayStats,
        forwarder: RelayNotificationForwarderHealthSnapshot,
        account_delivery: AccountDeliveryMetricsSnapshot,
    ) -> Self {
        Self {
            sdk_backed: true,
            total_relays: health.total_relays,
            initialized: health.initialized,
            pending: health.pending,
            connecting: health.connecting,
            connected: health.connected,
            disconnected: health.disconnected,
            terminated: health.terminated,
            banned: health.banned,
            sleeping: health.sleeping,
            connection_attempts: health.connection_attempts,
            connection_successes: health.connection_successes,
            notification_forwarder_running: forwarder.running,
            notification_forwarder_restarts: forwarder.restarts,
            notification_forwarder_lag_incidents: forwarder.lag_incidents,
            notification_forwarder_lagged_notifications: forwarder.lagged_notifications,
            notification_forwarder_panics: forwarder.panics,
            notification_forwarder_unexpected_exits: forwarder.unexpected_exits,
            account_delivery_queue_depth: account_delivery.queue_depth,
            account_delivery_max_queue_depth: account_delivery.max_queue_depth,
            account_delivery_dropped: account_delivery.dropped,
            account_delivery_spilled: account_delivery.spilled,
            account_delivery_spill_already_seen: account_delivery.spill_already_seen,
            account_delivery_recovery_attempts: account_delivery.recovery_attempts,
            account_delivery_recovery_successes: account_delivery.recovery_successes,
            account_delivery_recovery_failures: account_delivery.recovery_failures,
            account_delivery_recovery_elapsed_ms: account_delivery.recovery_elapsed_ms,
            directory_inflight_fetches: directory.inflight_fetches,
            directory_active_subscriptions: directory.active_subscriptions,
            directory_auth_required_routes: directory.auth_required_routes,
            directory_completed_fetches: directory.completed_fetches,
            directory_coalesced_waiters: directory.coalesced_waiters,
            directory_failed_fetches: directory.failed_fetches,
            directory_completed_subscription_syncs: directory.completed_subscription_syncs,
            directory_subscriptions_created: directory.subscriptions_created,
            directory_subscriptions_removed: directory.subscriptions_removed,
        }
    }

    fn from_directory(
        directory: DirectoryRelayStats,
        account_delivery: AccountDeliveryMetricsSnapshot,
    ) -> Self {
        Self {
            account_delivery_queue_depth: account_delivery.queue_depth,
            account_delivery_max_queue_depth: account_delivery.max_queue_depth,
            account_delivery_dropped: account_delivery.dropped,
            account_delivery_spilled: account_delivery.spilled,
            account_delivery_spill_already_seen: account_delivery.spill_already_seen,
            account_delivery_recovery_attempts: account_delivery.recovery_attempts,
            account_delivery_recovery_successes: account_delivery.recovery_successes,
            account_delivery_recovery_failures: account_delivery.recovery_failures,
            account_delivery_recovery_elapsed_ms: account_delivery.recovery_elapsed_ms,
            directory_inflight_fetches: directory.inflight_fetches,
            directory_active_subscriptions: directory.active_subscriptions,
            directory_auth_required_routes: directory.auth_required_routes,
            directory_completed_fetches: directory.completed_fetches,
            directory_coalesced_waiters: directory.coalesced_waiters,
            directory_failed_fetches: directory.failed_fetches,
            directory_completed_subscription_syncs: directory.completed_subscription_syncs,
            directory_subscriptions_created: directory.subscriptions_created,
            directory_subscriptions_removed: directory.subscriptions_removed,
            ..Self::default()
        }
    }
}

impl RelayNotificationForwarderHealth {
    fn snapshot(&self) -> RelayNotificationForwarderHealthSnapshot {
        RelayNotificationForwarderHealthSnapshot {
            running: self.running_count.load(Ordering::Relaxed) > 0,
            restarts: self.restarts.load(Ordering::Relaxed),
            lag_incidents: self.lag_incidents.load(Ordering::Relaxed),
            lagged_notifications: self.lagged_notifications.load(Ordering::Relaxed),
            panics: self.panics.load(Ordering::Relaxed),
            unexpected_exits: self.unexpected_exits.load(Ordering::Relaxed),
        }
    }

    fn increment(counter: &AtomicU64, value: u64) {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(value))
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayNotificationConsumerExit {
    Shutdown,
    Lagged(u64),
    Closed,
}

type RelayNotificationStream =
    Pin<Box<dyn Stream<Item = NotificationUpdate<ClientNotification>> + Send>>;

struct RelayNotificationConsumerOutcome {
    receiver: RelayNotificationStream,
    exit: RelayNotificationConsumerExit,
    /// The source's REQ floor, read where a lag was recorded. Unbounded for
    /// every other exit.
    lag_floor: NostrNotificationLossFloor,
}

impl RelayNotificationConsumerOutcome {
    fn new(receiver: RelayNotificationStream, exit: RelayNotificationConsumerExit) -> Self {
        Self {
            receiver,
            exit,
            lag_floor: NostrNotificationLossFloor::Unbounded,
        }
    }

    /// Record `abandoned` notifications as receiver loss, reading the floor
    /// at that point.
    fn lagged(
        receiver: RelayNotificationStream,
        source: &dyn RelayNotificationSource,
        abandoned: u64,
    ) -> Self {
        Self {
            receiver,
            exit: RelayNotificationConsumerExit::Lagged(abandoned),
            lag_floor: source.record_loss(abandoned),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RelayNotificationRestartBackoff {
    next: Duration,
}

impl Default for RelayNotificationRestartBackoff {
    fn default() -> Self {
        Self {
            next: RELAY_NOTIFICATION_RESTART_INITIAL_BACKOFF,
        }
    }
}

impl RelayNotificationRestartBackoff {
    fn delay_after_failure(&mut self, consumer_runtime: Duration) -> Duration {
        if consumer_runtime >= RELAY_NOTIFICATION_RESTART_HEALTHY_RUNTIME {
            self.next = RELAY_NOTIFICATION_RESTART_INITIAL_BACKOFF;
        }
        let delay = self.next;
        self.next = self
            .next
            .saturating_mul(2)
            .min(RELAY_NOTIFICATION_RESTART_MAX_BACKOFF);
        delay
    }
}

trait RelayNotificationSource: Send + Sync {
    fn notifications(&self) -> RelayNotificationStream;
    fn is_shutdown(&self) -> bool;
    /// Record receiver loss and return the lowest REQ `since` that could have
    /// delivered the lost notifications. A source without that evidence
    /// reports it unbounded.
    fn record_loss(&self, _skipped: u64) -> NostrNotificationLossFloor {
        NostrNotificationLossFloor::Unbounded
    }
    fn receiver_replaced(&self) {}
    #[cfg(test)]
    fn worker_failure_hook(&self) -> Option<Arc<NotificationWorkerFailureHook>> {
        None
    }
    #[cfg(test)]
    fn notification_queued(&self) {}
}

#[cfg(test)]
struct NotificationWorkerFailureHook {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    fail_once: AtomicBool,
    /// Hold the first notification like `fail_once`, then handle it normally:
    /// a busy, not failed, event worker.
    stall_once: AtomicBool,
}

struct SdkRelayNotificationSource {
    client: NostrSdkClient,
    loss: Option<NostrSdkRelayClient>,
}

impl RelayNotificationSource for SdkRelayNotificationSource {
    fn notifications(&self) -> RelayNotificationStream {
        self.client.notifications_with_gaps()
    }

    fn is_shutdown(&self) -> bool {
        self.client.is_shutdown()
    }

    fn record_loss(&self, skipped: u64) -> NostrNotificationLossFloor {
        let Some(loss) = &self.loss else {
            return NostrNotificationLossFloor::Unbounded;
        };
        loss.record_notification_gap(skipped);
        // Read at the lag: a later subscription change could raise it past
        // an event this gap lost.
        loss.notification_loss_floor()
    }

    fn receiver_replaced(&self) {
        if let Some(loss) = &self.loss {
            loss.notification_receiver_replaced();
        }
    }
}

fn spawn_relay_notification_forwarder(
    sdk_relay_client: NostrSdkRelayClient,
    transport: Arc<RelayPlaneTransport>,
) -> JoinHandle<()> {
    spawn_relay_notification_forwarder_scoped(sdk_relay_client, transport, None)
}

fn spawn_relay_notification_forwarder_scoped(
    sdk_relay_client: NostrSdkRelayClient,
    transport: Arc<RelayPlaneTransport>,
    account_id: Option<MemberId>,
) -> JoinHandle<()> {
    let source: Arc<dyn RelayNotificationSource> = Arc::new(SdkRelayNotificationSource {
        client: sdk_relay_client.client().clone(),
        loss: Some(sdk_relay_client),
    });
    spawn_relay_notification_supervisor_scoped(source, transport, account_id)
}

/// Public directory interests have their own unauthenticated SDK client and
/// receiver. A gap here invalidates directory coverage without interrupting
/// an account's live delivery or attributing the loss to an account.
fn spawn_directory_notification_forwarder(
    source: Arc<dyn RelayNotificationSource>,
    events: broadcast::Sender<DirectoryRelayPlaneEvent>,
    directory: DirectoryRelayPlane,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut receiver = source.notifications();
        loop {
            match receiver.next().await {
                Some(NotificationUpdate::Notification(ClientNotification::Event {
                    relay_url,
                    subscription_id,
                    event,
                })) => {
                    let subscription_id = subscription_id.to_string();
                    if let Ok(event) = NostrTransportEvent::from_nostr_event(&event)
                        && directory
                            .accepts_live_event_from(
                                &subscription_id,
                                relay_url.as_str(),
                                &event.pubkey,
                                event.kind,
                            )
                            .await
                    {
                        let _ = events.send(DirectoryRelayPlaneEvent::Record(
                            DirectoryRelayEventRecord {
                                endpoints: vec![TransportEndpoint(relay_url.to_string())],
                                event,
                            },
                        ));
                    }
                }
                Some(NotificationUpdate::Notification(ClientNotification::Message {
                    relay_url,
                    message,
                })) => {
                    if let RelayMessage::Closed {
                        subscription_id,
                        message,
                    } = *message
                        && message.starts_with("auth-required:")
                        && directory
                            .mark_auth_required(subscription_id.as_str(), relay_url.as_str())
                            .await
                    {
                        let count = directory.stats().await.auth_required_routes;
                        tracing::warn!(
                            target: "marmot_app::relay_plane",
                            method = "spawn_directory_notification_forwarder",
                            auth_required_routes = count,
                            "anonymous directory request requires authentication",
                        );
                    }
                }
                Some(NotificationUpdate::Notification(ClientNotification::Shutdown)) => break,
                Some(NotificationUpdate::Lagged { skipped }) => {
                    tracing::warn!(
                        target: "marmot_app::relay_plane",
                        method = "spawn_directory_notification_forwarder",
                        skipped_notifications = skipped,
                        "directory SDK receiver lost notifications",
                    );
                    let _ = events.send(DirectoryRelayPlaneEvent::RecoveryRequired);
                }
                None => {
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
fn spawn_relay_notification_supervisor(
    source: Arc<dyn RelayNotificationSource>,
    transport: Arc<RelayPlaneTransport>,
) -> JoinHandle<()> {
    spawn_relay_notification_supervisor_scoped(source, transport, None)
}

fn spawn_relay_notification_supervisor_scoped(
    source: Arc<dyn RelayNotificationSource>,
    transport: Arc<RelayPlaneTransport>,
    account_id: Option<MemberId>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _running = RunningSupervisorGuard::new(transport.notification_forwarder_health.clone());
        let mut receiver = None;
        let mut restart_backoff = RelayNotificationRestartBackoff::default();
        loop {
            let adapter = transport.adapter.clone();
            let source_for_consumer = source.clone();
            let next_receiver = receiver.take();
            let consumer_started_at = Instant::now();
            if next_receiver.is_none() {
                source.receiver_replaced();
            }
            let consumer_account_id = account_id.clone();
            let mut consumer = tokio::spawn(async move {
                let receiver = next_receiver.unwrap_or_else(|| source_for_consumer.notifications());
                run_relay_notification_consumer_scoped(
                    receiver,
                    adapter,
                    consumer_account_id,
                    source_for_consumer,
                )
                .await
            });
            let abort_on_drop = AbortTaskOnDrop(consumer.abort_handle());
            match (&mut consumer).await {
                Ok(outcome) => {
                    drop(abort_on_drop);
                    receiver = Some(outcome.receiver);
                    if outcome.exit == RelayNotificationConsumerExit::Shutdown
                        || transport.shutting_down.load(Ordering::SeqCst)
                        || source.is_shutdown()
                    {
                        if matches!(outcome.exit, RelayNotificationConsumerExit::Lagged(_)) {
                            recover_relay_notification_forwarder_scoped(
                                &transport,
                                outcome.exit,
                                outcome.lag_floor,
                                account_id.as_ref(),
                            );
                        }
                        break;
                    }
                    // A lag resumes the retained receiver at once; only an
                    // unexpected exit replaces it after a backoff.
                    recover_relay_notification_forwarder_scoped(
                        &transport,
                        outcome.exit,
                        outcome.lag_floor,
                        account_id.as_ref(),
                    );
                    if outcome.exit == RelayNotificationConsumerExit::Closed {
                        receiver = None;
                        tokio::time::sleep(
                            restart_backoff.delay_after_failure(consumer_started_at.elapsed()),
                        )
                        .await;
                    }
                }
                Err(join_error) => {
                    drop(abort_on_drop);
                    if transport.shutting_down.load(Ordering::SeqCst) || source.is_shutdown() {
                        break;
                    }
                    RelayNotificationForwarderHealth::increment(
                        &transport.notification_forwarder_health.panics,
                        u64::from(join_error.is_panic()),
                    );
                    receiver = None;
                    recover_relay_notification_forwarder_scoped(
                        &transport,
                        RelayNotificationConsumerExit::Closed,
                        NostrNotificationLossFloor::Unbounded,
                        account_id.as_ref(),
                    );
                    tokio::time::sleep(
                        restart_backoff.delay_after_failure(consumer_started_at.elapsed()),
                    )
                    .await;
                }
            }
        }
    })
}

struct RunningSupervisorGuard(Arc<RelayNotificationForwarderHealth>);

impl RunningSupervisorGuard {
    fn new(health: Arc<RelayNotificationForwarderHealth>) -> Self {
        health.running_count.fetch_add(1, Ordering::SeqCst);
        Self(health)
    }
}

impl Drop for RunningSupervisorGuard {
    fn drop(&mut self) {
        // Terminal shutdown may already have reset the aggregate to zero.
        let _ = self
            .0
            .running_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                Some(count.saturating_sub(1))
            });
    }
}

struct AbortTaskOnDrop(tokio::task::AbortHandle);

impl Drop for AbortTaskOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
async fn run_relay_notification_consumer(
    mut receiver: RelayNotificationStream,
    adapter: NostrTransportAdapter,
) -> RelayNotificationConsumerOutcome {
    loop {
        match receiver.next().await {
            Some(NotificationUpdate::Notification(notification)) => {
                let should_shutdown = handle_relay_notification(notification, &adapter, None).await;
                if should_shutdown {
                    return RelayNotificationConsumerOutcome::new(
                        receiver,
                        RelayNotificationConsumerExit::Shutdown,
                    );
                }
            }
            Some(NotificationUpdate::Lagged { skipped }) => {
                return RelayNotificationConsumerOutcome::new(
                    receiver,
                    RelayNotificationConsumerExit::Lagged(skipped),
                );
            }
            None => {
                return RelayNotificationConsumerOutcome::new(
                    receiver,
                    RelayNotificationConsumerExit::Closed,
                );
            }
        }
    }
}

/// Keep reading the SDK receiver while account delivery or telemetry awaits.
/// The bounded queue is an event lane; a full queue becomes a typed gap before
/// the reader can block, and the watch control lane advances independently.
fn abandoned_notification_lane(
    receiver: RelayNotificationStream,
    pending: &AtomicU64,
    source: &dyn RelayNotificationSource,
) -> RelayNotificationConsumerOutcome {
    let abandoned = pending.load(Ordering::SeqCst);
    if abandoned > 0 {
        RelayNotificationConsumerOutcome::lagged(receiver, source, abandoned)
    } else {
        RelayNotificationConsumerOutcome::new(receiver, RelayNotificationConsumerExit::Closed)
    }
}

async fn run_relay_notification_consumer_scoped(
    mut receiver: RelayNotificationStream,
    adapter: NostrTransportAdapter,
    account_id: Option<MemberId>,
    source: Arc<dyn RelayNotificationSource>,
) -> RelayNotificationConsumerOutcome {
    let (sender, mut event_rx) = mpsc::channel(RELAY_NOTIFICATION_EVENT_QUEUE_CAPACITY);
    // Channel capacity returns to its maximum when a panicked worker drops
    // the receiver, even though queued work was discarded. Count admitted
    // items independently until each worker operation actually finishes.
    let pending = Arc::new(AtomicU64::new(0));
    let worker_pending = pending.clone();
    #[cfg(test)]
    let worker_failure_hook = source.worker_failure_hook();
    let mut worker = tokio::spawn(async move {
        while let Some(notification) = event_rx.recv().await {
            #[cfg(test)]
            if let Some(hook) = &worker_failure_hook {
                let fail = hook.fail_once.swap(false, Ordering::SeqCst);
                if fail || hook.stall_once.swap(false, Ordering::SeqCst) {
                    hook.entered.notify_one();
                    hook.release.notified().await;
                    if fail {
                        panic!("injected relay notification worker failure");
                    }
                }
            }
            if handle_relay_notification(notification, &adapter, account_id.as_ref()).await {
                worker_pending.fetch_sub(1, Ordering::SeqCst);
                return true;
            }
            worker_pending.fetch_sub(1, Ordering::SeqCst);
        }
        false
    });
    let abort_on_drop = AbortTaskOnDrop(worker.abort_handle());
    loop {
        tokio::select! {
            worker_result = &mut worker => {
                drop(abort_on_drop);
                let mut outcome = abandoned_notification_lane(receiver, &pending, source.as_ref());
                if outcome.exit == RelayNotificationConsumerExit::Closed
                    && matches!(worker_result, Ok(true))
                {
                    outcome.exit = RelayNotificationConsumerExit::Shutdown;
                }
                return outcome;
            }
            update = receiver.next() => match update {
                Some(NotificationUpdate::Notification(notification)) => {
                    if matches!(notification, ClientNotification::Shutdown) {
                        let abandoned = pending.load(Ordering::SeqCst);
                        return if abandoned > 0 {
                            RelayNotificationConsumerOutcome::lagged(
                                receiver,
                                source.as_ref(),
                                abandoned,
                            )
                        } else {
                            RelayNotificationConsumerOutcome::new(
                                receiver,
                                RelayNotificationConsumerExit::Shutdown,
                            )
                        };
                    }
                    pending.fetch_add(1, Ordering::SeqCst);
                    if let Err(error) = sender.try_send(notification) {
                        pending.fetch_sub(1, Ordering::SeqCst);
                        let skipped = match error {
                            mpsc::error::TrySendError::Full(_) => {
                                1 + pending.load(Ordering::SeqCst)
                            }
                            mpsc::error::TrySendError::Closed(_) => 1,
                        };
                        return RelayNotificationConsumerOutcome::lagged(
                            receiver,
                            source.as_ref(),
                            skipped,
                        );
                    }
                    #[cfg(test)]
                    source.notification_queued();
                }
                Some(NotificationUpdate::Lagged { skipped }) => {
                    let abandoned = skipped
                        .saturating_add(pending.load(Ordering::SeqCst));
                    return RelayNotificationConsumerOutcome::lagged(
                        receiver,
                        source.as_ref(),
                        abandoned,
                    );
                }
                None => {
                    let abandoned = pending.load(Ordering::SeqCst);
                    return if abandoned > 0 {
                        RelayNotificationConsumerOutcome::lagged(
                            receiver,
                            source.as_ref(),
                            abandoned,
                        )
                    } else {
                        RelayNotificationConsumerOutcome::new(
                            receiver,
                            RelayNotificationConsumerExit::Closed,
                        )
                    };
                }
            }
        }
    }
}

async fn handle_relay_notification(
    notification: ClientNotification,
    adapter: &NostrTransportAdapter,
    account_id: Option<&MemberId>,
) -> bool {
    match notification {
        ClientNotification::Event {
            relay_url,
            subscription_id,
            event,
        } => {
            if let Ok(event) = NostrTransportEvent::from_nostr_event(&event) {
                tracing::trace!(
                    target: "marmot_app::relay_plane",
                    method = "handle_relay_notification",
                    "forwarding SDK relay event"
                );
                let endpoint = TransportEndpoint(relay_url.to_string());
                let subscription_id = subscription_id.to_string();
                let relay_event = transport_nostr_adapter::NostrRelayEvent {
                    endpoint,
                    subscription_id: Some(subscription_id),
                    event,
                };
                // Account notifications feed only account/group delivery.
                // Public directory interests use the anonymous receiver.
                let _ = if let Some(account_id) = account_id {
                    adapter
                        .handle_reconciled_event(account_id, relay_event)
                        .await
                } else {
                    adapter.handle_relay_event(relay_event).await
                };
            }
            false
        }
        ClientNotification::Message { relay_url, message } => {
            match *message {
                RelayMessage::Event {
                    subscription_id,
                    event,
                } => {
                    // Raw per-relay copy is telemetry only. Delivery uses the
                    // deduplicated Event notification above.
                    if let Ok(event) = NostrTransportEvent::from_nostr_event(&event) {
                        adapter
                            .observe_relay_event(transport_nostr_adapter::NostrRelayEvent {
                                endpoint: TransportEndpoint(relay_url.to_string()),
                                subscription_id: Some(subscription_id.to_string()),
                                event,
                            })
                            .await;
                    }
                }
                RelayMessage::EndOfStoredEvents(subscription_id) => {
                    adapter
                        .handle_relay_eose(
                            TransportEndpoint(relay_url.to_string()),
                            subscription_id.to_string(),
                        )
                        .await;
                }
                _ => {}
            }
            false
        }
        ClientNotification::Shutdown => {
            tracing::debug!(
                target: "marmot_app::relay_plane",
                method = "handle_relay_notification",
                "SDK relay pool shutdown observed"
            );
            true
        }
    }
}

fn recover_relay_notification_forwarder(
    transport: &Arc<RelayPlaneTransport>,
    exit: RelayNotificationConsumerExit,
) {
    recover_relay_notification_forwarder_scoped(
        transport,
        exit,
        NostrNotificationLossFloor::Unbounded,
        None,
    );
}

/// Record a consumer lag, or close account delivery after an unexpected
/// consumer exit. `lag_floor` is the source's REQ floor read at the lag.
fn recover_relay_notification_forwarder_scoped(
    transport: &Arc<RelayPlaneTransport>,
    exit: RelayNotificationConsumerExit,
    lag_floor: NostrNotificationLossFloor,
    account_id: Option<&MemberId>,
) {
    let account_count = match account_id {
        Some(account_id) => usize::from(
            account_deliveries_read(&transport.account_deliveries).contains_key(account_id),
        ),
        None => account_deliveries_read(&transport.account_deliveries).len(),
    };
    match exit {
        RelayNotificationConsumerExit::Lagged(skipped) => {
            // The live subscriptions did not fail; only this consumer fell
            // behind, and it resumes on the same receiver. Keep every route
            // open and charge the loss to each account's current generation.
            // A shared receiver's floor cannot be attributed to one account.
            let floor = if account_id.is_some() {
                lag_floor
            } else {
                NostrNotificationLossFloor::Unbounded
            };
            let routes = account_deliveries_read(&transport.account_deliveries);
            for (route_account_id, route) in routes.iter() {
                if account_id.is_some_and(|account_id| account_id != route_account_id) {
                    continue;
                }
                // A queued or deferred control record already carries this
                // generation, and the worker persists the lag without one.
                if let Some(generation) = route.overflow.record_notification_loss(floor) {
                    enqueue_account_delivery_overflow_signal(
                        &route.sender,
                        &route.overflow,
                        generation,
                    );
                }
            }
            drop(routes);
            // The lag may also have lost end-of-stored-events. It cannot tell
            // which, so it repairs coverage rather than marking any complete.
            schedule_eose_repair(
                transport,
                account_id,
                transport.adapter.notification_lag_mark(),
            );
            let health = &transport.notification_forwarder_health;
            RelayNotificationForwarderHealth::increment(&health.restarts, 1);
            RelayNotificationForwarderHealth::increment(&health.lag_incidents, 1);
            RelayNotificationForwarderHealth::increment(&health.lagged_notifications, skipped);
            tracing::warn!(
                target: "marmot_app::relay_plane",
                method = "recover_relay_notification_forwarder",
                skipped_notifications = skipped,
                affected_accounts = account_count,
                bounded = floor.since_seconds().is_some(),
                "relay notification consumer lagged; recording notification loss for comparison recovery",
            );
        }
        RelayNotificationConsumerExit::Closed => {
            // The receiver itself is gone. Latch account-local evidence before
            // closing receivers, and keep each loss handle in the account
            // registry so replacement adapters inherit the fence; the shared
            // router never awaits account database I/O.
            let mut routes = account_deliveries_write(&transport.account_deliveries);
            for (route_account_id, route) in routes.iter_mut() {
                if account_id.is_some_and(|account_id| account_id != route_account_id) {
                    continue;
                }
                // A queued control record dies with the closed queue. The
                // account worker persists pending loss before returning the
                // close signal.
                let generation = route
                    .overflow
                    .inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .generation;
                route.overflow.cancel_signal(generation);
                let (closed_sender, closed_receiver) = mpsc::channel(1);
                drop(closed_receiver);
                route.sender = closed_sender;
            }
            drop(routes);
            let health = &transport.notification_forwarder_health;
            RelayNotificationForwarderHealth::increment(&health.restarts, 1);
            RelayNotificationForwarderHealth::increment(&health.unexpected_exits, 1);
            tracing::warn!(
                target: "marmot_app::relay_plane",
                method = "recover_relay_notification_forwarder",
                affected_accounts = account_count,
                "relay notification consumer exited unexpectedly; restarting inbound delivery",
            );
        }
        RelayNotificationConsumerExit::Shutdown => {}
    }
}

/// Schedule a repair of the end-of-stored-events a lag on this receiver may
/// have lost, for the REQs issued by `lag`. `account_id` is the lagging
/// receiver's account, or `None` for a receiver shared across accounts. The
/// repair runs once the receiver has gone
/// [`NOTIFICATION_LAG_EOSE_REPAIR_SETTLE`] without another lag. A later lag in
/// the same scope postpones it and widens it to the REQs issued by then. A
/// repair that leaves relays unrepaired schedules itself again the same way.
fn schedule_eose_repair(
    transport: &Arc<RelayPlaneTransport>,
    account_id: Option<&MemberId>,
    lag: NotificationLagMark,
) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let settle = Duration::from_millis(transport.eose_repair_settle_ms.load(Ordering::Relaxed));
    let due = tokio::time::Instant::now() + settle;
    let scope = account_id.cloned();
    let mut repairs = transport
        .eose_repairs
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(pending) = repairs.get_mut(&scope) {
        pending.due = due;
        pending.lag = pending.lag.max(lag);
        return;
    }
    repairs.insert(scope.clone(), EoseRepairSchedule { due, lag });
    drop(repairs);
    runtime.spawn(run_eose_repair(Arc::downgrade(transport), scope));
}

/// Wait until a scheduled repair is due, then repair each REQ of its scope
/// that a relay has not answered with end-of-stored-events. Holds the plane
/// only weakly, so it never keeps a shut-down plane alive.
async fn run_eose_repair(transport: Weak<RelayPlaneTransport>, scope: Option<MemberId>) {
    let (transport, lag) = loop {
        let due = {
            let Some(transport) = transport.upgrade() else {
                return;
            };
            let repairs = transport
                .eose_repairs
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(pending) = repairs.get(&scope) else {
                return;
            };
            pending.due
        };
        tokio::time::sleep_until(due).await;
        let Some(transport) = transport.upgrade() else {
            return;
        };
        let lag = {
            let mut repairs = transport
                .eose_repairs
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match repairs.get(&scope) {
                Some(pending) if pending.due <= tokio::time::Instant::now() => {
                    repairs.remove(&scope).map(|pending| pending.lag)
                }
                // A later lag postponed it.
                Some(_) => None,
                None => return,
            }
        };
        if let Some(lag) = lag {
            break (transport, lag);
        }
    };
    if transport.shutting_down.load(Ordering::SeqCst) {
        return;
    }
    // The repair may wait for the subscription lifecycle lock.
    let adapter = transport.adapter.clone();
    let weak = Arc::downgrade(&transport);
    drop(transport);
    let summary = adapter
        .reissue_subscriptions_awaiting_eose(scope.as_ref(), lag)
        .await;
    tracing::info!(
        target: "marmot_app::relay_plane",
        method = "repair_lag_lost_eose",
        awaiting_relays = summary.awaiting_relays,
        complete_relays = summary.complete_relays,
        reissued_relays = summary.reissued_relays,
        failed_relays = summary.failed_relays,
        "repaired subscriptions whose end-of-stored-events a notification lag may have lost",
    );
    let unrepaired = summary.failed_relays;
    if unrepaired == 0 {
        return;
    }
    // Each unrepaired relay's claim was released. A relay that keeps failing
    // is tried again at most once per settle window, while a re-issue that
    // went out keeps its claim, so a replay that lags again cannot loop.
    let Some(transport) = weak.upgrade() else {
        return;
    };
    if transport.shutting_down.load(Ordering::SeqCst) {
        return;
    }
    tracing::info!(
        target: "marmot_app::relay_plane",
        method = "repair_lag_lost_eose",
        unrepaired_relays = unrepaired,
        "scheduling another lag-lost end-of-stored-events repair",
    );
    schedule_eose_repair(&transport, scope.as_ref(), lag);
}

impl MarmotRelayPlaneAccountAdapter {
    /// Explicit catch-up must reissue even settled, matching subscriptions.
    /// Cancellation leaves reuse disabled until an activation succeeds.
    pub(crate) async fn require_fresh_activation(&self) {
        *self.incremental_activation.lock().await = None;
    }

    /// The account this adapter is bound to — the `MemberId` every subscription
    /// issued through it carries (activation and group sync reject any other
    /// id), and the key its registrations bucket under on the shared relay
    /// plane. Draining the `subscription_rebuild` row uses this so a rebuild is
    /// attributed to exactly the account whose subscribes produced it.
    pub(crate) fn account_id(&self) -> &MemberId {
        &self.account_id
    }

    /// Read only the live activation ordinal for worker-owned comparison
    /// admission. An SDK connection generation is a different lifetime.
    pub(crate) async fn account_subscription_attempt(&self) -> Option<SubscriptionAttempt> {
        self.relay_plane
            .inner
            .transport
            .adapter
            .account_subscription_attempt(&self.account_id)
            .await
    }

    pub(crate) async fn reconcile_inbox_history(
        &self,
        endpoints: Vec<TransportEndpoint>,
        local_items: &[NostrReconciliationItem],
        reconcile_since: u64,
        reconcile_until: u64,
        progress: &dyn transport_nostr_adapter::NostrReconciliationProgress,
    ) -> Result<
        Option<(
            NostrReconciliationSummary,
            Vec<transport_nostr_adapter::NostrRelayEvent>,
        )>,
        TransportAdapterError,
    > {
        let Some(client) = &self.relay_plane.inner.transport.sdk_relay_client else {
            return Ok(None);
        };
        let activation = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_activation(TransportAccountActivation {
                account_id: self.account_id.clone(),
                inbox_endpoints: endpoints,
                group_subscriptions: Vec::new(),
                since: None,
            })
            .map_err(TransportAdapterError::Subscription)?;
        let result = client
            .reconcile_subscription(
                NostrSubscription::AccountInbox {
                    account_id: self.account_id.clone(),
                    endpoints: activation.inbox_endpoints,
                    since: None,
                    // A one-shot reconciliation REQ is not owned by an account
                    // activation and never feeds the replay-coverage gate.
                    attempt: SubscriptionAttempt::INITIAL,
                },
                local_items,
                reconcile_since,
                reconcile_until,
                progress,
            )
            .await;
        let metric = result
            .as_ref()
            .map(|(summary, _)| summary.clone())
            .unwrap_or_default();
        self.relay_plane
            .inner
            .transport
            .adapter
            .record_reconciliation(&metric)
            .await;
        Ok(Some(result?))
    }

    pub(crate) async fn reconcile_group_history(
        &self,
        group: TransportGroupSubscription,
        local_items: &[NostrReconciliationItem],
        reconcile_since: u64,
        reconcile_until: u64,
        progress: &dyn transport_nostr_adapter::NostrReconciliationProgress,
    ) -> Result<
        Option<(
            NostrReconciliationSummary,
            Vec<transport_nostr_adapter::NostrRelayEvent>,
        )>,
        TransportAdapterError,
    > {
        let Some(client) = &self.relay_plane.inner.transport.sdk_relay_client else {
            return Ok(None);
        };
        let sync = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_group_sync(TransportGroupSync {
                account_id: self.account_id.clone(),
                group_subscriptions: vec![group],
                since: None,
            })
            .map_err(TransportAdapterError::Subscription)?;
        let group = sync.group_subscriptions.into_iter().next().ok_or_else(|| {
            TransportAdapterError::Subscription(
                "reconciliation group subscription was empty".to_owned(),
            )
        })?;
        let result = client
            .reconcile_subscription(
                NostrSubscription::Group {
                    account_id: self.account_id.clone(),
                    group_id: group.group_id,
                    transport_group_id: group.transport_group_id,
                    endpoints: group.endpoints,
                    since: None,
                    // A one-shot reconciliation REQ is not owned by an account
                    // activation and never feeds the replay-coverage gate.
                    attempt: SubscriptionAttempt::INITIAL,
                },
                local_items,
                reconcile_since,
                reconcile_until,
                progress,
            )
            .await;
        let metric = result
            .as_ref()
            .map(|(summary, _)| summary.clone())
            .unwrap_or_default();
        self.relay_plane
            .inner
            .transport
            .adapter
            .record_reconciliation(&metric)
            .await;
        Ok(Some(result?))
    }

    /// This account's deliveries for one owned comparison event. The worker
    /// admits them directly, never through the live queue.
    pub(crate) async fn recovered_deliveries(
        &self,
        event: transport_nostr_adapter::NostrRelayEvent,
    ) -> Result<Vec<TransportDelivery>, TransportAdapterError> {
        self.relay_plane
            .inner
            .transport
            .adapter
            .reconciled_deliveries(&self.account_id, event)
            .await
    }

    /// Install a group's post-join maintenance REQ, floored at `since` so a
    /// notification lag while it is live stays bounded. `None` requests the
    /// group's full history.
    pub(crate) async fn install_group_maintenance_subscription(
        &self,
        group: TransportGroupSubscription,
        recovery_attempt: u64,
        since: Option<Timestamp>,
    ) -> Result<String, TransportAdapterError> {
        let sync = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_group_sync(TransportGroupSync {
                account_id: self.account_id.clone(),
                group_subscriptions: vec![group],
                since: None,
            })
            .map_err(TransportAdapterError::Subscription)?;
        let group = sync.group_subscriptions.into_iter().next().ok_or_else(|| {
            TransportAdapterError::Subscription(
                "maintenance group subscription was empty".to_owned(),
            )
        })?;
        self.relay_plane
            .inner
            .transport
            .adapter
            .install_group_maintenance_recovery_subscription(
                &self.account_id,
                &group,
                recovery_attempt,
                since,
            )
            .await
    }

    pub(crate) async fn group_maintenance_any_eose(&self, subscription_id: &str) -> Option<bool> {
        self.relay_plane
            .inner
            .transport
            .adapter
            .subscription_any_eose(subscription_id)
            .await
    }

    /// Operational capability identity only; SDK presence proves neither
    /// endpoint availability nor exhaustive historical coverage.
    pub(crate) fn recovery_comparison_capability_key(&self) -> &'static [u8] {
        if self.relay_plane.inner.transport.sdk_relay_client.is_some() {
            b"sdk-bounded-comparison-v1"
        } else {
            b"no-sdk-reconciliation-v1"
        }
    }

    pub(crate) async fn group_maintenance_endpoint_eose(
        &self,
        subscription_id: &str,
        endpoint: &TransportEndpoint,
    ) -> Option<bool> {
        self.relay_plane
            .inner
            .transport
            .adapter
            .subscription_endpoint_eose(subscription_id, endpoint)
            .await
    }

    /// End-of-stored-events progress across this account activation's frozen
    /// endpoint coverage snapshot.
    ///
    /// The epoch-gap backfill drain reads this to tell a relay that has
    /// finished replaying stored history from one that has simply gone quiet.
    ///
    /// TODO(#2076): the lost-EOSE repair lands in this plane and the transport
    /// adapter. When it merges, record one account-scoped audit v5 row per
    /// repair pass at its owner seam (not per poll): relays still awaiting
    /// EOSE, relays repaired through the SDK flag, REQs re-issued, and repairs
    /// that failed, as counts only. No row kind exists for it yet; see
    /// `docs/marmot-architecture/audit-logging.md` ("Lost-EOSE repair").
    pub(crate) async fn account_subscription_eose(&self) -> AccountSubscriptionEose {
        let mut eose = self
            .relay_plane
            .inner
            .transport
            .adapter
            .account_subscription_eose(&self.account_id)
            .await;
        if self.delivery_overflow.blocks_ordinary_eose() {
            eose.with_eose = 0;
        }
        eose
    }

    pub(crate) async fn receive_account_delivery(
        &self,
    ) -> Result<Option<AccountDeliveryReceive>, TransportAdapterError> {
        let event = self.delivery_rx.lock().await.recv().await;
        Ok(event.map(|event| self.account_delivery_receive(event)))
    }

    /// The next queued item, if one is ready now.
    pub(crate) fn try_receive_account_delivery(&self) -> Option<AccountDeliveryReceive> {
        let event = self.delivery_rx.try_lock().ok()?.try_recv().ok()?;
        Some(self.account_delivery_receive(event))
    }

    /// Wait for a queued item, or for spilled rows to become durable. A
    /// pending spill wakeup wins, so a continuously ready live queue cannot
    /// hide it; it fires once per writer batch, so live input is not starved.
    pub(crate) async fn receive_account_delivery_or_spill(&self) -> AccountDeliveryWait {
        let mut delivery_rx = self.delivery_rx.lock().await;
        tokio::select! {
            biased;
            () = self.delivery_overflow.spill_ready.notified() => AccountDeliveryWait::SpillReady,
            event = delivery_rx.recv() => match event {
                Some(event) => AccountDeliveryWait::Received(self.account_delivery_receive(event)),
                None => AccountDeliveryWait::Closed,
            },
        }
    }

    fn account_delivery_receive(&self, event: AccountDeliveryEvent) -> AccountDeliveryReceive {
        match event {
            AccountDeliveryEvent::Delivery(delivery) => {
                // Taken, it still caps every commit until its consumer
                // releases it: a failed ingest's checkpoint must not pass it.
                self.delivery_overflow.take(
                    self.delivery_epoch,
                    account_delivery_restart_key(&delivery),
                    &delivery.message.id,
                );
                AccountDeliveryReceive::Delivery(delivery)
            }
            AccountDeliveryEvent::Overflow { generation } => {
                AccountDeliveryReceive::Overflow(self.delivery_overflow.consume_signal(generation))
            }
        }
    }

    fn cursor_lookback_secs(&self) -> Option<u64> {
        self.relay_plane.subscription_rebuild_lookback_secs()
    }

    /// How far a commit may promote the transport cursor, decided under the
    /// router's placement lock: at most `candidate`, and never past a
    /// delivery still queued, or taken and not yet released, that the
    /// persisted cursor still lets a restart fetch. `None` while loss or a
    /// spill hand-off is pending. The caller persists the larger of this and
    /// its current cursor. The restart floor rises here, before the commit's
    /// save runs, so a delivery that arrives during that save and falls below
    /// it is spilled rather than queued.
    pub(crate) fn seal_transport_cursor(&self, candidate: Option<u64>) -> Option<u64> {
        self.delivery_overflow.seal_cursor(
            self.delivery_epoch,
            self.cursor_lookback_secs(),
            candidate,
        )
    }

    /// The delivery of event `id` no longer needs a restart to fetch it: its
    /// ingest is durable, or its consumer dropped it on purpose, as a
    /// duplicate or as input the account keeps no trace of by design. Its
    /// consumer calls this before the save that follows, so a committed
    /// delivery never holds the cursor back. A delivery whose ingest failed
    /// is never released: it caps every commit until a redelivery of the
    /// same event is released or its queue generation ends. An event this
    /// queue holds no pin for, such as one read back from the spill, has
    /// nothing to release.
    pub(crate) fn release_account_delivery(&self, id: &MessageId) {
        self.delivery_overflow.release(self.delivery_epoch, id);
    }

    /// A sealed commit's save failed and `restored` is still the persisted
    /// cursor. Undo the floor its seal raised.
    pub(crate) fn unseal_transport_cursor(&self, restored: Option<u64>) {
        self.delivery_overflow
            .unseal_cursor(self.cursor_lookback_secs(), restored);
    }

    /// A settled commit (a drain checkpoint, settled loss or a retired
    /// notice) saved what its seal reached, so the settled floor rises to it
    /// and the router stops spilling below. `reached` is what the seal
    /// returned, not the cursor the commit persisted, which may be an earlier
    /// live promotion's. A live commit never settles.
    pub(crate) fn settle_transport_cursor(&self, reached: Option<u64>) {
        self.delivery_overflow
            .settle_cursor(self.cursor_lookback_secs(), reached, false);
    }

    /// Record the cursor the account opened with.
    pub(crate) fn open_transport_cursor(&self, persisted: Option<u64>) {
        self.delivery_overflow
            .settle_cursor(self.cursor_lookback_secs(), persisted, true);
    }

    /// Whether the account has a settled cursor floor: the one it opened
    /// with, or one a drain checkpoint, settled loss or retired notice made
    /// durable. Only the account worker settles, so this cannot change
    /// between the worker's read and its next seal.
    pub(crate) fn transport_cursor_settled(&self) -> bool {
        self.delivery_overflow
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .admission
            .settled_since
            .is_some()
    }

    /// Cumulative account-queue placement counts for the transport-cursor
    /// audit row. Relaxed counters: a reader sees a recent value, never a
    /// torn one, and the row reports differences between two reads.
    pub(crate) fn delivery_placement_counts(&self) -> AccountDeliveryPlacementCounts {
        let metrics = &self.delivery_overflow.metrics;
        AccountDeliveryPlacementCounts {
            spilled_below_floor: metrics.spill_diverted_below_floor.load(Ordering::Relaxed),
            spilled_queue_full: metrics.spill_diverted_queue_full.load(Ordering::Relaxed),
            spill_already_seen: metrics.spill_already_seen.load(Ordering::Relaxed),
            queue_dropped: metrics.dropped.load(Ordering::Relaxed),
        }
    }

    /// Process-local overflow evidence becomes visible at the exact omission,
    /// before marker I/O or the queued control record can complete.
    pub(crate) fn notification_loss_persisted(&self, observed: AccountDeliveryOverflow) {
        self.delivery_overflow.notification_persisted(observed);
    }

    /// Unacknowledged loss, or a spilled delivery that is not yet durable,
    /// keeps the transport cursor from advancing.
    pub(crate) fn delivery_loss_blocks_cursor(&self) -> bool {
        let state = self
            .delivery_overflow
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        state.pending || state.spill_in_flight > 0
    }

    pub(crate) fn unpersisted_notification_loss(&self) -> Option<AccountDeliveryOverflow> {
        let state = self
            .delivery_overflow
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        (state.pending && state.notification_losses > state.notification_imported)
            .then(|| AccountDeliveryOverflowState::snapshot(&state))
    }

    /// Whether a queued or deferred control record will still report the
    /// pending loss generation to this account's consumer.
    pub(crate) fn delivery_overflow_signal_outstanding(&self) -> bool {
        let state = self
            .delivery_overflow
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        state.pending && state.signal_queued
    }

    pub(crate) fn pending_delivery_overflow(&self) -> Option<AccountDeliveryOverflow> {
        self.delivery_overflow.pending_snapshot()
    }

    /// Begin (or resume after process restart) the recovery job required by a
    /// durable account-delivery loss marker.
    pub(crate) fn start_delivery_overflow_recovery(
        &self,
        durable_marker_token: u64,
    ) -> AccountDeliveryOverflow {
        self.delivery_overflow.start_recovery(durable_marker_token)
    }

    /// Resolve only the exact overflow prefix the replay started against. A
    /// newer omitted delivery keeps the generation pending and forces another
    /// unfloored attempt.
    pub(crate) fn finish_delivery_overflow_recovery(
        &self,
        attempt: AccountDeliveryOverflow,
    ) -> Option<u64> {
        self.delivery_overflow.finish_recovery(attempt)
    }

    pub(crate) fn restore_delivery_overflow_guard(&self, durable_marker_token: u64) {
        self.delivery_overflow
            .restore_recovery_guard(durable_marker_token);
    }

    pub(crate) fn record_delivery_overflow_recovery_success(&self, elapsed_ms: u64) {
        self.delivery_overflow.record_recovery_success(elapsed_ms);
    }

    /// The pending loss generation, including one a recovery attempt holds.
    pub(crate) fn pending_delivery_overflow_generation(&self) -> Option<AccountDeliveryOverflow> {
        self.delivery_overflow.pending_generation()
    }

    /// Release the cursor fence for loss the account owner retired, only if
    /// `observed` is still exactly the pending generation. Never counts a
    /// recovery success. Returns true when no plane loss remains pending.
    pub(crate) fn retire_delivery_overflow(
        &self,
        observed: Option<AccountDeliveryOverflow>,
    ) -> bool {
        self.delivery_overflow.retire_recovery(observed)
    }

    pub(crate) fn fail_delivery_overflow_recovery(&self) {
        self.delivery_overflow.fail_recovery();
    }

    pub(crate) async fn remove_group_maintenance_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<(), TransportAdapterError> {
        self.relay_plane
            .inner
            .transport
            .adapter
            .remove_group_maintenance_recovery_subscription(&self.account_id, subscription_id)
            .await
    }
}

#[async_trait]
impl TransportAdapter for MarmotRelayPlaneAccountAdapter {
    async fn activate_account(
        &self,
        activation: TransportAccountActivation,
    ) -> Result<(), TransportAdapterError> {
        if activation.account_id != self.account_id {
            return Err(TransportAdapterError::AccountNotActive(
                activation.account_id,
            ));
        }
        let activation = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_activation(activation)
            .map_err(TransportAdapterError::Subscription)?;
        let incremental = activation.since.map(|since| IncrementalActivation {
            inbox_endpoints: activation.inbox_endpoints.clone(),
            since,
        });
        let mut previous = self.incremental_activation.lock().await;
        let reuse = incremental.is_some()
            && *previous == incremental
            && self.account_subscription_eose().await.complete();
        // Cancellation or failure must force the next call through activation's
        // unconditional orphan-REQ cleanup. None always requests full history.
        *previous = None;
        let adapter = &self.relay_plane.inner.transport.adapter;
        if reuse {
            adapter
                .sync_account_groups(TransportGroupSync {
                    account_id: activation.account_id,
                    group_subscriptions: activation.group_subscriptions,
                    since: activation.since,
                })
                .await?;
        } else {
            adapter.activate_account(activation).await?;
        }
        *previous = incremental;
        Ok(())
    }

    async fn sync_account_groups(
        &self,
        sync: TransportGroupSync,
    ) -> Result<(), TransportAdapterError> {
        if sync.account_id != self.account_id {
            return Err(TransportAdapterError::AccountNotActive(sync.account_id));
        }
        let sync = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_group_sync(sync)
            .map_err(TransportAdapterError::Subscription)?;
        self.relay_plane
            .inner
            .transport
            .adapter
            .sync_account_groups(sync)
            .await
    }

    async fn deactivate_account(&self, account_id: &MemberId) -> Result<(), TransportAdapterError> {
        if account_id != &self.account_id {
            return Err(TransportAdapterError::AccountNotActive(account_id.clone()));
        }
        let mut activation = self.incremental_activation.lock().await;
        *activation = None;
        self.relay_plane
            .deactivate_account_context(account_id)
            .await
    }

    async fn publish(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        if request.account_id != self.account_id {
            return Err(TransportAdapterError::AccountNotActive(request.account_id));
        }
        let request = self
            .relay_plane
            .inner
            .relay_safety
            .sanitize_publish_request(request)
            .map_err(TransportAdapterError::Publish)?;
        request.validate_envelope_matches_target()?;
        let event = NostrTransportEvent::from_transport_message(&request.message)
            .map_err(|e| TransportAdapterError::Publish(format!("Nostr payload: {e}")))?;
        let outcome = self
            .relay_plane
            .inner
            .transport
            .adapter
            .publish_event_with_client(
                self.publish_client.as_ref(),
                &request.account_id,
                request.target.endpoints(),
                &event,
                request.required_acks,
            )
            .await?;
        let local_fanout_endpoints = if !outcome.accepted.is_empty() {
            outcome
                .accepted
                .iter()
                .map(|receipt| receipt.endpoint.clone())
                .collect::<Vec<_>>()
        } else if outcome.failed.is_empty() {
            request.target.endpoints().to_vec()
        } else {
            Vec::new()
        };
        if !local_fanout_endpoints.is_empty() {
            let mut local_message = request.message.clone();
            if let Some(message_id) = outcome.message_id.clone() {
                local_message.id = message_id;
            }
            self.relay_plane
                .inner
                .transport
                .adapter
                .deliver_local_publish(&local_message, &local_fanout_endpoints)
                .await?;
        }
        Ok(publish_report_from_outcome(outcome, request))
    }

    async fn receive(&self) -> Result<Option<TransportDelivery>, TransportAdapterError> {
        match self.receive_account_delivery().await? {
            Some(AccountDeliveryReceive::Delivery(delivery)) => Ok(Some(*delivery)),
            Some(AccountDeliveryReceive::Overflow(_)) => Err(TransportAdapterError::Other(
                "account delivery overflow recovery required".to_owned(),
            )),
            None => Ok(None),
        }
    }
}

/// Hand one delivery to its account without awaiting the account queue: a
/// single account whose receiver has stalled (full buffer) must not block the
/// shared router and back-pressure delivery for every other account (and,
/// upstream, the relay notification pipeline).
///
/// A full queue hands the delivery to the account's durable spill, and so
/// does a delivery that a transport-cursor checkpoint still saving, or a live
/// promotion alone, stopped a restart from fetching again: the queue never
/// holds one of those. Only when the spill cannot take it does the delivery
/// join an explicit loss generation, using the one channel slot reserved for
/// its control record.
fn route_account_delivery(transport: &RelayPlaneTransport, delivery: TransportDelivery) {
    let Some(route) = account_deliveries_read(&transport.account_deliveries)
        .get(&delivery.account_id)
        .cloned()
    else {
        return;
    };
    let queue_depth = route
        .sender
        .max_capacity()
        .saturating_sub(route.sender.capacity());
    route.overflow.observe_queue_depth(queue_depth);
    let created_at = delivery.message.timestamp.0;
    let key = account_delivery_restart_key(&delivery);
    match route.overflow.place(
        route.epoch,
        key,
        route.sender.capacity() <= 1,
        route.spill.is_some(),
    ) {
        AccountDeliveryPlacement::Queue => {
            match route
                .sender
                .try_send(AccountDeliveryEvent::Delivery(Box::new(delivery)))
            {
                Ok(()) => {
                    let queue_depth = route
                        .sender
                        .max_capacity()
                        .saturating_sub(route.sender.capacity());
                    route.overflow.observe_queue_depth(queue_depth);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    route.overflow.unqueue(route.epoch, key);
                    // Only this router writes the route, and it reserves one
                    // control slot above, so reaching Full here indicates a
                    // violated queue invariant rather than ordinary
                    // backpressure.
                    tracing::warn!(
                        target: "marmot_app::relay_plane",
                        method = "route_account_delivery",
                        error_kind = "reserved_overflow_slot_unavailable",
                        "account delivery queue invariant failed",
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    route.overflow.unqueue(route.epoch, key);
                }
            }
        }
        AccountDeliveryPlacement::Spill => {
            let spilled = route
                .spill
                .as_ref()
                .is_some_and(|spill| spill.offer(delivery));
            if !spilled {
                // Record the loss before releasing the placement's fence, so
                // the cursor stays fenced throughout.
                omit_account_delivery(&route, Some(created_at));
                route.overflow.finish_spill(1, 0, 0);
            }
        }
        AccountDeliveryPlacement::Omit => omit_account_delivery(&route, Some(created_at)),
    }
}

/// Omit one delivery from a full account queue into the current loss
/// generation, persisting its evidence before the control record is queued.
fn omit_account_delivery(route: &AccountDeliveryRoute, created_at: Option<u64>) {
    let queue_depth = route
        .sender
        .max_capacity()
        .saturating_sub(route.sender.capacity());
    let signal_generation = route.overflow.record_drop(queue_depth, created_at);
    if let Some(marker) = route.recovery_marker.clone() {
        persist_queue_loss(&route.sender, &route.overflow, marker, signal_generation);
    } else if let Some(generation) = signal_generation {
        enqueue_account_delivery_overflow_signal(&route.sender, &route.overflow, generation);
    }
    tracing::warn!(
        target: "marmot_app::relay_plane",
        method = "omit_account_delivery",
        queue_depth,
        "omitting transport delivery: account delivery queue overflow recovery required",
    );
}

/// Count persistence is independent of whether a control record is already
/// queued. The one writer takes any deferred signal only after its latest
/// watermark is durable, including signals requested while that writer ran.
fn persist_queue_loss(
    sender: &mpsc::Sender<AccountDeliveryEvent>,
    overflow: &Arc<AccountDeliveryOverflowState>,
    marker: AccountDeliveryRecoveryMarker,
    signal: Option<u64>,
) {
    let generation = overflow
        .inner
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .generation;
    if let Some(generation) = signal {
        overflow.defer_marker_signal(generation);
    }
    if overflow.start_marker_persistence() {
        let sender = sender.clone();
        let overflow = overflow.clone();
        tokio::spawn(async move {
            overflow.persist_marker_before_drop(marker).await;
            if overflow.take_durable_marker_signal(generation) {
                enqueue_account_delivery_overflow_signal(&sender, &overflow, generation);
            }
        });
    } else if overflow.take_durable_marker_signal(generation) {
        enqueue_account_delivery_overflow_signal(sender, overflow, generation);
    }
}

/// Persist loss recorded after its route was retired. There is no queue for
/// a signal; whichever session comes next recovers from the durable marker.
fn persist_retired_queue_loss(
    overflow: &Arc<AccountDeliveryOverflowState>,
    marker: AccountDeliveryRecoveryMarker,
) {
    if overflow.start_marker_persistence() {
        let overflow = overflow.clone();
        tokio::spawn(async move { overflow.persist_marker_before_drop(marker).await });
    }
}

fn enqueue_account_delivery_overflow_signal(
    sender: &mpsc::Sender<AccountDeliveryEvent>,
    overflow: &AccountDeliveryOverflowState,
    generation: u64,
) {
    match sender.try_send(AccountDeliveryEvent::Overflow { generation }) {
        Ok(()) => {}
        Err(error) => {
            overflow.cancel_signal(generation);
            tracing::warn!(
                target: "marmot_app::relay_plane",
                method = "spawn_router",
                error_kind = match error {
                    mpsc::error::TrySendError::Full(_) => "queue_full",
                    mpsc::error::TrySendError::Closed(_) => "queue_closed",
                },
                "could not enqueue account delivery overflow recovery signal",
            );
        }
    }
}

fn account_deliveries_read(
    deliveries: &RwLock<HashMap<MemberId, AccountDeliveryRoute>>,
) -> RwLockReadGuard<'_, HashMap<MemberId, AccountDeliveryRoute>> {
    deliveries
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn account_deliveries_write(
    deliveries: &RwLock<HashMap<MemberId, AccountDeliveryRoute>>,
) -> RwLockWriteGuard<'_, HashMap<MemberId, AccountDeliveryRoute>> {
    deliveries
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn publish_report_from_outcome(
    outcome: NostrPublishOutcome,
    request: TransportPublishRequest,
) -> TransportPublishReport {
    TransportPublishReport {
        message_id: outcome.message_id.unwrap_or(request.message.id),
        accepted: outcome.accepted,
        failed: outcome.failed,
        required_acks: request.required_acks,
    }
}

#[cfg(test)]
mod tests;
