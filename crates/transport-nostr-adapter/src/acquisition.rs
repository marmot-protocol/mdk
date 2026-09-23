//! Owned transport evidence for a future bounded SDK acquisition backend.
use std::collections::HashSet;
use std::time::Duration;

use cgka_traits::{MemberId, TransportEndpoint};
use tokio::sync::watch;
use transport_nostr_peeler::NostrTransportEvent;

use crate::SubscriptionAttempt;

/// Caller-supplied correlation, copied unchanged into the result. The durable
/// owner supplies its existing attempt and frozen scope identifiers; this value
/// grants no authority to complete or clear an obligation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrAcquisitionCorrelation {
    pub account_id: MemberId,
    pub attempt_serial: u64,
    /// Existing `RecoveryScopeToken` identity and revision, copied as data.
    pub obligation_id: [u8; 16],
    pub scope_id: u64,
    pub scope_revision: u64,
    /// Account activation fence. This is not a physical socket generation.
    pub subscription_attempt: SubscriptionAttempt,
}

/// The exact Nostr query the recovery owner has justified. Explicit IDs can
/// reacquire known inventory; a history window is bounded investigation and
/// does not by itself establish complete coverage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NostrAcquisitionScope {
    KnownEventIds(Vec<[u8; 32]>),
    AccountInboxWindow {
        since: u64,
        until: u64,
    },
    GroupWindow {
        transport_group_id: [u8; 32],
        since: u64,
        until: u64,
    },
}

/// Per-endpoint received-item and serialized-event-JSON byte budgets, plus an
/// overall elapsed wall-clock deadline. Item/byte counters include duplicates
/// and events rejected at the budget boundary. These are not wire-byte or
/// process-memory ceilings; SDK queues, WebSocket/parser buffers, temporary
/// serialization, event/object overhead, in-flight data, and concurrent
/// requests remain outside them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NostrAcquisitionLimits {
    pub max_endpoints: usize,
    pub max_received_items_per_endpoint: usize,
    pub max_serialized_event_bytes_per_endpoint: usize,
    pub max_duration: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrAcquisitionRequest {
    pub correlation: NostrAcquisitionCorrelation,
    pub scope: NostrAcquisitionScope,
    pub endpoints: Vec<TransportEndpoint>,
    pub limits: NostrAcquisitionLimits,
}

impl NostrAcquisitionRequest {
    /// Backends call this before opening a REQ. An empty/invalid scope or a
    /// zero/unbounded budget must never fall back to ordinary subscriptions.
    pub fn validate(&self) -> Result<(), NostrAcquisitionError> {
        let limits = self.limits;
        if self.endpoints.is_empty()
            || limits.max_endpoints == 0
            || self.endpoints.len() > limits.max_endpoints
            || limits.max_received_items_per_endpoint == 0
            || limits.max_serialized_event_bytes_per_endpoint == 0
            || limits.max_duration.is_zero()
            || self.endpoints.iter().any(|endpoint| endpoint.0.is_empty())
            || self
                .endpoints
                .iter()
                .map(|endpoint| &endpoint.0)
                .collect::<HashSet<_>>()
                .len()
                != self.endpoints.len()
        {
            return Err(NostrAcquisitionError::InvalidRequest);
        }
        match &self.scope {
            NostrAcquisitionScope::KnownEventIds(ids)
                if ids.is_empty() || ids.iter().collect::<HashSet<_>>().len() != ids.len() =>
            {
                Err(NostrAcquisitionError::InvalidRequest)
            }
            NostrAcquisitionScope::AccountInboxWindow { since, until }
            | NostrAcquisitionScope::GroupWindow { since, until, .. }
                if since > until =>
            {
                Err(NostrAcquisitionError::InvalidRequest)
            }
            _ => Ok(()),
        }
    }
}

/// An unsupported backend refuses before doing work. Partial transport
/// failures belong in endpoint results so useful events are never discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NostrAcquisitionError {
    Unsupported,
    InvalidRequest,
}

/// Typed request termination. Only `RequestPolicySatisfied` completed the
/// selected request policy. Even that says nothing about durable admission,
/// complete history, decryption, or engine readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NostrAcquisitionEnd {
    RequestPolicySatisfied,
    ExitCountReached,
    ItemLimitReached,
    ByteLimitReached,
    Cancelled,
    Deadline,
    Disconnected,
    ReceiveLoss,
    ReceiverClosed,
    AuthenticationFailed,
    Rejected,
    RelayClosed,
    BackendFailed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NostrAcquisitionStats {
    pub received_items: usize,
    pub serialized_event_bytes: usize,
    pub duplicates: usize,
    pub retained_high_water_items: usize,
    pub retained_high_water_event_bytes: usize,
    /// Receiver-local skipped notifications, not unique missing events.
    pub receiver_skipped_notifications: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrAcquisitionEndpoint {
    pub endpoint: TransportEndpoint,
    /// Backend-observed connection lifetime, if available. It is evidence for
    /// rejecting stale network observations, not durable recovery progress.
    pub session_generation: Option<u64>,
    pub events: Vec<NostrTransportEvent>,
    pub end: NostrAcquisitionEnd,
    pub stats: NostrAcquisitionStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrAcquisitionResult {
    pub correlation: NostrAcquisitionCorrelation,
    /// Exactly one entry per requested endpoint, including failed endpoints.
    pub endpoints: Vec<NostrAcquisitionEndpoint>,
}

/// Loss scope is the SDK receiver, never an inferred group. The shared 0.44
/// client can report only shared-receiver loss. Account scope becomes valid
/// only when the backend owns a separate receiver for that account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NostrNotificationLossScope {
    SharedReceiver,
    AccountReceiver { account_id: MemberId },
}

/// Latest cumulative loss watermark for one relay-client lifetime. The scope
/// stays fixed and the count never resets, even when a replacement receiver
/// advances `receiver_generation`. Thus coalesced watch updates cannot erase
/// a gap from a prior receiver. The generation is transport evidence, distinct
/// from the durable attempt serial and account activation attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrNotificationLoss {
    pub scope: NostrNotificationLossScope,
    pub receiver_generation: u64,
    pub cumulative_skipped: u64,
}

/// Cloneable request-local cancellation. Dropping or cancelling a caller
/// future must be paired with backend request cleanup; neither operation may
/// unsubscribe unrelated live interests.
#[derive(Clone, Debug)]
pub struct NostrAcquisitionCancellation {
    tx: watch::Sender<bool>,
}

impl Default for NostrAcquisitionCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl NostrAcquisitionCancellation {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(false);
        Self { tx }
    }

    pub fn cancel(&self) {
        self.tx.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.tx.borrow()
    }

    pub async fn cancelled(&self) {
        let mut rx = self.tx.subscribe();
        while !*rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}
