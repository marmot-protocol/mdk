//! Owned transport evidence for a future bounded SDK acquisition backend.
use std::collections::HashSet;
use std::time::Duration;

use cgka_traits::{MemberId, TransportEndpoint};
use transport_nostr_peeler::NostrTransportEvent;

/// Request-local cancellation uses Tokio's shared cancellation primitive.
/// The backend must still clean up only this request's subscriptions when the
/// token fires or the acquisition future is dropped.
pub type NostrAcquisitionCancellation = tokio_util::sync::CancellationToken;

/// The exact Nostr query the recovery owner has justified. Explicit IDs can
/// reacquire known inventory; a history window is bounded investigation and
/// does not by itself establish complete coverage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NostrAcquisitionScope {
    /// Reacquire known Nostr event IDs. This cannot discover unknown history.
    KnownEventIds(Vec<[u8; 32]>),
    /// Kind-1059 gift wraps addressed to `request.account_id` via the `p` tag.
    /// Both time bounds are inclusive; never issue an unfiltered time REQ.
    AccountInboxWindow { since: u64, until: u64 },
    /// Kind-445 group events with the exact `h` tag below. Both time bounds
    /// are inclusive; never issue an unfiltered time REQ.
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
    /// Maximum IDs placed in a `KnownEventIds` request filter, independently
    /// of the received-item budget.
    pub max_requested_event_ids: usize,
    pub max_received_items_per_endpoint: usize,
    pub max_serialized_event_bytes_per_endpoint: usize,
    pub max_duration: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrAcquisitionRequest {
    /// Selects the account's authentication context and inbox recipient.
    /// The caller keeps its durable attempt, scope token, and revision fence.
    pub account_id: MemberId,
    pub scope: NostrAcquisitionScope,
    pub endpoints: Vec<TransportEndpoint>,
    pub limits: NostrAcquisitionLimits,
}

impl NostrAcquisitionRequest {
    /// The adapter validates before dispatch. Backend implementations also
    /// validate when called directly, before opening a REQ. This checks empty
    /// and zero budgets; deployment-wide upper ceilings belong to the caller.
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
                if ids.is_empty()
                    || limits.max_requested_event_ids == 0
                    || ids.len() > limits.max_requested_event_ids
                    || ids.iter().collect::<HashSet<_>>().len() != ids.len() =>
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

/// Typed request termination. The fixed request policy is per-endpoint EOSE;
/// only `RequestPolicySatisfied` reports it. Even EOSE says nothing about
/// durable admission, complete history, decryption, or engine readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NostrAcquisitionEnd {
    RequestPolicySatisfied,
    /// An SDK exit-count policy fired despite this interface's EOSE policy.
    /// Incomplete and never coverage evidence.
    UnexpectedExitLimit,
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
    SetupFailed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NostrAcquisitionStats {
    pub received_items: usize,
    pub serialized_event_bytes: usize,
    pub duplicates: usize,
    pub retained_high_water_items: usize,
    pub retained_high_water_event_bytes: usize,
    /// This request's `ReceiveLoss(u64)` skipped notifications, not unique
    /// missing events. Distinct from the lifetime-cumulative loss watch below.
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
/// from the caller-held durable attempt and account activation attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrNotificationLoss {
    pub scope: NostrNotificationLossScope,
    pub receiver_generation: u64,
    pub cumulative_skipped: u64,
}
