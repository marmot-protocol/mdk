//! Concrete Nostr transport adapter core.
//!
//! This crate implements the shared [`cgka_traits::TransportAdapter`] boundary
//! for Nostr-shaped Marmot messages. It owns account-aware subscription state,
//! endpoint routing, publish target validation, and conversion between
//! [`transport_nostr_peeler::NostrTransportEvent`] and
//! [`cgka_traits::TransportMessage`].
//!
//! Real relay sockets are deliberately behind [`NostrRelayClient`]. That keeps
//! the adapter testable while preserving the production boundary where a
//! `nostr-sdk` client can plug in.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cgka_traits::MessageId;
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::{
    GroupId, MemberId, TransportAccountActivation, TransportAdapter, TransportAdapterError,
    TransportDelivery, TransportDeliveryPlane, TransportDeliverySource, TransportEndpoint,
    TransportEndpointFailure, TransportEndpointReceipt, TransportEndpointRejectionCategory,
    TransportGroupSubscription, TransportGroupSync, TransportPublishReport,
    TransportPublishRequest, TransportWireMetadata,
};
use nostr::prelude::RelayUrl;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, OwnedMutexGuard, RwLock, mpsc, oneshot};
use tokio::task::JoinSet;
use transport_nostr_peeler::{
    KIND_MARMOT_GROUP_MESSAGE, KIND_NIP59_GIFT_WRAP, NOSTR_SOURCE, NostrPeelerError,
    NostrTransportEvent,
};

fn map_inbound_event_error(error: NostrPeelerError) -> TransportAdapterError {
    match error {
        NostrPeelerError::InvalidSignature => TransportAdapterError::InvalidInboundSignature,
        NostrPeelerError::Malformed(_)
        | NostrPeelerError::UnsupportedKind(_)
        | NostrPeelerError::MissingTag(_) => TransportAdapterError::InvalidInboundEncoding,
    }
}

/// Build forensic wire metadata for an inbound relay event. The
/// `transport_group_id` is read from the peeler-mapped envelope (the canonical
/// `h`-tag extraction) rather than re-parsing tags here.
fn inbound_wire_metadata(
    event: &NostrTransportEvent,
    envelope: &TransportEnvelope,
) -> TransportWireMetadata {
    let transport_group_id = match envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => {
            Some(hex::encode(transport_group_id))
        }
        TransportEnvelope::Welcome { .. } => None,
    };
    let is_gift_wrap = event.kind == KIND_NIP59_GIFT_WRAP;
    TransportWireMetadata {
        wire_id: Some(event.id.clone()),
        wire_kind: Some(event.kind),
        wire_pubkey_hex: Some(event.pubkey.clone()),
        transport_group_id,
        // For a NIP-59 gift wrap the carrying event id is the gift-wrap id; the
        // interior rumor (welcome) id is only known after peeling, so it is not
        // surfaced on this inbound carrier.
        gift_wrap_event_id: is_gift_wrap.then(|| event.id.clone()),
    }
}

mod acquisition;
mod key_package;
#[cfg(feature = "sdk")]
#[doc(hidden)]
pub mod network_proxy;
mod publish_accounting;
mod relay_list;
mod replay_admission;
mod replay_ingress;
#[cfg(feature = "sdk")]
mod sdk_client;
mod telemetry;

pub use acquisition::{
    NostrAcquisitionCancellation, NostrAcquisitionEnd, NostrAcquisitionEndpoint,
    NostrAcquisitionError, NostrAcquisitionLimits, NostrAcquisitionRequest, NostrAcquisitionResult,
    NostrAcquisitionScope, NostrAcquisitionStats, NostrNotificationLoss,
    NostrNotificationLossFloor, NostrNotificationLossScope,
};
pub use key_package::{
    CLIENT_TAG, KIND_MARMOT_KEY_PACKAGE, NostrKeyPackagePublication, NostrKeyPackagePublisher,
};
pub use relay_list::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_NIP65_RELAY_LIST, NostrAccountRelayListKind,
    NostrAccountRelayListPublication, NostrNip65RelayListPublication, NostrNip65RelaySet,
    parse_nip65_relay_set,
};
#[cfg(feature = "sdk")]
pub use sdk_client::{
    NostrReconciliationEndpointFailure, NostrReconciliationFailure, NostrReconciliationItem,
    NostrReconciliationProgress, NostrReconciliationSummary, NostrSdkNotification,
    NostrSdkRelayClient, NostrSdkRelayHealth, NostrSdkSubscriptionPlan, RelayRegistrationOutcome,
    dispatch_sdk_replay, sdk_subscription_refusal, sign_transport_event_for_publish,
};
pub use telemetry::{
    DurationHistogramSnapshot, HistogramBucket, RelayDeliverySpread, RelayDeliveryStats,
    RelayDeliveryTelemetry, RelayExportConsent, RelayIndex, RelayIndexRegistry,
    RelayLabelResolution, RelayLatencyStats, RelayRefusalStats, RelaySyncSnapshot,
    RelaySyncTelemetry,
};

const DELIVERY_BUFFER: usize = 1024;

pub use replay_admission::{
    ReplayCaptureOutcome, ReplayCapturePlan, ReplayCaptureToken, ReplayEndpointView,
    ReplayRequestView,
};
pub use replay_ingress::{ReplayBatch, ReplayBatchTake, ReplayIngress};

/// How long a subscription-lifecycle operation waits for subscribe tasks a
/// dropped caller left running (see `NostrTransportAdapter::subscribe_tasks`).
/// Subscribe calls only queue REQs, so a healthy client finishes in far less.
const SUBSCRIBE_STRAGGLER_WAIT: Duration = Duration::from_secs(2);

/// The most stored events a relay may return for one live REQ before EOSE.
/// strfry (and NIP-01 relays generally) silently clamp a REQ that carries no
/// `limit` to a default page, 500 on strfry, and then send EOSE as if the
/// stored history were exhausted. A replay that delivers this many events
/// before EOSE may therefore have been cut short, and is paged backwards
/// before its EOSE counts as coverage.
// Convergence ledger A17: page, admission and deadline bounds are one acquisition policy.
pub const RELAY_REPLAY_PAGE_LIMIT: usize = 500;

/// Upper bound on backward pages for one relay's replay of one group route,
/// or of the inbox. A batched REQ pages up to this many per route it carries,
/// so batching never shortens the history a route's replay reaches. A replay
/// still truncated after its bound stays incomplete rather than paging
/// without end; recovery owns history that deep.
const REPLAY_PAGE_MAX_PAGES: usize = 64;

// Hold ciphertext, not MLS state, until backward paging has reached its floor.
// A budget exit withholds admission and coverage rather than losing old keys.
const REPLAY_BUFFER_MAX_ITEMS: usize = RELAY_REPLAY_PAGE_LIMIT * REPLAY_PAGE_MAX_PAGES;
const REPLAY_BUFFER_MAX_BYTES: usize = 32 * 1024 * 1024;

/// The most group routes one live REQ carries, as `#h` values of a single
/// filter (#2266). One REQ per route reached a relay's per-connection REQ
/// limit (200 on strfry) at about 200 groups and then refused the rest and
/// recovery's own fetches. Batched, a 1,000-route account sharing one relay
/// and floor holds 21 REQs there; the limit comes back only near 10,000
/// routes, sooner where routes differ in relays or floor. A refused batch
/// leaves every route it carries without that relay, and its routes share
/// each 500-event replay page, which the page bound scales with.
pub const GROUP_BATCH_ROUTES: usize = 50;

/// Budget for one backward replay page. The item cap sits well above
/// [`RELAY_REPLAY_PAGE_LIMIT`] so a relay that does not clamp still answers a
/// page with EOSE instead of hitting the cap.
/// Its duration also bounds initial waiting and each active route's fetch.
/// Queueing, peer-release waits and delivery draining do not spend that allowance.
const REPLAY_PAGE_LIMITS: NostrAcquisitionLimits = NostrAcquisitionLimits {
    max_endpoints: 1,
    max_requested_event_ids: 1,
    max_received_items_per_endpoint: 8 * RELAY_REPLAY_PAGE_LIMIT,
    max_serialized_event_bytes_per_endpoint: 32 * 1024 * 1024,
    max_duration: Duration::from_secs(30),
};

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Which account-activation attempt issued a subscription.
///
/// A relay reports end-of-stored-events by subscription id and nothing else
/// (`RelayMessage::EndOfStoredEvents` carries only the id), so the id is the
/// only identity an EOSE can carry back. Without an attempt in it, a report
/// answering a REQ that has already been torn down is indistinguishable from a
/// report answering the REQ that replaced it — and lands on the replacement's
/// freshly reset replay coverage. Stamping the attempt into the id makes the
/// superseded report simply not match.
///
/// [`Self::INITIAL`] marks a subscription that no account activation owns —
/// one-shot reconciliation REQs and post-join maintenance. Activations count
/// from one.
///
/// Deliberately not [`Default`]: a silently zero-valued attempt on an account's
/// routes is the exact shape of the bug this type exists to prevent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionAttempt(u64);

impl SubscriptionAttempt {
    /// Not scoped to an account activation.
    pub const INITIAL: Self = Self(0);

    /// The attempt an account's next activation issues under.
    ///
    /// Saturating: monotonicity would silently stop at `u64::MAX`. Unreachable
    /// in practice — that is one activation per nanosecond for ~584 years on a
    /// single in-process adapter — and saturating beats wrapping back onto ids
    /// a live attempt may still be using.
    fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

/// One group route a [`NostrSubscription::GroupBatch`] carries.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupBatchRoute {
    pub group_id: GroupId,
    pub transport_group_id: Vec<u8>,
}

/// Low-level relay subscription request emitted by [`NostrTransportAdapter`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NostrSubscription {
    AccountInbox {
        account_id: MemberId,
        endpoints: Vec<TransportEndpoint>,
        since: Option<Timestamp>,
        /// Activation attempt that issued this REQ; see [`SubscriptionAttempt`].
        attempt: SubscriptionAttempt,
    },
    Group {
        account_id: MemberId,
        group_id: GroupId,
        transport_group_id: Vec<u8>,
        endpoints: Vec<TransportEndpoint>,
        since: Option<Timestamp>,
        /// Activation attempt that issued this REQ; see [`SubscriptionAttempt`].
        attempt: SubscriptionAttempt,
    },
    /// The live REQ for up to [`GROUP_BATCH_ROUTES`] group routes that share
    /// endpoints and `since`: one filter whose `#h` values are their routing
    /// ids. Activation packs every group route into batches, and a group
    /// sync that changes the routes repacks them all and closes the batches
    /// it replaced. `batch` numbers the account's batches within its
    /// activation attempt, never reused, so an id names one batch's REQ for
    /// good.
    GroupBatch {
        account_id: MemberId,
        routes: Vec<GroupBatchRoute>,
        endpoints: Vec<TransportEndpoint>,
        since: Option<Timestamp>,
        /// Activation attempt that issued this REQ; see [`SubscriptionAttempt`].
        attempt: SubscriptionAttempt,
        batch: u32,
    },
    /// Temporary history subscription used only by post-join maintenance.
    ///
    /// Its distinct id keeps it independent from the normal incremental group
    /// subscription even though both route the same authenticated MLS events.
    /// `since` is the caller's floor for the group history the joining member
    /// must see: the Welcome that installed its copy, less a clock-skew
    /// allowance. `None` asks for the group's full history. Like every other
    /// kind, the id never carries `since`.
    GroupMaintenance {
        account_id: MemberId,
        group_id: GroupId,
        transport_group_id: Vec<u8>,
        endpoints: Vec<TransportEndpoint>,
        since: Option<Timestamp>,
    },
}

impl NostrSubscription {
    pub fn subscription_id(&self) -> String {
        match self {
            Self::AccountInbox {
                account_id,
                endpoints,
                attempt,
                ..
            } => compact_subscription_id(
                "inbox",
                &[
                    account_id.as_slice(),
                    endpoint_set_digest(endpoints).as_bytes(),
                    &attempt.to_be_bytes(),
                ],
            ),
            Self::Group {
                account_id,
                group_id,
                transport_group_id,
                endpoints,
                attempt,
                ..
            } => {
                let h_tag = hex::encode(transport_group_id);
                compact_subscription_id(
                    "group",
                    &[
                        account_id.as_slice(),
                        group_id.as_slice(),
                        h_tag.as_bytes(),
                        endpoint_set_digest(endpoints).as_bytes(),
                        &attempt.to_be_bytes(),
                    ],
                )
            }
            Self::GroupBatch {
                account_id,
                endpoints,
                attempt,
                batch,
                ..
            } => compact_subscription_id(
                "group-batch",
                &[
                    account_id.as_slice(),
                    endpoint_set_digest(endpoints).as_bytes(),
                    &batch.to_be_bytes(),
                    &attempt.to_be_bytes(),
                ],
            ),
            Self::GroupMaintenance {
                account_id,
                group_id,
                transport_group_id,
                endpoints,
                ..
            } => {
                let h_tag = hex::encode(transport_group_id);
                compact_subscription_id(
                    "group-maintenance",
                    &[
                        account_id.as_slice(),
                        group_id.as_slice(),
                        h_tag.as_bytes(),
                        endpoint_set_digest(endpoints).as_bytes(),
                    ],
                )
            }
        }
    }

    /// Relay endpoints this subscription was issued to.
    pub fn endpoints(&self) -> &[TransportEndpoint] {
        match self {
            Self::AccountInbox { endpoints, .. }
            | Self::Group { endpoints, .. }
            | Self::GroupBatch { endpoints, .. }
            | Self::GroupMaintenance { endpoints, .. } => endpoints,
        }
    }

    /// Activation attempt this subscription was issued under. See
    /// [`SubscriptionAttempt`].
    pub fn attempt(&self) -> SubscriptionAttempt {
        match self {
            Self::AccountInbox { attempt, .. }
            | Self::Group { attempt, .. }
            | Self::GroupBatch { attempt, .. } => *attempt,
            Self::GroupMaintenance { .. } => SubscriptionAttempt::INITIAL,
        }
    }

    /// Whether this is a live group-route REQ: one route, or a batch of them.
    pub fn is_group_route(&self) -> bool {
        matches!(self, Self::Group { .. } | Self::GroupBatch { .. })
    }

    /// Whether this REQ asks for group `group_id`'s events: its own route or
    /// maintenance REQ, or a batch carrying one of its routes.
    pub fn carries_group(&self, group_id: &GroupId) -> bool {
        match self {
            Self::Group { group_id: own, .. } | Self::GroupMaintenance { group_id: own, .. } => {
                own == group_id
            }
            Self::GroupBatch { routes, .. } => {
                routes.iter().any(|route| &route.group_id == group_id)
            }
            Self::AccountInbox { .. } => false,
        }
    }

    /// Account this subscription belongs to.
    pub fn account_id(&self) -> &MemberId {
        match self {
            Self::AccountInbox { account_id, .. }
            | Self::Group { account_id, .. }
            | Self::GroupBatch { account_id, .. }
            | Self::GroupMaintenance { account_id, .. } => account_id,
        }
    }

    fn route_key(&self) -> NostrSubscriptionRouteKey {
        match self {
            Self::AccountInbox {
                account_id,
                endpoints,
                ..
            } => NostrSubscriptionRouteKey::AccountInbox {
                account_id: account_id.clone(),
                endpoints: normalized_endpoints(endpoints),
            },
            Self::Group {
                account_id,
                group_id,
                transport_group_id,
                endpoints,
                ..
            } => NostrSubscriptionRouteKey::Group {
                account_id: account_id.clone(),
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: normalized_endpoints(endpoints),
            },
            Self::GroupBatch {
                account_id,
                attempt,
                batch,
                ..
            } => NostrSubscriptionRouteKey::GroupBatch {
                account_id: account_id.clone(),
                attempt: *attempt,
                batch: *batch,
            },
            Self::GroupMaintenance {
                account_id,
                group_id,
                transport_group_id,
                endpoints,
                ..
            } => NostrSubscriptionRouteKey::GroupMaintenance {
                account_id: account_id.clone(),
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: normalized_endpoints(endpoints),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum NostrSubscriptionRouteKey {
    AccountInbox {
        account_id: MemberId,
        endpoints: Vec<TransportEndpoint>,
    },
    Group {
        account_id: MemberId,
        group_id: GroupId,
        transport_group_id: Vec<u8>,
        endpoints: Vec<TransportEndpoint>,
    },
    /// Never live again once closed: batch numbers are not reused within an
    /// attempt, and attempts are not reused at all.
    GroupBatch {
        account_id: MemberId,
        attempt: SubscriptionAttempt,
        batch: u32,
    },
    GroupMaintenance {
        account_id: MemberId,
        group_id: GroupId,
        transport_group_id: Vec<u8>,
        endpoints: Vec<TransportEndpoint>,
    },
}

/// Snapshot of adapter-local lifecycle counters.
///
/// These counters are diagnostic. They must not feed convergence or branch
/// selection.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NostrAdapterMetrics {
    pub active_accounts: usize,
    pub active_group_subscriptions: usize,
    pub subscriptions_created: usize,
    pub subscriptions_removed: usize,
    /// Gauge: unconfirmed relay teardowns queued until an unsubscribe succeeds
    /// or the route becomes live again. Routing state already reflects the removals.
    #[serde(default)]
    pub unsubscribe_retries_pending: usize,
    pub inbound_events_seen: usize,
    pub inbound_events_delivered: usize,
    pub inbound_events_dropped: usize,
    /// `TransportAdapter` publish calls that entered a relay client. One call
    /// is one attempt however many endpoints it targets. Once every started
    /// call has resolved or been dropped, attempts equal successes + failures
    /// + cancellations.
    pub publish_attempts: usize,
    /// Calls whose accepted-endpoint count met `required_acks.max(1)`.
    pub publish_successes: usize,
    /// Client errors and outcomes below that threshold, including empty
    /// acceptance.
    pub publish_failures: usize,
    /// Started calls whose caller dropped them before the client returned,
    /// such as outstanding endpoints abandoned once a fanout reaches quorum.
    /// These are not relay failures and may still have reached a relay.
    #[serde(default)]
    pub publish_cancellations: usize,
    /// Route-level NIP-77 passes attempted after ordinary subscription rebuilds.
    #[serde(default)]
    pub reconciliation_attempts: usize,
    #[serde(default)]
    pub reconciliation_relays_succeeded: usize,
    #[serde(default)]
    pub reconciliation_relays_failed: usize,
    /// Event ids the relays reported absent from the durable local route sets.
    #[serde(default)]
    pub reconciliation_remote_items: usize,
    /// Missing events successfully downloaded by reconciliation.
    #[serde(default)]
    pub reconciliation_received_items: usize,
    /// Group passes that returned nothing because no time order covered the
    /// history they were missing (`NostrReconciliationSummary::order_unproven`).
    #[serde(default)]
    pub reconciliation_order_unproven_passes: usize,
    /// Account activations whose every REQ reached every relay.
    #[serde(default)]
    pub activations_full: usize,
    /// Account activations that succeeded while some relay owed or refused a
    /// REQ ([`NostrSubscribeReport::is_degraded`]).
    #[serde(default)]
    pub activations_degraded: usize,
    /// Account activations that failed and rolled back.
    #[serde(default)]
    pub activations_failed: usize,
    /// Group syncs that issued REQs, each of which reached every relay.
    #[serde(default)]
    pub group_syncs_full: usize,
    /// Group syncs that issued REQs and succeeded while some relay owed or
    /// refused one.
    #[serde(default)]
    pub group_syncs_degraded: usize,
    /// Group syncs whose REQs failed, leaving the committed routes in place.
    #[serde(default)]
    pub group_syncs_failed: usize,
}

/// Successful/failed endpoint-level result from a relay client publish.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NostrPublishOutcome {
    pub message_id: Option<MessageId>,
    pub accepted: Vec<TransportEndpointReceipt>,
    pub failed: Vec<TransportEndpointFailure>,
}

impl NostrPublishOutcome {
    pub fn accepted(endpoints: impl IntoIterator<Item = TransportEndpoint>) -> Self {
        Self {
            message_id: None,
            accepted: endpoints
                .into_iter()
                .map(|endpoint| TransportEndpointReceipt {
                    endpoint,
                    accepted_at: None,
                    ack_kind: None,
                })
                .collect(),
            failed: Vec::new(),
        }
    }
}

/// One event in an ordered relay publish batch.
///
/// Batch-capable relay clients may retain and connect the union of these
/// endpoints for the duration of [`NostrRelayClient::publish_events`]. Results
/// remain ordered one-for-one with requests so callers can preserve per-event
/// partial-success reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrEventPublishRequest {
    pub endpoints: Vec<TransportEndpoint>,
    pub event: NostrTransportEvent,
    pub required_acks: usize,
}

/// Ordered outcomes and per-request completion latencies for one publish
/// batch. Durations are local monotonic values measured from the start of the
/// shared batch, so callers can compare fixed publication phases without
/// adding relay-, account-, event-, or caller-defined labels.
#[derive(Debug)]
pub struct NostrPublishBatch {
    pub outcomes: Vec<Result<NostrPublishOutcome, TransportAdapterError>>,
    pub request_durations: Vec<Duration>,
}

/// Relay event as observed by the Nostr relay client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrRelayEvent {
    pub endpoint: TransportEndpoint,
    pub subscription_id: Option<String>,
    pub event: NostrTransportEvent,
}

/// End-of-stored-events progress across one account's live inbox and batch REQs,
/// from [`NostrTransportAdapter::account_subscription_eose`].
///
/// The logical-subscription counts preserve the coarse progress used for
/// diagnostics. Completion is deliberately stricter: every endpoint-scoped
/// subscription attempt in the activation snapshot must finish stored history
/// and pass current admission and router placement. A fast,
/// empty relay is not evidence that another relay holding missing history has
/// served it, and an unavailable relay leaves recovery incomplete and
/// retryable rather than converting availability pressure into success.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountSubscriptionEose {
    /// The account's live subscriptions in the snapshot: its inbox plus one
    /// per group batch. Temporary post-join maintenance subscriptions are not
    /// among them — they are installed and removed on their own gate.
    pub subscriptions: usize,
    /// Of those, how many have at least one relay with admitted and placed
    /// stored history.
    pub with_eose: usize,
    /// Endpoint-scoped attempts across the activation snapshot. A two-relay
    /// inbox and two-relay group subscription contribute four attempts.
    pub relay_subscription_attempts: usize,
    /// Endpoint-scoped attempts whose stored history ended and passed current
    /// admission and placement, not merely raw wire EOSE receipt.
    pub relay_subscription_attempts_with_eose: usize,
    /// Endpoint-scoped attempts a relay ended with a dropped refusal before
    /// reporting EOSE (see [`SubscriptionRefusalDisposition::Dropped`]). They
    /// will never report EOSE. A pending refusal is not counted: the relay
    /// client re-sends that REQ, so it still awaits EOSE.
    pub relay_subscription_attempts_refused: usize,
    /// Subscriptions whose every relay ended them with a dropped refusal
    /// before reporting EOSE: no relay is serving them at all. An inbox here
    /// means the account receives no invitations.
    pub subscriptions_refused: usize,
}

impl AccountSubscriptionEose {
    /// Whether every issued endpoint's stored history is admitted and placed.
    ///
    /// An account holding no subscriptions is not complete: nothing was
    /// subscribed, so nothing can have served its stored history.
    pub fn complete(&self) -> bool {
        self.subscriptions > 0
            && self.with_eose == self.subscriptions
            && self.relay_subscription_attempts > 0
            && self.relay_subscription_attempts_with_eose == self.relay_subscription_attempts
    }

    /// Whether every endpoint-scoped attempt has answered, with EOSE or with a
    /// dropped refusal, so waiting longer brings no more stored history.
    ///
    /// Weaker than [`Self::complete`] on purpose: a refusal is not evidence
    /// that the refused relay's history was served. Use this only to stop
    /// waiting; never gate live cursor promotion or activation reuse on it.
    pub fn settled(&self) -> bool {
        self.relay_subscription_attempts > 0
            && self.relay_subscription_attempts_with_eose + self.relay_subscription_attempts_refused
                == self.relay_subscription_attempts
    }

    /// Whether any relay reported end-of-stored-events at all. `false` after a
    /// wait is the shape of an account whose relays accepted the subscription
    /// registration but never served it.
    pub fn any(&self) -> bool {
        self.relay_subscription_attempts_with_eose > 0
    }
}

/// Ciphertext admission is distinct from every relay's EOSE certificate.
pub struct ReplayAdmissionStatus<'a> {
    /// Ciphertext is still staged or being released to the delivery queue.
    pub pending: bool,
    /// Set by the relay plane while its spill placement is protected.
    pub spill_pending: bool,
    /// Discarded replay must enter the consumer's loss fence before a save.
    pub loss: Option<NostrNotificationLossFloor>,
    account_id: &'a MemberId,
    _guard: tokio::sync::RwLockReadGuard<'a, AdapterState>,
}

/// Why an ordered SDK source starts a new replay generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayRestart {
    /// The relay is about to restore its existing subscriptions.
    Connection,
    /// The receiver lost input; restored history needs an owned refetch.
    ReceiverLoss,
}

#[derive(Default)]
struct ReplayLosses {
    pending: std::sync::Mutex<HashMap<MemberId, NostrNotificationLossFloor>>,
    changed: Notify,
}

impl ReplayLosses {
    fn record(&self, account: &MemberId, since: u64) {
        let floor = if since == 0 {
            NostrNotificationLossFloor::Unbounded
        } else {
            NostrNotificationLossFloor::Since(since)
        };
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        pending
            .entry(account.clone())
            .and_modify(|old| {
                *old = match (*old, floor) {
                    (
                        NostrNotificationLossFloor::Since(a),
                        NostrNotificationLossFloor::Since(b),
                    ) => NostrNotificationLossFloor::Since(a.min(b)),
                    _ => NostrNotificationLossFloor::Unbounded,
                };
            })
            .or_insert(floor);
        self.changed.notify_one();
    }
}

/// Which of an account's live subscriptions a relay refused.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionRouteKind {
    /// The account inbox (gift-wrapped Welcomes).
    Inbox,
    /// A group route, current or retained.
    Group,
    /// A post-join or recovery maintenance subscription.
    Maintenance,
}

impl SubscriptionRouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbox => "inbox",
            Self::Group => "group",
            Self::Maintenance => "maintenance",
        }
    }
}

/// What the relay client does with a REQ that a relay closed.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionRefusalDisposition {
    /// The client keeps the REQ and sends it again after authenticating or
    /// reconnecting, as `nostr-sdk` does for `auth-required:` with an
    /// authenticator and for `rate-limited:`.
    Pending,
    /// The client dropped the REQ. Reconnecting does not restore it.
    Dropped,
}

impl SubscriptionRefusalDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Dropped => "dropped",
        }
    }
}

/// A relay's `CLOSED` for a live subscription, classified by the relay
/// client. The relay's reason text is discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SubscriptionRefusal {
    /// The reason's machine-readable prefix, or `None` when it had no prefix
    /// or an unknown one.
    pub category: Option<TransportEndpointRejectionCategory>,
    pub disposition: SubscriptionRefusalDisposition,
}

/// Distinct refusals [`NostrTransportAdapter::take_subscription_refusals`]
/// holds per account between drains. Repeats of one refusal coalesce into one
/// entry, so this bounds distinct relay/route/category combinations, not
/// closes.
pub const SUBSCRIPTION_REFUSAL_REPORT_LIMIT: usize = 32;

/// Repeated refusals of one route kind on one relay, for the forensic audit.
///
/// Carries the relay endpoint, which the consented audit channel records the
/// same way it records subscription and publish relays. Never log it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionRefusalReport {
    pub route_kind: SubscriptionRouteKind,
    pub endpoint: TransportEndpoint,
    pub category: Option<TransportEndpointRejectionCategory>,
    pub disposition: SubscriptionRefusalDisposition,
    /// How many times the relay sent this refusal since the last drain.
    pub count: u64,
}

/// One drain of an account's subscription refusals, from
/// [`NostrTransportAdapter::take_subscription_refusals`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionRefusalReports {
    /// Distinct refusals in arrival order.
    pub reports: Vec<SubscriptionRefusalReport>,
    /// Refusals shed because [`SUBSCRIPTION_REFUSAL_REPORT_LIMIT`] distinct
    /// entries were already held.
    pub dropped: u64,
}

/// Relays that could not take one subscription's REQ when it was issued.
///
/// Aggregate counts only, for degraded-activation telemetry (#1951). A
/// subscription is still live when this is degraded: an owed relay gets the
/// REQ on its next connection, and every other relay took it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NostrSubscribeReport {
    /// Relays that refused the REQ because they were unreachable. The relay
    /// client re-sends it, with the same id and filter, on each one's next
    /// connection.
    pub owed_relays: usize,
    /// Connected relays that refused the REQ while another relay took it.
    pub refused_relays: usize,
}

impl NostrSubscribeReport {
    /// Whether any relay did not take the REQ when it was issued.
    pub fn is_degraded(&self) -> bool {
        self.owed_relays > 0 || self.refused_relays > 0
    }

    fn add(&mut self, other: Self) {
        self.owed_relays += other.owed_relays;
        self.refused_relays += other.refused_relays;
    }
}

/// Boundary between this adapter and the actual Nostr relay implementation.
#[async_trait]
pub trait NostrRelayClient: Send + Sync {
    /// Optional bounded, request-scoped history operation. Implementations must
    /// validate the complete owned request before issuing any network work and
    /// return one terminal outcome for every requested endpoint. Cancellation
    /// closes only this request's subscriptions, never live interests.
    async fn acquire_history(
        &self,
        _request: NostrAcquisitionRequest,
        _cancellation: NostrAcquisitionCancellation,
    ) -> Result<NostrAcquisitionResult, NostrAcquisitionError> {
        Err(NostrAcquisitionError::Unsupported)
    }

    /// Independent, cumulative control signal for notification-channel loss.
    /// A watch receiver coalesces updates, so skipped counts must be cumulative
    /// within the reported receiver scope. The current SDK backend explicitly
    /// lacks this capability until its production migration.
    fn notification_loss(
        &self,
    ) -> Result<tokio::sync::watch::Receiver<Option<NostrNotificationLoss>>, NostrAcquisitionError>
    {
        Err(NostrAcquisitionError::Unsupported)
    }

    /// Select one account receiver when a client owns several immutable
    /// authentication contexts. A single coalescing watch cannot carry
    /// independent cumulative watermarks for multiple accounts.
    async fn notification_loss_for_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<tokio::sync::watch::Receiver<Option<NostrNotificationLoss>>, NostrAcquisitionError>
    {
        self.notification_loss()
    }

    async fn subscribe(&self, subscription: NostrSubscription)
    -> Result<(), TransportAdapterError>;

    /// `subscribe`, reporting the relays that did not take the REQ yet.
    ///
    /// An unreachable relay must not fail the subscription: the client keeps
    /// that relay's REQ owed and sends it on reconnect, under the same
    /// tracking `unsubscribe` and `unsubscribe_account` close. Fail only when
    /// no relay took the REQ or owes it. Clients without that distinction
    /// report every successful subscribe as full.
    async fn subscribe_reporting(
        &self,
        subscription: NostrSubscription,
    ) -> Result<NostrSubscribeReport, TransportAdapterError> {
        self.subscribe(subscription)
            .await
            .map(|()| NostrSubscribeReport::default())
    }

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError>;

    /// Whether this client preserves caller-supplied wire ids for both scoped
    /// subscribe and teardown. Checked before staging any recovery session.
    fn supports_scoped_subscriptions(&self) -> bool {
        false
    }

    /// Subscribe under an owner-fenced wire id. Older injected clients fail
    /// closed instead of silently issuing an unfenced maintenance request.
    async fn subscribe_scoped(
        &self,
        _subscription: NostrSubscription,
        _subscription_id: String,
    ) -> Result<(), TransportAdapterError> {
        Err(TransportAdapterError::Subscription(
            "scoped subscription unsupported".to_owned(),
        ))
    }

    /// Remove the exact wire id supplied to `subscribe_scoped`.
    async fn unsubscribe_scoped(
        &self,
        _subscription: NostrSubscription,
        _subscription_id: String,
    ) -> Result<(), TransportAdapterError> {
        Err(TransportAdapterError::Subscription(
            "scoped subscription unsupported".to_owned(),
        ))
    }

    /// Tear down every subscription this client holds for an account.
    ///
    /// `replacements` are the exact subscriptions the caller will issue next.
    /// Track their planned socket ownership before closing the old REQs so
    /// replacement activation preserves sockets still needed by the account.
    /// An empty slice requests final teardown without retaining socket ownership.
    /// This does not issue the replacement REQs; the caller subscribes afterward.
    ///
    /// Must return `Ok` when the account has no existing subscriptions, while
    /// still allowing nonempty `replacements` to register planned ownership.
    /// With empty replacements, teardown of an unknown account is a no-op.
    /// `activate_account` calls this unconditionally, including before the first
    /// activation, and propagates errors, so rejecting an unknown account would
    /// make every first activation fail.
    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
        replacements: &[NostrSubscription],
    ) -> Result<(), TransportAdapterError>;

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError>;

    /// Publish using the immutable authentication context selected by the
    /// operation's account identity. An implementation without account
    /// contexts must reject this call explicitly; it must never infer the
    /// context from the event's author (kind-445 authors are ephemeral).
    async fn publish_event_for_account(
        &self,
        _account_id: &MemberId,
        _endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        Err(TransportAdapterError::Publish(
            "account-scoped publication unsupported".to_owned(),
        ))
    }

    /// Ordered account-scoped batch; the default remains fail-closed for
    /// clients that do not implement the account-aware single-event method.
    async fn publish_events_for_account(
        &self,
        account_id: &MemberId,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        let mut outcomes = Vec::with_capacity(requests.len());
        for request in requests {
            outcomes.push(
                self.publish_event_for_account(
                    account_id,
                    &request.endpoints,
                    &request.event,
                    request.required_acks,
                )
                .await,
            );
        }
        outcomes
    }

    async fn publish_events_for_account_with_timings(
        &self,
        account_id: &MemberId,
        requests: &[NostrEventPublishRequest],
    ) -> NostrPublishBatch {
        let started_at = Instant::now();
        let outcomes = self.publish_events_for_account(account_id, requests).await;
        let elapsed = started_at.elapsed();
        NostrPublishBatch {
            request_durations: vec![elapsed; outcomes.len()],
            outcomes,
        }
    }

    /// Publish an ordered batch through one client lifecycle.
    ///
    /// The default preserves compatibility for injected relay clients. Socket
    /// implementations should override this when they can safely retain scoped
    /// write-only connections across the batch.
    async fn publish_events(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        let mut outcomes = Vec::with_capacity(requests.len());
        for request in requests {
            outcomes.push(
                self.publish_event(&request.endpoints, &request.event, request.required_acks)
                    .await,
            );
        }
        outcomes
    }

    /// Publish an ordered batch and expose bounded per-request completion
    /// timings. Injected clients inherit a conservative whole-batch duration;
    /// socket implementations may override this with precise request timings.
    async fn publish_events_with_timings(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> NostrPublishBatch {
        let started_at = Instant::now();
        let outcomes = self.publish_events(requests).await;
        let elapsed = started_at.elapsed();
        NostrPublishBatch {
            request_durations: vec![elapsed; outcomes.len()],
            outcomes,
        }
    }
}

/// Wait, bounded by [`SUBSCRIBE_STRAGGLER_WAIT`], for every subscribe task
/// holding the current barrier (see `NostrTransportAdapter::subscribe_tasks`).
/// On timeout, retire that barrier so stragglers fence themselves, rather than
/// letting a hung relay client wedge the adapter.
async fn settle_subscribe_tasks(barriers: &std::sync::Mutex<Arc<RwLock<()>>>) {
    let in_flight = barriers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if tokio::time::timeout(SUBSCRIBE_STRAGGLER_WAIT, in_flight.write())
        .await
        .is_err()
    {
        *barriers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(RwLock::new(()));
        tracing::warn!(
            target: "transport_nostr_adapter::adapter",
            method = "settle_subscribe_tasks",
            "abandoned relay subscribe tasks still running after the straggler wait"
        );
    }
}

/// Close the REQs a failed or cancelled group sync installed, once its
/// subscribe tasks have settled. Only ids the committed routes no longer want
/// are closed: a group sync reuses its activation's ids, so an id that is
/// still live belongs to a route that needs that REQ. A failed close is queued
/// for the next group sync's drain.
async fn close_abandoned_sync_batch(
    relay_client: &Arc<dyn NostrRelayClient>,
    state: &RwLock<AdapterState>,
    barriers: &std::sync::Mutex<Arc<RwLock<()>>>,
    batch: Vec<NostrSubscription>,
) {
    settle_subscribe_tasks(barriers).await;
    let abandoned = {
        let state = state.read().await;
        batch
            .into_iter()
            .filter(|subscription| {
                state
                    .live_subscription_route(&subscription.subscription_id())
                    .is_none()
            })
            .collect::<Vec<_>>()
    };
    let mut failed = Vec::new();
    for subscription in abandoned {
        if relay_client
            .unsubscribe(subscription.clone())
            .await
            .is_err()
        {
            failed.push(subscription);
        }
    }
    if !failed.is_empty() {
        state.write().await.queue_pending_unsubscribes(failed);
    }
}

/// A `JoinSet` that detaches its tasks when dropped instead of aborting them.
/// See `NostrTransportAdapter::subscribe_tasks` for why subscribe tasks must
/// run to completion.
struct DetachOnDrop<T: 'static>(JoinSet<T>);

impl<T: 'static> Drop for DetachOnDrop<T> {
    fn drop(&mut self) {
        self.0.detach_all();
    }
}

/// Nostr implementation of the shared transport adapter boundary.
#[derive(Clone)]
pub struct NostrTransportAdapter {
    relay_client: Arc<dyn NostrRelayClient>,
    state: Arc<RwLock<AdapterState>>,
    replay_losses: Arc<ReplayLosses>,
    delivery_tx: mpsc::Sender<TransportDelivery>,
    delivery_rx: Arc<Mutex<mpsc::Receiver<TransportDelivery>>>,
    /// Serializes the subscription-lifecycle operations (activate / deactivate /
    /// group sync) so their relay-side subscribe/unsubscribe network calls —
    /// which run OUTSIDE the `state` `RwLock` — cannot interleave. Without it a
    /// concurrent sync could re-add a group (minting the same deterministic
    /// subscription id) in the window between another sync's live-route filter
    /// and its stale `unsubscribe`, tearing the fresh subscription back down.
    /// The `RwLock` still guards the fast delivery/routing path independently.
    subscription_lock: Arc<Mutex<()>>,
    /// Held shared by every relay subscribe task `subscribe_all` spawns, for
    /// the task's whole life. A caller dropped mid-activation detaches those
    /// tasks rather than aborting them: an abort lands only at the task's next
    /// await, so a task already running could still register its REQ after the
    /// next activation's `unsubscribe_account` swept the account, leaving a live
    /// REQ nothing tracks. `lock_subscriptions` takes the current lock
    /// exclusively, so every lifecycle operation starts only after the
    /// stragglers have registered and can be swept. A straggler still running
    /// after [`SUBSCRIBE_STRAGGLER_WAIT`] is abandoned to a retired lock, so a
    /// relay client whose subscribe never returns cannot wedge the adapter.
    subscribe_tasks: Arc<std::sync::Mutex<Arc<RwLock<()>>>>,
    /// Local monotonic origin for delivery telemetry. Never `created_at`.
    monotonic_start: std::time::Instant,
    /// Shared by [`Clone`] and by every account adapter on this relay plane.
    publish_accounting: Arc<publish_accounting::PublishAccounting>,
    /// Refusals of each account's live subscriptions awaiting the next
    /// forensic drain. A plain mutex, never held across an await, so the
    /// account worker drains it from a synchronous seam. Bounded per account
    /// by [`SUBSCRIPTION_REFUSAL_REPORT_LIMIT`].
    subscription_refusals: Arc<std::sync::Mutex<HashMap<MemberId, PendingSubscriptionRefusals>>>,
    #[cfg(all(test, feature = "sdk"))]
    sdk_dto_builds: Arc<std::sync::atomic::AtomicUsize>,
}

impl NostrTransportAdapter {
    pub fn new(relay_client: Arc<dyn NostrRelayClient>) -> Self {
        let (delivery_tx, delivery_rx) = mpsc::channel(DELIVERY_BUFFER);
        let state = AdapterState::default();
        let replay_losses = state.replay_losses.clone();
        Self {
            relay_client,
            state: Arc::new(RwLock::new(state)),
            replay_losses,
            delivery_tx,
            delivery_rx: Arc::new(Mutex::new(delivery_rx)),
            subscription_lock: Arc::new(Mutex::new(())),
            subscribe_tasks: Arc::new(std::sync::Mutex::new(Arc::new(RwLock::new(())))),
            monotonic_start: std::time::Instant::now(),
            publish_accounting: publish_accounting::PublishAccounting::new(),
            subscription_refusals: Arc::default(),
            #[cfg(all(test, feature = "sdk"))]
            sdk_dto_builds: Arc::default(),
        }
    }

    /// Request owned, bounded transport evidence without borrowing adapter
    /// routing state across the network wait. Admission and completion remain
    /// with the account worker and recovery owner.
    pub async fn acquire_history(
        &self,
        request: NostrAcquisitionRequest,
        cancellation: NostrAcquisitionCancellation,
    ) -> Result<NostrAcquisitionResult, NostrAcquisitionError> {
        request.validate()?;
        self.relay_client
            .acquire_history(request, cancellation)
            .await
    }

    /// Observe receiver-scoped loss independently of the event-delivery queue.
    pub fn notification_loss(
        &self,
    ) -> Result<tokio::sync::watch::Receiver<Option<NostrNotificationLoss>>, NostrAcquisitionError>
    {
        self.relay_client.notification_loss()
    }

    pub async fn notification_loss_for_account(
        &self,
        account_id: &MemberId,
    ) -> Result<tokio::sync::watch::Receiver<Option<NostrNotificationLoss>>, NostrAcquisitionError>
    {
        self.relay_client
            .notification_loss_for_account(account_id)
            .await
    }

    pub async fn metrics(&self) -> NostrAdapterMetrics {
        tracing::trace!(
            target: "transport_nostr_adapter::adapter",
            method = "metrics",
            "snapshotting adapter metrics"
        );
        let mut metrics = {
            let state = self.state.read().await;
            let mut metrics = state.metrics.clone();
            metrics.active_accounts = state.accounts.len();
            metrics.active_group_subscriptions = state
                .accounts
                .values()
                .map(|account| account.groups.len())
                .sum();
            metrics.unsubscribe_retries_pending =
                state.pending_unsubscribes.len() + state.pending_scoped_unsubscribes.len();
            metrics
        };
        let publish = self.publish_accounting.snapshot();
        metrics.publish_attempts = publish.attempts;
        metrics.publish_successes = publish.successes;
        metrics.publish_failures = publish.failures;
        metrics.publish_cancellations = publish.cancellations;
        metrics
    }

    /// Execute one already-validated logical publication and record it on this
    /// adapter's shared counters, including any endpoint or authentication retries.
    ///
    /// Callers keep account, endpoint-safety, and envelope checks. This method
    /// does not revalidate, build a request, or fan out locally. Success
    /// follows [`cgka_traits::TransportPublishReport::met_required_acks`]:
    /// `accepted >= required_acks.max(1)`. Any other `Ok` outcome and any
    /// `Err` count as one failure. Dropping this future after it has started
    /// counts as one cancellation; dropping it before it is polled counts
    /// nothing. The publication's outcome or error is returned unchanged.
    pub async fn publish_event_with_client(
        &self,
        publication: impl Future<Output = Result<NostrPublishOutcome, TransportAdapterError>>,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        let mut attempt = self.publish_accounting.begin();
        let outcome = publication.await;
        match &outcome {
            Ok(result)
                if publish_accounting::outcome_met_required_acks(
                    result.accepted.len(),
                    required_acks,
                ) =>
            {
                attempt.succeed();
                tracing::debug!(
                    target: "transport_nostr_adapter::adapter",
                    method = "publish_event_with_client",
                    accepted_count = result.accepted.len(),
                    failed_count = result.failed.len(),
                    "transport publish completed"
                );
            }
            Ok(result) => {
                attempt.fail();
                tracing::debug!(
                    target: "transport_nostr_adapter::adapter",
                    method = "publish_event_with_client",
                    accepted_count = result.accepted.len(),
                    failed_count = result.failed.len(),
                    "transport publish fell below the acceptance threshold"
                );
            }
            Err(_) => {
                attempt.fail();
                tracing::warn!(
                    target: "transport_nostr_adapter::adapter",
                    method = "publish_event_with_client",
                    "transport publish failed"
                );
            }
        }
        outcome
    }

    /// Record one privacy-safe aggregate NIP-77 result. These counters are
    /// diagnostic only and never feed routing, convergence, or cursor policy.
    #[cfg(feature = "sdk")]
    pub async fn record_reconciliation(&self, summary: &NostrReconciliationSummary) {
        let mut state = self.state.write().await;
        state.metrics.reconciliation_attempts += 1;
        state.metrics.reconciliation_relays_succeeded += summary.relays_succeeded;
        state.metrics.reconciliation_relays_failed += summary.relays_failed;
        state.metrics.reconciliation_remote_items += summary.remote_items;
        state.metrics.reconciliation_received_items += summary.received_items;
        state.metrics.reconciliation_order_unproven_passes += usize::from(summary.order_unproven);
    }

    /// Take the subscription-lifecycle lock (see `subscription_lock`), then
    /// wait for any subscribe task a dropped caller left running (see
    /// `subscribe_tasks`). No new task can start meanwhile: only holders of this
    /// lock spawn them.
    async fn lock_subscriptions(&self) -> OwnedMutexGuard<()> {
        let guard = self.subscription_lock.clone().lock_owned().await;
        settle_subscribe_tasks(&self.subscribe_tasks).await;
        guard
    }

    fn current_subscribe_tasks(&self) -> Arc<RwLock<()>> {
        self.subscribe_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    async fn subscribe_all(
        &self,
        caller: &'static str,
        subscriptions: &[NostrSubscription],
    ) -> Result<NostrSubscribeReport, TransportAdapterError> {
        let mut tasks = DetachOnDrop(JoinSet::new());
        for (sub_index, subscription) in subscriptions.iter().cloned().enumerate() {
            let relay_client = self.relay_client.clone();
            let state = self.state.clone();
            let lifecycle = self.subscription_lock.clone();
            let barriers = self.subscribe_tasks.clone();
            let barrier = self.current_subscribe_tasks();
            let in_flight = barrier.clone().read_owned().await;
            tasks.0.spawn(async move {
                let result = relay_client.subscribe_reporting(subscription.clone()).await;
                // A lifecycle operation that gave up waiting for this task
                // retired its barrier and may already have swept the account,
                // so a REQ registered now could be live with nothing tracking
                // it. Close it, unless the current routes want that id: a
                // group sync reuses its activation's ids, and then this REQ is
                // the one the live route needs.
                let retired = !Arc::ptr_eq(
                    &barrier,
                    &barriers
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()),
                );
                // Release the barrier before taking the lifecycle lock: its
                // holder may be waiting on the current barrier. A retired task
                // never has a caller waiting on it, because only the lock's
                // holder retires barriers.
                drop(in_flight);
                if retired && result.is_ok() {
                    // Check and close under the lifecycle lock, so neither can
                    // interleave with an activation that has swept but not yet
                    // installed its routes, or with a retry re-registering the
                    // same id. A failed close is queued for the next drain.
                    let _lifecycle = lifecycle.lock().await;
                    let wanted = state
                        .read()
                        .await
                        .live_subscription_route(&subscription.subscription_id())
                        .is_some();
                    if !wanted
                        && relay_client
                            .unsubscribe(subscription.clone())
                            .await
                            .is_err()
                    {
                        state
                            .write()
                            .await
                            .queue_pending_unsubscribes(vec![subscription]);
                    }
                }
                (sub_index, result)
            });
        }
        let tasks = &mut tasks.0;

        // Let every sibling finish after a failure instead of aborting it. An
        // aborted task can stop between handing its REQ to the relay client and
        // returning, and the caller's rollback `unsubscribe_account` would then
        // race that REQ. Subscribe calls queue REQs without waiting for relay
        // replies, so draining the rest is short.
        let mut first_error = None;
        let mut report = NostrSubscribeReport::default();
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((_sub_index, Ok(issued))) => report.add(issued),
                Ok((sub_index, Err(err))) => {
                    tracing::warn!(
                        target: "transport_nostr_adapter::adapter",
                        method = caller,
                        sub_index,
                        issued_count = subscriptions.len(),
                        "transport subscription failed"
                    );
                    first_error.get_or_insert(err);
                }
                Err(err) => {
                    first_error.get_or_insert_with(|| {
                        TransportAdapterError::Subscription(format!(
                            "subscription task failed: {err}"
                        ))
                    });
                }
            }
        }

        first_error.map_or(Ok(report), Err)
    }

    /// Drain relay unsubscribes queued in `pending_unsubscribes`. A local
    /// snapshot is iterated once; the authoritative queue is updated only on
    /// confirmed relay teardown so cancellation cannot lose unresolved
    /// cleanups.
    async fn drain_pending_unsubscribes(&self) -> (usize, usize) {
        let drain_snapshot = {
            let mut state = self.state.write().await;
            state.prune_live_pending_unsubscribes();
            state.pending_unsubscribes.clone()
        };

        let mut confirmed = 0_usize;
        let mut failed_count = 0_usize;
        for subscription in drain_snapshot {
            let subscription_id = subscription.subscription_id();
            match self.relay_client.unsubscribe(subscription).await {
                Ok(()) => {
                    let mut state = self.state.write().await;
                    if state.remove_pending_unsubscribe_by_id(&subscription_id) {
                        state.record_confirmed_unsubscribes(1);
                        confirmed += 1;
                    }
                }
                Err(_) => {
                    failed_count += 1;
                }
            }
        }
        let scoped = self.state.read().await.pending_scoped_unsubscribes.clone();
        for (id, subscription) in scoped {
            match self
                .relay_client
                .unsubscribe_scoped(subscription, id.clone())
                .await
            {
                Ok(()) => {
                    let mut state = self.state.write().await;
                    if state.pending_scoped_unsubscribes.remove(&id).is_some() {
                        state.record_confirmed_unsubscribes(1);
                        confirmed += 1;
                    }
                }
                Err(_) => failed_count += 1,
            }
        }
        (confirmed, failed_count)
    }

    /// Aggregate cross-relay arrival-spread snapshot for diagnostics and
    /// quiescence tuning. Privacy-safe: counts and millisecond buckets only.
    pub async fn delivery_spread(&self) -> RelayDeliverySpread {
        tracing::trace!(
            target: "transport_nostr_adapter::adapter",
            method = "delivery_spread",
            "snapshotting delivery spread"
        );
        self.state.read().await.telemetry.snapshot()
    }

    /// Aggregate subscription sync-timing snapshot (first-event and EOSE
    /// latencies, initial-sync completion counts). Privacy-safe.
    pub async fn relay_sync(&self) -> RelaySyncSnapshot {
        tracing::trace!(
            target: "transport_nostr_adapter::adapter",
            method = "relay_sync",
            "snapshotting relay sync timing"
        );
        self.state.read().await.sync.snapshot()
    }

    /// Initial-sync gate: whether every endpoint of `subscription_id` has
    /// reached EOSE. `None` for an unknown subscription.
    pub async fn subscription_synced(&self, subscription_id: &str) -> Option<bool> {
        let state = self.state.read().await;
        for coverage in state.account_replay_coverage.values() {
            if let Some(relays) = coverage.subscriptions.get(subscription_id) {
                return Some(
                    !relays.is_empty()
                        && relays.values().all(|replay| *replay == RelayReplay::Eose)
                        && coverage.request_admitted(subscription_id, None),
                );
            }
        }
        state.sync.subscription_synced(subscription_id)
    }

    /// Whether at least one relay has returned EOSE for a live subscription.
    pub async fn subscription_any_eose(&self, subscription_id: &str) -> Option<bool> {
        let state = self.state.read().await;
        for coverage in state.account_replay_coverage.values() {
            if let Some(relays) = coverage.subscriptions.get(subscription_id) {
                return Some(
                    relays.values().any(|replay| *replay == RelayReplay::Eose)
                        && coverage.request_admitted(subscription_id, None),
                );
            }
        }
        state.sync.subscription_any_eose(subscription_id)
    }

    /// Session-bound EOSE for one caller-supplied endpoint. Unknown or retired
    /// subscription membership returns None. This is a protocol boundary only,
    /// never exhaustive historical coverage or durable admission. No reverse
    /// relay-index mapping or diagnostic identity export is performed.
    pub async fn subscription_endpoint_eose(
        &self,
        subscription_id: &str,
        endpoint: &TransportEndpoint,
    ) -> Option<bool> {
        let state = self.state.read().await;
        let relay = state.relay_index.existing_index_for(endpoint)?;
        for coverage in state.account_replay_coverage.values() {
            if let Some(relays) = coverage.subscriptions.get(subscription_id) {
                return relays.get(&relay).map(|replay| {
                    *replay == RelayReplay::Eose
                        && coverage.request_admitted(subscription_id, Some(relay))
                });
            }
        }
        state
            .sync
            .subscription_endpoint_eose(subscription_id, relay)
    }

    /// End-of-stored-events progress across the account's live inbox and group
    /// batch REQs, with every endpoint retained as an independent proof
    /// obligation.
    ///
    /// A group sync that changes the routes replaces the batch entries with
    /// its repack's, staged before their REQs go out; a route it still wants
    /// is never owed from a later floor, and only a removed route stops being
    /// owed. This lets a caller draining an unfloored
    /// re-activation avoid mistaking a quiet or fast-empty relay for a finished
    /// history replay. It reports counts only: no ids, endpoints, or routes
    /// cross the boundary.
    pub async fn account_subscription_eose(
        &self,
        account_id: &MemberId,
    ) -> AccountSubscriptionEose {
        self.state
            .read()
            .await
            .account_subscription_eose(account_id)
    }

    /// Drain replay loss into the caller's cursor/recovery fence. Import a
    /// returned loss synchronously before awaiting again, then drop the status.
    /// Its read guard keeps replay admission stable through a synchronous seal.
    /// Evidence survives replacement and coalesced wakeups until taken.
    pub async fn take_replay_status<'a>(
        &'a self,
        account_id: &'a MemberId,
    ) -> ReplayAdmissionStatus<'a> {
        let state = self.state.read().await;
        let pending = state
            .account_replay_coverage
            .get(account_id)
            .is_some_and(AccountReplayCoverage::admission_pending)
            || state
                .replay_ingresses
                .get(account_id)
                .is_some_and(|ingress| ingress.held().0 != 0);
        let loss = self
            .replay_losses
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(account_id);
        ReplayAdmissionStatus {
            pending,
            spill_pending: false,
            loss,
            account_id,
            _guard: state,
        }
    }

    /// Observe source changes and same-generation admission progress.
    pub async fn replay_changes(
        &self,
        account_id: &MemberId,
    ) -> Option<tokio::sync::watch::Receiver<u64>> {
        self.state
            .read()
            .await
            .account_replay_coverage
            .get(account_id)
            .map(|coverage| coverage.changes.tx.subscribe())
    }

    /// Release the adapter's admission pin only after the delivery router has
    /// placed the event in its pinned queue/spill or recorded delivery loss.
    pub async fn ack_replay_delivery(&self, account_id: &MemberId, id: &MessageId) {
        if let Some(coverage) = self
            .state
            .write()
            .await
            .account_replay_coverage
            .get_mut(account_id)
        {
            coverage.ack_placement(id);
        }
    }

    /// Wake the delivery router when replay has been discarded. The account
    /// evidence remains available through [`Self::take_replay_status`].
    pub async fn replay_loss_notified(&self) {
        self.replay_losses.changed.notified().await;
    }

    /// Fence queued SDK input before dispatch. Epochs are captured in the
    /// relay's ordered stream, not polled from its already-advanced SDK state.
    pub async fn observe_replay_epoch(
        &self,
        account: Option<&MemberId>,
        endpoint: &TransportEndpoint,
        epoch: [u64; 2],
        reason: ReplayRestart,
    ) -> bool {
        {
            let mut state = self.state.write().await;
            let relay = state.relay_index.index_for(endpoint);
            let key = (account.cloned(), relay);
            let previous = state.replay_epochs.get(&key).copied();
            if let Some(previous) = previous {
                if epoch < previous {
                    return false;
                }
                if epoch == previous {
                    return true;
                }
            }
            state.replay_epochs.insert(key, epoch);
            let restart = if reason == ReplayRestart::ReceiverLoss
                || previous.is_some_and(|previous| previous[0] != epoch[0])
            {
                ReplayRestart::ReceiverLoss
            } else {
                ReplayRestart::Connection
            };
            for (account_id, coverage) in &mut state.account_replay_coverage {
                if account.is_some_and(|account| account != account_id) {
                    continue;
                }
                coverage.restart_relay(
                    relay,
                    restart,
                    if previous.is_none() {
                        ReplayOrigin::Initial
                    } else {
                        ReplayOrigin::Changed
                    },
                );
            }
        }
        true
    }

    /// The id of the live batch REQ carrying the account's group route
    /// `transport_group_id`, or `None` when no live batch carries it.
    pub async fn group_route_subscription_id(
        &self,
        account_id: &MemberId,
        transport_group_id: &[u8],
    ) -> Option<String> {
        let state = self.state.read().await;
        let routes = state.accounts.get(account_id)?;
        routes
            .batches
            .iter()
            .rev()
            .find(|batch| {
                matches!(batch, NostrSubscription::GroupBatch { routes, .. }
                    if routes.iter().any(|route| route.transport_group_id == transport_group_id))
            })
            .map(NostrSubscription::subscription_id)
    }

    /// The activation attempt an account's live subscriptions were issued
    /// under, or `None` when the account is not active.
    ///
    /// Subscription ids are attempt-scoped (see [`SubscriptionAttempt`]), so a
    /// caller that rebuilds the id of a live subscription from route state —
    /// rather than reading it off the [`NostrSubscription`] the adapter issued —
    /// must stamp the same attempt. `None` keeps "unknown account" distinct from
    /// [`SubscriptionAttempt::INITIAL`], which means "not activation-owned". It
    /// reports an ordinal only: no ids, endpoints, or routes cross the boundary.
    pub async fn account_subscription_attempt(
        &self,
        account_id: &MemberId,
    ) -> Option<SubscriptionAttempt> {
        self.state.read().await.activation_attempt(account_id)
    }

    /// Execute only the owner's frozen, current source capabilities. Accepted
    /// tickets belong to the supervisor; dropping this waiter cancels its own
    /// child IO without releasing its network credit before IO cleanup.
    pub async fn capture_replay(
        &self,
        account_id: &MemberId,
        mut plan: ReplayCapturePlan,
        cancellation: NostrAcquisitionCancellation,
    ) -> Result<ReplayCaptureOutcome, TransportAdapterError> {
        if cancellation.is_cancelled() {
            return Ok(ReplayCaptureOutcome::Cancelled);
        }
        plan.sources.sort_unstable_by(|a, b| {
            a.request
                .cmp(&b.request)
                .then_with(|| a.relay.0.cmp(&b.relay.0))
        });
        plan.sources.dedup();
        let Some(first) = plan.sources.first() else {
            return Ok(ReplayCaptureOutcome::Complete);
        };
        if &first.account_id != account_id {
            return Ok(ReplayCaptureOutcome::Stale);
        }
        let account = account_id.clone();
        let (mut changes, attempt, wake) = {
            let mut state = self.state.write().await;
            let valid = state
                .account_replay_coverage
                .get(&account)
                .is_some_and(|coverage| {
                    plan.sources.iter().all(|token| {
                        token.account_id == account
                            && token.generation == coverage.wire_generation
                            && !coverage.maintenance.contains(token.request.as_ref())
                            && coverage.windows.contains_key(token.request.as_ref())
                            && coverage
                                .subscriptions
                                .get(token.request.as_ref())
                                .and_then(|relays| relays.get(&token.relay))
                                .is_some_and(|replay| *replay != RelayReplay::Refused)
                    })
                });
            if !valid {
                return Ok(ReplayCaptureOutcome::Stale);
            }
            let high = state.capture_attempts.get(&account).copied();
            if high.is_some_and(|high| plan.attempt_serial < high) {
                return Ok(ReplayCaptureOutcome::Stale);
            }
            if high == Some(plan.attempt_serial) {
                let coverage = &state.account_replay_coverage[&account];
                let Some(attempt) = coverage.attempt.as_ref().filter(|attempt| {
                    attempt.serial == plan.attempt_serial
                        && attempt.sources.len() == plan.sources.len()
                        && attempt
                            .sources
                            .iter()
                            .zip(&plan.sources)
                            .all(|(source, token)| source.token == *token)
                }) else {
                    return Ok(ReplayCaptureOutcome::Stale);
                };
                (
                    coverage.changes.tx.subscribe(),
                    attempt.clone(),
                    coverage.wake.clone(),
                )
            } else {
                state
                    .capture_attempts
                    .insert(account.clone(), plan.attempt_serial);
                let AdapterState {
                    relay_index,
                    account_replay_coverage,
                    ..
                } = &mut *state;
                let coverage = account_replay_coverage
                    .get_mut(&account)
                    .expect("validated current account");
                let operation = cancellation.child_token();
                let mut sources: Vec<ReplayCapture> = Vec::with_capacity(plan.sources.len());
                for token in plan.sources {
                    let endpoint = relay_index
                        .resolve(token.relay)
                        .expect("issued endpoint remains indexed")
                        .clone();
                    // Never join a mechanical truncated tail after actual loss:
                    // an explicit owner operation always restores the full REQ.
                    let (window, serial) = coverage
                        .restart_request(token.request.as_ref(), token.relay, ReplayStart::Capture)
                        .expect("validated current source");
                    coverage
                        .endpoint_deadlines
                        .get_mut(token.request.as_ref())
                        .expect("current request")
                        .get_mut(&token.relay)
                        .expect("current endpoint")
                        .cancellation = operation.child_token();
                    coverage.queue_capture(ReplayPaging {
                        account_id: account.clone(),
                        subscription_id: token.request.to_string(),
                        endpoint,
                        relay: token.relay,
                        serial,
                        window,
                        until: REPLAY_OPEN_UNTIL,
                        credit: Some(plan.credit.clone()),
                    });
                    sources.push(ReplayCapture { token, serial });
                }
                let attempt = Arc::new(ReplayAttempt {
                    serial: plan.attempt_serial,
                    sources,
                    cancellation: operation.clone(),
                });
                coverage.attempt = Some(attempt.clone());
                (
                    coverage.changes.tx.subscribe(),
                    attempt,
                    coverage.wake.clone(),
                )
            }
        };
        let operation = attempt.cancellation.clone();
        let mut waiter = ReplayWaiter {
            cancellation: Some(operation.clone()),
            wake,
        };
        loop {
            let outcome = {
                let state = self.state.read().await;
                state
                    .account_replay_coverage
                    .get(&account)
                    .map_or(Some(ReplayCaptureOutcome::Stale), |coverage| {
                        coverage.capture_outcome(&attempt)
                    })
            };
            if let Some(outcome) = outcome {
                if matches!(
                    outcome,
                    ReplayCaptureOutcome::Complete | ReplayCaptureOutcome::Incomplete
                ) {
                    waiter.cancellation.take();
                }
                return Ok(outcome);
            }
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(ReplayCaptureOutcome::Cancelled),
                _ = operation.cancelled() => return Ok(ReplayCaptureOutcome::Cancelled),
                changed = changes.changed() => {
                    if changed.is_err() {
                        return Ok(ReplayCaptureOutcome::Stale);
                    }
                }
            }
        }
    }

    /// Install the temporary, full-history subscription used by the post-join
    /// maintenance gate. The caller owns its eventual removal.
    pub async fn install_group_maintenance_subscription(
        &self,
        account_id: &MemberId,
        group: &TransportGroupSubscription,
    ) -> Result<String, TransportAdapterError> {
        self.install_maintenance_subscription(account_id, group, None, None)
            .await
    }

    /// Install a maintenance session fenced by the recovery owner's durable
    /// attempt. Reusing a live token joins that session. Once removed or failed,
    /// a strictly greater token is required, including across account activation.
    ///
    /// `since` floors the history it requests, and with it the notification
    /// loss a lag can charge while it is live. `None` requests the group's full
    /// history and leaves that loss unbounded.
    pub async fn install_group_maintenance_recovery_subscription(
        &self,
        account_id: &MemberId,
        group: &TransportGroupSubscription,
        attempt: u64,
        since: Option<Timestamp>,
    ) -> Result<String, TransportAdapterError> {
        self.install_maintenance_subscription(account_id, group, Some(attempt), since)
            .await
    }

    async fn install_maintenance_subscription(
        &self,
        account_id: &MemberId,
        group: &TransportGroupSubscription,
        attempt: Option<u64>,
        since: Option<Timestamp>,
    ) -> Result<String, TransportAdapterError> {
        if attempt.is_some() && !self.relay_client.supports_scoped_subscriptions() {
            return Err(TransportAdapterError::Subscription(
                "scoped subscription unsupported".into(),
            ));
        }
        let subscription_guard = self.lock_subscriptions().await;
        let subscription = NostrSubscription::GroupMaintenance {
            account_id: account_id.clone(),
            group_id: group.group_id.clone(),
            transport_group_id: group.transport_group_id.clone(),
            endpoints: group.endpoints.clone(),
            since,
        };
        let subscription_id = match attempt {
            Some(attempt) => compact_subscription_id(
                "maintenance-recovery",
                &[
                    subscription.subscription_id().as_bytes(),
                    &attempt.to_be_bytes(),
                ],
            ),
            None => subscription.subscription_id(),
        };
        let now_ms = self.now_ms();
        {
            let mut state = self.state.write().await;
            if !state.accounts.contains_key(account_id) {
                return Err(TransportAdapterError::AccountNotActive(account_id.clone()));
            }
            if state.maintenance_routes.contains_key(&subscription_id) {
                return Ok(subscription_id);
            }
            if let Some(attempt) = attempt {
                let key = (account_id.clone(), group.group_id.clone());
                if state
                    .maintenance_attempt_high_water
                    .get(&key)
                    .is_some_and(|high| attempt <= *high)
                {
                    return Err(TransportAdapterError::Subscription(
                        "maintenance recovery attempt was already consumed".into(),
                    ));
                }
                // Burn before I/O. Cancellation and even a confirmed CLOSE can
                // leave late notifications, so removal never resets this fence.
                state.maintenance_attempt_high_water.insert(key, attempt);
            }
            // A history REQ can synchronously replay messages. Routing must
            // exist before SDK deduplication consumes their first delivery.
            state
                .maintenance_routes
                .insert(subscription_id.clone(), subscription.clone());
            state.rebuild_transport_group_index();
            state.record_scoped_subscription_start(&subscription, &subscription_id, now_ms);
            state.stage_replay_subscription(account_id, &subscription, subscription_id.clone());
        }

        let (complete, abandoned) = oneshot::channel();
        let cleanup_state = self.state.clone();

        let cleanup_subscription = subscription.clone();
        let cleanup_id = subscription_id.clone();
        tokio::spawn(async move {
            let _subscription_guard = subscription_guard;
            if abandoned.await.is_err() {
                let mut state = cleanup_state.write().await;
                state.maintenance_routes.remove(&cleanup_id);
                state.sync.forget_subscription(&cleanup_id);
                if let Some(coverage) = state
                    .account_replay_coverage
                    .get_mut(cleanup_subscription.account_id())
                {
                    coverage.remove_subscription(&cleanup_id);
                }
                if attempt.is_some() {
                    state
                        .pending_scoped_unsubscribes
                        .insert(cleanup_id, cleanup_subscription);
                }
                state.rebuild_transport_group_index();
                drop(state);
            }
        });
        let result = if attempt.is_some() {
            self.relay_client
                .subscribe_scoped(subscription.clone(), subscription_id.clone())
                .await
        } else {
            self.relay_client.subscribe(subscription.clone()).await
        };
        if let Err(error) = result {
            let mut state = self.state.write().await;
            state.maintenance_routes.remove(&subscription_id);
            state.sync.forget_subscription(&subscription_id);
            if let Some(coverage) = state.account_replay_coverage.get_mut(account_id) {
                coverage.remove_subscription(&subscription_id);
            }
            if attempt.is_some() {
                state
                    .pending_scoped_unsubscribes
                    .insert(subscription_id.clone(), subscription);
            }
            state.rebuild_transport_group_index();
            let _ = complete.send(());
            drop(state);

            return Err(error);
        }
        let _ = complete.send(());
        Ok(subscription_id)
    }

    /// Remove a temporary post-join maintenance subscription.
    pub async fn remove_group_maintenance_subscription(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        let _subscription_guard = self.lock_subscriptions().await;
        let subscription_id = subscription.subscription_id();
        {
            let mut state = self.state.write().await;
            state.maintenance_routes.remove(&subscription_id);
            state.forget_subscription_starts(std::slice::from_ref(&subscription));
            if let Some(coverage) = state
                .account_replay_coverage
                .get_mut(subscription.account_id())
            {
                coverage.remove_subscription(&subscription_id);
            }
            state.rebuild_transport_group_index();
            // Keep teardown intent through relay errors and caller cancellation.
            state.queue_pending_unsubscribes(vec![subscription.clone()]);
        }
        self.relay_client.unsubscribe(subscription).await?;
        self.state
            .write()
            .await
            .remove_pending_unsubscribe_by_id(&subscription_id);

        Ok(())
    }

    /// Remove an exact maintenance session, retaining teardown intent on
    /// cancellation or relay error. Unknown/already removed ids are idempotent.
    pub async fn remove_group_maintenance_recovery_subscription(
        &self,
        account_id: &MemberId,
        subscription_id: &str,
    ) -> Result<(), TransportAdapterError> {
        let _guard = self.lock_subscriptions().await;
        let subscription = {
            let mut state = self.state.write().await;
            let subscription = state
                .maintenance_routes
                .get(subscription_id)
                .or_else(|| state.pending_scoped_unsubscribes.get(subscription_id))
                .cloned();
            let Some(subscription) = subscription else {
                return Ok(());
            };
            if subscription.account_id() != account_id {
                return Err(TransportAdapterError::Subscription(
                    "maintenance account mismatch".into(),
                ));
            }
            state.maintenance_routes.remove(subscription_id);
            state.sync.forget_subscription(subscription_id);
            if let Some(coverage) = state.account_replay_coverage.get_mut(account_id) {
                coverage.remove_subscription(subscription_id);
            }
            state.rebuild_transport_group_index();
            state
                .pending_scoped_unsubscribes
                .insert(subscription_id.to_owned(), subscription.clone());
            subscription
        };
        self.relay_client
            .unsubscribe_scoped(subscription, subscription_id.to_owned())
            .await?;
        self.state
            .write()
            .await
            .pending_scoped_unsubscribes
            .remove(subscription_id);

        Ok(())
    }

    /// Resolve opaque relay indices to relay endpoints for the opt-in export
    /// label boundary.
    ///
    /// This is the ONLY path that turns a device-local [`RelayIndex`] into a
    /// relay URL. It requires a [`RelayExportConsent`], which must be minted
    /// only where the user has opted in to relay telemetry export. Privacy
    /// contract: `docs/marmot-architecture/relay-observability.md`.
    pub async fn resolve_relay_labels(&self, _consent: RelayExportConsent) -> RelayLabelResolution {
        let state = self.state.read().await;
        RelayLabelResolution::from_pairs(state.relay_index.resolutions())
    }

    /// Local monotonic timestamp in milliseconds for delivery telemetry. Never
    /// the publisher-controlled `created_at`.
    fn now_ms(&self) -> u64 {
        self.monotonic_start.elapsed().as_millis() as u64
    }

    /// Convert a relay event into zero or more account-scoped deliveries.
    ///
    /// Invalid Nostr DTOs fail closed before the engine sees them. Valid but
    /// unsubscribed messages are dropped with `Ok(0)`.
    pub async fn handle_relay_event(
        &self,
        relay_event: NostrRelayEvent,
    ) -> Result<usize, TransportAdapterError> {
        self.handle_relay_event_scoped(relay_event, None, RelayCopy::Deduplicated)
            .await
    }

    /// Route a reconciliation result only to the account whose exact set was
    /// compared. The SDK database is shared across local accounts, so relying
    /// on its global duplicate suppression would otherwise let one account's
    /// cached copy mask another account's missing delivery.
    pub async fn handle_reconciled_event(
        &self,
        account_id: &MemberId,
        relay_event: NostrRelayEvent,
    ) -> Result<usize, TransportAdapterError> {
        self.handle_relay_event_scoped(relay_event, Some(account_id), RelayCopy::Deduplicated)
            .await
    }

    /// Route a verified raw group copy to its issuing account, including
    /// SDK-seen replay. Retired ids cannot deliver abandoned partial history.
    pub async fn handle_group_relay_copy(
        &self,
        relay_event: NostrRelayEvent,
        account_id: Option<&MemberId>,
    ) -> Result<usize, TransportAdapterError> {
        if relay_event.event.kind != KIND_MARMOT_GROUP_MESSAGE {
            return Ok(0);
        }
        let Some(subscription_id) = relay_event.subscription_id.as_deref() else {
            return Ok(0);
        };
        let Some(account) = self.group_copy_account(subscription_id, account_id).await else {
            return Ok(0);
        };
        self.handle_relay_event_scoped(relay_event, Some(&account), RelayCopy::RawGroup)
            .await
    }

    async fn group_copy_account(
        &self,
        id: &str,
        account_id: Option<&MemberId>,
    ) -> Option<MemberId> {
        let state = self.state.read().await;
        let owns = |coverage: &AccountReplayCoverage| {
            coverage
                .windows
                .get(id)
                .is_some_and(|window| matches!(window.scope, ReplayScope::Groups(_)))
        };
        match account_id {
            Some(account) => state
                .account_replay_coverage
                .get(account)
                .filter(|coverage| owns(coverage))
                .map(|_| account.clone()),
            // Shared SDK delivery still has a concrete issuing REQ. Another
            // account receives its own raw copy, including SDK-seen events.
            None => state
                .account_replay_coverage
                .iter()
                .find_map(|(account, coverage)| owns(coverage).then(|| account.clone())),
        }
    }

    /// Existing buffered bodies own their authenticated routing metadata;
    /// another SDK-verified relay copy adds only its independent source claim.
    #[cfg(feature = "sdk")]
    async fn handle_sdk_group_copy(
        &self,
        event: &nostr::prelude::Event,
        endpoint: TransportEndpoint,
        subscription_id: String,
        account_id: Option<&MemberId>,
    ) -> Result<usize, TransportAdapterError> {
        let Some(account) = self.group_copy_account(&subscription_id, account_id).await else {
            if !event.verify_id() {
                return Err(TransportAdapterError::InvalidInboundSignature);
            }
            self.observe_relay_event(
                event.id.as_bytes(),
                &endpoint,
                Some(&subscription_id),
                event.created_at.as_secs(),
            )
            .await;
            return Ok(0);
        };
        let id = event.id.to_bytes();
        let mut route = [0; 32];
        let route = event
            .tags
            .iter()
            .find_map(|tag| {
                let [name, value] = tag.as_slice() else {
                    return None;
                };
                (name == "h").then_some(value)
            })
            .filter(|value| hex::decode_to_slice(value, &mut route).is_ok())
            .map(|_| route);
        let parsed_endpoint = RelayUrl::parse(endpoint.as_str()).ok();
        {
            let mut state = self.state.write().await;
            let created_at = route.as_ref().and_then(|route| {
                let coverage = state.account_replay_coverage.get(&account)?;
                state
                    .by_transport_group
                    .get(route.as_slice())?
                    .iter()
                    .find_map(|entry| {
                        coverage
                            .groups
                            .get(&entry.group_id)?
                            .events
                            .get(&id)
                            .map(|held| held.delivery.message.timestamp.0)
                    })
            });
            let relay = state.relay_index.existing_index_for(&endpoint);
            let AdapterState {
                by_transport_group,
                account_replay_coverage,
                ..
            } = &mut *state;
            if let (Some(relay), Some(route), Some(coverage)) =
                (relay, route, account_replay_coverage.get_mut(&account))
            {
                coverage.expire_replay(tokio::time::Instant::now());
                let entries = by_transport_group
                    .get(route.as_slice())
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let matching = entries.iter().filter(|entry| {
                    entry.account_id == account
                        && entry
                            .endpoints
                            .iter()
                            .any(|candidate| candidate.matches(&endpoint, parsed_endpoint.as_ref()))
                });
                let released_live = !coverage.copy_is_historical(&subscription_id, relay)
                    && coverage.released.contains(&id);
                if released_live
                    || (created_at.is_some()
                        && matching.clone().all(|entry| {
                            coverage
                                .groups
                                .get(&entry.group_id)
                                .and_then(|group| group.events.get(&id))
                                .is_some_and(|held| {
                                    matches!(&held.delivery.message.envelope,
                            TransportEnvelope::GroupMessage { transport_group_id }
                                if transport_group_id.as_slice() == route.as_slice())
                                })
                        }))
                {
                    let mut delivered = 0;
                    for entry in matching {
                        if !released_live {
                            coverage.claim_buffered_copy(
                                &entry.group_id,
                                id,
                                &subscription_id,
                                relay,
                            );
                        }
                        delivered += 1;
                    }
                    let now_ms = self.now_ms();
                    if let Some(created_at) = created_at {
                        state.observe_relay_id(
                            &id,
                            &endpoint,
                            Some(&subscription_id),
                            created_at,
                            now_ms,
                        );
                    } else {
                        // Released live duplicates have no stored-page slot.
                        state.record_delivery_timing(&id, &endpoint, now_ms);
                        state.record_subscription_first_event(&subscription_id, &endpoint, now_ms);
                    }
                    state.record_inbound_event(delivered);
                    return Ok(delivered);
                }
            }
        }
        #[cfg(test)]
        self.sdk_dto_builds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let relay_event = NostrRelayEvent {
            endpoint,
            subscription_id: Some(subscription_id),
            event: NostrTransportEvent::from_nostr_event(event).map_err(map_inbound_event_error)?,
        };
        let message = match relay_event.event.to_transport_message() {
            Ok(message) => message,
            Err(error) => {
                if event.verify_id()
                    && let Some(subscription_id) = relay_event.subscription_id
                {
                    self.observe_unconvertible_relay_event(
                        relay_event.endpoint,
                        subscription_id,
                        event.created_at.as_secs(),
                    )
                    .await;
                }
                return Err(map_inbound_event_error(error));
            }
        };
        // Bind uncached metadata to the authenticated id before replay accounting.
        self.observe_relay_event(
            &id,
            &relay_event.endpoint,
            relay_event.subscription_id.as_deref(),
            message.timestamp.0,
        )
        .await;
        self.admit_relay_message(&relay_event, message, Some(&account), RelayCopy::RawGroup)
            .await
    }

    /// Route a comparison result to one account without the delivery queue.
    /// The caller admits each delivery itself, a few per worker turn.
    pub async fn reconciled_deliveries(
        &self,
        account_id: &MemberId,
        relay_event: NostrRelayEvent,
    ) -> Result<Vec<TransportDelivery>, TransportAdapterError> {
        let message = relay_event
            .event
            .to_transport_message()
            .map_err(map_inbound_event_error)?;
        relay_event
            .event
            .to_verified_nostr_event()
            .map_err(map_inbound_event_error)?;
        let mut state = self.state.write().await;
        let deliveries = state.deliveries_for(&relay_event, message, Some(account_id));
        state.record_inbound_event(deliveries.len());
        Ok(deliveries)
    }

    async fn handle_relay_event_scoped(
        &self,
        relay_event: NostrRelayEvent,
        account_id: Option<&MemberId>,
        copy: RelayCopy,
    ) -> Result<usize, TransportAdapterError> {
        let message = relay_event
            .event
            .to_transport_message()
            .map_err(map_inbound_event_error)?;
        relay_event
            .event
            .to_verified_nostr_event()
            .map_err(map_inbound_event_error)?;
        self.admit_relay_message(&relay_event, message, account_id, copy)
            .await
    }

    async fn admit_relay_message(
        &self,
        relay_event: &NostrRelayEvent,
        message: TransportMessage,
        account_id: Option<&MemberId>,
        copy: RelayCopy,
    ) -> Result<usize, TransportAdapterError> {
        let mut state = self.state.write().await;
        let deliveries = state.deliveries_for(relay_event, message, account_id);
        let delivered = state.admit_deliveries(deliveries, copy, &self.delivery_tx)?;
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "handle_relay_event", delivered,
            "handled relay event"
        );
        Ok(delivered)
    }

    /// Record telemetry for one relay's copy of an event, taken from the raw
    /// per-relay stream.
    ///
    /// Unlike [`Self::handle_relay_event`], this performs no delivery. It exists
    /// to observe every relay copy — including duplicates the delivery path
    /// deduplicates away — so cross-relay arrival spread and per-relay
    /// first-event timing can be measured. Timing uses the adapter's monotonic
    /// clock, never the publisher-controlled `created_at`. The caller supplies
    /// an authenticated event id; this path does not inspect or serialize a body.
    ///
    /// It also counts each relay's stored events for an activation REQ before
    /// that relay's EOSE, so [`Self::handle_relay_eose`] can tell a replay the
    /// relay may have clamped (see [`RELAY_REPLAY_PAGE_LIMIT`]). Callers must
    /// pass a relay's copies in order with its EOSE.
    pub async fn observe_relay_event(
        &self,
        id: &[u8],
        endpoint: &TransportEndpoint,
        subscription_id: Option<&str>,
        created_at: u64,
    ) {
        let now_ms = self.now_ms();
        self.state.write().await.observe_relay_id(
            id,
            endpoint,
            subscription_id,
            created_at,
            now_ms,
        );
    }

    /// Count one relay's copy of a stored event that could not be converted
    /// to a [`NostrTransportEvent`] at all. The relay still spent a slot of
    /// its replay page on it (see [`RELAY_REPLAY_PAGE_LIMIT`]), so notification
    /// consumers report it here, in order with the relay's EOSE, instead of
    /// dropping it.
    pub async fn observe_unconvertible_relay_event(
        &self,
        endpoint: TransportEndpoint,
        subscription_id: String,
        created_at: u64,
    ) {
        self.state.write().await.record_stored_replay_event(
            &subscription_id,
            &endpoint,
            created_at,
        );
    }

    /// Record a relay's `CLOSED` for a subscription on one relay endpoint.
    ///
    /// For a live inbox, group or maintenance REQ, a dropped refusal settles
    /// that relay's replay coverage (see [`AccountSubscriptionEose::settled`])
    /// without completing it, and every refusal is counted in
    /// [`Self::relay_sync`] and queued for [`Self::take_subscription_refusals`].
    /// A close for any other id, such as a superseded attempt or a one-shot
    /// fetch, is ignored. This produces no delivery and sends nothing.
    pub async fn handle_relay_closed(
        &self,
        endpoint: TransportEndpoint,
        subscription_id: String,
        refusal: SubscriptionRefusal,
    ) {
        let live = self.state.write().await.record_subscription_refusal(
            &subscription_id,
            &endpoint,
            refusal,
        );
        if let Some((account_id, route_kind)) = &live {
            self.subscription_refusals
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entry(account_id.clone())
                .or_default()
                .record(*route_kind, &endpoint, refusal);
        }

        let route_kind = live.map(|(_, route_kind)| route_kind);
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "handle_relay_closed",
            live = route_kind.is_some(),
            route_kind = route_kind.map(SubscriptionRouteKind::as_str),
            category = refusal.category.map(TransportEndpointRejectionCategory::as_str),
            disposition = refusal.disposition.as_str(),
            "handled relay closed"
        );
    }

    /// Drain the subscription refusals recorded for `account_id` since the
    /// last drain, for the forensic audit. Carries relay endpoints: record
    /// them only on the consented audit channel, never in logs. Reports
    /// outlive deactivation, bounded per account, until drained.
    pub fn take_subscription_refusals(&self, account_id: &MemberId) -> SubscriptionRefusalReports {
        let pending = self
            .subscription_refusals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(account_id)
            .unwrap_or_default();
        SubscriptionRefusalReports {
            reports: pending.reports,
            dropped: pending.dropped,
        }
    }

    /// Record an end-of-stored-events signal for a subscription on one relay
    /// endpoint. This advances the initial-sync gate; it produces no delivery.
    ///
    /// When the relay sent a full page of stored events for an activation REQ
    /// first, it may have clamped the replay (see [`RELAY_REPLAY_PAGE_LIMIT`]).
    /// That relay's coverage then waits while older pages are fetched in the
    /// background and delivered like reconciled events.
    pub async fn handle_relay_eose(&self, endpoint: TransportEndpoint, subscription_id: String) {
        let now_ms = self.now_ms();
        self.state
            .write()
            .await
            .record_subscription_eose(&subscription_id, &endpoint, now_ms);

        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "handle_relay_eose",
            "handled relay eose"
        );
    }
}

/// Owns work across frontend replacement without retaining the delivery receiver.
struct ReplaySupervisor {
    state: std::sync::Weak<RwLock<AdapterState>>,
    relay_client: Arc<dyn NostrRelayClient>,
    delivery_tx: mpsc::Sender<TransportDelivery>,
    account_id: MemberId,
    cancellation: NostrAcquisitionCancellation,
    wake: Arc<Notify>,
    monotonic_start: Instant,
}

impl ReplaySupervisor {
    async fn run(self: Arc<Self>) {
        let mut tasks = JoinSet::new();
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let deadline = {
                let Some(state) = self.state.upgrade() else {
                    return;
                };
                let mut guard = state.write().await;
                if self.cancellation.is_cancelled() {
                    return;
                }
                let Some(coverage) = guard.account_replay_coverage.get_mut(&self.account_id) else {
                    return;
                };
                coverage.admit_retained();
                coverage.publish_native_progress();
                coverage.expire_replay(tokio::time::Instant::now());
                coverage.refresh_boundaries();
                let mut deadline = coverage.deadlines.first_key_value().map(|(at, _)| *at);
                for endpoint in coverage
                    .endpoint_deadlines
                    .values_mut()
                    .flat_map(HashMap::values_mut)
                {
                    if let Some(paging) = endpoint.queued.take() {
                        let owner = self.clone();
                        tasks.spawn(async move { owner.page_replay(paging).await });
                    }
                    if let Some(next) = endpoint.deadline {
                        deadline = Some(deadline.map_or(next, |at| at.min(next)));
                    }
                }
                if !coverage.flushing && coverage.has_ready_deliveries() {
                    coverage.flushing = true;
                    let owner = self.clone();
                    tasks.spawn(async move { owner.drain_deliveries().await });
                }
                deadline
            };
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => return,
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = result {
                        {
                            let Some(state) = self.state.upgrade() else {
                                return;
                            };
                            let mut guard = state.write().await;
                            if self.cancellation.is_cancelled() {
                                return;
                            }
                            if let Some(coverage) = guard.account_replay_coverage.get_mut(&self.account_id) {
                                coverage.fail_execution();
                            }
                        }
                        // Fence lost bodies before cancelling the remaining work.
                        tasks.shutdown().await;
                        tracing::error!(target: "transport_nostr_adapter::adapter",
                            method = "replay_supervisor", panicked = error.is_panic(),
                            "stopped replay work after executor failure");
                    }
                },
                _ = &mut notified => {},
                _ = async { match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }} => {},
            }
        }
    }

    async fn drain_deliveries(&self) {
        loop {
            let mut deliveries = {
                let Some(state) = self.state.upgrade() else {
                    return;
                };
                let mut guard = state.write().await;
                if self.cancellation.is_cancelled() {
                    return;
                }
                let Some(coverage) = guard.account_replay_coverage.get_mut(&self.account_id) else {
                    return;
                };
                let deliveries = coverage.take_ready_deliveries();
                if deliveries.is_empty() {
                    coverage.flushing = false;
                    coverage.refresh_boundaries();
                    coverage.wake_replay();
                    return;
                }
                VecDeque::from(deliveries)
            };
            while let Some(delivery) = deliveries.pop_front() {
                let permit = tokio::select! {
                    biased;
                    _ = self.cancellation.cancelled() => return,
                    permit = self.delivery_tx.reserve() => permit,
                };
                let Some(state) = self.state.upgrade() else {
                    return;
                };
                let mut guard = state.write().await;
                if self.cancellation.is_cancelled() {
                    return;
                }
                let Some(coverage) = guard.account_replay_coverage.get_mut(&self.account_id) else {
                    return;
                };
                let Ok(permit) = permit else {
                    coverage.fail_execution();
                    return;
                };
                if coverage.releasing_items == 0 {
                    // A failed sibling already discarded this cached range
                    // and recorded its loss before aborting the drain task.
                    return;
                }
                // Capacity waits may cross a metadata-only source restart or
                // an older arrival. Rejoin the still-owned suffix before any
                // unstarted handoff; the next range is sorted after all peers
                // settle. The permit send and this check share the state lock.
                if delivery.group_id_hint.as_ref().is_some_and(|id| {
                    coverage.groups.get(id).is_some_and(|group| {
                        !coverage.group_ready(group) || !group.events.is_empty()
                    })
                }) {
                    deliveries.push_front(delivery);
                    coverage.restore_draining(deliveries);
                    break;
                }
                coverage.releasing_items -= 1;
                coverage.releasing_bytes -= delivery.message.payload.len();
                permit.send(delivery);
            }
        }
    }

    async fn wait_route_release(&self, paging: &ReplayPaging, window: &ReplayWindow) -> bool {
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (pending, cancellation) = {
                let Some(state) = self.state.upgrade() else {
                    return false;
                };
                let guard = state.read().await;
                let Some(coverage) = guard.account_replay_coverage.get(&self.account_id) else {
                    return false;
                };
                if !coverage.capture_current(paging) {
                    return false;
                }
                (
                    coverage.route_release_pending(paging, window),
                    coverage.endpoint_deadlines[&paging.subscription_id][&paging.relay]
                        .cancellation
                        .clone(),
                )
            };
            if !pending {
                return true;
            }
            // Peer claims have their own finite service leases. They do not
            // spend this source's network allowance or abandon its next group.
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => return false,
                _ = cancellation.cancelled() => return false,
                _ = &mut notified => {},
            }
        }
    }

    async fn page_replay(&self, paging: ReplayPaging) {
        async {
            let units = {
                let Some(state) = self.state.upgrade() else {
                    return;
                };
                let guard = state.read().await;
                let Some(coverage) = guard.account_replay_coverage.get(&self.account_id) else {
                    return;
                };
                if self.cancellation.is_cancelled() || !coverage.capture_current(&paging) {
                    return;
                }
                coverage.page_units(&paging)
            };
            let mut pages = 0;
            let mut delivered = 0;
            let mut complete = true;
            // Canonical group order prevents overlapping sources waiting in a cycle.
            for unit in units {
                for route in unit.per_route() {
                    {
                        let Some(state) = self.state.upgrade() else {
                            return;
                        };
                        let mut guard = state.write().await;
                        let Some(coverage) =
                            guard.account_replay_coverage.get_mut(&self.account_id)
                        else {
                            return;
                        };
                        if self.cancellation.is_cancelled() || !coverage.capture_current(&paging) {
                            return;
                        }
                        if !coverage.start_route(&paging, &route) {
                            complete = false;
                            continue;
                        }
                    }
                    let outcome = self
                        .page_window(
                            &paging,
                            &route,
                            paging.until,
                            route.max_pages(),
                            &mut pages,
                            &mut delivered,
                        )
                        .await;
                    let Some(state) = self.state.upgrade() else {
                        return;
                    };
                    let mut guard = state.write().await;
                    let Some(coverage) = guard.account_replay_coverage.get_mut(&self.account_id)
                    else {
                        return;
                    };
                    if self.cancellation.is_cancelled() || !coverage.capture_current(&paging) {
                        return;
                    }
                    if outcome != PagedWindow::Complete || !coverage.finish_route(&paging, &route) {
                        complete = false;
                        coverage.fail_route(&paging, &route);
                    }
                }
                if !self.wait_route_release(&paging, &unit).await {
                    return;
                }
            }
            {
                let Some(state) = self.state.upgrade() else {
                    return;
                };
                let mut guard = state.write().await;
                if self.cancellation.is_cancelled() {
                    return;
                }
                if complete {
                    guard.finish_replay_paging(
                        &paging,
                        self.monotonic_start.elapsed().as_millis() as u64,
                    );
                } else if let Some(coverage) =
                    guard.account_replay_coverage.get_mut(&self.account_id)
                    && coverage.capture_current(&paging)
                {
                    coverage.stop_capture(&paging.subscription_id, paging.relay);
                }
            }
            tracing::debug!(target: "transport_nostr_adapter::adapter",
            method = "page_replay", pages, delivered, "paged a clamped relay replay");
        }
        .await;
        if let Some(state) = self.state.upgrade() {
            let mut guard = state.write().await;
            if let Some(coverage) = guard.account_replay_coverage.get_mut(&self.account_id)
                && coverage.capture_current(&paging)
            {
                coverage.stop_capture(&paging.subscription_id, paging.relay);
            }
        }
        // The borrowed network future and source cleanup have both ended.
        // No IO scope can outlive its accepted owner's capacity.
        drop(paging.credit);
    }

    async fn page_window(
        &self,
        paging: &ReplayPaging,
        window: &ReplayWindow,
        mut until: u64,
        max_pages: usize,
        pages: &mut usize,
        delivered: &mut usize,
    ) -> PagedWindow {
        let mut window_pages = 0;
        let mut retrying = false;
        loop {
            if until < window.since || until > REPLAY_OPEN_UNTIL {
                return PagedWindow::Incomplete;
            }
            let (cancellation, deadline) = {
                let Some(state) = self.state.upgrade() else {
                    return PagedWindow::Closed;
                };
                let guard = state.read().await;
                let Some(coverage) = guard.account_replay_coverage.get(&self.account_id) else {
                    return PagedWindow::Closed;
                };
                if self.cancellation.is_cancelled() || !coverage.page_allowed(paging, window) {
                    return PagedWindow::Closed;
                }
                let Some(deadline) = coverage.page_deadline(paging, window) else {
                    return PagedWindow::Closed;
                };
                (
                    coverage.endpoint_deadlines[&paging.subscription_id][&paging.relay]
                        .cancellation
                        .clone(),
                    deadline,
                )
            };
            if window_pages == max_pages {
                return PagedWindow::Incomplete;
            }
            window_pages += 1;
            *pages += 1;
            let request = NostrAcquisitionRequest {
                account_id: self.account_id.clone(),
                scope: window.acquisition_scope(until),
                endpoints: vec![paging.endpoint.clone()],
                limits: NostrAcquisitionLimits {
                    max_duration: deadline.saturating_duration_since(tokio::time::Instant::now()),
                    ..REPLAY_PAGE_LIMITS
                },
            };
            let result = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return PagedWindow::Closed,
                result = tokio::time::timeout_at(deadline, self.relay_client.acquire_history(request, cancellation.clone())) => {
                    match result {
                        Ok(result) => result,
                        Err(_) => return PagedWindow::Incomplete,
                    }
                }
            };
            let page = match result {
                Ok(mut result) => match result.endpoints.pop() {
                    Some(page) => page,
                    None => return PagedWindow::Incomplete,
                },
                Err(NostrAcquisitionError::Unsupported | NostrAcquisitionError::InvalidRequest) => {
                    return PagedWindow::Incomplete;
                }
            };
            let received = page.events.len();
            let oldest = page.events.iter().map(|event| event.created_at).min();
            for event in page.events {
                let relay_event = NostrRelayEvent {
                    endpoint: paging.endpoint.clone(),
                    subscription_id: Some(paging.subscription_id.clone()),
                    event,
                };
                // Decode outside the state lock, once for all destinations.
                let Ok(message) = relay_event.event.to_transport_message() else {
                    continue;
                };
                if relay_event.event.to_verified_nostr_event().is_err() {
                    continue;
                }
                let Some(state) = self.state.upgrade() else {
                    return PagedWindow::Closed;
                };
                let mut guard = state.write().await;
                if cancellation.is_cancelled()
                    || !guard
                        .account_replay_coverage
                        .get(&self.account_id)
                        .is_some_and(|coverage| coverage.page_allowed(paging, window))
                {
                    // This is a decoded acquired body being discarded, not
                    // an empty cancellation or a missing metadata boundary.
                    guard
                        .replay_losses
                        .record(&self.account_id, paging.window.since);
                    return PagedWindow::Closed;
                }
                let deliveries =
                    guard.deliveries_for(&relay_event, message, Some(&self.account_id));
                match guard.admit_deliveries(
                    deliveries,
                    RelayCopy::Page(paging.serial),
                    &self.delivery_tx,
                ) {
                    Ok(count) => *delivered += count,
                    Err(TransportAdapterError::Closed) => return PagedWindow::Closed,
                    Err(_) => unreachable!("delivery admission only reports a closed channel"),
                }
            }
            if page.end != NostrAcquisitionEnd::RequestPolicySatisfied {
                if !retrying
                    && matches!(
                        page.end,
                        NostrAcquisitionEnd::Deadline
                            | NostrAcquisitionEnd::Disconnected
                            | NostrAcquisitionEnd::RelayClosed
                    )
                {
                    retrying = true;
                    continue;
                }
                return PagedWindow::Incomplete;
            }
            retrying = false;
            // Inclusive boundary copies share a body; a stuck full second is
            // explicit incomplete coverage, never a reason to skip that second.
            match oldest {
                Some(oldest) if received >= RELAY_REPLAY_PAGE_LIMIT && oldest < until => {
                    until = oldest
                }
                Some(_) if received >= RELAY_REPLAY_PAGE_LIMIT => {
                    return PagedWindow::Saturated(until);
                }
                _ => return PagedWindow::Complete,
            }
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl TransportAdapter for NostrTransportAdapter {
    async fn activate_account(
        &self,
        activation: TransportAccountActivation,
    ) -> Result<(), TransportAdapterError> {
        // Serialize with sync/deactivate so this account's re-subscribe cannot
        // interleave a concurrent sync's unsubscribe drain (see the field doc).
        let _subscription_guard = self.lock_subscriptions().await;
        let account_id = activation.account_id.clone();
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "activate_account",
            inbox_endpoint_count = activation.inbox_endpoints.len(),
            group_subscription_count = activation.group_subscriptions.len(),
            "activating transport account"
        );
        // Read the replaced route count and the attempt this activation issues
        // under together, under the subscription lock that serializes every
        // activate/sync/deactivate. Stamping the attempt into the re-issued ids
        // is what keeps a superseded attempt's in-flight EOSE from landing on
        // the coverage this activation is about to reset.
        let (replaced_count, attempt) = {
            let state = self.state.read().await;
            (
                state
                    .accounts
                    .get(&account_id)
                    .map(|routes| 1 + routes.batches.len())
                    .unwrap_or_default(),
                state.next_activation_attempt(&account_id),
            )
        };
        let prior_route_keys = prior_group_route_keys(&account_id, &activation.group_subscriptions);
        let routes = activation
            .group_subscriptions
            .iter()
            .map(|group| {
                let since =
                    group_route_since(&account_id, group, &prior_route_keys, activation.since);
                group_subscription(&account_id, group, since, attempt)
            })
            .collect::<Vec<_>>();
        // Every group route goes out in a batch REQ (#2266).
        let batches = pack_group_batches(&account_id, &routes, attempt, 0);
        let mut issued = Vec::with_capacity(1 + batches.len());
        issued.push(account_inbox_subscription(
            &account_id,
            activation.inbox_endpoints.clone(),
            inbox_since(activation.since),
            attempt,
        ));
        issued.extend(batches.iter().cloned());
        // Unconditional, not gated on live local routes. Attempt-scoped ids mean
        // a re-issued REQ no longer replaces its predecessor relay-side, and a
        // rolled-back activation can leave `accounts` empty while the relay
        // client still holds this account's subscriptions. An orphaned REQ
        // double-delivers, because routing is content-keyed rather than
        // subscription-keyed. Transfer planned ownership before closing old
        // REQs so sockets needed by the replacement stay open.
        if let Err(error) = self
            .relay_client
            .unsubscribe_account(&account_id, &issued)
            .await
        {
            self.state.write().await.metrics.activations_failed += 1;
            return Err(error);
        }

        // Register routing/telemetry state BEFORE the relay REQs go out: a
        // relay may stream stored events the moment it sees a subscription,
        // and an event arriving before the routes exist is dropped as
        // unroutable — stored catch-up history would be lost with nothing to
        // re-request it.
        {
            let now_ms = self.now_ms();
            let mut state = self.state.write().await;
            // Reactivation replaces the account's routes; evict telemetry for
            // the old subscription ids first (before recording the new starts,
            // since unchanged endpoint sets reuse the same ids).
            state.forget_account_subscription_starts(&account_id);
            // The blanket `unsubscribe_account` above supersedes any queued
            // per-subscription unsubscribes for this account.
            state.clear_pending_unsubscribes_for_account(&account_id);
            state.record_subscription_starts(&issued, now_ms);
            state.record_account_replay_start(&account_id, &issued);
            state.activate(activation, replaced_count, attempt, &routes, &batches);
            let coverage = &state.account_replay_coverage[&account_id];
            let owner = Arc::new(ReplaySupervisor {
                state: Arc::downgrade(&self.state),
                relay_client: self.relay_client.clone(),
                delivery_tx: self.delivery_tx.clone(),
                account_id: account_id.clone(),
                cancellation: coverage.cancellation.clone(),
                wake: coverage.wake.clone(),
                monotonic_start: self.monotonic_start,
            });
            tokio::spawn(owner.run());
        }

        let report = match self.subscribe_all("activate_account", &issued).await {
            Ok(report) => report,
            Err(error) => {
                // Some concurrent REQs may already have succeeded. Tear those
                // down best-effort, then always remove the pre-registered local
                // routes so callers never observe a half-active account.
                //
                // `state.activate` above already ran, so this activation's attempt
                // is in the high-water map before `subscribe_all` was even tried.
                // The retry depends on that ordering: `deactivate` below drops the
                // routes but not the high-water mark, so the retry issues a fresh
                // attempt rather than reusing the ids of REQs that did reach a
                // relay and are still streaming.
                let relay_cleanup_failed = self
                    .relay_client
                    .unsubscribe_account(&account_id, &[])
                    .await
                    .is_err();
                let mut state = self.state.write().await;
                state.forget_account_subscription_starts(&account_id);
                state.clear_pending_unsubscribes_for_account(&account_id);
                state.deactivate(&account_id, issued.len());
                state.metrics.activations_failed += 1;
                tracing::warn!(
                    target: "transport_nostr_adapter::adapter",
                    method = "activate_account",
                    relay_cleanup_failed,
                    "rolled back transport account after subscription failure"
                );
                return Err(error);
            }
        };
        {
            let mut state = self.state.write().await;
            if report.is_degraded() {
                state.metrics.activations_degraded += 1;
            } else {
                state.metrics.activations_full += 1;
            }
        }
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "activate_account",
            issued_count = issued.len(),
            owed_relay_count = report.owed_relays,
            refused_relay_count = report.refused_relays,
            "all transport subscriptions issued"
        );
        Ok(())
    }

    async fn sync_account_groups(
        &self,
        sync: TransportGroupSync,
    ) -> Result<(), TransportAdapterError> {
        // Serialize against other subscription-lifecycle operations so the
        // drain's live-route filter and its relay unsubscribes cannot race a
        // concurrent re-add of the same deterministic subscription id.
        let subscription_guard = self.lock_subscriptions().await;
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "sync_account_groups",
            desired_group_subscription_count = sync.group_subscriptions.len(),
            "syncing transport group subscriptions"
        );
        {
            let state = self.state.read().await;
            if !state.accounts.contains_key(&sync.account_id) {
                return Err(TransportAdapterError::AccountNotActive(
                    sync.account_id.clone(),
                ));
            }
        }

        let (to_add, desired, batches) = {
            let state = self.state.read().await;
            // The `AccountNotActive` guard above ran under the subscription
            // lock this call holds, and only activate/sync/deactivate can
            // remove an account's routes — all three serialize on that lock.
            let routes = state
                .accounts
                .get(&sync.account_id)
                .expect("the AccountNotActive guard above proved the account is active");
            // Sends repeat this sync. Keep the committed routes and telemetry
            // intact when nothing changed; failed relay teardown still retries.
            if routes.groups == sync.group_subscriptions
                && state.pending_unsubscribes.is_empty()
                && state.pending_scoped_unsubscribes.is_empty()
            {
                return Ok(());
            }
            // A sync amends the live activation's route set; it does not open a
            // new attempt, so both sides of the diff carry the activation's own
            // attempt and the ids stay stable across it.
            let attempt = routes.attempt;
            let (to_add, to_remove) = diff_group_subscriptions(
                &sync.account_id,
                &routes.groups,
                &routes.group_since,
                &sync.group_subscriptions,
                sync.since,
                attempt,
            );
            if to_add.is_empty() && to_remove.is_empty() {
                // Nothing to repack: only the teardown retries below run.
                (Vec::new(), None, Vec::new())
            } else {
                // Any change of routes repacks every group batch (#2266):
                // appending batches fragmented them past the relay's REQ
                // limit, kept a removed route's events arriving to be dropped,
                // and left sync-made batches outside replay coverage.
                let desired = repacked_group_routes(
                    &sync,
                    routes,
                    &to_add,
                    state.account_subscription_eose(&sync.account_id).complete(),
                );
                let batches =
                    pack_group_batches(&sync.account_id, &desired, attempt, routes.next_batch);
                (to_add, Some(desired), batches)
            }
        };
        let Some(desired) = desired else {
            // The same routes, perhaps reordered: keep the order the caller
            // sent so its repeats return early above.
            if let Some(routes) = self.state.write().await.accounts.get_mut(&sync.account_id) {
                routes.groups = sync.group_subscriptions;
            }
            self.drain_pending_unsubscribes().await;
            drop(subscription_guard);
            return Ok(());
        };

        // Stage new route coverage and a telemetry overlay BEFORE the relay REQs
        // go out. Existing routes and committed telemetry remain live until the
        // whole batch succeeds, while synchronous callbacks update the overlay.
        let now_ms = self.now_ms();
        {
            let mut state = self.state.write().await;
            state.stage_subscription_starts(&batches, now_ms);
            state.stage_replay_batches(&sync.account_id, &batches);
            state.stage_group_routes(&to_add);
            // Spend the batch numbers whether or not this sync commits: a
            // failed sync's batch may still be closing under its id, which a
            // later batch must never reuse.
            if let Some(routes) = state.accounts.get_mut(&sync.account_id) {
                routes.next_batch = routes
                    .next_batch
                    .saturating_add(u32::try_from(batches.len()).unwrap_or(u32::MAX));
            }
        }
        // Keep the lifecycle lock in a detached cleanup guard. If this future
        // is cancelled at any later await, dropping the sender wakes the guard,
        // which rolls back staged state before another lifecycle call can run.
        // A cancelled batch's subscribe tasks keep running detached, so the
        // guard also closes whatever REQs they installed once they settle.
        let (staging_complete, staging_abandoned) = oneshot::channel();
        let cleanup_state = Arc::clone(&self.state);
        let cleanup_client = Arc::clone(&self.relay_client);
        let cleanup_barriers = Arc::clone(&self.subscribe_tasks);
        let cleanup_batch = batches.clone();
        let cleanup_account = sync.account_id.clone();

        tokio::spawn(async move {
            let _subscription_guard = subscription_guard;
            if staging_abandoned.await.is_err() {
                {
                    let mut state = cleanup_state.write().await;
                    state.rollback_staged_subscription_starts();
                    state.retire_unlive_replay_batches(&cleanup_account, &cleanup_batch);
                    state.rebuild_transport_group_index();
                }
                close_abandoned_sync_batch(
                    &cleanup_client,
                    &cleanup_state,
                    &cleanup_barriers,
                    cleanup_batch,
                )
                .await;
            }
        });

        // The new batches go out before the ones they replace close, so no
        // route is ever without a live REQ.
        let report = match self.subscribe_all("sync_account_groups", &batches).await {
            Ok(report) => report,
            Err(error) => {
                // The authoritative routes and committed telemetry were never
                // replaced. Discard only this batch's staged callbacks and rebuild
                // the derived route index to remove its temporary coverage, then
                // close the REQs the batch's successful siblings installed.
                {
                    let mut state = self.state.write().await;
                    state.rollback_staged_subscription_starts();
                    state.retire_unlive_replay_batches(&sync.account_id, &batches);
                    state.rebuild_transport_group_index();
                    state.metrics.group_syncs_failed += 1;
                }
                close_abandoned_sync_batch(
                    &self.relay_client,
                    &self.state,
                    &self.subscribe_tasks,
                    batches,
                )
                .await;
                let _ = staging_complete.send(());

                return Err(error);
            }
        };

        // Commit routing intent BEFORE relay teardown: a failed unsubscribe
        // must never leave the routing index serving the old group set.
        // Removals are queued and drained below (plus any left over from
        // earlier syncs); failures there are absorbed and retried, never
        // surfaced as an error.
        {
            let mut state = self.state.write().await;
            state.commit_staged_subscription_starts();
            let account_id = sync.account_id.clone();
            let replaced = state.sync_groups(sync, &desired, &batches);
            state.retire_replay_batches(&account_id, &replaced);
            state.forget_subscription_starts(&replaced);
            state.queue_pending_unsubscribes(replaced);
            if report.is_degraded() {
                state.metrics.group_syncs_degraded += 1;
            } else {
                state.metrics.group_syncs_full += 1;
            }
        };

        let (confirmed, failed_unsubscribe_count) = self.drain_pending_unsubscribes().await;

        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "sync_account_groups",
            subscriptions_created = batches.len(),
            owed_relay_count = report.owed_relays,
            refused_relay_count = report.refused_relays,
            unsubscribes_confirmed = confirmed,
            "applied transport group subscription diff"
        );
        if failed_unsubscribe_count > 0 {
            let pending_retry_total = self.state.read().await.pending_unsubscribes.len();
            tracing::warn!(
                target: "transport_nostr_adapter::adapter",
                method = "sync_account_groups",
                failed_unsubscribe_count,
                pending_retry_total,
                "deferred relay unsubscribes; will retry on next group sync"
            );
        }
        let _ = staging_complete.send(());
        Ok(())
    }

    async fn deactivate_account(&self, account_id: &MemberId) -> Result<(), TransportAdapterError> {
        // Serialize with sync/activate so the blanket unsubscribe cannot
        // interleave a concurrent sync's unsubscribe drain (see the field doc).
        let _subscription_guard = self.lock_subscriptions().await;
        let removed_count = {
            let state = self.state.read().await;
            state
                .accounts
                .get(account_id)
                .map(|routes| 1 + routes.batches.len())
                .unwrap_or_default()
        };
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "deactivate_account",
            subscriptions_removed = removed_count,
            "deactivating transport account"
        );
        self.relay_client
            .unsubscribe_account(account_id, &[])
            .await?;
        let mut state = self.state.write().await;
        state.forget_account_subscription_starts(account_id);
        // The blanket `unsubscribe_account` above supersedes any queued
        // per-subscription unsubscribes for this account.
        state.clear_pending_unsubscribes_for_account(account_id);
        state.deactivate(account_id, removed_count);
        Ok(())
    }

    async fn publish(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        tracing::debug!(
            target: "transport_nostr_adapter::adapter",
            method = "publish",
            endpoint_count = request.target.endpoints().len(),
            required_acks = request.required_acks,
            "publishing transport message"
        );
        request.validate_envelope_matches_target()?;
        {
            let state = self.state.read().await;
            if !state.accounts.contains_key(&request.account_id) {
                return Err(TransportAdapterError::AccountNotActive(
                    request.account_id.clone(),
                ));
            }
        }

        let event = NostrTransportEvent::from_transport_message(&request.message)
            .map_err(|e| TransportAdapterError::Publish(format!("Nostr payload: {e}")))?;
        let outcome = self
            .publish_event_with_client(
                self.relay_client.publish_event_for_account(
                    &request.account_id,
                    request.target.endpoints(),
                    &event,
                    request.required_acks,
                ),
                request.required_acks,
            )
            .await?;

        Ok(TransportPublishReport {
            message_id: outcome.message_id.unwrap_or(request.message.id),
            accepted: outcome.accepted,
            failed: outcome.failed,
            required_acks: request.required_acks,
        })
    }

    async fn receive(&self) -> Result<Option<TransportDelivery>, TransportAdapterError> {
        Ok(self.delivery_rx.lock().await.recv().await)
    }
}

impl NostrTransportAdapter {
    pub async fn deliver_local_publish(
        &self,
        message: &TransportMessage,
        endpoints: &[TransportEndpoint],
    ) -> Result<usize, TransportAdapterError> {
        let mut delivered = 0;
        let mut seen_routes = HashSet::new();
        let received_at = Timestamp(unix_now_seconds());
        for endpoint in endpoints {
            let routes = {
                let state = self.state.read().await;
                state.routes_for(message, endpoint)
            };
            for route in routes {
                let key = (
                    route.account_id.clone(),
                    route.group_id_hint.clone(),
                    route.plane,
                );
                if !seen_routes.insert(key) {
                    continue;
                }
                let delivery = TransportDelivery {
                    account_id: route.account_id,
                    group_id_hint: route.group_id_hint,
                    message: message.clone(),
                    received_at,
                    source: TransportDeliverySource {
                        transport: TransportSource(NOSTR_SOURCE.into()),
                        plane: route.plane,
                        endpoint: Some(endpoint.clone()),
                        subscription_id: Some("local-publish".to_owned()),
                        // Local echo of our own publish: no inbound relay
                        // wire event to attribute.
                        wire: None,
                    },
                };
                if matches!(
                    &delivery.message.envelope,
                    TransportEnvelope::GroupMessage { .. }
                ) {
                    let mut permit: Option<mpsc::Permit<'_, TransportDelivery>> = None;
                    loop {
                        let mut state = self.state.write().await;
                        let relay = state.relay_index.existing_index_for(endpoint);
                        if let Some(coverage) =
                            state.account_replay_coverage.get_mut(&delivery.account_id)
                            && coverage.ingress.is_some()
                        {
                            // Local publication is not a relay history boundary.
                            // The registered group consumer still owns its order
                            // relative to every pending current replay source.
                            coverage.stage_delivery(
                                delivery,
                                relay,
                                ReplayInput::Untracked,
                                &self.delivery_tx,
                            )?;
                            break;
                        }
                        if let Some(permit) = permit {
                            // A consumer may register while ordinary capacity
                            // is unavailable. Recheck after that wait and keep
                            // the final legacy handoff under the same lock.
                            permit.send(delivery);
                            break;
                        }
                        drop(state);
                        permit = Some(
                            self.delivery_tx
                                .reserve()
                                .await
                                .map_err(|_| TransportAdapterError::Closed)?,
                        );
                    }
                } else {
                    self.delivery_tx
                        .send(delivery)
                        .await
                        .map_err(|_| TransportAdapterError::Closed)?;
                }
                delivered += 1;
            }
        }
        Ok(delivered)
    }
}

#[derive(Clone)]
struct DeliveryRoute {
    account_id: MemberId,
    group_id_hint: Option<GroupId>,
    plane: TransportDeliveryPlane,
}

#[derive(Clone)]
struct AccountRoutes {
    /// Pre-canonicalized so the Welcome/inbox arm of `routes_for` never re-parses
    /// the same stored inbox endpoint per event (#698/#752), mirroring the group
    /// arm's `by_transport_group` entries.
    inbox_endpoints: Vec<CanonicalEndpoint>,
    groups: Vec<TransportGroupSubscription>,
    /// The `since` each live group route was issued with, by route. A group
    /// sync adds a live retained route again only when that widens it; its
    /// repack then issues the route at the wider floor, in a batch with a new
    /// id, so a narrower filter never cuts off history the live one is still
    /// returning. Ids never carry `since`.
    group_since: HashMap<NostrSubscriptionRouteKey, Option<Timestamp>>,
    /// Attempt the live subscriptions for this account were issued under. Held
    /// here so `account_subscription_ids` can rebuild exactly the ids that went
    /// on the wire, and so a group sync reuses the activation's attempt rather
    /// than minting a new one.
    attempt: SubscriptionAttempt,
    /// The live batch REQs carrying exactly the group routes in `groups`.
    batches: Vec<NostrSubscription>,
    /// The number the next batch a group sync adds takes within `attempt`.
    /// Spent when a sync stages its batches, so numbers are never reused.
    next_batch: u32,
}

/// Endpoint coverage for the account's live inbox and group batch REQs, as
/// the most recent activation issued them and later group syncs repacked
/// them.
///
/// Kept apart from the live routing table: a sync stages its batches here
/// before their REQs go out and only then retires the ones they replace, so
/// a route still wanted is always owed from no later a floor than before,
/// and only a route the sync removed stops being owed.
#[derive(Default)]
struct AccountReplayCoverage {
    wire_generation: u64,
    changes: ReplayChanges,
    attempt: Option<Arc<ReplayAttempt>>,
    subscriptions: HashMap<String, HashMap<RelayIndex, RelayReplay>>,
    /// The stored-history window each issued REQ asked for, so a replay a relay
    /// cut short can be paged within it.
    windows: HashMap<String, ReplayWindow>,
    /// Stored events each relay sent for each REQ before its EOSE.
    stored: HashMap<String, HashMap<RelayIndex, StoredReplay>>,
    maintenance: HashSet<String>,
    groups: HashMap<GroupId, GroupReplay>,
    /// Issued membership keeps certification and restart scans request-local.
    request_groups: HashMap<String, HashSet<GroupId>>,
    buffered_bytes: usize,
    buffered_items: usize,
    releasing_bytes: usize,
    releasing_items: usize,
    outbox: VecDeque<TransportDelivery>,
    inbox_placements: usize,
    /// Covers retired windows and wider reconciliation bodies until scope exit.
    retained_since: Option<u64>,
    released: HashSet<[u8; 32]>,
    release_order: VecDeque<[u8; 32]>,
    unplaced: HashMap<[u8; 32], HashSet<GroupId>>,
    native_ids: HashMap<[u8; 32], ReplayFrameOrigin>,
    ingress: Option<Arc<replay_ingress::ReplayIngressState>>,
    scope: Arc<std::sync::atomic::AtomicBool>,
    deadlines: std::collections::BTreeMap<tokio::time::Instant, Vec<(GroupId, ReplayOwner)>>,
    endpoint_deadlines: HashMap<String, HashMap<RelayIndex, ReplayEndpoint>>,
    source_serial: u64,
    wake: Arc<tokio::sync::Notify>,
    flushing: bool,
    cancellation: NostrAcquisitionCancellation,
    loss: Option<(MemberId, Arc<ReplayLosses>)>,
}

impl Drop for AccountReplayCoverage {
    fn drop(&mut self) {
        self.cancellation.cancel();
        let discarded = !self.outbox.is_empty()
            || self.groups.values().any(|group| {
                group
                    .events
                    .iter()
                    .any(|(id, event)| !event.retained && !self.native_ids.contains_key(id))
            })
            || self
                .unplaced
                .keys()
                .any(|id| self.native_ids.get(id) != Some(&ReplayFrameOrigin::Retained));
        self.retain_native_scope();
        if discarded {
            self.record_loss(self.retained_since.unwrap_or(0));
        }
    }
}

struct ReplayChanges {
    tx: tokio::sync::watch::Sender<u64>,
    clock: Arc<std::sync::atomic::AtomicU64>,
}

impl Default for ReplayChanges {
    fn default() -> Self {
        Self {
            tx: tokio::sync::watch::channel(0).0,
            clock: Arc::default(),
        }
    }
}

struct ReplayCapture {
    token: ReplayCaptureToken,
    serial: u64,
}

struct ReplayAttempt {
    serial: u64,
    sources: Vec<ReplayCapture>,
    cancellation: NostrAcquisitionCancellation,
}

struct ReplayWaiter {
    cancellation: Option<NostrAcquisitionCancellation>,
    wake: Arc<Notify>,
}

impl Drop for ReplayWaiter {
    fn drop(&mut self) {
        if let Some(cancellation) = self.cancellation.take() {
            cancellation.cancel();
            self.wake.notify_waiters();
        }
    }
}

#[derive(Default)]
struct GroupReplay {
    routes: HashMap<String, Vec<[u8; 32]>>,
    // Adjacent request/route peers make readiness a single allocation-free pass.
    streams: std::collections::BTreeMap<ReplayOwner, HistoryReplay>,
    events: HashMap<[u8; 32], BufferedReplay>,
    live: HashSet<[u8; 32]>,
    ready_history: HashSet<[u8; 32]>,
    placements: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ReplayOwner {
    request: Arc<str>,
    route: [u8; 32],
    relay: RelayIndex,
}

struct HistoryReplay {
    phase: ReplayAdmission,
    claims: HashSet<[u8; 32]>,
    observed: bool,
    deadline: tokio::time::Instant,
    serial: u64,
    since: u64,
}

struct ReplayEndpoint {
    /// Only the unit currently receiving service owns a paging deadline.
    deadline: Option<tokio::time::Instant>,
    serial: u64,
    /// One task owns this serial, including its queued and draining units.
    capturing: bool,
    /// Complete original-range admission in this source's current wire epoch.
    boundary_admitted: bool,
    /// The owner takes this ticket; frontend cancellation cannot orphan it.
    queued: Option<ReplayPaging>,
    cancellation: NostrAcquisitionCancellation,
}

impl Drop for ReplayEndpoint {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayAdmission {
    Waiting,
    /// Waiting expired without observing or discarding any history.
    Dormant,
    /// This capture owns the route, but its service allowance has not begun.
    Queued,
    Paging,
    Complete,
    Abandoned,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplayAbandon {
    Unfinished,
    Interrupted,
    Lost,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplayOrigin {
    Initial,
    Changed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplayStart {
    Connection,
    Gap,
    /// Same wire epoch: replace IO ownership without discarding held bodies.
    Capture,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplayFrameOrigin {
    Remote,
    Retained,
}

struct BufferedReplay {
    delivery: TransportDelivery,
    owners: usize,
    retained: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelayCopy {
    Deduplicated,
    RawGroup,
    Page(u64),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplayInput {
    History,
    Live,
    Page,
    /// Routed input with no tracked historical REQ attribution.
    Untracked,
}

/// The stored-history window of one activation REQ.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayWindow {
    scope: ReplayScope,
    /// The REQ's `since`, or 0 when it asked for full history.
    since: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ReplayScope {
    Inbox,
    /// The routing ids of the group routes the REQ carries.
    Groups(Vec<[u8; 32]>),
}

// A17 keeps the full window open within signed relay timestamp parsers.
const REPLAY_OPEN_UNTIL: u64 = i64::MAX as u64;

impl ReplayWindow {
    fn for_subscription(subscription: &NostrSubscription) -> Option<Self> {
        let (scope, since) = match subscription {
            NostrSubscription::AccountInbox { since, .. } => (ReplayScope::Inbox, since),
            NostrSubscription::Group {
                transport_group_id,
                since,
                ..
            }
            | NostrSubscription::GroupMaintenance {
                transport_group_id,
                since,
                ..
            } => (
                ReplayScope::Groups(vec![transport_group_id.as_slice().try_into().ok()?]),
                since,
            ),
            NostrSubscription::GroupBatch { routes, since, .. } => {
                let mut ids = routes
                    .iter()
                    .map(|route| route.transport_group_id.as_slice().try_into().ok())
                    .collect::<Option<Vec<[u8; 32]>>>()?;
                ids.sort_unstable();
                ids.dedup();
                (ReplayScope::Groups(ids), since)
            }
        };
        Some(Self {
            scope,
            since: since.map_or(0, |since| since.0),
        })
    }

    fn acquisition_scope(&self, until: u64) -> NostrAcquisitionScope {
        let since = self.since;
        match &self.scope {
            ReplayScope::Inbox => NostrAcquisitionScope::AccountInboxWindow { since, until },
            ReplayScope::Groups(transport_group_ids) => NostrAcquisitionScope::GroupsWindow {
                transport_group_ids: transport_group_ids.clone(),
                since,
                until,
            },
        }
    }

    /// One window per route this window covers, with its floor.
    fn per_route(&self) -> Vec<ReplayWindow> {
        match &self.scope {
            ReplayScope::Inbox => vec![self.clone()],
            ReplayScope::Groups(ids) => ids
                .iter()
                .map(|id| ReplayWindow {
                    scope: ReplayScope::Groups(vec![*id]),
                    since: self.since,
                })
                .collect(),
        }
    }

    /// The most backward pages a replay of this window may take: the
    /// per-route bound for each route its REQ carries.
    fn max_pages(&self) -> usize {
        match &self.scope {
            ReplayScope::Inbox => REPLAY_PAGE_MAX_PAGES,
            ReplayScope::Groups(ids) => REPLAY_PAGE_MAX_PAGES.saturating_mul(ids.len().max(1)),
        }
    }
}

/// How one window's backward paging ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PagedWindow {
    /// A page came back short: the window's history up to its floor is in.
    Complete,
    /// Paging stopped short of the floor: a failed page, an unsupported
    /// backend, or the page bound.
    Incomplete,
    /// A full page could not move past this inclusive second.
    Saturated(u64),
    /// The delivery channel closed.
    Closed,
}

/// How many stored events one relay sent for one REQ before EOSE, and the
/// oldest `created_at` among them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StoredReplay {
    events: usize,
    oldest: Option<u64>,
    /// Physical EOSE, or a completed full-window acquisition before a refetch.
    /// Forced paging alone must not reclassify a partial stored page as live.
    ended: bool,
}

/// One relay's replay of one activation REQ that must be paged backwards
/// before its EOSE counts.
struct ReplayPaging {
    account_id: MemberId,
    subscription_id: String,
    endpoint: TransportEndpoint,
    relay: RelayIndex,
    serial: u64,
    window: ReplayWindow,
    /// Inclusive upper bound of the first page: the oldest event the live
    /// replay delivered.
    until: u64,
    /// Accepted owner work keeps capacity through queued and active IO cleanup.
    /// Mechanical native clamp continuation needs no owner credit.
    credit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

/// One relay's answer to one REQ of an activation's replay.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RelayReplay {
    /// No answer yet, or a pending refusal whose REQ the relay client will
    /// re-send.
    #[default]
    Awaiting,
    /// The relay reported end-of-stored-events. Final: a later `CLOSED` ends
    /// the live REQ but cannot take back history already served.
    Eose,
    /// The relay ended the REQ with a dropped refusal before EOSE.
    Refused,
    /// The relay sent EOSE after a full page of stored events, so it may have
    /// clamped the replay; older pages are being fetched. Neither complete nor
    /// settled. Failed captures become Incomplete; the account owner decides
    /// whether and when another original-window capture is authorized.
    Paging,
    /// Paging ended without proving coverage. Only actually discarded bodies
    /// enter the loss fence; later live input must not remain stuck.
    Incomplete,
}

impl AccountReplayCoverage {
    // Drop prevents a struct-update expression with Self::default().
    #[allow(clippy::field_reassign_with_default)]
    fn new(
        account: MemberId,
        losses: Arc<ReplayLosses>,
        clock: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        let mut coverage = Self::default();
        coverage.scope = Arc::new(std::sync::atomic::AtomicBool::new(true));
        coverage.loss = Some((account, losses));
        coverage.changes.clock = clock;
        coverage.change_sources();
        coverage
    }

    fn remember_delivery(&mut self, id: [u8; 32]) {
        if !self.released.insert(id) {
            return;
        }
        self.release_order.push_back(id);
        if self.release_order.len() > REPLAY_BUFFER_MAX_ITEMS
            && let Some(old) = self.release_order.pop_front()
        {
            self.released.remove(&old);
        }
    }

    fn record_loss(&self, since: u64) {
        if let Some((account, losses)) = &self.loss {
            losses.record(account, since);
        }
    }

    fn change_sources(&mut self) {
        self.wire_generation = self
            .changes
            .clock
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .checked_add(1)
            .expect("wire generation exhausted");
        self.wake_replay();
    }

    fn wake_replay(&self) {
        self.changes.tx.send_replace(self.wire_generation);
        self.wake.notify_waiters();
    }

    fn refresh_boundaries(&mut self) {
        // Readiness consults request/group bodies, not the endpoint leases.
        // Temporarily split those fields rather than allocate on every ACK.
        let mut endpoints = std::mem::take(&mut self.endpoint_deadlines);
        for (id, relays) in &mut endpoints {
            for (relay, endpoint) in relays {
                if !endpoint.boundary_admitted
                    && self
                        .subscriptions
                        .get(id)
                        .and_then(|relays| relays.get(relay))
                        == Some(&RelayReplay::Eose)
                    && self.request_admitted(id, Some(*relay))
                {
                    endpoint.boundary_admitted = true;
                }
            }
        }
        self.endpoint_deadlines = endpoints;
    }

    fn capture_outcome(&self, attempt: &ReplayAttempt) -> Option<ReplayCaptureOutcome> {
        let mut active = false;
        let mut admitted = true;
        let mut completion = ReplayCaptureOutcome::Complete;
        for source in &attempt.sources {
            let Some(endpoint) = self
                .endpoint_deadlines
                .get(source.token.request.as_ref())
                .and_then(|relays| relays.get(&source.token.relay))
                .filter(|endpoint| endpoint.serial == source.serial)
            else {
                return Some(ReplayCaptureOutcome::Stale);
            };
            active |= endpoint.capturing;
            admitted &= endpoint.boundary_admitted;
            if self
                .subscriptions
                .get(source.token.request.as_ref())
                .and_then(|relays| relays.get(&source.token.relay))
                != Some(&RelayReplay::Eose)
            {
                completion = ReplayCaptureOutcome::Incomplete;
            }
        }
        if !active && admitted {
            Some(ReplayCaptureOutcome::Complete)
        } else if attempt.cancellation.is_cancelled() {
            Some(ReplayCaptureOutcome::Cancelled)
        } else if active {
            None
        } else if completion == ReplayCaptureOutcome::Incomplete {
            Some(completion)
        } else if self.buffered_items != 0 || !self.unplaced.is_empty() || self.flushing {
            None
        } else {
            Some(ReplayCaptureOutcome::Incomplete)
        }
    }

    fn streams_ready<'a>(
        &self,
        streams: impl Iterator<Item = (&'a ReplayOwner, &'a HistoryReplay)>,
    ) -> bool {
        streams.into_iter().all(|(_, stream)| {
            !matches!(
                stream.phase,
                ReplayAdmission::Waiting | ReplayAdmission::Queued | ReplayAdmission::Paging
            )
        })
    }

    // Empty input may qualify limited native admission from one ready peer.
    // This is not permission to release ciphertext past a still-serving peer.
    fn empty_streams_admitted<'a>(
        &self,
        streams: impl Iterator<Item = (&'a ReplayOwner, &'a HistoryReplay)>,
    ) -> bool {
        let mut route = None;
        let mut waiting = false;
        let mut complete = false;
        let mut observed = false;
        for (owner, stream) in streams {
            let next = (owner.request.as_ref(), &owner.route);
            if route.is_some_and(|route| route != next) {
                if waiting && (!complete || observed) {
                    return false;
                }
                waiting = false;
                complete = false;
                observed = false;
            }
            route = Some(next);
            match stream.phase {
                ReplayAdmission::Waiting => {
                    waiting = true;
                    observed |= stream.observed
                        || self
                            .stored
                            .get(owner.request.as_ref())
                            .and_then(|relays| relays.get(&owner.relay))
                            .is_some_and(|stored| stored.events > 0);
                }
                ReplayAdmission::Queued | ReplayAdmission::Paging => return false,
                ReplayAdmission::Complete => complete = true,
                ReplayAdmission::Dormant | ReplayAdmission::Abandoned => {}
            }
        }
        !waiting || (complete && !observed)
    }

    fn request_ready(&self, group: &GroupReplay, id: &str) -> bool {
        group.routes.contains_key(id)
            && self.empty_streams_admitted(
                group
                    .streams
                    .iter()
                    .filter(|(owner, _)| owner.request.as_ref() == id),
            )
    }

    fn group_ready(&self, group: &GroupReplay) -> bool {
        self.streams_ready(group.streams.iter())
    }

    fn has_ready_deliveries(&self) -> bool {
        !self.outbox.is_empty()
            || self
                .groups
                .iter()
                .any(|(id, group)| self.owner_flushable(id, group))
    }

    fn admission_pending(&self) -> bool {
        self.flushing
            || self.buffered_items != 0
            || self.native_held().0 != 0
            || !self.unplaced.is_empty()
            || self.groups.values().any(|group| {
                group.streams.values().any(|stream| {
                    matches!(
                        stream.phase,
                        ReplayAdmission::Waiting
                            | ReplayAdmission::Queued
                            | ReplayAdmission::Paging
                    )
                })
            })
            || self
                .endpoint_deadlines
                .values()
                .any(|relays| relays.values().any(|endpoint| endpoint.capturing))
    }

    fn request_admitted(&self, id: &str, relay: Option<RelayIndex>) -> bool {
        if !self.subscriptions.contains_key(id) {
            return false;
        }
        let mut grouped = false;
        for group_id in self.request_groups.get(id).into_iter().flatten() {
            let Some(group) = self.groups.get(group_id) else {
                return false;
            };
            grouped = true;
            if (self.ingress.is_none() && group.placements != 0) || !self.request_ready(group, id) {
                return false;
            }
            let mut route = None;
            let mut routes = 0;
            let mut complete = false;
            for (owner, stream) in group
                .streams
                .iter()
                .filter(|(owner, _)| owner.request.as_ref() == id)
            {
                if route != Some(&owner.route) {
                    if route.is_some() && !complete {
                        return false;
                    }
                    route = Some(&owner.route);
                    routes += 1;
                    complete = false;
                }
                if !stream.claims.is_empty() {
                    return false;
                }
                complete |= relay.is_none_or(|relay| relay == owner.relay)
                    && stream.phase == ReplayAdmission::Complete;
            }
            if !complete || routes != group.routes[id].len() {
                return false;
            }
        }
        grouped
            || (self.outbox.is_empty()
                && self.inbox_placements == 0
                && self
                    .subscriptions
                    .get(id)
                    .is_some_and(|relays| match relay {
                        Some(relay) => relays.get(&relay) == Some(&RelayReplay::Eose),
                        None => relays.values().any(|replay| *replay == RelayReplay::Eose),
                    }))
    }

    fn pin_delivery(&mut self, id: [u8; 32], group_id: Option<&GroupId>) {
        let groups = match self.unplaced.entry(id) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                self.inbox_placements += usize::from(group_id.is_none());
                entry.insert(HashSet::new())
            }
        };
        if let Some(group_id) = group_id
            && groups.insert(group_id.clone())
            && let Some(group) = self.groups.get_mut(group_id)
        {
            group.placements += 1;
        }
    }

    fn ack_placement(&mut self, id: &MessageId) {
        let Ok(id) = <[u8; 32]>::try_from(id.as_slice()) else {
            return;
        };
        let native = self.native_ids.remove(&id).is_some();
        if let Some(groups) = self.unplaced.remove(&id) {
            self.inbox_placements -= usize::from(groups.is_empty());
            for group_id in groups {
                if let Some(group) = self.groups.get_mut(&group_id) {
                    group.placements -= 1;
                    if native {
                        for stream in group.streams.values_mut() {
                            stream.claims.remove(&id);
                        }
                    }
                }
            }
        }
        self.refresh_boundaries();
        self.wake_replay();
    }

    fn add_group_route(&mut self, id: &str, group_id: &GroupId, route: &[u8]) {
        let Ok(route) = <[u8; 32]>::try_from(route) else {
            return;
        };
        self.request_groups
            .get_mut(id)
            .expect("registered request membership")
            .insert(group_id.clone());
        let group = self.groups.entry(group_id.clone()).or_default();
        let routes = group.routes.entry(id.to_owned()).or_default();
        if !routes.contains(&route) {
            routes.push(route);
        }
    }

    fn add_subscription(
        &mut self,
        id: String,
        subscription: &NostrSubscription,
        relays: HashMap<RelayIndex, RelayReplay>,
    ) {
        // Registration is idempotent; a real retry has a fresh REQ id.
        if self.subscriptions.contains_key(&id) {
            return;
        }
        self.request_groups.insert(id.clone(), HashSet::new());
        match subscription {
            NostrSubscription::Group {
                group_id,
                transport_group_id,
                ..
            }
            | NostrSubscription::GroupMaintenance {
                group_id,
                transport_group_id,
                ..
            } => {
                self.add_group_route(&id, group_id, transport_group_id);
            }
            NostrSubscription::GroupBatch { routes, .. } => {
                for route in routes {
                    self.add_group_route(&id, &route.group_id, &route.transport_group_id);
                }
            }
            NostrSubscription::AccountInbox { .. } => {}
        }
        if matches!(subscription, NostrSubscription::GroupMaintenance { .. }) {
            self.maintenance.insert(id.clone());
        }
        let window = ReplayWindow::for_subscription(subscription);
        let since = window.as_ref().map_or(0, |window| window.since);
        self.retained_since = Some(self.retained_since.map_or(since, |held| held.min(since)));
        if let Some(window) = window {
            self.windows.insert(id.clone(), window);
        }
        let deadline = tokio::time::Instant::now() + REPLAY_PAGE_LIMITS.max_duration;
        self.source_serial += 1;
        let serial = self.source_serial;
        let request: Arc<str> = Arc::from(id.as_str());
        for (group_id, group) in &mut self.groups {
            let Some(routes) = group.routes.get(&id) else {
                continue;
            };
            for route in routes {
                for (relay, replay) in &relays {
                    let owner = ReplayOwner {
                        request: request.clone(),
                        relay: *relay,
                        route: *route,
                    };
                    let phase = match replay {
                        RelayReplay::Eose => ReplayAdmission::Complete,
                        RelayReplay::Refused | RelayReplay::Incomplete => {
                            ReplayAdmission::Abandoned
                        }
                        RelayReplay::Paging => ReplayAdmission::Paging,
                        RelayReplay::Awaiting => ReplayAdmission::Waiting,
                    };
                    group.streams.insert(
                        owner.clone(),
                        HistoryReplay {
                            phase,
                            claims: HashSet::new(),
                            observed: false,
                            deadline,
                            serial,
                            since,
                        },
                    );
                    if matches!(phase, ReplayAdmission::Waiting | ReplayAdmission::Paging) {
                        if let Some(ingress) = &self.ingress {
                            ingress.invalidate_group(group_id);
                        }
                        self.deadlines
                            .entry(deadline)
                            .or_default()
                            .push((group_id.clone(), owner));
                    }
                }
            }
        }
        self.endpoint_deadlines.insert(
            id.clone(),
            relays
                .keys()
                .map(|relay| {
                    (
                        *relay,
                        ReplayEndpoint {
                            deadline: Some(deadline),
                            serial,
                            capturing: false,
                            boundary_admitted: false,
                            queued: None,
                            cancellation: self.cancellation.child_token(),
                        },
                    )
                })
                .collect(),
        );
        self.stored.entry(id.clone()).or_default();
        let native = !self.maintenance.contains(&id);
        self.subscriptions.insert(id, relays);
        if native {
            self.change_sources();
        } else {
            self.wake_replay();
        }
    }

    fn delivery_owner(
        &self,
        group: &GroupReplay,
        source: Option<&str>,
        relay: Option<RelayIndex>,
        route: [u8; 32],
    ) -> Option<ReplayOwner> {
        let tracked = source.is_some_and(|id| self.subscriptions.contains_key(id));
        group
            .streams
            .iter()
            .filter(|(owner, _)| {
                owner.route == route
                    && relay.is_none_or(|relay| relay == owner.relay)
                    && (!tracked || source == Some(owner.request.as_ref()))
            })
            .max_by_key(|(owner, stream)| (stream.serial, owner.relay.0))
            .map(|(owner, _)| owner.clone())
    }

    fn drop_claims(&mut self, group_id: &GroupId, claims: HashSet<[u8; 32]>) -> bool {
        let Some(group) = self.groups.get_mut(group_id) else {
            return false;
        };
        let mut discarded = false;
        for id in claims {
            let Some(event) = group.events.get_mut(&id) else {
                continue;
            };
            event.owners -= 1;
            if event.owners == 0
                && let Some(event) = group.events.remove(&id)
            {
                self.buffered_items -= 1;
                self.buffered_bytes -= event.delivery.message.payload.len();
                discarded = true;
            }
        }
        discarded
    }

    fn abandon_stream(&mut self, group_id: &GroupId, owner: &ReplayOwner, reason: ReplayAbandon) {
        let force = reason == ReplayAbandon::Lost;
        let Some(group) = self.groups.get(group_id) else {
            return;
        };
        let Some(stream) = group.streams.get(owner) else {
            return;
        };
        if stream.phase == ReplayAdmission::Abandoned
            || (reason == ReplayAbandon::Unfinished && stream.phase == ReplayAdmission::Complete)
        {
            return;
        }
        let observed = stream.observed
            || self
                .stored
                .get(owner.request.as_ref())
                .and_then(|relays| relays.get(&owner.relay))
                .is_some_and(|stored| stored.events > 0);
        let since = stream.since;
        let dormant = !force
            && !observed
            && matches!(
                stream.phase,
                ReplayAdmission::Waiting | ReplayAdmission::Dormant
            );
        let stream = self
            .groups
            .get_mut(group_id)
            .and_then(|group| group.streams.get_mut(owner))
            .expect("owned replay still exists");
        stream.phase = if dormant {
            ReplayAdmission::Dormant
        } else {
            ReplayAdmission::Abandoned
        };
        let claims = std::mem::take(&mut stream.claims);
        let discarded = self.drop_claims(group_id, claims);
        if force || discarded {
            self.record_loss(since);
        }
        self.wake_replay();
    }

    fn stage_ready(
        &mut self,
        delivery: TransportDelivery,
        id: [u8; 32],
        delivery_tx: &mpsc::Sender<TransportDelivery>,
    ) -> Result<(), TransportAdapterError> {
        if !self.flushing && self.outbox.is_empty() {
            match delivery_tx.try_reserve() {
                Ok(permit) => {
                    self.pin_delivery(id, delivery.group_id_hint.as_ref());
                    permit.send(delivery);
                    return Ok(());
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.record_loss(self.retained_since.unwrap_or(0));
                    return Err(TransportAdapterError::Closed);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {}
            }
        }
        let bytes = delivery.message.payload.len();
        let (items_available, bytes_available) = self.buffer_available();
        if items_available == 0 || bytes > bytes_available {
            self.record_loss(self.retained_since.unwrap_or(0));
            return Ok(());
        }
        self.buffered_items += 1;
        self.buffered_bytes += bytes;
        self.outbox.push_back(delivery);
        self.wake_replay();
        Ok(())
    }

    fn copy_is_historical(&self, request: &str, relay: RelayIndex) -> bool {
        self.subscriptions
            .get(request)
            .and_then(|relays| relays.get(&relay))
            .is_some_and(|replay| *replay != RelayReplay::Eose)
            && !self
                .stored
                .get(request)
                .and_then(|relays| relays.get(&relay))
                .is_some_and(|stored| stored.ended)
    }

    fn claim_buffered_copy(
        &mut self,
        group_id: &GroupId,
        id: [u8; 32],
        request: &str,
        relay: RelayIndex,
    ) {
        let group = &self.groups[group_id];
        let message = &group.events[&id].delivery.message;
        let since = message.timestamp.0;
        self.retained_since = Some(self.retained_since.map_or(since, |held| held.min(since)));
        let TransportEnvelope::GroupMessage { transport_group_id } = &message.envelope else {
            return;
        };
        let route = transport_group_id
            .as_slice()
            .try_into()
            .expect("validated group route");
        let owner = self.delivery_owner(group, Some(request), Some(relay), route);
        let historical = self.copy_is_historical(request, relay);
        if historical {
            let Some(owner) = owner.as_ref() else { return };
            let stream = &group.streams[owner];
            if stream.phase == ReplayAdmission::Dormant {
                self.abandon_stream(group_id, owner, ReplayAbandon::Lost);
                return;
            }
            if stream.phase == ReplayAdmission::Abandoned {
                self.record_loss(stream.since);
                return;
            }
            if stream.claims.contains(&id) {
                return;
            }
        } else if self.released.contains(&id) || group.live.contains(&id) {
            return;
        }
        let native = historical && self.native_owned(group_id, &id);
        if historical
            && !native
            && let Some(ingress) = &self.ingress
        {
            ingress.invalidate_group(group_id);
        }
        let group = self.groups.get_mut(group_id).expect("buffered group");
        let claimed = if historical {
            let stream = group
                .streams
                .get_mut(owner.as_ref().expect("historical owner"))
                .expect("tracked source");
            stream.observed = true;
            stream.claims.insert(id)
        } else {
            group.live.insert(id)
        };
        if claimed && !native {
            group.events.get_mut(&id).expect("buffered body").owners += 1;
        }
        self.wake_replay();
    }

    fn stage_delivery(
        &mut self,
        delivery: TransportDelivery,
        relay: Option<RelayIndex>,
        input: ReplayInput,
        delivery_tx: &mpsc::Sender<TransportDelivery>,
    ) -> Result<(), TransportAdapterError> {
        self.expire_replay(tokio::time::Instant::now());
        let Ok(id) = <[u8; 32]>::try_from(delivery.message.id.as_slice()) else {
            return Ok(());
        };
        if matches!(input, ReplayInput::History | ReplayInput::Live)
            && let (Some(group_id), Some(request), Some(relay)) = (
                delivery.group_id_hint.as_ref(),
                delivery.source.subscription_id.as_deref(),
                relay,
            )
            && self.subscriptions.contains_key(request)
            && self
                .groups
                .get(group_id)
                .is_some_and(|group| group.events.contains_key(&id))
        {
            self.claim_buffered_copy(group_id, id, request, relay);
            return Ok(());
        }
        let since = delivery.message.timestamp.0;
        self.retained_since = Some(self.retained_since.map_or(since, |held| held.min(since)));
        let Some(group_id) = delivery.group_id_hint.as_ref() else {
            return self.stage_ready(delivery, id, delivery_tx);
        };
        let Some(group) = self.groups.get(group_id) else {
            self.record_loss(self.retained_since.unwrap_or(0));
            return Ok(());
        };
        if input == ReplayInput::Untracked
            && self.ingress.is_none()
            && group.events.is_empty()
            && self.group_ready(group)
            && !self.native_group_pending(group_id)
        {
            return self.stage_ready(delivery, id, delivery_tx);
        }
        let route = match &delivery.message.envelope {
            TransportEnvelope::GroupMessage { transport_group_id } => {
                let Ok(route) = <[u8; 32]>::try_from(transport_group_id.as_slice()) else {
                    return Ok(());
                };
                route
            }
            _ => return Ok(()),
        };
        let historical = matches!(input, ReplayInput::History | ReplayInput::Page);
        let owner = self.delivery_owner(
            group,
            delivery.source.subscription_id.as_deref(),
            relay,
            route,
        );
        if historical
            && owner
                .as_ref()
                .is_some_and(|owner| group.streams[owner].phase == ReplayAdmission::Dormant)
        {
            // Expiry released a healthy peer, not this late stored range.
            self.abandon_stream(
                group_id,
                owner.as_ref().expect("dormant owner exists"),
                ReplayAbandon::Lost,
            );
            return Ok(());
        }
        let group = &self.groups[group_id];
        if historical {
            let Some(owner) = owner.as_ref() else {
                return Ok(());
            };
            let stream = &group.streams[owner];
            if stream.phase == ReplayAdmission::Abandoned {
                self.record_loss(stream.since);
                return Ok(());
            }
            if (input == ReplayInput::Page && stream.phase != ReplayAdmission::Paging)
                || stream.claims.contains(&id)
            {
                return Ok(());
            }
        } else if self.released.contains(&id) || group.live.contains(&id) {
            return Ok(());
        }
        if historical && self.native_owned(group_id, &id) {
            let owner = owner.as_ref().expect("validated historical owner");
            let stream = self
                .groups
                .get_mut(group_id)
                .expect("native group")
                .streams
                .get_mut(owner)
                .expect("native source");
            stream.observed = true;
            stream.claims.insert(id);
            self.wake_replay();
            return Ok(());
        }
        // Newly recovered history can precede a borrowed suffix. Revoke that
        // loan until the complete range can merge; already-owned aliases do not.
        if historical && let Some(ingress) = &self.ingress {
            ingress.invalidate_group(group_id);
        }
        if !self.flushing
            && self.outbox.is_empty()
            && !self.native_group_pending(group_id)
            && self.ingress.is_none()
            && self.group_ready(group)
            && group.events.is_empty()
            && (!historical
                || owner
                    .as_ref()
                    .is_some_and(|owner| group.streams[owner].phase == ReplayAdmission::Complete))
        {
            // No await separates the admission pin from the actual handoff.
            match delivery_tx.try_reserve() {
                Ok(permit) => {
                    self.remember_delivery(id);
                    self.pin_delivery(id, Some(group_id));
                    permit.send(delivery);
                    return Ok(());
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.record_loss(self.retained_since.unwrap_or(0));
                    return Err(TransportAdapterError::Closed);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {}
            }
        }
        let fresh = !group.events.contains_key(&id);
        let bytes = delivery.message.payload.len();
        let (items_available, bytes_available) = self.buffer_available();
        if fresh && (items_available == 0 || bytes > bytes_available) {
            if historical {
                if let Some(owner) = owner.as_ref() {
                    self.abandon_stream(group_id, owner, ReplayAbandon::Lost);
                }
            } else {
                let since = owner
                    .as_ref()
                    .map_or(0, |owner| self.groups[group_id].streams[owner].since);
                self.record_loss(since.min(delivery.message.timestamp.0));
            }
            return Ok(());
        }
        let group = self
            .groups
            .get_mut(group_id)
            .expect("destination group exists");
        let claimed = if historical {
            let Some(owner) = owner.as_ref() else {
                return Ok(());
            };
            let stream = group.streams.get_mut(owner).expect("history owner exists");
            stream.observed = true;
            stream.claims.insert(id)
        } else {
            group.live.insert(id)
        };
        if claimed {
            match group.events.entry(id) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().owners += 1
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(BufferedReplay {
                        delivery,
                        owners: 1,
                        retained: false,
                    });
                    self.buffered_items += 1;
                    self.buffered_bytes += bytes;
                }
            }
        }
        self.wake_replay();
        Ok(())
    }

    fn buffer_available(&self) -> (usize, usize) {
        let (native_items, native_bytes) = self.native_held();
        let items = self.buffered_items + native_items;
        let bytes = self.buffered_bytes + native_bytes;
        // Preserve the pending pool plus one draining allowance. Restoring a
        // revoked suffix cannot grow that allowance on each source restart.
        (
            REPLAY_BUFFER_MAX_ITEMS
                .saturating_sub(items)
                .min((2 * REPLAY_BUFFER_MAX_ITEMS).saturating_sub(items + self.releasing_items)),
            REPLAY_BUFFER_MAX_BYTES
                .saturating_sub(bytes)
                .min((2 * REPLAY_BUFFER_MAX_BYTES).saturating_sub(bytes + self.releasing_bytes)),
        )
    }

    fn take_ready_deliveries(&mut self) -> Vec<TransportDelivery> {
        self.admit_retained();
        self.queue_owner_batches();
        let ready = self
            .groups
            .iter()
            .filter(|(_, group)| {
                self.ingress.is_none() && !group.events.is_empty() && self.group_ready(group)
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        let mut deliveries = self.outbox.drain(..).collect::<Vec<_>>();
        let ready_count = deliveries.len();
        self.buffered_items -= ready_count;
        self.buffered_bytes -= deliveries
            .iter()
            .map(|delivery| delivery.message.payload.len())
            .sum::<usize>();
        for group_id in ready {
            let group = self.groups.get_mut(&group_id).expect("ready group exists");
            for stream in group.streams.values_mut() {
                stream.claims.clear();
            }
            group.live.clear();
            group.ready_history.clear();
            for (_, event) in group.events.drain() {
                self.buffered_items -= 1;
                self.buffered_bytes -= event.delivery.message.payload.len();
                deliveries.push(event.delivery);
            }
        }
        deliveries[ready_count..].sort_unstable_by(|a, b| {
            (a.message.timestamp, a.message.id.as_slice())
                .cmp(&(b.message.timestamp, b.message.id.as_slice()))
                .then_with(|| {
                    a.group_id_hint
                        .as_ref()
                        .map(|id| id.as_slice())
                        .cmp(&b.group_id_hint.as_ref().map(|id| id.as_slice()))
                })
        });
        for delivery in &deliveries {
            let id = delivery
                .message
                .id
                .as_slice()
                .try_into()
                .expect("validated Nostr event id");
            if delivery.group_id_hint.is_some() {
                self.remember_delivery(id);
            }
            self.pin_delivery(id, delivery.group_id_hint.as_ref());
        }
        self.releasing_items += deliveries.len();
        self.releasing_bytes += deliveries
            .iter()
            .map(|delivery| delivery.message.payload.len())
            .sum::<usize>();
        self.wake_replay();
        deliveries
    }

    fn restore_draining(&mut self, deliveries: VecDeque<TransportDelivery>) {
        for delivery in deliveries {
            let bytes = delivery.message.payload.len();
            self.releasing_items -= 1;
            self.releasing_bytes -= bytes;
            let Some(group_id) = delivery.group_id_hint.as_ref() else {
                self.buffered_items += 1;
                self.buffered_bytes += bytes;
                self.outbox.push_back(delivery);
                continue;
            };
            let id = delivery
                .message
                .id
                .as_slice()
                .try_into()
                .expect("validated draining event id");
            let group = self.groups.entry(group_id.clone()).or_default();
            if group.ready_history.insert(id) {
                match group.events.entry(id) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().owners += 1;
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(BufferedReplay {
                            delivery,
                            owners: 1,
                            retained: false,
                        });
                        self.buffered_items += 1;
                        self.buffered_bytes += bytes;
                    }
                }
            }
        }
        self.wake_replay();
    }

    fn remove_subscription(&mut self, id: &str) {
        let owners = self
            .groups
            .iter()
            .flat_map(|(group_id, group)| {
                group
                    .streams
                    .keys()
                    .filter(|owner| owner.request.as_ref() == id)
                    .map(|owner| (group_id.clone(), owner.clone()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        // Decide every unavailable peer while all completed peers still exist.
        // Hash iteration order must not invent loss for an entirely silent peer.
        for (group_id, owner) in &owners {
            self.abandon_stream(group_id, owner, ReplayAbandon::Unfinished);
        }
        for (group_id, owner) in owners {
            let group = self
                .groups
                .get_mut(&group_id)
                .expect("retiring owner exists");
            if let Some(stream) = group.streams.remove(&owner) {
                // A fulfilled predecessor keeps its entire held range. Moving
                // a claim changes ownership, not the ciphertext body.
                let mut redundant = HashSet::new();
                for event in stream.claims {
                    if !group.ready_history.insert(event) {
                        redundant.insert(event);
                    }
                }
                self.drop_claims(&group_id, redundant);
            }
        }
        for group in self.groups.values_mut() {
            group.routes.remove(id);
        }
        let native = self.subscriptions.remove(id).is_some() && !self.maintenance.contains(id);
        self.windows.remove(id);
        self.stored.remove(id);
        self.maintenance.remove(id);
        self.endpoint_deadlines.remove(id);
        self.request_groups.remove(id);
        self.groups.retain(|_, group| {
            !group.routes.is_empty() || !group.events.is_empty() || group.placements != 0
        });
        if native {
            self.change_sources();
        } else {
            self.wake_replay();
        }
    }

    fn restart_relay(&mut self, relay: RelayIndex, restart: ReplayRestart, origin: ReplayOrigin) {
        let requests = self
            .subscriptions
            .iter()
            .filter(|(_, relays)| {
                relays
                    .get(&relay)
                    .is_some_and(|replay| *replay != RelayReplay::Refused)
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        let native = requests.iter().any(|id| !self.maintenance.contains(id));
        for request in requests {
            match restart {
                ReplayRestart::ReceiverLoss => {
                    if self
                        .restart_request(&request, relay, ReplayStart::Gap)
                        .is_some()
                    {
                        // A missing ordered payload invalidates this source;
                        // only the account owner may grant replacement IO.
                        self.stop_capture(&request, relay);
                    }
                }
                ReplayRestart::Connection => {
                    // An initial boundary starts the waiting allowance, but
                    // must not undo a completed source or an owned capture.
                    let complete = self
                        .subscriptions
                        .get(&request)
                        .and_then(|relays| relays.get(&relay))
                        == Some(&RelayReplay::Eose);
                    let capturing = self
                        .endpoint_deadlines
                        .get(&request)
                        .and_then(|relays| relays.get(&relay))
                        .is_some_and(|endpoint| endpoint.capturing);
                    if origin == ReplayOrigin::Changed || (!complete && !capturing) {
                        self.restart_request(&request, relay, ReplayStart::Connection);
                    }
                }
            }
        }
        if native {
            self.change_sources();
        }
    }

    fn queue_capture(&mut self, paging: ReplayPaging) {
        if let Some(endpoint) = self
            .endpoint_deadlines
            .get_mut(&paging.subscription_id)
            .and_then(|relays| relays.get_mut(&paging.relay))
            && endpoint.serial == paging.serial
            && endpoint.capturing
        {
            endpoint.queued = Some(paging);
            self.wake_replay();
        }
    }

    fn fail_execution(&mut self) {
        if !self.outbox.is_empty()
            || self.groups.values().any(|group| {
                group
                    .events
                    .iter()
                    .any(|(id, event)| !event.retained && !self.native_ids.contains_key(id))
            })
            || self
                .unplaced
                .keys()
                .any(|id| !self.native_ids.contains_key(id))
        {
            self.record_loss(self.retained_since.unwrap_or(0));
        }
        self.retain_supplements();
        self.unplaced
            .retain(|id, _| self.native_ids.contains_key(id));
        let mut placements = HashMap::<GroupId, usize>::new();
        for groups in self.unplaced.values() {
            for group in groups {
                *placements.entry(group.clone()).or_default() += 1;
            }
        }
        for endpoint in self
            .endpoint_deadlines
            .values_mut()
            .flat_map(HashMap::values_mut)
        {
            endpoint.cancellation.cancel();
            endpoint.queued = None;
            endpoint.capturing = false;
            endpoint.boundary_admitted = false;
            endpoint.deadline = None;
        }
        for replay in self
            .subscriptions
            .values_mut()
            .flat_map(HashMap::values_mut)
        {
            if *replay != RelayReplay::Refused {
                *replay = RelayReplay::Incomplete;
            }
        }
        for (id, group) in &mut self.groups {
            for stream in group.streams.values_mut() {
                stream.phase = ReplayAdmission::Abandoned;
                stream.claims.clear();
            }
            group.events.clear();
            group.live.clear();
            group.ready_history.clear();
            group.placements = placements.get(id).copied().unwrap_or(0);
        }
        self.outbox.clear();
        self.deadlines.clear();
        self.buffered_items = 0;
        self.buffered_bytes = 0;
        self.releasing_items = 0;
        self.releasing_bytes = 0;
        self.inbox_placements = 0;
        self.flushing = false;
        self.wake_replay();
    }

    fn restart_request(
        &mut self,
        id: &str,
        relay: RelayIndex,
        restart: ReplayStart,
    ) -> Option<(ReplayWindow, u64)> {
        if self.subscriptions.get(id)?.get(&relay)? == &RelayReplay::Refused {
            return None;
        }
        let window = self.windows.get(id)?.clone();
        self.source_serial += 1;
        let serial = self.source_serial;
        let deadline = tokio::time::Instant::now() + REPLAY_PAGE_LIMITS.max_duration;
        let owners = self
            .request_groups
            .get(id)
            .into_iter()
            .flatten()
            .filter_map(|group_id| self.groups.get(group_id).map(|group| (group_id, group)))
            .flat_map(|(group_id, group)| {
                let complete = group
                    .streams
                    .iter()
                    .filter(|(owner, _)| owner.request.as_ref() == id && owner.relay == relay)
                    .all(|(_, stream)| stream.phase == ReplayAdmission::Complete);
                group
                    .streams
                    .keys()
                    .filter(|owner| owner.request.as_ref() == id && owner.relay == relay)
                    .map(|owner| (group_id.clone(), owner.clone(), complete))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for (group_id, owner, complete) in owners {
            let observed = self
                .groups
                .get(&group_id)
                .and_then(|group| group.streams.get(&owner))
                .is_some_and(|stream| stream.observed || !stream.claims.is_empty())
                || self
                    .stored
                    .get(id)
                    .and_then(|relays| relays.get(&relay))
                    .is_some_and(|stored| stored.events > 0);
            if restart != ReplayStart::Capture && (observed || restart == ReplayStart::Gap) {
                self.abandon_stream(
                    &group_id,
                    &owner,
                    if complete {
                        ReplayAbandon::Unfinished
                    } else {
                        ReplayAbandon::Interrupted
                    },
                );
            }
            let group = self
                .groups
                .get_mut(&group_id)
                .expect("restarting source exists");
            let stream = group
                .streams
                .get_mut(&owner)
                .expect("restarting history exists");
            let mut redundant = HashSet::new();
            if restart != ReplayStart::Capture {
                for event in std::mem::take(&mut stream.claims) {
                    if !group.ready_history.insert(event) {
                        redundant.insert(event);
                    }
                }
                stream.observed = false;
            }
            stream.phase = match restart {
                ReplayStart::Connection => ReplayAdmission::Waiting,
                ReplayStart::Gap | ReplayStart::Capture => ReplayAdmission::Queued,
            };
            stream.deadline = deadline;
            stream.serial = serial;
            if let Some(ingress) = &self.ingress {
                ingress.invalidate_group(&group_id);
            }
            self.drop_claims(&group_id, redundant);
            if restart == ReplayStart::Connection {
                self.deadlines
                    .entry(deadline)
                    .or_default()
                    .push((group_id, owner));
            }
        }
        let ended = restart == ReplayStart::Gap
            && (self
                .subscriptions
                .get(id)
                .and_then(|relays| relays.get(&relay))
                == Some(&RelayReplay::Eose)
                || self
                    .stored
                    .get(id)
                    .and_then(|relays| relays.get(&relay))
                    .is_some_and(|stored| stored.ended));
        if restart != ReplayStart::Capture {
            self.stored.get_mut(id)?.insert(
                relay,
                StoredReplay {
                    ended,
                    ..StoredReplay::default()
                },
            );
        }
        let endpoint = self.endpoint_deadlines.get_mut(id)?.get_mut(&relay)?;
        endpoint.deadline = (restart == ReplayStart::Connection).then_some(deadline);
        endpoint.serial = serial;
        endpoint.capturing = restart != ReplayStart::Connection;
        endpoint.boundary_admitted = false;
        endpoint.queued = None;
        endpoint.cancellation.cancel();
        endpoint.cancellation = self.cancellation.child_token();
        *self.replay_mut(id, relay)? = match restart {
            ReplayStart::Connection => RelayReplay::Awaiting,
            ReplayStart::Gap | ReplayStart::Capture => RelayReplay::Paging,
        };
        self.wake_replay();
        Some((window, serial))
    }

    fn snapshot(&self) -> AccountSubscriptionEose {
        let mut progress = AccountSubscriptionEose {
            subscriptions: self.subscriptions.len() - self.maintenance.len(),
            ..AccountSubscriptionEose::default()
        };
        for (id, relays) in &self.subscriptions {
            if self.maintenance.contains(id) {
                continue;
            }
            let eose = relays
                .iter()
                .filter(|(relay, replay)| {
                    **replay == RelayReplay::Eose && self.request_admitted(id, Some(**relay))
                })
                .count();
            let refused = relays
                .values()
                .filter(|replay| **replay == RelayReplay::Refused)
                .count();
            progress.relay_subscription_attempts += relays.len();
            progress.relay_subscription_attempts_with_eose += eose;
            progress.relay_subscription_attempts_refused += refused;
            progress.with_eose += usize::from(eose > 0);
            progress.subscriptions_refused +=
                usize::from(!relays.is_empty() && refused == relays.len());
        }
        progress
    }

    fn record_stored_event(&mut self, id: &str, relay: RelayIndex, created_at: u64) {
        self.expire_replay(tokio::time::Instant::now());
        if self
            .subscriptions
            .get(id)
            .and_then(|relays| relays.get(&relay))
            != Some(&RelayReplay::Awaiting)
        {
            return;
        }
        let stored = self
            .stored
            .entry(id.to_owned())
            .or_default()
            .entry(relay)
            .or_default();
        stored.events += 1;
        stored.oldest = Some(
            stored
                .oldest
                .map_or(created_at, |oldest| oldest.min(created_at)),
        );
    }

    fn record_eose(
        &mut self,
        id: &str,
        relay: RelayIndex,
        now_ms: u64,
    ) -> Option<(ReplayWindow, u64)> {
        if !self
            .subscriptions
            .get(id)
            .is_some_and(|relays| relays.contains_key(&relay))
        {
            return None;
        }
        self.stored
            .entry(id.to_owned())
            .or_default()
            .entry(relay)
            .or_default()
            .ended = true;
        let stored = self
            .stored
            .get(id)
            .and_then(|relays| relays.get(&relay))
            .copied()
            .unwrap_or_default();
        let discarded = self.groups.values().any(|group| {
            group.streams.iter().any(|(owner, stream)| {
                owner.request.as_ref() == id
                    && owner.relay == relay
                    && stream.phase == ReplayAdmission::Abandoned
            })
        });
        if discarded {
            if self
                .endpoint_deadlines
                .get(id)
                .and_then(|relays| relays.get(&relay))
                .is_none_or(|endpoint| !endpoint.capturing)
            {
                let replay = self.replay_mut(id, relay)?;
                if *replay != RelayReplay::Refused {
                    *replay = RelayReplay::Incomplete;
                }
            }
            return None;
        }
        let replay = self.replay_mut(id, relay)?;
        if *replay != RelayReplay::Awaiting {
            return None;
        }
        if stored.events >= RELAY_REPLAY_PAGE_LIMIT
            && let Some(oldest) = stored.oldest
        {
            return self
                .own_replay_window(id, relay, now_ms)
                .map(|window| (window, oldest));
        }
        *replay = RelayReplay::Eose;
        for group in self.groups.values_mut() {
            for (owner, stream) in &mut group.streams {
                if owner.request.as_ref() != id
                    || owner.relay != relay
                    || !matches!(
                        stream.phase,
                        ReplayAdmission::Waiting | ReplayAdmission::Dormant
                    )
                {
                    continue;
                }
                stream.phase = ReplayAdmission::Complete;
            }
        }
        if let Some(endpoint) = self
            .endpoint_deadlines
            .get_mut(id)
            .and_then(|relays| relays.get_mut(&relay))
        {
            endpoint.deadline = None;
        }
        self.refresh_boundaries();
        // Apply this ordered EOF before peers at the same deadline expire.
        self.expire_replay(tokio::time::Instant::now());
        self.wake_replay();
        None
    }

    fn own_replay_window(
        &mut self,
        id: &str,
        relay: RelayIndex,
        _now_ms: u64,
    ) -> Option<ReplayWindow> {
        let window = self.windows.get(id)?.clone();
        let replay = self.replay_mut(id, relay)?;
        if *replay != RelayReplay::Awaiting {
            return None;
        }
        *replay = RelayReplay::Paging;
        if let Some(endpoint) = self
            .endpoint_deadlines
            .get_mut(id)
            .and_then(|relays| relays.get_mut(&relay))
        {
            endpoint.deadline = None;
            endpoint.capturing = true;
        }
        for (group_id, group) in &mut self.groups {
            for (owner, stream) in &mut group.streams {
                if owner.request.as_ref() == id
                    && owner.relay == relay
                    && matches!(stream.phase, ReplayAdmission::Waiting)
                {
                    stream.phase = ReplayAdmission::Queued;
                    if let Some(ingress) = &self.ingress {
                        ingress.invalidate_group(group_id);
                    }
                }
            }
        }
        self.wake_replay();
        Some(window)
    }

    fn finish_paging(&mut self, id: &str, relay: RelayIndex) {
        self.expire_replay(tokio::time::Instant::now());
        let incomplete = self.groups.values().any(|group| {
            group.streams.iter().any(|(owner, stream)| {
                owner.request.as_ref() == id
                    && owner.relay == relay
                    && stream.phase != ReplayAdmission::Complete
            })
        });
        if incomplete {
            self.stop_capture(id, relay);
            return;
        }
        let Some(endpoint) = self
            .endpoint_deadlines
            .get_mut(id)
            .and_then(|relays| relays.get_mut(&relay))
        else {
            return;
        };
        endpoint.capturing = false;
        endpoint.deadline = None;
        if let Some(replay) = self.replay_mut(id, relay) {
            *replay = RelayReplay::Eose;
        }
        self.refresh_boundaries();
        self.wake_replay();
    }

    fn stop_capture(&mut self, id: &str, relay: RelayIndex) {
        if let Some(endpoint) = self
            .endpoint_deadlines
            .get_mut(id)
            .and_then(|relays| relays.get_mut(&relay))
        {
            endpoint.capturing = false;
            endpoint.boundary_admitted = false;
            endpoint.queued = None;
            endpoint.cancellation.cancel();
            endpoint.deadline = None;
        }
        let owners = self
            .groups
            .iter()
            .flat_map(|(group_id, group)| {
                group
                    .streams
                    .iter()
                    .filter(move |(owner, stream)| {
                        owner.request.as_ref() == id
                            && owner.relay == relay
                            && (!stream.claims.is_empty()
                                || matches!(
                                    stream.phase,
                                    ReplayAdmission::Waiting
                                        | ReplayAdmission::Queued
                                        | ReplayAdmission::Paging
                                ))
                    })
                    .map(move |(owner, _)| (group_id.clone(), owner.clone()))
            })
            .collect::<Vec<_>>();
        for (group_id, owner) in owners {
            self.abandon_stream(&group_id, &owner, ReplayAbandon::Interrupted);
        }
        if let Some(replay) = self.replay_mut(id, relay)
            && *replay != RelayReplay::Refused
        {
            *replay = RelayReplay::Incomplete;
        }
        self.wake_replay();
    }

    fn record_refusal(
        &mut self,
        id: &str,
        relay: RelayIndex,
        disposition: SubscriptionRefusalDisposition,
    ) {
        let ended = self
            .stored
            .get(id)
            .and_then(|relays| relays.get(&relay))
            .is_some_and(|stored| stored.ended);
        let Some(replay) = self.replay_mut(id, relay) else {
            return;
        };
        if matches!(*replay, RelayReplay::Eose | RelayReplay::Refused) {
            return;
        }
        if disposition == SubscriptionRefusalDisposition::Pending {
            return;
        }
        // Only a physical EOSE makes a later CLOSED irrelevant to paging.
        // A refetch started after receiver loss has no such wire certificate.
        if *replay == RelayReplay::Paging && ended {
            return;
        }
        *replay = RelayReplay::Refused;
        if let Some(endpoint) = self
            .endpoint_deadlines
            .get_mut(id)
            .and_then(|relays| relays.get_mut(&relay))
        {
            endpoint.deadline = None;
            endpoint.capturing = false;
            endpoint.queued = None;
            endpoint.cancellation.cancel();
        }
        let owners = self
            .groups
            .iter()
            .flat_map(|(group_id, group)| {
                group
                    .streams
                    .keys()
                    .filter(|owner| owner.request.as_ref() == id && owner.relay == relay)
                    .map(|owner| (group_id.clone(), owner.clone()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for (group_id, owner) in owners {
            self.abandon_stream(&group_id, &owner, ReplayAbandon::Interrupted);
        }
        if self.maintenance.contains(id) {
            self.wake_replay();
        } else {
            self.change_sources();
        }
    }

    fn replay_mut(&mut self, id: &str, relay: RelayIndex) -> Option<&mut RelayReplay> {
        self.subscriptions
            .get_mut(id)
            .and_then(|relays| relays.get_mut(&relay))
    }

    fn page_units(&self, paging: &ReplayPaging) -> Vec<ReplayWindow> {
        let ReplayScope::Groups(ids) = &paging.window.scope else {
            return vec![paging.window.clone()];
        };
        let mut units = self
            .groups
            .iter()
            .filter_map(|(group_id, group)| {
                let mut routes = group
                    .routes
                    .get(&paging.subscription_id)?
                    .iter()
                    .filter(|route| ids.contains(route))
                    .copied()
                    .collect::<Vec<_>>();
                if routes.is_empty() {
                    return None;
                }
                routes.sort_unstable();
                routes.dedup();
                Some((
                    group_id,
                    ReplayWindow {
                        scope: ReplayScope::Groups(routes),
                        since: paging.window.since,
                    },
                ))
            })
            .collect::<Vec<_>>();
        units.sort_unstable_by(|(a, _), (b, _)| a.as_slice().cmp(b.as_slice()));
        units.into_iter().map(|(_, window)| window).collect()
    }

    fn page_allowed(&self, paging: &ReplayPaging, window: &ReplayWindow) -> bool {
        if self
            .endpoint_deadlines
            .get(&paging.subscription_id)
            .and_then(|relays| relays.get(&paging.relay))
            .is_none_or(|endpoint| endpoint.cancellation.is_cancelled())
        {
            return false;
        }
        if self
            .page_deadline(paging, window)
            .is_none_or(|deadline| deadline <= tokio::time::Instant::now())
        {
            return false;
        }
        match &window.scope {
            ReplayScope::Inbox => {
                self.subscriptions
                    .get(&paging.subscription_id)
                    .and_then(|relays| relays.get(&paging.relay))
                    == Some(&RelayReplay::Paging)
            }
            ReplayScope::Groups(routes) => self.groups.values().any(|group| {
                group.streams.iter().any(|(owner, stream)| {
                    owner.request.as_ref() == paging.subscription_id.as_str()
                        && owner.relay == paging.relay
                        && routes.contains(&owner.route)
                        && stream.phase == ReplayAdmission::Paging
                })
            }),
        }
    }

    fn page_deadline(
        &self,
        paging: &ReplayPaging,
        _window: &ReplayWindow,
    ) -> Option<tokio::time::Instant> {
        let endpoint = self
            .endpoint_deadlines
            .get(&paging.subscription_id)?
            .get(&paging.relay)?;
        (endpoint.serial == paging.serial && endpoint.capturing)
            .then_some(endpoint.deadline)
            .flatten()
    }

    fn capture_current(&self, paging: &ReplayPaging) -> bool {
        self.endpoint_deadlines
            .get(&paging.subscription_id)
            .and_then(|relays| relays.get(&paging.relay))
            .is_some_and(|endpoint| endpoint.serial == paging.serial && endpoint.capturing)
    }

    fn start_route(&mut self, paging: &ReplayPaging, window: &ReplayWindow) -> bool {
        if !self.capture_current(paging)
            || self.endpoint_deadlines[&paging.subscription_id][&paging.relay]
                .cancellation
                .is_cancelled()
        {
            return false;
        }
        let deadline = tokio::time::Instant::now() + REPLAY_PAGE_LIMITS.max_duration;
        let mut started = matches!(window.scope, ReplayScope::Inbox);
        if let ReplayScope::Groups(routes) = &window.scope {
            for (group_id, group) in &mut self.groups {
                for (owner, stream) in &mut group.streams {
                    if owner.request.as_ref() == paging.subscription_id.as_str()
                        && owner.relay == paging.relay
                        && routes.contains(&owner.route)
                        && stream.phase == ReplayAdmission::Queued
                    {
                        stream.phase = ReplayAdmission::Paging;
                        stream.deadline = deadline;
                        self.deadlines
                            .entry(deadline)
                            .or_default()
                            .push((group_id.clone(), owner.clone()));
                        started = true;
                    }
                }
            }
        }
        if started {
            self.endpoint_deadlines
                .get_mut(&paging.subscription_id)
                .expect("current request exists")
                .get_mut(&paging.relay)
                .expect("current relay exists")
                .deadline = Some(deadline);
            self.wake_replay();
        }
        started
    }

    fn finish_route(&mut self, paging: &ReplayPaging, window: &ReplayWindow) -> bool {
        self.expire_replay(tokio::time::Instant::now());
        if self.page_deadline(paging, window).is_none() {
            return false;
        }
        let mut finished = matches!(window.scope, ReplayScope::Inbox);
        if let ReplayScope::Groups(routes) = &window.scope {
            for group in self.groups.values_mut() {
                for (owner, stream) in &mut group.streams {
                    if owner.request.as_ref() == paging.subscription_id.as_str()
                        && owner.relay == paging.relay
                        && routes.contains(&owner.route)
                        && stream.phase == ReplayAdmission::Paging
                    {
                        stream.phase = ReplayAdmission::Complete;
                        finished = true;
                    }
                }
            }
        }
        self.endpoint_deadlines
            .get_mut(&paging.subscription_id)
            .expect("current request exists")
            .get_mut(&paging.relay)
            .expect("current relay exists")
            .deadline = None;
        self.wake_replay();
        finished
    }

    fn fail_route(&mut self, paging: &ReplayPaging, window: &ReplayWindow) {
        if !self.capture_current(paging) {
            return;
        }
        let endpoint = self
            .endpoint_deadlines
            .get_mut(&paging.subscription_id)
            .expect("current request exists")
            .get_mut(&paging.relay)
            .expect("current relay exists");
        endpoint.deadline = None;
        if let ReplayScope::Groups(routes) = &window.scope {
            let owners = self
                .groups
                .iter()
                .filter(|(_, group)| {
                    group
                        .routes
                        .get(&paging.subscription_id)
                        .is_some_and(|owned| owned.iter().any(|route| routes.contains(route)))
                })
                .flat_map(|(group_id, group)| {
                    group
                        .streams
                        .keys()
                        .filter(|owner| {
                            owner.request.as_ref() == paging.subscription_id.as_str()
                                && owner.relay == paging.relay
                        })
                        .map(|owner| (group_id.clone(), owner.clone()))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            for (group_id, owner) in owners {
                self.abandon_stream(&group_id, &owner, ReplayAbandon::Interrupted);
            }
        }
        self.wake_replay();
    }

    fn route_release_pending(&self, paging: &ReplayPaging, window: &ReplayWindow) -> bool {
        let ReplayScope::Groups(routes) = &window.scope else {
            return false;
        };
        self.groups.values().any(|group| {
            group
                .routes
                .get(&paging.subscription_id)
                .is_some_and(|owned| owned.iter().any(|route| routes.contains(route)))
                && (!group.ready_history.is_empty()
                    || group
                        .streams
                        .values()
                        .any(|stream| !stream.claims.is_empty()))
        })
    }

    fn expire_replay(&mut self, now: tokio::time::Instant) {
        while self
            .deadlines
            .first_key_value()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            let Some((deadline, owners)) = self.deadlines.pop_first() else {
                break;
            };
            for (group_id, owner) in owners {
                let expired = self
                    .groups
                    .get(&group_id)
                    .and_then(|group| group.streams.get(&owner))
                    .is_some_and(|stream| {
                        stream.deadline == deadline
                            && matches!(
                                stream.phase,
                                ReplayAdmission::Waiting | ReplayAdmission::Paging
                            )
                    });
                if expired {
                    let group = &self.groups[&group_id];
                    if group.streams[&owner].phase == ReplayAdmission::Paging {
                        // A completed newer tag is still partial while another
                        // tag of this same source/group has not finished.
                        let siblings = group
                            .streams
                            .keys()
                            .filter(|peer| {
                                peer.request == owner.request && peer.relay == owner.relay
                            })
                            .cloned()
                            .collect::<Vec<_>>();
                        for peer in siblings {
                            self.abandon_stream(&group_id, &peer, ReplayAbandon::Interrupted);
                        }
                    } else {
                        self.abandon_stream(&group_id, &owner, ReplayAbandon::Unfinished);
                    }
                }
            }
        }
        for relays in self.endpoint_deadlines.values_mut() {
            for endpoint in relays.values_mut() {
                if endpoint.deadline.is_none_or(|deadline| deadline > now) {
                    continue;
                }
                endpoint.deadline = None;
            }
        }
    }
}

/// An account's subscription refusals awaiting the next forensic drain,
/// coalesced and bounded by [`SUBSCRIPTION_REFUSAL_REPORT_LIMIT`].
#[derive(Default)]
struct PendingSubscriptionRefusals {
    reports: Vec<SubscriptionRefusalReport>,
    dropped: u64,
}

impl PendingSubscriptionRefusals {
    fn record(
        &mut self,
        route_kind: SubscriptionRouteKind,
        endpoint: &TransportEndpoint,
        refusal: SubscriptionRefusal,
    ) {
        if let Some(report) = self.reports.iter_mut().find(|report| {
            report.route_kind == route_kind
                && report.endpoint == *endpoint
                && report.category == refusal.category
                && report.disposition == refusal.disposition
        }) {
            report.count = report.count.saturating_add(1);
        } else if self.reports.len() < SUBSCRIPTION_REFUSAL_REPORT_LIMIT {
            self.reports.push(SubscriptionRefusalReport {
                route_kind,
                endpoint: endpoint.clone(),
                category: refusal.category,
                disposition: refusal.disposition,
                count: 1,
            });
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }
}

/// A stored routing endpoint paired with its parsed/canonical `RelayUrl`, cached
/// once when the route index is built so `routes_for` never re-parses the same
/// verbatim signed endpoint on every inbound event (#698/#752). The verbatim
/// string is preserved untouched (the signed-routing invariant); `parsed` is a
/// read-side accelerator (`None` for a non-relay endpoint that fails to parse).
#[derive(Clone)]
struct CanonicalEndpoint {
    verbatim: TransportEndpoint,
    parsed: Option<RelayUrl>,
}

impl CanonicalEndpoint {
    fn new(endpoint: &TransportEndpoint) -> Self {
        Self {
            parsed: RelayUrl::parse(endpoint.as_str()).ok(),
            verbatim: endpoint.clone(),
        }
    }

    /// Compare this stored route endpoint against the endpoint an inbound event
    /// arrived on, normalization-safe and without re-parsing either side.
    ///
    /// Routing must not depend on callers pre-canonicalizing relay URLs. Inbound
    /// endpoints are built from a parsed nostr `RelayUrl` (`sdk_client`), while
    /// stored group/inbox endpoints carry the verbatim signed routing strings
    /// (`marmot.transport.nostr.routing.v1`), which are intentionally never
    /// rewritten. A raw `==` therefore drops events whenever the two differ only
    /// by a `url`-canonicalizable detail (trailing slash, host case, default
    /// port, percent-encoding) — see mdk#482.
    ///
    /// Fast path is byte equality against the verbatim string. Otherwise both
    /// sides are compared by their cached/parsed `RelayUrl` value, folding those
    /// canonicalization differences together. If either side has no parse (e.g. a
    /// non-Nostr transport endpoint), fall back to byte inequality so behavior is
    /// never looser than exact match. Read-side only; the verbatim stored string
    /// is left untouched, preserving the signed-routing invariant.
    fn matches(&self, endpoint: &TransportEndpoint, parsed_endpoint: Option<&RelayUrl>) -> bool {
        if self.verbatim == *endpoint {
            return true;
        }
        match (self.parsed.as_ref(), parsed_endpoint) {
            (Some(stored), Some(inbound)) => stored == inbound,
            _ => false,
        }
    }
}

/// A group-delivery route resolved by `transport_group_id`, with its endpoints
/// pre-canonicalized. Entries in the [`AdapterState::by_transport_group`] index.
#[derive(Clone)]
struct GroupRouteEntry {
    account_id: MemberId,
    group_id: GroupId,
    endpoints: Vec<CanonicalEndpoint>,
}

#[derive(Default)]
struct AdapterState {
    accounts: HashMap<MemberId, AccountRoutes>,
    /// Endpoint-level EOSE proof for the route snapshot issued by the most
    /// recent activation of each account. This is intentionally independent of
    /// `accounts`, whose live group routes may change during the drain.
    account_replay_coverage: HashMap<MemberId, AccountReplayCoverage>,
    replay_ingresses: HashMap<MemberId, Arc<replay_ingress::ReplayIngressState>>,
    replay_losses: Arc<ReplayLosses>,
    /// Retained across account activation so queued old SDK generations fail closed.
    replay_epochs: HashMap<(Option<MemberId>, RelayIndex), [u64; 2]>,
    /// Highest activation attempt ever issued for each account in this process.
    ///
    /// Deliberately never cleared — not by `deactivate`, not by the failed
    /// activation rollback. Both drop the account's routes while the relay
    /// sockets stay open and the superseded attempt's REQs keep streaming, so
    /// recovering the ordinal from the routes would hand the next activation
    /// the ids its predecessor is still using. Bounded by the number of distinct
    /// accounts activated in this process.
    activation_attempt_high_water: HashMap<MemberId, SubscriptionAttempt>,
    // Lifetime fence, one scalar per account/group that used recovery maintenance.
    // Do not clear on route removal or deactivation: old EOSE can still arrive.
    maintenance_attempt_high_water: HashMap<(MemberId, GroupId), u64>,
    /// Consumed owner operation serials survive account replacement.
    capture_attempts: HashMap<MemberId, u64>,
    source_clock: Arc<std::sync::atomic::AtomicU64>,
    /// Derived accelerator for `routes_for` group delivery (#698/#752): maps a
    /// `transport_group_id` to its candidate routes, so an inbound group event is
    /// resolved in O(matching groups) instead of scanning O(accounts × groups)
    /// every event (attacker-floodable). Rebuilt wholesale from `accounts` (the
    /// authoritative signed-routing state) at every committed mutation. Group
    /// sync may append only missing pre-REQ routes while a subscribe batch is in
    /// flight; both success and failure rebuild the index before returning.
    by_transport_group: HashMap<Vec<u8>, Vec<GroupRouteEntry>>,
    maintenance_routes: HashMap<String, NostrSubscription>,
    /// Owning account of each group REQ a sync has sent but not yet committed
    /// to `accounts`, so a relay's `CLOSED` inside the subscribe window still
    /// finds a live REQ. Cleared on commit and rollback.
    staged_group_subscriptions: HashMap<String, MemberId>,
    /// Unconfirmed relay unsubscribes retained until teardown succeeds.
    /// Routing state (`accounts`/`by_transport_group`) already reflects the
    /// removal; these are relay-side cleanups only, drained on later
    /// `sync_account_groups` calls (never a reason to fail a sync).
    pending_unsubscribes: Vec<NostrSubscription>,
    pending_scoped_unsubscribes: HashMap<String, NostrSubscription>,
    metrics: NostrAdapterMetrics,
    relay_index: RelayIndexRegistry,
    telemetry: RelayDeliveryTelemetry,
    sync: RelaySyncTelemetry,
}

impl AdapterState {
    /// Rebuild the derived `by_transport_group` index from the authoritative
    /// `accounts` routing state. Called after every mutation so the index cannot
    /// drift from signed ordinary and temporary maintenance routes (#698/#752).
    fn rebuild_transport_group_index(&mut self) {
        let mut index: HashMap<Vec<u8>, Vec<GroupRouteEntry>> = HashMap::new();
        for (account_id, routes) in &self.accounts {
            for group in &routes.groups {
                index
                    .entry(group.transport_group_id.clone())
                    .or_default()
                    .push(GroupRouteEntry {
                        account_id: account_id.clone(),
                        group_id: group.group_id.clone(),
                        endpoints: group.endpoints.iter().map(CanonicalEndpoint::new).collect(),
                    });
            }
        }
        self.by_transport_group = index;
        let maintenance = std::mem::take(&mut self.maintenance_routes);
        for subscription in maintenance.values() {
            self.stage_group_routes(std::slice::from_ref(subscription));
        }
        self.maintenance_routes = maintenance;
    }

    /// Add the endpoint coverage needed by new group REQs without replacing
    /// any live route. Existing coverage is skipped (including canonical URL
    /// matches), preventing duplicate account deliveries during the staging
    /// window. A later index rebuild commits or discards these entries.
    fn stage_group_routes(&mut self, subscriptions: &[NostrSubscription]) {
        for subscription in subscriptions {
            let (NostrSubscription::Group {
                account_id,
                group_id,
                transport_group_id,
                endpoints,
                ..
            }
            | NostrSubscription::GroupMaintenance {
                account_id,
                group_id,
                transport_group_id,
                endpoints,
                ..
            }) = subscription
            else {
                continue;
            };
            let entries = self
                .by_transport_group
                .entry(transport_group_id.clone())
                .or_default();
            let staged_endpoints = endpoints
                .iter()
                .filter(|endpoint| {
                    let parsed_endpoint = RelayUrl::parse(endpoint.as_str()).ok();
                    !entries.iter().any(|entry| {
                        &entry.account_id == account_id
                            && &entry.group_id == group_id
                            && entry.endpoints.iter().any(|candidate| {
                                candidate.matches(endpoint, parsed_endpoint.as_ref())
                            })
                    })
                })
                .map(CanonicalEndpoint::new)
                .collect::<Vec<_>>();
            if !staged_endpoints.is_empty() {
                entries.push(GroupRouteEntry {
                    account_id: account_id.clone(),
                    group_id: group_id.clone(),
                    endpoints: staged_endpoints,
                });
            }
        }
    }

    fn activate(
        &mut self,
        activation: TransportAccountActivation,
        replaced: usize,
        attempt: SubscriptionAttempt,
        routes: &[NostrSubscription],
        batches: &[NostrSubscription],
    ) {
        self.metrics.subscriptions_created += 1 + batches.len();
        self.metrics.subscriptions_removed += replaced;
        // Raise the high-water mark before the routes take a copy of it: the
        // routes are the reconstruction source for `account_subscription_ids`,
        // the high-water map is what survives their removal.
        self.activation_attempt_high_water
            .insert(activation.account_id.clone(), attempt);
        self.forget_maintenance_routes(&activation.account_id);
        self.accounts.insert(
            activation.account_id,
            AccountRoutes {
                inbox_endpoints: activation
                    .inbox_endpoints
                    .iter()
                    .map(CanonicalEndpoint::new)
                    .collect(),
                groups: activation.group_subscriptions,
                group_since: issued_group_since(routes).collect(),
                attempt,
                batches: batches.to_vec(),
                next_batch: u32::try_from(batches.len()).unwrap_or(u32::MAX),
            },
        );
        self.rebuild_transport_group_index();
    }

    /// Commit a group sync that changed the route set: its routes, the floor
    /// each was issued at, and the batches that now carry them all. Returns
    /// the batches they replace, for the caller to close.
    fn sync_groups(
        &mut self,
        sync: TransportGroupSync,
        routes: &[NostrSubscription],
        batches: &[NostrSubscription],
    ) -> Vec<NostrSubscription> {
        let Some(account) = self.accounts.get_mut(&sync.account_id) else {
            return Vec::new();
        };
        account.groups = sync.group_subscriptions;
        account.group_since = issued_group_since(routes).collect();
        let replaced = std::mem::replace(&mut account.batches, batches.to_vec());
        self.metrics.subscriptions_created += batches.len();
        self.rebuild_transport_group_index();
        replaced
    }

    /// Add a repack's batches to the account's replay coverage before their
    /// REQs go out, as activation does, so a relay's stored events, EOSE or
    /// refusal for them count however soon they arrive. Until the sync
    /// commits, the batches they replace stay in coverage too, which only
    /// asks more of it.
    fn stage_replay_batches(&mut self, account_id: &MemberId, batches: &[NostrSubscription]) {
        for batch in batches {
            self.stage_replay_subscription(account_id, batch, batch.subscription_id());
        }
    }

    fn stage_replay_subscription(
        &mut self,
        account_id: &MemberId,
        subscription: &NostrSubscription,
        id: String,
    ) {
        let relays = subscription
            .endpoints()
            .iter()
            .map(|endpoint| (self.relay_index.index_for(endpoint), RelayReplay::Awaiting))
            .collect();
        if let Some(coverage) = self.account_replay_coverage.get_mut(account_id) {
            coverage.add_subscription(id, subscription, relays);
        }
    }

    /// Drop a repack's staged batches from replay coverage when its sync
    /// failed or was cancelled before committing them. A sync cancelled after
    /// its commit keeps them: they are live.
    fn retire_unlive_replay_batches(
        &mut self,
        account_id: &MemberId,
        batches: &[NostrSubscription],
    ) {
        let abandoned = batches
            .iter()
            .filter(|batch| {
                self.live_subscription_route(&batch.subscription_id())
                    .is_none()
            })
            .cloned()
            .collect::<Vec<_>>();
        self.retire_replay_batches(account_id, &abandoned);
    }

    /// Drop batches from the account's replay coverage: those a committed
    /// repack replaced, whose routes its own batches now carry from no later
    /// a floor, or a failed repack's own. A route the sync removed is no
    /// longer owed.
    fn retire_replay_batches(&mut self, account_id: &MemberId, batches: &[NostrSubscription]) {
        let Some(coverage) = self.account_replay_coverage.get_mut(account_id) else {
            return;
        };
        for batch in batches {
            let id = batch.subscription_id();
            coverage.remove_subscription(&id);
        }
    }

    /// Queue relay unsubscribes whose relay-side teardown has not been
    /// confirmed yet, deduplicated by subscription id (ids are deterministic
    /// content hashes, so a retried removal re-queues the same id).
    fn queue_pending_unsubscribes(&mut self, subscriptions: Vec<NostrSubscription>) {
        for subscription in subscriptions {
            let id = subscription.subscription_id();
            if self
                .pending_unsubscribes
                .iter()
                .any(|pending| pending.subscription_id() == id)
            {
                continue;
            }
            self.pending_unsubscribes.push(subscription);
        }
    }

    /// Drop queued unsubscribes whose route key is live again so a stale relay
    /// teardown cannot tear down a just-re-established subscription.
    fn prune_live_pending_unsubscribes(&mut self) {
        let live_route_keys = self.live_group_route_keys();
        self.pending_unsubscribes.retain(|subscription| {
            !live_route_keys.contains(&subscription.route_key())
                && !self
                    .maintenance_routes
                    .contains_key(&subscription.subscription_id())
        });
    }

    fn remove_pending_unsubscribe_by_id(&mut self, subscription_id: &str) -> bool {
        let index = self
            .pending_unsubscribes
            .iter()
            .position(|subscription| subscription.subscription_id() == subscription_id);
        match index {
            Some(index) => {
                self.pending_unsubscribes.remove(index);
                true
            }
            None => false,
        }
    }

    fn live_group_route_keys(&self) -> HashSet<NostrSubscriptionRouteKey> {
        self.accounts
            .iter()
            .flat_map(|(account_id, routes)| {
                routes
                    .groups
                    .iter()
                    .map(|group| group_route_key(account_id, group))
            })
            .collect()
    }

    /// Drop queued per-subscription unsubscribes for an account whose relay
    /// state is being torn down wholesale via `unsubscribe_account`.
    fn clear_pending_unsubscribes_for_account(&mut self, account_id: &MemberId) {
        self.pending_scoped_unsubscribes
            .retain(|_, subscription| subscription.account_id() != account_id);
        self.pending_unsubscribes
            .retain(|subscription| subscription.account_id() != account_id);
    }

    fn record_confirmed_unsubscribes(&mut self, count: usize) {
        self.metrics.subscriptions_removed += count;
    }

    /// Attempt ordinal the account's next activation issues under.
    ///
    /// Read from the high-water map rather than from the account's routes:
    /// deactivation and the failed-activation rollback both remove the routes,
    /// and neither closes the relay sockets the superseded attempt's REQs are
    /// still streaming on. Strictly increasing per account for the lifetime of
    /// this adapter, so a re-issued subscription never reuses a superseded
    /// attempt's id.
    fn next_activation_attempt(&self, account_id: &MemberId) -> SubscriptionAttempt {
        self.activation_attempt_high_water
            .get(account_id)
            .copied()
            .unwrap_or(SubscriptionAttempt::INITIAL)
            .next()
    }

    /// Attempt the account's live subscriptions were issued under, or `None`
    /// when the account is not active.
    fn activation_attempt(&self, account_id: &MemberId) -> Option<SubscriptionAttempt> {
        self.accounts.get(account_id).map(|routes| routes.attempt)
    }

    fn forget_maintenance_routes(&mut self, account_id: &MemberId) {
        self.maintenance_routes.retain(|id, subscription| {
            if subscription.account_id() != account_id {
                return true;
            }
            self.sync.forget_subscription(id);
            false
        });
    }

    fn deactivate(&mut self, account_id: &MemberId, removed_count: usize) {
        self.accounts.remove(account_id);
        self.forget_maintenance_routes(account_id);
        self.account_replay_coverage.remove(account_id);
        self.metrics.subscriptions_removed += removed_count;
        self.rebuild_transport_group_index();
    }

    fn record_inbound_event(&mut self, delivered: usize) {
        self.metrics.inbound_events_seen += 1;
        self.metrics.inbound_events_delivered += delivered;
        if delivered == 0 {
            self.metrics.inbound_events_dropped += 1;
        }
    }

    fn observe_relay_id(
        &mut self,
        id: &[u8],
        endpoint: &TransportEndpoint,
        subscription_id: Option<&str>,
        created_at: u64,
        now_ms: u64,
    ) {
        if let Some(subscription_id) = subscription_id {
            self.record_stored_replay_event(subscription_id, endpoint, created_at);
        }
        let Ok(id) = id.try_into() else { return };
        self.record_delivery_timing(id, endpoint, now_ms);
        if let Some(subscription_id) = subscription_id {
            self.record_subscription_first_event(subscription_id, endpoint, now_ms);
        }
    }

    fn record_delivery_timing(
        &mut self,
        message_id: &[u8; 32],
        endpoint: &TransportEndpoint,
        now_ms: u64,
    ) {
        let relay = self.relay_index.index_for(endpoint);
        self.telemetry.record_sighting(message_id, relay, now_ms);
    }

    fn record_scoped_subscription_start(
        &mut self,
        subscription: &NostrSubscription,
        id: &str,
        now_ms: u64,
    ) {
        let relays = subscription
            .endpoints()
            .iter()
            .map(|endpoint| self.relay_index.index_for(endpoint))
            .collect::<Vec<_>>();
        self.sync.record_subscription_start(id, &relays, now_ms);
    }

    fn record_subscription_starts(&mut self, subscriptions: &[NostrSubscription], now_ms: u64) {
        for subscription in subscriptions {
            self.record_scoped_subscription_start(
                subscription,
                &subscription.subscription_id(),
                now_ms,
            );
        }
    }

    fn record_account_replay_start(
        &mut self,
        account_id: &MemberId,
        subscriptions: &[NostrSubscription],
    ) {
        let mut coverage = AccountReplayCoverage::new(
            account_id.clone(),
            self.replay_losses.clone(),
            self.source_clock.clone(),
        );
        if let Some(ingress) = self.replay_ingresses.get(account_id) {
            coverage.attach_ingress(ingress.clone());
        }
        self.account_replay_coverage
            .insert(account_id.clone(), coverage);
        self.stage_replay_batches(account_id, subscriptions);
        if let Some(coverage) = self.account_replay_coverage.get_mut(account_id) {
            coverage.admit_retained();
        }
    }

    fn stage_subscription_starts(&mut self, subscriptions: &[NostrSubscription], now_ms: u64) {
        self.sync.begin_staged_subscription_starts();
        self.staged_group_subscriptions = subscriptions
            .iter()
            .filter(|subscription| {
                matches!(
                    subscription,
                    NostrSubscription::Group { .. } | NostrSubscription::GroupBatch { .. }
                )
            })
            .map(|subscription| {
                (
                    subscription.subscription_id(),
                    subscription.account_id().clone(),
                )
            })
            .collect();
        for subscription in subscriptions {
            let relays: Vec<RelayIndex> = subscription
                .endpoints()
                .iter()
                .map(|endpoint| self.relay_index.index_for(endpoint))
                .collect();
            self.sync
                .stage_subscription_start(&subscription.subscription_id(), &relays, now_ms);
        }
    }

    fn commit_staged_subscription_starts(&mut self) {
        self.sync.commit_staged_subscription_starts();
        self.staged_group_subscriptions.clear();
    }

    fn rollback_staged_subscription_starts(&mut self) {
        self.sync.rollback_staged_subscription_starts();
        self.staged_group_subscriptions.clear();
    }

    /// Evict sync-telemetry progress for subscriptions being removed, so the
    /// telemetry map tracks live subscriptions rather than historical churn.
    fn forget_subscription_starts(&mut self, subscriptions: &[NostrSubscription]) {
        for subscription in subscriptions {
            self.sync
                .forget_subscription(&subscription.subscription_id());
        }
    }

    /// Subscription ids implied by an account's stored routes: its inbox plus
    /// one per live group batch.
    ///
    /// The inbox id is rebuilt from its endpoints and the activation attempt
    /// stored with the routes (never `since`, which is not stored), so it is
    /// byte-identical to the one sent. Batch ids are read from the stored
    /// batches, never rebuilt from the routes: batch numbers come from a
    /// counter a failed sync also spends, so they are not a function of the
    /// route set. Empty for an account with no stored routes.
    fn account_subscription_ids(&self, account_id: &MemberId) -> Vec<String> {
        let Some(routes) = self.accounts.get(account_id) else {
            return Vec::new();
        };
        let mut ids = Vec::with_capacity(1 + routes.batches.len());
        ids.push(
            account_inbox_subscription(
                account_id,
                routes
                    .inbox_endpoints
                    .iter()
                    .map(|endpoint| endpoint.verbatim.clone())
                    .collect(),
                None,
                routes.attempt,
            )
            .subscription_id(),
        );
        ids.extend(
            routes
                .batches
                .iter()
                .map(NostrSubscription::subscription_id),
        );
        ids
    }

    /// Evict sync-telemetry progress for every subscription implied by an
    /// account's stored routes. Called before the routes are replaced
    /// (reactivate) or removed (deactivate).
    fn forget_account_subscription_starts(&mut self, account_id: &MemberId) {
        for id in self.account_subscription_ids(account_id) {
            self.sync.forget_subscription(&id);
        }
    }

    /// End-of-stored-events progress across the account activation's immutable
    /// route snapshot.
    fn account_subscription_eose(&self, account_id: &MemberId) -> AccountSubscriptionEose {
        self.account_replay_coverage
            .get(account_id)
            .map(AccountReplayCoverage::snapshot)
            .unwrap_or_default()
    }

    fn record_subscription_first_event(
        &mut self,
        subscription_id: &str,
        endpoint: &TransportEndpoint,
        now_ms: u64,
    ) {
        let relay = self.relay_index.index_for(endpoint);
        self.sync.record_first_event(subscription_id, relay, now_ms);
    }

    /// Record wire EOSE and its owned paging ticket in one critical section.
    fn record_subscription_eose(
        &mut self,
        subscription_id: &str,
        endpoint: &TransportEndpoint,
        now_ms: u64,
    ) {
        let relay = self.relay_index.index_for(endpoint);
        self.sync.record_eose(subscription_id, relay, now_ms);
        for (account_id, coverage) in &mut self.account_replay_coverage {
            if let Some((window, until)) = coverage.record_eose(subscription_id, relay, now_ms) {
                let serial = coverage.endpoint_deadlines[subscription_id][&relay].serial;
                coverage.queue_capture(ReplayPaging {
                    account_id: account_id.clone(),
                    subscription_id: subscription_id.to_owned(),
                    endpoint: endpoint.clone(),
                    relay,
                    serial,
                    window,
                    until,
                    credit: None,
                });
            }
        }
    }

    /// Count one relay's copy of a stored event for an activation REQ that has
    /// not reported EOSE on that relay yet.
    fn record_stored_replay_event(
        &mut self,
        subscription_id: &str,
        endpoint: &TransportEndpoint,
        created_at: u64,
    ) {
        let Some(relay) = self.relay_index.existing_index_for(endpoint) else {
            return;
        };
        for coverage in self.account_replay_coverage.values_mut() {
            coverage.record_stored_event(subscription_id, relay, created_at);
        }
    }

    /// A paged replay reached the start of its window. Applies only while the
    /// activation that issued the REQ is still current.
    fn finish_replay_paging(&mut self, paging: &ReplayPaging, now_ms: u64) {
        let Some(relay) = self.relay_index.existing_index_for(&paging.endpoint) else {
            return;
        };
        if let Some(coverage) = self.account_replay_coverage.get_mut(&paging.account_id)
            && coverage.capture_current(paging)
        {
            coverage.finish_paging(&paging.subscription_id, relay);
            if coverage
                .subscriptions
                .get(&paging.subscription_id)
                .and_then(|relays| relays.get(&relay))
                == Some(&RelayReplay::Eose)
            {
                self.sync
                    .record_eose(&paging.subscription_id, relay, now_ms);
            }
        }
    }

    /// The account and route kind of a live subscription id: an account's
    /// inbox, one of its group routes (committed, or staged by a group sync
    /// whose REQs are going out), or post-join maintenance. `None` for a
    /// superseded attempt's id, a one-shot fetch, or anything else not live.
    fn live_subscription_route(
        &self,
        subscription_id: &str,
    ) -> Option<(MemberId, SubscriptionRouteKind)> {
        if let Some(subscription) = self.maintenance_routes.get(subscription_id) {
            return Some((
                subscription.account_id().clone(),
                SubscriptionRouteKind::Maintenance,
            ));
        }
        if let Some(account_id) = self.staged_group_subscriptions.get(subscription_id) {
            return Some((account_id.clone(), SubscriptionRouteKind::Group));
        }
        self.accounts.keys().find_map(|account_id| {
            // `account_subscription_ids` lists the inbox first.
            self.account_subscription_ids(account_id)
                .iter()
                .position(|id| id == subscription_id)
                .map(|position| {
                    let route_kind = if position == 0 {
                        SubscriptionRouteKind::Inbox
                    } else {
                        SubscriptionRouteKind::Group
                    };
                    (account_id.clone(), route_kind)
                })
        })
    }

    /// Record a relay's refusal of a live subscription in replay coverage and
    /// telemetry. Returns the owning account and route kind, or `None` when
    /// the id is not live and nothing was recorded.
    fn record_subscription_refusal(
        &mut self,
        subscription_id: &str,
        endpoint: &TransportEndpoint,
        refusal: SubscriptionRefusal,
    ) -> Option<(MemberId, SubscriptionRouteKind)> {
        let (account_id, route_kind) = self.live_subscription_route(subscription_id)?;
        let relay = self.relay_index.index_for(endpoint);
        if let Some(coverage) = self.account_replay_coverage.get_mut(&account_id) {
            coverage.record_refusal(subscription_id, relay, refusal.disposition);
        }
        self.sync.record_refusal(relay, route_kind, refusal);
        Some((account_id, route_kind))
    }

    fn deliveries_for(
        &self,
        relay_event: &NostrRelayEvent,
        message: TransportMessage,
        account_id: Option<&MemberId>,
    ) -> Vec<TransportDelivery> {
        let received_at = Timestamp(unix_now_seconds());
        let mut routes = self.routes_for(&message, &relay_event.endpoint);
        if let Some(account_id) = account_id {
            routes.retain(|route| &route.account_id == account_id);
        }
        let mut routes = routes.into_iter();
        let Some(last_route) = routes.next_back() else {
            return Vec::new();
        };
        let wire = inbound_wire_metadata(&relay_event.event, &message.envelope);
        let delivery_for = |route: DeliveryRoute, message| TransportDelivery {
            account_id: route.account_id,
            group_id_hint: route.group_id_hint,
            message,
            received_at,
            source: TransportDeliverySource {
                transport: TransportSource(NOSTR_SOURCE.into()),
                plane: route.plane,
                endpoint: Some(relay_event.endpoint.clone()),
                subscription_id: relay_event.subscription_id.clone(),
                wire: Some(wire.clone()),
            },
        };
        let mut deliveries = Vec::with_capacity(routes.len() + 1);
        deliveries.extend(routes.map(|route| delivery_for(route, message.clone())));
        deliveries.push(delivery_for(last_route, message));
        deliveries
    }

    fn admit_deliveries(
        &mut self,
        deliveries: Vec<TransportDelivery>,
        copy: RelayCopy,
        delivery_tx: &mpsc::Sender<TransportDelivery>,
    ) -> Result<usize, TransportAdapterError> {
        let mut delivered = 0;
        for delivery in deliveries {
            let relay = delivery
                .source
                .endpoint
                .as_ref()
                .and_then(|endpoint| self.relay_index.existing_index_for(endpoint));
            // Classify by the issuing REQ, not an unrelated destination route.
            let source = delivery.source.subscription_id.as_ref().and_then(|id| {
                self.account_replay_coverage.values().find_map(|coverage| {
                    let window = coverage.windows.get(id)?;
                    let replay =
                        relay.and_then(|relay| coverage.subscriptions.get(id)?.get(&relay));
                    let serial = relay
                        .and_then(|relay| coverage.endpoint_deadlines.get(id)?.get(&relay))
                        .map(|endpoint| endpoint.serial);
                    let ended = relay
                        .and_then(|relay| coverage.stored.get(id)?.get(&relay))
                        .is_some_and(|stored| stored.ended);
                    Some((
                        matches!(window.scope, ReplayScope::Groups(_)),
                        replay.copied(),
                        serial,
                        ended,
                    ))
                })
            });
            if copy != RelayCopy::Deduplicated && source.is_none() {
                continue;
            }
            if copy == RelayCopy::RawGroup && !source.is_some_and(|source| source.0) {
                continue;
            }
            if let RelayCopy::Page(serial) = copy
                && !source.is_some_and(|source| source.2 == Some(serial))
            {
                continue;
            }
            let input = match copy {
                RelayCopy::Page(_) => ReplayInput::Page,
                _ if source.is_none() => ReplayInput::Untracked,
                _ if source.is_some_and(|source| {
                    source.1.is_some() && source.1 != Some(RelayReplay::Eose) && !source.3
                }) =>
                {
                    ReplayInput::History
                }
                _ => ReplayInput::Live,
            };
            if let Some(coverage) = self.account_replay_coverage.get_mut(&delivery.account_id) {
                delivered += 1;
                coverage.stage_delivery(delivery, relay, input, delivery_tx)?;
            }
        }
        self.record_inbound_event(delivered);
        Ok(delivered)
    }

    fn routes_for(
        &self,
        message: &TransportMessage,
        endpoint: &TransportEndpoint,
    ) -> Vec<DeliveryRoute> {
        match &message.envelope {
            TransportEnvelope::GroupMessage { transport_group_id } => {
                // #698/#752: O(1) index lookup by transport_group_id, then match
                // over ONLY that group's candidate routes — instead of scanning
                // every account × group per event. A miss (unknown/attacker id)
                // returns empty after a single hash probe. The inbound endpoint is
                // parsed once here; stored endpoints are pre-parsed in the index.
                let Some(entries) = self.by_transport_group.get(transport_group_id) else {
                    return Vec::new();
                };
                let parsed_endpoint = RelayUrl::parse(endpoint.as_str()).ok();
                entries
                    .iter()
                    .filter(|entry| {
                        entry
                            .endpoints
                            .iter()
                            .any(|candidate| candidate.matches(endpoint, parsed_endpoint.as_ref()))
                    })
                    .map(|entry| DeliveryRoute {
                        account_id: entry.account_id.clone(),
                        group_id_hint: Some(entry.group_id.clone()),
                        plane: TransportDeliveryPlane::Group,
                    })
                    .collect()
            }
            TransportEnvelope::Welcome { recipient } => {
                // #698/#752: parse the inbound endpoint once (not per candidate,
                // not per account) and match against pre-canonicalized inbox
                // endpoints, mirroring the group arm above.
                let parsed_endpoint = RelayUrl::parse(endpoint.as_str()).ok();
                self.accounts
                    .iter()
                    .filter(|(account_id, routes)| {
                        *account_id == recipient
                            && routes.inbox_endpoints.iter().any(|candidate| {
                                candidate.matches(endpoint, parsed_endpoint.as_ref())
                            })
                    })
                    .map(|(account_id, _)| DeliveryRoute {
                        account_id: account_id.clone(),
                        group_id_hint: None,
                        plane: TransportDeliveryPlane::AccountInbox,
                    })
                    .collect()
            }
        }
    }
}

/// NIP-59 gift wraps (welcomes) randomize the wrapper's `created_at` up to two
/// days into the past to resist timing analysis. A catch-up `since` derived
/// from the last-seen transport timestamp would therefore permanently skip any
/// welcome published while this device was offline whose tweak landed before
/// the cursor. Widen the inbox window by the full tweak range; re-delivered
/// wraps are deduplicated by seen-event ids downstream, and only welcomes
/// travel as gift wraps so the re-fetch volume stays small.
pub const NIP59_TIMESTAMP_TWEAK_SECS: u64 = 172_800;

fn inbox_since(since: Option<Timestamp>) -> Option<Timestamp> {
    since.map(|since| Timestamp(since.0.saturating_sub(NIP59_TIMESTAMP_TWEAK_SECS)))
}

/// Single construction point for the account-inbox subscription, shared by
/// activation issuance and telemetry-eviction id reconstruction so the two
/// can never derive different subscription ids.
fn account_inbox_subscription(
    account_id: &MemberId,
    endpoints: Vec<TransportEndpoint>,
    since: Option<Timestamp>,
    attempt: SubscriptionAttempt,
) -> NostrSubscription {
    NostrSubscription::AccountInbox {
        account_id: account_id.clone(),
        endpoints,
        since,
        attempt,
    }
}

fn group_subscription(
    account_id: &MemberId,
    group: &TransportGroupSubscription,
    since: Option<Timestamp>,
    attempt: SubscriptionAttempt,
) -> NostrSubscription {
    NostrSubscription::Group {
        account_id: account_id.clone(),
        group_id: group.group_id.clone(),
        transport_group_id: group.transport_group_id.clone(),
        endpoints: group.endpoints.clone(),
        since,
        attempt,
    }
}

/// Every route a changed group sync wants, each at the floor its repacked
/// batch asks from. A route the sync adds or widens takes its diff's floor.
/// A route already live keeps the floor it was issued at, unless the
/// activation's replay coverage is complete: its live REQs then served
/// everything up to now, so it starts where a fresh activation would, at the
/// sync's floor, instead of replaying that history again.
fn repacked_group_routes(
    sync: &TransportGroupSync,
    routes: &AccountRoutes,
    added: &[NostrSubscription],
    replay_complete: bool,
) -> Vec<NostrSubscription> {
    let account_id = &sync.account_id;
    let prior_route_keys = prior_group_route_keys(account_id, &sync.group_subscriptions);
    let added = added
        .iter()
        .map(|route| (route.route_key(), route.clone()))
        .collect::<HashMap<_, _>>();
    sync.group_subscriptions
        .iter()
        .map(|group| {
            let key = group_route_key(account_id, group);
            if let Some(route) = added.get(&key) {
                return route.clone();
            }
            let fresh = group_route_since(account_id, group, &prior_route_keys, sync.since);
            let since = match routes.group_since.get(&key) {
                Some(issued) if !replay_complete => issued
                    .zip(fresh)
                    .map(|(issued, requested)| issued.min(requested)),
                _ => fresh,
            };
            group_subscription(account_id, group, since, routes.attempt)
        })
        .collect()
}

/// Pack per-route group REQs into batches of at most [`GROUP_BATCH_ROUTES`]
/// routes that share endpoints and `since`, keeping the routes' order, and
/// number them from `first_batch`. Only routes with one floor share a batch,
/// so a deep retained or newly joined route never drags the others' replay
/// back with it.
fn pack_group_batches(
    account_id: &MemberId,
    routes: &[NostrSubscription],
    attempt: SubscriptionAttempt,
    first_batch: u32,
) -> Vec<NostrSubscription> {
    type BatchKey = (Vec<TransportEndpoint>, Option<Timestamp>);
    let mut families: Vec<(BatchKey, Vec<TransportEndpoint>, Vec<GroupBatchRoute>)> = Vec::new();
    for route in routes {
        let NostrSubscription::Group {
            group_id,
            transport_group_id,
            endpoints,
            since,
            ..
        } = route
        else {
            continue;
        };
        let key = (normalized_endpoints(endpoints), *since);
        let member = GroupBatchRoute {
            group_id: group_id.clone(),
            transport_group_id: transport_group_id.clone(),
        };
        match families.iter_mut().find(|(family, ..)| *family == key) {
            Some((_, _, members)) => members.push(member),
            None => families.push((key, endpoints.clone(), vec![member])),
        }
    }
    let mut batch = first_batch;
    let mut batches = Vec::new();
    for ((_, since), endpoints, members) in families {
        for chunk in members.chunks(GROUP_BATCH_ROUTES) {
            batches.push(NostrSubscription::GroupBatch {
                account_id: account_id.clone(),
                routes: chunk.to_vec(),
                endpoints: endpoints.clone(),
                since,
                attempt,
                batch,
            });
            batch = batch.saturating_add(1);
        }
    }
    batches
}

/// Route identity of a group subscription, independent of both the `since`
/// floor and the issuing attempt. Route comparison spans activations, so it
/// must not see either.
fn group_route_key(
    account_id: &MemberId,
    group: &TransportGroupSubscription,
) -> NostrSubscriptionRouteKey {
    NostrSubscriptionRouteKey::Group {
        account_id: account_id.clone(),
        group_id: group.group_id.clone(),
        transport_group_id: group.transport_group_id.clone(),
        endpoints: normalized_endpoints(&group.endpoints),
    }
}

/// The `since` a group route's REQ is issued with.
///
/// A group's current route resumes from the account's `since`. A retained
/// route resumes from its own floor, and never from later than the account's
/// `since`: members that have not applied the route change still send to the
/// old address, with timestamps the account cursor, which the current route
/// drives, may already have passed. A retained route without a floor is
/// backfilled in full.
fn group_route_since(
    account_id: &MemberId,
    group: &TransportGroupSubscription,
    prior_route_keys: &HashSet<NostrSubscriptionRouteKey>,
    since: Option<Timestamp>,
) -> Option<Timestamp> {
    if !is_retained_route(account_id, group, prior_route_keys) {
        return since;
    }
    group
        .retained_since
        .zip(since)
        .map(|(floor, since)| floor.min(since))
}

/// A route that carries a retained floor is retained wherever it sits, so it
/// never takes the current route's place, even where the relay-safety filter
/// dropped that route. A floorless route after its group's first is a
/// retained route whose switch time the caller does not know.
fn is_retained_route(
    account_id: &MemberId,
    group: &TransportGroupSubscription,
    prior_route_keys: &HashSet<NostrSubscriptionRouteKey>,
) -> bool {
    group.retained_since.is_some() || prior_route_keys.contains(&group_route_key(account_id, group))
}

/// Whether a REQ issued with `desired` reaches further back than one issued
/// with `issued`. `None` is unfloored, the widest of all.
fn floor_widens(desired: Option<Timestamp>, issued: Option<Timestamp>) -> bool {
    match (desired, issued) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(desired), Some(issued)) => desired < issued,
    }
}

/// The `since` of each group REQ in `subscriptions`, by route.
fn issued_group_since(
    subscriptions: &[NostrSubscription],
) -> impl Iterator<Item = (NostrSubscriptionRouteKey, Option<Timestamp>)> + '_ {
    subscriptions
        .iter()
        .filter_map(|subscription| match subscription {
            NostrSubscription::Group { since, .. } => Some((subscription.route_key(), *since)),
            _ => None,
        })
}

fn diff_group_subscriptions(
    account_id: &MemberId,
    current: &[TransportGroupSubscription],
    current_since: &HashMap<NostrSubscriptionRouteKey, Option<Timestamp>>,
    desired: &[TransportGroupSubscription],
    since: Option<Timestamp>,
    attempt: SubscriptionAttempt,
) -> (Vec<NostrSubscription>, Vec<NostrSubscription>) {
    let current_subscriptions = current
        .iter()
        .map(|group| group_subscription(account_id, group, None, attempt))
        .collect::<Vec<_>>();
    let desired_prior_keys = prior_group_route_keys(account_id, desired);
    let desired_subscriptions = desired
        .iter()
        .map(|group| {
            let retained = is_retained_route(account_id, group, &desired_prior_keys);
            let since = group_route_since(account_id, group, &desired_prior_keys, since);
            (
                retained,
                since,
                group_subscription(account_id, group, since, attempt),
            )
        })
        .collect::<Vec<_>>();
    let current_keys = current_subscriptions
        .iter()
        .map(NostrSubscription::route_key)
        .collect::<HashSet<_>>();
    let desired_keys = desired_subscriptions
        .iter()
        .map(|(_, _, subscription)| subscription.route_key())
        .collect::<HashSet<_>>();

    let to_add = desired_subscriptions
        .into_iter()
        .filter(|(retained, since, subscription)| {
            let route_key = subscription.route_key();
            // A live route is added again only to widen a retained route, such
            // as the current route a route change just displaced. It is then
            // repacked at the wider floor; a narrower one could cut off
            // history its live batch is still returning.
            !current_keys.contains(&route_key)
                || (*retained
                    && current_since
                        .get(&route_key)
                        .is_some_and(|issued| floor_widens(*since, *issued)))
        })
        .map(|(_, _, subscription)| subscription)
        .collect();
    let to_remove = current_subscriptions
        .into_iter()
        .filter(|subscription| !desired_keys.contains(&subscription.route_key()))
        .collect();

    (to_add, to_remove)
}

/// Return route keys for retained prior addresses that carry no floor. App
/// routing orders each group's current signed route first and its retained
/// historical routes immediately afterward. A floored retained route is
/// recognized by its floor (see [`is_retained_route`]), so position decides
/// only among floorless routes: the first is the current route, which keeps
/// the account cursor, and a later distinct one is a retained route whose
/// switch time the caller does not know.
fn prior_group_route_keys(
    account_id: &MemberId,
    groups: &[TransportGroupSubscription],
) -> HashSet<NostrSubscriptionRouteKey> {
    let mut current_routes = HashMap::new();
    let mut prior_route_keys = HashSet::new();
    for group in groups.iter().filter(|group| group.retained_since.is_none()) {
        let route_key = group_route_key(account_id, group);
        let current = current_routes
            .entry(group.group_id.clone())
            .or_insert_with(|| route_key.clone());
        if *current != route_key {
            prior_route_keys.insert(route_key);
        }
    }
    prior_route_keys
}

fn normalized_endpoints(endpoints: &[TransportEndpoint]) -> Vec<TransportEndpoint> {
    let mut endpoints = endpoints.to_vec();
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

fn endpoint_set_digest(endpoints: &[TransportEndpoint]) -> String {
    let mut values = endpoints
        .iter()
        .map(TransportEndpoint::as_str)
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();

    let mut hasher = Sha256::new();
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn compact_subscription_id(kind: &str, components: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hash_component(&mut hasher, kind.as_bytes());
    for component in components {
        hash_component(&mut hasher, component);
    }
    let digest = hex::encode(hasher.finalize());
    format!("marmot:{kind}:{}", &digest[..32])
}

fn hash_component(hasher: &mut Sha256, component: &[u8]) {
    hasher.update((component.len() as u64).to_be_bytes());
    hasher.update(component);
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    fn route(index: u8, endpoint: &str, since: Option<u64>) -> NostrSubscription {
        NostrSubscription::Group {
            account_id: MemberId::new(vec![0xA1; 32]),
            group_id: GroupId::new(vec![index; 16]),
            transport_group_id: vec![index; 32],
            endpoints: vec![TransportEndpoint(endpoint.to_owned())],
            since: since.map(Timestamp),
            attempt: SubscriptionAttempt::INITIAL,
        }
    }

    fn batch_shape(batch: &NostrSubscription) -> (u32, usize, Option<Timestamp>) {
        let NostrSubscription::GroupBatch {
            routes,
            since,
            batch,
            ..
        } = batch
        else {
            panic!("a group batch");
        };
        (*batch, routes.len(), *since)
    }

    /// Routes share a batch only with routes on the same relays at the same
    /// floor, in their order, at most `GROUP_BATCH_ROUTES` to a batch, and the
    /// batches are numbered from the first number given.
    #[test]
    fn routes_pack_by_relays_and_floor_in_whole_batches() {
        let mut routes = (0..GROUP_BATCH_ROUTES as u8 + 3)
            .map(|index| route(index, "wss://a.example", Some(100)))
            .collect::<Vec<_>>();
        routes.push(route(200, "wss://a.example", Some(50)));
        routes.push(route(201, "wss://b.example", Some(100)));
        let account = MemberId::new(vec![0xA1; 32]);
        let batches = pack_group_batches(&account, &routes, SubscriptionAttempt::INITIAL, 7);
        assert_eq!(
            batches.iter().map(batch_shape).collect::<Vec<_>>(),
            vec![
                (7, GROUP_BATCH_ROUTES, Some(Timestamp(100))),
                (8, 3, Some(Timestamp(100))),
                (9, 1, Some(Timestamp(50))),
                (10, 1, Some(Timestamp(100))),
            ]
        );
        let ids = batches
            .iter()
            .map(NostrSubscription::subscription_id)
            .collect::<HashSet<_>>();
        assert_eq!(ids.len(), batches.len(), "every batch has its own id");
        assert!(batches[0].carries_group(&GroupId::new(vec![0; 16])));
        assert!(!batches[0].carries_group(&GroupId::new(vec![200; 16])));
    }

    /// A batch's replay pages as deep, per route it carries, as one route's
    /// replay did alone.
    #[test]
    fn a_batch_replay_pages_per_route_it_carries() {
        let routes = (0..3)
            .map(|index| route(index, "wss://a.example", None))
            .collect::<Vec<_>>();
        let account = MemberId::new(vec![0xA1; 32]);
        let batch =
            pack_group_batches(&account, &routes, SubscriptionAttempt::INITIAL, 0).remove(0);
        let window = ReplayWindow::for_subscription(&batch).expect("a batch has a window");
        assert_eq!(window.max_pages(), 3 * REPLAY_PAGE_MAX_PAGES);
        let NostrAcquisitionScope::GroupsWindow {
            transport_group_ids,
            since,
            until,
        } = window.acquisition_scope(500)
        else {
            panic!("a batch pages its whole filter");
        };
        assert_eq!(transport_group_ids.len(), 3);
        assert_eq!((since, until), (0, 500));
    }

    fn replay_coverage(routes: usize) -> (AccountReplayCoverage, String, Arc<ReplayLosses>) {
        let account = MemberId::new(vec![0xA1; 32]);
        let routes = (0..routes as u8)
            .map(|index| route(index, "wss://a.example", Some(100)))
            .collect::<Vec<_>>();
        let batch =
            pack_group_batches(&account, &routes, SubscriptionAttempt::INITIAL, 0).remove(0);
        let id = batch.subscription_id();
        let losses = Arc::new(ReplayLosses::default());
        let mut coverage = AccountReplayCoverage::new(account, losses.clone(), Arc::default());
        coverage.add_subscription(
            id.clone(),
            &batch,
            HashMap::from([
                (RelayIndex(1), RelayReplay::Awaiting),
                (RelayIndex(2), RelayReplay::Awaiting),
            ]),
        );
        (coverage, id, losses)
    }

    fn paging_for(coverage: &mut AccountReplayCoverage, id: &str) -> ReplayPaging {
        let (window, serial) = coverage
            .restart_request(id, RelayIndex(2), ReplayStart::Capture)
            .expect("starts capture");
        ReplayPaging {
            account_id: MemberId::new(vec![0xA1; 32]),
            subscription_id: id.to_owned(),
            endpoint: TransportEndpoint("wss://a.example".to_owned()),
            relay: RelayIndex(2),
            serial,
            window,
            until: REPLAY_OPEN_UNTIL,
            credit: Some(Arc::new(
                Arc::new(tokio::sync::Semaphore::new(1))
                    .try_acquire_owned()
                    .unwrap(),
            )),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn repack_keeps_peer_fence() {
        let (mut coverage, old, losses) = replay_coverage(1);
        coverage.record_eose(&old, RelayIndex(1), 0);
        let mut previous = old;
        for serial in 1..=2 {
            let account = MemberId::new(vec![0xA1; 32]);
            let source = pack_group_batches(
                &account,
                &[route(0, "wss://a.example", Some(100))],
                SubscriptionAttempt::INITIAL,
                serial,
            )
            .remove(0);
            let id = source.subscription_id();
            coverage.add_subscription(
                id.clone(),
                &source,
                HashMap::from([
                    (RelayIndex(1), RelayReplay::Awaiting),
                    (RelayIndex(2), RelayReplay::Awaiting),
                ]),
            );
            coverage.remove_subscription(&previous);
            let group = coverage.groups.values().next().unwrap();
            assert!(
                !coverage.group_ready(group),
                "every replacement peer must establish its own history boundary"
            );
            previous = id;
        }
        assert!(losses.pending.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn empty_admission_holds_payload() {
        let (mut coverage, id, losses) = replay_coverage(1);
        coverage.record_eose(&id, RelayIndex(1), 0);
        let group = coverage.groups.values().next().unwrap();
        assert!(
            !coverage.group_ready(group),
            "a current peer still owes older input"
        );
        assert!(
            coverage.request_admitted(&id, Some(RelayIndex(1))),
            "empty input keeps limited one-peer native admission"
        );
        assert!(
            coverage.admission_pending(),
            "an in-deadline group peer still fences the cursor's original range"
        );
        assert!(
            !coverage.snapshot().complete(),
            "limited admission is not all-peer history certification"
        );
        tokio::time::advance(REPLAY_PAGE_LIMITS.max_duration).await;
        coverage.expire_replay(tokio::time::Instant::now());
        assert!(coverage.group_ready(coverage.groups.values().next().unwrap()));
        assert!(
            !coverage.admission_pending(),
            "finite empty expiry releases placement without inventing EOSE or loss"
        );
        assert!(!coverage.snapshot().complete());
        assert!(losses.pending.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn dormant_metadata_is_not_loss() {
        let (mut coverage, id, losses) = replay_coverage(1);
        coverage.record_eose(&id, RelayIndex(1), 0);
        tokio::time::advance(REPLAY_PAGE_LIMITS.max_duration).await;
        coverage.expire_replay(tokio::time::Instant::now());
        assert!(
            losses.pending.lock().unwrap().is_empty(),
            "an empty peer does not discard history"
        );
        coverage.record_stored_event(&id, RelayIndex(2), 150);
        assert!(losses.pending.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn dormant_empty_stream_can_end() {
        let (mut coverage, id, losses) = replay_coverage(1);
        coverage.record_eose(&id, RelayIndex(1), 0);
        tokio::time::advance(REPLAY_PAGE_LIMITS.max_duration).await;
        coverage.expire_replay(tokio::time::Instant::now());
        coverage.record_eose(&id, RelayIndex(2), 31_000);
        assert!(coverage.snapshot().complete());
        assert!(losses.pending.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn eose_wins_its_deadline() {
        let (mut coverage, id, losses) = replay_coverage(1);
        coverage.record_stored_event(&id, RelayIndex(1), 150);
        tokio::time::advance(REPLAY_PAGE_LIMITS.max_duration).await;
        coverage.record_eose(&id, RelayIndex(1), 30_000);
        assert!(coverage.request_admitted(&id, Some(RelayIndex(1))));
        assert!(coverage.endpoint_deadlines[&id][&RelayIndex(1)].boundary_admitted);
        assert!(losses.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn boundary_survives_live_pin() {
        let (mut coverage, id, _) = replay_coverage(1);
        coverage.record_eose(&id, RelayIndex(1), 0);
        let group = GroupId::new(vec![0; 16]);
        coverage.pin_delivery([7; 32], Some(&group));
        assert!(coverage.admission_pending());
        assert!(!coverage.request_admitted(&id, Some(RelayIndex(1))));
        assert!(coverage.endpoint_deadlines[&id][&RelayIndex(1)].boundary_admitted);
        coverage.ack_placement(&MessageId::new(vec![7; 32]));
        coverage.restart_request(&id, RelayIndex(1), ReplayStart::Gap);
        assert!(!coverage.endpoint_deadlines[&id][&RelayIndex(1)].boundary_admitted);
    }

    #[tokio::test]
    async fn generations_survive_reopen() {
        let account = MemberId::new(vec![0xA1; 32]);
        let clock = Arc::default();
        let losses = Arc::new(ReplayLosses::default());
        let mut first =
            AccountReplayCoverage::new(account.clone(), losses.clone(), Arc::clone(&clock));
        let generation = first.wire_generation;
        let mut changes = first.changes.tx.subscribe();
        changes.borrow_and_update();
        first.ack_placement(&MessageId::new(vec![7; 32]));
        assert_eq!(first.wire_generation, generation);
        assert!(
            changes.has_changed().unwrap(),
            "placement announces same-generation progress"
        );
        drop(first);
        let next = AccountReplayCoverage::new(account, losses, clock);
        assert!(next.wire_generation > generation);
    }

    #[test]
    fn repack_keeps_requested_floor() {
        let account = MemberId::new(vec![0xA1; 32]);
        let group = TransportGroupSubscription {
            group_id: GroupId::new(vec![0; 16]),
            transport_group_id: vec![1; 32],
            endpoints: vec![TransportEndpoint("wss://a.example".into())],
            retained_since: Some(Timestamp(900)),
        };
        let key = group_route_key(&account, &group);
        let routes = AccountRoutes {
            inbox_endpoints: Vec::new(),
            groups: vec![group.clone()],
            group_since: HashMap::from([(key, Some(Timestamp(900)))]),
            attempt: SubscriptionAttempt::INITIAL,
            batches: Vec::new(),
            next_batch: 0,
        };
        for complete in [false, true] {
            for floor in [None, Some(Timestamp(100))] {
                let sync = TransportGroupSync {
                    account_id: account.clone(),
                    group_subscriptions: vec![group.clone()],
                    since: floor,
                };
                let packed = repacked_group_routes(&sync, &routes, &[], complete);
                assert!(
                    matches!(&packed[0], NostrSubscription::Group { since, .. } if *since == floor)
                );
            }
        }
    }

    #[tokio::test]
    async fn all_group_tags_finish_first() {
        let account = MemberId::new(vec![0xA1; 32]);
        let group = GroupId::new(vec![0; 16]);
        let batch = NostrSubscription::GroupBatch {
            account_id: account.clone(),
            routes: vec![
                GroupBatchRoute {
                    group_id: group.clone(),
                    transport_group_id: vec![1; 32],
                },
                GroupBatchRoute {
                    group_id: group.clone(),
                    transport_group_id: vec![2; 32],
                },
            ],
            endpoints: vec![TransportEndpoint("wss://a.example".into())],
            since: Some(Timestamp(100)),
            attempt: SubscriptionAttempt::INITIAL,
            batch: 0,
        };
        let id = batch.subscription_id();
        let mut coverage = AccountReplayCoverage::new(account, Arc::default(), Arc::default());
        coverage.add_subscription(
            id.clone(),
            &batch,
            HashMap::from([(RelayIndex(2), RelayReplay::Awaiting)]),
        );
        let paging = paging_for(&mut coverage, &id);
        let units = coverage.page_units(&paging);
        assert_eq!(
            units.len(),
            1,
            "all tags of one MLS group form a single release unit"
        );
        let routes = units[0].per_route();
        assert_eq!(routes.len(), 2);
        assert!(coverage.start_route(&paging, &routes[0]));
        assert!(coverage.finish_route(&paging, &routes[0]));
        assert!(
            !coverage.group_ready(&coverage.groups[&group]),
            "an unobserved queued tag still fences its group"
        );
        assert!(!coverage.endpoint_deadlines[&id][&RelayIndex(2)].boundary_admitted);
        assert!(coverage.start_route(&paging, &routes[1]));
        assert!(coverage.finish_route(&paging, &routes[1]));
        coverage.finish_paging(&id, RelayIndex(2));
        assert!(coverage.endpoint_deadlines[&id][&RelayIndex(2)].boundary_admitted);
    }

    #[tokio::test]
    async fn failed_tag_discards_prefix() {
        let (mut coverage, old, losses) = replay_coverage(1);
        coverage.remove_subscription(&old);
        losses.pending.lock().unwrap().clear();
        let account = MemberId::new(vec![0xA1; 32]);
        let group = GroupId::new(vec![0; 16]);
        let endpoint = TransportEndpoint("wss://a.example".into());
        let batch = NostrSubscription::GroupBatch {
            account_id: account.clone(),
            routes: vec![
                GroupBatchRoute {
                    group_id: group.clone(),
                    transport_group_id: vec![1; 32],
                },
                GroupBatchRoute {
                    group_id: group.clone(),
                    transport_group_id: vec![2; 32],
                },
            ],
            endpoints: vec![endpoint.clone()],
            since: Some(Timestamp(100)),
            attempt: SubscriptionAttempt::INITIAL,
            batch: 1,
        };
        let id = batch.subscription_id();
        coverage.add_subscription(
            id.clone(),
            &batch,
            HashMap::from([(RelayIndex(2), RelayReplay::Awaiting)]),
        );
        let paging = paging_for(&mut coverage, &id);
        let routes = paging.window.per_route();
        assert!(coverage.start_route(&paging, &routes[0]));
        let delivery = TransportDelivery {
            account_id: account,
            group_id_hint: Some(group),
            message: TransportMessage {
                id: MessageId::new(vec![7; 32]),
                payload: vec![1, 2, 3],
                timestamp: Timestamp(500),
                causal_deps: Vec::new(),
                source: TransportSource(NOSTR_SOURCE.into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: vec![1; 32],
                },
            },
            received_at: Timestamp(600),
            source: TransportDeliverySource {
                transport: TransportSource(NOSTR_SOURCE.into()),
                plane: TransportDeliveryPlane::Group,
                endpoint: Some(endpoint),
                subscription_id: Some(id.clone()),
                wire: None,
            },
        };
        let (tx, _rx) = mpsc::channel(1);
        coverage
            .stage_delivery(delivery, Some(RelayIndex(2)), ReplayInput::Page, &tx)
            .unwrap();
        assert!(coverage.finish_route(&paging, &routes[0]));
        assert!(
            coverage.take_ready_deliveries().is_empty(),
            "the retained tag still owns older input"
        );
        assert!(coverage.start_route(&paging, &routes[1]));
        coverage.fail_route(&paging, &routes[1]);
        assert!(
            coverage.take_ready_deliveries().is_empty(),
            "a failed older tag cannot release the newer suffix"
        );
        assert_eq!(coverage.buffered_items, 0);
        assert_eq!(
            losses
                .pending
                .lock()
                .unwrap()
                .get(&MemberId::new(vec![0xA1; 32])),
            Some(&NostrNotificationLossFloor::Since(100))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn first_connection_reopens_wait() {
        let (mut coverage, id, losses) = replay_coverage(1);
        coverage.record_eose(&id, RelayIndex(1), 0);
        tokio::time::advance(REPLAY_PAGE_LIMITS.max_duration).await;
        coverage.expire_replay(tokio::time::Instant::now());
        coverage.restart_relay(
            RelayIndex(2),
            ReplayRestart::Connection,
            ReplayOrigin::Initial,
        );
        tokio::time::advance(Duration::from_secs(20)).await;
        coverage.record_stored_event(&id, RelayIndex(2), 150);
        coverage.record_eose(&id, RelayIndex(2), 51_000);
        assert!(
            coverage.snapshot().complete(),
            "initial ownership restarts at the actual connection boundary"
        );
        assert!(losses.pending.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn refusal_keeps_terminal_owner() {
        let (mut coverage, id, _) = replay_coverage(1);
        coverage.record_eose(&id, RelayIndex(1), 0);
        coverage.record_refusal(&id, RelayIndex(2), SubscriptionRefusalDisposition::Dropped);
        coverage.restart_relay(
            RelayIndex(2),
            ReplayRestart::Connection,
            ReplayOrigin::Changed,
        );
        coverage.restart_relay(
            RelayIndex(2),
            ReplayRestart::ReceiverLoss,
            ReplayOrigin::Changed,
        );
        assert!(
            coverage
                .restart_request(&id, RelayIndex(2), ReplayStart::Capture)
                .is_none()
        );
        coverage.record_eose(&id, RelayIndex(2), 3);
        assert_eq!(
            coverage.subscriptions[&id][&RelayIndex(2)],
            RelayReplay::Refused
        );
        assert!(coverage.snapshot().settled());
        assert!(
            !coverage.snapshot().complete(),
            "a removed live REQ is not restored by a private capture"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn queued_units_get_own_budget() {
        let (mut coverage, id, losses) = replay_coverage(3);
        coverage.record_eose(&id, RelayIndex(1), 0);
        let paging = paging_for(&mut coverage, &id);
        for unit in coverage.page_units(&paging) {
            assert!(coverage.start_route(&paging, &unit));
            assert_eq!(
                coverage.page_deadline(&paging, &unit),
                Some(tokio::time::Instant::now() + REPLAY_PAGE_LIMITS.max_duration)
            );
            tokio::time::advance(Duration::from_secs(12)).await;
            coverage.expire_replay(tokio::time::Instant::now());
            assert!(
                coverage.page_allowed(&paging, &unit),
                "a queued route did not spend its allowance before service"
            );
            coverage.finish_route(&paging, &unit);
        }
        coverage.finish_paging(&id, RelayIndex(2));
        assert!(
            coverage.snapshot().complete(),
            "the batch may take more than one route allowance"
        );
        assert!(losses.pending.lock().unwrap().is_empty());
    }

    /// Reports every REQ on `owing` as owed by that unreachable relay.
    struct OwingRelayClient {
        owing: TransportEndpoint,
    }

    #[async_trait]
    impl NostrRelayClient for OwingRelayClient {
        async fn subscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
            Ok(())
        }

        async fn subscribe_reporting(
            &self,
            subscription: NostrSubscription,
        ) -> Result<NostrSubscribeReport, TransportAdapterError> {
            Ok(NostrSubscribeReport {
                owed_relays: usize::from(subscription.endpoints().contains(&self.owing)),
                refused_relays: 0,
            })
        }

        async fn unsubscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
            Ok(())
        }

        async fn unsubscribe_account(
            &self,
            _: &MemberId,
            _: &[NostrSubscription],
        ) -> Result<(), TransportAdapterError> {
            Ok(())
        }

        async fn publish_event(
            &self,
            _: &[TransportEndpoint],
            _: &NostrTransportEvent,
            _: usize,
        ) -> Result<NostrPublishOutcome, TransportAdapterError> {
            unreachable!("replay coverage does not publish")
        }
    }

    /// A relay that owes a REQ (#1951) replays exactly like one that queued it
    /// while disconnected: `Awaiting` until its endpoint deadline, dormant
    /// after it, waiting again from its first connection, then complete at
    /// its EOSE. Owing adds no replay-coverage state.
    #[tokio::test(start_paused = true)]
    async fn owed_relay_replays_like_a_queued_one() {
        let owed = TransportEndpoint("wss://owed.example".to_owned());
        let queued = TransportEndpoint("wss://queued.example".to_owned());
        let inbox = TransportEndpoint("wss://inbox.example".to_owned());
        let adapter = NostrTransportAdapter::new(Arc::new(OwingRelayClient {
            owing: owed.clone(),
        }));
        let account = MemberId::new(vec![0xA1; 32]);
        let group = |index: u8, endpoint: &TransportEndpoint| TransportGroupSubscription {
            group_id: GroupId::new(vec![index; 16]),
            transport_group_id: vec![index; 32],
            endpoints: vec![endpoint.clone()],
            retained_since: None,
        };
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account.clone(),
                inbox_endpoints: vec![inbox.clone()],
                group_subscriptions: vec![group(1, &owed), group(2, &queued)],
                since: Some(Timestamp(100)),
            })
            .await
            .unwrap();
        let metrics = adapter.metrics().await;
        assert_eq!(
            (metrics.activations_degraded, metrics.activations_full),
            (1, 0)
        );
        let batch_on = |endpoint: &TransportEndpoint| {
            let adapter = adapter.clone();
            let endpoint = endpoint.clone();
            let account = account.clone();
            async move {
                adapter.state.read().await.accounts[&account]
                    .batches
                    .iter()
                    .find(|batch| batch.endpoints() == [endpoint.clone()])
                    .map(NostrSubscription::subscription_id)
                    .expect("one batch per relay")
            }
        };
        let sources = [
            (batch_on(&owed).await, owed.clone()),
            (batch_on(&queued).await, queued.clone()),
        ];
        let views = || async {
            let state = adapter.state.read().await;
            let coverage = &state.account_replay_coverage[&account];
            sources
                .iter()
                .map(|(id, endpoint)| {
                    let relay = state.relay_index.existing_index_for(endpoint).unwrap();
                    let phases = coverage
                        .groups
                        .values()
                        .flat_map(|group| &group.streams)
                        .filter(|(owner, _)| *owner.request == **id && owner.relay == relay)
                        .map(|(_, stream)| stream.phase)
                        .collect::<Vec<_>>();
                    (
                        coverage.subscriptions[id][&relay],
                        coverage.endpoint_deadlines[id][&relay].deadline,
                        phases,
                    )
                })
                .collect::<Vec<_>>()
        };
        let assert_alike =
            |views: Vec<(RelayReplay, Option<tokio::time::Instant>, Vec<_>)>,
             expected: (RelayReplay, Option<tokio::time::Instant>, Vec<_>)| {
                assert_eq!(
                    views[0], views[1],
                    "an owed relay replays like a queued one"
                );
                assert_eq!(views[0], expected);
            };

        let staged = tokio::time::Instant::now();
        assert_alike(
            views().await,
            (
                RelayReplay::Awaiting,
                Some(staged + REPLAY_PAGE_LIMITS.max_duration),
                vec![ReplayAdmission::Waiting],
            ),
        );

        tokio::time::advance(REPLAY_PAGE_LIMITS.max_duration).await;
        adapter
            .state
            .write()
            .await
            .account_replay_coverage
            .get_mut(&account)
            .unwrap()
            .expire_replay(tokio::time::Instant::now());
        assert_alike(
            views().await,
            (RelayReplay::Awaiting, None, vec![ReplayAdmission::Dormant]),
        );

        let connected = tokio::time::Instant::now();
        for (_, endpoint) in &sources {
            assert!(
                adapter
                    .observe_replay_epoch(
                        Some(&account),
                        endpoint,
                        [1, 1],
                        ReplayRestart::Connection
                    )
                    .await
            );
        }
        assert_alike(
            views().await,
            (
                RelayReplay::Awaiting,
                Some(connected + REPLAY_PAGE_LIMITS.max_duration),
                vec![ReplayAdmission::Waiting],
            ),
        );

        let inbox_id = adapter
            .state
            .read()
            .await
            .account_subscription_ids(&account)[0]
            .clone();
        adapter.handle_relay_eose(inbox, inbox_id).await;
        for (id, endpoint) in &sources {
            adapter
                .handle_relay_eose(endpoint.clone(), id.clone())
                .await;
        }
        let views = views().await;
        assert_eq!(
            views[0], views[1],
            "an owed relay replays like a queued one"
        );
        assert_eq!(views[0].0, RelayReplay::Eose);
        assert!(adapter.account_subscription_eose(&account).await.complete());
    }
}
