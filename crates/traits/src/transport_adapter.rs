//! Transport adapter boundary.
//!
//! A transport adapter owns network reachability and routing: account
//! activation, relay subscription state, publish quorum policy, and delivery
//! fanout. It must not decide CGKA convergence or inspect peeled MLS state.
//!
//! The engine receives [`crate::transport::TransportMessage`] values from this
//! boundary and remains the source of truth for commit ordering, branch
//! selection, and application-message validity.

use crate::engine_state::PendingStateRef;
use crate::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use crate::types::{GroupId, MemberId, MessageId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Transport-specific endpoint label.
///
/// For Nostr this is a relay URL. Other transports may use a mesh peer id,
/// mailbox address, or service endpoint string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TransportEndpoint(pub String);

impl TransportEndpoint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TransportEndpoint {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for TransportEndpoint {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for TransportEndpoint {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Display for TransportEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One group subscription from one local account's point of view.
///
/// `group_id` is the engine's MLS group id. `transport_group_id` is the
/// transport-visible routing id, such as a Nostr `h` tag. The 0.1 engine still
/// treats those as equal, but adapters should carry both so the later MIP-01
/// transport-data split has somewhere clean to land.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportGroupSubscription {
    pub group_id: GroupId,
    pub transport_group_id: Vec<u8>,
    pub endpoints: Vec<TransportEndpoint>,
}

/// Account-level subscription activation request.
///
/// This is deliberately signer-free. Concrete adapters obtain their signing /
/// decryption handles from the account-device layer that constructed them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportAccountActivation {
    pub account_id: MemberId,
    pub inbox_endpoints: Vec<TransportEndpoint>,
    pub group_subscriptions: Vec<TransportGroupSubscription>,
    pub since: Option<Timestamp>,
}

/// Group-only subscription refresh for an already-active account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportGroupSync {
    pub account_id: MemberId,
    pub group_subscriptions: Vec<TransportGroupSubscription>,
    pub since: Option<Timestamp>,
}

/// Publish target for an already-wrapped transport message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportPublishTarget {
    /// Publish a group message to the group's transport endpoint set.
    Group {
        group_id: GroupId,
        transport_group_id: Vec<u8>,
        endpoints: Vec<TransportEndpoint>,
    },
    /// Publish a welcome/giftwrap-style message to a recipient inbox.
    Inbox {
        recipient: MemberId,
        endpoints: Vec<TransportEndpoint>,
    },
}

impl TransportPublishTarget {
    pub fn endpoints(&self) -> &[TransportEndpoint] {
        match self {
            Self::Group { endpoints, .. } | Self::Inbox { endpoints, .. } => endpoints,
        }
    }

    fn kind_label(&self) -> &'static str {
        match self {
            Self::Group { .. } => "group",
            Self::Inbox { .. } => "inbox",
        }
    }
}

/// Publish request emitted by the application/coordinator after the peeler has
/// wrapped engine output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPublishRequest {
    pub account_id: MemberId,
    pub message: TransportMessage,
    pub target: TransportPublishTarget,
    /// Minimum endpoint acknowledgements the adapter should try to obtain
    /// before reporting success. A value of `0` means best effort: the adapter
    /// does not wait for a specific ack count, but a publish that no endpoint
    /// accepted still fails — [`TransportPublishReport::met_required_acks`]
    /// always requires at least one acceptance.
    pub required_acks: usize,
}

impl TransportPublishRequest {
    /// Verify that the publish target matches the message's routing envelope.
    ///
    /// This catches coordinator bugs before an adapter sends a welcome to group
    /// endpoints or a group message to an inbox endpoint set.
    pub fn validate_envelope_matches_target(&self) -> Result<(), TransportAdapterError> {
        match (&self.message.envelope, &self.target) {
            (
                TransportEnvelope::GroupMessage {
                    transport_group_id: msg_group_id,
                },
                TransportPublishTarget::Group {
                    transport_group_id: target_group_id,
                    ..
                },
            ) if msg_group_id == target_group_id => Ok(()),
            (
                TransportEnvelope::Welcome {
                    recipient: msg_recipient,
                },
                TransportPublishTarget::Inbox {
                    recipient: target_recipient,
                    ..
                },
            ) if msg_recipient == target_recipient => Ok(()),
            _ => Err(TransportAdapterError::PublishTargetMismatch {
                envelope: envelope_label(&self.message.envelope).into(),
                target: self.target.kind_label().into(),
            }),
        }
    }
}

/// Durable first-attempt state for one endpoint in a frozen publish fanout.
///
/// `Attempting` is written before the external send. A process that restarts
/// with an `Attempting` target treats it as outstanding and safely repeats the
/// same already-signed event bytes. Terminal callbacks are idempotent: once a
/// target is `Accepted` or `Failed`, later duplicate or contradictory results
/// do not change it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FanoutTargetStatus {
    NotAttempted,
    Attempting,
    Accepted,
    Failed,
}

impl FanoutTargetStatus {
    pub fn is_outstanding(self) -> bool {
        matches!(self, Self::NotAttempted | Self::Attempting)
    }

    pub fn is_terminal(self) -> bool {
        !self.is_outstanding()
    }
}

/// MLS half of a durable publish obligation.
///
/// Standalone application messages/proposals use `NotApplicable`. A group
/// evolution retains its opaque pending reference until the first endpoint
/// accepts, then transitions once to `Confirmed`; an all-failed first-attempt
/// fanout transitions once to `RolledBack`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "pending")]
pub enum FanoutMlsState {
    NotApplicable,
    Pending(PendingStateRef),
    Confirmed,
    RolledBack,
}

/// One durable transport fanout frozen before its first external side effect.
///
/// The request owns the exact serialized transport message and original target
/// set. `target_statuses` is positionally aligned with
/// `request.target.endpoints()`; construction is centralized in [`stage`] so a
/// valid record can never have a different status count.
///
/// [`stage`]: Self::stage
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundFanout {
    request: TransportPublishRequest,
    group_id: Option<GroupId>,
    target_statuses: Vec<FanoutTargetStatus>,
    mls_state: FanoutMlsState,
    created_at_ms: u64,
}

impl OutboundFanout {
    pub fn stage(
        request: TransportPublishRequest,
        pending: Option<PendingStateRef>,
        pending_group_id: Option<GroupId>,
        created_at_ms: u64,
    ) -> Result<Self, TransportAdapterError> {
        request.validate_envelope_matches_target()?;
        let target_group_id = match &request.target {
            TransportPublishTarget::Group { group_id, .. } => Some(group_id.clone()),
            TransportPublishTarget::Inbox { .. } => None,
        };
        if let (Some(target_group_id), Some(pending_group_id)) =
            (&target_group_id, &pending_group_id)
            && target_group_id != pending_group_id
        {
            return Err(TransportAdapterError::PublishTargetMismatch {
                envelope: "pending_group".into(),
                target: "group".into(),
            });
        }
        let target_count = request.target.endpoints().len();
        Ok(Self {
            request,
            group_id: target_group_id.or(pending_group_id),
            target_statuses: vec![FanoutTargetStatus::NotAttempted; target_count],
            mls_state: pending.map_or(FanoutMlsState::NotApplicable, FanoutMlsState::Pending),
            created_at_ms,
        })
    }

    pub fn request(&self) -> &TransportPublishRequest {
        &self.request
    }

    pub fn message_id(&self) -> &MessageId {
        &self.request.message.id
    }

    pub fn group_id(&self) -> Option<&GroupId> {
        self.group_id.as_ref()
    }

    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    pub fn target_statuses(&self) -> &[FanoutTargetStatus] {
        &self.target_statuses
    }

    pub fn target_status(&self, index: usize) -> Option<FanoutTargetStatus> {
        self.target_statuses.get(index).copied()
    }

    pub fn pending_ref(&self) -> Option<PendingStateRef> {
        match self.mls_state {
            FanoutMlsState::Pending(pending) => Some(pending),
            FanoutMlsState::NotApplicable
            | FanoutMlsState::Confirmed
            | FanoutMlsState::RolledBack => None,
        }
    }

    pub fn mls_state(&self) -> FanoutMlsState {
        self.mls_state
    }

    pub fn outstanding_target_indexes(&self) -> Vec<usize> {
        self.target_statuses
            .iter()
            .enumerate()
            .filter_map(|(index, status)| status.is_outstanding().then_some(index))
            .collect()
    }

    /// Persist the send-before-side-effect edge for one target.
    ///
    /// Returns `true` only for the first `NotAttempted -> Attempting`
    /// transition. Re-marking an `Attempting` target after restart is harmless;
    /// terminal targets remain unchanged.
    pub fn mark_attempt_started(&mut self, index: usize) -> Result<bool, TransportAdapterError> {
        let status = self.target_status_mut(index)?;
        match status {
            FanoutTargetStatus::NotAttempted => {
                *status = FanoutTargetStatus::Attempting;
                Ok(true)
            }
            FanoutTargetStatus::Attempting
            | FanoutTargetStatus::Accepted
            | FanoutTargetStatus::Failed => Ok(false),
        }
    }

    pub fn mark_target_accepted(&mut self, index: usize) -> Result<bool, TransportAdapterError> {
        self.mark_target_terminal(index, FanoutTargetStatus::Accepted)
    }

    pub fn mark_target_failed(&mut self, index: usize) -> Result<bool, TransportAdapterError> {
        self.mark_target_terminal(index, FanoutTargetStatus::Failed)
    }

    pub fn mark_mls_confirmed(&mut self) -> Result<bool, TransportAdapterError> {
        match self.mls_state {
            FanoutMlsState::Pending(_) => {
                self.mls_state = FanoutMlsState::Confirmed;
                Ok(true)
            }
            FanoutMlsState::Confirmed => Ok(false),
            FanoutMlsState::NotApplicable | FanoutMlsState::RolledBack => Err(
                TransportAdapterError::Other("fanout has no confirmable pending MLS state".into()),
            ),
        }
    }

    pub fn mark_mls_rolled_back(&mut self) -> Result<bool, TransportAdapterError> {
        match self.mls_state {
            FanoutMlsState::Pending(_) => {
                self.mls_state = FanoutMlsState::RolledBack;
                Ok(true)
            }
            FanoutMlsState::RolledBack => Ok(false),
            FanoutMlsState::NotApplicable | FanoutMlsState::Confirmed => Err(
                TransportAdapterError::Other("fanout has no rollbackable pending MLS state".into()),
            ),
        }
    }

    pub fn outcome(&self) -> OutboundFanoutOutcome {
        let accepted_targets = self
            .target_statuses
            .iter()
            .filter(|status| **status == FanoutTargetStatus::Accepted)
            .count();
        let failed_targets = self
            .target_statuses
            .iter()
            .filter(|status| **status == FanoutTargetStatus::Failed)
            .count();
        let outstanding_targets = self
            .target_statuses
            .iter()
            .filter(|status| status.is_outstanding())
            .count();
        OutboundFanoutOutcome {
            message_id: self.request.message.id.clone(),
            mls_confirmation_required: accepted_targets > 0
                && matches!(self.mls_state, FanoutMlsState::Pending(_)),
            mls_confirmed: self.mls_state == FanoutMlsState::Confirmed,
            fanout_complete: outstanding_targets == 0,
            accepted_targets,
            failed_targets,
            outstanding_targets,
        }
    }

    /// Verify that `self` is a monotonic update of an already-durable fanout.
    ///
    /// The signed bytes, message id, frozen target set, policy and creation
    /// time are immutable. Per-target and MLS states may only advance. Storage
    /// implementations use this guard before replacing the serialized record,
    /// so a stale callback or regenerated request cannot reopen terminal state
    /// or silently substitute a new route.
    pub fn validate_successor_of(&self, previous: &Self) -> Result<(), TransportAdapterError> {
        let immutable_matches = self.request == previous.request
            && self.group_id == previous.group_id
            && self.created_at_ms == previous.created_at_ms
            && self.target_statuses.len() == previous.target_statuses.len();
        let targets_advance = immutable_matches
            && self
                .target_statuses
                .iter()
                .zip(&previous.target_statuses)
                .all(|(next, prior)| target_status_advances(*prior, *next));
        let mls_advances = mls_state_advances(previous.mls_state, self.mls_state);
        if targets_advance && mls_advances {
            Ok(())
        } else {
            Err(TransportAdapterError::Other(
                "outbound fanout update is not monotonic".into(),
            ))
        }
    }

    fn target_status_mut(
        &mut self,
        index: usize,
    ) -> Result<&mut FanoutTargetStatus, TransportAdapterError> {
        self.target_statuses.get_mut(index).ok_or_else(|| {
            TransportAdapterError::Other("fanout target index is out of bounds".into())
        })
    }

    fn mark_target_terminal(
        &mut self,
        index: usize,
        terminal: FanoutTargetStatus,
    ) -> Result<bool, TransportAdapterError> {
        debug_assert!(terminal.is_terminal());
        let status = self.target_status_mut(index)?;
        if status.is_terminal() {
            return Ok(false);
        }
        *status = terminal;
        Ok(true)
    }
}

fn target_status_advances(prior: FanoutTargetStatus, next: FanoutTargetStatus) -> bool {
    prior == next
        || matches!(
            (prior, next),
            (
                FanoutTargetStatus::NotAttempted,
                FanoutTargetStatus::Attempting
            ) | (
                FanoutTargetStatus::Attempting,
                FanoutTargetStatus::Accepted | FanoutTargetStatus::Failed
            )
        )
}

fn mls_state_advances(prior: FanoutMlsState, next: FanoutMlsState) -> bool {
    prior == next
        || matches!(
            (prior, next),
            (
                FanoutMlsState::Pending(_),
                FanoutMlsState::Confirmed | FanoutMlsState::RolledBack
            )
        )
}

/// Privacy-safe caller/audit summary for one frozen fanout.
///
/// Counts and lifecycle booleans are exposed separately; relay endpoints are
/// deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundFanoutOutcome {
    pub message_id: MessageId,
    pub mls_confirmation_required: bool,
    pub mls_confirmed: bool,
    pub fanout_complete: bool,
    pub accepted_targets: usize,
    pub failed_targets: usize,
    pub outstanding_targets: usize,
}

/// Successful endpoint-level publish acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportEndpointReceipt {
    pub endpoint: TransportEndpoint,
    pub accepted_at: Option<Timestamp>,
}

/// Endpoint-level publish failure. The overall publish may still succeed if
/// enough other endpoints acknowledge the message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportEndpointFailure {
    pub endpoint: TransportEndpoint,
    pub reason: String,
}

/// Aggregate publish result from a transport adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPublishReport {
    pub message_id: MessageId,
    pub accepted: Vec<TransportEndpointReceipt>,
    pub failed: Vec<TransportEndpointFailure>,
    /// Threshold copied from the request; `0` relaxes the threshold but never
    /// the at-least-one-acceptance requirement (see [`met_required_acks`]).
    ///
    /// [`met_required_acks`]: Self::met_required_acks
    pub required_acks: usize,
}

impl TransportPublishReport {
    pub fn accepted_count(&self) -> usize {
        self.accepted.len()
    }

    /// Whether the publish reached enough endpoints to count as published.
    ///
    /// At least one acceptance is always required: a "best effort"
    /// (`required_acks == 0`) publish that no endpoint accepted reached no
    /// one, and confirming it would advance local state (epoch, membership)
    /// past a message that was never exposed.
    pub fn met_required_acks(&self) -> bool {
        self.accepted_count() >= self.required_acks.max(1)
    }
}

/// Which transport-control plane delivered a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportDeliveryPlane {
    Discovery,
    AccountInbox,
    Group,
    Ephemeral,
}

/// Transport wire identifiers for the event that carried a delivery, surfaced
/// to forensic auditing. Diagnostic only, never consensus input. Optional and
/// transport-generic: each field carries the wire-layer event metadata an
/// adapter has (e.g. for Nostr: the event id, kind, ephemeral pubkey, and the
/// `h`-tag transport group id). Never carries signatures, ciphertext, or keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportWireMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_kind: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gift_wrap_event_id: Option<String>,
}

/// Adapter-side delivery metadata. This is diagnostic/routing context, never
/// consensus input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportDeliverySource {
    pub transport: TransportSource,
    pub plane: TransportDeliveryPlane,
    pub endpoint: Option<TransportEndpoint>,
    pub subscription_id: Option<String>,
    /// Wire identifiers for the carrying event, for forensic audit only.
    /// `None` for delivery paths with no inbound wire event (e.g. local
    /// publish echo).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire: Option<TransportWireMetadata>,
}

/// Account-scoped message delivered by a transport adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportDelivery {
    pub account_id: MemberId,
    /// Local routing hint from the adapter's subscription registry. The engine
    /// still validates through the message envelope and peeler.
    pub group_id_hint: Option<GroupId>,
    pub message: TransportMessage,
    /// Local wall-clock observation time assigned by the receiving adapter.
    /// This is distinct from any publisher-controlled transport timestamp.
    pub received_at: Timestamp,
    pub source: TransportDeliverySource,
}

/// Errors returned by transport adapters.
#[derive(Debug, thiserror::Error)]
pub enum TransportAdapterError {
    #[error("account not active")]
    AccountNotActive(MemberId),

    #[error("publish target does not match message envelope: envelope={envelope}, target={target}")]
    PublishTargetMismatch { envelope: String, target: String },

    #[error("subscription failed: {0}")]
    Subscription(String),

    #[error("publish failed: {0}")]
    Publish(String),

    #[error("transport backend failure: {0}")]
    Backend(String),

    #[error("other transport adapter error: {0}")]
    Other(String),
}

/// Account-aware network adapter that moves wrapped transport messages.
#[async_trait]
pub trait TransportAdapter: Send + Sync {
    /// Activate inbox and group subscriptions for an account.
    async fn activate_account(
        &self,
        activation: TransportAccountActivation,
    ) -> Result<(), TransportAdapterError>;

    /// Refresh only the group subscription plane for an active account.
    ///
    /// Subscribe failures for added groups fail fast and leave adapter state
    /// untouched. Unsubscribe failures for removed groups are absorbed: the
    /// removal takes effect in the adapter's routing state immediately, the
    /// relay-side unsubscribe is retried on subsequent syncs, and such
    /// failures never fail the call.
    async fn sync_account_groups(
        &self,
        sync: TransportGroupSync,
    ) -> Result<(), TransportAdapterError>;

    /// Deactivate every subscription owned by an account.
    async fn deactivate_account(&self, account_id: &MemberId) -> Result<(), TransportAdapterError>;

    /// Publish a wrapped message. Implementations should validate the request
    /// before sending and return endpoint-level receipts when available.
    async fn publish(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError>;

    /// Receive the next account-scoped delivery. Returning `Ok(None)` means
    /// the adapter has shut down and will not produce more deliveries.
    async fn receive(&self) -> Result<Option<TransportDelivery>, TransportAdapterError>;
}

fn envelope_label(envelope: &TransportEnvelope) -> &'static str {
    match envelope {
        TransportEnvelope::GroupMessage { .. } => "group",
        TransportEnvelope::Welcome { .. } => "welcome",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fanout_request() -> TransportPublishRequest {
        TransportPublishRequest {
            account_id: MemberId::new(vec![0xA1; 32]),
            message: TransportMessage {
                id: MessageId::new(vec![0xB2; 32]),
                payload: b"exact signed event bytes".to_vec(),
                timestamp: Timestamp(1_700_000_000),
                causal_deps: Vec::new(),
                source: TransportSource("marmot.transport.nostr".into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: vec![0xC3; 32],
                },
            },
            target: TransportPublishTarget::Group {
                group_id: GroupId::new(vec![0xD4; 16]),
                transport_group_id: vec![0xC3; 32],
                endpoints: vec![
                    TransportEndpoint("wss://one.example".into()),
                    TransportEndpoint("wss://two.example".into()),
                    TransportEndpoint("wss://three.example".into()),
                ],
            },
            required_acks: 2,
        }
    }

    #[test]
    fn frozen_fanout_first_ack_releases_mls_before_fanout_completes() {
        let pending = crate::engine_state::PendingStateRef::new(9);
        let mut fanout = OutboundFanout::stage(
            fanout_request(),
            Some(pending),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();

        fanout.mark_attempt_started(1).unwrap();
        assert!(fanout.mark_target_accepted(1).unwrap());

        let outcome = fanout.outcome();
        assert!(outcome.mls_confirmation_required);
        assert!(!outcome.mls_confirmed);
        assert!(!outcome.fanout_complete);
        assert_eq!(outcome.accepted_targets, 1);
        assert_eq!(outcome.outstanding_targets, 2);
        assert_eq!(fanout.pending_ref(), Some(pending));
    }

    #[test]
    fn frozen_fanout_duplicate_and_late_callbacks_are_idempotent() {
        let pending = crate::engine_state::PendingStateRef::new(9);
        let mut fanout = OutboundFanout::stage(
            fanout_request(),
            Some(pending),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();

        fanout.mark_attempt_started(0).unwrap();
        assert!(fanout.mark_target_accepted(0).unwrap());
        fanout.mark_mls_confirmed().unwrap();

        assert!(!fanout.mark_target_accepted(0).unwrap());
        assert!(!fanout.mark_target_failed(0).unwrap());
        assert!(fanout.outcome().mls_confirmed);
        assert_eq!(fanout.outcome().accepted_targets, 1);
    }

    #[test]
    fn frozen_fanout_all_fail_is_complete_without_mls_confirmation() {
        let pending = crate::engine_state::PendingStateRef::new(9);
        let mut fanout = OutboundFanout::stage(
            fanout_request(),
            Some(pending),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();

        for index in 0..3 {
            fanout.mark_attempt_started(index).unwrap();
            assert!(fanout.mark_target_failed(index).unwrap());
        }

        let outcome = fanout.outcome();
        assert!(outcome.fanout_complete);
        assert!(!outcome.mls_confirmation_required);
        assert!(!outcome.mls_confirmed);
        assert_eq!(outcome.failed_targets, 3);
        assert_eq!(outcome.outstanding_targets, 0);
    }

    #[test]
    fn frozen_fanout_round_trip_preserves_bytes_id_and_original_targets() {
        let request = fanout_request();
        let original_bytes = request.message.payload.clone();
        let original_id = request.message.id.clone();
        let original_targets = request.target.endpoints().to_vec();
        let fanout = OutboundFanout::stage(
            request,
            Some(crate::engine_state::PendingStateRef::new(9)),
            Some(GroupId::new(vec![0xD4; 16])),
            55,
        )
        .unwrap();

        let encoded = serde_json::to_vec(&fanout).unwrap();
        let restored: OutboundFanout = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(restored.request().message.payload, original_bytes);
        assert_eq!(restored.request().message.id, original_id);
        assert_eq!(restored.request().target.endpoints(), original_targets);
        assert_eq!(restored.outstanding_target_indexes(), vec![0, 1, 2]);
    }

    fn report(accepted: usize, failed: usize, required_acks: usize) -> TransportPublishReport {
        TransportPublishReport {
            message_id: MessageId::new(*b"m1"),
            accepted: (0..accepted)
                .map(|i| TransportEndpointReceipt {
                    endpoint: TransportEndpoint(format!("wss://accepted-{i}.example")),
                    accepted_at: None,
                })
                .collect(),
            failed: (0..failed)
                .map(|i| TransportEndpointFailure {
                    endpoint: TransportEndpoint(format!("wss://failed-{i}.example")),
                    reason: "unreachable".into(),
                })
                .collect(),
            required_acks,
        }
    }

    #[test]
    fn met_required_acks_zero_required_fails_with_zero_accepted() {
        assert!(!report(0, 0, 0).met_required_acks());
        assert!(!report(0, 2, 0).met_required_acks());
    }

    #[test]
    fn met_required_acks_zero_required_passes_with_one_accepted() {
        assert!(report(1, 0, 0).met_required_acks());
        assert!(report(1, 3, 0).met_required_acks());
    }

    #[test]
    fn met_required_acks_nonzero_threshold_unchanged() {
        assert!(!report(0, 0, 1).met_required_acks());
        assert!(report(1, 0, 1).met_required_acks());
        assert!(!report(1, 1, 2).met_required_acks());
        assert!(report(2, 0, 2).met_required_acks());
    }
}
