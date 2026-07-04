//! Transport adapter boundary.
//!
//! A transport adapter owns network reachability and routing: account
//! activation, relay subscription state, publish quorum policy, and delivery
//! fanout. It must not decide CGKA convergence or inspect peeled MLS state.
//!
//! The engine receives [`crate::transport::TransportMessage`] values from this
//! boundary and remains the source of truth for commit ordering, branch
//! selection, and application-message validity.

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
