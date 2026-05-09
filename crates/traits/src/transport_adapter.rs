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
    /// before reporting success. A value of `0` means best effort.
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
    pub required_acks: usize,
}

impl TransportPublishReport {
    pub fn accepted_count(&self) -> usize {
        self.accepted.len()
    }

    pub fn met_required_acks(&self) -> bool {
        self.accepted_count() >= self.required_acks
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

/// Adapter-side delivery metadata. This is diagnostic/routing context, never
/// consensus input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportDeliverySource {
    pub transport: TransportSource,
    pub plane: TransportDeliveryPlane,
    pub endpoint: Option<TransportEndpoint>,
    pub subscription_id: Option<String>,
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
    #[error("account not active: {0}")]
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
