//! Cross-transport value types shared by the engine, peeler, and transport
//! adapters.

use crate::types::{MemberId, MessageId};
use serde::{Deserialize, Serialize};

/// Unix-seconds timestamp. Opaque — used for ordering hints only; the engine
/// never trusts it for correctness (coordinator dedup is by `MessageId`).
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Timestamp(pub u64);

/// Source label for a [`TransportMessage`]. Typically the transport adapter's
/// canonical name (e.g. `"nostr"`). Opaque string so new transports plug in
/// without type churn.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportSource(pub String);

/// Raw transport-layer message as it enters or leaves the engine. Payload is
/// still transport-wrapped; the peeler produces the decrypted
/// [`crate::ingest::PeeledMessage`].
///
/// The `envelope` field is the routing discriminator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportMessage {
    pub id: MessageId,
    pub payload: Vec<u8>,
    pub timestamp: Timestamp,
    pub causal_deps: Vec<MessageId>,
    pub source: TransportSource,
    pub envelope: TransportEnvelope,
}

/// Which kind of envelope this transport message carries. The coordinator
/// routes on this **before** peeling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportEnvelope {
    /// Group message. `transport_group_id` is the transport-visible group id
    /// (e.g. the Nostr `h`-tag value, which equals the `nostr_group_id` in
    /// `NostrTransportData`).
    GroupMessage { transport_group_id: Vec<u8> },
    /// Welcome addressed to a specific member. `recipient` is matched against
    /// `CgkaEngine::self_id`.
    Welcome { recipient: MemberId },
}

/// Opaque ciphertext + authenticated-data pair ready to be wrapped by a
/// [`crate::peeler::TransportPeeler`] into a [`TransportMessage`].
///
/// The engine produces these; the peeler wraps them in whatever outer layer
/// the transport requires (Nostr kind-445, FIPS mesh frame, …).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
}
