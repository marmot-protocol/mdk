//! Nostr transport peeler for Marmot CGKA messages.
//!
//! This crate owns the transport-edge conversion between Nostr-shaped events
//! and [`cgka_traits::transport::TransportMessage`]. It does not connect to
//! relays, manage subscriptions, pick relays, or own application sessions.
//! Real Nostr signing and relay publication belong in a transport adapter
//! above this crate.

mod error;
mod event;
mod peeler;

pub use error::NostrPeelerError;
pub use event::NostrTransportEvent;
pub use peeler::NostrMlsPeeler;

/// Nostr kind used by Marmot group messages.
pub const KIND_MARMOT_GROUP_MESSAGE: u64 = 445;

/// Nostr kind used by NIP-59 gift wraps.
pub const KIND_NIP59_GIFT_WRAP: u64 = 1059;

/// Marmot welcome rumor kind inside the NIP-59 seal.
pub const KIND_MARMOT_WELCOME_RUMOR: u16 = 444;

/// Source label carried by [`cgka_traits::transport::TransportMessage`] values
/// produced here.
pub const NOSTR_SOURCE: &str = "nostr";

/// Current engine exporter label. The future spec label may move to an MLS
/// application component; this default matches the engine as implemented now.
pub const DEFAULT_EXPORTER_LABEL: &str = "marmot/engine/v1";

/// ChaCha20Poly1305 key length for the outer kind-445 group wrap.
pub const NOSTR_GROUP_KEY_LEN: usize = 32;

pub(crate) const GROUP_TAG: &str = "h";
pub(crate) const RECIPIENT_TAG: &str = "p";
