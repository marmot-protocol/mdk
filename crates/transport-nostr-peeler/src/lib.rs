//! Nostr transport peeler for Marmot CGKA messages.
//!
//! This crate owns the transport-edge conversion between Nostr-shaped events
//! and [`cgka_traits::transport::TransportMessage`]. It does not connect to
//! relays, manage subscriptions, pick relays, or own application sessions.
//! Real Nostr relay publication belongs in a transport adapter above this
//! crate.
//!
//! Per `spec/transports/nostr.md`, each kind-445 group event is signed by a
//! fresh ephemeral Nostr key generated for that event (never the sender's
//! account identity, never reused), and its `content` is
//! `base64(nonce || ciphertext)` of a single ChaCha20-Poly1305 sealing of the
//! MLS message bytes under the empty AAD.

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

/// Group-context snapshot key for `MLS-Exporter("marmot", "group-event", 32)`.
pub const DEFAULT_EXPORTER_LABEL: &str = "marmot/group-event";

/// ChaCha20Poly1305 key length for the outer kind-445 group wrap.
pub const NOSTR_GROUP_KEY_LEN: usize = 32;

/// Minimum decoded length of a kind-445 `content` value: a 12-byte nonce plus
/// the 16-byte ChaCha20-Poly1305 authentication tag (`spec/transports/nostr.md`).
pub const NOSTR_GROUP_CONTENT_MIN_LEN: usize = 12 + 16;

pub(crate) const GROUP_TAG: &str = "h";
pub(crate) const RECIPIENT_TAG: &str = "p";
