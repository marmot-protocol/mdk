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
mod nip59;
mod peeler;
mod signer;

pub use error::NostrPeelerError;
pub use event::NostrTransportEvent;
pub use nip59::gift_wrap_rumor;
pub use peeler::{NostrMlsPeeler, WelcomePeelProvenance};
pub use signer::{MarmotNostrSigner, MarmotSignerError, SdkSigner, SignerFuture};

/// Nostr kind used by Marmot group messages.
pub const KIND_MARMOT_GROUP_MESSAGE: u64 = 445;

/// Nostr kind used by NIP-59 gift wraps.
pub const KIND_NIP59_GIFT_WRAP: u64 = 1059;

/// Marmot welcome rumor kind inside the NIP-59 seal.
pub const KIND_MARMOT_WELCOME_RUMOR: u16 = 444;

/// MDK-private recovery control rumor kind, carried only inside NIP-59.
/// This regular kind is proposed in marmot-protocol/marmot#451, NOT a
/// Marmot-standard allocation. Only the authenticated inner rumor carries
/// the singleton version tag; no recovery marker is exposed on the outer wrap.
pub const KIND_MDK_GROUP_RECOVERY_RUMOR: u16 = 1159;

/// Strict singleton authenticated inner version tag for private recovery.
pub const GROUP_RECOVERY_PROTOCOL_TAG: &str = "mdk_group_recovery";
/// Supported MDK-private recovery wire protocol version.
pub const GROUP_RECOVERY_PROTOCOL_VERSION: &str = "1";

/// Maximum recovery carrier bytes, enforced after verified inner-kind dispatch.
/// A hidden inner type cannot select a predecrypt limit; ordinary Welcome
/// acceptance is unchanged, and generic transport resource limits still apply.
pub const MAX_GROUP_RECOVERY_EVENT_BYTES: usize = 512 * 1024;

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

/// Serialized JSON length of a kind-445 event with empty `content`, counting
/// `created_at` and the optional `expiration` tag at the full width of a `u64`:
/// the 64-hex `id`, `pubkey` and `h` value, the 128-hex `sig`, and the member
/// names and punctuation.
const GROUP_EVENT_JSON_OVERHEAD: usize = 464;

/// Upper bound on the serialized JSON length of the kind-445 event that wraps
/// an `mls_message_len`-byte MLS message, the size relays measure an event by.
/// Exact except for the decimal width of `created_at` and `expiration`.
pub fn group_event_json_len_bound(mls_message_len: usize) -> usize {
    let sealed = NOSTR_GROUP_CONTENT_MIN_LEN + mls_message_len;
    GROUP_EVENT_JSON_OVERHEAD + sealed.div_ceil(3) * 4
}

pub(crate) const GROUP_TAG: &str = "h";
pub(crate) const EXPIRATION_TAG: &str = "expiration";
pub(crate) const RECIPIENT_TAG: &str = "p";
