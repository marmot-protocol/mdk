//! MLS wire-format policy for Marmot groups.
//!
//! ## Revisit Before External Rollout
//!
//! This engine uses `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` for MLS handshake
//! messages because:
//!
//! 1. **MIP-03 requires SelfRemove proposals be PublicMessage.** OpenMLS 0.8
//!    only offers `AlwaysPlaintext` or `AlwaysCiphertext` outgoing — there is
//!    no mixed-outgoing option. `leave_group_via_self_remove` refuses
//!    `AlwaysCiphertext`.
//! 2. **The outer transport layer already provides confidentiality.** Nostr
//!    kind-445 wraps the PublicMessage in ChaCha20Poly1305 keyed by the
//!    group's MLS exporter secret, so relays see ciphertext.
//!
//! Three alternative paths remain available:
//!
//! - **A.** Accept pure-plaintext MLS handshake messages (current choice).
//!   Architecturally fine if the outer transport wrap is the trust boundary.
//! - **B.** Patch OpenMLS upstream to allow mixed outgoing. Narrow change.
//! - **C.** Replace MIP-03 SelfRemove with a Marmot-custom proposal type
//!   whose wire-format constraints we control. See `custom_extensions.md`.
//!
//! **Trigger to revisit:** first external consumer asking for pure-ciphertext
//! MLS, OR OpenMLS shipping mixed-outgoing support.
//!
//! OpenMLS application messages are always encrypted `PrivateMessage`s
//! regardless of this handshake policy. Their within-epoch delivery window is
//! therefore governed separately by the sender-ratchet configuration below.
//!
//! ## Grep marker
//!
//! The `WIRE_FORMAT_POLICY_REVIEW_REQUIRED` constant below is grep-findable
//! so the decision surfaces on every audit pass.

use openmls::group::MlsGroupJoinConfig;
pub use openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
use openmls::prelude::SenderRatchetConfiguration;

/// Default number of past MLS epochs retained for delayed application
/// messages. This is intentionally small because it trades away some forward
/// secrecy for delivery robustness.
///
/// Pinned to the adopted convergence-policy v1 app-message window so MLS
/// decryptability and witness/delivery horizons cannot diverge.
pub const DEFAULT_MAX_PAST_EPOCHS: usize =
    crate::canonicalization::V1_APP_MESSAGE_PAST_EPOCH_LIMIT as usize;

/// Number of prior within-epoch application-message generations retained for
/// out-of-order delivery. Marmot transports do not provide total ordering, so
/// the OpenMLS default of 5 is too small for ordinary relay reordering and
/// offline catch-up floods.
pub const DEFAULT_OUT_OF_ORDER_TOLERANCE: u32 = 100;

/// Maximum within-epoch application-message generation gap OpenMLS will
/// advance across when earlier messages are missing.
pub const DEFAULT_MAXIMUM_FORWARD_DISTANCE: u32 = 1_000;

/// Grep marker: every release checklist item that audits "are we still
/// shipping pure-plaintext MLS?" should find this. Do NOT remove without
/// also revisiting `docs/marmot-architecture/further-context/custom_extensions.md`.
pub const WIRE_FORMAT_POLICY_REVIEW_REQUIRED: &str =
    "PURE_PLAINTEXT - see cgka-engine/src/wire_format.rs";

/// Join config preset used by every group. Separate helper so tests can
/// swap wire-format policies without forking the whole config.
pub fn default_join_config() -> MlsGroupJoinConfig {
    join_config(DEFAULT_MAX_PAST_EPOCHS)
}

pub fn default_sender_ratchet_configuration() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(
        DEFAULT_OUT_OF_ORDER_TOLERANCE,
        DEFAULT_MAXIMUM_FORWARD_DISTANCE,
    )
}

pub fn join_config(max_past_epochs: usize) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(max_past_epochs)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(default_sender_ratchet_configuration())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_join_config_pins_sender_ratchet_reordering_policy() {
        let ratchet = default_join_config()
            .sender_ratchet_configuration()
            .to_owned();
        assert_eq!(
            ratchet.out_of_order_tolerance(),
            DEFAULT_OUT_OF_ORDER_TOLERANCE
        );
        assert_eq!(
            ratchet.maximum_forward_distance(),
            DEFAULT_MAXIMUM_FORWARD_DISTANCE
        );
    }
}
