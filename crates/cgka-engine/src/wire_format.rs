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

/// Serialized length of the `MLSMessage` that the engine sends for a
/// `payload_len`-byte application payload in a group whose MLS group id is
/// `group_id_len` bytes.
///
/// An application message is always a `PrivateMessage` (RFC 9420 section 6.3).
/// Under the one ciphersuite the engine accepts
/// (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`: 64-byte Ed25519
/// signatures, 16-byte AES-GCM tags), with no padding and no authenticated
/// data, it is:
///
/// ```text
/// MLSMessage     = version[2] wire_format[2] PrivateMessage
/// PrivateMessage = <group_id> epoch[8] content_type[1] <authenticated_data: empty>
///                  <encrypted_sender_data: SenderData[12] || tag[16]>
///                  <ciphertext: <application_data> <signature[64]> || tag[16]>
/// ```
///
/// `<x>` is `x` behind its MLS variable-length size prefix. A payload must stay
/// below 2^30 bytes, the largest size that prefix encodes.
pub fn application_message_len(group_id_len: usize, payload_len: usize) -> usize {
    const SIGNATURE_LEN: usize = 64;
    const AEAD_TAG_LEN: usize = 16;
    const SENDER_DATA_LEN: usize = 4 + 4 + 4;
    fn sized(len: usize) -> usize {
        let prefix = match len {
            0..64 => 1,
            64..16_384 => 2,
            _ => 4,
        };
        prefix + len
    }
    let ciphertext = sized(payload_len) + sized(SIGNATURE_LEN) + AEAD_TAG_LEN;
    2 + 2
        + sized(group_id_len)
        + 8
        + 1
        + sized(0)
        + sized(SENDER_DATA_LEN + AEAD_TAG_LEN)
        + sized(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::DEFAULT_CIPHERSUITE;
    use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig};
    use openmls::prelude::{BasicCredential, CredentialWithKey};
    use openmls_basic_credential::SignatureKeyPair;
    use tls_codec::Serialize as _;

    /// The length model matches what OpenMLS writes, across every size-prefix
    /// boundary of the group id, the payload and the ciphertext.
    #[test]
    fn application_message_len_matches_openmls() {
        assert_eq!(default_join_config().padding_size(), 0);
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(DEFAULT_CIPHERSUITE.signature_algorithm()).unwrap();
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(DEFAULT_CIPHERSUITE)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(default_sender_ratchet_configuration())
            .build();
        assert_eq!(config.join_config().padding_size(), 0);
        for group_id_len in [1, 16, 32, 63, 64, 255] {
            let credential_with_key = CredentialWithKey {
                credential: BasicCredential::new(b"length-model".to_vec()).into(),
                signature_key: signer.public().into(),
            };
            let mut group = MlsGroup::new_with_group_id(
                &provider,
                &signer,
                &config,
                GroupId::from_slice(&vec![7; group_id_len]),
                credential_with_key,
            )
            .unwrap();
            for payload_len in [0, 1, 63, 64, 16_299, 16_300, 16_383, 16_384, 70_000] {
                let message = group
                    .create_message(&provider, &signer, &vec![b'x'; payload_len])
                    .unwrap()
                    .tls_serialize_detached()
                    .unwrap();
                assert_eq!(
                    message.len(),
                    application_message_len(group_id_len, payload_len),
                    "group id {group_id_len} bytes, payload {payload_len} bytes"
                );
            }
        }
    }
}
