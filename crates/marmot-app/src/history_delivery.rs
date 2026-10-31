//! Sealed history deliveries (mdk#2628 4.2b, decision D60): one history
//! bundle sent to one sibling device through the device group, readable only
//! by that device.
//!
//! A delivery's content is one UTF-8 JSON object written without whitespace,
//! members in this order, base64 standard with padding:
//!
//! ```text
//! {"v":1,"from":"<slot hex>","to":"<slot hex>","chat":"<MLS group id hex>","sealed":"<base64>","bundle":"<base64>"}
//! ```
//!
//! `bundle` is the bundle's ciphertext (`history_bundle.rs`), inline. `sealed`
//! is the bundle's key (32 bytes) then that ciphertext's SHA-256 (32 bytes),
//! sealed to `to`'s history key with [`delivery_context`]. The context binds
//! the purpose, both slots and the chat, so a sealed value never opens for
//! another purpose, sender, receiver or chat. Every sibling reads a delivery;
//! only `to` can open it. A content is at most
//! [`MAX_HISTORY_DELIVERY_CONTENT_BYTES`], which a bundle of at most
//! [`INLINE_BUNDLE_MAX_PLAINTEXT`] fits.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use cgka_traits::app_components::{DeviceSlotId, encode_component_vectors};
use zeroize::Zeroizing;

use crate::AppError;

/// A sealed history delivery.
pub(crate) const KIND_HISTORY_DELIVERY: u64 = 473;
/// The longest content a delivery carries, in bytes: the device-group
/// message budget small state uses.
pub(crate) const MAX_HISTORY_DELIVERY_CONTENT_BYTES: usize = 32_768;
/// The most plaintext a bundle sent inline holds. Its ciphertext in base64,
/// beside a 256-byte chat id, both slots and the sealed key, stays within
/// [`MAX_HISTORY_DELIVERY_CONTENT_BYTES`].
pub(crate) const INLINE_BUNDLE_MAX_PLAINTEXT: usize = 23_552;
/// The most inline bundles one chat's history is sent in. A longer history
/// waits for blob deliveries (4.2c), so one link never floods the device
/// group.
pub(crate) const MAX_INLINE_BUNDLES: usize = 8;
const DELIVERY_VERSION: u64 = 1;
/// The context's first part: what a sealed value is for.
const DELIVERY_PURPOSE: &[u8] = b"marmot history delivery v1";
/// The longest MLS group id a delivery names, as for bundles.
const MAX_CHAT_ID_BYTES: usize = 256;

/// One delivery: `bundle` from the device at `from` to the device at `to`,
/// for the chat `chat`, with its key and hash in `sealed`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HistoryDelivery {
    pub(crate) from: DeviceSlotId,
    pub(crate) to: DeviceSlotId,
    pub(crate) chat: Vec<u8>,
    pub(crate) sealed: Vec<u8>,
    pub(crate) bundle: Vec<u8>,
}

impl HistoryDelivery {
    /// The delivery's content, in the canonical form.
    pub(crate) fn encode(&self) -> String {
        format!(
            r#"{{"v":{DELIVERY_VERSION},"from":"{}","to":"{}","chat":"{}","sealed":"{}","bundle":"{}"}}"#,
            hex::encode(self.from),
            hex::encode(self.to),
            hex::encode(&self.chat),
            BASE64_STANDARD.encode(&self.sealed),
            BASE64_STANDARD.encode(&self.bundle),
        )
    }

    /// Decode a delivery's content, accepting only the canonical form within
    /// the size budget.
    pub(crate) fn decode(content: &str) -> Result<Self, AppError> {
        let invalid = || AppError::DeviceGroupRefused("history_delivery_format");
        if content.len() > MAX_HISTORY_DELIVERY_CONTENT_BYTES {
            return Err(invalid());
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            v: u64,
            from: String,
            to: String,
            chat: String,
            sealed: String,
            bundle: String,
        }
        let wire: Wire = serde_json::from_str(content).map_err(|_| invalid())?;
        let slot = |hex_slot: &str| {
            hex::decode(hex_slot)
                .ok()
                .and_then(|bytes| DeviceSlotId::try_from(bytes).ok())
                .ok_or_else(invalid)
        };
        let base64 = |value: &str| BASE64_STANDARD.decode(value).map_err(|_| invalid());
        let delivery = Self {
            from: slot(&wire.from)?,
            to: slot(&wire.to)?,
            chat: hex::decode(&wire.chat).map_err(|_| invalid())?,
            sealed: base64(&wire.sealed)?,
            bundle: base64(&wire.bundle)?,
        };
        if wire.v != DELIVERY_VERSION
            || delivery.chat.is_empty()
            || delivery.chat.len() > MAX_CHAT_ID_BYTES
            || delivery.bundle.is_empty()
            || delivery.encode() != content
        {
            return Err(invalid());
        }
        Ok(delivery)
    }
}

/// The context a delivery's key and hash are sealed with: the purpose, the
/// sending slot, the receiving slot and the chat's MLS group id, each a
/// length-prefixed vector.
pub(crate) fn delivery_context(from: &DeviceSlotId, to: &DeviceSlotId, chat: &[u8]) -> Vec<u8> {
    encode_component_vectors(&[DELIVERY_PURPOSE, from, to, chat])
}

/// What a delivery seals: the bundle's key, then its ciphertext's SHA-256.
pub(crate) fn sealed_plaintext(key: &[u8; 32], ciphertext_sha256: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(64));
    plaintext.extend_from_slice(key);
    plaintext.extend_from_slice(ciphertext_sha256);
    plaintext
}

/// The bundle's key and ciphertext hash from an opened sealed value, or none
/// unless it is exactly 64 bytes.
pub(crate) fn opened_key_and_hash(opened: &[u8]) -> Option<(Zeroizing<[u8; 32]>, [u8; 32])> {
    if opened.len() != 64 {
        return None;
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&opened[..32]);
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&opened[32..]);
    Some((key, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivery(chat_len: usize, bundle_len: usize) -> HistoryDelivery {
        HistoryDelivery {
            from: [1; 32],
            to: [2; 32],
            chat: vec![0xab; chat_len],
            // A sealed key and hash: kem output, then 64 bytes and a tag.
            sealed: vec![7; 1 + 32 + 1 + 64 + 16],
            bundle: vec![9; bundle_len],
        }
    }

    #[test]
    fn a_delivery_round_trips_only_in_its_canonical_form() {
        let delivery = delivery(16, 100);
        let content = delivery.encode();
        assert!(content.starts_with(r#"{"v":1,"from":"0101"#));
        assert_eq!(HistoryDelivery::decode(&content).unwrap(), delivery);

        for altered in [
            content.replacen("\"v\":1", "\"v\":2", 1),
            content.replacen("{\"v\":1,", "{ \"v\":1,", 1),
            content.replacen("abab", "ABAB", 1),
            content.replacen("}", ",\"extra\":1}", 1),
            content.replacen("\"to\"", "\"To\"", 1),
        ] {
            assert!(HistoryDelivery::decode(&altered).is_err(), "{altered}");
        }
        // Members out of order.
        let reordered = format!(
            r#"{{"from":"{}","v":1,"to":"{}","chat":"{}","sealed":"{}","bundle":"{}"}}"#,
            hex::encode(delivery.from),
            hex::encode(delivery.to),
            hex::encode(&delivery.chat),
            BASE64_STANDARD.encode(&delivery.sealed),
            BASE64_STANDARD.encode(&delivery.bundle),
        );
        assert!(HistoryDelivery::decode(&reordered).is_err());
    }

    #[test]
    fn a_delivery_refuses_an_empty_or_overlong_chat_or_an_empty_bundle() {
        for refused in [delivery(0, 100), delivery(257, 100), delivery(16, 0)] {
            assert!(HistoryDelivery::decode(&refused.encode()).is_err());
        }
        assert!(HistoryDelivery::decode(&delivery(256, 100).encode()).is_ok());
    }

    #[test]
    fn the_largest_inline_bundle_fits_the_budget_beside_the_longest_chat_id() {
        // ChaCha20-Poly1305 adds a 16-byte tag.
        let largest = delivery(MAX_CHAT_ID_BYTES, INLINE_BUNDLE_MAX_PLAINTEXT + 16);
        let content = largest.encode();
        assert!(content.len() <= MAX_HISTORY_DELIVERY_CONTENT_BYTES);
        assert_eq!(HistoryDelivery::decode(&content).unwrap(), largest);

        let mut overlong = largest.encode();
        overlong.push_str(&" ".repeat(MAX_HISTORY_DELIVERY_CONTENT_BYTES));
        assert!(HistoryDelivery::decode(&overlong).is_err());
    }

    #[test]
    fn the_context_binds_purpose_slots_and_chat() {
        let base = delivery_context(&[1; 32], &[2; 32], b"chat");
        assert_ne!(base, delivery_context(&[2; 32], &[1; 32], b"chat"));
        assert_ne!(base, delivery_context(&[1; 32], &[2; 32], b"chaT"));
        // Length prefixes keep the chat from running into a slot.
        assert_ne!(
            delivery_context(&[1; 32], &[2; 32], b"ab"),
            delivery_context(&[1; 32], &[2; 32], b"abc")
        );
        assert!(
            base.windows(DELIVERY_PURPOSE.len())
                .any(|w| w == DELIVERY_PURPOSE)
        );
    }

    #[test]
    fn an_opened_value_splits_into_key_and_hash_only_at_64_bytes() {
        let plaintext = sealed_plaintext(&[3; 32], &[4; 32]);
        let (key, hash) = opened_key_and_hash(&plaintext).unwrap();
        assert_eq!(*key, [3; 32]);
        assert_eq!(hash, [4; 32]);
        assert!(opened_key_and_hash(&plaintext[..63]).is_none());
        assert!(opened_key_and_hash(&[0; 65]).is_none());
    }
}
