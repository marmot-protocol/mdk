use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use mdk_storage_traits::groups::types::GroupExporterSecret;
use openmls::prelude::{Ciphersuite, ExtensionType};

use crate::Error;

/// Trait for formatting MLS types as Nostr tag values
///
/// This trait provides a consistent way to format MLS types (Ciphersuite, ExtensionType)
/// as hex strings for use in Nostr tags. The format is always "0x" followed by 4 lowercase
/// hex digits.
pub(crate) trait NostrTagFormat {
    /// Convert to Nostr tag hex format (e.g., "0x0001")
    fn to_nostr_tag(&self) -> String;
}

impl NostrTagFormat for Ciphersuite {
    fn to_nostr_tag(&self) -> String {
        format!("0x{:04x}", u16::from(*self))
    }
}

impl NostrTagFormat for ExtensionType {
    fn to_nostr_tag(&self) -> String {
        format!("0x{:04x}", u16::from(*self))
    }
}

/// Decrypts a kind:445 message content using ChaCha20-Poly1305 per MIP-03.
///
/// The content format is `base64(nonce || ciphertext)` where:
/// - `nonce` is 12 bytes
/// - `ciphertext` includes the 16-byte Poly1305 authentication tag
/// - `nostr_group_id` raw bytes are used as AAD
///
/// # Errors
///
/// Returns an error if:
/// - The content is not valid standard base64
/// - The decoded data is shorter than 12 bytes (malformed nonce)
/// - AEAD authentication fails (wrong key or tampered ciphertext)
pub(crate) fn decrypt_with_exporter_secret(
    secret: &GroupExporterSecret,
    encrypted_content: &str,
    nostr_group_id: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    // Decode base64 content (standard base64 with padding, per MIP-03)
    let combined = BASE64.decode(encrypted_content).map_err(|_| {
        Error::Message("Failed to decode message content: invalid base64".to_string())
    })?;

    // Minimum length: 12-byte nonce
    if combined.len() < 12 {
        return Err(Error::Message(
            "Malformed message content: nonce is shorter than 12 bytes".to_string(),
        ));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(secret.secret.as_ref())
        .map_err(|_| Error::Message("Failed to create cipher from exporter secret".to_string()))?;

    // AAD = raw 32-byte nostr_group_id (per MIP-03)
    let aad: &[u8] = nostr_group_id;

    // Decrypt and authenticate; any tampering or wrong key will cause an error here
    let message_bytes = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            Error::Message(
                "AEAD authentication failed: wrong key or tampered ciphertext".to_string(),
            )
        })?;

    Ok(message_bytes)
}

/// Encoding format for content fields
///
/// Only base64 encoding is supported per MIP-00/MIP-02.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentEncoding {
    /// Base64 encoding
    #[default]
    Base64,
}

impl ContentEncoding {
    /// Returns the tag value for this encoding format
    pub fn as_tag_value(&self) -> &'static str {
        match self {
            ContentEncoding::Base64 => "base64",
        }
    }

    /// Parse encoding from tag value
    pub fn from_tag_value(value: &str) -> Option<Self> {
        match value.to_lowercase().as_str() {
            "base64" => Some(ContentEncoding::Base64),
            _ => None,
        }
    }

    /// Extracts the encoding format from an iterator of tags.
    ///
    /// Looks for an `["encoding", "base64"]` tag.
    ///
    /// # Arguments
    ///
    /// * `tags` - An iterator over tags (works with both Event and UnsignedEvent)
    ///
    /// # Returns
    ///
    /// The ContentEncoding specified by the tag, or None if no tag present or invalid encoding.
    /// Callers must handle None and reject events without valid encoding tags.
    pub fn from_tags<'a>(tags: impl Iterator<Item = &'a nostr::Tag>) -> Option<Self> {
        for tag in tags {
            let slice = tag.as_slice();
            if slice.len() >= 2
                && slice[0] == "encoding"
                && let Some(encoding) = Self::from_tag_value(&slice[1])
            {
                return Some(encoding);
            }
        }
        // SECURITY: No default - encoding tag must be present per MIP-00/MIP-02
        None
    }
}

/// Encodes content using base64 encoding
///
/// # Arguments
///
/// * `bytes` - The bytes to encode
/// * `encoding` - The encoding format (must be Base64)
///
/// # Returns
///
/// The base64-encoded string
pub(crate) fn encode_content(bytes: &[u8], encoding: ContentEncoding) -> String {
    match encoding {
        ContentEncoding::Base64 => BASE64.encode(bytes),
    }
}

/// Decodes content using base64 encoding
///
/// The encoding format must be determined from the `["encoding", "base64"]` tag on the event.
///
/// Per MIP-00/MIP-02, the encoding tag is required. Callers must extract the encoding
/// using `ContentEncoding::from_tags()` and handle the None case by rejecting the event.
///
/// # Arguments
///
/// * `content` - The base64-encoded string
/// * `encoding` - The encoding format (must be Base64)
/// * `label` - A label for the content type (e.g., "key package", "welcome") used in error messages
///
/// # Returns
///
/// A tuple of (decoded bytes, format description) on success, or an error message string.
pub(crate) fn decode_content(
    content: &str,
    encoding: ContentEncoding,
    label: &str,
) -> Result<(Vec<u8>, &'static str), String> {
    match encoding {
        ContentEncoding::Base64 => BASE64
            .decode(content)
            .map(|bytes| (bytes, "base64"))
            .map_err(|e| format!("Failed to decode {} as base64: {}", label, e)),
    }
}

#[cfg(test)]
mod tests {
    use mdk_storage_traits::Secret;

    use super::*;
    use nostr::Tag;

    /// Test that ChaCha20-Poly1305 encrypt/decrypt round-trips correctly.
    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let nostr_group_id = [0xABu8; 32];
        let plaintext = b"hello marmot protocol";

        // Create a fake GroupExporterSecret
        use mdk_storage_traits::GroupId;
        let secret = mdk_storage_traits::groups::types::GroupExporterSecret {
            mls_group_id: GroupId::from_slice(&[1, 2, 3]),
            epoch: 0,
            secret: Secret::new(key),
        };

        // We need to manually encrypt to test decrypt.
        // Use the same logic as build_message_event.
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as BASE64;
        use chacha20poly1305::{
            ChaCha20Poly1305, Nonce,
            aead::{Aead, KeyInit},
        };

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce_bytes = [0x01u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &nostr_group_id,
                },
            )
            .unwrap();

        let mut combined = Vec::new();
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        let encrypted_content = BASE64.encode(&combined);

        // Now decrypt using our function
        let decrypted = decrypt_with_exporter_secret(&secret, &encrypted_content, &nostr_group_id)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    /// Test that decryption fails with the wrong AAD (nostr_group_id).
    #[test]
    fn test_chacha20poly1305_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let correct_group_id = [0xABu8; 32];
        let wrong_group_id = [0xCDu8; 32];
        let plaintext = b"secret content";

        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as BASE64;
        use chacha20poly1305::{
            ChaCha20Poly1305, Nonce,
            aead::{Aead, KeyInit},
        };
        use mdk_storage_traits::GroupId;

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce_bytes = [0x02u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &correct_group_id,
                },
            )
            .unwrap();

        let mut combined = Vec::new();
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        let encrypted_content = BASE64.encode(&combined);

        let secret = mdk_storage_traits::groups::types::GroupExporterSecret {
            mls_group_id: GroupId::from_slice(&[1, 2, 3]),
            epoch: 0,
            secret: Secret::new(key),
        };

        // Should fail with wrong AAD
        let result = decrypt_with_exporter_secret(&secret, &encrypted_content, &wrong_group_id);
        assert!(
            result.is_err(),
            "Decryption with wrong group_id AAD should fail"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("AEAD authentication failed"),
            "Error should indicate AEAD authentication failure"
        );
    }

    /// Test that decryption fails with invalid base64.
    #[test]
    fn test_decrypt_rejects_invalid_base64() {
        use mdk_storage_traits::GroupId;

        let secret = mdk_storage_traits::groups::types::GroupExporterSecret {
            mls_group_id: GroupId::from_slice(&[1, 2, 3]),
            epoch: 0,
            secret: Secret::new([0u8; 32]),
        };

        let result = decrypt_with_exporter_secret(&secret, "!!!not-base64!!!", &[0u8; 32]);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("invalid base64"),
            "Error should indicate invalid base64"
        );
    }

    /// Test that decryption fails when the content is shorter than 12 bytes (nonce).
    #[test]
    fn test_decrypt_rejects_short_nonce() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as BASE64;
        use mdk_storage_traits::GroupId;

        let secret = mdk_storage_traits::groups::types::GroupExporterSecret {
            mls_group_id: GroupId::from_slice(&[1, 2, 3]),
            epoch: 0,
            secret: Secret::new([0u8; 32]),
        };

        // Only 8 bytes - shorter than the required 12-byte nonce
        let too_short = BASE64.encode([0u8; 8]);
        let result = decrypt_with_exporter_secret(&secret, &too_short, &[0u8; 32]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("shorter than 12 bytes"),
            "Error should indicate malformed nonce"
        );
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = vec![0xde, 0xad, 0xbe, 0xef];

        // Base64 roundtrip
        let b64_encoded = encode_content(&original, ContentEncoding::Base64);
        let (b64_decoded, b64_fmt) =
            decode_content(&b64_encoded, ContentEncoding::Base64, "test").unwrap();
        assert_eq!(original, b64_decoded);
        assert_eq!(b64_fmt, "base64");
    }

    #[test]
    fn test_decode_invalid_content() {
        assert!(decode_content("!!!", ContentEncoding::Base64, "test").is_err());
    }

    #[test]
    fn test_content_encoding_tag_value_roundtrip() {
        assert_eq!(
            ContentEncoding::from_tag_value(ContentEncoding::Base64.as_tag_value()),
            Some(ContentEncoding::Base64)
        );
        assert_eq!(ContentEncoding::from_tag_value("invalid"), None);
        assert_eq!(ContentEncoding::from_tag_value("hex"), None);
    }

    #[test]
    fn test_from_tags_returns_encoding() {
        let tags_base64 = [Tag::custom(
            nostr::TagKind::Custom("encoding".into()),
            ["base64"],
        )];
        assert_eq!(
            ContentEncoding::from_tags(tags_base64.iter()),
            Some(ContentEncoding::Base64)
        );

        let tags_hex = [Tag::custom(
            nostr::TagKind::Custom("encoding".into()),
            ["hex"],
        )];
        assert_eq!(ContentEncoding::from_tags(tags_hex.iter()), None);

        let empty: [Tag; 0] = [];
        assert_eq!(ContentEncoding::from_tags(empty.iter()), None);
    }
}
