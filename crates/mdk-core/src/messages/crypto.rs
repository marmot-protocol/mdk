//! Cryptographic helpers for MIP-03 message wrapping.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use mdk_storage_traits::groups::types::GroupExporterSecret;
use nostr::nips::nip44;
use nostr::secp256k1::rand::{RngCore, rngs::OsRng};
use nostr::{Keys, SecretKey};

use crate::Error;

/// Encrypts a kind:445 message content using ChaCha20-Poly1305 per MIP-03.
///
/// The output format is `base64(nonce || ciphertext)` where:
/// - `nonce` is 12 bytes generated from OsRng
/// - `ciphertext` includes the 16-byte Poly1305 authentication tag
/// - No AAD is used per MIP-03
pub(crate) fn encrypt_message_with_exporter_secret(
    secret: &GroupExporterSecret,
    plaintext: &[u8],
) -> Result<String, Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(secret.secret.as_ref())
        .map_err(|_| Error::Message("Failed to create cipher from exporter secret".to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| Error::Message("Failed to generate random nonce".to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::Message("ChaCha20-Poly1305 encryption failed".to_string()))?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(&combined))
}

/// Minimum valid byte length of decoded `event.content`:
/// 12-byte nonce + 16-byte Poly1305 authentication tag + 0 bytes of plaintext.
const MIN_ENCRYPTED_CONTENT_LEN: usize = 28;

/// Decrypts a kind:445 message content using ChaCha20-Poly1305 per MIP-03.
///
/// The content format is `base64(nonce || ciphertext)` where:
/// - `nonce` is 12 bytes
/// - `ciphertext` includes the 16-byte Poly1305 authentication tag
/// - No AAD is used per MIP-03
///
/// The minimum valid decoded length is 28 bytes:
/// 12 (nonce) + 16 (Poly1305 tag) + 0 (empty plaintext).
pub(crate) fn decrypt_message_with_exporter_secret(
    secret: &GroupExporterSecret,
    encrypted_content: &str,
) -> Result<Vec<u8>, Error> {
    let combined = BASE64.decode(encrypted_content).map_err(|_| {
        Error::Message("Failed to decode message content: invalid base64".to_string())
    })?;

    if combined.len() < MIN_ENCRYPTED_CONTENT_LEN {
        return Err(Error::Message(
            "Malformed message content: decoded content is fewer than 28 bytes (nonce + auth tag required)".to_string(),
        ));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(secret.secret.as_ref())
        .map_err(|_| Error::Message("Failed to create cipher from exporter secret".to_string()))?;

    cipher.decrypt(nonce, ciphertext).map_err(|_| {
        Error::Message("AEAD authentication failed: wrong key or tampered ciphertext".to_string())
    })
}

pub(crate) fn decrypt_message_with_legacy_exporter_secret(
    secret: &GroupExporterSecret,
    encrypted_content: &str,
) -> Result<Vec<u8>, Error> {
    let secret_key = SecretKey::from_slice(secret.secret.as_ref())
        .map_err(|_| Error::Message("Failed to create NIP-44 secret key".to_string()))?;
    let export_nostr_keys = Keys::new(secret_key);

    nip44::decrypt_to_bytes(
        export_nostr_keys.secret_key(),
        &export_nostr_keys.public_key,
        encrypted_content,
    )
    .map_err(|_| Error::Message("NIP-44 decryption failed".to_string()))
}

pub(crate) fn decrypt_message_with_any_supported_format(
    secret: &GroupExporterSecret,
    encrypted_content: &str,
    allow_legacy_nip44: bool,
) -> Result<Vec<u8>, Error> {
    match decrypt_message_with_exporter_secret(secret, encrypted_content) {
        Ok(decrypted_bytes) => Ok(decrypted_bytes),
        Err(aead_error) if allow_legacy_nip44 => {
            tracing::trace!(
                target: "mdk_core::messages::crypto",
                "AEAD decryption failed, attempting legacy NIP-44 fallback: {:?}",
                aead_error
            );
            match decrypt_message_with_legacy_exporter_secret(secret, encrypted_content) {
                Ok(decrypted_bytes) => Ok(decrypted_bytes),
                Err(legacy_error) => {
                    tracing::trace!(
                        target: "mdk_core::messages::crypto",
                        "Legacy NIP-44 fallback also failed: {:?}",
                        legacy_error
                    );
                    Err(aead_error)
                }
            }
        }
        Err(aead_error) => Err(aead_error),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    };
    use mdk_storage_traits::{GroupId, Secret};
    use nostr::nips::nip44;
    use nostr::{Keys, SecretKey};

    use super::*;

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello marmot protocol";
        let secret = GroupExporterSecret {
            mls_group_id: GroupId::from_slice(&[1, 2, 3]),
            epoch: 0,
            secret: Secret::new(key),
        };

        let encrypted = encrypt_message_with_exporter_secret(&secret, plaintext).unwrap();
        let decrypted = decrypt_message_with_exporter_secret(&secret, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"secret content";

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce_bytes = [0x02u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ciphertext = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();
        ciphertext[0] ^= 0x01;

        let mut combined = Vec::new();
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        let encrypted_content = BASE64.encode(&combined);

        let secret = GroupExporterSecret {
            mls_group_id: GroupId::from_slice(&[1, 2, 3]),
            epoch: 0,
            secret: Secret::new(key),
        };

        let result = decrypt_message_with_exporter_secret(&secret, &encrypted_content);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_rejects_invalid_base64() {
        let secret = GroupExporterSecret {
            mls_group_id: GroupId::from_slice(&[9, 9, 9]),
            epoch: 0,
            secret: Secret::new([0u8; 32]),
        };

        let result = decrypt_message_with_exporter_secret(&secret, "!!!not-base64!!!");
        assert!(matches!(result, Err(Error::Message(msg)) if msg.contains("invalid base64")));
    }

    #[test]
    fn test_decrypt_rejects_too_short_content() {
        let secret = GroupExporterSecret {
            mls_group_id: GroupId::from_slice(&[9, 9, 8]),
            epoch: 0,
            secret: Secret::new([1u8; 32]),
        };

        // Any decoded length below 28 bytes must be rejected:
        // 12 (nonce) + 16 (Poly1305 tag) + 0 (empty plaintext) = 28 bytes minimum.
        for len in [0usize, 1, 11, 12, 13, 27] {
            let too_short = BASE64.encode(vec![0u8; len]);
            let result = decrypt_message_with_exporter_secret(&secret, &too_short);
            assert!(
                matches!(result, Err(Error::Message(ref msg)) if msg.contains("fewer than 28 bytes")),
                "Expected rejection for decoded length {len}, got: {result:?}"
            );
        }
    }

    #[test]
    fn test_legacy_nip44_roundtrip() {
        let secret = GroupExporterSecret {
            mls_group_id: GroupId::from_slice(&[7, 7, 7]),
            epoch: 0,
            secret: Secret::new([0x24u8; 32]),
        };
        let secret_key = SecretKey::from_slice(secret.secret.as_ref()).unwrap();
        let export_nostr_keys = Keys::new(secret_key);

        let encrypted = nip44::encrypt(
            export_nostr_keys.secret_key(),
            &export_nostr_keys.public_key,
            b"legacy wrapper",
            nip44::Version::default(),
        )
        .unwrap();

        let decrypted = decrypt_message_with_legacy_exporter_secret(&secret, &encrypted).unwrap();
        assert_eq!(decrypted, b"legacy wrapper");
    }

    #[test]
    fn test_any_supported_format_accepts_legacy_nip44() {
        let secret = GroupExporterSecret {
            mls_group_id: GroupId::from_slice(&[7, 7, 8]),
            epoch: 0,
            secret: Secret::new([0x25u8; 32]),
        };
        let secret_key = SecretKey::from_slice(secret.secret.as_ref()).unwrap();
        let export_nostr_keys = Keys::new(secret_key);

        let encrypted = nip44::encrypt(
            export_nostr_keys.secret_key(),
            &export_nostr_keys.public_key,
            b"legacy fallback",
            nip44::Version::default(),
        )
        .unwrap();

        let decrypted =
            decrypt_message_with_any_supported_format(&secret, &encrypted, true).unwrap();
        assert_eq!(decrypted, b"legacy fallback");
    }
}
