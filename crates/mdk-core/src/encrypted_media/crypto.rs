//! Cryptographic operations for encrypted media
//!
//! This module handles all encryption and decryption operations for media files,
//! including key derivation, nonce generation, and ChaCha20-Poly1305 AEAD operations
//! according to the Marmot protocol specification.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::encrypted_media::types::EncryptedMediaError;
use crate::{GroupId, MDK};
use mdk_storage_traits::{MdkStorageProvider, Secret};

/// Scheme label for MIP-04 version 1 encryption to provide domain separation
/// and prevent cross-version collisions
const SCHEME_LABEL: &[u8] = b"mip04-v1";

/// Build HKDF context for key/nonce derivation with scheme label for domain separation
fn build_hkdf_context(
    file_hash: &[u8; 32],
    mime_type: &str,
    filename: &str,
    suffix: &[u8],
) -> Vec<u8> {
    let mut context = Vec::new();
    context.extend_from_slice(SCHEME_LABEL);
    context.push(0x00);
    context.extend_from_slice(file_hash);
    context.push(0x00);
    context.extend_from_slice(mime_type.as_bytes());
    context.push(0x00);
    context.extend_from_slice(filename.as_bytes());
    context.push(0x00);
    context.extend_from_slice(suffix);
    context
}

/// Build AAD (Associated Authenticated Data) for AEAD encryption with scheme label
fn build_aad(file_hash: &[u8; 32], mime_type: &str, filename: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(SCHEME_LABEL);
    aad.push(0x00);
    aad.extend_from_slice(file_hash);
    aad.push(0x00);
    aad.extend_from_slice(mime_type.as_bytes());
    aad.push(0x00);
    aad.extend_from_slice(filename.as_bytes());
    aad
}

/// Derive encryption key from MLS group secret according to Marmot protocol specification
///
/// As specified in Marmot protocol 04.md, the encryption key is derived using:
/// file_key = HKDF-Expand(exporter_secret, SCHEME_LABEL || 0x00 || file_hash_bytes || 0x00 || mime_type_bytes || 0x00 || filename_bytes || 0x00 || "key", 32)
pub fn derive_encryption_key<Storage>(
    mdk: &MDK<Storage>,
    group_id: &GroupId,
    original_hash: &[u8; 32],
    mime_type: &str,
    filename: &str,
) -> Result<Secret<[u8; 32]>, EncryptedMediaError>
where
    Storage: MdkStorageProvider,
{
    // Get the group's exporter secret
    let exporter_secret = mdk
        .exporter_secret(group_id)
        .map_err(|_| EncryptedMediaError::GroupNotFound)?;

    // Create context as specified in Marmot protocol 04.md:
    // SCHEME_LABEL || 0x00 || file_hash_bytes || 0x00 || mime_type_bytes || 0x00 || filename_bytes || 0x00 || "key"
    let context = build_hkdf_context(original_hash, mime_type, filename, b"key");

    // Use HKDF to derive encryption key with context
    let hk = Hkdf::<Sha256>::new(None, exporter_secret.secret.as_ref());

    let mut key = [0u8; 32];
    hk.expand(&context, &mut key)
        .map_err(|e| EncryptedMediaError::EncryptionFailed {
            reason: format!("Key derivation failed: {}", e),
        })?;

    Ok(Secret::new(key))
}

/// Derive encryption nonce from context according to Marmot protocol specification
///
/// As specified in Marmot protocol 04.md, the encryption nonce is derived using:
/// nonce = HKDF-Expand(exporter_secret, SCHEME_LABEL || 0x00 || file_hash_bytes || 0x00 || mime_type_bytes || 0x00 || filename_bytes || 0x00 || "nonce", 12)
///
/// This ensures the nonce is deterministic and can be reproduced for decryption
/// without needing to store it separately.
pub fn derive_encryption_nonce<Storage>(
    mdk: &MDK<Storage>,
    group_id: &GroupId,
    original_hash: &[u8; 32],
    mime_type: &str,
    filename: &str,
) -> Result<Secret<[u8; 12]>, EncryptedMediaError>
where
    Storage: MdkStorageProvider,
{
    // Get the group's exporter secret
    let exporter_secret = mdk
        .exporter_secret(group_id)
        .map_err(|_| EncryptedMediaError::GroupNotFound)?;

    // Create context as specified in Marmot protocol 04.md:
    // SCHEME_LABEL || 0x00 || file_hash_bytes || 0x00 || mime_type_bytes || 0x00 || filename_bytes || 0x00 || "nonce"
    let context = build_hkdf_context(original_hash, mime_type, filename, b"nonce");

    // Use HKDF to derive nonce with context
    let hk = Hkdf::<Sha256>::new(None, exporter_secret.secret.as_ref());

    let mut nonce = [0u8; 12];
    hk.expand(&context, &mut nonce)
        .map_err(|e| EncryptedMediaError::EncryptionFailed {
            reason: format!("Nonce derivation failed: {}", e),
        })?;

    Ok(Secret::new(nonce))
}

/// Encrypt data using ChaCha20-Poly1305 AEAD with Associated Authenticated Data
///
/// As specified in MIP-04, the AAD includes:
/// aad = SCHEME_LABEL || 0x00 || file_hash_bytes || 0x00 || mime_type_bytes || 0x00 || filename_bytes
pub fn encrypt_data_with_aad(
    data: &[u8],
    key: &Secret<[u8; 32]>,
    nonce: &Secret<[u8; 12]>,
    file_hash: &[u8; 32],
    mime_type: &str,
    filename: &str,
) -> Result<Vec<u8>, EncryptedMediaError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|e| {
        EncryptedMediaError::EncryptionFailed {
            reason: format!("Failed to create cipher: {}", e),
        }
    })?;

    let nonce = Nonce::from_slice(nonce.as_ref());

    let aad = build_aad(file_hash, mime_type, filename);

    cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: data,
                aad: &aad,
            },
        )
        .map_err(|e| EncryptedMediaError::EncryptionFailed {
            reason: format!("Encryption failed: {}", e),
        })
}

/// Decrypt data using ChaCha20-Poly1305 AEAD with Associated Authenticated Data
///
/// As specified in MIP-04, the AAD includes:
/// aad = SCHEME_LABEL || 0x00 || file_hash_bytes || 0x00 || mime_type_bytes || 0x00 || filename_bytes
pub fn decrypt_data_with_aad(
    encrypted_data: &[u8],
    key: &Secret<[u8; 32]>,
    nonce: &Secret<[u8; 12]>,
    file_hash: &[u8; 32],
    mime_type: &str,
    filename: &str,
) -> Result<Vec<u8>, EncryptedMediaError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|e| {
        EncryptedMediaError::DecryptionFailed {
            reason: format!("Failed to create cipher: {}", e),
        }
    })?;

    let nonce = Nonce::from_slice(nonce.as_ref());

    let aad = build_aad(file_hash, mime_type, filename);

    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: encrypted_data,
                aad: &aad,
            },
        )
        .map_err(|e| EncryptedMediaError::DecryptionFailed {
            reason: format!("Decryption failed: {}", e),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdk_memory_storage::MdkMemoryStorage;
    use sha2::Digest;

    fn create_test_mdk() -> MDK<MdkMemoryStorage> {
        MDK::new(MdkMemoryStorage::default())
    }

    #[test]
    fn test_errors_without_group() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);

        let original_data =
            b"This is test image data that should be encrypted and decrypted properly";
        let mime_type = "image/jpeg";
        let filename = "test.jpg";

        let original_hash: [u8; 32] = Sha256::digest(original_data).into();

        // Test key and nonce derivation (these will fail without a proper group, but we can test the logic)
        let key_result =
            derive_encryption_key(&mdk, &group_id, &original_hash, mime_type, filename);
        let nonce_result =
            derive_encryption_nonce(&mdk, &group_id, &original_hash, mime_type, filename);

        // These should fail gracefully since we don't have a real MLS group
        assert!(key_result.is_err());
        assert!(nonce_result.is_err());

        // Verify the error is the expected "GroupNotFound" error
        if let Err(EncryptedMediaError::GroupNotFound) = key_result {
            // Expected behavior
        } else {
            panic!("Expected GroupNotFound error for key derivation");
        }
    }

    #[test]
    fn test_encrypt_decrypt_with_known_key() {
        // Test encryption/decryption with a known key and nonce
        let key = Secret::new([0x42u8; 32]);
        let nonce = Secret::new([0x24u8; 12]);
        let original_data = b"Hello, encrypted world!";
        let file_hash = [0x01u8; 32];
        let mime_type = "image/jpeg";
        let filename = "test.jpg";

        // Encrypt the data
        let encrypted_result =
            encrypt_data_with_aad(original_data, &key, &nonce, &file_hash, mime_type, filename);
        assert!(encrypted_result.is_ok());
        let encrypted_data = encrypted_result.unwrap();

        // Verify encrypted data is different from original
        assert_ne!(encrypted_data.as_slice(), original_data);
        assert!(encrypted_data.len() > original_data.len()); // Should include auth tag

        // Decrypt the data
        let decrypted_result = decrypt_data_with_aad(
            &encrypted_data,
            &key,
            &nonce,
            &file_hash,
            mime_type,
            filename,
        );
        assert!(decrypted_result.is_ok());
        let decrypted_data = decrypted_result.unwrap();

        // Verify decrypted data matches original
        assert_eq!(decrypted_data.as_slice(), original_data);
    }

    #[test]
    fn test_encrypt_decrypt_with_different_aad() {
        // Test that changing AAD components causes decryption to fail
        let key = Secret::new([0x42u8; 32]);
        let nonce = Secret::new([0x24u8; 12]);
        let original_data = b"Hello, encrypted world!";
        let file_hash = [0x01u8; 32];
        let mime_type = "image/jpeg";
        let filename = "test.jpg";

        // Encrypt with original parameters
        let encrypted_data =
            encrypt_data_with_aad(original_data, &key, &nonce, &file_hash, mime_type, filename)
                .unwrap();

        // Try to decrypt with different file hash (should fail)
        let different_hash = [0x02u8; 32];
        let result = decrypt_data_with_aad(
            &encrypted_data,
            &key,
            &nonce,
            &different_hash,
            mime_type,
            filename,
        );
        assert!(result.is_err());

        // Try to decrypt with different MIME type (should fail)
        let result = decrypt_data_with_aad(
            &encrypted_data,
            &key,
            &nonce,
            &file_hash,
            "image/png",
            filename,
        );
        assert!(result.is_err());

        // Try to decrypt with different filename (should fail)
        let result = decrypt_data_with_aad(
            &encrypted_data,
            &key,
            &nonce,
            &file_hash,
            mime_type,
            "different.jpg",
        );
        assert!(result.is_err());

        // Decrypt with correct parameters (should succeed)
        let result = decrypt_data_with_aad(
            &encrypted_data,
            &key,
            &nonce,
            &file_hash,
            mime_type,
            filename,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_slice(), original_data);
    }

    #[test]
    fn test_encrypt_decrypt_with_wrong_key() {
        // Test that using wrong key causes decryption to fail
        let key = Secret::new([0x42u8; 32]);
        let wrong_key = Secret::new([0x43u8; 32]);
        let nonce = Secret::new([0x24u8; 12]);
        let original_data = b"Hello, encrypted world!";
        let file_hash = [0x01u8; 32];
        let mime_type = "image/jpeg";
        let filename = "test.jpg";

        // Encrypt with original key
        let encrypted_data =
            encrypt_data_with_aad(original_data, &key, &nonce, &file_hash, mime_type, filename)
                .unwrap();

        // Try to decrypt with wrong key (should fail)
        let result = decrypt_data_with_aad(
            &encrypted_data,
            &wrong_key,
            &nonce,
            &file_hash,
            mime_type,
            filename,
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(EncryptedMediaError::DecryptionFailed { .. })
        ));
    }

    #[test]
    fn test_encrypt_decrypt_with_wrong_nonce() {
        // Test that using wrong nonce causes decryption to fail
        let key = Secret::new([0x42u8; 32]);
        let nonce = Secret::new([0x24u8; 12]);
        let wrong_nonce = Secret::new([0x25u8; 12]);
        let original_data = b"Hello, encrypted world!";
        let file_hash = [0x01u8; 32];
        let mime_type = "image/jpeg";
        let filename = "test.jpg";

        // Encrypt with original nonce
        let encrypted_data =
            encrypt_data_with_aad(original_data, &key, &nonce, &file_hash, mime_type, filename)
                .unwrap();

        // Try to decrypt with wrong nonce (should fail)
        let result = decrypt_data_with_aad(
            &encrypted_data,
            &key,
            &wrong_nonce,
            &file_hash,
            mime_type,
            filename,
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(EncryptedMediaError::DecryptionFailed { .. })
        ));
    }

    #[test]
    fn test_encrypt_empty_data() {
        // Test encryption of empty data
        let key = Secret::new([0x42u8; 32]);
        let nonce = Secret::new([0x24u8; 12]);
        let empty_data = b"";
        let file_hash = [0x01u8; 32];
        let mime_type = "image/jpeg";
        let filename = "empty.jpg";

        // Encrypt empty data
        let encrypted_result =
            encrypt_data_with_aad(empty_data, &key, &nonce, &file_hash, mime_type, filename);
        assert!(encrypted_result.is_ok());
        let encrypted_data = encrypted_result.unwrap();

        // Should still have auth tag even for empty data
        assert!(!encrypted_data.is_empty());

        // Decrypt and verify
        let decrypted_result = decrypt_data_with_aad(
            &encrypted_data,
            &key,
            &nonce,
            &file_hash,
            mime_type,
            filename,
        );
        assert!(decrypted_result.is_ok());
        assert_eq!(decrypted_result.unwrap().as_slice(), empty_data);
    }

    #[test]
    fn test_aad_construction() {
        // Test that AAD is constructed correctly by verifying different components
        // cause different encrypted outputs
        let key = Secret::new([0x42u8; 32]);
        let nonce = Secret::new([0x24u8; 12]);
        let data = b"test data";
        let file_hash = [0x01u8; 32];

        // Encrypt with first set of AAD components
        let encrypted1 =
            encrypt_data_with_aad(data, &key, &nonce, &file_hash, "image/jpeg", "photo.jpg")
                .unwrap();

        // Encrypt with different MIME type
        let encrypted2 =
            encrypt_data_with_aad(data, &key, &nonce, &file_hash, "image/png", "photo.jpg")
                .unwrap();

        // Encrypt with different filename
        let encrypted3 =
            encrypt_data_with_aad(data, &key, &nonce, &file_hash, "image/jpeg", "image.jpg")
                .unwrap();

        // All encrypted outputs should be different due to different AAD
        assert_ne!(encrypted1, encrypted2);
        assert_ne!(encrypted1, encrypted3);
        assert_ne!(encrypted2, encrypted3);
    }
}
