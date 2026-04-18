//! MIP-06 optional encrypted device name extension (`0xF2EF`).
//!
//! Device names are NIP-44 encrypted with the user's own Nostr keypair
//! so only the owner can read them.

use nostr::Keys;
use nostr::nips::nip44;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::error::Error;

/// TLS-serialized encrypted device name.
///
/// ```tls
/// struct {
///     opaque encrypted_device_name<1..2^16-1>;  // NIP-44 ciphertext
/// } EncryptedDeviceName;
/// ```
#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct EncryptedDeviceName {
    encrypted_device_name: Vec<u8>,
}

impl EncryptedDeviceName {
    /// Maximum device name length in UTF-8 characters.
    pub const MAX_NAME_CHARS: usize = 64;

    /// Encrypt a device name using NIP-44 with the user's own keypair.
    ///
    /// ```text
    /// conversation_key = NIP44.derive_conversation_key(nostr_privkey, nostr_pubkey)
    /// encrypted_name   = NIP44.encrypt(conversation_key, device_name_utf8)
    /// ```
    pub fn encrypt(keys: &Keys, device_name: &str) -> Result<Self, Error> {
        if device_name.chars().count() > Self::MAX_NAME_CHARS {
            return Err(Error::ExtensionFormatError(format!(
                "device name exceeds {} characters",
                Self::MAX_NAME_CHARS
            )));
        }

        let encrypted = nip44::encrypt(
            keys.secret_key(),
            &keys.public_key(),
            device_name,
            nip44::Version::default(),
        )
        .map_err(|e| Error::ExtensionFormatError(format!("NIP-44 encryption: {e}")))?;

        Ok(Self {
            encrypted_device_name: encrypted.into_bytes(),
        })
    }

    /// Decrypt the device name using the user's own keypair.
    pub fn decrypt(&self, keys: &Keys) -> Result<String, Error> {
        let ciphertext = std::str::from_utf8(&self.encrypted_device_name)
            .map_err(|e| Error::ExtensionFormatError(format!("invalid NIP-44 ciphertext: {e}")))?;

        nip44::decrypt_to_bytes(keys.secret_key(), &keys.public_key(), ciphertext)
            .map_err(|e| Error::ExtensionFormatError(format!("NIP-44 decryption: {e}")))
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|e| {
                    Error::ExtensionFormatError(format!("device name not valid UTF-8: {e}"))
                })
            })
    }

    /// Get the raw encrypted bytes.
    pub fn encrypted_bytes(&self) -> &[u8] {
        &self.encrypted_device_name
    }
}

#[cfg(test)]
mod tests {
    use tls_codec::{DeserializeBytes, Serialize};

    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keys = Keys::generate();
        let name = "My iPhone";

        let encrypted = EncryptedDeviceName::encrypt(&keys, name).unwrap();
        let decrypted = encrypted.decrypt(&keys).unwrap();
        assert_eq!(decrypted, name);
    }

    #[test]
    fn test_different_keys_cannot_decrypt() {
        let keys = Keys::generate();
        let other_keys = Keys::generate();

        let encrypted = EncryptedDeviceName::encrypt(&keys, "Desktop").unwrap();
        assert!(encrypted.decrypt(&other_keys).is_err());
    }

    #[test]
    fn test_name_too_long_rejected() {
        let keys = Keys::generate();
        let long_name: String = "a".repeat(65);
        assert!(EncryptedDeviceName::encrypt(&keys, &long_name).is_err());
    }

    #[test]
    fn test_max_length_accepted() {
        let keys = Keys::generate();
        let name: String = "a".repeat(64);
        let encrypted = EncryptedDeviceName::encrypt(&keys, &name).unwrap();
        let decrypted = encrypted.decrypt(&keys).unwrap();
        assert_eq!(decrypted, name);
    }

    #[test]
    fn test_tls_roundtrip() {
        let keys = Keys::generate();
        let encrypted = EncryptedDeviceName::encrypt(&keys, "Laptop").unwrap();

        let mut bytes = Vec::new();
        encrypted.tls_serialize(&mut bytes).unwrap();
        let (decoded, _) = EncryptedDeviceName::tls_deserialize_bytes(&bytes).unwrap();
        assert_eq!(encrypted, decoded);

        // Verify it still decrypts after TLS roundtrip
        let decrypted = decoded.decrypt(&keys).unwrap();
        assert_eq!(decrypted, "Laptop");
    }

    #[test]
    fn test_empty_name_rejected() {
        let keys = Keys::generate();
        // NIP-44 rejects empty plaintext
        assert!(EncryptedDeviceName::encrypt(&keys, "").is_err());
    }

    #[test]
    fn test_unicode_name() {
        let keys = Keys::generate();
        let name = "📱 Danny's iPhone 日本語";
        let encrypted = EncryptedDeviceName::encrypt(&keys, name).unwrap();
        let decrypted = encrypted.decrypt(&keys).unwrap();
        assert_eq!(decrypted, name);
    }

    #[test]
    fn test_max_length_unicode() {
        let keys = Keys::generate();
        // 64 multi-byte characters (each emoji is 1 char)
        let name: String = "🔑".repeat(64);
        assert_eq!(name.chars().count(), 64);
        let encrypted = EncryptedDeviceName::encrypt(&keys, &name).unwrap();
        let decrypted = encrypted.decrypt(&keys).unwrap();
        assert_eq!(decrypted, name);
    }

    #[test]
    fn test_65_chars_rejected_unicode() {
        let keys = Keys::generate();
        let name: String = "🔑".repeat(65);
        assert_eq!(name.chars().count(), 65);
        assert!(EncryptedDeviceName::encrypt(&keys, &name).is_err());
    }

    #[test]
    fn test_encrypted_bytes_non_empty() {
        let keys = Keys::generate();
        let encrypted = EncryptedDeviceName::encrypt(&keys, "Test").unwrap();
        assert!(!encrypted.encrypted_bytes().is_empty());
    }

    #[test]
    fn test_same_name_different_keys_different_ciphertext() {
        let keys1 = Keys::generate();
        let keys2 = Keys::generate();
        let name = "Shared Name";

        let encrypted1 = EncryptedDeviceName::encrypt(&keys1, name).unwrap();
        let encrypted2 = EncryptedDeviceName::encrypt(&keys2, name).unwrap();

        assert_ne!(encrypted1.encrypted_bytes(), encrypted2.encrypted_bytes());
    }

    #[test]
    fn test_same_name_same_keys_different_ciphertext() {
        // NIP-44 uses random padding, so two encryptions should differ
        let keys = Keys::generate();
        let name = "Determinism Check";

        let encrypted1 = EncryptedDeviceName::encrypt(&keys, name).unwrap();
        let encrypted2 = EncryptedDeviceName::encrypt(&keys, name).unwrap();

        // NIP-44 is probabilistic; ciphertexts should (almost certainly) differ
        assert_ne!(encrypted1.encrypted_bytes(), encrypted2.encrypted_bytes());

        // But both decrypt to the same name
        assert_eq!(encrypted1.decrypt(&keys).unwrap(), name);
        assert_eq!(encrypted2.decrypt(&keys).unwrap(), name);
    }
}
