//! MIP-06 pairing message encryption/decryption.
//!
//! Uses X25519 + HKDF-SHA256 + ChaCha20-Poly1305 as specified in MIP-06 §Phase 2.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use nostr::secp256k1::rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::Error;

/// Domain-separation salt for HKDF-Extract.
const HKDF_SALT: &[u8] = b"marmot-pairing-v1";

/// Info string for HKDF-Expand.
const HKDF_INFO: &[u8] = b"marmot-pairing-key";

/// AAD prefix.
const AAD_PREFIX: &[u8] = b"marmot-pairing-v1";

/// An encrypted pairing message as sent over the wire.
///
/// Wire format: `existing_ephemeral_pubkey[32] || nonce[12] || ciphertext`
#[derive(Debug, Clone)]
pub struct PairingMessage {
    /// The existing device's ephemeral X25519 public key.
    pub existing_ephemeral_pubkey: [u8; 32],
    /// The 12-byte nonce.
    pub nonce: [u8; 12],
    /// The ChaCha20-Poly1305 ciphertext (includes 16-byte tag).
    pub ciphertext: Vec<u8>,
}

impl PairingMessage {
    /// Minimum message size: 32 (pubkey) + 12 (nonce) + 16 (tag) = 60 bytes.
    const MIN_SIZE: usize = 32 + 12 + 16;

    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 12 + self.ciphertext.len());
        buf.extend_from_slice(&self.existing_ephemeral_pubkey);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Parse from wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < Self::MIN_SIZE {
            return Err(Error::PairingError(format!(
                "pairing message too short: {} bytes (min {})",
                bytes.len(),
                Self::MIN_SIZE
            )));
        }

        let mut existing_ephemeral_pubkey = [0u8; 32];
        existing_ephemeral_pubkey.copy_from_slice(&bytes[..32]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[32..44]);

        let ciphertext = bytes[44..].to_vec();

        Ok(Self {
            existing_ephemeral_pubkey,
            nonce,
            ciphertext,
        })
    }
}

/// Build the AAD for pairing encryption.
///
/// `aad = "marmot-pairing-v1" || new_ephemeral_pubkey || existing_ephemeral_pubkey`
fn build_aad(new_ephemeral_pubkey: &[u8; 32], existing_ephemeral_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 32 + 32);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(new_ephemeral_pubkey);
    aad.extend_from_slice(existing_ephemeral_pubkey);
    aad
}

/// Derive the encryption key from a shared secret.
fn derive_key(shared_secret: &[u8; 32]) -> Result<[u8; 32], Error> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|e| Error::PairingError(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Check that a shared secret is not all-zero (low-order point rejection).
fn reject_zero_shared_secret(shared_secret: &[u8; 32]) -> Result<(), Error> {
    if shared_secret.iter().all(|&b| b == 0) {
        return Err(Error::PairingError(
            "X25519 shared secret is all-zero (low-order point)".to_string(),
        ));
    }
    Ok(())
}

/// Encrypt a pairing payload (existing device → new device).
///
/// The existing device:
/// 1. Generates a fresh X25519 ephemeral keypair
/// 2. Computes `shared_secret = X25519(existing_priv, new_pub)`
/// 3. Derives encryption key via HKDF-SHA256
/// 4. Encrypts with ChaCha20-Poly1305 and AAD
///
/// Returns the existing device's ephemeral public key and the encrypted message.
pub fn encrypt_pairing_message(
    plaintext: &[u8],
    new_ephemeral_pubkey: &[u8; 32],
) -> Result<
    (
        /* existing_ephemeral_pubkey */ [u8; 32],
        PairingMessage,
    ),
    Error,
> {
    let existing_secret = StaticSecret::random_from_rng(OsRng);
    let existing_pubkey = X25519PublicKey::from(&existing_secret);
    let existing_pubkey_bytes: [u8; 32] = existing_pubkey.to_bytes();

    let new_pubkey = X25519PublicKey::from(*new_ephemeral_pubkey);
    let mut shared_secret: [u8; 32] = existing_secret.diffie_hellman(&new_pubkey).to_bytes();

    reject_zero_shared_secret(&shared_secret)?;

    let mut key = derive_key(&shared_secret)?;
    shared_secret.zeroize();

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let aad = build_aad(new_ephemeral_pubkey, &existing_pubkey_bytes);

    let cipher = ChaCha20Poly1305::new((&key).into());
    key.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| Error::PairingError(format!("encryption failed: {e}")))?;

    let message = PairingMessage {
        existing_ephemeral_pubkey: existing_pubkey_bytes,
        nonce: nonce_bytes,
        ciphertext,
    };

    Ok((existing_pubkey_bytes, message))
}

/// Decrypt a pairing message (new device side).
///
/// The new device:
/// 1. Extracts `existing_ephemeral_pubkey` from the message
/// 2. Computes `shared_secret = X25519(new_priv, existing_pub)`
/// 3. Derives decryption key via HKDF-SHA256
/// 4. Decrypts and verifies with ChaCha20-Poly1305 and AAD
pub fn decrypt_pairing_message(
    message: &PairingMessage,
    new_ephemeral_privkey: &StaticSecret,
    new_ephemeral_pubkey: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let existing_pubkey = X25519PublicKey::from(message.existing_ephemeral_pubkey);
    let mut shared_secret: [u8; 32] = new_ephemeral_privkey
        .diffie_hellman(&existing_pubkey)
        .to_bytes();

    reject_zero_shared_secret(&shared_secret)?;

    let mut key = derive_key(&shared_secret)?;
    shared_secret.zeroize();

    let aad = build_aad(new_ephemeral_pubkey, &message.existing_ephemeral_pubkey);

    let cipher = ChaCha20Poly1305::new((&key).into());
    key.zeroize();

    let nonce = Nonce::from_slice(&message.nonce);
    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &message.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| Error::PairingError(format!("decryption failed: {e}")))?;

    Ok(plaintext)
}

/// Generate a fresh X25519 keypair for the new device's pairing session.
///
/// Returns `(private_key, public_key_bytes)`.
/// The caller MUST securely delete the private key after the pairing session.
pub fn generate_new_device_keypair() -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let pubkey = X25519PublicKey::from(&secret);
    (secret, pubkey.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (new_priv, new_pub) = generate_new_device_keypair();
        let plaintext = b"hello multi-device world";

        let (_existing_pub, message) = encrypt_pairing_message(plaintext, &new_pub).unwrap();

        let decrypted = decrypt_pairing_message(&message, &new_priv, &new_pub).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let (new_priv, new_pub) = generate_new_device_keypair();
        let (wrong_priv, wrong_pub) = generate_new_device_keypair();
        let plaintext = b"secret data";

        let (_existing_pub, message) = encrypt_pairing_message(plaintext, &new_pub).unwrap();

        // Decrypt with wrong private key should fail
        let result = decrypt_pairing_message(&message, &wrong_priv, &new_pub);
        assert!(result.is_err());

        // Decrypt with wrong pubkey in AAD should also fail
        let result = decrypt_pairing_message(&message, &new_priv, &wrong_pub);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (new_priv, new_pub) = generate_new_device_keypair();
        let plaintext = b"important pairing data";

        let (_existing_pub, mut message) = encrypt_pairing_message(plaintext, &new_pub).unwrap();

        // Tamper with ciphertext
        if let Some(byte) = message.ciphertext.last_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt_pairing_message(&message, &new_priv, &new_pub);
        assert!(result.is_err());
    }

    #[test]
    fn test_pairing_message_wire_format_roundtrip() {
        let (new_priv, new_pub) = generate_new_device_keypair();
        let plaintext = b"wire format test";

        let (_existing_pub, message) = encrypt_pairing_message(plaintext, &new_pub).unwrap();

        let wire_bytes = message.to_bytes();
        let parsed = PairingMessage::from_bytes(&wire_bytes).unwrap();

        assert_eq!(
            parsed.existing_ephemeral_pubkey,
            message.existing_ephemeral_pubkey
        );
        assert_eq!(parsed.nonce, message.nonce);
        assert_eq!(parsed.ciphertext, message.ciphertext);

        // Decrypt the parsed message
        let decrypted = decrypt_pairing_message(&parsed, &new_priv, &new_pub).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_message_too_short() {
        assert!(PairingMessage::from_bytes(&[0u8; 59]).is_err());
        assert!(PairingMessage::from_bytes(&[0u8; 60]).is_ok());
    }
}
