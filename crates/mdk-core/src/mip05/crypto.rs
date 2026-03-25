use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use nostr::secp256k1::rand::{RngCore, rngs::OsRng};
use nostr::{Keys, PublicKey, SecretKey};
use sha2::Sha256;

use super::{
    ENCRYPTED_TOKEN_LEN, Mip05Error, TOKEN_ENCRYPTION_INFO, TOKEN_ENCRYPTION_SALT,
    TOKEN_PLAINTEXT_LEN,
};
use super::{EncryptedToken, PushTokenPlaintext};

const EPHEMERAL_PUBKEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const CIPHERTEXT_OFFSET: usize = EPHEMERAL_PUBKEY_LEN + NONCE_LEN;

/// Encrypt a validated push token using the MIP-05 wire format.
pub fn encrypt_push_token(
    server_pubkey: &PublicKey,
    plaintext: &PushTokenPlaintext,
) -> Result<EncryptedToken, Mip05Error> {
    let ephemeral_keys = Keys::generate();
    let token_padding_len = TOKEN_PLAINTEXT_LEN
        .checked_sub(3 + plaintext.device_token().len())
        .ok_or(Mip05Error::InvalidTokenPaddingLength)?;

    let mut nonce = [0u8; 12];
    let mut padding = vec![0u8; token_padding_len];
    OsRng.fill_bytes(&mut nonce);
    OsRng.fill_bytes(&mut padding);

    encrypt_push_token_with_materials(
        server_pubkey,
        plaintext,
        ephemeral_keys.secret_key().clone(),
        nonce,
        &padding,
    )
}

/// Decrypt a fixed-size MIP-05 encrypted token.
pub fn decrypt_push_token(
    server_secret_key: &SecretKey,
    encrypted_token: &EncryptedToken,
) -> Result<PushTokenPlaintext, Mip05Error> {
    let bytes = encrypted_token.as_bytes();
    let ephemeral_pubkey = PublicKey::from_slice(&bytes[..EPHEMERAL_PUBKEY_LEN])
        .map_err(|_| Mip05Error::InvalidEncryptedTokenPublicKey)?;
    let nonce_bytes: [u8; NONCE_LEN] = bytes[EPHEMERAL_PUBKEY_LEN..CIPHERTEXT_OFFSET]
        .try_into()
        .map_err(|_| Mip05Error::InvalidEncryptedTokenNonce)?;
    let ciphertext = &bytes[CIPHERTEXT_OFFSET..];

    let key = derive_encryption_key(server_secret_key, &ephemeral_pubkey)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: b"",
            },
        )
        .map_err(|_| Mip05Error::DecryptionFailed)?;

    PushTokenPlaintext::from_padded_slice(&plaintext)
}

fn derive_encryption_key(
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<[u8; 32], Mip05Error> {
    let shared_x = nostr::util::generate_shared_key(secret_key, public_key)
        .map_err(|_| Mip05Error::KeyDerivationFailed)?;
    let hkdf = Hkdf::<Sha256>::new(Some(TOKEN_ENCRYPTION_SALT), &shared_x);
    let mut encryption_key = [0u8; 32];
    hkdf.expand(TOKEN_ENCRYPTION_INFO, &mut encryption_key)
        .map_err(|_| Mip05Error::KeyDerivationFailed)?;
    Ok(encryption_key)
}

fn encrypt_push_token_with_materials(
    server_pubkey: &PublicKey,
    plaintext: &PushTokenPlaintext,
    ephemeral_secret_key: SecretKey,
    nonce_bytes: [u8; 12],
    padding: &[u8],
) -> Result<EncryptedToken, Mip05Error> {
    let ephemeral_keys = Keys::new(ephemeral_secret_key);
    let key = derive_encryption_key(ephemeral_keys.secret_key(), server_pubkey)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let padded_plaintext = plaintext.encode_padded(padding)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &padded_plaintext,
                aad: b"",
            },
        )
        .map_err(|_| Mip05Error::EncryptionFailed)?;

    if ciphertext.len() != ENCRYPTED_TOKEN_LEN - EPHEMERAL_PUBKEY_LEN - NONCE_LEN {
        return Err(Mip05Error::InvalidCiphertextLength);
    }

    let mut bytes = [0u8; ENCRYPTED_TOKEN_LEN];
    bytes[..EPHEMERAL_PUBKEY_LEN].copy_from_slice(ephemeral_keys.public_key().as_bytes());
    bytes[EPHEMERAL_PUBKEY_LEN..CIPHERTEXT_OFFSET].copy_from_slice(&nonce_bytes);
    bytes[CIPHERTEXT_OFFSET..].copy_from_slice(&ciphertext);

    Ok(EncryptedToken::from(bytes))
}

#[cfg(test)]
mod tests {
    use nostr::{Keys, SecretKey};

    use super::*;
    use crate::mip05::NotificationPlatform;

    #[test]
    fn test_encrypt_push_token_roundtrip_apns() {
        let server_keys = Keys::generate();
        let plaintext =
            PushTokenPlaintext::new(NotificationPlatform::Apns, vec![0xAB; 32]).unwrap();

        let encrypted = encrypt_push_token(&server_keys.public_key(), &plaintext).unwrap();
        let decrypted = decrypt_push_token(server_keys.secret_key(), &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(encrypted.as_bytes().len(), ENCRYPTED_TOKEN_LEN);
    }

    #[test]
    fn test_encrypt_push_token_roundtrip_fcm() {
        let server_keys = Keys::generate();
        let plaintext =
            PushTokenPlaintext::new(NotificationPlatform::Fcm, b"firebase-token".to_vec()).unwrap();

        let encrypted = encrypt_push_token(&server_keys.public_key(), &plaintext).unwrap();
        let decrypted = decrypt_push_token(server_keys.secret_key(), &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_push_token_uses_expected_wire_layout() {
        let server_secret_key =
            SecretKey::parse("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let server_keys = Keys::new(server_secret_key);
        let ephemeral_secret_key =
            SecretKey::parse("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();
        let plaintext =
            PushTokenPlaintext::new(NotificationPlatform::Apns, vec![0xCD; 32]).unwrap();
        let nonce = [0x55; 12];
        let padding = vec![0x99; TOKEN_PLAINTEXT_LEN - 35];

        let encrypted = encrypt_push_token_with_materials(
            &server_keys.public_key(),
            &plaintext,
            ephemeral_secret_key.clone(),
            nonce,
            &padding,
        )
        .unwrap();
        let ephemeral_keys = Keys::new(ephemeral_secret_key);

        assert_eq!(
            &encrypted.as_bytes()[..EPHEMERAL_PUBKEY_LEN],
            ephemeral_keys.public_key().as_bytes()
        );
        assert_eq!(
            &encrypted.as_bytes()[EPHEMERAL_PUBKEY_LEN..CIPHERTEXT_OFFSET],
            &nonce
        );
        assert_eq!(encrypted.as_bytes().len(), ENCRYPTED_TOKEN_LEN);

        let decrypted = decrypt_push_token(server_keys.secret_key(), &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_push_token_rejects_tampering() {
        let server_keys = Keys::generate();
        let plaintext =
            PushTokenPlaintext::new(NotificationPlatform::Fcm, b"firebase-token".to_vec()).unwrap();
        let mut tampered = encrypt_push_token(&server_keys.public_key(), &plaintext)
            .unwrap()
            .as_bytes()
            .to_vec();
        tampered[90] ^= 0x01;
        let tampered = EncryptedToken::from_slice(&tampered).unwrap();

        assert!(decrypt_push_token(server_keys.secret_key(), &tampered).is_err());
    }

    #[test]
    fn test_decrypt_push_token_rejects_invalid_plaintext_platform() {
        let server_secret_key =
            SecretKey::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let server_keys = Keys::new(server_secret_key);
        let ephemeral_secret_key =
            SecretKey::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        let mut invalid_plaintext = [0u8; TOKEN_PLAINTEXT_LEN];
        invalid_plaintext[0] = 0x77;
        invalid_plaintext[1..3].copy_from_slice(&32u16.to_be_bytes());
        invalid_plaintext[3..35].copy_from_slice(&[0x11; 32]);
        let nonce = [0x44; 12];
        let encrypted = encrypt_raw_plaintext(
            &server_keys.public_key(),
            invalid_plaintext,
            ephemeral_secret_key,
            nonce,
        )
        .unwrap();

        assert!(decrypt_push_token(server_keys.secret_key(), &encrypted).is_err());
    }

    fn encrypt_raw_plaintext(
        server_pubkey: &PublicKey,
        plaintext: [u8; TOKEN_PLAINTEXT_LEN],
        ephemeral_secret_key: SecretKey,
        nonce_bytes: [u8; 12],
    ) -> Result<EncryptedToken, Mip05Error> {
        let ephemeral_keys = Keys::new(ephemeral_secret_key);
        let key = derive_encryption_key(ephemeral_keys.secret_key(), server_pubkey)?;
        let cipher = ChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plaintext,
                    aad: b"",
                },
            )
            .map_err(|_| Mip05Error::EncryptionFailed)?;
        let mut bytes = [0u8; ENCRYPTED_TOKEN_LEN];
        bytes[..EPHEMERAL_PUBKEY_LEN].copy_from_slice(ephemeral_keys.public_key().as_bytes());
        bytes[EPHEMERAL_PUBKEY_LEN..CIPHERTEXT_OFFSET].copy_from_slice(&nonce_bytes);
        bytes[CIPHERTEXT_OFFSET..].copy_from_slice(&ciphertext);
        Ok(EncryptedToken::from(bytes))
    }
}
