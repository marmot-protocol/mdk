use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use super::DEFAULT_BLOSSOM_SERVER_URL;
use super::blossom::{blossom_blob_url, fetch_blossom_blob, upload_blossom_blob};
use super::crypto::canonical_media_type;
use crate::AppError;

const GROUP_IMAGE_VERSION: &str = "marmot-group-image-v1";

/// Result of encrypting + uploading a group avatar. Maps directly onto the
/// `marmot.group.blossom.image.v1` component fields. Unlike message media, the
/// content key travels in-band inside the (MLS-protected) component, so the
/// image is self-contained and content-addressed by `image_hash_hex` — no URL
/// or file name is stored.
pub(crate) struct GroupImageUpload {
    pub(crate) image_hash_hex: String,
    pub(crate) image_key_hex: String,
    pub(crate) image_nonce_hex: String,
    pub(crate) image_upload_key_hex: String,
    pub(crate) media_type: String,
}

fn group_image_aad(media_type: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(GROUP_IMAGE_VERSION.len() + 1 + media_type.len());
    aad.extend_from_slice(GROUP_IMAGE_VERSION.as_bytes());
    aad.push(0);
    aad.extend_from_slice(media_type.as_bytes());
    aad
}

/// Encrypt a group avatar with a fresh random content key + nonce and upload the
/// ciphertext to Blossom. The Blossom upload is authorized by a freshly generated
/// Nostr keypair whose secret is returned as `image_upload_key_hex`, so any group
/// member holding the (in-band) component can later manage the blob.
pub(crate) async fn upload_group_image(
    plaintext: &[u8],
    media_type: &str,
    server: Option<&str>,
) -> Result<GroupImageUpload, AppError> {
    if plaintext.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "group image cannot be empty".into(),
        ));
    }
    let media_type = canonical_media_type(media_type)?;
    if media_type.len() > 128 {
        return Err(AppError::InvalidEncryptedMedia(
            "group image media type must be at most 128 bytes".into(),
        ));
    }
    let mut content_key = [0_u8; 32];
    OsRng.fill_bytes(&mut content_key);
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let aad = group_image_aad(&media_type);
    let cipher = ChaCha20Poly1305::new_from_slice(&content_key)
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid group image key length".into()))?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::InvalidEncryptedMedia("group image encryption failed".into()))?;
    let encrypted_hash_hex = hex::encode(Sha256::digest(&encrypted));
    let upload_keys = nostr::Keys::generate();
    let server = server.unwrap_or(DEFAULT_BLOSSOM_SERVER_URL);
    // Group images upload to the public default Blossom server and are not part
    // of the loopback-blob-endpoint dev/test path, so loopback HTTP is never
    // permitted here.
    upload_blossom_blob(server, &encrypted, &encrypted_hash_hex, &upload_keys, false).await?;
    Ok(GroupImageUpload {
        image_hash_hex: encrypted_hash_hex,
        image_key_hex: hex::encode(content_key),
        image_nonce_hex: hex::encode(nonce),
        image_upload_key_hex: hex::encode(upload_keys.secret_key().to_secret_bytes()),
        media_type,
    })
}

/// Fetch a group avatar's ciphertext from Blossom (addressed by `image_hash_hex`)
/// and decrypt it with the in-band content key + nonce.
pub(crate) async fn fetch_group_image(
    image_hash_hex: &str,
    image_key_hex: &str,
    image_nonce_hex: &str,
    media_type: &str,
    server: Option<&str>,
) -> Result<Vec<u8>, AppError> {
    let media_type = canonical_media_type(media_type)?;
    let content_key: [u8; 32] = hex::decode(image_key_hex)?
        .try_into()
        .map_err(|_| AppError::InvalidEncryptedMedia("group image key must be 32 bytes".into()))?;
    let nonce: [u8; 12] = hex::decode(image_nonce_hex)?.try_into().map_err(|_| {
        AppError::InvalidEncryptedMedia("group image nonce must be 12 bytes".into())
    })?;
    let server = server.unwrap_or(DEFAULT_BLOSSOM_SERVER_URL);
    let url = blossom_blob_url(server, &image_hash_hex.to_ascii_lowercase());
    // Group images are content-addressed over the public default Blossom server
    // and are not part of the loopback-blob-endpoint dev/test path, so loopback
    // HTTP is never permitted here.
    let encrypted = fetch_blossom_blob(&url, false).await?;
    let actual_hash = hex::encode(Sha256::digest(&encrypted));
    if actual_hash != image_hash_hex.to_ascii_lowercase() {
        return Err(AppError::InvalidEncryptedMedia(
            "group image blob hash does not match component".into(),
        ));
    }
    let aad = group_image_aad(&media_type);
    let cipher = ChaCha20Poly1305::new_from_slice(&content_key)
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid group image key length".into()))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &encrypted,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::InvalidEncryptedMedia("group image decryption failed".into()))
}
