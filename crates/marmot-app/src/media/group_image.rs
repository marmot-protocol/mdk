use std::fmt;
use std::io::Cursor;

use bytes::Bytes;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use cgka_traits::app_components::canonicalize_marmot_media_type;

use super::DEFAULT_BLOSSOM_SERVER_URL;
use super::blossom::{
    BlossomHttpTransport, blossom_blob_url, fetch_blossom_blob_with_transport, upload_blossom_blob,
};
use crate::{AppError, AppGroupImageInput};

const GROUP_IMAGE_VERSION: &str = "marmot-group-image-v1";

/// Maximum encoded group-avatar source size accepted before encryption.
pub const MAX_GROUP_IMAGE_BYTES: usize = 10 * 1024 * 1024;
/// Maximum width or height accepted for a group avatar.
pub const MAX_GROUP_IMAGE_DIMENSION: u32 = 4096;
/// Maximum decoded pixel count accepted for a group avatar.
pub const MAX_GROUP_IMAGE_PIXELS: u64 = 16_777_216;

fn canonical_group_image_media_type(value: &str) -> Result<String, AppError> {
    canonicalize_marmot_media_type(value).map_err(AppError::InvalidEncryptedMedia)
}

fn validate_group_image_input(plaintext: &[u8], media_type: &str) -> Result<String, AppError> {
    if plaintext.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "group image cannot be empty".into(),
        ));
    }
    if plaintext.len() > MAX_GROUP_IMAGE_BYTES {
        return Err(AppError::InvalidEncryptedMedia(format!(
            "group image exceeds {MAX_GROUP_IMAGE_BYTES}-byte size limit"
        )));
    }
    let media_type = canonical_group_image_media_type(media_type)?;
    let reader = image::ImageReader::new(Cursor::new(plaintext))
        .with_guessed_format()
        .map_err(|_| AppError::InvalidEncryptedMedia("group image format is invalid".into()))?;
    let detected_format = reader.format().ok_or_else(|| {
        AppError::InvalidEncryptedMedia("group image format is not recognized".into())
    })?;
    let declared_format = match media_type.as_str() {
        "image/png" => image::ImageFormat::Png,
        "image/jpeg" => image::ImageFormat::Jpeg,
        "image/gif" => image::ImageFormat::Gif,
        "image/webp" => image::ImageFormat::WebP,
        _ => {
            return Err(AppError::InvalidEncryptedMedia(
                "group image media type is not supported".into(),
            ));
        }
    };
    if detected_format != declared_format {
        return Err(AppError::InvalidEncryptedMedia(
            "group image media type does not match its bytes".into(),
        ));
    }
    let (width, height) = reader.into_dimensions().map_err(|_| {
        AppError::InvalidEncryptedMedia("group image dimensions cannot be decoded".into())
    })?;
    let pixels = u64::from(width).saturating_mul(u64::from(height));
    if width > MAX_GROUP_IMAGE_DIMENSION
        || height > MAX_GROUP_IMAGE_DIMENSION
        || pixels > MAX_GROUP_IMAGE_PIXELS
    {
        return Err(AppError::InvalidEncryptedMedia(format!(
            "group image dimensions exceed {MAX_GROUP_IMAGE_DIMENSION}px or {MAX_GROUP_IMAGE_PIXELS} pixels"
        )));
    }
    Ok(media_type)
}

/// Result of encrypting + uploading a group avatar. Maps directly onto the
/// `marmot.group.blossom.image.v1` component fields. Unlike message media, the
/// content key travels in-band inside the (MLS-protected) component, so the
/// image is self-contained and content-addressed by `image_hash_hex` — no URL
/// or file name is stored.
///
/// `image_key_hex` (avatar decryption key) and `image_upload_key_hex` (Blossom
/// upload secret) are key material. They deliberately flow onward into the
/// MLS-protected component bytes and the SQLCipher-protected projections, but
/// must never be logged or `Debug`-rendered — do not add a `Debug` derive
/// here, and keep the raw key buffers in `upload_group_image`/
/// `fetch_group_image_with_transport` wrapped in `Zeroizing`.
pub(crate) struct GroupImageUpload {
    pub(crate) image_hash_hex: String,
    pub(crate) image_key_hex: String,
    pub(crate) image_nonce_hex: String,
    pub(crate) image_upload_key_hex: String,
    pub(crate) media_type: String,
}

pub(crate) struct PreparedGroupImageUpload {
    pub(crate) input: AppGroupImageInput,
    pub(crate) encrypted_blob: Vec<u8>,
    pub(crate) upload_secret: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for PreparedGroupImageUpload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedGroupImageUpload")
            .field("encrypted_blob_len", &self.encrypted_blob.len())
            .field("has_upload_secret", &true)
            .finish()
    }
}

impl From<GroupImageUpload> for AppGroupImageInput {
    fn from(upload: GroupImageUpload) -> Self {
        Self {
            image_hash_hex: upload.image_hash_hex,
            image_key_hex: upload.image_key_hex,
            image_nonce_hex: upload.image_nonce_hex,
            image_upload_key_hex: upload.image_upload_key_hex,
            media_type: Some(upload.media_type),
        }
    }
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
    let prepared = prepare_group_image_upload(plaintext, media_type)?;
    upload_prepared_group_image(
        prepared.encrypted_blob,
        &prepared.input.image_hash_hex,
        prepared.upload_secret,
        server,
        false,
    )
    .await?;
    Ok(GroupImageUpload {
        image_hash_hex: prepared.input.image_hash_hex,
        image_key_hex: prepared.input.image_key_hex,
        image_nonce_hex: prepared.input.image_nonce_hex,
        image_upload_key_hex: prepared.input.image_upload_key_hex,
        media_type: prepared.input.media_type.unwrap_or_default(),
    })
}

pub(crate) fn prepare_group_image_upload(
    plaintext: &[u8],
    media_type: &str,
) -> Result<PreparedGroupImageUpload, AppError> {
    let media_type = validate_group_image_input(plaintext, media_type)?;
    let mut content_key = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(content_key.as_mut());
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let aad = group_image_aad(&media_type);
    let cipher = ChaCha20Poly1305::new_from_slice(content_key.as_ref())
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
    let upload_secret = Zeroizing::new(upload_keys.secret_key().to_secret_bytes().to_vec());
    let image_upload_key_hex = hex::encode(&upload_secret);
    Ok(PreparedGroupImageUpload {
        encrypted_blob: encrypted,
        upload_secret,
        input: AppGroupImageInput {
            image_hash_hex: encrypted_hash_hex,
            image_key_hex: hex::encode(&content_key),
            image_nonce_hex: hex::encode(nonce),
            // The same upload key is carried in the MLS-protected component so
            // group members can manage the content-addressed blob later.
            image_upload_key_hex,
            media_type: Some(media_type),
        },
    })
}

pub(crate) async fn upload_prepared_group_image(
    encrypted_blob: Vec<u8>,
    image_hash_hex: &str,
    upload_secret: Zeroizing<Vec<u8>>,
    server: Option<&str>,
    allow_loopback_http: bool,
) -> Result<(), AppError> {
    let secret = nostr::SecretKey::from_slice(&upload_secret)
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid group image upload key".into()))?;
    let upload_keys = nostr::Keys::new(secret);
    let server = server.unwrap_or(DEFAULT_BLOSSOM_SERVER_URL);
    upload_blossom_blob(
        server,
        Bytes::from(encrypted_blob),
        image_hash_hex,
        &upload_keys,
        allow_loopback_http,
    )
    .await?;
    Ok(())
}

/// Fetch a group avatar's ciphertext from Blossom (addressed by `image_hash_hex`)
/// and decrypt it with the in-band content key + nonce.
pub(crate) async fn fetch_group_image_with_transport(
    image_hash_hex: &str,
    image_key_hex: &str,
    image_nonce_hex: &str,
    media_type: &str,
    server: Option<&str>,
    transport: &BlossomHttpTransport,
) -> Result<Vec<u8>, AppError> {
    let media_type = canonical_group_image_media_type(media_type)?;
    let content_key: Zeroizing<[u8; 32]> = Zeroizing::new(
        Zeroizing::new(hex::decode(image_key_hex)?)
            .as_slice()
            .try_into()
            .map_err(|_| {
                AppError::InvalidEncryptedMedia("group image key must be 32 bytes".to_owned())
            })?,
    );
    let nonce: [u8; 12] = hex::decode(image_nonce_hex)?.try_into().map_err(|_| {
        AppError::InvalidEncryptedMedia("group image nonce must be 12 bytes".into())
    })?;
    let server = server.unwrap_or(DEFAULT_BLOSSOM_SERVER_URL);
    let url = blossom_blob_url(server, &image_hash_hex.to_ascii_lowercase());
    // Group images are content-addressed over the public default Blossom server
    // and are not part of the loopback-blob-endpoint dev/test path, so loopback
    // HTTP is never permitted here.
    let encrypted =
        fetch_blossom_blob_with_transport(&url, &transport.with_loopback_disabled()).await?;
    let actual_hash = hex::encode(Sha256::digest(&encrypted));
    if actual_hash != image_hash_hex.to_ascii_lowercase() {
        return Err(AppError::InvalidEncryptedMedia(
            "group image blob hash does not match component".into(),
        ));
    }
    let aad = group_image_aad(&media_type);
    let cipher = ChaCha20Poly1305::new_from_slice(content_key.as_ref())
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{Mutex, Notify};

    use super::{
        MAX_GROUP_IMAGE_BYTES, MAX_GROUP_IMAGE_DIMENSION, prepare_group_image_upload,
        upload_prepared_group_image, validate_group_image_input,
    };

    fn png(width: u32, height: u32) -> Vec<u8> {
        use image::ImageEncoder;

        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(
                &vec![0_u8; width as usize * height as usize * 4],
                width,
                height,
                image::ExtendedColorType::Rgba8,
            )
            .unwrap();
        bytes
    }

    async fn read_upload(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..read]);
            if let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset + 4;
            }
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap();
        let hash = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("x-sha-256")
                    .then(|| value.trim().to_owned())
            })
            .unwrap();
        while request.len() < header_end + content_length {
            let read = stream.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..read]);
        }
        (
            hash,
            request[header_end..header_end + content_length].to_vec(),
        )
    }

    async fn write_response(stream: &mut tokio::net::TcpStream, status: u16, body: &str) {
        let reason = if status == 201 {
            "Created"
        } else {
            "Server Error"
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }

    #[test]
    fn group_image_rejects_payload_larger_than_budget_before_encryption() {
        let oversized = vec![0_u8; MAX_GROUP_IMAGE_BYTES + 1];
        let error = validate_group_image_input(&oversized, "image/png")
            .expect_err("oversized group image must be rejected");
        assert!(error.to_string().contains("size limit"));
    }

    #[test]
    fn group_image_accepts_payload_at_exact_byte_budget() {
        let mut maximum = png(1, 1);
        maximum.resize(MAX_GROUP_IMAGE_BYTES, 0);
        validate_group_image_input(&maximum, "image/png")
            .expect("the exact byte-limit image remains accepted");
    }

    #[test]
    fn group_image_rejects_declared_type_mismatch() {
        let error = validate_group_image_input(&png(1, 1), "image/jpeg")
            .expect_err("declared type must match encoded bytes");
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn group_image_rejects_media_types_outside_avatar_allowlist() {
        let error = validate_group_image_input(&png(1, 1), "image/tiff")
            .expect_err("non-avatar image media types must be rejected explicitly");
        assert!(error.to_string().contains("not supported"));
    }

    #[test]
    fn group_image_rejects_dimension_over_budget() {
        let oversized = png(MAX_GROUP_IMAGE_DIMENSION + 1, 1);
        let error = validate_group_image_input(&oversized, "image/png")
            .expect_err("oversized dimension must be rejected");
        assert!(error.to_string().contains("dimensions exceed"));
    }

    #[test]
    fn prepared_group_image_debug_redacts_keys_hash_and_ciphertext() {
        let prepared = prepare_group_image_upload(&png(1, 1), "image/png").unwrap();
        let debug = format!("{prepared:?}");
        assert!(!debug.contains(&prepared.input.image_hash_hex));
        assert!(!debug.contains(&prepared.input.image_key_hex));
        assert!(!debug.contains(&prepared.input.image_nonce_hex));
        assert!(!debug.contains(&prepared.input.image_upload_key_hex));
    }

    #[tokio::test]
    async fn prepared_upload_retry_reuses_exact_ciphertext_and_hash() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let statuses = Arc::new(Mutex::new(VecDeque::from([500_u16, 201_u16])));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let server_statuses = statuses.clone();
        let server_observed = observed.clone();
        let server_url = url.clone();
        let server = tokio::spawn(async move {
            while let Some(status) = server_statuses.lock().await.pop_front() {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (hash, body) = read_upload(&mut stream).await;
                server_observed.lock().await.push((hash.clone(), body));
                let descriptor = serde_json::json!({
                    "url": format!("{server_url}/{hash}.bin"),
                    "sha256": hash,
                })
                .to_string();
                write_response(&mut stream, status, &descriptor).await;
            }
        });

        let prepared = prepare_group_image_upload(&png(2, 2), "image/png").unwrap();
        let hash = prepared.input.image_hash_hex.clone();
        let first = upload_prepared_group_image(
            prepared.encrypted_blob.clone(),
            &hash,
            prepared.upload_secret.clone(),
            Some(&url),
            true,
        )
        .await;
        assert!(first.is_err());
        upload_prepared_group_image(
            prepared.encrypted_blob,
            &hash,
            prepared.upload_secret,
            Some(&url),
            true,
        )
        .await
        .unwrap();
        server.await.unwrap();

        let observed = observed.lock().await;
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0], observed[1]);
        assert_eq!(observed[0].0, hash);
    }

    #[tokio::test]
    async fn stalled_prepared_upload_is_cancellable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let accepted = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let server_accepted = accepted.clone();
        let server_release = release.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_upload(&mut stream).await;
            server_accepted.notify_one();
            server_release.notified().await;
        });
        let prepared = prepare_group_image_upload(&png(2, 2), "image/png").unwrap();
        let hash = prepared.input.image_hash_hex.clone();
        let upload_url = url.clone();
        let upload = tokio::spawn(async move {
            upload_prepared_group_image(
                prepared.encrypted_blob,
                &hash,
                prepared.upload_secret,
                Some(&upload_url),
                true,
            )
            .await
        });
        accepted.notified().await;
        upload.abort();
        assert!(upload.await.unwrap_err().is_cancelled());
        release.notify_one();
        server.await.unwrap();
    }
}
