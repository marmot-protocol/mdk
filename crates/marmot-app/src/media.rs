use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use cgka_traits::app_components::{
    BLOSSOM_LOCATOR_KIND_V1, BlobStoreEndpointV1, ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN,
    ENCRYPTED_MEDIA_FORMAT_V1,
};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use nostr::{EventBuilder, JsonUtil, Kind, Tag, Timestamp as NostrTimestamp};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::{AppError, SendSummary, unix_now_seconds};

pub const DEFAULT_BLOSSOM_SERVER_URL: &str = "https://blossom.primal.net";
pub const ENCRYPTED_MEDIA_VERSION: &str = ENCRYPTED_MEDIA_FORMAT_V1;
const BLOSSOM_UPLOAD_AUTH_TTL: Duration = Duration::from_secs(10 * 60);
const BLOSSOM_UPLOAD_CONTENT_TYPE: &str = "application/octet-stream";
const MEDIA_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MEDIA_HTTP_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MEDIA_HTTP_TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ENCRYPTED_MEDIA_BLOB_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaLocator {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaAttachmentReference {
    pub locators: Vec<MediaLocator>,
    pub ciphertext_sha256: String,
    pub plaintext_sha256: String,
    pub nonce_hex: String,
    pub file_name: String,
    pub media_type: String,
    pub version: String,
    pub source_epoch: u64,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

impl MediaAttachmentReference {
    pub(crate) fn validate(&self) -> Result<(), AppError> {
        validate_sha256_hex(&self.ciphertext_sha256, "media ciphertext_sha256")?;
        validate_sha256_hex(&self.plaintext_sha256, "media plaintext_sha256")?;
        let expected_ciphertext_sha256 = self.ciphertext_sha256.to_ascii_lowercase();
        let nonce = hex::decode(&self.nonce_hex)
            .map_err(|_| AppError::InvalidAppMessagePayload("media nonce must be hex".into()))?;
        if nonce.len() != 12 {
            return Err(AppError::InvalidAppMessagePayload(
                "media nonce must be 12 bytes".into(),
            ));
        }
        if self.locators.is_empty() {
            return Err(AppError::InvalidAppMessagePayload(
                "media attachment must include at least one locator".into(),
            ));
        }
        for locator in &self.locators {
            validate_locator(locator)?;
            let locator_hash = blossom_content_hash_from_url(&locator.value).ok_or_else(|| {
                AppError::InvalidAppMessagePayload(
                    "Blossom locator URL must include the encrypted blob hash".into(),
                )
            })?;
            if locator_hash != expected_ciphertext_sha256 {
                return Err(AppError::InvalidAppMessagePayload(
                    "Blossom locator hash does not match media reference".into(),
                ));
            }
        }
        if self.file_name.trim().is_empty() {
            return Err(AppError::InvalidAppMessagePayload(
                "media file name cannot be empty".into(),
            ));
        }
        canonical_media_type(&self.media_type)?;
        if self.version != ENCRYPTED_MEDIA_VERSION {
            return Err(AppError::InvalidAppMessagePayload(format!(
                "media version must be {ENCRYPTED_MEDIA_VERSION}"
            )));
        }
        Ok(())
    }

    pub(crate) fn imeta_tag(&self) -> Vec<String> {
        let mut tag = vec!["imeta".to_owned(), format!("v {}", self.version)];
        tag.extend(
            self.locators
                .iter()
                .map(|locator| format!("locator {} {}", locator.kind, locator.value)),
        );
        tag.extend([
            format!("ciphertext_sha256 {}", self.ciphertext_sha256),
            format!("plaintext_sha256 {}", self.plaintext_sha256),
            format!("nonce {}", self.nonce_hex),
            format!("m {}", self.media_type),
            format!("filename {}", self.file_name),
        ]);
        if let Some(dim) = self.dim.as_deref().filter(|value| !value.trim().is_empty()) {
            tag.push(format!("dim {}", dim));
        }
        if let Some(thumbhash) = self
            .thumbhash
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            tag.push(format!("thumbhash {}", thumbhash));
        }
        tag
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaUploadAttachmentRequest {
    pub file_name: String,
    pub media_type: String,
    pub plaintext: Vec<u8>,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaUploadRequest {
    pub attachments: Vec<MediaUploadAttachmentRequest>,
    pub caption: Option<String>,
    pub send: bool,
    /// Optional explicit Blossom endpoint for local testing. When absent, the
    /// group's `marmot.group.encrypted-media.v1` default endpoints are used.
    pub blossom_server: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaUploadAttachmentResult {
    pub reference: MediaAttachmentReference,
    pub encrypted_size_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaUploadResult {
    pub attachments: Vec<MediaUploadAttachmentResult>,
    pub sent: Option<SendSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaDownloadResult {
    pub plaintext: Vec<u8>,
    pub file_name: String,
    pub media_type: String,
    pub size_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct BlossomBlobDescriptor {
    url: Option<String>,
    sha256: Option<String>,
}

pub(crate) async fn upload_encrypted_media(
    request: MediaUploadRequest,
    source_epoch: u64,
    media_secret: &[u8],
    signing_keys: &nostr::Keys,
    default_endpoint: &BlobStoreEndpointV1,
) -> Result<MediaUploadResult, AppError> {
    if request.attachments.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "media upload requires at least one attachment".into(),
        ));
    }
    let server = request
        .blossom_server
        .as_deref()
        .unwrap_or(default_endpoint.base_url.as_str());
    let mut attachments = Vec::with_capacity(request.attachments.len());
    for attachment in request.attachments {
        attachments.push(
            upload_encrypted_media_attachment(
                attachment,
                source_epoch,
                media_secret,
                signing_keys,
                server,
            )
            .await?,
        );
    }
    Ok(MediaUploadResult {
        attachments,
        sent: None,
    })
}

async fn upload_encrypted_media_attachment(
    request: MediaUploadAttachmentRequest,
    source_epoch: u64,
    media_secret: &[u8],
    signing_keys: &nostr::Keys,
    server: &str,
) -> Result<MediaUploadAttachmentResult, AppError> {
    if request.plaintext.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "media plaintext cannot be empty".into(),
        ));
    }
    let file_name = request.file_name.trim().to_owned();
    if file_name.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "media file name cannot be empty".into(),
        ));
    }
    let media_type = canonical_media_type(&request.media_type)?;
    let plaintext_hash: [u8; 32] = Sha256::digest(&request.plaintext).into();
    let plaintext_sha256 = hex::encode(plaintext_hash);
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let file_key = derive_media_file_key(media_secret, &plaintext_hash, &media_type, &file_name)?;
    let aad = media_aad(&plaintext_hash, &media_type, &file_name);
    let cipher = ChaCha20Poly1305::new_from_slice(&file_key)
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid media key length".into()))?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &request.plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::InvalidEncryptedMedia("media encryption failed".into()))?;
    let ciphertext_sha256 = hex::encode(Sha256::digest(&encrypted));
    let url = upload_blossom_blob(server, &encrypted, &ciphertext_sha256, signing_keys).await?;
    let reference = MediaAttachmentReference {
        locators: vec![MediaLocator {
            kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
            value: url,
        }],
        ciphertext_sha256,
        plaintext_sha256,
        nonce_hex: hex::encode(nonce),
        file_name,
        media_type,
        version: ENCRYPTED_MEDIA_VERSION.to_owned(),
        source_epoch,
        dim: request.dim,
        thumbhash: request.thumbhash,
    };
    reference.validate()?;
    Ok(MediaUploadAttachmentResult {
        encrypted_size_bytes: encrypted.len() as u64,
        reference,
    })
}

pub(crate) async fn download_encrypted_media(
    reference: MediaAttachmentReference,
    media_secret: &[u8],
    fallback_endpoints: &[BlobStoreEndpointV1],
) -> Result<MediaDownloadResult, AppError> {
    reference.validate()?;
    let encrypted = fetch_encrypted_media_blob(&reference, fallback_endpoints).await?;
    let actual_encrypted_hash = hex::encode(Sha256::digest(&encrypted));
    if actual_encrypted_hash != reference.ciphertext_sha256 {
        return Err(AppError::InvalidEncryptedMedia(
            "encrypted blob hash does not match media reference".into(),
        ));
    }
    let plaintext_hash = media_hash_from_reference(&reference)?;
    let media_type = canonical_media_type(&reference.media_type)?;
    let nonce = media_nonce_from_reference(&reference)?;
    let file_key = derive_media_file_key(
        media_secret,
        &plaintext_hash,
        &media_type,
        &reference.file_name,
    )?;
    let aad = media_aad(&plaintext_hash, &media_type, &reference.file_name);
    let cipher = ChaCha20Poly1305::new_from_slice(&file_key)
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid media key length".into()))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &encrypted,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::InvalidEncryptedMedia("media decryption failed".into()))?;
    let actual_plaintext_hash: [u8; 32] = Sha256::digest(&plaintext).into();
    if actual_plaintext_hash != plaintext_hash {
        return Err(AppError::InvalidEncryptedMedia(
            "media plaintext hash does not match reference".into(),
        ));
    }
    Ok(MediaDownloadResult {
        size_bytes: plaintext.len() as u64,
        plaintext,
        file_name: reference.file_name,
        media_type,
    })
}

async fn fetch_encrypted_media_blob(
    reference: &MediaAttachmentReference,
    fallback_endpoints: &[BlobStoreEndpointV1],
) -> Result<Vec<u8>, AppError> {
    let mut candidates = reference
        .locators
        .iter()
        .filter(|locator| locator.kind == BLOSSOM_LOCATOR_KIND_V1)
        .map(|locator| locator.value.clone())
        .collect::<Vec<_>>();
    candidates.extend(
        fallback_endpoints
            .iter()
            .filter(|endpoint| endpoint.locator_kind == BLOSSOM_LOCATOR_KIND_V1)
            .map(|endpoint| blossom_blob_url(&endpoint.base_url, &reference.ciphertext_sha256)),
    );
    candidates.dedup();
    if candidates.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "media reference has no supported locators".into(),
        ));
    }
    let mut last_error = None;
    let expected_hash = reference.ciphertext_sha256.to_ascii_lowercase();
    for candidate in candidates {
        match blossom_content_hash_from_url(&candidate) {
            Some(hash) if hash == expected_hash => {}
            Some(_) => {
                last_error = Some(AppError::InvalidEncryptedMedia(
                    "Blossom locator hash does not match media reference".into(),
                ));
                continue;
            }
            None => {
                last_error = Some(AppError::InvalidEncryptedMedia(
                    "Blossom locator URL did not include encrypted blob hash".into(),
                ));
                continue;
            }
        }
        match fetch_blossom_blob(&candidate).await {
            Ok(bytes) => return Ok(bytes),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| AppError::BlobStore("download failed".into())))
}

pub(crate) fn media_attachment_from_imeta_tag(
    tag: &[String],
    source_epoch: Option<u64>,
) -> Result<MediaAttachmentReference, AppError> {
    if tag.first().map(String::as_str) != Some("imeta") {
        return Err(AppError::InvalidAppMessagePayload(
            "media tag must be imeta".into(),
        ));
    }
    let mut locators = Vec::new();
    let mut version = None;
    let mut ciphertext_sha256 = None;
    let mut plaintext_sha256 = None;
    let mut nonce_hex = None;
    let mut media_type = None;
    let mut file_name = None;
    let mut dim = None;
    let mut thumbhash = None;
    for field in tag.iter().skip(1) {
        if field.starts_with("blurhash ") {
            return Err(AppError::InvalidAppMessagePayload(
                "encrypted-media-v1 uses thumbhash, not blurhash".into(),
            ));
        }
        if let Some(rest) = field.strip_prefix("locator ") {
            let (kind, value) = rest.split_once(' ').ok_or_else(|| {
                AppError::InvalidAppMessagePayload(
                    "media locator must include kind and value".into(),
                )
            })?;
            locators.push(MediaLocator {
                kind: kind.to_owned(),
                value: value.to_owned(),
            });
            continue;
        }
        let Some((key, value)) = field.split_once(' ') else {
            continue;
        };
        match key {
            "v" => {
                if value != ENCRYPTED_MEDIA_VERSION {
                    return Err(AppError::InvalidAppMessagePayload(format!(
                        "media version must be {ENCRYPTED_MEDIA_VERSION}"
                    )));
                }
                if version.is_some() {
                    return Err(AppError::InvalidAppMessagePayload(
                        "media tag must contain exactly one version".into(),
                    ));
                }
                version = Some(value.to_owned());
            }
            "ciphertext_sha256" => ciphertext_sha256 = Some(value.to_owned()),
            "plaintext_sha256" => plaintext_sha256 = Some(value.to_owned()),
            "nonce" => nonce_hex = Some(value.to_owned()),
            "m" => media_type = Some(value.to_owned()),
            "filename" => file_name = Some(value.to_owned()),
            "dim" => dim = Some(value.to_owned()),
            "thumbhash" => thumbhash = Some(value.to_owned()),
            _ => {}
        }
    }
    let required = |name: &'static str, value: Option<String>| {
        value
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| AppError::InvalidAppMessagePayload(format!("media tag missing {name}")))
    };
    let reference = MediaAttachmentReference {
        locators,
        ciphertext_sha256: required("ciphertext_sha256", ciphertext_sha256)?,
        plaintext_sha256: required("plaintext_sha256", plaintext_sha256)?,
        nonce_hex: required("nonce", nonce_hex)?,
        file_name: required("filename", file_name)?,
        media_type: required("m", media_type)?,
        version: required("v", version)?,
        source_epoch: source_epoch.unwrap_or_default(),
        dim,
        thumbhash,
    };
    reference.validate()?;
    Ok(reference)
}

pub(crate) fn media_imeta_tags_are_valid(tags: &[Vec<String>]) -> bool {
    let mut found = false;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
    {
        found = true;
        if media_attachment_from_imeta_tag(tag, None).is_err() {
            return false;
        }
    }
    found
}

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
    upload_blossom_blob(server, &encrypted, &encrypted_hash_hex, &upload_keys).await?;
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
    let encrypted = fetch_blossom_blob(&url).await?;
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

fn canonical_media_type(value: &str) -> Result<String, AppError> {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type.is_empty() || !media_type.contains('/') {
        return Err(AppError::InvalidEncryptedMedia(
            "media type must be a MIME type".into(),
        ));
    }
    Ok(match media_type.as_str() {
        "image/jpg" => "image/jpeg".to_owned(),
        other => other.to_owned(),
    })
}

fn validate_sha256_hex(value: &str, label: &str) -> Result<(), AppError> {
    let hash = hex::decode(value)
        .map_err(|_| AppError::InvalidAppMessagePayload(format!("{label} must be hex")))?;
    if hash.len() != 32 {
        return Err(AppError::InvalidAppMessagePayload(format!(
            "{label} must be 32 bytes"
        )));
    }
    Ok(())
}

fn validate_locator(locator: &MediaLocator) -> Result<(), AppError> {
    if locator.kind.trim().is_empty() || locator.value.trim().is_empty() {
        return Err(AppError::InvalidAppMessagePayload(
            "media locator kind and value cannot be empty".into(),
        ));
    }
    if locator.kind != BLOSSOM_LOCATOR_KIND_V1 {
        return Err(AppError::InvalidAppMessagePayload(
            "unsupported media locator kind".into(),
        ));
    }
    let url = Url::parse(&locator.value)
        .map_err(|_| AppError::InvalidAppMessagePayload("media locator URL is invalid".into()))?;
    validate_blossom_fetch_url(&url, allow_loopback_media_http()).map_err(|err| {
        AppError::InvalidAppMessagePayload(format!("media locator URL is unsafe: {err}"))
    })?;
    Ok(())
}

fn allow_loopback_media_http() -> bool {
    cfg!(debug_assertions)
}

fn validate_blossom_fetch_url(url: &Url, allow_loopback_http: bool) -> Result<(), String> {
    if url.as_str().len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN {
        return Err(format!(
            "URL exceeds {ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN} bytes"
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL must not include credentials".into());
    }
    if url.fragment().is_some() {
        return Err("URL must not include a fragment".into());
    }
    let host = url.host().ok_or("URL must include a host")?;
    match url.scheme() {
        "https" => validate_public_or_allowed_loopback_host(host, false),
        "http" if allow_loopback_http && is_loopback_host(host) => Ok(()),
        "http" => Err("URL scheme must be https".into()),
        _ => Err("URL scheme must be https".into()),
    }
}

fn validate_public_or_allowed_loopback_host(
    host: Host<&str>,
    allow_loopback: bool,
) -> Result<(), String> {
    match host {
        Host::Domain(domain) => {
            let lowered = domain.to_ascii_lowercase();
            if lowered == "localhost" || lowered.ends_with(".localhost") {
                return if allow_loopback {
                    Ok(())
                } else {
                    Err("URL must not point at localhost".into())
                };
            }
            Ok(())
        }
        Host::Ipv4(addr) => reject_non_public_ip(IpAddr::V4(addr), allow_loopback),
        Host::Ipv6(addr) => reject_non_public_ip(IpAddr::V6(addr), allow_loopback),
    }
}

fn is_loopback_host(host: Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => {
            let lowered = domain.to_ascii_lowercase();
            lowered == "localhost" || lowered.ends_with(".localhost")
        }
        Host::Ipv4(addr) => addr.is_loopback(),
        Host::Ipv6(addr) => addr.is_loopback(),
    }
}

fn reject_non_public_ip(addr: IpAddr, allow_loopback: bool) -> Result<(), String> {
    match addr {
        IpAddr::V4(addr) if allow_loopback && addr.is_loopback() => Ok(()),
        IpAddr::V6(addr) if allow_loopback && addr.is_loopback() => Ok(()),
        IpAddr::V4(addr) if is_public_ipv4(addr) => Ok(()),
        IpAddr::V6(addr) if is_public_ipv6(addr) => Ok(()),
        _ => Err("URL must not point at a non-public address".into()),
    }
}

fn is_public_ipv4(addr: Ipv4Addr) -> bool {
    let [a, b, c, d] = addr.octets();
    !matches!(
        (a, b, c, d),
        (0, _, _, _)
            | (10, _, _, _)
            | (100, 64..=127, _, _)
            | (127, _, _, _)
            | (169, 254, _, _)
            | (172, 16..=31, _, _)
            | (192, 0, 0, _)
            | (192, 0, 2, _)
            | (192, 88, 99, _)
            | (192, 168, _, _)
            | (198, 18..=19, _, _)
            | (198, 51, 100, _)
            | (203, 0, 113, _)
            | (224..=255, _, _, _)
    )
}

fn is_public_ipv6(addr: Ipv6Addr) -> bool {
    if let Some(mapped) = addr.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return false;
    }
    let segments = addr.segments();
    let first = segments[0];
    let second = segments[1];
    if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
        return false;
    }
    if first == 0x2001 && second == 0x0db8 {
        return false;
    }
    (first & 0xe000) == 0x2000
}

fn media_hash_from_reference(reference: &MediaAttachmentReference) -> Result<[u8; 32], AppError> {
    hex::decode(&reference.plaintext_sha256)?
        .try_into()
        .map_err(|_| AppError::InvalidEncryptedMedia("media hash must be 32 bytes".into()))
}

fn media_nonce_from_reference(reference: &MediaAttachmentReference) -> Result<[u8; 12], AppError> {
    hex::decode(&reference.nonce_hex)?
        .try_into()
        .map_err(|_| AppError::InvalidEncryptedMedia("media nonce must be 12 bytes".into()))
}

fn derive_media_file_key(
    media_secret: &[u8],
    file_hash: &[u8; 32],
    media_type: &str,
    file_name: &str,
) -> Result<[u8; 32], AppError> {
    let hkdf = Hkdf::<Sha256>::from_prk(media_secret).map_err(|_| {
        AppError::InvalidEncryptedMedia("invalid encrypted-media component secret".into())
    })?;
    let mut key = [0_u8; 32];
    hkdf.expand(&media_key_info(file_hash, media_type, file_name), &mut key)
        .map_err(|_| AppError::InvalidEncryptedMedia("media key derivation failed".into()))?;
    Ok(key)
}

fn media_key_info(file_hash: &[u8; 32], media_type: &str, file_name: &str) -> Vec<u8> {
    let mut info = Vec::with_capacity(
        ENCRYPTED_MEDIA_VERSION.len() + 1 + 32 + 1 + media_type.len() + 1 + file_name.len() + 4,
    );
    info.extend_from_slice(ENCRYPTED_MEDIA_VERSION.as_bytes());
    info.push(0);
    info.extend_from_slice(file_hash);
    info.push(0);
    info.extend_from_slice(media_type.as_bytes());
    info.push(0);
    info.extend_from_slice(file_name.as_bytes());
    info.push(0);
    info.extend_from_slice(b"key");
    info
}

fn media_aad(file_hash: &[u8; 32], media_type: &str, file_name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        ENCRYPTED_MEDIA_VERSION.len() + 1 + 32 + 1 + media_type.len() + 1 + file_name.len(),
    );
    aad.extend_from_slice(ENCRYPTED_MEDIA_VERSION.as_bytes());
    aad.push(0);
    aad.extend_from_slice(file_hash);
    aad.push(0);
    aad.extend_from_slice(media_type.as_bytes());
    aad.push(0);
    aad.extend_from_slice(file_name.as_bytes());
    aad
}

async fn upload_blossom_blob(
    server: &str,
    encrypted: &[u8],
    encrypted_hash_hex: &str,
    signing_keys: &nostr::Keys,
) -> Result<String, AppError> {
    let (upload_url, server_host) = blossom_upload_endpoint(server)?;
    let authorization =
        blossom_authorization_header(signing_keys, &server_host, encrypted_hash_hex)?;
    let client = media_http_client_for_url(&upload_url).await?;
    let response = client
        .put(upload_url)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::CONTENT_TYPE, BLOSSOM_UPLOAD_CONTENT_TYPE)
        .header("X-SHA-256", encrypted_hash_hex)
        .body(encrypted.to_vec())
        .send()
        .await
        .map_err(reqwest_blob_error)?;
    if !response.status().is_success() {
        return Err(AppError::BlobStore(format!(
            "upload returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let descriptor = response
        .json::<BlossomBlobDescriptor>()
        .await
        .map_err(|_| AppError::BlobStore("upload returned an invalid descriptor".into()))?;
    if let Some(sha256) = descriptor.sha256.as_deref()
        && sha256.to_ascii_lowercase() != encrypted_hash_hex
    {
        return Err(AppError::BlobStore(
            "upload descriptor hash did not match encrypted blob".into(),
        ));
    }
    let url = descriptor
        .url
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| blossom_blob_url(server, encrypted_hash_hex));
    let content_hash = blossom_content_hash_from_url(&url).ok_or_else(|| {
        AppError::BlobStore("upload descriptor URL did not include encrypted blob hash".into())
    })?;
    if content_hash != encrypted_hash_hex {
        return Err(AppError::BlobStore(
            "upload descriptor URL hash did not match encrypted blob".into(),
        ));
    }
    Ok(url)
}

async fn fetch_blossom_blob(url: &str) -> Result<Vec<u8>, AppError> {
    let url = Url::parse(url)
        .map_err(|_| AppError::InvalidEncryptedMedia("media URL is invalid".into()))?;
    let client = media_http_client_for_url(&url).await?;
    let response = client.get(url).send().await.map_err(reqwest_blob_error)?;
    if !response.status().is_success() {
        return Err(AppError::BlobStore(format!(
            "download returned HTTP {}",
            response.status().as_u16()
        )));
    }
    read_limited_blossom_body(response, MAX_ENCRYPTED_MEDIA_BLOB_BYTES).await
}

async fn media_http_client_for_url(url: &Url) -> Result<reqwest::Client, AppError> {
    validate_blossom_fetch_url(url, allow_loopback_media_http())
        .map_err(|err| AppError::BlobStore(format!("unsafe Blossom URL: {err}")))?;
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(MEDIA_HTTP_CONNECT_TIMEOUT)
        .read_timeout(MEDIA_HTTP_READ_TIMEOUT)
        .timeout(MEDIA_HTTP_TOTAL_TIMEOUT)
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate();
    if let Some((domain, addrs)) = resolve_media_host(url).await? {
        builder = builder.resolve_to_addrs(&domain, &addrs);
    }
    builder
        .build()
        .map_err(|_| AppError::BlobStore("failed to build HTTP client".into()))
}

async fn resolve_media_host(url: &Url) -> Result<Option<(String, Vec<SocketAddr>)>, AppError> {
    let allow_loopback = url.scheme() == "http"
        && allow_loopback_media_http()
        && url.host().map(is_loopback_host).unwrap_or(false);
    match url
        .host()
        .ok_or_else(|| AppError::BlobStore("Blossom URL is missing a host".into()))?
    {
        Host::Domain(domain) => {
            let port = url
                .port_or_known_default()
                .ok_or_else(|| AppError::BlobStore("Blossom URL is missing a fetch port".into()))?;
            let addrs = tokio::net::lookup_host((domain, port))
                .await
                .map_err(|_| AppError::BlobStore("media host DNS lookup failed".into()))?
                .collect::<Vec<_>>();
            if addrs.is_empty() {
                return Err(AppError::BlobStore(
                    "media host DNS lookup returned no addresses".into(),
                ));
            }
            for addr in &addrs {
                reject_non_public_ip(addr.ip(), allow_loopback).map_err(|err| {
                    AppError::BlobStore(format!("unsafe media host address: {err}"))
                })?;
            }
            Ok(Some((domain.to_ascii_lowercase(), addrs)))
        }
        Host::Ipv4(addr) => {
            reject_non_public_ip(IpAddr::V4(addr), allow_loopback)
                .map_err(|err| AppError::BlobStore(format!("unsafe media host address: {err}")))?;
            Ok(None)
        }
        Host::Ipv6(addr) => {
            reject_non_public_ip(IpAddr::V6(addr), allow_loopback)
                .map_err(|err| AppError::BlobStore(format!("unsafe media host address: {err}")))?;
            Ok(None)
        }
    }
}

async fn read_limited_blossom_body(
    response: reqwest::Response,
    max_bytes: u64,
) -> Result<Vec<u8>, AppError> {
    if let Some(content_length) = response.content_length()
        && content_length > max_bytes
    {
        return Err(AppError::BlobStore(format!(
            "download exceeds {max_bytes} bytes"
        )));
    }
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await.map_err(reqwest_blob_error)? {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| AppError::BlobStore(format!("download exceeds {max_bytes} bytes")))?;
        if next_len as u64 > max_bytes {
            return Err(AppError::BlobStore(format!(
                "download exceeds {max_bytes} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn blossom_upload_endpoint(server: &str) -> Result<(Url, String), AppError> {
    let mut url = Url::parse(server.trim())
        .map_err(|_| AppError::BlobStore("invalid Blossom server URL".into()))?;
    match url.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(AppError::BlobStore(
                "Blossom server URL must be http or https".into(),
            ));
        }
    }
    let host = url
        .host_str()
        .ok_or_else(|| AppError::BlobStore("Blossom server URL is missing a host".into()))?
        .to_ascii_lowercase();
    url.set_path("upload");
    url.set_query(None);
    url.set_fragment(None);
    Ok((url, host))
}

fn blossom_blob_url(server: &str, encrypted_hash_hex: &str) -> String {
    match Url::parse(server.trim()) {
        Ok(mut url) => {
            url.set_path(&format!("{encrypted_hash_hex}.bin"));
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => format!(
            "{}/{}.bin",
            server.trim_end_matches('/'),
            encrypted_hash_hex
        ),
    }
}

fn blossom_content_hash_from_url(url: &str) -> Option<String> {
    let url = Url::parse(url).ok()?;
    let path = url.path();
    let bytes = path.as_bytes();
    bytes.windows(64).rev().find_map(|window| {
        let candidate = std::str::from_utf8(window).ok()?;
        (candidate.len() == 64 && hex::decode(candidate).is_ok())
            .then(|| candidate.to_ascii_lowercase())
    })
}

fn blossom_authorization_header(
    keys: &nostr::Keys,
    server_host: &str,
    encrypted_hash_hex: &str,
) -> Result<String, AppError> {
    let now = unix_now_seconds();
    let expiration = now + BLOSSOM_UPLOAD_AUTH_TTL.as_secs();
    let tags = [
        Tag::parse(["t", "upload"]),
        Tag::parse(["expiration", &expiration.to_string()]),
        Tag::parse(["x", encrypted_hash_hex]),
        Tag::parse(["server", server_host]),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|err| AppError::BlobStore(format!("failed to build Blossom auth tag: {err}")))?;
    let event = EventBuilder::new(Kind::Custom(24242), "Upload Blob")
        .tags(tags)
        .custom_created_at(NostrTimestamp::from(now))
        .sign_with_keys(keys)
        .map_err(|err| AppError::BlobStore(format!("failed to sign Blossom auth: {err}")))?;
    Ok(format!(
        "Nostr {}",
        BASE64_URL_SAFE_NO_PAD.encode(event.as_json())
    ))
}

fn reqwest_blob_error(err: reqwest::Error) -> AppError {
    if let Some(status) = err.status() {
        AppError::BlobStore(format!("HTTP {}", status.as_u16()))
    } else if err.is_timeout() {
        AppError::BlobStore("request timed out".into())
    } else if err.is_connect() {
        AppError::BlobStore("connection failed".into())
    } else if err.is_decode() {
        AppError::BlobStore("invalid response body".into())
    } else {
        AppError::BlobStore("request failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn valid_imeta_tag() -> Vec<String> {
        vec![
            "imeta".to_owned(),
            "v encrypted-media-v1".to_owned(),
            format!(
                "locator blossom-v1 https://media.example/{}.bin",
                "11".repeat(32)
            ),
            format!("ciphertext_sha256 {}", "11".repeat(32)),
            format!("plaintext_sha256 {}", "22".repeat(32)),
            "nonce 333333333333333333333333".to_owned(),
            "m image/png".to_owned(),
            "filename diagram.png".to_owned(),
        ]
    }

    fn valid_hash() -> String {
        "11".repeat(32)
    }

    fn tag_with_locator(locator: String) -> Vec<String> {
        let mut tag = valid_imeta_tag();
        tag[2] = format!("locator blossom-v1 {locator}");
        tag
    }

    fn spawn_http_response(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("test server addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(&response);
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn imeta_parser_rejects_legacy_version_even_when_later_current_version_present() {
        let mut tag = valid_imeta_tag();
        tag.insert(1, "v legacy-media-v0".to_owned());

        assert!(media_attachment_from_imeta_tag(&tag, None).is_err());
        assert!(!media_imeta_tags_are_valid(&[tag]));
    }

    #[test]
    fn imeta_parser_rejects_duplicate_current_version_fields() {
        let mut tag = valid_imeta_tag();
        tag.insert(1, "v encrypted-media-v1".to_owned());

        assert!(media_attachment_from_imeta_tag(&tag, None).is_err());
        assert!(!media_imeta_tags_are_valid(&[tag]));
    }

    #[test]
    fn imeta_parser_rejects_non_https_media_locator() {
        let tag = tag_with_locator(format!("http://media.example/{}.bin", valid_hash()));
        let err = media_attachment_from_imeta_tag(&tag, None).unwrap_err();

        assert!(err.to_string().contains("scheme must be https"));
        assert!(!media_imeta_tags_are_valid(&[tag]));
    }

    #[test]
    fn imeta_parser_rejects_private_ip_media_locator() {
        let tag = tag_with_locator(format!("https://10.0.0.5/{}.bin", valid_hash()));
        let err = media_attachment_from_imeta_tag(&tag, None).unwrap_err();

        assert!(err.to_string().contains("non-public"));
        assert!(!media_imeta_tags_are_valid(&[tag]));
    }

    #[test]
    fn imeta_parser_rejects_locator_without_content_hash() {
        let tag = tag_with_locator("https://media.example/download.bin".to_owned());
        let err = media_attachment_from_imeta_tag(&tag, None).unwrap_err();

        assert!(
            err.to_string()
                .contains("must include the encrypted blob hash")
        );
        assert!(!media_imeta_tags_are_valid(&[tag]));
    }

    #[test]
    fn imeta_parser_rejects_locator_hash_mismatch() {
        let tag = tag_with_locator(format!("https://media.example/{}.bin", "33".repeat(32)));
        let err = media_attachment_from_imeta_tag(&tag, None).unwrap_err();

        assert!(err.to_string().contains("hash does not match"));
        assert!(!media_imeta_tags_are_valid(&[tag]));
    }

    #[test]
    fn media_fetch_url_policy_allows_loopback_http_only_when_explicitly_enabled() {
        let url = Url::parse(&format!("http://127.0.0.1:3000/{}.bin", valid_hash())).unwrap();

        assert!(validate_blossom_fetch_url(&url, true).is_ok());
        assert!(validate_blossom_fetch_url(&url, false).is_err());
    }

    #[tokio::test]
    async fn fetch_blossom_blob_does_not_follow_redirects() {
        let server = spawn_http_response(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        );
        let url = format!("{server}/{}.bin", valid_hash());
        let err = fetch_blossom_blob(&url).await.unwrap_err();

        assert!(err.to_string().contains("HTTP 302"));
    }

    #[tokio::test]
    async fn fetch_blossom_blob_rejects_oversized_content_length() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_ENCRYPTED_MEDIA_BLOB_BYTES + 1
        );
        let server = spawn_http_response(response.into_bytes());
        let url = format!("{server}/{}.bin", valid_hash());
        let err = fetch_blossom_blob(&url).await.unwrap_err();

        assert!(err.to_string().contains("download exceeds"));
    }

    #[tokio::test]
    async fn limited_body_reader_rejects_chunked_body_over_cap() {
        let server = spawn_http_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nabcdef\r\n0\r\n\r\n"
                .to_vec(),
        );
        let response = reqwest::Client::new()
            .get(format!("{server}/{}.bin", valid_hash()))
            .send()
            .await
            .expect("fetch chunked test body");
        let err = read_limited_blossom_body(response, 5).await.unwrap_err();

        assert!(err.to_string().contains("download exceeds 5 bytes"));
    }
}
