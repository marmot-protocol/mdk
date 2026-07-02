use cgka_traits::app_components::{
    BLOSSOM_LOCATOR_KIND_V1, BlobStoreEndpointV1, ENCRYPTED_MEDIA_FORMAT_V1,
};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::{AppError, SendSummary};

mod blossom;
mod crypto;
mod group_image;
mod host_safety;

use blossom::{blossom_content_hash_from_url, upload_blossom_blob};
use crypto::{
    derive_media_file_key, media_aad, media_hash_from_reference, media_nonce_from_reference,
    validate_sha256_hex,
};
use host_safety::validate_locator;

pub(crate) use blossom::{blossom_blob_url, fetch_blossom_blob};
pub(crate) use crypto::canonical_media_type;
pub(crate) use group_image::{fetch_group_image, upload_group_image};
pub(crate) use host_safety::is_loopback_http_endpoint;

pub const DEFAULT_BLOSSOM_SERVER_URL: &str = "https://blossom.primal.net";
pub const ENCRYPTED_MEDIA_VERSION: &str = ENCRYPTED_MEDIA_FORMAT_V1;

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
    /// Structurally validate the reference. This is the ingest check: a
    /// reference is invalid ONLY for structural reasons (bad hashes/nonce, no
    /// locator, a locator with an empty kind/value or an unparseable URL, empty
    /// filename, bad MIME type, wrong/absent version). Per encrypted-media.md
    /// Validation, a well-formed locator whose kind is out of the group policy
    /// or unsupported by this client makes that locator UNFETCHABLE, not the
    /// reference invalid: media is authenticated by its `ciphertext_sha256` /
    /// `plaintext_sha256` + AEAD independent of the locator, so the locator
    /// cannot forge content and MUST NOT drop the containing message. Policy is
    /// applied at fetch time (see `fetch_encrypted_media_blob`) and before
    /// emitting an outbound reference (see `validate_outbound`).
    ///
    /// `allow_loopback_http` gates ONLY cleartext-`http` loopback Blossom
    /// locators (the dev/test escape hatch, driven by
    /// `MarmotAppConfig::allow_loopback_blob_endpoints`); private, link-local,
    /// documentation, IPv6-transition, and multicast hosts are rejected
    /// regardless of its value.
    pub(crate) fn validate(&self, allow_loopback_http: bool) -> Result<(), AppError> {
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
            validate_locator(locator, allow_loopback_http)?;
            // The blossom content-hash binding is Blossom-specific integrity, like
            // the host-safety check in `validate_locator`: a `blossom-v1` locator
            // URL MUST carry the ciphertext hash so the fetched blob is the one
            // this reference commits to. A non-Blossom locator is never fetched by
            // this client and carries no such URL convention, so it is subject only
            // to the structural checks above and stays merely unfetchable.
            if locator.kind == BLOSSOM_LOCATOR_KIND_V1 {
                let locator_hash =
                    blossom_content_hash_from_url(&locator.value).ok_or_else(|| {
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

    /// Validate an OUTBOUND reference this client is about to emit against the
    /// group's actual `allowed_locator_kinds`. Unlike ingest validation (which is
    /// purely structural — an out-of-policy locator only makes the attachment
    /// unfetchable, never invalid), the sender MUST NOT emit a reference whose
    /// locator kind its own group policy forbids, since receivers would skip it
    /// as unfetchable. This enforces structural validity AND policy membership
    /// for every locator. An empty `allowed` set falls back to the `blossom-v1`
    /// default (see `locator_kind_allowed`).
    pub(crate) fn validate_outbound(
        &self,
        allowed_locator_kinds: &[String],
        allow_loopback_http: bool,
    ) -> Result<(), AppError> {
        self.validate(allow_loopback_http)?;
        for locator in &self.locators {
            if !locator_kind_allowed(&locator.kind, allowed_locator_kinds) {
                return Err(AppError::InvalidEncryptedMedia(
                    "media locator kind is not allowed by the group policy".into(),
                ));
            }
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

pub(crate) async fn upload_encrypted_media(
    request: MediaUploadRequest,
    source_epoch: u64,
    media_secret: &[u8],
    signing_keys: &nostr::Keys,
    default_endpoints: &[BlobStoreEndpointV1],
    allowed_locator_kinds: &[String],
    allow_loopback_http: bool,
) -> Result<MediaUploadResult, AppError> {
    if request.attachments.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "media upload requires at least one attachment".into(),
        ));
    }
    let upload_servers = match request.blossom_server {
        Some(server) => vec![server],
        None => default_endpoints
            .iter()
            .map(|endpoint| endpoint.base_url.clone())
            .collect::<Vec<_>>(),
    };
    if upload_servers.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "group policy has no usable Blossom endpoint for upload".into(),
        ));
    }
    let mut attachments = Vec::with_capacity(request.attachments.len());
    for attachment in request.attachments {
        attachments.push(
            upload_encrypted_media_attachment(
                attachment,
                source_epoch,
                media_secret,
                signing_keys,
                &upload_servers,
                allowed_locator_kinds,
                allow_loopback_http,
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
    upload_servers: &[String],
    allowed_locator_kinds: &[String],
    allow_loopback_http: bool,
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
    let url = upload_blossom_blob_with_fallback(
        upload_servers,
        &encrypted,
        &ciphertext_sha256,
        signing_keys,
        allow_loopback_http,
    )
    .await?;
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
    // The reference we just built carries a single `blossom-v1` locator. Validate
    // it against the group's ACTUAL `allowed_locator_kinds` so an upload to a
    // group whose policy does not allow `blossom-v1` fails here rather than
    // emitting a reference its own receivers would reject.
    reference.validate_outbound(allowed_locator_kinds, allow_loopback_http)?;
    Ok(MediaUploadAttachmentResult {
        encrypted_size_bytes: encrypted.len() as u64,
        reference,
    })
}

async fn upload_blossom_blob_with_fallback(
    servers: &[String],
    encrypted: &[u8],
    encrypted_hash_hex: &str,
    signing_keys: &nostr::Keys,
    allow_loopback_http: bool,
) -> Result<String, AppError> {
    let mut failures = Vec::new();
    for (idx, server) in servers.iter().enumerate() {
        match upload_blossom_blob(
            server,
            encrypted,
            encrypted_hash_hex,
            signing_keys,
            allow_loopback_http,
        )
        .await
        {
            Ok(url) => return Ok(url),
            Err(err) => failures.push(format!(
                "server {}: {}",
                idx + 1,
                upload_error_summary(&err)
            )),
        }
    }
    Err(AppError::BlobStore(format!(
        "upload failed for all Blossom servers: {}",
        failures.join("; ")
    )))
}

fn upload_error_summary(err: &AppError) -> String {
    match err {
        AppError::BlobStore(message)
        | AppError::InvalidEncryptedMedia(message)
        | AppError::InvalidAppMessagePayload(message) => message.clone(),
        // `upload_blossom_blob` should currently surface upload failures through
        // the privacy-scrubbed variants above. Keep this fallback as a defensive
        // catch-all only; do not route URL-bearing transport errors here without
        // first adding an explicit scrubbed summary arm.
        other => other.to_string(),
    }
}

pub(crate) async fn download_encrypted_media(
    reference: MediaAttachmentReference,
    media_secret: &[u8],
    fallback_endpoints: &[BlobStoreEndpointV1],
    allowed_locator_kinds: &[String],
    allow_loopback_blob_endpoints: bool,
) -> Result<MediaDownloadResult, AppError> {
    // Structural validation only: an out-of-policy or client-unsupported locator
    // is judged at fetch time below, where it degrades to an unfetchable outcome
    // rather than a hard "corrupt reference" error.
    reference.validate(allow_loopback_blob_endpoints)?;
    let encrypted = fetch_encrypted_media_blob(
        &reference,
        fallback_endpoints,
        allowed_locator_kinds,
        allow_loopback_blob_endpoints,
    )
    .await?;
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
    allowed_locator_kinds: &[String],
    allow_loopback_blob_endpoints: bool,
) -> Result<Vec<u8>, AppError> {
    // Fetchability is judged against CURRENT policy + current client support.
    // This client only fetches `blossom-v1`, so if the group's current policy
    // does not allow `blossom-v1` there is no fetchable locator and the
    // reference degrades to unfetchable (not invalid): the reference may still
    // be valid and the message delivered, only the blob is unreachable here.
    if !locator_kind_allowed(BLOSSOM_LOCATOR_KIND_V1, allowed_locator_kinds) {
        return Err(AppError::InvalidEncryptedMedia(
            "media reference has no supported locators".into(),
        ));
    }
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
    if !allow_loopback_blob_endpoints {
        // A loopback-HTTP candidate is valid component state but unusable in a
        // production build: skip it rather than GETting the local host. The
        // candidate may come from a remote-admin policy endpoint or a
        // sender-chosen locator, so the gate applies to both.
        candidates.retain(|candidate| !is_loopback_http_endpoint(candidate));
    }
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
        match fetch_blossom_blob(&candidate, allow_loopback_blob_endpoints).await {
            Ok(bytes) => return Ok(bytes),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| AppError::BlobStore("download failed".into())))
}

pub fn media_attachment_from_imeta_tag(
    tag: &[String],
    source_epoch: Option<u64>,
    allow_loopback_http: bool,
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
    // Single-occurrence fields MUST appear at most once. m, filename, and
    // plaintext_sha256 feed file_key derivation and the AEAD AAD, so a first-wins
    // vs last-wins decoder would derive different keys for the same tag. Reject a
    // duplicate rather than overwriting (spec/features/encrypted-media.md).
    let set_once = |slot: &mut Option<String>, value: &str, label: &str| -> Result<(), AppError> {
        if slot.is_some() {
            return Err(AppError::InvalidAppMessagePayload(format!(
                "media tag must contain exactly one {label}"
            )));
        }
        *slot = Some(value.to_owned());
        Ok(())
    };
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
                set_once(&mut version, value, "version")?;
            }
            "ciphertext_sha256" => set_once(&mut ciphertext_sha256, value, "ciphertext_sha256")?,
            "plaintext_sha256" => set_once(&mut plaintext_sha256, value, "plaintext_sha256")?,
            "nonce" => set_once(&mut nonce_hex, value, "nonce")?,
            "m" => set_once(&mut media_type, value, "m")?,
            "filename" => set_once(&mut file_name, value, "filename")?,
            "dim" => set_once(&mut dim, value, "dim")?,
            "thumbhash" => set_once(&mut thumbhash, value, "thumbhash")?,
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
    reference.validate(allow_loopback_http)?;
    Ok(reference)
}

/// Whether every `imeta` tag in `tags` is a structurally valid media reference.
/// This is an ingest-time check only: locator-kind policy is NOT consulted here,
/// because an out-of-policy or client-unsupported locator makes only that
/// locator unfetchable and MUST NOT drop the containing message.
pub(crate) fn media_imeta_tags_are_valid(tags: &[Vec<String>], allow_loopback_http: bool) -> bool {
    let mut found = false;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
    {
        found = true;
        if media_attachment_from_imeta_tag(tag, None, allow_loopback_http).is_err() {
            return false;
        }
    }
    found
}

/// Whether `kind` is allowed by the group's `allowed_locator_kinds`. When the
/// group has no `marmot.group.encrypted-media.v1` component (empty set) the
/// well-known default of `blossom-v1` applies, matching the policy default and
/// preserving prior behavior. This drives FETCHABILITY (the download path) and
/// the OUTBOUND emit check; it MUST NOT be used to invalidate a reference at
/// ingest.
fn locator_kind_allowed(kind: &str, allowed_locator_kinds: &[String]) -> bool {
    if allowed_locator_kinds.is_empty() {
        kind == BLOSSOM_LOCATOR_KIND_V1
    } else {
        allowed_locator_kinds.iter().any(|allowed| allowed == kind)
    }
}

#[cfg(test)]
mod tests;
