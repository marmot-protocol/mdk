use std::time::Instant;

use bytes::Bytes;
use cgka_traits::app_components::{
    BLOSSOM_LOCATOR_KIND_V1, ENCRYPTED_MEDIA_FORMAT_V1, ENCRYPTED_MEDIA_FORMAT_V2,
    GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
    canonicalize_marmot_media_type,
};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use nostr::NostrSigner;
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::app_telemetry::{AppPerformanceOperation, AppPerformanceTelemetry};
use crate::{AppError, ChatListAttachmentKind, SendSummary};

mod blossom;
mod crypto;
mod group_image;
mod host_safety;

use blossom::{
    blossom_content_hash_from_url, upload_blossom_blob, upload_blossom_blob_with_content_type,
};
use crypto::{
    canonical_media_type_v1, canonical_media_type_v2, derive_media_file_key, media_aad,
    media_hash_from_reference, media_nonce_from_reference, validate_sha256_hex,
};
pub(crate) use host_safety::parse_profile_image_fetch_url;
use host_safety::{validate_blossom_fetch_url, validate_locator};

pub use blossom::MAX_ENCRYPTED_MEDIA_BLOB_BYTES;
#[cfg(test)]
pub(crate) use blossom::fetch_blossom_blob;
pub(crate) use blossom::{BlossomHttpTransport, blossom_blob_url};
pub use group_image::{MAX_GROUP_IMAGE_BYTES, MAX_GROUP_IMAGE_DIMENSION, MAX_GROUP_IMAGE_PIXELS};
pub(crate) use group_image::{
    fetch_group_image_with_transport, prepare_group_image_upload, upload_group_image,
    upload_prepared_group_image,
};
pub(crate) use host_safety::is_loopback_http_endpoint;

/// Feature-gated transport handle for the repository media backlog benchmark.
///
/// This surface is excluded from normal app artifacts and deliberately exposes
/// only the same fetch path used by encrypted-media downloads.
#[cfg(feature = "media-benchmarks")]
pub struct MediaDownloadBenchmarkTransport(BlossomHttpTransport);

#[cfg(feature = "media-benchmarks")]
impl MediaDownloadBenchmarkTransport {
    /// Create one transport whose vetted exact-origin clients can be reused.
    pub fn new() -> Self {
        Self(BlossomHttpTransport::new(true))
    }

    /// Fetch one bounded blob through the production download transport.
    pub async fn fetch(&self, url: &str) -> Result<Vec<u8>, AppError> {
        blossom::fetch_blossom_blob_with_transport(url, &self.0).await
    }

    /// Fetch one bounded blob while recording only the production transport's
    /// fixed, aggregate phase metrics for the repository benchmark.
    pub async fn fetch_with_telemetry(
        &self,
        url: &str,
        telemetry: &AppPerformanceTelemetry,
    ) -> Result<Vec<u8>, AppError> {
        blossom::fetch_blossom_blob_with_observer(url, &self.0, Some(telemetry)).await
    }
}

#[cfg(feature = "media-benchmarks")]
impl Default for MediaDownloadBenchmarkTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate and compact the latest-message encrypted-media metadata for the
/// chat-list surface. Raw tags and metadata never cross the app boundary.
///
/// A rejected attachment still counts as an attachment and classifies as
/// `File` (the generic glyph): the timeline renders a placeholder for it, so
/// the list preview must not describe the same message as text-only
/// (mdk#1787). Its media type is not trusted for classification because the
/// tag failed validation.
pub(crate) fn classify_chat_list_attachments(
    media_json: Option<&str>,
) -> (Option<ChatListAttachmentKind>, u32) {
    let media = media_json.and_then(|raw| serde_json::from_str::<Value>(raw).ok());
    let mut kinds = Vec::new();
    for outcome in media_attachment_outcomes_from_media_json(media.as_ref(), None, false) {
        let MediaAttachmentOutcome::Accepted { reference, .. } = outcome else {
            kinds.push(ChatListAttachmentKind::File);
            continue;
        };
        let media_type = reference.media_type.to_ascii_lowercase();
        let kind = if media_type.starts_with("image/") {
            ChatListAttachmentKind::Photo
        } else if media_type.starts_with("video/") {
            ChatListAttachmentKind::Video
        } else if media_type.starts_with("audio/") {
            ChatListAttachmentKind::Audio
        } else {
            ChatListAttachmentKind::File
        };
        kinds.push(kind);
    }

    let count = u32::try_from(kinds.len()).unwrap_or(u32::MAX);
    let Some(first) = kinds.first().copied() else {
        return (None, 0);
    };
    let kind = if kinds.iter().all(|candidate| *candidate == first) {
        first
    } else {
        ChatListAttachmentKind::Mixed
    };
    (Some(kind), count)
}

/// Built-in encrypted-media endpoints, in upload fallback order.
///
/// Every endpoint in this list must accept opaque `application/octet-stream`
/// blobs. Encrypted media and encrypted group images are indistinguishable
/// from random bytes, so media-only Blossom servers are not compatible even
/// when the original plaintext was an image or video.
pub const DEFAULT_BLOSSOM_SERVER_URLS: &[&str] = &[
    "https://blossom.divine.video",
    "https://blossom.ditto.pub",
    "https://cdn.hzrd149.com",
];

/// Primary built-in Blossom endpoint used by single-endpoint APIs such as
/// encrypted group-image upload.
pub const DEFAULT_BLOSSOM_SERVER_URL: &str = DEFAULT_BLOSSOM_SERVER_URLS[0];
/// Public-profile images are intentionally not encrypted: their Blossom URL is
/// published in Nostr kind:0 metadata and must be fetchable by other clients.
pub const DEFAULT_PROFILE_IMAGE_BLOSSOM_SERVER_URL: &str = "https://blossom.primal.net";
/// Maximum profile-image upload and dial-safe download size (10 MiB).
pub(crate) const MAX_PROFILE_IMAGE_BYTES: usize = 10 * 1024 * 1024;
/// Frozen legacy format label. New code chooses a version from group state.
pub const ENCRYPTED_MEDIA_VERSION: &str = ENCRYPTED_MEDIA_FORMAT_V1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptedMediaVersion {
    V1,
    V2,
}

impl EncryptedMediaVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => ENCRYPTED_MEDIA_FORMAT_V1,
            Self::V2 => ENCRYPTED_MEDIA_FORMAT_V2,
        }
    }

    pub(crate) const fn component_id(self) -> u16 {
        match self {
            Self::V1 => GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
            Self::V2 => GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
        }
    }

    pub fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            ENCRYPTED_MEDIA_FORMAT_V1 => Ok(Self::V1),
            ENCRYPTED_MEDIA_FORMAT_V2 => Ok(Self::V2),
            _ => Err(AppError::InvalidAppMessagePayload(
                "media version is not supported".into(),
            )),
        }
    }
}

#[cfg(test)]
pub(crate) async fn upload_profile_image(
    image: &[u8],
    media_type: &str,
    server: Option<&str>,
    signer: &dyn NostrSigner,
) -> Result<String, AppError> {
    upload_profile_image_with_policy(image, media_type, server, signer, false).await
}

pub(crate) async fn upload_profile_image_with_policy(
    image: &[u8],
    media_type: &str,
    server: Option<&str>,
    signer: &dyn NostrSigner,
    allow_loopback_http: bool,
) -> Result<String, AppError> {
    if image.is_empty() {
        return Err(AppError::BlobStore("profile image cannot be empty".into()));
    }
    if image.len() > MAX_PROFILE_IMAGE_BYTES {
        return Err(AppError::BlobStore(
            "profile image exceeds 10 MiB limit".into(),
        ));
    }
    let media_type = canonicalize_marmot_media_type(media_type)
        .map_err(|_| AppError::BlobStore("profile image has an invalid media type".into()))?;
    let (expected_format, extension) = match media_type.as_str() {
        "image/jpeg" | "image/jpg" => (image::ImageFormat::Jpeg, ".jpg"),
        "image/png" => (image::ImageFormat::Png, ".png"),
        "image/webp" => (image::ImageFormat::WebP, ".webp"),
        "image/gif" => (image::ImageFormat::Gif, ".gif"),
        _ => {
            return Err(AppError::BlobStore(
                "profile image must be JPEG, PNG, WebP, or GIF".into(),
            ));
        }
    };
    if image::guess_format(image).ok() != Some(expected_format) {
        return Err(AppError::BlobStore(
            "profile image bytes do not match the declared media type".into(),
        ));
    }
    let server = server.unwrap_or(DEFAULT_PROFILE_IMAGE_BLOSSOM_SERVER_URL);
    let hash_hex = hex::encode(Sha256::digest(image));
    let url = upload_blossom_blob_with_content_type(
        server,
        Bytes::copy_from_slice(image),
        &hash_hex,
        signer,
        allow_loopback_http,
        &media_type,
        Some(extension),
    )
    .await?;
    let parsed = url::Url::parse(&url)
        .map_err(|_| AppError::BlobStore("upload returned an invalid image URL".into()))?;
    host_safety::validate_blossom_fetch_url(&parsed, allow_loopback_http)
        .map_err(|_| AppError::BlobStore("upload returned an unsafe image URL".into()))?;
    Ok(url)
}

fn normalize_profile_image_max_bytes(max_bytes: u64) -> Result<u64, AppError> {
    if max_bytes == 0 {
        return Err(AppError::InvalidAppMessagePayload(
            "profile image max_bytes must be positive".into(),
        ));
    }
    let ceiling = MAX_PROFILE_IMAGE_BYTES as u64;
    if max_bytes > ceiling {
        return Err(AppError::InvalidAppMessagePayload(format!(
            "profile image max_bytes exceeds {ceiling} byte ceiling"
        )));
    }
    Ok(max_bytes)
}

/// Fetch one untrusted kind:0 profile `picture` URL with MDK dial-safe HTTPS
/// policy (pinned public resolution, bounded redirects, and streaming limits).
pub async fn download_profile_image(url: String, max_bytes: u64) -> Result<Vec<u8>, AppError> {
    let max_bytes = normalize_profile_image_max_bytes(max_bytes)?;
    blossom::fetch_profile_image(&url, max_bytes).await
}

#[cfg(test)]
pub(crate) async fn download_profile_image_with_test_loopback(
    url: String,
    max_bytes: u64,
) -> Result<Vec<u8>, AppError> {
    let max_bytes = normalize_profile_image_max_bytes(max_bytes)?;
    blossom::fetch_profile_image_with_loopback(&url, max_bytes).await
}

#[cfg(test)]
pub(crate) fn normalize_profile_image_max_bytes_for_test(max_bytes: u64) -> Result<u64, AppError> {
    normalize_profile_image_max_bytes(max_bytes)
}

/// Stable category of an encrypted-media attachment rejection.
///
/// Hosts branch on this instead of parsing error strings. The categories are
/// part of the binding contract: add variants, never renumber or repurpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MediaAttachmentRejectionKind {
    /// The entry is not a decodable encrypted-media `imeta` tag: it is not an
    /// array of strings, its first element is not `imeta`, a known field has
    /// no value, or a `locator` lacks its `kind value` pair.
    InvalidStructure,
    /// The `v` field is absent or names a media format this client does not
    /// implement. Legacy MIP-era shapes and future versions land here, so a
    /// host can say "unsupported attachment format" rather than "corrupt".
    UnsupportedFormat,
    /// A required field (`locator`, `ciphertext_sha256`, `plaintext_sha256`,
    /// `nonce`, `m`, `filename`) is absent or empty.
    MissingField,
    /// A single-occurrence field appears more than once. Rejected rather than
    /// resolved first- or last-wins because `m`, `filename`, and
    /// `plaintext_sha256` feed key derivation and the AEAD AAD.
    DuplicateField,
    /// A present field has an invalid value: non-hex or wrong-length hashes or
    /// nonce, an unparseable/unsafe locator URL, a Blossom URL that does not
    /// commit to the ciphertext hash, a non-canonical media type, an invalid
    /// filename, or a forbidden `blurhash`.
    MalformedField,
}

impl MediaAttachmentRejectionKind {
    /// Stable snake_case label shared by fixtures, CLI output, and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidStructure => "invalid_structure",
            Self::UnsupportedFormat => "unsupported_format",
            Self::MissingField => "missing_field",
            Self::DuplicateField => "duplicate_field",
            Self::MalformedField => "malformed_field",
        }
    }
}

/// Why one `imeta` attachment was rejected by the shared strict parser.
///
/// `detail` is presentation text for hosts and never echoes tag content
/// (URLs, filenames, hashes, media types). Tracing must log only `kind`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaAttachmentRejection {
    pub kind: MediaAttachmentRejectionKind,
    pub detail: String,
}

impl MediaAttachmentRejection {
    fn new(kind: MediaAttachmentRejectionKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    fn structure(detail: impl Into<String>) -> Self {
        Self::new(MediaAttachmentRejectionKind::InvalidStructure, detail)
    }

    fn unsupported(detail: impl Into<String>) -> Self {
        Self::new(MediaAttachmentRejectionKind::UnsupportedFormat, detail)
    }

    fn missing(detail: impl Into<String>) -> Self {
        Self::new(MediaAttachmentRejectionKind::MissingField, detail)
    }

    fn duplicate(detail: impl Into<String>) -> Self {
        Self::new(MediaAttachmentRejectionKind::DuplicateField, detail)
    }

    fn malformed(detail: impl Into<String>) -> Self {
        Self::new(MediaAttachmentRejectionKind::MalformedField, detail)
    }

    /// Reclassify a helper's `AppError` as a malformed-field rejection, keeping
    /// only its privacy-safe inner message.
    fn malformed_from(err: AppError) -> Self {
        Self::malformed(match err {
            AppError::InvalidAppMessagePayload(detail)
            | AppError::InvalidEncryptedMedia(detail) => detail,
            other => other.to_string(),
        })
    }
}

impl std::fmt::Display for MediaAttachmentRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl From<MediaAttachmentRejection> for AppError {
    fn from(rejection: MediaAttachmentRejection) -> Self {
        Self::MediaAttachmentRejected(rejection)
    }
}

/// One `imeta` attachment of a message, in tag order, either parsed or
/// rejected. `attachment_index` is the position among the message's `imeta`
/// tags (not among the accepted ones), so hosts can render an ordered mix of
/// media and placeholders and correlate with `list_media` records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MediaAttachmentOutcome {
    Accepted {
        attachment_index: u32,
        reference: MediaAttachmentReference,
    },
    Rejected {
        attachment_index: u32,
        rejection: MediaAttachmentRejection,
    },
}

impl MediaAttachmentOutcome {
    fn from_result(
        index: usize,
        result: Result<MediaAttachmentReference, MediaAttachmentRejection>,
    ) -> Self {
        let attachment_index = u32::try_from(index).unwrap_or(u32::MAX);
        match result {
            Ok(reference) => Self::Accepted {
                attachment_index,
                reference,
            },
            Err(rejection) => Self::Rejected {
                attachment_index,
                rejection,
            },
        }
    }
}

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
    ///
    /// Every failure is a typed [`MediaAttachmentRejection`]; callers that
    /// need an [`AppError`] convert with `?` and get
    /// [`AppError::MediaAttachmentRejected`].
    pub(crate) fn validate(
        &self,
        allow_loopback_http: bool,
    ) -> Result<(), MediaAttachmentRejection> {
        let version = EncryptedMediaVersion::parse(&self.version)
            .map_err(|_| MediaAttachmentRejection::unsupported("media version is not supported"))?;
        validate_sha256_hex(&self.ciphertext_sha256, "media ciphertext_sha256")
            .map_err(MediaAttachmentRejection::malformed_from)?;
        validate_sha256_hex(&self.plaintext_sha256, "media plaintext_sha256")
            .map_err(MediaAttachmentRejection::malformed_from)?;
        let expected_ciphertext_sha256 = self.ciphertext_sha256.to_ascii_lowercase();
        let nonce = hex::decode(&self.nonce_hex)
            .map_err(|_| MediaAttachmentRejection::malformed("media nonce must be hex"))?;
        if nonce.len() != 12 {
            return Err(MediaAttachmentRejection::malformed(
                "media nonce must be 12 bytes",
            ));
        }
        if self.locators.is_empty() {
            return Err(MediaAttachmentRejection::missing(
                "media attachment must include at least one locator",
            ));
        }
        for locator in &self.locators {
            validate_locator(locator, version, allow_loopback_http)
                .map_err(MediaAttachmentRejection::malformed_from)?;
            // The blossom content-hash binding is Blossom-specific integrity, like
            // the host-safety check in `validate_locator`: a `blossom-v1` locator
            // URL MUST carry the ciphertext hash so the fetched blob is the one
            // this reference commits to. A non-Blossom locator is never fetched by
            // this client and carries no such URL convention, so it is subject only
            // to the structural checks above and stays merely unfetchable.
            if version == EncryptedMediaVersion::V1 && locator.kind == BLOSSOM_LOCATOR_KIND_V1 {
                let locator_hash =
                    blossom_content_hash_from_url(&locator.value).ok_or_else(|| {
                        MediaAttachmentRejection::malformed(
                            "Blossom locator URL must include the encrypted blob hash",
                        )
                    })?;
                if locator_hash != expected_ciphertext_sha256 {
                    return Err(MediaAttachmentRejection::malformed(
                        "Blossom locator hash does not match media reference",
                    ));
                }
            }
        }
        match version {
            EncryptedMediaVersion::V1 if self.file_name.trim().is_empty() => {
                return Err(MediaAttachmentRejection::malformed(
                    "media file name cannot be empty",
                ));
            }
            EncryptedMediaVersion::V2
                if self.file_name.is_empty()
                    || self.file_name.len() > 255
                    || self.file_name.contains('\0') =>
            {
                return Err(MediaAttachmentRejection::malformed(
                    "media file name must be 1..255 UTF-8 bytes and contain no NUL",
                ));
            }
            _ => {}
        }
        match version {
            EncryptedMediaVersion::V1 => {
                canonical_media_type_v1(&self.media_type)
                    .map_err(MediaAttachmentRejection::malformed_from)?;
            }
            EncryptedMediaVersion::V2 => {
                let canonical = canonical_media_type_v2(&self.media_type)
                    .map_err(MediaAttachmentRejection::malformed_from)?;
                if canonical != self.media_type {
                    return Err(MediaAttachmentRejection::malformed(
                        "media type is not canonical for encrypted-media-v2",
                    ));
                }
            }
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
        expected_version: EncryptedMediaVersion,
        allowed_locator_kinds: &[String],
        allow_loopback_http: bool,
    ) -> Result<(), AppError> {
        self.validate(allow_loopback_http)?;
        if self.version != expected_version.as_str() {
            return Err(AppError::InvalidEncryptedMedia(format!(
                "group requires {} references",
                expected_version.as_str()
            )));
        }
        // Ingest still accepts noncanonical V1 `m` values for legacy wire
        // compatibility, but the checked outbound builder must emit the
        // canonical stored form exactly (same rule V2 already enforces in
        // `validate`).
        if expected_version == EncryptedMediaVersion::V1 {
            let canonical = canonical_media_type_v1(&self.media_type)?;
            if canonical != self.media_type {
                return Err(AppError::InvalidAppMessagePayload(
                    "media type is not canonical for encrypted-media-v1".into(),
                ));
            }
        }
        for locator in &self.locators {
            if !locator_kind_allowed(&locator.kind, allowed_locator_kinds) {
                return Err(AppError::InvalidEncryptedMedia(
                    "media locator kind is not allowed by the group policy".into(),
                ));
            }
        }
        Ok(())
    }

    /// Build the exact authenticated `imeta` tag for this reference after
    /// validating it against the target group's selected media version and
    /// locator policy.
    ///
    /// Host-facing callers must use this checked builder instead of formatting
    /// `imeta` fields themselves. In particular, the `version` carried by the
    /// reference cannot be used to smuggle a V1 reference into a V2 group (or
    /// vice versa).
    pub fn build_imeta_tag(
        &self,
        expected_version: EncryptedMediaVersion,
        allowed_locator_kinds: &[String],
        allow_loopback_http: bool,
    ) -> Result<Vec<String>, AppError> {
        self.validate_outbound(expected_version, allowed_locator_kinds, allow_loopback_http)?;
        Ok(self.imeta_tag())
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
        // Optional wire fields are emitted whenever they are present. `Some("")`
        // and `None` are distinct authenticated inputs; omitting a present-empty
        // value would make build -> parse lossy.
        if let Some(dim) = self.dim.as_deref() {
            tag.push(format!("dim {}", dim));
        }
        if let Some(thumbhash) = self.thumbhash.as_deref() {
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
    /// the group's versioned encrypted-media default endpoints are used.
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct MediaOperationPolicy<'a> {
    pub(crate) version: EncryptedMediaVersion,
    pub(crate) default_endpoints: &'a [crate::AppBlobEndpoint],
    pub(crate) allowed_locator_kinds: &'a [String],
    pub(crate) allow_loopback_http: bool,
}

pub(crate) async fn upload_encrypted_media(
    request: MediaUploadRequest,
    source_epoch: u64,
    media_secret: &[u8],
    signer: &dyn NostrSigner,
    policy: MediaOperationPolicy<'_>,
) -> Result<MediaUploadResult, AppError> {
    if request.attachments.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "media upload requires at least one attachment".into(),
        ));
    }
    validate_media_upload_batch(&request.attachments)?;
    let upload_servers = match request.blossom_server {
        Some(server) => vec![server],
        None => policy
            .default_endpoints
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
                signer,
                &upload_servers,
                policy,
            )
            .await?,
        );
    }
    Ok(MediaUploadResult {
        attachments,
        sent: None,
    })
}

fn validate_media_upload_batch(
    attachments: &[MediaUploadAttachmentRequest],
) -> Result<(), AppError> {
    validate_media_upload_batch_lengths(
        attachments
            .iter()
            .map(|attachment| attachment.plaintext.len() as u64),
    )
}

fn validate_media_upload_batch_lengths(
    lengths: impl IntoIterator<Item = u64>,
) -> Result<(), AppError> {
    let max_plaintext_bytes = MAX_ENCRYPTED_MEDIA_BLOB_BYTES - 16;
    let total_plaintext_bytes = lengths.into_iter().try_fold(0_u64, u64::checked_add);
    if total_plaintext_bytes.is_none_or(|total| total > max_plaintext_bytes) {
        return Err(AppError::InvalidEncryptedMedia(format!(
            "media upload batch exceeds {max_plaintext_bytes} bytes"
        )));
    }
    Ok(())
}

async fn upload_encrypted_media_attachment(
    request: MediaUploadAttachmentRequest,
    source_epoch: u64,
    media_secret: &[u8],
    signer: &dyn NostrSigner,
    upload_servers: &[String],
    policy: MediaOperationPolicy<'_>,
) -> Result<MediaUploadAttachmentResult, AppError> {
    if request.plaintext.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "media plaintext cannot be empty".into(),
        ));
    }
    validate_media_plaintext_len(request.plaintext.len() as u64)?;
    let file_name = match policy.version {
        EncryptedMediaVersion::V1 => request.file_name.trim().to_owned(),
        EncryptedMediaVersion::V2 => request.file_name,
    };
    validate_outbound_file_name(&file_name, policy.version)?;
    let media_type = match policy.version {
        EncryptedMediaVersion::V1 => canonical_media_type_v1(&request.media_type)?,
        EncryptedMediaVersion::V2 => canonical_media_type_v2(&request.media_type)?,
    };
    let plaintext_hash: [u8; 32] = Sha256::digest(&request.plaintext).into();
    let plaintext_sha256 = hex::encode(plaintext_hash);
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let file_key = derive_media_file_key(
        media_secret,
        policy.version,
        &plaintext_hash,
        &media_type,
        &file_name,
    )?;
    let aad = media_aad(policy.version, &plaintext_hash, &media_type, &file_name);
    let cipher = ChaCha20Poly1305::new_from_slice(&file_key)
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid media key length".into()))?;
    let mut encrypted = request.plaintext;
    cipher
        .encrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut encrypted)
        .map_err(|_| AppError::InvalidEncryptedMedia("media encryption failed".into()))?;
    let encrypted_size_bytes = encrypted.len() as u64;
    let ciphertext_sha256 = hex::encode(Sha256::digest(&encrypted));
    let url = upload_blossom_blob_with_fallback(
        upload_servers,
        Bytes::from(encrypted),
        &ciphertext_sha256,
        signer,
        policy.allow_loopback_http,
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
        version: policy.version.as_str().to_owned(),
        source_epoch,
        dim: request.dim,
        thumbhash: request.thumbhash,
    };
    // The reference we just built carries a single `blossom-v1` locator. Validate
    // it against the group's ACTUAL `allowed_locator_kinds` so an upload to a
    // group whose policy does not allow `blossom-v1` fails here rather than
    // emitting a reference its own receivers would reject.
    reference.validate_outbound(
        policy.version,
        policy.allowed_locator_kinds,
        policy.allow_loopback_http,
    )?;
    Ok(MediaUploadAttachmentResult {
        encrypted_size_bytes,
        reference,
    })
}

fn validate_media_plaintext_len(plaintext_bytes: u64) -> Result<(), AppError> {
    let max_plaintext_bytes = MAX_ENCRYPTED_MEDIA_BLOB_BYTES - 16;
    if plaintext_bytes > max_plaintext_bytes {
        return Err(AppError::InvalidEncryptedMedia(format!(
            "media plaintext exceeds {max_plaintext_bytes} bytes"
        )));
    }
    Ok(())
}

async fn upload_blossom_blob_with_fallback(
    servers: &[String],
    encrypted: Bytes,
    encrypted_hash_hex: &str,
    signer: &dyn NostrSigner,
    allow_loopback_http: bool,
) -> Result<String, AppError> {
    let mut failures = Vec::new();
    let mut timed_out = false;
    for (idx, server) in servers.iter().enumerate() {
        match upload_blossom_blob(
            server,
            encrypted.clone(),
            encrypted_hash_hex,
            signer,
            allow_loopback_http,
        )
        .await
        {
            Ok(url) => return Ok(url),
            Err(AppError::ExternalSignerRejected) => return Err(AppError::ExternalSignerRejected),
            Err(err) => {
                timed_out |= matches!(err, AppError::MediaUploadTimedOut);
                failures.push(format!(
                    "server {}: {}",
                    idx + 1,
                    upload_error_summary(&err)
                ));
            }
        }
    }
    if timed_out {
        // Any pre-publication timeout keeps the aggregate safely retryable,
        // even when another fallback also returned a terminal rejection.
        return Err(AppError::MediaUploadTimedOut);
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
        AppError::MediaUploadTimedOut => "request timed out".to_owned(),
        // `upload_blossom_blob` should currently surface upload failures through
        // the privacy-scrubbed variants above. Keep this fallback as a defensive
        // catch-all only; do not route URL-bearing transport errors here without
        // first adding an explicit scrubbed summary arm.
        other => other.to_string(),
    }
}

#[cfg(test)]
pub(crate) async fn download_encrypted_media(
    reference: MediaAttachmentReference,
    media_secret: &[u8],
    fallback_endpoints: &[crate::AppBlobEndpoint],
    allowed_locator_kinds: &[String],
    allow_loopback_blob_endpoints: bool,
) -> Result<MediaDownloadResult, AppError> {
    let transport = BlossomHttpTransport::new(allow_loopback_blob_endpoints);
    download_encrypted_media_with_transport(
        reference,
        media_secret,
        fallback_endpoints,
        allowed_locator_kinds,
        &transport,
        None,
    )
    .await
}

/// Download, authenticate, decrypt, and verify one attachment while optionally
/// recording only reviewed aggregate phase outcomes.
pub(crate) async fn download_encrypted_media_with_transport(
    reference: MediaAttachmentReference,
    media_secret: &[u8],
    fallback_endpoints: &[crate::AppBlobEndpoint],
    allowed_locator_kinds: &[String],
    transport: &BlossomHttpTransport,
    telemetry: Option<&AppPerformanceTelemetry>,
) -> Result<MediaDownloadResult, AppError> {
    // Structural validation only: an out-of-policy or client-unsupported locator
    // is judged at fetch time below, where it degrades to an unfetchable outcome
    // rather than a hard "corrupt reference" error.
    reference.validate(transport.allow_loopback_http)?;
    let version = EncryptedMediaVersion::parse(&reference.version)?;
    let encrypted = fetch_encrypted_media_blob_with_observer(
        &reference,
        fallback_endpoints,
        allowed_locator_kinds,
        transport,
        telemetry,
    )
    .await?;
    let plaintext_hash = media_hash_from_reference(&reference)?;
    let media_type = match version {
        EncryptedMediaVersion::V1 => canonical_media_type_v1(&reference.media_type)?,
        EncryptedMediaVersion::V2 => canonical_media_type_v2(&reference.media_type)?,
    };
    let nonce = media_nonce_from_reference(&reference)?;
    let file_key = derive_media_file_key(
        media_secret,
        version,
        &plaintext_hash,
        &media_type,
        &reference.file_name,
    )
    .map_err(media_download_failure)?;
    let aad = media_aad(version, &plaintext_hash, &media_type, &reference.file_name);
    let decrypt_started = Instant::now();
    let cipher = ChaCha20Poly1305::new_from_slice(&file_key).map_err(|_| {
        record_media_download_phase(
            telemetry,
            AppPerformanceOperation::MediaDownloadDecrypt,
            decrypt_started,
            false,
        );
        AppError::MediaDownloadFailed("invalid media key length".into())
    })?;
    let mut plaintext = encrypted;
    if cipher
        .decrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut plaintext)
        .is_err()
    {
        record_media_download_phase(
            telemetry,
            AppPerformanceOperation::MediaDownloadDecrypt,
            decrypt_started,
            false,
        );
        return Err(AppError::MediaDownloadFailed(
            "media decryption failed".into(),
        ));
    }
    record_media_download_phase(
        telemetry,
        AppPerformanceOperation::MediaDownloadDecrypt,
        decrypt_started,
        true,
    );
    let plaintext_verify_started = Instant::now();
    let actual_plaintext_hash: [u8; 32] = Sha256::digest(&plaintext).into();
    if actual_plaintext_hash != plaintext_hash {
        record_media_download_phase(
            telemetry,
            AppPerformanceOperation::MediaDownloadPlaintextVerify,
            plaintext_verify_started,
            false,
        );
        return Err(AppError::MediaDownloadFailed(
            "media plaintext hash does not match reference".into(),
        ));
    }
    record_media_download_phase(
        telemetry,
        AppPerformanceOperation::MediaDownloadPlaintextVerify,
        plaintext_verify_started,
        true,
    );
    Ok(MediaDownloadResult {
        size_bytes: plaintext.len() as u64,
        plaintext,
        file_name: reference.file_name,
        media_type,
    })
}

/// Compare downloaded ciphertext with the reference hash before decryption.
fn encrypted_media_hash_matches(encrypted: &[u8], expected_hash: &str) -> bool {
    hex::encode(Sha256::digest(encrypted)).eq_ignore_ascii_case(expected_hash)
}

#[cfg(test)]
async fn fetch_encrypted_media_blob(
    reference: &MediaAttachmentReference,
    fallback_endpoints: &[crate::AppBlobEndpoint],
    allowed_locator_kinds: &[String],
    allow_loopback_blob_endpoints: bool,
) -> Result<Vec<u8>, AppError> {
    let transport = BlossomHttpTransport::new(allow_loopback_blob_endpoints);
    fetch_encrypted_media_blob_with_transport(
        reference,
        fallback_endpoints,
        allowed_locator_kinds,
        &transport,
    )
    .await
}

#[cfg(test)]
async fn fetch_encrypted_media_blob_with_transport(
    reference: &MediaAttachmentReference,
    fallback_endpoints: &[crate::AppBlobEndpoint],
    allowed_locator_kinds: &[String],
    transport: &BlossomHttpTransport,
) -> Result<Vec<u8>, AppError> {
    fetch_encrypted_media_blob_with_observer(
        reference,
        fallback_endpoints,
        allowed_locator_kinds,
        transport,
        None,
    )
    .await
}

/// Try ordered locators under one deadline and record aggregate phase totals.
async fn fetch_encrypted_media_blob_with_observer(
    reference: &MediaAttachmentReference,
    fallback_endpoints: &[crate::AppBlobEndpoint],
    allowed_locator_kinds: &[String],
    transport: &BlossomHttpTransport,
    telemetry: Option<&AppPerformanceTelemetry>,
) -> Result<Vec<u8>, AppError> {
    // Fetchability is judged against CURRENT policy + current client support.
    // This client only fetches `blossom-v1`, so if the group's current policy
    // does not allow `blossom-v1` there is no fetchable locator and the
    // reference degrades to unfetchable (not invalid): the reference may still
    // be valid and the message delivered, only the blob is unreachable here.
    if !locator_kind_allowed(BLOSSOM_LOCATOR_KIND_V1, allowed_locator_kinds) {
        return Err(AppError::MediaUnfetchable(
            "media reference has no supported locators".into(),
        ));
    }
    let mut candidates = encrypted_media_fetch_candidates(reference, fallback_endpoints);
    // Host safety is client destination policy, judged before any dial: a
    // loopback-HTTP candidate is valid component state but unusable in a
    // production build, and a private/link-local/special-use literal host is
    // never dialed. Skip such candidates rather than GETting them. The
    // candidate may come from a remote-admin policy endpoint or a
    // sender-chosen locator, so the gate applies to both. What survives is
    // fetchable under policy; anything that then fails is a download failure.
    candidates.retain(|candidate| {
        url::Url::parse(candidate).is_ok_and(|url| {
            validate_blossom_fetch_url(&url, transport.allow_loopback_http).is_ok()
        })
    });
    if candidates.is_empty() {
        return Err(AppError::MediaUnfetchable(
            "media reference has no supported locators".into(),
        ));
    }
    let mut last_error = None;
    let expected_hash = reference.ciphertext_sha256.to_ascii_lowercase();
    let candidate_count = candidates.len();
    let download_deadline = tokio::time::Instant::now() + transport.transfer_timeout();
    for (index, candidate) in candidates.into_iter().enumerate() {
        let candidate_started = Instant::now();
        match blossom_content_hash_from_url(&candidate) {
            Some(hash) if hash == expected_hash => {}
            Some(_) => {
                // A URL that commits to a different blob cannot serve this
                // reference: the locator is unusable, so this candidate is
                // unfetchable rather than a failed download.
                last_error = Some(AppError::MediaUnfetchable(
                    "Blossom locator hash does not match media reference".into(),
                ));
                record_locator_failover_if_needed(
                    telemetry,
                    candidate_started,
                    index,
                    candidate_count,
                );
                continue;
            }
            None => {
                last_error = Some(AppError::MediaUnfetchable(
                    "Blossom locator URL did not include encrypted blob hash".into(),
                ));
                record_locator_failover_if_needed(
                    telemetry,
                    candidate_started,
                    index,
                    candidate_count,
                );
                continue;
            }
        }
        if download_deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .is_zero()
        {
            return Err(AppError::MediaDownloadFailed(
                "media download timed out".into(),
            ));
        }
        let fetched = blossom::fetch_blossom_blob_with_observer_until(
            &candidate,
            transport,
            telemetry,
            download_deadline,
        )
        .await;
        match fetched {
            Ok(bytes) => {
                let verify_started = Instant::now();
                let matches = encrypted_media_hash_matches(&bytes, &expected_hash);
                record_media_download_phase(
                    telemetry,
                    AppPerformanceOperation::MediaDownloadCiphertextVerify,
                    verify_started,
                    matches,
                );
                if matches {
                    return Ok(bytes);
                }
                last_error = Some(AppError::MediaDownloadFailed(
                    "encrypted blob hash does not match media reference".into(),
                ));
            }
            Err(err) => last_error = Some(media_download_failure(err)),
        }
        record_locator_failover_if_needed(telemetry, candidate_started, index, candidate_count);
    }
    Err(last_error.unwrap_or_else(|| AppError::MediaDownloadFailed("download failed".into())))
}

/// Classify a failure raised after a fetchable locator was selected. Transport
/// and integrity errors from the shared Blossom client arrive as `BlobStore` /
/// `InvalidEncryptedMedia`; on the encrypted-media download path they mean the
/// attachment is unavailable, never that the reference is invalid. Errors that
/// already carry a media class pass through unchanged.
fn media_download_failure(err: AppError) -> AppError {
    match err {
        AppError::BlobStore(detail)
        | AppError::InvalidEncryptedMedia(detail)
        | AppError::UnsafeMediaFetch(detail) => AppError::MediaDownloadFailed(detail),
        other => other,
    }
}

/// Record one reviewed media phase without dynamic labels or identifiers.
fn record_media_download_phase(
    telemetry: Option<&AppPerformanceTelemetry>,
    operation: AppPerformanceOperation,
    started_at: Instant,
    success: bool,
) {
    if let Some(telemetry) = telemetry {
        telemetry.record(operation, started_at.elapsed(), success);
    }
}

/// Record time lost to a candidate only when another locator will be tried.
fn record_locator_failover_if_needed(
    telemetry: Option<&AppPerformanceTelemetry>,
    started_at: Instant,
    candidate_index: usize,
    candidate_count: usize,
) {
    if candidate_index + 1 < candidate_count {
        record_media_download_phase(
            telemetry,
            AppPerformanceOperation::MediaDownloadLocatorFailover,
            started_at,
            true,
        );
    }
}

fn encrypted_media_fetch_candidates(
    reference: &MediaAttachmentReference,
    fallback_endpoints: &[crate::AppBlobEndpoint],
) -> Vec<String> {
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
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|candidate| seen.insert(candidate.clone()));
    candidates
}

/// Parse one authenticated `imeta` tag into a validated reference, or the
/// [`AppError::MediaAttachmentRejected`] wrapper around the typed rejection.
/// Prefer [`parse_media_attachment`] when the caller can act on the category.
pub fn media_attachment_from_imeta_tag(
    tag: &[String],
    source_epoch: Option<u64>,
    allow_loopback_http: bool,
) -> Result<MediaAttachmentReference, AppError> {
    parse_media_attachment(tag, source_epoch, allow_loopback_http).map_err(AppError::from)
}

/// The shared strict `imeta` parser: every projection, the standalone parse
/// binding, and the CLI reach the same verdict for the same tag.
///
/// The version field is judged before anything else so the rejection category
/// does not depend on field order: a tag with no `v`, or a `v` this client does
/// not implement (including MIP-era shapes), is [`UnsupportedFormat`]
/// regardless of what else is wrong with it. Strictness is unchanged; only the
/// precedence among several independent defects is fixed.
///
/// [`UnsupportedFormat`]: MediaAttachmentRejectionKind::UnsupportedFormat
pub fn parse_media_attachment(
    tag: &[String],
    source_epoch: Option<u64>,
    allow_loopback_http: bool,
) -> Result<MediaAttachmentReference, MediaAttachmentRejection> {
    if tag.first().map(String::as_str) != Some("imeta") {
        return Err(MediaAttachmentRejection::structure(
            "media tag must be imeta",
        ));
    }
    let mut version = None;
    for field in tag.iter().skip(1) {
        if field == "v" {
            return Err(MediaAttachmentRejection::structure(
                "media field v is missing its value",
            ));
        }
        if let Some(value) = field.strip_prefix("v ") {
            if version.is_some() {
                return Err(MediaAttachmentRejection::duplicate(
                    "media tag must contain exactly one version",
                ));
            }
            EncryptedMediaVersion::parse(value).map_err(|_| {
                MediaAttachmentRejection::unsupported("media version is not supported")
            })?;
            version = Some(value.to_owned());
        }
    }
    let Some(version) = version else {
        return Err(MediaAttachmentRejection::unsupported("media tag missing v"));
    };
    let mut locators = Vec::new();
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
    let set_once = |slot: &mut Option<String>,
                    value: &str,
                    label: &str|
     -> Result<(), MediaAttachmentRejection> {
        if slot.is_some() {
            return Err(MediaAttachmentRejection::duplicate(format!(
                "media tag must contain exactly one {label}"
            )));
        }
        *slot = Some(value.to_owned());
        Ok(())
    };
    for field in tag.iter().skip(1) {
        if field == "blurhash" || field.starts_with("blurhash ") {
            return Err(MediaAttachmentRejection::malformed(
                "encrypted media uses thumbhash, not blurhash",
            ));
        }
        if let Some(rest) = field.strip_prefix("locator ") {
            let (kind, value) = rest.split_once(' ').ok_or_else(|| {
                MediaAttachmentRejection::structure("media locator must include kind and value")
            })?;
            locators.push(MediaLocator {
                kind: kind.to_owned(),
                value: value.to_owned(),
            });
            continue;
        }
        let Some((key, value)) = field.split_once(' ') else {
            if matches!(
                field.as_str(),
                "locator"
                    | "ciphertext_sha256"
                    | "plaintext_sha256"
                    | "nonce"
                    | "m"
                    | "filename"
                    | "dim"
                    | "thumbhash"
            ) {
                return Err(MediaAttachmentRejection::structure(format!(
                    "media field {field} is missing its value"
                )));
            }
            continue;
        };
        match key {
            // Judged in the version pre-pass above.
            "v" => {}
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
            .filter(|value| !value.is_empty())
            .ok_or_else(|| MediaAttachmentRejection::missing(format!("media tag missing {name}")))
    };
    let reference = MediaAttachmentReference {
        locators,
        ciphertext_sha256: required("ciphertext_sha256", ciphertext_sha256)?,
        plaintext_sha256: required("plaintext_sha256", plaintext_sha256)?,
        nonce_hex: required("nonce", nonce_hex)?,
        file_name: required("filename", file_name)?,
        media_type: required("m", media_type)?,
        version,
        source_epoch: source_epoch.unwrap_or_default(),
        dim,
        thumbhash,
    };
    reference.validate(allow_loopback_http)?;
    Ok(reference)
}

/// Project a message's `imeta` tags into ordered per-attachment outcomes.
///
/// Only tags whose first element is `imeta` are attachments; other tags do not
/// consume an index. Rejection is attachment-local: a malformed tag yields a
/// [`MediaAttachmentOutcome::Rejected`] entry at its position and never hides
/// its valid siblings or the carrying message.
pub fn media_attachment_outcomes_from_tags(
    tags: &[Vec<String>],
    source_epoch: Option<u64>,
    allow_loopback_http: bool,
) -> Vec<MediaAttachmentOutcome> {
    tags.iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .enumerate()
        .map(|(index, tag)| {
            MediaAttachmentOutcome::from_result(
                index,
                parse_media_attachment(tag, source_epoch, allow_loopback_http),
            )
        })
        .collect()
}

/// Project a materialized timeline row's `media` metadata (`{ "imeta": [..] }`,
/// built by the storage projection from exactly the message's `imeta` tags in
/// order) into the same ordered outcomes as
/// [`media_attachment_outcomes_from_tags`] yields for the raw message, so a
/// timeline row and a `list_media` record for one message agree on every index.
///
/// `None`, or metadata without an `imeta` list, means the message has no
/// attachments. An entry that is not an array of strings is reported as an
/// [`InvalidStructure`] rejection at its position; an `imeta` value that is not
/// a list cannot be indexed and is reported once at index 0.
///
/// [`InvalidStructure`]: MediaAttachmentRejectionKind::InvalidStructure
pub fn media_attachment_outcomes_from_media_json(
    media: Option<&Value>,
    source_epoch: Option<u64>,
    allow_loopback_http: bool,
) -> Vec<MediaAttachmentOutcome> {
    let Some(imeta) = media.and_then(|media| media.get("imeta")) else {
        return Vec::new();
    };
    let Some(entries) = imeta.as_array() else {
        return vec![MediaAttachmentOutcome::from_result(
            0,
            Err(MediaAttachmentRejection::structure(
                "media metadata could not be decoded",
            )),
        )];
    };
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let parsed = serde_json::from_value::<Vec<String>>(entry.clone())
                .map_err(|_| MediaAttachmentRejection::structure("media tag could not be decoded"))
                .and_then(|tag| parse_media_attachment(&tag, source_epoch, allow_loopback_http));
            MediaAttachmentOutcome::from_result(index, parsed)
        })
        .collect()
}

/// Whether `tags` contains at least one structurally valid media reference.
/// Invalid references are attachment-local and do not suppress valid siblings.
pub(crate) fn media_imeta_tags_are_valid(tags: &[Vec<String>], allow_loopback_http: bool) -> bool {
    tags.iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .any(|tag| media_attachment_from_imeta_tag(tag, None, allow_loopback_http).is_ok())
}

/// Whether malformed encrypted-media references may preserve their carrying
/// app message.
///
/// Frozen V1 made structural rejection message-fatal. V2 deliberately changed
/// that rule to attachment-local rejection. Only tags that explicitly claim
/// V1 select the legacy behavior; malformed, absent, and future version fields
/// are invalid references but are not reinterpreted as V1.
pub(crate) fn media_imeta_tags_preserve_message(
    tags: &[Vec<String>],
    allow_loopback_http: bool,
) -> bool {
    tags.iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .filter(|tag| {
            tag.iter().skip(1).any(|field| {
                field.strip_prefix("v ").map(str::trim) == Some(ENCRYPTED_MEDIA_FORMAT_V1)
            })
        })
        .all(|tag| media_attachment_from_imeta_tag(tag, None, allow_loopback_http).is_ok())
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

fn validate_outbound_file_name(
    file_name: &str,
    version: EncryptedMediaVersion,
) -> Result<(), AppError> {
    let valid = match version {
        EncryptedMediaVersion::V1 => !file_name.trim().is_empty(),
        EncryptedMediaVersion::V2 => {
            !file_name.is_empty() && file_name.len() <= 255 && !file_name.contains('\0')
        }
    };
    if valid {
        Ok(())
    } else {
        Err(AppError::InvalidEncryptedMedia(match version {
            EncryptedMediaVersion::V1 => "media file name cannot be empty".into(),
            EncryptedMediaVersion::V2 => {
                "media file name must be 1..255 UTF-8 bytes and contain no NUL".into()
            }
        }))
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_profile_image;
