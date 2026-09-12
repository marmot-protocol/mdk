//! Privacy-safe, typed attachment validation and operation diagnostics.
//!
//! Hosts localize from the closed enums. `MediaDiagnostic::message` is
//! library-owned presentation text, never raw parser, URL, HTTP-body, or
//! cryptographic error text.

use serde_json::Value;

use super::{MediaAttachmentReference, media_attachment_from_imeta_tag};
use crate::AppError;

/// Which attachment pipeline stage produced a diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaErrorStage {
    Metadata,
    Outbound,
    Fetch,
    Decrypt,
}

/// Closed reason vocabulary for attachment failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaErrorCode {
    InvalidStructure,
    MissingField,
    DuplicateField,
    MalformedField,
    UnsupportedVersion,
    UnsupportedFormat,
    ProfileMismatch,
    DestinationPolicy,
    NoSupportedLocator,
    DownloadFailed,
    DecryptionFailed,
    IntegrityMismatch,
}

/// Closed field vocabulary. Never an untrusted tag key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaErrorField {
    Version,
    Locator,
    CiphertextSha256,
    PlaintextSha256,
    Nonce,
    MediaType,
    FileName,
    Dimensions,
    Thumbhash,
}

/// One privacy-safe attachment diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaDiagnostic {
    pub stage: MediaErrorStage,
    pub code: MediaErrorCode,
    pub field: Option<MediaErrorField>,
    pub message: String,
}

impl MediaDiagnostic {
    /// Build a diagnostic whose `message` is caller-supplied library-owned text.
    pub fn with_library_message(
        stage: MediaErrorStage,
        code: MediaErrorCode,
        field: Option<MediaErrorField>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            code,
            field,
            message: message.into(),
        }
    }

    pub fn metadata(
        code: MediaErrorCode,
        field: Option<MediaErrorField>,
        message: impl Into<String>,
    ) -> Self {
        Self::with_library_message(MediaErrorStage::Metadata, code, field, message)
    }

    pub fn outbound(
        code: MediaErrorCode,
        field: Option<MediaErrorField>,
        message: impl Into<String>,
    ) -> Self {
        Self::with_library_message(MediaErrorStage::Outbound, code, field, message)
    }

    pub fn fetch(
        code: MediaErrorCode,
        field: Option<MediaErrorField>,
        message: impl Into<String>,
    ) -> Self {
        Self::with_library_message(MediaErrorStage::Fetch, code, field, message)
    }

    pub fn decrypt(
        code: MediaErrorCode,
        field: Option<MediaErrorField>,
        message: impl Into<String>,
    ) -> Self {
        Self::with_library_message(MediaErrorStage::Decrypt, code, field, message)
    }
}

impl std::fmt::Display for MediaDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(formatter)
    }
}

impl From<MediaDiagnostic> for AppError {
    fn from(value: MediaDiagnostic) -> Self {
        Self::MediaAttachment(value)
    }
}

/// Parsed or rejected attachment outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MediaAttachmentResult {
    Parsed { reference: MediaAttachmentReference },
    Rejected { diagnostic: MediaDiagnostic },
}

/// One ordered candidate outcome. `attachment_index` is zero-based among
/// candidate `imeta` tags before validation, or the timeline `imeta` array
/// position. Only a malformed whole container uses `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaAttachmentProjection {
    pub attachment_index: Option<u32>,
    pub result: MediaAttachmentResult,
}

impl MediaAttachmentProjection {
    pub fn parsed(attachment_index: Option<u32>, reference: MediaAttachmentReference) -> Self {
        Self {
            attachment_index,
            result: MediaAttachmentResult::Parsed { reference },
        }
    }

    pub fn rejected(attachment_index: Option<u32>, diagnostic: MediaDiagnostic) -> Self {
        Self {
            attachment_index,
            result: MediaAttachmentResult::Rejected { diagnostic },
        }
    }

    pub fn parsed_reference(&self) -> Option<&MediaAttachmentReference> {
        match &self.result {
            MediaAttachmentResult::Parsed { reference } => Some(reference),
            MediaAttachmentResult::Rejected { .. } => None,
        }
    }
}

pub(crate) fn field_from_media_key(key: &str) -> Option<MediaErrorField> {
    match key {
        "v" | "version" => Some(MediaErrorField::Version),
        "locator" => Some(MediaErrorField::Locator),
        "ciphertext_sha256" => Some(MediaErrorField::CiphertextSha256),
        "plaintext_sha256" => Some(MediaErrorField::PlaintextSha256),
        "nonce" => Some(MediaErrorField::Nonce),
        "m" => Some(MediaErrorField::MediaType),
        "filename" => Some(MediaErrorField::FileName),
        "dim" => Some(MediaErrorField::Dimensions),
        "thumbhash" | "blurhash" => Some(MediaErrorField::Thumbhash),
        _ => None,
    }
}

pub(crate) fn metadata_error(
    code: MediaErrorCode,
    field: Option<MediaErrorField>,
    message: impl Into<String>,
) -> AppError {
    MediaDiagnostic::metadata(code, field, message).into()
}

fn container_invalid_structure() -> MediaAttachmentProjection {
    MediaAttachmentProjection::rejected(
        None,
        MediaDiagnostic::metadata(
            MediaErrorCode::InvalidStructure,
            None,
            "media container is malformed",
        ),
    )
}

fn entry_invalid_structure(attachment_index: Option<u32>) -> MediaAttachmentProjection {
    MediaAttachmentProjection::rejected(
        attachment_index,
        MediaDiagnostic::metadata(
            MediaErrorCode::InvalidStructure,
            None,
            "media attachment entry is malformed",
        ),
    )
}

fn outcome_from_parse(
    attachment_index: Option<u32>,
    result: Result<MediaAttachmentReference, AppError>,
) -> MediaAttachmentProjection {
    match result {
        Ok(reference) => MediaAttachmentProjection::parsed(attachment_index, reference),
        Err(AppError::MediaAttachment(diagnostic)) => {
            MediaAttachmentProjection::rejected(attachment_index, diagnostic)
        }
        Err(_) => entry_invalid_structure(attachment_index),
    }
}

/// Project message `imeta` tags into one ordered outcome per candidate.
///
/// Unrelated top-level tags are not candidates. `attachment_index` is
/// zero-based among `imeta` tags before validation.
pub fn project_media_attachments(
    tags: &[Vec<String>],
    source_epoch: Option<u64>,
    allow_loopback_http: bool,
) -> Vec<MediaAttachmentProjection> {
    tags.iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .enumerate()
        .map(|(index, tag)| {
            let attachment_index = Some(u32::try_from(index).unwrap_or(u32::MAX));
            outcome_from_parse(
                attachment_index,
                media_attachment_from_imeta_tag(tag, source_epoch, allow_loopback_http),
            )
        })
        .collect()
}

/// Project stored timeline media JSON into ordered outcomes.
///
/// `decode_failed` is a container-level `InvalidStructure` with no index.
/// A missing value or an object with no `imeta` (including an empty array)
/// yields no outcomes. Timeline entries use array positions, including
/// malformed entries.
pub fn project_timeline_media_attachments(
    media: Option<&Value>,
    decode_failed: bool,
    source_epoch: Option<u64>,
    allow_loopback_http: bool,
) -> Vec<MediaAttachmentProjection> {
    if decode_failed {
        return vec![container_invalid_structure()];
    }
    let Some(value) = media else {
        return Vec::new();
    };
    if !value.is_object() {
        return vec![container_invalid_structure()];
    }
    let Some(imeta) = value.get("imeta") else {
        return Vec::new();
    };
    if !imeta.is_array() {
        return vec![container_invalid_structure()];
    }
    let entries = imeta.as_array().expect("imeta array");
    if entries.is_empty() {
        return Vec::new();
    }
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let attachment_index = Some(u32::try_from(index).unwrap_or(u32::MAX));
            project_timeline_entry(entry, attachment_index, source_epoch, allow_loopback_http)
        })
        .collect()
}

fn project_timeline_entry(
    entry: &Value,
    attachment_index: Option<u32>,
    source_epoch: Option<u64>,
    allow_loopback_http: bool,
) -> MediaAttachmentProjection {
    let Some(array) = entry.as_array() else {
        return entry_invalid_structure(attachment_index);
    };
    if array.is_empty() {
        return entry_invalid_structure(attachment_index);
    }
    let mut tag = Vec::with_capacity(array.len());
    for field in array {
        let Some(text) = field.as_str() else {
            return entry_invalid_structure(attachment_index);
        };
        tag.push(text.to_owned());
    }
    if tag.first().map(String::as_str) != Some("imeta") {
        return entry_invalid_structure(attachment_index);
    }
    outcome_from_parse(
        attachment_index,
        media_attachment_from_imeta_tag(&tag, source_epoch, allow_loopback_http),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_v1_tag() -> Vec<String> {
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

    fn valid_v2_tag() -> Vec<String> {
        let mut tag = valid_v1_tag();
        tag[1] = "v encrypted-media-v2".to_owned();
        tag
    }

    fn rejected_code(projection: &MediaAttachmentProjection) -> MediaErrorCode {
        match &projection.result {
            MediaAttachmentResult::Rejected { diagnostic } => diagnostic.code,
            MediaAttachmentResult::Parsed { .. } => panic!("expected rejection"),
        }
    }

    #[test]
    fn project_media_attachments_skips_unrelated_tags_and_keeps_indices() {
        let tags = vec![
            vec!["p".to_owned(), "aa".repeat(32)],
            vec!["imeta".to_owned(), "v encrypted-media-v1".to_owned()],
            valid_v1_tag(),
            vec!["e".to_owned(), "bb".repeat(32)],
            vec!["imeta".to_owned(), "v encrypted-media-v1".to_owned()],
            valid_v2_tag(),
        ];

        let outcomes = project_media_attachments(&tags, Some(4), false);
        assert_eq!(outcomes.len(), 4);
        assert_eq!(outcomes[0].attachment_index, Some(0));
        assert_eq!(rejected_code(&outcomes[0]), MediaErrorCode::MissingField);
        assert_eq!(outcomes[1].attachment_index, Some(1));
        assert!(matches!(
            outcomes[1].result,
            MediaAttachmentResult::Parsed { .. }
        ));
        assert_eq!(outcomes[2].attachment_index, Some(2));
        assert_eq!(rejected_code(&outcomes[2]), MediaErrorCode::MissingField);
        assert_eq!(outcomes[3].attachment_index, Some(3));
        assert!(matches!(
            outcomes[3].result,
            MediaAttachmentResult::Parsed { .. }
        ));
        assert_eq!(
            outcomes[1].parsed_reference().unwrap().version,
            "encrypted-media-v1"
        );
        assert_eq!(
            outcomes[3].parsed_reference().unwrap().version,
            "encrypted-media-v2"
        );
    }

    #[test]
    fn project_timeline_no_media_and_empty_imeta_yield_no_outcomes() {
        assert!(project_timeline_media_attachments(None, false, Some(1), false).is_empty());
        assert!(
            project_timeline_media_attachments(Some(&serde_json::json!({})), false, Some(1), false)
                .is_empty()
        );
        assert!(
            project_timeline_media_attachments(
                Some(&serde_json::json!({ "imeta": [] })),
                false,
                Some(1),
                false
            )
            .is_empty()
        );
    }

    #[test]
    fn project_timeline_container_failures_have_no_index() {
        let decode_failed = project_timeline_media_attachments(None, true, Some(1), false);
        assert_eq!(decode_failed.len(), 1);
        assert_eq!(decode_failed[0].attachment_index, None);
        assert_eq!(
            rejected_code(&decode_failed[0]),
            MediaErrorCode::InvalidStructure
        );

        let nonobject =
            project_timeline_media_attachments(Some(&serde_json::json!([])), false, Some(1), false);
        assert_eq!(nonobject[0].attachment_index, None);
        assert_eq!(
            rejected_code(&nonobject[0]),
            MediaErrorCode::InvalidStructure
        );

        let nonarray = project_timeline_media_attachments(
            Some(&serde_json::json!({ "imeta": {} })),
            false,
            Some(1),
            false,
        );
        assert_eq!(nonarray[0].attachment_index, None);
        assert_eq!(
            rejected_code(&nonarray[0]),
            MediaErrorCode::InvalidStructure
        );
    }

    #[test]
    fn project_timeline_keeps_valid_entries_around_malformed_ones() {
        let media = serde_json::json!({
            "imeta": [
                ["imeta", "v encrypted-media-v1"],
                valid_v1_tag(),
                [],
                valid_v2_tag(),
                "not-an-array",
                ["notimeta", "v encrypted-media-v1"],
            ]
        });
        let outcomes = project_timeline_media_attachments(Some(&media), false, Some(9), false);
        assert_eq!(outcomes.len(), 6);
        assert_eq!(outcomes[0].attachment_index, Some(0));
        assert_eq!(rejected_code(&outcomes[0]), MediaErrorCode::MissingField);
        assert!(matches!(
            outcomes[1].result,
            MediaAttachmentResult::Parsed { .. }
        ));
        assert_eq!(outcomes[2].attachment_index, Some(2));
        assert_eq!(
            rejected_code(&outcomes[2]),
            MediaErrorCode::InvalidStructure
        );
        assert!(matches!(
            outcomes[3].result,
            MediaAttachmentResult::Parsed { .. }
        ));
        assert_eq!(
            rejected_code(&outcomes[4]),
            MediaErrorCode::InvalidStructure
        );
        assert_eq!(
            rejected_code(&outcomes[5]),
            MediaErrorCode::InvalidStructure
        );
        assert_eq!(outcomes[1].parsed_reference().unwrap().source_epoch, 9);
    }

    #[test]
    fn diagnostic_message_is_library_owned() {
        let diagnostic = MediaDiagnostic::metadata(
            MediaErrorCode::MalformedField,
            Some(MediaErrorField::Locator),
            "media locator URL is invalid",
        );
        assert!(!diagnostic.message.contains("http"));
        assert!(!diagnostic.message.contains("example"));
    }

    #[test]
    fn stages_differ_for_metadata_fetch_and_decrypt() {
        let metadata = MediaDiagnostic::metadata(
            MediaErrorCode::MissingField,
            Some(MediaErrorField::Nonce),
            "media attachment is missing nonce",
        );
        let fetch = MediaDiagnostic::fetch(
            MediaErrorCode::DownloadFailed,
            Some(MediaErrorField::Locator),
            "media download failed",
        );
        let decrypt = MediaDiagnostic::decrypt(
            MediaErrorCode::DecryptionFailed,
            None,
            "media decryption failed",
        );
        assert_eq!(metadata.stage, MediaErrorStage::Metadata);
        assert_eq!(fetch.stage, MediaErrorStage::Fetch);
        assert_eq!(decrypt.stage, MediaErrorStage::Decrypt);
        assert_ne!(metadata.code, fetch.code);
        assert_ne!(fetch.code, decrypt.code);
    }

    #[test]
    fn synthetic_marker_strings_do_not_appear_in_library_messages() {
        let marker = "https://leak.example/SECRET-TAG-filename.png#aabbcc";
        let err = media_attachment_from_imeta_tag(
            &[
                "imeta".to_owned(),
                "v encrypted-media-v1".to_owned(),
                format!("locator blossom-v1 {marker}"),
            ],
            Some(1),
            false,
        )
        .expect_err("incomplete tag must fail");
        let AppError::MediaAttachment(diagnostic) = err else {
            panic!("expected typed media diagnostic");
        };
        assert!(!diagnostic.message.contains(marker));
        assert!(!diagnostic.message.contains("leak.example"));
        assert!(!diagnostic.message.contains("SECRET-TAG"));
        assert!(!diagnostic.message.contains("filename.png"));
        assert!(!diagnostic.message.contains("aabbcc"));
    }
}
