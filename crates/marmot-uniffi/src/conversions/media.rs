//! Media locator, attachment, upload/download, and media-record FFI conversions.

use marmot_app::{
    AppError, AppMessageRecord, EncryptedMediaVersion, MediaAttachmentOutcome,
    MediaAttachmentReference, MediaAttachmentRejection, MediaAttachmentRejectionKind,
    MediaDownloadResult, MediaLocator, MediaUploadAttachmentRequest, MediaUploadRequest,
    MediaUploadResult,
};

use super::account::SendSummaryFfi;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum EncryptedMediaVersionFfi {
    V1,
    V2,
}

impl From<EncryptedMediaVersion> for EncryptedMediaVersionFfi {
    fn from(value: EncryptedMediaVersion) -> Self {
        match value {
            EncryptedMediaVersion::V1 => Self::V1,
            EncryptedMediaVersion::V2 => Self::V2,
        }
    }
}

impl From<EncryptedMediaVersionFfi> for EncryptedMediaVersion {
    fn from(value: EncryptedMediaVersionFfi) -> Self {
        match value {
            EncryptedMediaVersionFfi::V1 => Self::V1,
            EncryptedMediaVersionFfi::V2 => Self::V2,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaLocatorFfi {
    pub kind: String,
    pub value: String,
}

impl From<MediaLocator> for MediaLocatorFfi {
    fn from(value: MediaLocator) -> Self {
        Self {
            kind: value.kind,
            value: value.value,
        }
    }
}

impl From<MediaLocatorFfi> for MediaLocator {
    fn from(value: MediaLocatorFfi) -> Self {
        Self {
            kind: value.kind,
            value: value.value,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaAttachmentReferenceFfi {
    pub locators: Vec<MediaLocatorFfi>,
    pub ciphertext_sha256: String,
    pub plaintext_sha256: String,
    pub nonce_hex: String,
    pub file_name: String,
    pub media_type: String,
    pub version: EncryptedMediaVersionFfi,
    pub source_epoch: u64,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

impl TryFrom<MediaAttachmentReference> for MediaAttachmentReferenceFfi {
    type Error = AppError;

    fn try_from(value: MediaAttachmentReference) -> Result<Self, Self::Error> {
        Ok(Self {
            locators: value.locators.into_iter().map(Into::into).collect(),
            ciphertext_sha256: value.ciphertext_sha256,
            plaintext_sha256: value.plaintext_sha256,
            nonce_hex: value.nonce_hex,
            file_name: value.file_name,
            media_type: value.media_type,
            version: EncryptedMediaVersion::parse(&value.version)?.into(),
            source_epoch: value.source_epoch,
            dim: value.dim,
            thumbhash: value.thumbhash,
        })
    }
}

impl From<MediaAttachmentReferenceFfi> for MediaAttachmentReference {
    fn from(value: MediaAttachmentReferenceFfi) -> Self {
        Self {
            locators: value.locators.into_iter().map(Into::into).collect(),
            ciphertext_sha256: value.ciphertext_sha256,
            plaintext_sha256: value.plaintext_sha256,
            nonce_hex: value.nonce_hex,
            file_name: value.file_name,
            media_type: value.media_type,
            version: EncryptedMediaVersion::from(value.version)
                .as_str()
                .to_owned(),
            source_epoch: value.source_epoch,
            dim: value.dim,
            thumbhash: value.thumbhash,
        }
    }
}

/// Stable category of an encrypted-media attachment rejection (mdk#1787).
/// Branch on this instead of parsing `detail`; the set only grows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MediaAttachmentRejectionKindFfi {
    /// Not a decodable encrypted-media `imeta` tag (wrong marker, a non-string
    /// element, a field without its value, a locator without `kind value`).
    InvalidStructure,
    /// The `v` field is absent or names a format this build does not
    /// implement. Legacy MIP-era and future shapes land here: render as
    /// "unsupported attachment", not as corrupt content.
    UnsupportedFormat,
    /// A required field is absent or empty.
    MissingField,
    /// A single-occurrence field appears more than once.
    DuplicateField,
    /// A present field has an invalid value (hash, nonce, locator URL, media
    /// type, filename, or a forbidden `blurhash`).
    MalformedField,
}

impl From<MediaAttachmentRejectionKind> for MediaAttachmentRejectionKindFfi {
    fn from(value: MediaAttachmentRejectionKind) -> Self {
        match value {
            MediaAttachmentRejectionKind::InvalidStructure => Self::InvalidStructure,
            MediaAttachmentRejectionKind::UnsupportedFormat => Self::UnsupportedFormat,
            MediaAttachmentRejectionKind::MissingField => Self::MissingField,
            MediaAttachmentRejectionKind::DuplicateField => Self::DuplicateField,
            MediaAttachmentRejectionKind::MalformedField => Self::MalformedField,
        }
    }
}

impl From<MediaAttachmentRejectionKindFfi> for MediaAttachmentRejectionKind {
    fn from(value: MediaAttachmentRejectionKindFfi) -> Self {
        match value {
            MediaAttachmentRejectionKindFfi::InvalidStructure => Self::InvalidStructure,
            MediaAttachmentRejectionKindFfi::UnsupportedFormat => Self::UnsupportedFormat,
            MediaAttachmentRejectionKindFfi::MissingField => Self::MissingField,
            MediaAttachmentRejectionKindFfi::DuplicateField => Self::DuplicateField,
            MediaAttachmentRejectionKindFfi::MalformedField => Self::MalformedField,
        }
    }
}

impl std::fmt::Display for MediaAttachmentRejectionKindFfi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(MediaAttachmentRejectionKind::from(*self).as_str())
    }
}

/// Why one attachment was rejected. `detail` is privacy-safe presentation text
/// from the shared parser; it never echoes tag content.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MediaAttachmentRejectionFfi {
    pub kind: MediaAttachmentRejectionKindFfi,
    pub detail: String,
}

impl From<MediaAttachmentRejection> for MediaAttachmentRejectionFfi {
    fn from(value: MediaAttachmentRejection) -> Self {
        Self {
            kind: value.kind.into(),
            detail: value.detail,
        }
    }
}

/// One `imeta` attachment of a message, in tag order. `attachment_index` is the
/// position among the message's `imeta` tags (rejected siblings included), so a
/// host can render media and placeholders in order and correlate a timeline
/// row with `list_media` records for the same message. Pass an `Accepted`
/// reference to `download_media`; render `Rejected` as an unsupported/invalid
/// attachment placeholder using `rejection.kind`.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum MediaAttachmentOutcomeFfi {
    Accepted {
        attachment_index: u32,
        reference: MediaAttachmentReferenceFfi,
    },
    Rejected {
        attachment_index: u32,
        rejection: MediaAttachmentRejectionFfi,
    },
}

impl From<MediaAttachmentOutcome> for MediaAttachmentOutcomeFfi {
    fn from(value: MediaAttachmentOutcome) -> Self {
        match value {
            MediaAttachmentOutcome::Accepted {
                attachment_index,
                reference,
            } => match MediaAttachmentReferenceFfi::try_from(reference) {
                Ok(reference) => Self::Accepted {
                    attachment_index,
                    reference,
                },
                // The shared parser only accepts versions this build types, so
                // this is unreachable for projected content; keep the reason
                // rather than dropping the attachment if it ever fires.
                Err(_) => Self::Rejected {
                    attachment_index,
                    rejection: MediaAttachmentRejectionFfi {
                        kind: MediaAttachmentRejectionKindFfi::UnsupportedFormat,
                        detail: "media version is not supported".to_owned(),
                    },
                },
            },
            MediaAttachmentOutcome::Rejected {
                attachment_index,
                rejection,
            } => Self::Rejected {
                attachment_index,
                rejection: rejection.into(),
            },
        }
    }
}

/// Convert shared outcomes for the FFI boundary, logging only the aggregate
/// rejection count (never tag content or identifiers).
pub(crate) fn media_attachment_outcomes_ffi(
    method: &'static str,
    outcomes: Vec<MediaAttachmentOutcome>,
) -> Vec<MediaAttachmentOutcomeFfi> {
    let rejected = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, MediaAttachmentOutcome::Rejected { .. }))
        .count();
    if rejected > 0 {
        tracing::debug!(
            target: "marmot_uniffi::conversions",
            method,
            rejected_attachments = rejected,
            "projected media attachments the shared parser rejected",
        );
    }
    outcomes.into_iter().map(Into::into).collect()
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadAttachmentRequestFfi {
    pub file_name: String,
    pub media_type: String,
    pub plaintext: Vec<u8>,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

impl From<MediaUploadAttachmentRequestFfi> for MediaUploadAttachmentRequest {
    fn from(value: MediaUploadAttachmentRequestFfi) -> Self {
        Self {
            file_name: value.file_name,
            media_type: value.media_type,
            plaintext: value.plaintext,
            dim: value.dim,
            thumbhash: value.thumbhash,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadRequestFfi {
    pub attachments: Vec<MediaUploadAttachmentRequestFfi>,
    pub caption: Option<String>,
    pub send: bool,
    pub blossom_server: Option<String>,
}

impl From<MediaUploadRequestFfi> for MediaUploadRequest {
    fn from(value: MediaUploadRequestFfi) -> Self {
        Self {
            attachments: value.attachments.into_iter().map(Into::into).collect(),
            caption: value.caption,
            send: value.send,
            blossom_server: value.blossom_server,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadAttachmentResultFfi {
    pub reference: MediaAttachmentReferenceFfi,
    pub encrypted_size_bytes: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadResultFfi {
    pub attachments: Vec<MediaUploadAttachmentResultFfi>,
    pub sent: Option<SendSummaryFfi>,
}

impl TryFrom<MediaUploadResult> for MediaUploadResultFfi {
    type Error = AppError;

    fn try_from(value: MediaUploadResult) -> Result<Self, Self::Error> {
        Ok(Self {
            attachments: value
                .attachments
                .into_iter()
                .map(|attachment| {
                    Ok(MediaUploadAttachmentResultFfi {
                        reference: attachment.reference.try_into()?,
                        encrypted_size_bytes: attachment.encrypted_size_bytes,
                    })
                })
                .collect::<Result<Vec<_>, AppError>>()?,
            sent: value.sent.map(Into::into),
        })
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaDownloadResultFfi {
    pub plaintext: Vec<u8>,
    pub file_name: String,
    pub media_type: String,
    pub size_bytes: u64,
}

impl From<MediaDownloadResult> for MediaDownloadResultFfi {
    fn from(value: MediaDownloadResult) -> Self {
        Self {
            plaintext: value.plaintext,
            file_name: value.file_name,
            media_type: value.media_type,
            size_bytes: value.size_bytes,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaRecordFfi {
    pub message_id_hex: String,
    /// Position among the source message's `imeta` tags, rejected siblings
    /// included, so it matches the `attachment_index` of the same message's
    /// timeline `media` outcomes. `list_media` returns accepted attachments
    /// only; rejected ones appear on the timeline row.
    pub attachment_index: u32,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub reference: MediaAttachmentReferenceFfi,
    pub caption: Option<String>,
    pub recorded_at: u64,
    pub received_at: u64,
}

pub(crate) fn media_records_ffi(messages: Vec<AppMessageRecord>) -> Vec<MediaRecordFfi> {
    let mut records = Vec::new();
    for message in messages {
        let caption = (!message.plaintext.is_empty()).then_some(message.plaintext.clone());
        let outcomes = media_attachment_outcomes_ffi(
            "media_records_ffi",
            marmot_app::media_attachment_outcomes_from_tags(
                &message.tags,
                message.source_epoch,
                false,
            ),
        );
        for outcome in outcomes {
            let MediaAttachmentOutcomeFfi::Accepted {
                attachment_index,
                reference,
            } = outcome
            else {
                continue;
            };
            records.push(MediaRecordFfi {
                message_id_hex: message.message_id_hex.clone(),
                attachment_index,
                direction: message.direction.clone(),
                group_id_hex: message.group_id_hex.clone(),
                sender: message.sender.clone(),
                reference,
                caption: caption.clone(),
                recorded_at: message.recorded_at,
                received_at: message.received_at,
            });
        }
    }
    records
}

/// Resolve a materialized timeline row's `media` metadata (`{ "imeta": [..] }`,
/// produced by the storage timeline projection) plus the message's own
/// `source_epoch` into ordered per-attachment outcomes.
///
/// Shares the exact `imeta` parsing, validation, and error mapping that
/// `list_media` and `parse_media_imeta_tag` apply, so a row's `media`, the
/// `list_media` records, and the explicit parser resolve identically for the
/// same message. A malformed entry is a `Rejected` outcome at its position; the
/// message still renders as text and valid siblings stay downloadable. A row
/// with no media yields an empty vec.
pub(crate) fn timeline_media_outcomes_ffi(
    media: &Option<serde_json::Value>,
    source_epoch: Option<u64>,
) -> Vec<MediaAttachmentOutcomeFfi> {
    media_attachment_outcomes_ffi(
        "timeline_media_outcomes_ffi",
        marmot_app::media_attachment_outcomes_from_media_json(media.as_ref(), source_epoch, false),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imeta_tag(byte: u8, media_type: &str, file_name: &str, extra: &[&str]) -> Vec<String> {
        let mut tag = vec![
            "imeta".to_owned(),
            "v encrypted-media-v1".to_owned(),
            format!(
                "locator blossom-v1 https://media.example/{}.bin",
                hex::encode([byte; 32])
            ),
            format!("ciphertext_sha256 {}", hex::encode([byte; 32])),
            format!(
                "plaintext_sha256 {}",
                hex::encode([byte.wrapping_add(1); 32])
            ),
            format!("nonce {}", hex::encode([byte; 12])),
            format!("m {media_type}"),
            format!("filename {file_name}"),
        ];
        tag.extend(extra.iter().map(|field| (*field).to_owned()));
        tag
    }

    /// The MIP-era shape Amethyst emitted before adopting the spec format.
    fn legacy_mip04_tag() -> Vec<String> {
        vec![
            "imeta".to_owned(),
            "url https://media.example/legacy-upload.bin".to_owned(),
            "blurhash LEHV6nWB2yk8pyo0adR*.7kCMdnj".to_owned(),
            "m image/jpeg".to_owned(),
            "filename photo.jpg".to_owned(),
            format!("x {}", "cd".repeat(32)),
            "n efefefefefefefefefefefef".to_owned(),
            "v mip04-v2".to_owned(),
        ]
    }

    fn message(tags: Vec<Vec<String>>) -> AppMessageRecord {
        AppMessageRecord {
            message_id_hex: "aa".repeat(32),
            direction: "incoming".to_owned(),
            group_id_hex: "bb".repeat(32),
            sender: "alice".to_owned(),
            plaintext: "album caption".to_owned(),
            kind: 9,
            tags,
            source_epoch: Some(7),
            retention: None,
            recorded_at: 10,
            received_at: 11,
            insert_order: 0,
            invalidated: false,
            moderation_grant: false,
        }
    }

    fn accepted(outcome: &MediaAttachmentOutcomeFfi) -> (u32, &MediaAttachmentReferenceFfi) {
        match outcome {
            MediaAttachmentOutcomeFfi::Accepted {
                attachment_index,
                reference,
            } => (*attachment_index, reference),
            other => panic!("expected an accepted attachment, got {other:?}"),
        }
    }

    fn rejected(outcome: &MediaAttachmentOutcomeFfi) -> (u32, &MediaAttachmentRejectionFfi) {
        match outcome {
            MediaAttachmentOutcomeFfi::Rejected {
                attachment_index,
                rejection,
            } => (*attachment_index, rejection),
            other => panic!("expected a rejected attachment, got {other:?}"),
        }
    }

    #[test]
    fn media_records_ffi_projects_ordered_multi_attachment_records() {
        let message = message(vec![
            imeta_tag(
                0x11,
                "image/png",
                "diagram.png",
                &["dim 800x600", "thumbhash 1QcSHQRnh493V4dIh4eXh1h4kJUI"],
            ),
            imeta_tag(0x22, "video/mp4", "clip.mp4", &["dim 1920x1080"]),
            imeta_tag(0x33, "audio/ogg", "voice.ogg", &[]),
        ]);

        let records = media_records_ffi(vec![message]);

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].attachment_index, 0);
        assert_eq!(records[0].caption.as_deref(), Some("album caption"));
        assert_eq!(records[0].reference.media_type, "image/png");
        assert_eq!(records[0].reference.file_name, "diagram.png");
        assert_eq!(records[0].reference.source_epoch, 7);
        assert_eq!(records[0].reference.dim.as_deref(), Some("800x600"));
        assert_eq!(
            records[0].reference.thumbhash.as_deref(),
            Some("1QcSHQRnh493V4dIh4eXh1h4kJUI")
        );
        assert_eq!(records[1].attachment_index, 1);
        assert_eq!(records[1].reference.media_type, "video/mp4");
        assert_eq!(records[1].reference.file_name, "clip.mp4");
        assert_eq!(records[1].reference.dim.as_deref(), Some("1920x1080"));
        assert_eq!(records[2].attachment_index, 2);
        assert_eq!(records[2].reference.media_type, "audio/ogg");
        assert_eq!(records[2].reference.file_name, "voice.ogg");
    }

    #[test]
    fn media_records_ffi_keeps_tag_position_across_a_rejected_sibling() {
        // A rejected attachment is omitted from the downloadable list but still
        // consumes its index, so the record lines up with the timeline outcome
        // for the same message instead of silently renumbering.
        let message = message(vec![
            imeta_tag(0x11, "image/png", "first.png", &[]),
            legacy_mip04_tag(),
            imeta_tag(0x33, "audio/ogg", "third.ogg", &[]),
        ]);

        let records = media_records_ffi(vec![message]);

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].attachment_index, 0);
        assert_eq!(records[0].reference.file_name, "first.png");
        assert_eq!(records[1].attachment_index, 2);
        assert_eq!(records[1].reference.file_name, "third.ogg");
    }

    fn imeta_metadata(tags: &[Vec<String>]) -> serde_json::Value {
        serde_json::json!({ "imeta": tags })
    }

    #[test]
    fn timeline_media_outcomes_ffi_resolve_single_image() {
        let tag = imeta_tag(0x11, "image/png", "diagram.png", &["dim 800x600"]);
        let media = imeta_metadata(&[tag]);

        let outcomes = timeline_media_outcomes_ffi(&Some(media), Some(7));

        assert_eq!(outcomes.len(), 1);
        let (index, reference) = accepted(&outcomes[0]);
        assert_eq!(index, 0);
        assert_eq!(reference.media_type, "image/png");
        assert_eq!(reference.file_name, "diagram.png");
        assert_eq!(reference.source_epoch, 7);
        assert_eq!(reference.dim.as_deref(), Some("800x600"));
        assert_eq!(reference.version, EncryptedMediaVersionFfi::V1);
        assert_eq!(reference.locators.len(), 1);
    }

    #[test]
    fn timeline_media_outcomes_ffi_surface_v2_explicitly() {
        let mut tag = imeta_tag(0x11, "image/png", "diagram.png", &[]);
        tag[1] = "v encrypted-media-v2".to_owned();
        tag[2] = "locator blossom-v1 http://10.0.0.1/blob".to_owned();

        let outcomes = timeline_media_outcomes_ffi(&Some(imeta_metadata(&[tag])), Some(9));

        assert_eq!(outcomes.len(), 1);
        let (_, reference) = accepted(&outcomes[0]);
        assert_eq!(reference.version, EncryptedMediaVersionFfi::V2);
        assert_eq!(reference.source_epoch, 9);
    }

    #[test]
    fn timeline_media_outcomes_ffi_resolve_multi_attachment() {
        let media = imeta_metadata(&[
            imeta_tag(0x11, "image/png", "diagram.png", &[]),
            imeta_tag(0x22, "video/mp4", "clip.mp4", &[]),
            imeta_tag(0x33, "audio/ogg", "voice.ogg", &[]),
        ]);

        let outcomes = timeline_media_outcomes_ffi(&Some(media), Some(4));

        assert_eq!(outcomes.len(), 3);
        for (expected_index, (outcome, file_name)) in outcomes
            .iter()
            .zip(["diagram.png", "clip.mp4", "voice.ogg"])
            .enumerate()
        {
            let (index, reference) = accepted(outcome);
            assert_eq!(index, expected_index as u32);
            assert_eq!(reference.file_name, file_name);
            assert_eq!(reference.source_epoch, 4);
        }
    }

    #[test]
    fn timeline_media_outcomes_ffi_keep_rejected_siblings_in_order() {
        // Issue #1787: the host must be able to render [image][placeholder][image]
        // with a typed reason for the placeholder, never an empty list.
        let mut missing_nonce = imeta_tag(0x22, "video/mp4", "clip.mp4", &[]);
        missing_nonce.retain(|field| !field.starts_with("nonce "));
        let media = imeta_metadata(&[
            imeta_tag(0x11, "image/png", "ok.png", &[]),
            legacy_mip04_tag(),
            missing_nonce,
            imeta_tag(0x33, "audio/ogg", "voice.ogg", &[]),
        ]);

        let outcomes = timeline_media_outcomes_ffi(&Some(media), Some(1));

        assert_eq!(outcomes.len(), 4);
        let (index, reference) = accepted(&outcomes[0]);
        assert_eq!((index, reference.file_name.as_str()), (0, "ok.png"));
        let (index, rejection) = rejected(&outcomes[1]);
        assert_eq!(index, 1);
        assert_eq!(
            rejection.kind,
            MediaAttachmentRejectionKindFfi::UnsupportedFormat
        );
        assert!(rejection.detail.contains("version"), "{}", rejection.detail);
        assert!(
            !rejection.detail.contains("media.example"),
            "detail must not echo tag content: {}",
            rejection.detail
        );
        let (index, rejection) = rejected(&outcomes[2]);
        assert_eq!(index, 2);
        assert_eq!(
            rejection.kind,
            MediaAttachmentRejectionKindFfi::MissingField
        );
        assert!(rejection.detail.contains("nonce"), "{}", rejection.detail);
        let (index, reference) = accepted(&outcomes[3]);
        assert_eq!((index, reference.file_name.as_str()), (3, "voice.ogg"));
    }

    #[test]
    fn timeline_media_outcomes_ffi_report_undecodable_json_entries() {
        // Storage never writes these shapes, but a corrupt row must still tell
        // the host an attachment existed rather than vanishing.
        let media = serde_json::json!({
            "imeta": [imeta_tag(0x11, "image/png", "ok.png", &[]), 42, ["notimeta", "m image/png"]]
        });

        let outcomes = timeline_media_outcomes_ffi(&Some(media), Some(1));

        assert_eq!(outcomes.len(), 3);
        accepted(&outcomes[0]);
        for (position, outcome) in outcomes.iter().enumerate().skip(1) {
            let (index, rejection) = rejected(outcome);
            assert_eq!(index, position as u32);
            assert_eq!(
                rejection.kind,
                MediaAttachmentRejectionKindFfi::InvalidStructure
            );
        }

        let corrupt = serde_json::json!({ "imeta": "nope" });
        let outcomes = timeline_media_outcomes_ffi(&Some(corrupt), Some(1));
        assert_eq!(outcomes.len(), 1);
        let (index, rejection) = rejected(&outcomes[0]);
        assert_eq!(index, 0);
        assert_eq!(
            rejection.kind,
            MediaAttachmentRejectionKindFfi::InvalidStructure
        );
    }

    #[test]
    fn timeline_media_outcomes_ffi_empty_when_no_media() {
        assert!(timeline_media_outcomes_ffi(&None, Some(1)).is_empty());
        assert!(timeline_media_outcomes_ffi(&Some(serde_json::json!({})), Some(1)).is_empty());
    }

    #[test]
    fn timeline_media_outcomes_match_list_media_for_same_message() {
        let mut broken = imeta_tag(0x44, "image/webp", "broken.webp", &[]);
        broken.push("m image/jpeg".to_owned());
        let tags = vec![
            vec!["p".to_owned(), "cc".repeat(32)],
            imeta_tag(
                0x11,
                "image/png",
                "diagram.png",
                &["dim 800x600", "thumbhash abc"],
            ),
            broken,
            imeta_tag(0x22, "video/mp4", "clip.mp4", &["dim 1920x1080"]),
        ];
        let imeta: Vec<Vec<String>> = tags
            .iter()
            .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
            .cloned()
            .collect();

        let from_list: Vec<(u32, MediaAttachmentReference)> =
            media_records_ffi(vec![message(tags)])
                .into_iter()
                .map(|record| (record.attachment_index, record.reference.into()))
                .collect();
        let from_row: Vec<(u32, MediaAttachmentReference)> =
            timeline_media_outcomes_ffi(&Some(imeta_metadata(&imeta)), Some(7))
                .into_iter()
                .filter_map(|outcome| match outcome {
                    MediaAttachmentOutcomeFfi::Accepted {
                        attachment_index,
                        reference,
                    } => Some((attachment_index, reference.into())),
                    MediaAttachmentOutcomeFfi::Rejected { .. } => None,
                })
                .collect();

        assert_eq!(from_list, from_row);
        assert_eq!(
            from_list
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
    }

    #[test]
    fn media_attachment_reference_ffi_round_trips_non_image_type() {
        let ffi = MediaAttachmentReferenceFfi {
            locators: vec![MediaLocatorFfi {
                kind: "blossom-v1".to_owned(),
                value: format!("https://media.example/{}.bin", hex::encode([0x44; 32])),
            }],
            ciphertext_sha256: hex::encode([0x44; 32]),
            plaintext_sha256: hex::encode([0x45; 32]),
            nonce_hex: hex::encode([0x46; 12]),
            file_name: "brief.pdf".to_owned(),
            media_type: "application/pdf".to_owned(),
            version: EncryptedMediaVersionFfi::V2,
            source_epoch: 42,
            dim: None,
            thumbhash: None,
        };

        let app: MediaAttachmentReference = ffi.clone().into();
        let round_trip = MediaAttachmentReferenceFfi::try_from(app).unwrap();

        assert_eq!(round_trip.locators.len(), 1);
        assert_eq!(round_trip.locators[0].kind, "blossom-v1");
        assert_eq!(round_trip.media_type, "application/pdf");
        assert_eq!(round_trip.file_name, "brief.pdf");
        assert_eq!(round_trip.version, EncryptedMediaVersionFfi::V2);
        assert_eq!(round_trip.source_epoch, 42);
    }

    #[test]
    fn media_attachment_reference_ffi_rejects_unsupported_internal_version_without_panicking() {
        let mut app: MediaAttachmentReference = MediaAttachmentReferenceFfi {
            locators: vec![MediaLocatorFfi {
                kind: "blossom-v1".to_owned(),
                value: format!("https://media.example/{}.bin", hex::encode([0x44; 32])),
            }],
            ciphertext_sha256: hex::encode([0x44; 32]),
            plaintext_sha256: hex::encode([0x45; 32]),
            nonce_hex: hex::encode([0x46; 12]),
            file_name: "brief.pdf".to_owned(),
            media_type: "application/pdf".to_owned(),
            version: EncryptedMediaVersionFfi::V2,
            source_epoch: 42,
            dim: None,
            thumbhash: None,
        }
        .into();
        app.version = "future-media-version".to_owned();

        assert!(MediaAttachmentReferenceFfi::try_from(app.clone()).is_err());
        // The outcome conversion keeps the attachment visible with a typed
        // reason instead of dropping it.
        let outcome = MediaAttachmentOutcomeFfi::from(MediaAttachmentOutcome::Accepted {
            attachment_index: 3,
            reference: app,
        });
        let (index, rejection) = rejected(&outcome);
        assert_eq!(index, 3);
        assert_eq!(
            rejection.kind,
            MediaAttachmentRejectionKindFfi::UnsupportedFormat
        );
    }

    #[test]
    fn rejection_kind_ffi_round_trips_and_displays_stable_labels() {
        for kind in [
            MediaAttachmentRejectionKind::InvalidStructure,
            MediaAttachmentRejectionKind::UnsupportedFormat,
            MediaAttachmentRejectionKind::MissingField,
            MediaAttachmentRejectionKind::DuplicateField,
            MediaAttachmentRejectionKind::MalformedField,
        ] {
            let ffi = MediaAttachmentRejectionKindFfi::from(kind);
            assert_eq!(MediaAttachmentRejectionKind::from(ffi), kind);
            assert_eq!(ffi.to_string(), kind.as_str());
        }
    }
}
