//! Media locator, attachment, upload/download, and media-record FFI conversions.

use marmot_app::{
    AppError, AppMessageRecord, EncryptedMediaVersion, MediaAttachmentProjection,
    MediaAttachmentReference, MediaAttachmentResult, MediaDiagnostic, MediaDownloadResult,
    MediaErrorCode, MediaErrorField, MediaErrorStage, MediaLocator, MediaUploadAttachmentRequest,
    MediaUploadRequest, MediaUploadResult, project_media_attachments,
    project_timeline_media_attachments,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MediaErrorStageFfi {
    Metadata,
    Outbound,
    Fetch,
    Decrypt,
}

impl From<MediaErrorStage> for MediaErrorStageFfi {
    fn from(value: MediaErrorStage) -> Self {
        match value {
            MediaErrorStage::Metadata => Self::Metadata,
            MediaErrorStage::Outbound => Self::Outbound,
            MediaErrorStage::Fetch => Self::Fetch,
            MediaErrorStage::Decrypt => Self::Decrypt,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MediaErrorCodeFfi {
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

impl From<MediaErrorCode> for MediaErrorCodeFfi {
    fn from(value: MediaErrorCode) -> Self {
        match value {
            MediaErrorCode::InvalidStructure => Self::InvalidStructure,
            MediaErrorCode::MissingField => Self::MissingField,
            MediaErrorCode::DuplicateField => Self::DuplicateField,
            MediaErrorCode::MalformedField => Self::MalformedField,
            MediaErrorCode::UnsupportedVersion => Self::UnsupportedVersion,
            MediaErrorCode::UnsupportedFormat => Self::UnsupportedFormat,
            MediaErrorCode::ProfileMismatch => Self::ProfileMismatch,
            MediaErrorCode::DestinationPolicy => Self::DestinationPolicy,
            MediaErrorCode::NoSupportedLocator => Self::NoSupportedLocator,
            MediaErrorCode::DownloadFailed => Self::DownloadFailed,
            MediaErrorCode::DecryptionFailed => Self::DecryptionFailed,
            MediaErrorCode::IntegrityMismatch => Self::IntegrityMismatch,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MediaErrorFieldFfi {
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

impl From<MediaErrorField> for MediaErrorFieldFfi {
    fn from(value: MediaErrorField) -> Self {
        match value {
            MediaErrorField::Version => Self::Version,
            MediaErrorField::Locator => Self::Locator,
            MediaErrorField::CiphertextSha256 => Self::CiphertextSha256,
            MediaErrorField::PlaintextSha256 => Self::PlaintextSha256,
            MediaErrorField::Nonce => Self::Nonce,
            MediaErrorField::MediaType => Self::MediaType,
            MediaErrorField::FileName => Self::FileName,
            MediaErrorField::Dimensions => Self::Dimensions,
            MediaErrorField::Thumbhash => Self::Thumbhash,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MediaDiagnosticFfi {
    pub stage: MediaErrorStageFfi,
    pub code: MediaErrorCodeFfi,
    pub field: Option<MediaErrorFieldFfi>,
    pub message: String,
}

impl From<MediaDiagnostic> for MediaDiagnosticFfi {
    fn from(value: MediaDiagnostic) -> Self {
        Self {
            stage: value.stage.into(),
            code: value.code.into(),
            field: value.field.map(Into::into),
            message: value.message,
        }
    }
}

impl std::fmt::Display for MediaDiagnosticFfi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(formatter)
    }
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum MediaAttachmentResultFfi {
    Parsed {
        reference: MediaAttachmentReferenceFfi,
    },
    Rejected {
        diagnostic: MediaDiagnosticFfi,
    },
}

impl From<MediaAttachmentResult> for MediaAttachmentResultFfi {
    fn from(value: MediaAttachmentResult) -> Self {
        match value {
            MediaAttachmentResult::Parsed { reference } => match reference.try_into() {
                Ok(reference) => Self::Parsed { reference },
                Err(_) => Self::Rejected {
                    diagnostic: MediaDiagnosticFfi {
                        stage: MediaErrorStageFfi::Metadata,
                        code: MediaErrorCodeFfi::UnsupportedVersion,
                        field: Some(MediaErrorFieldFfi::Version),
                        message: "media version is not supported".to_owned(),
                    },
                },
            },
            MediaAttachmentResult::Rejected { diagnostic } => Self::Rejected {
                diagnostic: diagnostic.into(),
            },
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaAttachmentProjectionFfi {
    pub attachment_index: Option<u32>,
    pub result: MediaAttachmentResultFfi,
}

impl From<MediaAttachmentProjection> for MediaAttachmentProjectionFfi {
    fn from(value: MediaAttachmentProjection) -> Self {
        Self {
            attachment_index: value.attachment_index,
            result: value.result.into(),
        }
    }
}

pub(crate) fn parsed_media_references(
    projections: &[MediaAttachmentProjectionFfi],
) -> Vec<MediaAttachmentReferenceFfi> {
    projections
        .iter()
        .filter_map(|projection| match &projection.result {
            MediaAttachmentResultFfi::Parsed { reference } => Some(reference.clone()),
            MediaAttachmentResultFfi::Rejected { .. } => None,
        })
        .collect()
}

pub(crate) fn message_media_attachments_ffi(
    tags: &[Vec<String>],
    source_epoch: Option<u64>,
) -> Vec<MediaAttachmentProjectionFfi> {
    project_media_attachments(tags, source_epoch, false)
        .into_iter()
        .map(Into::into)
        .collect()
}

pub(crate) fn timeline_media_attachments_ffi(
    media: &Option<serde_json::Value>,
    decode_failed: bool,
    source_epoch: Option<u64>,
) -> Vec<MediaAttachmentProjectionFfi> {
    project_timeline_media_attachments(media.as_ref(), decode_failed, source_epoch, false)
        .into_iter()
        .map(Into::into)
        .collect()
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaRecordFfi {
    pub message_id_hex: String,
    pub attachment_index: u32,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub attachment: MediaAttachmentResultFfi,
    pub caption: Option<String>,
    pub recorded_at: u64,
    pub received_at: u64,
}

pub(crate) fn media_records_ffi(messages: Vec<AppMessageRecord>) -> Vec<MediaRecordFfi> {
    let mut records = Vec::new();
    for message in messages {
        let caption = (!message.plaintext.is_empty()).then_some(message.plaintext.clone());
        for projection in message_media_attachments_ffi(&message.tags, message.source_epoch) {
            let attachment_index = projection.attachment_index.unwrap_or(u32::MAX);
            records.push(MediaRecordFfi {
                message_id_hex: message.message_id_hex.clone(),
                attachment_index,
                direction: message.direction.clone(),
                group_id_hex: message.group_id_hex.clone(),
                sender: message.sender.clone(),
                attachment: projection.result,
                caption: caption.clone(),
                recorded_at: message.recorded_at,
                received_at: message.received_at,
            });
        }
    }
    records
}

/// Parsed-only view of a timeline row's media, derived from the same
/// outcomes as [`timeline_media_attachments_ffi`].
#[cfg(test)]
pub(crate) fn timeline_media_references_ffi(
    media: &Option<serde_json::Value>,
    source_epoch: Option<u64>,
) -> Vec<MediaAttachmentReferenceFfi> {
    parsed_media_references(&timeline_media_attachments_ffi(media, false, source_epoch))
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

    #[test]
    fn media_records_ffi_projects_ordered_multi_attachment_records() {
        let message = AppMessageRecord {
            message_id_hex: "aa".repeat(32),
            direction: "incoming".to_owned(),
            group_id_hex: "bb".repeat(32),
            sender: "alice".to_owned(),
            plaintext: "album caption".to_owned(),
            kind: 9,
            tags: vec![
                imeta_tag(
                    0x11,
                    "image/png",
                    "diagram.png",
                    &["dim 800x600", "thumbhash 1QcSHQRnh493V4dIh4eXh1h4kJUI"],
                ),
                imeta_tag(0x22, "video/mp4", "clip.mp4", &["dim 1920x1080"]),
                imeta_tag(0x33, "audio/ogg", "voice.ogg", &[]),
            ],
            source_epoch: Some(7),
            retention: None,
            recorded_at: 10,
            received_at: 11,
            insert_order: 0,
            invalidated: false,
            moderation_grant: false,
        };

        let records = media_records_ffi(vec![message]);

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].attachment_index, 0);
        assert_eq!(records[0].caption.as_deref(), Some("album caption"));
        let MediaAttachmentResultFfi::Parsed { reference } = &records[0].attachment else {
            panic!("expected parsed first attachment");
        };
        assert_eq!(reference.media_type, "image/png");
        assert_eq!(reference.file_name, "diagram.png");
        assert_eq!(reference.source_epoch, 7);
        assert_eq!(reference.dim.as_deref(), Some("800x600"));
        assert_eq!(
            reference.thumbhash.as_deref(),
            Some("1QcSHQRnh493V4dIh4eXh1h4kJUI")
        );
        let MediaAttachmentResultFfi::Parsed { reference } = &records[1].attachment else {
            panic!("expected parsed second attachment");
        };
        assert_eq!(records[1].attachment_index, 1);
        assert_eq!(reference.media_type, "video/mp4");
        assert_eq!(reference.file_name, "clip.mp4");
        assert_eq!(reference.dim.as_deref(), Some("1920x1080"));
        let MediaAttachmentResultFfi::Parsed { reference } = &records[2].attachment else {
            panic!("expected parsed third attachment");
        };
        assert_eq!(records[2].attachment_index, 2);
        assert_eq!(reference.media_type, "audio/ogg");
        assert_eq!(reference.file_name, "voice.ogg");
    }

    fn imeta_metadata(tags: &[Vec<String>]) -> serde_json::Value {
        serde_json::json!({ "imeta": tags })
    }

    #[test]
    fn timeline_media_references_ffi_resolves_single_image() {
        let tag = imeta_tag(0x11, "image/png", "diagram.png", &["dim 800x600"]);
        let media = imeta_metadata(&[tag]);

        let references = timeline_media_references_ffi(&Some(media), Some(7));

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].media_type, "image/png");
        assert_eq!(references[0].file_name, "diagram.png");
        assert_eq!(references[0].source_epoch, 7);
        assert_eq!(references[0].dim.as_deref(), Some("800x600"));
        assert_eq!(references[0].version, EncryptedMediaVersionFfi::V1);
        assert_eq!(references[0].locators.len(), 1);
    }

    #[test]
    fn timeline_media_references_ffi_surfaces_v2_explicitly() {
        let mut tag = imeta_tag(0x11, "image/png", "diagram.png", &[]);
        tag[1] = "v encrypted-media-v2".to_owned();
        tag[2] = "locator blossom-v1 http://10.0.0.1/blob".to_owned();

        let references = timeline_media_references_ffi(&Some(imeta_metadata(&[tag])), Some(9));

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].version, EncryptedMediaVersionFfi::V2);
        assert_eq!(references[0].source_epoch, 9);
    }

    #[test]
    fn timeline_media_references_ffi_resolves_multi_attachment() {
        let media = imeta_metadata(&[
            imeta_tag(0x11, "image/png", "diagram.png", &[]),
            imeta_tag(0x22, "video/mp4", "clip.mp4", &[]),
            imeta_tag(0x33, "audio/ogg", "voice.ogg", &[]),
        ]);

        let references = timeline_media_references_ffi(&Some(media), Some(4));

        assert_eq!(references.len(), 3);
        assert_eq!(references[0].file_name, "diagram.png");
        assert_eq!(references[1].file_name, "clip.mp4");
        assert_eq!(references[2].file_name, "voice.ogg");
        assert!(references.iter().all(|r| r.source_epoch == 4));
    }

    fn rejected_code(result: &MediaAttachmentResultFfi) -> MediaErrorCodeFfi {
        match result {
            MediaAttachmentResultFfi::Rejected { diagnostic } => diagnostic.code,
            MediaAttachmentResultFfi::Parsed { .. } => panic!("expected rejection"),
        }
    }

    #[test]
    fn mixed_invalid_valid_album_agrees_across_message_list_timeline_and_preview() {
        let invalid = vec!["imeta".to_owned(), "v encrypted-media-v1".to_owned()];
        let mut valid_v2 = imeta_tag(0x22, "image/png", "second.png", &[]);
        valid_v2[1] = "v encrypted-media-v2".to_owned();
        let tags = vec![
            vec!["p".to_owned(), "aa".repeat(32)],
            invalid.clone(),
            imeta_tag(0x11, "image/png", "first.png", &[]),
            vec!["e".to_owned(), "bb".repeat(32)],
            invalid.clone(),
            valid_v2.clone(),
        ];
        let message = AppMessageRecord {
            message_id_hex: "aa".repeat(32),
            direction: "incoming".to_owned(),
            group_id_hex: "bb".repeat(32),
            sender: "alice".to_owned(),
            plaintext: "keep the caption".to_owned(),
            kind: 9,
            tags: tags.clone(),
            source_epoch: Some(7),
            retention: None,
            recorded_at: 10,
            received_at: 11,
            insert_order: 0,
            invalidated: false,
            moderation_grant: false,
        };
        let received = marmot_app::ReceivedMessage {
            message_id_hex: message.message_id_hex.clone(),
            source_message_id_hex: message.message_id_hex.clone(),
            group_id: cgka_traits::GroupId::new(vec![0xbb; 16]),
            sender: message.sender.clone(),
            sender_display_name: None,
            plaintext: message.plaintext.clone(),
            kind: message.kind,
            tags: tags.clone(),
            source_epoch: 7,
            retention: None,
            recorded_at: 10,
            received_at: 11,
        };

        let from_message = crate::conversions::AppMessageRecordFfi::from(message.clone());
        let from_received = crate::conversions::ReceivedMessageFfi::from(&received);
        let from_list = media_records_ffi(vec![message.clone()]);
        let imeta_only = tags
            .iter()
            .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
            .cloned()
            .collect::<Vec<_>>();
        let media = imeta_metadata(&imeta_only);
        let from_timeline = timeline_media_attachments_ffi(&Some(media.clone()), false, Some(7));
        let preview =
            crate::conversions::TimelineReplyPreviewFfi::from(marmot_app::TimelineReplyPreview {
                message_id_hex: message.message_id_hex.clone(),
                sender: message.sender.clone(),
                plaintext: message.plaintext.clone(),
                kind: message.kind,
                source_epoch: Some(7),
                media: Some(media),
                media_decode_failed: false,
                agent_text_stream: None,
                deleted: false,
                invalidation_status: None,
            });

        assert_eq!(from_message.plaintext, "keep the caption");
        assert_eq!(from_message.media_attachments.len(), 4);
        assert_eq!(from_received.media_attachments.len(), 4);
        assert_eq!(from_list.len(), 4);
        assert_eq!(from_timeline.len(), 4);
        assert_eq!(preview.media_attachments.len(), 4);
        for (index, (message_outcome, list_record, timeline_outcome, preview_outcome)) in
            from_message
                .media_attachments
                .iter()
                .zip(from_list.iter())
                .zip(from_timeline.iter())
                .zip(preview.media_attachments.iter())
                .map(|(((a, b), c), d)| (a, b, c, d))
                .enumerate()
        {
            let index = u32::try_from(index).unwrap();
            assert_eq!(message_outcome.attachment_index, Some(index));
            assert_eq!(list_record.attachment_index, index);
            assert_eq!(timeline_outcome.attachment_index, Some(index));
            assert_eq!(preview_outcome.attachment_index, Some(index));
            assert_eq!(list_record.caption.as_deref(), Some("keep the caption"));
        }
        assert_eq!(
            rejected_code(&from_message.media_attachments[0].result),
            MediaErrorCodeFfi::MissingField
        );
        assert_eq!(
            rejected_code(&from_message.media_attachments[2].result),
            MediaErrorCodeFfi::MissingField
        );
        let MediaAttachmentResultFfi::Parsed { reference } =
            &from_message.media_attachments[1].result
        else {
            panic!("index 1 must stay parsed");
        };
        assert_eq!(reference.file_name, "first.png");
        assert_eq!(reference.version, EncryptedMediaVersionFfi::V1);
        let MediaAttachmentResultFfi::Parsed { reference } =
            &from_message.media_attachments[3].result
        else {
            panic!("index 3 must stay parsed");
        };
        assert_eq!(reference.file_name, "second.png");
        assert_eq!(reference.version, EncryptedMediaVersionFfi::V2);
        assert_eq!(preview.media.len(), 2);
        assert_eq!(preview.plaintext, "keep the caption");
    }

    #[test]
    fn all_invalid_media_only_message_still_lists_rejected_records() {
        let tags = vec![
            vec!["imeta".to_owned(), "v encrypted-media-v1".to_owned()],
            vec!["imeta".to_owned(), "v encrypted-media-v2".to_owned()],
        ];
        let message = AppMessageRecord {
            message_id_hex: "aa".repeat(32),
            direction: "incoming".to_owned(),
            group_id_hex: "bb".repeat(32),
            sender: "alice".to_owned(),
            plaintext: String::new(),
            kind: 9,
            tags,
            source_epoch: Some(1),
            retention: None,
            recorded_at: 10,
            received_at: 11,
            insert_order: 0,
            invalidated: false,
            moderation_grant: false,
        };
        let records = media_records_ffi(vec![message.clone()]);
        let projected = crate::conversions::AppMessageRecordFfi::from(message);
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| {
            matches!(record.attachment, MediaAttachmentResultFfi::Rejected { .. })
        }));
        assert_eq!(projected.media_attachments.len(), 2);
        assert!(projected.plaintext.is_empty());
    }

    #[test]
    fn timeline_media_references_ffi_drops_malformed_imeta_keeps_others() {
        // A tag missing the required ciphertext_sha256/nonce/etc. fields.
        let malformed = vec!["imeta".to_owned(), "v encrypted-media-v1".to_owned()];
        let media = imeta_metadata(&[imeta_tag(0x11, "image/png", "ok.png", &[]), malformed]);

        let references = timeline_media_references_ffi(&Some(media.clone()), Some(1));
        assert_eq!(references.len(), 1);
        assert_eq!(references[0].file_name, "ok.png");

        let outcomes = timeline_media_attachments_ffi(&Some(media), false, Some(1));
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].attachment_index, Some(0));
        assert!(matches!(
            outcomes[0].result,
            MediaAttachmentResultFfi::Parsed { .. }
        ));
        assert_eq!(outcomes[1].attachment_index, Some(1));
        assert!(matches!(
            outcomes[1].result,
            MediaAttachmentResultFfi::Rejected { .. }
        ));
    }

    #[test]
    fn timeline_media_references_ffi_rejects_tag_not_marked_imeta() {
        // A structurally complete attachment whose marker is not "imeta" must be
        // dropped, exactly as the `list_media` filter would drop it.
        let mut mislabeled = imeta_tag(0x11, "image/png", "ok.png", &[]);
        mislabeled[0] = "notimeta".to_owned();
        let media = imeta_metadata(&[mislabeled]);

        assert!(timeline_media_references_ffi(&Some(media), Some(1)).is_empty());
    }

    #[test]
    fn timeline_media_references_ffi_empty_when_no_media() {
        assert!(timeline_media_references_ffi(&None, Some(1)).is_empty());
        assert!(timeline_media_references_ffi(&Some(serde_json::json!({})), Some(1)).is_empty());
    }

    #[test]
    fn timeline_media_references_match_list_media_for_same_message() {
        let tags = vec![
            imeta_tag(
                0x11,
                "image/png",
                "diagram.png",
                &["dim 800x600", "thumbhash abc"],
            ),
            imeta_tag(0x22, "video/mp4", "clip.mp4", &["dim 1920x1080"]),
        ];
        let message = AppMessageRecord {
            message_id_hex: "aa".repeat(32),
            direction: "incoming".to_owned(),
            group_id_hex: "bb".repeat(32),
            sender: "alice".to_owned(),
            plaintext: "caption".to_owned(),
            kind: 9,
            tags: tags.clone(),
            source_epoch: Some(7),
            retention: None,
            recorded_at: 10,
            received_at: 11,
            insert_order: 0,
            invalidated: false,
            moderation_grant: false,
        };

        let from_list: Vec<MediaAttachmentReference> = media_records_ffi(vec![message])
            .into_iter()
            .map(|record| match record.attachment {
                MediaAttachmentResultFfi::Parsed { reference } => reference.into(),
                MediaAttachmentResultFfi::Rejected { diagnostic } => {
                    panic!("expected parsed list-media record, got {diagnostic:?}")
                }
            })
            .collect();
        let from_row: Vec<MediaAttachmentReference> =
            timeline_media_references_ffi(&Some(imeta_metadata(&tags)), Some(7))
                .into_iter()
                .map(Into::into)
                .collect();

        assert_eq!(from_list, from_row);
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

        assert!(MediaAttachmentReferenceFfi::try_from(app).is_err());
    }
}
