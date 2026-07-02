//! Media locator, attachment, upload/download, and media-record FFI conversions.

use std::collections::HashMap;

use marmot_app::{
    AppMessageRecord, MediaAttachmentReference, MediaDownloadResult, MediaLocator,
    MediaUploadAttachmentRequest, MediaUploadRequest, MediaUploadResult,
};

use super::account::SendSummaryFfi;

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
    pub version: String,
    pub source_epoch: u64,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

impl From<MediaAttachmentReference> for MediaAttachmentReferenceFfi {
    fn from(value: MediaAttachmentReference) -> Self {
        Self {
            locators: value.locators.into_iter().map(Into::into).collect(),
            ciphertext_sha256: value.ciphertext_sha256,
            plaintext_sha256: value.plaintext_sha256,
            nonce_hex: value.nonce_hex,
            file_name: value.file_name,
            media_type: value.media_type,
            version: value.version,
            source_epoch: value.source_epoch,
            dim: value.dim,
            thumbhash: value.thumbhash,
        }
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
            version: value.version,
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

impl From<MediaUploadResult> for MediaUploadResultFfi {
    fn from(value: MediaUploadResult) -> Self {
        Self {
            attachments: value
                .attachments
                .into_iter()
                .map(|attachment| MediaUploadAttachmentResultFfi {
                    reference: attachment.reference.into(),
                    encrypted_size_bytes: attachment.encrypted_size_bytes,
                })
                .collect(),
            sent: value.sent.map(Into::into),
        }
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
        for (attachment_index, reference) in media_attachments_from_message(&message)
            .into_iter()
            .enumerate()
        {
            records.push(MediaRecordFfi {
                message_id_hex: message.message_id_hex.clone(),
                attachment_index: attachment_index.try_into().unwrap_or(u32::MAX),
                direction: message.direction.clone(),
                group_id_hex: message.group_id_hex.clone(),
                sender: message.sender.clone(),
                reference: reference.into(),
                caption: caption.clone(),
                recorded_at: message.recorded_at,
                received_at: message.received_at,
            });
        }
    }
    records
}

fn media_attachments_from_message(message: &AppMessageRecord) -> Vec<MediaAttachmentReference> {
    message
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .filter_map(|tag| media_attachment_from_imeta_tag(tag, message.source_epoch))
        .collect()
}

/// Resolve a materialized timeline row's `media` metadata (`{ "imeta": [..] }`,
/// produced by the storage timeline projection) plus the message's own
/// `source_epoch` into fully-downloadable attachment references.
///
/// Shares the exact `imeta` parsing and validation that `list_media` applies
/// via [`media_attachment_from_imeta_tag`], so a row's `media` and the
/// `list_media` records for the same message resolve identically. A malformed
/// `imeta` tag is dropped (the message still renders as text); a row with no
/// media yields an empty vec.
pub(crate) fn timeline_media_references_ffi(
    media: &Option<serde_json::Value>,
    source_epoch: Option<u64>,
) -> Vec<MediaAttachmentReferenceFfi> {
    let Some(imeta) = media
        .as_ref()
        .and_then(|value| value.get("imeta"))
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    imeta
        .iter()
        .filter_map(|tag| {
            let tag: Vec<String> = serde_json::from_value(tag.clone()).ok()?;
            // Match `media_attachments_from_message` (the `list_media` path):
            // only tags marked `imeta` are resolved, so both paths reject the
            // same malformed payloads identically.
            if tag.first().map(String::as_str) != Some("imeta") {
                return None;
            }
            media_attachment_from_imeta_tag(&tag, source_epoch)
        })
        .map(Into::into)
        .collect()
}

fn media_attachment_from_imeta_tag(
    tag: &[String],
    source_epoch: Option<u64>,
) -> Option<MediaAttachmentReference> {
    let mut locators = Vec::new();
    let mut fields = HashMap::new();
    for field in tag.iter().skip(1) {
        if field.starts_with("blurhash ") {
            return None;
        }
        if let Some(rest) = field.strip_prefix("locator ") {
            let (kind, value) = rest.split_once(' ')?;
            locators.push(MediaLocator {
                kind: kind.to_owned(),
                value: value.to_owned(),
            });
            continue;
        }
        if let Some((key, value)) = field.split_once(' ') {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }
    let required = |key: &str| {
        fields
            .get(key)
            .cloned()
            .filter(|value| !value.trim().is_empty())
    };
    Some(MediaAttachmentReference {
        locators,
        ciphertext_sha256: required("ciphertext_sha256")?,
        plaintext_sha256: required("plaintext_sha256")?,
        nonce_hex: required("nonce")?,
        file_name: required("filename")?,
        media_type: required("m")?,
        version: required("v")?,
        source_epoch: source_epoch.unwrap_or_default(),
        dim: fields.get("dim").cloned(),
        thumbhash: fields.get("thumbhash").cloned(),
    })
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
            recorded_at: 10,
            received_at: 11,
            insert_order: 0,
        };

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
        assert_eq!(references[0].version, "encrypted-media-v1");
        assert_eq!(references[0].locators.len(), 1);
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

    #[test]
    fn timeline_media_references_ffi_drops_malformed_imeta_keeps_others() {
        // A tag missing the required ciphertext_sha256/nonce/etc. fields.
        let malformed = vec!["imeta".to_owned(), "v encrypted-media-v1".to_owned()];
        let media = imeta_metadata(&[imeta_tag(0x11, "image/png", "ok.png", &[]), malformed]);

        let references = timeline_media_references_ffi(&Some(media), Some(1));

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].file_name, "ok.png");
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
            recorded_at: 10,
            received_at: 11,
            insert_order: 0,
        };

        let from_list: Vec<MediaAttachmentReference> = media_records_ffi(vec![message])
            .into_iter()
            .map(|record| record.reference.into())
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
            version: "encrypted-media-v1".to_owned(),
            source_epoch: 42,
            dim: None,
            thumbhash: None,
        };

        let app: MediaAttachmentReference = ffi.clone().into();
        let round_trip: MediaAttachmentReferenceFfi = app.into();

        assert_eq!(round_trip.locators.len(), 1);
        assert_eq!(round_trip.locators[0].kind, "blossom-v1");
        assert_eq!(round_trip.media_type, "application/pdf");
        assert_eq!(round_trip.file_name, "brief.pdf");
        assert_eq!(round_trip.source_epoch, 42);
    }
}
