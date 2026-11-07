//! Source-slot lookup and verified local bytes, independent of transfer progress.
use marmot_app as app;
#[derive(Clone, uniffi::Record)]
pub struct AttachmentLocalTargetFfi {
    pub message_id_hex: String,
    pub source_message_id_hex: String,
    pub attachment_index: u32,
}
impl From<AttachmentLocalTargetFfi> for app::AttachmentLocalTarget {
    fn from(v: AttachmentLocalTargetFfi) -> Self {
        Self {
            message_id_hex: v.message_id_hex,
            source_message_id_hex: v.source_message_id_hex,
            attachment_index: v.attachment_index,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct AttachmentLocalAssetFfi {
    /// None means no readable retained bytes. It does not mean a download is queued.
    /// Opaque, account/store/source-bound locator; do not parse or persist it.
    pub reference: Option<String>,
    /// Verified full plaintext length, including zero for an available empty file.
    /// Zero also accompanies an unavailable reference; inspect reference first.
    pub byte_count: u64,
}
impl From<Option<app::RetainedAttachmentAsset>> for AttachmentLocalAssetFfi {
    fn from(v: Option<app::RetainedAttachmentAsset>) -> Self {
        match v {
            Some(v) => Self {
                reference: Some(v.reference.to_opaque()),
                byte_count: v.byte_count,
            },
            None => Self {
                reference: None,
                byte_count: 0,
            },
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct AttachmentLocalBytesFfi {
    /// False means discard any partially assembled host result. True with empty
    /// bytes means EOF, including a verified zero-byte attachment.
    pub available: bool,
    pub bytes: Vec<u8>,
}
impl From<Option<zeroize::Zeroizing<Vec<u8>>>> for AttachmentLocalBytesFfi {
    fn from(v: Option<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self {
            available: v.is_some(),
            bytes: v.map(|b| b.to_vec()).unwrap_or_default(),
        }
    }
}
/// A plaintext copy of a retained attachment lent to the host (a handoff
/// lease). Pass `path` to the OS surface that needs a file, then call
/// `release_attachment_handoff` with `lease` when it is done.
#[derive(Clone, uniffi::Record)]
pub struct AttachmentHandoffFfi {
    /// Opaque lease id for `release_attachment_handoff`.
    pub lease: String,
    /// Absolute path of the private plaintext copy under the account's
    /// `handoff/` directory. Valid until the lease is released.
    pub path: String,
    pub byte_count: u64,
    pub media_type: String,
    /// The file's name: the attachment's own name made safe, with an
    /// extension from the media type when it had none.
    pub file_name: String,
}
impl From<app::AttachmentHandoff> for AttachmentHandoffFfi {
    fn from(v: app::AttachmentHandoff) -> Self {
        Self {
            lease: v.lease,
            path: v.path.to_string_lossy().into_owned(),
            byte_count: v.byte_count,
            media_type: v.media_type,
            file_name: v.file_name,
        }
    }
}
redact!(AttachmentHandoffFfi);
redact!(AttachmentLocalTargetFfi);
redact!(AttachmentLocalAssetFfi);
redact!(AttachmentLocalBytesFfi);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_results_distinguish_unavailable_from_available_empty() {
        let locator = "1:00112233445566778899aabbccddeeff:ffeeddccbbaa99887766554433221100";
        let absent = AttachmentLocalAssetFfi::from(None);
        assert!(absent.reference.is_none());
        assert_eq!(absent.byte_count, 0);
        let empty = AttachmentLocalAssetFfi::from(Some(app::RetainedAttachmentAsset {
            reference: app::AttachmentAssetRef::from_opaque(locator).unwrap(),
            byte_count: 0,
        }));
        assert_eq!(empty.reference.as_deref(), Some(locator));
        assert_eq!(empty.byte_count, 0);
        let missing_bytes = AttachmentLocalBytesFfi::from(None);
        assert!(!missing_bytes.available && missing_bytes.bytes.is_empty());
        let empty_bytes = AttachmentLocalBytesFfi::from(Some(zeroize::Zeroizing::new(Vec::new())));
        assert!(empty_bytes.available && empty_bytes.bytes.is_empty());
        let bytes = AttachmentLocalBytesFfi::from(Some(zeroize::Zeroizing::new(vec![0x89, 0x2a])));
        assert!(bytes.available);
        assert_eq!(bytes.bytes, [0x89, 0x2a]);
    }
}
