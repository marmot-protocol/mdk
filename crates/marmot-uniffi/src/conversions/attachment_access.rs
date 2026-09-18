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
macro_rules! redacted_debug {
    ($($t:ty),+ $(,)?) => { $(impl std::fmt::Debug for $t {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct(stringify!($t)).finish_non_exhaustive()
        }
    })+ };
}
redacted_debug!(
    AttachmentLocalTargetFfi,
    AttachmentLocalAssetFfi,
    AttachmentLocalBytesFfi
);
