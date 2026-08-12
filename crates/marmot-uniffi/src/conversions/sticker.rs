use marmot_app::{
    AppSticker, AppStickerAsset, AppStickerImportResult, AppStickerPack, AppStickerRef,
    AppStickerSyncResult,
};

#[derive(Clone, Debug, uniffi::Record)]
pub struct StickerRefFfi {
    pub pack_coordinate: String,
    pub shortcode: String,
    pub plaintext_sha256: String,
}

impl From<AppStickerRef> for StickerRefFfi {
    fn from(value: AppStickerRef) -> Self {
        Self {
            pack_coordinate: value.pack_coordinate,
            shortcode: value.shortcode,
            plaintext_sha256: value.plaintext_sha256,
        }
    }
}

impl From<StickerRefFfi> for AppStickerRef {
    fn from(value: StickerRefFfi) -> Self {
        Self {
            pack_coordinate: value.pack_coordinate,
            shortcode: value.shortcode,
            plaintext_sha256: value.plaintext_sha256,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct StickerFfi {
    pub pack_coordinate: String,
    pub shortcode: String,
    pub url: String,
    pub sha256: String,
    pub mime: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub alt: Option<String>,
    pub emoji: Option<String>,
}

impl From<AppSticker> for StickerFfi {
    fn from(value: AppSticker) -> Self {
        Self {
            pack_coordinate: value.pack_coordinate,
            shortcode: value.shortcode,
            url: value.url,
            sha256: value.sha256,
            mime: value.mime,
            width: value.width,
            height: value.height,
            alt: value.alt,
            emoji: value.emoji,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct StickerPackFfi {
    pub coordinate: String,
    pub author_pubkey_hex: String,
    pub identifier: String,
    pub event_id_hex: String,
    pub created_at: u64,
    pub title: String,
    pub description: Option<String>,
    pub cover: Option<StickerFfi>,
    pub stickers: Vec<StickerFfi>,
    pub license: Option<String>,
    pub installed: bool,
}

impl From<AppStickerPack> for StickerPackFfi {
    fn from(value: AppStickerPack) -> Self {
        Self {
            coordinate: value.coordinate,
            author_pubkey_hex: value.author_pubkey_hex,
            identifier: value.identifier,
            event_id_hex: value.event_id_hex,
            created_at: value.created_at,
            title: value.title,
            description: value.description,
            cover: value.cover.map(Into::into),
            stickers: value.stickers.into_iter().map(Into::into).collect(),
            license: value.license,
            installed: value.installed,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct StickerAssetFfi {
    pub sticker: StickerFfi,
    pub bytes: Vec<u8>,
}

impl From<AppStickerAsset> for StickerAssetFfi {
    fn from(value: AppStickerAsset) -> Self {
        Self {
            sticker: value.sticker.into(),
            bytes: value.bytes,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct StickerSyncResultFfi {
    pub discovered: u32,
    pub updated: u32,
    pub installed: u32,
    pub pending_operations: u32,
}

impl From<AppStickerSyncResult> for StickerSyncResultFfi {
    fn from(value: AppStickerSyncResult) -> Self {
        Self {
            discovered: value.discovered,
            updated: value.updated,
            installed: value.installed,
            pending_operations: value.pending_operations,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct StickerImportResultFfi {
    pub pack: StickerPackFfi,
    pub skipped_signal_sticker_ids: Vec<u32>,
}

impl From<AppStickerImportResult> for StickerImportResultFfi {
    fn from(value: AppStickerImportResult) -> Self {
        Self {
            pack: value.pack.into(),
            skipped_signal_sticker_ids: value.skipped_signal_sticker_ids,
        }
    }
}
