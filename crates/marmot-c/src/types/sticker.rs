//! C mirrors of the Sonar sticker conversions.

use marmot_uniffi::conversions::{
    StickerAssetFfi, StickerFfi, StickerImportResultFfi, StickerPackFfi, StickerRefFfi,
    StickerSyncResultFfi,
};

use crate::macros::c_mirror;

c_mirror! {
    /// Exact kind-9 sticker reference: pack coordinate, shortcode, and plaintext hash.
    MarmotStickerRef from StickerRefFfi,
    free marmot_sticker_ref_free {
        str pack_coordinate,
        str shortcode,
        str plaintext_sha256,
    }
}

c_mirror! {
    /// One sticker in a pack projection.
    MarmotSticker from StickerFfi,
    free marmot_sticker_free,
    list(MarmotStickerList, marmot_sticker_list_free) {
        str pack_coordinate,
        str shortcode,
        str url,
        str sha256,
        str mime,
        opt_copy has_width/width: u32,
        opt_copy has_height/height: u32,
        opt_str alt,
        opt_str emoji,
    }
}

c_mirror! {
    /// A validated sticker pack and its install state.
    MarmotStickerPack from StickerPackFfi,
    free marmot_sticker_pack_free,
    list(MarmotStickerPackList, marmot_sticker_pack_list_free) {
        str coordinate,
        str author_pubkey_hex,
        str identifier,
        str event_id_hex,
        copy created_at: u64,
        str title,
        opt_str description,
        opt_rec cover: MarmotSticker,
        vec stickers/stickers_len: MarmotSticker,
        opt_str license,
        copy installed: bool,
    }
}

c_mirror! {
    /// Downloaded sticker bytes plus the validated reference metadata.
    MarmotStickerAsset from StickerAssetFfi,
    free marmot_sticker_asset_free {
        rec sticker: MarmotSticker,
        bytes bytes/bytes_len,
    }
}

c_mirror! {
    /// Counts from one bounded sticker-pack sync.
    MarmotStickerSyncResult from StickerSyncResultFfi,
    free marmot_sticker_sync_result_free {
        copy discovered: u32,
        copy updated: u32,
        copy installed: u32,
        copy pending_operations: u32,
    }
}

c_mirror! {
    /// A published imported pack and the Signal sticker ids that were skipped.
    MarmotStickerImportResult from StickerImportResultFfi,
    free marmot_sticker_import_result_free {
        rec pack: MarmotStickerPack,
        str_vec skipped_signal_sticker_ids/skipped_signal_sticker_ids_len,
    }
}
