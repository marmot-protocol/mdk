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

#[repr(C)]
pub struct MarmotStickerImportResult {
    pub pack: MarmotStickerPack,
    pub skipped_signal_sticker_ids: *mut *mut std::ffi::c_char,
    pub skipped_signal_sticker_ids_len: usize,
}

impl From<StickerImportResultFfi> for MarmotStickerImportResult {
    fn from(value: StickerImportResultFfi) -> Self {
        let mut ids = value
            .skipped_signal_sticker_ids
            .into_iter()
            .map(|id| crate::memory::owned_c_string(id.to_string()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let skipped_signal_sticker_ids_len = ids.len();
        let skipped_signal_sticker_ids = ids.as_mut_ptr();
        std::mem::forget(ids);
        Self {
            pack: value.pack.into(),
            skipped_signal_sticker_ids,
            skipped_signal_sticker_ids_len,
        }
    }
}

impl crate::memory::CFree for MarmotStickerImportResult {
    unsafe fn free_in_place(&mut self) {
        unsafe { self.pack.free_in_place() };
        if !self.skipped_signal_sticker_ids.is_null() {
            let ids = unsafe {
                Vec::from_raw_parts(
                    self.skipped_signal_sticker_ids,
                    self.skipped_signal_sticker_ids_len,
                    self.skipped_signal_sticker_ids_len,
                )
            };
            for id in ids {
                unsafe { crate::memory::free_c_string(id) };
            }
        }
        self.skipped_signal_sticker_ids = std::ptr::null_mut();
        self.skipped_signal_sticker_ids_len = 0;
    }
}

/// Free a sticker import result returned by this library.
///
/// # Safety
/// `value` must be NULL or a pointer returned by a Marmot sticker import call,
/// and it must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_sticker_import_result_free(value: *mut MarmotStickerImportResult) {
    unsafe { crate::memory::free_boxed(value) };
}
