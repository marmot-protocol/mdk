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
        /// SHA-256 of the plaintext image bytes: the exact hash
        /// `marmot_fetch_sticker_asset` and `marmot_send_sticker` take.
        str plaintext_sha256,
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

/// A Signal sticker import result.
#[repr(C)]
pub struct MarmotStickerImportResult {
    pub pack: MarmotStickerPack,
    /// Signal sticker ids the import skipped; `(NULL, 0)` when there are none.
    pub skipped_signal_sticker_ids: *mut u32,
    pub skipped_signal_sticker_ids_len: usize,
}

impl From<StickerImportResultFfi> for MarmotStickerImportResult {
    fn from(value: StickerImportResultFfi) -> Self {
        let (skipped_signal_sticker_ids, skipped_signal_sticker_ids_len) =
            crate::memory::owned_vec(value.skipped_signal_sticker_ids);
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
        unsafe {
            crate::memory::free_vec(
                self.skipped_signal_sticker_ids,
                self.skipped_signal_sticker_ids_len,
            )
        };
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
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(value) });
}

#[cfg(test)]
mod tests {
    use marmot_uniffi::conversions::{StickerFfi, StickerImportResultFfi, StickerPackFfi};

    use super::*;
    use crate::memory::boxed;

    fn pack() -> StickerPackFfi {
        StickerPackFfi {
            coordinate: format!("30031:{}:cats", "ab".repeat(32)),
            author_pubkey_hex: "ab".repeat(32),
            identifier: "cats".to_owned(),
            event_id_hex: "cd".repeat(32),
            created_at: 1,
            title: "Cats".to_owned(),
            description: None,
            cover: None,
            stickers: vec![StickerFfi {
                pack_coordinate: format!("30031:{}:cats", "ab".repeat(32)),
                shortcode: "wave".to_owned(),
                url: "https://cdn.example/wave.png".to_owned(),
                plaintext_sha256: "11".repeat(32),
                mime: "image/png".to_owned(),
                width: Some(32),
                height: Some(32),
                alt: None,
                emoji: None,
            }],
            license: None,
            installed: false,
        }
    }

    #[test]
    fn import_result_exports_skipped_ids_as_a_u32_array() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let populated: MarmotStickerImportResult = StickerImportResultFfi {
            pack: pack(),
            skipped_signal_sticker_ids: vec![3, 7],
        }
        .into();
        assert_eq!(populated.skipped_signal_sticker_ids_len, 2);
        let ids = unsafe {
            std::slice::from_raw_parts(
                populated.skipped_signal_sticker_ids,
                populated.skipped_signal_sticker_ids_len,
            )
        };
        assert_eq!(ids, [3, 7]);
        assert_eq!(populated.pack.stickers_len, 1);
        unsafe { marmot_sticker_import_result_free(boxed(populated)) };

        let empty: MarmotStickerImportResult = StickerImportResultFfi {
            pack: pack(),
            skipped_signal_sticker_ids: Vec::new(),
        }
        .into();
        assert!(empty.skipped_signal_sticker_ids.is_null());
        assert_eq!(empty.skipped_signal_sticker_ids_len, 0);
        unsafe { marmot_sticker_import_result_free(boxed(empty)) };
        unsafe { marmot_sticker_import_result_free(std::ptr::null_mut()) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }
}
