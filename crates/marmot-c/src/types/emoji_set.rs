//! C mirrors of the NIP-51 emoji set conversions.

use marmot_uniffi::conversions::{
    EmojiSetAssetFfi, EmojiSetCoverFfi, EmojiSetEmojiFfi, EmojiSetFfi, EmojiSetInstallProgressFfi,
    EmojiSetInstallResultFfi, EmojiSetSyncResultFfi, EmojiSkipFfi, EmojiSkipReasonFfi,
    InstalledCustomEmojiAssetFfi, InstalledCustomEmojiFfi, InstalledEmojiSetStateFfi,
    UserEmojiListFfi,
};

use crate::macros::{c_enum, c_mirror};

c_enum! {
    /// Why an emoji entry was not offered or not installed.
    MarmotEmojiSkipReason from EmojiSkipReasonFfi {
        InvalidShortcode,
        InvalidUrl,
        Duplicate,
        OverCap,
        DownloadFailed,
        TooLarge,
        UnsupportedImage,
        MimeMismatch,
    }
}

c_mirror! {
    /// One skipped emoji entry. `position` is the entry's index among the
    /// event's `emoji` tags when it was dropped while reading the set.
    MarmotEmojiSkip from EmojiSkipFfi {
        opt_copy has_position/position: u32,
        opt_str shortcode,
        copy reason: MarmotEmojiSkipReason,
    }
}

c_mirror! {
    /// One valid entry of a discovered set. Load its image only through
    /// `marmot_fetch_emoji_set_asset`.
    MarmotEmojiSetEmoji from EmojiSetEmojiFfi {
        str shortcode,
        str url,
    }
}

c_mirror! {
    /// The installed snapshot of a set.
    MarmotInstalledEmojiSetState from InstalledEmojiSetStateFfi {
        str event_id_hex,
        copy created_at: u64,
        copy installed_at: u64,
        copy emoji_count: u32,
        copy byte_len: u64,
        copy update_available: bool,
    }
}

c_mirror! {
    /// A kind-30030 emoji set, or the account's kind-10030 list read as the
    /// set of its loose emoji (`kind` 10030, empty `identifier`).
    MarmotEmojiSet from EmojiSetFfi,
    free marmot_emoji_set_free,
    list(MarmotEmojiSetList, marmot_emoji_set_list_free) {
        str coordinate,
        copy kind: u16,
        str author_pubkey_hex,
        str identifier,
        str event_id_hex,
        copy created_at: u64,
        opt_str title,
        opt_str description,
        opt_str image_url,
        vec emoji/emoji_len: MarmotEmojiSetEmoji,
        vec skipped/skipped_len: MarmotEmojiSkip,
        copy skipped_count: u32,
        opt_rec installed: MarmotInstalledEmojiSetState,
    }
}

c_mirror! {
    /// Counts from one text-only emoji set sync.
    MarmotEmojiSetSyncResult from EmojiSetSyncResultFfi,
    free marmot_emoji_set_sync_result_free {
        copy discovered: u32,
        copy updated: u32,
        copy complete: bool,
    }
}

c_mirror! {
    /// The installed set and every entry that was not installed.
    MarmotEmojiSetInstallResult from EmojiSetInstallResultFfi,
    free marmot_emoji_set_install_result_free {
        rec set: MarmotEmojiSet,
        copy installed_count: u32,
        vec skipped/skipped_len: MarmotEmojiSkip,
    }
}

c_mirror! {
    /// The account's own kind-10030 emoji list, read for suggestions.
    MarmotUserEmojiList from UserEmojiListFfi,
    free marmot_user_emoji_list_free {
        opt_str event_id_hex,
        opt_copy has_created_at/created_at: u64,
        opt_rec own_emoji: MarmotEmojiSet,
        vec sets/sets_len: MarmotEmojiSet,
        str_vec missing_set_coordinates/missing_set_coordinates_len,
        copy complete: bool,
    }
}

c_mirror! {
    /// A validated preview image of one emoji. Not stored.
    MarmotEmojiSetAsset from EmojiSetAssetFfi,
    free marmot_emoji_set_asset_free {
        str set_coordinate,
        str shortcode,
        str mime,
        copy width: u32,
        copy height: u32,
        copy frames: u32,
        str sha256,
        bytes bytes/bytes_len,
    }
}

c_mirror! {
    /// A set's validated cover image. Not stored.
    MarmotEmojiSetCover from EmojiSetCoverFfi,
    free marmot_emoji_set_cover_free {
        str set_coordinate,
        str mime,
        copy width: u32,
        copy height: u32,
        copy frames: u32,
        str sha256,
        bytes bytes/bytes_len,
    }
}

c_mirror! {
    /// Progress of one install, read with
    /// `marmot_emoji_set_install_control_progress`. Plain values; nothing to
    /// free.
    MarmotEmojiSetInstallProgress from EmojiSetInstallProgressFfi {
        copy completed_emoji: u32,
        copy total_emoji: u32,
        copy transferred_bytes: u64,
    }
}

c_mirror! {
    /// One installed emoji for a picker. `shortcode_collision` flags a
    /// shortcode another installed set also uses; the host decides.
    MarmotInstalledCustomEmoji from InstalledCustomEmojiFfi,
    free marmot_installed_custom_emoji_free,
    list(MarmotInstalledCustomEmojiList, marmot_installed_custom_emoji_list_free) {
        str set_coordinate,
        opt_str set_title,
        str author_pubkey_hex,
        str shortcode,
        str mime,
        copy width: u32,
        copy height: u32,
        copy frames: u32,
        str sha256,
        copy byte_len: u64,
        copy shortcode_collision: bool,
    }
}

c_mirror! {
    /// An installed emoji's stored bytes, checked against their SHA-256.
    MarmotInstalledCustomEmojiAsset from InstalledCustomEmojiAssetFfi,
    free marmot_installed_custom_emoji_asset_free {
        rec emoji: MarmotInstalledCustomEmoji,
        bytes bytes/bytes_len,
    }
}
