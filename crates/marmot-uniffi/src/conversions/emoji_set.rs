//! NIP-51 emoji set DTOs. Discovery DTOs carry URLs for disclosure only;
//! installed-emoji DTOs carry no URL at all.

use std::sync::Arc;

use marmot_app::{
    AppEmojiSet, AppEmojiSetAsset, AppEmojiSetCover, AppEmojiSetEmoji, AppEmojiSetInstallResult,
    AppEmojiSetSyncResult, AppEmojiSkip, AppEmojiSkipReason, AppInstalledCustomEmoji,
    AppInstalledCustomEmojiAsset, AppInstalledEmojiSetState, AppUserEmojiList,
    EmojiSetInstallControl, EmojiSetInstallProgress,
};

/// Why an emoji entry was not offered or not installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum EmojiSkipReasonFfi {
    /// Not 1–64 bytes of ASCII letters, digits, `-` and `_`.
    InvalidShortcode,
    /// Not a public HTTPS URL, or refused by the dial policy.
    InvalidUrl,
    /// A later entry repeating a shortcode.
    Duplicate,
    /// Past the per-set emoji cap or the stored-byte budget.
    OverCap,
    /// The image host could not be reached or answered with an error.
    DownloadFailed,
    /// Over 4 MiB, 4096 px per side, or 200 frames.
    TooLarge,
    /// Not PNG/APNG, GIF, WebP or JPEG, or malformed.
    UnsupportedImage,
    /// Served as a non-image type (such as `text/html`). Any `image/*` type,
    /// right or wrong, defers to the bytes.
    MimeMismatch,
}

impl From<AppEmojiSkipReason> for EmojiSkipReasonFfi {
    fn from(value: AppEmojiSkipReason) -> Self {
        match value {
            AppEmojiSkipReason::InvalidShortcode => Self::InvalidShortcode,
            AppEmojiSkipReason::InvalidUrl => Self::InvalidUrl,
            AppEmojiSkipReason::Duplicate => Self::Duplicate,
            AppEmojiSkipReason::OverCap => Self::OverCap,
            AppEmojiSkipReason::DownloadFailed => Self::DownloadFailed,
            AppEmojiSkipReason::TooLarge => Self::TooLarge,
            AppEmojiSkipReason::UnsupportedImage => Self::UnsupportedImage,
            AppEmojiSkipReason::MimeMismatch => Self::MimeMismatch,
        }
    }
}

/// One skipped entry. `position` (the entry's index among the event's
/// `emoji` tags) is set for entries dropped when the set was read;
/// `shortcode` is set whenever it is valid.
#[derive(Clone, Debug, uniffi::Record)]
pub struct EmojiSkipFfi {
    pub position: Option<u32>,
    pub shortcode: Option<String>,
    pub reason: EmojiSkipReasonFfi,
}

impl From<AppEmojiSkip> for EmojiSkipFfi {
    fn from(value: AppEmojiSkip) -> Self {
        Self {
            position: value.position,
            shortcode: value.shortcode,
            reason: value.reason.into(),
        }
    }
}

/// One valid entry of a discovered set. Show `url`'s host to disclose where
/// images load from; load the image only through `fetch_emoji_set_asset`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct EmojiSetEmojiFfi {
    pub shortcode: String,
    pub url: String,
}

impl From<AppEmojiSetEmoji> for EmojiSetEmojiFfi {
    fn from(value: AppEmojiSetEmoji) -> Self {
        Self {
            shortcode: value.shortcode,
            url: value.url,
        }
    }
}

/// The installed snapshot of a set.
#[derive(Clone, Debug, uniffi::Record)]
pub struct InstalledEmojiSetStateFfi {
    /// The set version the snapshot pinned.
    pub event_id_hex: String,
    pub created_at: u64,
    pub installed_at: u64,
    pub emoji_count: u32,
    pub byte_len: u64,
    /// A newer or different version is known; reinstall to take it.
    pub update_available: bool,
}

impl From<AppInstalledEmojiSetState> for InstalledEmojiSetStateFfi {
    fn from(value: AppInstalledEmojiSetState) -> Self {
        Self {
            event_id_hex: value.event_id_hex,
            created_at: value.created_at,
            installed_at: value.installed_at,
            emoji_count: value.emoji_count,
            byte_len: value.byte_len,
            update_available: value.update_available,
        }
    }
}

/// A NIP-51 emoji set (kind 30030), or the account's kind-10030 list read
/// as the set of its loose emoji (`kind` 10030, empty `identifier`).
#[derive(Clone, Debug, uniffi::Record)]
pub struct EmojiSetFfi {
    pub coordinate: String,
    pub kind: u16,
    pub author_pubkey_hex: String,
    pub identifier: String,
    pub event_id_hex: String,
    pub created_at: u64,
    pub title: Option<String>,
    pub description: Option<String>,
    /// The cover's URL, for disclosure; load it only through
    /// `fetch_emoji_set_cover`.
    pub image_url: Option<String>,
    pub emoji: Vec<EmojiSetEmojiFfi>,
    /// At most 64 entries; `skipped_count` counts every skipped entry.
    pub skipped: Vec<EmojiSkipFfi>,
    pub skipped_count: u32,
    pub installed: Option<InstalledEmojiSetStateFfi>,
}

impl From<AppEmojiSet> for EmojiSetFfi {
    fn from(value: AppEmojiSet) -> Self {
        Self {
            coordinate: value.coordinate,
            kind: value.kind,
            author_pubkey_hex: value.author_pubkey_hex,
            identifier: value.identifier,
            event_id_hex: value.event_id_hex,
            created_at: value.created_at,
            title: value.title,
            description: value.description,
            image_url: value.image_url,
            emoji: value.emoji.into_iter().map(Into::into).collect(),
            skipped: value.skipped.into_iter().map(Into::into).collect(),
            skipped_count: value.skipped_count,
            installed: value.installed.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct EmojiSetSyncResultFfi {
    pub discovered: u32,
    pub updated: u32,
    /// Whether every relay answered in full.
    pub complete: bool,
}

impl From<AppEmojiSetSyncResult> for EmojiSetSyncResultFfi {
    fn from(value: AppEmojiSetSyncResult) -> Self {
        Self {
            discovered: value.discovered,
            updated: value.updated,
            complete: value.complete,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct EmojiSetInstallResultFfi {
    pub set: EmojiSetFfi,
    pub installed_count: u32,
    /// Parse-time skips first, then install-time ones.
    pub skipped: Vec<EmojiSkipFfi>,
}

impl From<AppEmojiSetInstallResult> for EmojiSetInstallResultFfi {
    fn from(value: AppEmojiSetInstallResult) -> Self {
        Self {
            set: value.set.into(),
            installed_count: value.installed_count,
            skipped: value.skipped.into_iter().map(Into::into).collect(),
        }
    }
}

/// The account's own kind-10030 emoji list, read for suggestions.
#[derive(Clone, Debug, uniffi::Record)]
pub struct UserEmojiListFfi {
    /// Absent when no relay returned a list.
    pub event_id_hex: Option<String>,
    pub created_at: Option<u64>,
    /// The list's loose emoji as an installable set.
    pub own_emoji: Option<EmojiSetFfi>,
    pub sets: Vec<EmojiSetFfi>,
    pub missing_set_coordinates: Vec<String>,
    pub complete: bool,
}

impl From<AppUserEmojiList> for UserEmojiListFfi {
    fn from(value: AppUserEmojiList) -> Self {
        Self {
            event_id_hex: value.event_id_hex,
            created_at: value.created_at,
            own_emoji: value.own_emoji.map(Into::into),
            sets: value.sets.into_iter().map(Into::into).collect(),
            missing_set_coordinates: value.missing_set_coordinates,
            complete: value.complete,
        }
    }
}

/// A validated preview image of one emoji. Not stored.
#[derive(Clone, Debug, uniffi::Record)]
pub struct EmojiSetAssetFfi {
    pub set_coordinate: String,
    pub shortcode: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

impl From<AppEmojiSetAsset> for EmojiSetAssetFfi {
    fn from(value: AppEmojiSetAsset) -> Self {
        Self {
            set_coordinate: value.set_coordinate,
            shortcode: value.shortcode,
            mime: value.mime,
            width: value.width,
            height: value.height,
            frames: value.frames,
            sha256: value.sha256,
            bytes: value.bytes,
        }
    }
}

/// A set's validated cover image (its `image` tag). Not stored.
#[derive(Clone, Debug, uniffi::Record)]
pub struct EmojiSetCoverFfi {
    pub set_coordinate: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

impl From<AppEmojiSetCover> for EmojiSetCoverFfi {
    fn from(value: AppEmojiSetCover) -> Self {
        Self {
            set_coordinate: value.set_coordinate,
            mime: value.mime,
            width: value.width,
            height: value.height,
            frames: value.frames,
            sha256: value.sha256,
            bytes: value.bytes,
        }
    }
}

/// Progress of one install. `completed_emoji` reaches `total_emoji` when
/// every entry has been stored, skipped or given up on; `total_emoji` is 0
/// until the install has read the stored version. `transferred_bytes`
/// counts response bytes from image hosts as each download finishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct EmojiSetInstallProgressFfi {
    pub completed_emoji: u32,
    pub total_emoji: u32,
    pub transferred_bytes: u64,
}

impl From<EmojiSetInstallProgress> for EmojiSetInstallProgressFfi {
    fn from(value: EmojiSetInstallProgress) -> Self {
        Self {
            completed_emoji: value.completed_emoji,
            total_emoji: value.total_emoji,
            transferred_bytes: value.transferred_bytes,
        }
    }
}

/// Cancellation and progress for one `install_emoji_set` call. Create one
/// per install and poll `progress()` for a determinate bar. `cancel()`
/// stops new downloads, drops those in flight, stores nothing and makes the
/// install fail with `EmojiSetInstallCancelled`; a cancelled reinstall
/// leaves the previous snapshot untouched. Shutting down or closing the
/// runtime cancels it the same way. The final atomic write is not
/// interruptible: a cancellation that arrives once it has started is too
/// late and the install succeeds.
#[derive(uniffi::Object)]
pub struct EmojiSetInstallControlFfi {
    pub(crate) inner: Arc<EmojiSetInstallControl>,
}

#[uniffi::export]
impl EmojiSetInstallControlFfi {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::default(),
        })
    }

    pub fn cancel(&self) {
        self.inner.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    pub fn progress(&self) -> EmojiSetInstallProgressFfi {
        self.inner.progress().into()
    }
}

/// One installed emoji for a picker.
#[derive(Clone, Debug, uniffi::Record)]
pub struct InstalledCustomEmojiFfi {
    pub set_coordinate: String,
    pub set_title: Option<String>,
    pub author_pubkey_hex: String,
    pub shortcode: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    /// SHA-256 of the stored bytes, fixed at install.
    pub sha256: String,
    pub byte_len: u64,
    /// Another installed set has this exact shortcode; the host decides.
    pub shortcode_collision: bool,
}

impl From<AppInstalledCustomEmoji> for InstalledCustomEmojiFfi {
    fn from(value: AppInstalledCustomEmoji) -> Self {
        Self {
            set_coordinate: value.set_coordinate,
            set_title: value.set_title,
            author_pubkey_hex: value.author_pubkey_hex,
            shortcode: value.shortcode,
            mime: value.mime,
            width: value.width,
            height: value.height,
            frames: value.frames,
            sha256: value.sha256,
            byte_len: value.byte_len,
            shortcode_collision: value.shortcode_collision,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct InstalledCustomEmojiAssetFfi {
    pub emoji: InstalledCustomEmojiFfi,
    pub bytes: Vec<u8>,
}

impl From<AppInstalledCustomEmojiAsset> for InstalledCustomEmojiAssetFfi {
    fn from(value: AppInstalledCustomEmojiAsset) -> Self {
        Self {
            emoji: value.emoji.into(),
            bytes: value.bytes,
        }
    }
}
