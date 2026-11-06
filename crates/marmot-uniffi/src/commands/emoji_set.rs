//! NIP-51 emoji sets: text-only discovery, the account's own emoji list
//! (read only), explicit image fetches, and installed snapshots read locally.

use crate::Marmot;
use crate::conversions::{
    EmojiSetAssetFfi, EmojiSetFfi, EmojiSetInstallResultFfi, EmojiSetSyncResultFfi,
    InstalledCustomEmojiAssetFfi, InstalledCustomEmojiFfi, UserEmojiListFfi,
};
use crate::errors::MarmotKitError;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Read stored emoji sets, or only installed ones in install order.
    /// `search` matches title, description, author (hex or `npub`) and
    /// shortcodes. Local only; call off the UI thread.
    pub fn emoji_sets(
        &self,
        account_ref: String,
        installed_only: bool,
        search: Option<String>,
        limit: Option<u32>,
    ) -> Result<Vec<EmojiSetFfi>, MarmotKitError> {
        self.app
            .emoji_sets(
                &account_ref,
                installed_only,
                search.as_deref(),
                limit.map(|value| value as usize),
            )
            .map(|sets| sets.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }

    /// Read one stored set by coordinate or `naddr`. Local only.
    pub fn emoji_set(
        &self,
        account_ref: String,
        coordinate: String,
    ) -> Result<Option<EmojiSetFfi>, MarmotKitError> {
        self.app
            .emoji_set(&account_ref, &coordinate)
            .map(|set| set.map(Into::into))
            .map_err(Into::into)
    }

    /// Fetch the 60 newest kind-30030 sets from the account's relays. Text
    /// only: never fetches an image. A `search` that is an `npub` or hex
    /// public key narrows the fetch to that author.
    pub async fn sync_emoji_sets(
        &self,
        account_ref: String,
        search: Option<String>,
    ) -> Result<EmojiSetSyncResultFfi, MarmotKitError> {
        self.app
            .sync_emoji_sets(&account_ref, search.as_deref())
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Fetch one set from a pasted coordinate or `naddr` (up to 8 of its
    /// relay hints are tried). Text only.
    pub async fn fetch_emoji_set(
        &self,
        account_ref: String,
        input: String,
    ) -> Result<EmojiSetFfi, MarmotKitError> {
        self.app
            .fetch_emoji_set(&account_ref, &input)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Read the account's own kind-10030 emoji list and the sets it points
    /// to, as suggestions. Text only. MDK never publishes or edits this list.
    pub async fn user_emoji_list(
        &self,
        account_ref: String,
    ) -> Result<UserEmojiListFfi, MarmotKitError> {
        self.app
            .user_emoji_list(&account_ref)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Download every emoji of the stored set version once, validate it and
    /// store its bytes and SHA-256 under the account. Reveals the user's IP
    /// address to each image host in the set: call only after the user taps
    /// Install.
    pub async fn install_emoji_set(
        &self,
        account_ref: String,
        coordinate: String,
    ) -> Result<EmojiSetInstallResultFfi, MarmotKitError> {
        self.app
            .install_emoji_set(&account_ref, &coordinate)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Remove an installed set and its stored bytes. Returns whether it was
    /// installed. Local only.
    pub async fn uninstall_emoji_set(
        &self,
        account_ref: String,
        coordinate: String,
    ) -> Result<bool, MarmotKitError> {
        self.app
            .uninstall_emoji_set(&account_ref, &coordinate)
            .await
            .map_err(Into::into)
    }

    /// Download one emoji of a stored set for a preview. Reveals the user's
    /// IP address to the image host the set author chose: call only after
    /// the user opens the set. Nothing is stored.
    pub async fn fetch_emoji_set_asset(
        &self,
        account_ref: String,
        coordinate: String,
        shortcode: String,
    ) -> Result<EmojiSetAssetFfi, MarmotKitError> {
        self.app
            .fetch_emoji_set_asset(&account_ref, &coordinate, &shortcode)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Every installed emoji, in set install order then set order, for a
    /// picker. Shortcode collisions between sets are flagged, not resolved.
    /// Local only.
    pub fn installed_custom_emoji(
        &self,
        account_ref: String,
    ) -> Result<Vec<InstalledCustomEmojiFfi>, MarmotKitError> {
        self.app
            .installed_custom_emoji(&account_ref)
            .map(|emoji| emoji.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }

    /// An installed emoji's stored bytes, checked against their SHA-256.
    /// Local only: never touches the network.
    pub fn read_installed_custom_emoji(
        &self,
        account_ref: String,
        coordinate: String,
        shortcode: String,
    ) -> Result<InstalledCustomEmojiAssetFfi, MarmotKitError> {
        self.app
            .read_installed_custom_emoji(&account_ref, &coordinate, &shortcode)
            .map(Into::into)
            .map_err(Into::into)
    }
}
