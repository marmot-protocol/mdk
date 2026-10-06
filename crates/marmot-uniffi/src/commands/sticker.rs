//! Sonar-compatible sticker pack lifecycle, asset fetch, and import commands.

use crate::Marmot;
use crate::conversions::{
    StickerAssetFfi, StickerImportResultFfi, StickerPackFfi, StickerRefFfi, StickerSyncResultFfi,
};
use crate::errors::MarmotKitError;

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Read the encrypted native sticker projection. Call off the UI thread.
    pub fn sticker_packs(
        &self,
        account_ref: String,
        installed_only: bool,
        search: Option<String>,
        limit: Option<u32>,
    ) -> Result<Vec<StickerPackFfi>, MarmotKitError> {
        self.app
            .sticker_packs(
                &account_ref,
                installed_only,
                search.as_deref(),
                limit.map(|value| value as usize),
            )
            .map(|packs| packs.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }

    pub fn sticker_pack(
        &self,
        account_ref: String,
        input: String,
    ) -> Result<Option<StickerPackFfi>, MarmotKitError> {
        self.app
            .sticker_pack(&account_ref, &input)
            .map(|pack| pack.map(Into::into))
            .map_err(Into::into)
    }

    pub async fn sync_sticker_packs(
        &self,
        account_ref: String,
    ) -> Result<StickerSyncResultFfi, MarmotKitError> {
        self.app
            .sync_sticker_packs(&account_ref)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    pub async fn fetch_sticker_pack(
        &self,
        account_ref: String,
        input: String,
    ) -> Result<StickerPackFfi, MarmotKitError> {
        self.app
            .fetch_sticker_pack(&account_ref, &input)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    pub async fn install_sticker_pack(
        &self,
        account_ref: String,
        input: String,
    ) -> Result<StickerPackFfi, MarmotKitError> {
        self.app
            .install_sticker_pack(&account_ref, &input)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    pub async fn uninstall_sticker_pack(
        &self,
        account_ref: String,
        input: String,
    ) -> Result<(), MarmotKitError> {
        self.app
            .uninstall_sticker_pack(&account_ref, &input)
            .await
            .map_err(Into::into)
    }

    pub async fn import_signal_sticker_pack(
        &self,
        account_ref: String,
        signal_link: String,
        blossom_server: Option<String>,
    ) -> Result<StickerImportResultFfi, MarmotKitError> {
        self.app
            .import_signal_sticker_pack(&account_ref, signal_link, blossom_server.as_deref())
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    pub async fn fetch_sticker_asset(
        &self,
        account_ref: String,
        sticker_ref: StickerRefFfi,
    ) -> Result<StickerAssetFfi, MarmotKitError> {
        self.app
            .fetch_sticker_asset(&account_ref, sticker_ref.into())
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
