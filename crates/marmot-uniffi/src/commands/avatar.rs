use crate::conversions::{AvatarAssetFfi, AvatarBytesFfi};
use crate::{Marmot, MarmotKitError};
use marmot_app::{AppError, AvatarAssetRef, AvatarAssetTarget, MAX_AVATAR_BATCH_ITEMS};
fn check_count(count: usize) -> Result<(), MarmotKitError> {
    if count > MAX_AVATAR_BATCH_ITEMS {
        return Err(AppError::InvalidEncryptedMedia(format!(
            "avatar batch exceeds {MAX_AVATAR_BATCH_ITEMS} items"
        ))
        .into());
    }
    Ok(())
}
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Pass up to 16 opaque targets from visible screen metadata. Does not await HTTP.
    pub async fn request_avatar_assets(
        &self,
        account_ref: String,
        targets: Vec<String>,
    ) -> Result<Vec<AvatarAssetFfi>, MarmotKitError> {
        check_count(targets.len())?;
        let targets = targets
            .iter()
            .map(|v| AvatarAssetTarget::from_opaque(v))
            .collect::<Result<Vec<_>, _>>()
            .map_err(AppError::from)?;
        Ok(self
            .runtime
            .request_avatar_assets(&account_ref, targets)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    /// Local-only read, up to 16 references and a 1-byte..16-MiB aggregate byte budget.
    /// Results preserve input order; deferred entries can be retried in a later batch.
    pub async fn read_avatar_assets(
        &self,
        account_ref: String,
        references: Vec<String>,
        max_bytes: u64,
    ) -> Result<Vec<AvatarBytesFfi>, MarmotKitError> {
        check_count(references.len())?;
        let references = references
            .iter()
            .map(|v| AvatarAssetRef::from_opaque(v))
            .collect::<Result<Vec<_>, _>>()
            .map_err(AppError::from)?;
        Ok(self
            .runtime
            .read_avatar_assets(&account_ref, references, max_bytes)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    pub async fn clear_avatar_cache(&self, account_ref: String) -> Result<(), MarmotKitError> {
        Ok(self.runtime.clear_avatar_cache(&account_ref).await?)
    }
}
