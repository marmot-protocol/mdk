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
#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_avatar_count_guard_accepts_the_boundary_and_rejects_overflow() {
        assert!(check_count(0).is_ok());
        assert!(check_count(16).is_ok());
        assert!(
            matches!(check_count(17), Err(MarmotKitError::InvalidMediaReference { details }) if details == "avatar batch exceeds 16 items")
        );
        // Request/read consume this helper. Their opaque codecs and native
        // budgets/acquisition remain with their existing owners; no forwarding
        // observation is inferred from a lower guard that could mask omission.
    }
}
