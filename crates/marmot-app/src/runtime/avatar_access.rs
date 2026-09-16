//! Local native avatar access; all blocking SQL work stays off runtime/UI threads.
use super::{MarmotAppRuntime, blocking_app_task, wait_for_runtime_shutdown};
use crate::AppError;
use storage_sqlite::{
    AvatarAssetPresentation, AvatarAssetRead, AvatarAssetRef, AvatarAssetTarget,
    ChatPresentationRead,
};

pub const MAX_AVATAR_BATCH_ITEMS: usize = 16;
pub const MAX_AVATAR_BATCH_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAvatarRead {
    pub reference: AvatarAssetRef,
    pub result: AvatarAssetRead,
    /// Ready/stale bytes did not fit the remaining caller-selected batch budget.
    pub deferred: bool,
}
fn validate_count(count: usize) -> Result<(), AppError> {
    if count > MAX_AVATAR_BATCH_ITEMS {
        return Err(AppError::InvalidEncryptedMedia(
            "avatar batch exceeds 16 items".into(),
        ));
    }
    Ok(())
}
impl MarmotAppRuntime {
    /// Request only targets visible in the host viewport. Locators come directly
    /// from screen metadata; hosts do not choose sources or resolve profiles.
    pub async fn request_avatar_assets(
        &self,
        account_ref: &str,
        targets: Vec<AvatarAssetTarget>,
    ) -> Result<Vec<AvatarAssetPresentation>, AppError> {
        validate_count(targets.len())?;
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let app = self.accounts.app.clone();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => Err(AppError::RuntimeStopping),
            result = blocking_app_task(move || {
                if app.account_home().account(&account.label)?.account_id_hex != account.account_id_hex { return Err(marmot_account::AccountHomeError::AccountIdMismatch.into()); }
                let storage = app.account_storage(&account.label)?;
                let result = targets.into_iter().map(|target| {
                    let Some(group) = storage.resolve_avatar_target(&target)? else { return Ok(AvatarAssetPresentation::invalidated(target)); };
                    let (selected, version) = if let Some(member) = target.member() {
                        let Some(input) = storage.chat_presentation_input(&group)? else { return Ok(AvatarAssetPresentation::invalidated(target)); };
                        let (selected,version) = super::avatar::selected_identity(&app, &input, &account.account_id_hex, member)?;
                        (selected, Some(version))
                    } else {
                        let ChatPresentationRead::Ready(value) = storage.chat_presentation(&group)? else { return Ok(AvatarAssetPresentation::invalidated(target)); };
                        (value.presentation.avatar,None)
                    };
                    Ok(storage.request_avatar_target(&target, &selected, version.as_ref(), crate::unix_now_seconds())?)
                }).collect::<Result<Vec<_>,AppError>>();
                // Even a later-item failure must publish already committed demand.
                app.presentation_signals.wake();
                let _ = app.presentation_signals.avatars.send(account.label);
                result
            }) => result,
        }
    }

    /// Read at most 16 references and 16 MiB of encoded bytes, in input order.
    /// Missing/invalidated entries and budget-deferred images are explicit. No
    /// worker, relay, hydration, HTTP request or screen subscription is required.
    pub async fn read_avatar_assets(
        &self,
        account_ref: &str,
        references: Vec<AvatarAssetRef>,
        max_bytes: u64,
    ) -> Result<Vec<LocalAvatarRead>, AppError> {
        validate_count(references.len())?;
        if max_bytes == 0 || max_bytes > MAX_AVATAR_BATCH_BYTES {
            return Err(AppError::InvalidEncryptedMedia(
                "invalid avatar byte budget".into(),
            ));
        }
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let app = self.accounts.app.clone();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => Err(AppError::RuntimeStopping),
            result = blocking_app_task(move || {
                if app.account_home().account(&account.label)?.account_id_hex != account.account_id_hex { return Err(marmot_account::AccountHomeError::AccountIdMismatch.into()); }
                let storage = app.account_storage(&account.label)?;
                let mut remaining = max_bytes;
                let mut reads = Vec::with_capacity(references.len());
                let mut repaired = false;
                for reference in references {
                    let result = storage.read_avatar_bounded(&reference, crate::unix_now_seconds(), remaining)?;
                    let deferred = result.image.is_none() && result.status.byte_count > remaining;
                    repaired |= result.status.availability == storage_sqlite::AvatarAvailability::Missing;
                    if let Some(image) = &result.image { remaining -= image.bytes().len() as u64; }
                    reads.push(LocalAvatarRead { reference, result, deferred });
                }
                if repaired {
                    app.presentation_signals.wake();
                    let _ = app.presentation_signals.avatars.send(account.label);
                }
                Ok(reads)
            }) => result,
        }
    }

    /// Explicit local removal clears bytes and background demand. A later visible
    /// request may acquire them again; maintenance alone does not refill the cache.
    pub async fn clear_avatar_cache(&self, account_ref: &str) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let app = self.accounts.app.clone();
        blocking_app_task(move || {
            if app.account_home().account(&account.label)?.account_id_hex != account.account_id_hex
            {
                return Err(marmot_account::AccountHomeError::AccountIdMismatch.into());
            }
            app.account_storage(&account.label)?.clear_avatar_cache()?;
            let _ = app.presentation_signals.avatars.send(account.label);
            Ok(())
        })
        .await
    }
}
