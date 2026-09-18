//! Local retained attachment access. No demand, worker or engine is started here.
use super::MarmotAppRuntime;
use crate::AppError;
use cgka_traits::GroupId;
pub use storage_sqlite::{
    AttachmentAssetRef, MAX_ATTACHMENT_LOCAL_READ_BYTES, RetainedAttachmentAsset,
};
use zeroize::Zeroizing;

pub const MAX_ATTACHMENT_ASSET_LOOKUPS: usize = 64;

/// Original source slot from a timeline row or attachment history entry.
#[derive(Clone)]
pub struct AttachmentLocalTarget {
    pub message_id_hex: String,
    pub source_message_id_hex: String,
    pub attachment_index: u32,
}
impl std::fmt::Debug for AttachmentLocalTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentLocalTarget")
            .finish_non_exhaustive()
    }
}
impl MarmotAppRuntime {
    /// Look up up to 64 retained assets in input order, including duplicate targets.
    /// None means not locally available, not a download failure or queued demand.
    /// Metadata contains no bytes. Results are advisory: every subsequent read
    /// rechecks the source and retention deadline. No account worker is needed.
    pub async fn attachment_local_assets(
        &self,
        account_ref: &str,
        group: &GroupId,
        mut targets: Vec<AttachmentLocalTarget>,
    ) -> Result<Vec<Option<RetainedAttachmentAsset>>, AppError> {
        if targets.len() > MAX_ATTACHMENT_ASSET_LOOKUPS {
            return Err(AppError::InvalidEncryptedMedia(
                "too many attachment asset lookups".into(),
            ));
        }
        for target in &mut targets {
            for id in [
                &mut target.message_id_hex,
                &mut target.source_message_id_hex,
            ] {
                if id.len() != 64 || !id.bytes().all(|v| v.is_ascii_hexdigit()) {
                    return Err(AppError::InvalidEncryptedMedia(
                        "invalid attachment source id".into(),
                    ));
                }
                id.make_ascii_lowercase();
            }
        }
        let group = hex::encode(group.as_slice());
        self.attachment_read(account_ref, move |storage, _| {
            targets
                .into_iter()
                .map(|target| {
                    storage
                        .retained_attachment_asset(
                            &group,
                            &target.message_id_hex,
                            &target.source_message_id_hex,
                            target.attachment_index,
                            crate::unix_now_seconds(),
                        )
                        .map_err(Into::into)
                })
                .collect()
        })
        .await
    }

    /// Read 1..=1 MiB from a verified retained asset. None means unavailable or
    /// invalidated, including a handle from another account/store incarnation.
    /// Some(empty) is EOF (offset at or beyond length), including a zero-byte file.
    /// Hosts must discard any assembled content if a later chunk is unavailable.
    /// The account database is opened on the blocking pool, with no hydration/HTTP.
    pub async fn read_attachment_asset(
        &self,
        account_ref: &str,
        reference: AttachmentAssetRef,
        offset: u64,
        limit: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
        if limit == 0 || limit > MAX_ATTACHMENT_LOCAL_READ_BYTES || offset > i64::MAX as u64 {
            return Err(AppError::InvalidEncryptedMedia(
                "invalid attachment byte range".into(),
            ));
        }
        self.attachment_read(account_ref, move |storage, _| {
            storage
                .read_retained_attachment(&reference, crate::unix_now_seconds(), offset, limit)
                .map_err(Into::into)
        })
        .await
    }
}
#[cfg(test)]
mod tests;
