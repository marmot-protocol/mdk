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
        validate_targets(&mut targets)?;
        let group = hex::encode(group.as_slice());
        self.attachment_read(account_ref, move |storage, _| {
            targets
                .into_iter()
                .map(|target| {
                    storage
                        .app_storage()
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
        self.attachment_read_with(account_ref, move |app, label, storage, _| {
            // The database authorizes the read and locates the body; a media
            // file body is then read through the store on this blocking thread.
            match storage.app_storage().retained_attachment_read(
                &reference,
                crate::unix_now_seconds(),
                offset,
                limit,
            )? {
                None => Ok(None),
                Some(storage_sqlite::RetainedAttachmentRead::Bytes(bytes)) => Ok(Some(bytes)),
                Some(storage_sqlite::RetainedAttachmentRead::MediaFile(id)) => {
                    let media = app.account_media_store(label, &storage)?;
                    let mut bytes = Zeroizing::new(vec![0; limit]);
                    let Some(read) = media
                        .read_at(&id, offset, &mut bytes)
                        .map_err(storage_sqlite::media_storage_error)?
                    else {
                        return Ok(None);
                    };
                    bytes.truncate(read);
                    Ok(Some(bytes))
                }
            }
        })
        .await
    }
}
impl MarmotAppRuntime {
    /// Writes a plaintext copy of one retained attachment for an OS surface
    /// that needs a real file, and lends it to the host under a lease.
    /// `None` means the attachment is not held locally (as
    /// [`Self::attachment_local_assets`] reports it). The copy stays until
    /// [`Self::release_attachment_handoff`], account removal, or the wipe
    /// when the account worker next starts in a new process; removing the
    /// attachment does not revoke it. `control` reports copied bytes and
    /// cancels the copy. A copy the disk cannot hold beyond the reserve fails
    /// with the storage-full error. No network, demand or engine work.
    pub async fn open_attachment_handoff(
        &self,
        account_ref: &str,
        group: &GroupId,
        target: AttachmentLocalTarget,
        control: std::sync::Arc<crate::MediaFileTransferControl>,
    ) -> Result<Option<crate::media::handoff::AttachmentHandoff>, AppError> {
        let mut targets = [target];
        validate_targets(&mut targets)?;
        let [target] = targets;
        let group = hex::encode(group.as_slice());
        self.attachment_read_with(account_ref, move |app, label, storage, loopback| {
            let Some(source) =
                crate::media::handoff::HandoffSource::find(&storage, &group, &target, loopback)?
            else {
                return Ok(None);
            };
            crate::media::handoff::open(app, label, &storage, source, &control)
        })
        .await
        // Abandoning this call drops the pending copy where the blocking
        // task finishes, which discards it; only a delivered one is leased.
        .map(|pending| pending.map(crate::media::handoff::PendingHandoff::deliver))
    }

    /// Deletes a handoff copy. An unknown or already released lease is not
    /// an error. A malformed lease is `InvalidEncryptedMedia`, which no retry
    /// fixes. A copy that cannot be deleted is `AppError::Io` (its original
    /// `ErrorKind`, fixed text): the lease stays registered and the host
    /// should retry, since the file holds plaintext.
    pub async fn release_attachment_handoff(&self, lease: &str) -> Result<(), AppError> {
        let lease = lease.to_owned();
        tokio::task::spawn_blocking(move || crate::media::handoff::release(&lease))
            .await
            .map_err(|_| AppError::BlockingTask("attachment handoff release failed".into()))?
    }
}

#[cfg(test)]
mod tests;

pub(super) fn validate_targets(targets: &mut [AttachmentLocalTarget]) -> Result<(), AppError> {
    if targets.len() > MAX_ATTACHMENT_ASSET_LOOKUPS {
        return Err(AppError::InvalidEncryptedMedia(
            "too many attachment asset lookups".into(),
        ));
    }
    for target in targets {
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

    Ok(())
}
