use crate::conversions::{
    AttachmentHandoffFfi, AttachmentLocalAssetFfi, AttachmentLocalBytesFfi,
    AttachmentLocalTargetFfi, MediaFileTransferControlFfi, group_id_from_hex,
};
use crate::{Marmot, MarmotKitError};
use marmot_app::{AppError, AttachmentAssetRef, MAX_ATTACHMENT_ASSET_LOOKUPS};
use std::sync::Arc;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Local-only metadata for up to 64 original source slots in one group.
    /// Results preserve input order/duplicates. No bytes are loaded, jobs queued,
    /// downloads started or engine state hydrated. Requires no runtime start.
    pub async fn attachment_local_assets(
        &self,
        account_ref: String,
        group_id_hex: String,
        targets: Vec<AttachmentLocalTargetFfi>,
    ) -> Result<Vec<AttachmentLocalAssetFfi>, MarmotKitError> {
        // Reject before allocating the converted target vector; the runtime also
        // enforces this bound for callers that bypass the native adapter.
        if targets.len() > MAX_ATTACHMENT_ASSET_LOOKUPS {
            return Err(AppError::InvalidEncryptedMedia(
                "too many attachment asset lookups".into(),
            )
            .into());
        }
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .attachment_local_assets(
                &account_ref,
                &group,
                targets.into_iter().map(Into::into).collect(),
            )
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    /// Read 1..=1048576 bytes at an offset from an opaque local asset reference.
    /// Unavailable is distinct from available/empty EOF. Every call rechecks
    /// source visibility, expiry and account/store identity. No network fallback.
    /// Hosts own decoding and must discard assembled bytes if a chunk is unavailable.
    pub async fn read_attachment_asset(
        &self,
        account_ref: String,
        reference: String,
        offset: u64,
        limit: u32,
    ) -> Result<AttachmentLocalBytesFfi, MarmotKitError> {
        let reference = AttachmentAssetRef::from_opaque(&reference).map_err(AppError::from)?;
        Ok(self
            .runtime
            .read_attachment_asset(&account_ref, reference, offset, limit as usize)
            .await?
            .into())
    }

    /// Write a plaintext copy of one retained attachment for an OS surface
    /// that needs a real file (package installer, share sheet, "open with",
    /// Quick Look) and lend it under a lease. `None` means the attachment is
    /// not held locally, as `attachment_local_assets` reports it. The copy
    /// stays until `release_attachment_handoff`, account removal, or the
    /// account worker's next start in a new process; removing the attachment
    /// does not revoke it. `control` reports copied bytes and cancels the
    /// copy. `StorageFull` when the disk cannot hold the copy beyond the
    /// reserve. No network or download is started.
    ///
    /// Cancel a handoff only through `control`, which always leaves no copy
    /// and no lease. Do not cancel the awaiting coroutine or task: if that
    /// happens just as the call completes, the result can be dropped before
    /// the host sees the lease, and the copy then stays until the account
    /// worker's next start in a new process, which deletes it.
    // Polled on the caller, never spawned: a spawned export could finish and
    // drop the lease while a cancelled host never collects it. Dropped on
    // the caller, the pending copy is discarded instead.
    #[marmot_uniffi_macros::receive]
    pub async fn open_attachment_handoff(
        &self,
        account_ref: String,
        group_id_hex: String,
        target: AttachmentLocalTargetFfi,
        control: Arc<MediaFileTransferControlFfi>,
    ) -> Result<Option<AttachmentHandoffFfi>, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .open_attachment_handoff(&account_ref, &group, target.into(), control.inner.clone())
            .await?
            .map(Into::into))
    }

    /// Delete a handoff copy once the OS surface is done with it. An unknown
    /// or already released lease is not an error. A malformed lease returns
    /// `InvalidMediaReference`, which no retry fixes. A copy that cannot be
    /// deleted returns `Io` and stays leased: retry the release. A release
    /// the host stops waiting for still runs to completion.
    #[marmot_uniffi_macros::survives_cancellation]
    pub async fn release_attachment_handoff(&self, lease: String) -> Result<(), MarmotKitError> {
        Ok(self.runtime.release_attachment_handoff(&lease).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_account::AccountHome;
    use marmot_app::MarmotApp;
    #[tokio::test]
    async fn attachment_local_native_missing_validation_and_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        let target = AttachmentLocalTargetFfi {
            message_id_hex: "aa".repeat(32),
            source_message_id_hex: "bb".repeat(32),
            attachment_index: 0,
        };
        let result = kit
            .attachment_local_assets("alice".into(), "ab".repeat(16), vec![target.clone()])
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].reference.is_none());
        assert_eq!(result[0].byte_count, 0);
        let absent = format!("1:{}:{}", "00".repeat(16), "00".repeat(16));
        let bytes = kit
            .read_attachment_asset("alice".into(), absent.clone(), 0, 1)
            .await
            .unwrap();
        assert!(!bytes.available);
        assert!(bytes.bytes.is_empty());
        let control = MediaFileTransferControlFfi::new();
        assert!(
            kit.open_attachment_handoff(
                "alice".into(),
                "ab".repeat(16),
                target.clone(),
                control.clone()
            )
            .await
            .unwrap()
            .is_none(),
            "an attachment not held locally has no handoff"
        );
        kit.release_attachment_handoff("cd".repeat(16))
            .await
            .unwrap();
        assert!(matches!(
            kit.release_attachment_handoff("not-a-lease".into()).await,
            Err(MarmotKitError::InvalidMediaReference { .. })
        ));
        assert!(
            kit.read_attachment_asset("alice".into(), "bad".into(), 0, 1)
                .await
                .is_err()
        );
        for (offset, limit) in [(0, 0), (0, 1_048_577), (u64::MAX, 1)] {
            assert!(
                kit.read_attachment_asset("alice".into(), absent.clone(), offset, limit)
                    .await
                    .is_err()
            );
        }
        assert!(
            kit.attachment_local_assets("alice".into(), "ab".repeat(16), vec![target.clone(); 65])
                .await
                .is_err()
        );
        assert!(
            kit.attachment_local_assets("alice".into(), String::new(), vec![])
                .await
                .is_err()
        );
        assert!(
            kit.attachment_local_assets("missing".into(), "ab".repeat(16), vec![])
                .await
                .is_err()
        );
        kit.shutdown_and_close().await.unwrap();
        assert!(
            kit.attachment_local_assets("alice".into(), "ab".repeat(16), vec![target])
                .await
                .is_err()
        );
        assert!(
            kit.read_attachment_asset("alice".into(), absent, 0, 1)
                .await
                .is_err()
        );
        assert!(
            kit.open_attachment_handoff(
                "alice".into(),
                "ab".repeat(16),
                AttachmentLocalTargetFfi {
                    message_id_hex: "aa".repeat(32),
                    source_message_id_hex: "bb".repeat(32),
                    attachment_index: 0,
                },
                MediaFileTransferControlFfi::new(),
            )
            .await
            .is_err(),
            "a closed runtime refuses new handoffs"
        );
    }
}
