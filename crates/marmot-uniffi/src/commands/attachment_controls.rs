use crate::{Marmot, MarmotKitError, conversions::*};
use marmot_app::{AppError, AttachmentAssetRef};
use std::sync::Arc;
#[derive(uniffi::Object)]
pub struct AttachmentTransferSubscription {
    inner: Arc<marmot_app::RuntimeAttachmentTransferSubscription>,
}
#[uniffi::export(async_runtime = "tokio")]
impl AttachmentTransferSubscription {
    /// Initial snapshot, then coalesced replacements. None means closed. Errors
    /// terminate this observation; close/drop never cancels acquisition.
    pub async fn next(&self) -> Result<Option<AttachmentTransferSnapshotFfi>, MarmotKitError> {
        match self.inner.next().await {
            Ok(v) => Ok(v.map(Into::into)),
            Err(e) => {
                self.inner.close();
                Err(e.into())
            }
        }
    }
    pub fn cancel(&self) {
        self.inner.close();
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Revoke automatic permission before evaluating new host network policy.
    pub async fn begin_attachment_permission_update(
        &self,
        account_ref: String,
    ) -> Result<String, MarmotKitError> {
        Ok(self
            .runtime
            .begin_attachment_permission_update(&account_ref)
            .await?)
    }
    /// Apply a single-use generation; false means stale, foreign, or already used.
    pub async fn set_attachment_automatic_permission(
        &self,
        account_ref: String,
        generation: String,
        permission: AttachmentAutomaticPermissionFfi,
    ) -> Result<bool, MarmotKitError> {
        Ok(self
            .runtime
            .set_attachment_automatic_permission(&account_ref, generation, permission.into())
            .await?)
    }
    /// Idempotent automatic demand for the current authoritative source slot.
    pub async fn request_automatic_attachment(
        &self,
        account_ref: String,
        group_id_hex: String,
        target: AttachmentLocalTargetFfi,
    ) -> Result<AutomaticAttachmentRequestFfi, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .request_automatic_attachment(&account_ref, &group, target.into())
            .await?
            .into())
    }

    pub async fn attachment_download_policy(
        &self,
        account_ref: String,
    ) -> Result<AttachmentDownloadPolicyFfi, MarmotKitError> {
        Ok(self
            .runtime
            .attachment_download_policy(&account_ref)
            .await?
            .into())
    }
    pub async fn set_attachment_download_policy(
        &self,
        account_ref: String,
        policy: AttachmentDownloadPolicyFfi,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .set_attachment_download_policy(&account_ref, policy.into())
            .await?)
    }
    /// Cancel durably, retry explicitly, or remove local bytes. Returns false for
    /// obsolete references or ineligible operations; cancellation preserves ready bytes.
    pub async fn control_attachment(
        &self,
        account_ref: String,
        reference: String,
        control: AttachmentControlFfi,
    ) -> Result<bool, MarmotKitError> {
        let reference = AttachmentAssetRef::from_opaque(&reference).map_err(AppError::from)?;
        Ok(self
            .runtime
            .control_attachment(&account_ref, reference, control.into())
            .await?)
    }
    pub async fn download_attachment_again(
        &self,
        account_ref: String,
        group_id_hex: String,
        target: AttachmentLocalTargetFfi,
    ) -> Result<Option<String>, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .download_attachment_again(&account_ref, &group, target.into())
            .await?
            .map(|r| r.to_opaque()))
    }
    pub async fn attachment_transfer_snapshot(
        &self,
        account_ref: String,
        group_id_hex: String,
        targets: Vec<AttachmentLocalTargetFfi>,
    ) -> Result<AttachmentTransferSnapshotFfi, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        if targets.len() > marmot_app::MAX_ATTACHMENT_ASSET_LOOKUPS {
            return Err(
                AppError::InvalidEncryptedMedia("too many attachment targets".into()).into(),
            );
        }
        Ok(self
            .runtime
            .attachment_transfer_snapshot(
                &account_ref,
                &group,
                targets.into_iter().map(Into::into).collect(),
            )
            .await?
            .into())
    }
    pub async fn subscribe_attachment_transfers(
        &self,
        account_ref: String,
        group_id_hex: String,
        targets: Vec<AttachmentLocalTargetFfi>,
    ) -> Result<Arc<AttachmentTransferSubscription>, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        if targets.len() > marmot_app::MAX_ATTACHMENT_ASSET_LOOKUPS {
            return Err(
                AppError::InvalidEncryptedMedia("too many attachment targets".into()).into(),
            );
        }
        Ok(Arc::new(AttachmentTransferSubscription {
            inner: self
                .runtime
                .subscribe_attachment_transfers(
                    &account_ref,
                    &group,
                    targets.into_iter().map(Into::into).collect(),
                )
                .await?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_account::AccountHome;
    use marmot_app::MarmotApp;
    #[tokio::test]
    async fn attachment_native_policy_roundtrip_bounded_stream_timeout_close_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        let mut policy = kit
            .attachment_download_policy("alice".into())
            .await
            .unwrap();
        assert!(policy.automatic);
        policy.automatic = false;
        kit.set_attachment_download_policy("alice".into(), policy.clone())
            .await
            .unwrap();
        assert!(
            !kit.attachment_download_policy("alice".into())
                .await
                .unwrap()
                .automatic
        );
        policy.transfer_limit = 0;
        assert!(
            kit.set_attachment_download_policy("alice".into(), policy)
                .await
                .is_err()
        );
        let target = AttachmentLocalTargetFfi {
            message_id_hex: "aa".repeat(32),
            source_message_id_hex: "bb".repeat(32),
            attachment_index: 0,
        };
        let stream = kit
            .subscribe_attachment_transfers(
                "alice".into(),
                "ab".repeat(16),
                vec![target.clone(); 2],
            )
            .await
            .unwrap();
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.items.len(), 2);
        assert!(matches!(
            first.items[0].state,
            AttachmentTransferStateFfi::Unavailable
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), stream.next())
                .await
                .is_err()
        );
        stream.cancel();
        assert!(stream.next().await.unwrap().is_none());
        assert!(
            kit.attachment_transfer_snapshot("alice".into(), "ab".repeat(16), vec![target; 65])
                .await
                .is_err()
        );
        let stream = kit
            .subscribe_attachment_transfers("alice".into(), "ab".repeat(16), vec![])
            .await
            .unwrap();
        stream.next().await.unwrap();
        kit.shutdown_and_close().await.unwrap();
        assert!(stream.next().await.unwrap().is_none());
    }
}
