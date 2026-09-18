use crate::conversions::{
    AttachmentLocalAssetFfi, AttachmentLocalBytesFfi, AttachmentLocalTargetFfi, group_id_from_hex,
};
use crate::{Marmot, MarmotKitError};
use marmot_app::{AppError, AttachmentAssetRef, MAX_ATTACHMENT_ASSET_LOOKUPS};

#[uniffi::export(async_runtime = "tokio")]
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
    }
}
