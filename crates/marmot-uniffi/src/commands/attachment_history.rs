//! Account/group-scoped attachment pages independent of engine readiness.
use crate::conversions::{
    AttachmentHistoryCursor, AttachmentHistoryVersion, AttachmentPageReadFfi, group_id_from_hex,
};
use crate::{Marmot, MarmotKitError};
use std::sync::Arc;

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Read 1..=100 attachment slots in canonical newest-first order. Rejected slots
    /// consume the limit. Filter categories within returned pages; an empty filtered
    /// page is not exhaustion while has_more is true. No downloads are started.
    /// Keep cursors/versions in memory only and restart after runtime reconstruction.
    pub async fn attachment_history_page(
        &self,
        account_ref: String,
        group_id_hex: String,
        limit: u32,
        cursor: Option<Arc<AttachmentHistoryCursor>>,
    ) -> Result<AttachmentPageReadFfi, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .attachment_history_page(
                &account_ref,
                &group,
                limit as usize,
                cursor.map(|c| c.inner.clone()),
            )
            .await?
            .into())
    }
    /// Cheap local refresh signal, including for a fully loaded or empty library.
    /// Compare against the baseline version captured when the current collection began: replacing
    /// that baseline with a newer page can hide a destructive change to earlier rows.
    pub async fn attachment_history_version(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Arc<AttachmentHistoryVersion>, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(Arc::new(AttachmentHistoryVersion {
            inner: self
                .runtime
                .attachment_history_version(&account_ref, &group)
                .await?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversions::{
        AttachmentCategoryFfi, AttachmentHistoryChangeFfi, AttachmentPageFfi,
        EncryptedMediaVersionFfi, MediaAttachmentOutcomeFfi, MediaAttachmentReferenceFfi,
        MediaLocatorFfi,
    };
    use cgka_traits::TransportEndpoint;
    use marmot_app::{AccountSetupRequest, MarmotApp};
    use nostr_relay_builder::{LocalRelay, RelayBuilder, builder::RateLimit};
    use std::collections::HashSet;

    fn reference(mime: &str) -> MediaAttachmentReferenceFfi {
        MediaAttachmentReferenceFfi {
            locators: vec![MediaLocatorFfi {
                kind: "blossom-v1".into(),
                value: format!("https://media.example/{}.bin", "11".repeat(32)),
            }],
            ciphertext_sha256: "11".repeat(32),
            plaintext_sha256: "22".repeat(32),
            nonce_hex: "33".repeat(12),
            file_name: "attachment.bin".into(),
            media_type: mime.into(),
            version: EncryptedMediaVersionFfi::V2,
            source_epoch: 0,
            dim: None,
            thumbhash: None,
        }
    }
    fn page(value: AttachmentPageReadFfi) -> AttachmentPageFfi {
        let AttachmentPageReadFfi::Page { page } = value else {
            panic!("expected page: {value:?}")
        };
        page
    }
    #[tokio::test]
    async fn attachment_native_pages_traverse_beyond_window_and_refresh_deleted_rows() {
        // Populate 205 messages on one persistent socket without exercising
        // the mock's default 60-event/minute limiter in this pagination test.
        let relay = LocalRelay::new(RelayBuilder::default().rate_limit(RateLimit {
            notes_per_minute: 1_000,
            ..Default::default()
        }));
        relay.run().await.unwrap();
        let url = relay.url().await.to_string();
        let root = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relays(root.path(), vec![url.clone()]);
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        let endpoint = TransportEndpoint(url);
        let account = kit
            .runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .account
            .account_id_hex;
        let group = kit
            .create_group(account.clone(), "attachment pages".into(), vec![], None)
            .await
            .unwrap();
        // Unique captions prevent same-second NIP-01 duplicate message IDs.
        for i in 0..205 {
            if i % 7 == 0 {
                kit.send_media_attachments(
                    account.clone(),
                    group.clone(),
                    vec![reference("image/png"), reference("audio/ogg")],
                    Some(format!("album {i}")),
                )
                .await
                .unwrap();
            } else {
                kit.send_text(account.clone(), group.clone(), format!("text {i}"))
                    .await
                    .unwrap();
            }
        }
        let first = page(
            kit.attachment_history_page(account.clone(), group.to_uppercase(), 1, None)
                .await
                .unwrap(),
        );
        assert!(first.has_more);
        let baseline = first.version.clone();
        assert_eq!(
            kit.attachment_history_version(account.clone(), group.clone())
                .await
                .unwrap()
                .change_since(baseline.clone()),
            AttachmentHistoryChangeFfi::Unchanged
        );
        let mut current = first.clone();
        let mut seen = HashSet::new();
        loop {
            assert_eq!(current.entries.len(), 1);
            let entry = &current.entries[0];
            let MediaAttachmentOutcomeFfi::Accepted {
                attachment_index,
                reference,
            } = &entry.attachment
            else {
                panic!("accepted")
            };
            assert_eq!(
                entry.category,
                if *attachment_index == 0 {
                    AttachmentCategoryFfi::Image
                } else {
                    AttachmentCategoryFfi::Audio
                }
            );
            assert_eq!(Some(reference.source_epoch), entry.source_epoch);
            assert!(seen.insert((entry.message_id_hex.clone(), *attachment_index)));
            assert_eq!(current.has_more, current.next_cursor.is_some());
            if !current.has_more {
                break;
            }
            current = page(
                kit.attachment_history_page(account.clone(), group.clone(), 1, current.next_cursor)
                    .await
                    .unwrap(),
            );
            assert!(seen.len() < 61);
        }
        assert_eq!(seen.len(), 60);
        assert!(matches!(
            kit.attachment_history_page(
                account.clone(),
                "ab".repeat(16),
                1,
                first.next_cursor.clone()
            )
            .await
            .unwrap(),
            AttachmentPageReadFfi::CursorMismatch
        ));
        let other = marmot_account::AccountHome::open(root.path())
            .create_nostr_account()
            .unwrap()
            .account_id_hex;
        assert!(
            page(
                kit.attachment_history_page(other.clone(), group.clone(), 10, None)
                    .await
                    .unwrap()
            )
            .entries
            .is_empty()
        );
        assert!(matches!(
            kit.attachment_history_page(other, group.clone(), 1, first.next_cursor.clone())
                .await
                .unwrap(),
            AttachmentPageReadFfi::CursorMismatch
        ));
        for limit in [0, 101] {
            assert!(matches!(
                kit.attachment_history_page(account.clone(), group.clone(), limit, None)
                    .await
                    .unwrap(),
                AttachmentPageReadFfi::InvalidLimit
            ));
        }
        assert!(
            kit.attachment_history_page(account.clone(), String::new(), 1, None)
                .await
                .is_err()
        );
        kit.send_media_attachments(
            account.clone(),
            group.clone(),
            vec![reference("application/pdf")],
            Some("new attachment".into()),
        )
        .await
        .unwrap();
        assert_eq!(
            kit.attachment_history_version(account.clone(), group.clone())
                .await
                .unwrap()
                .change_since(baseline.clone()),
            AttachmentHistoryChangeFfi::Additions
        );
        assert!(matches!(
            kit.attachment_history_page(
                account.clone(),
                group.clone(),
                1,
                first.next_cursor.clone()
            )
            .await
            .unwrap(),
            AttachmentPageReadFfi::Page { .. }
        ));
        let deleted = first.entries[0].message_id_hex.clone();
        kit.delete_message(account.clone(), group.clone(), deleted.clone())
            .await
            .unwrap();
        assert_eq!(
            kit.attachment_history_version(account.clone(), group.clone())
                .await
                .unwrap()
                .change_since(baseline),
            AttachmentHistoryChangeFfi::RestartRequired
        );
        assert!(matches!(
            kit.attachment_history_page(account.clone(), group.clone(), 1, first.next_cursor)
                .await
                .unwrap(),
            AttachmentPageReadFfi::RestartRequired
        ));
        let fresh = page(
            kit.attachment_history_page(account.clone(), group.clone(), 100, None)
                .await
                .unwrap(),
        );
        assert_eq!(fresh.entries.len(), 59);
        assert!(fresh.entries.iter().all(|e| e.message_id_hex != deleted));
        kit.shutdown_and_close().await.unwrap();
        assert!(
            kit.attachment_history_page(account, group, 1, None)
                .await
                .is_err()
        );
    }
}
