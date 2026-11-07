//! Account/group-scoped attachment pages independent of engine readiness.
use crate::conversions::{
    AttachmentEntryFfi, AttachmentHistoryCursor, AttachmentHistoryVersion, AttachmentPageReadFfi,
    group_id_from_hex,
};
use crate::{Marmot, MarmotKitError};
use std::sync::Arc;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Resolve one active custom-emoji reaction's matching encrypted artwork.
    /// This bounded local read starts no download. Use the returned original
    /// source slot with attachment acquisition and opaque local reads.
    pub async fn reaction_attachment(
        &self,
        account_ref: String,
        group_id_hex: String,
        reaction_message_id_hex: String,
    ) -> Result<Option<AttachmentEntryFfi>, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .reaction_attachment(&account_ref, &group, &reaction_message_id_hex)
            .await?
            .map(Into::into))
    }

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
        AccountAttachmentPageFfi, AccountAttachmentPageReadFfi, AccountAttachmentQueryFfi,
        AttachmentCategoryFfi, AttachmentHistoryChangeFfi, AttachmentLocalTargetFfi,
        AttachmentPageFfi, AttachmentTransferStateFfi, MediaAttachmentOutcomeFfi,
        MediaUploadAttachmentRequestFfi, MediaUploadRequestFfi, RetainedAttachmentsPageFfi,
    };
    use cgka_traits::TransportEndpoint;
    use marmot_app::{AccountSetupRequest, MarmotApp};
    use nostr_relay_builder::{LocalRelay, RelayBuilder, builder::RateLimit};
    use std::collections::HashSet;

    // A real upload supplies the local provenance that an outbound reference needs.
    async fn upload_sink() -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let base = url.clone();
        let blobs = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
            String,
            Vec<u8>,
        >::new()));
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let base = base.clone();
                let blobs = blobs.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0; 4096];
                    let end = loop {
                        let n = socket.read(&mut buf).await.unwrap();
                        assert_ne!(n, 0);
                        request.extend_from_slice(&buf[..n]);
                        if let Some(end) = request.windows(4).position(|x| x == b"\r\n\r\n") {
                            break end + 4;
                        }
                    };
                    let headers = String::from_utf8_lossy(&request[..end]);
                    if headers.starts_with("GET /") {
                        let hash = headers
                            .lines()
                            .next()
                            .unwrap()
                            .split_whitespace()
                            .nth(1)
                            .unwrap()
                            .trim_start_matches('/');
                        let body = blobs
                            .lock()
                            .unwrap()
                            .get(hash)
                            .expect("GET must address a real uploaded ciphertext")
                            .clone();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        socket.write_all(response.as_bytes()).await.unwrap();
                        socket.write_all(&body).await.unwrap();
                        return;
                    }
                    assert!(headers.starts_with("PUT /upload "));
                    let header = |name: &str| {
                        headers
                            .lines()
                            .filter_map(|line| line.split_once(':'))
                            .find(|(key, _)| key.eq_ignore_ascii_case(name))
                            .unwrap()
                            .1
                            .trim()
                            .to_owned()
                    };
                    let len: usize = header("content-length").parse().unwrap();
                    let hash = header("x-sha-256");
                    while request.len() < end + len {
                        let n = socket.read(&mut buf).await.unwrap();
                        assert_ne!(n, 0);
                        request.extend_from_slice(&buf[..n]);
                    }
                    blobs
                        .lock()
                        .unwrap()
                        .insert(hash.clone(), request[end..end + len].to_vec());
                    let body = serde_json::json!({"url": format!("{base}/{hash}"), "sha256": hash,
                        "size": len, "type": "application/octet-stream", "uploaded": 1})
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        (url, task)
    }
    fn page(value: AttachmentPageReadFfi) -> AttachmentPageFfi {
        let AttachmentPageReadFfi::Page { page } = value else {
            panic!("expected page: {value:?}")
        };
        page
    }
    fn account_page(value: AccountAttachmentPageReadFfi) -> AccountAttachmentPageFfi {
        let AccountAttachmentPageReadFfi::Page { page } = value else {
            panic!("expected account page: {value:?}")
        };
        page
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        let app = MarmotApp::with_relays_and_config(
            root.path(),
            vec![url.clone()],
            marmot_app::MarmotAppConfig::white_noise()
                .with_allow_loopback_relay_endpoints(true)
                .with_allow_loopback_blob_endpoints(true)
                .with_open_ranking_provider(None, Vec::new()),
        );
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
        let (server, upload_task) = upload_sink().await;
        let uploaded = kit
            .upload_media(
                account.clone(),
                group.clone(),
                MediaUploadRequestFfi {
                    attachments: ["image/png", "audio/ogg", "application/pdf"]
                        .into_iter()
                        .map(|mime| MediaUploadAttachmentRequestFfi {
                            file_name: "attachment.bin".into(),
                            media_type: mime.into(),
                            plaintext: b"attachment fixture".to_vec(),
                            dim: None,
                            thumbhash: None,
                        })
                        .collect(),
                    caption: None,
                    send: false,
                    blossom_server: Some(server.clone()),
                    message_tags: Vec::new(),
                },
            )
            .await
            .unwrap();
        let references: Vec<_> = uploaded
            .attachments
            .into_iter()
            .map(|attachment| attachment.reference)
            .collect();
        // Unique captions prevent same-second NIP-01 duplicate message IDs.
        for i in 0..205 {
            if i % 7 == 0 {
                kit.send_media_attachments(
                    account.clone(),
                    group.clone(),
                    vec![references[0].clone(), references[1].clone()],
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
        let account_first = account_page(
            kit.account_attachment_history_page(
                account.clone(),
                AccountAttachmentQueryFfi::default(),
                1,
                None,
            )
            .await
            .unwrap(),
        );
        assert_eq!(account_first.entries.len(), 1);
        assert_eq!(account_first.entries[0].group_id_hex, group);
        assert_eq!(
            account_first.entries[0].entry.message_id_hex,
            first.entries[0].message_id_hex
        );
        assert!(account_first.next_cursor.is_some());
        let account_baseline = account_first.version.clone();
        assert_eq!(
            kit.account_attachment_history_version(account.clone())
                .await
                .unwrap()
                .change_since(account_baseline.clone()),
            AttachmentHistoryChangeFfi::Unchanged
        );
        let excluded_query = AccountAttachmentQueryFfi {
            groups: vec!["ab".repeat(16)],
            ..Default::default()
        };
        let filtered = account_page(
            kit.account_attachment_history_page(account.clone(), excluded_query.clone(), 1, None)
                .await
                .unwrap(),
        );
        assert!(filtered.entries.is_empty());
        assert!(
            filtered.next_cursor.is_some(),
            "a filtered empty page still has an authoritative continuation"
        );
        let filtered_next = account_page(
            kit.account_attachment_history_page(
                account.clone(),
                excluded_query,
                1,
                filtered.next_cursor.clone(),
            )
            .await
            .unwrap(),
        );
        assert!(filtered_next.entries.is_empty());
        assert!(filtered_next.next_cursor.is_some());
        assert!(matches!(
            kit.account_attachment_history_page(
                account.clone(),
                AccountAttachmentQueryFfi::default(),
                1,
                filtered.next_cursor
            )
            .await
            .unwrap(),
            AccountAttachmentPageReadFfi::CursorMismatch
        ));
        assert!(matches!(
            kit.account_attachment_history_page(
                account.clone(),
                AccountAttachmentQueryFfi {
                    groups: vec!["invalid!".into()],
                    ..Default::default()
                },
                1,
                None
            )
            .await
            .unwrap(),
            AccountAttachmentPageReadFfi::InvalidQuery
        ));
        for limit in [0, 101] {
            assert!(matches!(
                kit.account_attachment_history_page(
                    account.clone(),
                    AccountAttachmentQueryFfi::default(),
                    limit,
                    None
                )
                .await
                .unwrap(),
                AccountAttachmentPageReadFfi::InvalidLimit
            ));
        }
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
        let mut retained_targets = Vec::new();
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
            if retained_targets.len() < 2 {
                retained_targets.push(AttachmentLocalTargetFfi {
                    message_id_hex: entry.message_id_hex.clone(),
                    source_message_id_hex: entry.source_message_id_hex.clone(),
                    attachment_index: *attachment_index,
                });
            }
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
        // Acquire two actual source slots before reading their native summaries.
        // Outgoing retention is optional and may not have finished at this point.
        // The peer serves the exact encrypted bytes received by the real upload.
        for target in &retained_targets {
            kit.request_explicit_attachment(account.clone(), group.clone(), target.clone())
                .await
                .unwrap()
                .expect("an accepted source slot admits explicit demand");
        }
        let transfers = kit
            .subscribe_attachment_transfers(
                account.clone(),
                group.clone(),
                retained_targets.clone(),
            )
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let snapshot = transfers
                    .next()
                    .await
                    .unwrap()
                    .expect("live acquisition observation");
                assert_eq!(snapshot.items.len(), 2);
                if snapshot
                    .items
                    .iter()
                    .all(|item| matches!(item.state, AttachmentTransferStateFfi::Ready))
                {
                    break;
                }
            }
        })
        .await
        .expect("two real attachment slots must become ready");
        transfers.cancel();
        let assets = kit
            .attachment_local_assets(account.clone(), group.clone(), retained_targets)
            .await
            .unwrap();
        assert_eq!(assets.len(), 2);
        assert!(
            assets
                .iter()
                .all(|asset| asset.reference.is_some() && asset.byte_count == 18)
        );
        // Freeze one actual native snapshot for the manual full/short constructor;
        // this does not assert completeness of the background retained collection.
        let captured = kit
            .runtime
            .largest_retained_attachments(
                &account,
                Some(&cgka_traits::GroupId::new(hex::decode(&group).unwrap())),
                None,
                64,
            )
            .await
            .unwrap();
        assert!(
            captured.len() >= 2,
            "the two acquired slots must produce actual retained summaries"
        );
        let full = RetainedAttachmentsPageFfi::new(captured[..2].to_vec(), 2);
        assert_eq!(full.attachments.len(), 2);
        let cursor = full
            .next_cursor
            .expect("a full retained page must continue");
        assert_eq!(cursor.inner, captured[1].cursor);
        assert_ne!(cursor.inner, captured[0].cursor);
        let short = RetainedAttachmentsPageFfi::new(vec![captured[1].clone()], 2);
        assert_eq!(short.attachments.len(), 1);
        assert!(short.next_cursor.is_none());
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
            kit.account_attachment_history_page(
                other.clone(),
                AccountAttachmentQueryFfi::default(),
                1,
                account_first.next_cursor.clone()
            )
            .await
            .unwrap(),
            AccountAttachmentPageReadFfi::CursorMismatch
        ));
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
        assert!(matches!(
            kit.attachment_history_page(account.clone(), String::new(), 1, None)
                .await,
            Err(MarmotKitError::InvalidHex { .. })
        ));
        kit.send_media_attachments(
            account.clone(),
            group.clone(),
            vec![references[2].clone()],
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
        assert_eq!(
            kit.account_attachment_history_version(account.clone())
                .await
                .unwrap()
                .change_since(account_baseline.clone()),
            AttachmentHistoryChangeFfi::Additions
        );
        assert!(matches!(
            kit.account_attachment_history_page(
                account.clone(),
                AccountAttachmentQueryFfi::default(),
                1,
                account_first.next_cursor.clone()
            )
            .await
            .unwrap(),
            AccountAttachmentPageReadFfi::Page { .. }
        ));
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
        assert_eq!(
            kit.account_attachment_history_version(account.clone())
                .await
                .unwrap()
                .change_since(account_baseline),
            AttachmentHistoryChangeFfi::RestartRequired
        );
        assert!(matches!(
            kit.account_attachment_history_page(
                account.clone(),
                AccountAttachmentQueryFfi::default(),
                1,
                account_first.next_cursor
            )
            .await
            .unwrap(),
            AccountAttachmentPageReadFfi::RestartRequired
        ));
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
        // A real retention-bearing send produces the otherwise opaque expiry
        // token; this checks only that the account-page wrapper exposes it.
        kit.update_message_retention(account.clone(), group.clone(), 3600)
            .await
            .unwrap();
        kit.upload_media(
            account.clone(),
            group.clone(),
            MediaUploadRequestFfi {
                attachments: vec![MediaUploadAttachmentRequestFfi {
                    file_name: "expiring.pdf".into(),
                    media_type: "application/pdf".into(),
                    plaintext: b"expiring attachment fixture".to_vec(),
                    dim: None,
                    thumbhash: None,
                }],
                caption: Some("expiring attachment".into()),
                send: true,
                blossom_server: Some(server),
                message_tags: vec![],
            },
        )
        .await
        .unwrap();
        let native_expiry = kit
            .runtime
            .account_attachment_history_version(&account)
            .await
            .unwrap()
            .next_expiry
            .expect("the actual expiring send must produce an expiry token");
        let expiring = account_page(
            kit.account_attachment_history_page(
                account.clone(),
                AccountAttachmentQueryFfi::default(),
                1,
                None,
            )
            .await
            .unwrap(),
        );
        assert_eq!(expiring.next_expiry, Some(native_expiry));
        upload_task.abort();
        let _ = upload_task.await;
        kit.shutdown_and_close().await.unwrap();
        assert!(matches!(
            kit.attachment_history_page(account, group, 1, None).await,
            Err(MarmotKitError::RuntimeStopping)
        ));
    }
}
