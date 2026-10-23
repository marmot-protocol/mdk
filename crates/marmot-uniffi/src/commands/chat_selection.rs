//! Additive complete-scope command; IDs and capture remain native-owned.
use crate::conversions::ChatSelectionOpenFfi;
use crate::subscriptions::ChatSelection;
use crate::{Marmot, MarmotKitError};
use std::sync::Arc;
mod departure;
#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    pub async fn open_chat_selection(
        &self,
        account_ref: String,
        open: ChatSelectionOpenFfi,
    ) -> Result<Arc<ChatSelection>, MarmotKitError> {
        Ok(ChatSelection::new(
            self.runtime
                .open_complete_chat_list_selection(&account_ref, open.into())
                .await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversions::*;
    use cgka_traits::TransportEndpoint;
    use marmot_app::{AccountSetupRequest, MarmotApp};
    use nostr_relay_builder::MockRelay;

    fn open(account: &str) -> ChatSelectionOpenFfi {
        ChatSelectionOpenFfi {
            scope: ChatSelectionScopeFfi {
                selected_folder: None,
                filter_folders: None,
                named_chats: None,
                direct: true,
                groups: true,
                search: None,
            },
            base: ChatSelectionBaseScopeFfi::ActiveAndArchived,
            context: ChatSelectionContextFfi {
                host: ChatSelectionHostContextFfi {
                    account_id_hex: account.into(),
                    runtime_generation: 1,
                    selection_generation: 1,
                    presentation_context_id: 1,
                },
                overlays: ChatSelectionHostOverlaysFfi {
                    sending: Default::default(),
                    muted: Default::default(),
                    removed: vec![],
                    invite_conflicts: vec![],
                    preview_overrides: Default::default(),
                    media_preview_fallbacks: Default::default(),
                },
                capture_now_ms: 0,
            },
        }
    }
    async fn kit() -> (MockRelay, tempfile::TempDir, Arc<Marmot>, String) {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relays(dir.path(), vec![url.clone()]);
        let kit = Arc::new(Marmot {
            runtime: app.runtime(),
            app,
        });
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
        (relay, dir, kit, account)
    }
    #[tokio::test(flavor = "current_thread")]
    async fn chat_selection_actual_current_thread_worker_refuses_new_scan() {
        let (_relay, _dir, kit, account) = kit().await;
        assert_eq!(
            tokio::runtime::Handle::current().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::CurrentThread
        );
        // Match the actual native CurrentThread-worker oracle: account setup
        // alone is not an assertion that the live worker is past startup.
        kit.runtime.catch_up_accounts().await.unwrap();
        let result = kit
            .__ffi_open_chat_selection(account.clone(), open(&account))
            .await;
        let classification = match &result {
            Ok(selection) => {
                selection.close_selection();
                "accepted"
            }
            Err(MarmotKitError::ChatSelectionUnsupportedRuntime) => "unsupported-runtime",
            Err(MarmotKitError::ChatSelectionNotReady) => "not-ready",
            Err(MarmotKitError::ChatSelectionClosed) => "closed",
            Err(_) => "other-error",
        };
        let refused = matches!(result, Err(MarmotKitError::ChatSelectionUnsupportedRuntime));
        kit.runtime.shutdown_and_close().await.unwrap();
        assert!(
            refused,
            "actual warmed CurrentThread selection classification={classification}"
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chat_selection_actual_plain_host_wrappers_keep_complete_count_membership_and_close() {
        let (_relay, _dir, kit, account) = kit().await;
        for i in 0..51 {
            kit.create_group(account.clone(), format!("Selection {i}"), vec![], None)
                .await
                .unwrap();
        }
        kit.runtime.drain_in_flight_work().await.unwrap();
        // Existing presented owner prepares real stored values; no test-only SQL
        // or visibility relaxation is needed at the binding boundary.
        kit.runtime
            .presented_chat_list(&account, true)
            .await
            .unwrap();
        let caller = kit.clone();
        tokio::task::spawn_blocking(move || {
            futures::executor::block_on(async move {
                let selection = caller
                    .__ffi_open_chat_selection(account.clone(), open(&account))
                    .await
                    .unwrap();
                let status = selection.__ffi_status().await.unwrap();
                assert_eq!(status.count, Some(51));
                assert_eq!(status.all_archived, Some(false));
                assert_eq!(status.all_direct, Some(false));
                let page = selection.__ffi_page(status.revision, 0, 200).await.unwrap();
                assert_eq!(page.group_ids.len(), 51);
                let ids = page.group_ids[..2].to_vec();
                assert_eq!(
                    selection
                        .__ffi_membership(status.revision, ids.clone())
                        .await
                        .unwrap(),
                    vec![true, true]
                );
                let shrunk = selection
                    .__ffi_exclude(status.revision, ids.clone())
                    .await
                    .unwrap();
                assert_eq!(shrunk.count, Some(49));
                let restored = selection
                    .__ffi_reselect(shrunk.revision, open(&account).context, ids.clone())
                    .await
                    .unwrap();
                assert_eq!(restored.count, Some(51));
                assert_eq!(
                    selection
                        .__ffi_membership(restored.revision, ids)
                        .await
                        .unwrap(),
                    vec![true, true]
                );

                assert!(matches!(
                    selection.__ffi_page(status.revision, 0, 200).await,
                    Err(MarmotKitError::ChatSelectionStale)
                ));
                selection.close_selection();
                assert!(matches!(
                    selection.__ffi_count().await,
                    Err(MarmotKitError::ChatSelectionClosed)
                ));
            })
        })
        .await
        .unwrap();
        kit.runtime.shutdown_and_close().await.unwrap();
    }
}
