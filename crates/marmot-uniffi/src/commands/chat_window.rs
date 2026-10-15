//! Additive native entry points for C4's bounded lists and independent summaries.
use crate::conversions::ChatListViewFfi;
use crate::subscriptions::{AccountAttentionSubscription, ChatListWindowSubscription};
use crate::{Marmot, MarmotKitError};
use std::sync::Arc;
#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Bind to one account/view. None defaults to 50; explicit sizes must be 1–100.
    pub async fn open_chat_list_window(
        &self,
        account_ref: String,
        view: ChatListViewFfi,
        initial_rows: Option<u32>,
    ) -> Result<Arc<ChatListWindowSubscription>, MarmotKitError> {
        Ok(ChatListWindowSubscription::new(
            self.runtime
                .open_chat_list_window(&account_ref, view.into(), initial_rows.map(|n| n as usize))
                .await?,
        ))
    }
    /// Signed-in local/external accounts, independent of any list or active worker.
    pub async fn subscribe_account_attention(
        &self,
    ) -> Result<Arc<AccountAttentionSubscription>, MarmotKitError> {
        Ok(AccountAttentionSubscription::new(
            self.runtime.subscribe_account_attention().await?,
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
    use std::time::Duration;

    /// A kit with one account holding `groups` local groups. Keep the relay and
    /// directory alive for the test's duration.
    async fn kit_with_groups(groups: &[&str]) -> (MockRelay, tempfile::TempDir, Marmot, String) {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relays(dir.path(), vec![url.clone()]);
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
        for name in groups {
            kit.create_group(account.clone(), (*name).into(), vec![], None)
                .await
                .unwrap();
        }
        (relay, dir, kit, account)
    }

    #[tokio::test]
    async fn native_window_commands_run_during_receive_and_attention_is_independent() {
        let (_relay, _dir, kit, account) = kit_with_groups(&["One", "Two", "Three"]).await;
        let attention = kit.subscribe_account_attention().await.unwrap();
        let summary = attention.snapshot().unwrap();
        assert!(attention.snapshot().is_none());
        assert_eq!(summary.accounts.len(), 1);
        assert!(
            matches!(summary.accounts[0].state, AccountAttentionStateFfi::Ready {total} if total.unread_conversations == 0)
        );
        assert!(matches!(
            kit.open_chat_list_window(account.clone(), ChatListViewFfi::Chats, Some(0))
                .await,
            Err(MarmotKitError::ChatWindowInvalidLimit)
        ));
        assert!(matches!(
            kit.open_chat_list_window(account.clone(), ChatListViewFfi::Chats, Some(101))
                .await,
            Err(MarmotKitError::ChatWindowInvalidLimit)
        ));
        let window = kit
            .open_chat_list_window(account.clone(), ChatListViewFfi::Chats, Some(1))
            .await
            .unwrap();
        let initial = window.snapshot().unwrap();
        assert!(window.snapshot().is_none());
        assert_eq!(initial.rows.len(), 1);
        assert!(initial.has_more_after);
        assert!(!initial.has_more_before);
        let mut pending = Box::pin(window.next());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut pending)
                .await
                .is_err()
        );
        let page = tokio::time::timeout(
            Duration::from_secs(5),
            window.page(initial.sequence, ChatListPageDirectionFfi::Forward, 1),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(page.rows.len(), 2);
        let update = pending.await.unwrap().unwrap();
        assert_eq!(update.sequence, page.sequence);
        assert_eq!(
            update.subscription_generation,
            initial.subscription_generation
        );
        assert!(matches!(
            window
                .page(initial.sequence, ChatListPageDirectionFfi::Forward, 1)
                .await,
            Err(MarmotKitError::ChatWindowStale)
        ));
        assert!(matches!(
            window
                .set_visible_anchor(page.sequence, "abcd".into())
                .await,
            Err(MarmotKitError::ChatWindowAnchorOutside)
        ));
        let anchor_id = page.rows[1].row.group_id_hex.clone();
        let anchored = window
            .set_visible_anchor(page.sequence, anchor_id.clone())
            .await
            .unwrap();
        assert!(
            matches!(&anchored.anchor, ChatListAnchorOutcomeFfi::Retained {group_id_hex, index:1} if group_id_hex == &anchor_id)
        );
        let top = window.return_to_top(anchored.sequence).await.unwrap();
        assert!(matches!(top.anchor, ChatListAnchorOutcomeFfi::Top));
        drop(window);
        kit.set_chat_manually_unread(account.clone(), anchor_id.clone(), true)
            .unwrap();
        let summary = tokio::time::timeout(Duration::from_secs(5), attention.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            matches!(summary.accounts[0].state, AccountAttentionStateFfi::Ready {total} if total.unread_conversations == 1 && total.attention_only_conversations == 1 && total.unread_count == 0)
        );
        for (view, expected) in [
            (ChatListViewFfi::Chats, 3),
            (ChatListViewFfi::Unread, 1),
            (ChatListViewFfi::Archived, 0),
            (ChatListViewFfi::Left, 0),
        ] {
            let handle = kit
                .open_chat_list_window(account.clone(), view, None)
                .await
                .unwrap();
            assert_eq!(handle.snapshot().unwrap().rows.len(), expected);
        }
        let window = kit
            .open_chat_list_window(account, ChatListViewFfi::Chats, None)
            .await
            .unwrap();
        let last = window.snapshot().unwrap();
        kit.runtime.shutdown_and_close().await.unwrap();
        assert!(window.next().await.unwrap().is_none());
        assert!(attention.next().await.unwrap().is_none());
        assert!(matches!(
            window.return_to_top(last.sequence).await,
            Err(MarmotKitError::ChatWindowClosed)
        ));
    }

    /// A Kotlin caller can cancel a waiting `next()`. The update that arrives
    /// meanwhile must reach the following call rather than the cancelled one.
    #[tokio::test]
    async fn a_cancelled_window_wait_leaves_the_update_for_the_next_call() {
        let (_relay, _dir, kit, account) = kit_with_groups(&["One", "Two"]).await;
        let window = kit
            .open_chat_list_window(account, ChatListViewFfi::Chats, Some(1))
            .await
            .unwrap();
        let initial = window.snapshot().unwrap();
        let mut waiting = Box::pin(window.__ffi_next());
        assert!(futures::poll!(&mut waiting).is_pending());
        let page = window
            .page(initial.sequence, ChatListPageDirectionFfi::Forward, 1)
            .await
            .unwrap();
        // Give the runtime every chance to hand the update to the waiting call.
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(waiting);
        let update = tokio::time::timeout(Duration::from_secs(5), window.__ffi_next())
            .await
            .expect("the update outlives the cancelled wait")
            .unwrap()
            .unwrap();
        assert_eq!(update.sequence, page.sequence);
        kit.runtime.shutdown_and_close().await.unwrap();
    }
}
